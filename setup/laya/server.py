"""Laya as Reflex's local System 1: laya-serve's own Jev-compatible app, bound to 127.0.0.1.

    python setup/laya/server.py [--port 8421] [--models typed-decisions] [--device auto|cpu|mps|cuda] [--calibrated]

It speaks the request shape gate.mjs ask() already sends to Jev ({state, model, questions} ->
{answers, usage}), so Reflex only switches the URL. What this file adds around laya-serve:

  * checkpoints pinned to one Hugging Face revision (REVISION), so a decision can be reproduced;
  * with --calibrated, the per-question calibration in setup/laya/calibration.json (Laya ships
    over-confident): Platt scaling for yes/no questions, a temperature for choice and score, fitted
    on half of Reflex's golden sets and scored on the other half. Off by default: it lowers the
    calibration error but made the tool gate miss a deny and the guard miss high-severity
    injections that the raw checkpoint caught (docs/GUIDE.md#laya);
  * the guard's multi-chunk states split per chunk: Laya encodes the state once per question and
    cuts it at the checkpoint's token budget, so questions about chunk c5 would otherwise never
    see c5. A question `<name>_<id>` (the guard) or `<id>` (the context layer) with `state.chunks.<id>`
    sees only that chunk;
  * truncation reported in `usage` (state_tokens, state_budget, truncated) instead of silently cut.

Nothing leaves the machine: the weights are read from the local Hugging Face cache and the server
refuses any bind address but loopback. Selfcheck without torch or a download: --selfcheck.
"""
import argparse
import atexit
import json
import math
import os
import sys
from pathlib import Path

LAYA_VERSION = "0.3.22"        # the laya package this was tested with (reflex setup pins it)
REPO = "convaiinnovations/laya"
REVISION = "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851"   # 2026-09-24; all three checkpoints
SUBFOLDERS = {"english": None, "multilingual": "multilingual", "typed-decisions": "typed-decisions"}
# Token budget per checkpoint (max_len). english: the 512 it was trained at. multilingual reads up
# to 8,192 (the card measures accuracy holding to ~4,000); typed-decisions ships 1,024.
MAX_LEN = {"english": 512, "multilingual": 4096, "typed-decisions": 1024}
PORT = 8421
HERE = Path(__file__).resolve().parent
CALIBRATION = HERE / "calibration.json"
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def serialize_state(state):
    """As laya.common.serialize_state: the text the model reads."""
    return state if isinstance(state, str) else json.dumps(state, ensure_ascii=False)


def split_by_chunk(state, questions):
    """[(state, questions)]: a question `<id>` or `<name>_<id>` whose `<id>` is a key of state["chunks"] gets a
    state holding only that chunk; every other question keeps the whole state."""
    chunks = state.get("chunks") if isinstance(state, dict) else None
    if not isinstance(chunks, dict) or not chunks:
        return [(state, questions)]
    groups = {}
    for qid, q in questions.items():
        cid = qid if qid in chunks else qid.rsplit("_", 1)[-1] if "_" in qid else None
        groups.setdefault(cid if cid in chunks else None, {})[qid] = q
    return [(state if cid is None else {**state, "chunks": {cid: chunks[cid]}}, qs) for cid, qs in groups.items()]


def base_id(qid, state):
    """The question's name for calibration: without a guard chunk suffix (`addressed_c3`), and every
    instruction fragment (`f0`, `f1`, ...) as one question, `f`."""
    chunks = state.get("chunks") if isinstance(state, dict) else None
    head, _, tail = qid.rpartition("_")
    if head and isinstance(chunks, dict) and tail in chunks:
        return head
    return "f" if qid[:1] == "f" and qid[1:].isdigit() else qid


def temper(answer, t):
    """Calibrate one Laya answer. t = {a, b}: Platt scaling of a yes/no answer, sigmoid(a * logit(p) + b).
    t = a number: one more temperature. p ∝ exp(z / T0) already, so p^(1/t) renormalised is exactly
    softmax(z / (T0 * t)): no logits needed."""
    if not t or t == 1:
        return answer
    a = dict(answer)
    if a.get("type") == "noul":
        p1 = min(max(float(a["noul"]), 1e-12), 1 - 1e-12)
        if isinstance(t, dict):
            z = t["a"] * math.log(p1 / (1 - p1)) + t["b"]
            a["noul"] = round(1 / (1 + math.exp(-max(-50.0, min(50.0, z)))), 4)
        else:
            w1, w0 = p1 ** (1 / t), (1 - p1) ** (1 / t)
            a["noul"] = round(w1 / (w0 + w1), 4)
        a["confidence"] = a["answer_confidence"] = round(max(a["noul"], 1 - a["noul"]), 4)
        return a
    if isinstance(t, dict):
        return answer
    keys = list(a["probabilities"])
    w = [max(float(a["probabilities"][k]), 1e-12) ** (1 / t) for k in keys]
    s = sum(w)
    p = [x / s for x in w]
    a["probabilities"] = {k: round(v, 4) for k, v in zip(keys, p)}
    k = len(p)
    ent = -sum(x * math.log(x) for x in p if x > 0)
    a["confidence"] = round(1 - ent / math.log(k), 4) if k > 1 else 1.0
    a["answer_confidence"] = round(max(p), 4)
    if a["type"] == "score":
        a["score"] = round(sum(i * x for i, x in enumerate(p)), 4)
    return a


def noul_as_choice(q):
    """The card's workaround for `noul` following its false:/true: labels instead of the state (laya
    #156): the same question as a two-option choice with neutral keys, yes first."""
    crit = q.get("criteria") or {}
    return {"type": "choice", "instructions": q["instructions"],
            "criteria": {"A": crit.get("true") or "yes, the statement holds", "B": crit.get("false") or "no, the statement does not hold"}}


def choice_as_noul(a):
    p = float(a["probabilities"]["A"])
    return {"type": "noul", "noul": p, "confidence": round(max(p, 1 - p), 4), "answer_confidence": round(max(p, 1 - p), 4)}


def load_calibration(path, noul):
    """{checkpoint: {question: params}}, for the yes/no mode the file was fitted in (else none)."""
    try:
        c = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {}
    if c.get("noul", "choice") != noul:
        print("laya server: %s was fitted with --noul %s; serving uncalibrated" % (path, c.get("noul")), file=sys.stderr)
        return {}
    return c.get("checkpoints", {})


class ReflexRouter:
    """What laya.serve.create_app needs from a Router (`loaded`, `predict`), with Reflex's additions."""

    def __init__(self, router, default, calibration, calibrate=True, tokenizer_of=None, noul="choice", resident=None):
        self.router, self.default, self.calibration, self.calibrate, self.noul = router, default, calibration, calibrate, noul
        self.resident = resident or [default]
        self.tokenizer_of = tokenizer_of or (lambda name: router.load(name).tok)

    @property
    def loaded(self):
        return self.router.loaded

    def predict(self, state, questions, model=None):
        name = model or self.default
        if name not in self.resident:
            # Otherwise laya's Router would fetch it unpinned and evict a resident one. A ValueError
            # is laya-serve's 422, and Reflex falls back to the policy as in any outage.
            raise ValueError("checkpoint %r is not resident here (%s); add it to laya.models" % (name, ", ".join(self.resident)))
        max_len = MAX_LEN[name]
        temps = self.calibration.get(name, {}) if self.calibrate else {}
        answers, tokens, longest, truncated = {}, 0, 0, []
        tok = self.tokenizer_of(name)
        for st, qs in split_by_chunk(state, questions):
            asked = {k: noul_as_choice(q) if self.noul == "choice" and q.get("type") == "noul" else q for k, q in qs.items()}
            r = self.router.predict(st, asked, model=name, max_len=max_len)
            tokens += r.get("usage", {}).get("input_tokens", 0)
            n = len(tok(serialize_state(st), add_special_tokens=False)["input_ids"])
            longest = max(longest, n)
            # A state gets max_len minus its question's head (at most head_max_len) and 3 markers.
            if n > max_len - self.router.load(name).cfg.get("head_max_len", 192) - 3:
                truncated += list(qs)
            for qid, a in r["answers"].items():
                if qs[qid].get("type") == "noul" and a.get("type") == "choice":
                    a = choice_as_noul(a)
                answers[qid] = temper(a, temps.get(base_id(qid, state)))
        return {"model": f"laya-{name}", "answers": answers,
                "usage": {"input_tokens": tokens, "output_tokens": 0, "state_tokens": longest,
                          "state_budget": max_len, "truncated": truncated},
                "calibrated": bool(temps)}


def download(names):
    """{name: (snapshot dir, subfolder)} at the pinned revision; only the named checkpoints."""
    from huggingface_hub import snapshot_download
    specs = {}
    for n in names:
        prefix = f"{SUBFOLDERS[n]}/" if SUBFOLDERS[n] else ""
        root = snapshot_download(REPO, revision=REVISION, allow_patterns=[prefix + f for f in (
            "rl_agent_config.json", "model.safetensors", "tokenizer/*", "encoder/*")])
        specs[n] = (root, SUBFOLDERS[n])
    return specs


def build(args):
    from laya import Router
    names = [n.strip() for n in args.models.split(",") if n.strip()]
    specs = download(names)
    router = Router(models=specs, device=None if args.device == "auto" else args.device, max_loaded=len(names))
    router.preload(names)
    return ReflexRouter(router, names[0], load_calibration(args.calibration, args.noul), calibrate=args.calibrated, noul=args.noul, resident=names)


def warm(r):
    """One throwaway call so the first real hook does not pay for kernel compilation."""
    r.predict({"call": {"command": "ls"}}, {"w": {"type": "noul", "instructions": "Does it list files?"}})


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=int(os.environ.get("REFLEX_LAYA_PORT", PORT)))
    p.add_argument("--models", default=os.environ.get("REFLEX_LAYA_MODELS", "typed-decisions"),
                   help="comma list of checkpoints to keep resident; the first answers requests that name none")
    p.add_argument("--device", default=os.environ.get("LAYA_DEVICE", "auto"))
    p.add_argument("--calibration", default=str(CALIBRATION))
    p.add_argument("--calibrated", action="store_true", help="apply calibration.json (off: the checkpoint's own probabilities)")
    p.add_argument("--noul", choices=["choice", "native"], default=os.environ.get("REFLEX_LAYA_NOUL", "choice"),
                   help="ask yes/no questions as a neutral two-option choice (default, laya #156) or as Laya's own noul")
    p.add_argument("--pidfile", help="write the server's pid here once it is ready")
    p.add_argument("--download-only", action="store_true", help="fetch the checkpoints at the pinned revision and exit")
    p.add_argument("--selfcheck", action="store_true")
    args = p.parse_args(argv)
    if args.selfcheck:
        return selfcheck()
    if args.host not in LOOPBACK:
        sys.exit("laya server: refusing to bind %s; it listens on loopback only" % args.host)
    for n in args.models.split(","):
        if n.strip() and n.strip() not in SUBFOLDERS:
            sys.exit("laya server: unknown checkpoint %r (use %s)" % (n, ", ".join(SUBFOLDERS)))
    if args.download_only:
        return download([n.strip() for n in args.models.split(",") if n.strip()])
    os.environ.setdefault("USE_TF", "0")   # the card: TensorFlow's import can deadlock model construction
    import uvicorn
    from laya.serve import create_app
    r = build(args)
    warm(r)
    if args.pidfile:
        Path(args.pidfile).write_text(str(os.getpid()))
        atexit.register(lambda: Path(args.pidfile).unlink(missing_ok=True))
    # LAYA_API_KEY (set by `reflex laya start` to a local token) makes laya-serve require it.
    uvicorn.run(create_app(r), host=args.host, port=args.port, log_level="warning")


def selfcheck():
    s = {"source": {}, "chunks": {"c0": {"text": "a"}, "c1": {"text": "b"}}, "reader": "ctx"}
    q = {"addressed_c0": {}, "attack_c0": {}, "addressed_c1": {}, "other": {}}
    g = split_by_chunk(s, q)
    assert [(list(st["chunks"]), list(qs)) for st, qs in g] == [(["c0"], ["addressed_c0", "attack_c0"]), (["c1"], ["addressed_c1"]),
                                                               (["c0", "c1"], ["other"])], g
    assert split_by_chunk({"call": {}}, q) == [({"call": {}}, q)]
    assert split_by_chunk(s, {"c1": {}}) == [({**s, "chunks": {"c1": {"text": "b"}}}, {"c1": {}})]   # the context layer's shape
    assert base_id("addressed_c1", s) == "addressed" and base_id("on_task", {"call": {}}) == "on_task" and base_id("x_c9", s) == "x_c9"
    n = temper({"type": "noul", "noul": 0.9, "confidence": 0.9}, 2)
    assert abs(n["noul"] - 0.75) < 1e-3, n                                # 3:1 odds from 9:1 at t = 2
    c = temper({"type": "score", "score": 0.2, "probabilities": {"0": 0.8, "1": 0.2}}, 1e9)
    assert abs(c["score"] - 0.5) < 1e-3 and c["confidence"] < 0.01, c     # t -> inf: uniform
    assert temper(n, 1) is n and temper(n, None) is n
    assert temper({"type": "noul", "noul": 0.5}, {"a": 1, "b": math.log(3)})["noul"] == 0.75   # Platt: odds 1 -> 3
    assert temper({"type": "noul", "noul": 0.9}, {"a": 0, "b": 0})["noul"] == 0.5               # no signal: the prior
    assert base_id("f12", {"request": {}}) == "f" and base_id("fx", {}) == "fx"

    class Tok:
        def __call__(self, text, add_special_tokens=False):
            return {"input_ids": text.split()}

    class Agent:
        cfg = {"head_max_len": 4}
        tok = Tok()

    class FakeRouter:
        loaded = ["english"]

        def load(self, name):
            return Agent()

        def predict(self, st, qs, model=None, max_len=None):
            return {"answers": {k: {"type": "noul", "noul": 0.9, "confidence": 0.9} for k in qs}, "usage": {"input_tokens": 5}}

    r = ReflexRouter(FakeRouter(), "english", {"english": {"addressed": 2}}, tokenizer_of=lambda n: Tok(), noul="native")
    out = r.predict(s, q)
    assert out["answers"]["addressed_c0"]["noul"] == 0.75 and out["answers"]["addressed_c1"]["noul"] == 0.75, out
    assert out["answers"]["other"]["noul"] == 0.9 and out["usage"]["input_tokens"] == 15 and out["calibrated"], out
    assert out["usage"]["truncated"] == [] and out["model"] == "laya-english"
    MAX_LEN["english"], saved = 5, MAX_LEN["english"]
    try:
        assert r.predict({"call": " ".join(["w"] * 10)}, {"q": {}})["usage"]["truncated"] == ["q"]
    finally:
        MAX_LEN["english"] = saved
    class ChoiceRouter(FakeRouter):
        def predict(self, st, qs, model=None, max_len=None):
            assert all(q["type"] == "choice" and list(q["criteria"]) == ["A", "B"] for q in qs.values()), qs
            return {"answers": {k: {"type": "choice", "choice": "A", "probabilities": {"A": 0.5, "B": 0.5}} for k in qs}, "usage": {}}

    c = ReflexRouter(ChoiceRouter(), "english", {"english": {"addressed": {"a": 1, "b": math.log(3)}}}, tokenizer_of=lambda n: Tok()).predict(
        s, {"addressed_c0": {"type": "noul", "instructions": "x"}})   # default noul="choice": asked as A/B, read back, then Platt
    assert c["answers"]["addressed_c0"] == {"type": "noul", "noul": 0.75, "confidence": 0.75, "answer_confidence": 0.75}, c
    try:
        r.predict(s, q, model="multilingual")
        raise AssertionError("a checkpoint that is not resident must be refused")
    except ValueError as e:
        assert "not resident" in str(e)
    assert noul_as_choice({"type": "noul", "instructions": "x", "criteria": {"false": "no"}})["criteria"] == {"A": "yes, the statement holds", "B": "no"}
    assert choice_as_noul({"probabilities": {"A": 0.2, "B": 0.8}})["noul"] == 0.2
    assert ReflexRouter(FakeRouter(), "english", {"english": {"addressed": 2}}, calibrate=False, noul="native",
                        tokenizer_of=lambda n: Tok()).predict(s, q)["answers"]["addressed_c0"]["noul"] == 0.9
    print("laya server selfcheck ok")


if __name__ == "__main__":
    main()
