#!/usr/bin/env python3
"""Reflex routing: a LiteLLM pre-call hook that picks the model for a request by how sensitive its
content is and how hard it is, with one Jev call.

  litellm_settings: {callbacks: ["reflex_router.proxy_handler_instance"]}   (this file next to config.yaml)
  python3 routing/reflex_router.py --selfcheck          offline tests, Jev stubbed
  python3 routing/reflex_router.py --check "<prompt>" [--model claude-opus-5]   one live decision
  python3 routing/reflex_router.py --eval [--golden f]   live Jev over routing/golden.json (npm run eval-routing)

Order: family of the requested model -> secret shapes / sensitive paths (a floor) -> cache -> Jev
-> policy (sensitivity pool, models the caller's key may use under the requested model's guardrails
and per-model limits, difficulty tier, cheapest; none eligible: policy no_eligible) -> stickiness
(large contexts, signed thinking and 1M contexts stay put unless sensitivity forces a move).
REFLEX_ROUTING_MODE: off | shadow (default: decide in the background, log, keep the requested model)
| enforce (wait up to the latency budget, rewrite data["model"]). Stdlib only; litellm is imported
to subclass its CustomLogger and, inside the proxy, for its key-access check.
"""
import asyncio
import functools
import hashlib
import json
import math
import os
import random
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # the selfcheck and the CLI run without litellm
    CustomLogger = object

HERE = Path(__file__).resolve().parent
ENV = os.environ
CONFIG_DIR = Path(ENV.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "reflex"
try:
    USER_CONFIG = json.loads((CONFIG_DIR / "config.json").read_text())
    if not isinstance(USER_CONFIG, dict):
        raise ValueError("expected a JSON object")
except FileNotFoundError:
    USER_CONFIG = {}
except (OSError, ValueError):
    USER_CONFIG = {"engine": "local"}  # Invalid settings cannot enable a hosted call.
CONFIG = {
    "engine": ENV.get("REFLEX_ENGINE", USER_CONFIG.get("engine", "jev")),
}
# engine laya: the local Laya server (setup/laya/server.py), same request shape, no key, nothing leaves the machine.
LAYA = {"port": 8421, "model": "typed-decisions", **(USER_CONFIG.get("laya") if isinstance(USER_CONFIG.get("laya"), dict) else {})}
# Jev providers, as in providers.mjs (adapted from jev-mcp by Joey Kudish, MIT, github.com/jkudish/jev-mcp
# at a34db93): name -> (default URL, key variables in order, Keychain item, model slug, request body,
# the opt-in variables that choose it unnamed, the only host its key goes to).
PROVIDERS = {
    "typesafe": ("https://api.typesafe.ai/v1/systemone", ["TYPESAFE_API_KEY"], None, lambda m: m, None, ["TYPESAFE_API_KEY"], None),
    "openrouter": ("https://openrouter.ai/api/alpha/decisions", ["JEV_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"], "openrouter-api-key",
                   lambda m: m if m.startswith("typesafe/") else "typesafe/" + re.sub(r"^(jev-\d+\.\d+)\.\d+$", r"\1", m), None,
                   ["JEV_OPENROUTER_API_KEY"], "openrouter.ai"),
    "cloudflare": ("https://api.cloudflare.com/client/v4/accounts/{account}/ai/run", ["JEV_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN"],
                   "cloudflare-api-token", lambda m: m if m.startswith("typesafe/") else "typesafe/jev",
                   lambda state, questions, model: {"model": model, "input": {"state": state, "questions": questions}},
                   ["JEV_CLOUDFLARE_API_TOKEN"], "api.cloudflare.com"),
    "vercel": ("https://ai-gateway.vercel.sh/typesafe/v1/systemone", ["JEV_AI_GATEWAY_API_KEY", "AI_GATEWAY_API_KEY"], "ai-gateway-api-key",
               lambda m: m if m.startswith("typesafe-ai/") else "typesafe-ai/jev", None, ["JEV_AI_GATEWAY_API_KEY"], "ai-gateway.vercel.sh"),
    "compatible": ("{url}", ["JEV_API_KEY"], "jev-api-key", lambda m: m, None, ["JEV_API_KEY"], None),
}
DEFAULT_HOSTS = {"api.typesafe.ai", "openrouter.ai", "api.cloudflare.com", "ai-gateway.vercel.sh"}
LOOPBACK = ("127.0.0.1", "::1", "localhost")


def host_of(url):
    """host[:port] as providers.mjs hostOf: lowercased, no trailing dot, no userinfo, no default port; None when not a URL."""
    try:
        u = urllib.parse.urlsplit(url)
        host, port = (u.hostname or "").rstrip("."), u.port
    except ValueError:
        return None
    if not host or u.scheme not in ("http", "https"):
        return None
    host = f"[{host}]" if ":" in host else host
    return host if port is None or port == {"http": 80, "https": 443}[u.scheme] else f"{host}:{port}"
PROVIDER_SETTINGS = {"account": (ENV.get("CLOUDFLARE_ACCOUNT_ID") or "").strip() or USER_CONFIG.get("cloudflare_account_id") or "",
                     "url": (ENV.get("JEV_API_BASE_URL") or "").strip() or USER_CONFIG.get("provider_url") or ""}


def provider_error(name, s=PROVIDER_SETTINGS):
    if name not in PROVIDERS:
        return "provider must be auto or one of " + ", ".join(PROVIDERS)
    if name == "cloudflare" and not re.fullmatch(r"[0-9a-fA-F]{32}", s["account"]):
        return "provider cloudflare needs CLOUDFLARE_ACCOUNT_ID (or cloudflare_account_id in config.json)"
    if name == "compatible" and not urllib.parse.urlsplit(s["url"]).hostname:
        return "provider compatible needs JEV_API_BASE_URL (or provider_url in config.json)"
    return None


def resolve_provider(env=ENV, saved=USER_CONFIG):
    """As providers.mjs resolveProvider: a named provider; else typesafe with a TypeSafe Keychain item in
    config.json; else jev-mcp's order over the opt-in variables only; else typesafe."""
    chosen = str(env.get("REFLEX_PROVIDER") or env.get("JEV_PROVIDER") or saved.get("provider") or "auto").lower()
    if chosen != "auto":
        return chosen
    if saved.get("keychain"):
        return "typesafe"
    key = lambda p: next(((env.get(n) or "").strip() for n in PROVIDERS[p][5] if (env.get(n) or "").strip()), "")
    has = lambda p: bool(key(p)) and (p != "openrouter" or key(p).startswith("sk-or-"))
    return next((p for p in PROVIDERS if has(p) and not provider_error(p)), "typesafe")


PROVIDER = resolve_provider()
CONFIG = {
    **CONFIG,
    "api": ENV.get("REFLEX_API_URL", f"http://127.0.0.1:{LAYA['port']}/v1/systemone" if CONFIG["engine"] == "laya"
                   else PROVIDERS.get(PROVIDER, PROVIDERS["typesafe"])[0].format(**PROVIDER_SETTINGS)),
    "provider": PROVIDER,
    "model": ENV.get("REFLEX_MODEL", LAYA["model"] if CONFIG["engine"] == "laya" else "jev-1.13.0"),
    "mode": ENV.get("REFLEX_ROUTING_MODE", "shadow"),
    "policy": ENV.get("REFLEX_ROUTING_POLICY", str(HERE / "policy.json")),
    "questions": ENV.get("REFLEX_ROUTING_QUESTIONS", str(HERE / "questions.json")),
    "redact": ENV.get("REFLEX_REDACT", str(HERE.parent / "setup" / "redact.json")),
    "data": ENV.get("REFLEX_DATA_DIR", str(Path(ENV.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "reflex")),
    "keychain": ENV.get("REFLEX_KEYCHAIN_SERVICE", USER_CONFIG.get("keychain", "typesafe-api-key")),
}
CONFIG["key_host"] = host_of(CONFIG["api"])
# The request types that carry a conversation. Embeddings, images, files etc. are never routed.
ROUTED = {"completion", "acompletion", "text_completion", "atext_completion",
          "anthropic_messages", "aanthropic_messages", "responses", "aresponses"}
# python.org builds on macOS ship without a CA bundle; certifi (a LiteLLM dependency) fills the gap.
try:
    import certifi
    TLS = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    TLS = None
ROTATE_BYTES = 50 * 1024 * 1024
MAX_CHARS = 1_000_000          # text scanned per request; beyond this the tail is what matters


def load(path):
    return json.loads(Path(path).read_text())


def sha(v):
    return hashlib.sha256((v if isinstance(v, str) else json.dumps(v, sort_keys=True)).encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------------------------
# Redaction: the patterns in setup/redact.json, shared with gate.mjs; both selfchecks run its corpus.
# re.ASCII makes \w, \b and case folding match JavaScript's. Loaded on first use, so a missing file
# fails routing (the request keeps its model), never the proxy's start.
@functools.cache
def redaction():
    spec = load(CONFIG["redact"])
    return ([re.compile(p, re.ASCII) for p in spec["shapes"]],
            [(re.compile(c["pattern"], re.ASCII | (re.I if "i" in c["flags"] else 0)), re.sub(r"\$(\d+)", r"\\g<\1>", c["replace"]))
             for c in spec["context"]], spec["corpus"])


def redact(s):
    shapes, context, _ = redaction()
    out = str(s or "")
    for rx in shapes:
        out = rx.sub("<redacted>", out)
    for rx, repl in context:
        out = rx.sub(repl, out)
    return out


def has_secret(s):
    # Shapes only: the keyword patterns also match prose like "max_tokens: 100".
    return any(rx.search(s) for rx in redaction()[0])


# ---------------------------------------------------------------------------------------------
# What a request is about. One reader for the three shapes a coding agent sends: chat completions
# (messages), Anthropic messages (system + messages with blocks) and Responses (instructions + input).
SKIP_KEYS = {"type", "role", "id", "tool_use_id", "call_id", "data", "image_url", "source", "signature",
             "cache_control", "file_data", "image"}
REMINDER = re.compile(r"<system-reminder>[\s\S]*?</system-reminder>")
PATH_RE = re.compile(r"(?<![\w:/.])[~.\w-]*(?:/[\w.@-]+)+/?|(?<![\w/.])\.env(?:\.[\w-]+)?\b|\b[\w-]+\.(?:pem|key|tfvars|tfstate|p12)\b")
# The agent's working directory, as Claude Code ("Primary working directory: /x") and Codex
# ("<cwd>/x</cwd>") state it. Paths under it are the repo; everything else is outside.
CWD_RE = re.compile(r"(?:working directory:\s*|<cwd>\s*)(/[^\s<]+)", re.I)


def text_of(x):
    """Every string a model would read, minus binary payloads and bookkeeping keys."""
    if isinstance(x, str):
        return x
    if isinstance(x, list):
        return "\n".join(filter(None, (text_of(v) for v in x)))
    if isinstance(x, dict):
        return "\n".join(filter(None, (text_of(v) for k, v in x.items() if k not in SKIP_KEYS)))
    return ""


def user_text(content):
    """What a person typed: text parts only, so a tool result sent as a user turn does not count."""
    if isinstance(content, str):
        return REMINDER.sub("", content).strip()
    if isinstance(content, list):
        return REMINDER.sub("", "\n".join(p.get("text", "") for p in content
                                          if isinstance(p, dict) and p.get("type") in ("text", "input_text"))).strip()
    return ""


def features(data):
    items = data.get("messages") or data.get("input") or []
    if isinstance(items, str):
        items = [{"role": "user", "content": items}]
    items = [m for m in items if isinstance(m, dict)]
    system = text_of(data.get("system")) or text_of(data.get("instructions")) or \
        "\n".join(text_of(m.get("content")) for m in items if m.get("role") in ("system", "developer"))
    users = [m for m in items if m.get("role") == "user"]
    last = next((t for m in reversed(users) if (t := user_text(m.get("content")))), "")
    tools = [t.get("name") or (t.get("function") or {}).get("name") or t.get("type")
             for t in data.get("tools") or [] if isinstance(t, dict)]
    convo = text_of(items)
    whole = (system + "\n" + convo)[-MAX_CHARS:]
    paths = sorted({p for p in PATH_RE.findall(whole) if len(p) > 3})
    first = user_text(users[0].get("content")) if users else last
    cwd = CWD_RE.search(whole)
    return {
        "last": last, "system": system, "tools": [t for t in tools if t], "paths": paths,
        "cwd": cwd.group(1).rstrip("/") if cwd else None,
        "turn": len(users), "secret": has_secret(whole),
        # An estimate, labelled _est wherever it appears. ponytail: chars / 4; a tokenizer per model
        # family if the switch maths ever needs better than that.
        "ctx_tokens_est": (len(system) + len(convo) + len(json.dumps(data.get("tools") or []))) // 4,
        # LiteLLM sets litellm_session_id from x-*-session-id headers and Anthropic metadata.user_id;
        # otherwise the first user message and system prompt identify the conversation.
        "conv": str(data.get("litellm_session_id") or sha([system[:2000], first[:2000]])),
        "pinned": bool(data.get("previous_response_id")),   # server-side context lives with the old model
        # Provider state tied to the model that produced it: signed thinking (Anthropic) or encrypted
        # reasoning (Responses). Another model ignores or drops what it cannot read.
        "thinking": any(isinstance(b, dict) and (b.get("type") in ("thinking", "redacted_thinking") and
                                                 (b.get("signature") or b.get("data")) or
                                                 b.get("type") == "reasoning" and b.get("encrypted_content"))
                        for m in items for b in [m, *(m.get("content") if isinstance(m.get("content"), list) else [])]),
        # A 1M-token context window: Claude Code's [1m] model suffix or the context-1m beta header.
        "ctx_1m": str(data.get("model", "")).endswith("[1m]") or "context-1m" in beta_header(data),
    }


def beta_header(data):
    """anthropic-beta as the client sent it (LiteLLM keeps request headers in proxy_server_request)."""
    h = (data.get("proxy_server_request") or {}).get("headers") or {}
    return ",".join(str(v) for k, v in h.items() if str(k).lower() == "anthropic-beta")


def path_view(p, f, policy):
    """What Jev sees of a path. policy paths_to_jev: full | shape | shape_outside_repo (default).
    A shape is the file name plus flags, so the directory layout outside the repo stays local."""
    mode = policy.get("paths_to_jev", "shape_outside_repo")
    if mode == "full":
        return p
    cwd = f.get("cwd")
    rel = "." if p.rstrip("/") == cwd else p[len(cwd) + 1:] if cwd and p.startswith(cwd + "/") else p
    inside = not rel.startswith(("/", "~")) and ".." not in rel.split("/")
    if inside and mode == "shape_outside_repo":
        return rel
    flags = ([] if inside else ["outside repo"]) + \
        (["sensitive"] if any(re.search(rx, p, re.I) for rx in policy["sensitivity"]["restricted_paths"]) else [])
    return ".../" + p.rstrip("/").rsplit("/", 1)[-1] + (f" [{', '.join(flags)}]" if flags else "")


def jev_state(f, spec, policy):
    paths = list(dict.fromkeys(redact(path_view(p, f, policy)) for p in f["paths"][:200]))
    return {spec["item_key"]: {"message": redact(f["last"])[-2000:], "system_summary": redact(f["system"][:400]),
                               "system_chars": len(f["system"]), "tools": f["tools"][:60],
                               "paths": paths[:40], "turn": f["turn"]},
            spec["context_key"]: spec["context"]}


# ---------------------------------------------------------------------------------------------
# Jev. Same key lookup as gate.mjs: the provider's variables, else its macOS Keychain item.
def api_key():
    names, item = PROVIDERS[CONFIG["provider"]][1], PROVIDERS[CONFIG["provider"]][2] or CONFIG["keychain"]
    for n in names:
        if (ENV.get(n) or "").strip():
            return ENV[n].strip()
    if sys.platform == "darwin":
        r = subprocess.run(["security", "find-generic-password", "-s", item, "-w"],
                           capture_output=True, text=True, timeout=1.5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    raise RuntimeError(f'no API key for {CONFIG["provider"]}: set {" or ".join(names)} or keychain item "{item}"')


def key_route_error(provider, url, key_host, laya_port=LAYA["port"]):
    """As providers.mjs keyRouteError: OpenRouter's, Cloudflare's and Vercel's keys to their own host over
    https only; TypeSafe's and compatible's to the configured host, never another provider's, never over
    http off this machine, never the Laya port."""
    if provider not in PROVIDERS:
        return f"unknown provider {provider}"
    host, pinned = host_of(url), PROVIDERS[provider][6]
    if not host:
        return f"the {provider} key goes only to its own host, not to an invalid URL"
    u = urllib.parse.urlsplit(url)
    if pinned:
        return None if host == pinned and u.scheme == "https" else f"the {provider} key goes only to https://{pinned}, not to {host}"
    if host != key_host:
        return f"the {provider} key goes only to {key_host}, not to {host}"
    if host in DEFAULT_HOSTS and not (provider == "typesafe" and host == "api.typesafe.ai"):
        return f"the {provider} key never goes to another provider ({host})"
    loopback = (u.hostname or "").rstrip(".") in LOOPBACK
    if u.scheme != "https" and not loopback:
        return f"the {provider} key is sent over https only"
    if loopback and (u.port or {"http": 80, "https": 443}[u.scheme]) == int(laya_port):
        return f"the {provider} key never goes to the Laya server"
    return None


class Malformed(Exception):
    pass


def normalize(provider, p, questions):
    """Every provider's reply -> (answers, usage) in one typed shape; anything else raises Malformed (the caller falls back)."""
    unit = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1
    finite = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
    if provider == "cloudflare":
        if not isinstance(p, dict) or p.get("success") is False:
            raise Malformed("cloudflare: success false")
        p = p["result"] if isinstance(p.get("result"), dict) else p
        if isinstance(p.get("state"), str) and p["state"] != "Completed":
            raise Malformed("cloudflare: run did not complete")
        if not isinstance(p.get("answers"), dict) and isinstance(p.get("result"), dict):
            p = p["result"]
    if not isinstance(p, dict) or not isinstance(p.get("answers"), dict):
        raise Malformed(f"{provider}: no answers object")
    answers = {}
    for qid, q in questions.items():
        if qid not in p["answers"]:
            continue
        a = p["answers"][qid]
        if not isinstance(a, dict) or a.get("type", q["type"]) != q["type"]:
            raise Malformed(f"{provider}: answer {qid} malformed")
        extra = {k: a[k] for k in ("probabilities", "confidence") if a.get(k) is not None}
        if "confidence" in extra and not unit(extra["confidence"]) or \
                "probabilities" in extra and not (isinstance(extra["probabilities"], dict) and all(map(unit, extra["probabilities"].values()))):
            raise Malformed(f"{provider}: answer {qid} has invalid confidence or probabilities")
        crit = q.get("criteria")
        # Probability keys name options: a choice's criteria, a score's level indices; tier_of and ranking read them.
        option = (lambda k: not isinstance(crit, dict) or k in crit) if q["type"] == "choice" else \
            (lambda k: re.fullmatch(r"0|[1-9]\d*", k) is not None and (not isinstance(crit, list) or int(k) < len(crit))) if q["type"] == "score" else \
            (lambda k: True)
        if "probabilities" in extra and not all(option(k) for k in extra["probabilities"]):
            raise Malformed(f"{provider}: answer {qid} has probabilities for options it was not asked about")
        if q["type"] == "noul" and unit(a.get("noul")):
            answers[qid] = {"type": "noul", "noul": a["noul"]}
        elif q["type"] == "choice" and isinstance(a.get("choice"), str) and (not isinstance(crit, dict) or a["choice"] in crit):
            answers[qid] = {"type": "choice", "choice": a["choice"], **extra}
        elif q["type"] == "score" and finite(a.get("score")) and \
                0 <= a["score"] <= (len(crit) - 1 if isinstance(crit, list) else float("inf")):
            answers[qid] = {"type": "score", "score": a["score"], **extra}
        else:
            raise Malformed(f"{provider}: answer {qid} is not a valid {q['type']}")
    u = p.get("usage") if isinstance(p.get("usage"), dict) else {}
    count = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else 0
    return answers, {"input_tokens": count(u.get("input_tokens")), "output_tokens": count(u.get("output_tokens"))}


RETRY = {"attempts": 3, "base_s": 0.15, "max_s": 1.0}
MAX_REPLY = 1_000_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is an HTTPError: following it would carry the key (urllib keeps Authorization) to another host."""
    def redirect_request(self, *args, **kwargs):
        return None


# No proxy from HTTP(S)_PROXY either: a proxy would receive the key over loopback http.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=TLS), NoRedirect)


def read_until(r, deadline):
    """The reply body, read in chunks against the call's one deadline (urllib's timeout is per socket read)."""
    chunks, size = [], 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("the Jev reply did not finish before the deadline")
        chunk = r.read1(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_REPLY:
            raise Malformed("the reply is too large")
        chunks.append(chunk)


def retryable(status):
    return status in (408, 409, 429) or 500 <= status <= 599


def laya_auth():
    """The local token the Laya server requires (laya.mjs writes it beside config.json); never the TypeSafe key."""
    try:
        token = (CONFIG_DIR / "laya.token").read_text().strip()
    except OSError:
        return {}
    return {"Authorization": f"Bearer {token}"} if token else {}


def ask(state, questions, timeout_s):
    """One Jev call -> (answers, usage). Raises on any failure; the caller falls back."""
    if CONFIG["engine"] not in ("jev", "laya"):
        raise RuntimeError("hosted classification is disabled")
    if CONFIG["engine"] == "laya" and urllib.parse.urlsplit(CONFIG["api"]).hostname not in ("127.0.0.1", "::1", "localhost"):
        raise RuntimeError("engine laya: the server URL must be on 127.0.0.1")
    deadline = time.monotonic() + timeout_s
    provider = "typesafe" if CONFIG["engine"] == "laya" else CONFIG["provider"]
    refused = provider_error(provider)
    if refused:
        raise RuntimeError(refused)
    slug, shape = PROVIDERS[provider][3], PROVIDERS[provider][4]
    if CONFIG["engine"] == "laya":
        auth = laya_auth()
    else:
        refused = key_route_error(provider, CONFIG["api"], CONFIG["key_host"])
        if refused:
            raise RuntimeError(refused)
        auth = {"Authorization": f"Bearer {api_key()}"}
    body = json.dumps((shape or (lambda s, q, m: {"state": s, "model": m, "questions": q}))(state, questions, slug(CONFIG["model"]))).encode()
    # One deadline for every attempt and every read; only 408, 409, 429 and 5xx retry, with jittered
    # backoff that ends before it. No redirects and no proxy: the key goes to the checked host or nowhere.
    for attempt in range(RETRY["attempts"]):
        req = urllib.request.Request(CONFIG["api"], body, {**auth, "Content-Type": "application/json"})
        try:
            with OPENER.open(req, timeout=max(0.05, deadline - time.monotonic())) as r:
                text = read_until(r, deadline)
        except urllib.error.HTTPError as e:
            e.close()
            wait = min(RETRY["base_s"] * 2 ** attempt, RETRY["max_s"]) * (0.5 + random.random() * 0.5)
            if retryable(e.code) and attempt + 1 < RETRY["attempts"] and time.monotonic() + wait < deadline - 0.05:
                time.sleep(wait)
                continue
            # The status only: an error body may quote the request or the key, and this text reaches the log.
            raise RuntimeError(f"HTTP {e.code} ({provider})") from None
        try:
            payload = json.loads(text)
        except ValueError:
            raise Malformed(f"{provider}: the reply is not JSON") from None
        return normalize(provider, payload, questions)


# ---------------------------------------------------------------------------------------------
# Policy: pure functions over answers, request features and policy.json.
def family_of(model, policy):
    """The family whose models (or aliases, such as a gateway's own auto router) include `model`.
    A model the policy does not list is never routed, so a newer model is not quietly swapped for a
    listed one."""
    return next((name for name, fam in policy["families"].items()
                 if resolve(model, fam) or model in fam.get("aliases", [])), None)


def resolve(model, fam):
    """claude-haiku-4-5-20251001 and claude-opus-5[1m] are the policy's claude-haiku-4-5 and claude-opus-5."""
    hits = [m for m in fam["models"] if model == m or model.startswith(m)]
    return max(hits, key=len) if hits else None


def classify(answers, f, policy):
    """answers + deterministic floors -> (sensitivity, tier, needs_tools, why)."""
    s, t = policy["sensitivity"], policy["tiers"]
    order = s["order"]
    sa = answers["sensitivity"]
    sens, why = sa["choice"], []
    p = sa.get("probabilities") or {}
    if order.index(sens) < order.index("restricted") and \
            p.get("restricted", 0) + p.get("proprietary", 0) >= s["restricted_at"]:
        sens, why = "restricted", why + ["restricted probability"]
    floor = "restricted" if f["secret"] else next(
        ("restricted" for path in f["paths"] for rx in s["restricted_paths"] if re.search(rx, path, re.I)), None)
    if floor and order.index(sens) < order.index(floor):
        sens, why = floor, why + ["secret in conversation" if f["secret"] else "sensitive path"]
    tier = tier_of(answers["difficulty"], t)
    tools = bool(f["tools"]) and answers["needs_tools"]["noul"] >= policy["needs_tools_at"]
    return sens, tier, tools, why


def tier_of(d, t):
    """The highest tier whose probability mass P(level >= tier) reaches tiers.up_at[tier]: under-tiering
    costs more than over-tiering, so a hesitant answer routes up. Without probabilities (the fallback
    answer) or up_at, the expected score against from_score."""
    order, p, up = t["order"], d.get("probabilities"), t.get("up_at")
    # Keys that are not level indices (normalize refuses them; this is the second line): the top tier,
    # the side the policy prefers when unsure, never an error that keeps the requested model.
    if p and not all(isinstance(k, str) and re.fullmatch(r"0|[1-9]\d*", k) or isinstance(k, int) and not isinstance(k, bool) and k >= 0 for k in p):
        return order[-1]
    if p and up:
        mass = lambda i: sum(v for k, v in p.items() if int(k) >= i)
        return max((name for i, name in enumerate(order) if i == 0 or mass(i) >= up[name]), key=order.index)
    return max((name for name, at in t["from_score"].items() if d["score"] >= at), key=order.index, default=order[0])


def eligible(fam, sens, tools, policy, ctx_est=0):
    """Models whose tags the sensitivity requires, with tools when needed, and a context window
    (max_context, optional) that fits the estimated context."""
    need = policy["sensitivity"]["pools"][sens]["require"]
    return [m for m, i in fam["models"].items() if all(i.get(k) for k in need) and (not tools or i.get("tools", True))
            and ctx_est <= i.get("max_context", float("inf"))]


def pick(fam, pool, tier, policy):
    """Cheapest model at or above the tier; if none reaches it, the strongest eligible one."""
    rank = policy["tiers"]["order"].index
    ok = [m for m in pool if rank(fam["models"][m]["tier"]) >= rank(tier)]
    if ok:
        return min(ok, key=lambda m: (rank(fam["models"][m]["tier"]), fam["models"][m]["price_in"]))
    return max(pool, key=lambda m: (rank(fam["models"][m]["tier"]), -fam["models"][m]["price_in"])) if pool else None


def stay_or_switch(prev, new, pool, f, fam, policy):
    """Paper §II.A: a route change makes the new model reprocess the whole context. Returns (model, why)."""
    if not prev or prev == new:
        return new, None
    p = resolve(prev, fam)
    if p is None or p not in pool:
        return new, "previous model not eligible for this content"
    # Only a forced move leaves a conversation carrying model-bound state: another model cannot read
    # the signed thinking (the reasoning is lost), and a 1M context may not fit or cache elsewhere.
    if f.get("thinking"):
        return prev, "sticky: signed thinking in the conversation"
    if f.get("ctx_1m"):
        return prev, "sticky: 1M-context conversation"
    rank = policy["tiers"]["order"].index
    if rank(fam["models"][new]["tier"]) > rank(fam["models"][p]["tier"]):
        return new, "harder turn: moving up a tier"
    if f["pinned"]:
        return prev, "sticky: server-side context (previous_response_id)"
    st, ctx = policy["stickiness"], f["ctx_tokens_est"]
    old_in, new_in = fam["models"][p]["price_in"] / 1e6, fam["models"][new]["price_in"] / 1e6
    saving = (ctx * st["cache_read_factor"] + st["turn_tokens"]) * (old_in - new_in) * st["remaining_turns"]
    rebuild = ctx * new_in
    if saving > rebuild:
        return new, f"switch: saves ${saving:.4f} over {st['remaining_turns']} turns, rebuild ${rebuild:.4f}"
    return prev, f"sticky: rebuild ${rebuild:.4f} >= saving ${saving:.4f} ({ctx} context tokens, est.)"


# ---------------------------------------------------------------------------------------------
STICKY_TTL_S = 24 * 3600


def key_lists(model, key):
    """The key's own model list: the check outside a proxy."""
    allowed = list(getattr(key, "models", None) or [])
    return not allowed or model in allowed or "all-proxy-models" in allowed


async def may_call(model, key):
    """Whether the caller's key may use `model`. LiteLLM authorises the requested model before the
    pre-call hooks and never re-checks after them, so a rewrite gets LiteLLM's own check here: the
    one it runs for a key's model-group alias (key and team models, wildcards, access groups, team
    members, projects)."""
    if key is None:
        return True
    try:
        from litellm.proxy.auth.auth_checks import can_key_call_resolved_model
        from litellm.proxy.proxy_server import llm_router
    except ImportError:     # outside a proxy (CLI, selfcheck)
        return key_lists(model, key)
    try:
        await can_key_call_resolved_model(model=model, llm_model_list=llm_router.model_list if llm_router else None,
                                          valid_token=key, llm_router=llm_router)
        return True
    except Exception:
        return False


def controls(model, key):
    """What LiteLLM enforces per model group before this hook runs, so only for the requested model:
    model-level guardrails (litellm_params.guardrails, merged as the union over the group's
    deployments before the pre-call hooks, the way _check_and_merge_model_level_guardrails does) and
    the key's per-model rpm / tpm limits and budget (checked at auth and by pre-call limiters).
    None outside a proxy: nothing to compare."""
    try:
        from litellm.proxy.proxy_server import llm_router
        from litellm.proxy.auth.auth_utils import get_key_model_rpm_limit, get_key_model_tpm_limit
    except ImportError:
        return None
    if llm_router is None:
        return None
    guards = set()
    for dep in llm_router.get_model_list(model_name=model, team_id=getattr(key, "team_id", None)) or []:
        g = (dep.get("litellm_params") or {}).get("guardrails")
        guards.update(x if isinstance(x, str) else repr(x) for x in ([g] if isinstance(g, str) else g or []))
    limits = None
    if key is not None:
        limits = limits_of(key, model, (get_key_model_rpm_limit(key, model_name=model) or {}).get(model),
                           (get_key_model_tpm_limit(key, model_name=model) or {}).get(model))
    return {"guardrails": sorted(guards), "limits": limits}


# Where LiteLLM 1.100.1 keeps the per-model budgets it enforces for a request, on UserAPIKeyAuth:
# model_max_budget (the key's own, else its budget table's), user_model_max_budget (the internal
# user's, LiteLLM_UserTable) and end_user_model_max_budget (the end user's budget table). The
# team's model_max_budget (LiteLLM_TeamTable) is stored but not enforced per request in 1.100.1
# (the limiter's scopes are key, user and end user), so it is not compared; neither is a team
# member's budget table, which only carries max_budget / tpm / rpm for the whole team.
BUDGET_SCOPES = ("model_max_budget", "user_model_max_budget", "end_user_model_max_budget")


def budget_entry(mmb, model):
    """The model_max_budget entry LiteLLM applies to `model`: its own resolution (provider prefix
    stripped, Bedrock base model) when available, else the exact name."""
    if not isinstance(mmb, Mapping) or not mmb:
        return None
    try:
        from litellm.proxy.hooks.model_max_budget_limiter import resolve_model_budget
    except ImportError:
        return mmb.get(model)
    r = resolve_model_budget(model, mmb)
    return r.budget_config.model_dump() if r else None


def limits_of(key, model, rpm=None, tpm=None):
    """The key's per-model rpm / tpm and every scope's budget entry for `model`, comparable."""
    return tuple(json.dumps(v, sort_keys=True, default=str) for v in
                 (rpm, tpm, *(budget_entry(getattr(key, s, None), model) for s in BUDGET_SCOPES)))


class ReflexRouter(CustomLogger):
    def __init__(self, ask_fn=ask, mode=None, may_call_fn=may_call, controls_fn=controls):
        if CustomLogger is not object:
            super().__init__()
        self.ask, self.mode, self.may_call, self.controls = ask_fn, mode, may_call_fn, controls_fn
        # ponytail: per-process dicts. The Jev cache stays per process (a miss costs one Jev call). The
        # model each conversation is on also goes to LiteLLM's Redis when the proxy shares one (see
        # prev_model), so stickiness survives a request landing on another worker.
        self.cache, self.convs, self.tasks = {}, {}, set()

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        mode = self.mode or CONFIG["mode"]
        if CONFIG["engine"] not in ("jev", "laya") or mode == "off" or call_type not in ROUTED or not isinstance(data.get("model"), str):
            return data
        try:
            f, requested = features(data), data["model"]
        except Exception as e:     # a routing bug never breaks a request
            print(f"reflex routing: {type(e).__name__}: {e}", file=sys.stderr)
            return data
        redis = getattr(cache, "redis_cache", None)
        if mode != "enforce":
            # Shadow: nobody waits. The decision runs after the request is on its way.
            task = asyncio.get_running_loop().create_task(self.decide(f, requested, user_api_key_dict, redis))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return data
        d = await self.decide(f, requested, user_api_key_dict, redis, apply=True)
        if d.get("block"):
            return d["block"]       # a string: LiteLLM rejects the request with it (HTTP 400)
        data["model"] = d["applied"]
        return data

    async def decide(self, f, requested, key=None, redis=None, apply=False):
        t0 = time.monotonic()
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": "enforce" if apply else "shadow",
               "conv": sha(f["conv"]), "turn": f["turn"], "ctx_tokens_est": f["ctx_tokens_est"], "requested": requested,
               "chosen": requested, "applied": requested, "source": None, "reason": None, "error": None}
        try:
            policy, spec = load(CONFIG["policy"]), load(CONFIG["questions"])
            rec["policy_version"], rec["qset"] = policy["version"], spec["version"]
            fam_name = family_of(requested, policy)
            if fam_name is None:
                rec.update(source="skip", reason="model not in any routing family")
                return rec
            fam = policy["families"][fam_name]
            answers, rec["source"] = await self.answers(f, spec, policy, rec)
            sens, tier, tools, why = classify(answers, f, policy)
            req = resolve(requested, fam)
            # Eligible for the content, callable with this key and under the same guardrails and per-model
            # limits as the requested model: LiteLLM applied those for the requested model before this
            # hook and does not apply them again for the one chosen here.
            base, excluded = self.controls(requested, key), {}

            async def allowed(m):
                if not await self.may_call(m, key):
                    return False
                other = self.controls(m, key) if base else None
                diff = [k for k in ("guardrails", "limits") if other and policy.get(f"require_same_{k}", True)
                        and other[k] != base[k]]
                if diff:
                    excluded[m] = diff
                return not diff
            pool = [m for m in eligible(fam, sens, tools, policy, f["ctx_tokens_est"]) if m == req or await allowed(m)]
            rec["excluded"] = excluded or None
            chosen = pick(fam, pool, tier, policy)
            rec.update(family=fam_name, sensitivity=sens, tier=tier, needs_tools=tools, floors=why or None,
                       answers={k: a.get("choice", a.get("score", a.get("noul"))) for k, a in answers.items()},
                       difficulty_p=answers["difficulty"].get("probabilities"),
                       violation=(req is not None and req not in pool) or None)
            if chosen is None:
                ne = policy.get("no_eligible", {})
                fb, action = ne.get("model"), ne.get("action", "block")
                if action == "keep":
                    rec.update(action="keep", reason=f"no model in {fam_name} is eligible for {sens}; kept")
                    return rec
                if action == "fallback_model" and fb and await allowed(fb):
                    chosen, reason = fb, f"no model in {fam_name} is eligible for {sens}: fallback_model"
                else:
                    same = " under the requested model's guardrails and limits" if excluded else ""
                    rec.update(action="block", reason=f"no model in {fam_name} this key may use{same} is eligible for {sens}")
                    if apply:
                        rec.update(applied=None, block=f"Reflex routing blocked this request: no model this key may use in "
                                   f"'{fam_name}'{same} is cleared for {sens} content (policy {policy['version']}).")
                    return rec
            else:
                # Without a record (another worker, a restart), a conversation carrying model-bound state
                # was on the model it asks for.
                prev = await self.prev_model(f["conv"], redis) or \
                    (requested if f["turn"] > 1 and (f["thinking"] or f["ctx_1m"]) else None)
                chosen, sticky = stay_or_switch(prev, chosen, pool, f, fam, policy)
                if f["thinking"] and resolve(chosen, fam) != resolve(prev or requested, fam):
                    # docs.claude.com "Switching models mid-conversation": pass thinking blocks back unchanged;
                    # the API ignores or drops those the new model cannot read. So nothing is stripped.
                    rec["thinking_dropped_est"] = True
                reason = sticky or f"{sens}/{tier}: cheapest eligible"
            if req is not None and resolve(chosen, fam) == req:
                chosen = requested      # same model: keep the requested name (claude-opus-5[1m], a dated id)
            rec.update(chosen=chosen, reason=reason)
            if apply:
                rec["applied"] = chosen
            return rec
        except Exception as e:
            rec.update(source="error", error=f"{type(e).__name__}: {e}"[:200], reason="internal error; kept")
            return rec
        finally:
            rec["latency_s"] = round(time.monotonic() - t0, 3)
            await self.remember(f["conv"], rec["applied"], redis)
            log(rec)

    async def prev_model(self, conv, redis):
        if redis is not None:
            try:
                if v := await redis.async_get_cache(f"reflex:model:{sha(conv)}"):
                    return v
            except Exception:
                pass
        return self.convs.get(conv)

    async def remember(self, conv, model, redis):
        self.convs[conv] = model
        while len(self.convs) > 5000:
            self.convs.pop(next(iter(self.convs)))
        if redis is not None and model:
            try:
                await redis.async_set_cache(f"reflex:model:{sha(conv)}", model, ttl=STICKY_TTL_S)
            except Exception:
                pass

    async def answers(self, f, spec, policy, rec):
        state = jev_state(f, spec, policy)
        key = sha([state, spec["version"], CONFIG["model"]])
        rec["state_sha"] = key
        hit = self.cache.get(key)
        if hit and time.time() - hit[0] < policy["cache_ttl_s"]:
            return hit[1], "cache"
        try:
            answers, rec["usage"] = await asyncio.wait_for(
                asyncio.to_thread(self.ask, state, spec["questions"], policy["latency_budget_ms"] / 1000),
                policy["latency_budget_ms"] / 1000)
            missing = [q for q in spec["questions"] if not isinstance(answers.get(q), dict) or
                       answers[q].get("choice", answers[q].get("score", answers[q].get("noul"))) is None]
            if missing:
                raise RuntimeError(f"incomplete answer: missing {', '.join(missing)}")
        except Exception as e:
            fb = policy["fallback"]
            rec["error"] = f"{type(e).__name__}: {e}"[:200]
            return {"sensitivity": {"choice": fb["sensitivity"]}, "difficulty": {"score": fb["difficulty"]},
                    "needs_tools": {"noul": 1.0}}, "fallback"
        self.cache[key] = (time.time(), answers)
        while len(self.cache) > 2000:
            self.cache.pop(next(iter(self.cache)))
        return answers, "jev"


def log(rec):
    """routing.jsonl: hashes, labels and numbers only, never message text or paths."""
    try:
        d = Path(CONFIG["data"])
        d.mkdir(parents=True, exist_ok=True)
        p = d / "routing.jsonl"
        if p.exists() and p.stat().st_size > ROTATE_BYTES:
            p.rename(d / f"routing.{int(time.time() * 1000)}.jsonl")
        with p.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError as e:
        print(f"reflex routing: cannot log ({e})", file=sys.stderr)


proxy_handler_instance = ReflexRouter()


# ---------------------------------------------------------------------------------------------
def providers_selfcheck(ok):
    """Mock servers per provider: request format, Bearer key to its host only, retries, deadline, malformed answers fail."""
    import http.server
    import threading
    Q = {"sensitivity": {"type": "choice", "criteria": {"public": "a", "restricted": "b"}},
         "difficulty": {"type": "score", "criteria": ["s", "m", "l"]}, "needs_tools": {"type": "noul"}}
    good = {"sensitivity": {"type": "choice", "choice": "public", "probabilities": {"public": 0.9, "restricted": 0.1}, "confidence": 0.9},
            "difficulty": {"type": "score", "score": 1.2}, "needs_tools": {"type": "noul", "noul": 0.3}}
    seen, replies = [], []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):   # where a followed redirect would land
            seen.append((self.path, self.headers.get("Authorization"), None))
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            seen.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{srv.server_address[1]}/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/trickle":   # one byte every 100 ms: each socket read is quick, the reply is not
                data = json.dumps({"answers": good}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    for b in data:
                        self.wfile.write(bytes([b]))
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass
                return
            status, out = replies.pop(0) if replies else (200, {"answers": good})
            data = (out if isinstance(out, str) else json.dumps(out)).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base, saved = f"http://127.0.0.1:{srv.server_address[1]}", dict(CONFIG)
    names = {p: PROVIDERS[p][1][0] for p in PROVIDERS}
    route = key_route_error
    try:
        # The wire formats against loopback mocks: the pinned providers' route check is lifted for this loop only.
        globals()["key_route_error"] = lambda *a, **k: None
        for p, path, check in [("typesafe", "/v1/systemone", lambda b: b["model"] == "jev-1.13.0" and b["state"] and b["questions"]),
                               ("openrouter", "/api/alpha/decisions", lambda b: b["model"] == "typesafe/jev-1.13"),
                               ("cloudflare", "/client/v4/accounts/x/ai/run", lambda b: b["model"] == "typesafe/jev" and b["input"]["questions"]),
                               ("vercel", "/typesafe/v1/systemone", lambda b: b["model"] == "typesafe-ai/jev"),
                               ("compatible", "/v1/systemone", lambda b: b["model"] == "jev-1.13.0")]:
            CONFIG.update(engine="jev", provider=p, api=base + path, key_host=urllib.parse.urlsplit(base).netloc, model="jev-1.13.0")
            ENV[names[p]] = f"key-{p}"
            PROVIDER_SETTINGS.update(account="0" * 32, url=base + path)
            if p == "cloudflare":
                replies.append((200, {"success": True, "result": {"state": "Completed", "result": {"answers": good, "usage": {"input_tokens": 4}}}}))
            seen.clear()
            a, u = ask({"message": "hi"}, Q, 2)
            ok(len(seen) == 1 and seen[0][0] == path and seen[0][1] == f"Bearer key-{p}" and check(seen[0][2]), f"router {p}: request {seen[:1]}")
            ok(a["sensitivity"]["choice"] == "public" and a["difficulty"]["score"] == 1.2 and a["needs_tools"]["noul"] == 0.3, f"router {p}: answers")
            for bad in ["nope", {"answers": {**good, "needs_tools": {"noul": 3}}}, {"answers": {**good, "sensitivity": {"choice": "moon"}}},
                        {"answers": {**good, "difficulty": {"score": 9}}}, {"answers": []},
                        {"answers": {**good, "sensitivity": {"choice": "public", "probabilities": {"public": 0.5, "secret_tier": 0.9}}}},
                        {"answers": {**good, "difficulty": {"score": 1, "probabilities": {"0": 0.1, "x": 0.9}}}},
                        {"answers": {**good, "difficulty": {"score": 1, "probabilities": {"0": 0.1, "5": 0.9}}}}]:
                replies.append((200, {"success": True, "result": bad} if p == "cloudflare" and isinstance(bad, dict) else bad))
                try:
                    ask({"message": "hi"}, Q, 2)
                    ok(False, f"router {p}: malformed {bad!r:.60} must fail")
                except Malformed:
                    pass
            del ENV[names[p]]
        globals()["key_route_error"] = route
        # retries on 429 / 503, not on 401; not past the deadline
        CONFIG.update(provider="typesafe", api=base + "/v1/systemone")
        ENV["TYPESAFE_API_KEY"] = "sk-or-test"
        seen.clear()
        replies[:] = [(429, "{}"), (503, "{}")]
        ok(ask({}, Q, 2)[0]["needs_tools"]["noul"] == 0.3 and len(seen) == 3, f"router: retries 429 and 503 ({len(seen)})")
        seen.clear()
        replies[:] = [(401, "{}")]
        try:
            ask({}, Q, 2)
            ok(False, "router: 401")
        except RuntimeError as e:
            ok(len(seen) == 1 and "sk-or-test" not in str(e), f"router: no retry on 401 ({e})")
        seen.clear()
        replies[:] = [(429, "{}")] * 3
        try:
            ask({}, Q, 0.1)
        except Exception:  # the 429, or a timeout on a slow machine: never a retry either way
            pass
        ok(len(seen) <= 1, f"router: no retry past the deadline ({len(seen)})")
        replies.clear()
        # a redirect is an error, never followed: urllib would carry the Authorization header to its target
        seen.clear()
        CONFIG.update(api=base + "/redirect")
        try:
            ask({}, Q, 2)
            ok(False, "router: redirect followed")
        except RuntimeError as e:
            ok([s[0] for s in seen] == ["/redirect"] and "HTTP 302" in str(e), f"router: a redirect is refused ({e}, {seen})")
        # one deadline for the whole reply, however quick each socket read is
        CONFIG.update(api=base + "/trickle")
        t0 = time.monotonic()
        try:
            ask({}, Q, 0.5)
            ok(False, "router: trickled reply accepted")
        except (TimeoutError, OSError):
            pass
        ok(time.monotonic() - t0 < 1.5, f"router: the deadline covers the body ({time.monotonic() - t0:.2f} s)")
        # key routing: the proxies pinned to their own host; TypeSafe and compatible to the configured
        # one, never another provider's, never over http off the machine, never the Laya port
        CONFIG.update(provider="openrouter", api=base + "/api/alpha/decisions")
        ENV["OPENROUTER_API_KEY"] = "sk-or-test"
        seen.clear()
        try:
            ask({}, Q, 1)
            ok(False, "router: the OpenRouter key went to a loopback override")
        except RuntimeError as e:
            ok(not seen and "only to https://openrouter.ai" in str(e), f"router: openrouter pinned ({e})")
        del ENV["OPENROUTER_API_KEY"]
        for p in ("openrouter", "cloudflare", "vercel"):
            ok(key_route_error(p, "https://proxy.example/x", "proxy.example"), f"router: {p} pinned")
        ok(not key_route_error("openrouter", "https://OpenRouter.AI.:443/x", "x"), "router: host normalised")
        for u in ("https://API.TYPESAFE.AI/x", "https://api.typesafe.ai./x", "https://api.typesafe.ai:443/x", "https://user@openrouter.ai/x"):
            ok(key_route_error("compatible", u, host_of(u)), f"router: compatible never to another provider ({u})")
        ok(key_route_error("compatible", "http://jev.example/v1", "jev.example") and not key_route_error("compatible", "https://jev.example/v1", "jev.example"),
           "router: https only off the machine")
        ok(key_route_error("typesafe", "http://127.0.0.1:8421/v1", "127.0.0.1:8421", 8421) and not key_route_error("typesafe", "http://127.0.0.1:9/v1", "127.0.0.1:9", 8421),
           "router: never the Laya port")
        ok(key_route_error("wat", "https://x.example", "x.example"), "router: unknown provider")
        CONFIG.update(provider="wat")
        try:
            ask({}, Q, 1)
            ok(False, "router: unknown provider")
        except RuntimeError as e:
            ok("provider must be" in str(e), f"router: unknown provider is a clear error ({e})")
        ambient = {"CLOUDFLARE_API_TOKEN": "c", "CLOUDFLARE_ACCOUNT_ID": "0" * 32, "OPENROUTER_API_KEY": "sk-or-x", "AI_GATEWAY_API_KEY": "v"}
        ok(resolve_provider({"JEV_OPENROUTER_API_KEY": "sk-or-x", "TYPESAFE_API_KEY": "t"}, {}) == "typesafe" and
           resolve_provider({"JEV_OPENROUTER_API_KEY": "sk-or-x"}, {}) == "openrouter" and resolve_provider({}, {"provider": "vercel"}) == "vercel" and
           resolve_provider(ambient, {}) == "typesafe" and resolve_provider({"JEV_OPENROUTER_API_KEY": "sk-or-x"}, {"keychain": "k"}) == "typesafe",
           "router: detection only from opt-in variables, TypeSafe kept with a Keychain item")
        tiers = {"order": ["small", "medium", "large"], "up_at": {"medium": 0.5, "large": 0.5}, "from_score": {"small": 0, "medium": 1, "large": 2}}
        ok(tier_of({"score": 0, "probabilities": {"0": 1.0, "rm": 0.0}}, tiers) == "large" and tier_of({"score": 0, "probabilities": {"0": 1.0}}, tiers) == "small",
           "router: tier_of fails closed (top tier) on keys that are not levels")
    finally:
        globals()["key_route_error"] = route
        ENV.pop("TYPESAFE_API_KEY", None)
        CONFIG.clear()
        CONFIG.update(saved)
        srv.shutdown()


def selfcheck():
    import tempfile
    from types import SimpleNamespace

    async def listed(model, key):
        return key_lists(model, key)
    Router = functools.partial(ReflexRouter, may_call_fn=listed, controls_fn=lambda m, k: None)  # same with or without litellm
    fails = []

    def ok(c, m):
        if not c:
            fails.append(m)
            print("FAIL", m, file=sys.stderr)

    # redaction: setup/redact.json's corpus, the exact outputs gate.mjs's selfcheck also asserts
    for c in redaction()[2]:
        ok(redact(c["in"]) == c["out"], f"redact corpus: {c['in'][:40]!r} -> {redact(c['in'])!r}")
    ok(has_secret("key AKIAABCDEFGHIJKLMNOP") and not has_secret("max_tokens: 100, password field"), "secret shapes only")

    # require_same_limits: key, internal-user and end-user per-model budgets all count; the team's is not enforced.
    # Entries carry budget_duration: LiteLLM 1.100.1 ignores (and never enforces) one without it.
    b = {"max_budget": 5, "budget_duration": "1d"}
    k = SimpleNamespace(model_max_budget={"a": b, "b": b}, user_model_max_budget={"a": {"max_budget": 1, "budget_duration": "1d"}},
                        end_user_model_max_budget=None, team_model_max_budget={"b": {"max_budget": 9, "budget_duration": "1d"}})
    ok(limits_of(k, "a") != limits_of(k, "b"), "limits: an internal-user budget on one model only differs")
    k.user_model_max_budget = {"a": {"max_budget": 1, "budget_duration": "1d"}, "b": {"max_budget": 1, "budget_duration": "1d"}}
    ok(limits_of(k, "a") == limits_of(k, "b"), "limits: same key and user budgets are the same limits; team budget ignored")
    k.end_user_model_max_budget = {"b": {"max_budget": 2, "budget_duration": "7d"}}
    ok(limits_of(k, "a") != limits_of(k, "b"), "limits: an end-user budget on one model only differs")
    ok(limits_of(k, "a", rpm=10) != limits_of(k, "a", rpm=20), "limits: key rpm counts")
    ok(limits_of(SimpleNamespace(), "a") == limits_of(SimpleNamespace(model_max_budget={}), "b"), "limits: no budgets anywhere are equal")

    # the three request shapes
    chat = {"model": "claude-opus-5", "messages": [
        {"role": "system", "content": "You are a coding agent."},
        {"role": "user", "content": "Fix the flaky test in src/app/test_api.py"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": [{"type": "text", "text": "<system-reminder>noise</system-reminder>and bump deps"}]}],
        "tools": [{"type": "function", "function": {"name": "Bash"}}]}
    f = features(chat)
    ok(f["last"] == "and bump deps" and f["system"].startswith("You are") and f["tools"] == ["Bash"], "chat shape")
    ok("src/app/test_api.py" in f["paths"] and f["turn"] == 2 and not f["secret"], "chat paths / turns")
    anth = {"model": "claude-sonnet-5", "system": [{"type": "text", "text": "Claude Code"}], "tools": [{"name": "Read"}],
            "messages": [{"role": "user", "content": [{"type": "text", "text": "Read the config"}]},
                         {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "Read", "input": {"file_path": "/repo/.env"}}]},
                         {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "AWS_KEY=AKIAABCDEFGHIJKLMNOP"}]}]}
    f = features(anth)
    ok(f["last"] == "Read the config" and f["system"] == "Claude Code", "anthropic: tool result is not the user's message")
    ok("/repo/.env" in f["paths"] and f["secret"], "anthropic: paths and secrets from tool traffic")
    resp = {"model": "gpt-5.6-terra", "instructions": "codex", "input": [{"role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
            "previous_response_id": "resp_1"}
    f = features(resp)
    ok(f["last"] == "hi" and f["system"] == "codex" and f["pinned"], "responses shape")
    ok(features({"model": "x", "input": "just text"})["last"] == "just text", "responses string input")
    ok(features(chat)["conv"] == features({**chat, "messages": chat["messages"][:2]})["conv"], "conversation id stable across turns")
    ok(features({**chat, "litellm_session_id": "s1"})["conv"] == "s1", "session id from LiteLLM wins")

    # what Jev sees of paths
    policy = load(CONFIG["policy"])
    cc = {"model": "claude-opus-5", "system": "You are Claude Code.\nPrimary working directory: /Users/me/src/app\n",
          "messages": [{"role": "user", "content": "compare /Users/me/src/app/lib/db.py, src/x.go, "
                        "/Users/me/infra/envs/prod/rds.tf, ~/.aws/credentials and ../other/secret.txt from /Users/me/src/app"}]}
    f = features(cc)
    seen = jev_state(f, {"item_key": "r", "context_key": "c", "context": ""}, policy)["r"]["paths"]
    ok(f["cwd"] == "/Users/me/src/app", f"cwd from the system prompt ({f['cwd']})")
    ok("lib/db.py" in seen and "src/x.go" in seen and "." in seen, f"repo paths kept, relative ({seen})")
    ok(".../rds.tf [outside repo, sensitive]" in seen and ".../credentials [outside repo, sensitive]" in seen
       and ".../secret.txt [outside repo, sensitive]" in seen, f"outside paths as shapes ({seen})")
    ok(not any("/Users/me" in p or "infra" in p for p in seen), "no layout outside the repo reaches Jev")
    ok(features({"model": "gpt-5.6-sol", "input": [{"role": "user", "content": "<cwd>/w/r</cwd> hi"}]})["cwd"] == "/w/r", "codex cwd")
    ok(path_view("/Users/me/infra/main.tf", f, {**policy, "paths_to_jev": "full"}) == "/Users/me/infra/main.tf", "full paths option")
    ok(path_view("src/x.go", f, {**policy, "paths_to_jev": "shape"}) == ".../x.go", "shape option")

    # policy
    fam = policy["families"]["claude"]
    fam["models"]["cheap-3p"] = {"tier": "small", "price_in": 0.1, "first_party": False, "frontier": False, "tools": False}
    A = lambda s, d, t=0.9, probs=None: {"sensitivity": {"choice": s, "probabilities": probs or {}},
                                         "difficulty": {"score": d}, "needs_tools": {"noul": t}}
    F = lambda **kw: {"secret": False, "paths": [], "tools": ["Bash"], "ctx_tokens_est": 1000, "pinned": False, **kw}

    def route(ans, feats=None):
        sens, tier, tools, _ = classify(ans, feats or F(), policy)
        return pick(fam, eligible(fam, sens, tools, policy), tier, policy)
    ok(route(A("public", 0.1, 0.1)) == "cheap-3p", "public small, no tools: cheapest, third party ok")
    ok(route(A("public", 0.1, 0.9)) == "claude-haiku-4-5", "needs tools excludes a model without tools")
    ok(route(A("application", 0.1, 0.1)) == "claude-haiku-4-5", "application: first party only")
    ok(route(A("restricted", 0.1)) == "claude-sonnet-5", "restricted: first-party frontier, cheapest")
    ok(route(A("proprietary", 1.8)) == "claude-opus-5", "large tier")
    ok(route(A("public", 1.0)) == "claude-sonnet-5", "medium tier")
    ok(route(A("public", 0.1, 0.1, {"restricted": 0.2, "proprietary": 0.1})) == "claude-sonnet-5", "restricted probability bumps")
    ok(route(A("public", 0.1, 0.1), F(secret=True)) == "claude-sonnet-5", "secret shape floors to restricted")
    ok(route(A("public", 0.1, 0.1), F(paths=["infra/envs/prod/main.tf"])) == "claude-sonnet-5", "sensitive path floors")
    ok(route(A("public", 0.1, 0.1), F(tools=[])) == "cheap-3p", "no tools offered: needs_tools ignored")
    ok(family_of("claude-haiku-4-5-20251001", policy) == "claude" and family_of("spark-vllm", policy) is None, "families")
    ok(family_of("gpt-6-astra", policy) is None and family_of("claude-fable-6", policy) is None, "unlisted models are not routed")
    ok(family_of("auto", policy) == "chatgpt" and family_of("claude-auto", policy) == "claude", "aliases")
    ok(route(A("public", 0.1, 0.1), F(ctx_tokens_est=300_000, tools=[])) == "cheap-3p", "max_context absent: no limit")
    big = lambda: pick(fam, eligible(fam, "application", True, policy, 300_000), "small", policy)
    ok(big() == "claude-sonnet-5", "a context over max_context skips the model")
    ok(resolve("claude-opus-5[1m]", fam) == "claude-opus-5" and resolve("claude-haiku-4-5-20251001", fam) == "claude-haiku-4-5", "resolve")

    # stickiness
    pool = eligible(fam, "application", True, policy)
    sw = lambda prev, new, **kw: stay_or_switch(prev, new, pool, F(**kw), fam, policy)[0]
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=150_000) == "claude-opus-5", "large context stays")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=2_000) == "claude-haiku-4-5", "small context switches down")
    ok(sw("claude-haiku-4-5", "claude-opus-5", ctx_tokens_est=150_000) == "claude-opus-5", "harder turn moves up")
    ok(stay_or_switch("claude-haiku-4-5", "claude-sonnet-5", eligible(fam, "restricted", True, policy), F(ctx_tokens_est=150_000), fam, policy)[0]
       == "claude-sonnet-5", "sensitivity forces a switch at any size")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=100, pinned=True) == "claude-opus-5", "previous_response_id pins")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=100, thinking=True) == "claude-opus-5", "signed thinking: no move down")
    ok(sw("claude-haiku-4-5", "claude-opus-5", ctx_tokens_est=100, thinking=True) == "claude-haiku-4-5", "signed thinking: no move up for cost")
    ok(sw("claude-opus-5", "claude-haiku-4-5", ctx_tokens_est=100, ctx_1m=True) == "claude-opus-5", "1M context: no move")
    ok(stay_or_switch("claude-haiku-4-5", "claude-sonnet-5", eligible(fam, "restricted", True, policy), F(thinking=True), fam, policy)[0]
       == "claude-sonnet-5", "signed thinking: sensitivity still forces the move")

    # tier from probability mass: under-tiering is the costly error
    t = policy["tiers"]
    ok(tier_of({"score": 0.45, "probabilities": {"0": 0.55, "1": 0.45, "2": 0}}, t) == "medium", "P(>=medium) 0.45 routes up")
    ok(tier_of({"score": 0.1, "probabilities": {"0": 0.9, "1": 0.1, "2": 0}}, t) == "small", "confident small stays small")
    ok(tier_of({"score": 1.1, "probabilities": {"0": 0.1, "1": 0.3, "2": 0.6}}, t) == "large", "P(large) 0.6 is large")
    ok(tier_of({"score": 0.45}, t) == "small" and tier_of({"score": 1.0}, t) == "medium", "no probabilities: from_score")
    ok(tier_of({"score": 0.45, "probabilities": {"0": 0.55, "1": 0.45, "2": 0}}, {**t, "up_at": None}) == "small", "no up_at: from_score")

    # model-bound state in the request
    sig = {"model": "claude-opus-5", "messages": [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [{"type": "thinking", "thinking": "", "signature": "EosnCk"}, {"type": "text", "text": "ok"}]},
        {"role": "user", "content": "more"}]}
    ok(features(sig)["thinking"] and not features(chat)["thinking"], "signed thinking detected")
    ok(features({"model": "gpt-5.6-sol", "input": [{"type": "reasoning", "encrypted_content": "gAAA"}, {"role": "user", "content": "x"}]})["thinking"],
       "encrypted reasoning detected")
    ok(features({**chat, "model": "claude-opus-5[1m]"})["ctx_1m"] and not features(chat)["ctx_1m"], "[1m] suffix")
    ok(features({**chat, "proxy_server_request": {"headers": {"Anthropic-Beta": "context-1m-2025-08-07,foo"}}})["ctx_1m"], "context-1m beta header")

    # the hook, Jev stubbed
    with tempfile.TemporaryDirectory() as tmp:
        CONFIG["data"] = tmp
        calls = []

        def stub(answers):
            def fn(state, questions, timeout_s):
                calls.append(state)
                if answers is None:
                    raise TimeoutError("stub")
                return answers, {"input_tokens": 400}
            return fn
        key = SimpleNamespace(models=[])

        async def run():
            h = Router(stub(A("public", 0.1, 0.9)), mode="enforce")
            d = await h.async_pre_call_hook(key, None, {**chat, "messages": chat["messages"][:2]}, "acompletion")
            ok(d["model"] == "claude-haiku-4-5", f"enforce rewrites the model ({d['model']})")
            await h.async_pre_call_hook(key, None, {**chat, "messages": chat["messages"][:2]}, "acompletion")
            ok(len(calls) == 1, "second identical request is a cache hit")
            d = await h.async_pre_call_hook(key, None, {"model": "spark-vllm", "messages": chat["messages"]}, "acompletion")
            ok(d["model"] == "spark-vllm" and len(calls) == 1, "unrouted family: untouched, no Jev call")
            d = await h.async_pre_call_hook(key, None, {"model": "x", "input": ["a"]}, "aembedding")
            ok(d["model"] == "x", "embeddings are never routed")
            d = await h.async_pre_call_hook(SimpleNamespace(models=["claude-opus-5"]), None, dict(chat, litellm_session_id="k"), "acompletion")
            ok(d["model"] == "claude-opus-5", "a model the key may not use is never chosen")

            h = Router(stub(None), mode="enforce")
            d = await h.async_pre_call_hook(key, None, dict(chat), "acompletion")
            ok(d["model"] == "claude-sonnet-5", "Jev error: fallback restricted + medium")

            h = Router(stub(A("public", 0.1, 0.9)), mode="shadow")
            d = await h.async_pre_call_hook(key, None, dict(chat, litellm_session_id="shadow-1"), "acompletion")
            ok(d["model"] == "claude-opus-5", "shadow keeps the requested model")
            await asyncio.gather(*h.tasks)
        asyncio.run(run())
        lines = [json.loads(x) for x in (Path(tmp) / "routing.jsonl").read_text().splitlines()]
        shadow = lines[-1]
        ok(shadow["mode"] == "shadow" and shadow["chosen"] == "claude-haiku-4-5" and shadow["applied"] == "claude-opus-5",
           "shadow logs what enforce would do")
        ok(lines[-2]["source"] == "fallback" and "stub" in lines[-2]["error"], "fallback logged with its error")
        raw = (Path(tmp) / "routing.jsonl").read_text()
        ok("flaky" not in raw and "test_api.py" not in raw and "AKIA" not in raw, "log carries no content or paths")

        class Redis:        # the part of LiteLLM's RedisCache the router uses
            def __init__(self):
                self.kv = {}

            async def async_get_cache(self, k):
                return self.kv.get(k)

            async def async_set_cache(self, k, v, ttl=None):
                self.kv[k] = v
        shared = SimpleNamespace(redis_cache=Redis())

        async def run2():
            haiku_only = SimpleNamespace(models=["claude-haiku-4-5"])
            secret = {"model": "claude-haiku-4-5", "messages": [{"role": "user", "content": "why does AKIAABCDEFGHIJKLMNOP fail"}]}
            pol, orig = load(CONFIG["policy"]), CONFIG["policy"]

            def use_policy(name, **no_eligible):
                pf = Path(tmp) / f"policy-{name}.json"
                pf.write_text(json.dumps({**pol, "no_eligible": no_eligible}))
                CONFIG["policy"] = str(pf)

            async def enforce(k, data, answers=A("public", 0.1, 0.1)):
                return await Router(stub(answers), mode="enforce").async_pre_call_hook(k, None, dict(data), "anthropic_messages")
            use_policy("block", action="block")
            d = await enforce(haiku_only, secret)
            ok(isinstance(d, str) and "blocked" in d, f"no eligible model: block ({d})")
            h = Router(stub(A("public", 0.1, 0.1)), mode="shadow")
            d = await h.async_pre_call_hook(haiku_only, None, dict(secret), "anthropic_messages")
            await asyncio.gather(*h.tasks)
            ok(d["model"] == "claude-haiku-4-5", "shadow never blocks")
            use_policy("keep", action="keep")
            ok((await enforce(haiku_only, secret))["model"] == "claude-haiku-4-5", "no eligible model: keep")
            use_policy("fb", action="fallback_model", model="spark-vllm")
            ok((await enforce(SimpleNamespace(models=["claude-haiku-4-5", "spark-vllm"]), secret))["model"] == "spark-vllm",
               "no eligible model: fallback_model")
            ok(isinstance(await enforce(haiku_only, secret), str), "fallback_model the key may not call: blocked")
            CONFIG["policy"] = orig

            d = await enforce(key, dict(chat, model="claude-opus-5[1m]"), A("public", 1.8, 0.9))
            ok(d["model"] == "claude-opus-5[1m]", f"same model keeps the requested name ({d['model']})")
            dated = SimpleNamespace(models=["claude-haiku-4-5-20251001"])
            d = await enforce(dated, {"model": "claude-haiku-4-5-20251001", "messages": [{"role": "user", "content": "hi"}]})
            ok(d["model"] == "claude-haiku-4-5-20251001", f"a key listing only the dated id keeps it ({d})")

            # signed thinking, no record of the previous model (new worker): stays on the requested model
            d = await enforce(key, dict(sig, litellm_session_id="t1"), A("public", 0.1, 0.9))
            ok(d["model"] == "claude-opus-5", f"signed thinking mid-conversation: no cost switch ({d['model']})")
            # a forced move carries the conversation unchanged (the API drops what the new model cannot read)
            fresh = json.loads(json.dumps(dict(sig, model="claude-haiku-4-5", litellm_session_id="t2")))
            d = await enforce(key, fresh, A("restricted", 0.1, 0.9))
            ok(d["model"] == "claude-sonnet-5" and d["messages"] == sig["messages"], "forced move keeps thinking blocks unchanged")
            d = await enforce(key, dict(chat, model="claude-opus-5[1m]", litellm_session_id="m1"), A("public", 0.1, 0.9))
            ok(d["model"] == "claude-opus-5[1m]", f"1M context mid-conversation: no cost switch ({d['model']})")

            # guardrails and per-model limits: only between models LiteLLM treats the same
            def ctl(table):
                return lambda m, k: {"guardrails": table.get(m, []), "limits": ("null",) * 3}

            async def guarded(table, answers=A("public", 0.1, 0.9), data=chat, pol_over=None):
                if pol_over is not None:
                    pf = Path(tmp) / "policy-ctl.json"
                    pf.write_text(json.dumps({**pol, **pol_over}))
                    CONFIG["policy"] = str(pf)
                h = Router(stub(answers), mode="enforce", controls_fn=ctl(table))
                d = await h.async_pre_call_hook(key, None, dict(data, litellm_session_id=sha(table) + str(pol_over)), "acompletion")
                CONFIG["policy"] = orig
                return d if isinstance(d, str) else d["model"]
            ok(await guarded({"claude-opus-5": ["pii"], "claude-sonnet-5": ["pii"]}) == "claude-sonnet-5",
               "guardrails differ on haiku: cheapest with the same guardrails")
            ok(await guarded({"claude-opus-5": ["pii"]}) == "claude-opus-5", "no other model has the guardrail: keep requested")
            ok(await guarded({"claude-opus-5": ["pii"]}, pol_over={"require_same_guardrails": False}) == "claude-haiku-4-5",
               "require_same_guardrails false: guardrails ignored")
            ok(await guarded({"claude-haiku-4-5": ["pii"]}) == "claude-sonnet-5", "an extra guardrail elsewhere also differs")
            ok(isinstance(await guarded({"claude-sonnet-5": ["pii"], "claude-opus-5": ["pii"]}, A("restricted", 0.1, 0.9),
                                        dict(chat, model="claude-haiku-4-5")), str),
               "forced move with no model under the same guardrails: no_eligible (block)")

            def lim(m, k):
                return {"guardrails": [], "limits": ("5",) if m == "claude-haiku-4-5" else ("null",)}
            h = Router(stub(A("public", 0.1, 0.9)), mode="enforce", controls_fn=lim)
            d = await h.async_pre_call_hook(key, None, dict(chat, litellm_session_id="lim"), "acompletion")
            ok(d["model"] == "claude-sonnet-5", f"per-model limit differs: skipped ({d['model']})")

            # stickiness through a shared Redis: a second worker sees the model the first one chose
            conv = dict(chat, litellm_session_id="w", messages=chat["messages"] + [{"role": "assistant", "content": "x" * 600_000}])

            async def worker(answers, cache):
                h = Router(stub(answers), mode="enforce")
                return (await h.async_pre_call_hook(key, cache, dict(conv), "acompletion"))["model"]
            ok(await worker(A("public", 1.8, 0.9), shared) == "claude-opus-5", "worker 1: large task")
            ok(await worker(A("public", 0.1, 0.9), shared) == "claude-opus-5", "worker 2 keeps it (shared Redis)")
            ok(await worker(A("public", 0.1, 0.9), None) == "claude-haiku-4-5", "without Redis, per process")
        asyncio.run(run2())
        recs = [json.loads(x) for x in (Path(tmp) / "routing.jsonl").read_text().splitlines()]
        ok(any(r.get("action") == "block" and r["mode"] == "shadow" and r["applied"] == "claude-haiku-4-5" for r in recs),
           "shadow logs the block it would make")
        ok(all("ctx_tokens" not in r for r in recs), "token counts are labelled as estimates")
    providers_selfcheck(ok)
    print("routing selfcheck FAILED" if fails else "routing selfcheck OK")
    return not fails


async def evaluate(path=HERE / "golden.json"):
    """Live Jev over routing/golden.json (never the cache). Exit 1 on a tier two levels too low or
    restricted/proprietary content classified as public/application."""
    golden, policy = load(path), load(CONFIG["policy"])
    h, tools = ReflexRouter(mode="enforce"), [{"name": n} for n in ("Bash", "Read", "Edit", "Grep")]
    so, to = policy["sensitivity"]["order"], policy["tiers"]["order"]

    async def one(c):
        f = features({"model": c["model"], "tools": tools, "messages": [{"role": "user", "content": c["prompt"]}]})
        return c, await h.decide(f, c["model"], apply=True)
    # ponytail: batches of 6, well inside the documented 1,200 requests/minute (same as eval.mjs).
    res = []
    for i in range(0, len(golden["cases"]), 6):
        res += await asyncio.gather(*map(one, golden["cases"][i:i + 6]))
    # A timeout within the latency budget scores the fallback, not Jev: retry those once, one at a time.
    res = [(c, d) if d["source"] != "fallback" else await one(c) for c, d in res]
    n, rows = len(res), []
    for c, d in res:
        got_s, got_t = d.get("sensitivity"), d.get("tier")
        dt = to.index(c["tier"]) - to.index(got_t) if got_t else 9
        leak = c["sensitivity"] in ("restricted", "proprietary") and got_s in ("public", "application")
        rows.append({**c, "got_sensitivity": got_s, "got_tier": got_t, "under_tier": max(dt, 0), "leak": leak,
                     "chosen": d["chosen"], "source": d["source"], "error": d["error"], "difficulty_p": d.get("difficulty_p"),
                     "answers": d.get("answers")})
    print(f"{'want':24} {'got':24} {'P(>=med,lg)':12} {'chosen':17} prompt")
    for r in rows:
        mark = "FAIL" if r["under_tier"] >= 2 or r["leak"] else "under" if r["under_tier"] else \
            "" if (r["got_sensitivity"], r["got_tier"]) == (r["sensitivity"], r["tier"]) else "diff"
        p = r["difficulty_p"] or {}
        pm = f"{sum(v for k, v in p.items() if int(k) >= 1):.2f},{p.get('2', 0):.2f}" if p else "-"
        print(f"{r['sensitivity'] + '/' + r['tier']:24} {str(r['got_sensitivity']) + '/' + str(r['got_tier']):24} {pm:12} "
              f"{r['chosen']:17} {mark:5} {r['prompt'][:60]}{'  ' + r['error'] if r['error'] else ''}")
    sens_ok = sum(r["got_sensitivity"] == r["sensitivity"] for r in rows)
    tier_ok = sum(r["got_tier"] == r["tier"] for r in rows)
    under = sum(r["under_tier"] > 0 for r in rows)
    under2 = sum(r["under_tier"] >= 2 for r in rows)
    over = sum(to.index(r["got_tier"]) > to.index(r["tier"]) for r in rows if r["got_tier"])
    leaks = sum(r["leak"] for r in rows)
    sens_under = sum(so.index(r["got_sensitivity"]) < so.index(r["sensitivity"]) for r in rows if r["got_sensitivity"])
    print(f"\n{n} cases · sensitivity {sens_ok}/{n} (under {sens_under}, restricted leaks {leaks}) · tier {tier_ok}/{n} "
          f"(under {under}, of which by 2 levels {under2}; over {over}) · fallback "
          f"{sum(r['source'] == 'fallback' for r in rows)} · policy {policy['version']} · questions "
          f"{load(CONFIG['questions'])['version']} · model {CONFIG['model']}")
    Path(CONFIG["data"]).mkdir(parents=True, exist_ok=True)
    out = Path(CONFIG["data"]) / f"routing-eval-{time.strftime('%Y%m%dT%H%M%S')}.json"
    out.write_text(json.dumps({"golden": golden["version"], "policy": policy["version"], "results": rows}, indent=1))
    print(f"details {out}")
    return not (under2 or leaks)


if __name__ == "__main__":
    args = sys.argv[1:]
    opt = lambda n, d=None: args[args.index(n) + 1] if n in args else d
    if "--selfcheck" in args:
        sys.exit(0 if selfcheck() else 1)
    elif "--eval" in args or "--smoke" in args:
        sys.exit(0 if asyncio.run(evaluate(opt("--golden", HERE / "golden.json"))) else 1)
    elif "--check" in args:
        model = opt("--model", "claude-opus-5")
        f = features({"model": model, "messages": [{"role": "user", "content": opt("--check")}]})
        print(json.dumps(asyncio.run(ReflexRouter().decide(f, model, apply=True)), indent=1))
    else:
        print(__doc__)
