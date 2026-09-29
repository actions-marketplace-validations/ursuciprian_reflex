#!/usr/bin/env node
// Reflex context layer: Jev decides, per request, how much of each piece of context the coding
// agent sees, instead of compacting blindly. Nothing is deleted: full texts stay in a chunk store
// and the agent can get any of them back with the expand_chunk tool.
//
//   ladder()      a large tool output -> one Jev choice per chunk: hide / short / long / full
//   assemble()    before each LLM call: re-level earlier tool results for a new request, and keep
//                 the cached prompt prefix unless rebuilding it pays for itself (rebuildCost)
//   recall()      /fresh: a clean start that reloads only what Jev scores relevant to the new goal
//   bundle()      one retrieval pass over a git change (files, symbols, diff) that read-only
//                 background tasks share; scripts/reflex-review is the example consumer
//
// This layer optimises, it is not a gate: every entry point fails open (on any error the caller
// leaves the context as it was). Decisions are logged to $REFLEX_DATA_DIR/context.jsonl.
//
//   node context.mjs --selfcheck                                 offline tests, fake Jev on localhost
//   node context.mjs --bundle [--base REF] [--goal T] [--out F]  write a retrieval bundle
//   node context.mjs --expand <id> [--lines a-b]                 print a stored chunk
//   node context.mjs --prune                                     apply the chunk store's age / size limits
//   node context.mjs --smoke                                     live Jev ladder on a grep of this repo
//   node context.mjs --eval-context                              live golden set for the ladder (npm run eval-context)
import {appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, rmSync, statSync, utimesSync,
  writeFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {execFileSync, spawnSync} from "node:child_process";
import {createServer} from "node:http";
import {tmpdir} from "node:os";
import {basename, dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {ask as jevAsk, redact, CONFIG} from "./gate.mjs";
import {hostOf} from "./providers.mjs";

const ENV = process.env;
const HERE = dirname(fileURLToPath(import.meta.url));
// A context decision may take longer than a gate call (up to 24 questions in one request); omp
// gives a handler 30 s, so the budget is capped at 25 s to leave room for the rest of the handler.
const timeoutMs = () => Math.min(25_000, Number(ENV.REFLEX_CONTEXT_TIMEOUT_MS) || 8000);
// hideMin: a "hide" below this probability is shown as "short"; hiding is the only level that can
// cost the agent something, so doubt goes to the cheap view that still shows the matching lines.
export const LIMITS = {minLines: 200, minBytes: 16_384, maxChunks: 24, excerpt: 1000, matches: 6, minStub: 2000,
  recallChars: 24_000, hideMin: 0.7};
export const LEVELS = ["hide", "short", "long", "full"];
const LADDER = {
  hide: "Nothing in it bears on the request or the current step.",
  short: "Marginal or possibly relevant: a glance at the lines that match the request is enough.",
  long: "Relevant: the agent needs the lines that matter, with some context around them.",
  full: "Essential: the exact, complete text is needed (to edit it, quote it, or debug it line by line).",
};

const sha = s => createHash("sha256").update(s).digest("hex").slice(0, 12);
const readText = p => { try { return readFileSync(p, "utf8"); } catch { return null; } };
const safe = s => String(s ?? "").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 80) || "default";
const clip = (s, n) => s.length <= n ? s : `${s.slice(0, Math.floor(n * 0.7))}\n…\n${s.slice(-Math.floor(n * 0.3))}`;
const excerpt = t => clip(redact(t ?? ""), LIMITS.excerpt);
// ponytail: chars/4, not a tokenizer; the cost model only needs the order of magnitude.
export const tokens = s => Math.ceil((s?.length ?? 0) / 4);
export const textOf = m => typeof m?.content === "string" ? m.content
  : (m?.content ?? []).filter(c => c.type === "text").map(c => c.text).join("\n");
const onlyText = m => typeof m.content === "string" || (m.content ?? []).every(c => c.type === "text");
const tally = ls => LEVELS.map(l => `${ls.filter(x => x === l).length} ${l === "hide" ? "hidden" : l}`).join(", ");

export function log(entry) {
  try {
    mkdirSync(CONFIG.data, {recursive: true});
    appendFileSync(join(CONFIG.data, "context.jsonl"), JSON.stringify({ts: new Date().toISOString(), model: CONFIG.model, ...entry}) + "\n");
  } catch { /* logging must never break the agent */ }
}

// ---------------------------------------------------------------------------------------------
// Chunk store: $REFLEX_DATA_DIR/chunks/<session>/<id>.txt. Ids are content hashes, so storing the
// same text twice is a no-op. The store holds tool output as the tool printed it, unredacted, like
// the agent's own session file would: directories are 0700, files 0600, and pruneChunks() drops
// chunks unused for REFLEX_CHUNK_DAYS (7) and the oldest ones beyond REFLEX_CHUNK_MB (200).
const chunkDir = () => join(CONFIG.data, "chunks");
const PRIVATE = {recursive: true, mode: 0o700};
const CHUNK_ID = /^[a-z0-9]{4,40}$/;
export function storeChunk(session, id, text) {
  const dir = join(chunkDir(), safe(session)), file = join(dir, `${id}.txt`);
  mkdirSync(dir, PRIVATE);
  if (!existsSync(file)) writeFileSync(file, text, {mode: 0o600});
  else touch(file);
}
const touch = f => { try { const now = new Date(); utimesSync(f, now, now); } catch { /* best effort */ } };
// The stored full text for an id: this session first; /fresh starts a new session that still refers
// to the old one's chunks. Reading a chunk renews it for pruning.
export function readChunk(id, session) {
  if (!CHUNK_ID.test(id ?? "")) return null;   // the id may come from the model: never a path
  let dirs = [];
  try { dirs = readdirSync(chunkDir()); } catch { /* empty store */ }
  for (const d of [safe(session), ...dirs]) {
    const f = join(chunkDir(), d, `${id}.txt`), t = readText(f);
    if (t != null) return touch(f), t;
  }
  return null;
}
export function expandChunk(id, lines, session) {
  if (!CHUNK_ID.test(id ?? "")) return `reflex: invalid chunk id ${JSON.stringify(id)}`;
  const t = readChunk(id, session);
  if (t == null) return `reflex: chunk ${id} not found (pruned after REFLEX_CHUNK_DAYS, or from another machine)`;
  const m = /^(\d+)-(\d+)$/.exec(String(lines ?? "").trim());
  return m ? t.split("\n").slice(Math.max(0, m[1] - 1), Math.max(0, +m[2])).join("\n") : t;
}
export function pruneChunks({days = Number(ENV.REFLEX_CHUNK_DAYS) || 7, mb = Number(ENV.REFLEX_CHUNK_MB) || 200, now = Date.now()} = {}) {
  const files = [];
  let dirs = [];
  try { chmodSync(chunkDir(), 0o700); dirs = readdirSync(chunkDir()); } catch { return {removed: 0, kept: 0}; }
  for (const d of dirs) {
    let names = [];
    try { names = readdirSync(join(chunkDir(), d)); } catch { continue; }
    for (const n of names) try {
      const f = join(chunkDir(), d, n), s = statSync(f);
      files.push({f, at: s.mtimeMs, size: s.size});
    } catch { /* raced with another pruner */ }
  }
  files.sort((a, b) => b.at - a.at);   // newest first
  let total = 0, removed = 0;
  for (const x of files) {
    total += x.size;
    if (now - x.at <= days * 86_400_000 && total <= mb * 1_048_576) continue;
    // re-check: another session may have just reused (touched) this chunk
    try { if (statSync(x.f).mtimeMs === x.at) { rmSync(x.f, {force: true}); removed++; } } catch { /* already gone */ }
  }
  // rmdir, not rm -r: a session writing its first chunk right now keeps its directory
  for (const d of dirs) try { rmdirSync(join(chunkDir(), d)); } catch { /* not empty or gone */ }
  if (removed) log({kind: "prune", removed, kept: files.length - removed, days, mb});
  return {removed, kept: files.length - removed};
}

// A tool result already cut by the ladder ends with a note naming its stored full output. Re-level
// from that text, not from the cut view, when the store still has it and the view really is a
// selection of its lines (so a tool output that merely imitates the note cannot pull in another chunk).
const NOTE = /\n\[reflex: [^\n]*expand_chunk \{"id":"(o[0-9a-f]{12})"\}[^\n]*\]$/;
export function sourceOf(m, session) {
  const text = textOf(m), id = NOTE.exec(text)?.[1];
  const full = id ? readChunk(id, session) : null;
  if (full != null) {
    const have = new Set(full.split("\n"));
    if (text.replace(NOTE, "").split("\n").every(l => have.has(l) || /^… \[lines \d+-\d+ hidden\] …$/.test(l)))
      return {id, text: full, stored: true};
  }
  return {id: `m${sha(text)}`, text, stored: false};
}

// ---------------------------------------------------------------------------------------------
// Rendering. Jev picks the level; code picks the lines, because Jev judges and does not write
// text: short = head, tail and the lines that mention the request; long = the same with context
// around each hit; full = everything.
const STOP = new Set(("the and for with that this from what why how does are was were into when where which about have has " +
  "not you your can should would could will then than them they their there here also just only some more most make " +
  "need using use file files line lines code output show find look").split(" "));
// ponytail: prefix stemming (drop the last two letters of long words, one of five-letter ones), so
// "cached" finds CACHE_TTL and "tools" finds "tool"; a real stemmer when this is too noisy.
const stem = w => w.length >= 6 ? w.slice(0, -2) : w.length === 5 ? w.slice(0, -1) : w;
export const terms = text => [...new Set((text ?? "").toLowerCase().match(/[a-z_][a-z0-9_]{2,}/g) ?? [])]
  .filter(w => !STOP.has(w)).map(stem).filter((w, i, a) => a.indexOf(w) === i).slice(0, 40);

// Lines that mention the request, those sharing the most words with it first.
export function hitsOf(lines, words) {
  const n = l => { const x = l.toLowerCase(); return words.filter(w => x.includes(w)).length; };
  return lines.map((l, i) => [i, n(l)]).filter(([, c]) => c).sort((a, b) => b[1] - a[1] || a[0] - b[0]).map(([i]) => i);
}
// Words from the request that occur on most lines of an output ("request", "call" in a grep of an
// HTTP client) point at everything and so at nothing: drop them, unless nothing else is left.
export function focus(words, lines) {
  if (lines.length < 50) return words;
  const max = Math.max(5, lines.length / 5), low = lines.map(l => l.toLowerCase());
  const kept = words.filter(w => low.filter(l => l.includes(w)).length <= max);
  return kept.length ? kept : words;
}

// Code is also outlined: the first definitions of a chunk are kept next to the hits, because the
// line a question is about ("const SKIP = …" for "which tools are never shortened") often shares no
// word with the question.
const DEFINES = /\b(?:function|def|func|class|interface|type|struct|enum|fn|const|let|var)\s+\*?\s*[A-Za-z_$][\w$]*\s*[=({<:]/;
export function keep(lines, level, words) {
  const n = lines.length;
  if (level === "hide") return [];
  if (level !== "short" && level !== "long") return lines.map((_, i) => i);
  const [head, tail, around, cap, outline] = level === "short" ? [2, 1, 0, 12, 6] : [5, 3, 3, 60, 12];
  const s = new Set();
  for (let i = 0; i < Math.min(head, n); i++) s.add(i);
  for (let i = Math.max(0, n - tail); i < n; i++) s.add(i);
  const hits = hitsOf(lines, words);
  for (const h of hits) {
    if (s.size >= cap) break;
    for (let i = Math.max(0, h - around); i <= Math.min(n - 1, h + around); i++) s.add(i);
  }
  lines.flatMap((l, i) => DEFINES.test(l) && !s.has(i) ? [i] : []).slice(0, outline).forEach(i => s.add(i));
  if (level === "long" && !hits.length) for (let i = 0; i < Math.min(20, n); i++) s.add(i);
  return [...s].sort((a, b) => a - b);
}

export function view(lines, ranges, levels, words) {
  const kept = ranges.flatMap(([s, e], i) => keep(lines.slice(s, e), levels[i], words).map(j => s + j));
  const out = [];
  let next = 0;
  const gap = to => { if (to > next) out.push(`… [lines ${next + 1}-${to} hidden] …`); };
  for (const i of kept) { gap(i); out.push(lines[i]); next = i + 1; }
  gap(lines.length);
  return {text: out.join("\n"), shown: kept.length};
}

// Split an output into at most `max` chunks along its own structure: a grep hit list by file,
// anything else by blank-line-separated sections, packed to an even size.
// A diff is cut at every file and hunk, and never packed across files while the budget allows, so
// a chunk is about one file. A line is blank when nothing follows a `cat -n` number or a diff marker.
const GREP = /^([^\s:]+):\d+[:-]/, DIFF = /^diff --git a\/(\S+)/, HUNK = /^@@ /;
const blank = l => !l.replace(/^\s*\d+\t/, "").replace(/^[+ -]/, "").trim();
export function chunk(lines, max = LIMITS.maxChunks) {
  const g = lines.map(l => GREP.exec(l)?.[1] ?? null);
  const cuts = [0], files = new Set();
  for (let i = 1; i < lines.length; i++)
    if (DIFF.test(lines[i])) { cuts.push(i); files.add(i); }
    else if (HUNK.test(lines[i]) || (g[i] || g[i - 1] ? g[i] !== g[i - 1] : blank(lines[i - 1]) && !blank(lines[i]))) cuts.push(i);
  cuts.push(lines.length);
  const blocks = cuts.slice(1).map((e, i) => [cuts[i], e]);
  for (let size = Math.max(10, Math.ceil(lines.length / max)); ; size *= 2) {
    const out = [], apart = size < lines.length;   // once one chunk could hold everything, merge freely
    for (const [bs, be] of blocks)
      for (let s = bs; s < be; s += size) {
        const e = Math.min(be, s + size), last = out.at(-1);
        if (last && e - last[0] <= size && !(apart && files.has(s))) last[1] = e; else out.push([s, e]);
      }
    if (out.length <= max) return out;
  }
}

// One Jev request: a choice per item (capped by the caller), plus any extra questions. Per item Jev
// sees where it comes from (`what`, and the files in a grep chunk), `matches`: its lines that share
// the most words with the request, numbered, and `excerpt`: its start and end. Returns the levels
// and the focused words to render them with.
export async function judgeChunks({request, intent, items, extra = {}, ask = jevAsk}) {
  const words = focus(terms(`${request ?? ""} ${intent ?? ""}`), items.flatMap(it => it.text.split("\n")));
  const chunkState = it => {
    const ls = it.text.split("\n"), files = [...new Set(ls.map(l => (GREP.exec(l) ?? DIFF.exec(l))?.[1]).filter(Boolean))];
    const matches = hitsOf(ls, words).slice(0, LIMITS.matches).sort((a, b) => a - b)
      .map(i => `${(it.start ?? 0) + i + 1}: ${redact(ls[i]).slice(0, 200)}`);
    return {what: it.what, ...(files.length ? {files: files.slice(0, 8)} : {}), ...(matches.length ? {matches} : {}),
            excerpt: clip(redact(it.text), LIMITS.excerpt)};
  };
  const state = {request: redact(request ?? "").slice(0, 2000), ...(intent ? {intent: redact(intent).slice(-1500)} : {}),
    chunks: Object.fromEntries(items.map(it => [it.id, chunkState(it)])), ...extra.state};
  const questions = Object.fromEntries(items.map(it => [it.id, {type: "choice", criteria: LADDER,
    instructions: `Would the coding agent need any of \`chunks.${it.id}\` in its context to answer or carry out \`request\`` +
      `${intent ? " (its current step is `intent`)" : ""}? \`matches\` lists the chunk's lines that share words with the request, ` +
      "numbered; `excerpt` samples its start and end. If any of those lines could be what the request asks about (a " +
      "definition, setting, default value, error, or a call it names), choose short or more. Choose hide only when " +
      "nothing in the chunk bears on the request."}]));
  const r = await ask(state, {...questions, ...extra.questions}, {timeoutMs: timeoutMs()});
  if (r.error || items.some(it => !LADDER[r.answers?.[it.id]?.choice])) return {...r, words, levels: null, error: r.error ?? "incomplete answers"};
  const levels = Object.fromEntries(items.map(it => {
    const a = r.answers[it.id];
    return [it.id, a.choice === "hide" && (a.probabilities?.hide ?? 1) < LIMITS.hideMin ? "short" : a.choice];
  }));
  return {...r, words, levels};
}

// ---------------------------------------------------------------------------------------------
// §V ladder on one tool output. Returns {id, text} to replace the output, or null to leave it.
export async function ladder({text, tool, input, request, intent, session, ask}) {
  const entry = {kind: "ladder", session, tool};
  try {
    const lines = text.split("\n");
    if (lines.length < LIMITS.minLines && text.length < LIMITS.minBytes) return null;
    const id = `o${sha(text)}`, ranges = chunk(lines);
    const items = ranges.map(([s, e], i) => ({id: `c${i}`, what: `${tool} output, lines ${s + 1}-${e}`, start: s, text: lines.slice(s, e).join("\n")}));
    const j = await judgeChunks({request, intent, items, ask,
      extra: {state: {tool: {name: tool, input: excerpt(JSON.stringify(input ?? {}))}}}});
    Object.assign(entry, {id, lines: lines.length, chunks: ranges.length, usage: j.usage, latency_s: j.latency_s, error: j.error ?? null});
    if (!j.levels) return log(entry), null;
    const levels = items.map(it => j.levels[it.id]);
    const v = view(lines, ranges, levels, j.words);
    Object.assign(entry, {levels: tally(levels), shown: v.shown, applied: v.text.length < text.length * 0.8});
    if (!entry.applied) return log(entry), null;
    storeChunk(session, id, text);   // before replacing: if this throws, the output stays whole
    log(entry);
    return {id, text: `${v.text}\n[reflex: ${v.shown} of ${lines.length} lines shown, chosen for the current request (chunks: ${tally(levels)}). ` +
      `Nothing is lost: expand_chunk {"id":"${id}"} returns the full output, {"id":"${id}","lines":"a-b"} a line range.]`};
  } catch (e) {
    log({...entry, error: String(e)});
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// §V per-request assembly and the cache decision.
//
// Cost model, in units of one uncached input token. Providers cache the longest unchanged prompt
// prefix, so changing message k re-sends everything after k uncached (a cache write).
//   keep    = H · T · r                      T tokens after k, read from cache on each of H calls
//   rebuild = (T − S) · w + (H − 1) · (T − S) · r    written once, then read on H − 1 calls
// S = tokens the new view saves, r = cache-read price ratio (REFLEX_CACHE_READ, 0.1), w = cache-
// write ratio (REFLEX_CACHE_WRITE, 1.25; use 1 where writes are not surcharged), H = LLM calls
// expected to reuse the prefix (average calls per user request so far, 2..20). Rebuild pays when
// rebuild < keep. Money is not everything: when Jev says the old context no longer fits the new
// request, the rebuild happens anyway, because stale context costs answer quality.
export function rebuildCost({tail, saving, horizon}) {
  const r = Number(ENV.REFLEX_CACHE_READ ?? 0.1), w = Number(ENV.REFLEX_CACHE_WRITE ?? 1.25);
  const keep = horizon * tail * r, rebuild = (tail - saving) * (w + (horizon - 1) * r);
  return {tail, saving, horizon, keep: Math.round(keep), rebuild: Math.round(rebuild), worth: saving > 0 && rebuild < keep};
}

// src = sourceOf(m): the full text (from the store when the ladder already cut this result) and its id.
function stubText(m, level, words, src) {
  const {text, id} = src, lines = text.split("\n");
  if (level === "hide") return {id, text: `[reflex: ${m.toolName} output (${lines.length} lines) hidden for the current request; expand_chunk {"id":"${id}"} returns it.]`};
  const v = view(lines, [[0, lines.length]], [level], words);
  return {id, text: `${v.text}\n[reflex: ${level} view, ${v.shown} of ${lines.length} lines; expand_chunk {"id":"${id}"} returns all of it.]`};
}

// st is the caller's per-session state: {sig, query, view: {toolCallId: level}, words, stubs}.
// Returns a new message list, or undefined to leave the context untouched. Between requests the
// same view is re-applied on every call, so the prefix stays byte-identical and cacheable.
export async function assemble(messages, st, {session, ask} = {}) {
  try {
    const users = messages.flatMap((m, i) => m.role === "user" ? [i] : []);
    if (!users.length) return undefined;
    const u = users.at(-1), query = textOf(messages[u]), sig = `${users.length}:${sha(query)}`;
    if (st.sig !== sig) {
      const prev = st.query;
      Object.assign(st, {sig, query});   // set first: a failed decision is not retried on every call
      await relevel(messages, u, query, prev, st, {session, ask, users: users.length});
    }
    return apply(messages, st, session);
  } catch (e) {
    log({kind: "assemble", session, error: String(e)});
    return undefined;
  }
}

async function relevel(messages, u, query, prev, st, {session, ask, users}) {
  st.view ??= {};
  const srcs = new Map(), src = m => srcs.get(m) ?? srcs.set(m, sourceOf(m, session)).get(m);
  const cands = messages.slice(0, u)
    .filter(m => m.role === "toolResult" && m.toolName !== "expand_chunk" && onlyText(m) && src(m).text.length >= LIMITS.minStub)
    .sort((a, b) => src(b).text.length - src(a).text.length).slice(0, LIMITS.maxChunks);
  if (!cands.length) return;
  const items = cands.map((m, i) => ({id: `c${i}`, what: `earlier ${m.toolName} result`, text: src(m).text, m}));
  const j = await judgeChunks({request: query, items, ask, extra: prev ? {
    state: {previous_request: redact(prev).slice(0, 2000)},
    questions: {same_context: {type: "noul", instructions: "The coding agent's context was put together for " +
      "`previous_request`. Is it still the right context for the new `request`, i.e. does the new request continue " +
      "the same task with the same material?"}}} : {}});
  const entry = {kind: "assemble", session, candidates: items.length, usage: j.usage, latency_s: j.latency_s, error: j.error ?? null};
  if (!j.levels) return log(entry);
  const proposed = {...st.view};
  for (const it of items) proposed[it.m.toolCallId] = j.levels[it.id];
  const words = j.words;
  // T and S of the cost model, over the messages before the new request. A view that would not be
  // smaller leaves the message as it is (see apply), and so costs what the message costs.
  const size = (m, v, w) => {
    if (m.role !== "toolResult") return tokens(JSON.stringify(m.content));
    const level = v[m.toolCallId] ?? "full", t = textOf(m);
    const stub = level === "full" || !onlyText(m) ? t : stubText(m, level, w, src(m)).text;
    return tokens(stub.length < t.length ? stub : t);
  };
  const k = messages.slice(0, u).findIndex(m => m.role === "toolResult" && (st.view[m.toolCallId] ?? "full") !== (proposed[m.toolCallId] ?? "full"));
  let tail = 0, saving = 0;
  if (k >= 0) for (const m of messages.slice(k, u)) {
    const before = size(m, st.view, st.words ?? words);
    tail += before;
    saving += before - size(m, proposed, words);
  }
  const calls = messages.filter(m => m.role === "assistant").length;
  const cost = rebuildCost({tail, saving, horizon: Math.min(20, Math.max(2, Math.round(calls / users)))});
  const same = j.answers.same_context?.noul;
  const rebuild = saving > 0 && (cost.worth || (same ?? 1) < 0.5);
  log({...entry, levels: tally(items.map(it => j.levels[it.id])), same_context: same ?? null, ...cost,
       decision: rebuild ? "rebuild" : "keep"});
  if (rebuild) Object.assign(st, {view: proposed, words, stubs: {}});
}

function apply(messages, st, session) {
  if (!Object.values(st.view ?? {}).some(l => l !== "full")) return undefined;
  st.stubs ??= {};
  return messages.map(m => {
    const level = m.role === "toolResult" ? st.view[m.toolCallId] : undefined;
    if (!level || level === "full" || !onlyText(m)) return m;
    const key = `${m.toolCallId}:${level}`;
    if (!st.stubs[key]) {
      const src = sourceOf(m, session), s = stubText(m, level, st.words ?? [], src);
      if (s.text.length >= textOf(m).length) s.text = null;   // not smaller: leave the message
      else if (!src.stored) storeChunk(session, s.id, src.text);
      st.stubs[key] = s;
    }
    return st.stubs[key].text ? {...m, content: [{type: "text", text: st.stubs[key].text}]} : m;
  });
}

// ---------------------------------------------------------------------------------------------
// §II.E restart with recall. Returns {text} for the first message of a clean session, or null.
export async function recall({goal, messages, session, ask}) {
  try {
    const items = messages
      .filter(m => ["user", "assistant", "toolResult"].includes(m.role) && onlyTextish(m) && textOf(m).trim())
      .slice(-LIMITS.maxChunks)
      .map(m => ({m, src: m.role === "toolResult" ? sourceOf(m, session) : {id: `m${sha(textOf(m))}`, text: textOf(m), stored: false}}))
      .map(({m, src}, i) => ({id: `c${i}`, m, src, text: src.text,
        what: m.role === "toolResult" ? `${m.toolName} result` : m.role === "user" ? "user request" : "assistant reply"}));
    if (!items.length) return {text: goal, recalled: 0};
    const j = await judgeChunks({request: goal, items, ask});
    const entry = {kind: "recall", session, candidates: items.length, usage: j.usage, latency_s: j.latency_s, error: j.error ?? null};
    if (!j.levels) return log(entry), null;
    const words = j.words, parts = [];
    let room = LIMITS.recallChars;
    for (const it of items) {
      const level = j.levels[it.id], id = it.src.id;
      if (!it.src.stored) storeChunk(session, id, it.text);
      if (level === "hide") continue;
      const lines = it.text.split("\n");
      const body = view(lines, [[0, lines.length]], [level], words).text;
      const part = `### ${it.what} (${level}; expand_chunk {"id":"${id}"})\n${body}`;
      if (part.length > room) continue;
      room -= part.length;
      parts.push(part);
    }
    log({...entry, levels: tally(items.map(it => j.levels[it.id])), recalled: parts.length});
    return {recalled: parts.length, text: parts.length ? `${goal}\n\n[reflex /fresh: context recalled from the previous session because ` +
      `it is relevant to this goal; everything else was left behind and can be fetched with expand_chunk.]\n\n${parts.join("\n\n")}` : goal};
  } catch (e) {
    log({kind: "recall", session, error: String(e)});
    return null;
  }
}
const onlyTextish = m => typeof m.content === "string" || (m.content ?? []).some(c => c.type === "text");

// ---------------------------------------------------------------------------------------------
// §X shared retrieval: given a change, find the files and symbols around it once, have Jev rate
// each candidate, and write a bundle any read-only background task can consume (review, eval
// generation, a progress page). ponytail: `git grep -w` on names, not a language index; add
// ripgrep or an LSP when names are too common to be useful.
const RELEVANCE = {
  irrelevant: "Only shares a name by coincidence; someone reviewing the change does not need it.",
  related: "Uses or is used by the changed code; its matching lines are worth a look.",
  essential: "The change cannot be judged without reading this file: callers that may break, tests of the changed behaviour, the contract it implements.",
};
const DEF = /\b(?:function|def|func|class|interface|type|struct|enum|fn|const|let|var)\s+\*?\s*([A-Za-z_$][\w$]{2,})/g;
const git = (cwd, args) => execFileSync("git", ["-C", cwd, ...args], {encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "ignore"]});
const tryGit = (cwd, args) => { try { return git(cwd, args); } catch { return ""; } };   // git grep exits 1 on no match

export async function bundle({cwd = process.cwd(), base = "HEAD", goal, ask = jevAsk} = {}) {
  // New files the change adds but nobody has `git add`ed yet are part of it too: list them and diff
  // each against /dev/null (exit 1 = "differs", so read stdout whatever the status).
  const untracked = git(cwd, ["ls-files", "--others", "--exclude-standard"]).split("\n").filter(Boolean).slice(0, 100);
  const diff = git(cwd, ["diff", "--no-color", base]) + untracked.map(f => spawnSync("git",
    ["-C", cwd, "diff", "--no-color", "--no-index", "--", "/dev/null", f], {encoding: "utf8", maxBuffer: 64 << 20}).stdout ?? "").join("");
  const changed = [...git(cwd, ["diff", "--name-only", base]).split("\n").filter(Boolean), ...untracked];
  // Names defined on changed lines or in the hunk's context lines (the enclosing definition).
  const touched = diff.split("\n").filter(l => /^[ +\-@]/.test(l) && !/^(\+\+\+|---) /.test(l));
  const symbols = [...new Set(touched.flatMap(l => [...l.matchAll(DEF)].map(d => d[1])))].slice(0, 20);
  const stems = changed.map(f => basename(f).replace(/\.[^.]+$/, "")).filter(s => s.length >= 3);
  const hits = new Map();
  for (const s of new Set([...symbols, ...stems]))
    for (const f of tryGit(cwd, ["grep", "--untracked", "-l", "-w", "-F", "-e", s, "--", "."]).split("\n").filter(Boolean).slice(0, 50))
      if (!changed.includes(f)) hits.set(f, [...(hits.get(f) ?? []), s]);
  const cands = [...hits].sort((a, b) => b[1].length - a[1].length).slice(0, LIMITS.maxChunks).map(([path, syms], i) => ({
    id: `f${i}`, path, symbols: syms,
    matches: tryGit(cwd, ["grep", "--untracked", "-n", "-w", "-F", ...syms.flatMap(s => ["-e", s]), "--", path]).split("\n").slice(0, 15).join("\n")}));
  const j = cands.length ? await ask(
    {change: {goal: goal && redact(goal).slice(0, 2000), files: changed, diff: clip(redact(diff), 6000)},
     candidates: Object.fromEntries(cands.map(c => [c.id, {path: c.path, matches: redact(c.matches)}]))},
    Object.fromEntries(cands.map(c => [c.id, {type: "choice", criteria: RELEVANCE,
      instructions: `How relevant is the file in \`candidates.${c.id}\` to reviewing or testing \`change\`?`}])),
    {timeoutMs: timeoutMs()}) : {answers: {}, usage: {}, latency_s: 0};
  // Fail open: without Jev every candidate is kept as "related", unjudged.
  const judged = !j.error && cands.every(c => RELEVANCE[j.answers?.[c.id]?.choice]);
  const rated = cands.map(({id, ...c}) => ({...c, relevance: judged ? j.answers[id].choice : "related"}));
  const context = rated.filter(c => c.relevance !== "irrelevant");
  for (const c of context) if (c.relevance === "essential") c.content = readText(join(cwd, c.path))?.slice(0, 20_000);
  const b = {version: 1, created: new Date().toISOString(), cwd, base, head: tryGit(cwd, ["rev-parse", "HEAD"]).trim(), goal: goal ?? null,
    changed, symbols, diff: diff.slice(0, 200_000), context, skipped: rated.filter(c => c.relevance === "irrelevant").map(c => c.path),
    judged, usage: j.usage ?? {}, latency_s: j.latency_s ?? 0, error: j.error ?? null};
  log({kind: "bundle", cwd, base, changed: changed.length, candidates: cands.length, kept: context.length, judged,
       usage: b.usage, latency_s: b.latency_s, error: b.error});
  return b;
}

export function writeBundle(b, out = join(CONFIG.data, "bundles", `${Date.now()}.json`)) {
  mkdirSync(dirname(out), {recursive: true, mode: 0o700});
  writeFileSync(out, JSON.stringify(b, null, 1), {mode: 0o600});   // diff and code, unredacted
  return out;
}

export function reviewPrompt(b) {
  const fence = (s, lang = "") => `\`\`\`${lang}\n${s}\n\`\`\``;
  return [
    "Review this code change. You are a read-only reviewer: do not modify files or run commands that change anything.",
    b.goal ? `Goal of the change: ${b.goal}` : "",
    `Changed files: ${b.changed.join(", ") || "(none)"}`,
    "## Diff", fence(b.diff, "diff"),
    "## Related code (selected once for all background tasks)",
    ...b.context.map(c => `### ${c.path} (${c.relevance}; symbols ${c.symbols.join(", ")})\n${fence(c.content ?? c.matches)}`),
    "Report correctness bugs, security issues and missing tests, most severe first, each with file:line and a one-line fix. " +
      "Write \"no findings\" if there are none.",
  ].filter(Boolean).join("\n\n");
}

// @reflex:setup-only begin
// ---------------------------------------------------------------------------------------------
async function selfcheck() {
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  const tmp = mkdtempSync(join(tmpdir(), "reflex-ctx-"));
  CONFIG.data = join(tmp, "data");
  process.env.TYPESAFE_API_KEY = "fake";   // never leaves the machine: CONFIG.api points at the fake below
  // Fake Jev: a chunk is "long" when it mentions timeouts, "full" when marked ESSENTIAL, else hidden;
  // same_context answers SAME. calls counts requests.
  const fake = {calls: 0, same: 0.9, fail: false};
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", d => (body += d));
    req.on("end", () => {
      fake.calls++;
      if (fake.fail) { res.writeHead(500); return res.end("boom"); }
      const {state, questions} = JSON.parse(body), answers = {};
      for (const [id, q] of Object.entries(questions)) {
        if (q.type === "noul") { answers[id] = {type: "noul", noul: fake.same}; continue; }
        const t = JSON.stringify(state.chunks?.[id] ?? state.candidates?.[id] ?? "");
        const choice = q.criteria.essential ? (/parseThing/.test(t) ? "essential" : "irrelevant")
          : /ESSENTIAL/.test(t) ? "full" : /timeout/i.test(t) ? "long" : "hide";
        answers[id] = {type: "choice", choice, probabilities: {[choice]: 0.9}};
      }
      res.end(JSON.stringify({answers, usage: {input_tokens: body.length / 4}}));
    });
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  CONFIG.api = `http://127.0.0.1:${server.address().port}/v1/systemone`;
  CONFIG.keyHost = hostOf(CONFIG.api);   // the key goes only to the host it was configured for
  try {
    // chunking and rendering
    const grep = [];
    for (let f = 0; f < 40; f++) for (let l = 1; l <= 10; l++)
      grep.push(`src/f${f}.mjs:${l}:${f === 7 ? "const timeoutMs = 3000 // timeout" : `let value${l} = compute(${f})`}`);
    const ranges = chunk(grep);
    ok(ranges.length <= LIMITS.maxChunks && ranges[0][0] === 0 && ranges.at(-1)[1] === grep.length, "chunk: bounded, covers all lines");
    ok(ranges.every(([s, e]) => e === grep.length || grep[e].split(":")[0] !== grep[e - 1].split(":")[0]), "chunk: cuts on file boundaries");
    ok(chunk(["a", "b", "", "c"], 24).length === 1 && chunk([]).length === 0, "chunk: small and empty");
    const v = view(["h1", "h2", "x", "timeout here", "y", "z", "t1"], [[0, 7]], ["short"], ["timeout"]);
    ok(v.text === "h1\nh2\n… [lines 3-3 hidden] …\ntimeout here\n… [lines 5-6 hidden] …\nt1" && v.shown === 4, "view: short keeps head, hits, tail");
    ok(keep(["a", "b"], "full", []).length === 2 && keep(["a"], "hide", []).length === 0, "keep: full / hide");
    ok(terms("Why does the gate time out? REFLEX_TIMEOUT_MS").includes("reflex_timeout_") && terms("cached tools").join() === "cach,tool" && !terms("why does the").length, "terms: stop words, prefix stems");

    // ladder: relevant chunk kept, the rest hidden, the full output stored and expandable
    const text = grep.join("\n");
    const L = await ladder({text, tool: "bash", input: {command: "grep -rn value src"}, request: "why does the request time out",
                            intent: "looking for the timeout", session: "s1"});
    ok(L && L.text.includes("const timeoutMs = 3000") && !L.text.includes("src/f3.mjs:5:") && L.text.includes(`"id":"${L.id}"`), "ladder: keeps relevant, hides the rest");
    ok(L && L.text.length < text.length / 4, "ladder: output much smaller");
    ok(expandChunk(L?.id, undefined, "s1") === text && expandChunk(L?.id, "2-3", "other") === grep.slice(1, 3).join("\n"), "expand: full / range / any session");
    ok(/invalid/.test(expandChunk("../../etc/passwd")) && /not found/.test(expandChunk("oabcdef012345")), "expand: id validated");
    let calls = fake.calls;
    ok(await ladder({text: "small\noutput", tool: "bash", request: "x", session: "s1"}) === null && fake.calls === calls, "ladder: small output untouched, no call");
    fake.fail = true;
    ok(await ladder({text: text + "\nother", tool: "bash", request: "x", session: "s1"}) === null, "ladder: Jev error -> untouched");
    fake.fail = false;
    const logged = readFileSync(join(CONFIG.data, "context.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l));
    ok(logged.some(e => e.kind === "ladder" && e.applied) && logged.some(e => e.kind === "ladder" && /HTTP 500/.test(e.error)), "ladder: decisions logged");
    const diffOut = ["diff --git a/x.mjs b/x.mjs", "@@ -1 +1 @@", ...Array(30).fill("+a"), "diff --git a/y.mjs b/y.mjs", "@@ -1 +1 @@", ...Array(30).fill("+b")];
    ok(chunk(diffOut).every(([s, e]) => !diffOut.slice(s + 1, e).some(l => l.startsWith("diff --git"))), "chunk: a diff chunk never spans two files");
    ok(view(["x", "y", "// note", "const SKIP = new Set([1]);", "z", "w"], [[0, 6]], ["short"], ["nothing"]).text.includes("const SKIP"), "view: short outlines definitions");

    // store: private modes, ranges, and a laddered result maps back to its full output
    const sdir = join(CONFIG.data, "chunks", "s1");
    ok((statSync(sdir).mode & 0o777) === 0o700 && (statSync(join(sdir, `${L?.id}.txt`)).mode & 0o777) === 0o600, "store: dir 0700, files 0600");
    ok(expandChunk(L?.id, "0-2", "s1") === grep.slice(0, 2).join("\n"), "expand: range clamped at line 1");
    const src = sourceOf({content: [{type: "text", text: L?.text ?? ""}]}, "s9");
    ok(src.stored && src.id === L?.id && src.text === text, "sourceOf: a laddered result maps back to its stored full output");
    const forged = `something else\n[reflex: 1 of 2 lines shown. expand_chunk {"id":"${L?.id}"} returns the full output.]`;
    ok(!sourceOf({content: [{type: "text", text: forged}]}, "s1").stored, "sourceOf: a note under unrelated text is not trusted");

    // cost model
    const c1 = rebuildCost({tail: 10_000, saving: 8_000, horizon: 4}), c2 = rebuildCost({tail: 10_000, saving: 1_000, horizon: 4});
    ok(c1.worth && !c2.worth && c1.keep === 4000 && c1.rebuild === 3100, "rebuildCost: worth only when saving is large");
    ok(!rebuildCost({tail: 100, saving: 0, horizon: 20}).worth, "rebuildCost: nothing saved");

    // assembly: new request re-levels, same request re-applies the same view without Jev
    const big = (tag, n = 300) => Array.from({length: n}, (_, i) => `${tag} line ${i}`).join("\n");
    const tr = (id, text) => ({role: "toolResult", toolCallId: id, toolName: "bash", content: [{type: "text", text}], isError: false});
    const msgs = [
      {role: "user", content: "list the build files"},
      {role: "assistant", content: [{type: "toolCall", id: "t1", name: "bash", arguments: {}}]}, tr("t1", big("webpack config")),
      {role: "assistant", content: [{type: "toolCall", id: "t2", name: "bash", arguments: {}}]}, tr("t2", big("request timeout retry")),
      {role: "assistant", content: [{type: "text", text: "done"}]},
      {role: "user", content: [{type: "text", text: "now fix the timeout"}]},
    ];
    const frozen = JSON.stringify(msgs), st = {};
    calls = fake.calls;
    const a1 = await assemble(msgs, st, {session: "s2"});
    ok(a1 && a1.length === msgs.length && JSON.stringify(msgs) === frozen, "assemble: new list, input untouched");
    ok(a1 && /hidden for the current request/.test(textOf(a1[2])) && a1[2].toolCallId === "t1", "assemble: irrelevant result stubbed, id kept");
    ok(a1 && /long view/.test(textOf(a1[4])), "assemble: relevant result at long level");
    ok(expandChunk(/"id":"(m[0-9a-f]+)"/.exec(textOf(a1?.[2]))?.[1], undefined, "s2") === big("webpack config"), "assemble: stub expands to the original");
    const a2 = await assemble([...msgs, {role: "assistant", content: [{type: "text", text: "on it"}]}], st, {session: "s2"});
    ok(fake.calls === calls + 1 && JSON.stringify(a2?.slice(0, msgs.length)) === JSON.stringify(a1), "assemble: same request, no Jev call, byte-identical prefix");
    // next request continues the task and saves nothing new: keep the prefix
    fake.same = 0.9;
    const msgs3 = [...msgs, {role: "assistant", content: [{type: "text", text: "fixed"}]}, {role: "user", content: "and the retry timeout?"}];
    const a3 = await assemble(msgs3, st, {session: "s2"});
    ok(fake.calls === calls + 2 && textOf(a3?.[2]) === textOf(a1?.[2]), "assemble: cache kept when rebuilding does not pay");
    const last = readFileSync(join(CONFIG.data, "context.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l)).filter(e => e.kind === "assemble");
    ok(last[0]?.decision === "rebuild" && last[0].same_context === null && last.at(-1)?.decision === "keep" && last.at(-1).same_context === 0.9, "assemble: decisions logged");
    // the cost model says keep (a small result changes before a large one), Jev's topic check decides
    const msgs4 = [{role: "user", content: "a"}, tr("u1", big("webpack config", 120)), tr("u2", big("ESSENTIAL", 3000)), {role: "user", content: "b"}];
    fake.same = 0.9;
    ok(await assemble(msgs4, {sig: "x", query: "old", view: {}}, {session: "s2"}) === undefined, "assemble: same task, cache kept");
    fake.same = 0.1;
    const a4 = await assemble(msgs4, {sig: "x", query: "old", view: {}}, {session: "s2"});
    ok(a4 && /hidden/.test(textOf(a4[1])) && textOf(a4[2]) === textOf(msgs4[2]), "assemble: topic changed, rebuilt despite the cache");
    fake.fail = true;
    ok(await assemble([...msgs3, {role: "user", content: "other"}], {}, {session: "s2"}) === undefined, "assemble: Jev error -> untouched");
    fake.fail = false;
    ok(await assemble([{role: "user", content: "hi"}], {}, {}) === undefined, "assemble: nothing to do");
    fake.same = 0.1;
    const aL = await assemble([{role: "user", content: "a"}, tr("L1", L?.text ?? ""), {role: "user", content: "list the values"}],
                              {sig: "x", query: "old", view: {}}, {session: "s1"});
    ok(aL && textOf(aL[1]).includes(`"id":"${L?.id}"`) && textOf(aL[1]).includes(`(${grep.length} lines)`), "assemble: a laddered result is re-levelled from its stored full output");

    // recall
    const R = await recall({goal: "fix the request timeout", messages: msgs, session: "s3"});
    ok(R && R.text.startsWith("fix the request timeout") && R.text.includes("request timeout retry line 0") && !R.text.includes("webpack config line 5"), "recall: relevant only");

    // retrieval bundle on a throwaway repo
    const repo = join(tmp, "repo");
    mkdirSync(repo);
    const sh = (...a) => execFileSync("git", ["-C", repo, ...a], {stdio: "ignore"});
    sh("init", "-q");
    writeFileSync(join(repo, "parse.mjs"), "export function parseThing(s) {\n  return s.trim();\n}\n");
    writeFileSync(join(repo, "b.mjs"), "import {parseThing} from './parse.mjs';\nconsole.log(parseThing(' x '));\n");
    writeFileSync(join(repo, "c.mjs"), "export const other = 1;\n");
    writeFileSync(join(repo, "d.md"), "Notes: we parse input twice.\n");
    sh("add", ".");
    sh("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init");
    writeFileSync(join(repo, "parse.mjs"), "export function parseThing(s) {\n  return s.trim().toLowerCase();\n}\n");
    const B = await bundle({cwd: repo, goal: "normalise case"});
    ok(B.changed.join() === "parse.mjs" && B.symbols.includes("parseThing") && /toLowerCase/.test(B.diff), "bundle: change, symbols, diff");
    ok(B.judged && B.context.map(c => c.path).join() === "b.mjs" && B.context[0].relevance === "essential" && /console.log/.test(B.context[0].content), "bundle: Jev-rated context");
    ok(!B.context.some(c => c.path === "c.mjs") && B.skipped.includes("d.md"), "bundle: unrelated and irrelevant files left out");
    fake.fail = true;
    const B2 = await bundle({cwd: repo});
    ok(!B2.judged && B2.context.length === 2 && B2.context.every(c => c.relevance === "related"), "bundle: Jev error -> all candidates, unjudged");
    fake.fail = false;
    writeFileSync(join(repo, "e.mjs"), "import {parseThing} from './parse.mjs';\nexport const e = parseThing('E');\n");
    const B3 = await bundle({cwd: repo});
    ok(B3.changed.includes("e.mjs") && /\+export const e = parseThing/.test(B3.diff) && !B3.context.some(c => c.path === "e.mjs"), "bundle: untracked files are part of the change");

    // pruning: by age, then the oldest beyond the size cap; recent chunks survive
    const pd = join(CONFIG.data, "chunks", "old");
    mkdirSync(pd, {recursive: true});
    for (const [n, age] of [["a", 10], ["b", 2], ["c", 1]]) {
      const f = join(pd, `${n}.txt`), t = new Date(Date.now() - age * 86_400_000);
      writeFileSync(f, "x".repeat(600_000));
      utimesSync(f, t, t);
    }
    const p1 = pruneChunks({days: 7, mb: 1000});
    ok(p1.removed === 1 && !existsSync(join(pd, "a.txt")) && existsSync(join(pd, "b.txt")), "prune: by age");
    pruneChunks({days: 7, mb: 1});
    ok(!existsSync(join(pd, "b.txt")) && existsSync(join(pd, "c.txt")) && expandChunk(L?.id, undefined, "s1") === text, "prune: size cap drops the oldest first");
    pruneChunks({days: 0.5, mb: 1});
    ok(!existsSync(pd), "prune: empty session directories removed");

    // reflex-review consumes a bundle with a fake reviewer (never a paid model in tests)
    const bf = writeBundle(B, join(tmp, "bundle.json")), out = join(tmp, "review.md");
    const r = spawnSync(process.execPath, [join(HERE, "scripts/reflex-review"), "--bundle", bf, "--reviewer", "grep -c parseThing", "--out", out],
                        {encoding: "utf8", timeout: 30_000, env: {...ENV, REFLEX_DATA_DIR: CONFIG.data}});
    ok(r.status === 0 && Number(readText(out)) >= 3, `reflex-review: prompt reaches the reviewer (${r.stderr.trim()})`);
    const r2 = spawnSync(process.execPath, [join(HERE, "scripts/reflex-review"), "--bundle", bf, "--reviewer", "exit 3", "--out", out], {encoding: "utf8", timeout: 30_000});
    ok(r2.status === 3, "reflex-review: reviewer failure is reported");

    await adapterCheck(ok, fake, tmp, text);
  } finally {
    server.close();
    rmSync(tmp, {recursive: true, force: true});
  }
  console.log(process.exitCode ? "context selfcheck FAILED" : "context selfcheck OK");
}

// The pi / omp extension, driven with a fake `pi` and fake events, as the agents call it.
async function adapterCheck(ok, fake, tmp, text) {
  let mod;
  process.env.REFLEX_CONTEXT = fileURLToPath(import.meta.url);   // the same module instance, same CONFIG
  try { mod = await import(join(HERE, "adapters/pi-context.ts")); }
  catch (e) { return console.log(`context selfcheck: adapter skipped, this node cannot load .ts (${e.code ?? e.message})`); }
  const handlers = {}, tools = {}, commands = {}, sent = [];
  mod.default({on: (ev, h) => (handlers[ev] = h), registerTool: t => (tools[t.name] = t),
               registerCommand: (n, c) => (commands[n] = c), sendUserMessage: m => sent.push(["pi", m])});
  ok(handlers.tool_result && handlers.context && tools.expand_chunk && commands.fresh, "adapter: registers handlers, tool, command");
  ok(tools.expand_chunk.parameters.required?.includes("id") && tools.expand_chunk.approval === "read", "adapter: expand_chunk schema");
  const branch = [
    {type: "message", message: {role: "user", content: [{type: "text", text: "why does the request time out"}]}},
    {type: "message", message: {role: "assistant", content: [{type: "text", text: "Searching for the timeout."}]}},
  ];
  const ctx = {cwd: tmp, hasUI: false, sessionManager: {getBranch: () => branch, getSessionId: () => "pi-1", getSessionFile: () => "/x.jsonl"},
    ui: {notify: () => {}}, waitForIdle: async () => {},
    newSession: async o => { await o.withSession?.({sendUserMessage: async m => sent.push(["new", m])}); return {cancelled: false}; }};
  const r = await handlers.tool_result({toolName: "bash", toolCallId: "x1", input: {command: "grep"}, content: [{type: "text", text}], isError: false}, ctx);
  const id = /"id":"(o[0-9a-f]+)"/.exec(r?.content?.[0]?.text ?? "")?.[1];
  ok(id && r.content.length === 1 && r.content[0].text.includes("timeoutMs = 3000"), "adapter: tool_result laddered");
  ok(await handlers.tool_result({toolName: "read", toolCallId: "x2", input: {}, content: [{type: "text", text}]}, ctx) === undefined, "adapter: read results untouched");
  const e = await tools.expand_chunk.execute("x3", {id}, undefined, undefined, ctx);
  ok(e.content[0].text === text, "adapter: expand_chunk returns the full output");
  const msgs = [{role: "user", content: "a"}, {role: "toolResult", toolCallId: "y", toolName: "bash", content: [{type: "text", text}]},
                {role: "user", content: "why the timeout"}];
  const c = await handlers.context({type: "context", messages: msgs}, ctx);
  ok(c?.messages?.length === 3 && textOf(c.messages[1]).length < text.length, "adapter: context re-levels earlier output");
  await commands.fresh.handler("fix the request timeout", ctx);
  ok(sent.length === 1 && sent[0][0] === "new" && sent[0][1].startsWith("fix the request timeout"), "adapter: /fresh sends the goal into the new session (pi)");
  ctx.newSession = async () => ({cancelled: false});   // omp: no withSession callback
  await commands.fresh.handler("fix the request timeout", ctx);
  ok(sent.length === 2 && sent[1][0] === "pi", "adapter: /fresh falls back to pi.sendUserMessage (omp)");
  const port = CONFIG.api;
  CONFIG.api = "http://127.0.0.1:9/v1/systemone";   // nothing listens: fail open everywhere
  ok(await handlers.tool_result({toolName: "bash", toolCallId: "x4", input: {}, content: [{type: "text", text: text + "\nz"}]}, ctx) === undefined, "adapter: Jev down -> tool_result untouched");
  const ctx2 = {...ctx, sessionManager: {...ctx.sessionManager, getSessionId: () => "pi-2"}};
  ok(await handlers.context({type: "context", messages: msgs}, ctx2) === undefined, "adapter: Jev down -> context untouched");
  CONFIG.api = port;
  ok(fake.calls > 0, "adapter: went through the fake Jev");
}

// ---------------------------------------------------------------------------------------------
// Live smoke: a real grep of this repo through the ladder. Prints tokens, latency, what was hidden.
async function smoke() {
  const out = execFileSync("git", ["-C", HERE, "grep", "-n", "-i", "-e", "const", "-e", "function", "--", "*.mjs"], {encoding: "utf8"});
  const request = "Where is the Jev request timeout configured, and how is a slow call retried?";
  const t0 = Date.now();
  const L = await ladder({text: out, tool: "bash", input: {command: "git grep -n -i -e const -e function -- '*.mjs'"}, request, session: "smoke"});
  const e = readFileSync(join(CONFIG.data, "context.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l)).filter(x => x.kind === "ladder").at(-1);
  console.log(JSON.stringify({request, lines: out.split("\n").length, chars: out.length, chunks: e?.chunks, levels: e?.levels, shown_lines: e?.shown,
    shown_chars: L?.text.length ?? null, hidden_pct: L ? Math.round(100 * (1 - L.text.length / out.length)) : 0,
    usage: e?.usage, latency_s: e?.latency_s, wall_s: (Date.now() - t0) / 1000, error: e?.error}, null, 1));
  if (L) console.log(`\n--- what the agent sees ---\n${L.text}`);
}

// Live golden set for the ladder: real outputs of this repo at a pinned commit, each with the lines
// the agent must still see. Reports must-keep recall and how much was hidden; exits 1 on a miss.
// About 12 Jev calls, ~6-10k input tokens each.
async function evalContext() {
  const golden = JSON.parse(readFileSync(opt("--golden") ?? join(HERE, "setup/context/golden.json"), "utf8"));
  const only = opt("--only");
  const run = async c => {
    let out = execFileSync("git", ["-C", HERE, ...c.git], {encoding: "utf8", maxBuffer: 64 << 20});
    if (c.strip) out = out.replaceAll(new RegExp(`^${golden.commit}:`, "gm"), "");
    if (c.number) out = out.split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");
    const bad = c.must_keep.filter(k => !out.includes(k));
    if (bad.length) throw new Error(`${c.id}: must_keep not in the output: ${bad.join(" | ")}`);
    const L = await ladder({text: out, tool: "bash", input: {command: c.command}, request: c.request, session: "eval-context"});
    const e = readFileSync(join(CONFIG.data, "context.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l))
      .filter(x => x.kind === "ladder" && x.id === `o${sha(out)}`).at(-1);
    const shown = L?.text ?? out, kept = c.must_keep.filter(k => shown.includes(k));
    return {id: c.id, lines: out.split("\n").length, levels: e?.levels ?? null, applied: !!L, kept: kept.length, want: c.must_keep.length,
            missed: c.must_keep.filter(k => !kept.includes(k)), hidden_pct: Math.round(100 * (1 - shown.length / out.length)),
            tokens: e?.usage?.input_tokens ?? 0, latency_s: e?.latency_s ?? null, error: e?.error ?? null};
  };
  const cases = golden.cases.filter(c => !only || c.id.includes(only)), results = [];
  for (const c of cases) results.push(await run(c));   // one at a time: cases share outputs, the log is matched by output id
  for (const r of results)
    console.log(`${r.missed.length ? "MISS" : "ok  "} ${r.id.padEnd(26)} ${String(r.lines).padStart(5)} lines  hidden ${String(r.hidden_pct).padStart(3)} %  ` +
                `${r.levels ?? "(untouched)"}  ${r.tokens} tok  ${r.latency_s}s${r.error ? "  ERROR " + r.error : ""}${r.missed.length ? "\n     missed: " + r.missed.join(" | ") : ""}`);
  const want = results.reduce((s, r) => s + r.want, 0), kept = results.reduce((s, r) => s + r.kept, 0);
  const mean = k => results.length ? Math.round(results.reduce((s, r) => s + r[k], 0) / results.length) : 0;
  console.log(`\n${results.length} cases · must-keep recall ${kept}/${want} (${Math.round(100 * kept / want)} %) · ` +
              `hidden ${mean("hidden_pct")} % on average · ${results.reduce((s, r) => s + r.tokens, 0)} input tokens · model ${CONFIG.model}`);
  if (kept < want) process.exitCode = 1;
}
// @reflex:setup-only end

const argv = process.argv.slice(2);
const opt = n => { const i = argv.indexOf(n); return i > -1 ? argv[i + 1] : undefined; };
// No top-level await: the selfcheck imports the pi adapter, which imports this module again, and
// that import would wait forever on a module still evaluating.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) (async () => {
  if (argv.includes("--prune")) console.log(JSON.stringify(pruneChunks()));
  else if (argv.includes("--expand")) console.log(expandChunk(opt("--expand"), opt("--lines")));
  else if (argv.includes("--bundle")) console.log(writeBundle(await bundle({base: opt("--base") ?? "HEAD", goal: opt("--goal")}), opt("--out")));
  // @reflex:setup-only begin
  else if (argv.includes("--selfcheck")) await selfcheck();
  else if (argv.includes("--smoke")) await smoke();
  else if (argv.includes("--eval-context")) await evalContext();
  // @reflex:setup-only end
  else console.error("usage: context.mjs --selfcheck | --smoke | --eval-context | --prune | --expand <id> [--lines a-b] | --bundle [--base REF] [--goal T] [--out F]");
})().catch(e => { console.error(`reflex context: ${e.message}`); process.exitCode = 1; });
