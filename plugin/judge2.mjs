#!/usr/bin/env node
// System 2: the stronger model an uncertain decision escalates to in the autonomous profile.
//
// Jev (System 1) resolves the confident majority. A decision that would be `ask` and is not in the
// always-human class (setup/tool-gate/escalation.json) comes here with everything Reflex knows about
// it, redacted, and gets one structured verdict: approve | deny | human, a confidence and a one-line
// reason. autonomy.mjs applies it; this file only asks.
//
// Backends (judge.backend; setup picks one, see scripts/reflex):
//   anthropic          POST <url>/v1/messages, the Messages API (x-api-key, anthropic-version 2023-06-01)
//   openai-compatible  POST <url>/v1/chat/completions: OpenAI, Ollama, vLLM, LM Studio, LiteLLM,
//                      OpenRouter; Authorization: Bearer <key> only when a key is configured
//   none               no System 2: uncertain decisions go to a human
// The Claude Code plugin has no cli backend: it never starts another agent session. There System 2
// is anthropic or openai-compatible, keyed by the judge_api_key option; a saved cli is none (config.mjs).
//
// Everything that is not a strictly valid verdict is `human`: an HTTP or CLI error, a timeout, a
// refusal, a truncated answer, prose around the JSON, an extra key, a confidence outside 0..1, an
// approve below min_confidence, a missing key or CLI, an exhausted daily budget. Never approve.
//
//   node judge2.mjs --probe            is the configured judge reachable (no paid call)
import {accessSync, constants, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync} from "node:fs";
import {createServer} from "node:http";
import {platform, tmpdir} from "node:os";
import {delimiter, join} from "node:path";
import {fileURLToPath} from "node:url";
import {BACKEND_DEFAULTS, CONFIG, append, load, redact, sha} from "./gate.mjs";
import {PLUGIN_MODE, pluginJudgeKey} from "./plugin.mjs";
import {isMain} from "./failsafe.mjs";

const ENV = process.env;
const VERDICTS = ["approve", "deny", "human"];
const LOG = () => join(CONFIG.data, "judge.jsonl");
const BUDGET = () => join(CONFIG.data, "judge-budget.json");
const today = () => new Date().toISOString().slice(0, 10);   // UTC day
const SCHEMA = {type: "object", additionalProperties: false, required: ["verdict", "confidence", "reason"],
  properties: {verdict: {type: "string", enum: VERDICTS}, confidence: {type: "number", minimum: 0, maximum: 1}, reason: {type: "string", maxLength: 200}}};
// Where an HTTP request goes. `url` is the base (https://api.anthropic.com); a trailing /v1 is tolerated.
export const endpoint = (j, path) => `${String(j.url).replace(/\/+$/, "").replace(/\/v1$/, "")}/v1/${path}`;

// The key: the environment variable named in judge.key_env, else the macOS Keychain item named in
// judge.keychain (the same pattern as the TypeSafe key), else none. Never logged or printed.
// In the Claude Code plugin: the System 2 API key plugin option only.
export function judgeKey(j = CONFIG.judge) {
  if (PLUGIN_MODE) return pluginJudgeKey();
  return null;
}
const headers = (j, key) => j.backend === "anthropic"
  ? {"content-type": "application/json", "anthropic-version": "2023-06-01", ...(key && {"x-api-key": key})}
  : {"content-type": "application/json", ...(key && {authorization: `Bearer ${key}`})};

// Strict: the whole answer is one JSON object with exactly verdict, confidence and reason.
// The first JSON object in the answer: a model wraps it in ```json fences or adds prose after it
// despite the instructions (measured). Found by a brace scan that respects strings.
export function firstObject(text) {
  const start = text.indexOf("{");
  if (start < 0) return null;
  let depth = 0, str = false, esc = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (str) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') str = false; continue; }
    if (c === '"') str = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return text.slice(start, i + 1);
  }
  return null;
}
// Strict on what the object holds: exactly verdict, confidence and reason, with valid values.
export function parseVerdict(text) {
  if (typeof text !== "string") return null;
  const t = firstObject(text);
  if (!t) return null;
  let v;
  try { v = JSON.parse(t); } catch { return null; }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  if (Object.keys(v).sort().join() !== "confidence,reason,verdict") return null;
  if (!VERDICTS.includes(v.verdict)) return null;
  if (typeof v.confidence !== "number" || !Number.isFinite(v.confidence) || v.confidence < 0 || v.confidence > 1) return null;
  if (typeof v.reason !== "string" || !v.reason.trim() || v.reason.length > 300 || /[\r\n]/.test(v.reason)) return null;
  return {verdict: v.verdict, confidence: v.confidence, reason: v.reason.trim()};
}

// Budget: per day and per agent session, a count and an estimated cost (usage x judge.price per
// million tokens; a CLI backend counts calls only). A call is reserved before it is made, so
// parallel hooks cannot run far past a cap.
// ponytail: whole-file rewrite, no lock; parallel hooks can undercount by a call or two.
export function budgetState(j = CONFIG.judge, session = null) {
  let b;
  try { b = JSON.parse(readFileSync(BUDGET(), "utf8")); } catch { b = null; }
  if (!b || b.day !== today()) b = {day: today(), calls: 0, usd: 0, sessions: {}};
  b.sessions ??= {};
  const s = session != null ? b.sessions[sha(String(session))] ?? {calls: 0, usd: 0} : null;
  return {...b, calls_left: Math.max(0, j.budget.calls - b.calls), usd_left: Math.max(0, +(j.budget.usd - b.usd).toFixed(4)),
          ...(s && {session: s, session_calls_left: Math.max(0, j.budget.session_calls - s.calls), session_usd_left: Math.max(0, +(j.budget.session_usd - s.usd).toFixed(4))})};
}
function spend(session, calls, usd) {
  const {day, sessions = {}, ...b} = budgetState();
  const key = session != null ? sha(String(session)) : null, s = key ? sessions[key] ?? {calls: 0, usd: 0} : null;
  const next = {day, calls: b.calls + calls, usd: +(b.usd + usd).toFixed(6), sessions: key ? {...sessions, [key]: {calls: s.calls + calls, usd: +(s.usd + usd).toFixed(6)}} : sessions};
  mkdirSync(CONFIG.data, {recursive: true});
  writeFileSync(`${BUDGET()}.${process.pid}`, JSON.stringify(next));
  renameSync(`${BUDGET()}.${process.pid}`, BUDGET());
}
export const estimateCost = (j, usage) => ((usage.input - (usage.cached ?? 0)) * j.price.input + (usage.cached ?? 0) * j.price.input * 0.1 + usage.output * j.price.output) / 1e6;

// ---------------------------------------------------------------------------------------------
// Few tokens per call. The prompt is static (setup/tool-gate/escalation.json) and goes first, so a
// provider's prompt cache can reuse it; the case goes last, assembled to fit judge.max_input_tokens
// (estimated at 4 characters a token): the command, cwd, environment names, System 1's answers, the
// envelope, a one-line intent and only the script lines that matter. What does not fit is cut,
// least useful first, and the cut is said in the context (`trimmed`).
export const estimateTokens = s => Math.ceil(String(s ?? "").length / 4);
export function fit(context, prompt, cap) {
  const c = JSON.parse(JSON.stringify(context)), size = () => estimateTokens(prompt) + estimateTokens(JSON.stringify(c)), trimmed = [];
  const steps = [
    () => { if (c.script?.lines?.length > 4) { c.script.lines = c.script.lines.slice(0, Math.ceil(c.script.lines.length / 2)); return "script lines"; } },
    () => { if (c.envelope?.repo?.length > 200) { c.envelope.repo = `${c.envelope.repo.slice(0, 200)} …`; return "repository envelope"; } },
    () => { if (c.envelope?.user?.length > 300) { c.envelope.user = `${c.envelope.user.slice(0, 300)} …`; return "user envelope"; } },
    () => { if (c.script) { delete c.script; return "script"; } },
    () => { if (c.system1?.answers) { delete c.system1.answers; return "System 1 answers"; } },
    () => { if (c.command?.length > 400) { c.command = `${c.command.slice(0, Math.max(400, c.command.length / 2))} …`; return "command"; } },
  ];
  for (let i = 0; size() > cap && i < 40; i++) {
    const done = steps.map(f => f()).find(Boolean);
    if (!done) break;
    if (!trimmed.includes(done)) trimmed.push(done);
  }
  if (trimmed.length) c.trimmed = trimmed;
  return {context: c, tokens: size(), over: size() > cap};
}

// A command reduced to its shape, for the verdict cache and for fast-lane candidates: the redacted
// text with identifiers that do not decide safety as slots: UUIDs (not after --subscription, --account,
// --tenant or --project, which pick an environment), git-style hex ids of 7+ characters, ISO
// timestamps, and the number of a PR, issue, run, job, build or pipeline. ponytail: names, paths and
// other numbers are NOT slots: `rm -rf build` / `src`, `--replicas=0` / `3`, `chmod 0644` / `0777`,
// `kill 1234` / `5678` and account ids are different decisions.
export const template = command => redact(String(command ?? "")).replace(/\s+/g, " ").trim()
  .replace(/(?<!(?:subscription|account[\w-]*|tenant|project)[= ])\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<id>")
  .replace(/\b\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?\b/g, "<ts>")
  .replace(/\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{7,64}\b/gi, "<hex>")
  .replace(/\b((?:pr|issue|run|job|build|pipeline)\b(?:\s+[a-z-]+)?\s+#?)\d+\b/gi, "$1<n>");

// The verdict cache: <data>/judge-cache.json, {key: {at, verdict, confidence, reason}}. The caller's
// key names everything a verdict depends on (autonomy.mjs: template, cwd, environment, envelope,
// script contents, taint and egress, the policy gate that asked, versions, backend and model).
// Only answers that parsed are kept, never an error, a timeout or a spent budget.
// ponytail: whole-file rewrite of at most 500 entries; parallel hooks can drop one, which costs a call.
const CACHE = () => join(CONFIG.data, "judge-cache.json");
const readCache = () => { try { return JSON.parse(readFileSync(CACHE(), "utf8")); } catch { return {}; } };
function cacheGet(key, j) {
  const e = key && readCache()[key];
  return e && Date.now() - e.at < j.cache_ttl_hours * 3600e3 ? e : null;
}
function cachePut(key, v) {
  if (!key) return;
  try {
    const c = readCache();
    c[key] = {at: Date.now(), verdict: v.verdict, confidence: v.confidence, reason: v.reason};
    mkdirSync(CONFIG.data, {recursive: true});
    writeFileSync(`${CACHE()}.${process.pid}`, JSON.stringify(Object.fromEntries(Object.entries(c).slice(-500))));
    renameSync(`${CACHE()}.${process.pid}`, CACHE());
  } catch { /* a cache that cannot be written only costs a call */ }
}

// ---------------------------------------------------------------------------------------------
// The CLI backend starts another agent CLI, so it is setup-only: the Claude Code plugin never has it.
// There a saved cli backend is none and a cli tier is dropped (config.mjs judgeSettings), and one
// that still got here answers human without a call.
let cliJudge = () => Promise.resolve({error: "no cli", reason: "System 2 has no cli backend in the Claude Code plugin"});

async function runHttp(j, prompt, user, fetchImpl) {
  const key = judgeKey(j);
  // The static prompt first, marked for Anthropic's prompt cache (an OpenAI-compatible server caches
  // a repeated prefix on its own, where it caches at all); the case last. JSON only, a small
  // max_tokens, and no extended thinking (judge.thinking: "disabled"; null leaves the model's default).
  // ponytail: providers only cache prefixes past a model-specific minimum (1,024 tokens or more), which
  // the ~400-token prompt does not reach; the marker costs nothing and applies if the prompt grows.
  const body = j.backend === "anthropic"
    ? {model: j.model, max_tokens: j.max_tokens, system: [{type: "text", text: prompt, cache_control: {type: "ephemeral"}}],
       messages: [{role: "user", content: user}], ...(j.thinking && {thinking: {type: j.thinking}}), ...(j.effort && {output_config: {effort: j.effort}})}
    : {model: j.model, max_tokens: j.max_tokens, messages: [{role: "system", content: prompt}, {role: "user", content: user}]};
  let payload, status;
  try {
    const r = await fetchImpl(endpoint(j, j.backend === "anthropic" ? "messages" : "chat/completions"),
      {method: "POST", headers: headers(j, key), body: JSON.stringify(body), signal: AbortSignal.timeout(j.timeout_ms)});
    status = r.status;
    if (!r.ok) return {error: `HTTP ${r.status}`, reason: `System 2 unavailable (HTTP ${r.status})`};
    payload = await r.json();
  } catch (e) {
    const why = e.name === "TimeoutError" ? "timeout" : e.name;
    return {error: why, reason: `System 2 unavailable (${why})`};
  }
  const u = payload?.usage ?? {};
  const usage = j.backend === "anthropic"
    ? {input: (u.input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0), cached: u.cache_read_input_tokens ?? 0, output: u.output_tokens ?? 0}
    : {input: u.prompt_tokens ?? 0, cached: u.prompt_tokens_details?.cached_tokens ?? 0, output: u.completion_tokens ?? 0};
  // No usage reported: estimate from characters, so the cost cap still counts.
  if (!usage.input && !usage.output) Object.assign(usage, {input: estimateTokens(prompt) + estimateTokens(user), output: 30, estimated: true});
  const refused = j.backend === "anthropic" ? payload?.stop_reason === "refusal" : payload?.choices?.[0]?.finish_reason === "content_filter";
  if (refused) return {error: "refusal", reason: "System 2 answer was a refusal", usage};
  return {usage, status, text: j.backend === "anthropic"
    ? (Array.isArray(payload?.content) ? payload.content.filter(c => c?.type === "text").map(c => c.text).join("") : null)
    : payload?.choices?.[0]?.message?.content};
}

/** The configured judge, or its tiers (judge.tiers: overrides applied in order, cheapest first). */
export const tiersOf = j => (Array.isArray(j.tiers) && j.tiers.length ? j.tiers : [{}]).map((t, i, all) =>
  ({...j, ...(t.backend && t.backend !== j.backend ? BACKEND_DEFAULTS[t.backend] : {}), ...t, budget: j.budget, tier: all.length > 1 ? i + 1 : null, last: i === all.length - 1}));

/**
 * One verdict for one escalated decision. `context` is redacted by the caller and again here.
 * `key`: the verdict cache key (autonomy.mjs); a hit makes no call. `session`: the agent session, for its cap.
 */
export async function judge2(context, {fetchImpl = fetch, call = {}, key = null} = {}) {
  const j = CONFIG.judge, t0 = Date.now(), session = call.session_id ?? null;
  const log = (res, tier) => {
    // hashes, the verdict, the redacted one-line reason and the numbers: never the command or the context
    try {
      append(LOG(), {ts: new Date().toISOString(), backend: tier.backend, ...(tier.backend === "cli" && {cli: tier.cli}), model: tier.model ?? null,
        ...(tier.tier && {tier: tier.tier}), context_sha: sha(context), command_sha: sha(context?.command ?? ""), call_id: call.call_id ?? null,
        verdict: res.verdict, confidence: res.confidence, reason: redact(res.reason).slice(0, 200), error: res.error, usage: res.usage,
        cost_usd: +res.cost_usd.toFixed(6), ...(res.cached && {cached: true}), ...(res.context_tokens && {context_tokens: res.context_tokens}),
        ...(res.reported_usd != null && {reported_usd: res.reported_usd}), latency_s: +((Date.now() - t0) / 1000).toFixed(2)});
    } catch { /* logging must not change a verdict */ }
    return res;
  };
  const blank = {verdict: "human", confidence: 0, reason: "", error: null, usage: {input: 0, cached: 0, output: 0}, cost_usd: 0, backend: j.backend, model: j.model ?? null};
  if (j.backend === "none" || !j.enabled) return log({...blank, error: "off", reason: "System 2 is off"}, j);
  const hit = cacheGet(key, j);
  if (hit) return log({...blank, verdict: hit.verdict, confidence: hit.confidence, reason: hit.reason, cached: true}, j);
  const prompt = load("escalation.json").judge_prompt;
  const {context: fitted, tokens} = fit(scrub(context), prompt, j.max_input_tokens);
  const user = JSON.stringify(fitted);
  let res = blank;
  for (const tier of tiersOf(j)) {
    const b = budgetState(j, session);
    if (b.calls_left <= 0 || b.usd_left <= 0) return log({...blank, error: "budget", reason: `System 2 daily budget used (${b.calls} calls, $${b.usd.toFixed(2)})`}, tier);
    if (b.session_calls_left <= 0 || b.session_usd_left <= 0) return log({...blank, error: "session budget", reason: `System 2 budget for this session used (${b.session.calls} calls)`}, tier);
    if (tier.backend === "anthropic" && !judgeKey(tier)) { res = log({...blank, error: "no key", reason: `no key for System 2 ($${tier.key_env ?? "judge.key_env"} or judge.keychain)`}, tier); continue; }
    // One deadline for the whole call, tiers included, so the hook's timeout (sized from it) is never reached.
    const left = t0 + j.timeout_ms - Date.now();
    if (left < 1000) { res = log({...blank, error: "timeout", reason: "System 2 unavailable (timeout)"}, tier); break; }
    spend(session, 1, 0);
    const timed = {...tier, timeout_ms: Math.min(tier.timeout_ms, left)};
    const r = tier.backend === "cli" ? await cliJudge(timed, prompt, user) : await runHttp(timed, prompt, user, fetchImpl);
    const usage = {cached: 0, ...r.usage ?? {input: 0, output: 0}}, cost_usd = tier.backend === "cli" ? r.reported_usd ?? 0 : estimateCost(tier, usage);
    if (cost_usd) spend(session, 0, cost_usd);
    const extra = {usage, cost_usd, context_tokens: tokens, backend: tier.backend, model: tier.model ?? null, ...(r.reported_usd != null && {reported_usd: r.reported_usd})};
    const v = r.error ? null : parseVerdict(r.text);
    res = r.error ? {...blank, ...extra, error: r.error, reason: r.reason}
      : !v ? {...blank, ...extra, error: "unparsable", reason: `System 2 answer was not a valid verdict${r.status ? ` (HTTP ${r.status})` : ""}`}
      : v.verdict === "approve" && v.confidence < (tier.min_confidence ?? j.min_confidence)
        ? {...blank, ...extra, ...v, verdict: "human", low: true, reason: `System 2 leaned approve at ${v.confidence.toFixed(2)}, below ${tier.min_confidence ?? j.min_confidence}: ${v.reason}`}
      : {...blank, ...extra, ...v};
    log(res, tier);
    // A cheaper tier's deny or confident approve stands; its human, an unsure lean or an error goes up a tier.
    if (tier.last || (!res.error && (res.verdict === "deny" || (res.verdict === "approve" && !res.low)))) break;
  }
  // Only an answer that parsed is remembered; an unsure lean is remembered as the human it became.
  if (!res.error) cachePut(key, res);
  return res;
}
// Every string in the context goes through the shared redaction again: the judge never sees a secret
// the patterns know, even one a caller forgot.
const scrub = v => typeof v === "string" ? redact(v) : Array.isArray(v) ? v.map(scrub)
  : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x)])) : v;

/** Reachability without a paid call: the CLI is on PATH, or GET <url>/v1/models answers (a keyless gateway may say 401). */
export async function probe(j = CONFIG.judge, fetchImpl = fetch) {
  if (j.backend === "none") return {reachable: false, ok: false, status: null, url: null, error: "off"};
  const url = endpoint(j, "models");
  try {
    const r = await fetchImpl(url, {headers: headers(j, judgeKey(j)), signal: AbortSignal.timeout(2500)});
    return {reachable: true, ok: r.ok, status: r.status, url};
  } catch (e) { return {reachable: false, ok: false, status: null, url, error: e.cause?.code ?? e.name}; }
}

// ---------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------

const argv = process.argv.slice(2);
if (isMain(import.meta)) {
  if (argv.includes("--probe")) console.log(JSON.stringify(await probe()));
  else console.error("usage: judge2.mjs --selfcheck | --stub [--approve-all] | --fake-cli <dir> | --probe");
}
