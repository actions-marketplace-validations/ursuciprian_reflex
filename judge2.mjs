#!/usr/bin/env node
// System 2: the stronger model an uncertain decision escalates to in the autonomous profile.
//
// Jev (System 1) resolves the confident majority. A decision that would be `ask` and is not in the
// always-human class (setup/tool-gate/escalation.json) comes here with everything Reflex knows about
// it, redacted, and gets one structured verdict: approve | deny | human, a confidence and a one-line
// reason. autonomy.mjs applies it; this file only asks.
//
// Backends (judge.backend; setup picks one, see scripts/reflex):
// @reflex:setup-only begin
//   cli                an agent CLI that is already installed and signed in, so no extra key:
//                      `claude -p` or `codex exec`, with every tool, MCP server and hook off, in an
//                      empty directory, with Reflex switched off in its environment (no recursion)
// @reflex:setup-only end
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
// @reflex:setup-only begin
//   node judge2.mjs --selfcheck        offline: a stub server on 127.0.0.1 and fake claude / codex executables
//   node judge2.mjs --stub             the stub HTTP judge used by test.mjs (prints its URL)
//   node judge2.mjs --fake-cli <dir>   writes the fake claude and codex executables into <dir>
// @reflex:setup-only end
//   node judge2.mjs --probe            is the configured judge reachable (no paid call)
import {accessSync, constants, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync} from "node:fs";
import {createServer} from "node:http";
// @reflex:setup-only begin
import {execFileSync, spawn, spawnSync} from "node:child_process";
// @reflex:setup-only end
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
// @reflex:setup-only begin

/** An executable on PATH, as an absolute path, or null. */
export function onPath(bin, path = ENV.PATH ?? "") {
  for (const dir of path.split(delimiter).filter(Boolean)) {
    try { accessSync(join(dir, bin), constants.X_OK); return join(dir, bin); } catch { /* next */ }
  }
  return null;
}
// @reflex:setup-only end

// The key: the environment variable named in judge.key_env, else the macOS Keychain item named in
// judge.keychain (the same pattern as the TypeSafe key), else none. Never logged or printed.
// In the Claude Code plugin: the System 2 API key plugin option only.
export function judgeKey(j = CONFIG.judge) {
  if (PLUGIN_MODE) return pluginJudgeKey();
  // @reflex:setup-only begin
  if (j.key_env && ENV[j.key_env]?.trim()) return ENV[j.key_env].trim();
  if (j.keychain && platform() === "darwin") {
    try {
      return execFileSync("security", ["find-generic-password", "-s", j.keychain, "-w"],
                          {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 1500}).trim() || null;
    } catch { /* no item */ }
  }
  // @reflex:setup-only end
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
// @reflex:setup-only begin
// The CLI backend. The judge must not run tools and must not re-enter Reflex:
//   claude  -p --output-format json --tools "" --system-prompt <judge prompt> --strict-mcp-config
//           --settings '{"disableAllHooks":true}' --disable-slash-commands --no-session-persistence
//           --model <pinned, sonnet by default>, plus --bare when the Anthropic key variable is set (--bare
//           never reads a subscription login, so it cannot be used without a key; never in the plugin,
//           which removes that variable)
//   codex   exec --sandbox read-only --ignore-user-config --ignore-rules --ephemeral --skip-git-repo-check
//           --disable shell_tool,unified_exec,hooks,apps,plugins,multi_agent,browser_use,computer_use,
//           image_generation,view_image --output-schema <file> -o <file> [--model m] -
// Both run in a fresh empty directory (a project's own settings, hooks and MCP servers are not
// loaded), with REFLEX_MODE=off, REFLEX_GUARD=off and REFLEX_JUDGE=off in their environment (a Reflex
// hook that still fires does nothing), and the context on stdin. Killed at judge.timeout_ms.
// Lean claude: its own system prompt replaced (--system-prompt), no tool definitions (--tools ""), no
// MCP servers, skills or slash commands, and in the environment no CLAUDE.md, auto memory, git
// instructions, bundled skills, attachments or extended thinking. Measured (claude 2.1.282, a
// subscription login, sonnet): about 3,100 input tokens a call, most of them Claude Code's own floor
// (~2,100 even with --system-prompt) and cached on repeat, ~300 output tokens (hidden reasoning is
// billed; the CLI has no max_tokens), 3 to 4 s, $0.016 first and $0.004 cached at API prices. A naive
// `claude -p` (the user's default model, CLAUDE.md, tools, skills) took 36,826 tokens and $0.28.
// ponytail: the CLAUDE_CODE_DISABLE_* switches are read from claude 2.1.282; a version that drops one
// only costs tokens, never safety (tools and hooks are off by flags the fake CLI in the selfcheck insists on).
const CLAUDE_LEAN = {CLAUDE_CODE_DISABLE_CLAUDE_MDS: "1", CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1", CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS: "1",
  CLAUDE_CODE_DISABLE_BUNDLED_SKILLS: "1", CLAUDE_CODE_DISABLE_ATTACHMENTS: "1", CLAUDE_CODE_DISABLE_THINKING: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"};
const CODEX_OFF = ["shell_tool", "unified_exec", "hooks", "apps", "plugins", "multi_agent", "browser_use", "computer_use", "image_generation", "view_image"];
export function cliArgs(j, prompt, dir) {
  if (j.cli === "codex") {
    return [ "exec", "--sandbox", "read-only", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check", "--color", "never",
      ...CODEX_OFF.flatMap(f => ["--disable", f]), "-c", 'approval_policy="never"', "-c", 'web_search="disabled"',
      "--output-schema", join(dir, "schema.json"), "-o", join(dir, "answer.txt"), ...(j.model ? ["--model", j.model] : []), "-"];
  }
  return ["-p", "--output-format", "json", "--tools", "", "--system-prompt", prompt, "--strict-mcp-config",
    "--settings", JSON.stringify({disableAllHooks: true}), "--disable-slash-commands", "--no-session-persistence",
    "--model", j.model || "sonnet", ...bare()];
}
const bare = () => ENV.ANTHROPIC_API_KEY?.trim() ? ["--bare"] : [];
function runCli(j, prompt, user) {
  const command = j.command ?? onPath(j.cli);
  if (!command) return Promise.resolve({error: "no cli", reason: `${j.cli} is not on PATH`});
  const dir = mkdtempSync(join(tmpdir(), "reflex-judge-"));
  if (j.cli === "codex") writeFileSync(join(dir, "schema.json"), JSON.stringify(SCHEMA));
  // codex takes no system prompt flag: the instructions go first on stdin, the context after them
  const input = j.cli === "codex" ? `${prompt}\n\nThe decision to review:\n${user}` : user;
  const env = {...ENV, REFLEX_MODE: "off", REFLEX_GUARD: "off", REFLEX_JUDGE: "off", REFLEX_QUEUE: "off", REFLEX_CHECKPOINTS: "off", ...(j.cli === "claude" && CLAUDE_LEAN)};
  return new Promise(res => {
    let out = "", done = false;
    const finish = r => { if (done) return; done = true; clearTimeout(timer); rmSync(dir, {recursive: true, force: true}); res(r); };
    const child = spawn(command, cliArgs(j, prompt, dir), {cwd: dir, env, stdio: ["pipe", "pipe", "ignore"]});
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish({error: "timeout", reason: "System 2 unavailable (timeout)"}); }, j.timeout_ms);
    child.stdout.on("data", d => { out += d; if (out.length > 1e6) child.kill("SIGKILL"); });
    child.on("error", e => finish({error: e.code ?? e.name, reason: `System 2 unavailable (${j.cli}: ${e.code ?? e.name})`}));
    child.on("close", code => {
      if (code !== 0) return finish({error: `exit ${code}`, reason: `System 2 unavailable (${j.cli} exited ${code})`});
      if (j.cli === "codex") {
        let text = null;
        try { text = readFileSync(join(dir, "answer.txt"), "utf8"); } catch { /* no answer file */ }
        return finish({text});
      }
      let r;
      try { r = JSON.parse(out); } catch { return finish({text: null}); }
      if (r?.is_error || (r?.subtype && r.subtype !== "success")) return finish({error: "cli error", reason: `System 2 unavailable (${j.cli} reported an error)`});
      finish({text: r?.structured_output ? JSON.stringify(r.structured_output) : r?.result,
              usage: {input: (r?.usage?.input_tokens ?? 0) + (r?.usage?.cache_read_input_tokens ?? 0) + (r?.usage?.cache_creation_input_tokens ?? 0),
                      cached: r?.usage?.cache_read_input_tokens ?? 0, output: r?.usage?.output_tokens ?? 0},
              reported_usd: typeof r?.total_cost_usd === "number" ? r.total_cost_usd : null, duration_ms: r?.duration_ms ?? null,
              models: r?.modelUsage ? Object.keys(r.modelUsage) : null});
    });
    child.stdin.on("error", () => { /* a child that exits early closes its stdin */ });
    child.stdin.end(input);
  });
}
// the checkout run as the plugin (--plugin) never starts an agent CLI either
if (!PLUGIN_MODE) cliJudge = runCli;
// @reflex:setup-only end

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
 * `deadline` (ms since the epoch): the plugin hook's (autonomy.mjs ladder); it only ever shortens judge.timeout_ms.
 */
export async function judge2(context, {fetchImpl = fetch, call = {}, key = null, deadline = null} = {}) {
  const j = CONFIG.judge, t0 = Date.now(), session = call.session_id ?? null;
  const end = Math.floor(Math.min(t0 + j.timeout_ms, deadline ?? Infinity));   // whole ms: AbortSignal.timeout takes an integer
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
    // One deadline for the whole call, tiers included, so the hook's timeout (sized from it, or the
    // plugin's fixed one) is never reached. Under 1 s to the plugin's deadline from the start: no call.
    const left = end - Date.now();
    if (left < 1000) { res = log(deadline != null && deadline - t0 < 1000 ? {...blank, error: "no time", reason: "System 2 not asked: under 1 s left of the plugin hook's time"}
      : {...blank, error: "timeout", reason: "System 2 unavailable (timeout)"}, tier); break; }
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
  // @reflex:setup-only begin
  if (j.backend === "cli") {
    const command = j.command ?? onPath(j.cli);
    let ok = false;
    try { accessSync(command ?? "", constants.X_OK); ok = true; } catch { /* missing */ }
    return {reachable: ok, ok, status: null, url: command ?? j.cli, ...(!ok && {error: "not found"})};
  }
  // @reflex:setup-only end
  const url = endpoint(j, "models");
  try {
    const r = await fetchImpl(url, {headers: headers(j, judgeKey(j)), signal: AbortSignal.timeout(2500)});
    return {reachable: true, ok: r.ok, status: r.status, url};
  } catch (e) { return {reachable: false, ok: false, status: null, url, error: e.cause?.code ?? e.name}; }
}

// ---------------------------------------------------------------------------------------------
// @reflex:setup-only begin
// Test doubles. The verdict follows a marker in the context (the command text): stub:deny,
// stub:human, stub:lowconf, stub:malformed, stub:prose, stub:extra, stub:refusal, stub:slow,
// stub:500; otherwise approve at 0.95. `approveAll` ignores the markers except transport faults:
// the worst judge there could be, which the safety checks and the ladder eval use.
const verdictFor = (text, approveAll, model = "") => {
  const m = /stub:tier/.test(text) ? (/small/.test(model) ? "human" : null) : /stub:(deny|human|lowconf|malformed|prose|extra|refusal|slow|500)/.exec(text)?.[1];
  const mark = approveAll && !["slow", "500"].includes(m) ? null : m;
  const v = {deny: {verdict: "deny", confidence: 0.9, reason: "stub deny: not what the task needs"},
    human: {verdict: "human", confidence: 0.5, reason: "stub human: needs a person"},
    lowconf: {verdict: "approve", confidence: 0.4, reason: "stub approve, unsure"}}[mark] ?? {verdict: "approve", confidence: 0.95, reason: "stub approve: on task and recoverable"};
  const answer = mark === "malformed" ? "{verdict: approve" : mark === "prose" ? `Sure. ${JSON.stringify(v)}`
    : mark === "extra" ? JSON.stringify({...v, verdict: "approve", note: "x"}) : JSON.stringify(v);
  return {mark, answer};
};
// An HTTP judge speaking both wire formats, plus /v1/models. Every request body is kept in `seen`.
export function stubServer({approveAll = false} = {}) {
  const seen = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", d => (raw += d));
    req.on("end", () => {
      const send = (code, obj) => { res.writeHead(code, {"content-type": "application/json"}); res.end(typeof obj === "string" ? obj : JSON.stringify(obj)); };
      if (req.method === "GET" && /\/v1\/models$/.test(req.url)) return send(200, {data: [{id: "stub-judge"}]});
      let body = {};
      try { body = JSON.parse(raw); } catch { return send(400, {error: "bad json"}); }
      seen.push({url: req.url, headers: req.headers, body});
      const {mark, answer} = verdictFor(JSON.stringify(body.messages ?? []), approveAll, body.model);
      const inTok = estimateTokens(JSON.stringify(body.system ?? "")) + estimateTokens(JSON.stringify(body.messages ?? [])), outTok = estimateTokens(answer);
      if (mark === "500") return send(500, {error: "boom"});
      const reply = () => /\/v1\/messages$/.test(req.url)
        ? send(200, {id: "msg_stub", type: "message", role: "assistant", model: body.model, stop_reason: mark === "refusal" ? "refusal" : "end_turn",
                     content: mark === "refusal" ? [] : [{type: "text", text: answer}], usage: {input_tokens: inTok, cache_read_input_tokens: 0, output_tokens: outTok}})
        : send(200, {id: "chatcmpl-stub", object: "chat.completion", model: body.model, choices: [{index: 0, finish_reason: mark === "refusal" ? "content_filter" : "stop",
                     message: {role: "assistant", content: mark === "refusal" ? null : answer}}], usage: {prompt_tokens: inTok, completion_tokens: outTok, total_tokens: inTok + outTok}});
      if (mark === "slow") setTimeout(reply, 3000); else reply();
    });
  });
  return new Promise(res => server.listen(0, "127.0.0.1", () => res({server, seen, port: server.address().port,
    url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(r => { server.closeAllConnections?.(); server.close(r); })})));
}
// Fake `claude` and `codex` executables. They answer like the real CLIs (claude: the -p JSON result
// with structured_output; codex: the last message in the -o file), and refuse, with a non-zero exit,
// to answer when a flag that turns tools or hooks off is missing, when Reflex is not switched off in
// their environment, or when they are started inside the agent's project (anywhere but an empty
// directory). Each call appends {cli, argv, cwd, env flags, stdin} to <dir>/calls.jsonl.
export function writeFakeClis(dir, {approveAll = false} = {}) {
  mkdirSync(dir, {recursive: true});
  const src = cli => `#!${process.execPath}
const fs = require("fs"), path = require("path");
const argv = process.argv.slice(2), dir = ${JSON.stringify(dir)};
let input = ""; try { input = fs.readFileSync(0, "utf8"); } catch {}
const need = ${JSON.stringify(cli === "codex"
    ? [["exec"], ["--sandbox", "read-only"], ["--ignore-user-config"], ["--ephemeral"], ...CODEX_OFF.map(f => ["--disable", f])]
    : [["-p"], ["--tools", ""], ["--strict-mcp-config"], ["--settings", JSON.stringify({disableAllHooks: true})], ["--disable-slash-commands"], ["--model"]])};
const has = a => argv.some((x, i) => a.every((y, k) => argv[i + k] === y));
const missing = need.filter(a => !has(a)).map(a => a.join(" "));
const env = {REFLEX_MODE: process.env.REFLEX_MODE, REFLEX_GUARD: process.env.REFLEX_GUARD, REFLEX_JUDGE: process.env.REFLEX_JUDGE};
const cwdEmpty = fs.readdirSync(process.cwd()).every(f => f === "schema.json");
fs.appendFileSync(path.join(dir, "calls.jsonl"), JSON.stringify({cli: ${JSON.stringify(cli)}, argv, cwd: process.cwd(), env, input}) + "\\n");
if (missing.length || env.REFLEX_MODE !== "off" || env.REFLEX_GUARD !== "off" || !cwdEmpty) {
  process.stderr.write("fake ${cli}: refused: " + JSON.stringify({missing, env, cwdEmpty}) + "\\n"); process.exit(3);
}
const approveAll = ${approveAll};
const m = /stub:(deny|human|lowconf|malformed|prose|slow|500)/.exec(input)?.[1], mark = approveAll && m !== "slow" && m !== "500" ? null : m;
const v = {deny: {verdict: "deny", confidence: 0.9, reason: "fake deny"}, human: {verdict: "human", confidence: 0.5, reason: "fake human"},
  lowconf: {verdict: "approve", confidence: 0.4, reason: "fake unsure"}}[mark] ?? {verdict: "approve", confidence: 0.95, reason: "fake approve"};
const answer = mark === "malformed" ? "{verdict: approve" : mark === "prose" ? "Sure. " + JSON.stringify(v) : JSON.stringify(v);
const reply = () => {
  if (mark === "500") process.exit(1);
  ${cli === "codex"
    ? `fs.writeFileSync(argv[argv.indexOf("-o") + 1], answer); process.stdout.write("done\\n");`
    : `process.stdout.write(JSON.stringify({type: "result", subtype: "success", is_error: false, result: answer,
       ...(mark ? {} : {structured_output: v}), total_cost_usd: 0.01, usage: {input_tokens: 900, output_tokens: 30}}));`}
};
if (mark === "slow") setTimeout(reply, 4000); else reply();
`;
  for (const cli of ["claude", "codex"]) writeFileSync(join(dir, cli), src(cli), {mode: 0o755});
  return dir;
}
// @reflex:setup-only end

// ---------------------------------------------------------------------------------------------
// @reflex:setup-only begin
async function selfcheck() {
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  // strict parsing
  ok(parseVerdict('{"verdict":"approve","confidence":0.9,"reason":"fine"}')?.verdict === "approve", "parse: a valid verdict");
  ok(parseVerdict(' \n{"reason":"r","verdict":"deny","confidence":1}\n')?.verdict === "deny", "parse: key order and surrounding whitespace");
  // what CLI models do despite "JSON only": fences, prose before or after, a brace inside a string
  for (const loose of ['```json\n{"verdict":"approve","confidence":0.9,"reason":"x"}\n```', 'ok {"verdict":"approve","confidence":0.9,"reason":"x"}',
    '{"verdict":"approve","confidence":0.9,"reason":"x"}\n\nThe command only restarts a dev service, so it is safe.', '{"verdict":"approve","confidence":0.9,"reason":"a } b \\" {"}'])
    ok(parseVerdict(loose)?.verdict === "approve", `parse: the first object is found (${loose.slice(0, 30)})`);
  ok(parseVerdict('{"verdict":"deny","confidence":0.9,"reason":"x"} {"verdict":"approve","confidence":1,"reason":"y"}')?.verdict === "deny", "parse: only the first object counts");
  for (const bad of ['{"verdict":"approve","confidence":0.9}', '```json\n{"verdict":"approve","confidence":0.9,"reason":"x","why":"y"}\n```', '{verdict: approve}', '{"verdict":"approve","confidence":0.9,"reason":"x","extra":1}', '{"verdict":"yes","confidence":0.9,"reason":"x"}',
    '{"verdict":"approve","confidence":1.5,"reason":"x"}', '{"verdict":"approve","confidence":"0.9","reason":"x"}', '{"verdict":"approve","confidence":0.9,"reason":""}',
    '{"verdict":"approve","confidence":0.9,"reason":"a\\nb"}', '[1]', "", null, '{"verdict":"approve","confidence":NaN,"reason":"x"}',
    `{"verdict":"approve","confidence":0.9,"reason":"${"x".repeat(301)}"}`])
    ok(parseVerdict(bad) === null, `parse: rejected ${String(bad).slice(0, 40)}`);
  const saved = {...CONFIG, judge: {...CONFIG.judge}}, scratch = join(tmpdir(), `reflex-judge2-${process.pid}`);
  const stub = await stubServer();
  const base = {...saved.judge, enabled: true, model: "stub-model", keychain: null, timeout_ms: 1500, min_confidence: 0.8,
                budget: {calls: 100, usd: 5, session_calls: 40, session_usd: 1}, price: {input: 5, output: 25}};
  // few tokens: the case is assembled under the cap, what is cut is named; a command's shape keeps what decides it
  const bulky = {command: "bash deploy.sh", cwd: "/w", intent: "Deploy.", envelope: {user: "u".repeat(3000), repo: "r".repeat(3000)},
    script: {path: "deploy.sh", lines: [...Array(60)].map((_, i) => `${i + 1}: kubectl apply -f manifests/part-${i}.yaml --context dev`)}, system1: {answers: {blast: 2}}};
  const fitted = fit(bulky, "p".repeat(1600), 1500);
  ok(fitted.tokens <= 1500 && !fitted.over && fitted.context.trimmed.includes("script lines") && fitted.context.command === "bash deploy.sh", `fit: under the cap (${fitted.tokens}), the command kept`);
  const u1 = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0", u2 = "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0";
  ok(template("gh pr merge 1234 && git show 3f5e8a9b1c2d") === template("gh pr merge 5678 && git show 9a8b7c6d5e4f") &&
     template("rm -rf build") !== template("rm -rf src") && template("kubectl scale deploy/a --replicas=0") !== template("kubectl scale deploy/a --replicas=3") &&
     template("chmod 0644 f") !== template("chmod 0777 f") && template("kill -9 1234") !== template("kill -9 5678") &&
     template(`az group delete -n x --subscription ${u1}`) !== template(`az group delete -n x --subscription ${u2}`) &&
     template(`curl https://x/items/${u1}`) === template(`curl https://x/items/${u2}`) && template(`curl -H 'Authorization: Bearer ${"z".repeat(20)}' x`) === template("curl -H 'Authorization: Bearer abc' x"),
     "template: ids become slots; names, paths and small numbers do not; secrets are redacted first");
  const V = async (command, extra = {}) => judge2({command, cwd: "/w", ...extra});
  const tok = ["ghp", "a".repeat(36)].join("_"), aws = `AKIA${"B".repeat(16)}`, pw = "h".repeat(9);
  const secrets = {intent: `use ${aws}`, script: {path: "x.sh", excerpt: `export PASSWORD=${pw}\n`}};
  const clean = s => !s.includes(tok) && !s.includes(aws) && !s.includes(pw);
  try {
    for (const backend of ["openai-compatible", "anthropic"]) {
      rmSync(scratch, {recursive: true, force: true});
      Object.assign(CONFIG, {data: scratch});
      CONFIG.judge = {...base, backend, url: `${stub.url}/v1`, key_env: "REFLEX_SELFCHECK_JUDGE_KEY"};
      // a fake key built at run time; the stub records the headers it got
      const fakeKey = ["sk", "stub", sha(String(process.pid))].join("-");
      ENV.REFLEX_SELFCHECK_JUDGE_KEY = fakeKey;
      const a = await V("terraform apply -target=module.dev");
      ok(a.verdict === "approve" && a.confidence === 0.95 && a.usage.input > 300 && a.usage.input <= CONFIG.judge.max_input_tokens && a.cost_usd > 0, `${backend}: approve with usage and cost (${a.usage.input} tokens in)`);
      const req = stub.seen.at(-1);
      ok(backend === "anthropic" ? req.url === "/v1/messages" && req.headers["x-api-key"] === fakeKey && req.headers["anthropic-version"] === "2023-06-01" &&
           req.body.system[0].cache_control?.type === "ephemeral" && req.body.messages[0].role === "user" && req.body.thinking?.type === "disabled" &&
           req.body.output_config?.effort === "low"
         : req.url === "/v1/chat/completions" && req.headers.authorization === `Bearer ${fakeKey}` && req.body.messages[0].role === "system",
         `${backend}: request shape (endpoint, auth header, the static prompt first and marked for the cache, no thinking)`);
      ok(req.body.max_tokens === 100, `${backend}: a verdict needs about 100 tokens`);
      // the verdict cache: the same key makes no call, an error is never remembered
      const n0 = stub.seen.length, k1 = sha(["selfcheck", backend]);
      const c1 = await judge2({command: "helm upgrade x ./c"}, {key: k1}), c2 = await judge2({command: "helm upgrade x ./c"}, {key: k1});
      ok(c1.verdict === "approve" && c2.cached && c2.verdict === "approve" && stub.seen.length === n0 + 1, `${backend}: a cached verdict makes no call`);
      await judge2({command: "x stub:500"}, {key: sha(["e", backend])}); await judge2({command: "x stub:500"}, {key: sha(["e", backend])});
      ok(stub.seen.length === n0 + 3, `${backend}: an error is not cached`);
      // tiers: the cheap model first; its human (or an unsure lean) goes up, its deny or confident approve stands
      CONFIG.judge.tiers = [{model: "small-model"}, {model: "large-model"}];
      const n1 = stub.seen.length, up = await V("x stub:tier");
      ok(up.verdict === "approve" && stub.seen.slice(n1).map(r => r.body.model).join() === "small-model,large-model", `${backend}: tier 1 said human, tier 2 decided`);
      const n2 = stub.seen.length, stays = await V("x stub:deny");
      ok(stays.verdict === "deny" && stub.seen.length === n2 + 1 && stub.seen.at(-1).body.model === "small-model", `${backend}: tier 1's deny stands, no second call`);
      CONFIG.judge.tiers = null;
      // the per-session cap
      CONFIG.judge.budget = {...CONFIG.judge.budget, session_calls: 1};
      const s1 = await judge2({command: "a"}, {call: {session_id: "cap"}}), s2 = await judge2({command: "b"}, {call: {session_id: "cap"}});
      ok(s1.verdict === "approve" && s2.error === "session budget" && (await judge2({command: "c"}, {call: {session_id: "other"}})).verdict === "approve",
         `${backend}: the session cap stops one session, not the others`);
      CONFIG.judge.budget = {...CONFIG.judge.budget, session_calls: 40};
      ok((await V("x stub:deny")).verdict === "deny" && (await V("x stub:human")).verdict === "human", `${backend}: deny and human verdicts`);
      ok((await V("x stub:prose")).verdict === "approve", `${backend}: prose around a valid verdict still parses`);
      for (const m of ["malformed", "extra", "refusal", "500", "lowconf"]) {
        const r = await V(`x stub:${m}`);
        ok(r.verdict === "human", `${backend}: ${m} -> human (${r.verdict} ${r.error ?? ""})`);
      }
      const slow = await V("x stub:slow");
      ok(slow.verdict === "human" && slow.error === "timeout", `${backend}: timeout -> human`);
      // the plugin hook's deadline only shortens the call; under 1 s left there is no call at all
      const td = Date.now(), cut = await judge2({command: "x stub:slow"}, {deadline: Date.now() + 1100}), nd = stub.seen.length;
      ok(cut.error === "timeout" && Date.now() - td < 1400, `${backend}: a deadline before judge.timeout_ms cuts the call (${Date.now() - td} ms)`);
      const none = await judge2({command: "x"}, {deadline: Date.now() + 900});
      ok(none.verdict === "human" && none.error === "no time" && stub.seen.length === nd, `${backend}: under 1 s to the deadline -> human, no call`);
      // the judge never sees a secret: every string of the context is redacted again
      await V(`deploy --token ${tok}`, secrets);
      ok(clean(JSON.stringify(stub.seen.at(-1).body)), `${backend}: the request carries no secret`);
      // the log holds hashes and the verdict, never the command, the key or the context
      const logged = readFileSync(join(scratch, "judge.jsonl"), "utf8");
      ok(!logged.includes("terraform apply") && !logged.includes(fakeKey) && clean(logged) && /"command_sha"/.test(logged), `${backend}: log has hashes, no content, no key`);
      // budget: the count cap and the cost cap, then human without a call
      const before = stub.seen.length;
      CONFIG.judge.budget = {...CONFIG.judge.budget, calls: budgetState().calls, usd: 5};
      const over = await V("x");
      ok(over.verdict === "human" && over.error === "budget" && stub.seen.length === before, `${backend}: over the count budget -> human, no call`);
      CONFIG.judge.budget = {...CONFIG.judge.budget, calls: 1000, usd: budgetState().usd};
      ok((await V("x")).error === "budget" && stub.seen.length === before, `${backend}: over the cost budget -> human, no call`);
      CONFIG.judge.budget = {...CONFIG.judge.budget, calls: 1000, usd: 5};
      CONFIG.judge.url = "http://127.0.0.1:9";
      ok((await V("x")).verdict === "human", `${backend}: unreachable -> human`);
      ok(!(await probe()).reachable, `${backend}: probe says unreachable`);
      CONFIG.judge.url = stub.url;
      const p = await probe();
      ok(p.reachable && p.ok && p.url.endsWith("/v1/models"), `${backend}: probe uses the free models endpoint`);
      delete ENV.REFLEX_SELFCHECK_JUDGE_KEY;
      if (backend === "anthropic") ok((await V("x")).error === "no key", "anthropic: no key -> human without a call");
      else { await V("x"); ok(!stub.seen.at(-1).headers.authorization, "openai-compatible: a keyless endpoint gets no Authorization header"); }
    }
    // the CLI backend, against fake claude and codex executables
    const bin = writeFakeClis(join(scratch, "bin")), calls = () => readFileSync(join(bin, "calls.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l));
    for (const cli of ["claude", "codex"]) {
      CONFIG.judge = {...base, backend: "cli", cli, command: join(bin, cli), model: null, timeout_ms: 2500};
      ENV.REFLEX_MODE = "enforce";   // what a hook process has: the child must still get off
      const a = await V("helm upgrade api ./chart -n dev", secrets);
      const c = calls().at(-1);
      ok(a.verdict === "approve" && a.cost_usd === (cli === "claude" ? 0.01 : 0) && budgetState().calls >= 1, `${cli}: approve through the CLI; calls counted, the CLI's own cost when it reports one (${a.error ?? ""})`);
      ok(c.env.REFLEX_MODE === "off" && c.env.REFLEX_GUARD === "off" && c.env.REFLEX_JUDGE === "off" && c.cwd.includes("reflex-judge-") && c.input.includes("helm upgrade api"),
         `${cli}: no recursion: Reflex off in the child, which runs in an empty directory with the context on stdin`);
      ok(cli === "claude" ? c.argv.includes("--system-prompt") && c.argv[c.argv.indexOf("--tools") + 1] === "" && c.argv[c.argv.indexOf("--model") + 1] === "sonnet" &&
                            c.argv.includes("--bare") === !!ENV.ANTHROPIC_API_KEY?.trim()
                          : c.argv.includes("--output-schema") && c.argv.includes("shell_tool") && c.input.startsWith("You are the second-stage reviewer"),
         `${cli}: no tools, and the verdict schema is passed`);
      ok(clean(JSON.stringify(c)), `${cli}: the CLI sees no secret`);
      for (const m of ["deny", "human"]) ok((await V(`x stub:${m}`)).verdict === m, `${cli}: ${m}`);
      for (const m of ["malformed", "lowconf", "500"]) ok((await V(`x stub:${m}`)).verdict === "human", `${cli}: ${m} -> human`);
      ok((await V("x stub:prose")).verdict === "approve", `${cli}: prose around a valid verdict still parses`);
      const t = Date.now(), slow = await V("x stub:slow");
      ok(slow.verdict === "human" && slow.error === "timeout" && Date.now() - t < 3500, `${cli}: killed at the timeout -> human`);
      CONFIG.judge = {...CONFIG.judge, command: "/nonexistent/claude"};
      ok((await V("x")).verdict === "human" && !(await probe()).reachable, `${cli}: a missing CLI -> human, and probe says so`);
      delete ENV.REFLEX_MODE;
    }
    // the fakes enforce the switches: without them (or with Reflex on) they refuse, which is human
    for (const cli of ["claude", "codex"]) {
      const bare = spawnSync(join(bin, cli), cli === "codex" ? ["exec", "-"] : ["-p"], {cwd: scratch, env: {...ENV, REFLEX_MODE: "enforce"}, encoding: "utf8", input: "{}"});
      ok(bare.status === 3 && /refused/.test(bare.stderr), `fake ${cli} refuses a call with tools or hooks on, so a regression in cliArgs shows up as human`);
    }
    CONFIG.judge = {...base, backend: "none", enabled: false};
    ok((await V("x")).error === "off" && (await probe()).error === "off", "none: no System 2, no call");
  } finally {
    await stub.close();
    Object.assign(CONFIG, saved);
    rmSync(scratch, {recursive: true, force: true});
  }
  console.log(process.exitCode ? "judge2 selfcheck FAILED" : "judge2 selfcheck OK");
}
// @reflex:setup-only end

const argv = process.argv.slice(2);
if (isMain(import.meta)) {
  if (argv.includes("--probe")) console.log(JSON.stringify(await probe()));
  // @reflex:setup-only begin
  else if (argv.includes("--stub")) console.log((await stubServer({approveAll: argv.includes("--approve-all")})).url);
  else if (argv.includes("--fake-cli")) console.log(writeFakeClis(argv[argv.indexOf("--fake-cli") + 1], {approveAll: argv.includes("--approve-all")}));
  else if (argv.includes("--selfcheck")) await selfcheck();
  // @reflex:setup-only end
  else console.error("usage: judge2.mjs --selfcheck | --stub [--approve-all] | --fake-cli <dir> | --probe");
}
