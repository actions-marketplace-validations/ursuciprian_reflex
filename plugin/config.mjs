// The gate's settings (gate.mjs): config.json, the environment and the hook flags, their validation,
// and secret redaction. Imported first by the other gate modules; imports none of them.
import {PLUGIN_FLAG, PLUGIN_MODE, pluginKey, PLUGIN_ERROR} from "./plugin.mjs";
import {readFileSync, existsSync} from "node:fs";
import {createHash} from "node:crypto";
import {homedir} from "node:os";
import {dirname, join} from "node:path";
import {isatty} from "node:tty";
import {fileURLToPath} from "node:url";
import {infraError} from "./infra.mjs";
import {parseFreeze} from "./freeze.mjs";
import {notifyTarget} from "./notify.mjs";
import {resolveProvider, providerUrl, hostOf} from "./providers.mjs";

export const HERE = dirname(fileURLToPath(import.meta.url));
export const ENV = process.env;
const flagValue = (n, d) => process.argv.includes(n) ? process.argv[process.argv.indexOf(n) + 1] : d;
// Machine-wide settings written by `install.mjs --keychain` (~/.config/reflex/config.json), so every
// hook sees them whichever agent started it. The environment still wins.
export const USER_CONFIG_FILE = join(ENV.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "reflex/config.json");
export let USER_CONFIG_ERROR = null;
export const USER_CONFIG = (() => {
  try {
    const value = JSON.parse(readFileSync(USER_CONFIG_FILE, "utf8"));
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("expected a JSON object");
    return value;
  } catch (e) { if (e.code !== "ENOENT") USER_CONFIG_ERROR = `invalid ${USER_CONFIG_FILE}: ${e.message}`; return {}; }
})();
// System 2 (judge2.mjs). `backend`: cli (an agent CLI already installed and signed in: claude or
// codex, no extra key), anthropic (Messages API), openai-compatible (any /v1/chat/completions
// endpoint: OpenAI, Ollama, vLLM, LM Studio, LiteLLM, OpenRouter), none. A per-day cap of 200 calls
// or $5 (price: USD per million input / output tokens, for the estimate; a CLI counts calls only).
export const ENGINES = ["local", "jev", "laya"];
export const JUDGE_BACKENDS = ["cli", "anthropic", "openai-compatible", "none"];
// Spend is small by design: a case assembled to max_input_tokens, a JSON verdict in max_tokens, no
// extended thinking, a verdict cache, optional cheaper tiers first (judge.tiers), per-day and
// per-session caps, and a breaker that pauses System 2 when the last hour escalated too much.
export const JUDGE_DEFAULTS = {backend: "none", url: null, model: null, key_env: null, keychain: null, timeout_ms: 20000, max_tokens: 100,
  max_input_tokens: 1500, thinking: "disabled", effort: "low", min_confidence: 0.8, cache_ttl_hours: 12, tiers: null,
  budget: {calls: 200, usd: 5, session_calls: 40, session_usd: 1}, price: {input: 5, output: 25},
  breaker: {rate: 0.3, window_minutes: 60, min_decisions: 20}};
// Keyless (engine local): no Jev, so every command the rules, the read-only list and the fast lane do
// not cover goes to System 2. Measured on 14,445 real Bash commands: 62 % of all of them, about 90 %
// of the ones the ladder judges, 115 calls on a median active day and 294 at p90. The breaker's 30 %
// would stay open (it guards against a Jev outage or a noisy policy, neither of which exists here),
// so it is off and the caps bound the spend: 300 calls a day covers nine days in ten.
export const KEYLESS_JUDGE_DEFAULTS = {budget: {calls: 300, session_calls: 100, session_usd: 2}, breaker: {rate: 1}};
export const BACKEND_DEFAULTS = {cli: {cli: "claude", model: "sonnet"}, anthropic: {url: "https://api.anthropic.com", model: "claude-sonnet-5"},
  "openai-compatible": {}, none: {}};
// The anthropic backend's key variable. The plugin takes the System 2 key from its option only (judge2.mjs judgeKey).
export const QUEUE_DEFAULTS = {ttl_hours: 24, notify: null};
// The runaway guard (autonomy.mjs): stops a session that loops, storms the gate, burns through
// commands or spend, or climbs in risk. Tuned on 14 days of real sessions (docs/GUIDE.md) so that
// normal work, a long test-fix cycle included, never trips it. On unless config.json or
// REFLEX_RUNAWAY=off turns it off; it follows the mode: shadow logs, enforce denies.
export const RUNAWAY_DEFAULTS = {loop: {repeats: 10, read_only_repeats: 20, failures: 8, window_minutes: 5}, storm: {denies: 8, window_minutes: 5},
  burn: {per_minute: 50, jev_calls: 2000, system2_calls: 150}, escalation: {steps: 4, rise: 1, at: 2.5, window_minutes: 15}};
export function runawaySettings(saved = {}, env) {
  const s = saved && typeof saved === "object" ? saved : {};
  if (env === undefined && saved === false) env = "off";
  return {...Object.fromEntries(Object.entries(RUNAWAY_DEFAULTS).map(([k, v]) => [k, {...v, ...s[k]}])),
          enabled: env === "on" ? true : env === "off" ? false : env !== undefined ? env : s.enabled ?? true};
}
// Claude Code plugin (hooks/hooks.json passes --plugin). `reflex setup` writes the same hooks into
// the user's Claude Code settings; when those are there, they win and every plugin hook exits at
// once, so no call is judged or counted twice. This is the user settings file Claude Code reads
// (install.mjs writes ~/.claude/settings.json, which is that file unless CLAUDE_CONFIG_DIR is set).
// A hook counts only when the script it names exists: a stale entry from a deleted checkout fails
// in Claude Code, so the plugin must not stand down for it.
export const CLAUDE_SETTINGS = join(ENV.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"), "settings.json");
// The Codex CLI plugin (hooks/codex.json, also --plugin) does the same against the hooks file Codex
// reads, $CODEX_HOME/hooks.json, which is the ~/.codex/hooks.json install.mjs writes unless CODEX_HOME is set.
export const CODEX_HOOKS = join(ENV.CODEX_HOME || join(homedir(), ".codex"), "hooks.json");
const reflexHook = agent => new RegExp(String.raw`(?:"((?:[^"\\]|\\.)*?(?:gate|guard|instructions)\.mjs)"|'([^']*?(?:gate|guard|instructions)\.mjs)'|(\S*(?:gate|guard|instructions)\.mjs))\s+--${agent}(?:-post|-prompted|-prompt)?(?=\s|$)`);
/** Reflex hooks in an agent's hooks file: `live` scripts exist, `stale` ones do not. Plugin hooks are not counted. */
export function settingsHooks(file = CLAUDE_SETTINGS, agent = "claude") {
  const live = [], stale = [], hook = reflexHook(agent);
  try {
    for (const g of Object.values(JSON.parse(readFileSync(file, "utf8")).hooks ?? {}).flat())
      for (const h of g?.hooks ?? []) {
        const m = typeof h?.command === "string" && !/\s--plugin(\s|$)/.test(h.command) && h.command.match(hook);
        if (!m) continue;
        const script = m[1]?.replace(/\\(.)/g, "$1") ?? m[2] ?? m[3];
        (existsSync(script) ? live : stale).push(script);
      }
  } catch { /* no settings file, or not JSON: nothing installed there */ }
  return {live: [...new Set(live)], stale: [...new Set(stale)]};
}
export const settingsHooksInstalled = (file, agent) => settingsHooks(file, agent).live.length > 0;
export const PLUGIN = PLUGIN_FLAG;
const CODEX_PLUGIN = PLUGIN && process.argv.some(a => /^--codex(-|$)/.test(a));
// The PreToolUse matchers of the live Reflex gate hooks in an agent's hooks file, and whether one
// of them covers a tool: a hook `reflex setup` wrote before the tool gate matched Bash|Task|Agent
// only, so the plugin must still judge MCP tools and file writes for it.
export function settingsCovers(file, agent, tool) {
  const hook = reflexHook(agent);
  try {
    return (JSON.parse(readFileSync(file, "utf8")).hooks?.PreToolUse ?? []).some(g => (g?.hooks ?? []).some(h => {
      const m = typeof h?.command === "string" && !/\s--plugin(\s|$)/.test(h.command) && h.command.match(hook);
      return m && !/--\w+-(post|prompted|prompt)\b/.test(m[0]) && existsSync(m[1]?.replace(/\\(.)/g, "$1") ?? m[2] ?? m[3]);
    }) && matcherCovers(g.matcher, tool));
  } catch { return false; }
}
// Claude Code and Codex: no matcher, "" or "*" match every tool, a list of names matches exactly, anything else is a regex.
const matcherCovers = (m, tool) => !m || m === "*" || (/^[\w|]+$/.test(m) ? m.split("|").includes(tool) : (() => { try { return new RegExp(m).test(tool); } catch { return false; } })());
// Standing down, read the input first: an agent writing a large tool result must not get EPIPE.
// The PreToolUse gate stands down only when the settings hook covers this tool; the input it read is kept for it.
export let STDIN = null;
if (PLUGIN && process.argv.some(a => /^--(claude|codex)(-|$)/.test(a)) && (CODEX_PLUGIN ? settingsHooksInstalled(CODEX_HOOKS, "codex") : settingsHooksInstalled())) {
  // isatty, not process.stdin.isTTY: touching process.stdin makes a pipe non-blocking and the read fails with EAGAIN
  if (!isatty(0)) try { STDIN = readFileSync(0, "utf8"); } catch { /* nothing to read */ }
  const pre = process.argv.some(a => a === "--claude" || a === "--codex");
  let tool = null;
  try { tool = JSON.parse(STDIN ?? "{}").tool_name ?? null; } catch { /* not JSON: the hook's own parse answers */ }
  if (!pre || !tool || settingsCovers(CODEX_PLUGIN ? CODEX_HOOKS : CLAUDE_SETTINGS, CODEX_PLUGIN ? "codex" : "claude", tool)) process.exit(0);
}
// With no saved engine the gate starts where a fresh `reflex setup` does: local, no key needed, or
// Jev when a TypeSafe key is in the environment, or a Keychain item or an earlier install is
// recorded. The Claude Code plugin starts local too, or Jev when its options hold a key.
// Which provider carries Jev (providers.mjs): TypeSafe direct, OpenRouter, Cloudflare, Vercel or a
// compatible endpoint, from REFLEX_PROVIDER, config.json "provider" or the keys in the environment.
export const PROVIDER = resolveProvider(ENV, USER_CONFIG);
// The Claude Code plugin: jev when its options hold a key, else local (no Keychain, no environment).
export const ENGINE = ENV.REFLEX_ENGINE ?? flagValue("--engine", USER_CONFIG.engine ?? (PLUGIN_MODE ? (pluginKey() ? "jev" : "local") :
  (PROVIDER.detected || USER_CONFIG.provider || USER_CONFIG.keychain ||
   Object.keys(USER_CONFIG.agents ?? {}).length ? "jev" : "local")));
// engine laya: the same questions and policy as Jev, answered by a Laya checkpoint served on this
// machine (setup/laya/server.py, `reflex laya start`); nothing leaves it and no key is needed.
export const LAYA_DEFAULTS = {port: 8421, model: "typed-decisions"};
export const LAYA_CHECKPOINTS = ["english", "multilingual", "typed-decisions"];
export const layaUrl = port => `http://127.0.0.1:${port}/v1/systemone`;
// The local token the Laya server requires (laya.mjs writes it); beside config.json, so every
// process of this user finds it whatever its REFLEX_DATA_DIR.
export const LAYA_TOKEN = () => join(dirname(USER_CONFIG_FILE), "laya.token");
export const LAYA = {...LAYA_DEFAULTS, ...USER_CONFIG.laya};
export const CONFIG = {
  api: ENV.REFLEX_API_URL ?? (ENGINE === "laya" ? layaUrl(LAYA.port) : providerUrl(PROVIDER.name, PROVIDER.settings)),
  provider: PROVIDER.name,
  model: ENV.REFLEX_MODEL ?? (ENGINE === "laya" ? LAYA.model : "jev-1.13.0"),   // pinned so a decision can be reproduced
  // off | shadow | enforce. The environment wins, so one session can be switched for a test;
  // otherwise the --mode flag that install.mjs writes into each agent's hook command.
  mode: ENV.REFLEX_MODE ?? flagValue("--mode", USER_CONFIG.mode ?? "shadow"),
  engine: ENGINE,
  // off | shadow | on: what a policy "allow" becomes. off: pass, the gate only tightens.
  // shadow: logged as would_allow, effective pass. on: effective allow, in enforce mode only.
  allow: ENV.REFLEX_ALLOW ?? flagValue("--allow", USER_CONFIG.allow ?? "off"),
  setup: ENV.REFLEX_SETUP_DIR ?? join(HERE, "setup/tool-gate"),
  data: ENV.REFLEX_DATA_DIR ?? join(ENV.XDG_STATE_HOME ?? join(homedir(), ".local/state"), "reflex"),
  timeoutMs: Number(ENV.REFLEX_TIMEOUT_MS ?? 3000),
  // The TypeSafe Keychain item; the plugin never reads the Keychain.
  // The escalation ladder (autonomous profile, autonomy.mjs): System 2, the async human queue and
  // checkpoints. Off unless config.json turns them on; REFLEX_JUDGE / REFLEX_QUEUE / REFLEX_CHECKPOINTS
  // (on | off) override for one session (`reflex run` turns them off: a human is at the terminal).
  profile: USER_CONFIG.profile ?? "supervised",
  judge: judgeSettings(USER_CONFIG.judge, ENV.REFLEX_JUDGE, ENGINE),
  queue: {...QUEUE_DEFAULTS, ...USER_CONFIG.queue, enabled: onOff(ENV.REFLEX_QUEUE, USER_CONFIG.queue?.enabled)},
  checkpoints: onOff(ENV.REFLEX_CHECKPOINTS, USER_CONFIG.checkpoints),
  runaway: runawaySettings(USER_CONFIG.runaway, ENV.REFLEX_RUNAWAY),
  // change freezes (freeze.mjs) and the decision webhook (notify.mjs), both from config.json only
  freeze: parseFreeze(USER_CONFIG.freeze, "config.json freeze"),
  notify: notifyTarget(USER_CONFIG.notify, "config.json notify"),
  // MCP tool calls the rules do not cover (tools.mjs): "shadow" logs them (Jev judges them when
  // enforcing with a key), "ask" asks in every mode. config.json only.
  // infra (default on): an unknown tool on a cloud, cluster, IaC or database server (gate.mjs mcpInfraServer)
  // goes to the engine when there is one and asks keyless, instead of only being logged.
  mcp: {unknown: USER_CONFIG.mcp?.unknown ?? "shadow", infra: USER_CONFIG.mcp?.infra ?? true},
  // The keyless workspace allowlist (workspace.mjs): a few exact in-tree command shapes pass with a
  // checkpoint first. On unless REFLEX_WORKSPACE=off or config.json "workspace": false.
  workspace: onOff(ENV.REFLEX_WORKSPACE, USER_CONFIG.workspace ?? true),
};
// The one host the provider's key may go to (authorization()): where its endpoint was configured.
CONFIG.keyHost = hostOf(CONFIG.api);
/** Saved judge settings with the backend's (and, keyless, the engine's) defaults filled in; `enabled` unless the backend is none or REFLEX_JUDGE=off.
 * config.json "judge": "off" is the opt-out from human-last: no System 2, and `reflex setup` does not pick one again. */
export function judgeSettings(saved = {}, env, engine = "jev") {
  if (saved === "off") saved = {backend: "none"};
  const backend = saved?.backend ?? JUDGE_DEFAULTS.backend, s = saved ?? {}, k = engine === "local" ? KEYLESS_JUDGE_DEFAULTS : {};
  return {...JUDGE_DEFAULTS, ...BACKEND_DEFAULTS[backend], ...s, backend, budget: {...JUDGE_DEFAULTS.budget, ...k.budget, ...s.budget},
          price: {...JUDGE_DEFAULTS.price, ...s.price}, breaker: {...JUDGE_DEFAULTS.breaker, ...k.breaker, ...s.breaker},
          enabled: env === undefined || env === "on" ? backend !== "none" : env === "off" ? false : env};
}
function onOff(env, saved) { return env === undefined ? saved === true : env === "on" ? true : env === "off" ? false : env; }
// Functions, not constants, so the self-check can point the whole gate at a scratch directory.
export const TRACE = () => join(CONFIG.data, "trace.jsonl");
export const FEEDBACK = () => join(CONFIG.data, "feedback.jsonl");
export const CACHE = () => join(CONFIG.data, "cache.json");
export const CACHE_TTL_MS = 24 * 3600 * 1000;
export const ROTATE_BYTES = 50 * 1024 * 1024;
export function configurationError() {
  return USER_CONFIG_ERROR ?? PLUGIN_ERROR ?? (!ENGINES.includes(CONFIG.engine) ? "engine must be local, jev or laya"
    : CONFIG.engine === "jev" && PROVIDER.error ? PROVIDER.error
    : !["off", "shadow", "enforce"].includes(CONFIG.mode) ? "mode must be off, shadow or enforce"
    : !["off", "shadow", "on"].includes(CONFIG.allow) ? "allow must be off, shadow or on"
    : ![undefined, "simple", "legacy"].includes(ENV.REFLEX_READONLY ?? USER_CONFIG.readonly) ? "readonly must be simple or legacy"
    : typeof CONFIG.workspace !== "boolean" || ![undefined, true, false].includes(USER_CONFIG.workspace) ? "workspace must be on or off (config.json true or false)" : layaError() ?? ladderError() ?? infraError(USER_CONFIG.infra) ?? toolError());
}
// Invalid tool gate settings ask, like any invalid configuration.
function toolError() {
  const m = USER_CONFIG.mcp, p = USER_CONFIG.protected;
  if (m !== undefined && (!m || typeof m !== "object" || Array.isArray(m) || Object.keys(m).some(k => !["unknown", "infra"].includes(k)) ||
      !["shadow", "ask", undefined].includes(m.unknown) || (m.infra !== undefined && typeof m.infra !== "boolean")))
    return 'mcp takes only "unknown": "shadow" | "ask" and "infra": true | false';
  if (p !== undefined && (!Array.isArray(p) || p.some(g => typeof g !== "string" || !g.trim() || g.length > 200)))
    return "protected must be a list of globs";
  return null;
}
// engine laya promises that nothing leaves the machine: a loopback URL, a known checkpoint, a sane port.
function layaError() {
  if (CONFIG.engine !== "laya") return null;
  const s = USER_CONFIG.laya ?? {}, url = (() => { try { return new URL(CONFIG.api); } catch { return null; } })();
  const names = String(s.models ?? CONFIG.model).split(",").map(n => n.trim());
  if (typeof s !== "object" || Array.isArray(s)) return "laya must be an object";
  if (s.port !== undefined && !(Number.isInteger(s.port) && s.port > 0 && s.port < 65536)) return "laya.port must be a port number";
  if (!url || url.protocol !== "http:" || !["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)) return "engine laya: the server URL must be http on 127.0.0.1";
  if (![CONFIG.model, ...names].every(n => LAYA_CHECKPOINTS.includes(n))) return `laya: the checkpoint must be one of ${LAYA_CHECKPOINTS.join(", ")}`;
  if (s.device !== undefined && !["auto", "cpu", "mps", "cuda"].includes(s.device)) return "laya.device must be auto, cpu, mps or cuda";
  if (s.noul !== undefined && !["choice", "native"].includes(s.noul)) return "laya.noul must be choice or native";
  return null;
}
// Invalid ladder settings ask, like any invalid configuration: a typo must not turn System 2 into an approver.
function ladderError() {
  const j = CONFIG.judge, q = CONFIG.queue, num = (v, lo, hi = Infinity) => typeof v === "number" && Number.isFinite(v) && v >= lo && v <= hi;
  const sj = USER_CONFIG.judge;
  if (sj !== undefined && sj !== "off" && (!sj || typeof sj !== "object" || Array.isArray(sj))) return 'judge must be "off" or the System 2 settings';
  for (const [k, v] of [["judge", j.enabled], ["queue", q.enabled], ["checkpoints", CONFIG.checkpoints], ["runaway", CONFIG.runaway.enabled]])
    if (typeof v !== "boolean") return `${k} must be on or off`;
  const r = CONFIG.runaway;
  if (!Object.entries(RUNAWAY_DEFAULTS).every(([k, v]) => r[k] && typeof r[k] === "object" && Object.keys(v).every(f => num(r[k][f], f === "rise" || f === "at" ? 0 : 1))))
    return `runaway: ${Object.entries(RUNAWAY_DEFAULTS).map(([k, v]) => `${k}.{${Object.keys(v).join(",")}}`).join(", ")} must be positive numbers`;
  if (!["supervised", "autonomous"].includes(CONFIG.profile)) return "profile must be supervised or autonomous";
  if (!num(q.ttl_hours, 0.01) || (q.notify != null && typeof q.notify !== "string")) return "queue.ttl_hours must be a positive number and queue.notify a command";
  if (!JUDGE_BACKENDS.includes(j.backend)) return `judge.backend must be one of ${JUDGE_BACKENDS.join(", ")}`;
  if (!j.enabled) return null;
  if (j.backend === "cli") {
    if (!["claude", "codex"].includes(j.cli)) return "judge.cli must be claude or codex";
    if (j.command != null && (typeof j.command !== "string" || !j.command.startsWith("/"))) return "judge.command must be an absolute path";
    if (j.model != null && (typeof j.model !== "string" || !/^[\w.:\/-]+$/.test(j.model))) return "judge.model must be a model name";
  } else {
    let url;
    try { url = new URL(j.url); } catch { return `judge.url must be a URL (the ${j.backend} endpoint)`; }
    if (!/^https?:$/.test(url.protocol)) return "judge.url must be http or https";
    if (typeof j.model !== "string" || !j.model) return "judge.model must be a model name";
  }
  if (!num(j.timeout_ms, 100) || !num(j.max_tokens, 16) || !num(j.max_input_tokens, 200) || !num(j.min_confidence, 0, 1) || !num(j.cache_ttl_hours, 0) ||
      !["calls", "usd", "session_calls", "session_usd"].every(k => num(j.budget[k], 0)) || !num(j.price.input, 0) || !num(j.price.output, 0) ||
      !num(j.breaker.rate, 0, 1) || !num(j.breaker.window_minutes, 1) || !num(j.breaker.min_decisions, 1))
    return "judge: timeout_ms, max_tokens, max_input_tokens, min_confidence, cache_ttl_hours, budget, price and breaker must be numbers in range";
  if (j.tiers != null && (!Array.isArray(j.tiers) || j.tiers.some(t => !t || typeof t !== "object" || (t.backend && !JUDGE_BACKENDS.includes(t.backend)) ||
      (t.min_confidence != null && !num(t.min_confidence, 0, 1)))))
    return "judge.tiers must be a list of overrides ({model, backend, url, min_confidence, ...}), cheapest first";
  if (j.thinking != null && !["disabled", "adaptive"].includes(j.thinking)) return "judge.thinking must be disabled, adaptive or null";
  return null;
}
export const sha = v => createHash("sha256").update(typeof v === "string" ? v : JSON.stringify(v)).digest("hex").slice(0, 12);
export const readText = p => { try { return readFileSync(p, "utf8"); } catch { return null; } };

// ---------------------------------------------------------------------------------------------
// Secrets never leave the machine or land in the trace. The patterns live in setup/redact.json,
// shared with routing/reflex_router.py; both selfchecks run its corpus.
export const REDACT = JSON.parse(readFileSync(join(HERE, "setup/redact.json"), "utf8"));
const SECRET_PATTERNS = REDACT.shapes.map(p => new RegExp(p, "g"));
const SECRET_CONTEXT = REDACT.context.map(c => [new RegExp(c.pattern, c.flags + "g"), c.replace]);
export function redact(s) {
  let out = String(s ?? "");
  for (const re of SECRET_PATTERNS) out = out.replace(re, "<redacted>");
  for (const [re, repl] of SECRET_CONTEXT) out = out.replace(re, repl);
  return out;
}
