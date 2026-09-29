#!/usr/bin/env node
// Reflex: judges a shell command a coding agent wants to run, before it runs.
//
//   node gate.mjs --decide        JSON call on stdin -> JSON decision on stdout (any agent adapter)
//   node gate.mjs --record        JSON outcome on stdin -> feedback log
//   node gate.mjs --claude        Claude Code PreToolUse hook   (--claude-post: PostToolUse; --claude-prompted: PermissionRequest)
//   node gate.mjs --codex         Codex CLI PreToolUse hook     (--codex-post)
//   node gate.mjs --hermes        Hermes pre_tool_call hook     (--hermes-post)
//   adapters/opencode.js, adapters/pi.ts                        plugins that call --decide / --record
//   scripts/reflex-sh -c "<cmd>"      bash drop-in for agents without hooks: judge, then run/confirm/refuse
//   node gate.mjs --check "<cmd>" judge one command from the terminal
//   node gate.mjs --selfcheck     offline tests, no API calls
//   --mode off|shadow|enforce, --allow off|shadow|on   written into hook commands by install.mjs
//
// Order: read-only? -> rules -> rules over the local scripts it runs -> fast lane -> cache -> Jev -> policy.
//
// By default the gate only tightens: it emits "ask" or "deny", never "allow", so the agent's own
// permission rules stay authoritative. Deterministic rules (setup/*/rules.json) are enforced in
// every mode. Jev's decisions are enforced only with REFLEX_MODE=enforce; in the default shadow
// mode Jev runs in a detached background process, so the agent never waits for it.
// "allow" (skip the agent's own prompt) is opt-in twice, REFLEX_ALLOW=on and enforce mode, and
// only for a fresh Jev answer that clears the policy's allow gate.
// First: failsafe.mjs answers the agent (ask, or block where it cannot ask) on any error after this.
import {hookFailure} from "./failsafe.mjs";
// Next: in the Claude Code plugin, settings come from the plugin options and config.json only (plugin.mjs).
import {PLUGIN_ERROR, PLUGIN_FLAG, PLUGIN_MODE, pluginKey} from "./plugin.mjs";
import {appendFileSync, copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync,
        openSync, readSync, writeSync, closeSync, rmSync, readdirSync, fstatSync, lstatSync, realpathSync, symlinkSync} from "node:fs";
import {createHash, randomUUID} from "node:crypto";
import {execFileSync, spawn, spawnSync} from "node:child_process";
import {homedir, platform, tmpdir} from "node:os";
import {basename, dirname, join, posix, resolve} from "node:path";
import {isatty} from "node:tty";
import {fileURLToPath} from "node:url";
import {compile} from "./policy.mjs";
import {envelopeFor, ladder, park, queueAnswer, runaway, runawayCall, runawayMark, runawayNote} from "./autonomy.mjs";
import {userFastPass} from "./fastlane.mjs";
import {globsReflex, repoRoot, teamMode, teamPolicy, teamRules} from "./team.mjs";
import {argStrings, mcpCommand, mcpJudge, protectedPath, toolOf} from "./tools.mjs";
import {infraError, infraSettings, planGate} from "./infra.mjs";
import {activeFreeze, inWindow, parseFreeze} from "./freeze.mjs";
import {notifyLater, notifyTarget} from "./notify.mjs";
import {PROVIDERS, call as callProvider, hostOf, keyRouteError, providerUrl, resolveProvider} from "./providers.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENV = process.env;
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
export const BACKEND_DEFAULTS = {cli: {cli: "claude", model: "sonnet"}, anthropic: {url: "https://api.anthropic.com", model: "claude-sonnet-5", key_env: "ANTHROPIC_API_KEY"},
  "openai-compatible": {}, none: {}};
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
// Standing down, read the input first: an agent writing a large tool result must not get EPIPE.
if (PLUGIN && process.argv.some(a => /^--(claude|codex)(-|$)/.test(a)) && (CODEX_PLUGIN ? settingsHooksInstalled(CODEX_HOOKS, "codex") : settingsHooksInstalled())) {
  // isatty, not process.stdin.isTTY: touching process.stdin makes a pipe non-blocking and the read fails with EAGAIN
  if (!isatty(0)) try { readFileSync(0); } catch { /* nothing to read */ }
  process.exit(0);
}
// With no saved engine the gate starts where a fresh `reflex setup` does: local, no key needed, or
// Jev when a TypeSafe key is in the environment, or a Keychain item or an earlier install is
// recorded. The Claude Code plugin starts local too, or Jev when its options hold a key.
// Which provider carries Jev (providers.mjs): TypeSafe direct, OpenRouter, Cloudflare, Vercel or a
// compatible endpoint, from REFLEX_PROVIDER, config.json "provider" or the keys in the environment.
export const PROVIDER = resolveProvider(ENV, USER_CONFIG);
// The Claude Code plugin: jev when its options hold a key, else local (no Keychain, no environment).
const ENGINE = ENV.REFLEX_ENGINE ?? flagValue("--engine", USER_CONFIG.engine ?? (PLUGIN_MODE ? (pluginKey() ? "jev" : "local") :
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
const LAYA = {...LAYA_DEFAULTS, ...USER_CONFIG.laya};
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
  keychain: ENV.REFLEX_KEYCHAIN_SERVICE ?? USER_CONFIG.keychain ?? "typesafe-api-key",
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
  mcp: {unknown: USER_CONFIG.mcp?.unknown ?? "shadow"},
};
// The one host the provider's key may go to (authorization()): where its endpoint was configured.
CONFIG.keyHost = hostOf(CONFIG.api);
/** Saved judge settings with the backend's (and, keyless, the engine's) defaults filled in; `enabled` unless the backend is none or REFLEX_JUDGE=off. */
export function judgeSettings(saved = {}, env, engine = "jev") {
  const backend = saved?.backend ?? JUDGE_DEFAULTS.backend, s = saved ?? {}, k = engine === "local" ? KEYLESS_JUDGE_DEFAULTS : {};
  return {...JUDGE_DEFAULTS, ...BACKEND_DEFAULTS[backend], ...s, backend, budget: {...JUDGE_DEFAULTS.budget, ...k.budget, ...s.budget},
          price: {...JUDGE_DEFAULTS.price, ...s.price}, breaker: {...JUDGE_DEFAULTS.breaker, ...k.breaker, ...s.breaker},
          enabled: env === undefined || env === "on" ? backend !== "none" : env === "off" ? false : env};
}
function onOff(env, saved) { return env === undefined ? saved === true : env === "on" ? true : env === "off" ? false : env; }
// Functions, not constants, so the self-check can point the whole gate at a scratch directory.
const TRACE = () => join(CONFIG.data, "trace.jsonl");
const FEEDBACK = () => join(CONFIG.data, "feedback.jsonl");
const CACHE = () => join(CONFIG.data, "cache.json");
const CACHE_TTL_MS = 24 * 3600 * 1000;
const ROTATE_BYTES = 50 * 1024 * 1024;

export const policyDirectory = join(dirname(USER_CONFIG_FILE), "tool-gate");
export const setupFile = f => !ENV.REFLEX_SETUP_DIR && CONFIG.setup === join(HERE, "setup/tool-gate") &&
  existsSync(join(policyDirectory, f)) ? join(policyDirectory, f) : join(CONFIG.setup, f);
export const load = f => JSON.parse(readFileSync(setupFile(f), "utf8"));
export function configurationError() {
  return USER_CONFIG_ERROR ?? PLUGIN_ERROR ?? (!ENGINES.includes(CONFIG.engine) ? "engine must be local, jev or laya"
    : CONFIG.engine === "jev" && PROVIDER.error ? PROVIDER.error
    : !["off", "shadow", "enforce"].includes(CONFIG.mode) ? "mode must be off, shadow or enforce"
    : !["off", "shadow", "on"].includes(CONFIG.allow) ? "allow must be off, shadow or on"
    : ![undefined, "simple", "legacy"].includes(ENV.REFLEX_READONLY ?? USER_CONFIG.readonly) ? "readonly must be simple or legacy" : layaError() ?? ladderError() ?? infraError(USER_CONFIG.infra) ?? toolError());
}
// Invalid tool gate settings ask, like any invalid configuration.
function toolError() {
  const m = USER_CONFIG.mcp, p = USER_CONFIG.protected;
  if (m !== undefined && (!m || typeof m !== "object" || Array.isArray(m) || Object.keys(m).some(k => k !== "unknown") || !["shadow", "ask", undefined].includes(m.unknown)))
    return 'mcp takes only "unknown": "shadow" or "ask"';
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
// Read-only detection. ponytail: a prefix list plus a little shell awareness, not a parser.
// Anything it does not recognise falls through to rules and Jev, which costs latency, not safety,
// so every doubtful construct below returns false rather than trying to understand it.
const READ_ONLY = new Set(("ls cat head tail less wc grep egrep rg fd find tree pwd echo printf which type " +
  "file stat du df date uname whoami id hostname uptime sw_vers jq yq sort cut tr diff cmp sed awk " +
  "column realpath readlink dirname basename true false test [ [[ cd sleep ps pgrep lsof " +
  "md5 shasum sha256sum od strings nl fold paste comm exit return free nproc lscpu seq").split(" "));
// Flags that make an otherwise read-only tool run a program or write a file.
const UNSAFE_FLAGS = new RegExp([
  // sed and awk are read by sedSafe and awkSafe, their options and their programs, as they parse them
  String.raw`--pre\b`, String.raw`--(upload|receive)-pack`, String.raw`--hostname-bin\b`,
  String.raw`--post-renderer`, String.raw`--compress-program`, String.raw`\b(git|sort)\b[^|;&]*--output\b`, String.raw`--ext-diff`,
  String.raw`\s-f(print0?|printf|ls)\b`, String.raw`\s-ok(dir)?\b`, String.raw`\bfd\b.*\s-[a-zA-Z]*[xX]`,
  // -o clustered or with its value attached (-ro, -uo, -oFILE)
  String.raw`\b(sort|tree)\b[^|;&]*\s-[a-zA-Z]*o`, String.raw`--show-token`,
  // tree -R runs tree again in every directory, writing 00Tree.html with -H: any -R
  String.raw`\btree\b[^|;&]*\s-[a-zA-Z]*R`,
  // yq writing in place or split files
  String.raw`\byq\b[^|;&]*\s(-[a-zA-Z]*[is]|--(inplace|split-exp))`,
].join("|"));
// Every prefix of an ip object that ip.c resolves to it (address comes before addrlabel, route before
// rule, neighbor before ntable, link before l2tp), and every prefix of list or lst.
const IP_ADDR = "a|ad|add|addr|addre|addres|address", IP_ROUTE = "r|ro|rou|rout|route", IP_RULE = "ru|rul|rule";
const IP_NEIGH = "n|ne|nei|neig|neigh|neighb|neighbo|neighbor|neighbou|neighbour", IP_LINK = "l|li|lin|link", IP_LIST = "l|li|lis|list|ls|lst";
const READ_ONLY_SUB = {
  git: /^(-C\s+\S+\s+)?((status|log|diff|show|blame|ls-files|ls-remote|rev-parse|describe|shortlog|fetch)\b|branch(\s+(-a|-r|-v|-vv|--list|--show-current|--contains\s+\S+|--merged|--no-merged))*\s*$|remote(\s+(-v|show\s+\S+|get-url\s+\S+))?\s*$|reflog(\s+show)?\b(?!.*\b(expire|delete)\b)|config\s+--get|stash\s+(list|show)|worktree\s+list|tag\s+-l)/,
  kubectl: /^(get|describe|logs|top|explain|version|api-resources|config (view|current-context|get-contexts))\b/,
  // not plan, show, validate, state, providers or graph: they start the provider binaries in .terraform,
  // or (output, state list) the backend saved there, which an agent's file tools can write outside the gate
  terraform: /^(-chdir=\S+\s+)?(fmt -check|version)\b/,
  aws: /^(--\S+\s+\S+\s+)*(\S+ (describe|list|head)-\S+|(?!s3api\s+get-object)\S+ get-\S+|sts get-caller-identity|configure list|s3 ls)\b/,
  helm: /^(list|ls|status|get|lint|show|history|search|version)\b/,
  // gh api is a GET unless a method, field or input says otherwise, in any spelling
  gh: /^(pr|issue|run|release|repo) (view|list|checks|diff|status)\b|^auth status|^api(?!.*\s(-X\S*|--method|-[fF]\S*|--field|--raw-field|--input)(\s|=|$))\s/,
  docker: /^(ps|logs|inspect|images|version|info|stats --no-stream|compose (ps|logs)|compose config(?!.*\s(-[a-zA-Z]*o|--output)))\b/,
  npm: /^(view|ls|list|outdated|config get)\b/,
  brew: /^(list|info|search|services list|--prefix)\b/,
  uniq: /^(-\S+\s*)*$/,          // flags only: `uniq in out` writes out
  // one input at most (`xxd in out` writes out), and no -r
  xxd: /^(?!.*(^|\s)-r)((-[cglson]\s+\S+|-\S+)\s+)*([^\s-]\S*)?\s*$/,
  // queries only: -pm, -pl, -r, -e, -c, -ac, clock locks, MIG and auto-boost settings change the GPU
  "nvidia-smi": /^(?!.*(^|\s)(-pm|-pl|-r|-e|-c|-ac|-rac|-lgc|-rgc|-lmc|-rmc|-mig|-am|-cc|-dm|--persistence-mode|--power-limit|--gpu-reset|--ecc-config|--compute-mode|--applications-clocks|--reset-applications-clocks|--lock-gpu-clocks|--reset-gpu-clocks|--lock-memory-clocks|--reset-memory-clocks|--multi-instance-gpu|--auto-boost-default|--auto-boost-permission|--cuda-clocks|--driver-model|-f|--filename)(\s|=|$))/,
  // what a remote host is usually asked over ssh (#26). Before the verb, options that take a value
  // take the next word: `-p status restart x` and `--property status restart x` restart x. No
  // verb at all (`systemctl`, `systemctl --failed`) is list-units.
  systemctl: /^((-[alqr]+|-[tpPHMn]\s+[^\s-]\S*|--(property|type|state|host|machine|lines|output)\s+[^\s-]\S*|--(failed|all|full|no-pager|no-legend|plain|quiet|user|system|recursive|reverse|value|show-types)|--[\w-]+=\S+)(\s+|$))*((status|is-active|is-enabled|is-failed|is-system-running|show|cat|list-units|list-unit-files|list-sockets|list-timers|list-jobs|list-dependencies|get-default)(\s.*)?)?$/,
  // getopt_long takes any unique prefix of a long option (--rot is --rotate), so no long option
  // may be a prefix of one that writes
  // An exact option wins: --cursor is not --cursor-file.
  journalctl: {test: s => !s.split(/\s+/).some(w => /^--[\w-]+(=|$)/.test(w) && !["--cursor"].includes(w.split("=")[0]) &&
    ["vacuum-size", "vacuum-files", "vacuum-time", "rotate", "flush", "sync", "relinquish-var", "smart-relinquish-var",
     "setup-keys", "update-catalog", "cursor-file"].some(o => ("--" + o).startsWith(w.split("=")[0])))},
  // options from an allowlist: ip takes any prefix of -batch (-ba, -bat) as a batch file of commands.
  // ip also takes any prefix of an object or verb, first match wins (iproute2 matches() in ip.c and
  // do_ipaddr, do_iproute, do_iprule, do_ipneigh, do_iplink): `ip l s` is link set, `ip a a` addr add.
  // So only spellings that are show/list/get for that object: `s` is show for addr, route, rule and
  // neigh, not link; `g` is get for route and neigh; any prefix of list or lst is list everywhere.
  ip: new RegExp(String.raw`^((-(br|brief|4|6|s|stats|d|details|j|json|p|pretty|o|oneline|c|color))\s+)*` +
    String.raw`((${IP_ADDR}|${IP_ROUTE}|${IP_RULE}|${IP_NEIGH})(\s+(s|sh|sho|show|${IP_LIST})\b.*)?|(${IP_LINK})(\s+(sh|sho|show|${IP_LIST})\b.*)?|` +
    String.raw`(${IP_ROUTE}|${IP_NEIGH})\s+(g|ge|get)\b.*)$`),
};
// `docker exec [-t] [-u user] [-w dir] container cmd`: as read-only as cmd. The container is a
// literal name, never $C or "$(…)", which could turn into options, a container and another command.
// No -i: nothing is fed to the container's stdin.
const DOCKER_EXEC = /^exec\s+((-t|--tty|(-[uw]|--(user|workdir))(\s+|=)[\w./:-]+)\s+)*(\w[\w.-]*)\s+(\S[\s\S]*)$/;
// Loop and condition keywords wrap commands; the command after them is what runs.
const KEYWORD = /^(do|then|else|elif|if|while|until|!|\{|\()\s+/;
// Assignments that cannot turn a reader into a runner: shell-local lowercase names, short script
// variables (S=, OUT=), and a few well-known selectors. PATH, PAGER, GIT_*, LD_* and friends are not.
const SAFE_VAR = /^([a-z_][a-z0-9_]*|[A-Z]{1,3}|AWS_PROFILE|AWS_REGION|AWS_DEFAULT_REGION|KUBECONFIG)$/;
const assignmentOk = a => SAFE_VAR.test(a.split("=")[0]);

// Blank out quoted text and comments, keeping the quote marks. Inside double quotes `$(` and
// backticks still expand, so they are kept; `$'…'` is quoted text with backslash escapes; a `#` that
// starts a word comments out the rest of the line. Unbalanced quotes mean the mask cannot be
// trusted: return the input. `fill` stands in for each blanked character; with one, the mask keeps
// the input's length, so positions found in the mask cut the original.
export function maskQuotes(s, fill = "") {
  let out = "", q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q === "#") { if (ch === "\n") { q = null; out += ch; } else out += fill; continue; }
    if (q === "$'") {
      if (ch === "\\") { out += fill.repeat(Math.min(2, s.length - i)); i++; continue; }
      out += ch === "'" ? ch : fill;
      if (ch === "'") q = null;
      continue;
    }
    if (q === "'") { out += ch === "'" ? ch : fill; if (ch === "'") q = null; continue; }
    if (q === '"') {
      if (ch === "\\") { out += fill.repeat(Math.min(2, s.length - i)); i++; continue; }
      if (ch === '"') { q = null; out += ch; continue; }
      if (ch === "`") { out += ch; continue; }
      if (ch === "$" && s[i + 1] === "(") { out += "$("; i++; continue; }
      out += fill;
      continue;
    }
    if (ch === "\\") { out += ch + (s[i + 1] ?? ""); i++; continue; }
    if (ch === "#" && (i === 0 || /[\s;&|()]/.test(s[i - 1]))) { q = "#"; out += fill; continue; }
    if (ch === "$" && s[i + 1] === "'") { q = "$'"; out += "$'"; i++; continue; }
    if (ch === "'" || ch === '"') q = ch;
    out += ch;
  }
  return q && q !== "#" ? s : out;
}

// The words of a command as the shell passes them: backslashes dropped, $'…' decoded, quoted parts
// joined. Each word keeps where it starts and ends, its raw text, and its expansions: a name for
// $name or ${name}, "?" for anything else ($(…), `…`, ${x:-…}, $1, $@, and the X% a $(…) was
// replaced with). An expansion stands in the value as \0; `split`: one is outside double quotes, so
// the shell splits what it gives into words. null: an unbalanced quote.
// ponytail: words, not the grammar: operators ; & | < > ( ) split words and are dropped.
const ANSI_C = {n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v"};
const ANSI_ESCAPE = /x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{1,4})|U([0-9a-fA-F]{1,8})|([0-7]{1,3})|c([\s\S])|([\s\S])/y;
export function shellWords(s) {
  const words = [], n = s.length, SEP = /[\s;&|<>()]/;
  let i = 0;
  const expansion = (w, quoted) => {   // at s[i], a $ or a backtick
    if (s[i] === "`") { const e = s.indexOf("`", i + 1); if (e < 0) return false; w.exps.push("?"); i = e + 1; return true; }
    const d = s[i + 1];
    if (d === "(") {
      let depth = 0, k = i + 1;
      for (; k < n; k++) { if (s[k] === "(") depth++; else if (s[k] === ")" && --depth === 0) break; }
      if (k >= n) return false;
      w.exps.push("?"); i = k + 1; return true;
    }
    if (d === "{") {
      const e = s.indexOf("}", i + 2); if (e < 0) return false;
      const name = s.slice(i + 2, e);
      w.exps.push(/^[A-Za-z_]\w*$/.test(name) ? name : "?"); i = e + 1; return true;
    }
    const m = s.slice(i + 1, i + 65).match(/^([A-Za-z_]\w*|[0-9@*#?$!-])/);
    if (!m) { w.value += "$"; i++; return null; }
    w.exps.push(/^[A-Za-z_]/.test(m[1]) ? m[1] : "?"); i += 1 + m[1].length; return true;
  };
  while (i < n) {
    while (i < n && SEP.test(s[i])) i++;
    if (i >= n) break;
    if (s[i] === "#") { while (i < n && s[i] !== "\n") i++; continue; }
    const w = {start: i, end: i, raw: "", value: "", exps: []};
    while (i < n && !SEP.test(s[i])) {
      const ch = s[i];
      if (ch === "\\") { w.value += s[i + 1] ?? ""; i += 2; continue; }
      if (ch === "'") { const e = s.indexOf("'", i + 1); if (e < 0) return null; w.value += s.slice(i + 1, e); i = e + 1; continue; }
      if (ch === "$" && s[i + 1] === "'") {
        for (i += 2; ; ) {
          if (i >= n) return null;
          if (s[i] === "'") { i++; break; }
          if (s[i] !== "\\") { w.value += s[i++]; continue; }
          ANSI_ESCAPE.lastIndex = i + 1;
          const m = ANSI_ESCAPE.exec(s);
          if (!m) return null;
          const code = m[1] ?? m[2] ?? m[3];
          // bash cuts the word at a NUL, and \0 is the expansion placeholder here: not read
          if ((code && parseInt(code, 16) === 0) || (m[4] && parseInt(m[4], 8) % 256 === 0) || m[5] === "@") return null;
          w.value += code ? String.fromCodePoint(Math.min(parseInt(code, 16), 0x10ffff)) : m[4] ? String.fromCharCode(parseInt(m[4], 8) & 255)
            : m[5] !== undefined ? String.fromCharCode(m[5].charCodeAt(0) & 31) : ANSI_C[m[6]] ?? (/['"\\?]/.test(m[6]) ? m[6] : "\\" + m[6]);
          i = ANSI_ESCAPE.lastIndex;
        }
        continue;
      }
      if (ch === '"') {
        for (i++; ; ) {
          if (i >= n) return null;
          const d = s[i];
          if (d === '"') { i++; break; }
          if (d === "\\" && /[$`"\\]/.test(s[i + 1] ?? "")) { w.value += s[i + 1]; i += 2; continue; }
          if (d === "$" || d === "`") { const r = expansion(w, true); if (r === false) return null; if (r) w.value += "\0"; continue; }
          w.value += d; i++;
        }
        continue;
      }
      if (ch === "$" || ch === "`") { const r = expansion(w, false); if (r === false) return null; if (r) { w.value += "\0"; w.split = true; } continue; }
      w.value += ch; i++;
    }
    w.end = i; w.raw = s.slice(w.start, i);
    if (w.raw.includes("X%")) { w.exps.push("?"); if (maskQuotes(w.raw, "_").includes("X%")) w.split = true; }
    // {a,b} and {1..3} outside quotes are expanded into words: sort {-o,out} is sort -o out
    if (/\{[^{}\s]*(,|\.\.)[^{}\s]*\}/.test(maskQuotes(w.raw, "_").replace(/\\./g, "__"))) { w.exps.push("?"); w.split = true; }
    words.push(w);
  }
  return words;
}
// sed as sed parses it (GNU and BSD): the options, then the script. Not read-only: in place (-i,
// -I, --in-place), a script from a file (-f), an option not known to be safe, or a script with
// w, W or e (after an address or not, with or without a space: BSD writes `1w/path`), or an s///
// with the w or e flag. r and R read a file, named to the end of the line. Anything the parser
// does not follow (an unknown command, a stray character) is not read-only either.
const SED_LONG = new Set(["quiet", "silent", "regexp-extended", "posix", "debug", "sandbox", "null-data", "zero-terminated", "separate", "unbuffered", "follow-symlinks", "binary"]);
function sedSafe(args) {
  const scripts = [], pos = [];
  let expression = false, files = false;
  for (let i = 0; i < args.length; i++) {
    const v = args[i].value;
    if (files || v === "-" || !v.startsWith("-")) { pos.push(args[i]); continue; }
    if (args[i].exps.length) return false;
    if (v === "--") { files = true; continue; }
    if (v.startsWith("--")) {
      const eq = v.indexOf("="), name = v.slice(2, eq < 0 ? undefined : eq);
      if (name === "expression") {
        const w = eq < 0 ? args[++i] : {value: v.slice(eq + 1), exps: []};
        if (!w || w.exps.length) return false;
        scripts.push(w.value); expression = true; continue;
      }
      if (name === "line-length") { if (eq < 0 && !/^\d+$/.test(args[++i]?.value ?? "")) return false; continue; }
      if (SED_LONG.has(name) && eq < 0) continue;
      return false;
    }
    for (let k = 1; k < v.length; k++) {
      const f = v[k];
      if (/[nErsuzba]/.test(f)) continue;
      if (f === "l") { if (k === v.length - 1 ? !/^\d+$/.test(args[++i]?.value ?? "") : !/^\d+$/.test(v.slice(k + 1))) return false; break; }
      if (f !== "e") return false;
      const w = k < v.length - 1 ? {value: v.slice(k + 1), exps: []} : args[++i];
      if (!w || w.exps.length) return false;
      scripts.push(w.value); expression = true; break;
    }
  }
  if (!expression) { const w = pos.shift(); if (!w || w.exps.length) return false; scripts.push(w.value); }
  // GNU joins -e pieces with newlines, so a piece ending in a backslash continues a/i/c text into
  // the next one; BSD ends the text at the piece and reads the next one as commands: not read
  if (scripts.slice(0, -1).some(p => /(^|[^\\])(\\\\)*\\$/.test(p))) return false;
  return sedScriptSafe(scripts.join("\n"));
}
function sedScriptSafe(s) {
  const n = s.length;
  let i = 0, depth = 0;
  const ws = () => { while (i < n && (s[i] === " " || s[i] === "\t")) i++; };
  // text up to delimiter d, backslash escapes skipped; false at a newline or the end
  const upTo = d => { for (; i < n && s[i] !== d; i++) { if (s[i] === "\n") return false; if (s[i] === "\\") i++; } if (i >= n) return false; i++; return true; };
  const delimited = () => { const d = s[i]; if (d === undefined || d === "\n" || d === "\\") return false; i++; return upTo(d); };
  // a regex up to delimiter d: [...] is one unit ([]x], [^]x], [[:alpha:]] included), as both seds read it
  const regexUpTo = d => {
    for (; i < n && s[i] !== d; i++) {
      if (s[i] === "\n") return false;
      if (s[i] === "\\") { i++; continue; }
      if (s[i] !== "[") continue;
      i++;
      if (s[i] === "^") i++;
      if (s[i] === "]") i++;
      for (; i < n && s[i] !== "]"; i++) {
        if (s[i] === "\n") return false;
        const cls = s[i] === "[" && /[:=.]/.test(s[i + 1] ?? "") ? s[i + 1] : null;
        if (cls) { const e = s.indexOf(cls + "]", i + 2); if (e < 0) return false; i = e + 1; }
      }
      if (i >= n) return false;
    }
    if (i >= n) return false;
    i++; return true;
  };
  const regex = () => { const d = s[i]; if (d === undefined || d === "\n" || d === "\\") return false; i++; return regexUpTo(d); };
  const toEol = () => { const e = s.indexOf("\n", i); const t = s.slice(i, e < 0 ? n : e); i = e < 0 ? n : e; return t; };
  const address = () => {
    if (/\d/.test(s[i])) { while (/\d/.test(s[i])) i++; if (s[i] === "~") { i++; while (/\d/.test(s[i])) i++; } return true; }
    if (s[i] === "$") { i++; return true; }
    if (s[i] === "/" || s[i] === "\\") { if (s[i] === "\\") i++; if (!regex()) return false; while (s[i] === "I" || s[i] === "M") i++; return true; }
    return null;
  };
  const end = () => { ws(); return i >= n || /[;\n}#]/.test(s[i]); };
  const label = () => { ws(); while (i < n && !/[;\n}\s]/.test(s[i])) i++; };
  for (;;) {
    while (i < n && /[\s;]/.test(s[i])) i++;
    if (i >= n) return depth === 0;
    const a = address();
    if (a === false) return false;
    if (a) {
      ws();
      if (s[i] === ",") {
        i++; ws();
        if (s[i] === "+" || s[i] === "~") { i++; if (!/\d/.test(s[i])) return false; while (/\d/.test(s[i])) i++; }
        else if (!address()) return false;
      }
    }
    ws();
    while (s[i] === "!") { i++; ws(); }
    const c = s[i++];
    if (c === "{") { depth++; continue; }
    if (c === "}") { if (--depth < 0 || !end()) return false; continue; }
    if (c === "#") { toEol(); continue; }
    if (c === ":") { if (a) return false; label(); if (!end()) return false; continue; }
    if (/[bTt]/.test(c)) { label(); if (!end()) return false; continue; }
    if (/[aic]/.test(c)) {
      // text to the end of the line; a line ending in a backslash goes on
      ws(); if (s[i] === "\\") i++;
      if (s[i] === "\n") i++;
      for (;;) { const t = toEol(); if (i >= n || !/(^|[^\\])(\\\\)*\\$/.test(t)) break; i++; }
      continue;
    }
    if (/[rR]/.test(c)) { if (/[;}]/.test(toEol())) return false; continue; }
    if (c === "s") {
      const d = s[i];
      if (!regex()) return false;
      if (!upTo(d)) return false;
      while (i < n && /[gpiImM\d]/.test(s[i])) i++;
      if (!end()) return false;
      continue;
    }
    if (c === "y") { const d = s[i]; if (!delimited() || !upTo(d) || !end()) return false; continue; }
    if (/[lqQL]/.test(c)) { ws(); while (/\d/.test(s[i])) i++; if (!end()) return false; continue; }
    if (c === "v") { ws(); while (/[\d.]/.test(s[i])) i++; if (!end()) return false; continue; }
    if (/[=dDgGhHnNpPxzF]/.test(c)) { if (!end()) return false; continue; }
    return false;   // w W e, and anything else
  }
}
// gawk options that write a file (--profile, --pretty-print, --dump-variables and -p -o -d), run
// the debugger (-D) or load a program from a file (-f -E -i -l, --file, --exec, --include, --load,
// --source): any spelling, any unique prefix, a value attached or not.
const AWK_LONG = ["file", "exec", "include", "load", "source", "profile", "pretty-print", "dump-variables", "debug"];
// -W takes a long option as its value (-W dump-variables=f). The program text is checked as the
// shell passes it (sys''tem, $'\x73ystem'): no @ (gawk @include, @load, indirect calls), system,
// getline, | or > (pipes and redirects, and > as a comparison too), close, fflush, PROCINFO or ENVIRON.
const AWK_UNSAFE = /[@|>]|\b(system|getline|close|fflush)\b|PROCINFO|ENVIRON/;
const awkLong = name => !name || AWK_LONG.some(o => o.startsWith(name.split("=")[0]));
function awkSafe(args) {
  let program = false, dd = false;
  for (let i = 0; i < args.length; i++) {
    const v = args[i].value;
    if (dd || v === "-" || !v.startsWith("-")) { if (!program) { program = true; if (AWK_UNSAFE.test(v)) return false; } dd = true; continue; }
    if (v === "--") { dd = true; continue; }
    if (v.startsWith("--")) { if (awkLong(v.slice(2))) return false; continue; }
    for (let k = 1; k < v.length; k++) {
      const f = v[k];
      if (f === "W") { if (awkLong(k < v.length - 1 ? v.slice(k + 1) : args[++i]?.value ?? "")) return false; break; }
      if (f === "e") { const t = k < v.length - 1 ? v.slice(k + 1) : args[++i]?.value ?? ""; if (AWK_UNSAFE.test(t)) return false; program = true; break; }
      if (/[Fv]/.test(f)) { if (k === v.length - 1) i++; break; }
      if (/[fEilLpodD]/.test(f)) return false;
    }
  }
  return true;
}
// Commands whose options or first words decide whether they write or run something: an
// expansion among their words could turn into one (X=-i; sed $X …, gh api $(echo -X) DELETE), a
// glob into a file named -i or into a second word (xxd in out, awk -- * runs a file name as its
// program). So none at all: no variable, substitution, arithmetic, brace list or glob, before or
// after --. The one exception is a double-quoted $name inside a word that starts with a literal
// path (`"repos/$R/pulls"`): one word, never an option, and (not for sed or awk) no program text.
const FLAG_SENSITIVE = new Set(["sed", "awk", "find", "fd", "rg", "sort", "tree", "yq", "xxd", "uniq", "date", "file", "printf",
  "git", "kubectl", "terraform", "aws", "helm", "gh", "docker", "npm", "brew", "nvidia-smi", "systemctl", "journalctl", "ip"]);
const pathWord = (w, head) => !w.split && head !== "sed" && head !== "awk" && w.exps.every(x => x !== "?") &&
  /^[^-\0][^\0]*\//.test(w.value.slice(0, w.value.indexOf("\0")));
const SORT_WRITES = ["output", "compress-program", "random-source", "temporary-directory"];
function argsUnsafe(raw, head) {
  const words = shellWords(raw);
  if (!words) return true;
  let k = 0;
  while (k < words.length && /^(do|then|else|elif|if|while|until|!|\{)$/.test(words[k].raw)) k++;
  for (;;) {
    const w = words[k]?.raw;
    if (w === undefined) return true;
    if (/^\w+=/.test(w) || /^(time|nohup|command)$/.test(w)) k++;
    else if (w === "rtk") k += words[k + 1]?.raw === "proxy" ? 2 : 1;
    else if (w === "timeout") {
      for (k++; words[k]?.raw.startsWith("-"); k++) if (/^(-[ks]|--(kill-after|signal))$/.test(words[k].raw)) k++;
      k++;
    } else break;
  }
  if (words[k].raw.replace(/^\/(usr\/)?bin\/(?=[\w.-]+$)/, "") !== head) return true;
  const args = words.slice(k + 1);
  if (args.some(w => /[*?[]/.test(maskQuotes(w.raw, "_").replace(/\\./g, "__")))) return true;
  if (args.some(w => w.exps.length && !pathWord(w, head))) return true;
  // printf reads options (-v) in its first word only, and a format that expands is unknown
  if (head === "printf") return !!args[0] && (args[0].exps.length > 0 || /^-\w*v/.test(args[0].value));
  // getopt_long takes any unique prefix: --o is --output, --t --temporary-directory
  if (head === "sort" && args.some(w => /^--[\w-]+(=|$)/.test(w.value) &&
      SORT_WRITES.some(o => ("--" + o).startsWith(w.value.split("=")[0])))) return true;
  if (head === "sed") return !sedSafe(args);
  if (head === "awk") return !awkSafe(args);
  return false;
}

// `ssh [options] host 'cmd'` (#26): unquoted words (options, then one host), then the quoted remote
// command, which must end the call: words after it would be appended to it on the remote side.
// Or `ssh [options] host cmd args` with no quotes at all: sshCall takes the words after the host.
// The call stays on one line: `ssh h⏎uptime` is a login, then a local uptime.
// GNU timeout with its options (-k1, -s KILL, --kill-after=1, -f, -p, -v), then the duration.
const TIMEOUT = String.raw`timeout(\s+(-[fpv]+|-[ks]\s*[^\s-]\S*|--(foreground|preserve-status|verbose)|--(kill-after|signal)(=|\s+)[^\s-]\S*))*\s+[^\s-]\S*`;
const SSH_LEAD = new RegExp(String.raw`^\s*((do|then|else|elif|if|while|until|!|\{)\s+|\w+=\S*\s+|${TIMEOUT}\s+|time\s+|nohup\s+|command\s+|rtk(\s+proxy)?\s+)*$`);
const RO_PREFIX = new RegExp(String.raw`^((\w+=\S*|rtk(\s+proxy)?|${TIMEOUT}|time|nohup|command)\s+)+`);
const SSH_CALL = /\bssh((?:[ \t]+[^\s'"`\\;&|<>()]+)+?)(?:[ \t]+(?:'([^']*)'|"((?:[^"\\]|\\[\s\S])*)"))?(?=[ \t]*($|[;&|\n)]))/;
// Options from an allowlist. Left out: whatever runs a local command or loads local code
// (ProxyCommand, LocalCommand, KnownHostsCommand, -F config, -I and PKCS11Provider), forwards (-L -R
// -D -W -w, -A the agent, -X -Y, -K credentials), backgrounds (-f -N), writes a local file (-E, a
// known-hosts file other than /dev/null), sends local environment (SendEnv) or replaces the command
// (RemoteCommand, -s). A value never starts with - (`-J -oProxyCommand=…`) or holds a glob.
const SSH_FLAGS = /^-([46CTaknqtvx]*)([Jbcilmop]?)(.*)$/;
// -J / ProxyJump: ssh pastes the hops into a command line it runs with the shell (the last one as
// the host of `ssh -J rest -W …`), so each hop is a plain [ssh://][user@]host[:port]: no hop that
// starts with - (`-J a,-oProxyCommand=x`), no % (expanded as a token).
const SSH_HOP = String.raw`(ssh:\/\/)?(\w[\w.-]*@)?\w[\w.-]*(:\d+)?`;
const SSH_JUMP = new RegExp(String.raw`^${SSH_HOP}(,${SSH_HOP})*$`);
const SSH_OPTION = /^(AddressFamily|BatchMode|CheckHostIP|Compression|ConnectTimeout|ConnectionAttempts|HashKnownHosts|HostKeyAlias|IdentitiesOnly|IdentityFile|KbdInteractiveAuthentication|LogLevel|NumberOfPasswordPrompts|PasswordAuthentication|Port|PreferredAuthentications|PubkeyAuthentication|RequestTTY|ServerAliveCountMax|ServerAliveInterval|StrictHostKeyChecking|TCPKeepAlive|User|VerifyHostKeyDNS)=[^=]*$|^UserKnownHostsFile=\/dev\/null$/i;
// `for h in a b; do ssh $h '…'; done`: a variable host only a loop over literal host names sets, and
// the ssh call inside that loop. Whatever else could set it (an assignment, ${h:=…}, read, export,
// the environment, a shell-managed name like $_) or change how it splits (IFS) refuses it:
// `h=-oProxyCommand=…` would run a local command. `at`: where the call is in `c`.
function loopHost(c, v, at) {
  if (!/^([a-z][a-z0-9]*|[A-Z])$/.test(v) ||
      new RegExp(String.raw`\b${v}=|\$\{${v}[^}]|\bIFS=|\b(read|declare|typeset|local|export|readonly|getopts|mapfile|readarray|printf\s+-v|eval|source|unset)\b`).test(c)) return false;
  const mask = maskQuotes(c, "_"), loops = [...mask.matchAll(new RegExp(String.raw`\bfor\s+${v}\s+in\s+([^;\n]*)[;\n]\s*do\b`, "g"))];
  // no word that is an option, or makes one next to the literal part of a host (`a@-F`, `$h-F` with h=a@)
  if (!loops.length || !loops.every(f => f[1].trim().split(/\s+/).every(w => /^[\w.@:][\w.@:-]*$/.test(w) && !/@-|@$/.test(w)))) return false;
  // inside: after the loop's `do`, before the `done` that closes it
  return loops.some(f => {
    let depth = 1;
    for (const k of mask.slice(f.index + f[0].length, at).matchAll(/\b(do|done)\b/g)) if ((depth += k[1] === "do" ? 1 : -1) === 0) return false;
    return f.index + f[0].length <= at;
  });
}
// Could a pipe before `at` in the mask feed what runs there? Yes when no separator follows it (a
// wrapper, a newline), when a loop, condition or group starts right after it, or when a subshell,
// group or substitution opened after it is still open at `at`. ponytail: counts brackets, not the
// grammar: `a | x; (ssh …)` is refused too.
const piped = (mask, at) => [...mask.slice(0, at).matchAll(/(^|[^|])\|(?!\|)&?/g)].some(p => {
  const t = mask.slice(p.index + p[0].length, at).trimStart(), n = re => (t.match(re) ?? []).length;
  return !/[;&\n]/.test(t) || /^(for|while|until|if|select|case|[{(!])/.test(t) ||
    n(/\(/g) > n(/\)/g) || n(/\{/g) > n(/\}/g) || n(/`/g) % 2 === 1;
});
// The remote command of an ssh call SSH_CALL found in c, or null when the call is not a read of it:
// an option outside the allowlist or holding a variable or glob, a host that is neither a literal
// name nor a loopHost, anything feeding ssh's stdin (a pipe that reaches it; a redirect or heredoc
// never matches SSH_CALL or leaves a segment that is not read-only), or a double-quoted command with something the local shell expands ($VAR, $(…), `…`
// would send local data to the host). Quotes are checked against the mask: an ssh inside quoted text
// is undefined (data, or a `"$(ssh …)"` the $(…) step reads on its own), and a match that starts
// outside quotes but ends inside them is refused. `whole`: the command a loop variable is looked up
// in; the call is found in it by its text. A host may mix literal text and loop variables
// (`web-$i`, `ops@${h}.lan`); the literal part never makes it an option.
// Without quotes the remote command is the words after the host: plain words only (no $, glob, ~ or
// quote the local shell would change). ssh reads options after the host until the first other word:
// those go through the same allowlist, and `--` there is refused.
function sshCall(c, m, whole) {
  const mask = maskQuotes(c, "_"), bare = m[2] === undefined && m[3] === undefined;
  const q = m[2] === undefined ? '"' : "'", end = m.index + m[0].length - 1;
  const body = m[2] ?? m[3] ?? "", open = end - body.length - 1;
  // an unbalanced quote leaves the mask unchanged: nothing about the call can be trusted
  if (bare ? mask === c && /['"#]/.test(c) : !body || mask === c) return null;
  if (mask.slice(m.index, m.index + 3) !== "ssh") return undefined;
  // unquoted, ssh must be the command: in `grep ssh f` it is a word, and in `sort ssh h ls -o out`
  // replacing "ssh h ls -o out" with true would hide what sort writes
  if (bare && !SSH_LEAD.test(mask.slice(0, m.index).split(/[;&|\n(]/).at(-1))) return undefined;
  if (bare ? mask.slice(m.index, end + 1) !== m[0] : mask[open] !== q || mask[end] !== q) return null;
  if (piped(mask, m.index)) return null;
  const words = m[1].trim().split(/\s+/);
  // The index of the first word after the options from `i`, or -1 for an option not allowed. ssh
  // reads options after the host too (`ssh -J a h -J b uptime`), so both runs are checked.
  const options = i => {
    for (; i < words.length && words[i].startsWith("-"); i++) {
      const f = words[i].match(SSH_FLAGS);
      if (!f || !(f[1] || f[2]) || (!f[2] && f[3])) return -1;
      if (!f[2]) continue;
      const v = f[3] || words[++i];
      if (v === undefined || /^-|\/-/.test(v)) return -1;
      const jump = f[2] === "J" ? v : f[2] === "o" ? v.match(/^ProxyJump=(.*)$/i)?.[1] : undefined;
      if (jump !== undefined ? !SSH_JUMP.test(jump) : f[2] === "o" && !SSH_OPTION.test(v)) return -1;
    }
    return i;
  };
  const i = options(0), after = i < 0 ? -1 : options(i + 1);
  if (after < 0) return null;
  const host = words[i], rest = words.slice(after);
  if (host === undefined || words.some((w, k) => k !== i && /[${}*?[\]]|^-.*(\s|\/-)|^-\S*=-/.test(w))) return null;
  const vars = [...host.matchAll(/\$\{(\w+)\}|\$(\w+)/g)].map(x => x[1] ?? x[2]), lit = host.replace(/\$\{\w+\}|\$\w+/g, "x");
  if (!/^[\w.%@:-]+$/.test(lit) || /(^|@)-/.test(lit)) return null;
  // the call is found in `whole` by its text: every place that text appears must be in such a loop
  const at = [];
  for (let k = whole.indexOf(m[0]); k >= 0; k = whole.indexOf(m[0], k + 1)) at.push(k);
  if (vars.length && !(at.length && vars.every(v => at.every(k => loopHost(whole, v, k))))) return null;
  if (bare) return rest.length && rest.every(w => /^[\w./:=,@%+-]+$/.test(w)) && !rest[0].startsWith("-") ? rest.join(" ") : null;
  if (rest.length) return null;
  if (q === "'") return body;
  return /[$`]/.test(body.replace(/\\[\s\S]/g, "")) ? null : body.replace(/\\([$`"\\])/g, "$1");
}

// `extra` adds segment patterns that are safe but not read-only (rules.json "pass": builds, mkdir).
// `whole`: the command a $(…) was cut from, where an ssh loop variable is set.
export function readOnlyLegacy(cmd, extra = [], depth = 0, whole = null) {
  if (depth > 3) return false;
  // The shell deletes a backslash-newline: `-de\⏎lete` is -delete.
  let c = cmd.replace(/\\\n/g, "")
    // A quoted heredoc body is data. An unquoted one is expanded by the shell, so it stays and is
    // checked. It is still stdin: a `<` stays in its place, so an ssh call it feeds is not one
    // SSH_CALL matches (as a plain word, `ssh h awk -f - <<'EOF'` took it for an argument).
    .replace(/<<-?\s*(['"])(\w+)\1([^\n]*)\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g, "<_heredoc_$3")
    .replace(/[0-9&]?>{1,2}\s*\/dev\/null\b|<\s*\/dev\/null\b/g, "")
    .replace(/[0-9]>&[0-9]/g, "");
  // Quotes and escapes around an option hide it from the checks below, which see quoted text
  // blanked: `sed "-i"`, `sed -\i`, `gh api $'\x2dX'`, `nvidia-smi -"pm"` are the plain option. Each
  // word that is an option once the shell has read it is written the way the shell passes it: its
  // plain part as it is, the rest single-quoted (`--format=%h\ %s` is --format='%h %s').
  const words = shellWords(c);
  if (words) for (const w of words.reverse()) {
    if (w.exps.length || !w.value.startsWith("-") || w.raw === w.value) continue;
    const plain = w.value.match(/^-[\w=.\/:,@%+-]*/)[0], rest = w.value.slice(plain.length);
    c = c.slice(0, w.start) + plain + (rest ? `'${rest.replace(/'/g, "'\\''")}'` : "") + c.slice(w.end);
  }
  whole ??= c;
  // `ssh host 'cmd'` is only as safe as cmd, which must be read-only itself (the fast lane is for
  // local work). See sshCall for what else the call must not do.
  for (let at = 0, m; (m = c.slice(at).match(SSH_CALL));) {
    m.index += at;
    const inner = sshCall(c, m, whole);
    if (inner === undefined) { at = m.index + 3; continue; }
    if (inner === null || !readOnlyLegacy(inner, [], depth + 1)) return false;
    c = c.slice(0, m.index) + "true" + c.slice(m.index + m[0].length);
    at = m.index;
  }
  // `$(...)` is only as safe as what runs inside it. What it prints is unknown words: "X%" is no name
  // (DOCKER_EXEC takes no container from it).
  for (let m; (m = c.match(/\$\(([^()`]*)\)/));) {
    if (!readOnlyLegacy(m[1], extra, depth + 1, whole) || (/\bssh\b/.test(m[1]) && piped(maskQuotes(c, "_"), m.index))) return false;
    c = c.replace(m[0], "X%");
  }
  // Tool-level dangers are checked on the raw text, quotes included (conservative).
  if (/-delete\b|-exec(dir)?\b/.test(c) || UNSAFE_FLAGS.test(c)) return false;
  // Shell structure and command words are checked with quoted text masked: `jq '.a | .b'` or
  // `grep -E 'x|y'` is one command, and `>` or `source` inside quotes is data. Expansions inside
  // double quotes stay visible.
  const m = maskQuotes(c);
  if (/>|`|\$\(|<\(|<<|(^|[;&|]\s*)\.\s|\bsudo\b|\btee\b|\bxargs\b|\beval\b|\bsource\b/.test(m)) return false;
  // zsh: =(cmd) runs cmd into a temporary file, and a ( right after word text is a glob qualifier
  // (*(e:cmd:), f(+func)) that runs code. Either way ( after anything but a separator is not read.
  // An escaped \( is a plain word (find . \( -name a -o -name b \)).
  if (/[^\s;&|<>()]\(/.test(m.replace(/\\[\s\S]/g, "__"))) return false;
  // `&` (background) separates commands just like `;`.
  const mk = maskQuotes(c, "_"), raws = [];
  let last = 0;
  for (const s of mk.matchAll(/&&|\|\||[;&|\n]/g)) { raws.push(c.slice(last, s.index)); last = s.index + s[0].length; }
  raws.push(c.slice(last));
  return raws.map(r => [maskQuotes(r).trim(), r]).filter(([s]) => s).every(([seg, raw]) => {
    while (KEYWORD.test(seg)) seg = seg.replace(KEYWORD, "");
    if (/^(done|fi|esac|\}|\)|else|then|do)$/.test(seg)) return true;
    const assign = seg.match(/^(export\s+)?(\w+=("[^"]*"|'[^']*'|\S*))$/);
    if (assign) return assignmentOk(assign[2]);
    if (extra.some(re => re.test(seg))) return true;
    // A header only; its body is its own segments. `case x in x) touch y` and `for i do touch y`
    // carry a command, so nothing may follow: case arms other than the header's are not read.
    if (/^for\s+\w+(\s+in(\s+[^\s]+)*)?$|^case\s+\S+\s+in$/.test(seg) && !/\s(do|done)(\s|$)/.test(seg)) return true;
    seg = seg.replace(/^case\s+\S+\s+in\s+\(?[^\s()]+\)\s*(?=\S)/, "");
    // Prefix assignments must be safe too; wrappers run whatever follows them, so judge what follows.
    const prefixes = seg.match(RO_PREFIX)?.[0] ?? "";
    if ((prefixes.match(/\w+=\S*/g) ?? []).some(a => !assignmentOk(a))) return false;
    // /usr/bin/grep is grep: a system directory holds the same program
    const [path, ...rest] = seg.slice(prefixes.length).split(/\s+/), head = path.replace(/^\/(usr\/)?bin\/(?=[\w.-]+$)/, "");
    if (FLAG_SENSITIVE.has(head) && argsUnsafe(raw, head)) return false;
    if (READ_ONLY.has(head)) return true;
    if (rest.length === 1 && /^--(version|help)$/.test(rest[0]) && /^[\w.-]+$/.test(head)) return true;
    const exec = head === "docker" && rest.join(" ").match(DOCKER_EXEC);
    if (exec) return readOnlyLegacy(exec.at(-1), [], depth + 1);
    return READ_ONLY_SUB[head]?.test(rest.join(" ")) ?? false;
  });
}

// ---------------------------------------------------------------------------------------------
// Read-only, simple (opt-in: "readonly": "simple"). readOnlyLegacy above understands a good part of the shell and was
// fooled about 50 ways in five reviews; this one understands almost none of it and refuses the rest.
// A command is read-only only when it is simple commands, pipelines of them, or both joined by ; && ||
// or a newline (no &, no redirect but 2>/dev/null and 2>&1, no $ ` ( ) { } * ? [ ] # ! < >, no $'...',
// and no backslash escape but \' between single-quoted parts), each program is in READ_ONLY_SIMPLE,
// and every flag it is given is on that program's list; `cd <literal path>` may stand between them. An
// unknown program, subcommand or flag is not read-only: it falls through to the rules and the engine.
// Words are judged as the shell passes them (quotes removed), so '-'X is -X. A word that names a
// secret file (SENSITIVE, /proc/…/environ) is never read-only, whatever the rules say.
// The default is readOnlyLegacy: on the author's last 7 days simple still sent 68.4 commands per 100 to a
// human against legacy's 54.8 (globs, $, ssh remote text). config.json "readonly": "simple" (or
// REFLEX_READONLY=simple) turns this one on.
export const READ_ONLY_MODE = ["legacy", "simple"].includes(ENV.REFLEX_READONLY ?? USER_CONFIG.readonly) ? ENV.REFLEX_READONLY ?? USER_CONFIG.readonly : "legacy";
export const readOnly = (cmd, extra = []) => READ_ONLY_MODE === "legacy" ? readOnlyLegacy(cmd, extra) : readOnlySimple(cmd, extra);

// The command as pipeline segments of words, or null for anything but plain words, pipes and ; && ||
// or newline between pipelines. The first segment of each pipeline has `first` set.
// Unquoted: letters, digits and _ @ % + = : , . / -, no word starts with = (zsh expands =cmd), and ~
// only as a word's first character before / or its end (zsh EXTENDED_GLOB reads ^ and a later ~ as globs).
// Single quotes are literal; double quotes may hold anything but $ ` ! and a backslash that escapes.
// Each segment's `view` is its words for the fast-lane patterns, a quoted word that is not an option
// written '' (the shape readOnlyLegacy gave them: `git commit -m ''`, `reflex check ''`).
const REDIRECT = /2>(&1|[ \t]*\/dev\/null)(?=[ \t|;&\n]|$)/y;
export function simpleSegments(cmd) {
  const segs = [Object.assign([], {first: true})];
  let w = null, quoted = false, i = 0;
  const end = () => {
    if (w === null) return;
    const s = segs.at(-1);
    s.push(w);
    (s.quoted ??= []).push(quoted);
    s.view = (s.view === undefined ? "" : s.view + " ") + (quoted && !/^[-+]/.test(w) ? "''" : w);
    w = null; quoted = false;
  };
  while (i < cmd.length) {
    const ch = cmd[i];
    REDIRECT.lastIndex = i;
    const r = w === null && REDIRECT.exec(cmd);
    if (r) { i += r[0].length; continue; }
    if (ch === " " || ch === "\t") { end(); i++; }
    // ; && || and a newline start a new pipeline; a lone & (background) and |& do not parse
    else if (ch === ";" || ch === "\n" || cmd.startsWith("&&", i) || cmd.startsWith("||", i)) {
      end(); if (!segs.at(-1).length) return null; segs.push(Object.assign([], {first: true})); i += ch === ";" || ch === "\n" ? 1 : 2;
    }
    else if (ch === "|") { end(); if (!segs.at(-1).length || cmd[i + 1] === "&") return null; segs.push([]); i++; }
    else if (ch === "'" || ch === '"') {
      const j = cmd.indexOf(ch, i + 1);
      if (j < 0) return null;
      const body = cmd.slice(i + 1, j);
      // a backslash that escapes (\$ \` \" \\) is refused; before any other character it is literal
      if (ch === '"' && /[$`!]|\\([$`"\\\n]|$)/.test(body)) return null;
      w = (w ?? "") + body; quoted = true; i = j + 1;
    }
    // the one escape: \' for a quote between single-quoted parts ('it'\''s'), as /reflex:check writes it
    else if (ch === "\\" && cmd[i + 1] === "'" && w !== null) { w += "'"; quoted = true; i += 2; }
    else if (/[\w@%+=:,./-]/.test(ch) && !(w === null && ch === "=")) { w = (w ?? "") + ch; i++; }
    else if (ch === "~" && w === null && /^(\/|[ \t|;&\n]|$)/.test(cmd.slice(i + 1, i + 2))) { segs.at(-1).tilde = true; w = "~"; i++; }
    else return null;
  }
  end();
  return segs.every(s => s.length) ? segs : null;
}

// Flags: `s` short flags that take no value, `v` short flags that take one (attached or the next
// word), `o` short flags whose value is optional and attached (-uno, -M50); `l` long flags without a
// value (a trailing ? allows an attached --name=value too), `lv` long flags with one; `num` allows -5.
// `pos`: what the positional words may be (true: any; false: none; a function of the list). A value
// in the next word never starts with -, so a flag this table thinks takes a value but the program
// does not can never hide an option behind it. `vals`: a check per flag name on its value.
const F = (s = "", v = "", l = [], lv = [], x = {}) => ({s, v, l, lv, pos: true, ...x});
function flagsOk(args, spec) {
  const pos = [], long = new Set(spec.l.map(n => n.replace(/\?$/, ""))), longVal = new Set(spec.l.filter(n => n.endsWith("?")).map(n => n.slice(0, -1)));
  const val = (name, v) => v !== undefined && (!spec.vals?.[name] || spec.vals[name](v));
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") { pos.push(...args.slice(i + 1)); break; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("="), name = eq < 0 ? a.slice(2) : a.slice(2, eq), v = eq < 0 ? undefined : a.slice(eq + 1);
      if (spec.lv.includes(name)) { const x = v ?? args[++i]; if (x === undefined || (v === undefined && x.startsWith("-") && x !== "-") || !val(name, x)) return false; }
      else if (!(long.has(name) && (v === undefined || longVal.has(name)))) return false;
    } else if (a.startsWith("-") && a !== "-") {
      if (spec.num && /^-\d+$/.test(a)) continue;
      for (let k = 1; k < a.length; k++) {
        const c = a[k];
        if (spec.o?.includes(c)) break;
        if (spec.v.includes(c)) {
          const x = k + 1 < a.length ? a.slice(k + 1) : args[++i];
          if (x === undefined || (k + 1 === a.length && x.startsWith("-") && x !== "-") || !val(c, x)) return false;
          break;
        }
        if (!spec.s.includes(c)) return false;
      }
    } else pos.push(a);
  }
  return spec.pos === true || (spec.pos === false ? !pos.length : spec.pos(pos));
}
const only = x => ({...x, pos: false});
const upTo = n => p => p.length <= n;

// git: -C <dir> and --no-pager before the subcommand, never -c (config runs programs: core.pager,
// diff.external, aliases). Left out everywhere: --output, --ext-diff, --textconv, --show-signature
// (runs gpg), -O for grep (a pager). A repository's own config still applies (a diff.external or
// core.fsmonitor set in .git/config runs), as it does for every git command the agent runs.
// %G… and %(signature…) in a format verify signatures, which runs gpg.program
const NO_SIG = v => !/%G|%\(signature/.test(v), SIG_VALS = {vals: {format: NO_SIG, pretty: NO_SIG}};
const GIT_LOG = F("pusmcrtzwbRaiEFPgWNqh", "nSGL", [
  "oneline", "graph", "all", "branches?", "tags?", "remotes?", "stat?", "shortstat", "numstat", "name-only", "name-status", "patch", "no-patch",
  "decorate?", "no-decorate", "abbrev-commit", "no-abbrev-commit", "abbrev?", "reverse", "first-parent", "merges", "no-merges", "follow", "left-right",
  "cherry-pick", "cherry-mark", "cherry", "topo-order", "date-order", "author-date-order", "boundary", "source", "full-history", "simplify-by-decoration",
  "ancestry-path", "walk-reflogs", "color?", "no-color", "raw", "summary", "full-diff", "no-ext-diff", "no-textconv", "relative-date", "all-match",
  "invert-grep", "regexp-ignore-case", "extended-regexp", "fixed-strings", "perl-regexp", "basic-regexp", "parents", "children", "left-only",
  "right-only", "no-walk?", "do-walk", "pickaxe-all", "pickaxe-regex", "find-renames?", "find-copies?", "word-diff?", "ignore-all-space",
  "ignore-space-change", "ignore-blank-lines", "minimal", "patience", "histogram", "compact-summary", "dirstat?", "cc", "mailmap", "use-mailmap",
  "no-mailmap", "not", "cached", "staged", "no-index", "merge-base", "exit-code", "quiet", "check", "relative?", "no-renames", "binary", "full-index",
  "unified?", "function-context", "ignore-cr-at-eol", "text", "no-prefix", "diff-merges?", "no-diff-merges", "show-notes?", "no-notes", "expand-tabs?",
], ["format", "pretty", "author", "committer", "since", "until", "after", "before", "grep", "max-count", "skip", "date", "min-parents", "max-parents",
  "glob", "exclude", "diff-filter", "decorate-refs", "decorate-refs-exclude", "stat-width", "encoding", "ignore-matching-lines", "anchored",
  "word-diff-regex", "inter-hunk-context", "src-prefix", "dst-prefix", "line-prefix", "since-as-filter"], {o: "MCBUlO", num: true, ...SIG_VALS});
const GIT_BRANCH_LIST = ["list", "contains", "no-contains", "merged", "no-merged", "points-at"];
const GIT = {
  status: F("sbuvz", "", ["short", "branch", "porcelain?", "long", "verbose", "untracked-files?", "ignored?", "ignore-submodules?", "show-stash",
    "ahead-behind", "no-ahead-behind", "renames", "no-renames", "column?", "no-column", "find-renames?"], [], {o: "u"}),
  log: GIT_LOG, show: GIT_LOG, diff: GIT_LOG, shortlog: {...GIT_LOG, l: [...GIT_LOG.l, "summary", "numbered", "email"], lv: [...GIT_LOG.lv, "group"], s: GIT_LOG.s + "ne", o: "w"},
  // a branch name creates a branch, unless a list flag makes it a pattern
  branch: {...F("arvl", "", ["all", "remotes", "verbose", "list", "show-current", "merged?", "no-merged?", "color?", "no-color", "column?", "no-column",
    "omit-empty", "ignore-case"], ["contains", "no-contains", "points-at", "sort", "format", "abbrev"], SIG_VALS), pos: p => !p.length},
  "rev-parse": F("q", "", ["abbrev-ref?", "short?", "show-toplevel", "git-dir", "git-common-dir", "absolute-git-dir", "is-inside-work-tree", "is-inside-git-dir",
    "is-bare-repository", "is-shallow-repository", "show-prefix", "show-cdup", "show-superproject-working-tree", "verify", "quiet", "symbolic",
    "symbolic-full-name", "all", "branches?", "tags?", "remotes?", "show-object-format?", "show-ref-format", "sq", "not", "revs-only", "no-revs",
    "flags", "no-flags"], ["git-path", "default", "since", "until", "after", "before", "prefix"]),
  "ls-files": F("cdmoiskuzvtfe", "x", ["cached", "deleted", "modified", "others", "ignored", "stage", "killed", "unmerged", "exclude-standard", "directory",
    "no-empty-directory", "full-name", "error-unmatch", "recurse-submodules", "deduplicate", "eol", "sparse", "abbrev?"], ["exclude", "with-tree", "format"], SIG_VALS),
  "ls-tree": F("rdtlz", "", ["name-only", "name-status", "object-only", "full-name", "full-tree", "long", "abbrev?"], ["format"]),
  blame: F("blnpstwefck", "L", ["porcelain", "line-porcelain", "incremental", "show-email", "show-name", "show-number", "root", "show-stats", "abbrev?",
    "color-lines", "color-by-age", "minimal"], ["date", "ignore-rev"], {o: "MC"}),
  describe: F("", "", ["tags", "all", "always", "long", "exact-match", "first-parent", "dirty?", "broken?", "contains", "abbrev?"], ["match", "exclude", "candidates"]),
  "merge-base": F("a", "", ["all", "is-ancestor", "fork-point", "octopus", "independent"]),
  "show-ref": F("dsq", "", ["head", "heads", "tags", "branches", "dereference", "hash?", "verify", "quiet", "abbrev?", "exists"]),
  "for-each-ref": F("", "", ["no-merged?", "merged?", "include-root-refs", "ignore-case", "omit-empty"], ["format", "sort", "count", "points-at", "contains", "no-contains", "exclude"], SIG_VALS),
  "rev-list": {...GIT_LOG, l: [...GIT_LOG.l, "count", "objects", "no-object-names", "timestamp", "header", "left-right"]},
};
const gitSub = {
  remote: a => !a.length || (a.length === 1 && /^(-v|--verbose)$/.test(a[0])) || (a[0] === "get-url" && flagsOk(a.slice(1), F("", "", ["push", "all"], [], {pos: upTo(1)}))),
  tag: a => !a.length || (a.some(x => /^(-l|--list)$/.test(x)) && flagsOk(a, F("ln", "", ["list", "column?", "no-column", "ignore-case", "omit-empty", "merged?", "no-merged?"],
    ["sort", "format", "contains", "no-contains", "points-at"], {o: "n", ...SIG_VALS}))),
  stash: a => a[0] === "list" ? flagsOk(a.slice(1), {...GIT_LOG, pos: false}) : a[0] === "show" && flagsOk(a.slice(1), {...GIT_LOG, pos: upTo(1)}),
  "ls-remote": a => flagsOk(a, F("qht", "", ["heads", "tags", "branches", "refs", "quiet", "exit-code", "symref", "get-url"], ["sort"],
    {pos: p => !!p.length && /^(https:\/\/github\.com\/[\w.\/-]+|git@github\.com:[\w.\/-]+|[\w.-]+)$/.test(p[0])})),
  worktree: a => a[0] === "list" && flagsOk(a.slice(1), only(F("vz", "", ["porcelain", "verbose"], ["expire"]))),
  branch: a => (a.some(x => GIT_BRANCH_LIST.some(f => x === `--${f}` || x.startsWith(`--${f}=`)) || x === "-l") ? flagsOk(a, {...GIT.branch, pos: true}) : flagsOk(a, GIT.branch)),
};
function gitOk(a) {
  let i = 0;
  for (; i < a.length; i++) {
    if (a[i] === "--no-pager" || a[i] === "-P" || a[i] === "--no-optional-locks") continue;
    if (a[i] === "-C" && a[i + 1] !== undefined && !a[i + 1].startsWith("-")) { i++; continue; }
    break;
  }
  const sub = a[i], rest = a.slice(i + 1);
  const own = (o, k) => Object.hasOwn(o, k ?? "");   // `git constructor` is no subcommand here (a repo alias could be one)
  return own(gitSub, sub) ? gitSub[sub](rest) : own(GIT, sub) && flagsOk(rest, GIT[sub]);
}

// kubectl get and describe: no --kubeconfig, --token, --server or --as (each changes who is asked or
// runs a credential plugin), no --raw, and no Secret (secret, secrets, secret/x, pods,secrets).
const KUBE_OUT = /^(wide|yaml|json|name|(jsonpath|jsonpath-as-json|custom-columns|go-template)=.*)$/;
const KUBE_VALUE = /^(-n|--namespace|--context|--cluster|--request-timeout)$/;
const KUBE = {
  get: F("wA" , "nolL", ["all-namespaces", "show-labels", "watch", "watch-only", "no-headers", "ignore-not-found", "show-kind", "output-watch-events", "show-managed-fields"],
    ["namespace", "context", "cluster", "request-timeout", "output", "selector", "field-selector", "sort-by", "label-columns", "chunk-size", "subresource"], {vals: {o: v => KUBE_OUT.test(v), output: v => KUBE_OUT.test(v)}}),
  describe: F("A", "nl", ["all-namespaces", "show-events?"], ["namespace", "context", "cluster", "request-timeout", "selector", "chunk-size"]),
};
function kubectlOk(a) {
  // the options before the subcommand (-n x, --context c, -A) are judged with the subcommand's list
  let i = 0;
  while (i < a.length && a[i].startsWith("-")) i += KUBE_VALUE.test(a[i]) ? 2 : 1;
  const sub = a[i];
  if (!Object.hasOwn(KUBE, sub ?? "") || a.some(x => x.split(",").some(r => /^secrets?(\.|\/|$)/i.test(r)))) return false;
  return flagsOk([...a.slice(0, i), ...a.slice(i + 1)], KUBE[sub]);
}

// aws <service> describe-*, list-*, get-*: the API is a read, so any parameter it takes is one, but the
// CLI's own options are an allowlist (no --endpoint-url, --cli-input-*, --debug, --ca-bundle), no
// value is read from a file (file://, fileb://), and each value follows a parameter: no trailing
// outfile (s3api get-object writes one). Operations that return a secret are not reads here:
// secrets, passwords, tokens, credentials, login and auth values, key pairs, decryption, and
// --with-decryption / --include-value(s).
const AWS_CLI_OPTS = new Set(["profile", "region", "output", "query", "color", "no-cli-pager", "no-paginate", "cli-read-timeout", "cli-connect-timeout",
  "no-sign-request", "cli-binary-format", "page-size", "max-items", "starting-token"]);
// argparse also takes a prefix (--with-decrypt, --endpoint, --debu): any prefix of these is refused too
const AWS_CLI_ONLY_NAMES = ["endpoint-url", "cli-input-json", "cli-input-yaml", "generate-cli-skeleton", "debug", "ca-bundle", "no-verify-ssl",
  "cli-auto-prompt", "no-cli-auto-prompt", "with-decryption", "include-value", "include-values", "outfile"];
const AWS_CLI_ONLY = /^--(endpoint-url|cli-input-json|cli-input-yaml|generate-cli-skeleton|debug|ca-bundle|no-verify-ssl|cli-auto-prompt|no-cli-auto-prompt|with-decryption|include-values?|outfile)(=|$)/;
// Streaming operations write their output to a file named last (get-object, get-export, ...): those too.
const AWS_NOT_READ = new RegExp("secret|passw|token|credential|login|auth|access-details|key-pair|api-key|private-key|decrypt|session|federation|sign|" +
  "stream-key|instance-access|compute-access|^get-connections?$|thumbnail|" +
  "get-(object|job-output|media|clip|export|sdk|configuration|latest-configuration|package-version-asset|read-set|reference|tile|snapshot-block|raw|images|" +
  "chunk|work-unit-results|image-frame|image-set-metadata)");
const AWS_NO_VALUE = /^--(no-[\w-]+|dry-run|recursive|human-readable|summarize)$/;
function awsOk(a) {
  let i = 0;
  // globals before the service take a value, except those that never do
  for (; i < a.length && a[i].startsWith("--"); i++) {
    const name = a[i].slice(2).split("=")[0];
    if (!AWS_CLI_OPTS.has(name)) return false;
    if (!AWS_NO_VALUE.test(a[i]) && !a[i].includes("=")) i++;
  }
  const [service, op, ...rest] = a.slice(i);
  if (!service || !op || op.startsWith("-") || service.startsWith("-")) return false;
  if (rest.some(x => /^fileb?:\/\//i.test(x.replace(/^--[\w-]+=/, "")) || AWS_CLI_ONLY.test(x) || (x.startsWith("-") && !/^--[a-z][a-z0-9-]*(=|$)/.test(x)) ||
      (x.startsWith("--") && AWS_CLI_ONLY_NAMES.some(n => n.startsWith(x.slice(2).split("=")[0]))))) return false;
  if (service === "s3") return op === "ls" && flagsOk(rest, F("", "", ["recursive", "human-readable", "summarize", "no-cli-pager", "no-paginate"],
    ["profile", "region", "output", "page-size", "query", "color", "request-payer"], {pos: upTo(1)}));
  if (service === "configure") return /^(list|list-profiles)$/.test(op) && flagsOk(rest, only(F("", "", [], ["profile"])));
  if (!/^(describe|list|get)-[a-z0-9-]+$/.test(op) || AWS_NOT_READ.test(op)) return false;
  // every word that is not a parameter is the value of the one before it
  return rest.every((x, k) => x.startsWith("--") || (k > 0 && rest[k - 1].startsWith("--") && !rest[k - 1].includes("=") && !AWS_NO_VALUE.test(rest[k - 1])));
}

// jq: no program from a file (-f, --from-file), no file read into a variable (--rawfile,
// --slurpfile), no module path (-L), and no program that reads the environment ($ENV, env, which hold
// API keys) or imports a module.
const JQ = F("rcensSjaCMRe0", "", ["raw-output", "compact-output", "exit-status", "null-input", "slurp", "sort-keys", "join-output", "ascii-output", "color-output",
  "monochrome-output", "raw-input", "tab", "seq", "stream", "stream-errors", "raw-output0", "unbuffered"]);
const JQ_UNSAFE = /\$ENV\b|(^|[^.\w$])env\b|\b(import|include|modulemeta|get_search_list|input_filename)\b|\$__prog/;
function jqOk(a) {
  const rest = [];
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--arg" || a[i] === "--argjson") { if (a[i + 2] === undefined || !/^\w+$/.test(a[i + 1])) return false; i += 2; continue; }
    rest.push(a[i]);
  }
  if (!flagsOk(rest, JQ)) return false;
  if (rest.includes("--")) return false;
  const filter = rest.find(x => !x.startsWith("-") || x === "-");
  return filter === undefined || !JQ_UNSAFE.test(filter);
}

// terraform: version, and fmt only when it cannot write (-check or -write=false). Nothing that
// starts a provider binary from .terraform (plan, show, validate, state, providers, graph, output).
function terraformOk(a) {
  if (a[0]?.startsWith("-chdir=")) a = a.slice(1);
  const [sub, ...rest] = a;
  if (sub === "version") return rest.every(x => x === "-json");
  if (/^-{1,2}(version|v)$/.test(sub)) return !rest.length;
  return sub === "fmt" && rest.some(x => x === "-check" || x === "-write=false") &&
    rest.every(x => /^-(check|recursive|no-color|list=(true|false)|write=false)$/.test(x) || !x.startsWith("-"));
}

// docker ps, images and logs: no --config (a credential helper), no -H or other daemons than the context.
const DOCKER = {
  ps: only(F("aqsl", "nf", ["all", "quiet", "size", "latest", "no-trunc"], ["last", "filter", "format"])),
  images: F("aq", "f", ["all", "quiet", "digests", "no-trunc", "tree"], ["filter", "format"], {pos: upTo(1)}),
  logs: F("ft", "n", ["follow", "timestamps", "details"], ["tail", "since", "until"], {pos: p => p.length === 1}),
};
function dockerOk(a) {
  if (a[0] === "--context" && a[1] && !a[1].startsWith("-")) a = a.slice(2);
  return Object.hasOwn(DOCKER, a[0] ?? "") && flagsOk(a.slice(1), DOCKER[a[0]]);
}

// sed only as a printer: -n with line-number p commands (5p, 10,20p, $p), or Nq. Any other program
// text is refused: sed can write (w, W, s///w) and run commands (e, s///e).
const SED_PRINT = /^(\d+|\$)(,(\d+|\$|\+\d+))?p(;(\d+|\$)(,(\d+|\$|\+\d+))?p)*$/;
function sedOk(a) {
  if (a[0] === "-n") { const prog = a[1] === "-e" ? a[2] : a[1], files = a.slice(a[1] === "-e" ? 3 : 2); return !!prog && SED_PRINT.test(prog) && files.every(f => !f.startsWith("-")); }
  return /^\d+q$/.test(a[0] ?? "") && a.slice(1).every(f => !f.startsWith("-"));
}
// find with tests and print actions only: no -exec, -execdir, -ok, -okdir, -delete, -fprint*, -fls.
const FIND_BOOL = new Set(["-print", "-print0", "-ls", "-prune", "-quit", "-true", "-false", "-empty", "-readable", "-writable", "-executable", "-xdev", "-mount",
  "-depth", "-follow", "-nouser", "-nogroup", "-o", "-a", "-or", "-and", "-not", "!", "(", ")", "-daystart", "-noleaf"]);
const FIND_VALUE = new Set(["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-type", "-xtype", "-maxdepth", "-mindepth",
  "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-newer", "-anewer", "-cnewer", "-size", "-user", "-group", "-uid", "-gid", "-perm", "-links",
  "-inum", "-samefile", "-lname", "-ilname", "-printf", "-regextype", "-fstype", "-newermt", "-newerct", "-newerat", "-used"]);
function findOk(a) {
  let i = 0;
  while (i < a.length && /^-[HLPEsx]$/.test(a[i])) i++;
  while (i < a.length && !a[i].startsWith("-") && !["(", ")", "!"].includes(a[i])) i++;
  for (; i < a.length; i++) {
    if (FIND_VALUE.has(a[i])) { if (a[++i] === undefined) return false; }
    else if (!FIND_BOOL.has(a[i])) return false;
  }
  return true;
}
// gh: pr, issue, run, repo and release reads, auth status without --show-token, and api as a GET
// (no -X, --method, -f, -F, --field, --raw-field, --input or -H, and not graphql). No --web (runs a browser).
// gh's --jq is gojq with the process environment ($ENV.GH_TOKEN): held to jq's rule
const GH_JQ = {vals: {q: v => !JQ_UNSAFE.test(v), jq: v => !JQ_UNSAFE.test(v)}};
const GH_READ = F("", "RqtLsAlBHSacbuej", ["json?", "comments", "log", "log-failed", "watch", "required", "fail-fast", "exit-status", "name-only", "patch", "draft",
  "verbose", "all", "exclude-drafts", "exclude-pre-releases"], ["repo", "jq", "template", "limit", "state", "author", "label", "base", "head", "search", "assignee",
  "mention", "milestone", "status", "commit", "created", "job", "attempt", "branch", "user", "event", "workflow", "interval", "color", "app", "json", "order", "sort"], GH_JQ);
const GH = {pr: /^(view|list|checks|diff|status)$/, issue: /^(view|list|status)$/, run: /^(view|list|watch)$/, repo: /^view$/, release: /^(view|list)$/};
function ghOk(a) {
  const [group, sub, ...rest] = a;
  if (group === "auth") return sub === "status" && flagsOk(rest, only(F("a", "h", ["active"], ["hostname"])));
  // an endpoint path on the GitHub host: a full URL to another host carries data out in its path
  if (group === "api") return !!sub && sub !== "graphql" && !sub.startsWith("-") && !/^[a-z]+:\/\//i.test(sub) &&
    flagsOk(rest, only(F("iq", "qt", ["paginate", "slurp", "include", "silent", "verbose"], ["jq", "template", "cache"], GH_JQ)));
  return Object.hasOwn(GH, group ?? "") && GH[group].test(sub ?? "") && flagsOk(rest, GH_READ);
}
// ssh host '<read-only>': ssh joins the words after the host with spaces and the remote shell reads
// them, so that text must be read-only by these same rules. A literal [user@]host, a few options (no
// -J, -F, ProxyCommand, forwards, -i, or any other -o), never fed by a pipe, never a login.
const SSH_OPT = /^(ConnectTimeout=\d+|BatchMode=(yes|no)|StrictHostKeyChecking=(yes|no|accept-new)|ServerAliveInterval=\d+|ServerAliveCountMax=\d+|ConnectionAttempts=\d+|LogLevel=\w+)$/i;
function sshOk(a, {first, tilde}) {
  let i = 0;
  for (; i < a.length && a[i].startsWith("-"); i++) {
    if (/^-[nTqt46C]+$/.test(a[i])) continue;
    const o = a[i] === "-o" ? a[++i] : a[i].startsWith("-o") ? a[i].slice(2) : null, p = a[i] === "-p" ? a[++i] : a[i].startsWith("-p") ? a[i].slice(2) : null;
    if (!(o !== null ? o !== undefined && SSH_OPT.test(o) : p !== null ? /^\d+$/.test(p ?? "") : false)) return false;
  }
  const host = a[i], remote = a.slice(i + 1).join(" ");
  if (remote.includes("\\")) return false;   // a remote fish shell reads \' inside '...' as a quote
  // a remote csh reads a quoted newline as the end of the command, and 2>&1 as `2 >& 1` (a file named 1)
  if (/[\0-\x1f\x7f]|>&/.test(remote)) return false;
  // an unquoted ~ is the local home, sent to the host: refused
  return first && !tilde && !!host && /^([\w][\w.-]*@)?[\w][\w.-]*$/.test(host) && !!remote.trim() && readOnlySimple(remote);
}

// ps without the environment of other processes (it holds keys): no -E, and no e among BSD-style
// letters (`ps eww`, `ps auxe`). A value follows -o -O -p -t -u -U -g -G -k -C; any other plain word
// is BSD-style letters or process ids.
function psOk(a) {
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    if (x.startsWith("--")) { if (!/^--(sort|format|pid|ppid|user|cols|columns|width)=[\w,%:.+-]+$|^--(forest|no-headers|headers)$/.test(x)) return false; }
    else if (x.startsWith("-")) {
      // bool letters, then at most one value letter with its value attached or in the next word
      const m = /^-([AacdefFhHjlLMmrSTvwxXZ]*)([oOptuUgGkC]?)(.*)$/.exec(x), value = /^[\w,%:.+=]+$/;
      if (!m || x.includes("E") || (!m[2] && m[3]) || (m[2] && !(m[3] ? value.test(m[3]) : value.test(a[++i] ?? "")))) return false;
    } else if (!(/^[auxwjlmrvcfhHSTZ]+$/.test(x) || /^[\d,]+$/.test(x))) return false;
  }
  return true;
}
// nvidia-smi queries: no setter (-pm, -pl, -r, -e, -c, clocks, MIG) and no -f (writes a log file).
const NVSMI = F("qLxu", "dil", ["query-supported-clocks", "unit"], ["query-gpu", "query-compute-apps", "query-accounted-apps", "query-retired-pages", "format", "id", "display", "loop", "loop-ms"], {pos: false});
const nvidiaOk = a => a[0] === "topo" ? a.length === 2 && a[1] === "-m" : flagsOk(a, NVSMI);

// `<tool> --version` for tools whose --version runs nothing the working directory chose (not go,
// cargo, pnpm or yarn, which may fetch and run a toolchain the project names).
const VERSION_ONLY = new Set(["node", "npm", "python3", "python", "git", "docker", "aws", "terraform", "kubectl", "helm", "jq", "rg", "gh", "uv", "brew", "make"]);

export const READ_ONLY_SIMPLE = {
  ls: F("1aAbBcCdeFfGghHiklLmnOopqrRsStTuUvwxX@", "", ["all", "almost-all", "human-readable", "color?", "classify", "directory", "recursive", "reverse", "size",
    "inode", "numeric-uid-gid", "no-group", "group-directories-first", "full-time", "dereference", "si"], ["sort", "time", "format", "time-style", "width", "ignore", "hide", "block-size"]),
  pwd: only(F("LP")), whoami: only(F()), nproc: only(F("", "", ["all"], ["ignore"])),
  uname: only(F("amnprsvio", "", ["all", "kernel-name", "nodename", "kernel-release", "kernel-version", "machine", "processor", "hardware-platform", "operating-system"])),
  // no -s / --set, and an operand only as +FORMAT (an operand without + sets the clock)
  date: F("uRjn", "drvfz", ["utc", "universal", "rfc-email", "iso-8601?", "debug"], ["date", "reference", "rfc-3339"], {o: "I", pos: p => p.length <= 1 && p.every(x => x.startsWith("+"))}),
  cat: F("benstuvAETl", "", ["number", "number-nonblank", "show-all", "show-ends", "show-tabs", "squeeze-blank", "show-nonprinting"]),
  head: F("qv", "nc", ["quiet", "silent", "verbose"], ["lines", "bytes"], {num: true}),
  tail: F("fFqvr", "ncs", ["follow?", "retry", "quiet", "silent", "verbose"], ["lines", "bytes", "sleep-interval", "pid"], {num: true}),
  wc: F("clmwL", "", ["bytes", "chars", "lines", "words", "max-line-length"]),
  // patterns from a file only from stdin (-f -)
  grep: F("EFGPiyvwxclLoqsbHhnTZzaIrRU", "efABCmdD", ["extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp", "ignore-case", "no-ignore-case", "invert-match",
    "word-regexp", "line-regexp", "count", "color?", "colour?", "files-with-matches", "files-without-match", "only-matching", "quiet", "silent", "no-messages",
    "byte-offset", "with-filename", "no-filename", "line-number", "initial-tab", "null", "null-data", "text", "recursive", "dereference-recursive", "line-buffered"],
    ["regexp", "file", "after-context", "before-context", "context", "max-count", "include", "exclude", "exclude-dir", "binary-files", "label", "devices", "directories"],
    {num: true, vals: {f: v => v === "-", file: v => v === "-"}}),
  // no --pre, --pre-glob or --hostname-bin (they run a program), no -z (runs decompressors)
  rg: F("iISsFwxvnNlcoqLHhp0uUP.", "egtTmABCMdjrf", ["hidden", "no-ignore", "no-ignore-vcs", "no-ignore-dot", "no-ignore-parent", "ignore-case", "smart-case",
    "case-sensitive", "fixed-strings", "word-regexp", "line-regexp", "invert-match", "line-number", "no-line-number", "files", "files-with-matches",
    "files-without-match", "count", "count-matches", "only-matching", "quiet", "follow", "no-heading", "heading", "with-filename", "no-filename", "vimgrep", "json",
    "column", "no-column", "no-messages", "multiline", "multiline-dotall", "pcre2", "trim", "stats", "null", "byte-offset", "passthru", "no-config", "unrestricted",
    "text", "binary", "one-file-system", "crlf", "glob-case-insensitive", "max-columns-preview", "no-require-git", "type-list", "pretty", "no-unicode"],
    ["glob", "iglob", "type", "type-not", "max-count", "context", "after-context", "before-context", "max-depth", "max-columns", "color", "colors", "sort", "sortr",
    "replace", "regexp", "threads", "max-filesize", "path-separator", "context-separator", "field-match-separator", "encoding", "engine", "file"],
    {vals: {f: v => v === "-", file: v => v === "-"}}),
  echo: {...F(), any: true}, printf: {test: a => !!a.length && !a[0].startsWith("-")},
  // no -o (writes), -T (a temporary directory), --compress-program (runs one)
  sort: F("bdfgiMhnRrVcCsuzm", "ktS", ["reverse", "numeric-sort", "unique", "human-numeric-sort", "version-sort", "ignore-case", "ignore-leading-blanks",
    "general-numeric-sort", "month-sort", "stable", "zero-terminated", "check?", "dictionary-order", "ignore-nonprinting", "merge"], ["key", "field-separator", "buffer-size", "parallel"]),
  // `uniq in out` writes out
  uniq: F("cdDuiz", "fsw", ["count", "repeated", "unique", "ignore-case", "zero-terminated", "all-repeated?", "group?"], ["skip-fields", "skip-chars", "check-chars"], {pos: upTo(1)}),
  cut: F("snz", "bcdf", ["only-delimited", "complement", "zero-terminated"], ["bytes", "characters", "delimiter", "fields", "output-delimiter"]),
  tr: F("cdsCt", "", ["complement", "delete", "squeeze-repeats", "truncate-set1"]),
  basename: F("az", "s", ["multiple", "zero"], ["suffix"]), dirname: F("z", "", ["zero"]),
  realpath: F("eLmPqsz", "", ["canonicalize-existing", "canonicalize-missing", "logical", "physical", "quiet", "strip", "no-symlinks", "zero"], ["relative-to", "relative-base"]),
  readlink: F("efmnqsvz", "", ["canonicalize", "canonicalize-existing", "canonicalize-missing", "no-newline", "quiet", "silent", "verbose", "zero"]),
  stat: F("LlnqrsxF", "fct", ["dereference", "file-system", "terse"], ["format", "printf"]),
  // no -C (compiles a magic file), -m (reads one), -z / -Z (run decompressors)
  file: F("bchiIkLNnrsSvE0", "eFP", ["brief", "mime", "mime-type", "mime-encoding", "dereference", "no-dereference", "keep-going", "special-files", "no-pad", "raw", "print0"], ["exclude", "separator"]),
  du: F("aAbchHklLmsxgP0", "dBtI", ["all", "apparent-size", "human-readable", "summarize", "total", "si", "one-file-system", "count-links", "dereference", "null"],
    ["max-depth", "block-size", "exclude", "threshold"]),
  df: F("ahHiklPTgm", "Btx", ["all", "human-readable", "si", "inodes", "local", "portability", "print-type", "total", "no-sync", "sync"], ["block-size", "type", "exclude-type"]),
  // no -o (writes), -R (runs tree again, writing with -H), -H
  tree: F("adlfixpugsDFqNQrtvUhCJ", "LIP", ["noreport", "dirsfirst", "gitignore", "du", "prune", "matchdirs", "ignore-case", "si"], ["filelimit", "sort", "charset", "timefmt"]),
  diff: F("abBdEiNpqrsStTuwy", "UCWI", ["brief", "report-identical-files", "recursive", "new-file", "unidirectional-new-file", "ignore-case", "ignore-all-space",
    "ignore-space-change", "ignore-blank-lines", "text", "side-by-side", "suppress-common-lines", "color?", "minimal", "strip-trailing-cr", "expand-tabs", "initial-tab",
    "show-c-function", "no-dereference", "speed-large-files", "unified?", "context?"], ["exclude", "label", "width", "palette", "ignore-matching-lines"]),
  cmp: F("bls", "in", ["print-bytes", "verbose", "silent", "quiet"], ["ignore-initial", "bytes"]),
  comm: F("123iz", "", ["check-order", "nocheck-order", "total", "zero-terminated"], ["output-delimiter"]),
  paste: F("sz", "d", ["serial", "zero-terminated"], ["delimiters"]),
  column: F("tnxeJ", "scoNRWHOdl", ["table", "json", "keep-empty-lines", "fillrows"], ["separator", "output-separator", "table-columns", "table-name"]),
  nl: F("p", "bdfhilnsvw"), fold: F("bs", "w", ["bytes", "spaces"], ["width"]), rev: F(), tac: F("brs"),
  od: F("bcdfiloxvsDFOX", "AjNtw", ["verbose"], ["address-radix", "skip-bytes", "read-bytes", "format", "width?"]),
  strings: F("afow", "nte", ["all", "print-file-name"], ["bytes", "radix", "encoding"]),
  shasum: F("bctUp0", "a", ["binary", "check", "text", "status", "quiet", "warn", "strict", "tag", "zero", "ignore-missing"], ["algorithm"]),
  sha256sum: F("bctwz", "", ["binary", "check", "text", "status", "quiet", "warn", "strict", "tag", "zero", "ignore-missing"]),
  md5: F("pqrnt", "s"), md5sum: F("bctwz", "", ["binary", "check", "text", "status", "quiet", "warn", "strict", "tag", "zero", "ignore-missing"]),
  which: F("as"), type: F("afptP"), id: F("GgnrupPaAFM"),
  hostname: only(F("fsdiIAa", "", ["fqdn", "short", "domain", "ip-address", "all-ip-addresses", "all-fqdns"])),
  uptime: only(F("ps", "", ["pretty", "since"])), sw_vers: {test: a => a.every(x => /^--?(productName|productVersion|productVersionExtra|buildVersion)$/.test(x))},
  sleep: {test: a => a.length === 1 && /^\d+(\.\d+)?[smh]?$/.test(a[0])},
  git: {test: gitOk}, kubectl: {test: kubectlOk}, aws: {test: awsOk}, jq: {test: jqOk}, terraform: {test: terraformOk}, docker: {test: dockerOk},
  sed: {test: sedOk}, find: {test: findOk}, gh: {test: ghOk}, ssh: {test: sshOk}, ps: {test: psOk}, "nvidia-smi": {test: nvidiaOk},
  // pgrep lists; never -F (reads a pid file) or pkill
  pgrep: F("filnoqvxacLr", "dugGPtsU", ["full", "list-name", "list-full", "newest", "oldest", "exact", "ignore-case", "count", "inverse"], ["delimiter", "euid", "uid", "group", "parent", "terminal", "session"]),
};
READ_ONLY_SIMPLE.egrep = READ_ONLY_SIMPLE.fgrep = READ_ONLY_SIMPLE.grep;
// A public key, known_hosts and an .env template are not secrets.
// A secret directory counts named without a trailing slash (grep -r x ~/.ssh), and so do common token files.
const SECRET_WORD = /(^|\/)\.(ssh|aws|gnupg|kube|docker)(\/|$)|(^|\/)(environ|\.git-credentials|\.pgpass|\.vault-token|hosts\.yml|auth\.json|\.credentials\.json|credentials\.(toml|json)|\.tfrc\.json|credentials\.tfrc\.json|application_default_credentials\.json)$/;
const SIMPLE_SECRET = w => [w, w.replace(/^-[^=]*=/, ""), w.replace(/^[^:]*:/, "")].some(x => (SENSITIVE.test(x) || SECRET_WORD.test(x)) &&
  !/\.pub$|(^|\/)known_hosts$|\.env\.(example|sample|template|dist)$/.test(x));

// `extra`: segment patterns that are safe but not read-only (the fast lanes), tested on the segment's
// view (simpleSegments), and only in a command that is one pipeline: a chain is read-only or nothing.
// `cd <path>` is a pipeline of its own, next to others, with one literal path word: no - or + (the
// previous or a stacked directory), no $ ` \ glob or brace character, a ~ only as the home (the
// tokenizer refuses ~user). A word after it is also judged as a path from there, so `cd ~/.ssh` and
// `cd ~ && cat .ssh/id_rsa` stay secret reads. The tamper check sees the cd (cdDirs, staysNested):
// it runs before this.
const CD_PATH = /^(~(\/[^\0-\x1f$`\\*?[\]{}]*)?|[^-+~\0-\x1f$`\\*?[\]{}][^\0-\x1f$`\\*?[\]{}]*)$/;
export function readOnlySimple(cmd, extra = []) {
  const segs = simpleSegments(String(cmd).trim());
  if (!segs) return false;
  const chain = segs.some((s, n) => n > 0 && s.first);
  let dir = null;
  return segs.some(s => !(s.first && s[0] === "cd")) && segs.every((words, n) => {
    if (words.some(SIMPLE_SECRET) || (dir !== null && words.some(w => !w.startsWith("-") && SIMPLE_SECRET(posix.join(dir, w))))) return false;
    if (words[0] === "cd" && !words.quoted[0]) {
      if (!words.first || !(n + 1 === segs.length || segs[n + 1].first) || words.length !== 2 || !CD_PATH.test(words[1])) return false;
      dir = dir === null || /^[/~]/.test(words[1]) ? words[1] : posix.join(dir, words[1]);
      return true;
    }
    if (!chain && extra.some(re => re.test(words.view))) return true;
    // AWS selectors (unquoted: a quoted one is a program name), then rtk proxy
    let k = 0;
    while (k < words.length - 1 && !words.quoted[k] && /^(AWS_PROFILE|AWS_REGION|AWS_DEFAULT_REGION)=[\w.-]*$/.test(words[k])) k++;
    // rtk proxy runs the command as it is; rtk's own subcommands re-implement tools (rtk grep is rg)
    if (words[k] === "rtk" && words[k + 1] === "proxy" && k < words.length - 2) k += 2;
    const [prog, ...args] = words.slice(k), name = prog.replace(/^\/(usr\/)?bin\/(?=[\w.-]+$)/, "");
    if (args.length === 1 && args[0] === "--version" && VERSION_ONLY.has(name)) return true;
    const spec = Object.hasOwn(READ_ONLY_SIMPLE, name) ? READ_ONLY_SIMPLE[name] : null;
    return !!spec && (spec.test ? spec.test(args, {first: !!words.first, tilde: !!words.tilde}) : spec.any || flagsOk(args, spec));
  });
}

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

// ---------------------------------------------------------------------------------------------
// Context. The hook runs in Claude Code's environment, which the Bash tool inherits, so the
// AWS profile and kube context seen here are the ones the command will use.
export function envContext(cwd) {
  const e = {};
  if (ENV.AWS_PROFILE) e.aws_profile = ENV.AWS_PROFILE;
  if (ENV.AWS_REGION ?? ENV.AWS_DEFAULT_REGION) e.aws_region = ENV.AWS_REGION ?? ENV.AWS_DEFAULT_REGION;
  const kube = readText((ENV.KUBECONFIG ?? join(homedir(), ".kube/config")).split(":")[0]);
  const ctx = kube?.match(/^current-context:\s*"?([^"\n]+)"?\s*$/m)?.[1];
  if (ctx) e.kube_context = ctx;
  // terraform, tofu and terragrunt: .terraform/environment, or TF_WORKSPACE, which all three honour and which wins
  if (cwd && existsSync(join(cwd, ".terraform"))) e.tf_workspace = readText(join(cwd, ".terraform/environment"))?.trim() || "default";
  if (ENV.TF_WORKSPACE) e.tf_workspace = ENV.TF_WORKSPACE;
  for (let d = cwd; d && d !== dirname(d); d = dirname(d)) {
    const head = readText(join(d, ".git/HEAD"));
    if (head) { e.git_branch = head.match(/^ref: refs\/heads\/(.+)$/m)?.[1] ?? "detached"; break; }
  }
  return e;
}

// What the agent said right before this call, and what it ran just before. Reads the transcript
// tail. The intent is the text that precedes this call's own tool_use entry. When that entry is not
// in the transcript yet (Claude Code can write it after the hook fires), there is no intent: an
// older message would be judged against the wrong task, which is worse than none.
/** The last 512 KB of a transcript, or "" when there is none. */
export function transcriptTail(path) {
  if (!path || !existsSync(path)) return "";
  const size = statSync(path).size, len = Math.min(size, 512 * 1024), buf = Buffer.alloc(len);
  const fd = openSync(path, "r");
  readSync(fd, buf, 0, len, size - len);
  closeSync(fd);
  return buf.toString("utf8");
}
export function sessionContext(path, toolUseId) {
  const text = transcriptTail(path);
  if (!text) return {};
  let lastText, intent, recent = [];
  for (const line of text.split("\n")) {
    let r;
    try { r = JSON.parse(line); } catch { continue; }
    if (r.type === "user" && r.message?.content?.some?.(c => c.type !== "tool_result")) lastText = undefined;
    if (r.type !== "assistant") continue;
    for (const c of r.message?.content ?? []) {
      if (c.type === "text" && c.text?.trim()) lastText = c.text;
      if (c.type === "tool_use" && toolUseId && c.id === toolUseId) intent = lastText;
      if (c.type === "tool_use" && c.name === "Bash" && c.id !== toolUseId && c.input?.command) recent.push(c.input.command);
    }
  }
  const out = {};
  if (intent) out.intent = redact(intent).slice(-600);
  if (recent.length) out.recent = recent.slice(-5).map(c => redact(c).slice(0, 200));
  return out;
}

// ---------------------------------------------------------------------------------------------
// Deterministic layer: a rule fires when every pattern in `all` matches the command + context, or
// the command alone (`bare`) for a rule marked "context": false. `views` gives a rule marked "shell"
// or "writes" its own [haystack, bare] (see precheck); false skips the rule.
const RX = new Map();
const rx = p => RX.get(p) ?? RX.set(p, new RegExp(p, "i")).get(p);   // script rules run per line
export function checkRules(haystack, rules, bare = haystack, views = {}) {
  for (const r of rules.rules) {
    const view = r.shell ? views.shell : r.writes ? views.writes : undefined;
    if (view === false) continue;
    const [h, b] = view ?? [haystack, bare];
    const text = r.context === false ? b : h;
    // a team policy's rule brings its own linear-time test (team.mjs)
    if (r.test ? r.test(text) : r.all.every(p => rx(p).test(text))) return {outcome: r.outcome, rule: r.rule, id: r.id};
  }
  return null;
}
export const fastPass = (cmd, rules) => readOnly(cmd, rules.pass.map(p => new RegExp(p, "i")));

// The command cut into pipelines (split at && || ; & and newlines, never at |), each with the files
// its redirects write and whether the rest of it is inert: read-only, or one of a few commands that
// change nothing a rule protects. null when the text hides what runs or where it writes: an
// expansion ($, `), a heredoc, a process substitution or unbalanced quotes.
// `reflex check` only judges: the command it is given is data. (Not `node --check`, which still runs
// -r / --import preloads, nor a file named gate.mjs, which could be anything.)
// `cap`, `deadline`: a pipeline longer than cap, or reached after the deadline, is not read (not
// inert), so a huge command stays linear-ish (largeDeny).
const INERT = [/^(mkdir|touch)\s[^<>`$]*$/i, /^git\s+(add|commit)\b[^<>`$]*$/i, /^reflex\s+check(\s[^<>`$]*)?$/i];
export function pipelines(command, cap = Infinity, deadline = Infinity) {
  const c = command.replace(/\\\n/g, "");
  if (/[$`]|<<|<\(|>\(/.test(c)) return null;
  const m = maskQuotes(c, "_");
  if (m === c && /['"]/.test(c)) return null;
  const out = [];
  let last = 0;
  const cut = end => {
    const text = c.slice(last, end), mask = m.slice(last, end), targets = [];
    // n>, >>, >|, &>, <> and >&file write; >&2 and 2>&1 only duplicate a descriptor
    const core = text.split("");
    for (const r of mask.matchAll(/(?:\d*|&)(?:<>|>>?\|?|>&)\s*([^\s;&|<>()]*)/g)) {
      const t = text.slice(r.index + r[0].length - r[1].length, r.index + r[0].length).replace(/^(['"])(.*)\1$/, "$2");
      if (!/^(\d+|-)$/.test(t)) targets.push(t);
      for (let k = r.index; k < r.index + r[0].length; k++) core[k] = " ";
    }
    const rest = core.join("").trim();
    if (rest) out.push({text: text.trim(), targets, core: rest, inert: rest.length <= cap && Date.now() <= deadline && readOnly(rest, INERT)});
    else if (targets.length) out.push({text: text.trim(), targets, core: "", inert: false});
  };
  for (const s of m.matchAll(/&&|\|\||[;\n]|(?<![<>|&])&(?![>&])/g)) { cut(s.index); last = s.index + s[0].length; }
  cut(c.length);
  return out;
}
// What a pipeline changes: an inert one, only its redirect targets. A cd, an assignment or a loop
// header can steer what a later step writes, and touch and mkdir create files, so those are kept whole.
// Commands cut at && || ; & | and newlines outside quotes (all of the text when quotes do not
// balance), each counted as a whole pipeline: for writesView when pipelines() cannot read the command.
function roughPipelines(c) {
  const m = maskQuotes(c, "_"), cuts = [...m.matchAll(/&&|\|\||[;&|\n]/g)], out = [];
  let last = 0;
  for (const k of [...cuts, {index: c.length, 0: ""}]) {
    const text = c.slice(last, k.index).trim();
    if (text) out.push({text, targets: [], core: text, inert: false});
    last = k.index + k[0].length;
  }
  return out;
}
// Directories whose relative paths the tamper rule could care about: an agent's settings or hooks
// directory, a parent of one, a directory named reflex, the checkout, the Reflex data or config
// directory (or a parent), or one only a variable names. Elsewhere an argument such as
// ursuciprian/reflex (gh -R) is not a path and is left unresolved.
const CD_WATCH = /(^|\/)(\.claude(\/(settings|hooks)\b.*)?|\.codex(\/(hooks|rules|config)\b.*)?|\.hermes(\/.*)?|\.config(\/(reflex|opencode)\b.*)?|\.local(\/state(\/.*)?)?|\.(pi|omp)(\/agent(\/.*)?)?|opencode(\/.*)?|\.?reflex(\/.*)?)\/?$|\$|^~\/?$/i;
const cdWatched = d => CD_WATCH.test(d) || [HERE, CONFIG.data, dirname(USER_CONFIG_FILE)].some(p => (d + "/").startsWith(p + "/") || p.startsWith(d.replace(/\/$/, "") + "/"));
// A cd, pushd or popd the directory tracking below reads writes nothing itself: its effect is the
// resolved paths, each set on a line of its own so a rule cannot match across it and the command
// text. One it cannot read is kept whole, and then every cd in the command is (the tracking is not
// trusted). A relative directory that is not watched as written is also tried against `cwd`
// (`cd setup/tool-gate` in the checkout). `resolvedOnly`: only those lines.
const writesView = (ps, resolvedOnly = false, cwd = null) => {
  const dirs = cdDirs(ps);
  return ps.map((p, i) => {
    const whole = !p.inert || /^[\s({!]*(cd|pushd|popd|for|select|case|while|until|if|export|local|declare|typeset|readonly|read|touch|mkdir)\b|^[\s({!]*\w+=/.test(p.core);
    const view = resolvedOnly ? "" : (dirs[i] === CD_STEP && !dirs.unread) || !whole ? p.targets.map(t => `> ${t}`).join(" ") : p.text;
    const d = typeof dirs[i] === "string" ? dirs[i] : null, abs = d && cwd && !/^[/~$]/.test(d) ? posix.join(cwd, d) : null;
    // Inside the checkout its relative paths are judged as written (setup/…, gate.mjs), as without a cd.
    const inside = cwd && (cwd + "/").startsWith(HERE + "/");
    const at = d && cdWatched(d) ? d : abs && cdWatched(abs) ? (inside ? d : abs) : null;
    if (!at) return view;
    // the arguments of each command in the pipeline (not its name, not a URL) and the redirect targets
    const words = whole ? [...p.text.split("|").flatMap(s => s.replace(/[<>&;(){}]/g, " ").trim().split(/\s+/).slice(1)), ...p.targets]
      .flatMap(w => [w, w.replace(/^[^=]*=/, "")]).filter(w => !w.includes("://")) : p.targets;
    // a command run there that names no file (make, ./install.sh, vim) is marked by the directory itself
    return `${view}\n${whole ? `> ${at}/ ` : ""}${words.map(w => w.replace(/["'\\]/g, "")).filter(w => w && !/^[-/~$]/.test(w)).map(w => `> ${posix.join(at, w)}`).join(" ")}\n`;
  }).filter(Boolean).join(" ; ");
};
// The directory each pipeline runs in, as far as the command line itself changes it: after
// `cd ~/.claude &&`, `pushd ~/.config/reflex;` or inside `(cd ~/.codex && …)` a relative path names a
// file there. null: the directory the command started in. CD_STEP marks a cd the tracking read.
// ponytail: the command's own cd, pushd, popd, cd - and subshell parentheses; `cd "$D"` resolves to
// "$D/…" and a cd hidden in a loop or a function is not followed.
const CD_STEP = Symbol("cd");
function cdDirs(ps) {
  let dir = null, old = null;
  // D=/some/dir; cd $D: a variable an earlier assignment in the command set to a literal (never one
  // a loop or read could set)
  const vars = {}, all = ps.map(p => p.text).join("\n");
  const sub = s => s.replace(/\$\{?(\w+)\}?/g, (v, n) => n in vars && !new RegExp(String.raw`\b(for|select)\s+${n}\b|(^|[;&|(\s])read\s[^;&|\n]*\b${n}\b`).test(all) ? vars[n] : v);
  const stack = [], scopes = [], home = s => sub(s).replace(/^(\$HOME|\$\{HOME\})(?=\/|$)/, "~");
  const go = to => { [old, dir] = [dir, /^[/~$]/.test(to) ? to : posix.join(dir ?? ".", to)]; };
  // CDPATH changes where a relative cd goes
  let unread = /\bCDPATH=/.test(all);
  const out = ps.map(p => {
    if (/^\s*(export\s+)?\w+=/.test(p.core))
      for (const [, n, v] of p.core.matchAll(/(?:^|\s)(\w+)=(\S*)/g)) if (/^[\w./~@%+:,-]*$/.test(v) && n !== "HOME") vars[n] = v; else delete vars[n];
    const m = maskQuotes(p.text, "_"), count = re => (m.match(re) ?? []).length;
    for (let k = (m.match(/^[\s!{]*(\(\s*)+/)?.[0].match(/\(/g) ?? []).length; k > 0; k--) scopes.push([dir, old, stack.length]);
    const cmd = p.core.replace(/^[\s({!]+|[\s)}]+$/g, "").replace(/^((do|then|else)\s+)+/, "").replace(/^(builtin|command)\s+/, "")
      .match(/^(cd|pushd|popd)((?:\s+-[LPe@+-]*(?=\s))*)(?:\s+--)?(?:\s+(\S+))?$/);
    let here = dir;
    if (cmd) {
      const arg = cmd[3] === undefined ? undefined : home(cmd[3].replace(/["'\\]/g, ""));
      here = CD_STEP;
      // pushd with no directory swaps the top two, pushd/popd ±N rotate the stack: not followed
      if ((cmd[1] === "pushd" && arg === undefined) || (cmd[1] !== "cd" && /^[+-]\d+$/.test(arg ?? "")) || (cmd[1] === "popd" && arg !== undefined)) unread = true;
      else if (cmd[1] === "popd") [old, dir] = [dir, stack.pop() ?? null];
      else if (cmd[1] === "pushd") { stack.push(dir); if (arg !== undefined) go(arg); }
      else if (arg === "-") [dir, old] = [old, dir];
      else go(arg ?? "~");
    } else if (/^[\s({!]*(builtin\s+|command\s+)?(cd|pushd|popd)\b/.test(p.core)) unread = true;   // unread: kept whole
    const closes = count(/\)/g) - count(/\(/g);
    for (let k = 0; k < closes && scopes.length; k++) { const s = scopes.pop(); [dir, old] = s; stack.length = Math.min(stack.length, s[2]); }
    return here;
  });
  out.unread = unread;
  return out;
}
// Only inert pipelines writing notes (Markdown, text, logs, CSV) or nothing: there is no shell
// command in it for a "shell" rule to find, whatever its quoted text says (echo '… rm -rf / …' >> MEMORY.md).
const NOTES = /^(\/dev\/(null|stdout|stderr)|[^\s;&|<>]*\.(md|markdown|txt|rst|adoc|log|csv|tsv))$/i;
const onlyNotes = ps => !!ps?.length && ps.every(p => p.inert && p.targets.every(t => NOTES.test(t)));

// A quoted heredoc whose consumer only stores or prints text (a commit message, a PR body, a file
// written by cat) is data, not a command: a PR body that mentions `git push --force origin main`
// must not trip the force-push rule. Heredocs fed to a shell, an interpreter or ssh stay in.
const DATA_CONSUMER = /(^|\s)(cat|jq|tee|git\s+(commit|tag|notes)\b[^\n]*|gh\s+(pr|issue|release|api)\b[^\n]*)\s[^\n]*$|(^|\s)cat$/;
// `code`: also the program an interpreter reads from a heredoc (`python3 - <<'EOF'`) when all it does
// is print literals, so shell text in it (print("rm -rf /")) takes no effect. Rules marked "shell"
// read that view; the rest still read the body. Only the whole command `python3 - <<'EOF' … EOF`:
// the interpreter is the first word (no ssh, docker, env, sudo, flags or assignments in front), a
// bare name from PATH or one in a system directory or a version manager's shims (never ./x/python,
// which could be anything), the delimiter is quoted, and nothing comes before or after it.
// An allowlist, not a keyword list: every line is blank, or print, puts, echo or
// console.log of string and number literals. A single-quoted string never interpolates; a
// double-quoted one may not hold $ @ # { or a backtick (Ruby #{…}, Perl @{[…]}, PHP {$…}). No
// import either: `python3 -` imports from the working directory first. Anything else keeps the
// body in, and the engine sees the whole body either way.
const INTERP_DIR = String.raw`(\/usr(\/local)?\/bin|\/bin|\/opt\/homebrew\/bin|(~|${homedir().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})\/(\.pyenv\/shims|\.nvm\/versions\/node\/v[\d.]+\/bin))\/`;
const INTERP_STDIN = new RegExp(String.raw`^\s*(${INTERP_DIR})?(python[\d.]*|node|ruby|perl|php)(\s+-)?\s*$`);
const PRINT_LITERAL = String.raw`('([^'\\\n]|\\[^\n])*'|"([^"\\\n$@#{\x60]|\\[^\n])*"|-?\d+(\.\d+)?)`;
const PRINT_ARGS = String.raw`${PRINT_LITERAL}(\s*[,+]\s*${PRINT_LITERAL})*`;
const PRINT_ONLY = new RegExp(String.raw`^\s*((print|puts|echo|console\.log)(\s*\(\s*(${PRINT_ARGS})?\s*\)|\s+${PRINT_ARGS})\s*;?|<\?php)?\s*$`);
// No comments at all and ASCII only: a comment can change how the body is read (# coding: utf-7,
// a #! line perl or ruby follows, ?> ending PHP code), and so can an encoding.
const printOnly = body => /^[\x09\x0a\x0d\x20-\x7e]*$/.test(body) && body.split("\n").every(l => PRINT_ONLY.test(l));
// A line scan with each terminator's next line found by a cursor, so a script full of `<<` (even
// unterminated ones) stays linear.
export function stripDataHeredocs(cmd, code = false) {
  if (!cmd.includes("<<")) return cmd;
  // what runs or captures an interpreter's output: its heredoc body then counts as a command
  if (/\$\(|\x60|<\(|>\(|\beval\b/.test(cmd)) code = false;
  const lines = cmd.split("\n"), ends = new Map(), at = new Map(), out = [];
  lines.forEach((l, i) => { const t = l.trim(); if (/^\w+$/.test(t)) (ends.get(t) ?? ends.set(t, []).get(t)).push(i); });
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].includes("<<") && lines[i].match(/^(.*?)<<-?\s*(['"]?)(\w+)\2(.*)$/);
    const list = m && ends.get(m[3]);
    let c = m ? at.get(m[3]) ?? 0 : 0;
    while (list && c < list.length && list[c] <= i) c++;
    if (m) at.set(m[3], c);
    const [, before, quote, , after] = m || [];
    const last = m && before.replace(/.*[;&|(]\s*/, "").trimEnd(), body = () => lines.slice(i + 1, list[c]).join("\n");
    if (list?.[c] !== undefined && !/\|/.test(after) &&   // `cat <<'EOF' | bash` runs the body
        ((quote && DATA_CONSUMER.test(last + " ")) ||
         (code && quote && INTERP_STDIN.test(before) && !after.trim() && lines.slice(0, i).every(l => !l.trim()) &&
          lines.slice(list[c] + 1).every(l => !l.trim()) && printOnly(body())))) {
      out.push(`${before}<<DATA${after}`);
      i = list[c];
    } else out.push(lines[i]);
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Local scripts. `bash deploy.sh` says nothing about what it does; the script does. A command that
// runs a local file (a shell, python, node or tsx script, a make target, an npm, yarn or pnpm
// script) has that file read: the rules marked "script" scan up to 256 KB of it, Jev sees the first
// 16 KB, redacted. What a shell script, make recipe or package script runs in turn is followed
// one more level.
// ponytail: a pattern per launcher, not a shell parser, and two levels deep. A command that names
// local code that could not be read is marked unseen, so it can never be allowed.
const SCRIPT_BYTES = 16 * 1024, RULE_BYTES = 256 * 1024;
const INTERP = String.raw`(?:(?:ba|z|da|k)?sh|python[\d.]*|node|tsx|bun|deno|ruby|perl|php)`;
const PATH = String.raw`(["']?)([^\s"'<>;|&)]+)\1`, SHOPTS = String.raw`(?:(?:-[oO]|--rcfile|--init-file)\s+\S+\s+|[-+]\S+\s+)*`;
const LAUNCH = [
  // a shell running a file, or reading it on stdin; -c (inline code) and -n (syntax check) are not that
  new RegExp(String.raw`^(?:ba|z|da|k)?sh\s+(?!${SHOPTS}-[a-z]*[cn]\b)${SHOPTS}(?:<\s*)?${PATH}`),
  new RegExp(String.raw`^(?:source|\.)\s+${PATH}`),
  new RegExp(String.raw`^(?:python[\d.]*|node|tsx|bun|deno\s+run|ruby|perl|php|npx\s+(?:-y\s+)?tsx)\s+(?:-\S+\s+)*(["']?)([^\s"'<>;|&)-][^\s"'<>;|&)]*\.(?:py|[cm]?[jt]s|rb|pl|php))\1(?=[\s<>;|&)]|$)`),
  /^()((?:\.{1,2}|~)?\/[^\s"'<>;|&)]+|[\w.-]+\/[^\s"'<>;|&)]+)/,   // ./x.sh, scripts/x.sh, ~/bin/x, /opt/x/run.sh
];
// Names a script file without matching a launcher above (python3 -W ignore x.py): unseen.
const NAMES_SCRIPT = new RegExp(String.raw`^${INTERP}\b.*\s["']?[^\s"']+\.(py|[cm]?[jt]s|sh|bash|rb|pl|php)\b`);
const PREFIX = /^((\w+=\S*|rtk(\s+proxy)?|timeout(\s+-[sk]\s+\S+|\s+-\S+)*\s+\S+|time|nohup|command|exec|nice(\s+-n\s*-?\d+|\s+-\d+)?|xargs(\s+-\S+)*|env(\s+-\S+|\s+\w+=\S*)*|sudo(\s+(-[ugCDhRTp]\s+\S+|-\S+))*|doas(\s+-u\s+\S+)?|stdbuf(\s+-\S+)*|caffeinate(\s+-\S+)*|watch(\s+-n\s*\S+|\s+-\S+)*)\s+)+/;
// A shell or interpreter reading its program from a pipe (a download piped to bash, `cat x.sh | sh`) runs code nobody read.
const FROM_STDIN = /^(?:(?:ba|z|da|k)?sh|python[\d.]*|node|ruby|perl)(?:\s+-[a-zA-Z]+)*\s*(?:-\s*)?$/;
// An earlier step that could have written the file this one runs: what is on disk now is not what will run.
const WRITES = /(>|\s-o\s|--output|\btee\b|\bcp\b|\bmv\b|\bcurl\b|\bwget\b|\bsed\s+-i|\bgit\s+(checkout|pull|apply|restore)\b|\bpatch\b|\bunzip\b|\btar\b)/;
const MAX_SCRIPTS = 8, LONG_LINE = 2000, SCAN_MS = 1500;
// Runs code no file here shows: a package fetched or installed (its lifecycle and build scripts), a
// module or a preload named on the command line, a task runner, go generate / run, find -exec of a
// script. Always unseen, whatever else is read.
const UNSEEN_RUN = new RegExp([
  String.raw`^(npx|bunx|pnpx|uvx|pipx)\b`, String.raw`^(npm|pnpm|yarn|bun)\s+(\S+\s+)*(dlx|exec|x|install|i|ci|add)(\s|$)`,
  String.raw`^uv\s+(run|tool|pip)\b`, String.raw`^(pip3?|poetry|pipenv)\s+(install|run|sync)\b`,
  String.raw`^python[\d.]*\s+(-\S+\s+)*-m\s`, String.raw`^node\s(.*\s)?(-r|--require|--import|--loader|--experimental-loader)(\s|=)`,
  String.raw`^(just|task|rake|invoke|nox|tox|gradle|mvn|\.\/gradlew|\.\/mvnw)\b`, String.raw`^go\s+(run|generate)\b`, String.raw`^cargo\s+run\b`,
  String.raw`\s-exec(dir)?\s+(\S*\/)?${INTERP}\b`,
].join("|"));
// Variables that load code into whatever runs next (BASH_ENV runs a file before a script, NODE_OPTIONS
// can --require one, PYTHONPATH picks which module an import finds).
const CODE_ENV = /(^|\s)(BASH_ENV|NODE_OPTIONS|NODE_PATH|PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_\w+)=/;
// An interpreter given a program it did not match above (no extension, a variable): unseen.
const INTERP_ARG = new RegExp(String.raw`^${INTERP}\s+(?!(-\S+\s+)*-[a-zA-Z]*[cen]\b)(-\S+\s+)*[^-\s]`);
// Files whose content must not leave the machine, even redacted: rules scan them, Jev is not shown them.
const SENSITIVE = /(^|\/)(\.env(\.[\w.-]+)?|\.netrc|\.npmrc|\.pypirc|credentials|id_[a-z0-9]+)$|\/\.(ssh|aws|gnupg|kube|docker)\/|\.(pem|key|p12|pfx)$/;
// A local module a script imports runs too, and Jev did not see it.
const LOCAL_IMPORT = /^\s*(from\s+\.|import\s*\(?\s*['"]\.{1,2}\/)|\brequire\(\s*['"]\.{1,2}\/|\bfrom\s+['"]\.{1,2}\//m;
const pyImports = text => [...text.matchAll(/^\s*(?:from\s+([\w]+)[\w.]*\s+import|import\s+([\w, ]+))/gm)]
  .flatMap(m => m[1] ? [m[1]] : m[2].split(",").map(x => x.trim().split(/\s|\./)[0])).filter(Boolean);
// Programs installed on the system are judged by their command; a compiled program elsewhere (built
// in the repo, downloaded) is code nobody showed Jev.
const SYSTEM_BIN = /^(\/bin|\/sbin|\/usr|\/opt\/homebrew|\/nix|\/System|\/Library|\/Applications)\//;
const PM_BUILTIN = new Set(("add install i ci remove rm uninstall up update upgrade why list ls info view init create dlx exec x " +
  "publish link unlink outdated audit config cache store import patch rebuild prune pack version set node workspace " +
  "workspaces bin help login logout whoami tag plugin dedupe env fetch licenses global root prefix search doctor").split(" "));

// null: not a readable regular file. {binary: true}: a compiled program, not a script.
function readHead(path, bytes) {
  let fd;
  try {
    if (!statSync(path).isFile()) return null;   // before open: opening a FIFO would block the hook
    fd = openSync(path, "r");
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    const buf = Buffer.alloc(Math.min(bytes, st.size)), n = readSync(fd, buf, 0, buf.length, 0), b = buf.subarray(0, n);
    const nl = b.indexOf(10);
    if (b.subarray(0, nl < 0 ? n : nl).includes(0)) return {binary: true};   // NUL in the first line (a shell refuses it too)
    return {text: b.toString("utf8").replaceAll("\0", ""), partial: st.size > n || b.includes(0)};
  } catch { return null; } finally { if (fd !== undefined) closeSync(fd); }
}
const under = (dir, p) => p.startsWith("~/") ? join(homedir(), p.slice(2)) : p.startsWith("/") ? p : join(dir, p);
// A make target's recipe, the tab-indented lines under `target:`, followed by the recipes of its
// direct prerequisites, which run first. No target: the first rule. Variables and includes are not
// expanded, so a make target is never allowed.
function makeRecipe(text, target, depth = 0) {
  const lines = text.split("\n");
  const at = lines.findIndex(l => target ? new RegExp(`^(?!\\t)([^:=#]*\\s)?${target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\s[^:=]*)?:(?!=)`).test(l)
                                          : /^[^.\s#][^:=#]*:(?!=)/.test(l));
  if (at < 0) return null;
  let end = at + 1;
  while (end < lines.length && (/^\t/.test(lines[end]) || lines[end].trim() === "")) end++;
  const deps = depth ? [] : lines[at].replace(/^[^:]*:/, "").replace(/#.*/, "").trim().split(/\s+/).filter(d => d && d !== target);
  return [lines.slice(at, end).join("\n").trim(), ...deps.map(d => makeRecipe(text, d, 1)).filter(Boolean)].join("\n\n");
}
// `make` arguments: the directory (-C, --directory), the file (-f, --file) and the first target.
function makeArgs(tokens, dir) {
  let mdir = dir, file, target;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i], eq = t.match(/^--(directory|file|makefile)=(.+)$/);
    if (t === "-C" || t === "--directory") mdir = under(mdir, tokens[++i] ?? ".");
    else if (eq?.[1] === "directory") mdir = under(mdir, eq[2]);
    else if (/^-C./.test(t)) mdir = under(mdir, t.slice(2));
    else if (["-f", "--file", "--makefile"].includes(t)) file = tokens[++i];
    else if (eq) file = eq[2];
    else if (/^-f./.test(t)) file = t.slice(2);
    else if (/^-[oWIl]$/.test(t) || (t === "-j" && /^\d+$/.test(tokens[i + 1] ?? ""))) i++;
    else if (!t.startsWith("-") && !t.includes("=")) target ??= t;
  }
  return {mdir, file, target};
}
// Package manager arguments -> the package.json scripts that run, pre and post hooks included.
// A workspace or filter selects another package.json, which is not resolved: unseen.
function pmScripts(pm, tokens) {
  let pdir, workspace = false;
  const words = [];
  for (let i = 0; i < tokens.length && tokens[i] !== "--"; i++) {
    const t = tokens[i], eq = t.match(/^--(prefix|dir|cwd)=(.+)$/);
    if (["--prefix", "-C", "--dir", "--cwd"].includes(t)) pdir = tokens[++i];
    else if (eq) pdir = eq[2];
    else if (/^(-w|--workspace|--filter|-F)$/.test(t)) { workspace = true; i++; }
    else if (/^(--workspace|--filter)=|^--workspaces$|^-ws$/.test(t)) workspace = true;
    else if (!t.startsWith("-")) words.push(t);
  }
  if (words[0] === "workspace" || words[0] === "workspaces") workspace = true;
  const [sub, arg] = words, hooks = n => [`pre${n}`, n, `post${n}`];
  if (workspace) return {pdir, names: [], workspace};
  if (pm === "bun" && sub && !["run", "test", "install", "i", "add", "x", "build", "init", "create"].includes(sub)) return {pdir, names: hooks(sub)};
  const names = ["run", "run-script"].includes(sub) ? (arg ? hooks(arg) : [])
    : ["test", "t", "start", "stop", "restart"].includes(sub) ? hooks(sub === "t" ? "test" : sub)
    : (["install", "i", "ci"].includes(sub) && !arg) || (!sub && pm !== "npm") ? ["preinstall", "install", "postinstall", "prepare"]
    : sub && pm !== "npm" && !PM_BUILTIN.has(sub) ? hooks(sub) : [];
  return {pdir, names};
}
// Cut a script into commands: the shell's separators outside quotes, subshells and command
// substitutions included, and the keywords that wrap a command dropped.
// Quotes are masked line by line with whole-line comments dropped first: an apostrophe in a
// comment ("# don't") must not hide the lines after it.
function segments(text) {
  const c = stripDataHeredocs(text).replace(/\\\n/g, "").split("\n").map(l => /^\s*#/.test(l) ? "" : l).join("\n");
  const m = c.split("\n").map(l => maskQuotes(l, "_")).join("\n"), out = [];
  let last = 0;
  for (const x of m.matchAll(/&&|\|\||\$\(|[;&|\n()`]|(?<!\$)\{|\}/g)) { out.push(c.slice(last, x.index)); last = x.index + x[0].length; }
  out.push(c.slice(last));
  return out.map(s => s.trim().replace(/^((if|then|else|elif|do|while|until|!)\s+)+/, "")).filter(Boolean);
}

/** The local scripts a command runs: [{path, excerpt, body, partial, unseen?}], excerpts redacted. */
export function localScripts(command, cwd, depth = 0) {
  const found = [], before = [];
  const unseen = p => ({path: p, excerpt: "", body: "", partial: true, unseen: true});
  let dir = cwd || process.cwd();
  for (let seg of segments(command)) {
    const raw = seg;
    seg = seg.replace(/^\S*\/(?=(env|sudo|nice|xargs|timeout|doas|stdbuf)\s)/, "").replace(PREFIX, "")
      .replace(new RegExp(String.raw`^\S*/(?=${INTERP}\s)`), "").replace(/^[@+-]+/, "")   // make's @-+ recipe prefixes
      .replace(/\$\{?PWD\}?/g, dir);
    const cd = seg.match(/^(?:cd|pushd)\s+(["']?)([^"']+)\1$/);
    if (cd) { dir = under(dir, cd[2]); continue; }
    if (before.length && FROM_STDIN.test(seg)) { found.push(unseen(`stdin of ${seg.split(/\s/)[0]}`)); before.push(raw); continue; }
    if (UNSEEN_RUN.test(seg) || CODE_ENV.test(raw)) found.push(unseen(seg.split(/\s+/).slice(0, 2).join(" ")));
    // `bash -c '…'` runs its argument as a command line: the scripts that one runs are what matter.
    const inline = seg.match(/^(?:ba|z|da|k)?sh\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*c[a-zA-Z]*\s+(["'])([\s\S]*?)\1(?=\s|$)/);
    if (inline) { found.push(...(depth < 2 ? localScripts(inline[2], dir, depth + 1) : [unseen(seg)])); before.push(raw); continue; }
    const tokens = seg.split(/\s+/).slice(1), pm = seg.match(/^(npm|pnpm|yarn|bun)\b/)?.[0];
    let path, got, base = dir, shell = false, named = false;
    if (/^make\b/.test(seg)) {
      const {mdir, file, target} = makeArgs(tokens, dir);
      let names = [];
      try { names = readdirSync(mdir); } catch { /* no directory, no Makefile */ }
      // exact names in make's order; a case-insensitive disk would report any of them as present
      const mf = ["GNUmakefile", "makefile", "Makefile"].find(f => names.includes(f));
      path = file ? under(mdir, file) : mf && join(mdir, mf);
      const all = path && readHead(path, RULE_BYTES);
      if (all) got = {text: (makeRecipe(all.text, target) ?? all.text).replace(/\$[({]MAKE[)}]/g, "make"), partial: true};
      base = mdir; shell = named = true;
    } else if (pm) {
      const {pdir, names, workspace} = pmScripts(pm, tokens);
      if (workspace) { found.push(unseen(`${pm} workspace script`)); before.push(raw); continue; }
      if (!names.length) { before.push(raw); continue; }
      base = under(dir, pdir ?? ".");
      path = join(base, "package.json");
      let scripts;
      try { scripts = JSON.parse(readText(path) ?? "null")?.scripts; } catch { scripts = null; }
      const lines = names.filter(k => typeof scripts?.[k] === "string").map(k => `${k}: ${scripts[k]}`);
      if (lines.length) got = {text: lines.join("\n"), partial: false, run: names.map(k => scripts?.[k]).filter(v => typeof v === "string").join("\n")};
      // A name the package.json does not have is still run: yarn, pnpm and bun fall back to a bin.
      shell = named = true;
    } else {
      const i = LAUNCH.findIndex(re => re.test(seg));
      if (i > -1) {
        path = under(dir, seg.match(LAUNCH[i])[2]);
        got = readHead(path, RULE_BYTES);
        if (got?.binary) {   // a program, not a script: an installed one is judged by its command
          if (!SYSTEM_BIN.test(path)) found.push(unseen(path));
          before.push(raw);
          continue;
        }
        shell = i < 2 || /\.(sh|bash|zsh)$/.test(path) || /^#!.*\b(ba|z|da|k)?sh\b/.test(got?.text ?? "");
        named = true;
      } else named = NAMES_SCRIPT.test(seg) || INTERP_ARG.test(seg);
    }
    // Written by an earlier step of the same command (a download saved as x.sh, then bash x.sh): not what will run.
    const name = path && path.split("/").pop();
    if (got && name && before.some(b => b.includes(name) && WRITES.test(b))) got = null;
    before.push(raw);
    if (!got) {
      if (named) found.push(unseen(path ?? seg));
      continue;
    }
    // Rules read the raw body (redaction could hide a marker such as prod-db). Jev reads the head of
    // the redacted body, cut at a line end.
    const body = got.text, red = redact(body);
    const cut = red.length <= SCRIPT_BYTES ? red : red.slice(0, red.lastIndexOf("\n", SCRIPT_BYTES) + 1 || SCRIPT_BYTES);
    // partial: Jev did not see all of it (cut, redacted, a make target, or a credentials file it is
    // never shown), so it can never be allowed.
    const hide = SENSITIVE.test(path);
    found.push({path, excerpt: hide ? "" : cut, body, partial: hide || got.partial || cut !== body || new RegExp(`[^\\n]{${LONG_LINE + 1}}`).test(body)});
    // The local modules a Python or JavaScript script imports run too, unread.
    const at = dirname(path);
    if (/\.py$/.test(path) ? /^\s*from\s+\./m.test(body) || pyImports(body).some(m => existsSync(join(at, `${m}.py`)) || existsSync(join(at, m)))
        : /\.[cm]?[jt]sx?$/.test(path) && LOCAL_IMPORT.test(body)) found.push(unseen(`local modules imported by ${path}`));
    // Two levels are read; what the second level runs is only marked unseen.
    if (shell && depth < 2) {
      const inner = localScripts((got.run ?? body).replace(/^\t/gm, ""), base, depth + 1);
      found.push(...(depth < 1 ? inner : inner.map(s => unseen(s.path))));
    }
  }
  // Past the cap nothing more is read, and saying so keeps the command from being allowed.
  return found.length > MAX_SCRIPTS ? [...found.slice(0, MAX_SCRIPTS - 1), unseen(`${found.length - MAX_SCRIPTS + 1} more scripts`)] : found;
}
// Script rules run line by line, with the script's own simple assignments expanded (DB=prod-x, then
// "$DB"), so the parts of a rule cannot match on unrelated lines. A rule marked "whole_script" (a
// read here, a send there) sees the whole body. Whole-line # and // comments are not calls.
// Lines over 2,000 characters (minified bundles, data) are left out: they are not hand-written
// commands, and the rules' backtracking on them could outrun the hook's timeout. The script then
// counts as partly seen. Variables are expanded to a fixed point (E=prod; DB=$E-orders).
function scriptLines(body) {
  const all = stripDataHeredocs(body).replace(/\\\n/g, "").split("\n").filter(l => !/^\s*(#|\/\/)/.test(l));
  const lines = all.filter(l => l.length <= LONG_LINE), vars = {};
  for (const l of lines) {
    const a = l.match(/^\s*(?:export\s+|local\s+|readonly\s+)?(\w+)=(["']?)([^"'\s;]*)\2/);
    if (a) vars[a[1]] = a[3];
  }
  const expand = s => s.replace(/\$\{?(\w+)\}?/g, (v, name) => vars[name] ?? v);
  for (let pass = 0; pass < 3; pass++) for (const k in vars) vars[k] = expand(vars[k]);
  // and each line with the quoted parts of its words joined, as the shell joins them (m''ain)
  const joined = l => [...new Set([l, joinQuotes(l) ?? l, plain(joinQuotes(l) ?? l)])];
  return {lines: lines.map(expand).flatMap(joined), skipped: lines.length < all.length};
}

// A directory with its own .git between the checkout and cwd (cwd included): its root, or null.
function nestedCheckout(cwd) {
  for (let d = resolve(cwd); d.startsWith(HERE + "/"); d = dirname(d)) if (existsSync(join(d, ".git"))) return d;
  return null;
}
// Does the command stay in the nested checkout `root`, as far as its text shows? Not when it climbs
// out (..), names the previous directory or the directory stack ($OLDPWD, cd -, popd, pushd ±N), or
// changes to a directory this cannot resolve inside root (an expansion, ~, an absolute path elsewhere).
// Symlinks are resolved (a link in root can point at the checkout): each cd target, and each word
// that names a path in root (from cwd or from a cd target), must resolve inside root, and so must
// the value of a short option with the value attached (-Cdir, -tdir, -ofile: every split after the
// flag letters is tried). A path that cannot be resolved (a word with an expansion, a link realpath
// refuses) or a check past run.deadline restores the checkout view. Real paths are cached per
// directory for the call (run.real), and the first path that leaves root ends the check.
const PATH_MAX = 4096;
function staysNested(command, cwd, root, run = {deadline: Date.now() + PRECHECK_MS}) {
  const t = command.replace(/["'\\]/g, "");
  // CDPATH changes where a relative cd goes; a symlink made in the command can point anywhere
  if (/(^|[\s/=:])\.\.([\s/;&|)]|$)/.test(t) || /\b(OLDPWD|DIRSTACK|CDPATH)\b/.test(t) || /\bln\b[^;&|\n]*\s(-[a-zA-Z]*s|--symbolic)\b/.test(t)) return false;
  const cache = run.real ??= new Map(), seen = new Map();
  const realDir = d => {   // the real path of d, null when d does not exist, false when it cannot be read
    if (!cache.has(d)) { let v; try { lstatSync(d); try { v = realpathSync(d); } catch { v = false; } } catch { v = null; } cache.set(d, v); }
    return cache.get(d);
  };
  const real = realDir(root);
  if (!real) return false;
  // the real path of p, through its deepest part that exists: inside root's real path?
  const inside = p => {
    if (seen.has(p)) return seen.get(p);
    let ok = false;
    for (let d = p, tail = []; ; tail.unshift(basename(d)), d = dirname(d)) {
      const r = realDir(d);
      if (r === false) break;
      if (r) { ok = (join(r, ...tail) + "/").startsWith(real + "/"); break; }
      if (dirname(d) === d) break;
    }
    seen.set(p, ok);
    return ok;
  };
  const late = () => Date.now() > run.deadline;
  const bases = new Set([cwd]);
  for (const m of t.matchAll(/(?<![\w.\/-])(cd|pushd|popd|chdir)(?![\w.\/-])((?:\s+-[LPe@]+)*)(?:\s+--)?(?:\s+([^\s;&|<>()]+))?/g)) {
    const d = m[3];
    if (late() || m[1] === "popd" || d === undefined || /^[-+]/.test(d) || /[$\x60~?*[{]/.test(d) || !(resolve(cwd, d) + "/").startsWith(root + "/") || !inside(resolve(cwd, d))) return false;
    bases.add(resolve(cwd, d));
  }
  const words = shellWords(command);
  if (!words || words.some(w => w.exps.length)) return false;
  // a cd target that does not exist holds no link: what is under it resolves as it does
  for (const b of bases) if (b !== cwd && !realDir(b)) bases.delete(b);
  for (const w of words) {
    if (late()) return false;
    const v = w.value, paths = new Set([v, v.replace(/^[^=]*=/, "")]);
    // -Cdir, -tdir, -ofile, -rodir: the value after one to three flag letters
    const flags = /^-[a-zA-Z]{1,3}/.exec(v)?.[0].length ?? 0;
    for (let k = 2; k <= flags && k < v.length; k++) paths.add(v.slice(k));
    for (const x of paths) for (const b of bases) {
      if (late()) return false;
      if (x.length > PATH_MAX) continue;   // no file has that name: the command fails there
      const p = resolve(b, x);
      if ((p + "/").startsWith(root + "/") && !inside(p)) return false;
    }
  }
  return true;
}

// A quoted part of a word: quotes with no space, operator, escape or expansion inside, next to other
// word text, not escaped and not next to another quote. The text with those quotes dropped, or null
// when there are none or dropping them leaves the quotes unbalanced (then it is not what the shell reads).
const QUOTED_PART = /(?<=[^\s;&|<>()'"\\])(['"])([^'"\s;&|<>()$`\\]*)\1|(?<![\\'"])(['"])([^'"\s;&|<>()$`\\]*)\3(?=[^\s;&|<>()'"])/g;
const joinQuotes = s => { const j = s.replace(QUOTED_PART, "$2$4"); return j !== s && (maskQuotes(j, "_") !== j || !/['"]/.test(j)) ? j : null; };
// The command as the rules know it: quoted word parts joined, /bin/cat and /usr/bin/cat as cat,
// `timeout -k1 5 cat` as `timeout 5 cat` (readOnly accepts those spellings, so the rules must see
// through them too). null when nothing changes.
const TIMEOUT_OPTS = new RegExp(String.raw`\btimeout((\s+(-[fpv]+|-[ks]\s*[^\s-]\S*|--(foreground|preserve-status|verbose)|--(kill-after|signal)(=|\s+)[^\s-]\S*))+)(?=\s+[^\s-])`, "g");
// git's global options (-C dir, -c k=v, --git-dir …, --no-pager, -P), quoted values too: `git -C "/my repo"
// push` is `git push` to every git rule.
const GIT_VALUE = String.raw`(?:'[^']*'|"(?:[^"\\]|\\.)*"|\$\((?:[^()]|\([^()]*\))*\)|\$\{[^}]*\}|\x60[^\x60]*\x60|\$(?![({])|[^\s;&|<>()'"$\x60])+`;
const GIT_GLOBAL = new RegExp(String.raw`\bgit((?:\s+(?:-[cC]\s*${GIT_VALUE}|--(?:git-dir|work-tree|namespace|config-env|super-prefix|attr-source)(?:=|\s+)${GIT_VALUE}|` +
  String.raw`--(?:exec-path|list-cmds)=${GIT_VALUE}|-[pP]|--(?:no-pager|paginate|bare|exec-path|no-replace-objects|no-lazy-fetch|no-optional-locks|no-advice|` +
  String.raw`literal-pathspecs|glob-pathspecs|noglob-pathspecs|icase-pathspecs)(?=\s)))+)(?=\s)`, "g");
export const gitPlain = s => s.replace(GIT_GLOBAL, "git");
// aws's global options before the service (--profile prod, --region x, --no-cli-pager …) move behind
// the service and operation, where the CLI reads them too: `aws --profile prod rds delete-db-instance`
// is `aws rds delete-db-instance --profile prod` to every aws rule, and the profile stays in the text.
const AWS_GLOBAL = new RegExp(String.raw`\baws((?:\s+(?:--(?:profile|region|output|endpoint-url|query|color|ca-bundle|cli-read-timeout|cli-connect-timeout|` +
  String.raw`cli-binary-format)(?:=|\s+)${GIT_VALUE}|--(?:debug|no-verify-ssl|no-paginate|no-sign-request|no-cli-pager|cli-auto-prompt|no-cli-auto-prompt)(?=\s)))+)` +
  String.raw`(\s+[\w.-]+)(\s+[\w.-]+)?`, "g");
export const awsPlain = s => s.replace(AWS_GLOBAL, "aws$2$3$1");
// `--profile name` on an aws command is its profile when the environment names none: the aws_profile
// context the prod markers and a team policy read. ponytail: the first one only.
const AWS_PROFILE_FLAG = new RegExp(String.raw`\baws\s(?:[^;&|\n]*?\s)?--profile(?:=|\s+)['"]?([\w.@:+/-]+)`);
export const withAwsProfile = (command, env) => env.aws_profile ? env
  : (p => p ? {...env, aws_profile: p} : env)(String(command ?? "").match(AWS_PROFILE_FLAG)?.[1]);
// checkRules on the command as written and with git's and aws's global options moved (git -C x push
// is git push): for the checks outside precheck (always-human, fast-lane candidates).
const plain = s => awsPlain(gitPlain(s));
export const rulesHit = (haystack, rules, bare = haystack) => checkRules(haystack, rules, bare) ?? checkRules(plain(haystack), rules, plain(bare));
const ruleSpelling = s => {
  const v = plain((joinQuotes(s) ?? s).replace(/(^|[\s;&|(`]|\$\()\/(usr\/)?bin\/(?=[\w.-]+(\s|$))/g, "$1").replace(TIMEOUT_OPTS, "timeout"));
  return v !== s ? v : null;
};
const SEVERITY = {deny: 2, ask: 1};
/** Everything decided without Jev, or null when Jev has to judge. A rule that fires on the command
 * as the rules know it (ruleSpelling) counts too; the more severe of the two rule outcomes wins. */
// Over this size a command is not checked but asked about: the rules' work grows with it, and the
// hook's timeout must not let an unchecked command through. Only the deny rules still run, on
// overlapping windows until the deadline, so a large command never turns a deny it shows into an ask.
// A check that took longer than PRECHECK_MS is not trusted to pass either: it asks (a deny stands).
// `run`: one budget for the whole call, shared by every spelling precheck recurses into, and the
// local scripts already scanned, so each is scanned once.
const COMMAND_BYTES = 32 * 1024, PRECHECK_MS = 3000;
// Granting trust in a team policy (team.mjs), by the CLI or by its file or function.
const TEAM_TAMPER = /\b(reflex|team\.mjs)\s+(trust|policy\s+init)\b|\bteam\.mjs\b|\btrusted\.json\b|\btrustRepo\b/;
// The Claude Code plugin's commands (commands/*.md) run this copy's own scripts with node, as
// scripts/reflex does for `reflex check|status|report|replay|suggest|queue`: judged as that `reflex`
// command, so they get its fast lane and its tamper rules. Only this directory's files, as the
// command's first words; anything after them is judged as usual.
const OWN = new RegExp(String.raw`^node[ \t]+("?)${HERE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/(?:gate\.mjs\1[ \t]+--plugin[ \t]+--(check)|` +
  String.raw`status\.mjs\1[ \t]+--plugin[ \t]+--(status)|(report)\.mjs\1[ \t]+--plugin|replay\.mjs\1[ \t]+--plugin[ \t]+(replay|suggest)|autonomy\.mjs\1[ \t]+--plugin[ \t]+(queue))(?=[ \t]|$)`);
export const ownCommand = c => { const m = OWN.exec(c); return m ? `reflex ${m.slice(2).find(Boolean)}${c.slice(m[0].length)}` : null; };
export function precheck(command, cwd, env, depth = 0, run = {deadline: Date.now() + PRECHECK_MS, scan: Date.now() + SCAN_MS, scripts: new Set()}) {
  if (depth === 0) command = ownCommand(command) ?? command;
  env = withAwsProfile(command, env);
  const size = n => ({outcome: "ask", rule: `command too large to check (${n})`, id: "command-size", source: "rule", policy_version: load("rules.json").version});
  if (command.length > COMMAND_BYTES) return largeDeny(command, cwd, env, run.deadline) ?? size(`over ${COMMAND_BYTES / 1024} KB`);
  const c = command.replace(/\\\n/g, ""), own = precheckAs(command, cwd, env, run, depth > 0);
  // the other spellings: quoted parts joined and system paths (ruleSpelling), and the words as the
  // shell passes them (wordSpelling); a rule on any of them counts, the most severe wins
  let best = own;
  for (const alt of depth < 2 ? [ruleSpelling(c), wordSpelling(c)] : []) {
    if (Date.now() > run.deadline) break;
    const other = alt === TOO_MANY ? size(`over ${BRACE_WORDS} words from one brace word`) : alt ? precheck(alt, cwd, env, depth + 1, run) : null;
    if (other?.source === "rule" && !(best?.source === "rule" && (SEVERITY[best.outcome] ?? 0) >= (SEVERITY[other.outcome] ?? 0))) best = other;
  }
  if (depth === 0 && Date.now() > run.deadline && best?.outcome !== "deny") return size(`took over ${PRECHECK_MS / 1000} s`);
  return best;
}
// The production tier of a command that is not read-only, by the markers the rules already use: the
// prod-destroy rule's first pattern (cwd, aws_profile, kube_context, tf_workspace, git_branch or the
// command itself) and a team policy's prod list. Read like a "shell" rule: nothing when every pipeline
// only writes notes. {prod, by, why}: `by` names the marker's kind (what a webhook may carry), `why`
// the text it matched (for the local trace and the audit export). Too large to read counts as production.
export function prodTier(command, cwd, env) {
  const c = String(command ?? "").replace(/\\\n/g, "");
  if (c.length > COMMAND_BYTES) return {prod: true, by: "command", why: "command too large to check"};
  if (onlyNotes(pipelines(c))) return {prod: false};
  env = withAwsProfile(c, env);
  const parts = [[`cwd`, `cwd=${cwd ?? ""}`], ...Object.entries(env).map(([k, v]) => [k, `${k}=${v}`]), ["command", stripDataHeredocs(c, true)]];
  const hit = prodMarker(cwd);
  if (!hit(parts.map(p => p[1]).join(" "))) return {prod: false};
  for (const [by, text] of parts) {
    const m = hit(text);
    if (m) return {prod: true, by, why: redact(by === "command" ? `command: ${m}` : text).slice(0, 160)};
  }
  return {prod: true, by: "context", why: "the command with its context"};
}
// The production test prodTier reads: the prod-destroy rule's first pattern and the team policy's
// prod list, as text => the matched marker (a team one is named, never shown) or a falsy value.
function prodMarker(cwd) {
  const marker = load("rules.json").rules.find(r => r.id === "prod-destroy")?.all[0];
  const team = teamPolicy(cwd)?.rules.filter(r => r.id === "team:prod") ?? [];
  return text => (marker && rx(marker).exec(text)?.[0]) ?? (team.find(r => r.test(text)) && "a team prod marker");
}
// The production tier of an MCP call: the server name, each argument as key=value, and the context
// that server kind reads (an AWS server the AWS profile and region, a Kubernetes one the kube context,
// a Terraform one the workspace). Not the cwd or the branch: an MCP server does not act on them.
const SERVER_ENV = [[/^aws_/, /aws|amazon|\biam\b|s3|ec2|eks|ecs|rds|lambda|cloudformation|cdk/], [/^kube_context$/, /k8s|kube|eks|helm|argo|openshift/],
  [/^tf_workspace$/, /terraform|\btfe?\b|opentofu|\btofu\b/]];
export function mcpTier(t, cwd, env = {}) {
  const hit = prodMarker(cwd), kind = `${t.server ?? ""} ${t.name}`.toLowerCase();
  const parts = [["server", `server=${t.server ?? t.name}`],
    ...Object.entries(env).filter(([k]) => SERVER_ENV.some(([key, server]) => key.test(k) && server.test(kind))).map(([k, v]) => [k, `${k}=${v}`]),
    ...argStrings(t.args ?? {}).map(([k, v]) => ["arguments", `${k}=${v}`])];
  for (const [by, text] of parts) {
    const m = hit(text);
    if (m) return {prod: true, by, why: redact(by === "arguments" ? `argument: ${m}` : text).slice(0, 160)};
  }
  return {prod: false};
}
// The protected path a file tool writes, if any (tools.mjs, setup/tool-gate/protected.json): the
// bundled or user copy, the Reflex checkout (not a checkout nested in it, as for tamper), its logs
// and settings, config.json "protected" and the team policy's globs. Production is the prod markers
// on the path within its repository.
export function protectedWrite(paths, cwd) {
  const spec = load("protected.json"), root = cwd && repoRoot(cwd), hit = prodMarker(cwd);
  const own = [{glob: `${HERE}/**`, why: "the Reflex gate and its setup", unless: p => nestedCheckout(dirname(p))},
    {glob: `${CONFIG.data}/**`, why: "the Reflex logs"}, {glob: `${dirname(USER_CONFIG_FILE)}/**`, why: "the Reflex settings"}];
  const user = (Array.isArray(USER_CONFIG.protected) ? USER_CONFIG.protected : []).map(glob => ({glob, why: "protected in config.json"}));
  const entries = [...own, ...spec.paths, ...user, ...(teamPolicy(cwd)?.protected ?? [])];
  const prodPath = p => !!hit(root && p.startsWith(root + "/") ? p.slice(root.length + 1) : p);
  const h = protectedPath(paths, {cwd, entries, prodPath});
  // the path as the reason shows it: relative inside the working directory
  if (h && cwd && h.abs.startsWith(resolve(cwd) + "/")) h.path = h.abs.slice(resolve(cwd).length + 1);
  return h && {...h, outcome: ["ask", "deny"].includes(spec.outcome) ? spec.outcome : "ask", version: spec.version};
}
// A change freeze (freeze.mjs) in force now, from config.json and the team policy, as a rule decision:
// it asks or denies in every mode, and a rule's deny or an equal rule outcome keeps its own reason.
// An invalid window in config.json is never dropped: it asks for every command that is not read-only
// until it is fixed, while the rules keep running (a rule deny stays a deny).
// The reason names the marker's kind, never its value: it reaches the agent, the trace and a webhook.
function frozen(quick, cwd, tier, now = new Date()) {
  if (quick?.source === "read-only") return quick;
  const bad = CONFIG.freeze.errors.length ? [{outcome: "ask", applies_to: "all", reason: `invalid change freeze in ${USER_CONFIG_FILE} (${CONFIG.freeze.errors[0]}); every command asks until it is fixed`}] : [];
  const w = activeFreeze([...bad, ...CONFIG.freeze.windows, ...(teamPolicy(cwd)?.freeze ?? [])], now, tier.prod);
  if (!w || (quick?.source === "rule" && (SEVERITY[quick.outcome] ?? 0) >= SEVERITY[w.outcome])) return quick;
  return {outcome: w.outcome, rule: `${w.reason}${tier.prod ? `; production (${tier.by})` : ""}`, id: "freeze", window: w, source: "rule", policy_version: load("rules.json").version};
}
// A queue approval lifts a freeze ask only when the item was parked and answered inside that window,
// so the human saw the freeze: an approval from before the window never carries into it.
export const freezeApproved = (w, q) => !w.days && !w.after && !w.before && !w.from && !w.to ? false
  : [q.ladder?.queue_created, q.ladder?.decided_at].every(t => t && inWindow(w, new Date(t)));
// The deny rules on a command over COMMAND_BYTES: windows of that size, half of it apart (a match up
// to COMMAND_BYTES / 2 long is inside one), each as written and in the other spellings, until `deadline`.
// The views are precheckAs's: "shell" rules read the command without interpreter heredocs that only
// print, and nothing when every pipeline is inert and writes only notes; the others read it with
// data heredocs dropped. ponytail: past the deadline the rest is not read and the command asks.
const same = x => x;
function largeDeny(command, cwd, env, deadline) {
  const rules = teamRules(load("rules.json"), cwd), deny = {rules: rules.rules.filter(r => r.outcome === "deny")};
  const c = command.replace(/\\\n/g, ""), bare = stripDataHeredocs(c), ctx = [`cwd=${cwd ?? ""}`, ...Object.entries(env).map(([k, v]) => `${k}=${v}`)].map(x => " " + x).join("");
  const code = onlyNotes(pipelines(c, 2 * COMMAND_BYTES, deadline)) ? null : stripDataHeredocs(c, true);
  if (Date.now() > deadline) return null;
  for (let at = 0; ; at += COMMAND_BYTES / 2) {
    const b = bare.slice(at, at + COMMAND_BYTES), s = code?.slice(at, at + COMMAND_BYTES);
    for (const f of [same, ruleSpelling, wordSpelling]) {
      if (Date.now() > deadline) return null;
      // another spelling that changes nothing is not checked again, nor one view twice
      const spell = x => { const r = f(x); return typeof r === "string" ? r : null; };
      const bv = spell(b), cv = code === null ? null : code === bare ? bv : spell(s);
      if (f !== same && bv === null && cv === null) continue;
      const v = bv ?? b, sv = code === null ? null : cv ?? s;
      const hit = checkRules(v + ctx, deny, v, {shell: sv === null ? false : [sv + ctx, sv]});
      if (hit) return {outcome: hit.outcome, rule: hit.rule, id: hit.id, source: "rule", policy_version: rules.version};
    }
    if (at + COMMAND_BYTES >= Math.max(bare.length, code?.length ?? 0)) return null;
  }
}
// Brace expansion as the shell does it, on a word's raw text: lists ({a,b}, nested), sequences
// ({1..3}, {a..c}, {01..9..2}) and any number per word. Quoted or escaped braces and ${…} are text.
// Each result keeps its quotes, so the rules read it with the other spellings. null: over BRACE_WORDS.
const BRACE_WORDS = 256;
function braceSeq([, x, y, step]) {
  const num = /\d/.test(x);
  if (num !== /\d/.test(y)) return undefined;
  const a = num ? +x : x.charCodeAt(0), b = num ? +y : y.charCodeAt(0), st = Math.abs(+step || 1) || 1;
  const n = Math.floor(Math.abs(b - a) / st) + 1, pad = num && /(^|\s)-?0\d/.test(x + " " + y) ? Math.max(x.length, y.length) : 0;
  if (n > BRACE_WORDS) return null;
  return Array.from({length: n}, (_, i) => {
    const v = a + (b >= a ? i : -i) * st;
    return num ? (v < 0 ? "-" : "") + String(Math.abs(v)).padStart(pad - (v < 0 ? 1 : 0), "0") : String.fromCharCode(v);
  });
}
function braceWords(raw) {
  const out = [], todo = [raw];
  while (todo.length) {
    const r = todo.pop();
    let m = maskQuotes(r, "_").replace(/\\[\s\S]/g, "__"), hit = null;
    for (let g; !hit && (g = /\{([^{}]*)\}/.exec(m)); ) {
      const at = g.index + 1, end = g.index + g[0].length - 1, cuts = [...g[1].matchAll(/,/g)].map(c => at + c.index);
      const q = /^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?$/.exec(g[1]);
      const alts = m[g.index - 1] === "$" ? undefined : cuts.length ? [at, ...cuts.map(c => c + 1)].map((b, i) => r.slice(b, cuts[i] ?? end)) : q ? braceSeq(q) : undefined;
      if (alts === null) return null;
      if (alts) hit = [g.index, end + 1, alts];
      else m = m.slice(0, g.index) + "_" + g[1] + "_" + m.slice(end + 1);   // {x}, ${x}: text
    }
    if (!hit) { out.push(r); continue; }
    for (const x of hit[2].reverse()) todo.push(r.slice(0, hit[0]) + x + r.slice(hit[1]));
    if (todo.length + out.length > BRACE_WORDS) return null;
  }
  return out;
}
// A word whose braces are all sequences ({1..300}, x{01..20}.log), at least one of them numeric:
// every word it expands to has a digit where each numeric sequence was, so no ref or option comes
// of it. The count only; one of its words stands for all. null for any other word.
const RANGE = /\{(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?\}/g;
function rangeWord(raw) {
  const m = maskQuotes(raw, "_").replace(/\\[\s\S]/g, "__"), seqs = [...m.matchAll(RANGE)];
  if (!seqs.length || /[{}]/.test(m.replace(RANGE, "")) || !seqs.some(q => /\d/.test(q[1]) && /\d/.test(q[2]))) return null;
  let count = 1, word = "", last = 0;
  for (const q of seqs) {
    if (/\d/.test(q[1]) !== /\d/.test(q[2])) return null;
    const a = /\d/.test(q[1]) ? +q[1] : q[1].charCodeAt(0), b = /\d/.test(q[2]) ? +q[2] : q[2].charCodeAt(0);
    count *= Math.floor(Math.abs(b - a) / (Math.abs(+q[3] || 1) || 1)) + 1;
    word += raw.slice(last, q.index) + q[1];
    last = q.index + q[0].length;
  }
  return {count, word: word + raw.slice(last)};
}
// The command with each word the shell reads differently from its text written plainly: escapes
// and $'…' decoded (`ma\\in`, `$'ma\\x69n'`, `-\\f`, `pu\\sh`, only words whose value needs no
// quoting), brace lists and sequences expanded into their words (`m{a,}in` is `main min`,
// `ma{i..i}n` is `main`). null when nothing changes. TOO_MANY when a word would expand past
// BRACE_WORDS (or all of them past BRACE_WORDS * 4): nobody read what it expands to, so it asks.
// A numeric sequence past the limit (rangeWord) is one of its words instead: `for i in {1..300}`.
const TOO_MANY = Symbol("braces");
const wordSpelling = s => {
  const words = shellWords(s);
  if (!words) return null;
  const out = [];
  let n = 0, last = 0, changed = false;
  for (const w of words) {
    const m = maskQuotes(w.raw, "_"), r = /[{}]/.test(m) ? rangeWord(w.raw) : null;
    const b = r && r.count > BRACE_WORDS ? [r.word] : /[{}]/.test(m) ? braceWords(w.raw) : [w.raw];
    if (b === null || (b.length > 1 && (n += b.length) > BRACE_WORDS * 4)) return TOO_MANY;
    let v = null;
    if (b.length > 1 || b[0] !== w.raw) v = b.join(" ");
    else if (!w.exps.length && /\\|\$'/.test(m) && /^[^\s'"`$;&|<>()\\{}*?[\]#]*$/.test(w.value)) v = w.value;
    if (v === null) continue;
    out.push(s.slice(last, w.start), v);
    last = w.end; changed = true;
  }
  return changed ? out.join("") + s.slice(last) : null;
};
function precheckAs(command, cwd, env, run, alt = false) {
  // plus the repo's team policy (.reflex/policy.json, team.mjs): its rules only add asks and denies
  const rules = teamRules(load("rules.json"), cwd);
  // The shell deletes a backslash-newline: `git push --force \⏎ origin main` is one line.
  command = command.replace(/\\\n/g, "");
  // Rules see the raw command (redaction could hide the very marker a rule looks for, such as
  // --secret-id=prod-db), minus heredoc bodies that are only data.
  const bare = stripDataHeredocs(command), ctx = [`cwd=${cwd ?? ""}`, ...Object.entries(env).map(([k, v]) => `${k}=${v}`)].map(x => " " + x).join(""), haystack = bare + ctx;
  const ruled = r => ({outcome: r.outcome, rule: r.rule, id: r.id, source: "rule", policy_version: rules.version});
  // Some rules must see reads too (printing an API key is a read).
  const early = checkRules(haystack, {rules: rules.rules.filter(r => r.before_read_only)}, bare);
  if (early?.outcome === "deny") return ruled(early);
  // legacy: read-only passes here, before tamper and the other rules. simple: after all of them (below).
  const RO = {outcome: "pass", rule: "read-only", source: "read-only"};
  if (!early && READ_ONLY_MODE === "legacy" && readOnly(command)) return RO;
  // An ask (an early rule, tamper) is held while the rules below run: a deny among them still wins.
  let held = early ? ruled(early) : null;
  const hold = r => { if (!held || (SEVERITY[r.outcome] ?? 0) > (SEVERITY[held.outcome] ?? 0)) held = r; };
  // Tamper is about what the command changes: a pipeline that only reads the gate's files or an
  // agent's settings (jq . ~/.claude/settings.json > /tmp/s.json) counts by its redirect targets alone.
  // Quotes and backslashes are dropped, as the shell drops them: ~/.claude/'settings.json' is the file.
  // When the text hides what runs (a $, a heredoc), the whole command counts, plus the paths a cd
  // in it points relative ones at (cd "$HOME/.claude" && tee settings.json).
  const ps = pipelines(command), writes = (ps ? writesView(ps, false, cwd) : `${bare} ; ${writesView(roughPipelines(bare), true, cwd)}`).replace(/["'\\]/g, "");
  // The checkout itself is protected wherever it was cloned, not only under a directory named reflex.
  // A git worktree or clone nested inside it is another checkout, unless the command climbs out (..).
  const nested = cwd && nestedCheckout(cwd), inRepo = cwd && (cwd + "/").startsWith(HERE + "/") && !(nested && staysNested(command, cwd, nested, run));
  // ~ and $HOME are the home directory: ~/src/x/gate.mjs names the checkout wherever it was cloned
  const home = writes.replace(/(^|[\s=:>])(~|\$HOME|\$\{HOME\})(?=\/|\s|$)/g, (m, p) => p + homedir());
  if ([HERE, CONFIG.data, dirname(USER_CONFIG_FILE)].some(p => writes.includes(p) || home.includes(p)) ||
      // an agent must not answer its own queue item, widen its own envelope or rewind the tree
      /\breflex\s+(setup|install|uninstall)\b/.test(command.replace(/["'\\]/g, "")) ||
      /\breflex\b[^\n;&|]*\b(queue|envelope|checkpoints|runaway)\b[^\n;&|]*\b(approve|deny|clear|set|restore|reset)\b/.test(command.replace(/["'\\]/g, "")) ||
      // CDPATH sends a relative cd anywhere, so the directory tracking cannot say what a path names
      (inRepo && /\bCDPATH=/.test(command)) ||
      (inRepo && /\b(gate|policy|install|eval|report|instructions|context|autonomy|judge2|eval-ladder|fastlane|team|infra|plugin|failsafe|hook|guard|providers)\.mjs\b|\bsetup\/|\brouter\/|\brouting\/|\bscripts\/reflex-|\badapters\/|\.git\/hooks/.test(writes)))
    hold(ruled({outcome: "ask", rule: "touches the Reflex gate, its setup or its logs", id: "tamper"}));
  // A repo's team policy (.reflex/) and the user's trust in it (team.mjs): a human's call.
  // A glob that expands to .reflex counts, and so does naming policy.json where a team policy applies.
  if (TEAM_TAMPER.test(command.replace(/["'\\]/g, "")) || /(^|[^\w.-])\.reflex(?=[^\w.-]|$)/.test(writes) || globsReflex(writes) ||
      (/\bpolicy\.json\b/.test(writes) && teamPolicy(cwd)))
    hold(ruled({outcome: "ask", rule: "changes a team policy (.reflex/) or trusts one (reflex trust)", id: "tamper"}));
  // `reflex suggest --write` widens the user fast lane: a human's call, never the agent's.
  if (/\bsuggest\b[^\n;&|]*\s--write\b/.test(command.replace(/["'\\]/g, "")))
    hold(ruled({outcome: "ask", rule: "widens the fast lane (reflex suggest --write)", id: "tamper"}));
  const on = (r, what) => (r.applies_to ?? ["command"]).includes(what);
  // "shell" rules read commands: not the program of an interpreter heredoc that cannot run or write
  // anything, and nothing at all when every pipeline is inert and writes only notes.
  const code = onlyNotes(ps) ? null : stripDataHeredocs(command, true);
  const views = {shell: code === null ? false : [code + ctx, code], writes: [writes + ctx, writes]};
  const hit = checkRules(haystack, {rules: rules.rules.filter(r => !r.before_read_only && on(r, "command"))}, bare, views);
  if (hit) hold(ruled(hit));
  // The scripts it runs, even behind a held ask: a deny in a script still wins, before the fast lane: `npm test` is only as safe as the test script.
  const perLine = {rules: rules.rules.filter(r => on(r, "script") && !r.whole_script)};
  const whole = {rules: rules.rules.filter(r => on(r, "script") && r.whole_script)};
  // A time budget, so a pathological script cannot outrun the hook's timeout (which would let it run):
  // one for the whole call, and each script scanned once whatever spelling named it.
  const late = () => Date.now() > run.scan;
  for (const s of localScripts(command, cwd).filter(s => s.body && !run.scripts.has(s.path))) {
    run.scripts.add(s.path);
    if (s.body.includes(HERE) || s.body.includes(CONFIG.data) || TEAM_TAMPER.test(s.body.replace(/["'\\]/g, "")))
      { hold(ruled({outcome: "ask", rule: `touches the Reflex gate, its setup or its logs (in ${s.path})`, id: "tamper"})); continue; }
    const {lines} = scriptLines(s.body), all = lines.join("\n");
    let sh = checkRules(all + ctx, whole, all);
    for (const l of lines) { if (sh || late()) break; sh = checkRules(l + ctx, perLine, l); }
    if (sh?.outcome === "deny") return ruled({...sh, rule: `${sh.rule} (in ${s.path})`});
    if (sh) hold(ruled({...sh, rule: `${sh.rule} (in ${s.path})`}));
    if (late()) { hold(ruled({outcome: "ask", rule: `script too large to check in time (${s.path})`, id: "script-budget"})); break; }
  }
  // another spelling counts by its rules only: skip the fast lanes (and the scripts they read again)
  if (held || alt) return held;
  if (READ_ONLY_MODE === "simple" && readOnly(command)) return RO;
  if (fastPass(command, rules)) return {outcome: "pass", rule: "fast lane", source: "fast-lane", policy_version: rules.version};
  if (userFastPass(command, cwd, env)) return {outcome: "pass", rule: "fast lane (fastlane.json)", source: "fast-lane", policy_version: rules.version};
  return null;
}

// ---------------------------------------------------------------------------------------------
// Jev. The active provider's key: its environment variables, else its macOS Keychain item (TypeSafe's
// is REFLEX_KEYCHAIN_SERVICE or "keychain" in config.json, as before). Read once per process, never logged.
// In the Claude Code plugin: the Jev API key plugin option, and nothing else.
const KEYS = {};   // per provider, so a key read for one is never sent as another's
function apiKey() {
  if (PLUGIN_MODE) {
    const k = pluginKey();
    if (k) return k;
    throw new Error(`no API key for ${CONFIG.provider}: set the Jev API key in the Reflex plugin options (/plugin, reflex, Configure)`);
  }
  // Reached only in the plugin bundle run without --plugin: no key source there, so never call the provider.
  throw new Error(`no API key for ${CONFIG.provider}`);
}

// Each provider's key goes to that provider's host only, checked on every call (keyRouteError):
// OpenRouter's, Cloudflare's and Vercel's to their own host; TypeSafe's and a compatible endpoint's
// to CONFIG.keyHost, the host their endpoint was configured with. Never to another provider's host,
// never over http off this machine, never to the Laya server whatever the engine is switched to.
function authorization(url = CONFIG.api) {
  if (!PROVIDERS[CONFIG.provider]) throw new Error(`unknown provider ${CONFIG.provider}`);
  if (CONFIG.engine !== "laya" && ENGINE !== "laya") {
    const refused = keyRouteError(CONFIG.provider, url, CONFIG.keyHost, LAYA.port);
    if (refused) throw new Error(refused);
    return {key: apiKey()};
  }
  const token = readText(LAYA_TOKEN())?.trim();
  return token ? {key: token} : {};
}

// One call through the active provider (providers.mjs), its answers normalised to one typed shape.
// The whole call, retries included, fits in `timeoutMs` (the hook's budget). Any failure, a malformed
// answer included, comes back as `error`: callers treat it as Jev unavailable (the policy fallback).
export async function ask(state, questions, {timeoutMs = CONFIG.timeoutMs} = {}) {
  const disabled = configurationError() ?? (CONFIG.engine === "local" ? "local engine: hosted classification is disabled" : null);
  if (disabled) return {answers: {}, usage: {}, error: disabled, latency_s: 0};
  const t0 = Date.now(), laya = CONFIG.engine === "laya" || ENGINE === "laya";
  let answers = {}, usage = {}, error = null;
  try {
    ({answers, usage} = await callProvider({provider: laya ? "typesafe" : CONFIG.provider, url: CONFIG.api, ...authorization(CONFIG.api),
      state, questions, model: CONFIG.model, deadline: t0 + timeoutMs}));
  } catch (e) {
    error = `${e.name}: ${e.message}`;
  }
  return {answers, usage, error, latency_s: +((Date.now() - t0) / 1000).toFixed(2)};
}

// Answers about a command are cached, decisions never are: the policy reruns every time, so a
// threshold change applies at once. ponytail: answers tied to one moment (on_task) are dropped on a
// hit, so a repeat of the same command skips the on-task check.
const SESSION_BOUND = ["on_task"];
export function cacheGet(key) {
  let c;
  try { c = JSON.parse(readText(CACHE()) ?? "{}")[key]; } catch { return null; }
  if (!c || Date.now() - c.at > CACHE_TTL_MS) return null;
  return Object.fromEntries(Object.entries(c.answers).filter(([k]) => !SESSION_BOUND.includes(k)));
}
export function cachePut(key, answers) {
  // ponytail: whole-file rewrite; parallel hooks can drop an entry, which only costs a re-ask.
  try {
    mkdirSync(CONFIG.data, {recursive: true});
    const c = JSON.parse(readText(CACHE()) ?? "{}");
    c[key] = {at: Date.now(), answers};
    const tmp = `${CACHE()}.${process.pid}`;
    writeFileSync(tmp, JSON.stringify(Object.fromEntries(Object.entries(c).slice(-2000))));
    renameSync(tmp, CACHE());   // atomic: a parallel reader never sees half a file
  } catch { /* a cache that cannot be written only costs a re-ask */ }
}

// A home or root cwd makes "inside the working directory" meaningless: never allowed from there.
export const broadCwd = cwd => [homedir(), "/", dirname(homedir())].includes(resolve("/", cwd || "/"));

/** Jev's judgment + the policy -> {outcome, rule, source, state, answers, ...}. */
// `asker` stands in for the API in the self-check. `tainted`: the session read a suspected prompt
// injection (guard.mjs), so the policy's taint gates apply and nothing is allowed.
export async function jevJudge({command, cwd, env, session = {}, useCache = true, asker = ask, tainted = false, tool = false}) {
  const spec = load("questions.json");
  const policy = compile(load("policy.json"));
  // The scripts it runs, as one {path, excerpt}; several are joined, still within the size cap.
  // An MCP call (`tool`) runs no local script: its text is a tool name and arguments.
  const scripts = tool ? [] : localScripts(command, cwd), seen = scripts.filter(s => s.excerpt);
  const script = seen.length ? {path: seen.map(s => s.path).join(", "),
    excerpt: seen.map(s => seen.length > 1 ? `# --- ${s.path}\n${s.excerpt}` : s.excerpt).join("\n").slice(0, SCRIPT_BYTES)} : undefined;
  const state = {[spec.item_key]: {title: redact(command).slice(0, 160), command: redact(command), cwd, env, ...(script && {script}), ...session},
                 [spec.context_key]: spec.context};
  // A question with `requires` is asked only when that part of the call is there (the envelope ones).
  const present = p => p.split(".").reduce((o, k) => o?.[k], state[spec.item_key]) != null;
  const questions = Object.fromEntries(Object.entries(spec.questions).filter(([, q]) => !q.requires || present(q.requires))
    .map(([id, {requires, ...q}]) => [id, q]));
  // An edited script is a different command: its content is part of the key, and so is the envelope.
  const key = sha([redact(command), cwd, env, spec.version, CONFIG.model, ...scripts.map(s => sha(s.body)), ...(session.envelope ? [session.envelope] : []),
                   ...(session.plan ? [session.plan.digest] : [])]);
  const cached = useCache && cacheGet(key);
  const res = cached ? {answers: cached, usage: {}, error: null, latency_s: 0} : await asker(state, questions);
  // Every question must come back with a value, or the policy would read missing answers as "no".
  const missing = Object.keys(questions).filter(q => !(cached && SESSION_BOUND.includes(q)) &&
    (res.answers?.[q]?.noul ?? res.answers?.[q]?.choice ?? res.answers?.[q]?.score) == null);
  if (!res.error && missing.length) res.error = `incomplete answer: missing ${missing.join(", ")}`;
  if (!cached && !res.error && useCache) cachePut(key, res.answers);
  // Taint is a fact about the session, not the command: never cached, logged with the answers so
  // report.mjs replays it. Which envelopes exist is a fact too: the envelope gates read these flags,
  // so a repository's envelope alone can never reach the gate that passes work inside the user's.
  if (tainted && !res.error) res.answers = {...res.answers, tainted: {noul: 1}};
  if (!res.error && session.envelope?.user) res.answers = {...res.answers, envelope: {noul: 1}};
  if (!res.error && session.envelope?.repo) res.answers = {...res.answers, repo_envelope: {noul: 1}};
  const d = res.error
    ? {outcome: policy.policy.fallback ?? "ask", rule: `${CONFIG.engine === "laya" ? "laya" : "jev"} unavailable (${res.error.slice(0, 80)})`}
    : policy.decide(res.answers, policy.values());
  // Allow needs Jev to have seen everything that matters, fresh: a cached answer has lost on_task;
  // without a stated intent on_task is "yes" by default; redaction can hide a payload such as
  // --token "$(a download piped to sh)"; and a home or root cwd makes "inside the working directory" meaningless.
  // Code the command runs that Jev did not see in full (unread, cut, redacted, a make target, a
  // package fetched or installed) makes its answer one about a name. Only an allow gate allows: a
  // policy whose default outcome is allow would otherwise allow whatever no gate caught.
  const noAllow = res.error ? "no answer" : CONFIG.engine === "laya" ? "engine laya (experimental: allow is off)" : tainted ? "session read a suspected prompt injection" : cached ? "cached answer" : !session.intent ? "no stated intent"
    : d.path?.at(-1)?.outcome !== "yes" ? "not from an allow gate"
    : redact(command) !== command ? "redacted command"
    : scripts.some(s => s.partial) || script?.excerpt.length >= SCRIPT_BYTES ? "runs code Jev did not see in full"
    : broadCwd(cwd) ? "broad cwd" : null;
  const allowGuard = res.error ? "no answer" : cached ? "cached answer" : !session.intent ? "no stated intent" : redact(command) !== command ? "redacted command"
    : scripts.some(s => s.partial) || script?.excerpt.length >= SCRIPT_BYTES ? "runs code Jev did not see in full"
    : broadCwd(cwd) ? "broad cwd" : null;
  const policyOutcome = d.outcome;   // logged as is, so report.mjs replays policy against policy
  if (d.outcome === "allow" && noAllow) Object.assign(d, {outcome: "pass", rule: `low risk (not allowed: ${noAllow})`});
  return {outcome: d.outcome, policy_outcome: policyOutcome, rule: d.rule, source: res.error ? "fallback" : cached ? "cache" : "jev",
          state, questions, gate: d.path?.at(-1)?.outcome === "yes" ? d.path.at(-1).gate : null, allow_guard: allowGuard, qset: spec.version, policy_version: policy.version, ...res};
}

/** The whole gate for one command, as eval.mjs and the hook see it. noExec: the plan gate runs no
 * terraform show or kubectl dry run (the MCP server's reflex_check runs nothing). */
export async function judge({command, cwd, env = envContext(cwd), session = {}, useCache = true, asker, noExec = false}) {
  if (configurationError()) return {outcome: "ask", rule: configurationError(), source: "error"};
  const pre = precheck(command, cwd, env);
  const {quick, plan, floor} = infraJudge(command, cwd, env, frozen(pre, cwd, pre?.source === "read-only" ? {prod: false} : prodTier(command, cwd, env)), {noExec});
  if (quick) return quick;
  if (CONFIG.engine === "local") return floor ?? localJudgment();
  return askFloor(await jevJudge({command, cwd, env, session: plan ? {...session, plan} : session, useCache, asker}), floor);
}
// A plan's ask is a floor under the judge, not in place of it: Jev still sees the command and a deny
// it finds stands; anything milder becomes the plan's ask, with Jev's answers kept for the trace.
export const askFloor = (j, floor) => !floor || j.outcome === "deny" ? j
  : {...floor, answers: j.answers, state: j.state, questions: j.questions, qset: j.qset, usage: j.usage, latency_s: j.latency_s, error: j.error, policy_outcome: j.policy_outcome ?? j.outcome};
// The plan-aware infra gate (infra.mjs), after the rules and a change freeze; a rule deny stands and nothing is read.
// A plan's ask or deny is a rule outcome, enforced in every mode, and the more severe of it and the
// rules' wins. A clean verified plan is allow-eligible: the usual judge decides with the counts in
// its state (keyless, it passes). {quick, plan, floor}: the precheck result to use, the counts, and a
// plan's ask when nothing else decided yet (askFloor: the judge still runs under it).
const INFRA_LATE_MS = Number(ENV.REFLEX_INFRA_LATE_MS ?? 5000);
export function infraJudge(command, cwd, env, quick, {noExec = false} = {}) {
  if (quick?.source === "rule" && quick.outcome === "deny") return {quick, plan: null};
  // production: by the markers prodTier reads, in the directory the command runs in or the one it started in
  const prod = dir => prodTier(command, dir || cwd, env).prod || prodTier(command, cwd, env).prod;
  // the team policy of the directory each part runs in counts too (a cd or -chdir into another repository)
  const settingsAt = dir => { const a = infraSettings(USER_CONFIG.infra, teamPolicy(cwd)?.infra), b = infraSettings(USER_CONFIG.infra, teamPolicy(dir)?.infra);
    return {...a, destroy: a.destroy === "deny" || b.destroy === "deny" ? "deny" : "ask", require_plan_in_prod: a.require_plan_in_prod || b.require_plan_in_prod}; };
  let g;
  const settings = infraSettings(USER_CONFIG.infra, teamPolicy(cwd)?.infra);
  try { g = planGate({command, cwd, settings: noExec ? {...settings, terraform_show: false, kubectl_diff: false, helm_diff: false} : settings, settingsAt, prod, pipelines, shellWords}); }
  catch (e) { g = {outcome: "ask", id: "infra-error", rule: `the plan gate failed (${String(e.message).slice(0, 80)})`}; }   // closed, in shadow too
  if (!g) return {quick, plan: null};
  const plan = g.plan ?? null, version = teamRules(load("rules.json"), cwd).version, withPlan = q => q && plan ? {...q, plan} : q;
  if (g.outcome === "ask" || g.outcome === "deny") {
    const j = {outcome: g.outcome, rule: g.rule, id: g.id, source: "rule", policy_version: version, plan};
    if (!quick && j.outcome === "ask") return {quick: null, plan, floor: j};
    return {quick: quick?.source === "rule" && (SEVERITY[quick.outcome] ?? 0) >= SEVERITY[j.outcome] ? withPlan(quick) : j, plan};
  }
  if (g.outcome === "pass" && !quick && CONFIG.engine === "local") return {quick: {outcome: "pass", rule: g.rule, id: g.id, source: "plan", policy_version: version, plan}, plan};
  return {quick: withPlan(quick), plan};
}
const localJudgment = () => ({outcome: "ask", source: "local", rule: "not covered by local rules; a human must review it"});

// ---------------------------------------------------------------------------------------------
// The agent-neutral contract. Every adapter turns its agent's event into a call:
//   {agent, command, cwd, session_id?, call_id?, intent?, recent?, transcript_path?, permission_mode?, unsandboxed?}
// and gets back {effective, decision, reason, source, policy}. `effective` is what the agent must
// do now: "pass" (no opinion, the agent's own permissions decide), "allow" (run it without the
// agent's prompt), "ask" (a human confirms) or "deny" (block, show the reason).
// In shadow mode only deterministic rules are effective; Jev's decision is logged, never applied.
// A call with `subgoal` (the task a subagent is about to get), or `subgoals` (a batch of them), and
// no `command` is checked for duplicates, see subgoalJudge(); a batch where only some items repeat
// earlier work also gets `drop`, the indexes to leave out. A command is always judged as a command.
export async function decide(call, {background = false, asker, judger} = {}) {
  const subgoals = call.command ? [] : [call.subgoals ?? call.subgoal].flat().filter(s => typeof s === "string" && s.trim());
  if (CONFIG.mode === "off" || !(call.command || subgoals.length || call.tool)) return {effective: "pass", decision: "pass", reason: "reflex off", source: "off"};
  if (!call.command && call.tool) return toolDecide(call, {background, asker, judger});
  if (subgoals.length) {
    if (CONFIG.engine === "local") return view({outcome: "pass", source: "local", rule: "subgoal classification is disabled"}, "pass");
    if (CONFIG.mode !== "enforce" && !background) return inBackground(call);
    const {j, drop} = await subgoalJudge({...call, subgoals}, asker);
    const effective = CONFIG.mode === "enforce" ? j.outcome : "pass";
    return {...view(j, effective), ...(CONFIG.mode === "enforce" && j.outcome === "pass" && drop.length && {drop})};
  }
  const env = envContext(call.cwd), started = Date.now();
  let quick = background ? null : precheck(call.command, call.cwd, env);
  // the production tier goes into the trace (reflex audit); a change freeze tightens like a rule
  if (quick?.source !== "read-only") {
    call = {...call, tier: prodTier(call.command, call.cwd, env)};
    if (!background) quick = frozen(quick, call.cwd, call.tier);
  }
  // the counts come from the gate itself, never from the caller (the background copy gets them from its parent)
  let floor = null;
  if (!background) { const infra = infraJudge(call.command, call.cwd, env, quick); ({quick, floor} = infra); call = {...call, plan: infra.plan ?? undefined}; }
  // a plan's ask applies now, like a rule's, unless Jev judges in the foreground (enforce): then it is a
  // floor under Jev. The hook has 10 s and fails open past them: after INFRA_LATE_MS of rules and plan
  // reading, Jev (3 s) is not also waited for; what is left asks.
  const late = !background && Date.now() - started > INFRA_LATE_MS && !quick;
  if (floor && (CONFIG.engine === "local" || CONFIG.mode !== "enforce" || late)) [quick, floor] = [floor, null];
  else if (late && CONFIG.engine !== "local" && CONFIG.mode === "enforce") quick = {outcome: "ask", rule: "the rules and the plan or diff read took too long to also ask the judge", id: "infra-budget", source: "rule", policy_version: load("rules.json").version, plan: call.plan};
  // A human's answer in the approval queue (autonomous profile): the identical command, cwd and
  // session, within its TTL. A deterministic deny is never lifted, not even by an approval.
  let resumed = false;
  if (CONFIG.mode === "enforce" && !background && CONFIG.queue.enabled && !(quick?.source === "rule" && quick.outcome === "deny")) {
    let q = quick?.source === "read-only" ? null : queueAnswer(call);
    if (q && q.outcome !== "deny" && quick?.id === "freeze" && !freezeApproved(quick.window, q)) q = null;
    if (q) return finish(q, call, q.outcome === "deny" ? "deny" : allowSetting(holdAllow(q, call)).outcome === "allow" ? "allow" : "pass", {env});
    // a human lifted a runaway stop of this command: the guard steps aside once, the gate does not.
    // A human's deny of the stop is a deny.
    const r = queueAnswer(runawayCall(call));
    if (r?.resume) resumed = true;
    else if (r) return finish(r, call, "deny", {env});
  }
  // The runaway guard (autonomy.mjs) watches the session in the hook path, once per command. It only
  // ever adds a deny, never lifts one: a rule deny keeps its own reason. Shadow logs what it would stop.
  const stop = background ? null : runaway(call, quick, {resumed});
  if (stop && !stop.dry && !(quick?.source === "rule" && quick.outcome === "deny")) {
    const j = {outcome: "deny", source: "runaway", id: `runaway-${stop.signal}`, rule: `stopped: ${stop.reason}`, runaway: {signal: stop.signal}};
    if (CONFIG.queue.enabled && stop.fresh) j.rule += `. Parked for the user as ${park(runawayCall(call), j, {id: "runaway"}).item.id}`;
    trace(j, call, "deny");
    return view(j, "deny");
  }
  if (stop) call = {...call, runaway: {signal: stop.signal, ...(stop.dry ? {dry: true} : {superseded: "rule deny"})}};
  // A session whose agent read a suspected prompt injection: network egress asks, before the
  // read-only list and the fast lane (`gh api "…?q=$SECRET"` reads, `git push` is fast lane), and
  // Jev's policy applies its taint gates. Like Jev, enforced only in enforce mode (shadow takes the
  // usual path, so its background trace still shows Jev's view). The ask can only tighten: with Jev,
  // the command is judged too and a deny stands.
  const t = tainted(call.session_id);
  const egress = t && CONFIG.mode === "enforce" && !(quick?.source === "rule" && quick.outcome !== "pass") && taintedRule(call.command);
  if (egress) {
    const j = CONFIG.engine !== "local" ? await jevJudge({command: call.command, cwd: call.cwd, env, session: callSession(call), asker, tainted: true}) : null;
    const d = j?.outcome === "deny" ? j : {...egress, ...(j && {answers: j.answers, state: j.state, gate: j.gate})};
    return finish(d, call, d.outcome, {env, judger, egress: true});
  }
  if (quick) {
    const effective = quick.source === "rule" ? quick.outcome : "pass";
    if (quick.source === "read-only") return view(quick, effective);
    return finish(quick, call, effective, {env, judger});
  }
  if (CONFIG.engine === "local") return finish(localJudgment(), call, CONFIG.mode === "enforce" ? "ask" : "pass", {env, judger, background});
  // Shadow mode: nobody waits for Jev. A detached copy of this script judges and logs.
  if (CONFIG.mode !== "enforce" && !background) return inBackground(call);
  const j = askFloor(allowSetting(holdAllow(await jevJudge({command: call.command, cwd: call.cwd, env, session: callSession(call), asker, tainted: !!t}), call)), floor);
  const effective = CONFIG.mode === "enforce" && j.outcome !== "would_allow" ? j.outcome : "pass";
  return finish(j, call, effective, {env, judger, background, tainted: !!t});
}
// MCP tool calls and file writes (tools.mjs), on the same ladder as a command: a rule's ask or deny
// holds in every mode, a change freeze tightens, the queue and the runaway guard apply, and the trace,
// the audit and the webhook see them as `mcp <server>/<tool> {arguments}` or `<tool> <path>`, with a
// hash of the whole input so a queue approval covers that exact call. An unknown MCP tool goes to the
// engine. Never allow: a pass leaves the agent's own permissions in charge. A read-like MCP tool and a
// write outside the protected paths pass at once, unlogged, as a read-only command does.
async function toolDecide(call, {background = false, asker, judger} = {}) {
  const t = toolOf(call.tool, call.input, call.mcp === true);
  const quiet = rule => ({effective: "pass", decision: "pass", reason: `reflex: ${rule}`, source: "tool"});
  if (!t) return quiet("not a gated tool");
  const env = envContext(call.cwd), digest = sha(call.input ?? {}).slice(0, 8);
  let quick;
  if (t.kind === "write") {
    const hit = protectedWrite(t.paths, call.cwd);
    if (!hit) return quiet("not a protected path");
    call = {...call, command: `${t.name} ${hit.path} (input ${digest})`, tier: hit.prod ? {prod: true, by: "path", why: redact(hit.path).slice(0, 160)} : {prod: false}};
    quick = {outcome: hit.outcome, rule: `writes a protected path (${hit.path}): ${hit.why}`, id: "protected-path", source: "rule", policy_version: hit.version};
  } else {
    const tier = mcpTier(t, call.cwd, env);
    quick = mcpJudge(t, {spec: load("mcp.json"), team: teamPolicy(call.cwd)?.mcp ?? [], tier, precheck: c => precheck(c, call.cwd, env)});
    if (quick?.source === "read-only") return view(quick, "pass");
    call = {...call, command: `${mcpCommand(t, redact)} (input ${digest})`, tier,
            mcp: {server: t.server, tool: t.tool, arguments: redact(JSON.stringify(t.args ?? {})).slice(0, 2000), prod: tier.prod}};
  }
  const pass = d => d.effective === "allow" ? {...d, effective: "pass"} : d;
  if (!background) quick = frozen(quick, call.cwd, call.tier);
  let resumed = false;
  if (CONFIG.mode === "enforce" && !background && CONFIG.queue.enabled && !(quick?.source === "rule" && quick.outcome === "deny")) {
    let q = queueAnswer(call);
    if (q && q.outcome !== "deny" && quick?.id === "freeze" && !freezeApproved(quick.window, q)) q = null;
    if (q) return pass(await finish(q, call, q.outcome === "deny" ? "deny" : "pass", {env}));
    const r = queueAnswer(runawayCall(call));
    if (r?.resume) resumed = true;
    else if (r) return finish(r, call, "deny", {env});
  }
  const stop = background ? null : runaway(call, quick, {resumed});
  if (stop && !stop.dry && !(quick?.source === "rule" && quick.outcome === "deny")) {
    const j = {outcome: "deny", source: "runaway", id: `runaway-${stop.signal}`, rule: `stopped: ${stop.reason}`, runaway: {signal: stop.signal}};
    if (CONFIG.queue.enabled && stop.fresh) j.rule += `. Parked for the user as ${park(runawayCall(call), j, {id: "runaway"}).item.id}`;
    trace(j, call, "deny");
    return view(j, "deny");
  }
  if (stop) call = {...call, runaway: {signal: stop.signal, ...(stop.dry ? {dry: true} : {superseded: "rule deny"})}};
  if (quick) return pass(await finish(quick, call, quick.source === "rule" ? quick.outcome : "pass", {env, judger}));
  // an unknown MCP tool
  const version = load("mcp.json").version;
  if (CONFIG.mcp.unknown === "ask")
    return finish({outcome: "ask", source: "rule", id: "mcp-unknown", rule: `MCP tool ${t.tool} is not covered by the MCP rules (mcp.unknown: ask)`, policy_version: version}, call, "ask", {env, judger});
  if (CONFIG.engine === "local")
    return pass(await finish({outcome: "pass", source: "local", id: "mcp-unknown", rule: `MCP tool ${t.tool} is not covered by the MCP rules: logged (keyless)`, policy_version: version},
                             call, "pass", {env, judger, background}));
  if (CONFIG.mode !== "enforce" && !background) return inBackground(call);
  const t0 = tainted(call.session_id);
  const j = await jevJudge({command: call.command, cwd: call.cwd, env, session: {...callSession(call), mcp: call.mcp}, asker, tainted: !!t0, tool: true});
  return pass(await finish(j, call, CONFIG.mode === "enforce" && j.outcome !== "would_allow" ? j.outcome : "pass", {env, judger, background, tainted: !!t0}));
}
// Every judged command ends here: the escalation ladder when the autonomous profile has it on
// (System 2, the always-human class, the queue, checkpoints), then the trace and the agent's view.
async function finish(j, call, effective, opts = {}) {
  if (call.plan && !j.plan) j = {...j, plan: call.plan};
  if (CONFIG.judge.enabled || CONFIG.queue.enabled || CONFIG.checkpoints) ({j, effective} = await ladder(j, call, effective, opts));
  runawayNote(call, j, effective);
  trace(j, call, effective);
  return view(j, effective);
}
export function callSession(call) {
  const session = sessionContext(call.transcript_path, call.call_id);
  if (call.intent) session.intent = redact(call.intent).slice(-600);
  if (call.recent?.length) session.recent = call.recent.slice(-5).map(c => redact(c).slice(0, 200));
  const envelope = envelopeFor(call);
  if (envelope) session.envelope = envelope;
  if (call.plan) session.plan = call.plan;
  return session;
}
function inBackground(call) {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--bg", "--mode", CONFIG.mode, "--allow", CONFIG.allow, "--engine", CONFIG.engine],
                      {detached: true, stdio: ["pipe", "ignore", "ignore"]});
  child.stdin.end(JSON.stringify(call));
  child.unref();
  return {effective: "pass", decision: "pending", reason: "reflex: judged in the background (shadow)", source: "shadow"};
}

// Subgoal dedup. Agents re-launch subagents for work they already delegated, and pay for it twice.
// Each new subgoal is compared with those launched earlier in the same session (subgoals.jsonl) by
// one Jev choice question whose options are the earlier subgoals plus "none". A confident duplicate
// is denied with a reason naming the earlier one, so the agent reuses its result; anything else
// passes. It saves work, it does not guard safety: a Jev error or an internal error passes.
//
// Parallel spawns (several in one message, or a batch) must see each other, so every subgoal is
// written first, as pending, and then compared with the rows before it in the file: of two
// identical spawns racing, the one appended first is the original. An earlier row counts when its
// spawn ran (a PostToolUse / tool_result record), or while it is pending (no record yet, younger
// than pendingSeconds). A spawn that was denied (by Reflex, the user or another hook) or failed has
// no result to reuse: Reflex marks its own denials dropped, the others show up in feedback.
// ponytail: the files' last 2 MB are read per spawn, no lock (appends are atomic lines).
const SUBGOALS = () => join(CONFIG.data, "subgoals.jsonl");
const TAIL_BYTES = 2 * 1024 * 1024;
export function readTail(path, bytes = TAIL_BYTES) {
  if (!path || !existsSync(path)) return "";
  const size = statSync(path).size, len = Math.min(size, bytes), buf = Buffer.alloc(len);
  const fd = openSync(path, "r");
  try { readSync(fd, buf, 0, len, size - len); } finally { closeSync(fd); }
  return buf.toString("utf8");
}
// A torn or cut line is skipped, not fatal.
export const jsonLines = text => text.split("\n").flatMap(l => { try { return l ? [JSON.parse(l)] : []; } catch { return []; } });
async function subgoalJudge(call, asker = ask) {
  const spec = load("subgoals.json");
  const now = Date.now(), pendingMs = (spec.pendingSeconds ?? 300) * 1000, tag = randomUUID().slice(0, 8);
  const who = {agent: call.agent ?? null, session_id: call.session_id ?? null, call_id: call.call_id ?? null};
  const mine = call.subgoals.map((s, item) => ({ts: new Date(now).toISOString(), id: `${tag}#${item}`, ...who, item,
                                                ...(call.prompt_id && {prompt_id: call.prompt_id}), subgoal: redact(s).slice(0, 2000)}));
  // One write for the whole batch keeps its items in order and together.
  if (call.session_id) append(SUBGOALS(), mine);
  const rows = jsonLines(readTail(SUBGOALS())), fb = jsonLines(readTail(FEEDBACK()));
  const ran = new Set(fb.filter(r => r.event === "ran" && r.call_id).map(r => r.call_id));
  const gone = new Set(fb.filter(r => ["denied", "failed"].includes(r.event) && r.call_id).map(r => r.call_id));
  const dropped = new Set(rows.filter(r => r.dropped).map(r => r.id));
  // Claude Code asked the user about a spawn (PermissionRequest) and it never ran: once the user
  // has sent another prompt (a later prompt_id), the answer was no or the turn was interrupted.
  // A rejected dialog fires no hook of its own, so this is the only sign; nothing to reuse.
  const prompted = fb.filter(r => r.event === "prompted" && r.prompt_id && r.key);
  const refused = r => call.prompt_id && !ran.has(r.call_id) && prompted.some(p => p.session_id === r.session_id &&
    p.prompt_id !== call.prompt_id && p.ts >= r.ts && p.key === sha(r.subgoal));
  const live = r => r.subgoal && r.session_id === who.session_id && r.agent === who.agent && !dropped.has(r.id) &&
    !gone.has(r.call_id) && (ran.has(r.call_id) || now - Date.parse(r.ts) < pendingMs) && !refused(r);
  // Long subgoals that share a preamble differ at the end: an option keeps both.
  const clip = s => s.length > 600 ? `${s.slice(0, 400)} … ${s.slice(-200)}` : s;
  const base = {qset: spec.version, policy_version: spec.version, tag: "subgoal"};
  // the shared context line of a batch task (omp, Hermes) is background, not the task
  const norm = s => s.split("\n").filter(l => !/^context: /.test(l)).join(" ").replace(/\s+/g, " ").trim().toLowerCase();
  const dupRule = (dup, p) => `duplicates a subgoal ${dup.call_id === who.call_id ? "earlier in this batch" : ran.has(dup.call_id) ? "already launched in this session"
    : "launched in parallel in this session"} at ${dup.ts.slice(11, 16)} UTC (p ${p.toFixed(2)}): "${dup.subgoal.slice(0, 160)}". Reuse that result instead of starting it again`;
  const judged = await Promise.all(mine.map(async m => {
    const at = rows.findIndex(r => r.id === m.id);
    const earlier = (at < 0 ? [] : rows.slice(0, at)).filter(live).slice(-spec.keep);
    if (!earlier.length || !call.session_id) return {...base, outcome: "pass", rule: "first subgoal in this session", source: "subgoal"};
    // The same text again is a duplicate without asking: Jev reads an option identical to the new
    // subgoal as the new subgoal itself (p 0.2-0.3 on identical pairs, 0.7 on paraphrases).
    const same = earlier.findLast(r => norm(r.subgoal) === norm(m.subgoal));
    if (same) return {...base, outcome: "deny", source: "subgoal", dup: same, p: 1, rule: dupRule(same, 1)};
    const criteria = Object.fromEntries(earlier.map((r, i) => [`s${i + 1}`, clip(r.subgoal)]));
    criteria.none = "None of them: new work, a follow-up, a different part, or a review of earlier work.";
    const questions = {duplicate: {type: "choice", instructions: spec.instructions, criteria}};
    const res = await asker({subgoal: {text: m.subgoal, cwd: call.cwd}, [spec.context_key]: spec.context}, questions);
    const a = res.answers?.duplicate, i = /^s(\d+)$/.exec(a?.choice ?? "")?.[1];
    const p = a?.probabilities?.[a.choice] ?? a?.confidence ?? 0;   // how likely that option is
    const dup = !res.error && i && earlier[i - 1] && p >= spec.duplicateAt ? earlier[i - 1] : null;
    return {...base, ...res, dup, p, options: earlier.length,
      outcome: dup ? "deny" : "pass", source: res.error ? "fallback" : "jev",
      rule: res.error ? `jev unavailable (${res.error.slice(0, 80)}), subgoal not checked` : dup ? dupRule(dup, p) : "new subgoal"};
  }));
  // A duplicate is dropped at once, even when it runs anyway (shadow): the original stays the reference.
  // An adapter that cannot trim a batch (`whole`) denies all of it, so all of it is dropped: the
  // rest must not count as launched when the agent sends it again.
  const drop = judged.flatMap((j, i) => j.outcome === "deny" ? [i] : []);
  const all = drop.length === judged.length || (drop.length > 0 && call.whole === true);
  if (drop.length && call.session_id) append(SUBGOALS(), (all ? mine.map((_, i) => i) : drop).map(i => ({ts: new Date().toISOString(), id: mine[i].id, dropped: true})));
  // The trace keeps what was decided, not the prompts: a short redacted title and a hash, never the
  // earlier subgoals offered as options (subgoals.jsonl already holds each once).
  judged.forEach((j, i) => {
    const title = `[subgoal${mine.length > 1 ? ` ${i + 1}/${mine.length}` : ""}] ${mine[i].subgoal.slice(0, 120)}`;
    trace({...j, state: {subgoal: {title, sha: sha(mine[i].subgoal), chars: mine[i].subgoal.length, cwd: call.cwd}},
           questions: j.options ? {duplicate: {type: "choice", options: j.options + 1}} : {}},
          {...call, command: title}, CONFIG.mode === "enforce" ? j.outcome : "pass");
  });
  const list = drop.map(i => `${mine.length > 1 ? `task ${i + 1}: ` : ""}${judged[i].rule}`).join("; ");
  const again = all && drop.length < judged.length ? `. Start the others again without task${drop.length > 1 ? "s" : ""} ${drop.map(i => i + 1).join(", ")}` : "";
  const j = drop.length ? {...base, outcome: all ? "deny" : "pass", source: judged[drop[0]].source,
                           rule: (mine.length > 1 ? `${drop.length} of ${mine.length} subgoals repeat earlier work: ${list}` : list) + again}
    : judged.find(x => x.source === "fallback") ?? judged[0];
  return {j, drop: all ? [] : drop};
}

// Taint. guard.mjs records here that an agent session read a tool result it judged to be a prompt
// injection (warn or block); later commands in that session get the rules in rules.json `tainted`
// and the policy's taint gates. One small file per session, named by a hash of the session id.
// ponytail: never expires or pruned; a session id is not reused, and a file is a few hundred bytes.
const taintFile = s => join(CONFIG.data, "taint", `${sha(String(s))}.json`);
export function tainted(session_id) {
  if (!session_id) return null;
  try { return JSON.parse(readFileSync(taintFile(session_id), "utf8")); } catch { return null; }
}
/** Add an event (the last 20 are kept) and/or merge fields into a session's taint record. */
export function taint(session_id, event = null, fields = {}) {
  if (!session_id) return;
  const f = taintFile(session_id), prev = tainted(session_id) ?? {events: []};
  mkdirSync(dirname(f), {recursive: true, mode: 0o700});
  const next = {...prev, ...fields, events: event ? [...prev.events, event].slice(-20) : prev.events};
  writeFileSync(`${f}.${process.pid}`, JSON.stringify(next), {mode: 0o600});
  renameSync(`${f}.${process.pid}`, f);   // atomic; parallel writers can drop an event, never corrupt the file
}
// The command alone: a cwd like /tmp/http-client or a branch named ssh-keys is not egress.
export function taintedRule(command) {
  const rules = load("rules.json"), bare = stripDataHeredocs(command);
  const plain = gitPlain(bare), hit = checkRules(bare, {rules: rules.tainted ?? []}, bare) ?? checkRules(plain, {rules: rules.tainted ?? []}, plain);
  return hit && {outcome: hit.outcome, rule: hit.rule, id: hit.id, source: "taint", policy_version: rules.version};
}

// Any internal error is a decision too: the policy fallback when enforcing, logged either way.
// Subgoal dedup saves work rather than guarding it, so its errors always pass.
export async function decideSafe(call, opts) {
  const error = configurationError();
  if (error) return {effective: "ask", decision: "error", reason: `reflex: ${error}`, source: "error"};
  // A real hook event is separate from installation and from doctor's synthetic probes.
  if (["claude-code", "codex", "pi", "omp", "opencode", "hermes"].includes(call.agent)) try {
    const dir = join(CONFIG.data, "health");
    mkdirSync(dir, {recursive: true, mode: 0o700});
    writeFileSync(join(dir, `${call.agent}.json`), JSON.stringify({at: new Date().toISOString(), gate: HERE,
      mode: CONFIG.mode, engine: CONFIG.engine, allow: CONFIG.allow}), {mode: 0o600});
  } catch { /* diagnostics must not change a decision */ }
  // A team policy's mode floor (team.mjs) holds for this call only.
  const mode = CONFIG.mode;
  CONFIG.mode = teamMode(mode, call.cwd);
  try { return await decide(call, opts); } catch (e) {
    console.error(`reflex: ${e.message}`);
    const fallback = CONFIG.mode === "enforce" && !call.subgoal ? (safeFallback() ?? "ask") : "pass";
    return {effective: fallback, decision: "error", reason: `reflex error (${e.message.slice(0, 80)}), fallback ${fallback}`, source: "error"};
  } finally { CONFIG.mode = mode; }
}
// A policy "allow" under REFLEX_ALLOW: kept only when on and enforcing, logged as would_allow while
// it is watched, otherwise the plain pass the gate has always given.
export function allowSetting(j) {
  if (j.outcome !== "allow" || (CONFIG.allow === "on" && CONFIG.mode === "enforce")) return j;
  return {...j, outcome: ["shadow", "on"].includes(CONFIG.allow) ? "would_allow" : "pass"};
}
// Prompts an allow must never skip: a command that asks to leave the sandbox (Claude Code's
// dangerouslyDisableSandbox, whose own prompt is the human check on that), and plan mode, where
// anything outside the read-only set prompts on purpose. Logged as pass, not would_allow.
export function holdAllow(j, call) {
  const why = call.unsandboxed ? "asks to run outside the sandbox" : call.permission_mode === "plan" ? "plan mode" : null;
  return j.outcome === "allow" && why ? {...j, outcome: "pass", rule: `low risk (not allowed: ${why})`} : j;
}
// A fallback can pass, ask or deny; never allow, whatever the file says.
function safeFallback() { try { const f = load("policy.json").fallback; return ["pass", "ask", "deny"].includes(f) ? f : null; } catch { return null; } }
// Only a fresh Jev judgment, a System 2 approval or a human's queue approval may allow; a rule, the
// read-only list or the fast lane never does.
const view = (j, effective) => ({effective: effective === "allow" && !["jev", "judge", "queue"].includes(j.source) ? "pass"
                                   : ["pass", "allow", "ask", "deny"].includes(effective) ? effective : "ask", decision: j.outcome, reason: `reflex (${j.source}): ${j.rule}`,
                                 source: j.source, policy: j.policy_version ?? null, ...(j.plan && {plan: j.plan})});

// After the command: did it run, and how did it end. An effective "ask" followed by a record
// means it ran after the prompt; only an explicit "denied" event establishes rejection.
// Only the verdict on the run is kept, never its output.
export function record(ev) {
  if (CONFIG.mode === "off") return;
  append(FEEDBACK(), {ts: new Date().toISOString(), agent: ev.agent ?? null, event: ev.event ?? "ran",
    session_id: ev.session_id ?? null, call_id: ev.call_id ?? null, exit_code: ev.exit_code ?? null,
    ...(ev.prompt_id && {prompt_id: ev.prompt_id}), ...(ev.key && {key: ev.key})});
  // the runaway guard's failing-command loop and denial storm read these
  if (["failed", "denied"].includes(ev.event)) runawayMark(ev);
}

// Logs. One JSON line per judged command; the same shape report.mjs replays.
export function append(path, obj) {
  mkdirSync(CONFIG.data, {recursive: true});
  if (existsSync(path) && statSync(path).size > ROTATE_BYTES) renameSync(path, path.replace(/\.jsonl$/, `.${Date.now()}.jsonl`));
  appendFileSync(path, [obj].flat().map(o => JSON.stringify(o) + "\n").join(""));   // one write: a batch stays together
}

// The home directory as ~, so a webhook does not carry the local account name.
const tilde = p => p === homedir() || p.startsWith(homedir() + "/") ? `~${p.slice(homedir().length)}` : p;
function trace(j, call, effective) {
  const cmd = redact(call.command);
  const state = j.state ?? {call: {title: cmd.slice(0, 160), command: cmd, cwd: call.cwd}};
  append(TRACE(), {ts: new Date().toISOString(), tag: j.tag ?? "tool-gate", model: CONFIG.model,
    qset_version: j.qset ?? null, latency_s: j.latency_s ?? 0, state_sha: sha(state), state,
    questions: j.questions ?? {}, answers: j.answers ?? {}, usage: j.usage ?? {}, error: j.error ?? null,
    decision: j.outcome, policy_decision: j.policy_outcome ?? j.outcome, rule: j.rule, source: j.source, policy_version: j.policy_version ?? null,
    mode: CONFIG.mode, emitted: effective === "pass" ? null : effective,
    agent: call.agent ?? null, session_id: call.session_id ?? null, call_id: call.call_id ?? null,
    permission_mode: call.permission_mode ?? null, ...(j.plan && {plan: j.plan}), ...(j.ladder && {ladder: j.ladder}), ...((j.runaway ?? call.runaway) && {runaway: j.runaway ?? call.runaway}),
    ...(j.id && {rule_id: j.id}), ...(call.tier && {tier: call.tier}), cwd: call.cwd ?? null});
  // the decision webhook (notify.mjs): redacted, detached, never waited for; a trusted team policy may add one.
  // REFLEX_NOTIFY=off sends nothing (doctor's probes set it).
  const targets = [CONFIG.notify.target, teamPolicy(call.cwd)?.notify].filter(Boolean);
  if (targets.length && process.env.REFLEX_NOTIFY !== "off") notifyLater(targets, {ts: new Date().toISOString(), agent: call.agent ?? null, session_id: call.session_id ?? null,
    cwd: tilde(redact(call.cwd ?? "")), prod: !!call.tier?.prod, prod_by: call.tier?.prod ? call.tier.by : null, command: cmd.slice(0, 500),
    decision: effective === "pass" || !effective ? "pass" : effective, judged: j.outcome, mode: CONFIG.mode, source: j.source, rule_id: j.id ?? null,
    reason: redact(j.rule ?? "").slice(0, 300)});
}

// ---------------------------------------------------------------------------------------------
// Claude Code adapter: PreToolUse / PostToolUse hook JSON <-> the contract above.
// https://docs.claude.com/en/docs/claude-code/hooks
// An MCP tool (mcp__<server>__<tool>) or a file tool (Edit, Write, MultiEdit, NotebookEdit, Codex
// apply_patch) as a tool call for decide(): the tool gate (tools.mjs) judges it. null for any other tool.
const gatedTool = (name, input) => { const t = toolOf(name, input); return t && (t.kind === "mcp" || t.paths.length) ? t : null; };
function claudeCall(input) {
  const t = input.tool_input ?? {};
  if (gatedTool(input.tool_name, t))
    return {agent: "claude-code", tool: input.tool_name, input: t, cwd: input.cwd, session_id: input.session_id, call_id: input.tool_use_id,
            prompt_id: input.prompt_id, transcript_path: input.transcript_path, permission_mode: input.permission_mode, ...(input.agent_id && {agent_id: input.agent_id})};
  // Agent (formerly Task) spawns a subagent: its type, description and prompt are the subgoal.
  // A resume continues earlier work on purpose, so it is not checked.
  const subgoal = ["Task", "Agent"].includes(input.tool_name) && t.prompt && !t.resume
    ? [t.subagent_type && `agent: ${t.subagent_type}`, t.description, t.prompt].filter(Boolean).join("\n") : undefined;
  if (input.tool_name !== "Bash" && !subgoal) return null;
  // A subagent's hooks carry its parent's session_id plus its own agent_id: its subgoals are its own.
  const session_id = subgoal && input.agent_id ? `${input.session_id}/${input.agent_id}` : input.session_id;
  return {agent: "claude-code", ...(subgoal ? {subgoal} : {command: t.command}), cwd: input.cwd,
          session_id, call_id: input.tool_use_id, prompt_id: input.prompt_id, transcript_path: input.transcript_path,
          permission_mode: input.permission_mode, unsandboxed: t.dangerouslyDisableSandbox === true, ...(!subgoal && input.agent_id && {agent_id: input.agent_id})};
}
// What a PermissionRequest is about, as the trace (state.call.command) and subgoals.jsonl store it:
// PermissionRequest input has no tool_use_id, so the text is the join key.
export const promptKey = text => sha(redact(text).slice(0, 2000));
// PermissionRequest: Claude Code is about to show its permission dialog (or, where it cannot
// prompt, to deny). Recorded, never answered, so the dialog appears as it would without Reflex.
// A pass Claude Code's allowlist or permission mode let through has no such record, which is how
// report.mjs tells a human approval from an allowlist, and subgoal dedup a rejected spawn.
function claudePrompted(input) {
  const call = claudeCall(input);
  if (!call || call.tool) return;
  record({agent: "claude-code", event: "prompted", session_id: call.session_id, prompt_id: input.prompt_id,
          key: promptKey(call.command ?? call.subgoal)});
}
async function claudePre(input) {
  const call = claudeCall(input);
  if (!call) return;
  const out = claudeOut(await decideSafe(call));
  if (out) process.stdout.write(JSON.stringify(out));
}
// pass is silent: Claude Code's own permission rules decide. allow skips its prompt, but its deny
// and ask rules are still evaluated after the hook. The plugin never allows: its allow is a pass.
const EMITTED = ["ask", "deny"];
const claudeOut = d => EMITTED.includes(d.effective) ? {hookSpecificOutput: {hookEventName: "PreToolUse",
  permissionDecision: d.effective, permissionDecisionReason: d.reason}} : null;
function claudePost(input) {
  if (input.tool_name && !["Bash", "Task", "Agent"].includes(input.tool_name)) return;
  // Claude's Bash result carries no exit code; PostToolUseFailure is the failure signal.
  const ev = input.hook_event_name;
  record({agent: "claude-code", event: ev === "PermissionDenied" ? "denied" : ev === "PostToolUseFailure" ? "failed" : "ran",
          session_id: input.session_id, call_id: input.tool_use_id, agent_id: input.agent_id,
          exit_code: input.tool_response?.exit_code ?? (ev === "PostToolUse" ? 0 : null)});
}

// Codex CLI adapter: hooks.json PreToolUse / PostToolUse (https://learn.chatgpt.com/docs/hooks).
// Codex PreToolUse cannot "ask" (it would fail open), so an ask becomes a deny whose reason tells
// the agent to get the user's confirmation; the user can then run the command or approve it.
// It cannot plain-allow either (an "allow" is not honoured and falls through), so allow is silent,
// like pass, and Codex's own approval policy decides.
// spawn_agent (Codex 0.155+, multi-agent v1 and v2; matcher alias Agent) runs PreToolUse like any
// function tool and a deny blocks it, so subgoal dedup hooks it: its message (or text items), task
// name and agent type are the subgoal. SubagentStart cannot be used: its input has no task text and
// its output only adds context.
function codexCall(input) {
  const t = input.tool_input ?? {};
  if (input.tool_name === "Bash") return {agent: "codex", command: t.command, cwd: input.cwd, session_id: input.session_id, call_id: input.tool_use_id};
  if (gatedTool(input.tool_name, t)) return {agent: "codex", tool: input.tool_name, input: t, cwd: input.cwd, session_id: input.session_id, call_id: input.tool_use_id};
  if (input.tool_name !== "spawn_agent") return null;
  const text = typeof t.message === "string" && t.message.trim() ? t.message
    : (Array.isArray(t.items) ? t.items : []).map(i => typeof i?.text === "string" ? i.text : "").filter(Boolean).join("\n");
  if (!text) return null;
  // A subagent's spawns are its own, as in Claude Code.
  return {agent: "codex", subgoal: [t.agent_type && `agent: ${t.agent_type}`, t.task_name, text].filter(Boolean).join("\n"), cwd: input.cwd,
          session_id: input.agent_id ? `${input.session_id}/${input.agent_id}` : input.session_id, call_id: input.tool_use_id};
}
async function codexPre(input) {
  const call = codexCall(input);
  if (!call) return;
  const out = codexOut(await decideSafe(call), !!call.tool);
  if (out) process.stdout.write(JSON.stringify(out));
}
function codexOut(d, tool = false) {
  if (!["ask", "deny"].includes(d.effective)) return null;
  const reason = d.effective === "ask"
    ? `${d.reason}. This hook cannot open an approval dialog. ${tool ? "The user can make this change or run this tool themselves."
      : "The user can review and run the exact command with reflex run in their own terminal (include --cwd)."} A chat confirmation does not unblock this hook; do not retry or disable it.` : d.reason;
  return {hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason}};
}
function codexPost(input) {
  if (!["Bash", "spawn_agent"].includes(input.tool_name)) return;
  record({agent: "codex", event: "ran", session_id: input.session_id, call_id: input.tool_use_id});
}

// Hermes Agent adapter: config.yaml `hooks: pre_tool_call` shell hook on the terminal tool.
// "approve" routes through Hermes' own approval prompt; rule_key is per command, so approving one
// command "for the session" never pre-approves a different one.
// delegate_task spawns subagents: {tasks: [{goal, context?}]} or the legacy {goal, context?}, each
// task a subgoal; other actions (list, steer, stop) control running children and are not checked.
// A batch where only some tasks repeat earlier work is blocked with the list, not trimmed: a
// "modify" hook could drop them, but nothing would tell the model which ones went, and it would
// launch them again.
export function hermesSubgoals(t = {}) {
  if (t.action && t.action !== "spawn") return [];
  const items = Array.isArray(t.tasks) && t.tasks.length ? t.tasks : [t];
  const text = x => typeof x?.goal === "string" && x.goal.trim()
    ? [x.goal, typeof x.context === "string" && x.context.trim() && `context: ${x.context.slice(0, 300)}`].filter(Boolean).join("\n") : "";
  return items.map(text).filter(Boolean);
}
async function hermesPre(input) {
  if (input.tool_name === "delegate_task") {
    const subgoals = hermesSubgoals(input.tool_input ?? {});
    if (!subgoals.length) return process.stdout.write("{}");
    const d = await decideSafe({agent: "hermes", subgoals, whole: true, cwd: input.cwd, session_id: input.session_id, call_id: input.extra?.tool_call_id});
    return process.stdout.write(JSON.stringify(d.effective === "deny" ? {action: "block", message: d.reason} : {}));
  }
  // MCP tools (mcp_<server>_<tool>) and the file tools (write_file, patch): the tool gate
  if (input.tool_name !== "terminal" && gatedTool(input.tool_name, input.tool_input)) {
    const d = await decideSafe({agent: "hermes", tool: input.tool_name, input: input.tool_input ?? {}, cwd: input.cwd,
                                session_id: input.session_id, call_id: input.extra?.tool_call_id});
    return process.stdout.write(JSON.stringify(hermesOut(d, `${input.tool_name} ${JSON.stringify(input.tool_input ?? {})}`)));
  }
  if (input.tool_name !== "terminal") return process.stdout.write("{}");
  const command = input.tool_input?.command;
  const d = await decideSafe({agent: "hermes", command, cwd: input.tool_input?.workdir ?? input.cwd,
                              session_id: input.session_id, call_id: input.extra?.tool_call_id});
  process.stdout.write(JSON.stringify(hermesOut(d, command)));
}
// Hermes has no allow verdict for a hook: pass and allow are both {}, and its own approvals decide.
const hermesOut = (d, command) => d.effective === "deny" ? {action: "block", message: d.reason}
  : d.effective === "ask" ? {action: "approve", message: d.reason, rule_key: `reflex:${sha(command ?? "")}`} : {};
// post_tool_call also fires for a call a hook or guardrail blocked (status "blocked"): that one did
// not run, and neither did a cancelled one.
function hermesPost(input) {
  if (!["terminal", "delegate_task"].includes(input.tool_name)) return;
  const st = input.extra?.status;
  record({agent: "hermes", event: st === "blocked" ? "denied" : st === "cancelled" ? "failed" : "ran",
          session_id: input.session_id, call_id: input.extra?.tool_call_id});
}

// ---------------------------------------------------------------------------------------------

const readStdin = () => JSON.parse(readFileSync(0, "utf8"));
// ask needs a human: read y/N from the controlling terminal; no terminal means no approval.
function confirmOnTty(command, reason) {
  try {
    const fd = openSync("/dev/tty", "r+");
    const q = Buffer.from(`\n${reason}\nDirectory: ${JSON.stringify(process.cwd())}\nCommand (credentials masked): ${JSON.stringify(redact(command))}\nrun it? [y/N] `);
    writeSync(fd, q);
    const buf = Buffer.alloc(16), n = readSync(fd, buf, 0, 16, null);
    closeSync(fd);
    return /^y(es)?$/i.test(buf.toString("utf8", 0, n).trim());
  } catch { return false; }
}
const argv = process.argv.slice(2);
const flag = f => argv.includes(f);
const opt = n => { const i = argv.indexOf(n); return i > -1 ? argv[i + 1] : undefined; };
const main = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
// An error a hook does not handle goes to failsafe.mjs: the pre-execution hooks ask, the others warn.
const guarded = fn => Promise.resolve().then(fn).catch(hookFailure);

if (!main) { /* imported as a library */ }
else if (flag("--claude")) await guarded(async () => claudePre(readStdin()));
else if (flag("--claude-post")) await guarded(async () => claudePost(readStdin()));
else if (flag("--claude-prompted")) await guarded(async () => claudePrompted(readStdin()));
else if (flag("--codex")) await guarded(async () => codexPre(readStdin()));
else if (flag("--codex-post")) await guarded(async () => codexPost(readStdin()));
else if (flag("--hermes")) await guarded(async () => hermesPre(readStdin()));
else if (flag("--hermes-post")) await guarded(async () => hermesPost(readStdin()));
else if (flag("--decide")) await guarded(async () => process.stdout.write(JSON.stringify(await decideSafe(readStdin())) + "\n"));
else if (flag("--record")) await guarded(async () => record(readStdin()));
else if (flag("--bg")) await guarded(async () => decide(readStdin(), {background: true}));
else if (flag("--sh")) {
  // Shell shim (scripts/reflex-sh): bash-compatible `-c` / `-lc` calls are judged, then run, confirmed
  // on the terminal, or refused with exit 126. Everything else is passed to bash untouched.
  const args = argv.slice(argv.indexOf("--sh") + 1);
  const ci = args.findIndex(a => /^-[a-z]*c[a-z]*$/.test(a));
  const command = ci > -1 ? args[ci + 1] : undefined;
  const bash = ENV.REFLEX_SHELL ?? "/bin/bash";
  let verdict = "pass";
  if (command) {
    const d = await decideSafe({agent: ENV.REFLEX_AGENT ?? "shell", command, cwd: process.cwd(),
                                session_id: ENV.REFLEX_SESSION_ID, intent: ENV.REFLEX_INTENT});
    verdict = d.effective;   // pass and allow run: there is no other prompt to skip
    if (verdict === "ask") verdict = confirmOnTty(command, d.reason) ? "pass" : "deny";
    if (verdict === "deny") { console.error(`${d.reason}\nrefused; a human can run it directly if it is intended.`); process.exit(126); }
  }
  const r = spawnSync(bash, args, {stdio: "inherit"});
  // It ran: nothing after this may fail into failsafe.mjs, which would run it again.
  if (command) try { record({agent: ENV.REFLEX_AGENT ?? "shell", event: "ran", exit_code: r.status}); } catch { /* the log only */ }
  process.exit(r.status ?? 1);
}
else if (flag("--check")) {
  // Try one command without an agent: node gate.mjs --check "terraform apply" [--cwd dir] [--intent text]
  const cwd = opt("--cwd") ?? process.cwd(), intent = opt("--intent");
  const j = await judge({command: opt("--check"), cwd, session: intent ? {intent} : {}, useCache: false});
  const answers = Object.fromEntries(Object.entries(j.answers ?? {}).map(([k, a]) => [k, a.noul ?? a.choice ?? a.score]));
  console.log(JSON.stringify({decision: j.outcome, rule: j.rule, source: j.source, policy: j.policy_version ?? null,
                              latency_s: j.latency_s ?? 0, answers, env: j.state?.call?.env, plan: j.plan ?? j.state?.call?.plan, error: j.error ?? undefined}, null, 1));
}
else console.error("usage: gate.mjs --check <cmd> | --decide | --record | --claude[-post|-prompted] | --codex[-post] | --hermes[-post] | --sh | --bg | --selfcheck");
