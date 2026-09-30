// Jev (gate.mjs): the context a call is judged in, the provider's key and where it may go, one
// call through the provider, the answer cache and jevJudge.
import {PLUGIN_MODE, pluginKey} from "./plugin.mjs";
import {existsSync, statSync, openSync, readSync, closeSync, mkdirSync, writeFileSync, renameSync, rmSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {homedir, platform} from "node:os";
import {join, dirname, resolve} from "node:path";
import {compile} from "./policy.mjs";
import {PROVIDERS, keyRouteError, call as callProvider} from "./providers.mjs";
import {ENV, readText, redact, CONFIG, ENGINE, LAYA_TOKEN, LAYA, configurationError, CACHE_TTL_MS, CACHE, sha} from "./config.mjs";
import {localScripts, SCRIPT_BYTES} from "./scripts.mjs";
import {load} from "./rules.mjs";

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
  // @reflex:setup-only begin
  if (KEYS[CONFIG.provider]) return KEYS[CONFIG.provider];
  const p = PROVIDERS[CONFIG.provider], env = p.env.map(n => ENV[n]?.trim()).find(Boolean);
  if (env) return (KEYS[CONFIG.provider] = env);
  const item = CONFIG.provider === "typesafe" ? CONFIG.keychain : p.keychain;
  if (platform() === "darwin") {
    try {
      const k = execFileSync("security", ["find-generic-password", "-s", item, "-w"],
                             {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 1500}).trim();
      if (k) return (KEYS[CONFIG.provider] = k);
    } catch { /* fall through */ }
  }
  throw new Error(`no API key for ${CONFIG.provider}: set ${p.env.join(" or ")} or keychain item "${item}"`);
  // @reflex:setup-only end
  // Reached only in the plugin bundle run without --plugin: no key source there, so never call the provider.
  throw new Error(`no API key for ${CONFIG.provider}`);
}

// A missing key is a configuration error, not an outage: every engine decision falls back until it is
// fixed. The hook that meets one records it (key-error.json in the data directory), a fresh Jev answer
// clears it, and the Claude Code hook shows the warning once per session; status and doctor show it too.
export const isKeyError = error => /\bno API key for /.test(error ?? "");
export const KEY_ERROR = () => join(CONFIG.data, "key-error.json");
export function keyErrorMessage() {
  const head = "Jev engine has no API key: every engine decision falls back";
  if (PLUGIN_MODE) return `${head}; set the Jev API key in the Reflex plugin options (/plugin, reflex, Configure) or set the engine option to local`;
  // @reflex:setup-only begin
  return `${head}; run reflex setup --keychain <item> or set ${PROVIDERS[CONFIG.provider]?.env.join(" or ") ?? "the provider's key variable"}`;
  // @reflex:setup-only end
  return head;
}
const readKeyError = () => { try { return JSON.parse(readText(KEY_ERROR()) ?? "null"); } catch { return null; } };
function writeKeyError(k) {
  mkdirSync(CONFIG.data, {recursive: true});
  const tmp = `${KEY_ERROR()}.${process.pid}`;
  writeFileSync(tmp, JSON.stringify(k), {mode: 0o600});
  renameSync(tmp, KEY_ERROR());   // atomic; a parallel hook can drop a session id, which only repeats the warning
}
/** After a judgment: remember a missing key, forget it once Jev answers. Never throws. */
export function noteKeyError(j) {
  try {
    if (isKeyError(j.error)) { if (!readKeyError()) writeKeyError({at: new Date().toISOString(), provider: CONFIG.provider, warned: []}); }
    else if (j.source === "jev" && existsSync(KEY_ERROR())) rmSync(KEY_ERROR(), {force: true});
  } catch { /* a diagnostic must not change a decision */ }
}
/** The recorded missing-key error while the engine is jev, or null. */
export const keyError = () => CONFIG.engine === "jev" ? readKeyError() : null;
/** The warning for this session, once: null when there is no missing key or the session was warned. */
// `mode`: the mode the call ran in (a team policy's floor included).
export function keyWarning(session, mode = CONFIG.mode) {
  try {
    const k = mode === "off" ? null : keyError();
    if (!k || (session && k.warned?.includes(session))) return null;
    // ponytail: read, then write; a Jev answer that clears the marker in between can bring it back until the next answer
    if (session && existsSync(KEY_ERROR())) writeKeyError({...k, warned: [...(k.warned ?? []), session].slice(-200)});
    return `reflex: ${keyErrorMessage()}. ${mode === "enforce" ? "In enforce mode they ask (the policy fallback)." : "In shadow mode they are logged and pass; only deterministic rules act."}`;
  } catch { return null; }
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
