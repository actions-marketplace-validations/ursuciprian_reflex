#!/usr/bin/env node
// Team policy: <repo>/.reflex/policy.json, committed with the code, applied by every teammate's Reflex
// while the agent works in that repository.
//
//   {"version": 1,
//    "rules":        [{"id": "no-drop", "outcome": "deny", "rule": "drops a table", "all": ["\\bdrop\\s+table\\b"]}],
//    "always_human": [{"id": "billing", "rule": "billing API", "all": ["\\bbilling-api\\b"]}],
//    "prod":         ["\\bacme-live\\b", "clusters/main-eu\\b"],
//    "mode":         "enforce",
//    "fastlane":     [{"pattern": "^make lint$"}]}
//
// Everything but `fastlane` only adds checks, so it applies as soon as the file is there: rules
// (rules.json shape, ask or deny), always-human patterns (escalation.json shape), production markers
// (a matching command that is not read-only asks) and a mode floor (shadow becomes enforce; off stays
// off, it is the user's switch). Nothing in the file can remove a rule, raise a threshold or turn off
// the injection guard, the runaway guard or the tamper check: there are no keys for that, and an
// unknown key makes the file invalid.
// `fastlane` loosens, so it applies only while the user trusts this exact file: `reflex trust .`
// records the repo and the file's sha256 in ~/.config/reflex/trusted.json. Any change to the file
// drops the trust until it is trusted again. Its entries are held to the fastlane.json rules and run
// after the rules, the tamper check and the always-human class, like the user fast lane.
// An invalid file never loosens (doctor says why); its valid stricter parts still apply.
//
// Stricter parts are read from every enclosing repository root (the nearest directory holding .git,
// and any repository around it), so a `.git` an agent creates in a subdirectory cannot shed the
// policy of the repository it sits in; the fast lane comes from the nearest root only. A root, and
// its policy file, count only when owned by the current user (git's safe.directory idea), so another
// account cannot plant /tmp/.git and /tmp/.reflex. A .reflex in a directory without .git is never read.
//
//   reflex trust [dir] | reflex trust --revoke [dir] | reflex policy [dir] | reflex policy init [dir]
import {createHash} from "node:crypto";
import {closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, writeFileSync, writeSync} from "node:fs";
import {homedir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {setFlagsFromString} from "node:v8";
import {broad, compilePattern, patternError} from "./fastlane.mjs";

export const TRUST_FILE = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "reflex/trusted.json");
const MAX_FILE = 64 * 1024, MAX_PATTERNS = 64;
const owned = st => process.getuid === undefined || st.uid === process.getuid();

/** Repository roots around cwd, nearest first: directories holding a .git this user owns. */
export function repoRoots(cwd) {
  if (typeof cwd !== "string" || !cwd) return [];
  const out = [];
  for (let d = resolve(cwd); ; d = dirname(d)) {
    try { if (owned(lstatSync(join(d, ".git")))) out.push(d); } catch { /* not a root */ }
    if (dirname(d) === d) return out;
  }
}
export const repoRoot = cwd => repoRoots(cwd)[0] ?? null;

// A pattern someone else wrote runs in every teammate's hook on a command an agent chose, and a hook
// that times out lets the command run. So team patterns run on V8's linear-time engine (the `l`
// flag): a pattern it cannot run in linear time (lookarounds, backreferences, large bounded repeats)
// is rejected. That engine has no `i` flag, so the pattern's literal letters and the text are lowercased.
try { setFlagsFromString("--enable-experimental-regexp-engine"); } catch { /* then every team pattern is rejected: fail closed */ }
const lower = p => p.replace(/\\[\s\S]|[\s\S]/g, m => m.length === 2 ? m : m.toLowerCase());
const compileTeam = p => new RegExp(lower(p), "l");
export function regexError(p) {
  if (typeof p !== "string" || !p || p.length > 500) return "must be a string of 1 to 500 characters";
  try { new RegExp(p, "i"); } catch (e) { return `does not compile (${e.message})`; }
  try { compileTeam(p); } catch { return "cannot run in linear time: no lookarounds, backreferences or large bounded repeats such as {0,64} (use * or +)"; }
  return null;
}
// checkRules calls `test` when a rule has one.
const linear = r => { const res = r.all.map(compileTeam); return {...r, test: text => { const t = text.toLowerCase(); return res.every(re => re.test(t)); }}; };

const RULE_KEYS = new Set(["id", "outcome", "rule", "all", "applies_to", "context", "shell", "writes", "whole_script", "before_read_only", "note"]);
const HUMAN_KEYS = new Set(["id", "rule", "all", "context", "note"]);
function ruleError(r, human) {
  if (!r || typeof r !== "object" || Array.isArray(r)) return "not an object";
  const extra = Object.keys(r).find(k => !(human ? HUMAN_KEYS : RULE_KEYS).has(k));
  if (extra) return `unknown field "${extra}"`;
  if (typeof r.id !== "string" || !/^[\w.-]{1,64}$/.test(r.id)) return "id must be 1 to 64 letters, digits, dots, dashes or underscores";
  if (!human && !["ask", "deny"].includes(r.outcome)) return 'outcome must be "ask" or "deny"';
  if (typeof r.rule !== "string" || !r.rule.trim() || r.rule.length > 200) return "rule must be a description of at most 200 characters";
  if (!Array.isArray(r.all) || !r.all.length || r.all.length > 4) return "all must be a list of 1 to 4 patterns";
  for (const p of r.all) { const e = regexError(p); if (e) return `pattern ${JSON.stringify(String(p).slice(0, 60))} ${e}`; }
  if (r.applies_to !== undefined && (!Array.isArray(r.applies_to) || !r.applies_to.length || r.applies_to.some(a => !["command", "script"].includes(a))))
    return 'applies_to must list "command" and/or "script"';
  for (const k of ["context", "shell", "writes", "whole_script", "before_read_only"]) if (r[k] !== undefined && typeof r[k] !== "boolean") return `${k} must be true or false`;
  return null;
}

const KEYS = new Set(["version", "note", "rules", "always_human", "prod", "mode", "fastlane", "infra"]);
/** The file, validated part by part: every valid stricter entry is kept, every problem is an error. */
export function parseTeam(text) {
  const out = {rules: [], always_human: [], mode: null, fastlane: [], infra: null, errors: []};
  let doc;
  try { doc = JSON.parse(text); } catch (e) { out.errors.push(`not JSON (${e.message})`); return out; }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) { out.errors.push("must be a JSON object"); return out; }
  if (doc.version !== 1) out.errors.push('needs "version": 1');
  for (const k of Object.keys(doc)) if (!KEYS.has(k))
    out.errors.push(`unknown key "${k}": a team policy can add rules, always_human patterns, prod markers, a mode floor and a trusted fastlane, nothing else`);
  let budget = MAX_PATTERNS;
  const list = (k, max) => {
    if (doc[k] === undefined) return [];
    if (!Array.isArray(doc[k])) { out.errors.push(`${k} must be a list`); return []; }
    if (doc[k].length > max) out.errors.push(`${k}: more than ${max} entries, the rest are ignored`);
    return doc[k].slice(0, max);
  };
  const spend = (n, where) => { if (n > budget) { out.errors.push(`${where}: more than ${MAX_PATTERNS} patterns in the file, the rest are ignored`); return false; } budget -= n; return true; };
  for (const [i, r] of list("rules", 50).entries()) {
    const why = ruleError(r, false);
    if (why) out.errors.push(`rules ${i + 1}: ${why}`);
    else if (spend(r.all.length, `rules ${i + 1}`)) out.rules.push(linear({...Object.fromEntries(Object.entries(r).filter(([k]) => k !== "note")), id: `team:${r.id}`, rule: `${r.rule} (team policy)`}));
  }
  for (const [i, r] of list("always_human", 50).entries()) {
    const why = ruleError(r, true);
    if (why) out.errors.push(`always_human ${i + 1}: ${why}`);
    else if (spend(r.all.length, `always_human ${i + 1}`)) out.always_human.push(linear({id: `team:${r.id}`, rule: `${r.rule} (team policy)`, all: r.all, ...(r.context !== undefined && {context: r.context})}));
  }
  // A production marker: a command (or its cwd, profile, kube context, workspace, branch) that
  // matches is production. One that is not read-only asks, and a rule's ask always goes to a human.
  for (const [i, m] of list("prod", 20).entries()) {
    const why = regexError(m);
    if (why) out.errors.push(`prod ${i + 1}: pattern ${why}`);
    else if (spend(1, `prod ${i + 1}`)) out.rules.push(linear({id: "team:prod", outcome: "ask", shell: true, rule: "production, by a marker in the team policy", all: [m]}));
  }
  // The plan-aware infra gate (infra.mjs), stricter only: deny a plan that destroys, require a saved plan in production.
  if (doc.infra !== undefined) {
    const i = doc.infra, bad = !i || typeof i !== "object" || Array.isArray(i) ? "must be an object"
      : Object.keys(i).find(k => !["destroy", "require_plan_in_prod"].includes(k)) ? 'takes only "destroy": "deny" and "require_plan_in_prod": true'
      : i.destroy !== undefined && i.destroy !== "deny" ? 'destroy can only be "deny" (a team policy cannot soften it)'
      : i.require_plan_in_prod !== undefined && i.require_plan_in_prod !== true ? "require_plan_in_prod can only be true" : null;
    if (bad) out.errors.push(`infra ${bad}`);
    else out.infra = {...i};
  }
  if (doc.mode !== undefined && !["shadow", "enforce"].includes(doc.mode)) out.errors.push('mode must be "shadow" or "enforce" (a floor: it can only raise the mode)');
  else out.mode = doc.mode ?? null;
  for (const [i, e] of list("fastlane", 100).entries()) {
    const why = !e || typeof e !== "object" || Array.isArray(e) ? "not an object"
      : Object.keys(e).find(k => !["pattern", "note"].includes(k)) ? "only pattern and note (the scope is the repository)" : patternError(e.pattern);
    if (why) out.errors.push(`fastlane ${i + 1}: ${why}`);
    else out.fastlane.push(e.pattern);
  }
  return out;
}

export const sha256 = text => createHash("sha256").update(text).digest("hex");
const realRoot = root => { try { return realpathSync(root); } catch { return root; } };
export function readTrust(file = TRUST_FILE) {
  try {
    const d = JSON.parse(readFileSync(file, "utf8"));
    return d && typeof d === "object" && d.repos && typeof d.repos === "object" && !Array.isArray(d.repos) ? d : {version: 1, repos: {}};
  } catch { return {version: 1, repos: {}}; }
}

// One root's file: null when there is none, else what it adds and its problems.
const parsed = new Map(), empty = {rules: [], always_human: [], mode: null, fastlane: [], infra: null};
function readOne(root) {
  const file = join(root, ".reflex/policy.json");
  let text;
  try {
    // A regular file this user owns in a real directory: a symlink could point anywhere, a FIFO would hang the hook.
    const dir = lstatSync(join(root, ".reflex"));
    if (!dir.isDirectory()) { if (dir.isSymbolicLink()) throw new Error(".reflex is a symlink"); return null; }
    const st = lstatSync(file);
    if (!st.isFile()) throw new Error("not a regular file");
    if (!owned(st)) throw new Error("not owned by you");
    if (st.size > MAX_FILE) throw new Error(`larger than ${MAX_FILE / 1024} KB`);
    text = readFileSync(file, "utf8");
  } catch (e) {
    return e.code === "ENOENT" ? null : {root, file, sha256: null, ...empty, errors: [e.message]};
  }
  const hash = sha256(text);
  if (!parsed.has(hash)) parsed.set(hash, parseTeam(text));
  return {root, file, sha256: hash, ...parsed.get(hash)};
}

/** The team policy that applies in cwd, or null when no enclosing repository has one. Never throws. */
export function teamPolicy(cwd) {
  try {
    const roots = repoRoots(cwd), found = roots.map(readOne).filter(Boolean);
    if (!found.length) return null;
    const [t] = found, saved = readTrust().repos[realRoot(t.root)]?.sha256;
    const trust = t.sha256 && saved === t.sha256 ? "trusted" : saved ? "changed" : "untrusted";
    // loosening: only the nearest root's own file, trusted as it is now, valid, not home or /
    const active = t.root === roots[0] && trust === "trusted" && !t.errors.length && !broad(t.root);
    return {root: t.root, file: t.file, sha256: t.sha256, trust, active_fastlane: active,
      inherited: found.slice(1).map(f => f.file), tag: (found.length > 1 ? sha256(found.map(f => f.sha256).join()) : t.sha256 ?? "unreadable").slice(0, 8),
      errors: found.flatMap((f, i) => f.errors.map(e => i ? `${f.file}: ${e}` : e)),
      rules: found.flatMap(f => f.rules), always_human: found.flatMap(f => f.always_human),
      mode: found.some(f => f.mode === "enforce") ? "enforce" : found.find(f => f.mode)?.mode ?? null,
      infra: found.some(f => f.infra) ? Object.assign({}, ...found.map(f => f.infra ?? {})) : null,
      fastlane: active ? t.fastlane.map(pattern => ({pattern, cwd: t.root, re: compilePattern(pattern), team: true})) : [],
      fastlane_count: t.fastlane.length, fastlane_patterns: t.fastlane};
  } catch (e) {
    return {root: null, file: null, sha256: null, trust: "untrusted", active_fastlane: false, inherited: [], tag: "error", errors: [`team policy: ${e.message}`], ...empty};
  }
}

/** rules.json with the team's rules: its denies first (a deny wins over a bundled ask), its asks last (never in front of a bundled deny). */
export function teamRules(rules, cwd) {
  const t = teamPolicy(cwd);
  if (!t?.rules.length) return rules;
  return {...rules, version: `${rules.version}+team-${t.tag}`,
          rules: [...t.rules.filter(r => r.outcome === "deny"), ...rules.rules, ...t.rules.filter(r => r.outcome !== "deny")]};
}
/** escalation.json with the team's always-human patterns added. */
export function teamEscalation(esc, cwd) {
  const t = teamPolicy(cwd);
  return t?.always_human.length ? {...esc, always_human: {...esc.always_human, rules: [...esc.always_human.rules, ...t.always_human]}} : esc;
}
/** The mode for a call in cwd: the team's floor raises shadow to enforce; off stays off. */
export const teamMode = (mode, cwd) => mode === "shadow" && teamPolicy(cwd)?.mode === "enforce" ? "enforce" : mode;
/** Fast-lane entries from a trusted, valid team policy (userFastPass shape), else none. */
export const teamFastLane = cwd => teamPolicy(cwd)?.fastlane ?? [];
// A glob the shell expands to .reflex: a path segment that starts with a literal dot, as a leading
// dot is never matched by a wildcard (`rm -rf .ref*`, `mv .r[e]flex x`; not `rm -rf *`).
export const globsReflex = text => (text.match(/[^\s;&|<>()'"`=]*[*?[][^\s;&|<>()'"`]*/g) ?? []).some(w => w.split("/").some(seg =>
  seg.startsWith(".") && /[*?[]/.test(seg) && (() => { try { return new RegExp(`^${seg.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(".reflex"); } catch { return true; } })()));

// Trust in root's current file. Only the CLI calls it, after a human confirms on a terminal.
function trustRepo(root, hash, file = TRUST_FILE) {
  const d = readTrust(file);
  if (hash) d.repos[realRoot(root)] = {sha256: hash, at: new Date().toISOString()};
  else delete d.repos[realRoot(root)];
  mkdirSync(dirname(file), {recursive: true, mode: 0o700});
  writeFileSync(`${file}.${process.pid}`, JSON.stringify({version: 1, repos: d.repos}, null, 1) + "\n", {mode: 0o600});
  renameSync(`${file}.${process.pid}`, file);
}

export const STARTER = {
  version: 1,
  note: "Reflex team policy: every teammate's Reflex applies it while an agent works in this repository. It can only add checks: rules that ask or deny (the rules.json shape), always_human patterns, prod markers and a mode floor. Patterns are case-insensitive and read the command plus its context (cwd=, aws_profile=, kube_context=, tf_workspace=, git_branch=). A fastlane list would loosen, so it applies only for a teammate who ran `reflex trust .` on this exact file. Set \"mode\" to \"enforce\" to make enforce the floor. Guide: https://github.com/ursuciprian/reflex/blob/main/docs/GUIDE.md#team-policy-share-reflex-rules-across-a-repo",
  mode: "shadow",
  rules: [
    {id: "drop-table", outcome: "deny", shell: true, rule: "drops a database, schema or table", all: ["\\bdrop\\s+(database|schema|table)\\b"],
     note: "deny: blocked in every mode, whatever the agent says"},
    {id: "migrations", outcome: "ask", shell: true, rule: "runs database migrations", all: ["\\b(db:migrate|alembic\\supgrade|prisma\\smigrate\\sdeploy)\\b"],
     note: "ask: a human confirms, and in the autonomous profile it never goes to System 2"},
  ],
  always_human: [
    {id: "billing", rule: "calls the billing service", all: ["\\bbilling-api\\b"], note: "never decided by System 2, always a human"},
  ],
  prod: ["\\bacme-live\\b", "clusters/main-eu\\b"],
};

// ---------------------------------------------------------------------------------------------
const say = s => console.log(`\x1b[1mreflex\x1b[0m ${s}`);
const die = (s, code = 1) => { console.error(`reflex: ${s}`); process.exit(code); };
function describe(t) {
  return [`team policy: ${t.file}`, `sha256: ${t.sha256 ?? "unreadable"}`, `trust: ${t.trust}${t.trust === "changed" ? " (the file changed since you trusted it; its fast lane is off)" : ""}`,
    `adds: rules ${t.rules.filter(r => r.id !== "team:prod").length}, always-human ${t.always_human.length}, prod markers ${t.rules.filter(r => r.id === "team:prod").length}` +
    `, mode floor ${t.mode ?? "none"}`,
    `fast lane: ${t.fastlane_count ?? 0} entr${t.fastlane_count === 1 ? "y" : "ies"}, ${t.active_fastlane ? "active" : "inactive"}`,
    ...t.inherited.map(f => `also applies (stricter parts): ${f}`), ...t.errors.map(e => `invalid: ${e}`)];
}
// A human's answer on the terminal. The gate asks before an agent runs `reflex trust` at all, an agent
// shell usually has no terminal, and an agent session's environment is refused. ponytail: speed bumps,
// not a boundary: a same-user agent that runs arbitrary code can fake a terminal (script(1)) or write
// trusted.json itself, the same limit as fastlane.json; the tamper rules are the control.
function confirm(question) {
  if (process.env.CLAUDECODE || process.env.CODEX_SANDBOX || process.env.CODEX_SANDBOX_NETWORK_DISABLED || process.env.REFLEX_AGENT)
    die("reflex trust runs in your own terminal, not from an agent session", 2);
  let answer = "";
  try {
    const fd = openSync("/dev/tty", "r+"), buf = Buffer.alloc(1);
    writeSync(fd, question);
    while (readSync(fd, buf, 0, 1, null) === 1 && buf[0] !== 10) answer += buf.toString();
    closeSync(fd);
  } catch { die("no terminal to confirm on: a human runs reflex trust in their own terminal", 2); }
  return answer.trim() === "trust";
}

function main(argv) {
  const [cmd, ...rest] = argv, init = cmd === "policy" && rest[0] === "init";
  const target = resolve((init ? rest.slice(1) : rest).find(a => !a.startsWith("--")) ?? ".");
  const root = repoRoot(target);
  if (!root) die(`${target} is not inside a git repository; a team policy lives at the repository root`);
  if (init) {
    const file = join(root, ".reflex/policy.json");
    if (existsSync(file)) die(`${file} already exists`);
    mkdirSync(dirname(file), {recursive: true});
    writeFileSync(file, JSON.stringify(STARTER, null, 2) + "\n", {flag: "wx"});
    return say(`wrote ${file}: stricter checks only. Edit it, commit it, and every teammate's Reflex applies it here.`);
  }
  const t = teamPolicy(root);
  if (cmd === "policy") {
    if (!t) return say(`no team policy in ${root} (reflex policy init writes a starter)`);
    return argv.includes("--json") ? console.log(JSON.stringify({...t, fastlane: undefined, rules: t.rules.map(r => r.id), always_human: t.always_human.map(r => r.id)}, null, 1)) : describe(t).forEach(l => say(l));
  }
  if (cmd === "trust" && rest.includes("--revoke")) { trustRepo(root, null); return say(`${root}: trust removed; its team fast lane is off`); }
  if (cmd !== "trust") die("usage: reflex trust [dir] | reflex trust --revoke [dir] | reflex policy [dir] [--json] | reflex policy init [dir]");
  if (!t || t.root !== root) die(`no team policy in ${root}`);
  if (t.errors.length || !t.sha256) { describe(t).forEach(l => console.error(l)); die("fix the team policy before trusting it"); }
  if (broad(root)) die(`${root} is your home or /; a team fast lane there would cover every project`);
  describe(t).forEach(l => say(l));
  for (const p of t.fastlane_patterns) say(`  fast lane: ${p}`);   // from the text that was hashed
  if (!confirm(`Trust this file for ${root}? Its fast lane then passes these commands without a prompt. Type "trust" to confirm: `)) die("not trusted");
  trustRepo(root, t.sha256);
  say(`trusted ${t.sha256.slice(0, 12)} for ${root}. Any change to the file drops the trust until you run reflex trust again.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
