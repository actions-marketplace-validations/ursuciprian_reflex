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
// The file is read from the repository root only: the nearest directory holding .git, as the
// instruction layer finds it. A .reflex above the repo (/tmp, a shared home) is never read.
//
//   reflex trust [dir] | reflex trust --revoke [dir] | reflex policy [dir] | reflex policy init [dir]
import {createHash} from "node:crypto";
import {closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, writeFileSync, writeSync} from "node:fs";
import {homedir} from "node:os";
import {dirname, isAbsolute, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {broad, compilePattern, patternError} from "./fastlane.mjs";

export const TRUST_FILE = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "reflex/trusted.json");
const MAX_FILE = 64 * 1024, MAX_PATTERNS = 64;
// Team patterns run over commands of at most this size; a larger one asks (see teamRules).
export const TEAM_BYTES = 8 * 1024;

/** The repository root for cwd: the nearest directory holding .git, or null outside a repo. */
export function repoRoot(cwd) {
  if (typeof cwd !== "string" || !isAbsolute(cwd)) return null;
  for (let d = resolve(cwd); ; d = dirname(d)) {
    if (existsSync(join(d, ".git"))) return d;
    if (dirname(d) === d) return null;
  }
}

// A pattern someone else wrote runs in every teammate's hook, so it must finish in time on a command
// an agent chose: no backreference or lookbehind, no repeated group holding a quantifier or an
// alternation, and at most one unbounded repetition (two nested scans of 8 KB take minutes).
// ponytail: a syntactic check, not a proof of linear time; with the 8 KB cap one scan is ~25 ms.
const unboundedAt = (p, i) => p[i] === "*" || p[i] === "+" || (p[i] === "{" && /^\{\d*,\}/.test(p.slice(i)));
export function regexError(p) {
  if (typeof p !== "string" || !p || p.length > 500) return "must be a string of 1 to 500 characters";
  try { new RegExp(p, "i"); } catch (e) { return `does not compile (${e.message})`; }
  if (/\\[1-9]|\\k<|\(\?<[=!]/.test(p)) return "must not use backreferences or lookbehind";
  let cls = false, unbounded = 0;
  const groups = [];
  for (let i = 0; i < p.length; i++) {
    const ch = p[i];
    if (ch === "\\") { i++; continue; }
    if (cls) { if (ch === "]") cls = false; continue; }
    if (ch === "[") cls = true;
    else if (ch === "(") groups.push({q: false});
    else if (ch === "|") { if (groups.length) groups.at(-1).q = true; }
    else if (ch === ")") {
      const g = groups.pop() ?? {q: false};
      if (g.q && (unboundedAt(p, i + 1) || p[i + 1] === "{")) return "must not repeat a group that holds a quantifier or an alternation";
      if (g.q && groups.length) groups.at(-1).q = true;
    } else if (unboundedAt(p, i) || ch === "{") {
      if (unboundedAt(p, i)) unbounded++;
      if (groups.length) groups.at(-1).q = true;
    }
  }
  return unbounded > 1 ? "must use at most one unbounded repetition (*, + or {n,}); split it into several `all` patterns" : null;
}

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

const KEYS = new Set(["version", "note", "rules", "always_human", "prod", "mode", "fastlane"]);
/** The file, validated part by part: every valid stricter entry is kept, every problem is an error. */
export function parseTeam(text) {
  const out = {rules: [], always_human: [], mode: null, fastlane: [], errors: []};
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
    else if (spend(r.all.length, `rules ${i + 1}`)) out.rules.push({...Object.fromEntries(Object.entries(r).filter(([k]) => k !== "note")), id: `team:${r.id}`, rule: `${r.rule} (team policy)`});
  }
  for (const [i, r] of list("always_human", 50).entries()) {
    const why = ruleError(r, true);
    if (why) out.errors.push(`always_human ${i + 1}: ${why}`);
    else if (spend(r.all.length, `always_human ${i + 1}`)) out.always_human.push({id: `team:${r.id}`, rule: `${r.rule} (team policy)`, all: r.all, ...(r.context !== undefined && {context: r.context})});
  }
  // A production marker: a command (or its cwd, profile, kube context, workspace, branch) that
  // matches is production. One that is not read-only asks, and a rule's ask always goes to a human.
  for (const [i, m] of list("prod", 20).entries()) {
    const why = regexError(m);
    if (why) out.errors.push(`prod ${i + 1}: pattern ${why}`);
    else if (spend(1, `prod ${i + 1}`)) out.rules.push({id: "team:prod", outcome: "ask", shell: true, rule: "production, by a marker in the team policy", all: [m]});
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

const parsed = new Map();
/** The team policy that applies in cwd, or null when its repo has none. Never throws. */
export function teamPolicy(cwd) {
  try {
    const root = repoRoot(cwd);
    if (!root) return null;
    const file = join(root, ".reflex/policy.json"), none = {rules: [], always_human: [], mode: null, fastlane: []};
    let text;
    try {
      // A regular file in a real directory: a symlink could point anywhere, a FIFO would hang the hook.
      const dir = lstatSync(join(root, ".reflex"));
      if (!dir.isDirectory()) throw Object.assign(new Error(".reflex is not a directory"), {code: dir.isSymbolicLink() ? "LINK" : "NOTDIR"});
      const st = lstatSync(file);
      if (!st.isFile()) throw new Error("not a regular file");
      if (st.size > MAX_FILE) throw new Error(`larger than ${MAX_FILE / 1024} KB`);
      text = readFileSync(file, "utf8");
    } catch (e) {
      if (e.code === "ENOENT" || e.code === "NOTDIR") return null;
      return {root, file, sha256: null, trust: "untrusted", active_fastlane: false, errors: [e.message], ...none};
    }
    const hash = sha256(text);
    let p = parsed.get(hash);
    if (!p) parsed.set(hash, p = parseTeam(text));
    const saved = readTrust().repos[realRoot(root)]?.sha256;
    const trust = saved === hash ? "trusted" : saved ? "changed" : "untrusted";
    const active = trust === "trusted" && !p.errors.length && !broad(root);
    return {root, file, sha256: hash, trust, active_fastlane: active, errors: p.errors, rules: p.rules, always_human: p.always_human, mode: p.mode,
            fastlane: active ? p.fastlane.map(pattern => ({pattern, cwd: root, re: compilePattern(pattern), team: true})) : [], fastlane_count: p.fastlane.length};
  } catch (e) {
    return {root: null, file: null, sha256: null, trust: "untrusted", active_fastlane: false, errors: [`team policy: ${e.message}`], rules: [], always_human: [], mode: null, fastlane: []};
  }
}

// Merged into what the gate loads. A command over TEAM_BYTES gets one ask in place of the team's
// patterns, so a large command can neither stall the hook nor slip past them.
const sizeRule = {id: "team:size", outcome: "ask", before_read_only: true, rule: `command too large for the team policy's rules (over ${TEAM_BYTES / 1024} KB)`, all: ["[\\s\\S]"]};
/** rules.json with the team's rules: its denies first (a deny wins over a bundled ask), its asks last (never in front of a bundled deny). */
export function teamRules(rules, cwd, command = "") {
  const t = teamPolicy(cwd);
  if (!t?.rules.length) return rules;
  const extra = command.length > TEAM_BYTES ? [sizeRule] : t.rules;
  return {...rules, version: `${rules.version}+team-${t.sha256.slice(0, 8)}`,
          rules: [...extra.filter(r => r.outcome === "deny"), ...rules.rules, ...extra.filter(r => r.outcome !== "deny")]};
}
/** escalation.json with the team's always-human patterns added. */
export function teamEscalation(esc, cwd, command = "") {
  const t = teamPolicy(cwd);
  if (!t?.always_human.length) return esc;
  return {...esc, always_human: {...esc.always_human, rules: [...esc.always_human.rules, ...(command.length > TEAM_BYTES ? [sizeRule] : t.always_human)]}};
}
/** The mode for a call in cwd: the team's floor raises shadow to enforce; off stays off. */
export const teamMode = (mode, cwd) => mode === "shadow" && teamPolicy(cwd)?.mode === "enforce" ? "enforce" : mode;
/** Fast-lane entries from a trusted, valid team policy (userFastPass shape), else none. */
export const teamFastLane = cwd => teamPolicy(cwd)?.fastlane ?? [];

/** Record trust in root's current policy file. The CLI confirms on a terminal first. */
export function trustRepo(root, hash, file = TRUST_FILE) {
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
    ...t.errors.map(e => `invalid: ${e}`)];
}
// A human's answer on the terminal. An agent's shell has no terminal, and the gate asks before an
// agent runs `reflex trust` at all; an agent session's environment is refused outright.
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
    return argv.includes("--json") ? console.log(JSON.stringify({...t, fastlane: undefined, rules: t.rules.map(r => r.id)}, null, 1)) : describe(t).forEach(l => say(l));
  }
  if (cmd === "trust" && rest.includes("--revoke")) { trustRepo(root, null); return say(`${root}: trust removed; its team fast lane is off`); }
  if (cmd !== "trust") die("usage: reflex trust [dir] | reflex trust --revoke [dir] | reflex policy [dir] [--json] | reflex policy init [dir]");
  if (!t) die(`no team policy in ${root}`);
  if (t.errors.length || !t.sha256) { describe(t).forEach(l => console.error(l)); die("fix the team policy before trusting it"); }
  if (broad(root)) die(`${root} is your home or /; a team fast lane there would cover every project`);
  describe(t).forEach(l => say(l));
  for (const p of parseTeam(readFileSync(t.file, "utf8")).fastlane) say(`  fast lane: ${p}`);
  if (!confirm(`Trust this file for ${root}? Its fast lane then passes these commands without a prompt. Type "trust" to confirm: `)) die("not trusted");
  trustRepo(root, t.sha256);
  say(`trusted ${t.sha256.slice(0, 12)} for ${root}. Any change to the file drops the trust until you run reflex trust again.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
