// The user fast lane: ~/.config/reflex/fastlane.json, command shapes you run all the time that the
// bundled fast lane does not know (`make lint`, `pnpm typecheck`), each scoped to one project.
// `reflex suggest --write` fills it from your own sessions; you can also edit it by hand.
//
//   {"version": 1, "entries": [{"pattern": "^make lint$", "cwd": "/Users/me/work/api", "note": "..."}]}
//
// It can only turn an engine decision into a pass. It runs after the rules, the tamper check and the
// script rules (precheck), so it never overrides a deny, a secret read or a tamper ask, and a command
// in the always-human class (escalation.json, every rule) or with a word from DENY is never passed.
// A file that does not validate is ignored as a whole (`reflex doctor` says why): a typo never widens.
import {readFileSync} from "node:fs";
import {homedir} from "node:os";
import {dirname, isAbsolute, join, resolve} from "node:path";
import {checkRules, load, localScripts, maskQuotes, readOnly, stripDataHeredocs} from "./gate.mjs";

export const FASTLANE_FILE = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "reflex/fastlane.json");

// Words that are never fast lane, whatever a pattern says: deletes, moves and overwrites, pushes and
// deploys, installs and publishes, privilege and permission changes, network tools and cloud CLIs,
// code fetched and run, secrets and production. Checked on every segment a user pattern passes and on
// every local script (package.json script, make recipe, shell file) the command runs.
export const DENY = new RegExp([
  String.raw`\b(rm|rmdir|unlink|mv|cp|dd|shred|truncate|ln|rsync|scp|sftp|ftp|install|uninstall|reinstall)\b`,
  String.raw`\b(push|pull|fetch|clone|apply|delete|destroy|drop|prune|purge|reset|clean|rebase|merge|revert|restore|checkout|switch|tag|release|publish|deploy|upload|login|logout|import|taint|terminate|kill|pkill|killall|stop|restart|shutdown|reboot|upgrade|update|link|exec|eval|source|migrate|seed|rollback)\b`,
  String.raw`\b(sudo|su|doas|chmod|chown|chgrp|chflags|xattr|launchctl|systemctl|crontab|defaults|visudo|mount|umount|diskutil)\b`,
  String.raw`\b(curl|wget|nc|ncat|netcat|telnet|ssh|socat|httpie?|https?:\/\/)`,
  String.raw`\b(gh|git|aws|gcloud|gsutil|az|kubectl|helm|eksctl|doctl|heroku|vercel|netlify|flyctl|firebase|stripe|vault|op|security|docker(?!\s+compose\s+(ps|logs|images|top|ls|version)\b)|podman|terraform|tofu|pulumi|ansible\S*)\b`,
  String.raw`\b(npx|bunx|pnpx|uvx|pipx|dlx|pip3?|gem|brew|apt|apt-get|yum|dnf|cargo\s+install|go\s+(install|get|run|generate))\b`,
  String.raw`(\.env\b|\.pem\b|\.p12\b|\.key\b|id_(rsa|ed25519|ecdsa)|\.ssh\b|\.aws\b|\.kube\b|\.gnupg\b|\.netrc\b|\.npmrc\b|\.pypirc\b|credential|secret|passw|token|api[-_]?key|keychain)`,
  String.raw`(?<!(non|pre)[-_])\b(prod|production|prd|live)\b`,
].join("|"), "i");

// The file, validated. {entries: [{pattern, cwd, re}], error}. Missing: no entries, no error.
export function parseFastLane(text) {
  let doc;
  try { doc = JSON.parse(text); } catch (e) { return {entries: [], error: `not JSON (${e.message})`}; }
  if (!doc || typeof doc !== "object" || doc.version !== 1 || !Array.isArray(doc.entries)) return {entries: [], error: 'needs {"version": 1, "entries": [...]}'};
  if (doc.entries.length > 500) return {entries: [], error: "more than 500 entries"};
  const entries = [];
  for (const [i, e] of doc.entries.entries()) {
    const why = entryError(e);
    if (why) return {entries: [], error: `entry ${i + 1}: ${why}`};
    entries.push({pattern: e.pattern, cwd: e.cwd, re: compilePattern(e.pattern)});
  }
  return {entries, error: null};
}

export const broad = cwd => [homedir(), "/", dirname(homedir())].includes(cwd);
function entryError(e) {
  if (!e || typeof e !== "object") return "not an object";
  if (typeof e.cwd !== "string" || !isAbsolute(e.cwd) || resolve(e.cwd) !== e.cwd) return "cwd must be an absolute, normalised path";
  if (broad(e.cwd)) return "cwd must be a project directory, not / or your home";
  return patternError(e.pattern);
}

// An anchored pattern with no wildcard: no `.` outside a character class, no negated class, no \S, \W
// or \D, no space in a class, no repeated group, no lookaround or backreference. `[\w./-]+` is as open
// as it gets, so a pattern never takes a quote, a `$`, a `;` or an extra word it did not spell out.
export function patternError(p) {
  if (typeof p !== "string" || !p.startsWith("^") || !p.endsWith("$") || p.endsWith("\\$") || p.length > 400) return "pattern must be a string of at most 400 characters, from ^ to $";
  let cls = false;
  const groups = [];
  for (let i = 1; i < p.length - 1; i++) {
    const ch = p[i];
    if (ch === "\\") {
      if (/[SWDbBk1-9]/.test(p[i + 1] ?? "") || (cls && p[i + 1] === "s")) return `pattern must not use \\${p[i + 1]}${cls ? " in a class" : ""}`;
      i++;
    } else if (cls) { if (ch === "]") cls = false; else if (/\s/.test(ch)) return "pattern must not put a space in a class"; }
    else if (ch === "[") { if (p[i + 1] === "^") return "pattern must not use a negated class [^...]"; cls = true; }
    else if (ch === ".") return "pattern must not use . (any character); escape it as \\.";
    else if (ch === "$" || ch === "^") return "pattern must not use ^ or $ inside";
    else if (ch === "(") {
      if (p[i + 1] === "?" && p[i + 2] !== ":") return "pattern must not use lookarounds or named groups";
      groups.push(i);
    } else if (ch === ")") {
      const start = groups.pop() ?? 0;
      if (/[*+?{]/.test(p[i + 1] ?? "") && /\\s|\s/.test(p.slice(start, i))) return "pattern must not repeat a group that spans words";
    }
  }
  try { compilePattern(p); } catch (e) { return `pattern does not compile (${e.message})`; }
  return null;
}
// Anchored as a whole: `^a$|b` is ^(?:a$|b)$, which cannot match "xb".
export const compilePattern = p => new RegExp(`^(?:${p.slice(1, -1)})$`);

let loaded;
export function loadFastLane(file = FASTLANE_FILE) {
  if (file === FASTLANE_FILE && loaded) return loaded;
  let text;
  try { text = readFileSync(file, "utf8"); } catch (e) { return e.code === "ENOENT" ? {entries: [], error: null} : {entries: [], error: e.message}; }
  const r = parseFastLane(text);
  if (file === FASTLANE_FILE) loaded = r;
  return r;
}

const inside = (cwd, root) => cwd === root || cwd.startsWith(root + "/");
/** True when the user fast lane passes the command: every segment read-only, bundled fast lane or a
 *  user pattern for this directory, no DENY word, no `cd`, every local script it runs read in full and
 *  free of DENY words, and nothing in the always-human class. precheck calls it last, after the rules. */
export function userFastPass(command, cwd, env = {}, entries = loadFastLane().entries) {
  if (!entries.length || !cwd || !isAbsolute(cwd)) return false;
  cwd = resolve(cwd);
  const mine = entries.filter(e => inside(cwd, e.cwd));
  if (!mine.length) return false;
  // `cd` moves the command out of the directory its scope names.
  if (/(^|[\s;&|(])(cd|pushd|popd)(\s|$)/.test(maskQuotes(command, "_"))) return false;
  const rules = load("rules.json"), bundled = rules.pass.map(p => new RegExp(p, "i"));
  let used = false;
  const user = {test: seg => { const hit = !DENY.test(seg) && mine.some(e => e.re.test(seg)); used ||= hit; return hit; }};
  if (!readOnly(command, [...bundled, user]) || !used) return false;
  if (localScripts(command, cwd).some(s => s.unseen || !s.body || DENY.test(s.body))) return false;
  const bare = stripDataHeredocs(command), haystack = [bare, `cwd=${cwd}`, ...Object.entries(env).map(([k, v]) => `${k}=${v}`)].join(" ");
  return !checkRules(haystack, {rules: load("escalation.json").always_human.rules}, bare);
}
