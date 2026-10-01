// Tamper detection (gate.mjs): what a command changes of Reflex itself, the directories its cd steps
// point at, a nested checkout, and the plugin's own commands.
import {realpathSync, existsSync, lstatSync, readdirSync} from "node:fs";
import {homedir, tmpdir} from "node:os";
import {dirname, posix, resolve, join, basename} from "node:path";
import {HERE, CONFIG, USER_CONFIG_FILE} from "./config.mjs";
import {maskQuotes, shellWords} from "./shell.mjs";
import {pipelines, roughPipelines} from "./readonly.mjs";
import {PRECHECK_MS} from "./rules.mjs";

// Directories whose relative paths the tamper rule could care about: an agent's settings or hooks
// directory, a parent of one, a directory named reflex, the checkout, the Reflex data or config
// directory (or a parent), or one only a variable names. Elsewhere an argument such as
// ursuciprian/reflex (gh -R) is not a path and is left unresolved.
const CD_WATCH = /(^|\/)(\.claude(\/(settings|hooks)\b.*)?|\.codex(\/(hooks|rules|config)\b.*)?|\.hermes(\/.*)?|\.config(\/(reflex|opencode)\b.*)?|\.local(\/state(\/.*)?)?|\.(pi|omp)(\/agent(\/.*)?)?|opencode(\/.*)?|\.?reflex(\/.*)?)\/?$|\$|^~\/?$/i;
const ownDir = d => [CONFIG.data, dirname(USER_CONFIG_FILE)].some(p => (d + "/").startsWith(p + "/") || p.startsWith(d.replace(/\/$/, "") + "/"));
const cdWatched = d => CD_WATCH.test(d) || [HERE, CONFIG.data, dirname(USER_CONFIG_FILE)].some(p => (d + "/").startsWith(p + "/") || p.startsWith(d.replace(/\/$/, "") + "/"));
// A cd, pushd or popd the directory tracking below reads writes nothing itself: its effect is the
// resolved paths, each set on a line of its own so a rule cannot match across it and the command
// text. One it cannot read is kept whole, and then every cd in the command is (the tracking is not
// trusted). A relative directory that is not watched as written is also tried against `cwd`
// (`cd setup/tool-gate` in the checkout), and before any cd the directory is `cwd` itself (an agent
// started in ~/.local/state writing reflex/trace.jsonl). `resolvedOnly`: only those lines.
// A program that unpacks an archive into the directory it runs in (tar x, not tar c).
const EXTRACT = /(^|[\s|(])((bsd|g)?tar\s([^|;&]*\s)?(-?[a-wyzA-Z]*x[a-zA-Z]*|--extract|--get)(\s|$)|(unzip|unrar|unar)\s|7z[az]?\s+[xe]\s|cpio\s[^|;&]*-[a-zA-Z]*i|pax\s[^|;&]*-[a-zA-Z]*r)/;
const writesView = (ps, resolvedOnly = false, cwd = null) => {
  const dirs = cdDirs(ps);
  return ps.map((p, i) => {
    const whole = !p.inert || /^[\s({!]*(cd|pushd|popd|for|select|case|while|until|if|export|local|declare|typeset|readonly|read|touch|mkdir)\b|^[\s({!]*\w+=/.test(p.core);
    const view = resolvedOnly ? "" : (dirs[i] === CD_STEP && !dirs.unread) || !whole ? p.targets.map(t => `> ${t}`).join(" ") : p.text;
    const d = typeof dirs[i] === "string" ? dirs[i] : null;
    const abs = !cwd ? null : d === null ? (dirs[i] === null ? cwd : null) : !/^[/~$]/.test(d) ? posix.join(cwd, d) : null;
    // Inside the checkout its relative paths are judged as written (setup/…, gate.mjs), as without a cd.
    const inside = cwd && (cwd + "/").startsWith(HERE + "/");
    // A relative cd into the Reflex data or config directory (cd reflex from ~/.local/state) is resolved.
    const at = abs && !inside && ownDir(abs) ? abs : d && cdWatched(d) ? d : abs && cdWatched(abs) ? (inside ? d : abs) : null;
    if (!at) return view;
    // the arguments of each command in the pipeline (not its name, not a URL) and the redirect targets
    const words = whole ? [...p.text.split("|").flatMap(s => s.replace(/[<>&;(){}]/g, " ").trim().split(/\s+/).slice(1)), ...p.targets]
      .flatMap(w => [w, w.replace(/^[^=]*=/, "")]).filter(w => !w.includes("://")) : p.targets;
    // a command run there that names no file (make, ./install.sh, vim) is marked by the directory itself;
    // one that names it (cp -r x/. ., rsync x/ ./) or unpacks an archive into it names it without the slash
    const into = whole && EXTRACT.test(p.core) ? ` > ${at}` : "";
    return `${view}\n${whole ? `> ${at}/ ` : ""}${words.map(w => w.replace(/["'\\]/g, "")).filter(w => w && !/^[-/~$]/.test(w))
      .map(w => `> ${/^\.\/?$/.test(w) ? at : posix.join(at, w)}`).join(" ")}${into}\n`;
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
    const opened = (m.match(/^[\s!{]*(\(\s*)+/)?.[0].match(/\(/g) ?? []).length;
    for (let k = opened; k > 0; k--) scopes.push([dir, old, stack.length]);
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
      else if (arg === "-" || arg === "~-") [dir, old] = [old, dir];
      else if (arg === "~+") old = dir;
      else go(arg ?? "~");
    } else if (/^[\s({!]*(builtin\s+|command\s+)?(cd|pushd|popd)\b/.test(p.core)) unread = true;   // unread: kept whole
    // the parentheses this pipeline opened count too: (cd /tmp) opens and closes its own scope
    const closes = count(/\)/g) - (count(/\(/g) - opened);
    for (let k = 0; k < closes && scopes.length; k++) { const s = scopes.pop(); [dir, old] = s; stack.length = Math.min(stack.length, s[2]); }
    return here;
  });
  out.unread = unread;
  return out;
}
// What a command changes, as the tamper check reads it (writesView), quotes and backslashes dropped.
export const writesOf = (command, cwd, ps = pipelines(command)) =>
  (ps ? writesView(ps, false, cwd) : `${command} ; ${writesView(roughPipelines(command), true, cwd)}`).replace(/["'\\]/g, "");
// The checkout, the Reflex data directory or its config directory, named in the text. ~ and $HOME
// are the home directory: ~/src/x/gate.mjs names the checkout wherever it was cloned.
const homeOf = text => text.replace(/(^|[\s=:>])(~|\$HOME|\$\{HOME\})(?=\/|\s|$)/g, (m, p) => p + homedir());
export const namesOwn = text => {
  const home = homeOf(text);
  // the directory itself or a path in it, not a sibling that starts with its name (reflex-old)
  const at = (s, p) => { for (let i = s.indexOf(p); i > -1; i = s.indexOf(p, i + 1)) if (!/[\w.-]/.test(s[i + p.length] ?? "")) return true; return false; };
  return [HERE, CONFIG.data, dirname(USER_CONFIG_FILE)].some(p => at(text, p) || at(home, p));
};
// The same directories as path words, spelled any way the shell or the file system accepts: . and
// .. and // in them, another case (macOS), a symlinked spelling (/tmp for /private/tmp), a glob
// (refle?, [r]eflex), a climb from `cwd` (../state/reflex). Also the parent of the data or config
// directory named as a word (tar -C ~/.local/state, cp -r x/. . or tar -xf run there), unless that
// parent is a directory everything happens in (home, /, the temp directory). ponytail: an unknown
// program run in the parent that writes reflex/ without naming it is not caught.
const real = p => { try { return realpathSync(p); } catch { return p; } };
const BROAD = () => new Set([homedir(), "/", tmpdir(), real(tmpdir()), "/tmp", "/private/tmp"].map(p => p.replace(/\/$/, "").toLowerCase() || "/"));
// A glob the shell would take literally (an unclosed `[`) is not a valid pattern: it counts as a
// match, so the command is treated as touching Reflex (fail closed) instead of crashing the gate.
const globPart = g => { try { return new RegExp(`^${g.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".").replace(/\[!/g, "[^")}$`, "i"); } catch { return {test: () => true}; } };
function pathsOwn(writes, cwd) {
  const own = [...new Set([HERE, CONFIG.data, dirname(USER_CONFIG_FILE)].flatMap(p => [p, real(p)]).map(p => p.toLowerCase()))];
  const broad = BROAD(), parents = [CONFIG.data, dirname(USER_CONFIG_FILE)].flatMap(p => [dirname(p), dirname(real(p))])
    .map(p => p.toLowerCase()).filter(p => !broad.has(p));
  for (let t of homeOf(writes).split(/[\s=:>,;&|()<]+/)) {
    if (cwd && /^\.\.(\/|$)/.test(t)) t = posix.join(cwd, t);
    if (!t.startsWith("/")) continue;
    // the parent as a word of its own; with a trailing slash it is the mark of a command run there
    const named = !t.endsWith("/");
    t = posix.normalize(t).replace(/(.)\/$/, "$1").toLowerCase();
    if (named && parents.includes(t)) return true;
    for (const p of own) {
      if (t === p || t.startsWith(p + "/")) return true;
      if (!/[*?[]/.test(t)) continue;
      const tc = t.split("/"), pc = p.split("/");
      if (tc.length >= pc.length && pc.every((c, k) => c === tc[k] || (/[*?[]/.test(tc[k]) && globPart(tc[k]).test(c)))) return true;
    }
  }
  return false;
}
// A Reflex file written under a variable the command does not set ($D/trace.jsonl, ${D}feedback.jsonl,
// cd "$X" && tee q-1.json): where it points is unknown, so it counts as the data or config directory.
// $HOME, $PWD and the temp directory variables are known. ponytail: by file name; a bare $F or a
// generic name (config.json) under a variable is not caught.
const OWN_UNDER_VAR = /\$[^\s;&|<>]*?(?<=[/}])(reflex(\/|\s|$)|(trace|feedback|judge|guard|context|instructions|subgoals)(\.\d+)?\.jsonl\b|q-[\w-]+\.json\b|(queue|taint|runaway)\/[\w-]+\.json\b|(envelopes|cache|judge-cache|judge-budget|fastlane)\.json\b|laya\.token\b)/;
const knownVars = (s, cwd) => s.replace(/\$HOME\b|\$\{HOME\}/g, homedir()).replace(/\$(TMPDIR|TMP|TEMP)\b|\$\{(TMPDIR|TMP|TEMP)\}/g, tmpdir())
  .replace(/\$PWD\b|\$\{PWD\}/g, cwd ?? "$PWD");
export const touchesOwn = (writes, cwd) => { const w = knownVars(writes, cwd); return namesOwn(w) || pathsOwn(w, cwd) || OWN_UNDER_VAR.test(w); };

// What Reflex runs from its checkout, as the relative paths a command run inside it names. Read
// from the checkout itself, not kept by hand, so a module added later is covered the day it lands:
// every file at the top that is code or config (*.mjs, *.js, *.sh, *.json: install.sh, package.json,
// .mcp.json) and everything under these directories. The gate's selfcheck fails when a file of
// the checkout is neither covered here nor in NOT_RUNTIME (selfcheck.mjs).
export const OWN_DIRS = ["setup", "scripts", "adapters", "hooks", "router", "routing", "plugin", "commands", "skills", ".claude-plugin", ".codex-plugin", ".agents"];
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
let ownFiles = null;
const OWN_FILES = () => ownFiles ??= (() => {
  let top = [];
  try { top = readdirSync(HERE, {withFileTypes: true}).filter(e => e.isFile() && /\.(mjs|js|sh|json)$/.test(e.name)).map(e => e.name); } catch { /* none */ }
  // a file by its name (gate.mjs, ./gate.mjs, x/gate.mjs), a directory by the path under it (setup/…)
  // or, a dot directory, by its name (.claude-plugin); .git/hooks is the checkout's own hooks
  return new RegExp(String.raw`(?<![\w.-])(${top.map(esc).join("|") || "(?!)"})(?![\w-])|(?<![\w.-])(${OWN_DIRS.map(esc).join("|")})\/|` +
    String.raw`(?<![\w.-])(${OWN_DIRS.filter(d => d.startsWith(".")).map(esc).join("|")})(?![\w.-])|\.git\/hooks`);
})();
export const namesOwnFile = writes => OWN_FILES().test(writes);

// A directory with its own .git between the checkout and cwd (cwd included): its root, or null.
export function nestedCheckout(cwd) {
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
export function staysNested(command, cwd, root, run = {deadline: Date.now() + PRECHECK_MS}) {
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
// The reflex CLI forms that change Reflex itself: setup, answering a queue item, an envelope, a
// checkpoint restore, a runaway reset. Read on the command and on every local script it runs.
const unquoted = t => t.replace(/["'\\]/g, "");
export const reflexChanges = t => /\breflex\s+(setup|install|uninstall)\b/.test(unquoted(t)) ||
  /\breflex\b[^\n;&|]*\b(queue|envelope|checkpoints|runaway)\b[^\n;&|]*\b(approve|deny|clear|set|restore|reset)\b/.test(unquoted(t));
// suggest or learn writing fastlane.json, spelled out or with its flags hidden in a variable, "$@",
// xargs, eval or a function, where the text cannot show which flags it gets.
export const fastLaneEdit = t => /\b(suggest|learn)\b[^\n;&|]*\s--(write|forget|prune)\b/.test(unquoted(t)) ||
  (/\b(reflex|replay\.mjs)\b/.test(t) && /\b(suggest|learn)\b/.test(t) && /\$|\bxargs\b|\beval\b|\(\)\s*\{|\bfunction\b/.test(t));
// Granting trust in a team policy (team.mjs), by the CLI or by its file or function.
export const TEAM_TAMPER = /\b(reflex|team\.mjs)\s+(trust|policy\s+init)\b|\bteam\.mjs\b|\btrusted\.json\b|\btrustRepo\b/;
// The Claude Code plugin's commands (commands/*.md) run this copy's own scripts/<name>.sh, which do
// what scripts/reflex does for `reflex check|status|report|replay|suggest claude|queue`: judged as that
// `reflex` command, so they get its fast lane and its tamper rules. Only this directory's scripts, as
// the command's first word; anything after them is judged as usual.
const OWN = new RegExp(String.raw`^("?)${HERE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/scripts/(check|status|report|replay|suggest|queue)\.sh\1(?=[ \t]|$)`);
export const ownCommand = c => {
  const m = OWN.exec(c);
  return m ? `reflex ${m[2] === "suggest" ? "suggest claude" : m[2]}${c.slice(m[0].length)}` : null;
};
