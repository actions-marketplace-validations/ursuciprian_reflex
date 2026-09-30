// The local scripts a command runs (gate.mjs): found, read and cut into lines for the script rules and Jev.
import {statSync, openSync, fstatSync, readSync, closeSync, readdirSync, existsSync} from "node:fs";
import {homedir} from "node:os";
import {join, dirname} from "node:path";
import {redact, readText} from "./config.mjs";
import {stripDataHeredocs, maskQuotes, joinQuotes, plain} from "./shell.mjs";

// ---------------------------------------------------------------------------------------------
// Local scripts. `bash deploy.sh` says nothing about what it does; the script does. A command that
// runs a local file (a shell, python, node or tsx script, a make target, an npm, yarn or pnpm
// script) has that file read: the rules marked "script" scan up to 256 KB of it, Jev sees the first
// 16 KB, redacted. What a shell script, make recipe or package script runs in turn is followed
// one more level.
// ponytail: a pattern per launcher, not a shell parser, and two levels deep. A command that names
// local code that could not be read is marked unseen, so it can never be allowed.
export const SCRIPT_BYTES = 16 * 1024, RULE_BYTES = 256 * 1024;
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
export const MAX_SCRIPTS = 8, LONG_LINE = 2000, SCAN_MS = 1500;
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
export const SENSITIVE = /(^|\/)(\.env(\.[\w.-]+)?|\.netrc|\.npmrc|\.pypirc|credentials|id_[a-z0-9]+)$|\/\.(ssh|aws|gnupg|kube|docker)\/|\.(pem|key|p12|pfx)$/;
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
export function scriptLines(body) {
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
