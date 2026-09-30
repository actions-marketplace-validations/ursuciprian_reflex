#!/usr/bin/env node
// The keyless workspace allowlist: a handful of exact command shapes that pass without an engine
// because their whole effect is inside the git working tree and git can undo it. Allowlist only:
// anything that is not one of these shapes, word for word, returns null and goes to the engine or
// the ladder unchanged. It never detects what is dangerous; it recognises what is known to be safe.
//
//   mkdir -p <path>...                    new directories
//   touch <path>...                       new empty files, or a timestamp
//   sed -i -e '<s>' <file>                GNU sed (and sed -i '<s>' <file>)
//   sed -i '' -e '<s>' <file>             BSD sed, as on macOS (and sed -i '' '<s>' <file>)
//   cp <file> <new path>                  a tracked file copied or moved to a path that does not
//   mv <file> <new path>                  exist yet
//
// One simple command: no operator, pipe, redirect, expansion, glob, quote other than one whole
// single-quoted sed script, and no flag but the ones above. <s> is one s/regex/replacement/flags
// with / as the delimiter and flags from g, p, i, I, m, M and digits (never w or e). Every path is a
// plain relative path that stays in the tree (no leading /, no ~, no segment starting with a dot, so
// no .., .git, .reflex, .github or .husky), has no symlink on the way and no nested repository, and
// is not a protected path (protected.json, the Reflex checkout, its logs and settings). <file> is a
// regular file git tracks with no skip-worktree or assume-unchanged bit, so the checkpoint the gate
// takes first (gate.mjs decide) records it and `reflex checkpoints restore` brings it back. The
// sed forms follow the sed on PATH: GNU sed reads -i '' as a script, BSD sed reads -i -e as a
// backup suffix, so each flavour gets only the forms that mean the same edit there.
// ponytail: the flavour is the hook's PATH sed; an agent shell with a different sed first on PATH
// runs another sed. Detect per shell if that ever matters.
import {lstatSync, realpathSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {join, relative, resolve} from "node:path";
import {isMain} from "./failsafe.mjs";

const PLAIN = /^[A-Za-z0-9_@%+,=:/.-]+$/;
const SCRIPT = /^s\/(?:[^/\\\n]|\\[^\n])*\/(?:[^/\\\n]|\\[^\n])*\/[gpiImM0-9]*$/;
const MAX_WORDS = 24, MAX_LENGTH = 1000;

// The words of one simple command: plain words and whole '...' strings, separated by spaces or
// tabs. Anything else (a double quote, $, `, ;, &, |, <, >, a glob, a backslash, a newline, a word
// glued to a quote) is not a simple command here: null.
export function words(command) {
  if (typeof command !== "string" || command.length > MAX_LENGTH) return null;
  const out = [], re = /[ \t]*(?:'([^'\n]*)'|([A-Za-z0-9_@%+,=:/.-]+))(?=[ \t]|$)/y;
  let i = 0;
  const s = command.trim();
  while (i < s.length) {
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m || (out.length && !/[ \t]/.test(s[i]))) return null;
    out.push(m[1] !== undefined ? {text: m[1], quoted: true} : {text: m[2], quoted: false});
    i = re.lastIndex;
    if (out.length > MAX_WORDS) return null;
  }
  return out.length ? out : null;
}

const git = (cwd, args) => spawnSync("git", ["-C", cwd, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "--literal-pathspecs", ...args],
  {encoding: "utf8", timeout: 3000, env: {...process.env, GIT_OPTIONAL_LOCKS: "0"}});
let flavour;
export const sedFlavour = () => flavour ??= /^sed \(GNU sed\)/m.test(spawnSync("sed", ["--version"], {encoding: "utf8", timeout: 2000}).stdout ?? "") ? "gnu" : "bsd";
const lstat = p => { try { return lstatSync(p); } catch { return null; } };

// A path word inside the tree: {abs, stat} or null. Every existing step from the root is checked:
// no symlink, and no directory below the root holding a .git (another repository).
function inTree(word, ctx, {dir = false} = {}) {
  if (word.quoted || !PLAIN.test(word.text) || word.text.startsWith("-") || word.text.startsWith("/")) return null;
  if (!dir && word.text.endsWith("/")) return null;
  const segs = word.text.split("/").filter(s => s && s !== ".");
  if (!segs.length) return null;
  const rel = [...ctx.base, ...segs];
  if (rel.some(s => s.startsWith("."))) return null;
  let cur = ctx.root, stat = null;
  for (const [i, seg] of rel.entries()) {
    cur = join(cur, seg);
    stat = lstat(cur);
    if (!stat) { if (i < rel.length - 1) stat = undefined; break; }
    if (stat.isSymbolicLink()) return null;
    if (i < rel.length - 1 && (!stat.isDirectory() || lstat(join(cur, ".git")))) return null;
  }
  const abs = join(ctx.root, ...rel);
  if (ctx.protectedWrite?.([abs], ctx.cwd)) return null;
  return {abs, rel: rel.join("/"), stat: stat ?? null, parent: stat !== undefined};
}
// A regular file git tracks as a plain cached entry (ls-files -v tag H): not skip-worktree (S),
// not assume-unchanged (h), not unmerged (M), so a checkpoint records its current content.
function tracked(p, ctx) {
  if (!p?.stat?.isFile()) return false;
  const r = git(ctx.root, ["ls-files", "-v", "--error-unmatch", "--", p.rel]);
  const lines = r.status === 0 ? r.stdout.split("\n").filter(Boolean) : [];
  return lines.length === 1 && lines[0] === `H ${p.rel}`;
}

/** {outcome: "allow", source: "workspace", id, rule} for one of the shapes above, else null. */
export function workspacePass(command, cwd, {protectedWrite} = {}) {
  const w = words(command);
  if (!w || w[0].quoted || !cwd) return null;
  const prog = w[0].text, args = w.slice(1);
  if (!["mkdir", "touch", "sed", "cp", "mv"].includes(prog) || !args.length) return null;
  let real;
  try { real = realpathSync(cwd); } catch { return null; }
  const top = git(real, ["rev-parse", "--show-toplevel"]);
  if (top.status !== 0) return null;
  let root;
  try { root = realpathSync(top.stdout.trim()); } catch { return null; }
  const base = relative(root, real);
  if (base.startsWith("..") || resolve(root, base) !== real) return null;
  const ctx = {root, cwd, base: base ? base.split("/") : [], protectedWrite};
  const pass = rule => ({outcome: "allow", source: "workspace", id: `workspace-${prog}`, rule: `${rule} (workspace allowlist; checkpoint first)`});
  const flag = (x, f) => x && !x.quoted && x.text === f;
  if (prog === "mkdir") {
    if (!flag(args[0], "-p") || args.length < 2) return null;
    return args.slice(1).every(a => { const p = inTree(a, ctx, {dir: true}); return p && (!p.stat || p.stat.isDirectory()); })
      ? pass("new directories in the working tree") : null;
  }
  if (prog === "touch")
    return args.every(a => { const p = inTree(a, ctx); return p && (!p.stat || p.stat.isFile() || p.stat.isDirectory()); })
      ? pass("new or touched files in the working tree") : null;
  if (prog === "sed") {
    if (!flag(args[0], "-i")) return null;
    const gnu = sedFlavour() === "gnu", rest = args.slice(1);
    // BSD: -i takes its backup suffix as the next word, '' for none
    if (!gnu && !(rest[0]?.quoted && rest[0].text === "")) return null;
    const form = gnu ? rest : rest.slice(1);
    const [script, file, extra] = flag(form[0], "-e") ? form.slice(1) : form;
    if (extra || !script?.quoted || !SCRIPT.test(script.text) || !file) return null;
    return tracked(inTree(file, ctx), ctx) ? pass("an in-place s/// edit of a tracked file") : null;
  }
  // cp and mv: a tracked file to a path that does not exist yet, whose directory does
  if (args.length !== 2) return null;
  const src = inTree(args[0], ctx), dst = inTree(args[1], ctx);
  return tracked(src, ctx) && dst && !dst.stat && dst.parent ? pass(`a tracked file ${prog === "cp" ? "copied" : "moved"} to a new path in the working tree`) : null;
}

