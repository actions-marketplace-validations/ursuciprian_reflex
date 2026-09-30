// The gate's shell reading (gate.mjs): quote masking, the words of a command, data heredocs, and the
// other spellings the rules read (quoted parts joined, git's and aws's global options, braces, escapes).
import {homedir} from "node:os";

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

// A quoted part of a word: quotes with no space, operator, escape or expansion inside, next to other
// word text, not escaped and not next to another quote. The text with those quotes dropped, or null
// when there are none or dropping them leaves the quotes unbalanced (then it is not what the shell reads).
const QUOTED_PART = /(?<=[^\s;&|<>()'"\\])(['"])([^'"\s;&|<>()$`\\]*)\1|(?<![\\'"])(['"])([^'"\s;&|<>()$`\\]*)\3(?=[^\s;&|<>()'"])/g;
export const joinQuotes = s => { const j = s.replace(QUOTED_PART, "$2$4"); return j !== s && (maskQuotes(j, "_") !== j || !/['"]/.test(j)) ? j : null; };
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
export const plain = s => awsPlain(gitPlain(s));
export const ruleSpelling = s => {
  const v = plain((joinQuotes(s) ?? s).replace(/(^|[\s;&|(`]|\$\()\/(usr\/)?bin\/(?=[\w.-]+(\s|$))/g, "$1").replace(TIMEOUT_OPTS, "timeout"));
  return v !== s ? v : null;
};
// Brace expansion as the shell does it, on a word's raw text: lists ({a,b}, nested), sequences
// ({1..3}, {a..c}, {01..9..2}) and any number per word. Quoted or escaped braces and ${…} are text.
// Each result keeps its quotes, so the rules read it with the other spellings. null: over BRACE_WORDS.
export const BRACE_WORDS = 256;
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
export const TOO_MANY = Symbol("braces");
export const wordSpelling = s => {
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
