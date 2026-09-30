// Read-only detection (gate.mjs): readOnlyLegacy, readOnlySimple and their tables, and the command
// cut into pipelines, each marked inert or not.
import {posix} from "node:path";
import {ENV, USER_CONFIG} from "./config.mjs";
import {shellWords, maskQuotes} from "./shell.mjs";
import {SENSITIVE} from "./scripts.mjs";

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
export function roughPipelines(c) {
  const m = maskQuotes(c, "_"), cuts = [...m.matchAll(/&&|\|\||[;&|\n]/g)], out = [];
  let last = 0;
  for (const k of [...cuts, {index: c.length, 0: ""}]) {
    const text = c.slice(last, k.index).trim();
    if (text) out.push({text, targets: [], core: text, inert: false});
    last = k.index + k[0].length;
  }
  return out;
}
// Only inert pipelines writing notes (Markdown, text, logs, CSV) or nothing: there is no shell
// command in it for a "shell" rule to find, whatever its quoted text says (echo '… rm -rf / …' >> MEMORY.md).
const NOTES = /^(\/dev\/(null|stdout|stderr)|[^\s;&|<>]*\.(md|markdown|txt|rst|adoc|log|csv|tsv))$/i;
export const onlyNotes = ps => !!ps?.length && ps.every(p => p.inert && p.targets.every(t => NOTES.test(t)));
