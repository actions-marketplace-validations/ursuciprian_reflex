// The tool gate: MCP tool calls and file writes, judged before they run (gate.mjs decide() calls it).
//
//   MCP tool calls   setup/tool-gate/mcp.json: rules keyed on the server, the tool name and the
//                    arguments. A destructive verb in the tool name asks, and denies when the
//                    arguments or the server point at production. A shell command in an argument
//                    (aws-mcp call_aws, a kubectl tool) goes through the shell rules. Read-like tools
//                    pass; anything else is unknown and goes to the engine.
//   File writes      setup/tool-gate/protected.json: CI workflows, production infrastructure, team
//                    policy, agent settings and hooks, shell startup files. A write there asks.
//
// Pure: what it needs from the gate (the shell precheck, the production test) is passed in.
import {realpathSync} from "node:fs";
import {homedir} from "node:os";
import {basename, dirname, isAbsolute, join, resolve} from "node:path";

// ---------------------------------------------------------------------------------------------
// Which tool call is what. `name` is the agent's tool name, `input` its arguments, `mcp` the adapter's
// word that a tool is not built in (opencode names MCP tools <server>_<tool>, pi's direct tools too).
// {kind: "mcp", name, server, tool, args} | {kind: "write", name, paths} | null (not gated here).
const WRITE_TOOLS = new Set(["write", "edit", "multiedit", "notebookedit", "write_file", "apply_patch", "patch"]);
export function toolOf(name, input, mcp = false) {
  if (typeof name !== "string" || !name) return null;
  const a = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  // Claude Code and Codex: mcp__<server>__<tool>
  const cc = /^mcp__(.+?)__(.+)$/.exec(name);
  if (cc) return {kind: "mcp", name, server: cc[1], tool: cc[2], args: a};
  // pi-mcp-adapter's proxy: mcp({tool, server?, args}); without `tool` it searches, lists or connects
  if (name === "mcp") {
    if (typeof a.tool !== "string" || !a.tool) return null;
    let args = a.args;
    if (typeof args === "string") try { args = JSON.parse(args); } catch { args = {raw: args}; }
    return {kind: "mcp", name, server: typeof a.server === "string" ? a.server : null, tool: a.tool, args: args && typeof args === "object" ? args : {}};
  }
  if (WRITE_TOOLS.has(name.toLowerCase())) {
    const paths = [a.file_path, a.filePath, a.path, a.notebook_path].filter(p => typeof p === "string" && p);
    // a patch as a string, or as the argv Codex can send (["apply_patch", "*** Begin Patch..."])
    for (const k of ["command", "input", "patch", "patchText"])
      for (const v of [a[k]].flat()) if (typeof v === "string" && v.trim()) paths.push(...patchPaths(v));
    // a write whose files cannot be read is not waved through: it asks (gate.mjs toolRules)
    return {kind: "write", name, paths: [...new Set(paths)], ...(!paths.length && {unreadable: true})};
  }
  // Hermes (mcp_<server>_<tool>), omp, and any tool an adapter says is not built in
  if (mcp || /^mcp[_:.]/.test(name)) return {kind: "mcp", name, server: null, tool: name.replace(/^mcp[_:.]/, ""), args: a};
  return null;
}
// The files a patch touches: apply_patch's own format (Codex, opencode, Hermes) and a unified diff.
// In an apply_patch body a removed line can start with "--", so the diff headers are read only without one.
export const patchPaths = text => {
  const s = String(text), v4a = /^\*\*\* Begin Patch/m.test(s);
  const re = v4a ? /^\*\*\* (?:(?:Add|Update|Delete) File|Move to): *(.+?) *$/gm
    : /^\*\*\* (?:(?:Add|Update|Delete) File|Move to): *(.+?) *$|^(?:\+\+\+ |--- |rename (?:from|to) |copy (?:from|to) )(?:[ab]\/)?(.+?)(?:\t.*)?$/gm;
  return [...new Set([...s.matchAll(re)].map(m => (m[1] ?? m[2]).trim()).filter(p => p && p !== "/dev/null"))];
};

// ---------------------------------------------------------------------------------------------
// MCP. A tool name as words: deleteStack, delete-stack and delete_stack are all delete_stack.
export const words = s => String(s ?? "").replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
const COMMAND_KEYS = /^(command|cli_command|cmd|shell_command|shell|script|bash)$/i;
const SQL_KEYS = /^(sql|query|statement|stmt)$/i;
// a value under an SQL key, comments stripped, that starts like a statement
const sqlText = v => String(v).replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, " ");
const DOCS = /(^|_)(docs?|documentation|search|help|guide|ask|library|recall|memory|memories|corpus)(_|$)/;
const SQL_START = /^[\s(]*(select|with|show|explain|describe|desc|values|table|insert|update|delete|merge|drop|alter|truncate|create|grant|revoke|replace|copy|call|exec|execute|set|begin|commit|vacuum|lock|analyze)\b/i;
/** Every string in the arguments (depth 6, 400 values), as [key, value]. */
export function argStrings(args, out = [], key = "", depth = 0) {
  if (out.length >= 400 || depth > 6) return out;
  if (typeof args === "string") out.push([key, args]);
  else if (typeof args === "number" || typeof args === "boolean") out.push([key, String(args)]);
  else if (Array.isArray(args)) for (const v of args) argStrings(v, out, key, depth + 1);
  else if (args && typeof args === "object") for (const [k, v] of Object.entries(args)) argStrings(v, out, k, depth + 1);
  return out;
}
// SELECT only: every statement starts with a read keyword and no write keyword stands anywhere
// outside comments and string literals (a CTE that deletes, SELECT ... INTO, a second statement).
export function selectOnly(sql) {
  const s = String(sql).replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, " ").replace(/'(?:[^']|'')*'|"(?:[^"]|"")*"|`[^`]*`/g, "''");
  const parts = s.split(";").map(p => p.trim()).filter(Boolean);
  return parts.length > 0 && parts.every(p => /^\(*\s*(select|with|show|explain|describe|desc|values|table)\b/i.test(p)) &&
    !/\b(insert|update|delete|merge|upsert|drop|alter|truncate|create|grant|revoke|replace|copy|call|exec|execute|into|lock|vacuum|set|attach|detach|pragma|load|import)\b/i.test(s);
}
// Without a server name (Hermes, opencode) the tool name starts with the server's: an anchored tool
// pattern also reads it with one to three leading words dropped. `sql`: a pattern on each statement.
const toolViews = t => { const w = words(t.tool).split("_"); return t.server ? [w.join("_")] : [0, 1, 2, 3].map(n => w.slice(n).join("_")).filter(Boolean); };
const hitRule = (r, t, text, sql = []) => (!r.server || r.server.test(t.server ?? t.name)) && (!r.tool || toolViews(t).some(v => r.tool.test(v))) &&
  (!r.args || r.args.test(text)) && (!r.sql || sql.some(([, v]) => sqlText(v).split(";").some(st => r.sql.test(st.trim()))));
const SEVERITY = {deny: 2, ask: 1};
/** The rule decision on an MCP call, or null when no rule and no read check covers it (unknown).
 * spec: mcp.json; team: a team policy's mcp rules (compiled, `test` or regexes); tier: {prod, by};
 * precheck: the shell gate's precheck on a command string. */
export function mcpJudge(t, {spec, team = [], tier = {prod: false}, precheck = () => null}) {
  const text = JSON.stringify(t.args ?? {}), strs = argStrings(t.args ?? {}), tool = words(t.tool);
  const sql = DOCS.test(tool) ? [] : strs.filter(([k, v]) => SQL_KEYS.test(k) && SQL_START.test(sqlText(v)));
  const label = `${t.server ? `${t.server}/` : ""}${t.tool}`;
  const version = spec.version, ruled = (r, extra = "") => ({outcome: r.outcome, rule: `${r.rule} (${label})${extra}`, id: r.id, source: "rule", policy_version: version});
  let best = null;
  const take = j => { if (!best || (SEVERITY[j.outcome] ?? 0) > (SEVERITY[best.outcome] ?? 0)) best = j; };
  // a shell command in an argument is judged by the shell rules, as if the agent ran it
  const commands = strs.filter(([k, v]) => COMMAND_KEYS.test(k) && v.trim());
  const shell = commands.map(([k, v]) => [k, precheck(v)]);
  for (const [k, r] of shell) if (r?.source === "rule" && r.outcome !== "pass") take({...r, rule: `${r.rule} (MCP ${label}, argument ${k})`});
  for (const r of [...spec.rules.map(compileRule), ...team]) {
    if (!(r.test ? r.test(t, text, words) : hitRule(r, t, text, sql))) continue;
    const prod = tier.prod && r.prod === "deny";
    take(prod ? {...ruled(r, ` on production (${tier.by})`), outcome: "deny"} : ruled(r));
  }
  if (best) return best;
  // read-like: the tool name starts with a read verb, a SQL argument is SELECT only, a shell argument is read-only
  // the verb is the first word; after the server's own name when the tool repeats it (aws-mcp's
  // aws___search_documentation), or the second word when the agent gives no server (Hermes mcp_<server>_<tool>)
  const w = tool.split("_"), own = new Set(words(t.server ?? "").split("_"));
  const verb = t.server ? (own.has(w[0]) && w.length > 1 ? w[1] : w[0]) : [w[0], w[1]].find(x => spec.read.includes(x)) ?? w[0];
  const read = spec.read.includes(verb);
  const sqlVerb = new RegExp(`(^|_)(${(spec.sql_verbs ?? []).join("|")})(_|$)`).test(tool);
  if (commands.length) return shell.every(([, r]) => r?.source === "read-only") ? {outcome: "pass", rule: "read-only (MCP shell argument)", source: "read-only"} : null;
  if (sql.length && (sqlVerb || read)) return sql.every(([, v]) => selectOnly(v)) ? {outcome: "pass", rule: "read-only (MCP query, SELECT only)", source: "read-only"} : null;
  if (read) return {outcome: "pass", rule: `read-only (MCP tool ${verb})`, source: "read-only"};
  // tools that only move a browser around, write to local agent memory, or send an HTTP GET (mcp.json `pass`)
  const quiet = (spec.pass ?? []).map(compileRule).find(r => hitRule(r, t, text, sql));
  return !sql.length && quiet ? {outcome: "pass", rule: `${quiet.rule} (${label})`, source: "read-only"} : null;
}
const compiled = new WeakMap();
function compileRule(r) {
  if (!compiled.has(r)) compiled.set(r, {...r, ...Object.fromEntries(["server", "tool", "args", "sql"].filter(k => r[k]).map(k => [k, new RegExp(r[k], "i")]))});
  return compiled.get(r);
}
// An MCP tool that writes a file (a filesystem server's write_file, move_file, edit_file): its path
// arguments go through the protected paths like a file tool's.
const PATH_KEYS = /^(path|paths|file|file_?path|file_?name|destination|dest|target|new_?path|to)$/i;
export const mcpWritePaths = t => /(^|_)(write|edit|create|move|rename|copy|append|save|put|upload|patch|replace|overwrite|mkdir)(_|$)/.test(words(t.tool))
  ? argStrings(t.args ?? {}).filter(([k, v]) => PATH_KEYS.test(k) && v.trim()).map(([, v]) => v) : [];
/** What the trace, the queue and System 2 see of an MCP call: one line, arguments redacted and cut. */
export const mcpCommand = (t, redact) => `mcp ${t.server ? `${t.server}/` : ""}${t.tool} ${redact(JSON.stringify(t.args ?? {})).slice(0, 2000)}`;

// ---------------------------------------------------------------------------------------------
// Protected paths. A glob as a regular expression over an absolute path: ~/ and / anchor it, any
// other glob matches at any depth (gitignore style). ** crosses directories, * and ? do not.
const esc = s => s.replace(/[.+^${}()|[\]\\]/g, "\\$&");
export function globRegex(glob, home = homedir()) {
  let g = String(glob).trim(), anchor = "(^|/)";
  if (g.startsWith("~/")) { g = g.slice(2); anchor = `^${esc(home)}/`; }
  else if (g.startsWith("/")) { g = g.slice(1); anchor = "^/"; }
  const body = g.split(/(\*\*\/|\*\*|\*|\?)/).map(p => p === "**/" ? "(.*/)?" : p === "**" ? ".*" : p === "*" ? "[^/]*" : p === "?" ? "[^/]" : esc(p)).join("");
  // macOS and Windows file systems ignore case by default: .GitHub/Workflows is .github/workflows
  return new RegExp(`${anchor}${body}$`, CASELESS ? "i" : "");
}
const CASELESS = ["darwin", "win32"].includes(process.platform);
// the path with symlinks resolved, through the nearest directory above it that exists
const real = p => {
  for (let d = p, rest = []; ; rest.unshift(basename(d)), d = dirname(d)) {
    try { return join(realpathSync.native(d), ...rest); } catch { if (dirname(d) === d) return p; }
  }
};
/** The first protected path among `paths`: {path, abs, why, glob, prod} or null.
 * entries: [{glob, why, prod?, unless?}]; prodPath: whether a path points at production. */
export function protectedPath(paths, {cwd, entries, prodPath = () => false, home = homedir()}) {
  const rx = entries.map(e => ({...e, re: globRegex(e.glob, home)}));
  for (const p of paths) {
    const raw = p.startsWith("~/") ? join(home, p.slice(2)) : p;
    const abs = resolve(isAbsolute(raw) ? raw : resolve(cwd || home, raw));
    for (const view of [...new Set([abs, real(abs)])]) {
      const e = rx.find(e => e.re.test(view) && (!e.prod || prodPath(view)) && !e.unless?.(view));
      if (e) return {path: p, abs: view, why: e.why, glob: e.glob, prod: !!e.prod || prodPath(view)};
    }
  }
  return null;
}
