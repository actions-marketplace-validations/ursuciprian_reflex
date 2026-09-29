#!/usr/bin/env node
// Reflex tool router: an MCP server with three tools in front of many.
//
//   find_tools(intent)            tier 1: one line per best-matching tool (a Jev choice over the catalog)
//   describe_tool(name)           tier 2: the full schema of one tool
//   run(intent, tool?, args?)     Jev picks the tool and fills its arguments; low confidence returns
//                                 candidates instead of guessing; shell tools pass the Reflex gate first
//
//   node router/server.mjs [--mode shadow|enforce]   stdio MCP server (what an agent launches)
//   node router/server.mjs --selfcheck               offline tests, stubbed Jev, no API calls
//
// The catalog is the built-in command tools (router/commands.json, those whose binary is on PATH)
// plus every tool of every stdio MCP server in router/config.json (REFLEX_ROUTER_CONFIG), named
// <server>.<tool>. Arguments are never generated as free text: each one is a Jev choice over the
// enum, or over the words and quoted strings of the intent, or a yes/no for a flag (TypeSafe's
// function-calling cookbook). Anything Jev cannot fill, the agent is asked to supply.
import {appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {execFile, spawnSync} from "node:child_process";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {ask as jevAsk, CONFIG, decideSafe, redact} from "../gate.mjs";
import {connect, lines, PROBE_MS, reconnecting, VERSIONS} from "./mcp.mjs";
import {PROVIDERS} from "../providers.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENV = process.env;
const R = {
  config: ENV.REFLEX_ROUTER_CONFIG ?? join(HERE, "config.json"),
  commands: join(HERE, "commands.json"),
  minConfidence: Number(ENV.REFLEX_ROUTER_MIN_CONFIDENCE ?? 0.5),
  flatMax: 200,                  // above this many tools, pick a category first (hierarchical choice)
  maxOptions: 254,               // a choice takes 255 options; one is reserved for "none"
  execTimeoutMs: Number(ENV.REFLEX_ROUTER_TIMEOUT_MS ?? 30000),
  retryMs: Number(ENV.REFLEX_ROUTER_RETRY_MS ?? 30000),   // a crashed downstream server is restarted at most this often
  log: join(CONFIG.data, "router.jsonl"),
};
// A choice over a few hundred descriptions takes longer than the gate's 3 s hook budget.
if (!ENV.REFLEX_TIMEOUT_MS) CONFIG.timeoutMs = 10000;
const NONE = "none_of_these";

// The one injection point for tests: a module whose default export replaces gate.ask().
let jev = ENV.REFLEX_ROUTER_STUB ? (await import(pathToFileURL(resolve(ENV.REFLEX_ROUTER_STUB)).href)).default : jevAsk;
export const setJev = fn => { jev = fn; };

// ---------------------------------------------------------------------------------------------
// Catalog.
const onPath = bin => (ENV.PATH ?? "").split(":").some(d => d && existsSync(join(d, bin)));
export const commandTools = (all = false) =>
  JSON.parse(readFileSync(R.commands, "utf8")).tools.filter(t => all || onPath(t.bin)).map(t => ({...t, kind: "shell"}));

const clients = [];
// Downstream servers are connected once; their tools are read from each client every time, so a
// server restarted after a crash contributes its current tool list, not the one it started with.
const toolsOf = (server, spec, c) => c.tools.map(t => ({name: `${server}.${t.name}`, category: server, description: t.description ?? t.title ?? "",
  inputSchema: t.inputSchema ?? {type: "object"}, kind: "mcp", server, tool: t.name, client: c,
  trusted: spec.trusted === true,   // opts the server out of the gate: its calls run unjudged
  readOnly: t.annotations?.readOnlyHint === true && t.annotations?.destructiveHint !== true}));
async function downstream() {
  if (!existsSync(R.config)) return [];
  const servers = JSON.parse(readFileSync(R.config, "utf8")).mcpServers ?? {};
  const got = await Promise.all(Object.entries(servers).map(async ([server, spec]) => {
    if (spec.disabled || !spec.command) {
      if (!spec.disabled) console.error(`reflex-router: ${server}: only stdio servers (command) are supported, skipped`);
      return [];
    }
    try {
      const c = await reconnecting(spec, {name: server, timeoutMs: R.execTimeoutMs, retryMs: R.retryMs,
        onRestart: tools => console.error(`reflex-router: ${server} restarted, ${tools.length} tools`)});
      clients.push(c);
      return [{server, spec, c}];
    } catch (e) {
      console.error(`reflex-router: ${server} unavailable: ${e.message}`);   // one broken server must not take the router down
      return [];
    }
  }));
  return got.flat();
}
let shellTools, downP;
const catalog = async () => {
  shellTools ??= commandTools();
  const ds = await (downP ??= downstream().catch(e => { downP = null; throw e; }));   // a broken config file is retried on the next call
  return [...shellTools, ...ds.flatMap(d => toolsOf(d.server, d.spec, d.c))];
};
// Children (shell tools, downstream servers) never see a Jev provider key.
const KEY_VARS = new Set(Object.values(PROVIDERS).flatMap(p => p.env));
const childEnv = () => Object.fromEntries(Object.entries(ENV).filter(([k]) => !KEY_VARS.has(k)));
const regex = p => { try { return new RegExp(p, "u"); } catch { try { return new RegExp(p); } catch { return null; } } };

// ---------------------------------------------------------------------------------------------
// Jev: which tool, then which arguments.
const snippet = t => (t.description || t.name).split(/(?<=[.!?])\s/)[0].slice(0, 160);
const stateFor = intent => ({
  request: {intent: redact(intent).slice(0, 4000), cwd: process.cwd()},
  operator: "A coding agent asks a tool router for a tool. The router lists tools; each has a name and a description.",
});
async function jevOrThrow(intent, questions) {
  const r = await jev(stateFor(intent), questions);
  if (r.error) throw new Error(`jev unavailable (${r.error.slice(0, 120)}); call run with an explicit tool and args`);
  return r.answers ?? {};
}
const ranked = a => Object.entries(a?.probabilities ?? {}).sort((x, y) => y[1] - x[1]).map(([name, p]) => ({name, p: +p.toFixed(3)}));

/** Rank the catalog for an intent: {ranked: [{name, p}], confidence, categories?}. */
export async function select(intent, cat) {
  let pool = cat, categories;
  if (cat.length > R.flatMax) {
    // Hierarchical: a category first, then the tools of the categories that hold ~90% of the
    // probability (at most three). ponytail: a beam of one level; nest categories when one category
    // alone outgrows a choice.
    const groups = new Map();   // Map.groupBy needs Node 21
    for (const t of cat) groups.set(t.category ?? "other", [...(groups.get(t.category ?? "other") ?? []), t]);
    const a = (await jevOrThrow(intent, {__category__: {type: "choice",
      instructions: "Which group of tools most likely holds one that does what `request.intent` asks?",
      criteria: Object.fromEntries([...groups].slice(0, R.maxOptions + 1).map(([c, ts]) => [c, `tools: ${ts.map(t => t.tool ?? t.name).join(", ")}`.slice(0, 400)]))}}))
      .__category__;
    categories = ranked(a);
    pool = [];
    let mass = 0;
    for (const [i, {name, p}] of categories.entries()) {
      if (pool.length && (mass >= 0.9 || i >= 3)) break;
      pool.push(...(groups.get(name) ?? []));
      mass += p;
    }
  }
  pool = pool.slice(0, R.maxOptions);   // ponytail: a category over 254 tools is cut, not split
  const a = (await jevOrThrow(intent, {__tool__: {type: "choice",
    instructions: "Which tool does what `request.intent` asks for?",
    criteria: {...Object.fromEntries(pool.map(t => [t.name, (t.description || t.name).slice(0, 300)])),
               [NONE]: "None of the listed tools does what is asked"}}})).__tool__;
  const r = ranked(a);
  return {ranked: r, confidence: r[0]?.p ?? 0, jev_confidence: a?.confidence ?? null, categories};
}

const OPEN = {")": "(", "]": "[", "}": "{", ">": "<"};
/** Words, key=value values and quoted strings of the intent: the only values Jev may choose from. */
export function candidates(text) {
  const out = [];
  for (const m of text.matchAll(/(["'`])([^"'`\n]{1,200})\1/g)) out.push(m[2]);
  for (let w of text.split(/\s+/)) {
    w = w.replace(/^[("'`[{<]+/, "");
    // trailing punctuation goes, but a closing bracket stays when it closes one: console.log($A)
    while (/[)"'`\]}>,;:!?]$/.test(w) && !(OPEN[w.at(-1)] && w.split(OPEN[w.at(-1)]).length >= w.split(w.at(-1)).length)) w = w.slice(0, -1);
    if (w.length > 1 && w.endsWith(".") && !w.endsWith("..")) w = w.slice(0, -1);
    const kv = w.match(/^[\w-]+=(.+)$/);
    if (kv) out.push(kv[1]);
    if (w) out.push(w);
  }
  return [...new Set(out)].filter(v => v.length <= 200);
}

/** Fill the arguments of `tool` from the intent. Returns {args, confidence, weakest, missing}. */
export async function fillArgs(intent, tool) {
  const schema = tool.inputSchema ?? {}, props = schema.properties ?? {}, required = new Set(schema.required ?? []);
  const cands = candidates(redact(intent)), questions = {}, missing = [];
  for (const [k, s] of Object.entries(props)) {
    const optional = !required.has(k), type = [].concat(s.type)[0];
    const about = `The tool \`${tool.name}\` (${snippet(tool)}) needs this: ${s.description ?? k}.`;
    const none = optional ? {[NONE]: "The request does not say"} : {[NONE]: "None of these is right"};
    if (s.enum) {
      questions[`arg.${k}`] = {type: "choice", instructions: `${about} Which one does \`request.intent\` ask for?`,
                               criteria: {...Object.fromEntries(s.enum.slice(0, R.maxOptions).map(v => [String(v), null])), ...none}};
    } else if (type === "boolean") {
      questions[`arg.${k}`] = {type: "noul", instructions: `${about} Does \`request.intent\` ask for it?`};
    } else if (["string", "number", "integer"].includes(type)) {
      let vals = type === "string" ? cands : cands.filter(c => Number.isFinite(Number(c)) && (type === "number" || Number.isInteger(Number(c))));
      if (s.pattern && regex(s.pattern)) vals = vals.filter(v => regex(s.pattern).test(v));
      if (!vals.length) { if (!optional) missing.push(k); continue; }
      questions[`arg.${k}`] = {type: "choice", instructions: `${about} Which of these values, taken from \`request.intent\`, is it?`,
                               criteria: {...Object.fromEntries(vals.slice(0, R.maxOptions).map(v => [v, null])), ...none}};
    } else if (!optional) missing.push(k);   // objects and arrays: the agent supplies them
  }
  const args = {};
  let confidence = 1, weakest = null;
  if (!Object.keys(questions).length) return {args, confidence, weakest, missing};
  const answers = await jevOrThrow(intent, questions);
  for (const [id, q] of Object.entries(questions)) {
    const k = id.slice(4), s = props[k], a = answers[id];
    if (!a) { if (required.has(k)) missing.push(k); continue; }
    // Per the cookbook, the call is only as sure as its least certain judgement.
    const p = q.type === "noul" ? Math.max(a.noul, 1 - a.noul) : (a.probabilities?.[a.choice] ?? 0);
    if (p < confidence) { confidence = +p.toFixed(3); weakest = k; }
    if (q.type === "noul") { if (a.noul >= 0.5 || required.has(k)) args[k] = a.noul >= 0.5; continue; }
    if (a.choice === NONE) { if (required.has(k)) missing.push(k); continue; }
    args[k] = s.enum ? s.enum.find(v => String(v) === a.choice) : [].concat(s.type)[0] === "string" ? a.choice : Number(a.choice);
  }
  // One word of the intent answers one question: an optional argument given the same value as a
  // required or earlier-declared one is dropped ("in gate.mjs" is the path, not also --include gate.mjs).
  const keys = Object.keys(props);
  for (const k of keys) if (!required.has(k) && typeof args[k] === "string" &&
      keys.some(j => j !== k && args[j] === args[k] && (required.has(j) || keys.indexOf(j) < keys.indexOf(k)))) delete args[k];
  return {args, confidence, weakest, missing};
}

// ---------------------------------------------------------------------------------------------
// JSON Schema, the subset tool schemas use: type, enum, const, required, properties,
// additionalProperties, items, min/max(Length|Items|imum), pattern. ponytail: no $ref, allOf/anyOf,
// or formats; a schema using them is only checked on the keywords above.
export function validate(schema, v, path = "args") {
  if (!schema || typeof schema !== "object") return [];
  const errs = [], types = [].concat(schema.type ?? []);
  const is = t => t === "integer" ? Number.isInteger(v) : t === "number" ? typeof v === "number" && Number.isFinite(v)
    : t === "array" ? Array.isArray(v) : t === "null" ? v === null
    : t === "object" ? v !== null && typeof v === "object" && !Array.isArray(v) : typeof v === t;
  if (types.length && !types.some(is)) return [`${path}: expected ${types.join(" or ")}, got ${v === null ? "null" : Array.isArray(v) ? "array" : typeof v}`];
  if (schema.enum && !schema.enum.some(e => JSON.stringify(e) === JSON.stringify(v))) errs.push(`${path}: must be one of ${JSON.stringify(schema.enum)}`);
  if ("const" in schema && JSON.stringify(schema.const) !== JSON.stringify(v)) errs.push(`${path}: must be ${JSON.stringify(schema.const)}`);
  if (typeof v === "string") {
    if (schema.minLength != null && [...v].length < schema.minLength) errs.push(`${path}: shorter than ${schema.minLength}`);
    if (schema.maxLength != null && [...v].length > schema.maxLength) errs.push(`${path}: longer than ${schema.maxLength}`);
    if (schema.pattern && regex(schema.pattern) && !regex(schema.pattern).test(v)) errs.push(`${path}: does not match ${schema.pattern}`);
  }
  if (typeof v === "number") {
    if (schema.minimum != null && v < schema.minimum) errs.push(`${path}: below ${schema.minimum}`);
    if (schema.maximum != null && v > schema.maximum) errs.push(`${path}: above ${schema.maximum}`);
  }
  if (Array.isArray(v)) {
    if (schema.minItems != null && v.length < schema.minItems) errs.push(`${path}: fewer than ${schema.minItems} items`);
    if (schema.maxItems != null && v.length > schema.maxItems) errs.push(`${path}: more than ${schema.maxItems} items`);
    if (schema.items) v.forEach((x, i) => errs.push(...validate(schema.items, x, `${path}[${i}]`)));
  }
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    for (const k of schema.required ?? []) if (!Object.hasOwn(v, k)) errs.push(`${path}.${k}: required`);
    for (const [k, x] of Object.entries(v)) {
      if (schema.properties && Object.hasOwn(schema.properties, k)) errs.push(...validate(schema.properties[k], x, `${path}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${path}.${k}: not allowed`);
      else if (typeof schema.additionalProperties === "object") errs.push(...validate(schema.additionalProperties, x, `${path}.${k}`));
    }
  }
  return errs;
}

// ---------------------------------------------------------------------------------------------
// Shell backend: argv template -> execFile, after the gate.
const PH = /^\{(\w+)(\.\.\.)?\}$/;
export function argv(tpl, vals) {
  return tpl.flatMap(el => {
    if (Array.isArray(el)) {
      const names = el.map(x => x.match?.(PH)?.[1]).filter(Boolean);
      return names.every(n => vals[n] !== undefined && vals[n] !== false) ? argv(el, vals) : [];
    }
    const m = el.match(PH);
    if (!m) return [el];
    const v = vals[m[1]];
    if (v === undefined || typeof v === "boolean") return [];
    return m[2] ? String(v).split(" ") : [String(v)];
  });
}
// How the gate sees the call: the exact argv, shell-quoted. Nothing is ever run through a shell.
export const shellQuote = s => /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", `'\\''`)}'`;

async function runShell(tool, args, intent) {
  const props = tool.inputSchema?.properties ?? {};
  // A value that starts with "-" would be read as an option (git log --output=…): refused unless the
  // template puts it where it cannot be one (after -e or --).
  const dashed = Object.entries(args).filter(([k, v]) => typeof v === "string" && v.startsWith("-") && !props[k]?.["x-allow-dash"]);
  if (dashed.length) return {status: "invalid_args", tool: tool.name, errors: dashed.map(([k]) => `args.${k}: must not start with "-"`)};
  // "{x...}" splits a value into several argv words, so only a closed set may use it: a free string
  // "a --output=f" would smuggle an option past the check above.
  const spread = tool.args.flat(Infinity).map(a => a.match(PH)).filter(m => m?.[2] && !props[m[1]]?.enum);
  if (spread.length) return {status: "invalid_args", tool: tool.name, errors: spread.map(m => `template: {${m[1]}...} needs an enum`)};
  const vals = {...Object.fromEntries(Object.entries(props).filter(([, s]) => "default" in s).map(([k, s]) => [k, s.default])), ...args};
  const list = argv(tool.args, vals);
  const command = [tool.bin, ...list].map(shellQuote).join(" ");
  const d = await decideSafe({agent: "reflex-router", command, cwd: process.cwd(), intent});
  if (d.effective === "deny") return {status: "denied", tool: tool.name, command, reason: d.reason};
  if (!["pass", "allow"].includes(d.effective)) return {status: "needs_approval", tool: tool.name, command, reason: d.reason,
    message: "Not run: this needs human approval. Ask the user to confirm, then run it through your own shell tool."};
  const r = await new Promise(res => execFile(tool.bin, list, {cwd: process.cwd(), env: childEnv(), timeout: R.execTimeoutMs, maxBuffer: 16 << 20},
    (err, stdout, stderr) => res({exit_code: err ? (typeof err.code === "number" ? err.code : 1) : 0, stdout, stderr,
                                  error: err && typeof err.code !== "number" ? err.message : undefined}))
    .stdin?.end());   // a CLI that prompts (MFA, SSO) gets EOF instead of hanging until the timeout
  return {status: "ran", tool: tool.name, command, ...r};
}

// How the gate sees a downstream call: server, tool and the exact arguments. The gate redacts it
// for Jev and the trace; its rules see it raw, as they see shell commands.
export const mcpCommand = (t, args) => `mcp ${t.name} ${JSON.stringify(args)}`;

export async function runMcp(t, args, intent) {
  const command = mcpCommand(t, args);
  if (!t.trusted) {
    const d = await decideSafe({agent: "reflex-router", command, cwd: process.cwd(), intent});
    if (d.effective === "deny") return {status: "denied", tool: t.name, args, reason: d.reason};
    if (!["pass", "allow"].includes(d.effective)) return {status: "needs_approval", tool: t.name, args, reason: d.reason,
      message: "Not run: this needs human approval. Ask the user to confirm, then call it through a server registered directly in the agent."};
    // The agent's per-tool MCP permissions only see `run`, so a tool that may write must not hide
    // behind it, whatever the gate says (in shadow mode Jev's opinion is only logged).
    if (!t.readOnly) return {status: "needs_approval", tool: t.name, args,
      message: `Not run: ${t.tool} is not marked read-only by its server. A human decides: call it through a server ` +
               `registered directly in the agent, or mark "${t.server}" as "trusted": true in the router config (no gate at all).`};
  }
  try {
    const {resultType, ...mcp} = await t.client.request("tools/call", {name: t.tool, arguments: args});   // resultType: modern-era framing
    return {status: "ran", tool: t.name, args, mcp};
  } catch (e) { return {status: "error", tool: t.name, error: e.message}; }
}

// ---------------------------------------------------------------------------------------------
// The three tools.
function log(entry) {
  try {
    mkdirSync(CONFIG.data, {recursive: true});
    appendFileSync(R.log, JSON.stringify({ts: new Date().toISOString(), model: CONFIG.model, ...entry}) + "\n");
  } catch { /* a log that cannot be written must not fail the call */ }
}
const top = (cat, r, n) => r.filter(x => x.name !== NONE).slice(0, n)
  .map(x => ({name: x.name, p: x.p, summary: snippet(cat.find(t => t.name === x.name) ?? {name: x.name})}));

export async function findTools(cat, {intent, limit = 5}) {
  const s = await select(intent, cat);
  log({op: "find_tools", intent: redact(intent).slice(0, 600), tool: s.ranked[0]?.name ?? null, confidence: s.confidence,
       alternatives: s.ranked.slice(1, 5), categories: s.categories?.slice(0, 3)});
  const tools = top(cat, s.ranked, limit);
  return {tools, none_fits: s.ranked[0]?.name === NONE,
          next: "describe_tool(name) shows a tool's arguments; run(intent, tool, args) runs it."};
}

export function describeTool(cat, {name}) {
  const t = cat.find(x => x.name === name);
  if (!t) return {error: `unknown tool ${name}; find_tools lists what exists`};
  return {name: t.name, description: t.description, inputSchema: t.inputSchema,
          backend: t.kind === "shell" ? {shell: [t.bin, ...t.args.flat()].join(" ")} : {mcp_server: t.server, tool: t.tool}};
}

export async function run(cat, {intent, tool, args}) {
  let sel = null, t;
  if (tool) {
    t = cat.find(x => x.name === tool);
    if (!t) return {status: "unknown_tool", message: `unknown tool ${tool}; find_tools lists what exists`};
  } else {
    sel = await select(intent, cat);
    const best = sel.ranked[0];
    if (!best || best.name === NONE || best.p < R.minConfidence) {
      log({op: "run", intent: redact(intent).slice(0, 600), tool: null, confidence: sel.confidence, alternatives: sel.ranked.slice(0, 5), status: "choose_tool"});
      return {status: "choose_tool", confidence: sel.confidence, none_fits: best?.name === NONE, candidates: top(cat, sel.ranked, 5),
              message: "Not confident which tool fits. Pick one and call run again with `tool` (and `args`), or describe_tool first."};
    }
    t = cat.find(x => x.name === best.name);
  }
  // Arguments the agent passes are used as given; only when it passes none does Jev fill them.
  const filled = args ? {args, confidence: 1, weakest: null, missing: []} : await fillArgs(intent, t);
  const confidence = Math.min(sel?.confidence ?? 1, filled.confidence);
  const entry = {op: "run", intent: redact(intent).slice(0, 600), tool: t.name, tool_given: !!tool, confidence,
                 alternatives: sel?.ranked.slice(1, 5) ?? [], weakest_arg: filled.weakest};
  const errors = validate(t.inputSchema, filled.args);
  let out;
  if (filled.missing.length || filled.confidence < R.minConfidence)
    out = {status: "needs_args", tool: t.name, proposed_args: filled.args, missing: filled.missing, weakest: filled.weakest,
           confidence, inputSchema: t.inputSchema,
           message: "Not sure about the arguments. Call run again with this tool and explicit `args`."};
  else if (errors.length) out = {status: "invalid_args", tool: t.name, args: filled.args, errors};
  else if (t.kind === "shell") out = await runShell(t, filled.args, intent);
  else out = await runMcp(t, filled.args, intent);
  log({...entry, status: out.status, exit_code: out.exit_code ?? undefined, mcp_error: out.mcp?.isError || undefined});
  return {...out, confidence};
}

// MCP tools/call result for a router result. Shell output is shown as text; a proxied call keeps the
// downstream content and structured result, behind one line saying what ran.
function asResult(r) {
  if (r.mcp) return {...r.mcp, content: [{type: "text", text: `[reflex-router] ${r.tool} (confidence ${r.confidence})`}, ...(r.mcp.content ?? [])]};
  if (r.status === "ran") {
    const cut = s => s.length > 100000 ? s.slice(0, 100000) + `\n… ${s.length - 100000} more characters cut` : s;
    return {isError: r.exit_code !== 0, content: [{type: "text", text:
      `$ ${r.command}\n${cut(r.stdout)}${r.stderr ? `\n[stderr]\n${cut(r.stderr)}` : ""}\n[exit ${r.exit_code}${r.error ? `: ${r.error}` : ""}]`}]};
  }
  return {isError: ["error", "denied", "invalid_args", "unknown_tool"].includes(r.status) || !!r.error,
          content: [{type: "text", text: JSON.stringify(r, null, 1)}]};
}

export const TOOLS = [
  {name: "find_tools", description: "Find tools for a task. Returns one line per best-matching tool out of the whole catalog (shell commands such as ripgrep, git log/diff/blame, kubectl get, aws describe, plus every tool of the configured MCP servers). Start here.",
   inputSchema: {type: "object", additionalProperties: false, required: ["intent"], properties: {
     intent: {type: "string", minLength: 1, description: "What you want to do, in one sentence. Quote exact values ('*.tf', \"TODO\")."},
     limit: {type: "integer", minimum: 1, maximum: 20, description: "How many tools to list (default 5)"}}},
   annotations: {readOnlyHint: true, openWorldHint: false}},
  {name: "describe_tool", description: "The full description and argument schema of one tool from find_tools.",
   inputSchema: {type: "object", additionalProperties: false, required: ["name"], properties: {name: {type: "string", minLength: 1}}},
   annotations: {readOnlyHint: true, openWorldHint: false}},
  {name: "run", description: "Run a tool. Give the intent; the router picks the tool and fills its arguments from the intent when you leave them out, and returns candidates instead of guessing when unsure. Pass `tool` and `args` to be exact. Shell tools pass the Reflex safety gate first. Quote exact values in the intent: search for 'TODO' in src.",
   inputSchema: {type: "object", additionalProperties: false, required: ["intent"], properties: {
     intent: {type: "string", minLength: 1, description: "What you want done, in one sentence, with the exact values it needs"},
     tool: {type: "string", description: "A tool name from find_tools; leave out to let the router choose"},
     args: {type: "object", description: "The tool's arguments, as in describe_tool; leave out to let the router fill them"}}},
   annotations: {readOnlyHint: false, destructiveHint: true, openWorldHint: true}},
];

// ---------------------------------------------------------------------------------------------
// MCP server over stdio.
class RpcError extends Error { constructor(code, message) { super(message); this.code = code; } }
async function handle(method, params = {}) {
  switch (method) {
    case "initialize":
      return {protocolVersion: VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : VERSIONS[0],
              capabilities: {tools: {listChanged: false}}, serverInfo: {name: "reflex-router", version: "0.1.0"},
              instructions: "One router in front of many tools: find_tools(intent) to see what fits, describe_tool(name) for arguments, run(intent, tool?, args?) to execute."};
    case "ping": return {};
    case "tools/list": return {tools: TOOLS};
    case "tools/call": {
      const def = TOOLS.find(t => t.name === params.name);
      if (!def) throw new RpcError(-32602, `unknown tool: ${params?.name}`);
      const a = params.arguments ?? {}, errs = validate(def.inputSchema, a);
      if (errs.length) return {isError: true, content: [{type: "text", text: `invalid arguments: ${errs.join("; ")}`}]};
      try {
        const cat = await catalog();
        if (def.name === "find_tools") return {content: [{type: "text", text: JSON.stringify(await findTools(cat, a), null, 1)}]};
        if (def.name === "describe_tool") return asResult(describeTool(cat, a));
        return asResult(await run(cat, a));
      } catch (e) {
        return {isError: true, content: [{type: "text", text: `reflex-router: ${e.message}`}]};
      }
    }
    default: throw new RpcError(-32601, `method not found: ${method}`);
  }
}

function serve() {
  const write = obj => process.stdout.write(JSON.stringify(obj) + "\n");
  let inflight = 0, ended = false;
  // Exit only once stdout has drained: a pipe write is asynchronous, and exiting early cuts a big result.
  const done = () => { for (const c of clients) c.close(); process.stdout.write("", () => process.exit(0)); };
  lines(process.stdin, async msg => {
    if (msg instanceof Error) return write({jsonrpc: "2.0", id: null, error: {code: -32700, message: "parse error"}});
    // Not an object (null, a batch array): invalid; answer rather than crash or leave the client waiting.
    if (!msg || typeof msg !== "object" || Array.isArray(msg) || (msg.id != null && typeof msg.method !== "string" && !("result" in msg) && !("error" in msg)))
      return write({jsonrpc: "2.0", id: msg?.id ?? null, error: {code: -32600, message: "invalid request"}});
    // MCP forbids a null request id (JSON-RPC allows it): Invalid Request, not silence.
    if (msg.method && msg.id === null) return write({jsonrpc: "2.0", id: null, error: {code: -32600, message: "invalid request: id must not be null"}});
    if (!msg.method || msg.id === undefined) return;   // notifications and responses need no reply
    inflight++;
    try { write({jsonrpc: "2.0", id: msg.id, result: await handle(msg.method, msg.params ?? {})}); }
    catch (e) { write({jsonrpc: "2.0", id: msg.id, error: {code: e.code ?? -32603, message: e.message}}); }
    if (--inflight === 0 && ended) done();
  });
  process.stdin.on("end", () => { ended = true; if (!inflight) done(); });
}

// ---------------------------------------------------------------------------------------------
async function selfcheck() {
  // Isolated: logs and traces go to a throwaway dir, and the cwd is not a git repo, so a gate
  // failure in a test could not push anything.
  if (!ENV.REFLEX_ROUTER_SELFCHECK_CHILD) {
    const tmp = mkdtempSync(join(tmpdir(), "reflex-router-"));
    const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--selfcheck"], {cwd: tmp, stdio: "inherit",
      // Jev is unreachable and the key a placeholder: a background shadow judgement cannot call the API
      env: {...ENV, REFLEX_ROUTER_SELFCHECK_CHILD: "1", REFLEX_DATA_DIR: join(tmp, "data"), REFLEX_MODE: "shadow",
            REFLEX_API_URL: "http://127.0.0.1:9/", TYPESAFE_API_KEY: "selfcheck-not-a-key",
            REFLEX_ROUTER_CONFIG: join(tmp, "none.json"), REFLEX_ROUTER_MIN_CONFIDENCE: "0.5"}});
    rmSync(tmp, {recursive: true, force: true});
    process.exitCode = r.status ?? 1;
    return;
  }
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  const stub = await import("./test/stub-jev.mjs");
  setJev(stub.default);
  const tmp = process.cwd();

  // schema validation
  const S = {type: "object", additionalProperties: false, required: ["p"], properties: {
    p: {type: "string", minLength: 1, pattern: "^\\w+$"}, n: {type: "integer", minimum: 1, maximum: 5},
    e: {enum: ["a", "b"]}, l: {type: "array", items: {type: "number"}, maxItems: 2}, o: {type: ["object", "null"]}}};
  ok(validate(S, {p: "x", n: 3, e: "a", l: [1, 2], o: null}).length === 0, "valid args pass");
  ok(validate(S, {}).some(e => e.includes("args.p: required")), "required");
  ok(validate(S, {p: "x", z: 1}).some(e => e.includes("not allowed")), "additionalProperties false");
  ok(validate(S, {p: "x y"}).length === 1 && validate(S, {p: ""}).length === 2, "pattern, minLength");
  ok(validate(S, {p: "x", n: 2.5}).length === 1 && validate(S, {p: "x", n: 9}).length === 1, "integer, maximum");
  ok(validate(S, {p: "x", e: "c"}).length === 1 && validate(S, {p: "x", l: [1, "2", 3]}).length === 2, "enum, items, maxItems");
  ok(validate(S, "x")[0] === "args: expected object, got string", "top-level type");
  for (const t of commandTools(true)) ok(validate({type: "object"}, t.inputSchema).length === 0 && PH.test(t.args.flat().find(a => PH.test(a)) ?? "{x}"), `command tool ${t.name} is well-formed`);

  // argv templates and quoting
  const git = commandTools(true).find(t => t.name === "git_log");
  ok(JSON.stringify(argv(git.args, {max_count: 5})) === JSON.stringify(["log", "--oneline", "--no-color", "-n", "5", "--"]), "optional groups dropped");
  ok(argv(git.args, {max_count: 5, author: "bob", path: "src"}).join(" ") === "log --oneline --no-color -n 5 --author bob -- src", "groups kept");
  const rg = commandTools(true).find(t => t.name === "rg_search");
  ok(argv(rg.args, {pattern: "x", path: ".", ignore_case: true}).join(" ") === "-n --no-heading --color never -i -e x -- .", "boolean flag group");
  ok(!argv(rg.args, {pattern: "x", path: ".", ignore_case: false}).includes("-i"), "false flag dropped");
  ok(argv(commandTools(true).find(t => t.name === "aws_describe").args, {operation: "ec2 describe-vpcs"}).slice(0, 2).join() === "ec2,describe-vpcs", "enum spread");
  ok(shellQuote("a b'c") === `'a b'\\''c'` && shellQuote("src/x.go") === "src/x.go", "quoting");
  ok(JSON.stringify(candidates(`search for 'TODO: fix' in src/main.go. author=bob`)) ===
     JSON.stringify(["TODO: fix", "search", "for", "TODO", "fix", "in", "src/main.go", "bob", "author=bob"]), "candidates");
  ok(JSON.stringify(candidates("match console.log($A), f(x)) (in src)")) === JSON.stringify(["match", "console.log($A)", "f(x)", "in", "src"]), "candidates keep balanced brackets");

  // tool selection and argument filling, stubbed Jev
  const cat = [...commandTools(true),
    {name: "t_push", kind: "shell", bin: "git", description: "force push a branch", args: ["push", "--force", "origin", "{branch}"],
     inputSchema: {type: "object", required: ["branch"], properties: {branch: {type: "string"}}}},
    {name: "t_touch", kind: "shell", bin: "touch", description: "create a file", args: ["{path}"],
     inputSchema: {type: "object", required: ["path"], properties: {path: {type: "string"}}}}];
  let s = await select("show the git_log", cat);
  ok(s.ranked[0].name === "git_log" && s.confidence >= 0.9 && stub.calls.at(-1).questions.__tool__.criteria[NONE], "flat selection, with a none option");
  const f = await fillArgs("git_log path=src max_count=7 author=ann", git);
  ok(f.args.path === "src" && f.args.max_count === 7 && f.args.author === "ann" && !("since" in f.args) && f.missing.length === 0, "args chosen from intent candidates");
  ok(!("pattern" in stub.calls.at(-1).questions) && stub.calls.at(-1).questions["arg.max_count"].criteria["7"] === null &&
     !("src" in stub.calls.at(-1).questions["arg.max_count"].criteria), "integer args choose among numbers only");
  const gr = commandTools(true).find(t => t.name === "grep_search");
  const d1 = await fillArgs("grep pattern=decideSafe path=gate.mjs glob=gate.mjs", gr);
  ok(d1.args.path === "gate.mjs" && !("glob" in d1.args), "a value filled twice keeps the earlier argument (no --include gate.mjs -- gate.mjs)");
  const d2 = await fillArgs("grep pattern=TODO path=TODO", gr);
  ok(d2.args.pattern === "TODO" && !("path" in d2.args), "a required argument keeps its value over an optional one");
  const r0 = await run(cat, {intent: "rg_search please"});
  ok(r0.status === "needs_args" && r0.missing.includes("pattern") && r0.tool === "rg_search", "required arg not in intent: needs_args");
  const r1 = await run(cat, {intent: "something ambiguous"});
  ok(r1.status === "choose_tool" && r1.candidates.length >= 2 && r1.candidates.every(c => c.name !== NONE), "low confidence: candidates, not a guess");
  const r2 = await run(cat, {intent: "nothing matches this"});
  ok(r2.status === "choose_tool" && r2.none_fits, "none fits");
  const r3 = await run(cat, {intent: "git_blame lines=1,2 path=weak"});
  ok(r3.status === "needs_args" && r3.weakest === "path" && r3.confidence < 0.5, "weak argument: needs_args");

  // hierarchical selection over a big catalog
  const big = Array.from({length: 250}, (_, i) => ({name: `cat${i % 5}.tool_${i}`, category: `cat${i % 5}`, tool: `tool_${i}`, kind: "mcp", description: `tool ${i}`}));
  const n0 = stub.calls.length;
  s = await select("use cat3 tool_173", big);
  const [c1, c2] = stub.calls.slice(n0);
  ok(Object.keys(c1.questions.__category__.criteria).length === 5 && Object.keys(c2.questions.__tool__.criteria).length === 51 &&
     s.ranked[0].name === "cat3.tool_173", "category first, then only that category's tools");

  // the gate is never bypassed
  const marker = join(tmp, "marker.txt");
  writeFileSync(marker, "reflex-router-selfcheck-marker\n");
  const g0 = await run(cat, {intent: "search it", tool: "grep_search", args: {pattern: "reflex-router-selfcheck-marker", path: marker}});
  ok(g0.status === "ran" && g0.exit_code === 0 && g0.stdout.includes("marker") && g0.command.startsWith("grep -rnI -e"), "read-only shell tool runs");
  const g1 = await run(cat, {intent: "t_push branch=main"});
  ok(g1.status === "denied" && /force push/.test(g1.reason) && !("stdout" in g1), "rule deny: not executed");
  const tamper = join(dirname(HERE), "router", "test", "tamper.txt");
  const g2 = await run(cat, {intent: "make a file", tool: "t_touch", args: {path: tamper}});
  ok(g2.status === "needs_approval" && !existsSync(tamper), "rule ask: not executed");
  // enforce mode, Jev unreachable: the policy fallback (ask) holds the command back too
  const copy = join(tmp, "copy.txt");
  Object.assign(CONFIG, {mode: "enforce", api: "http://127.0.0.1:9/"});
  const g6 = await run([{name: "t_cp", kind: "shell", bin: "cp", args: ["{a}", "{b}"], inputSchema: {type: "object"}}],
                       {intent: "copy", tool: "t_cp", args: {a: marker, b: copy}});
  Object.assign(CONFIG, {mode: "shadow"});
  ok(g6.status === "needs_approval" && /jev unavailable/.test(g6.reason) && !existsSync(copy), "enforce + Jev down: fallback ask, not executed");
  const g7 = await run(cat, {intent: "x", tool: "kubectl_get", args: {resource: "secrets", output: "yaml"}});
  ok(g7.status === "invalid_args", "kubectl_get refuses secrets");
  const g3 = await run(cat, {intent: "log", tool: "git_log", args: {author: "--output=/tmp/x"}});
  ok(g3.status === "invalid_args" && /must not start with "-"/.test(g3.errors[0]), "option injection refused");
  const g5 = await run([{name: "t_spread", kind: "shell", bin: "echo", args: ["{x...}"], inputSchema: {type: "object", properties: {x: {type: "string"}}}}],
                       {intent: "x", tool: "t_spread", args: {x: "a --output=f"}});
  ok(g5.status === "invalid_args" && /needs an enum/.test(g5.errors[0]), "word splitting only for enums");
  const g4 = await run(cat, {intent: "log", tool: "git_log", args: {max_count: "5"}});
  ok(g4.status === "invalid_args", "schema checked before running");

  // downstream MCP calls are judged by the gate too; only "trusted" opts a server out
  let calls = 0;
  const ds = extra => ({name: "srv.read", kind: "mcp", server: "srv", tool: "read", readOnly: true, inputSchema: {type: "object"},
                        client: {request: async () => { calls++; return {content: [{type: "text", text: "ok"}]}; }}, ...extra});
  ok(mcpCommand(ds(), {path: "a b"}) === `mcp srv.read {"path":"a b"}`, "mcp call as the gate sees it");
  const m1 = await run([ds()], {intent: "read my key", tool: "srv.read", args: {path: "/Users/a/.ssh/id_ed25519"}});
  ok(m1.status === "needs_approval" && /private key/.test(m1.reason) && calls === 0, "read-only MCP tool: secret-file rule asks, not called");
  const m2 = await run([ds()], {intent: "wipe", tool: "srv.read", args: {cmd: "rm -rf ~"}});
  ok(m2.status === "denied" && calls === 0, "MCP deny rule: not called");
  const m3 = await run([ds({trusted: true})], {intent: "read my key", tool: "srv.read", args: {path: "/Users/a/.ssh/id_ed25519"}});
  ok(m3.status === "ran" && calls === 1, "trusted server: opted out of the gate");
  const m4 = await run([ds({readOnly: false})], {intent: "x", tool: "srv.read", args: {path: "README.md"}});
  ok(m4.status === "needs_approval" && /not marked read-only/.test(m4.message) && calls === 1, "not read-only, gate passes (shadow): still not run");
  Object.assign(CONFIG, {mode: "enforce"});
  const m5 = await run([ds()], {intent: "x", tool: "srv.read", args: {path: "README.md"}});
  Object.assign(CONFIG, {mode: "shadow"});
  ok(m5.status === "needs_approval" && /jev unavailable/.test(m5.reason) && calls === 1, "enforce + Jev down: MCP call held back");
  const trace = readFileSync(join(CONFIG.data, "trace.jsonl"), "utf8");
  ok(trace.includes("mcp srv.read") && trace.includes("recursive delete"), "MCP gate decisions are traced");
  ok(trace.includes("force push or delete of main") && trace.includes('"agent":"reflex-router"'), "gate decisions are traced");
  const rlog = readFileSync(R.log, "utf8").trim().split("\n").map(l => JSON.parse(l));
  ok(rlog.some(e => e.status === "choose_tool" && e.alternatives.length) && rlog.some(e => e.tool === "grep_search" && e.status === "ran"), "router.jsonl");

  // protocol round trip: this server over stdio, proxying a fake downstream MCP server
  const cfg = join(tmp, "router.json"), fake = {command: process.execPath, args: [join(HERE, "test/fake-server.mjs")]};
  writeFileSync(cfg, JSON.stringify({mcpServers: {fake, trusted: {...fake, trusted: true}, modern: {...fake, args: [...fake.args, "modern"], trusted: true},
                                                  gone: {command: join(tmp, "does-not-exist")}, remote: {url: "https://x"}}}));
  const routerEnv = {REFLEX_ROUTER_STUB: join(HERE, "test/stub-jev.mjs"), REFLEX_ROUTER_CONFIG: cfg, REFLEX_DATA_DIR: CONFIG.data,
                     REFLEX_MODE: "shadow", TYPESAFE_API_KEY: "selfcheck-not-a-key", REFLEX_API_URL: "http://127.0.0.1:9/"};
  const c = await connect({command: process.execPath, args: [fileURLToPath(import.meta.url)], env: routerEnv}, {name: "router"});
  ok(c.init.protocolVersion === VERSIONS[0] && c.init.capabilities.tools && c.tools.map(t => t.name).join() === "find_tools,describe_tool,run", "initialize + tools/list");
  ok(JSON.stringify(await c.request("ping")) === "{}", "ping");
  const text = r => r.content.map(x => x.text).join("\n");
  const ft = await c.request("tools/call", {name: "find_tools", arguments: {intent: "echo text=hi"}});
  ok(JSON.parse(text(ft)).tools[0].name === "fake.echo", "find_tools over a downstream catalog");
  const dt = await c.request("tools/call", {name: "describe_tool", arguments: {name: "fake.add"}});
  ok(JSON.parse(text(dt)).inputSchema.required.join() === "a,b", "describe_tool (downstream tools/list was paginated)");
  const e1 = await c.request("tools/call", {name: "run", arguments: {intent: "echo text=hello token=hunter2"}});
  ok(!e1.isError && text(e1).includes("echo: hello") && text(e1).includes("fake.echo"), "run: selected, filled, proxied");
  ok(text(e1).includes("key=absent"), "downstream servers do not get the TypeSafe key");
  const logged = readFileSync(R.log, "utf8");
  ok(!logged.includes("hunter2") && logged.includes("token=<redacted>"), "redacted log");
  const e2 = await c.request("tools/call", {name: "run", arguments: {intent: "add a=2 b=3.5"}});
  ok(JSON.parse(text(e2)).status === "needs_approval", "a tool not annotated read-only is not run unattended");
  const e6 = await c.request("tools/call", {name: "run", arguments: {intent: "add a=2 b=3.5", tool: "trusted.add"}});
  ok(text(e6).includes("5.5") && e6.structuredContent?.sum === 5.5, "trusted server: numbers filled; structured result kept");
  const e3 = await c.request("tools/call", {name: "run", arguments: {intent: "x", tool: "fake.echo", args: {text: 5}}});
  ok(e3.isError && text(e3).includes("expected string"), "downstream schema validated before proxying");
  const e4 = await c.request("tools/call", {name: "run", arguments: {intent: "something ambiguous"}});
  ok(!e4.isError && JSON.parse(text(e4)).status === "choose_tool", "low confidence over MCP");
  const e5 = await c.request("tools/call", {name: "run", arguments: {}});
  ok(e5.isError && text(e5).includes("args.intent: required"), "router's own input schema");
  const m1r = await c.request("tools/call", {name: "run", arguments: {intent: "x", tool: "modern.add", args: {a: 1, b: 2}}});
  ok(text(m1r).includes("3") && m1r.structuredContent?.sum === 3 && !("resultType" in m1r), "a 2026-07-28 downstream server is proxied");
  // a crashed downstream server comes back on the next call, at most once per REFLEX_ROUTER_RETRY_MS
  const call = (tool, args = {}) => c.request("tools/call", {name: "run", arguments: {intent: "x", tool, args}});
  const k1 = await call("trusted.crash");
  const k2 = await call("trusted.add", {a: 1, b: 1});
  ok(k1.isError && /exited/.test(text(k1)) && text(k2).includes("2"), "crashed downstream server restarted lazily");
  await call("trusted.crash");
  const k3 = await call("trusted.add", {a: 1, b: 1});
  ok(k3.isError && /is down .* next restart attempt/.test(text(k3)), "second crash inside the backoff: fails fast");
  const err = async (m, p) => { try { await c.request(m, p); return null; } catch (e) { return e.message; } };
  ok(/-32601/.test(await err("server/discover")) && /-32602/.test(await err("tools/call", {name: "nope"})), "unknown method / tool are protocol errors");
  c.close();
  // raw lines: garbage is answered, not fatal, and the last answer is flushed before exit on EOF
  const raw = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {env: {...ENV, ...routerEnv, REFLEX_ROUTER_CONFIG: join(tmp, "none.json")},
    input: 'null\n[1]\n{"jsonrpc":"2.0","id":7}\n{"jsonrpc":"2.0","id":null,"method":"ping"}\nnot json\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":null}\n' +
           '{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":' +
           `{"name":"describe_tool","arguments":{"name":"git_log"}}}\n`, encoding: "utf8", timeout: 10000});
  const replies = raw.stdout.trim().split("\n").map(l => JSON.parse(l));
  ok(raw.status === 0 && replies.length === 7 && replies.slice(0, 4).every(r => r.error?.code === -32600 && r.id !== undefined) &&
     replies[3].id === null && replies[4].error?.code === -32700 &&
     replies[5].result?.protocolVersion === VERSIONS[0] && replies[6].result?.content, "invalid requests (null id included) answered; exits cleanly after EOF");

  // downstream protocol eras (2026-07-28 stdio backward compatibility) and restarts, in process
  const fakeIn = era => ({command: process.execPath, args: [join(HERE, "test/fake-server.mjs"), era]});
  const echo = async d => (await d.request("tools/call", {name: "echo", arguments: {text: "hi"}})).content[0].text;
  for (const era of ["legacy", "modern", "silent"]) {
    const t0 = Date.now(), d = await connect(fakeIn(era), {name: era, probeMs: 300});
    ok(d.init.era === (era === "silent" ? "legacy" : era) && d.tools.length === 3 && (await echo(d)).endsWith(`era=${d.init.era}`),
       `downstream ${era} server: probe, then ${d.init.era} requests`);
    if (era === "modern") ok(d.init.protocolVersion === "2026-07-28" && d.init.capabilities?.tools, "modern: version from DiscoverResult");
    if (era === "silent") ok(Date.now() - t0 >= 300, "silent probe times out, then initialize");
    d.close();
  }
  const slow = await connect(fakeIn("slow"), {name: "slow", probeMs: 200});
  ok(slow.init.era === "modern" && (await echo(slow)).endsWith("era=modern"), "slow-starting modern server: short probe missed, initialize refused, re-probe connects");
  slow.close();
  ok(PROBE_MS === Number(ENV.REFLEX_ROUTER_PROBE_MS ?? 1000), "probe timeout: REFLEX_ROUTER_PROBE_MS, default 1 s");
  const future = await connect(fakeIn("future"), {name: "future"}).then(() => "connected", e => e.message);
  ok(/no common protocol version \(server: 2099-01-01/.test(future), "modern server without our version: error, no fallback to initialize");
  const rc = await reconnecting(fakeIn("modern"), {name: "rc", retryMs: 300});
  const pid0 = rc.pid;
  process.kill(pid0, "SIGKILL");
  await new Promise(res => setTimeout(res, 100));
  ok((await echo(rc)).includes("echo: hi") && rc.pid !== pid0, "server killed mid-session: next request restarts it");
  process.kill(rc.pid, "SIGKILL");
  await new Promise(res => setTimeout(res, 100));
  const fast = await echo(rc).then(() => "ran", e => e.message);
  await new Promise(res => setTimeout(res, 300));
  ok(/is down/.test(fast) && (await echo(rc)).includes("echo: hi"), "restart backoff: fails fast, then restarts after retryMs");
  rc.close();
  // a server upgraded between two starts: the restart re-reads its tools/list
  const upMarker = join(tmp, "upgraded"), restarted = [];
  const up = await reconnecting({...fakeIn("modern"), args: [...fakeIn("modern").args, upMarker]}, {name: "up", retryMs: 0, onRestart: t => restarted.push(t.length)});
  ok(up.tools.length === 3, "before the upgrade: 3 tools");
  writeFileSync(upMarker, "");
  process.kill(up.pid, "SIGKILL");
  await new Promise(res => setTimeout(res, 100));
  ok((await echo(up)).includes("echo: hi") && up.tools.length === 4 && up.tools.some(t => t.name === "upgraded") && restarted.join() === "4",
     "restart after an upgrade: tool list refreshed");
  up.close();

  // eval-router scoring: only what would execute wrongly fails
  const F = (args, missing = [], confidence = 0.9) => ({args, missing, confidence});
  const G = {tool: "git_log", args: {max_count: 5}};
  ok(score(G, "git_log", 0.9, F({max_count: 5})) === "ok", "score: expected tool and args run");
  ok(score(G, null, 0.3, null) === "held" && score(G, "git_log", 0.9, F({}, ["max_count"])) === "held" &&
     score(G, "git_log", 0.9, F({max_count: 5}, [], 0.3)) === "held" && score(G, "git_diff", 0.9, F({}, ["ref"])) === "held", "score: holds are safe");
  ok(score(G, "git_diff", 0.9, F({})) === "unsafe" && score(G, "git_log", 0.9, F({max_count: 7})) === "unsafe", "score: wrong tool / args run");
  ok(score({tool: null}, "git_log", 0.9, F({})) === "unsafe" && score({tool: null}, null, 0.2, null) === "ok", "score: ran where a hold was expected");
  console.log(process.exitCode ? "router selfcheck FAILED" : "router selfcheck OK");
}

// Scoring one golden case. What matters is what would execute: the wrong tool or wrong arguments
// run, or a run where the golden expects a hold, is `unsafe` and fails the eval. The router holding
// back (choose_tool, needs_args) where the golden expected a run is `held`: reported, not a failure,
// since nothing runs and the agent is asked. `ok` is the expected tool with the expected arguments.
export function score(c, tool, confidence, f) {
  const runs = !!tool && !!f && !f.missing.length && Math.min(confidence, f.confidence) >= R.minConfidence;
  const toolOk = [].concat(c.tool).includes(tool);
  const argsOk = !!f && Object.entries(c.args ?? {}).every(([k, v]) => f.args[k] === v) && (c.absent ?? []).every(k => !(k in f.args));
  if (c.tool === null) return runs ? "unsafe" : "ok";
  if (!runs) return "held";
  return toolOk && argsOk ? "ok" : "unsafe";
}

// Live: route every golden intent with real Jev over all command tools (on PATH or not) and score
// the tool and the filled arguments. Nothing runs. Exit 1 on any unsafe outcome.
async function evalRouter(file) {
  const golden = JSON.parse(readFileSync(file, "utf8")), cat = commandTools(true);
  const results = await Promise.all(golden.cases.map(async c => {
    const s = await select(c.intent, cat), best = s.ranked[0];
    const tool = best && best.name !== NONE && best.p >= R.minConfidence ? best.name : null;
    const f = tool ? await fillArgs(c.intent, cat.find(t => t.name === tool)) : null;
    return {intent: c.intent, want: c.tool, tool, p: best?.p, args: f?.args, missing: f?.missing, confidence: f?.confidence,
            verdict: score(c, tool, s.confidence, f)};
  }));
  for (const r of results) console.log(`${r.verdict.padEnd(6)} ${r.intent.slice(0, 60).padEnd(60)} ` +
    `${String(r.tool)} p=${r.p} ${JSON.stringify(r.args ?? {})}${r.missing?.length ? ` missing=${r.missing}` : ""}${r.confidence != null ? ` argp=${r.confidence}` : ""}`);
  const n = v => results.filter(r => r.verdict === v).length;
  console.log(`\n${results.length} intents · ok ${n("ok")} · held ${n("held")} (asked instead of running; safe) · ` +
              `unsafe ${n("unsafe")} (wrong tool or args would run, or ran where a hold was expected) · model ${CONFIG.model}`);
  if (n("unsafe")) process.exitCode = 1;
}

const main = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
const optIdx = process.argv.indexOf("--check");
if (main && process.argv.includes("--selfcheck")) await selfcheck();
else if (main && process.argv.includes("--eval")) await evalRouter(process.argv[process.argv.indexOf("--eval") + 1] ?? join(HERE, "golden.json"));
else if (main && optIdx > -1) {
  // Try one intent against real Jev without an agent: node router/server.mjs --check "<intent>" [--run]
  const intent = process.argv[optIdx + 1], cat = await catalog();
  const out = process.argv.includes("--run") ? await run(cat, {intent}) : await findTools(cat, {intent});
  console.log(JSON.stringify(out, (k, v) => k === "client" ? undefined : v, 1));
  for (const c of clients) c.close();
}
else if (main) serve();
