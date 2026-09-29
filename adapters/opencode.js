// Reflex plugin for opencode (https://opencode.ai/docs/plugins).
// Installed by `node install.mjs --agent opencode` into ~/.config/opencode/plugins/reflex.js.
//
// opencode 1.4 plugins can block a tool call (throw) but cannot open a permission prompt, so an
// "ask" blocks with a reason that tells the agent to get the user's confirmation first.
//
// Conditional instructions: chat.message sees each new user message and picks the fragments that
// apply; experimental.chat.system.transform appends them to the system prompt of every model call
// in that session until the next user message, so compaction cannot drop them.
//
// Injection guard (guard.mjs): tool.execute.after sends each result of a tool that can carry
// third-party text to the guard and edits it in place (output.output; an MCP tool's hook output is
// the raw CallToolResult, so its content[].text): block replaces the offending text, warn appends
// a note. chat.message checks each prompt for pasted credentials; a block throws, which is the only
// way a plugin can stop a message in opencode 1.4 (it surfaces as an error).
//
// The same file is the opencode npm plugin ("plugin": ["@ursuciprian/reflex"] in opencode.json;
// package.json "main" points here). Unfilled, it runs the gate next to it with `node` from PATH (opencode
// itself runs on Bun), and the gate reads the mode and allow on every call from the environment or
// $XDG_CONFIG_HOME/reflex/config.json, as for any hook without flags. It stands down when `reflex setup` wrote the plugin file into opencode's global
// plugins directory and that file's gate exists, so no call is judged twice.
import {spawnSync} from "node:child_process";
import {existsSync, readFileSync} from "node:fs";
import {homedir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";

const FILLED = "__REFLEX_GATE__".endsWith("gate.mjs");   // install.mjs replaced the placeholders
const XDG = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
const saved = key => { try { return JSON.parse(readFileSync(join(XDG, "reflex/config.json"), "utf8"))[key]; } catch { return undefined; } };
const GATE = process.env.REFLEX_GATE ?? (FILLED ? "__REFLEX_GATE__" : fileURLToPath(new URL("../gate.mjs", import.meta.url)));
const NODE = process.env.REFLEX_NODE ?? (FILLED ? "__REFLEX_NODE__" : "node");
// Unfilled, no --mode/--allow is passed: the gate reads them per call, so a change applies without a restart.
const MODE = FILLED ? process.env.REFLEX_MODE ?? "__REFLEX_MODE__" : null;
const ALLOW = FILLED ? process.env.REFLEX_ALLOW ?? "__REFLEX_ALLOW__" : null;
const mode = () => MODE ?? process.env.REFLEX_MODE ?? saved("mode") ?? "shadow";
// The file `reflex setup --agent opencode` writes, where opencode loads it, with a gate that still
// exists (a stale file gates nothing, so the npm plugin keeps running). Not exported: opencode calls
// every exported function as a plugin.
function setupPluginLive(file = join(XDG, "opencode/plugins/reflex.js")) {
  try { const gate = readFileSync(file, "utf8").match(/"(\/[^"]*\/gate\.mjs)"/)?.[1]; return !!gate && existsSync(gate); }
  catch { return false; }
}
const INSTRUCTIONS = GATE.replace(/gate\.mjs$/, "instructions.mjs");
const GUARD = GATE.replace(/gate\.mjs$/, "guard.mjs");
// Every script runs through hook.mjs, so an error while it loads still gives a JSON answer (fails closed).
const HOOK = GATE.replace(/gate\.mjs$/, "hook.mjs");
// 0: the default; with System 2 on, install.mjs writes how long a gate call may take (Jev plus the judge).
const GATE_TIMEOUT_MS = Number("__REFLEX_GATE_TIMEOUT_MS__") || 15000;
const selected = new Map();   // sessionID -> injected text. ponytail: never pruned; one short string per session.
// Built-in tools: those that only touch the user's own work are not sent to the guard; any tool
// not built in is an MCP (or plugin) tool. ponytail: a list per opencode version.
const LOCAL_TOOLS = new Set(["edit", "write", "apply_patch", "grep", "glob", "todowrite", "task", "skill", "lsp", "invalid", "question", "plan_exit"]);
const BUILTIN = new Set([...LOCAL_TOOLS, "bash", "read", "webfetch", "websearch", "codesearch", "list", "multiedit", "patch", "todoread"]);
const WRITE_TOOLS = new Set(["write", "edit", "multiedit", "apply_patch", "patch"]);
// A subagent (task) runs in a child session. Taint and decisions are kept under the root session,
// so a child that read an injection makes its parent stricter and a tainted parent's children
// start strict. ponytail: never pruned; one short string per session.
const roots = new Map();
async function rootOf(client, id) {
  if (!id || !client?.session?.get) return id;
  if (!roots.has(id)) {
    let root = id;
    try {
      for (let s = id, i = 0; s && i < 8; i++) {
        const r = await Promise.race([client.session.get({path: {id: s}}), new Promise(res => setTimeout(res, 1000).unref?.())]);
        if (!r) return root;   // timed out: not cached, asked again next time
        const parent = (r.data ?? r)?.parentID;
        if (!parent) break;
        root = s = parent;
      }
    } catch { return root; }
    roots.set(id, root);
  }
  return roots.get(id);
}

// The guard's verdict on one result, applied to the hook's output in place.
function guardResult(input, output, directory, session_id) {
  if (LOCAL_TOOLS.has(input.tool) || !output) return;
  const parts = typeof output.output === "string" ? null : Array.isArray(output.content) ? output.content : null;
  const slots = parts ? parts.flatMap(c => typeof c?.text === "string" ? [[c, "text"]] : typeof c?.resource?.text === "string" ? [[c.resource, "text"]] : [])
    : typeof output.output === "string" ? [[output, "output"]] : [];
  const texts = slots.map(([o, k]) => o[k]);
  if (!texts.some(t => t.trim())) return;
  let d;
  try {
    d = JSON.parse(gate("--scan", {agent: "opencode", tool: input.tool, input: input.args, texts, cwd: directory,
      session_id, call_id: input.callID, mcp: !BUILTIN.has(input.tool)}, GUARD));
  } catch { return; }
  if (d.effective === "block" && Array.isArray(d.texts)) slots.forEach(([o, k], i) => { o[k] = d.texts[i] ?? ""; });
  if (d.effective === "block" || d.effective === "warn") {
    if (parts) parts.push({type: "text", text: d.note});
    else output.output += `\n\n${d.note}`;
  }
}

function gate(flag, payload, script = GATE) {
  const args = !FILLED ? [script, flag] : script === GATE ? [script, flag, "--mode", MODE, "--allow", ALLOW] : [script, flag, "--mode", MODE];
  // the guard: an 8 s Jev budget plus node start; the gate: Jev, and System 2 when it is on
  const r = spawnSync(NODE, [HOOK, ...args], {input: JSON.stringify(payload), encoding: "utf8", timeout: script === GATE ? GATE_TIMEOUT_MS : 15000});
  return r.error ? "" : r.stdout;   // not started, or killed at the timeout: no answer
}

export const Reflex = async ({directory, client}) => !FILLED && setupPluginLive() ? {} : ({
  "chat.message": async (input, output) => {
    const prompt = (output.parts ?? []).filter(p => p.type === "text" && !p.synthetic).map(p => p.text).join("\n");
    if (!prompt.trim()) return;
    let p = null;
    try { p = JSON.parse(gate("--prompt", {agent: "opencode", prompt, session_id: input.sessionID}, GUARD)); }
    catch { /* the credential check could not run: the prompt goes on */ }
    if (p?.effective === "block") throw new Error(p.reason);
    let r = null;
    try { r = JSON.parse(gate("--select", {agent: "opencode", prompt, cwd: directory, session_id: input.sessionID}, INSTRUCTIONS)); }
    catch { /* instructions are advisory: nothing is injected */ }
    selected.set(input.sessionID, r?.text ?? "");
  },
  "experimental.chat.system.transform": async (input, output) => {
    const text = input.sessionID && selected.get(input.sessionID);
    if (text) output.system.push(text);
  },
  "tool.execute.before": async (input, output) => {
    if (input.tool === "task") {
      // Subgoal dedup: a subagent asked to repeat work already delegated in this session.
      const a = output.args ?? {};
      if (!a.prompt || a.task_id) return;   // task_id resumes earlier work on purpose
      let d;
      try {
        d = JSON.parse(gate("--decide", {agent: "opencode", subgoal: [a.subagent_type && `agent: ${a.subagent_type}`, a.description, a.prompt]
          .filter(Boolean).join("\n"), cwd: directory, session_id: input.sessionID, call_id: input.callID}));
      } catch { return; }   // dedup saves work; it never blocks when the gate cannot run
      if (d.effective === "deny") throw new Error(d.reason);
      return;
    }
    // The tool gate: file writes (a protected path asks) and MCP tools (any tool not built in).
    const tool = WRITE_TOOLS.has(input.tool) || !BUILTIN.has(input.tool);
    if (input.tool !== "bash" && !tool) return;
    let d;
    try {
      d = JSON.parse(gate("--decide", tool
        ? {agent: "opencode", tool: input.tool, input: output.args ?? {}, mcp: !BUILTIN.has(input.tool), cwd: directory,
           session_id: await rootOf(client, input.sessionID), call_id: input.callID}
        : {agent: "opencode", command: output.args?.command,
           cwd: output.args?.workdir || directory, session_id: await rootOf(client, input.sessionID), call_id: input.callID}));
    } catch {
      // No JSON answer (the gate did not start, timed out or crashed before hook.mjs could answer): an
      // ask, except in shadow and off, which never get in the way.
      d = ["shadow", "off"].includes(mode()) ? {effective: "pass"}
        : {effective: "ask", reason: "reflex error: the gate gave no decision; a human must review"};
    }
    // pass and allow both run: opencode has no prompt of its own here to skip. Anything else asks.
    if (d?.effective === "deny") throw new Error(d.reason);
    if (!["pass", "allow"].includes(d?.effective)) throw new Error(`${d?.reason ?? "reflex error: the gate gave no decision; a human must review"}. This plugin cannot open an approval dialog. ${tool
      ? "The user can make this change or run this tool themselves."
      : "The user can review and run the exact command with reflex run in their own terminal (include --cwd)."} A chat confirmation does not unblock this plugin; do not retry or disable it.`);
  },
  "tool.execute.after": async (input, output) => {
    // A task that ran is a launched subgoal: dedup offers only those.
    if (input.tool === "task") return void gate("--record", {agent: "opencode", event: "ran", session_id: input.sessionID, call_id: input.callID});
    if (input.tool === "bash") gate("--record", {agent: "opencode", event: "ran", session_id: input.sessionID, call_id: input.callID,
                                                 exit_code: output?.metadata?.exit ?? null});
    guardResult(input, output, directory, await rootOf(client, input.sessionID));
  },
});
