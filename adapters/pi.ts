// Reflex extension for pi and oh-my-pi. The same file works in both; install.mjs copies it to
// ~/.pi/agent/extensions/reflex.ts and ~/.omp/agent/extensions/reflex.ts with the paths filled in.
//
// tool_call runs before every tool. For bash, Reflex decides: pass, ask (native confirm dialog),
// or deny (the call is blocked and the model sees the reason). Without a UI (print/json mode) an
// ask cannot be answered, so it blocks.
//
// before_agent_start runs once per user prompt: instructions.mjs picks the conditional instruction
// fragments that apply, and they are appended to that turn's system prompt, so they are back on
// every prompt where the condition holds and never lost to compaction. Any failure adds nothing.
//
// Injection guard (guard.mjs): tool_result sends each result of a tool that can carry third-party
// text to the guard; a block replaces the result's text with the neutralised text (tool_result
// may patch content), a warn appends a note. input checks each prompt for pasted credentials; a
// block drops it (pi: {action: "handled"}, omp: {handled: true}) and says why in a notification.
// Any failure leaves the result or prompt as it was.
import {spawn} from "node:child_process";

const GATE = process.env.REFLEX_GATE ?? "__REFLEX_GATE__";
const NODE = process.env.REFLEX_NODE ?? "__REFLEX_NODE__";
const MODE = process.env.REFLEX_MODE ?? "__REFLEX_MODE__";
const ALLOW = process.env.REFLEX_ALLOW ?? "__REFLEX_ALLOW__";
const AGENT = "__REFLEX_AGENT__";
// 0: the default; with System 2 on, install.mjs writes the gate's budget, capped under omp's 30 s.
const GATE_TIMEOUT_MS = Number("__REFLEX_GATE_TIMEOUT_MS__") || 20_000;
const INSTRUCTIONS = GATE.replace(/gate\.mjs$/, "instructions.mjs");
const GUARD = GATE.replace(/gate\.mjs$/, "guard.mjs");
// Every script runs through hook.mjs, so an error while it loads still gives a JSON answer (fails closed).
const HOOK = GATE.replace(/gate\.mjs$/, "hook.mjs");
// Tools whose results are the user's own work, never third-party text: not sent to the guard.
const LOCAL_TOOLS = new Set(["edit", "write", "grep", "find", "ls", "task", "todo", "todo_write", "goal", "ask"]);

// pass and allow both run: pi and omp have no prompt of their own for bash to skip.
type Decision = {effective: "pass" | "allow" | "ask" | "deny"; reason?: string};

function gate(flag: string, payload: unknown, signal?: AbortSignal, script = GATE): Promise<string> {
  return new Promise(resolve => {
    const args = script === GATE ? [script, flag, "--mode", MODE, "--allow", ALLOW] : [script, flag, "--mode", MODE];
    const p = spawn(NODE, [HOOK, ...args], {signal, stdio: ["pipe", "pipe", "ignore"]});
    let out = "";
    const t = setTimeout(() => p.kill("SIGKILL"), script === GATE ? GATE_TIMEOUT_MS : 20_000);   // omp gives a handler 30 s
    p.stdout.on("data", d => (out += d));
    p.on("error", () => { clearTimeout(t); resolve(""); });
    p.on("close", () => { clearTimeout(t); resolve(out); });
    p.stdin.end(JSON.stringify(payload));
  });
}

function lastAssistantText(ctx: any): string | undefined {
  const branch = ctx.sessionManager?.getBranch?.() ?? [];
  for (let i = branch.length - 1; i >= 0; i--) {
    const m = branch[i]?.type === "message" ? branch[i].message : undefined;
    if (m?.role === "assistant") {
      const text = (m.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
      if (text.trim()) return text;
    }
  }
}

// Paths the agent's recent tool calls touched (read, edit and write all take a path argument).
function recentFiles(ctx: any): string[] {
  const files: string[] = [];
  for (const e of (ctx.sessionManager?.getBranch?.() ?? []).slice(-40)) {
    const m = e?.type === "message" ? e.message : undefined;
    for (const c of m?.role === "assistant" ? m.content ?? [] : []) {
      const p = c?.type === "toolCall" ? c.arguments?.path ?? c.arguments?.file_path : undefined;
      if (typeof p === "string") files.push(p);
    }
  }
  return [...new Set(files.reverse())].slice(0, 10);
}
// omp's task tool spawns subagents: {task, agent?} or a batch {context, tasks: [{task, agent?}]}.
// Each task is its own subgoal (the batch's shared context, cut short, goes with each), so a batch
// that repeats one earlier task loses only that task: the tool runs with the rest (a tool_call
// handler may replace the input) and its result says which were left out and why. pi has no
// subagents, so this never fires there.
function subgoalsOf(input: any): string[] {
  const batch = Array.isArray(input?.tasks);
  const context = batch && typeof input.context === "string" && input.context.trim() ? `context: ${input.context.slice(0, 200)}` : "";
  return (batch ? input.tasks : [input]).map((t: any) => typeof t?.task === "string" && t.task.trim()
    ? [t.agent && `agent: ${t.agent}`, t.task, context].filter(Boolean).join("\n") : "");
}
const dropped = new Map<string, string>();   // toolCallId -> why some batch tasks were left out

// The guard's verdict on one result -> the content the model sees, or undefined to leave it.
async function guardResult(event: any, ctx: any) {
  if (LOCAL_TOOLS.has(event.toolName)) return;
  const blocks: any[] = event.content ?? [];
  const isText = (c: any) => c?.type === "text" && typeof c.text === "string";
  const texts = blocks.filter(isText).map(c => c.text);
  if (!texts.some(t => t.trim())) return;
  let d: {effective?: string; texts?: string[]; note?: string};
  try {
    d = JSON.parse(await gate("--scan", {agent: AGENT, tool: event.toolName, input: event.input, texts, cwd: ctx?.cwd,
      session_id: ctx?.sessionManager?.getSessionId?.(), call_id: event.toolCallId, mcp: /^mcp[_:.]/.test(event.toolName)}, ctx?.signal, GUARD));
  } catch { return; }
  const note = {type: "text", text: `\n${d.note}`};
  if (d.effective === "block" && Array.isArray(d.texts)) {
    let i = 0;
    return {content: [...blocks.map(c => isText(c) ? {...c, text: d.texts![i++] ?? ""} : c), note]};
  }
  if (d.effective === "warn") return {content: [...blocks, note]};
}

export default function (pi: any) {
  pi.on("input", async (event: any, ctx: any) => {
    const text = event?.text ?? event?.prompt;
    if (typeof text !== "string" || !text.trim()) return;
    let r: {effective?: string; reason?: string};
    try {
      r = JSON.parse(await gate("--prompt", {agent: AGENT, prompt: text, session_id: ctx?.sessionManager?.getSessionId?.()}, ctx?.signal, GUARD));
    } catch { return; }
    if (r.effective !== "block") return;
    try { ctx?.ui?.notify?.(r.reason, "error"); } catch { /* no UI: the prompt is still dropped */ }
    return {action: "handled", handled: true};   // pi reads action, omp reads handled
  });

  pi.on("before_agent_start", async (event: any, ctx: any) => {
    let r: {text?: string};
    try {
      r = JSON.parse(await gate("--select", {agent: AGENT, prompt: event.prompt, cwd: ctx.cwd,
                                             recent_files: recentFiles(ctx)}, ctx.signal, INSTRUCTIONS));
    } catch { return; }
    if (!r?.text) return;
    // pi passes the system prompt as a string, omp as an array of sections.
    const sp = event.systemPrompt;
    return {systemPrompt: Array.isArray(sp) ? [...sp, r.text] : `${sp ?? ""}\n\n${r.text}`};
  });

  pi.on("tool_call", async (event: any, ctx: any) => {
    if (event.toolName === "task") {
      const subgoals = subgoalsOf(event.input), batch = Array.isArray(event.input?.tasks);
      if (!subgoals.length || subgoals.some(s => !s)) return;   // malformed: omp's own validation answers
      let d: Decision & {drop?: number[]};
      try {
        d = JSON.parse(await gate("--decide", {agent: AGENT, ...(batch ? {subgoals} : {subgoal: subgoals[0]}), cwd: ctx.cwd,
                                               call_id: event.toolCallId, session_id: ctx.sessionManager?.getSessionId?.()}, ctx.signal));
      } catch { return; }   // dedup saves work; it never blocks when the gate cannot run
      if (d.effective === "deny") return {block: true, reason: d.reason};
      if (batch && d.drop?.length) {
        dropped.set(event.toolCallId, d.reason ?? "");
        return {input: {...event.input, tasks: event.input.tasks.filter((_: any, i: number) => !d.drop!.includes(i))}};
      }
      return;
    }
    // The tool gate: file writes (a protected path asks) and MCP calls (pi-mcp-adapter's mcp proxy, mcp_* tools).
    const tool = ["edit", "write"].includes(event.toolName) || event.toolName === "mcp" || /^mcp[_:.]/.test(event.toolName);
    if (!tool && (event.toolName !== "bash" || !event.input?.command)) return;
    let d: Decision;
    try {
      d = JSON.parse(await gate("--decide", tool
        ? {agent: AGENT, tool: event.toolName, input: event.input ?? {}, cwd: ctx.cwd, call_id: event.toolCallId,
           session_id: ctx.sessionManager?.getSessionId?.(), intent: lastAssistantText(ctx)}
        : {agent: AGENT, command: event.input.command, cwd: event.input.cwd ?? ctx.cwd,
           call_id: event.toolCallId, session_id: ctx.sessionManager?.getSessionId?.(), intent: lastAssistantText(ctx)}, ctx.signal));
    } catch {
      // No JSON answer (the gate did not start, was killed at the timeout, or crashed before hook.mjs
      // could answer): an ask, except in shadow and off, which never get in the way.
      if (["shadow", "off"].includes(MODE)) return;
      d = {effective: "ask", reason: "reflex error: the gate gave no decision; a human must review"};
    }
    if (d?.effective === "deny") return {block: true, reason: d.reason};
    if (!["pass", "allow"].includes(d?.effective)) {   // ask, or an answer that is not a decision
      d = {effective: "ask", reason: d?.reason ?? "reflex error: the gate gave no decision; a human must review"};
      if (!ctx.hasUI) return {block: true, reason: `${d.reason}. Needs human approval and there is no UI to ask.`};
      const ok = tool ? await ctx.ui.confirm(`Reflex: run ${event.toolName}?`, `${JSON.stringify(event.input ?? {}).slice(0, 600)}\n\n${d.reason}`)
        : await ctx.ui.confirm("Reflex: run this command?", `${event.input.command}\n\n${d.reason}`);
      if (!ok) {
        await gate("--record", {agent: AGENT, event: "denied", call_id: event.toolCallId, session_id: ctx.sessionManager?.getSessionId?.()});
        return {block: true, reason: `${d.reason}. The user declined.`};
      }
    }
  });

  pi.on("tool_result", async (event: any, ctx: any) => {
    // A task that ran is a launched subgoal; one that failed or was blocked is not.
    if (event.toolName === "task") {
      gate("--record", {agent: AGENT, event: event.isError ? "failed" : "ran", call_id: event.toolCallId, session_id: ctx?.sessionManager?.getSessionId?.()});
      const note = dropped.get(event.toolCallId);
      if (!note) return;
      dropped.delete(event.toolCallId);
      return {content: [...(event.content ?? []), {type: "text", text: `\n[reflex] Some tasks were not started: ${note}`}]};
    }
    if (event.toolName === "bash") {
      const text = (event.content ?? []).map((c: any) => c.text ?? "").join("");
      const exit = typeof event.details?.exitCode === "number" ? event.details.exitCode            // omp
        : event.isError ? Number(/Command exited with code (\d+)/.exec(text)?.[1] ?? -1) : 0;      // pi
      gate("--record", {agent: AGENT, event: "ran", call_id: event.toolCallId, exit_code: exit});
    }
    return guardResult(event, ctx);
  });
}
