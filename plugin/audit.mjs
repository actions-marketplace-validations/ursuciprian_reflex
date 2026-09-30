#!/usr/bin/env node
// reflex audit: one row per decision the gate logged, for change management evidence (SOC 2, ISO 27001).
// Read-only over the trace (trace*.jsonl, rotated files included), the approval queue and the
// execution feedback; it writes nothing and calls nothing. Commands and reasons are redacted again.
//
//   reflex audit [--since 7d] [--format csv|json|jsonl] [--prod-only] [--agent claude-code]
import {readdirSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {CONFIG, jsonLines, redact} from "./gate.mjs";
import {listItems} from "./autonomy.mjs";
import {isMain} from "./failsafe.mjs";

const argv = process.argv.slice(2);
const die = s => { console.error(`reflex audit: ${s}`); process.exit(2); };
const opt = (n, d) => { const i = argv.indexOf(n); if (i < 0) return d; if (argv[i + 1] === undefined || argv[i + 1].startsWith("--")) die(`${n} needs a value`); return argv[i + 1]; };
const known = new Set(["--since", "--format", "--agent", "--prod-only"]);
// The script itself runs only when started (node audit.mjs), never when the file is imported.
if (isMain(import.meta)) {
for (const [i, a] of argv.entries()) if (a.startsWith("--") && !known.has(a)) die(`unknown option ${a}`); else if (!a.startsWith("--") && !["--since", "--format", "--agent"].includes(argv[i - 1])) die(`unexpected ${a}`);
const window = opt("--since", "7d"), m = /^(\d+)([dhm])?$/.exec(window);
if (!m) die("--since takes a number and d, h or m (7d, 12h, 30m)");
const since = Date.now() - Number(m[1]) * {d: 864e5, h: 36e5, m: 6e4}[m[2] ?? "d"];
const format = opt("--format", "csv"), agent = opt("--agent"), prodOnly = argv.includes("--prod-only");
if (!["csv", "json", "jsonl"].includes(format)) die("--format is csv, json or jsonl");

const lines = name => { try { return jsonLines(readFileSync(join(CONFIG.data, name), "utf8")); } catch { return []; } };
let names = [];
try { names = readdirSync(CONFIG.data).filter(n => /^trace(\.\d+)?\.jsonl$/.test(n)); } catch { /* no data yet */ }
const trace = names.flatMap(lines).filter(r => r.tag !== "subgoal" && Date.parse(r.ts) >= since &&
  (!agent || r.agent === agent) && (!prodOnly || r.tier?.prod === true)).sort((a, b) => a.ts.localeCompare(b.ts));
const feedback = lines("feedback.jsonl"), items = new Map(listItems().map(i => [i.id, i]));
const ran = new Set(feedback.filter(r => ["ran", "failed"].includes(r.event ?? "ran")).map(r => r.call_id).filter(Boolean));
const rejected = new Set(feedback.filter(r => r.event === "denied").map(r => r.call_id).filter(Boolean));

// Who approved or answered it, when that is known: a human in the approval queue, System 2, or the
// agent's own prompt (the command ran after an ask, or the agent reported the prompt was refused).
function approval(r) {
  // A queue id is reused when the same command is parked again: the item counts only while it is the
  // one this row parked or used (same created time; rows from before that field was logged match by id).
  const L = r.ladder ?? {}, found = L.queue && items.get(L.queue);
  const it = found && (!L.queue_created || found.created === L.queue_created) ? found : null;
  const who = it ? `${it.decided_by ? ` by ${it.decided_by}` : ""}${it.decided_at ? ` at ${it.decided_at}` : ""}` : "";
  if (r.source === "queue") return `${L.answered ?? "answered"} in the approval queue (${L.queue}${who || (L.decided_at ? ` at ${L.decided_at}` : "")})`;
  if (L.queue && !it) return `parked in the approval queue (${L.queue}); its answer is no longer on record`;
  if (it) {
    const expired = it.expires && Date.now() > Date.parse(it.expires);
    return it.status === "pending" ? `waiting in the approval queue (${it.id})`
      : it.status === "used" ? `approved in the approval queue (${it.id}${who}), then run`
      : `${it.status === "denied" ? "denied" : "approved"} in the approval queue (${it.id}${who})${expired ? `, expired ${it.expires}${it.status === "approved" ? " unused" : ""}` : ""}`;
  }
  if (["approve", "deny"].includes(L.judge?.verdict))
    return `${L.dry ? "System 2 would " : "System 2 "}${L.judge.verdict === "approve" ? (L.dry ? "approve" : "approved") : (L.dry ? "deny" : "denied")}` +
      `${L.judge.confidence != null ? ` (confidence ${L.judge.confidence})` : ""}${L.dry ? " (shadow)" : ""}`;
  if (r.emitted === "ask" && r.call_id)
    return rejected.has(r.call_id) ? "rejected at the agent's prompt" : ran.has(r.call_id) ? "approved at the agent's prompt (it ran)" : "no answer recorded";
  return "";
}
const rows = trace.map(r => ({time: r.ts, agent: r.agent ?? "", session: r.session_id ?? "", cwd: redact(r.cwd ?? r.state?.call?.cwd ?? ""),
  env_tier: !r.tier ? "unknown" : r.tier.prod ? "prod" : "non-prod", env_reason: redact(r.tier?.why ?? ""),
  command: redact(r.state?.call?.command ?? ""), decision: r.emitted ?? "pass", judged: r.decision ?? "", mode: r.mode ?? "",
  source: r.source ?? "", rule_id: r.rule_id ?? "", rule: redact(r.rule ?? ""), approved_by: approval(r)}));

// A cell a spreadsheet would run as a formula (=, +, -, @, tab, CR) starts with a quote.
const cell = v => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
const COLUMNS = ["time", "agent", "session", "cwd", "env_tier", "env_reason", "command", "decision", "judged", "mode", "source", "rule_id", "rule", "approved_by"];
if (format === "json") console.log(JSON.stringify(rows, null, 1));
else if (format === "jsonl") for (const r of rows) console.log(JSON.stringify(r));
else console.log([COLUMNS.join(","), ...rows.map(r => COLUMNS.map(c => cell(r[c])).join(","))].join("\n"));
}
