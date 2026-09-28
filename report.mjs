#!/usr/bin/env node
// What the gate and the injection guard have been doing, and what a policy change would do. No API calls.
//
//   node report.mjs                         summary of the last 7 days
//   node report.mjs --since 30              ... of the last 30 days
//   node report.mjs --list ask              the commands that got "ask" (or pass / deny)
//   node report.mjs --policy candidate.json replay stored answers through another policy
//   node report.mjs --push http://localhost:9091   also push metrics to a Prometheus Pushgateway
//   node report.mjs --calibration           how well blast / mutates predict your approvals (ECE)
import {existsSync, readFileSync} from "node:fs";
import {join} from "node:path";
import {CONFIG, load, promptKey, rulesHit, setupFile} from "./gate.mjs";
import {compile} from "./policy.mjs";
import {budgetState} from "./judge2.mjs";
import {alwaysHuman, breaker, listItems, runawayTrips} from "./autonomy.mjs";
import {template} from "./judge2.mjs";

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
const rows = f => existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
const since = Date.now() - Number(arg("--since", 7)) * 864e5;
// Subgoal checks (tag "subgoal") are counted apart: they are not commands and have no policy to replay.
const logged = rows(join(CONFIG.data, "trace.jsonl")).filter(r => Date.parse(r.ts) >= since);
const trace = logged.filter(r => r.tag !== "subgoal"), subgoals = logged.filter(r => r.tag === "subgoal");
const feedback = rows(join(CONFIG.data, "feedback.jsonl"));
const ran = new Set(feedback.filter(r => r.event === "ran" || r.event === "failed" || r.event == null).map(r => r.call_id ?? r.tool_use_id));
const denied = new Set(feedback.filter(r => r.event === "denied").map(r => r.call_id ?? r.tool_use_id).filter(Boolean));
// Claude Code's PermissionRequest hook: the dialogs it actually showed, by session and command.
const prompted = feedback.filter(r => r.event === "prompted");
const promptedSince = prompted.map(r => r.ts).sort()[0];
const policy = compile(JSON.parse(readFileSync(arg("--policy", setupFile("policy.json")), "utf8")));

const count = (list, key) => list.reduce((m, r) => { const k = key(r); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const q = (xs, p) => xs.length ? xs[Math.min(xs.length - 1, Math.floor(p * xs.length))] : 0;
const jev = trace.filter(r => r.source === "jev");
const lat = jev.map(r => r.latency_s).sort((a, b) => a - b);
// Missing execution feedback can mean an abandoned session or a lost event, never a rejection.
const asks = trace.filter(r => r.emitted === "ask");
const verdict = r => {
  const id = r.call_id ?? r.tool_use_id;
  return id && denied.has(id) ? "rejected" : id && ran.has(id) ? "approved"
    : Date.now() - Date.parse(r.ts) > 6e5 ? "unknown" : "pending";
};
const resolved = count(asks, verdict);
// Replay: stored Jev answers through the chosen policy; rule and fast-lane decisions are code.
// Policy is compared with policy: the logged policy_decision is what the policy said before
// REFLEX_ALLOW and the allow guards applied (older rows only have the decision).
const replayed = jev.map(r => ({r, now: policy.decide(r.answers, policy.values()).outcome}));
const changed = replayed.filter(x => x.now !== (x.r.policy_decision ?? x.r.decision));

// Calibration: the Jev-judged commands a human ruled on, approved when the command then ran:
// asks Reflex emitted in enforce mode, and commands allow would have let through (logged
// would_allow, or allow on replay) in Claude Code, the one agent where a pass still meets a
// prompt, but only when its PermissionRequest hook saw that prompt (within 10 minutes): a pass
// its allowlist or permission mode let through never met a human. Rows older than the first
// PermissionRequest record predate the hook; there, as before, any would-be allow in default
// mode counts. ponytail: the first record marks the install, per machine rather than per session.
// Commands actually allowed ran without a human, so they carry no label; nor do would-be allows in
// a permission mode other than default (acceptEdits, auto, bypassPermissions, plan).
const shown = r => !promptedSince || r.ts < promptedSince || prompted.some(p => p.session_id === r.session_id && p.ts >= r.ts &&
  Date.parse(p.ts) - Date.parse(r.ts) < 6e5 && p.key === promptKey(r.state?.call?.command ?? ""));
const humanLabels = replayed.filter(({r, now}) => r.emitted !== "allow" && r.answers?.blast?.score != null &&
    ((r.emitted === "ask" && r.mode === "enforce") || (r.agent === "claude-code" && [undefined, null, "default"].includes(r.permission_mode) &&
      (now === "allow" || r.decision === "would_allow") && shown(r))))
  .map(({r}) => ({blast: r.answers.blast.score, conf: r.answers.blast.confidence ?? 0, mutates: r.answers.mutates?.noul, v: verdict(r)}))
  .filter(x => ["approved", "rejected"].includes(x.v)).map(x => ({...x, ok: x.v === "approved" ? 1 : 0}));
// System 2's verdicts label the commands Jev was unsure about, from day one: its approve or deny,
// next to Jev's answers in the same trace row. This is how the autonomous profile bootstraps the
// calibration a human would otherwise supply one prompt at a time. Errors and "human" are no label.
const judged = trace.filter(r => ["approve", "deny"].includes(r.ladder?.judge?.verdict) && r.answers?.blast?.score != null);
const systemLabels = judged.map(r => ({blast: r.answers.blast.score, conf: r.answers.blast.confidence ?? 0, mutates: r.answers.mutates?.noul,
  v: "system2", ok: r.ladder.judge.verdict === "approve" ? 1 : 0}));
const labelled = [...humanLabels, ...systemLabels];
const rate = xs => xs.length ? `${xs.filter(x => x.ok).length}/${xs.length} (${Math.round(100 * xs.filter(x => x.ok).length / xs.length)}%)` : "-";
const bucket = (xs, f, edges) => edges.slice(0, -1).map((lo, i) => `${lo}-${edges[i + 1]} ${rate(xs.filter(x => f(x) >= lo && (f(x) < edges[i + 1] || i === edges.length - 2)))}`).join(" · ");
// The band covering the most commands you approved at least 95% of (10+ labelled); among equals
// the tightest, so no threshold is recommended beyond where there is data.
// ponytail: a fixed grid and one threshold pair; per-agent or per-env thresholds when the data allows.
const MIN_N = 10;
const bands = [0.5, 0.8, 1, 1.2, 1.5, 2].flatMap(b => [0.5, 0.6, 0.7, 0.8, 0.9].map(c => {
  const xs = labelled.filter(x => x.blast <= b && x.conf >= c);
  return {b, c, n: xs.length, ok: xs.filter(x => x.ok).length};
})).filter(x => x.n >= MIN_N && x.ok / x.n >= 0.95).sort((x, y) => y.n - x.n || x.b - y.b || y.c - x.c);

if (process.argv.includes("--calibration")) {
  // Expected calibration error of each answer read as an approval probability: 1 - blast/3 and
  // 1 - mutates. ponytail: 5 equal-width bins; a reliability curve per question needs more data.
  const NEED = 20;
  console.log(`calibration · ${labelled.length} labelled commands, ${humanLabels.length} by a human (approved = it ran after the ask, or after Claude Code's own prompt), ${systemLabels.length} by System 2`);
  if (labelled.length < NEED) {
    console.log(`  not enough data: ${labelled.length} labelled, need ${NEED}. Run in enforce mode, or with REFLEX_ALLOW=shadow, and come back.`);
    process.exit(0);
  }
  const clamp = v => Math.min(1, Math.max(0, v));
  for (const [name, p] of [["blast", x => clamp(1 - x.blast / 3)], ["mutates", x => clamp(1 - (x.mutates ?? 0.5))]]) {
    let ece = 0;
    const bins = [];
    for (let i = 0; i < 5; i++) {
      const xs = labelled.filter(x => Math.min(4, Math.floor(p(x) * 5)) === i);
      if (!xs.length) continue;
      const pm = xs.reduce((s, x) => s + p(x), 0) / xs.length, ym = xs.reduce((s, x) => s + x.ok, 0) / xs.length;
      ece += xs.length / labelled.length * Math.abs(pm - ym);
      bins.push(`${(i / 5).toFixed(1)}-${((i + 1) / 5).toFixed(1)} said ${pm.toFixed(2)} saw ${ym.toFixed(2)} (n ${xs.length})`);
    }
    console.log(`  ${name.padEnd(8)} ECE ${ece.toFixed(3)}   ${bins.join(" · ")}`);
  }
  process.exit(0);
}

const list = arg("--list");
if (list) {
  for (const r of trace.filter(r => r.decision === list)) {
    console.log(`${r.ts.slice(0, 16)}  ${(r.source ?? "").padEnd(9)} ${(r.rule ?? "").slice(0, 44).padEnd(44)}  ${r.state?.call?.command?.slice(0, 90)}`);
  }
  process.exit(0);
}

console.log(`reflex · last ${arg("--since", 7)} days · ${trace.length} judged commands (read-only ones are not logged)`);
console.log(`  by source    ${JSON.stringify(count(trace, r => r.source))}`);
console.log(`  by decision  ${JSON.stringify(count(trace, r => r.decision))}`);
console.log(`  by mode      ${JSON.stringify(count(trace, r => r.mode))}`);
console.log(`  jev latency  p50 ${q(lat, .5)}s · p95 ${q(lat, .95)}s · p99 ${q(lat, .99)}s · fallbacks ${trace.filter(r => r.source === "fallback").length}`);
console.log(`  tokens       ${logged.reduce((s, r) => s + (r.usage?.input_tokens ?? 0), 0)} input (subgoal checks included)`);
console.log(`  emitted asks ${JSON.stringify(resolved)}   (enforce mode only; approved = a human let it run)`);
console.log(`  replay       ${changed.length} of ${jev.length} Jev decisions change under ${policy.version}`);
for (const [k, v] of Object.entries(count(changed, x => `${x.r.decision} -> ${x.now}`))) console.log(`                 ${k}: ${v}`);
console.log(`  subgoals     ${subgoals.length} checked · ${subgoals.filter(r => r.decision === "deny").length} duplicates` +
            ` (${subgoals.filter(r => r.emitted === "deny").length} denied, the rest shadow)`);
console.log(`  allow        ${JSON.stringify(count(trace.filter(r => ["allow", "would_allow"].includes(r.decision)), r => r.decision))}   (REFLEX_ALLOW ${CONFIG.allow})`);
console.log(`  calibration  ${labelled.length} labelled: ${humanLabels.length} by a human (asks in enforce mode + would-be allows in Claude Code; approved = it ran), ${systemLabels.length} by System 2 (approve or deny)`);
if (labelled.length) {
  console.log(`    by blast       ${bucket(labelled, x => x.blast, [0, 0.5, 1, 1.5, 2, 3])}`);
  console.log(`    by confidence  ${bucket(labelled, x => x.conf, [0, 0.5, 0.7, 0.85, 1])}`);
}
const best = bands[0], pv = policy.values();
console.log(best
  ? `    recommend      of ${best.n} with blast <= ${best.b} and confidence >= ${best.c}, ${systemLabels.length ? "you or System 2 approved" : "you approved"} ${Math.round(100 * best.ok / best.n)}%` +
    ` -> allowBlastMax ${best.b}, allowConfidence ${best.c} (now ${pv.allowBlastMax}, ${pv.allowConfidence})`
  : `    recommend      not enough data: no band with ${MIN_N}+ labelled commands approved 95%+ of the time; keep ${pv.allowBlastMax} / ${pv.allowConfidence}`);

// The injection guard (guard.jsonl): counts only. Its log holds hashes and signals, never text.
const guardRows = rows(join(CONFIG.data, "guard.jsonl")).filter(r => Date.parse(r.ts) >= since);
const results = guardRows.filter(r => r.kind === "result"), prompts = guardRows.filter(r => r.kind === "prompt");
console.log(`  guard        ${results.length} tool results judged · by source ${JSON.stringify(count(results, r => r.source_kind))}`);
console.log(`    outcome      ${JSON.stringify(count(results, r => r.outcome))} · effective ${JSON.stringify(count(results, r => r.effective))} · fallbacks ${results.filter(r => r.source === "fallback").length}`);
console.log(`    attacks      ${JSON.stringify(count(results.flatMap(r => (r.chunks ?? []).filter(c => c.attack && c.attack !== "none")), c => c.attack))} (Jev, per chunk) · rules ${JSON.stringify(count(results.filter(r => r.outcome !== "pass"), r => r.gate ?? "none"))}`);
console.log(`    tainted      ${new Set(results.filter(r => r.tainted && r.session_id).map(r => r.session_id)).size} sessions`);
console.log(`    credentials  ${prompts.filter(r => r.effective === "block").length} prompts blocked, ${prompts.filter(r => r.effective !== "block").length} seen in shadow · ${JSON.stringify(count(prompts.flatMap(r => r.found ?? []), f => f.type))}`);

// The runaway guard: the sessions it stopped, by signal (shadow: would have stopped). Counts only.
const trips = runawayTrips(since);
console.log(`  runaway      ${trips.length} stop${trips.length === 1 ? "" : "s"} in ${new Set(trips.map(t => t.session)).size} sessions · by signal ${JSON.stringify(count(trips, t => t.signal))}` +
            ` · ${trips.filter(t => t.dry).length} in shadow · ${trips.reduce((s, t) => s + t.n, 0)} commands denied or flagged (guard ${CONFIG.runaway.enabled ? "on" : "off"})`);

// The escalation ladder (autonomous profile): who resolved each judged command, how often a human
// was needed, what System 2 said and cost, and how long the queue kept people waiting. Counts only.
const ladderRows = trace.filter(r => r.ladder && !r.ladder.dry), dryRows = trace.filter(r => r.ladder?.dry);
const escalated = ladderRows.filter(r => r.ladder.judge && r.ladder.judge.verdict !== "not called in the hook path");
const verdicts = count(escalated, r => r.ladder.judge.error ? `human (${r.ladder.judge.error})` : r.ladder.judge.verdict);
const shownAsks = trace.filter(r => r.emitted === "ask").length, newItems = ladderRows.filter(r => r.ladder.parked === "new").length;
const per100 = n => trace.length ? (100 * n / trace.length).toFixed(1) : "-";
const pct = (n, d) => d ? `${Math.round(100 * n / d)}%` : "-";
// Agreement: Jev's blast read as a lean (<= 1.5 approve, above it deny) against System 2's approve or deny.
const agree = judged.filter(r => (r.answers.blast.score <= 1.5) === (r.ladder.judge.verdict === "approve")).length;
const judgeLog = rows(join(CONFIG.data, "judge.jsonl")).filter(r => Date.parse(r.ts) >= since);
const spent = judgeLog.reduce((s, r) => s + (r.cost_usd ?? 0), 0);
// A call is a request that went out; a cache hit, System 2 off, a spent budget or a missing key made none.
const NO_CALL = ["off", "budget", "session budget", "no key", "no cli"];
const calls = judgeLog.filter(r => !r.cached && !NO_CALL.includes(r.error)), hits = judgeLog.filter(r => r.cached);
const metered = calls.filter(r => r.usage?.input > 0), mean = f => metered.length ? Math.round(metered.reduce((s, r) => s + f(r), 0) / metered.length) : 0;
const tokensIn = mean(r => r.usage.input), tokensOut = mean(r => r.usage.output ?? 0), tokensCached = mean(r => r.usage.cached ?? 0);
// Fast-lane candidates: command shapes System 2 approved again and again and never denied. Printed for
// a human to review and add to rules.json "pass" by hand; never added automatically, and never one
// that touches the always-human class or a rule.
const MIN_APPROVALS = Number(arg("--candidates", 5));
const byShape = new Map();
for (const r of trace.filter(r => ["approve", "deny"].includes(r.ladder?.judge?.verdict) && r.state?.call?.command)) {
  const t = template(r.state.call.command), e = byShape.get(t) ?? {approve: 0, deny: 0, command: r.state.call.command};
  e[r.ladder.judge.verdict]++;
  byShape.set(t, e);
}
const rules = load("rules.json");
const candidates = [...byShape].filter(([t, e]) => e.approve >= MIN_APPROVALS && !e.deny && !t.includes("<redacted>") &&
  !alwaysHuman({source: "jev"}, {command: e.command, cwd: ""}, {}, {system1: true}) && !rulesHit(e.command, rules))
  .map(([t, e]) => ({approvals: e.approve, pattern: `^${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/<(id|hex|n|ts)>/g, "\\S+")}$`}))
  .sort((a, b) => b.approvals - a.approvals);
const items = listItems(), answered = items.filter(i => i.decided_at && Date.parse(i.decided_at) >= since);
const waits = answered.map(i => (Date.parse(i.decided_at) - Date.parse(i.created)) / 60e3).sort((a, b) => a - b);
const mins = m => m < 90 ? `${m.toFixed(1)} min` : `${(m / 60).toFixed(1)} h`;
if (ladderRows.length || dryRows.length || judgeLog.length || items.length) {
  const b = budgetState();
  console.log(`  ladder       ${ladderRows.length} judged commands with the ladder on · resolved by ${JSON.stringify(count(ladderRows, r => r.ladder.resolver ?? "system1"))}` +
              (dryRows.length ? ` · ${dryRows.length} more logged in shadow (would: ${JSON.stringify(count(dryRows, r => r.ladder.resolver ?? "system1"))})` : ""));
  console.log(`    humans       ${per100(shownAsks + newItems)} per 100 judged commands (${shownAsks} asks shown in the agent + ${newItems} new queue items; read-only commands are not counted)`);
  console.log(`    system 2     ${escalated.length} escalated (${pct(escalated.length, ladderRows.length)} of the ladder's commands) · ${JSON.stringify(verdicts)}` +
              ` · agrees with Jev on ${agree} of ${judged.length} (${pct(agree, judged.length)}; Jev blast <= 1.5 read as approve)`);
  console.log(`    tokens       ${metered.length ? `${tokensIn} in (${tokensCached} of them cached) · ${tokensOut} out per call (mean of ${metered.length})` : "no metered calls"}` +
              ` · cache hits ${hits.length} of ${hits.length + calls.length} (${pct(hits.length, hits.length + calls.length)})`);
  console.log(`    budget       $${spent.toFixed(4)} over ${calls.length} calls in this window, $${trace.length ? (100 * spent / trace.length).toFixed(4) : "0"} per 100 judged commands` +
              ` · today ${b.calls} calls, $${b.usd.toFixed(4)} used; ${b.calls_left} calls, $${b.usd_left} left`);
  const br = breaker();
  if (br.open) console.log(`    warning      System 2 is paused: ${Math.round(100 * br.rate)}% of the last ${br.n} commands escalated, above ${Math.round(100 * CONFIG.judge.breaker.rate)}%; cases go to the queue`);
  console.log(`    queue        ${items.filter(i => i.status === "pending").length} pending · ${answered.length} answered` +
              (waits.length ? `, waited p50 ${mins(q(waits, .5))} · p95 ${mins(q(waits, .95))}` : "") + ` · ${JSON.stringify(count(answered, i => i.status))}`);
  for (const c of candidates.slice(0, 10))
    console.log(`    candidate    ${c.approvals} System 2 approvals, no deny: ${c.pattern}  (review; add to rules.json "pass" by hand if it is always safe)`);
}

const push = arg("--push");
if (push) {
  const lines = [
    "# TYPE reflex_decisions gauge",
    ...Object.entries(count(trace, r => `${r.source}|${r.decision}|${r.mode}`)).map(([k, v]) => {
      const [source, decision, mode] = k.split("|");
      return `reflex_decisions{source="${source}",decision="${decision}",mode="${mode}"} ${v}`;
    }),
    "# TYPE reflex_latency_seconds gauge",
    ...[0.5, 0.95, 0.99].map(p => `reflex_latency_seconds{quantile="${p}"} ${q(lat, p)}`),
    "# TYPE reflex_asks gauge",
    ...Object.entries(resolved).map(([k, v]) => `reflex_asks{resolution="${k}"} ${v}`),
    "# TYPE reflex_replay_changes gauge",
    `reflex_replay_changes ${changed.length}`,
    "# TYPE reflex_input_tokens gauge",
    `reflex_input_tokens ${logged.reduce((s, r) => s + (r.usage?.input_tokens ?? 0), 0)}`,
    "# TYPE reflex_ladder gauge",
    ...Object.entries(count(ladderRows, r => r.ladder.resolver ?? "system1")).map(([k, v]) => `reflex_ladder{resolver="${k}"} ${v}`),
    "# TYPE reflex_system2 gauge",
    ...Object.entries(verdicts).map(([k, v]) => `reflex_system2{verdict="${k}"} ${v}`),
    "# TYPE reflex_human_interventions gauge",
    `reflex_human_interventions ${shownAsks + newItems}`,
    "# TYPE reflex_system2_usd gauge",
    `reflex_system2_usd ${spent.toFixed(6)}`,
    "# TYPE reflex_system2_tokens gauge",
    `reflex_system2_tokens{kind="input"} ${tokensIn}`, `reflex_system2_tokens{kind="output"} ${tokensOut}`, `reflex_system2_tokens{kind="cached"} ${tokensCached}`,
    "# TYPE reflex_system2_cache_hits gauge",
    `reflex_system2_cache_hits ${hits.length}`,
    "# TYPE reflex_queue_pending gauge",
    `reflex_queue_pending ${items.filter(i => i.status === "pending").length}`,
  ];
  const user = encodeURIComponent(process.env.USER ?? "unknown");
  const r = await fetch(`${push.replace(/\/$/, "")}/metrics/job/reflex/user/${user}`,
                        {method: "PUT", body: lines.join("\n") + "\n"});
  console.log(`  pushed       ${r.status} ${push}`);
}
