// `reflex learn`: user fast-lane entries (fastlane.json) from what you approved yourself.
// The answers are a human's only: approval queue items a person approved or denied (reflex queue),
// and asks shown at the agent's own prompt (a Reflex ask, or Claude Code's PermissionRequest) that
// then ran, were refused, or were never answered. A System 1 allow and a System 2 verdict are never
// an answer. The templates, their safety proof and the effect are suggest.mjs's; on top of that a
// shape is proposed only when it was approved in two sessions or more, was never refused or left
// unanswered, and is not production, always-human or a denied word. It writes nothing on its own:
// replay.mjs's `reflex learn --write` appends to fastlane.json after a human confirms. CLI only; the
// Claude Code plugin does not ship this file.
import {createHash} from "node:crypto";
import {readFileSync, readdirSync} from "node:fs";
import {join} from "node:path";
import {CONFIG, jsonLines, precheck, prodTier, promptKey} from "./gate.mjs";
import {alwaysHuman, listItems} from "./autonomy.mjs";
import {DENY, FASTLANE_FILE, compilePattern, parseFastLane} from "./fastlane.mjs";
import {blockingSegments, mergeSuggestions, projectOf, suggest, writeSuggestions} from "./suggest.mjs";

export const STALE_DAYS = 60;
const DAY = 864e5, ANSWER_MS = 6e5;
const iso = t => Number.isFinite(t) ? new Date(t).toISOString() : null;
const inside = (cwd, root) => cwd === root || String(cwd).startsWith(root + "/");
// The segments a fast-lane pattern is matched against, as suggest() and the hook split them.
const segs = command => (blockingSegments(command) ?? []).map(s => s.trim());
const tally = (xs, f) => xs.reduce((m, x) => ({...m, [f(x)]: (m[f(x)] ?? 0) + 1}), {});
// trace.jsonl / feedback.jsonl and their rotated files
const logs = name => {
  let files = [];
  try { files = readdirSync(CONFIG.data).filter(n => new RegExp(`^${name}(\\.\\d+)?\\.jsonl$`).test(n)); } catch { /* no data yet */ }
  return files.flatMap(n => { try { return jsonLines(readFileSync(join(CONFIG.data, n), "utf8")); } catch { return []; } });
};

/** What a human approved and refused since `since`: [{command, cwd, session, ts, source, id}]. */
export function humanAnswers({since = 0, now = Date.now()} = {}) {
  const approved = [], denied = [];
  // `reflex queue approve|deny` is a person at a terminal (an agent running it is a tamper ask).
  for (const it of listItems()) {
    const ts = Date.parse(it.decided_at);
    if (!(ts >= since) || typeof it.command !== "string") continue;
    const x = {command: it.command, cwd: it.cwd, session: it.session_id, ts, source: "queue", id: it.id};
    if (["approved", "used"].includes(it.status)) approved.push(x);
    else if (it.status === "denied") denied.push(x);
  }
  const fb = logs("feedback"), ids = events => new Set(fb.filter(r => events.includes(r.event ?? "ran")).map(r => r.call_id).filter(Boolean));
  const ran = ids(["ran", "failed"]), refused = ids(["denied"]), prompted = fb.filter(r => r.event === "prompted" && r.key);
  const seen = new Set();
  for (const r of logs("trace")) {
    const command = r.state?.call?.command, ts = Date.parse(r.ts), id = r.call_id;
    // shell commands only: never a subgoal or an MCP tool call
    if (!(ts >= since) || typeof command !== "string" || !id || seen.has(id) || (r.tag ?? "tool-gate") !== "tool-gate" || r.state.call.tool || /^mcp__/.test(command)) continue;
    // Not a human's answer: an allow (System 1 or 2), a deny, a queue approval (counted above), a System 2 verdict.
    if (["allow", "deny"].includes(r.emitted) || r.source === "queue" || ["approve", "deny"].includes(r.ladder?.judge?.verdict)) continue;
    // Shown to a human: a Reflex ask, or a pass that met Claude Code's own dialog (report.mjs's join).
    const shown = r.emitted === "ask" || (!r.emitted && r.agent === "claude-code" && prompted.some(p => p.session_id === r.session_id &&
      p.key === promptKey(command) && p.ts >= r.ts && Date.parse(p.ts) - ts < ANSWER_MS));
    if (!shown) continue;
    seen.add(id);
    const x = {command, cwd: r.cwd ?? r.state?.call?.cwd, session: r.session_id, ts, source: r.emitted === "ask" ? "reflex ask" : "agent prompt", id};
    if (refused.has(id)) denied.push(x);
    // A change freeze ask says nothing about the shape outside the window.
    else if (ran.has(id)) { if (r.rule_id !== "freeze") approved.push(x); }
    // No answer and no run: refused at the prompt or interrupted. Counts against the shape.
    else if (now - ts > ANSWER_MS) denied.push({...x, interrupted: true});
  }
  return {approved, denied};
}

export const entryId = (cwd, pattern) => `l-${createHash("sha256").update(`${cwd}\0${pattern}`).digest("hex").slice(0, 8)}`;
// The pattern found anywhere in a command, between word edges: a refusal of `make lint > x`, `sudo make
// lint` or `make lint --fix` holds `^make\s+lint$` back too.
const loose = pattern => new RegExp(`(?<![\\w./-])(?:${pattern.slice(1, -1)})(?![\\w./-])`);
// What the learned pattern names, in words: for the denied-word check.
const words = pattern => pattern.slice(1, -1).replace(/\\s\+/g, " ").replace(/\\(.)/g, "$1");
// Never learned, whatever was approved: a denied word, production, the always-human class (a rule or
// the tamper check deciding a command already keeps it out of suggest()'s groups).
function never(pattern, calls) {
  const w = words(pattern).match(DENY);
  if (w) return `names ${w[0].trim()}`;
  for (const c of calls) {
    if (prodTier(c.command, c.cwd, {}).prod) return "production";
    const h = alwaysHuman({source: "local"}, c, {}, {system1: true});
    if (h) return `always-human (${h.id})`;
  }
  return null;
}

/** Proposals from the answers: suggest()'s templates and proof, then the learning conditions. */
export function learn({approved, denied}, {judge = precheck, min = 3, sessions = 2, mask = s => s} = {}) {
  const r = suggest(approved.map(a => ({...a, agent: a.source})), {judge, min, mask});
  const proposals = [], held = r.rejected.map(x => ({pattern: x.pattern, cwd: x.cwd, approved: x.count, denied: 0, why: x.why}));
  for (const s of r.suggestions) {
    const re = compilePattern(s.pattern), near = loose(s.pattern);
    // the approvals behind it: suggest() grouped only the commands no rule or fast lane decides
    const mine = approved.filter(a => projectOf(a.cwd) === s.cwd && segs(a.command).some(seg => re.test(seg)) && !judge(a.command, a.cwd, {}));
    const no = denied.filter(d => near.test(d.command.replace(/\s+/g, " ")));
    const why = no.length ? `refused or left unanswered ${no.length} time${no.length === 1 ? "" : "s"} in this shape`
      : s.sessions < sessions ? `approved in ${s.sessions} session${s.sessions === 1 ? "" : "s"}; needs ${sessions}`
      : !mine.length ? "no approved command matches it" : never(s.pattern, mine);
    if (why) { held.push({pattern: s.pattern, cwd: s.cwd, approved: s.count, denied: no.length, why}); continue; }
    proposals.push({id: entryId(s.cwd, s.pattern), pattern: s.pattern, cwd: s.cwd, approved: s.count, denied: 0, sessions: s.sessions,
      first: iso(s.first), last: iso(s.last), sources: tally(mine, a => a.source), samples: s.samples, why: s.why});
  }
  return {proposals, held, skipped: r.skipped};
}

// A proposal as a fastlane.json entry, with where it came from.
const toEntry = (p, today) => ({id: p.id, pattern: p.pattern, cwd: p.cwd, note: `reflex learn ${today}: approved ${p.approved} times in ${p.sessions} sessions`,
  learned_at: new Date().toISOString(), learned_from: {approved: p.approved, denied: 0, sessions: p.sessions, first: p.first, last: p.last, sources: p.sources}});
export const mergeLearned = (proposals, file = FASTLANE_FILE) => mergeSuggestions(proposals, file, toEntry);

// The file as written (loadFastLane keeps only pattern and cwd), validated as the hook reads it.
function readDoc(file) {
  let text;
  try { text = readFileSync(file, "utf8"); } catch (e) { if (e.code === "ENOENT") return {doc: {version: 1, entries: []}}; throw e; }
  const {error} = parseFastLane(text);
  if (error) throw new Error(`${file} is invalid (${error}); fix or remove it first`);
  return {doc: JSON.parse(text)};
}
/** Learned entries with their last use (a fast-lane pass in the trace that the entry matches) and whether they are stale. */
export function learnedEntries(file = FASTLANE_FILE, now = Date.now()) {
  const learned = readDoc(file).doc.entries.filter(e => e.learned_from);
  if (!learned.length) return [];
  const passes = logs("trace").filter(r => r.source === "fast-lane" && /fastlane\.json/.test(r.rule ?? "") && typeof r.state?.call?.command === "string");
  return learned.map(e => {
    const re = compilePattern(e.pattern), cwd = e.cwd;
    const used = passes.filter(r => inside(r.cwd ?? r.state.call.cwd, cwd) && segs(r.state.call.command).some(s => re.test(s)))
      .map(r => Date.parse(r.ts)).filter(Number.isFinite);
    const last = Math.max(Date.parse(e.learned_at) || 0, ...used);
    return {...e, uses: used.length, last_used: used.length ? iso(Math.max(...used)) : null, stale: now - last > STALE_DAYS * DAY};
  });
}
/** Remove entries: by id (forget) or every stale learned entry (prune). Returns the removed entries. */
export function removeEntries(select, file = FASTLANE_FILE) {
  const {doc} = readDoc(file), gone = doc.entries.filter(select);
  if (!gone.length) return [];
  doc.entries = doc.entries.filter(e => !gone.includes(e));
  writeSuggestions(JSON.stringify(doc, null, 2) + "\n", file);
  return gone;
}
export const forget = (id, file = FASTLANE_FILE) => removeEntries(e => e.id === id && !!e.learned_from, file);
export function prune(file = FASTLANE_FILE, now = Date.now()) {
  const stale = new Set(learnedEntries(file, now).filter(e => e.stale).map(e => e.id));
  return removeEntries(e => !!e.learned_from && stale.has(e.id), file);
}
/** A team policy snippet per repository: {root: {fastlane: [{pattern, note}]}} for .reflex/policy.json. */
export const teamSnippet = proposals => Object.fromEntries([...new Set(proposals.map(p => p.cwd))].map(root => [root,
  {fastlane: proposals.filter(p => p.cwd === root).map(p => ({pattern: p.pattern, note: `reflex learn: approved ${p.approved} times in ${p.sessions} sessions`}))}]));
/** For reflex status: how many shapes you approved often enough could stop asking (logs only, no transcripts). */
export function nudge({since = Date.now() - 30 * DAY, min = 3} = {}) {
  try {
    const a = humanAnswers({since});
    return a.approved.length >= min ? learn(a, {min}).proposals.length : 0;
  } catch { return 0; }
}
