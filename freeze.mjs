#!/usr/bin/env node
// Change windows and freezes: during a window, a command that is not read-only and touches
// production (or, with "applies_to": "all", any such command) gets the window's outcome, ask or deny.
//
//   "freeze": [{"days": ["fri"], "after": "15:00", "tz": "Europe/Bucharest", "outcome": "ask"},
//              {"from": "2026-12-20", "to": "2027-01-03", "outcome": "deny", "note": "year-end freeze"}]
//
// It lives in the user's config.json and in a team policy (.reflex/policy.json). It only adds asks
// and denies: there is no way to write a window that lets anything through. Every field given must
// hold (days AND after AND from...), times are local to `tz` (default UTC) through Intl, `after` is
// inclusive, `before` exclusive, and `from` / `to` are inclusive dates. An invalid window is an
// error, never a smaller window. No dependencies; the clock is a parameter.
const DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const KEYS = new Set(["days", "after", "before", "from", "to", "tz", "applies_to", "outcome", "note"]);
const MAX_WINDOWS = 20;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const validDate = s => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && new Date(`${s}T00:00:00Z`).toISOString().slice(0, 10) === s;
const formats = new Map();
function formatter(tz) {
  if (!formats.has(tz)) formats.set(tz, new Intl.DateTimeFormat("en-US", {timeZone: tz, hourCycle: "h23", weekday: "short",
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}));
  return formats.get(tz);
}
/** The wall clock in tz: {day: "fri", date: "2026-10-02", time: "15:04"}. */
export function localTime(now, tz) {
  const p = Object.fromEntries(formatter(tz).formatToParts(now).map(x => [x.type, x.value]));
  return {day: p.weekday.toLowerCase(), date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour === "24" ? "00" : p.hour}:${p.minute}`};
}
const list = xs => xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`;
function describe(w) {
  const when = [w.days && list(w.days.map(d => NAMES[DAYS.indexOf(d)])), w.after && `after ${w.after}`, w.before && `before ${w.before}`,
    w.from && w.to ? `${w.from} to ${w.to}` : w.from ? `from ${w.from}` : w.to && `until ${w.to}`].filter(Boolean).join(" ");
  return `change freeze: ${when} (${w.tz})${w.note ? `: ${w.note}` : ""}`;
}
function windowError(w) {
  if (!w || typeof w !== "object" || Array.isArray(w)) return "not an object";
  const extra = Object.keys(w).find(k => !KEYS.has(k));
  if (extra) return `unknown field "${extra}"`;
  if (!["days", "after", "before", "from", "to"].some(k => w[k] !== undefined)) return "needs at least one of days, after, before, from, to";
  if (w.days !== undefined && (!Array.isArray(w.days) || !w.days.length || w.days.some(d => !DAYS.includes(d)) || new Set(w.days).size !== w.days.length))
    return `days must be a list of distinct ${DAYS.join(", ")}`;
  for (const k of ["after", "before"]) if (w[k] !== undefined && !(typeof w[k] === "string" && TIME.test(w[k]))) return `${k} must be HH:MM, 00:00 to 23:59`;
  if (w.after && w.before && w.after >= w.before) return "after must be earlier than before; for a window across midnight, write two windows";
  for (const k of ["from", "to"]) if (w[k] !== undefined && !validDate(w[k])) return `${k} must be a date, YYYY-MM-DD`;
  if (w.from && w.to && w.from > w.to) return "from must not be later than to";
  if (w.tz !== undefined) {
    if (typeof w.tz !== "string" || !w.tz) return "tz must be a time zone name such as Europe/Bucharest";
    try { formatter(w.tz); } catch { return `tz "${String(w.tz).slice(0, 60)}" is not a time zone this Node.js knows`; }
  }
  if (w.applies_to !== undefined && !["prod", "all"].includes(w.applies_to)) return 'applies_to must be "prod" or "all"';
  if (w.outcome !== undefined && !["ask", "deny"].includes(w.outcome)) return 'outcome must be "ask" or "deny"';
  if (w.note !== undefined && (typeof w.note !== "string" || w.note.length > 200)) return "note must be text of at most 200 characters";
  return null;
}
/** A freeze list, validated window by window: every valid window is kept, every problem is an error. */
export function parseFreeze(value, where = "freeze") {
  const out = {windows: [], errors: []};
  if (value === undefined || value === null) return out;
  if (!Array.isArray(value)) { out.errors.push(`${where} must be a list of windows`); return out; }
  if (value.length > MAX_WINDOWS) out.errors.push(`${where}: more than ${MAX_WINDOWS} windows, the rest are ignored`);
  for (const [i, w] of value.slice(0, MAX_WINDOWS).entries()) {
    const why = windowError(w);
    if (why) { out.errors.push(`${where} ${i + 1}: ${why}`); continue; }
    const v = {applies_to: "prod", outcome: "ask", ...w, tz: w.tz ?? "UTC"};
    out.windows.push({...v, reason: describe(v)});
  }
  return out;
}
/** Does the window hold at `now`? */
export function inWindow(w, now = new Date()) {
  const t = localTime(now, w.tz);
  return (!w.days || w.days.includes(t.day)) && (!w.after || t.time >= w.after) && (!w.before || t.time < w.before) &&
    (!w.from || t.date >= w.from) && (!w.to || t.date <= w.to);
}
/** The window that applies to a command now, a deny before an ask, or null. `prod`: the command touches production. */
export function activeFreeze(windows, now = new Date(), prod = true) {
  const on = (windows ?? []).filter(w => (prod || w.applies_to === "all") && inWindow(w, now));
  return on.find(w => w.outcome === "deny") ?? on[0] ?? null;
}

function selfcheck() {
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  const one = w => parseFreeze([w]);
  const fri = one({days: ["fri"], after: "15:00", tz: "Europe/Bucharest"});
  ok(!fri.errors.length && fri.windows[0].reason === "change freeze: Friday after 15:00 (Europe/Bucharest)" && fri.windows[0].outcome === "ask" &&
     fri.windows[0].applies_to === "prod", `reason and defaults: ${JSON.stringify(fri)}`);
  // 2026-10-02 is a Friday; Bucharest is UTC+3 in October (EEST), UTC+2 in winter (EET)
  const w = fri.windows[0];
  ok(inWindow(w, new Date("2026-10-02T12:00:00Z")) && !inWindow(w, new Date("2026-10-02T11:59:00Z")), "Friday 15:00 local is 12:00 UTC in summer time");
  ok(inWindow(w, new Date("2026-10-02T20:59:00Z")) && !inWindow(w, new Date("2026-10-02T21:00:00Z")), "Friday ends at local midnight (Saturday 00:00)");
  ok(inWindow(w, new Date("2026-12-04T13:00:00Z")) && !inWindow(w, new Date("2026-12-04T12:59:00Z")), "winter time: 15:00 local is 13:00 UTC");
  ok(!inWindow(w, new Date("2026-10-01T14:00:00Z")), "Thursday is outside");
  const range = one({from: "2026-12-20", to: "2027-01-03", outcome: "deny"}).windows[0];
  ok(range.reason === "change freeze: 2026-12-20 to 2027-01-03 (UTC)" && inWindow(range, new Date("2026-12-20T00:00:00Z")) &&
     inWindow(range, new Date("2027-01-03T23:59:59Z")) && !inWindow(range, new Date("2027-01-04T00:00:00Z")) && !inWindow(range, new Date("2026-12-19T23:59:59Z")),
     "a date range is inclusive at both ends");
  const tokyo = one({from: "2026-12-20", tz: "Asia/Tokyo"}).windows[0];
  ok(inWindow(tokyo, new Date("2026-12-19T15:00:00Z")) && !inWindow(tokyo, new Date("2026-12-19T14:59:00Z")), "a date range follows its tz");
  const night = one({before: "08:00", after: "00:00", days: ["mon", "tue"]}).windows[0];
  ok(night.reason === "change freeze: Monday and Tuesday after 00:00 before 08:00 (UTC)" && inWindow(night, new Date("2026-09-28T07:59:00Z")) &&
     !inWindow(night, new Date("2026-09-28T08:00:00Z")), "before is exclusive");
  // strict validation: every problem is an error, never a smaller window
  for (const bad of [{days: ["friday"]}, {days: []}, {days: ["fri", "fri"]}, {after: "25:00"}, {after: "9:00"}, {after: "18:00", before: "08:00"},
    {from: "2026-02-30"}, {from: "2027-01-03", to: "2026-12-20"}, {tz: "Mars/Olympus", days: ["fri"]}, {days: ["fri"], outcome: "allow"},
    {days: ["fri"], outcome: "pass"}, {days: ["fri"], applies_to: "dev"}, {days: ["fri"], until: "x"}, {tz: "UTC"}, {}, "fri", null, [], {days: ["fri"], note: 5}])
    ok(one(bad).errors.length === 1 && one(bad).windows.length === 0, `invalid: ${JSON.stringify(bad)}`);
  const mixed = parseFreeze([{days: ["fri"]}, {days: ["xyz"]}]);
  ok(mixed.windows.length === 1 && mixed.errors.length === 1, "valid windows stay, invalid ones are errors");
  ok(parseFreeze("fri").errors.length === 1 && !parseFreeze(undefined).errors.length, "the list itself is checked");
  // deny before ask; applies_to all covers commands that are not production
  const both = parseFreeze([{from: "2026-01-01"}, {from: "2026-01-01", outcome: "deny"}, {from: "2026-01-01", applies_to: "all"}]).windows, t = new Date("2026-06-01T00:00:00Z");
  ok(activeFreeze(both, t, true).outcome === "deny" && activeFreeze(both, t, false).applies_to === "all" && activeFreeze(both.slice(0, 2), t, false) === null &&
     activeFreeze(both, new Date("2025-06-01T00:00:00Z"), true) === null, "a deny wins; applies_to all covers every command");
  console.log(process.exitCode ? "freeze selfcheck FAILED" : "freeze selfcheck OK");
}
if (process.argv[1]?.endsWith("freeze.mjs") && process.argv.includes("--selfcheck")) selfcheck();
