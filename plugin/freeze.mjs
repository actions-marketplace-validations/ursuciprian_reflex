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
const validDate = s => { if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false; const d = new Date(`${s}T00:00:00Z`); return !isNaN(d) && d.toISOString().slice(0, 10) === s; };
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
  if (w.before === "00:00") return "before 00:00 never holds; leave before out to mean midnight";
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
    let why;
    try { why = windowError(w); } catch (e) { why = `cannot be read (${e.message})`; }   // an error, never a crash: a crash fails open
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

