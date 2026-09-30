#!/usr/bin/env node
// Decision webhooks: config.json `notify: {url, on: ["deny", "ask", "prod"], format: "json" | "slack"}`.
// A webhook is data egress, so: the URL is https (or http on this machine), it comes from the user's
// config.json (a team policy's `notify` counts only while the user trusts that exact file, team.mjs),
// and a message carries the redacted command and reason plus the decision's metadata, never an
// environment value (the production tier says which marker, not its value). The hook never waits: a
// detached child posts each message once, with a 2 s timeout, no retries and no redirects.
// This module imports nothing from the gate; the caller hands it an event that is already redacted.
import {spawn} from "node:child_process";
import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {isMain} from "./failsafe.mjs";

const ON = ["deny", "ask", "prod"], LOCAL = ["localhost", "127.0.0.1", "[::1]"], TIMEOUT_MS = 2000;
/** Why a URL may not receive decisions, or null. */
export function urlError(u) {
  let url;
  try { url = new URL(u); } catch { return "url must be a URL"; }
  if (url.username || url.password) return "url must not carry a user name or password";
  if (url.protocol === "https:" || (url.protocol === "http:" && LOCAL.includes(url.hostname))) return null;
  return "url must be https, or http on localhost";
}
function notifyError(n) {
  if (!n || typeof n !== "object" || Array.isArray(n)) return "must be an object {url, on, format}";
  const extra = Object.keys(n).find(k => !["url", "on", "format", "note"].includes(k));
  if (extra) return `unknown field "${extra}"`;
  if (typeof n.url !== "string") return "url must be a URL";
  const u = urlError(n.url);
  if (u) return u;
  if (n.on !== undefined && (!Array.isArray(n.on) || !n.on.length || n.on.some(o => !ON.includes(o)) || new Set(n.on).size !== n.on.length))
    return `on must be a list of distinct ${ON.join(", ")}`;
  if (n.format !== undefined && !["json", "slack"].includes(n.format)) return 'format must be "json" or "slack"';
  return null;
}
/** A notify setting, validated: {target, error}. An invalid one sends nothing. */
export function notifyTarget(n, where = "notify") {
  if (n === undefined || n === null) return {target: null, error: null};
  const e = notifyError(n);
  return e ? {target: null, error: `${where}: ${e}`} : {target: {url: n.url, on: n.on ?? ["deny"], format: n.format ?? "json", where}, error: null};
}
/** What a person may see of a target: the host, never the path (a Slack webhook's path is its secret). */
export const targetLabel = t => `${new URL(t.url).host} (${t.where}; on ${t.on.join(", ")}; ${t.format})`;

const slackText = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
/** The message body for one decision event (already redacted by the caller). */
export function body(ev, format) {
  if (format !== "slack") return JSON.stringify({event: "reflex.decision", ...ev});
  const tier = ev.prod ? ` in production (${ev.prod_by})` : "";
  return JSON.stringify({text: slackText(`reflex ${ev.decision}${tier}: ${ev.command.replace(/`/g, "'")} | ${ev.reason} | ${ev.agent ?? "agent"} in ${ev.cwd}`)});
}
export const wants = (t, ev) => (t.on.includes("deny") && ev.decision === "deny") || (t.on.includes("ask") && ev.decision === "ask") ||
  (t.on.includes("prod") && ev.prod);

/** Post the event to every target that wants it, from a detached child; returns at once. Never throws. */
export function notifyLater(targets, ev) {
  try {
    const jobs = targets.filter(t => t && wants(t, ev)).map(t => ({url: t.url, body: body(ev, t.format)}));
    if (!jobs.length) return false;
    // through hook.mjs, like every hook: an error in the child is logged (health/errors.jsonl), not lost
    const child = spawn(process.execPath, [fileURLToPath(new URL("hook.mjs", import.meta.url)), fileURLToPath(import.meta.url), "--send"], {detached: true, stdio: ["pipe", "ignore", "ignore"]});
    child.on("error", () => {});
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(jobs));
    child.unref();
    return true;
  } catch { return false; }   // a notification must never change or delay a decision
}
/** One POST, 2 s, no retry, no redirect: {status} or {error}. */
export async function post(url, text) {
  if (urlError(url)) return {error: urlError(url)};
  try {
    const r = await fetch(url, {method: "POST", headers: {"content-type": "application/json"}, body: text, redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS)});
    return {status: r.status};
  } catch (e) { return {error: e.name === "TimeoutError" ? "timed out after 2 s" : e.cause?.code ?? e.message}; }
}
/** reflex doctor --notify-test: a dry-run message to each target, awaited. */
export async function testTargets(targets) {
  const text = "reflex doctor: test notification (dry run). No command was judged.";
  return Promise.all(targets.map(async t => ({target: targetLabel(t),
    ...await post(t.url, t.format === "slack" ? JSON.stringify({text}) : JSON.stringify({event: "reflex.test", dry_run: true, text}))})));
}

if (isMain(import.meta) && process.argv.includes("--send")) {
  setTimeout(() => process.exit(0), TIMEOUT_MS + 1000).unref();
  try { await Promise.allSettled(JSON.parse(readFileSync(0, "utf8")).map(j => post(j.url, j.body))); } catch { /* nothing to send */ }
  process.exit(0);
}
