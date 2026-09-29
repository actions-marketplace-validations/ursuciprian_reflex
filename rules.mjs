// The deterministic rules (gate.mjs): the setup files, checkRules and its spellings, and the deny
// rules on a command too large to check.
import {existsSync, readFileSync} from "node:fs";
import {join, dirname} from "node:path";
import {teamRules} from "./team.mjs";
import {USER_CONFIG_FILE, ENV, CONFIG, HERE} from "./config.mjs";
import {plain, stripDataHeredocs, ruleSpelling, wordSpelling} from "./shell.mjs";
import {readOnly, onlyNotes, pipelines} from "./readonly.mjs";

export const policyDirectory = join(dirname(USER_CONFIG_FILE), "tool-gate");
export const setupFile = f => !ENV.REFLEX_SETUP_DIR && CONFIG.setup === join(HERE, "setup/tool-gate") &&
  existsSync(join(policyDirectory, f)) ? join(policyDirectory, f) : join(CONFIG.setup, f);
export const load = f => JSON.parse(readFileSync(setupFile(f), "utf8"));

// ---------------------------------------------------------------------------------------------
// Deterministic layer: a rule fires when every pattern in `all` matches the command + context, or
// the command alone (`bare`) for a rule marked "context": false. `views` gives a rule marked "shell"
// or "writes" its own [haystack, bare] (see precheck); false skips the rule.
const RX = new Map();
export const rx = p => RX.get(p) ?? RX.set(p, new RegExp(p, "i")).get(p);   // script rules run per line
export function checkRules(haystack, rules, bare = haystack, views = {}) {
  for (const r of rules.rules) {
    const view = r.shell ? views.shell : r.writes ? views.writes : undefined;
    if (view === false) continue;
    const [h, b] = view ?? [haystack, bare];
    const text = r.context === false ? b : h;
    // a team policy's rule brings its own linear-time test (team.mjs)
    if (r.test ? r.test(text) : r.all.every(p => rx(p).test(text))) return {outcome: r.outcome, rule: r.rule, id: r.id};
  }
  return null;
}
export const fastPass = (cmd, rules) => readOnly(cmd, rules.pass.map(p => new RegExp(p, "i")));
// checkRules on the command as written and with git's and aws's global options moved (git -C x push
// is git push): for the checks outside precheck (always-human, fast-lane candidates).
export const rulesHit = (haystack, rules, bare = haystack) => checkRules(haystack, rules, bare) ?? checkRules(plain(haystack), rules, plain(bare));
export const SEVERITY = {deny: 2, ask: 1};
// Over this size a command is not checked but asked about: the rules' work grows with it, and the
// hook's timeout must not let an unchecked command through. Only the deny rules still run, on
// overlapping windows until the deadline, so a large command never turns a deny it shows into an ask.
// A check that took longer than PRECHECK_MS is not trusted to pass either: it asks (a deny stands).
// `run`: one budget for the whole call, shared by every spelling precheck recurses into, and the
// local scripts already scanned, so each is scanned once.
export const COMMAND_BYTES = 32 * 1024, PRECHECK_MS = 3000;
// The deny rules on a command over COMMAND_BYTES: windows of that size, half of it apart (a match up
// to COMMAND_BYTES / 2 long is inside one), each as written and in the other spellings, until `deadline`.
// The views are precheckAs's: "shell" rules read the command without interpreter heredocs that only
// print, and nothing when every pipeline is inert and writes only notes; the others read it with
// data heredocs dropped. ponytail: past the deadline the rest is not read and the command asks.
const same = x => x;
export function largeDeny(command, cwd, env, deadline) {
  const rules = teamRules(load("rules.json"), cwd), deny = {rules: rules.rules.filter(r => r.outcome === "deny")};
  const c = command.replace(/\\\n/g, ""), bare = stripDataHeredocs(c), ctx = [`cwd=${cwd ?? ""}`, ...Object.entries(env).map(([k, v]) => `${k}=${v}`)].map(x => " " + x).join("");
  const code = onlyNotes(pipelines(c, 2 * COMMAND_BYTES, deadline)) ? null : stripDataHeredocs(c, true);
  if (Date.now() > deadline) return null;
  for (let at = 0; ; at += COMMAND_BYTES / 2) {
    const b = bare.slice(at, at + COMMAND_BYTES), s = code?.slice(at, at + COMMAND_BYTES);
    for (const f of [same, ruleSpelling, wordSpelling]) {
      if (Date.now() > deadline) return null;
      // another spelling that changes nothing is not checked again, nor one view twice
      const spell = x => { const r = f(x); return typeof r === "string" ? r : null; };
      const bv = spell(b), cv = code === null ? null : code === bare ? bv : spell(s);
      if (f !== same && bv === null && cv === null) continue;
      const v = bv ?? b, sv = code === null ? null : cv ?? s;
      const hit = checkRules(v + ctx, deny, v, {shell: sv === null ? false : [sv + ctx, sv]});
      if (hit) return {outcome: hit.outcome, rule: hit.rule, id: hit.id, source: "rule", policy_version: rules.version};
    }
    if (at + COMMAND_BYTES >= Math.max(bare.length, code?.length ?? 0)) return null;
  }
}
