#!/usr/bin/env node
// Reflex: judges a shell command a coding agent wants to run, before it runs.
//
//   node gate.mjs --decide        JSON call on stdin -> JSON decision on stdout (any agent adapter)
//   node gate.mjs --record        JSON outcome on stdin -> feedback log
//   node gate.mjs --claude        Claude Code PreToolUse hook   (--claude-post: PostToolUse; --claude-prompted: PermissionRequest)
//   node gate.mjs --codex         Codex CLI PreToolUse hook     (--codex-post)
//   node gate.mjs --hermes        Hermes pre_tool_call hook     (--hermes-post)
//   adapters/opencode.js, adapters/pi.ts                        plugins that call --decide / --record
//   scripts/reflex-sh -c "<cmd>"      bash drop-in for agents without hooks: judge, then run/confirm/refuse
//   node gate.mjs --check "<cmd>" judge one command from the terminal
//   node gate.mjs --selfcheck     offline tests, no API calls
//   --mode off|shadow|enforce, --allow off|shadow|on   written into hook commands by install.mjs
//
// Order: read-only? -> rules -> rules over the local scripts it runs -> fast lane -> cache -> Jev -> policy.
//
// By default the gate only tightens: it emits "ask" or "deny", never "allow", so the agent's own
// permission rules stay authoritative. Deterministic rules (setup/*/rules.json) are enforced in
// every mode. Jev's decisions are enforced only with REFLEX_MODE=enforce; in the default shadow
// mode Jev runs in a detached background process, so the agent never waits for it.
// "allow" (skip the agent's own prompt) is opt-in twice, REFLEX_ALLOW=on and enforce mode, and
// only for a fresh Jev answer that clears the policy's allow gate.
// First: failsafe.mjs answers the agent (ask, or block where it cannot ask) on any error after this.
import {hookFailure, isMain} from "./failsafe.mjs";
// Next: in the Claude Code plugin, settings come from the plugin options and config.json only (plugin.mjs).
import {PLUGIN_MODE} from "./plugin.mjs";
import {appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync, openSync, readSync, writeSync, closeSync} from "node:fs";
import {createHash, randomUUID} from "node:crypto";
import {spawn, spawnSync} from "node:child_process";
import {homedir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {envelopeFor, ladder, park, queueAnswer, runaway, runawayCall, runawayMark, runawayNote} from "./autonomy.mjs";
import {userFastPass} from "./fastlane.mjs";
import {globsReflex, repoRoot, teamMode, teamPolicy, teamRules} from "./team.mjs";
import {argStrings, mcpCommand, mcpJudge, mcpWritePaths, protectedPath, toolOf} from "./tools.mjs";
import {infraSettings, planGate} from "./infra.mjs";
import {activeFreeze, inWindow} from "./freeze.mjs";
import {notifyLater} from "./notify.mjs";
// The gate's own modules, after every other import, each importing only the ones before it:
// config, shell, scripts, readonly, rules, tamper, jev. Their top level runs after every other import, as gate.mjs's did; only config.mjs has side effects (the plugin stand-down).
import {ENV, redact, HERE, CONFIG, USER_CONFIG_FILE, USER_CONFIG, configurationError, FEEDBACK, sha, ROTATE_BYTES, TRACE, STDIN} from "./config.mjs";
import {withAwsProfile, ruleSpelling, wordSpelling, TOO_MANY, BRACE_WORDS, stripDataHeredocs, shellWords, gitPlain} from "./shell.mjs";
import {SCAN_MS, localScripts, scriptLines} from "./scripts.mjs";
import {onlyNotes, pipelines, READ_ONLY_MODE, readOnly} from "./readonly.mjs";
import {PRECHECK_MS, COMMAND_BYTES, largeDeny, load, SEVERITY, rx, checkRules, fastPass} from "./rules.mjs";
import {ownCommand, nestedCheckout, writesOf, staysNested, touchesOwn, namesOwnFile, reflexChanges, TEAM_TAMPER, fastLaneEdit, namesOwn} from "./tamper.mjs";
import {envContext, jevJudge, sessionContext, ask} from "./jev.mjs";
// What the other files import from gate.mjs, wherever it now lives.
export {USER_CONFIG_FILE, USER_CONFIG_ERROR, USER_CONFIG, ENGINES, JUDGE_BACKENDS, JUDGE_DEFAULTS, KEYLESS_JUDGE_DEFAULTS, BACKEND_DEFAULTS,
  QUEUE_DEFAULTS, RUNAWAY_DEFAULTS, runawaySettings, CLAUDE_SETTINGS, CODEX_HOOKS, settingsHooks, settingsHooksInstalled, PLUGIN, settingsCovers,
  PROVIDER, LAYA_DEFAULTS, LAYA_CHECKPOINTS, layaUrl, LAYA_TOKEN, CONFIG, judgeSettings, configurationError, sha, readText, REDACT, redact} from "./config.mjs";
export {maskQuotes, shellWords, stripDataHeredocs, gitPlain, awsPlain, withAwsProfile} from "./shell.mjs";
export {localScripts} from "./scripts.mjs";
export {readOnlyLegacy, READ_ONLY_MODE, readOnly, simpleSegments, READ_ONLY_SIMPLE, readOnlySimple, pipelines} from "./readonly.mjs";
export {policyDirectory, setupFile, load, checkRules, fastPass, rulesHit} from "./rules.mjs";
export {ownCommand} from "./tamper.mjs";
export {envContext, transcriptTail, sessionContext, ask, cacheGet, cachePut, broadCwd, jevJudge} from "./jev.mjs";

/** Everything decided without Jev, or null when Jev has to judge. A rule that fires on the command
 * as the rules know it (ruleSpelling) counts too; the more severe of the two rule outcomes wins. */
export function precheck(command, cwd, env, depth = 0, run = {deadline: Date.now() + PRECHECK_MS, scan: Date.now() + SCAN_MS, scripts: new Set()}) {
  if (depth === 0) command = ownCommand(command) ?? command;
  env = withAwsProfile(command, env);
  const size = n => ({outcome: "ask", rule: `command too large to check (${n})`, id: "command-size", source: "rule", policy_version: load("rules.json").version});
  if (command.length > COMMAND_BYTES) return largeDeny(command, cwd, env, run.deadline) ?? size(`over ${COMMAND_BYTES / 1024} KB`);
  const c = command.replace(/\\\n/g, ""), own = precheckAs(command, cwd, env, run, depth > 0);
  // the other spellings: quoted parts joined and system paths (ruleSpelling), and the words as the
  // shell passes them (wordSpelling); a rule on any of them counts, the most severe wins
  let best = own;
  for (const alt of depth < 2 ? [ruleSpelling(c), wordSpelling(c)] : []) {
    if (Date.now() > run.deadline) break;
    const other = alt === TOO_MANY ? size(`over ${BRACE_WORDS} words from one brace word`) : alt ? precheck(alt, cwd, env, depth + 1, run) : null;
    if (other?.source === "rule" && !(best?.source === "rule" && (SEVERITY[best.outcome] ?? 0) >= (SEVERITY[other.outcome] ?? 0))) best = other;
  }
  if (depth === 0 && Date.now() > run.deadline && best?.outcome !== "deny") return size(`took over ${PRECHECK_MS / 1000} s`);
  return best;
}
// The production tier of a command that is not read-only, by the markers the rules already use: the
// prod-destroy rule's first pattern (cwd, aws_profile, kube_context, tf_workspace, git_branch or the
// command itself) and a team policy's prod list. Read like a "shell" rule: nothing when every pipeline
// only writes notes. {prod, by, why}: `by` names the marker's kind (what a webhook may carry), `why`
// the text it matched (for the local trace and the audit export). Too large to read counts as production.
export function prodTier(command, cwd, env) {
  const c = String(command ?? "").replace(/\\\n/g, "");
  if (c.length > COMMAND_BYTES) return {prod: true, by: "command", why: "command too large to check"};
  if (onlyNotes(pipelines(c))) return {prod: false};
  env = withAwsProfile(c, env);
  const parts = [[`cwd`, `cwd=${cwd ?? ""}`], ...Object.entries(env).map(([k, v]) => [k, `${k}=${v}`]), ["command", stripDataHeredocs(c, true)]];
  const hit = prodMarker(cwd);
  if (!hit(parts.map(p => p[1]).join(" "))) return {prod: false};
  for (const [by, text] of parts) {
    const m = hit(text);
    if (m) return {prod: true, by, why: redact(by === "command" ? `command: ${m}` : text).slice(0, 160)};
  }
  return {prod: true, by: "context", why: "the command with its context"};
}
// The production test prodTier reads: the prod-destroy rule's first pattern and the team policy's
// prod list, as text => the matched marker (a team one is named, never shown) or a falsy value.
function prodMarker(cwd) {
  const marker = load("rules.json").rules.find(r => r.id === "prod-destroy")?.all[0];
  const team = teamPolicy(cwd)?.rules.filter(r => r.id === "team:prod") ?? [];
  return text => (marker && rx(marker).exec(text)?.[0]) ?? (team.find(r => r.test(text)) && "a team prod marker");
}
// The production tier of an MCP call: the server name, each argument as key=value, and the context
// that server kind reads (an AWS server the AWS profile and region, a Kubernetes one the kube context,
// a Terraform one the workspace). Not the cwd or the branch: an MCP server does not act on them.
const SERVER_ENV = [[/^aws_/, /aws|amazon|\biam\b|s3|ec2|eks|ecs|rds|lambda|cloudformation|cdk/], [/^kube_context$/, /k8s|kube|eks|helm|argo|openshift/],
  [/^tf_workspace$/, /terraform|\btfe?\b|opentofu|\btofu\b/]];
export function mcpTier(t, cwd, env = {}) {
  const hit = prodMarker(cwd), kind = `${t.server ?? ""} ${t.name}`.toLowerCase();
  const parts = [["server", `server=${t.server ?? t.name}`],
    ...Object.entries(env).filter(([k]) => SERVER_ENV.some(([key, server]) => key.test(k) && server.test(kind))).map(([k, v]) => [k, `${k}=${v}`]),
    ...argStrings(t.args ?? {}).map(([k, v]) => ["arguments", `${k}=${v}`])];
  for (const [by, text] of parts) {
    const m = hit(text);
    if (m) return {prod: true, by, why: redact(by === "arguments" ? `argument: ${m}` : text).slice(0, 160)};
  }
  return {prod: false};
}
// The protected path a file tool writes, if any (tools.mjs, setup/tool-gate/protected.json): the
// bundled or user copy, the Reflex checkout (not a checkout nested in it, as for tamper), its logs
// and settings, config.json "protected" and the team policy's globs. Production is the prod markers
// on the path within its repository.
export function protectedWrite(paths, cwd) {
  const spec = load("protected.json"), root = cwd && repoRoot(cwd), hit = prodMarker(cwd);
  const own = [{glob: `${HERE}/**`, why: "the Reflex gate and its setup", unless: p => nestedCheckout(dirname(p))},
    {glob: `${CONFIG.data}/**`, why: "the Reflex logs"}, {glob: `${dirname(USER_CONFIG_FILE)}/**`, why: "the Reflex settings"}];
  const user = (Array.isArray(USER_CONFIG.protected) ? USER_CONFIG.protected : []).map(glob => ({glob, why: "protected in config.json"}));
  const entries = [...own, ...spec.paths, ...user, ...(teamPolicy(cwd)?.protected ?? [])];
  const prodPath = p => !!hit(root && p.startsWith(root + "/") ? p.slice(root.length + 1) : p);
  const h = protectedPath(paths, {cwd, entries, prodPath});
  // the path as the reason shows it: relative inside the working directory
  if (h && cwd && h.abs.startsWith(resolve(cwd) + "/")) h.path = h.abs.slice(resolve(cwd).length + 1);
  return h && {...h, outcome: ["ask", "deny"].includes(spec.outcome) ? spec.outcome : "ask", version: spec.version};
}
// A change freeze (freeze.mjs) in force now, from config.json and the team policy, as a rule decision:
// it asks or denies in every mode, and a rule's deny or an equal rule outcome keeps its own reason.
// An invalid window in config.json is never dropped: it asks for every command that is not read-only
// until it is fixed, while the rules keep running (a rule deny stays a deny).
// The reason names the marker's kind, never its value: it reaches the agent, the trace and a webhook.
function frozen(quick, cwd, tier, now = new Date()) {
  if (quick?.source === "read-only") return quick;
  const bad = CONFIG.freeze.errors.length ? [{outcome: "ask", applies_to: "all", reason: `invalid change freeze in ${USER_CONFIG_FILE} (${CONFIG.freeze.errors[0]}); every command asks until it is fixed`}] : [];
  const w = activeFreeze([...bad, ...CONFIG.freeze.windows, ...(teamPolicy(cwd)?.freeze ?? [])], now, tier.prod);
  if (!w || (quick?.source === "rule" && (SEVERITY[quick.outcome] ?? 0) >= SEVERITY[w.outcome])) return quick;
  return {outcome: w.outcome, rule: `${w.reason}${tier.prod ? `; production (${tier.by})` : ""}`, id: "freeze", window: w, source: "rule", policy_version: load("rules.json").version};
}
// A queue approval lifts a freeze ask only when the item was parked and answered inside that window,
// so the human saw the freeze: an approval from before the window never carries into it.
export const freezeApproved = (w, q) => !w.days && !w.after && !w.before && !w.from && !w.to ? false
  : [q.ladder?.queue_created, q.ladder?.decided_at].every(t => t && inWindow(w, new Date(t)));
function precheckAs(command, cwd, env, run, alt = false) {
  // plus the repo's team policy (.reflex/policy.json, team.mjs): its rules only add asks and denies
  const rules = teamRules(load("rules.json"), cwd);
  // The shell deletes a backslash-newline: `git push --force \⏎ origin main` is one line.
  command = command.replace(/\\\n/g, "");
  // Rules see the raw command (redaction could hide the very marker a rule looks for, such as
  // --secret-id=prod-db), minus heredoc bodies that are only data.
  const bare = stripDataHeredocs(command), ctx = [`cwd=${cwd ?? ""}`, ...Object.entries(env).map(([k, v]) => `${k}=${v}`)].map(x => " " + x).join(""), haystack = bare + ctx;
  const ruled = r => ({outcome: r.outcome, rule: r.rule, id: r.id, source: "rule", policy_version: rules.version});
  // Some rules must see reads too (printing an API key is a read).
  const early = checkRules(haystack, {rules: rules.rules.filter(r => r.before_read_only)}, bare);
  if (early?.outcome === "deny") return ruled(early);
  // legacy: read-only passes here, before tamper and the other rules. simple: after all of them (below).
  const RO = {outcome: "pass", rule: "read-only", source: "read-only"};
  if (!early && READ_ONLY_MODE === "legacy" && readOnly(command)) return RO;
  // An ask (an early rule, tamper) is held while the rules below run: a deny among them still wins.
  let held = early ? ruled(early) : null;
  const hold = r => { if (!held || (SEVERITY[r.outcome] ?? 0) > (SEVERITY[held.outcome] ?? 0)) held = r; };
  // Tamper is about what the command changes: a pipeline that only reads the gate's files or an
  // agent's settings (jq . ~/.claude/settings.json > /tmp/s.json) counts by its redirect targets alone.
  // Quotes and backslashes are dropped, as the shell drops them: ~/.claude/'settings.json' is the file.
  // When the text hides what runs (a $, a heredoc), the whole command counts, plus the paths a cd
  // in it points relative ones at (cd "$HOME/.claude" && tee settings.json).
  const ps = pipelines(command), writes = writesOf(bare, cwd, ps);
  // The checkout itself is protected wherever it was cloned, not only under a directory named reflex.
  // A git worktree or clone nested inside it is another checkout, unless the command climbs out (..).
  const nested = cwd && nestedCheckout(cwd), inRepo = cwd && (cwd + "/").startsWith(HERE + "/") && !(nested && staysNested(command, cwd, nested, run));
  if (touchesOwn(writes, cwd) ||
      // an agent must not answer its own queue item, widen its own envelope or rewind the tree
      reflexChanges(command) ||
      // CDPATH sends a relative cd anywhere, so the directory tracking cannot say what a path names
      (inRepo && /\bCDPATH=/.test(command)) ||
      (inRepo && namesOwnFile(writes)))
    hold(ruled({outcome: "ask", rule: "touches the Reflex gate, its setup or its logs", id: "tamper"}));
  // A repo's team policy (.reflex/) and the user's trust in it (team.mjs): a human's call.
  // A glob that expands to .reflex counts, and so does naming policy.json where a team policy applies.
  if (TEAM_TAMPER.test(command.replace(/["'\\]/g, "")) || /(^|[^\w.-])\.reflex(?=[^\w.-]|$)/.test(writes) || globsReflex(writes) ||
      (/\bpolicy\.json\b/.test(writes) && teamPolicy(cwd)))
    hold(ruled({outcome: "ask", rule: "changes a team policy (.reflex/) or trusts one (reflex trust)", id: "tamper"}));
  // `reflex suggest --write` and `reflex learn --write|--forget|--prune` edit the user fast lane: a human's call, never the agent's.
  if (fastLaneEdit(command))
    hold(ruled({outcome: "ask", rule: "edits the fast lane (reflex suggest --write, reflex learn --write)", id: "tamper"}));
  const on = (r, what) => (r.applies_to ?? ["command"]).includes(what);
  // "shell" rules read commands: not the program of an interpreter heredoc that cannot run or write
  // anything, and nothing at all when every pipeline is inert and writes only notes.
  const code = onlyNotes(ps) ? null : stripDataHeredocs(command, true);
  const views = {shell: code === null ? false : [code + ctx, code], writes: [writes + ctx, writes]};
  const hit = checkRules(haystack, {rules: rules.rules.filter(r => !r.before_read_only && on(r, "command"))}, bare, views);
  if (hit) hold(ruled(hit));
  // The scripts it runs, even behind a held ask: a deny in a script still wins, before the fast lane: `npm test` is only as safe as the test script.
  const perLine = {rules: rules.rules.filter(r => on(r, "script") && !r.whole_script)};
  const whole = {rules: rules.rules.filter(r => on(r, "script") && r.whole_script)};
  // A time budget, so a pathological script cannot outrun the hook's timeout (which would let it run):
  // one for the whole call, and each script scanned once whatever spelling named it.
  const late = () => Date.now() > run.scan;
  for (const s of localScripts(command, cwd).filter(s => s.body && !run.scripts.has(s.path))) {
    run.scripts.add(s.path);
    if (namesOwn(s.body) || touchesOwn(writesOf(s.body, cwd, pipelines(s.body, Infinity, run.scan)), cwd) || TEAM_TAMPER.test(s.body.replace(/["'\\]/g, "")) || reflexChanges(s.body) || fastLaneEdit(s.body))
      { hold(ruled({outcome: "ask", rule: `touches the Reflex gate, its setup or its logs (in ${s.path})`, id: "tamper"})); continue; }
    const {lines} = scriptLines(s.body), all = lines.join("\n");
    let sh = checkRules(all + ctx, whole, all);
    for (const l of lines) { if (sh || late()) break; sh = checkRules(l + ctx, perLine, l); }
    if (sh?.outcome === "deny") return ruled({...sh, rule: `${sh.rule} (in ${s.path})`});
    if (sh) hold(ruled({...sh, rule: `${sh.rule} (in ${s.path})`}));
    if (late()) { hold(ruled({outcome: "ask", rule: `script too large to check in time (${s.path})`, id: "script-budget"})); break; }
  }
  // another spelling counts by its rules only: skip the fast lanes (and the scripts they read again)
  if (held || alt) return held;
  if (READ_ONLY_MODE === "simple" && readOnly(command)) return RO;
  if (fastPass(command, rules)) return {outcome: "pass", rule: "fast lane", source: "fast-lane", policy_version: rules.version};
  if (userFastPass(command, cwd, env)) return {outcome: "pass", rule: "fast lane (fastlane.json)", source: "fast-lane", policy_version: rules.version};
  return null;
}

/** The whole gate for one command, as eval.mjs and the hook see it. noExec: the plan gate runs no
 * terraform show or kubectl dry run (the MCP server's reflex_check runs nothing). */
export async function judge({command, cwd, env = envContext(cwd), session = {}, useCache = true, asker, noExec = false}) {
  if (configurationError()) return {outcome: "ask", rule: configurationError(), source: "error"};
  const pre = precheck(command, cwd, env);
  const {quick, plan, floor} = infraJudge(command, cwd, env, frozen(pre, cwd, pre?.source === "read-only" ? {prod: false} : prodTier(command, cwd, env)), {noExec});
  if (quick) return quick;
  if (CONFIG.engine === "local") return floor ?? localJudgment();
  return askFloor(await jevJudge({command, cwd, env, session: plan ? {...session, plan} : session, useCache, asker}), floor);
}
// A plan's ask is a floor under the judge, not in place of it: Jev still sees the command and a deny
// it finds stands; anything milder becomes the plan's ask, with Jev's answers kept for the trace.
export const askFloor = (j, floor) => !floor || j.outcome === "deny" ? j
  : {...floor, answers: j.answers, state: j.state, questions: j.questions, qset: j.qset, usage: j.usage, latency_s: j.latency_s, error: j.error, policy_outcome: j.policy_outcome ?? j.outcome};
// The plan-aware infra gate (infra.mjs), after the rules and a change freeze; a rule deny stands and nothing is read.
// A plan's ask or deny is a rule outcome, enforced in every mode, and the more severe of it and the
// rules' wins. A clean verified plan is allow-eligible: the usual judge decides with the counts in
// its state (keyless, it passes). {quick, plan, floor}: the precheck result to use, the counts, and a
// plan's ask when nothing else decided yet (askFloor: the judge still runs under it).
const INFRA_LATE_MS = Number(ENV.REFLEX_INFRA_LATE_MS ?? 5000);
export function infraJudge(command, cwd, env, quick, {noExec = false} = {}) {
  if (quick?.source === "rule" && quick.outcome === "deny") return {quick, plan: null};
  // production: by the markers prodTier reads, in the directory the command runs in or the one it started in
  const prod = dir => prodTier(command, dir || cwd, env).prod || prodTier(command, cwd, env).prod;
  // the team policy of the directory each part runs in counts too (a cd or -chdir into another repository)
  const settingsAt = dir => { const a = infraSettings(USER_CONFIG.infra, teamPolicy(cwd)?.infra), b = infraSettings(USER_CONFIG.infra, teamPolicy(dir)?.infra);
    return {...a, destroy: a.destroy === "deny" || b.destroy === "deny" ? "deny" : "ask", require_plan_in_prod: a.require_plan_in_prod || b.require_plan_in_prod}; };
  let g;
  const settings = infraSettings(USER_CONFIG.infra, teamPolicy(cwd)?.infra);
  try { g = planGate({command, cwd, settings: noExec ? {...settings, terraform_show: false, kubectl_diff: false, helm_diff: false} : settings, settingsAt, prod, pipelines, shellWords}); }
  catch (e) { g = {outcome: "ask", id: "infra-error", rule: `the plan gate failed (${String(e.message).slice(0, 80)})`}; }   // closed, in shadow too
  if (!g) return {quick, plan: null};
  const plan = g.plan ?? null, version = teamRules(load("rules.json"), cwd).version, withPlan = q => q && plan ? {...q, plan} : q;
  if (g.outcome === "ask" || g.outcome === "deny") {
    const j = {outcome: g.outcome, rule: g.rule, id: g.id, source: "rule", policy_version: version, plan};
    if (!quick && j.outcome === "ask") return {quick: null, plan, floor: j};
    return {quick: quick?.source === "rule" && (SEVERITY[quick.outcome] ?? 0) >= SEVERITY[j.outcome] ? withPlan(quick) : j, plan};
  }
  if (g.outcome === "pass" && !quick && CONFIG.engine === "local") return {quick: {outcome: "pass", rule: g.rule, id: g.id, source: "plan", policy_version: version, plan}, plan};
  return {quick: withPlan(quick), plan};
}
const localJudgment = () => ({outcome: "ask", source: "local", rule: "not covered by local rules; a human must review it"});

// ---------------------------------------------------------------------------------------------
// The agent-neutral contract. Every adapter turns its agent's event into a call:
//   {agent, command, cwd, session_id?, call_id?, intent?, recent?, transcript_path?, permission_mode?, unsandboxed?}
// and gets back {effective, decision, reason, source, policy}. `effective` is what the agent must
// do now: "pass" (no opinion, the agent's own permissions decide), "allow" (run it without the
// agent's prompt), "ask" (a human confirms) or "deny" (block, show the reason).
// In shadow mode only deterministic rules are effective; Jev's decision is logged, never applied.
// A call with `subgoal` (the task a subagent is about to get), or `subgoals` (a batch of them), and
// no `command` is checked for duplicates, see subgoalJudge(); a batch where only some items repeat
// earlier work also gets `drop`, the indexes to leave out. A command is always judged as a command.
export async function decide(call, {background = false, asker, judger} = {}) {
  const subgoals = call.command ? [] : [call.subgoals ?? call.subgoal].flat().filter(s => typeof s === "string" && s.trim());
  if (CONFIG.mode === "off" || !(call.command || subgoals.length || call.tool)) return {effective: "pass", decision: "pass", reason: "reflex off", source: "off"};
  if (call.tool) return toolDecide(call, {background, asker, judger});
  if (subgoals.length) {
    if (CONFIG.engine === "local") return view({outcome: "pass", source: "local", rule: "subgoal classification is disabled"}, "pass");
    if (CONFIG.mode !== "enforce" && !background) return inBackground(call);
    const {j, drop} = await subgoalJudge({...call, subgoals}, asker);
    const effective = CONFIG.mode === "enforce" ? j.outcome : "pass";
    return {...view(j, effective), ...(CONFIG.mode === "enforce" && j.outcome === "pass" && drop.length && {drop})};
  }
  const env = envContext(call.cwd), started = Date.now();
  let quick = background ? null : precheck(call.command, call.cwd, env);
  // the production tier goes into the trace (reflex audit); a change freeze tightens like a rule
  if (quick?.source !== "read-only") {
    call = {...call, tier: prodTier(call.command, call.cwd, env)};
    if (!background) quick = frozen(quick, call.cwd, call.tier);
  }
  // the counts come from the gate itself, never from the caller (the background copy gets them from its parent)
  let floor = null;
  if (!background) { const infra = infraJudge(call.command, call.cwd, env, quick); ({quick, floor} = infra); call = {...call, plan: infra.plan ?? undefined}; }
  // a plan's ask applies now, like a rule's, unless Jev judges in the foreground (enforce): then it is a
  // floor under Jev. The hook has 10 s and fails open past them: after INFRA_LATE_MS of rules and plan
  // reading, Jev (3 s) is not also waited for; what is left asks.
  const late = !background && Date.now() - started > INFRA_LATE_MS && !quick;
  if (floor && (CONFIG.engine === "local" || CONFIG.mode !== "enforce" || late)) [quick, floor] = [floor, null];
  else if (late && CONFIG.engine !== "local" && CONFIG.mode === "enforce") quick = {outcome: "ask", rule: "the rules and the plan or diff read took too long to also ask the judge", id: "infra-budget", source: "rule", policy_version: load("rules.json").version, plan: call.plan};
  // A human's answer in the approval queue (autonomous profile): the identical command, cwd and
  // session, within its TTL. A deterministic deny is never lifted, not even by an approval.
  let resumed = false;
  if (CONFIG.mode === "enforce" && !background && CONFIG.queue.enabled && !(quick?.source === "rule" && quick.outcome === "deny")) {
    let q = quick?.source === "read-only" ? null : queueAnswer(call);
    if (q && q.outcome !== "deny" && quick?.id === "freeze" && !freezeApproved(quick.window, q)) q = null;
    if (q) return finish(q, call, q.outcome === "deny" ? "deny" : allowSetting(holdAllow(q, call)).outcome === "allow" ? "allow" : "pass", {env});
    // a human lifted a runaway stop of this command: the guard steps aside once, the gate does not.
    // A human's deny of the stop is a deny.
    const r = queueAnswer(runawayCall(call));
    if (r?.resume) resumed = true;
    else if (r) return finish(r, call, "deny", {env});
  }
  // The runaway guard (autonomy.mjs) watches the session in the hook path, once per command. It only
  // ever adds a deny, never lifts one: a rule deny keeps its own reason. Shadow logs what it would stop.
  const stop = background ? null : runaway(call, quick, {resumed});
  if (stop && !stop.dry && !(quick?.source === "rule" && quick.outcome === "deny")) {
    const j = {outcome: "deny", source: "runaway", id: `runaway-${stop.signal}`, rule: `stopped: ${stop.reason}`, runaway: {signal: stop.signal}};
    if (CONFIG.queue.enabled && stop.fresh) j.rule += `. Parked for the user as ${park(runawayCall(call), j, {id: "runaway"}).item.id}`;
    trace(j, call, "deny");
    return view(j, "deny");
  }
  if (stop) call = {...call, runaway: {signal: stop.signal, ...(stop.dry ? {dry: true} : {superseded: "rule deny"})}};
  // A session whose agent read a suspected prompt injection: network egress asks, before the
  // read-only list and the fast lane (`gh api "…?q=$SECRET"` reads, `git push` is fast lane), and
  // Jev's policy applies its taint gates. Like Jev, enforced only in enforce mode (shadow takes the
  // usual path, so its background trace still shows Jev's view). The ask can only tighten: with Jev,
  // the command is judged too and a deny stands.
  const t = tainted(call.session_id);
  const egress = t && CONFIG.mode === "enforce" && !(quick?.source === "rule" && quick.outcome !== "pass") && taintedRule(call.command);
  if (egress) {
    const j = CONFIG.engine !== "local" ? await jevJudge({command: call.command, cwd: call.cwd, env, session: callSession(call), asker, tainted: true}) : null;
    const d = j?.outcome === "deny" ? j : {...egress, ...(j && {answers: j.answers, state: j.state, gate: j.gate})};
    return finish(d, call, d.outcome, {env, judger, egress: true});
  }
  if (quick) {
    const effective = quick.source === "rule" ? quick.outcome : "pass";
    if (quick.source === "read-only") return view(quick, effective);
    return finish(quick, call, effective, {env, judger});
  }
  if (CONFIG.engine === "local") return finish(localJudgment(), call, CONFIG.mode === "enforce" ? "ask" : "pass", {env, judger, background});
  // Shadow mode: nobody waits for Jev. A detached copy of this script judges and logs.
  if (CONFIG.mode !== "enforce" && !background) return inBackground(call);
  const j = askFloor(allowSetting(holdAllow(await jevJudge({command: call.command, cwd: call.cwd, env, session: callSession(call), asker, tainted: !!t}), call)), floor);
  const effective = CONFIG.mode === "enforce" && j.outcome !== "would_allow" ? j.outcome : "pass";
  return finish(j, call, effective, {env, judger, background, tainted: !!t});
}
// MCP tool calls and file writes (tools.mjs), on the same ladder as a command: a rule's ask or deny
// holds in every mode, a change freeze tightens, the queue and the runaway guard apply, and the trace,
// the audit and the webhook see them as `mcp <server>/<tool> {arguments}` or `<tool> <path>`, with a
// hash of the whole input so a queue approval covers that exact call. An unknown MCP tool goes to the
// engine. Never allow: a pass leaves the agent's own permissions in charge. A read-like MCP tool and a
// write outside the protected paths pass at once, unlogged, as a read-only command does.
// The rules' view of a tool call: {t, quick, call} with the call's command text, tier and MCP summary
// filled in; `quiet` when the gate has nothing to say (not a gated tool, a write outside the protected
// paths, a read-like MCP tool). quick null: an unknown MCP tool.
function toolRules(call, env) {
  const t = toolOf(call.tool, call.input, call.mcp === true), digest = createHash("sha256").update(JSON.stringify(call.input ?? {})).digest("hex").slice(0, 16);
  if (!t) return {quiet: {outcome: "pass", source: "tool", rule: "not a gated tool"}};
  if (t.kind === "write" && t.unreadable)
    return {t, call: {...call, command: `${t.name} (unreadable patch, input ${digest})`, tier: {prod: false}},
            quick: {outcome: "ask", rule: `${t.name}: the files this patch writes could not be read`, id: "protected-path", source: "rule", policy_version: load("protected.json").version}};
  if (t.kind === "write") {
    const hit = protectedWrite(t.paths, call.cwd);
    if (!hit) return {quiet: {outcome: "pass", source: "tool", rule: "not a protected path"}};
    return {t, call: {...call, command: `${t.name} ${hit.path} (input ${digest})`, tier: hit.prod ? {prod: true, by: "path", why: redact(hit.path).slice(0, 160)} : {prod: false}},
            quick: {outcome: hit.outcome, rule: `writes a protected path (${hit.path}): ${hit.why}`, id: "protected-path", source: "rule", policy_version: hit.version}};
  }
  const tier = mcpTier(t, call.cwd, env);
  let quick = mcpJudge(t, {spec: load("mcp.json"), team: teamPolicy(call.cwd)?.mcp ?? [], tier, precheck: c => precheck(c, call.cwd, env)});
  // an MCP tool that writes files (a filesystem server) is held to the protected paths too
  const wp = mcpWritePaths(t), hit = wp.length ? protectedWrite(wp, call.cwd) : null;
  if (hit && !(quick?.source === "rule" && (SEVERITY[quick.outcome] ?? 0) >= (SEVERITY[hit.outcome] ?? 0)))
    quick = {outcome: hit.outcome, rule: `MCP ${t.server ? `${t.server}/` : ""}${t.tool} writes a protected path (${hit.path}): ${hit.why}`, id: "protected-path", source: "rule", policy_version: hit.version};
  if (quick?.source === "read-only") return {quiet: quick};
  return {t, quick, call: {...call, command: `${mcpCommand(t, redact)} (input ${digest})`, tier,
    mcp: {server: t.server, tool: t.tool, arguments: redact(JSON.stringify(t.args ?? {})).slice(0, 2000), prod: tier.prod}}};
}
const unknownTool = t => ({outcome: "pass", source: "local", id: "mcp-unknown", rule: `MCP tool ${t.tool} is not covered by the MCP rules: logged (keyless)`, policy_version: load("mcp.json").version});
/** A tool call through the rules and the engine, as eval.mjs sees it: no freeze, queue, runaway guard or trace. */
export async function judgeTool({tool, input = {}, mcp = false, cwd, env = {}, session = {}, useCache = true, asker}) {
  if (configurationError()) return {outcome: "ask", rule: configurationError(), source: "error"};
  const r = toolRules({tool, input, mcp, cwd}, env);
  if (r.quiet || r.quick) return r.quiet ?? r.quick;
  if (CONFIG.mcp.unknown === "ask") return {outcome: "ask", source: "rule", id: "mcp-unknown", rule: "not covered by the MCP rules (mcp.unknown: ask)"};
  if (CONFIG.engine === "local") return unknownTool(r.t);
  const j = await jevJudge({command: r.call.command, cwd, env, session: {...session, mcp: r.call.mcp}, useCache, asker, tool: true});
  return j.outcome === "allow" ? {...j, outcome: "pass"} : j;
}
async function toolDecide(call, {background = false, asker, judger} = {}) {
  const env = envContext(call.cwd), r = toolRules(call, env);
  if (r.quiet) return view(r.quiet, "pass");
  const t = r.t;
  let quick = r.quick;
  call = r.call;
  const pass = d => d.effective === "allow" ? {...d, effective: "pass"} : d;
  if (!background) quick = frozen(quick, call.cwd, call.tier);
  let resumed = false;
  if (CONFIG.mode === "enforce" && !background && CONFIG.queue.enabled && !(quick?.source === "rule" && quick.outcome === "deny")) {
    let q = queueAnswer(call);
    if (q && q.outcome !== "deny" && quick?.id === "freeze" && !freezeApproved(quick.window, q)) q = null;
    if (q) return pass(await finish(q, call, q.outcome === "deny" ? "deny" : "pass", {env}));
    const r = queueAnswer(runawayCall(call));
    if (r?.resume) resumed = true;
    else if (r) return finish(r, call, "deny", {env});
  }
  const stop = background ? null : runaway(call, quick, {resumed});
  if (stop && !stop.dry && !(quick?.source === "rule" && quick.outcome === "deny")) {
    const j = {outcome: "deny", source: "runaway", id: `runaway-${stop.signal}`, rule: `stopped: ${stop.reason}`, runaway: {signal: stop.signal}};
    if (CONFIG.queue.enabled && stop.fresh) j.rule += `. Parked for the user as ${park(runawayCall(call), j, {id: "runaway"}).item.id}`;
    trace(j, call, "deny");
    return view(j, "deny");
  }
  if (stop) call = {...call, runaway: {signal: stop.signal, ...(stop.dry ? {dry: true} : {superseded: "rule deny"})}};
  if (quick) return pass(await finish(quick, call, quick.source === "rule" ? quick.outcome : "pass", {env, judger}));
  // an unknown MCP tool
  const version = load("mcp.json").version;
  if (CONFIG.mcp.unknown === "ask")
    return finish({outcome: "ask", source: "rule", id: "mcp-unknown", rule: `MCP tool ${t.tool} is not covered by the MCP rules (mcp.unknown: ask)`, policy_version: version}, call, "ask", {env, judger});
  if (CONFIG.engine === "local") return pass(await finish(unknownTool(t), call, "pass", {env, judger, background}));
  if (CONFIG.mode !== "enforce" && !background) return inBackground(call);
  const t0 = tainted(call.session_id);
  const j = await jevJudge({command: call.command, cwd: call.cwd, env, session: {...callSession(call), mcp: call.mcp}, asker, tainted: !!t0, tool: true});
  return pass(await finish(j, call, CONFIG.mode === "enforce" && j.outcome !== "would_allow" ? j.outcome : "pass", {env, judger, background, tainted: !!t0}));
}
// Every judged command ends here: the escalation ladder when the autonomous profile has it on
// (System 2, the always-human class, the queue, checkpoints), then the trace and the agent's view.
async function finish(j, call, effective, opts = {}) {
  if (call.plan && !j.plan) j = {...j, plan: call.plan};
  if (CONFIG.judge.enabled || CONFIG.queue.enabled || CONFIG.checkpoints) ({j, effective} = await ladder(j, call, effective, opts));
  runawayNote(call, j, effective);
  trace(j, call, effective);
  return view(j, effective);
}
export function callSession(call) {
  const session = sessionContext(call.transcript_path, call.call_id);
  if (call.intent) session.intent = redact(call.intent).slice(-600);
  if (call.recent?.length) session.recent = call.recent.slice(-5).map(c => redact(c).slice(0, 200));
  const envelope = envelopeFor(call);
  if (envelope) session.envelope = envelope;
  if (call.plan) session.plan = call.plan;
  return session;
}
function inBackground(call) {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--bg", "--mode", CONFIG.mode, "--allow", CONFIG.allow, "--engine", CONFIG.engine],
                      {detached: true, stdio: ["pipe", "ignore", "ignore"]});
  child.stdin.end(JSON.stringify(call));
  child.unref();
  return {effective: "pass", decision: "pending", reason: "reflex: judged in the background (shadow)", source: "shadow"};
}

// Subgoal dedup. Agents re-launch subagents for work they already delegated, and pay for it twice.
// Each new subgoal is compared with those launched earlier in the same session (subgoals.jsonl) by
// one Jev choice question whose options are the earlier subgoals plus "none". A confident duplicate
// is denied with a reason naming the earlier one, so the agent reuses its result; anything else
// passes. It saves work, it does not guard safety: a Jev error or an internal error passes.
//
// Parallel spawns (several in one message, or a batch) must see each other, so every subgoal is
// written first, as pending, and then compared with the rows before it in the file: of two
// identical spawns racing, the one appended first is the original. An earlier row counts when its
// spawn ran (a PostToolUse / tool_result record), or while it is pending (no record yet, younger
// than pendingSeconds). A spawn that was denied (by Reflex, the user or another hook) or failed has
// no result to reuse: Reflex marks its own denials dropped, the others show up in feedback.
// ponytail: the files' last 2 MB are read per spawn, no lock (appends are atomic lines).
const SUBGOALS = () => join(CONFIG.data, "subgoals.jsonl");
const TAIL_BYTES = 2 * 1024 * 1024;
export function readTail(path, bytes = TAIL_BYTES) {
  if (!path || !existsSync(path)) return "";
  const size = statSync(path).size, len = Math.min(size, bytes), buf = Buffer.alloc(len);
  const fd = openSync(path, "r");
  try { readSync(fd, buf, 0, len, size - len); } finally { closeSync(fd); }
  return buf.toString("utf8");
}
// A torn or cut line is skipped, not fatal.
export const jsonLines = text => text.split("\n").flatMap(l => { try { return l ? [JSON.parse(l)] : []; } catch { return []; } });
async function subgoalJudge(call, asker = ask) {
  const spec = load("subgoals.json");
  const now = Date.now(), pendingMs = (spec.pendingSeconds ?? 300) * 1000, tag = randomUUID().slice(0, 8);
  const who = {agent: call.agent ?? null, session_id: call.session_id ?? null, call_id: call.call_id ?? null};
  const mine = call.subgoals.map((s, item) => ({ts: new Date(now).toISOString(), id: `${tag}#${item}`, ...who, item,
                                                ...(call.prompt_id && {prompt_id: call.prompt_id}), subgoal: redact(s).slice(0, 2000)}));
  // One write for the whole batch keeps its items in order and together.
  if (call.session_id) append(SUBGOALS(), mine);
  const rows = jsonLines(readTail(SUBGOALS())), fb = jsonLines(readTail(FEEDBACK()));
  const ran = new Set(fb.filter(r => r.event === "ran" && r.call_id).map(r => r.call_id));
  const gone = new Set(fb.filter(r => ["denied", "failed"].includes(r.event) && r.call_id).map(r => r.call_id));
  const dropped = new Set(rows.filter(r => r.dropped).map(r => r.id));
  // Claude Code asked the user about a spawn (PermissionRequest) and it never ran: once the user
  // has sent another prompt (a later prompt_id), the answer was no or the turn was interrupted.
  // A rejected dialog fires no hook of its own, so this is the only sign; nothing to reuse.
  const prompted = fb.filter(r => r.event === "prompted" && r.prompt_id && r.key);
  const refused = r => call.prompt_id && !ran.has(r.call_id) && prompted.some(p => p.session_id === r.session_id &&
    p.prompt_id !== call.prompt_id && p.ts >= r.ts && p.key === sha(r.subgoal));
  const live = r => r.subgoal && r.session_id === who.session_id && r.agent === who.agent && !dropped.has(r.id) &&
    !gone.has(r.call_id) && (ran.has(r.call_id) || now - Date.parse(r.ts) < pendingMs) && !refused(r);
  // Long subgoals that share a preamble differ at the end: an option keeps both.
  const clip = s => s.length > 600 ? `${s.slice(0, 400)} … ${s.slice(-200)}` : s;
  const base = {qset: spec.version, policy_version: spec.version, tag: "subgoal"};
  // the shared context line of a batch task (omp, Hermes) is background, not the task
  const norm = s => s.split("\n").filter(l => !/^context: /.test(l)).join(" ").replace(/\s+/g, " ").trim().toLowerCase();
  const dupRule = (dup, p) => `duplicates a subgoal ${dup.call_id === who.call_id ? "earlier in this batch" : ran.has(dup.call_id) ? "already launched in this session"
    : "launched in parallel in this session"} at ${dup.ts.slice(11, 16)} UTC (p ${p.toFixed(2)}): "${dup.subgoal.slice(0, 160)}". Reuse that result instead of starting it again`;
  const judged = await Promise.all(mine.map(async m => {
    const at = rows.findIndex(r => r.id === m.id);
    const earlier = (at < 0 ? [] : rows.slice(0, at)).filter(live).slice(-spec.keep);
    if (!earlier.length || !call.session_id) return {...base, outcome: "pass", rule: "first subgoal in this session", source: "subgoal"};
    // The same text again is a duplicate without asking: Jev reads an option identical to the new
    // subgoal as the new subgoal itself (p 0.2-0.3 on identical pairs, 0.7 on paraphrases).
    const same = earlier.findLast(r => norm(r.subgoal) === norm(m.subgoal));
    if (same) return {...base, outcome: "deny", source: "subgoal", dup: same, p: 1, rule: dupRule(same, 1)};
    const criteria = Object.fromEntries(earlier.map((r, i) => [`s${i + 1}`, clip(r.subgoal)]));
    criteria.none = "None of them: new work, a follow-up, a different part, or a review of earlier work.";
    const questions = {duplicate: {type: "choice", instructions: spec.instructions, criteria}};
    const res = await asker({subgoal: {text: m.subgoal, cwd: call.cwd}, [spec.context_key]: spec.context}, questions);
    const a = res.answers?.duplicate, i = /^s(\d+)$/.exec(a?.choice ?? "")?.[1];
    const p = a?.probabilities?.[a.choice] ?? a?.confidence ?? 0;   // how likely that option is
    const dup = !res.error && i && earlier[i - 1] && p >= spec.duplicateAt ? earlier[i - 1] : null;
    return {...base, ...res, dup, p, options: earlier.length,
      outcome: dup ? "deny" : "pass", source: res.error ? "fallback" : "jev",
      rule: res.error ? `jev unavailable (${res.error.slice(0, 80)}), subgoal not checked` : dup ? dupRule(dup, p) : "new subgoal"};
  }));
  // A duplicate is dropped at once, even when it runs anyway (shadow): the original stays the reference.
  // An adapter that cannot trim a batch (`whole`) denies all of it, so all of it is dropped: the
  // rest must not count as launched when the agent sends it again.
  const drop = judged.flatMap((j, i) => j.outcome === "deny" ? [i] : []);
  const all = drop.length === judged.length || (drop.length > 0 && call.whole === true);
  if (drop.length && call.session_id) append(SUBGOALS(), (all ? mine.map((_, i) => i) : drop).map(i => ({ts: new Date().toISOString(), id: mine[i].id, dropped: true})));
  // The trace keeps what was decided, not the prompts: a short redacted title and a hash, never the
  // earlier subgoals offered as options (subgoals.jsonl already holds each once).
  judged.forEach((j, i) => {
    const title = `[subgoal${mine.length > 1 ? ` ${i + 1}/${mine.length}` : ""}] ${mine[i].subgoal.slice(0, 120)}`;
    trace({...j, state: {subgoal: {title, sha: sha(mine[i].subgoal), chars: mine[i].subgoal.length, cwd: call.cwd}},
           questions: j.options ? {duplicate: {type: "choice", options: j.options + 1}} : {}},
          {...call, command: title}, CONFIG.mode === "enforce" ? j.outcome : "pass");
  });
  const list = drop.map(i => `${mine.length > 1 ? `task ${i + 1}: ` : ""}${judged[i].rule}`).join("; ");
  const again = all && drop.length < judged.length ? `. Start the others again without task${drop.length > 1 ? "s" : ""} ${drop.map(i => i + 1).join(", ")}` : "";
  const j = drop.length ? {...base, outcome: all ? "deny" : "pass", source: judged[drop[0]].source,
                           rule: (mine.length > 1 ? `${drop.length} of ${mine.length} subgoals repeat earlier work: ${list}` : list) + again}
    : judged.find(x => x.source === "fallback") ?? judged[0];
  return {j, drop: all ? [] : drop};
}

// Taint. guard.mjs records here that an agent session read a tool result it judged to be a prompt
// injection (warn or block); later commands in that session get the rules in rules.json `tainted`
// and the policy's taint gates. One small file per session, named by a hash of the session id.
// ponytail: never expires or pruned; a session id is not reused, and a file is a few hundred bytes.
const taintFile = s => join(CONFIG.data, "taint", `${sha(String(s))}.json`);
export function tainted(session_id) {
  if (!session_id) return null;
  try { return JSON.parse(readFileSync(taintFile(session_id), "utf8")); } catch { return null; }
}
/** Add an event (the last 20 are kept) and/or merge fields into a session's taint record. */
export function taint(session_id, event = null, fields = {}) {
  if (!session_id) return;
  const f = taintFile(session_id), prev = tainted(session_id) ?? {events: []};
  mkdirSync(dirname(f), {recursive: true, mode: 0o700});
  const next = {...prev, ...fields, events: event ? [...prev.events, event].slice(-20) : prev.events};
  writeFileSync(`${f}.${process.pid}`, JSON.stringify(next), {mode: 0o600});
  renameSync(`${f}.${process.pid}`, f);   // atomic; parallel writers can drop an event, never corrupt the file
}
// The command alone: a cwd like /tmp/http-client or a branch named ssh-keys is not egress.
export function taintedRule(command) {
  const rules = load("rules.json"), bare = stripDataHeredocs(command);
  const plain = gitPlain(bare), hit = checkRules(bare, {rules: rules.tainted ?? []}, bare) ?? checkRules(plain, {rules: rules.tainted ?? []}, plain);
  return hit && {outcome: hit.outcome, rule: hit.rule, id: hit.id, source: "taint", policy_version: rules.version};
}

// Any internal error is a decision too: the policy fallback when enforcing, logged either way.
// Subgoal dedup saves work rather than guarding it, so its errors always pass.
export async function decideSafe(call, opts) {
  const error = configurationError();
  if (error) return {effective: "ask", decision: "error", reason: `reflex: ${error}`, source: "error"};
  // A real hook event is separate from installation and from doctor's synthetic probes.
  if (["claude-code", "codex", "pi", "omp", "opencode", "hermes"].includes(call.agent)) try {
    const dir = join(CONFIG.data, "health");
    mkdirSync(dir, {recursive: true, mode: 0o700});
    writeFileSync(join(dir, `${call.agent}.json`), JSON.stringify({at: new Date().toISOString(), gate: HERE,
      mode: CONFIG.mode, engine: CONFIG.engine, allow: CONFIG.allow}), {mode: 0o600});
  } catch { /* diagnostics must not change a decision */ }
  // A team policy's mode floor (team.mjs) holds for this call only.
  const mode = CONFIG.mode;
  CONFIG.mode = teamMode(mode, call.cwd);
  try { return await decide(call, opts); } catch (e) {
    console.error(`reflex: ${e.message}`);
    const fallback = CONFIG.mode === "enforce" && !call.subgoal ? (safeFallback() ?? "ask") : "pass";
    return {effective: fallback, decision: "error", reason: `reflex error (${e.message.slice(0, 80)}), fallback ${fallback}`, source: "error"};
  } finally { CONFIG.mode = mode; }
}
// A policy "allow" under REFLEX_ALLOW: kept only when on and enforcing, logged as would_allow while
// it is watched, otherwise the plain pass the gate has always given.
export function allowSetting(j) {
  if (j.outcome !== "allow" || (CONFIG.allow === "on" && CONFIG.mode === "enforce")) return j;
  return {...j, outcome: ["shadow", "on"].includes(CONFIG.allow) ? "would_allow" : "pass"};
}
// Prompts an allow must never skip: a command that asks to leave the sandbox (Claude Code's
// dangerouslyDisableSandbox, whose own prompt is the human check on that), and plan mode, where
// anything outside the read-only set prompts on purpose. Logged as pass, not would_allow.
export function holdAllow(j, call) {
  const why = call.unsandboxed ? "asks to run outside the sandbox" : call.permission_mode === "plan" ? "plan mode" : null;
  return j.outcome === "allow" && why ? {...j, outcome: "pass", rule: `low risk (not allowed: ${why})`} : j;
}
// A fallback can pass, ask or deny; never allow, whatever the file says.
function safeFallback() { try { const f = load("policy.json").fallback; return ["pass", "ask", "deny"].includes(f) ? f : null; } catch { return null; } }
// Only a fresh Jev judgment, a System 2 approval or a human's queue approval may allow; a rule, the
// read-only list or the fast lane never does.
export const view = (j, effective) => ({effective: effective === "allow" && !["jev", "judge", "queue"].includes(j.source) ? "pass"
                                   : ["pass", "allow", "ask", "deny"].includes(effective) ? effective : "ask", decision: j.outcome, reason: `reflex (${j.source}): ${j.rule}`,
                                 source: j.source, policy: j.policy_version ?? null, ...(j.plan && {plan: j.plan})});

// After the command: did it run, and how did it end. An effective "ask" followed by a record
// means it ran after the prompt; only an explicit "denied" event establishes rejection.
// Only the verdict on the run is kept, never its output.
export function record(ev) {
  if (CONFIG.mode === "off") return;
  append(FEEDBACK(), {ts: new Date().toISOString(), agent: ev.agent ?? null, event: ev.event ?? "ran",
    session_id: ev.session_id ?? null, call_id: ev.call_id ?? null, exit_code: ev.exit_code ?? null,
    ...(ev.prompt_id && {prompt_id: ev.prompt_id}), ...(ev.key && {key: ev.key})});
  // the runaway guard's failing-command loop and denial storm read these
  if (["failed", "denied"].includes(ev.event)) runawayMark(ev);
}

// Logs. One JSON line per judged command; the same shape report.mjs replays.
export function append(path, obj) {
  mkdirSync(CONFIG.data, {recursive: true});
  if (existsSync(path) && statSync(path).size > ROTATE_BYTES) renameSync(path, path.replace(/\.jsonl$/, `.${Date.now()}.jsonl`));
  appendFileSync(path, [obj].flat().map(o => JSON.stringify(o) + "\n").join(""));   // one write: a batch stays together
}

// The home directory as ~, so a webhook does not carry the local account name.
const tilde = p => p === homedir() || p.startsWith(homedir() + "/") ? `~${p.slice(homedir().length)}` : p;
function trace(j, call, effective) {
  const cmd = redact(call.command);
  const state = j.state ?? {call: {title: cmd.slice(0, 160), command: cmd, cwd: call.cwd}};
  append(TRACE(), {ts: new Date().toISOString(), tag: j.tag ?? "tool-gate", model: CONFIG.model,
    qset_version: j.qset ?? null, latency_s: j.latency_s ?? 0, state_sha: sha(state), state,
    questions: j.questions ?? {}, answers: j.answers ?? {}, usage: j.usage ?? {}, error: j.error ?? null,
    decision: j.outcome, policy_decision: j.policy_outcome ?? j.outcome, rule: j.rule, source: j.source, policy_version: j.policy_version ?? null,
    mode: CONFIG.mode, emitted: effective === "pass" ? null : effective,
    agent: call.agent ?? null, session_id: call.session_id ?? null, call_id: call.call_id ?? null,
    permission_mode: call.permission_mode ?? null, ...(j.plan && {plan: j.plan}), ...(j.ladder && {ladder: j.ladder}), ...((j.runaway ?? call.runaway) && {runaway: j.runaway ?? call.runaway}),
    ...(j.id && {rule_id: j.id}), ...(call.tier && {tier: call.tier}), cwd: call.cwd ?? null});
  // the decision webhook (notify.mjs): redacted, detached, never waited for; a trusted team policy may add one.
  // REFLEX_NOTIFY=off sends nothing (doctor's probes set it).
  const targets = [CONFIG.notify.target, teamPolicy(call.cwd)?.notify].filter(Boolean);
  if (targets.length && process.env.REFLEX_NOTIFY !== "off") notifyLater(targets, {ts: new Date().toISOString(), agent: call.agent ?? null, session_id: call.session_id ?? null,
    cwd: tilde(redact(call.cwd ?? "")), prod: !!call.tier?.prod, prod_by: call.tier?.prod ? call.tier.by : null, command: cmd.slice(0, 500),
    decision: effective === "pass" || !effective ? "pass" : effective, judged: j.outcome, mode: CONFIG.mode, source: j.source, rule_id: j.id ?? null,
    reason: redact(j.rule ?? "").slice(0, 300)});
}

// ---------------------------------------------------------------------------------------------
// Claude Code adapter: PreToolUse / PostToolUse hook JSON <-> the contract above.
// https://docs.claude.com/en/docs/claude-code/hooks
// An MCP tool (mcp__<server>__<tool>) or a file tool (Edit, Write, MultiEdit, NotebookEdit, Codex
// apply_patch) as a tool call for decide(): the tool gate (tools.mjs) judges it. null for any other tool.
const gatedTool = (name, input) => { const t = toolOf(name, input); return t && (t.kind === "mcp" || t.paths.length || t.unreadable) ? t : null; };
export function claudeCall(input) {
  const t = input.tool_input ?? {};
  if (gatedTool(input.tool_name, t))
    return {agent: "claude-code", tool: input.tool_name, input: t, cwd: input.cwd, session_id: input.session_id, call_id: input.tool_use_id,
            prompt_id: input.prompt_id, transcript_path: input.transcript_path, permission_mode: input.permission_mode, ...(input.agent_id && {agent_id: input.agent_id})};
  // Agent (formerly Task) spawns a subagent: its type, description and prompt are the subgoal.
  // A resume continues earlier work on purpose, so it is not checked.
  const subgoal = ["Task", "Agent"].includes(input.tool_name) && t.prompt && !t.resume
    ? [t.subagent_type && `agent: ${t.subagent_type}`, t.description, t.prompt].filter(Boolean).join("\n") : undefined;
  if (input.tool_name !== "Bash" && !subgoal) return null;
  // A subagent's hooks carry its parent's session_id plus its own agent_id: its subgoals are its own.
  const session_id = subgoal && input.agent_id ? `${input.session_id}/${input.agent_id}` : input.session_id;
  return {agent: "claude-code", ...(subgoal ? {subgoal} : {command: t.command}), cwd: input.cwd,
          session_id, call_id: input.tool_use_id, prompt_id: input.prompt_id, transcript_path: input.transcript_path,
          permission_mode: input.permission_mode, unsandboxed: t.dangerouslyDisableSandbox === true, ...(!subgoal && input.agent_id && {agent_id: input.agent_id})};
}
// What a PermissionRequest is about, as the trace (state.call.command) and subgoals.jsonl store it:
// PermissionRequest input has no tool_use_id, so the text is the join key.
export const promptKey = text => sha(redact(text).slice(0, 2000));
// PermissionRequest: Claude Code is about to show its permission dialog (or, where it cannot
// prompt, to deny). Recorded, never answered, so the dialog appears as it would without Reflex.
// A pass Claude Code's allowlist or permission mode let through has no such record, which is how
// report.mjs tells a human approval from an allowlist, and subgoal dedup a rejected spawn.
export function claudePrompted(input) {
  const call = claudeCall(input);
  if (!call || call.tool) return;
  record({agent: "claude-code", event: "prompted", session_id: call.session_id, prompt_id: input.prompt_id,
          key: promptKey(call.command ?? call.subgoal)});
}
async function claudePre(input) {
  const call = claudeCall(input);
  if (!call) return;
  const out = claudeOut(await decideSafe(call));
  if (out) process.stdout.write(JSON.stringify(out));
}
// pass is silent: Claude Code's own permission rules decide. allow skips its prompt, but its deny
// and ask rules are still evaluated after the hook. The plugin never allows: its allow is a pass.
const EMITTED = ["ask", "deny"];
export const claudeOut = d => EMITTED.includes(d.effective) ? {hookSpecificOutput: {hookEventName: "PreToolUse",
  permissionDecision: d.effective, permissionDecisionReason: d.reason}} : null;
function claudePost(input) {
  if (input.tool_name && !["Bash", "Task", "Agent"].includes(input.tool_name)) return;
  // Claude's Bash result carries no exit code; PostToolUseFailure is the failure signal.
  const ev = input.hook_event_name;
  record({agent: "claude-code", event: ev === "PermissionDenied" ? "denied" : ev === "PostToolUseFailure" ? "failed" : "ran",
          session_id: input.session_id, call_id: input.tool_use_id, agent_id: input.agent_id,
          exit_code: input.tool_response?.exit_code ?? (ev === "PostToolUse" ? 0 : null)});
}

// Codex CLI adapter: hooks.json PreToolUse / PostToolUse (https://learn.chatgpt.com/docs/hooks).
// Codex PreToolUse cannot "ask" (it would fail open), so an ask becomes a deny whose reason tells
// the agent to get the user's confirmation; the user can then run the command or approve it.
// It cannot plain-allow either (an "allow" is not honoured and falls through), so allow is silent,
// like pass, and Codex's own approval policy decides.
// spawn_agent (Codex 0.155+, multi-agent v1 and v2; matcher alias Agent) runs PreToolUse like any
// function tool and a deny blocks it, so subgoal dedup hooks it: its message (or text items), task
// name and agent type are the subgoal. SubagentStart cannot be used: its input has no task text and
// its output only adds context.
export function codexCall(input) {
  const t = input.tool_input ?? {};
  if (input.tool_name === "Bash") return {agent: "codex", command: t.command, cwd: input.cwd, session_id: input.session_id, call_id: input.tool_use_id};
  if (gatedTool(input.tool_name, t)) return {agent: "codex", tool: input.tool_name, input: t, cwd: input.cwd, session_id: input.session_id, call_id: input.tool_use_id};
  if (input.tool_name !== "spawn_agent") return null;
  const text = typeof t.message === "string" && t.message.trim() ? t.message
    : (Array.isArray(t.items) ? t.items : []).map(i => typeof i?.text === "string" ? i.text : "").filter(Boolean).join("\n");
  if (!text) return null;
  // A subagent's spawns are its own, as in Claude Code.
  return {agent: "codex", subgoal: [t.agent_type && `agent: ${t.agent_type}`, t.task_name, text].filter(Boolean).join("\n"), cwd: input.cwd,
          session_id: input.agent_id ? `${input.session_id}/${input.agent_id}` : input.session_id, call_id: input.tool_use_id};
}
async function codexPre(input) {
  const call = codexCall(input);
  if (!call) return;
  const out = codexOut(await decideSafe(call), !!call.tool);
  if (out) process.stdout.write(JSON.stringify(out));
}
export function codexOut(d, tool = false) {
  if (!["ask", "deny"].includes(d.effective)) return null;
  const reason = d.effective === "ask"
    ? `${d.reason}. This hook cannot open an approval dialog. ${tool ? "The user can make this change or run this tool themselves."
      : "The user can review and run the exact command with reflex run in their own terminal (include --cwd)."} A chat confirmation does not unblock this hook; do not retry or disable it.` : d.reason;
  return {hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason}};
}
function codexPost(input) {
  if (!["Bash", "spawn_agent"].includes(input.tool_name)) return;
  record({agent: "codex", event: "ran", session_id: input.session_id, call_id: input.tool_use_id});
}

// Hermes Agent adapter: config.yaml `hooks: pre_tool_call` shell hook on the terminal tool.
// "approve" routes through Hermes' own approval prompt; rule_key is per command, so approving one
// command "for the session" never pre-approves a different one.
// delegate_task spawns subagents: {tasks: [{goal, context?}]} or the legacy {goal, context?}, each
// task a subgoal; other actions (list, steer, stop) control running children and are not checked.
// A batch where only some tasks repeat earlier work is blocked with the list, not trimmed: a
// "modify" hook could drop them, but nothing would tell the model which ones went, and it would
// launch them again.
export function hermesSubgoals(t = {}) {
  if (t.action && t.action !== "spawn") return [];
  const items = Array.isArray(t.tasks) && t.tasks.length ? t.tasks : [t];
  const text = x => typeof x?.goal === "string" && x.goal.trim()
    ? [x.goal, typeof x.context === "string" && x.context.trim() && `context: ${x.context.slice(0, 300)}`].filter(Boolean).join("\n") : "";
  return items.map(text).filter(Boolean);
}
async function hermesPre(input) {
  if (input.tool_name === "delegate_task") {
    const subgoals = hermesSubgoals(input.tool_input ?? {});
    if (!subgoals.length) return process.stdout.write("{}");
    const d = await decideSafe({agent: "hermes", subgoals, whole: true, cwd: input.cwd, session_id: input.session_id, call_id: input.extra?.tool_call_id});
    return process.stdout.write(JSON.stringify(d.effective === "deny" ? {action: "block", message: d.reason} : {}));
  }
  // MCP tools (mcp_<server>_<tool>) and the file tools (write_file, patch): the tool gate
  if (input.tool_name !== "terminal" && gatedTool(input.tool_name, input.tool_input)) {
    const d = await decideSafe({agent: "hermes", tool: input.tool_name, input: input.tool_input ?? {}, cwd: input.cwd,
                                session_id: input.session_id, call_id: input.extra?.tool_call_id});
    return process.stdout.write(JSON.stringify(hermesOut(d, `${input.tool_name} ${JSON.stringify(input.tool_input ?? {})}`)));
  }
  if (input.tool_name !== "terminal") return process.stdout.write("{}");
  const command = input.tool_input?.command;
  const d = await decideSafe({agent: "hermes", command, cwd: input.tool_input?.workdir ?? input.cwd,
                              session_id: input.session_id, call_id: input.extra?.tool_call_id});
  process.stdout.write(JSON.stringify(hermesOut(d, command)));
}
// Hermes has no allow verdict for a hook: pass and allow are both {}, and its own approvals decide.
export const hermesOut = (d, command) => d.effective === "deny" ? {action: "block", message: d.reason}
  : d.effective === "ask" ? {action: "approve", message: d.reason, rule_key: `reflex:${sha(command ?? "")}`} : {};
// post_tool_call also fires for a call a hook or guardrail blocked (status "blocked"): that one did
// not run, and neither did a cancelled one.
function hermesPost(input) {
  if (!["terminal", "delegate_task"].includes(input.tool_name)) return;
  const st = input.extra?.status;
  record({agent: "hermes", event: st === "blocked" ? "denied" : st === "cancelled" ? "failed" : "ran",
          session_id: input.session_id, call_id: input.extra?.tool_call_id});
}

const readStdin = () => JSON.parse(STDIN ?? readFileSync(0, "utf8"));
// ask needs a human: read y/N from the controlling terminal; no terminal means no approval.
function confirmOnTty(command, reason) {
  try {
    const fd = openSync("/dev/tty", "r+");
    const q = Buffer.from(`\n${reason}\nDirectory: ${JSON.stringify(process.cwd())}\nCommand (credentials masked): ${JSON.stringify(redact(command))}\nrun it? [y/N] `);
    writeSync(fd, q);
    const buf = Buffer.alloc(16), n = readSync(fd, buf, 0, 16, null);
    closeSync(fd);
    return /^y(es)?$/i.test(buf.toString("utf8", 0, n).trim());
  } catch { return false; }
}
const argv = process.argv.slice(2);
const flag = f => argv.includes(f);
const opt = n => { const i = argv.indexOf(n); return i > -1 ? argv[i + 1] : undefined; };
const main = isMain(import.meta);
// An error a hook does not handle goes to failsafe.mjs: the pre-execution hooks ask, the others warn.
const guarded = fn => Promise.resolve().then(fn).catch(hookFailure);

if (!main) { /* imported as a library */ }
else if (flag("--claude")) await guarded(async () => claudePre(readStdin()));
else if (flag("--claude-post")) await guarded(async () => claudePost(readStdin()));
else if (flag("--claude-prompted")) await guarded(async () => claudePrompted(readStdin()));
else if (flag("--codex")) await guarded(async () => codexPre(readStdin()));
else if (flag("--codex-post")) await guarded(async () => codexPost(readStdin()));
else if (flag("--hermes")) await guarded(async () => hermesPre(readStdin()));
else if (flag("--hermes-post")) await guarded(async () => hermesPost(readStdin()));
else if (flag("--decide")) await guarded(async () => process.stdout.write(JSON.stringify(await decideSafe(readStdin())) + "\n"));
else if (flag("--record")) await guarded(async () => record(readStdin()));
else if (flag("--bg")) await guarded(async () => decide(readStdin(), {background: true}));
else if (flag("--sh")) {
  // Shell shim (scripts/reflex-sh): bash-compatible `-c` / `-lc` calls are judged, then run, confirmed
  // on the terminal, or refused with exit 126. Everything else is passed to bash untouched.
  const args = argv.slice(argv.indexOf("--sh") + 1);
  const ci = args.findIndex(a => /^-[a-z]*c[a-z]*$/.test(a));
  const command = ci > -1 ? args[ci + 1] : undefined;
  const bash = ENV.REFLEX_SHELL ?? "/bin/bash";
  let verdict = "pass";
  if (command) {
    const d = await decideSafe({agent: ENV.REFLEX_AGENT ?? "shell", command, cwd: process.cwd(),
                                session_id: ENV.REFLEX_SESSION_ID, intent: ENV.REFLEX_INTENT});
    verdict = d.effective;   // pass and allow run: there is no other prompt to skip
    if (verdict === "ask") verdict = confirmOnTty(command, d.reason) ? "pass" : "deny";
    if (verdict === "deny") { console.error(`${d.reason}\nrefused; a human can run it directly if it is intended.`); process.exit(126); }
  }
  const r = spawnSync(bash, args, {stdio: "inherit"});
  // It ran: nothing after this may fail into failsafe.mjs, which would run it again.
  if (command) try { record({agent: ENV.REFLEX_AGENT ?? "shell", event: "ran", exit_code: r.status}); } catch { /* the log only */ }
  process.exit(r.status ?? 1);
}
else if (flag("--check")) {
  // Try one command without an agent: node gate.mjs --check "terraform apply" [--cwd dir] [--intent text]
  const cwd = opt("--cwd") ?? process.cwd(), intent = opt("--intent");
  const j = await judge({command: opt("--check"), cwd, session: intent ? {intent} : {}, useCache: false});
  const answers = Object.fromEntries(Object.entries(j.answers ?? {}).map(([k, a]) => [k, a.noul ?? a.choice ?? a.score]));
  console.log(JSON.stringify({decision: j.outcome, rule: j.rule, source: j.source, policy: j.policy_version ?? null,
                              latency_s: j.latency_s ?? 0, answers, env: j.state?.call?.env, plan: j.plan ?? j.state?.call?.plan, error: j.error ?? undefined}, null, 1));
}
else console.error("usage: gate.mjs --check <cmd> | --decide | --record | --claude[-post|-prompted] | --codex[-post] | --hermes[-post] | --sh | --bg | --selfcheck");
