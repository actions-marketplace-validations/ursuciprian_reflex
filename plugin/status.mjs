#!/usr/bin/env node
// Installation checks are local. A synthetic probe cannot establish that a host trusted a hook.
import {existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {homedir, platform, tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {CLAUDE_SETTINGS, CODEX_HOOKS, CONFIG, USER_CONFIG, USER_CONFIG_FILE, configurationError, load, settingsHooks, setupFile} from "./gate.mjs";
import {compile} from "./policy.mjs";
import {OPTIONS_VISIBLE, PLUGIN_MODE, pluginKey} from "./plugin.mjs";
import {PROVIDERS, keyRouteError} from "./providers.mjs";
import {detectors, guardMode, sourceKind} from "./guard.mjs";
import {judgeKey, probe, budgetState} from "./judge2.mjs";
import {breaker, listItems, runawayTrips} from "./autonomy.mjs";
import {health as layaHealth} from "./laya.mjs";
import {FASTLANE_FILE, loadFastLane} from "./fastlane.mjs";
import {teamPolicy} from "./team.mjs";
import {infraSettings, which} from "./infra.mjs";
import {inWindow} from "./freeze.mjs";
import {targetLabel, testTargets} from "./notify.mjs";
import {isMain} from "./failsafe.mjs";

// The script itself runs only when started (node status.mjs), never when the file is imported.
if (isMain(import.meta)) {
const doctor = process.argv.includes("--doctor"), json = process.argv.includes("--json");
const errors = [], warnings = [], agents = [];
const home = homedir();
const files = {claude: join(home, ".claude/settings.json"), codex: CODEX_HOOKS, pi: join(home, ".pi/agent/extensions/reflex.ts"),
  omp: join(home, ".omp/agent/extensions/reflex.ts"), opencode: join(process.env.XDG_CONFIG_HOME || join(home, ".config"), "opencode/plugins/reflex.js")};
const quote = s => `"${s.replace(/(["\\`$])/g, "\\$1")}"`;
const read = path => JSON.parse(readFileSync(path, "utf8"));
const configuration = configurationError();
if (configuration) errors.push(configuration);
if (platform() === "win32") errors.push("Native Windows is not supported; run Reflex and the agent inside WSL.");
if (CONFIG.mode === "off") warnings.push("Protection is off.");
// Keyless autonomy: the local engine with System 2 on, so what the rules do not cover goes to System 2, not to a human.
const keyless = CONFIG.engine === "local" && CONFIG.judge.enabled;
if (CONFIG.engine === "local") warnings.push(`Local coverage: shell rules and deterministic instructions; ${keyless ? "keyless autonomy: commands they do not cover go to System 2, which allows only small ones" : "uncertain commands ask in enforce mode"}. Hosted features are disabled.`);
const fastlane = loadFastLane();
if (fastlane.error) warnings.push(`${FASTLANE_FILE} is ignored: ${fastlane.error}. Fix it or remove it; until then only the bundled fast lane applies.`);
// The team policy of the repository this runs in (.reflex/policy.json, team.mjs).
const tp = teamPolicy(process.cwd());
const team_policy = tp && {file: tp.file, sha256: tp.sha256, trust: tp.trust, fastlane_active: tp.active_fastlane, valid: !tp.errors.length,
  rules: tp.rules.filter(r => r.id !== "team:prod").length, always_human: tp.always_human.length, prod_markers: tp.rules.filter(r => r.id === "team:prod").length,
  mode_floor: tp.mode, freezes: tp.freeze.length, fastlane_entries: tp.fastlane_count ?? 0, notify: tp.notify_target ? (tp.notify ? "active" : "inactive (needs trust)") : "none", errors: tp.errors};
if (tp?.errors.length) warnings.push(`Team policy ${tp.file} is invalid: ${tp.errors.join("; ")}. Its valid stricter parts apply; its fast lane does not.`);
if (tp?.trust === "changed") warnings.push(`Team policy ${tp.file} changed since you trusted it: its fast lane is off until you review it and run reflex trust again.`);
if (tp?.mode === "enforce" && CONFIG.mode === "shadow") warnings.push(`Team policy sets a mode floor: enforce applies in ${tp.root}.`);
// The plan-aware infra gate (infra.mjs): which binaries it would read plans and diffs with.
const infraSet = infraSettings(USER_CONFIG.infra, tp?.infra);
const infra = {enabled: infraSet.enabled, destroy: infraSet.destroy, require_plan_in_prod: infraSet.require_plan_in_prod, kubectl_diff: infraSet.kubectl_diff,
  helm_diff: infraSet.helm_diff, timeout_ms: infraSet.timeout_ms, terraform: which("terraform"), tofu: which("tofu"), kubectl: which("kubectl"), helm: which("helm")};
if (infra.enabled && infra.kubectl_diff && !infra.kubectl) warnings.push("infra.kubectl_diff is on but kubectl is not on PATH: kubectl changes are judged by the command text only.");
if (infra.enabled && infra.helm_diff && !infra.helm) warnings.push("infra.helm_diff is on but helm is not on PATH: helm upgrades are judged by the command text only.");
if (CONFIG.mode === "shadow") warnings.push("Shadow mode enforces deterministic rules. Other decisions are logged without blocking.");
// Change freezes (freeze.mjs): config.json and this directory's team policy, checked against the clock now.
const windows = [...CONFIG.freeze.windows, ...(tp?.freeze ?? [])], onNow = windows.filter(w => inWindow(w, new Date()));
const freeze = {windows: windows.length, active: onNow.map(w => ({reason: w.reason, outcome: w.outcome, applies_to: w.applies_to}))};
const scope = w => w.applies_to === "all" ? "every command that is not read-only" : "production commands that are not read-only";
if (onNow.length) warnings.push(`Change freeze in force now: ${onNow.map(w => `${w.reason}; ${scope(w)} ${w.outcome === "deny" ? "are denied" : "ask"}`).join(" | ")}.`);
// The decision webhook (notify.mjs). Only --notify-test sends anything: one dry-run message per target.
const hooks = [CONFIG.notify.target, tp?.notify].filter(Boolean);
const notify = {targets: hooks.map(targetLabel), test: null};
for (const e of CONFIG.freeze.errors) errors.push(`${e}. Until it is fixed, every command that is not read-only asks.`);
if (CONFIG.notify.error) errors.push(`${CONFIG.notify.error}. Nothing is sent until it is fixed.`);
if (process.argv.includes("--notify-test")) {
  if (!hooks.length) warnings.push("--notify-test: no notify webhook is configured (config.json notify).");
  notify.test = await testTargets(hooks);
  for (const t of notify.test) if (t.error || t.status >= 300) errors.push(`notify test to ${t.target} failed: ${t.error ?? `HTTP ${t.status}`}.`);
}
const policy = setupFile("policy.json");
try { compile(load("policy.json")); load("rules.json"); load("questions.json"); }
catch (e) { errors.push(`Cannot load policy: ${e.message}`); }
try { detectors(); sourceKind({tool: "WebFetch"}); }
catch (e) { errors.push(`Cannot load the injection guard setup: ${e.message}`); }
if (guardMode() !== CONFIG.mode) warnings.push(`Injection guard mode is ${guardMode()} (REFLEX_GUARD or "guard" in config.json).`);
let key = "not required";
// The Jev provider and the host its key goes to; never the key itself.
const provider = CONFIG.engine === "jev" ? {name: CONFIG.provider, host: PROVIDERS[CONFIG.provider]?.pinned ?? CONFIG.keyHost} : null;
const route = provider && PROVIDERS[CONFIG.provider] && keyRouteError(CONFIG.provider, CONFIG.api, CONFIG.keyHost, USER_CONFIG.laya?.port ?? 8421);
if (route) errors.push(`Jev: ${route}, so every Jev call is refused (check REFLEX_API_URL).`);
// The Claude Code plugin reads its key from its options only: no environment, no Keychain lookup.
// From the Bash tool (/reflex:status) the options are not visible: this report is config.json's view.
if (PLUGIN_MODE && !OPTIONS_VISIBLE) warnings.push("The plugin options (engine, provider, mode, keys) reach only the plugin's hooks, not a command run with the Bash tool: this report shows config.json and the defaults. The hooks apply the options on top.");
if (CONFIG.engine === "jev" && PLUGIN_MODE && !OPTIONS_VISIBLE) key = "plugin option (not visible from the Bash tool)";
else if (CONFIG.engine === "jev" && PLUGIN_MODE) {
  key = pluginKey() ? "plugin option" : "missing";
  if (key === "missing") errors.push(`Jev through ${CONFIG.provider} needs the Jev API key plugin option (/plugin, reflex, Configure), or the engine option set to local.`);
}
// engine laya: the local server must answer, or System 1 falls back to the policy exactly as in a Jev outage.
const laya = CONFIG.engine === "laya" ? await layaHealth() : null;
if (laya && !laya.ok) errors.push(`Laya server not reachable at ${CONFIG.api} (${laya.error}): reflex laya start. Until it answers, System 1 falls back to the policy, as in a Jev outage.`);
if (laya) warnings.push("Engine laya is experimental: measured far below Jev on every golden set (docs/GUIDE.md#laya-local-system-1); keep shadow mode, or use Jev to enforce.");
if (laya?.ok && !laya.loaded.includes(CONFIG.model)) errors.push(`Laya server at ${CONFIG.api} does not hold checkpoint ${CONFIG.model} (resident: ${laya.loaded.join(", ")}).`);

for (const [name, saved] of Object.entries(USER_CONFIG.agents ?? {})) {
  if (!saved || typeof saved.root !== "string" || typeof saved.node !== "string") { errors.push(`${name}: invalid installation record`); continue; }
  const item = {name, configured: false, guard: false, mode: process.env.REFLEX_MODE ?? saved.mode, allow: process.env.REFLEX_ALLOW ?? saved.allow,
    engine: CONFIG.engine, hook_observed: false, last_seen: null, version: null, checks: []};
  const gate = join(saved.root, "gate.mjs"), guard = join(saved.root, "guard.mjs");
  const version = spawnSync(name, ["--version"], {encoding: "utf8", timeout: 3000});
  if (version.status === 0) item.version = version.stdout.trim().split("\n")[0].slice(0, 160);
  else warnings.push(`${name}: executable not available on this PATH; verify in the environment where the agent runs.`);
  if (saved.manual || name === "hermes") {
    warnings.push(`${name}: configuration is manual; use hermes hooks list in each profile. Doctor cannot verify its YAML or trust settings.`);
  } else if (files[name]) try {
    const file = files[name], source = readFileSync(file, "utf8");
    if (["claude", "codex"].includes(name)) {
      // Through hook.mjs (fails closed); the form before it still gates, but a crash while it loads passes.
      const entry = [`${quote(saved.node)} ${quote(join(saved.root, "hook.mjs"))} `, `${quote(saved.node)} `];
      const expected = entry.map(e => `${e}${quote(gate)} --${name} --mode ${saved.mode} --allow ${saved.allow}`);
      // the matcher before the tool gate (MCP tool calls, file writes) still gates commands
      const matchers = name === "claude" ? ["^(Bash|Task|Agent|Edit|Write|MultiEdit|NotebookEdit)$|^mcp__", "Bash|Task|Agent"] : ["^(Bash|spawn_agent|apply_patch)$|^mcp__", "^(Bash|spawn_agent)$"];
      const groups = JSON.parse(source).hooks?.PreToolUse ?? [];
      const pre = groups.flatMap(g => matchers.includes(g.matcher) ? g.hooks ?? [] : []).filter(h => h.type === "command");
      item.configured = pre.some(h => expected.includes(h.command));
      if (item.configured && !groups.some(g => g.matcher === matchers[0] && g.hooks?.some(h => expected.includes(h.command))))
        warnings.push(`${name}: the gate hook in ${file} predates the tool gate: MCP tool calls and file writes are not checked. Re-run reflex setup --agents ${name}.`);
      if (item.configured && !pre.some(h => h.command === expected[0]))
        warnings.push(`${name}: the hooks in ${file} predate the fail-closed entry (hook.mjs): an error while Reflex loads would let the command run. Re-run reflex setup --agents ${name}.`);
      const post = entry.map(e => `${e}${quote(guard)} --${name} --mode ${saved.mode}`);
      item.guard = (JSON.parse(source).hooks?.PostToolUse ?? []).some(g => g.hooks?.some(h => h.type === "command" && post.includes(h.command)));
    } else {
      item.configured = source.includes(JSON.stringify(gate)) && source.includes(JSON.stringify(saved.node)) &&
        source.includes(JSON.stringify(saved.mode)) && source.includes(JSON.stringify(saved.allow));
      item.guard = source.includes('"--scan"') && source.includes('"--prompt"');
    }
    if (item.configured && !item.guard) errors.push(`${name}: the injection guard hooks are missing in ${file}. Re-run reflex setup --agents ${name}.`);
    if (!item.configured) errors.push(`${name}: expected Reflex pre-execution adapter is missing or changed in ${file}. Re-run reflex setup --agents ${name}.`);
  } catch (e) { errors.push(`${name}: cannot read its adapter: ${e.message}`); }
  if (!existsSync(gate)) errors.push(`${name}: gate is missing at ${gate}. Re-run setup.`);
  try {
    const seen = read(join(CONFIG.data, "health", `${name === "claude" ? "claude-code" : name}.json`));
    item.last_seen = seen.at;
    item.hook_observed = seen.gate === saved.root && Date.parse(seen.at) >= Date.parse(saved.installed_at) &&
      seen.mode === item.mode && seen.engine === item.engine && seen.allow === item.allow;
  } catch { /* no real hook event yet */ }
  if (!item.hook_observed) warnings.push(`${name}: awaiting a real pre-execution event. Restart the agent${name === "codex" ? " and trust the hooks in /hooks" : ""}, run a harmless command, then check status again.`);
  agents.push(item);
}
// The Claude Code plugin (reflex@<marketplace>). Its hooks stand down while `reflex setup` hooks are
// in the settings file, so exactly one of the two judges each call.
const found = settingsHooks(), settingsLive = found.live.length > 0;
for (const s of found.stale) errors.push(`Claude Code: ${CLAUDE_SETTINGS} has a Reflex hook for ${s}, which does not exist; that hook fails and gates nothing. Re-run reflex setup --agents claude, or remove it.`);
let installs = [], enabled = {};
try { installs = Object.entries(read(join(dirname(CLAUDE_SETTINGS), "plugins/installed_plugins.json")).plugins ?? {})
  .filter(([id]) => id.startsWith("reflex@")).flatMap(([id, list]) => (Array.isArray(list) ? list : []).map(i => ({id, ...i}))); } catch { /* no plugins */ }
try { enabled = read(CLAUDE_SETTINGS).enabledPlugins ?? {}; } catch { /* no settings */ }
// Only a user-scope install applies everywhere; a project or local one applies in its own project,
// which this check does not know, so it is reported and not probed.
const userInstalls = installs.filter(i => i.scope === "user" && enabled[i.id] !== false);
const pluginOn = userInstalls.length > 0;
const plugin = {installed: installs.map(i => ({id: i.id, scope: i.scope, project: i.projectPath ?? null, version: i.version ?? null, path: i.installPath ?? null})),
  enabled: pluginOn, active: pluginOn && !settingsLive, settings_hooks: settingsLive, stale_settings_hooks: found.stale, checks: []};
const scoped = installs.filter(i => i.scope !== "user").map(i => `${i.id} (${i.scope}${i.projectPath ? ` ${i.projectPath}` : ""})`);
const claudeHooks = (settingsLive ? `reflex setup hooks in ${CLAUDE_SETTINGS}${pluginOn || scoped.length ? " (the plugin stands down)" : ""}`
  : pluginOn ? `the Claude Code plugin (${userInstalls[0].id})` : "none recorded") + (scoped.length ? `; plugin installed for a project: ${scoped.join(", ")}` : "");
if (plugin.active && CONFIG.judge.enabled) warnings.push("System 2 is on, but the plugin's PreToolUse hook has a 10 s timeout and a longer judge call fails open. Use reflex setup --agents claude, which sizes the timeout to the judge.");
if (doctor && plugin.active) for (const i of userInstalls) {
  const gate = join(i.installPath ?? "", "gate.mjs");
  if (!existsSync(gate)) { errors.push(`plugin ${i.id}: gate is missing at ${gate}. Run claude plugin update ${i.id}.`); continue; }
  const scratch = mkdtempSync(join(tmpdir(), "reflex-doctor-"));
  try {
    for (const [command, expected] of [["git status", "pass"], ["git push --force origin main", "deny"]]) {
      // judged, never executed; the probe's records go to a disposable directory
      const r = spawnSync(process.execPath, [gate, "--claude", "--plugin"], {encoding: "utf8", timeout: 10000,
        input: JSON.stringify({tool_name: "Bash", tool_input: {command}, cwd: scratch, session_id: "reflex-doctor"}),
        env: {...process.env, REFLEX_ENGINE: "local", REFLEX_DATA_DIR: scratch, REFLEX_NOTIFY: "off"}});
      let actual;
      try { actual = JSON.parse(r.stdout.trim() || "{}").hookSpecificOutput?.permissionDecision ?? "pass"; } catch { /* invalid output fails below */ }
      const ok = r.status === 0 && actual === expected;
      plugin.checks.push({command, expected, actual: actual ?? null, ok});
      if (!ok) errors.push(`plugin ${i.id}: ${expected} probe failed (${r.error?.message ?? actual ?? "invalid output"}).`);
    }
  } finally { rmSync(scratch, {recursive: true, force: true}); }
}
// The Codex CLI plugin: `codex plugin add reflex@<marketplace>` copies it to
// $CODEX_HOME/plugins/cache/<marketplace>/reflex/<version> and writes [plugins."reflex@<marketplace>"]
// enabled = true into config.toml. Its hooks stand down while `reflex setup` hooks are in hooks.json.
const codexHome = dirname(CODEX_HOOKS), codexFound = settingsHooks(CODEX_HOOKS, "codex"), codexLive = codexFound.live.length > 0;
for (const s of codexFound.stale) errors.push(`Codex CLI: ${CODEX_HOOKS} has a Reflex hook for ${s}, which does not exist; that hook fails and gates nothing. Re-run reflex setup --agents codex, or remove it.`);
let codexToml = "";
try { codexToml = readFileSync(join(codexHome, "config.toml"), "utf8"); } catch { /* no config */ }
// ponytail: a line scan, not a TOML parser; enough for the table codex plugin add writes.
const codexEnabled = id => {
  const lines = codexToml.split("\n"), start = lines.findIndex(l => l.trim() === `[plugins."${id}"]`);
  if (start < 0) return false;
  const end = lines.findIndex((l, i) => i > start && /^\s*\[/.test(l));
  return !lines.slice(start + 1, end < 0 ? undefined : end).some(l => /^\s*enabled\s*=\s*false\b/.test(l));
};
const ls = d => { try { return readdirSync(d); } catch { return []; } };
const codexInstalls = ls(join(codexHome, "plugins/cache")).flatMap(m => ls(join(codexHome, "plugins/cache", m, "reflex"))
  .map(v => ({id: `reflex@${m}`, version: v, path: join(codexHome, "plugins/cache", m, "reflex", v)})));
// Codex keeps one cached copy per version; the newest per marketplace is the one it runs.
const newer = (a, b) => b.version.localeCompare(a.version, undefined, {numeric: true});
const codexOn = [...new Map(codexInstalls.filter(i => codexEnabled(i.id)).sort(newer).reverse().map(i => [i.id, i])).values()];
const codex_plugin = {installed: codexInstalls, enabled: codexOn.length > 0, active: codexOn.length > 0 && !codexLive, settings_hooks: codexLive, checks: []};
const codex_hooks = codexLive ? `reflex setup hooks in ${CODEX_HOOKS}${codexOn.length ? " (the plugin stands down)" : ""}`
  : codexOn.length ? `the Codex CLI plugin (${codexOn[0].id} ${codexOn[0].version})` : "none recorded";
// The opencode npm plugin ("@ursuciprian/reflex" in the global opencode.json). It registers no hooks
// while the plugin file `reflex setup` writes is in opencode's global plugins directory.
const ocDir = join(process.env.XDG_CONFIG_HOME || join(home, ".config"), "opencode"), ocFile = join(ocDir, "plugins/reflex.js");
let ocNpm = null;
for (const f of ["opencode.json", "opencode.jsonc"]) try {
  if (/"@ursuciprian\/reflex(?:@[^"]*)?"/.test(readFileSync(join(ocDir, f), "utf8"))) ocNpm = join(ocDir, f);
} catch { /* not there */ }
let ocSetup = false;
try { const g = readFileSync(ocFile, "utf8").match(/"(\/[^"]*\/gate\.mjs)"/)?.[1]; ocSetup = !!g && existsSync(g); } catch { /* not there */ }
const opencode_plugin = ocSetup ? `reflex setup plugin file ${ocFile}${ocNpm ? " (the npm plugin stands down)" : ""}`
  : ocNpm ? `the opencode npm plugin (@ursuciprian/reflex in the global ${ocNpm})` : "none recorded";
if (doctor && codex_plugin.active) for (const i of codexOn) {
  const gate = join(i.path, "gate.mjs");
  if (!existsSync(gate)) { errors.push(`Codex plugin ${i.id}: gate is missing at ${gate}. Run codex plugin add ${i.id}.`); continue; }
  const scratch = mkdtempSync(join(tmpdir(), "reflex-doctor-"));
  try {
    for (const [command, expected] of [["git status", "pass"], ["git push --force origin main", "deny"]]) {
      // judged, never executed; the probe's records go to a disposable directory
      // the installed hook command itself, the way Codex runs it: $SHELL -lc with PLUGIN_ROOT set, so a
      // node missing from the login shell PATH fails here as it would in Codex
      let hook;
      try { hook = read(join(i.path, "hooks/codex.json")).hooks.PreToolUse[0].hooks[0].command; } catch { hook = null; }
      const r = hook ? spawnSync(process.env.SHELL || "/bin/sh", ["-lc", hook], {encoding: "utf8", timeout: 10000,
        input: JSON.stringify({tool_name: "Bash", tool_input: {command}, cwd: scratch, session_id: "reflex-doctor"}),
        env: {...process.env, PLUGIN_ROOT: i.path, REFLEX_ENGINE: "local", REFLEX_DATA_DIR: scratch, REFLEX_NOTIFY: "off"}}) : {status: 1, stdout: "", error: {message: "hooks/codex.json is missing or invalid"}};
      let actual;
      try { actual = JSON.parse(r.stdout.trim() || "{}").hookSpecificOutput?.permissionDecision ?? "pass"; } catch { /* invalid output fails below */ }
      const ok = r.status === 0 && actual === expected;
      codex_plugin.checks.push({command, expected, actual: actual ?? null, ok});
      if (!ok) errors.push(`Codex plugin ${i.id}: ${expected} probe failed (${r.error?.message ?? actual ?? "invalid output"}).`);
    }
  } finally { rmSync(scratch, {recursive: true, force: true}); }
}
if ((codex_plugin.active || (ocNpm && !ocSetup)) && CONFIG.judge.enabled) warnings.push("System 2 is on, but the Codex and opencode plugins give a gate call 15 s and a longer judge call fails open. Use reflex setup --agents codex,opencode, which sizes the timeout to the judge.");
let codexSeen = null;
try { codexSeen = read(join(CONFIG.data, "health", "codex.json")); } catch { /* no hook event yet */ }
if (codex_plugin.active && !codexOn.some(i => { try { return codexSeen?.gate === realpathSync(i.path); } catch { return false; } }))
  warnings.push("Codex CLI plugin: no hook event from it yet. Codex runs plugin hooks only after you trust them: open codex, run /hooks and trust the Reflex entries.");
// Setup hooks silence the plugin even while Codex does not run them (untrusted or disabled in /hooks).
if (codexLive && codexOn.length && !agents.find(a => a.name === "codex")?.hook_observed)
  warnings.push(`Codex CLI: the plugin stands down for the reflex setup hooks in ${CODEX_HOOKS}, but none of them has run yet. Trust them in /hooks, or remove them (install.mjs --agent codex --uninstall) to let the plugin gate.`);
if (doctor && ocNpm && !ocSetup && spawnSync("node", ["--version"], {stdio: "ignore", timeout: 5000}).status !== 0)
  errors.push("opencode npm plugin: node is not on this PATH; the plugin runs the gate with node from the PATH opencode starts with, and gates nothing without it.");
if (!agents.length && !plugin.active && !codex_plugin.active && !ocNpm) warnings.push("No agent installations recorded. Run reflex setup --agents claude,codex, or use reflex run in your own terminal.");
// The escalation ladder. Reachability is a GET of the judge's model list: never a paid call.
const cliJudge = CONFIG.judge.backend === "cli";
const judge = {enabled: CONFIG.judge.enabled, backend: CONFIG.judge.backend, ...(cliJudge ? {cli: CONFIG.judge.cli, command: CONFIG.judge.command ?? null}
  : {url: CONFIG.judge.url, key: judgeKey() ? "found" : CONFIG.judge.key_env || CONFIG.judge.keychain ? "missing" : "none configured"}),
  model: CONFIG.judge.model ?? null, reachable: null, status: null, budget: null};
if (!configuration && CONFIG.judge.enabled) {
  const p = await probe();
  const b = budgetState();
  Object.assign(judge, {reachable: p.reachable, status: p.status, budget: {day: b.day, calls_used: b.calls, calls_left: b.calls_left, usd_used: +b.usd.toFixed(4), usd_left: b.usd_left}});
  if (!p.reachable) warnings.push(cliJudge ? `System 2's CLI (${p.url}) was not found: every escalation goes to a human. Re-run reflex setup --profile autonomous.`
    : `System 2 is not reachable at ${p.url} (${p.error}): every escalation goes to a human.`);
  else if (!p.ok) warnings.push(`System 2 answered HTTP ${p.status} at ${p.url}${p.status === 401 || p.status === 403 ? `: check the key (${CONFIG.judge.key_env ? `$${CONFIG.judge.key_env}` : "judge.keychain"})` : ""}.`);
  if (b.calls_left <= 0 || b.usd_left <= 0) warnings.push("System 2's daily budget is used up: escalations go to a human until tomorrow (UTC).");
  const br = breaker();
  judge.breaker = {open: br.open, rate: +br.rate.toFixed(2), decisions: br.n};
  if (br.open) warnings.push(`System 2 is paused: ${Math.round(100 * br.rate)}% of the last ${br.n} commands escalated in ${CONFIG.judge.breaker.window_minutes} min, above ${Math.round(100 * CONFIG.judge.breaker.rate)}%; cases go to the queue.`);
  if (CONFIG.mode !== "enforce") warnings.push(`System 2 is on but the mode is ${CONFIG.mode}: it is logged as what would have happened.`);
}
const items = listItems(), pending = items.filter(i => i.status === "pending");
const queue = {enabled: CONFIG.queue.enabled, pending: pending.length, total: items.length, oldest_pending: pending.at(-1)?.created ?? null};
if (pending.length) warnings.push(`${pending.length} item${pending.length === 1 ? "" : "s"} waiting in the approval queue: reflex queue list.`);
// The runaway guard: sessions it stopped (or, in shadow, would have) in the last hour.
const trips = runawayTrips(Date.now() - 36e5);
const runaway = {enabled: CONFIG.runaway.enabled, stops_last_hour: trips.length, sessions: new Set(trips.map(t => t.session)).size, last: trips[0] ?? null};
if (trips.length) warnings.push(`The runaway guard ${trips[0].dry ? "would have stopped (shadow)" : "stopped"} ${trips[0].agent ?? "a"} session ${Math.round((Date.now() - trips[0].last) / 60e3)} min ago (${trips[0].signal}): ${trips[0].reason}. reflex runaway list shows every stop.`);
// Hook errors (failsafe.mjs): a hook that broke and answered ask, block, pass (shadow) or a warning instead of a decision.
const errorsFile = join(CONFIG.data, "health", "errors.jsonl");
let hookErrors = [];
try { hookErrors = readFileSync(errorsFile, "utf8").split("\n").flatMap(l => { try { const e = JSON.parse(l); return Date.parse(e.at) > Date.now() - 864e5 ? [e] : []; } catch { return []; } }); }
catch { /* no hook has failed */ }
const hook_errors = {last_day: hookErrors.length, gate: hookErrors.filter(e => e.script === "gate.mjs" && !/post|prompted|record|bg/.test(e.flag)).length, last: hookErrors.at(-1) ?? null, file: errorsFile};
if (hook_errors.last) {
  const l = hook_errors.last, ago = Math.round((Date.now() - Date.parse(l.at)) / 60e3);
  (hook_errors.gate ? errors : warnings).push(`${hookErrors.length} Reflex hook error${hookErrors.length === 1 ? "" : "s"} in the last 24 h, ${hook_errors.gate} in the pre-execution gate; last ${ago} min ago: ${l.script} ${l.flag} (${l.mode} mode) answered ${l.outcome}: ${l.error}.` +
    `${hookErrors.some(e => e.outcome === "pass" && e.mode === "shadow") ? " In shadow mode a broken gate checks nothing, deterministic rules included." : ""} Log: ${errorsFile}.`);
}
// reflex learn (learn.mjs, CLI only): what your own approvals could stop asking, and learned entries gone unused.
let learned = null;
const result = {profile: CONFIG.profile, engine: CONFIG.engine, system1: CONFIG.engine === "jev" ? `Jev via ${provider.name} (${provider.host}) + policy` : laya ? `Laya ${CONFIG.model} (local, ${laya.ok ? "running" : "DOWN"}) + policy` : keyless ? "local rules (keyless: what they do not cover goes to System 2)" : "local rules", mode: CONFIG.mode, guard: guardMode(), allow: CONFIG.allow, config: USER_CONFIG_FILE,
  policy, provider, api_key: key, claude_hooks: claudeHooks, plugin, codex_hooks, codex_plugin, opencode_plugin, judge, queue, checkpoints: CONFIG.checkpoints, runaway, hook_errors, learned, team_policy, freeze, notify, infra, agents, errors, warnings};
if (json) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`Reflex: ${CONFIG.profile} profile · ${CONFIG.engine} engine · ${CONFIG.mode} mode · guard ${guardMode()} · allow ${CONFIG.allow}`);
  console.log(`Settings: ${USER_CONFIG_FILE}\nPolicy: ${policy}\nAPI key: ${key}\nSystem 1: ${result.system1}`);
  console.log(`System 2: ${judge.enabled ? `${cliJudge ? `cli ${judge.cli} (${judge.command ?? "from PATH"})` : `${judge.backend} ${judge.url}; key ${judge.key}`}; model ${judge.model ?? "default"}; ` +
    `${judge.reachable ? (cliJudge ? "found" : `reachable (HTTP ${judge.status})`) : judge.reachable === false ? "NOT reachable" : "not checked"}` +
    (judge.budget ? `; budget left today ${judge.budget.calls_left} calls, $${judge.budget.usd_left}` : "") : "off"}`);
  console.log(`Queue: ${queue.enabled ? "on" : "off"}; ${queue.pending} pending of ${queue.total} · checkpoints ${CONFIG.checkpoints ? "on" : "off"}`);
  console.log(`Team policy: ${team_policy ? `${team_policy.file}; ${team_policy.trust}${team_policy.valid ? "" : ", INVALID"}; sha256 ${team_policy.sha256?.slice(0, 12) ?? "unreadable"}; ` +
    `rules ${team_policy.rules}, always-human ${team_policy.always_human}, prod markers ${team_policy.prod_markers}, mode floor ${team_policy.mode_floor ?? "none"}, ` +
    `freezes ${team_policy.freezes}, fast lane ${team_policy.fastlane_entries} (${team_policy.fastlane_active ? "active" : "inactive"}), notify ${team_policy.notify}` : "none in this directory"}`);
  console.log(`Infra gate: ${infra.enabled ? `on; destroy ${infra.destroy}; saved plan required in prod ${infra.require_plan_in_prod ? "yes" : "no"}; ` +
    `terraform ${infra.terraform ?? "not found"}; tofu ${infra.tofu ?? "not found"}; kubectl ${infra.kubectl ?? "not found"} (diff ${infra.kubectl_diff ? "on" : "off"}); ` +
    `helm ${infra.helm ?? "not found"} (diff ${infra.helm_diff ? "on" : "off"})` : "off"}`);
  console.log(`Change freeze: ${freeze.active.length ? `ACTIVE now: ${freeze.active.map(w => `${w.reason} (${w.outcome}, ${w.applies_to})`).join("; ")}` : "none active"} (${freeze.windows} window${freeze.windows === 1 ? "" : "s"})`);
  console.log(`Notify: ${notify.targets.length ? notify.targets.join("; ") : "off"}${notify.test ? `; test ${notify.test.map(t => t.error ?? `HTTP ${t.status}`).join(", ") || "not sent"}` : ""}`);
  console.log(`Runaway guard: ${runaway.enabled ? `on (${CONFIG.mode === "enforce" ? "stops" : CONFIG.mode === "shadow" ? "logs only, shadow" : "off with the mode"}); ${runaway.stops_last_hour} stop${runaway.stops_last_hour === 1 ? "" : "s"} in the last hour` : "off"}`);
  console.log(`Claude Code hooks: ${claudeHooks}${plugin.checks.length ? `; plugin probes ${plugin.checks.every(c => c.ok) ? "passed" : "FAILED"}` : ""}`);
  console.log(`Codex CLI hooks: ${codex_hooks}${codex_plugin.checks.length ? `; plugin probes ${codex_plugin.checks.every(c => c.ok) ? "passed" : "FAILED"}` : ""}`);
  console.log(`opencode plugin: ${opencode_plugin}`);
  for (const a of agents) console.log(`${a.name}: ${a.configured ? "configured" : "not verified"}${a.guard ? " + guard" : ""}; ${a.mode}/${a.engine}; ${a.hook_observed ? "hook observed" : "awaiting hook event"}; ${a.version ?? "version unknown"}${a.checks.length ? `; probes ${a.checks.every(c => c.ok) ? "passed" : "FAILED"}` : ""}`);
  for (const w of warnings) console.log(`Note: ${w}`);
  for (const e of errors) console.error(`Error: ${e}`);
  if (doctor) console.log("Doctor checks local configuration and synthetic decisions; host approval dialogs require verification in a real session. No commands were executed or sent to TypeSafe.");
}
process.exitCode = errors.length ? 1 : 0;
}
