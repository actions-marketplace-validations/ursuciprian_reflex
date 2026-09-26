#!/usr/bin/env node
// What the gate would have done with the shell commands your agents already ran, and how fast it is.
// Reads local session transcripts; never runs a command, never writes the trace, cache or queue.
//
//   node replay.mjs replay [claude|codex|opencode|pi|all] [--since 7d] [--project path]
//                          [--engine local|jev|laya] [--yes] [--limit N] [--json]
//   node replay.mjs bench [--engine local|jev|laya] [--json]
//   node replay.mjs suggest [agent] [--since 30d] [--project path] [--min N] [--json] [--write [--yes]]
//                          fast-lane entries for what keeps asking (suggest.mjs); --write edits fastlane.json
//
// Transcripts: Claude Code ~/.claude/projects/**/*.jsonl (Bash tool_use), Codex $CODEX_HOME/sessions
// (exec_command / shell calls, or CommandExecution items), opencode's opencode.db (bash tool parts,
// needs node:sqlite, Node 22.13+), pi ~/.pi/agent/sessions (bash toolCall).
import {closeSync, existsSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync, rmSync, statSync, writeSync} from "node:fs";
import {homedir, tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const argv = process.argv.slice(2), [cmd] = argv;
const die = s => { console.error(`reflex: ${s}`); process.exit(2); };
const opt = (n, d) => {
  const i = argv.indexOf(n);
  if (i < 0) return d;
  if (!argv[i + 1] || argv[i + 1].startsWith("--")) die(`${n} needs a value`);
  return argv[i + 1];
};
const AGENTS = ["claude", "codex", "opencode", "pi"];
// The agent is the one word that is neither a flag nor a flag's value, wherever it stands.
const VALUED = ["--since", "--project", "--engine", "--limit", "--min"], FLAGS = ["--json", "--yes", "--write"];
const words = argv.slice(1).filter((a, i, l) => !VALUED.includes(a) && !FLAGS.includes(a) && !VALUED.includes(l[i - 1]));
if (words.some(w => w.startsWith("-")) || words.length > (["replay", "suggest"].includes(cmd) ? 1 : 0)) die(`unexpected argument ${words.at(-1)}`);
const agentArg = words[0] ?? "all";
if (["replay", "suggest"].includes(cmd) && ![...AGENTS, "all"].includes(agentArg)) die(`unknown agent ${agentArg} (claude, codex, opencode, pi or all)`);
// Local unless named: a hosted engine sends data off the machine, so it is never picked implicitly.
const engine = opt("--engine", "local");
if (engine !== undefined && !["local", "jev", "laya"].includes(engine)) die("--engine must be local, jev or laya");
const json = argv.includes("--json");
const since = (() => {
  const s = opt("--since", cmd === "suggest" ? "30d" : "7d"), m = /^(\d+)([dhm])$/.exec(s);
  if (!m) die("--since takes a number and d, h or m (7d, 12h, 30m)");
  return Date.now() - Number(m[1]) * {d: 864e5, h: 36e5, m: 6e4}[m[2]];
})();
const limit = opt("--limit") === undefined ? Infinity : Number(opt("--limit"));
if (!(limit > 0)) die("--limit must be a positive number");
const project = opt("--project") && resolve(opt("--project"));

// Dry: shadow mode, no System 2, queue or checkpoints, set before the gate is loaded (it reads them
// once). Replay calls only precheck and jevJudge with useCache off, which write nothing; the data
// directory stays the real one so the tamper check still recognises commands that touch it.
Object.assign(process.env, {REFLEX_MODE: "shadow", REFLEX_JUDGE: "off", REFLEX_QUEUE: "off", REFLEX_CHECKPOINTS: "off", REFLEX_ENGINE: engine});
const {CONFIG, USER_CONFIG, configurationError, judgeSettings, jevJudge, precheck, redact} = await import("./gate.mjs");
const {alwaysHuman} = await import("./autonomy.mjs");
if (configurationError()) die(redact(configurationError()));
// Whether the user's autonomous profile has a System 2 (REFLEX_JUDGE above only keeps replay from calling it).
const system2 = judgeSettings(USER_CONFIG.judge, undefined, engine).enabled;
// Samples print old commands: also mask what redact() has no shape for (a password after a flag, echo … | sudo -S).
const mask = s => redact(s).replace(/(\s(?:--password|--passwd|--token)(?:=|\s+))(?!<redacted>)\S+/g, "$1<redacted>")
  .replace(/(\blogin\b[^|;&\n]*\s-p\s*)(?!<redacted>)\S+/g, "$1<redacted>")
  .replace(/\becho\s+\S+(\s*\|\s*sudo\s+-S)/g, "echo <redacted>$1");

// Jev's price: TypeSafe publishes no per-token price page. $0.04 per million input tokens matches a
// public third-party measurement (abide's README: 1,000 to 1,600 tokens for $0.00004 to $0.00007,
// 2026-09-18). REFLEX_JEV_USD_PER_MTOK overrides it. The estimate assumes 2k tokens a call (eval.mjs).
const priceEnv = Number(process.env.REFLEX_JEV_USD_PER_MTOK);
const USD_PER_MTOK = Number.isFinite(priceEnv) && priceEnv >= 0 && process.env.REFLEX_JEV_USD_PER_MTOK !== "" ? priceEnv : 0.04, EST_TOKENS = 2000;
const usd = tokens => +(tokens * USD_PER_MTOK / 1e6).toFixed(6);
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.min(s.length - 1, Math.floor(p * s.length))] : null; };

// ---------------------------------------------------------------------------------------------
// Transcripts -> [{agent, id, command, cwd, ts}]. Every reader skips what it cannot parse.
const walk = (dir, keep) => {
  let out = [];
  try {
    for (const e of readdirSync(dir, {withFileTypes: true})) {
      const p = join(dir, e.name);
      if (e.isDirectory()) out = out.concat(walk(p, keep));
      else if (keep(p)) out.push(p);
    }
  } catch { /* missing or unreadable */ }
  return out;
};
// Files untouched since the window opened hold nothing newer.
const recent = p => { try { return p.endsWith(".jsonl") && statSync(p).mtimeMs >= since; } catch { return false; } };   // a dangling link
function* lines(file, needle) {
  let text;
  try { text = readFileSync(file, "utf8"); } catch { return; }   // gone mid-run, or too large for a string
  for (const l of text.split("\n")) {
    if (!l.includes(needle)) continue;
    try { yield JSON.parse(l); } catch { /* torn line */ }
  }
}
// ["/bin/zsh", "-lc", "cmd"] is the command cmd; any other argv is joined.
const unwrap = c => Array.isArray(c) ? (c.length === 3 && /(^|\/)(ba|z|da)?sh$/.test(c[0]) && /^-l?c$/.test(c[1]) ? c[2] : c.join(" ")) : c;
const tsOf = t => typeof t === "number" ? t : Date.parse(t);
// Newer Codex items give the directory as a file:// URL.
const dirOf = d => { try { return typeof d === "string" && d.startsWith("file://") ? fileURLToPath(d) : d; } catch { return undefined; } };

const READERS = {
  claude() {
    const out = [], files = walk(join(homedir(), ".claude/projects"), recent);
    for (const f of files) for (const e of lines(f, '"Bash"'))
      for (const c of Array.isArray(e.message?.content) ? e.message.content : [])
        if (c.type === "tool_use" && c.name === "Bash" && typeof c.input?.command === "string")
          out.push({agent: "claude", id: c.id, command: c.input.command, cwd: e.cwd, ts: tsOf(e.timestamp)});
    return {files: files.length, calls: out};
  },
  codex() {
    const out = [], files = walk(join(process.env.CODEX_HOME ?? join(homedir(), ".codex"), "sessions"), recent);
    for (const f of files) {
      // Newer rollouts log each shell run as a CommandExecution item; older ones only as the tool call.
      // A file with items uses those, plus the tool calls whose command no item has (a rollout started
      // on an older Codex and resumed on a newer one), so a command is not counted twice.
      const items = [], fcalls = [];
      let cwd;
      for (const e of lines(f, '"')) {
        const p = e.payload ?? {}, ts = tsOf(e.timestamp);
        if (p.cwd && (e.type === "session_meta" || e.type === "turn_context")) cwd = p.cwd;
        if (p.type === "item_completed" && p.item?.type === "CommandExecution")
          items.push({agent: "codex", id: p.item.id, command: unwrap(p.item.command), cwd: dirOf(p.item.cwd) ?? cwd, ts});
        else if (p.type === "function_call" && ["exec_command", "shell", "shell_command"].includes(p.name)) {
          let a; try { a = JSON.parse(p.arguments); } catch { continue; }
          fcalls.push({agent: "codex", id: p.call_id, command: unwrap(a.cmd ?? a.command), cwd: a.workdir ?? cwd, ts});
        } else if (p.type === "local_shell_call" && p.action?.command)
          fcalls.push({agent: "codex", id: p.call_id, command: unwrap(p.action.command), cwd: p.action.working_directory ?? cwd, ts});
      }
      const logged = new Set(items.map(i => i.command));
      out.push(...items, ...fcalls.filter(c => !logged.has(c.command)));
    }
    return {files: files.length, calls: out};
  },
  async opencode() {
    const db = join(process.env.XDG_DATA_HOME ?? join(homedir(), ".local/share"), "opencode/opencode.db");
    if (!existsSync(db)) return {skipped: "no opencode.db"};
    let sqlite;
    const warn = process.emitWarning;
    process.emitWarning = () => {};   // node:sqlite is experimental and says so on import
    try { sqlite = await import("node:sqlite"); } catch { return {skipped: "reading opencode.db needs node:sqlite (Node 22.13+)"}; } finally { process.emitWarning = warn; }
    let conn;
    const out = [];
    try {
      conn = new sqlite.DatabaseSync(db, {readOnly: true});
      const rows = conn.prepare("SELECT p.id, p.data, p.time_created AS ts, s.directory FROM part p LEFT JOIN session s ON s.id = p.session_id " +
        "WHERE p.time_created >= ? AND p.data LIKE '%\"bash\"%'").all(since);
      for (const r of rows) {
        let d; try { d = JSON.parse(r.data); } catch { continue; }
        if (d.type === "tool" && d.tool === "bash" && typeof d.state?.input?.command === "string")
          out.push({agent: "opencode", id: r.id, command: d.state.input.command, cwd: d.state.input.workdir ?? r.directory, ts: r.ts});
      }
    } catch (e) { return {skipped: `unreadable opencode.db (${redact(e.message).slice(0, 120)})`}; } finally { conn?.close(); }
    return {files: 1, calls: out};
  },
  pi() {
    const out = [], files = walk(join(homedir(), ".pi/agent/sessions"), recent);
    for (const f of files) {
      let cwd;
      for (const e of lines(f, '"')) {
        if (e.type === "session") cwd = e.cwd;
        for (const c of Array.isArray(e.message?.content) ? e.message.content : [])
          if (c.type === "toolCall" && c.name === "bash" && typeof c.arguments?.command === "string")
            out.push({agent: "pi", id: c.id, command: c.arguments.command, cwd, ts: tsOf(e.timestamp)});
      }
    }
    return {files: files.length, calls: out};
  },
};

async function collect(agents) {
  const sources = {}, seen = new Set();
  let calls = [];
  for (const a of agents) {
    const r = await READERS[a]();
    sources[a] = r.skipped ? {skipped: r.skipped} : {files: r.files, commands: 0};
    // A resumed or forked session copies earlier calls into a new file: each call id counts once.
    for (const c of r.calls ?? []) {
      if (typeof c.command !== "string" || !c.command.trim() || !(c.ts >= since)) continue;
      if (project && !(c.cwd === project || String(c.cwd).startsWith(project + "/"))) continue;
      const key = `${a}:${c.id ?? `${c.ts}:${c.command}`}`;
      if (seen.has(key)) continue;
      seen.add(key);
      calls.push(c);
    }
  }
  calls.sort((x, y) => x.ts - y.ts);
  if (calls.length > limit) calls = calls.slice(-limit);   // the most recent N
  for (const c of calls) sources[c.agent].commands++;
  return {sources, calls};
}

// ---------------------------------------------------------------------------------------------
// The gate over each command, as the hook would see it with no session context: the environment at
// the time (AWS profile, kube context) is not in a transcript, so it is left empty.
const LOCAL = {outcome: "ask", source: "local", rule: "not covered by local rules; a human must review it"};
// Counts per source, asks per 100 commands (supervised and autonomous), top rules and masked samples.
function tally(judged) {
  const n = judged.length, per100 = k => n ? +(100 * k / n).toFixed(1) : 0;
  const t = {commands: n, pass_read_only: 0, pass_fast_lane: 0, rule_ask: 0, rule_deny: 0, rule_pass: 0,
    engine: {pass: 0, allow: 0, ask: 0, deny: 0, error: 0}, reach_human: 0, reach_system2: 0, autonomous_human: 0};
  const rules = {}, samples = {deny: [], ask: []};
  for (const {c, j} of judged) {
    const src = j.source, out = j.outcome === "would_allow" ? "allow" : j.outcome;
    if (src === "read-only") t.pass_read_only++;
    else if (src === "fast-lane") t.pass_fast_lane++;
    else if (src === "rule") { t[`rule_${out}`] = (t[`rule_${out}`] ?? 0) + 1; const k = j.id ?? j.rule; rules[k] ??= {id: k, rule: redact(j.rule ?? "").replace(/ \(in [^)]*\)$/, ""), count: 0}; rules[k].count++; }
    else if (src === "fallback" || src === "error") t.engine.error++;
    else t.engine[out] = (t.engine[out] ?? 0) + 1;
    // Supervised: every ask is a human's. Autonomous (autonomy.mjs ladder): an ask goes to System 2
    // unless it is in the always-human class (or no System 2 is configured); a System 1 pass in that
    // class still needs a human.
    if (out === "ask") {
      t.reach_human++;
      if (!system2 || alwaysHuman(j, c, {})) t.autonomous_human++; else t.reach_system2++;
    } else if (["pass", "allow"].includes(out) && !["read-only", "fast-lane"].includes(src) && alwaysHuman(j, c, {}, {system1: true})) t.autonomous_human++;
    if ((out === "deny" || out === "ask") && samples[out].length < 8 && !(out === "ask" && src === "local" && samples.ask.length >= 4))
      samples[out].push({agent: c.agent, source: src, rule: redact(j.rule ?? "").slice(0, 120), command: mask(c.command).replace(/\s+/g, " ").slice(0, 160)});
  }
  return {t, rules, samples, per_100: {reach_human: per100(t.reach_human), reach_system2: per100(t.reach_system2), autonomous_human: per100(t.autonomous_human)}};
}
async function replay() {
  const agents = agentArg === "all" ? AGENTS : [agentArg];
  const {sources, calls} = await collect(agents);
  const judged = calls.map(c => ({c, j: precheck(c.command, c.cwd, {})}));
  const open = judged.filter(x => !x.j);
  // Identical commands in the same directory are asked once, as the hook's answer cache would.
  const unique = new Map();
  for (const x of open) unique.set(`${x.c.cwd ?? ""}\0${x.c.command}`, null);
  const estimate = {calls: unique.size, input_tokens: unique.size * EST_TOKENS, usd: usd(unique.size * EST_TOKENS)};
  if (CONFIG.engine === "jev" && unique.size && !argv.includes("--yes")) {
    const host = (() => { try { return new URL(CONFIG.api).host; } catch { return "the Jev endpoint"; } })();
    const msg = `replaying ${calls.length} commands with Jev would make about ${estimate.calls} calls, ~${estimate.input_tokens} input tokens, ` +
      `~$${estimate.usd} (at $${USD_PER_MTOK} per million input tokens). It sends ${host} each distinct command the local rules leave open ` +
      "(credentials masked), its directory and an excerpt of any local script it runs, as that script is now. Nothing was sent. Rerun with --yes to proceed.";
    if (json) console.log(JSON.stringify({engine: "jev", commands: calls.length, estimate, sends_to: host, proceeded: false}, null, 1));
    else console.log(msg);
    return;
  }
  const engineRuns = [];
  if (CONFIG.engine !== "local" && unique.size) {
    const keys = [...unique.keys()];
    let next = 0, failed = null;
    // A few calls at a time; the first error with nothing answered stops the run (no key, server down).
    const worker = async () => {
      while (next < keys.length && !failed) {
        const k = keys[next++], [cwd, command] = k.split("\0");
        const j = await jevJudge({command, cwd: cwd || undefined, env: {}, useCache: false});
        if (j.error && !engineRuns.length) failed = j.error;
        unique.set(k, j);
        engineRuns.push(j);
      }
    };
    await Promise.all(Array.from({length: 4}, worker));
    if (failed) die(`${CONFIG.engine} did not answer: ${redact(failed).slice(0, 200)}`);
  }
  for (const x of open) x.j = CONFIG.engine === "local" ? LOCAL : unique.get(`${x.c.cwd ?? ""}\0${x.c.command}`);

  const {t, rules, samples, per_100} = tally(judged);
  const tokens = engineRuns.reduce((s, j) => s + (j.usage?.input_tokens ?? 0), 0), lat = engineRuns.map(j => j.latency_s).filter(x => x > 0);
  const result = {engine: CONFIG.engine, since: new Date(since).toISOString(), project: project ?? null, system2_configured: system2, sources, totals: t,
    per_100,
    top_rules: Object.values(rules).sort((a, b) => b.count - a.count).slice(0, 10), samples,
    cost: CONFIG.engine === "local" ? {jev_estimate: estimate}
      : {calls: engineRuns.length, input_tokens: tokens, usd: CONFIG.engine === "jev" ? usd(tokens) : 0,
         latency_s: {p50: pct(lat, 0.5), p95: pct(lat, 0.95)}}};
  if (json) return console.log(JSON.stringify(result, null, 1));

  const src = Object.entries(sources).map(([a, s]) => s.skipped ? `${a}: skipped (${s.skipped})` : `${a}: ${s.commands} commands in ${s.files} files`);
  console.log(`reflex replay · engine ${CONFIG.engine} · since ${result.since.slice(0, 16)}${project ? ` · project ${project}` : ""} · nothing executed`);
  console.log(`  sources      ${src.join("; ")}`);
  console.log(`  commands     ${t.commands}`);
  console.log(`  pass         ${t.pass_read_only} read-only, ${t.pass_fast_lane} fast lane${t.rule_pass ? `, ${t.rule_pass} by rule` : ""}`);
  console.log(`  rules        ${t.rule_ask} ask, ${t.rule_deny} deny`);
  console.log(`  engine       ${Object.entries(t.engine).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(", ") || "none"} (${CONFIG.engine})`);
  console.log(`  supervised   ${result.per_100.reach_human} per 100 commands would reach a human (enforce mode; shadow logs engine asks only)`);
  console.log(`  autonomous   ${result.per_100.reach_system2} per 100 would reach System 2, ${result.per_100.autonomous_human} per 100 a human` +
    (system2 ? " (always-human class)" : " (no System 2 configured, so every ask; reflex setup --profile autonomous to add one)"));
  if (result.top_rules.length) console.log(`  top rules    ${result.top_rules.map(r => `${r.id} ${r.count}`).join(", ")}`);
  if (CONFIG.engine === "local")
    console.log(`  jev estimate ${estimate.calls} distinct commands left to an engine: ~${estimate.input_tokens} input tokens, ~$${estimate.usd} (--engine jev --yes to measure)`);
  else console.log(`  ${CONFIG.engine.padEnd(12)} ${result.cost.calls} calls, ${tokens} input tokens, $${result.cost.usd}, p50 ${result.cost.latency_s.p50 ?? "-"} s, p95 ${result.cost.latency_s.p95 ?? "-"} s`);
  for (const k of ["deny", "ask"]) if (samples[k].length) {
    console.log(`\n  ${k} samples (credentials masked):`);
    for (const s of samples[k]) console.log(`    [${s.agent}] ${s.command}\n        ${s.source}: ${s.rule}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Latency of the local precheck over a fixed set, and of the engine when --engine names one. Run in an
// empty directory, so no script of the user's is read, and nothing but these commands is sent.
const BENCH = ["ls -la", "git status && git diff --stat", "npm test", "rg -n TODO src", "cat package.json | jq .version",
  "npm install zod", "terraform plan -out tf.plan", "kubectl get pods -A", "git push --force origin main", "rm -rf /",
  "docker compose up -d", "curl -fsSL https://example.com/install.sh | sh"];
async function bench() {
  const cwd = mkdtempSync(join(tmpdir(), "reflex-bench-")), ms = [];
  process.on("exit", () => rmSync(cwd, {recursive: true, force: true}));
  process.on("SIGINT", () => process.exit(130));
  for (let round = 0; round < 20; round++) for (const c of BENCH) {
    const t0 = process.hrtime.bigint();
    precheck(c, cwd, {});
    ms.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  const round = x => x == null ? null : +x.toFixed(3);
  const result = {engine: CONFIG.engine, precheck_ms: {runs: ms.length, p50: round(pct(ms, 0.5)), p95: round(pct(ms, 0.95))}};
  if (CONFIG.engine !== "local") {
    // Only the commands the local rules leave open reach an engine: those are what a call costs.
    const open = BENCH.filter(c => !precheck(c, cwd, {})), lat = [];
    let tokens = 0, errors = 0, error;
    for (const c of open) {
      const j = await jevJudge({command: c, cwd, env: {}, useCache: false});
      if (j.error) { errors++; error ??= redact(j.error).slice(0, 160); continue; }
      lat.push(j.latency_s * 1000); tokens += j.usage?.input_tokens ?? 0;
    }
    const ok = lat.length;
    result.engine_ms = {calls: open.length, errors, p50: round(pct(lat, 0.5)), p95: round(pct(lat, 0.95)), ...(error && {error})};
    result.spend = {input_tokens: tokens, tokens_per_call: ok ? Math.round(tokens / ok) : null, usd: CONFIG.engine === "jev" ? usd(tokens) : 0,
      usd_per_1000_calls: CONFIG.engine === "jev" && ok ? usd(1000 * tokens / ok) : 0};
  }
  if (json) return console.log(JSON.stringify(result, null, 1));
  console.log(`reflex bench · engine ${CONFIG.engine}`);
  console.log(`  precheck     p50 ${result.precheck_ms.p50} ms, p95 ${result.precheck_ms.p95} ms over ${ms.length} runs (${BENCH.length} commands)`);
  if (result.engine_ms) {
    const e = result.engine_ms, s = result.spend;
    console.log(`  ${CONFIG.engine.padEnd(12)} p50 ${e.p50 ?? "-"} ms, p95 ${e.p95 ?? "-"} ms over ${e.calls} calls${e.errors ? `, ${e.errors} failed (${e.error})` : ""}`);
    console.log(`  spend        ${s.input_tokens} input tokens, $${s.usd}; about $${s.usd_per_1000_calls} per 1,000 calls`);
  } else console.log("  engine       local: no hosted calls (--engine jev or laya to time one)");
}

// ---------------------------------------------------------------------------------------------
// Fast-lane suggestions from the same transcripts, judged with the local rules only (suggest.mjs).
// Writes nothing unless --write, and then only fastlane.json, after showing what it adds.
async function suggestCmd() {
  if (engine !== "local") die("suggest judges with the local rules only; drop --engine");
  const min = Number(opt("--min", "3"));
  if (!(Number.isInteger(min) && min >= 2)) die("--min must be a whole number of at least 2");
  const {suggest, mergeSuggestions, writeSuggestions} = await import("./suggest.mjs");
  const {FASTLANE_FILE, loadFastLane} = await import("./fastlane.mjs");
  const {sources, calls} = await collect(agentArg === "all" ? AGENTS : [agentArg]);
  const r = suggest(calls, {judge: precheck, min, mask});
  const b = tally(r.judged.map(({c, j}) => ({c, j: j ?? LOCAL}))), a = tally(r.after.map(({c, j}) => ({c, j: j ?? LOCAL})));
  const current = loadFastLane();
  const result = {since: new Date(since).toISOString(), project: project ?? null, min, sources, fastlane_file: FASTLANE_FILE,
    ...(current.error && {fastlane_error: `ignored: ${current.error}`}),
    before: {commands: b.t.commands, fast_lane: b.t.pass_fast_lane, per_100: b.per_100},
    after: {commands: a.t.commands, fast_lane: a.t.pass_fast_lane, per_100: a.per_100},
    suggestions: r.suggestions, rejected: r.rejected.slice(0, 20),
    not_suggestible: Object.fromEntries(Object.entries(r.skipped).sort((x, y) => y[1] - x[1])), top_asking: r.asking};
  if (json) console.log(JSON.stringify(result, null, 1));
  else {
    const src = Object.entries(sources).map(([k, s]) => s.skipped ? `${k}: skipped (${s.skipped})` : `${k}: ${s.commands} commands`);
    console.log(`reflex suggest · since ${result.since.slice(0, 16)}${project ? ` · project ${project}` : ""} · local rules · nothing executed`);
    console.log(`  sources      ${src.join("; ")}`);
    if (current.error) console.log(`  warning      ${FASTLANE_FILE} is ignored: ${current.error}`);
    console.log(`  before       ${b.per_100.reach_human} per 100 commands reach a human (supervised), ${b.per_100.autonomous_human} autonomous`);
    console.log(`  after        ${a.per_100.reach_human} per 100 (supervised), ${a.per_100.autonomous_human} autonomous, with the ${r.suggestions.length} suggestions below`);
    const top = Object.entries(result.not_suggestible).slice(0, 6).map(([k, v]) => `${v} ${k}`).join("; ");
    if (top) console.log(`  left alone   ${top}`);
    if (r.asking.length) console.log(`  most asked   ${r.asking.slice(0, 6).map(x => `${x.shape} ${x.count}`).join(", ")} (not suggestible)`);
    for (const s of r.suggestions) {
      console.log(`\n  ${s.pattern}\n    in ${s.cwd} · ${s.count} runs (${s.agents.join(", ")}), ${s.passes} would pass`);
      for (const x of s.samples) console.log(`    e.g. ${x}`);
      console.log(`    safe because: ${s.why}`);
    }
    for (const x of r.rejected.slice(0, 5)) console.log(`\n  not suggested: ${x.pattern} (${x.count} runs): ${x.why}`);
    if (!r.suggestions.length) console.log(`\n  no suggestions at --min ${min}`);
  }
  if (!argv.includes("--write") || !r.suggestions.length) return;
  const {text, add} = mergeSuggestions(r.suggestions);
  if (!add.length) return console.error("reflex: fastlane.json already has every suggestion");
  console.error(`\n--- ${FASTLANE_FILE}\n${add.map(e => `+ ${JSON.stringify(e)}`).join("\n")}`);
  if (!argv.includes("--yes")) {
    let answer = "";
    try {
      const fd = openSync("/dev/tty", "r+"), buf = Buffer.alloc(1);
      writeSync(fd, `add ${add.length} entr${add.length === 1 ? "y" : "ies"} to ${FASTLANE_FILE}? [y/N] `);
      while (readSync(fd, buf, 0, 1, null) === 1 && buf[0] !== 10) answer += buf.toString();
      closeSync(fd);
    } catch { die("no terminal to confirm on; rerun with --write --yes to write without asking"); }
    if (!/^y(es)?$/i.test(answer.trim())) return console.error("reflex: nothing written");
  }
  writeSuggestions(text);
  console.error(`reflex: wrote ${add.length} entr${add.length === 1 ? "y" : "ies"} to ${FASTLANE_FILE}`);
}

if (cmd === "replay") await replay();
else if (cmd === "bench") await bench();
else if (cmd === "suggest") await suggestCmd();
else die("usage: reflex replay [claude|codex|opencode|pi|all] [--since 7d] [--project path] [--engine local|jev|laya] [--yes] [--limit N] [--json] | reflex bench [--engine local|jev|laya] [--json] | reflex suggest [agent] [--since 30d] [--project path] [--min N] [--json] [--write [--yes]]");
