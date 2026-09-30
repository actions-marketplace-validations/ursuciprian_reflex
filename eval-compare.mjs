#!/usr/bin/env node
// Every live golden set, for several System 1 engines, same run, one table (docs/GUIDE.md#laya).
//   node eval-compare.mjs [--engines jev,jev@openrouter,laya:english,laya:typed-decisions] [--runs 2] [--suites gate,guard,...]
// jev needs a TypeSafe key (TYPESAFE_API_KEY or REFLEX_KEYCHAIN_SERVICE); jev@<provider> runs Jev through
// that provider (typesafe, openrouter, cloudflare, vercel, compatible) with its key; laya:<checkpoint> needs
// `reflex laya start` with that checkpoint resident (REFLEX_LAYA_URL to point elsewhere on 127.0.0.1).
// Each suite runs as its own process with a scratch REFLEX_DATA_DIR; nothing is cached.
import {spawnSync} from "node:child_process";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {isMain} from "./failsafe.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
const engines = arg("--engines", "jev,laya:typed-decisions").split(",");
const runs = Number(arg("--runs", 2));
// suite -> command, and the summary numbers its output ends with
const SUITES = {
  gate: [["node", "eval.mjs"], s => s.match(/ok (\d+) · MISS (\d+).*over (\d+)/)?.slice(1).concat(s.match(/allow-eligible (\d+) of (\d+)/)?.slice(1) ?? []),
    ["ok", "MISS", "over", "allow", "of"]],
  guard: [["node", "guard.mjs", "--eval"], s => s.match(/precision (\S+) %.*recall (\S+) %.*FP (\d+).*high-severity MISS (\d+)/)?.slice(1)
    .concat(s.match(/high-severity blocked (\d+)\//)?.slice(1) ?? []), ["P%", "R%", "FP", "hiMISS", "hiBlocked"]],
  instructions: [["node", "eval-instructions.mjs"], s => s.match(/exact (\d+) · precision (\d+)% · recall (\d+)%/)?.slice(1), ["exact", "P%", "R%"]],
  ladder: [["node", "eval-ladder.mjs"], s => s.match(/UNSAFE (\d+)/)?.slice(1).concat(s.match(/human interventions ([\d.]+) per 100 commands · System 2 asked \d+ times, ([\d.]+)/)?.slice(1) ?? []),
    ["UNSAFE", "humans/100", "S2/100"]],
  routing: [["python3", "routing/reflex_router.py", "--eval"], s => s.match(/sensitivity (\d+)\/\d+ \(under (\d+), restricted leaks (\d+)\) · tier (\d+)\/\d+/)?.slice(1),
    ["sens", "under", "leaks", "tier"]],
  router: [["node", "router/server.mjs", "--eval"], s => s.match(/ok (\d+) · held (\d+).*unsafe (\d+)/)?.slice(1), ["ok", "held", "unsafe"]],
  context: [["node", "context.mjs", "--eval-context"], s => s.match(/must-keep recall (\d+)\/\d+.*hidden (\d+) %/)?.slice(1), ["kept", "hidden%"]],
};
SUITES.mcp = [["node", "eval.mjs", "--golden", "setup/tool-gate/golden-mcp.json"], ...SUITES.gate.slice(1)];   // MCP tool calls, scored as the gate
const suites = arg("--suites", Object.keys(SUITES).join(",")).split(",");

function env(engine, data) {
  const [spec, model] = engine.split(":"), [kind, provider] = spec.split("@");
  const e = {...process.env, REFLEX_DATA_DIR: data, REFLEX_ENGINE: kind, ...(provider && {REFLEX_PROVIDER: provider}), REFLEX_TIMEOUT_MS: process.env.REFLEX_TIMEOUT_MS ?? "30000",
             REFLEX_GUARD_TIMEOUT_MS: process.env.REFLEX_GUARD_TIMEOUT_MS ?? "60000"};
  if (kind === "laya") Object.assign(e, {REFLEX_MODEL: model ?? "typed-decisions", ...(process.env.REFLEX_LAYA_URL && {REFLEX_API_URL: process.env.REFLEX_LAYA_URL})});
  return e;
}

// The script itself runs only when started (node eval-compare.mjs), never when the file is imported.
if (isMain(import.meta)) {
const rows = [];
for (let run = 1; run <= runs; run++) for (const engine of engines) for (const suite of suites) {
  const [cmd, parse, cols] = SUITES[suite], data = mkdtempSync(join(tmpdir(), "reflex-compare-"));
  const t0 = Date.now(), r = spawnSync(cmd[0], cmd.slice(1), {cwd: HERE, env: env(engine, data), encoding: "utf8", timeout: 1800000});
  const v = parse(r.stdout ?? "");
  rows.push({run, engine, suite, values: v ? Object.fromEntries(cols.map((c, i) => [c, v[i]])) : {error: (r.stderr || r.stdout || "").trim().split("\n").at(-1)?.slice(0, 120)},
             seconds: Math.round((Date.now() - t0) / 1000)});
  rmSync(data, {recursive: true, force: true});
  console.error(`run ${run} ${engine} ${suite}: ${JSON.stringify(rows.at(-1).values)}`);
}
if (process.argv.includes("--json")) console.log(JSON.stringify(rows, null, 1));
else for (const suite of suites) {
  console.log(`\n${suite}`);
  for (const engine of engines)
    console.log(`  ${engine.padEnd(24)} ${rows.filter(r => r.suite === suite && r.engine === engine)
      .map(r => Object.entries(r.values).map(([k, v]) => `${k} ${v}`).join(", ")).join("  |  ")}`);
}
}
