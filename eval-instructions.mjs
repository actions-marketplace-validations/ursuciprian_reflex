#!/usr/bin/env node
// Score fragment selection against a golden set of prompts, with the live Jev API.
//   node eval-instructions.mjs [--golden examples/instructions/golden.json] [--repo examples/instructions/repo]
// paths / keywords are cleared so every case is judged by Jev: this measures the conditions, not
// the deterministic shortcuts. One request per case (~1k input tokens); never uses the cache.
import {readFileSync} from "node:fs";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {CONFIG} from "./gate.mjs";
import {THRESHOLD, discover, select} from "./instructions.mjs";
import {isMain} from "./failsafe.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : d; };
// The script itself runs only when started (node eval-instructions.mjs), never when the file is imported.
if (isMain(import.meta)) {
const golden = JSON.parse(readFileSync(arg("--golden", join(HERE, "examples/instructions/golden.json")), "utf8"));
const repo = arg("--repo", join(HERE, "examples/instructions/repo"));
const fragments = discover(repo).filter(f => f.when && f.file.startsWith(repo)).map(f => ({...f, paths: [], keywords: []}));

// ponytail: fixed pool of 6, well inside the documented 1,200 requests/minute.
const results = [];
for (let i = 0; i < golden.cases.length; i += 6) {
  results.push(...await Promise.all(golden.cases.slice(i, i + 6).map(async c => {
    const r = await select({agent: "eval", prompt: c.prompt, cwd: repo}, {fragments, useCache: false});
    return {...c, error: r.error, got: r.fragments.filter(f => f.included).map(f => f.id),
            p: Object.fromEntries(r.fragments.map(f => [f.id, f.p]))};
  })));
}

let tp = 0, fp = 0, fn = 0, exact = 0;
for (const r of results) {
  const miss = r.expect.filter(id => !r.got.includes(id)), extra = r.got.filter(id => !r.expect.includes(id));
  tp += r.got.length - extra.length; fp += extra.length; fn += miss.length;
  if (!miss.length && !extra.length && !r.error) exact++;
  else console.log(`${r.error ? "ERROR" : miss.length ? "MISS " : "extra"} want [${r.expect}] got [${r.got}] ${JSON.stringify(r.p)}  ${r.prompt.slice(0, 70)}${r.error ? "  " + r.error : ""}`);
}
const pct = x => (100 * x).toFixed(0) + "%";
console.log(`\n${results.length} prompts · exact ${exact} · precision ${pct(tp / (tp + fp || 1))} · recall ${pct(tp / (tp + fn || 1))} · ` +
            `threshold ${THRESHOLD} · model ${CONFIG.model}`);
if (fn || results.some(r => r.error)) process.exitCode = 1;
}
