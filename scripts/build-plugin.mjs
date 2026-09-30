#!/usr/bin/env node
// Builds plugin/, the Claude Code plugin the marketplace installs (.claude-plugin/marketplace.json
// "source": "./plugin"). Only what plugin mode (--plugin, plugin.mjs) runs goes in: the runtime
// modules, the setup files the gate and the guard read, the hooks, commands, skill, MCP server
// entry, README, LICENSE and the icon. Setup-only code is cut out of the modules:
//
//   // @reflex:setup-only begin            (<!-- @reflex:setup-only begin --> in Markdown)
//   ...code that plugin mode never runs...
//   // @reflex:setup-only end
//
// A region may only hold code that plugin mode cannot reach: a branch under !PLUGIN_MODE, a branch
// after one that always returns in plugin mode, a selfcheck, eval or setup CLI. It may never hold a
// check that tightens a decision. The build fails when a region is unbalanced or nested, when a
// module does not parse or does not link (every import resolves to a bundled file and names an
// export it has), when a file is over 256 KiB, when a file other than the icon is binary, or when a
// FORBIDDEN pattern is left anywhere in the bundle.
//
//   node scripts/build-plugin.mjs     writes plugin/ (committed; CI fails on drift)
import {copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {dirname, join, relative} from "node:path";
import {fileURLToPath} from "node:url";
import {isMain} from "../failsafe.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), ".."), OUT = join(ROOT, "plugin");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

// Every module a plugin hook, command or the MCP server loads, spawns or imports (statically or not).
const MODULES = ["hook.mjs", "failsafe.mjs", "plugin.mjs", "gate.mjs", "config.mjs", "shell.mjs", "scripts.mjs", "readonly.mjs", "rules.mjs",
  "tamper.mjs", "jev.mjs", "guard.mjs", "instructions.mjs", "policy.mjs", "providers.mjs",
  "autonomy.mjs", "fastlane.mjs", "team.mjs", "infra.mjs", "freeze.mjs", "notify.mjs", "context.mjs", "judge2.mjs", "laya.mjs",
  "mcp.mjs", "audit.mjs", "status.mjs", "replay.mjs", "report.mjs", "suggest.mjs", "tools.mjs", "workspace.mjs"];
// The setup files read at runtime; the golden sets, fixtures and plan fixtures stay out.
const DATA = ["setup/redact.json", ...["rules", "policy", "questions", "escalation", "subgoals", "mcp", "protected"].map(f => `setup/tool-gate/${f}.json`),
  ...["policy", "detectors", "questions"].map(f => `setup/injection/${f}.json`)];
const FILES = [".mcp.json", "hooks/hooks.json", "LICENSE", "assets/logo-512.png",
  ...readdirSync(join(ROOT, "commands")).filter(f => f.endsWith(".md")).sort().map(f => `commands/${f}`), "skills/reflex/SKILL.md"];
const BINARY = ["assets/logo-512.png"];
const MAX = 256 * 1024;

// What the directory's policy holds a plugin to: never allow, never rewrite a tool's input or
// output, no key from the machine (Keychain, key variables), no install-time download or install.
// [pattern, the files where it may stand, why]; an exception is data that detects the pattern.
const FORBIDDEN = [
  [/permissionDecision.*allow|"behavior"\s*:\s*"allow"/], [/updatedInput/], [/updated(MCP)?ToolOutput/],
  [/find-generic-password/, ["setup/tool-gate/rules.json"], "the rule that asks before a command reads a Keychain secret"],
  [/security find-generic-password|["']security["']/],
  [/TYPESAFE_API_KEY/], [/OPENROUTER_API_KEY/], [/CLOUDFLARE_API_TOKEN/], [/AI_GATEWAY_API_KEY/],
  [/pip install|bin\/pip|-m", "venv"|laya-venv|laya\[serve\]/], [/huggingface|HF_HUB|HF_HOME/i],
  [/curl /, ["suggest.mjs"], "probes a fast-lane suggestion must never pass (command substitution, a .env upload)"],
  [/npx /], [/npm install -g|npm i -g/], [/child_process.*install/], [/@reflex:setup-only/],
];

const MARK = /@reflex:setup-only (begin|end)\b/;
function strip(text, file) {
  const out = [];
  let open = 0;
  text.split("\n").forEach((line, i) => {
    const m = line.match(MARK);
    if (!m) { if (!open) out.push(line); return; }
    if (!/^\s*(\/\/|<!--)/.test(line)) throw new Error(`${file}:${i + 1}: a marker must be a comment line of its own`);
    if (m[1] === "begin" && open) throw new Error(`${file}:${i + 1}: nested setup-only region (the one at ${open})`);
    if (m[1] === "end" && !open) throw new Error(`${file}:${i + 1}: setup-only end without begin`);
    open = m[1] === "begin" ? i + 1 : 0;
  });
  if (open) throw new Error(`${file}:${open}: setup-only region not closed`);
  return out.join("\n");
}

const MANIFEST = {
  name: "reflex", displayName: "Reflex", version: pkg.version,
  description: "Prod-safe AI coding agents for infra teams: a pre-execution hook that judges each shell command by where it points and what it will change, then runs it, asks a human, or blocks it.",
  author: {name: "Ciprian Ursu", url: "https://github.com/ursuciprian"},
  homepage: "https://github.com/ursuciprian/reflex#readme", repository: "https://github.com/ursuciprian/reflex", license: pkg.license,
  icon: "./assets/logo-512.png",
  keywords: ["claude-code", "claude-code-hooks", "claude-code-plugin", "claude-code-security", "pre-tool-use", "pre-execution-hook", "command-approval",
    "guardrails", "agent-security", "prompt-injection", "prompt-injection-protection", "human-in-the-loop", "tool-call-gating", "permission-prompts",
    "devsecops", "jev", "typesafe"],
  userConfig: {
    engine: {type: "string", title: "Engine", default: "",
      description: "local (rules only: no key, nothing leaves the machine) or jev (hosted classification through the Jev provider; needs the Jev API key). Empty: the engine in ~/.config/reflex/config.json, else jev when the Jev API key is set, else local."},
    provider: {type: "string", title: "Jev provider", default: "",
      description: "typesafe, openrouter, cloudflare, vercel or compatible. Empty: the provider in ~/.config/reflex/config.json, else typesafe. cloudflare also needs cloudflare_account_id, and compatible provider_url, in config.json."},
    jev_api_key: {type: "string", title: "Jev API key", sensitive: true, default: "",
      description: "The key for the Jev provider (a TypeSafe key for typesafe). Kept in your system's secure storage. The plugin reads its key from here only: never from the Keychain, never from an environment variable."},
    mode: {type: "string", title: "Mode", default: "",
      description: "off, shadow (logs; deterministic rules still ask and deny) or enforce. Empty: the mode in ~/.config/reflex/config.json, else shadow."},
    judge_api_key: {type: "string", title: "System 2 API key", sensitive: true, default: "",
      description: "Optional: the key for a System 2 judge with backend anthropic or openai-compatible (judge in ~/.config/reflex/config.json). Kept in your system's secure storage."},
  },
};

const json = v => JSON.stringify(v, null, 2) + "\n";
const put = (rel, body) => { mkdirSync(dirname(join(OUT, rel)), {recursive: true}); writeFileSync(join(OUT, rel), body, {mode: 0o644}); };
function build() {
  rmSync(OUT, {recursive: true, force: true});
  for (const f of MODULES) put(f, strip(readFileSync(join(ROOT, f), "utf8"), f));
  for (const f of DATA) {
    const d = JSON.parse(readFileSync(join(ROOT, f), "utf8"));
    if (f === "setup/redact.json") delete d.corpus;   // the selfchecks' test corpus
    put(f, json(d));
  }
  for (const f of FILES) {
    if (BINARY.includes(f)) { mkdirSync(dirname(join(OUT, f)), {recursive: true}); copyFileSync(join(ROOT, f), join(OUT, f)); }
    else put(f, strip(readFileSync(join(ROOT, f), "utf8"), f));
  }
  put(".claude-plugin/plugin.json", json(MANIFEST));
  // mcp.mjs reports this version; nothing is installed from it.
  put("package.json", json({name: pkg.name, version: pkg.version, private: true, type: "module", license: pkg.license}));
  put("README.md", readFileSync(join(ROOT, "scripts/plugin-README.md"), "utf8"));
}

const walk = d => readdirSync(d, {withFileTypes: true}).flatMap(e => e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]);
function verify() {
  const problems = [], files = walk(OUT).map(p => relative(OUT, p)).sort();
  for (const f of files) {
    const buf = readFileSync(join(OUT, f)), size = statSync(join(OUT, f)).size;
    if (size > MAX) problems.push(`${f}: ${size} bytes, over 256 KiB`);
    if (BINARY.includes(f)) continue;
    if (buf.includes(0)) { problems.push(`${f}: binary`); continue; }
    buf.toString("utf8").split("\n").forEach((line, i) => {
      for (const [re, allowed = []] of FORBIDDEN) if (re.test(line) && !allowed.includes(f)) problems.push(`${f}:${i + 1}: ${re} in ${line.trim().slice(0, 120)}`);
    });
  }
  for (const f of files.filter(f => f.endsWith(".mjs"))) {
    const r = spawnSync(process.execPath, ["--check", join(OUT, f)], {encoding: "utf8"});
    if (r.status !== 0) problems.push(`${f}: does not parse\n${r.stderr}`);
  }
  const link = spawnSync(process.execPath, ["--experimental-vm-modules", "--no-warnings", fileURLToPath(import.meta.url), "--link", OUT], {encoding: "utf8"});
  if (link.status !== 0) problems.push(`link: ${link.stderr || link.stdout}`);
  return {problems, files};
}

// Links every bundled module without running it: each import must resolve to a bundled file (or a
// node: builtin) and name an export that file has; a destructured dynamic import too.
async function linkCheck(dir) {
  const vm = await import("node:vm"), mods = new Map(), errors = [];
  const load = p => {
    if (!mods.has(p)) mods.set(p, new vm.SourceTextModule(readFileSync(p, "utf8"), {identifier: p}));
    return mods.get(p);
  };
  const linker = async (spec, from) => {
    if (spec.startsWith("node:")) {
      const ns = await import(spec), keys = Object.keys(ns);
      return new vm.SyntheticModule(keys, function () { for (const k of keys) this.setExport(k, ns[k]); }, {identifier: spec});
    }
    const p = join(dirname(from.identifier), spec);
    try { statSync(p); } catch { throw new Error(`${relative(dir, from.identifier)} imports ${spec}, which is not in the bundle`); }
    return load(p);
  };
  for (const f of readdirSync(dir).filter(f => f.endsWith(".mjs"))) {
    try { const m = load(join(dir, f)); if (m.status === "unlinked") await m.link(linker); } catch (e) { errors.push(`${f}: ${e.message}`); }
  }
  for (const f of readdirSync(dir).filter(f => f.endsWith(".mjs"))) {
    const src = readFileSync(join(dir, f), "utf8");
    for (const [, names, spec] of src.matchAll(/\{([^{}]*)\}\s*=\s*await import\("(\.\/[\w.-]+)"\)/g)) {
      const target = mods.get(join(dir, spec));
      if (!target) { errors.push(`${f}: dynamic import of ${spec}, which is not in the bundle`); continue; }
      for (const n of names.split(",").map(s => s.split(":")[0].trim()).filter(Boolean))
        if (!(n in target.namespace)) errors.push(`${f}: ${spec} has no export ${n}`);
    }
  }
  if (errors.length) { console.error(errors.join("\n")); process.exit(1); }
}

// The script itself runs only when started (node build-plugin.mjs), never when the file is imported.
if (isMain(import.meta)) {
if (process.argv[2] === "--link") await linkCheck(process.argv[3]);
else {
  build();
  const {problems, files} = verify();
  if (problems.length) { console.error(`plugin build FAILED:\n${problems.join("\n")}`); process.exit(1); }
  for (const f of files) console.log(`${String(statSync(join(OUT, f)).size).padStart(8)}  plugin/${f}`);
  console.log(`plugin build OK: ${files.length} files, no forbidden pattern, every module parses and links`);
}
}
