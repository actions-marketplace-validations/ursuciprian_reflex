#!/usr/bin/env node
// The local Laya server (engine laya): one long-lived process, so a hook never loads a model.
// @reflex:setup-only begin
//   reflex laya start | stop | status [--json] | install-service | uninstall-service
//   reflex laya setup [--dry-run]     Python >= 3.10 venv, laya[serve] pinned, checkpoint, start
// @reflex:setup-only end
// The server is setup/laya/server.py on 127.0.0.1 only; its pid file and log are in REFLEX_DATA_DIR.
// It requires a random local token (~/.config/reflex/laya.token, 0600), so no other local process
// can stand in for it on the port or query it; Reflex sends that token, never the TypeSafe key.
// config.json "laya": {port, model, models, device, calibrated, noul}: `model` is the checkpoint the
// hooks ask (english | multilingual | typed-decisions), `models` the ones kept resident (default:
// model). REFLEX_API_URL / REFLEX_MODEL override them with engine laya, as with Jev.
import {spawn, spawnSync} from "node:child_process";
import {randomBytes} from "node:crypto";
import {chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {homedir, platform} from "node:os";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";
import {CONFIG, LAYA_DEFAULTS, LAYA_TOKEN, USER_CONFIG, layaUrl} from "./gate.mjs";
import {isMain} from "./failsafe.mjs";

const HERE = dirname(fileURLToPath(import.meta.url)), ENV = process.env;
// @reflex:setup-only begin
export const LAYA_PACKAGE = "laya[serve]==0.3.22";   // the version the evaluation ran on (setup/laya/server.py LAYA_VERSION)
const PREFIX = ENV.REFLEX_PREFIX ?? join(homedir(), ".local/share/reflex");
// @reflex:setup-only end
export const laya = () => {
  const s = {...LAYA_DEFAULTS, ...USER_CONFIG.laya}, url = CONFIG.engine === "laya" ? CONFIG.api : layaUrl(s.port);
  return {...s, url, port: new URL(url).port, model: CONFIG.engine === "laya" ? CONFIG.model : s.model, models: s.models ?? s.model, device: s.device ?? "auto",
          // @reflex:setup-only begin
          venv: join(PREFIX, "laya-venv"), hf: join(PREFIX, "laya-hf"),
          // @reflex:setup-only end
          pid: join(CONFIG.data, "laya.pid"), log: join(CONFIG.data, "laya.log"), health: new URL("/health", url).href};
};
// @reflex:setup-only begin
// Disk and resident memory, measured on an Apple M5 Max (torch 2.14): the higher of MPS and CPU (docs/GUIDE.md#laya-local-system-1).
const SIZES = {english: {disk: 0.80, rss: 2.4}, multilingual: {disk: 0.61, rss: 1.4}, "typed-decisions": {disk: 0.80, rss: 2.3}};
const VENV_GB = 0.9;
const LABEL = platform() === "darwin" ? "com.ursuciprian.reflex-laya" : "reflex-laya";
const serviceFile = () => platform() === "darwin" ? join(homedir(), "Library/LaunchAgents", `${LABEL}.plist`)
  : join(ENV.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "systemd/user", `${LABEL}.service`);
// @reflex:setup-only end

/** GET /health within `ms`: {ok, loaded, device} or {ok: false, error}. */
export async function health(ms = 1500) {
  try {
    const r = await fetch(laya().health, {signal: AbortSignal.timeout(ms)});
    const b = r.ok ? await r.json() : null;
    return b?.status === "ok" ? {ok: true, ...b, loaded: Array.isArray(b.loaded) ? b.loaded : []} : {ok: false, error: r.ok ? "not a Laya server" : `HTTP ${r.status}`};
  } catch (e) { return {ok: false, error: e.cause?.code ?? e.name}; }
}
// @reflex:setup-only begin
// A pid file can outlive its server (a crash, a reboot) and the pid be reused: only a live process
// running setup/laya/server.py counts, so stop never signals anything else.
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const isServer = pid => alive(pid) && (spawnSync("ps", ["-p", String(pid), "-o", "command="], {encoding: "utf8"}).stdout ?? "").includes("setup/laya/server.py");
const pidOf = () => { const p = Number(readFileSync(laya().pid, "utf8")); return p > 0 && isServer(p) ? p : null; };
const runningPid = () => { try { return pidOf(); } catch { return null; } };

function serverArgs(s = laya()) {
  return [join(HERE, "setup/laya/server.py"), "--port", String(s.port), "--models", s.models, "--device", s.device, "--pidfile", s.pid,
          ...(s.calibrated === true ? ["--calibrated"] : []), ...(s.noul ? ["--noul", s.noul] : [])];
}
function token() {
  if (!existsSync(LAYA_TOKEN())) {
    mkdirSync(dirname(LAYA_TOKEN()), {recursive: true, mode: 0o700});
    writeFileSync(LAYA_TOKEN(), randomBytes(24).toString("hex"), {mode: 0o600});
  }
  return readFileSync(LAYA_TOKEN(), "utf8").trim();
}
// Only what the server needs: never the user's keys (TypeSafe, cloud) in a third-party process.
const serverEnv = s => ({...Object.fromEntries(["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"].filter(k => ENV[k]).map(k => [k, ENV[k]])),
  HF_HOME: s.hf, HF_HUB_OFFLINE: "1", USE_TF: "0", PYTORCH_ENABLE_MPS_FALLBACK: "1", LAYA_API_KEY: token()});

export async function start({wait = 180} = {}) {
  const s = laya();
  const up = await health();
  if (up.ok) return say(`already running (${s.url}, ${up.loaded.join(", ")})${up.loaded.join(",") !== s.models.replace(/\s/g, "") ?
    `; settings changed: reflex laya stop, then start, to load ${s.models}` : ""}`);
  if (!existsSync(join(s.venv, "bin/python"))) return fail("no Laya install: run reflex setup --engine laya (or reflex laya setup)");
  mkdirSync(CONFIG.data, {recursive: true});
  const out = openSync(s.log, "a");
  const child = spawn(join(s.venv, "bin/python"), serverArgs(s), {detached: true, stdio: ["ignore", out, out], env: serverEnv(s)});
  child.unref();
  closeSync(out);
  for (let i = 0; i < wait * 2; i++) {
    await new Promise(r => setTimeout(r, 500));
    const h = await health();
    if (h.ok) return say(`running on ${s.url} (pid ${child.pid}, ${h.loaded.join(", ")}); log ${s.log}`);
    if (!alive(child.pid)) return fail(`the server exited; see ${s.log}`);
  }
  fail(`not healthy after ${wait} s; see ${s.log}`);
}

export function stop() {
  const pid = runningPid();
  if (existsSync(serviceFile())) say(`note: ${serviceFile()} restarts it; reflex laya uninstall-service to stop for good`);
  if (!pid) return say("not running");
  process.kill(pid, "SIGTERM");
  rmSync(laya().pid, {force: true});
  say(`stopped (pid ${pid})`);
}

export async function status({json = false} = {}) {
  const s = laya(), h = await health();
  const r = {engine: CONFIG.engine, url: s.url, model: s.model, resident: s.models, running: h.ok, pid: runningPid(),
             loaded: h.loaded ?? [], error: h.ok ? null : h.error, installed: existsSync(join(s.venv, "bin/python")),
             service: existsSync(serviceFile()) ? serviceFile() : null, log: s.log};
  if (json) console.log(JSON.stringify(r, null, 2));
  else say(`${r.running ? "running" : "NOT running"} · ${r.url} · model ${r.model} · resident ${r.loaded.join(", ") || r.resident}` +
           `${r.pid ? ` · pid ${r.pid}` : ""}${r.error ? ` · ${r.error}` : ""} · venv ${r.installed ? "installed" : "missing"}` +
           `${r.service ? " · service installed" : ""}`);
  return r;
}

export function serviceText(s = laya()) {
  const argv = [join(s.venv, "bin/python"), ...serverArgs(s)], env = serverEnv(s);
  const x = v => String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;");
  if (platform() === "darwin") return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array>${argv.map(a => `<string>${x(a)}</string>`).join("")}</array>
  <key>EnvironmentVariables</key><dict>${Object.entries(env).map(([k, v]) => `<key>${k}</key><string>${x(v)}</string>`).join("")}</dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${x(s.log)}</string>
  <key>StandardErrorPath</key><string>${x(s.log)}</string>
</dict></plist>
`;
  const q = a => `"${String(a).replace(/(["\\])/g, "\\$1").replace(/%/g, "%%").replace(/\$/g, "$$$$")}"`;   // systemd quoting, specifiers, variables
  return `[Unit]
Description=Reflex Laya server (local System 1, 127.0.0.1 only)

[Service]
ExecStart=${argv.map(q).join(" ")}
${Object.entries(env).map(([k, v]) => `Environment=${q(`${k}=${v}`)}`).join("\n")}
Restart=on-failure

[Install]
WantedBy=default.target
`;
}

export function installService() {
  const f = serviceFile();
  mkdirSync(dirname(f), {recursive: true});
  mkdirSync(CONFIG.data, {recursive: true});
  writeFileSync(f, serviceText(), {mode: 0o600});   // it holds the local token
  chmodSync(f, 0o600);
  const r = platform() === "darwin" ? spawnSync("launchctl", ["load", "-w", f], {stdio: "inherit"})
    : spawnSync("systemctl", ["--user", "enable", "--now", `${LABEL}.service`], {stdio: "inherit"});
  say(`${f} written${r.status === 0 ? " and loaded: the server starts at login" : "; load it by hand"}`);
}
export function uninstallService() {
  const f = serviceFile();
  if (!existsSync(f)) return say("no service installed");
  if (platform() === "darwin") spawnSync("launchctl", ["unload", "-w", f], {stdio: "inherit"});
  else spawnSync("systemctl", ["--user", "disable", "--now", `${LABEL}.service`], {stdio: "inherit"});
  rmSync(f, {force: true});
  say(`${f} removed`);
}

/** A Python >= 3.10 on PATH, newest tested first. */
export function findPython() {
  for (const p of ["python3.12", "python3.13", "python3.11", "python3.10", "python3"]) {
    const r = spawnSync(p, ["-c", "import sys; print('%d.%d' % sys.version_info[:2])"], {encoding: "utf8"});
    const [maj, min] = (r.stdout ?? "").trim().split(".").map(Number);
    if (r.status === 0 && (maj > 3 || (maj === 3 && min >= 10))) return {python: p, version: `${maj}.${min}`};
  }
  return null;
}

export function plan(s = laya()) {
  const names = s.models.split(",").map(n => n.trim()).filter(Boolean);
  const unknown = names.filter(n => !SIZES[n]);
  if (unknown.length) return {error: `unknown Laya checkpoint ${unknown.join(", ")} (english, multilingual, typed-decisions)`};
  const disk = VENV_GB + names.reduce((t, n) => t + SIZES[n].disk, 0), rss = names.reduce((t, n) => t + SIZES[n].rss, 0);
  return {names, disk: +disk.toFixed(1), rss: +rss.toFixed(1), lines: [
    `Laya: ${LAYA_PACKAGE} in ${s.venv} (${VENV_GB} GB with torch), checkpoint ${names.join(", ")} in ${s.hf}`,
    `  disk about ${disk.toFixed(1)} GB · server memory up to ${rss.toFixed(1)} GB resident · 127.0.0.1:${s.port} only, no TypeSafe key, nothing leaves the machine`]};
}

export async function setup({dryRun = false} = {}) {
  const s = laya(), p = plan(s), py = findPython();
  if (p.error) return fail(p.error);
  for (const l of p.lines) say(l);
  if (!py) return fail("Laya needs Python 3.10 or newer on PATH (python3.10 ... python3.13)");
  say(`  python ${py.python} (${py.version})`);
  if (dryRun) return;
  const step = (what, cmd, argv, env) => {
    say(what);
    return spawnSync(cmd, argv, {stdio: "inherit", env: env ?? ENV}).status === 0 || (fail(`${what} failed`), false);
  };
  if (!existsSync(join(s.venv, "bin/python")) && !step("creating the venv", py.python, ["-m", "venv", s.venv])) return;
  if (!step(`installing ${LAYA_PACKAGE}`, join(s.venv, "bin/pip"), ["install", "--quiet", LAYA_PACKAGE])) return;
  if (!step(`downloading ${p.names.join(", ")} (pinned revision)`, join(s.venv, "bin/python"),
            [join(HERE, "setup/laya/server.py"), "--models", s.models, "--download-only"], {...serverEnv(s), HF_HUB_OFFLINE: "0"})) return;
  await start();
}

const say = m => console.log(`\x1b[1mreflex laya\x1b[0m ${m}`);
function fail(m) { console.error(`\x1b[31mreflex laya: ${m}\x1b[0m`); process.exitCode = 1; }

if (isMain(import.meta)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const actions = {start, stop, status: () => status({json: rest.includes("--json")}), "install-service": installService,
    "uninstall-service": uninstallService, setup: () => setup({dryRun: rest.includes("--dry-run")}), service: () => process.stdout.write(serviceText())};
  if (!actions[cmd]) { console.error("usage: reflex laya start | stop | status [--json] | setup [--dry-run] | install-service | uninstall-service"); process.exit(2); }
  await actions[cmd]();
}
// @reflex:setup-only end
