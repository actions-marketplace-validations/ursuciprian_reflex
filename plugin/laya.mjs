#!/usr/bin/env node
// The local Laya server (engine laya): one long-lived process, so a hook never loads a model.
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

const HERE = dirname(fileURLToPath(import.meta.url)), ENV = process.env;
export const laya = () => {
  const s = {...LAYA_DEFAULTS, ...USER_CONFIG.laya}, url = CONFIG.engine === "laya" ? CONFIG.api : layaUrl(s.port);
  return {...s, url, port: new URL(url).port, model: CONFIG.engine === "laya" ? CONFIG.model : s.model, models: s.models ?? s.model, device: s.device ?? "auto",
          pid: join(CONFIG.data, "laya.pid"), log: join(CONFIG.data, "laya.log"), health: new URL("/health", url).href};
};

/** GET /health within `ms`: {ok, loaded, device} or {ok: false, error}. */
export async function health(ms = 1500) {
  try {
    const r = await fetch(laya().health, {signal: AbortSignal.timeout(ms)});
    const b = r.ok ? await r.json() : null;
    return b?.status === "ok" ? {ok: true, ...b, loaded: Array.isArray(b.loaded) ? b.loaded : []} : {ok: false, error: r.ok ? "not a Laya server" : `HTTP ${r.status}`};
  } catch (e) { return {ok: false, error: e.cause?.code ?? e.name}; }
}
