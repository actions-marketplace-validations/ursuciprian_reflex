#!/usr/bin/env node
// Jev providers: the same System One contract ({state, model, questions} in, typed answers out)
// through TypeSafe direct, OpenRouter's Decisions API, Cloudflare Workers AI, the Vercel AI Gateway
// or any compatible endpoint (a full URL and a Bearer token). gate.mjs ask() and its callers see one
// shape whichever carries the call.
//
// Adapted from jev-mcp by Joey Kudish (MIT, https://github.com/jkudish/jev-mcp, commit a34db93,
// src/provider.ts and src/lib.ts): the provider names and their auto-detection order, the model
// slugs, the Cloudflare envelope, the 408/409/429/5xx retry allowlist with jittered backoff inside
// one deadline, and key redaction in error text. Request and response formats were checked against
// each provider's documentation: openrouter.ai/docs (Decisions API), developers.cloudflare.com/ai
// (typesafe/jev, the /ai/run endpoint), vercel.com/docs/ai-gateway (TypeSafe-compatible API).
//
//   node providers.mjs --selfcheck    mock servers for every provider, no network
import {createServer} from "node:http";
import {isMain} from "./failsafe.mjs";

export const PROVIDER_NAMES = ["typesafe", "openrouter", "cloudflare", "vercel", "compatible"];
const typesafeBody = (state, questions, model) => ({state, model, questions});
// url: the default endpoint. pinned: its key goes to this host and no other.
// keychain: the macOS Keychain item (TypeSafe's is REFLEX_KEYCHAIN_SERVICE or "keychain" in config.json).
// env and detect (below): the environment variables its key is read from.
export const PROVIDERS = {
  typesafe: {url: () => "https://api.typesafe.ai/v1/systemone", keychain: "typesafe-api-key",
    model: m => m, body: typesafeBody},
  // OpenRouter serves pinned minor versions (typesafe/jev-1.13), no patch level and no latest alias.
  openrouter: {url: () => "https://openrouter.ai/api/alpha/decisions",
    keychain: "openrouter-api-key", pinned: "openrouter.ai",
    model: m => m.startsWith("typesafe/") ? m : `typesafe/${m.replace(/^(jev-\d+\.\d+)\.\d+$/, "$1")}`, body: typesafeBody,
    headers: {"HTTP-Referer": "https://github.com/ursuciprian/reflex", "X-Title": "Reflex"}},
  // Cloudflare serves one always-current alias, typesafe/jev; the call wraps the contract in {model, input}.
  cloudflare: {url: s => `https://api.cloudflare.com/client/v4/accounts/${s.account}/ai/run`,
    keychain: "cloudflare-api-token", pinned: "api.cloudflare.com",
    model: m => m.startsWith("typesafe/") ? m : "typesafe/jev", body: (state, questions, model) => ({model, input: {state, questions}})},
  // The gateway's TypeSafe-compatible API: TypeSafe's request and response shapes, model typesafe-ai/jev.
  vercel: {url: () => "https://ai-gateway.vercel.sh/typesafe/v1/systemone",
    keychain: "ai-gateway-api-key", pinned: "ai-gateway.vercel.sh", model: m => m.startsWith("typesafe-ai/") ? m : "typesafe-ai/jev", body: typesafeBody},
  compatible: {url: s => s.url, keychain: "jev-api-key", model: m => m, body: typesafeBody},
};
/** host[:port] lowercased, without a trailing dot or the scheme's default port; null when not a URL. */
export const hostOf = u => { try { const x = new URL(u); return x.hostname.replace(/\.$/, "") + (x.port ? `:${x.port}` : ""); } catch { return null; } };
export const DEFAULT_HOSTS = ["api.typesafe.ai", "openrouter.ai", "api.cloudflare.com", "ai-gateway.vercel.sh"];
const LOOPBACK = ["127.0.0.1", "[::1]", "localhost"];
/** The key for provider `p` in `env`; when `detecting`, only from the variables that may choose it. */
export const envKey = (env, p, detecting) => (detecting ? PROVIDERS[p].detect : PROVIDERS[p].env)?.map(n => env[n]?.trim()).find(Boolean) ?? null;

/**
 * The provider from the environment and saved settings (no Keychain lookup, so it is cheap on every
 * hook): REFLEX_PROVIDER, JEV_PROVIDER or config.json "provider" wins. With a TypeSafe key, or a
 * TypeSafe Keychain item named in config.json, TypeSafe. Otherwise jev-mcp's order over the opt-in
 * `detect` variables, else TypeSafe with its Keychain item, as before. `reflex setup` also looks in
 * the Keychain, in the same order, and saves what it finds.
 */
export function resolveProvider(env, saved = {}) {
  const chosen = String(env.REFLEX_PROVIDER || env.JEV_PROVIDER || saved.provider || "auto").toLowerCase();
  const settings = {account: env.CLOUDFLARE_ACCOUNT_ID?.trim() || saved.cloudflare_account_id, url: env.JEV_API_BASE_URL?.trim() || saved.provider_url};
  const found = chosen === "auto" && !saved.keychain && detect(p => !!envKey(env, p, true) &&
    (p !== "openrouter" || /^sk-or-/.test(envKey(env, p, true))), settings);
  const name = chosen !== "auto" ? chosen : found || "typesafe";
  return {name, explicit: chosen !== "auto", detected: !!found, settings, error: providerError(name, settings)};
}
/** The first provider in jev-mcp's order that has a key (`has`) and the rest of what it needs. */
export function detect(has, settings) {
  return PROVIDER_NAMES.find(p => has(p) && !providerError(p, settings));
}
export function providerError(name, s) {
  if (!PROVIDERS[name]) return `provider must be auto or one of ${PROVIDER_NAMES.join(", ")}`;
  // an account id is 32 hex characters; checked, since it becomes part of the URL
  if (name === "cloudflare" && !/^[0-9a-f]{32}$/i.test(s.account ?? "")) return "provider cloudflare needs CLOUDFLARE_ACCOUNT_ID (or cloudflare_account_id in config.json)";
  if (name === "compatible" && !s.url) return "provider compatible needs JEV_API_BASE_URL (or provider_url in config.json): the full URL, /v1/systemone included";
  const url = PROVIDERS[name].url(s);
  if (name === "compatible" && !hostOf(url)) return "provider_url must be a full http(s) URL";
  return null;
}
export const providerUrl = (name, s) => PROVIDERS[name]?.url(s) ?? null;

/**
 * Whether a provider's key may go to `url`. OpenRouter's, Cloudflare's and Vercel's go to their own
 * host over https and nowhere else. TypeSafe's and a compatible endpoint's go to the host their
 * endpoint was configured with (`keyHost`), never to another provider's host, never in clear text
 * off this machine, and never to the Laya server's port (`layaPort`).
 */
export function keyRouteError(name, url, keyHost, layaPort = 8421) {
  const host = hostOf(url), spec = PROVIDERS[name];
  if (!spec) return `unknown provider ${name}`;
  if (!host) return `the ${name} key goes only to its own host, not to an invalid URL`;
  const u = new URL(url), loopback = LOOPBACK.includes(u.hostname);
  if (spec.pinned) return host === spec.pinned && u.protocol === "https:" ? null : `the ${name} key goes only to https://${spec.pinned}, not to ${host}`;
  if (host !== keyHost) return `the ${name} key goes only to ${keyHost}, not to ${host}`;
  if (DEFAULT_HOSTS.includes(host) && host !== (name === "typesafe" ? "api.typesafe.ai" : null)) return `the ${name} key never goes to another provider (${host})`;
  if (u.protocol !== "https:" && !loopback) return `the ${name} key is sent over https only`;
  if (loopback && Number(u.port || (u.protocol === "https:" ? 443 : 80)) === Number(layaPort)) return `the ${name} key never goes to the Laya server`;
  return null;
}

// ---------------------------------------------------------------------------------------------
// Answers: every provider's reply becomes {answers: {id: {type, noul | choice | score, probabilities?,
// confidence?}}, usage: {input_tokens, output_tokens}}. A reply that cannot be read that way is an
// error, which callers treat as Jev unavailable (the policy fallback asks), never as a pass. An answer
// a question did not get is left to the caller, which already reads a missing one as incomplete.
export class Malformed extends Error { name = "Malformed"; }
const isObject = v => v !== null && typeof v === "object" && !Array.isArray(v);
const unit = v => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;
export function normalize(provider, payload, questions) {
  let p = payload;
  if (provider === "cloudflare") {
    // The v4 envelope {success, result, errors}; /ai/run may add {state, result} inside it.
    if (!isObject(p) || p.success === false) throw new Malformed("cloudflare: success false");
    p = isObject(p.result) ? p.result : p;
    if (typeof p.state === "string" && p.state !== "Completed") throw new Malformed(`cloudflare: run ${p.state.slice(0, 20)}`);
    if (!isObject(p.answers) && isObject(p.result)) p = p.result;
  }
  if (!isObject(p) || !isObject(p.answers)) throw new Malformed(`${provider}: no answers object`);
  const answers = {};
  for (const [id, q] of Object.entries(questions)) {
    if (!Object.hasOwn(p.answers, id)) continue;
    const a = p.answers[id];
    const bad = why => new Malformed(`${provider}: answer ${id} ${why}`);
    if (!isObject(a)) throw bad("is not an object");
    if (a.type !== undefined && a.type !== q.type) throw bad(`has type ${String(a.type).slice(0, 10)}`);
    const confidence = a.confidence ?? undefined;
    if (confidence !== undefined && !unit(confidence)) throw bad("has an invalid confidence");
    const probabilities = a.probabilities ?? undefined;
    if (probabilities !== undefined && !(isObject(probabilities) && Object.values(probabilities).every(unit))) throw bad("has invalid probabilities");
    // Probability keys name options: a choice's criteria, a score's level indices. Callers rank by them.
    const option = k => q.type === "choice" ? !isObject(q.criteria) || Object.hasOwn(q.criteria, k)
      : q.type === "score" ? /^(0|[1-9]\d*)$/.test(k) && (!Array.isArray(q.criteria) || Number(k) < q.criteria.length) : true;
    if (probabilities !== undefined && !Object.keys(probabilities).every(option)) throw bad("has probabilities for options it was not asked about");
    const extra = {...(probabilities && {probabilities}), ...(confidence !== undefined && {confidence})};
    if (q.type === "noul") {
      if (!unit(a.noul)) throw bad("is not a probability");
      answers[id] = {type: "noul", noul: a.noul};
    } else if (q.type === "choice") {
      if (typeof a.choice !== "string" || (isObject(q.criteria) && !Object.hasOwn(q.criteria, a.choice))) throw bad("is not one of its criteria");
      answers[id] = {type: "choice", choice: a.choice, ...extra};
    } else if (q.type === "score") {
      const top = Array.isArray(q.criteria) ? q.criteria.length - 1 : Infinity;
      if (typeof a.score !== "number" || !Number.isFinite(a.score) || a.score < 0 || a.score > top) throw bad("is not on its scale");
      answers[id] = {type: "score", score: a.score, ...extra};
    } else throw bad(`answers an unknown question type`);
  }
  const u = isObject(p.usage) ? p.usage : {}, count = v => typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
  return {answers, usage: {input_tokens: count(u.input_tokens), output_tokens: count(u.output_tokens), ...(typeof u.cost === "number" && {cost: u.cost})}};
}

// ---------------------------------------------------------------------------------------------
// One call. One deadline covers every attempt and the body read (the hook's time budget, not a
// per-attempt timeout). Only 408, 409, 429 and 5xx are retried, with jittered exponential backoff,
// and only when the backoff still ends before the deadline. A network error is not retried: without
// an idempotency key a re-send can be charged twice (jev-mcp's reasoning). No error text quotes a key.
export const RETRY = {attempts: 3, base_ms: 150, max_ms: 1000};
export const retryable = s => s === 408 || s === 409 || s === 429 || (s >= 500 && s <= 599);
export const backoff = (attempt, r = Math.random()) => Math.min(RETRY.base_ms * 2 ** attempt, RETRY.max_ms) * (0.5 + r * 0.5);

export async function call({provider, url, key, headers = {}, state, questions, model, deadline, retry = RETRY}) {
  const spec = PROVIDERS[provider] ?? PROVIDERS.typesafe;
  const scrub = s => key ? String(s).split(key).join("[key]") : String(s);
  const signal = AbortSignal.timeout(Math.max(1, deadline - Date.now()));
  const body = JSON.stringify(spec.body(state, questions, spec.model(model)));
  for (let attempt = 0; ; attempt++) {
    let r;
    try {
      // redirect: "error": a redirect would re-send the state (and answer for Jev) from another host
      r = await fetch(url, {method: "POST", signal, body, redirect: "error",
        headers: {...spec.headers, ...headers, ...(key && {Authorization: `Bearer ${key}`}), "Content-Type": "application/json"}});
    } catch (e) { throw Object.assign(new Error(scrub(e.message)), {name: e.name}); }
    if (retryable(r.status) && attempt + 1 < retry.attempts) {
      const wait = backoff(attempt);
      if (Date.now() + wait < deadline - 50) {
        await r.body?.cancel().catch(() => {});
        await new Promise(res => setTimeout(res, wait));
        continue;
      }
    }
    // The status only: an error body may echo the request or the key, and this text reaches the trace.
    if (!r.ok) { await r.body?.cancel().catch(() => {}); throw new Error(`HTTP ${r.status} (${provider})`); }
    let text;
    try { text = await r.text(); } catch (e) { throw Object.assign(new Error(scrub(e.message)), {name: e.name}); }
    let payload;
    try { payload = JSON.parse(text); } catch { throw new Malformed(`${provider}: the reply is not JSON`); }
    return normalize(provider, payload, questions);
  }
}

// ---------------------------------------------------------------------------------------------

