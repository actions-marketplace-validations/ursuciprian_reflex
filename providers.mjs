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

export const PROVIDER_NAMES = ["typesafe", "openrouter", "cloudflare", "vercel", "compatible"];
const typesafeBody = (state, questions, model) => ({state, model, questions});
// url: the default endpoint. env: where its key is read, in order. keychain: the macOS Keychain item
// (TypeSafe's is configurable, as before: REFLEX_KEYCHAIN_SERVICE or "keychain" in config.json).
export const PROVIDERS = {
  typesafe: {url: () => "https://api.typesafe.ai/v1/systemone", env: ["TYPESAFE_API_KEY"], keychain: "typesafe-api-key",
    model: m => m, body: typesafeBody},
  // OpenRouter serves pinned minor versions (typesafe/jev-1.13), no patch level and no latest alias.
  openrouter: {url: () => "https://openrouter.ai/api/alpha/decisions", env: ["OPENROUTER_API_KEY"], keychain: "openrouter-api-key",
    model: m => m.startsWith("typesafe/") ? m : `typesafe/${m.replace(/^(jev-\d+\.\d+)\.\d+$/, "$1")}`, body: typesafeBody,
    headers: {"HTTP-Referer": "https://github.com/ursuciprian/reflex", "X-Title": "Reflex"}},
  // Cloudflare serves one always-current alias, typesafe/jev; the call wraps the contract in {model, input}.
  cloudflare: {url: s => `https://api.cloudflare.com/client/v4/accounts/${s.account}/ai/run`, env: ["JEV_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN"],
    keychain: "cloudflare-api-token", model: m => m.startsWith("typesafe/") ? m : "typesafe/jev",
    body: (state, questions, model) => ({model, input: {state, questions}})},
  // The gateway's TypeSafe-compatible API: TypeSafe's request and response shapes, model typesafe-ai/jev.
  vercel: {url: () => "https://ai-gateway.vercel.sh/typesafe/v1/systemone", env: ["AI_GATEWAY_API_KEY"], keychain: "ai-gateway-api-key",
    model: m => m.startsWith("typesafe-ai/") ? m : "typesafe-ai/jev", body: typesafeBody},
  compatible: {url: s => s.url, env: ["JEV_API_KEY"], keychain: "jev-api-key", model: m => m, body: typesafeBody},
};
const hostOf = u => { try { return new URL(u).host; } catch { return null; } };
export const DEFAULT_HOSTS = ["typesafe", "openrouter", "vercel"].map(p => hostOf(PROVIDERS[p].url()))
  .concat("api.cloudflare.com");

/**
 * The provider from the environment and saved settings (no Keychain lookup, so it is cheap on every
 * hook): REFLEX_PROVIDER, JEV_PROVIDER or config.json "provider" wins; otherwise jev-mcp's order over
 * the environment, and TypeSafe when none is set (its key then comes from the Keychain, as before).
 * `reflex setup` also looks in the Keychain, in the same order, and saves what it finds.
 */
export function resolveProvider(env, saved = {}) {
  const chosen = String(env.REFLEX_PROVIDER ?? env.JEV_PROVIDER ?? saved.provider ?? "auto").toLowerCase();
  const settings = {account: env.CLOUDFLARE_ACCOUNT_ID?.trim() || saved.cloudflare_account_id, url: env.JEV_API_BASE_URL?.trim() || saved.provider_url};
  const found = chosen === "auto" && detect(p => PROVIDERS[p].env.some(n => env[n]?.trim()) &&
    (p !== "openrouter" || /^sk-or-/.test(env.OPENROUTER_API_KEY.trim())), settings);
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
 * Whether a provider's key may go to `url`: only to the host that provider was configured with
 * (`keyHost`), never to another built-in provider's host, and never in clear text off this machine.
 */
export function keyRouteError(name, url, keyHost) {
  const host = hostOf(url);
  if (!host || host !== keyHost) return `the ${name} key goes only to ${keyHost}, not to ${host ?? "an invalid URL"}`;
  const own = name === "cloudflare" ? "api.cloudflare.com" : hostOf(PROVIDERS[name].url({}) ?? "");
  if (DEFAULT_HOSTS.includes(host) && host !== own) return `the ${name} key never goes to another provider (${host})`;
  const u = new URL(url);
  if (u.protocol !== "https:" && !["127.0.0.1", "[::1]", "localhost"].includes(u.hostname)) return `the ${name} key is sent over https only`;
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
      r = await fetch(url, {method: "POST", signal, body,
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
    let text;
    try { text = await r.text(); } catch (e) { throw Object.assign(new Error(scrub(e.message)), {name: e.name}); }
    if (!r.ok) throw new Error(`HTTP ${r.status} (${provider}): ${scrub(text).slice(0, 200)}`);
    let payload;
    try { payload = JSON.parse(text); } catch { throw new Malformed(`${provider}: the reply is not JSON`); }
    return normalize(provider, payload, questions);
  }
}

// ---------------------------------------------------------------------------------------------
async function selfcheck() {
  const ok = (c, m) => { if (!c) { console.error("FAIL", m); process.exitCode = 1; } };
  const Q = {mutates: {type: "noul", instructions: "x"}, env: {type: "choice", instructions: "x", criteria: {local: "a", prod: "b"}},
             blast: {type: "score", instructions: "x", criteria: ["none", "small", "large"]}};
  const good = {mutates: {type: "noul", noul: 0.1}, env: {type: "choice", choice: "local", probabilities: {local: 0.9, prod: 0.1}, confidence: 0.8},
                blast: {type: "score", score: 0.4, confidence: 0.9}};
  // A mock server per test: `reply(req, body, n)` -> [status, json|string]; every request is recorded.
  const serve = async reply => {
    const seen = [];
    const server = createServer(async (req, res) => {
      let b = ""; for await (const c of req) b += c;
      seen.push({url: req.url, headers: req.headers, body: b ? JSON.parse(b) : null});
      const [status, out, delay = 0] = await reply(req, seen.at(-1).body, seen.length);
      setTimeout(() => { res.writeHead(status, {"Content-Type": "application/json"}); res.end(typeof out === "string" ? out : JSON.stringify(out)); }, delay);
    });
    await new Promise(r => server.listen(0, "127.0.0.1", r));
    return {seen, url: path => `http://127.0.0.1:${server.address().port}${path}`, close: () => new Promise(r => server.close(r))};
  };
  const KEY = ["sk-or-v1", "selfcheck", process.pid].join("-");
  const go = (s, provider, path, extra = {}) => call({provider, url: s.url(path), key: KEY, state: {call: {command: "ls"}}, questions: Q,
    model: "jev-1.13.0", deadline: Date.now() + 2000, ...extra});
  const wire = {
    typesafe: [ "/v1/systemone", b => b.model === "jev-1.13.0" && b.state.call.command === "ls" && b.questions.mutates, {answers: good, usage: {input_tokens: 5, output_tokens: 1}}],
    openrouter: ["/api/alpha/decisions", b => b.model === "typesafe/jev-1.13" && b.state && b.questions,
      {id: "gen-1", model: "typesafe/jev-1.13", provider: "TypeSafe", answers: good, usage: {input_tokens: 5, output_tokens: 1, cost: 0.0000002}}],
    cloudflare: ["/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/run", b => b.model === "typesafe/jev" && b.input.state && b.input.questions && !b.state,
      {success: true, errors: [], result: {state: "Completed", result: {model: "jev-1.13.0", answers: good, usage: {input_tokens: 5, output_tokens: 1}}}}],
    vercel: ["/typesafe/v1/systemone", b => b.model === "typesafe-ai/jev" && b.state && b.questions,
      {model: "typesafe-ai/jev", answers: good, usage: {input_tokens: 5, output_tokens: 1}, provider_metadata: {gateway: {cost: "0.00001"}}}],
    compatible: ["/v1/systemone", b => b.model === "jev-1.13.0", {answers: good, usage: {input_tokens: 5, output_tokens: 1}}],
  };
  for (const [p, [path, shape, reply]] of Object.entries(wire)) {
    const s = await serve(() => [200, reply]);
    const r = await go(s, p, path);
    const h = s.seen[0].headers;
    ok(s.seen.length === 1 && s.seen[0].url === path && shape(s.seen[0].body), `${p}: request format ${JSON.stringify(s.seen[0].body).slice(0, 120)}`);
    ok(h.authorization === `Bearer ${KEY}` && h["content-type"] === "application/json", `${p}: Bearer auth header`);
    ok(r.answers.mutates.noul === 0.1 && r.answers.env.choice === "local" && r.answers.env.confidence === 0.8 && r.answers.blast.score === 0.4 &&
       r.usage.input_tokens === 5 && r.usage.output_tokens === 1, `${p}: normalised answers ${JSON.stringify(r)}`);
    if (p === "openrouter") ok(h["http-referer"] && h["x-title"] === "Reflex", "openrouter: app attribution headers");
    await s.close();
  }
  // Cloudflare's other documented shapes: the output directly in result, and a run that did not complete.
  { const s = await serve((_, __, n) => [200, n === 1 ? {success: true, result: {answers: good, usage: {}}} : n === 2 ? {success: true, result: {state: "Failed"}} : {success: false, errors: [{code: 1}]}]);
    const p = wire.cloudflare[0];
    ok((await go(s, "cloudflare", p)).answers.env.choice === "local", "cloudflare: answers directly in result");
    await go(s, "cloudflare", p).then(() => ok(false, "cloudflare: Failed state"), e => ok(e instanceof Malformed, "cloudflare: a run that did not complete is malformed"));
    await go(s, "cloudflare", p).then(() => ok(false, "cloudflare: success false"), e => ok(e instanceof Malformed, "cloudflare: success false is malformed"));
    await s.close(); }
  // Malformed answers fail closed: every one is an error (callers ask), none becomes an answer.
  const malformed = [["not JSON", "<html>"], ["no answers", {usage: {}}], ["answers an array", {answers: []}],
    ["noul out of range", {answers: {...good, mutates: {type: "noul", noul: 7}}}], ["noul a string", {answers: {...good, mutates: {noul: "no"}}}],
    ["choice outside criteria", {answers: {...good, env: {choice: "moon"}}}], ["wrong type", {answers: {...good, mutates: {type: "choice", choice: "local"}}}],
    ["score off the scale", {answers: {...good, blast: {score: 9}}}], ["negative score", {answers: {...good, blast: {score: -1}}}],
    ["bad confidence", {answers: {...good, env: {choice: "local", confidence: 3}}}], ["bad probabilities", {answers: {...good, env: {choice: "local", probabilities: {local: "x"}}}}],
    ["answer not an object", {answers: {...good, mutates: 0}}]];
  for (const p of PROVIDER_NAMES) {
    const s = await serve((_, __, n) => [200, p === "cloudflare" && typeof malformed[n - 1][1] === "object" ? {success: true, result: malformed[n - 1][1]} : malformed[n - 1][1]]);
    for (const [why] of malformed)
      await go(s, p, wire[p][0]).then(r => ok(false, `${p}: ${why} must fail, got ${JSON.stringify(r)}`), e => ok(e instanceof Malformed, `${p}: ${why} is Malformed (${e.message})`));
    await s.close();
  }
  // A missing answer is not invented: the caller sees it missing (gate.mjs reads that as incomplete).
  { const s = await serve(() => [200, {answers: {mutates: good.mutates}}]);
    const r = await go(s, "typesafe", "/v1/systemone");
    ok(!("env" in r.answers) && r.answers.mutates.noul === 0.1, "a missing answer stays missing"); await s.close(); }
  // Retries: 408, 409, 429 and 5xx, then success; never a 4xx such as 401, never past attempts.
  for (const status of [408, 409, 429, 500, 503, 529]) {
    const s = await serve((_, __, n) => n === 1 ? [status, {error: "busy"}] : [200, {answers: good}]);
    ok((await go(s, "openrouter", "/api/alpha/decisions")).answers.env.choice === "local" && s.seen.length === 2, `retry on ${status}`); await s.close();
  }
  for (const status of [400, 401, 403, 404]) {
    const s = await serve(() => [status, {error: {message: `echo Bearer ${KEY}`}}]);
    await go(s, "vercel", "/typesafe/v1/systemone").then(() => ok(false, `${status}`), e => ok(s.seen.length === 1 && e.message.startsWith(`HTTP ${status}`) && !e.message.includes(KEY),
      `no retry on ${status}, and the echoed key is scrubbed: ${e.message}`));
    await s.close();
  }
  { const s = await serve(() => [503, {}]);
    await go(s, "cloudflare", wire.cloudflare[0]).then(() => ok(false, "503 forever"), e => ok(s.seen.length === RETRY.attempts && /HTTP 503/.test(e.message), `attempts capped at ${RETRY.attempts}`));
    await s.close(); }
  // The deadline: one budget for all attempts. A retry whose backoff would end past it is not made,
  // and a slow reply is cut at the deadline, not at deadline x attempts.
  { const s = await serve(() => [429, {}]);
    const t0 = Date.now();
    await go(s, "typesafe", "/v1/systemone", {deadline: Date.now() + 120}).then(() => ok(false, "429"), e => ok(/HTTP 429/.test(e.message), e.message));
    ok(s.seen.length === 1 && Date.now() - t0 < 120, `no retry past the deadline (${s.seen.length} attempts)`); await s.close(); }
  { const s = await serve(() => [200, {answers: good}, 5000]);
    const t0 = Date.now();
    await go(s, "compatible", "/v1/systemone", {deadline: Date.now() + 300}).then(() => ok(false, "slow"), e => ok(e.name === "TimeoutError" || e.name === "AbortError", `slow reply: ${e.name}`));
    ok(Date.now() - t0 < 1000, `the deadline covers the whole call (${Date.now() - t0} ms)`); await s.close(); }
  { const s = await serve((_, __, n) => n < 3 ? [500, {}, 200] : [200, {answers: good}]);
    const t0 = Date.now();
    await go(s, "openrouter", "/api/alpha/decisions", {deadline: Date.now() + 500}).then(() => ok(false, "slow 500s"), () => {});
    ok(Date.now() - t0 < 700, `retries stay inside the one deadline (${Date.now() - t0} ms, ${s.seen.length} attempts)`); await s.close(); }
  ok(backoff(0, 0) === RETRY.base_ms / 2 && backoff(0, 1) === RETRY.base_ms && backoff(10, 1) === RETRY.max_ms, "backoff: jittered, doubling, capped");
  // Detection: jev-mcp's order over the environment; an explicit choice wins; what each one needs.
  const A = "0123456789abcdef0123456789abcdef";
  const R = (env, saved) => resolveProvider(env, saved);
  ok(R({TYPESAFE_API_KEY: "t", OPENROUTER_API_KEY: "sk-or-x"}).name === "typesafe", "detect: TypeSafe first");
  ok(R({OPENROUTER_API_KEY: "sk-or-x", CLOUDFLARE_API_TOKEN: "c", CLOUDFLARE_ACCOUNT_ID: A}).name === "openrouter", "detect: OpenRouter second");
  ok(R({OPENROUTER_API_KEY: "not-openrouter", CLOUDFLARE_API_TOKEN: "c", CLOUDFLARE_ACCOUNT_ID: A}).name === "cloudflare", "detect: only an sk-or- key is OpenRouter");
  ok(R({CLOUDFLARE_API_TOKEN: "c", AI_GATEWAY_API_KEY: "v"}).name === "vercel", "detect: Cloudflare needs its account id");
  ok(R({AI_GATEWAY_API_KEY: "v", JEV_API_KEY: "j", JEV_API_BASE_URL: "https://x.example/v1/systemone"}).name === "vercel", "detect: Vercel before compatible");
  ok(R({JEV_API_KEY: "j", JEV_API_BASE_URL: "https://x.example/v1/systemone"}).name === "compatible", "detect: compatible last");
  ok(R({}).name === "typesafe" && !R({}).explicit, "detect: nothing set is TypeSafe (its Keychain item)");
  ok(R({TYPESAFE_API_KEY: "t"}, {provider: "vercel"}).name === "vercel" && R({REFLEX_PROVIDER: "openrouter"}, {provider: "vercel"}).name === "openrouter", "explicit: environment, then config.json");
  ok(R({}, {provider: "cloudflare"}).error && !R({}, {provider: "cloudflare", cloudflare_account_id: A}).error, "cloudflare needs an account id");
  ok(R({CLOUDFLARE_ACCOUNT_ID: "../../x"}, {provider: "cloudflare"}).error, "cloudflare: an account id that is not one is refused");
  ok(R({}, {provider: "compatible"}).error && R({}, {provider: "wat"}).error, "compatible needs a URL; unknown names are errors");
  // Key routing: only the configured host, never another provider's, never clear text off the machine.
  ok(!keyRouteError("openrouter", "https://openrouter.ai/api/alpha/decisions", "openrouter.ai"), "route: own host");
  ok(keyRouteError("openrouter", "https://api.typesafe.ai/v1/systemone", "openrouter.ai"), "route: not another provider's host");
  ok(keyRouteError("openrouter", "https://api.typesafe.ai/v1/systemone", "api.typesafe.ai"), "route: not another provider's host even when configured there");
  ok(!keyRouteError("typesafe", "http://127.0.0.1:9/v1/systemone", "127.0.0.1:9"), "route: a loopback override is fine");
  ok(keyRouteError("compatible", "http://jev.example/v1/systemone", "jev.example"), "route: no key over http off the machine");
  ok(keyRouteError("vercel", "http://127.0.0.1:8421/v1/systemone", "ai-gateway.vercel.sh"), "route: never the Laya URL");
  if (!process.exitCode) console.log("providers selfcheck ok");
}

if (process.argv.includes("--selfcheck") && import.meta.url === `file://${process.argv[1]}`) await selfcheck();
