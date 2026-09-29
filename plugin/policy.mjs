// A policy is data, not code: gates in order, each with a condition over the answers.
// This file evaluates one, in the server and in the browser, with no eval() and no domain
// knowledge — every label, outcome and threshold comes from the policy file.
//
//   const p = compile(policyJson);
//   p.decide(answers, p.values())   ->  {outcome, rule, path, notes}

const NUM = /^-?\d+(\.\d+)?$/;
const OPS = {
  "<":  (a, b) => a < b,
  "<=": (a, b) => a <= b,
  ">":  (a, b) => a > b,
  ">=": (a, b) => a >= b,
  "==": (a, b) => a === b,
  "!=": (a, b) => a !== b,
};

// `answers.<id>` -> the answer's value; `<id>.confidence` -> its confidence; `$name` -> a
// param or flag; a bare number or quoted string -> itself.
function term(token, answers, vars) {
  if (token.startsWith("$")) return vars[token.slice(1)];
  if (NUM.test(token)) return Number(token);
  if (/^'.*'$/.test(token) || /^".*"$/.test(token)) return token.slice(1, -1);
  if (token === "true") return true;
  if (token === "false") return false;
  const [id, prop] = token.split(".");
  const a = answers[id];
  if (a == null) return undefined;
  if (prop === "confidence") return a.confidence;
  return a.noul ?? a.choice ?? a.score;
}

// One clause: "<term> <op> <term>", or a bare term read as truthy. Clauses join with
// " and " / " or ", left to right, no parentheses — enough for a policy, small enough to trust.
function clause(text, answers, vars) {
  const m = text.trim().match(/^(\S+)\s*(<=|>=|==|!=|<|>)\s*(\S+)$/);
  if (!m) {
    const v = term(text.trim(), answers, vars);
    return Boolean(v);
  }
  const [, l, op, r] = m;
  const a = term(l, answers, vars), b = term(r, answers, vars);
  if (a === undefined || b === undefined) return false;
  return OPS[op](a, b);
}

export function test(expr, answers, vars) {
  if (!expr) return true;
  const ors = String(expr).split(/\s+or\s+/i);
  return ors.some(part => part.split(/\s+and\s+/i).every(c => clause(c, answers, vars)));
}

// The values a condition read, by token: {"applies": 0.62, "$fitFloor": 0.4}. Missing -> null.
// Same tokenizer shape as clause(), so the board shows exactly what the gate compared.
export function seen(expr, answers, vars) {
  const out = {};
  for (const tok of String(expr ?? "").split(/\s+|<=|>=|==|!=|<|>/)) {
    if (!tok || /^(and|or|true|false)$/i.test(tok) || NUM.test(tok) || /^['"]/.test(tok)) continue;
    out[tok] = term(tok, answers, vars) ?? null;
  }
  return out;
}

// Fills {value} placeholders in labels: "{applies} below {$fitFloor}"
function fill(text, answers, vars) {
  return String(text ?? "").replace(/\{([^}]+)\}/g, (_, token) => {
    const v = term(token.trim(), answers, vars);
    return typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(2)) : String(v ?? "?");
  });
}

export function compile(policy) {
  const params = policy.params ?? {};
  const flags = policy.flags ?? {};
  const outcomes = policy.outcomes ?? {};
  const gates = policy.gates ?? [];

  const values = (over = {}) => ({
    ...Object.fromEntries(Object.entries(params).map(([k, v]) => [k, v.default])),
    ...Object.fromEntries(Object.entries(flags).map(([k, v]) => [k, v.default])),
    ...over,
  });

  function decide(answers, vars = values()) {
    const path = [];
    const notes = [];
    for (const n of policy.notes ?? []) {
      if (test(n.when, answers, vars)) notes.push(fill(n.text, answers, vars));
    }
    for (const g of gates) {
      if (!test(g.enabled_when, answers, vars)) continue;
      const hit = test(g.test, answers, vars);
      path.push({gate: g.id, label: g.label, outcome: hit ? "yes" : "no",
                 test: g.test, seen: seen(g.test, answers, vars),
                 detail: fill(hit ? g.detail_yes ?? g.detail : g.detail_no ?? g.detail, answers, vars)});
      if (hit) {
        return {outcome: g.outcome, rule: fill(g.rule ?? g.label, answers, vars), path,
                notes: [...notes, ...(g.notes ?? []).map(t => fill(t, answers, vars))]};
      }
    }
    return {outcome: policy.default_outcome, rule: fill(policy.default_rule ?? "default", answers, {}),
            path, notes: [...notes, ...(policy.default_notes ?? []).map(t => fill(t, answers, {}))]};
  }

  const order = Object.keys(outcomes);
  return {policy, params, flags, outcomes, gates, values, decide,
          order, version: policy.version ?? "unversioned",
          color: id => outcomes[id]?.color ?? "#888",
          label: id => outcomes[id]?.label ?? id};
}

export function selfcheck() {
  const p = compile({
    version: "t1",
    params: {floor: {default: 0.5, min: 0, max: 1, step: 0.1, label: "Floor"}},
    flags: {strict: {default: true, label: "Strict"}},
    outcomes: {drop: {label: "Drop", color: "#a00"}, keep: {label: "Keep", color: "#0a0"}},
    gates: [
      {id: "fit", label: "Fits?", test: "fit < $floor", outcome: "drop",
       detail: "{fit} vs {$floor}", rule: "below {$floor}"},
      {id: "strictly", label: "Strict check", enabled_when: "$strict",
       test: "kind == 'bad'", outcome: "drop", detail: "{kind}"},
    ],
    default_outcome: "keep",
    notes: [{when: "fit < 0.8", text: "fit is only {fit}"}],
  });
  const A = (fit, kind) => ({fit: {noul: fit}, kind: {choice: kind}});
  console.assert(p.decide(A(0.2, "good")).outcome === "drop", "gate 1 fires");
  console.assert(p.decide(A(0.9, "bad")).outcome === "drop", "gate 2 fires");
  console.assert(p.decide(A(0.9, "good")).outcome === "keep", "default outcome");
  console.assert(p.decide(A(0.9, "bad"), p.values({strict: false})).outcome === "keep", "flag disables a gate");
  console.assert(p.decide(A(0.6, "good")).notes[0] === "fit is only 0.60", "note filled");
  console.assert(p.decide(A(0.2, "good")).rule === "below 0.50", "rule filled");
  console.assert(p.decide(A(0.9, "good"), p.values({floor: 0.95})).outcome === "drop", "param moves the line");
  console.assert(test("a >= 2 and b == 'x'", {a: {score: 3}, b: {choice: "x"}}, {}), "and");
  console.assert(test("a > 5 or b == 'x'", {a: {score: 3}, b: {choice: "x"}}, {}), "or");
  console.assert(!test("missing > 1", {}, {}), "missing answer is false, never a crash");
  const walk = p.decide(A(0.2, "good")).path[0];
  console.assert(walk.test === "fit < $floor" && walk.seen.fit === 0.2 && walk.seen.$floor === 0.5, "path carries what it saw");
  console.assert(seen("x>=2 and y == 'a'", {}, {}).x === null, "missing value seen as null");
  console.log("policy selfcheck OK");
}

if (typeof process !== "undefined" && process.argv?.[1]?.endsWith("policy.mjs")) selfcheck();
