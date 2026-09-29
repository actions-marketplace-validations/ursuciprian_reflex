#!/usr/bin/env node
// Plan-aware infra gate: judge `terraform apply` and `kubectl apply|delete|replace|patch` by what they
// will change, not only by the command text. gate.mjs calls planGate() after the rules.
//
// terraform: the hook never runs `terraform plan` or `terraform apply`. Plan executes providers with
// the user's credentials, runs `data "external"` programs and is slow. The hook only reads a saved
// plan the agent produced, with `terraform show -json <planfile>`: local, no provider API calls (it
// starts the provider binaries in .terraform only to read their schemas, as `terraform validate`
// does, which the fast lane already passes). A strict timeout, a sanitized environment without cloud
// credentials, CHECKPOINT_DISABLE so Terraform does not call HashiCorp's version service.
//   0 deletes and 0 replaces: allow-eligible (the usual policy decides), ask in production
//   any delete or replace:    deny (infra.destroy: "ask" softens it), stateful types named first
//   no plan file:             ask (deny in production with infra.require_plan_in_prod)
//   unreadable, stale, not a plan, show failed or timed out: ask ("no readable saved plan")
// kubectl: only with infra.kubectl_diff (it calls the API server): `kubectl diff` for apply, and
// `--dry-run=server -o name` for delete, replace and patch, with the same arguments. Deletes of
// namespaces, PVCs, PVs, statefulsets or CRDs follow infra.destroy; other deletes ask. Off, or on
// any failure, the gate behaves as before.
//
// ponytail: the plan is read when the hook runs and applied a moment later. A process the agent
// left running could swap the file in between; Terraform itself still refuses a plan whose state
// moved. Only a command that is nothing but cd steps and the apply can pass on a clean plan.
import {accessSync, constants, lstatSync, openSync, readSync, closeSync, readdirSync, realpathSync, statSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {homedir} from "node:os";
import {basename, dirname, isAbsolute, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

export const INFRA_DEFAULTS = {enabled: true, destroy: "deny", require_plan_in_prod: false, kubectl_diff: false, timeout_ms: 3000};
/** User settings (config.json `infra`) with the team's stricter parts: a team can force deny-on-destroy or a saved plan in prod. */
export function infraSettings(saved, team) {
  const s = {...INFRA_DEFAULTS, ...(saved && typeof saved === "object" && !Array.isArray(saved) ? saved : {})};
  if (team?.destroy === "deny") s.destroy = "deny";
  if (team?.require_plan_in_prod === true) s.require_plan_in_prod = true;
  if (team) s.enabled = true;   // a team that asks for the plan gate gets it
  return s;
}
export function infraError(saved) {
  if (saved === undefined) return null;
  if (!saved || typeof saved !== "object" || Array.isArray(saved)) return "infra must be an object";
  const extra = Object.keys(saved).find(k => !(k in INFRA_DEFAULTS));
  if (extra) return `infra: unknown key "${extra}" (${Object.keys(INFRA_DEFAULTS).join(", ")})`;
  for (const k of ["enabled", "require_plan_in_prod", "kubectl_diff"]) if (saved[k] !== undefined && typeof saved[k] !== "boolean") return `infra.${k} must be true or false`;
  if (saved.destroy !== undefined && !["deny", "ask"].includes(saved.destroy)) return 'infra.destroy must be "deny" or "ask"';
  // the hook has 10 s in all: a plan read that could take most of it would let the command through
  if (saved.timeout_ms !== undefined && !(Number.isInteger(saved.timeout_ms) && saved.timeout_ms >= 100 && saved.timeout_ms <= 4000)) return "infra.timeout_ms must be 100 to 4000";
  return null;
}

// Types whose delete loses data, not just a resource to recreate.
const STATEFUL = /^(aws_(db_instance|rds_cluster(_instance)?|s3_bucket|dynamodb_table|efs_file_system|ebs_volume|elasticache_(cluster|replication_group)|redshift_cluster|docdb_cluster|neptune_cluster|opensearch_domain|elasticsearch_domain|kms_key|secretsmanager_secret|backup_vault|fsx_\w+_file_system|memorydb_cluster|timestreamwrite_table|qldb_ledger|kinesis_stream|msk_cluster|ecr_repository|cognito_user_pool)|google_(sql_database_instance|sql_database|storage_bucket|bigquery_(dataset|table)|compute_disk|spanner_(instance|database)|bigtable_(instance|table)|filestore_instance|redis_instance|kms_crypto_key)|azurerm_\w*(database|sql|storage_account|cosmosdb|managed_disk|key_vault|redis)\w*|kubernetes_(persistent_volume\w*|namespace\w*|stateful_set\w*)|helm_release)$/;
export const statefulType = t => STATEFUL.test(String(t));

/** Counts from `terraform show -json` of a saved plan. null when the JSON is not a plan (a state file shows too). */
export function countPlan(json) {
  let j;
  try { j = typeof json === "string" ? JSON.parse(json) : json; } catch { return null; }
  if (!j || typeof j !== "object" || typeof j.format_version !== "string" || !("planned_values" in j) || j.errored === true) return null;
  if (j.resource_changes !== undefined && !Array.isArray(j.resource_changes)) return null;
  const p = {create: 0, update: 0, delete: 0, replace: 0, stateful: [], destroyed: []};
  // code that runs at apply time whatever the counts say: provisioners (local-exec), a data source read
  // deferred to apply (external, http), actions. Such a plan is never passed on its counts alone.
  const runs = [];
  const walk = m => { for (const r of m?.resources ?? []) if (r?.provisioners?.length) runs.push(`provisioner in ${r.address}`);
    for (const c of Object.values(m?.module_calls ?? {})) walk(c?.module); };
  walk(j.configuration?.root_module);
  if (Array.isArray(j.action_invocations) && j.action_invocations.length) runs.push("action invocations");
  for (const rc of j.resource_changes ?? []) {
    if (rc?.mode === "data") { if (rc.change?.actions?.includes("read") && /^(external|http)$/.test(rc.type)) runs.push(`data read at apply: ${rc.address}`); continue; }
    const a = rc?.change?.actions;
    if (!Array.isArray(a)) return null;
    const k = a.join(",");
    const kind = k === "create" ? "create" : k === "update" ? "update" : k === "delete" ? "delete" : k === "delete,create" || k === "create,delete" ? "replace"
      : ["no-op", "read", "forget", ""].includes(k) ? null : "unknown";
    if (kind === "unknown") return null;   // an action this parser does not know is not read as harmless
    if (!kind) continue;
    p[kind]++;
    if (kind === "delete" || kind === "replace") {
      const addr = String(rc.address ?? `${rc.type}.${rc.name}`) + (rc.deposed ? ` (deposed ${rc.deposed})` : "");
      p.destroyed.push({address: addr, replace: kind === "replace", stateful: statefulType(rc.type)});
      if (statefulType(rc.type)) p.stateful.push(addr);
    }
  }
  if (runs.length) p.runs = runs;
  return p;
}

// A binary from PATH: absolute directories only, so a relative entry (., node_modules/.bin) cannot
// put a planted `terraform` in front of the real one.
export function which(name, path = process.env.PATH ?? "") {
  for (const d of path.split(":")) {
    if (!isAbsolute(d)) continue;
    const f = join(d, name);
    try { if (statSync(f).isFile()) { accessSync(f, constants.X_OK); return f; } } catch { /* next */ }
  }
  return null;
}
// What terraform show gets: enough to find its plugins and data dir, no cloud credentials or tokens.
const TF_KEEP = /^(PATH|HOME|TMPDIR|LANG|LC_\w+|USER|LOGNAME|TF_DATA_DIR|TF_PLUGIN_CACHE_DIR|TF_CLI_CONFIG_FILE)$/;
export const tfEnv = (env = process.env) => ({...Object.fromEntries(Object.entries(env).filter(([k]) => TF_KEEP.test(k))),
  CHECKPOINT_DISABLE: "1", TF_IN_AUTOMATION: "1", TF_INPUT: "0", NO_COLOR: "1"});

const run = (bin, args, cwd, env, ms) => {
  const r = spawnSync(bin, args, {cwd, env, timeout: Math.max(1, ms), killSignal: "SIGKILL", encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024});
  return {status: r.status, out: r.stdout ?? "", err: r.stderr ?? "", timedOut: r.error?.code === "ETIMEDOUT" || r.signal === "SIGKILL", error: r.error};
};
const sha = s => createHash("sha256").update(s).digest("hex").slice(0, 16);

// The files a saved plan was made from, in its working directory: newer than the plan, it is stale.
const PLAN_INPUTS = /(\.tf|\.tf\.json|\.tfvars|\.tfvars\.json)$|^\.terraform\.lock\.hcl$|^terraform\.tfstate$/;
function staleBy(dir, planMtime) {
  let names = [];
  try { names = readdirSync(dir); } catch { return null; }
  for (const n of names) if (PLAN_INPUTS.test(n)) try { if (statSync(join(dir, n)).mtimeMs > planMtime) return n; } catch { /* gone */ }
  return null;
}

/** Read one saved plan. {plan} or {why} (why the plan cannot be trusted). */
export function readPlan(dir, file, {deadline, env = process.env} = {}) {
  const path = resolve(dir, file);
  let st;
  try { st = lstatSync(path); } catch { return {why: `plan file ${file} not found`}; }
  if (!st.isFile()) return {why: `${file} is not a regular file`};
  if (st.size > 256 * 1024 * 1024) return {why: `${file} is too large`};
  // a saved plan is a zip archive; a state file or anything else is not a plan, whatever show prints for it
  const head = Buffer.alloc(4);
  try { const fd = openSync(path, "r"); readSync(fd, head, 0, 4, 0); closeSync(fd); } catch { return {why: `${file} is not readable`}; }
  if (head.toString("latin1") !== "PK\x03\x04") return {why: `${file} is not a saved plan`};
  // the physical directory, for production markers (a `current` symlink to envs/prod); a .. never passes (terraformApply)
  let real;
  try { real = realpathSync(path); } catch { return {why: `${file} is not readable`}; }
  const stale = staleBy(dir, st.mtimeMs);
  if (stale) return {why: `stale: ${stale} changed after ${file} was written`};
  const bin = which("terraform", env.PATH);
  if (!bin) return {why: "terraform not found on PATH"};
  const left = deadline - Date.now();
  if (left < 50) return {why: "out of time"};
  const r = run(bin, ["show", "-json", "-no-color", path], dir, tfEnv(env), left);
  if (r.timedOut) return {why: `terraform show timed out`};
  if (r.status !== 0) return {why: `terraform show failed (${(r.err.trim().split("\n").find(l => l.trim()) ?? `exit ${r.status}`).replace(/[^\x20-\x7e]/g, "").slice(0, 80)})`};
  const plan = countPlan(r.out);
  if (!plan) return {why: `${file} did not read as a complete plan`};
  const realDir = realpathSync(dir);
  return {plan: {...plan, digest: sha(r.out)}, realDir, realPlanDir: dirname(real)};
}

// ---------------------------------------------------------------------------------------------
// The command line. Leading words that only wrap a program, then the program's own arguments.
// `strict`: only wrappers that change nothing about what runs where (rtk, time, nohup, command,
// timeout N). An assignment (PATH=., TF_CLI_ARGS_apply=-destroy), env, sudo or nice can change the
// binary, its arguments or its directory: the command is still found, but it never passes on a plan.
const WRAP = /^(rtk|time|nohup|command)$/;
function program(words) {
  let i = 0, strict = true;
  while (i < words.length) {
    const v = words[i].value;
    if (WRAP.test(v) || (v === "proxy" && words[i - 1]?.value === "rtk")) { i++; continue; }
    if (/^[A-Za-z_]\w*=/.test(v) || v === "builtin" || v === "exec" || v === "nice") { strict = false; i++; continue; }
    if (v === "env") { strict = false; i++; while (i < words.length && (/^[A-Za-z_]\w*=/.test(words[i].value) || /^-/.test(words[i].value))) i += /^-[CSu]$/.test(words[i].value) ? 2 : 1; continue; }
    if (v === "sudo" || v === "doas") { strict = false; i++; while (i < words.length && /^-/.test(words[i].value)) i += /^-[ugCDhpRTUr]$/.test(words[i].value) ? 2 : 1; continue; }
    if (v === "timeout") {
      i++;
      if (!/^\d+(\.\d+)?[smhd]?$/.test(words[i]?.value ?? "")) strict = false;
      while (i < words.length && /^-/.test(words[i].value)) i += /^-[ks]$/.test(words[i].value) ? 2 : 1;
      i++; continue;
    }
    break;
  }
  const out = words.slice(i);
  out.strict = strict;
  return out;
}
// terraform [-chdir=DIR] apply [options] [PLAN]. Go's flag package: -x and --x, a value after = or as
// the next word for the options that take one. Returns {chdir, plan} or null when it is not an apply.
const TF_VALUE = new Set(["var", "var-file", "target", "replace", "lock-timeout", "parallelism", "state", "state-out", "backup"]);
// Only these options leave a saved plan apply exactly the plan; anything else (--destroy, -target,
// -state-out, -exclude, a future option) makes the command not pass on a plan.
const TF_PASS = /^--?(auto-approve|input=false|no-color|compact-warnings|json|lock-timeout=\d+[smh]?|parallelism=\d+)$/;
export function terraformApply(words) {
  if (!words.length || basename(words[0].value) !== "terraform") return null;
  // ./terraform, bin/../terraform: an agent's own program, not the terraform that read the plan
  let exact = words[0].value === "terraform";
  let i = 1, chdir = null;
  for (; i < words.length && words[i].value.startsWith("-"); i++) {
    const m = words[i].value.match(/^--?chdir=(.*)$/);
    if (m) chdir = m[1];
    else if (/^--?chdir$/.test(words[i].value)) return {unreadable: "-chdir needs -chdir=DIR"};
    else exact = false;
  }
  if (words[i]?.value !== "apply") return null;
  const positional = [];
  for (i++; i < words.length; i++) {
    const v = words[i].value;
    if (v === "--") { positional.push(...words.slice(i + 1).map(w => w.value)); break; }
    if (!v.startsWith("-") || v === "-") { positional.push(v); continue; }
    if (!TF_PASS.test(v)) exact = false;
    const name = v.replace(/^--?/, "").split("=")[0];
    if (!v.includes("=") && TF_VALUE.has(name)) i++;
  }
  if (positional.length > 1) return {chdir, unreadable: "more than one plan file"};
  // a .. is resolved here by the text and by Terraform through the symlinks on the way: no pass on it.
  // Nor on a word the shell expands first (a glob, a brace, ~, a leading = in zsh): Reflex read the literal file.
  if ([chdir, positional[0]].some(x => x != null && /(^|\/)\.\.(\/|$)/.test(x))) exact = false;
  if (words.slice(1).some(w => !/^[\w./@:+=,-]+$/.test(w.raw) || /^=/.test(w.raw) || /^--?chdir==/.test(w.raw))) exact = false;
  const home = x => x != null && /^~\//.test(x) ? join(homedir(), x.slice(2)) : x;   // read the file the shell will name
  return {chdir: home(chdir), plan: home(positional[0]) ?? null, exact};
}
// kubectl [globals] apply|delete|replace|patch ...; the verb is the first word that is one of them
// and not the value of a global option that takes one.
const KUBE_VALUE = new Set(["-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server", "--token", "--as", "--as-group", "--request-timeout", "--cache-dir", "--tls-server-name", "--certificate-authority", "--client-certificate", "--client-key"]);
export function kubectlChange(words) {
  if (!words.length || basename(words[0].value) !== "kubectl") return null;
  for (let i = 1; i < words.length; i++) {
    const v = words[i].value;
    if (KUBE_VALUE.has(v)) { i++; continue; }
    // before the verb only the flags known above: an unknown one may take the next word as its value
    if (v.startsWith("-")) { if (!/^--?[\w-]+=/.test(v) || !KUBE_VALUE.has(v.split("=")[0])) return null; continue; }
    if (!["apply", "delete", "replace", "patch"].includes(v)) return null;
    const args = words.map(w => w.value);
    // apply's subcommands (edit-last-applied, set-last-applied, view-last-applied) write or open an editor
    if (v === "apply" && args[i + 1] && !args[i + 1].startsWith("-")) return null;
    return {verb: v, at: i, args};
  }
  return null;
}
// Kinds whose delete takes data or everything inside with it.
const KUBE_FLAG = /^(namespaces?|ns|persistentvolumeclaims?|pvc|persistentvolumes?|pv|statefulsets?(\.apps)?|sts|customresourcedefinitions?(\.apiextensions\.k8s\.io)?|crds?)$/i;
const kubeFlagged = name => KUBE_FLAG.test(name.split("/")[0]) || /^(v1\.(Namespace|PersistentVolumeClaim|PersistentVolume)|apps\.v1\.StatefulSet|apiextensions\.k8s\.io\.v1\.CustomResourceDefinition)\./.test(name);

/** What `kubectl diff` output says: objects changed, and those a prune would delete (`+0,0`). */
export function countDiff(out) {
  const objects = [], lines = out.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\+\+\+ (\S+)/);
    if (!m) continue;
    const hunk = lines.slice(i + 1).find(l => l.startsWith("@@")) ?? "";
    objects.push({name: basename(m[1]), deleted: /^@@ -\d+(,\d+)? \+0,0 @@/.test(hunk)});
  }
  const deleted = objects.filter(o => o.deleted).map(o => o.name);
  return {changed: objects.length, deleted, flagged: deleted.filter(kubeFlagged)};
}

function kubeCheck(k, dir, s, deadline, env) {
  const a = k.args;
  // nothing that could make the dry run real or read what we cannot give it: a dry run already, --
  // (the rest is not flags), stdin, --raw (a URL request that ignores --dry-run), an editor
  if (a.some(x => /^--dry-run(=|$)|^--raw(=|$)|^--edit$|^--?$/.test(x)) || a.some((x, i) => (/^(-f|--filename)$/.test(x) && a[i + 1] === "-") || /^(-f-|--filename=-)$/.test(x))) return null;
  // not with a kubeconfig, server or token the command names (it could be the agent's: an exec
  // credential plugin runs code, a server of its own receives the user's credentials), nor its own -o
  // (cobra reads global flags anywhere, attached shorthand values too: -shttps://..., -oyaml)
  if (a.some(x => /^(--kubeconfig|--server|-s|--token|-o|--output|--username|--password)(=|$)|^-[os]\S/.test(x))) return null;
  if (String(env.KUBECONFIG ?? "").split(":").some(f => f && (!isAbsolute(f) || (dir + "/").startsWith(resolve(f, "..") + "/") || resolve(f).startsWith(dir + "/")))) return null;
  const bin = which("kubectl", env.PATH);
  if (!bin || deadline - Date.now() < 50) return null;
  const {KUBECTL_EXTERNAL_DIFF, ...kenv} = env;   // our own parser reads the default unified diff
  if (k.verb === "apply") {
    const r = run(bin, [...a.slice(1, k.at), "diff", ...a.slice(k.at + 1)], dir, kenv, deadline - Date.now());
    if (r.timedOut || ![0, 1].includes(r.status)) return null;   // >1: kubectl or diff failed
    const d = countDiff(r.out);
    return {kind: "kubectl", ...d, deleted: d.deleted.length, digest: sha(r.out)};
  }
  // right after the verb: a flag of the agent's left waiting for a value must not swallow --dry-run
  const r = run(bin, [...a.slice(1, k.at + 1), "--dry-run=server", "-o", "name", ...a.slice(k.at + 1)], dir, kenv, deadline - Date.now());
  if (r.timedOut || r.status !== 0) return null;
  const names = r.out.split("\n").map(l => l.trim()).filter(Boolean);
  const gone = k.verb === "delete" || (k.verb === "replace" && a.includes("--force")) ? names : [];
  return {kind: "kubectl", changed: names.length, deleted: gone.length, flagged: gone.filter(kubeFlagged), digest: sha(r.out)};
}

const list = (xs, n = 5) => xs.slice(0, n).join(", ") + (xs.length > n ? ", ..." : "");
const RANK = {pass: 0, ask: 1, deny: 2};
const FIX = "run `terraform plan -out=tfplan` and apply the plan file (terraform apply tfplan)";

/**
 * The plan gate for one command. null: no infra change it can speak to (the gate goes on as before).
 * Otherwise {outcome, id, rule, plan}: outcome ask or deny is a rule; "pass" means every part of the
 * command was a verified clean plan (allow-eligible); null outcome carries only the counts.
 * `prod(dir)`: whether the command, run in dir, is production (the gate's markers).
 */
export function planGate({command, cwd, settings: s, settingsAt = () => s, prod, pipelines, shellWords, env = process.env}) {
  if (!s?.enabled || !/\b(terraform|kubectl)\b/.test(command)) return null;
  const ps = pipelines(command);
  if (!ps) return null;   // an expansion, a heredoc or unbalanced quotes: the rules and the usual judge decide
  const deadline = Date.now() + s.timeout_ms, parts = [], prodAt = prod;
  let dir = cwd && isAbsolute(cwd) ? cwd : null, other = false, dotdot = false;
  // a cd is followed only across && ; and newlines: in a pipe or behind & it runs in a subshell, and
  // after || the next command runs only when it failed. ponytail: a || or & anywhere, even quoted, stops it.
  const cdOk = !/\|\||(?<![&>])&(?![&>])/.test(command);
  // TF_CLI_ARGS in the hook's environment reaches the apply too: nothing passes on a plan then
  const tfArgs = Object.keys(env).some(k => /^TF_CLI_ARGS/.test(k));
  for (const p of ps) {
    const segs = p.core.split(/(?<!\|)\|(?!\|)/);
    for (const seg of segs) {
      const words = shellWords(seg.replace(/^[\s({!]+|[\s)}]+$/g, "")) ?? [];
      const w = program(words);
      if (!w.length) continue;
      if (w[0].value === "cd") {
        const to = w[1]?.value;
        // CDPATH sends a relative cd elsewhere; a glob or brace names what the shell finds
        dir = !cdOk || segs.length > 1 || w.length > 2 || !to || to === "-" || /^~[^/]/.test(to) || !/^[\w./@:+,~-]+$/.test(w[1].raw) ||
          (env.CDPATH && !/^[/~.]/.test(to)) || !dir && !isAbsolute(to) && !to.startsWith("~") ? null
          : to.startsWith("~") ? join(homedir(), to.slice(1)) : resolve(dir ?? "/", to);
        if (/(^|\/)\.\.(\/|$)/.test(to ?? "")) dotdot = true;
        if (ps.length > 1 && /[()]/.test(p.core)) dir = null;   // a subshell's cd: not followed
        continue;
      }
      const tf = terraformApply(w), kube = !tf && s.kubectl_diff ? kubectlChange(w) : null;
      if (!tf && !kube) { other = true; continue; }
      const here = tf?.chdir != null ? (dir ? resolve(dir, tf.chdir) : null) : dir;
      parts.push({tf, kube, dir: here, prod: prod(here ?? cwd ?? ""), strict: w.strict && !!tf?.exact && !tfArgs && !dotdot && segs.length === 1});
    }
  }
  if (!parts.length) return null;
  const results = parts.map(({tf, kube, dir, prod, strict}) => {
    const sd = dir ? settingsAt(dir) : s;
    if (kube) {
      const k = dir ? kubeCheck(kube, dir, s, deadline, env) : null;
      if (!k) return null;
      if (k.flagged.length) return {outcome: sd.destroy, id: "kube-destroy", plan: k, rule: `kubectl ${kube.verb} deletes ${k.deleted}: ${list(k.flagged)} (namespace, volume, statefulset or CRD)`};
      if (k.deleted) return {outcome: "ask", id: "kube-delete", plan: k, rule: `kubectl ${kube.verb} deletes ${k.deleted} object${k.deleted === 1 ? "" : "s"} (server dry run)`};
      return {outcome: null, id: "kube-diff", plan: k, rule: `kubectl ${kube.verb} changes ${k.changed} object${k.changed === 1 ? "" : "s"} (server dry run)`};
    }
    const noPlan = prod && sd.require_plan_in_prod ? "deny" : "ask";
    if (tf.unreadable) return {outcome: noPlan, id: "plan-unreadable", rule: `no readable saved plan (${tf.unreadable}): ${FIX}`};
    if (!tf.plan) return {outcome: noPlan, id: "plan-missing", rule: `terraform apply without a saved plan: ${FIX}`};
    if (!dir) return {outcome: noPlan, id: "plan-unreadable", rule: `no readable saved plan (the directory it runs in is unknown): ${FIX}`};
    const r = readPlan(dir, tf.plan, {deadline, env});
    if (!r.plan) return {outcome: noPlan, id: "plan-unreadable", rule: `no readable saved plan (${r.why}): ${FIX}`};
    const p = r.plan, counts = `${p.create} create, ${p.update} update, ${p.delete} delete, ${p.replace} replace`;
    const plan = {kind: "terraform", create: p.create, update: p.update, delete: p.delete, replace: p.replace, stateful: p.stateful, digest: p.digest};
    if (p.delete + p.replace) {
      const addrs = [...p.destroyed.filter(d => d.stateful), ...p.destroyed.filter(d => !d.stateful)].map(d => d.address);
      return {outcome: sd.destroy, id: "plan-destroy", plan, rule: `plan destroys ${addrs.length}: ${list(addrs)}${p.replace ? ` (${p.replace} replace)` : ""}` +
        (p.stateful.length ? `; stateful: ${list(p.stateful)}` : "")};
    }
    // production also by the physical directory (a `current` symlink to envs/prod)
    if (prod || (r.realDir !== dir && prodAt(r.realDir)) || (r.realPlanDir !== r.realDir && prodAt(r.realPlanDir))) return {outcome: "ask", id: "plan-prod", plan, rule: `production apply of a verified saved plan (${counts})`};
    if (p.runs) return {outcome: null, id: "plan-runs-code", plan, rule: `verified saved plan (${counts}) that runs code at apply: ${list(p.runs, 3)}`};
    if (!strict) return {outcome: null, id: "plan-clean", plan, rule: `verified saved plan: ${counts} (not passed: the command changes what runs, how or where)`};
    return {outcome: "pass", id: "plan-clean", plan, rule: `verified saved plan: ${counts}`};
  });
  // a kubectl check that could not run: that part is judged as before, and nothing passes on it
  const known = results.filter(Boolean);
  if (!known.length) return null;
  const worst = known.reduce((a, b) => (RANK[b.outcome] ?? -1) > (RANK[a.outcome] ?? -1) ? b : a);
  const plans = known.map(r => r.plan).filter(Boolean);
  const plan = plans.length === 1 ? plans[0] : plans.length ? {kind: "several", parts: plans, digest: sha(plans.map(x => x.digest).join())} : null;
  // pass only when every part of the command is a clean, verified plan (or a cd)
  if (worst.outcome === "pass" && (other || known.length < results.length || known.some(r => r.outcome !== "pass")))
    return {...worst, outcome: null, rule: known.map(r => r.rule).join("; ")};
  return {...worst, plan, rule: known.length > 1 ? known.map(r => r.rule).join("; ") : worst.rule};
}

// ---------------------------------------------------------------------------------------------
// node infra.mjs --selfcheck: fixture plans (setup/tool-gate/plans), a fake terraform and a fake
// kubectl on PATH that log every call. No real binary, cluster or cloud is touched.
async function selfcheck() {
  const {default: assert} = await import("node:assert/strict");
  const {chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync} = await import("node:fs");
  const {tmpdir} = await import("node:os");
  const {pipelines, shellWords} = await import("./gate.mjs");
  const here = fileURLToPath(new URL(".", import.meta.url)), fixture = n => readFileSync(join(here, "setup/tool-gate/plans", `${n}.json`), "utf8");
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "reflex-infra-"))), bin = join(tmp, "bin"), log = join(bin, "calls.log");
  mkdirSync(bin);
  // fake terraform: `show -json -no-color <plan>` prints the plan's JSON (after the zip marker line);
  // a plan naming SLEEP hangs, one naming FAIL fails. Every call and its environment are logged.
  writeFileSync(join(bin, "terraform"), `#!/bin/sh\necho "terraform $*" >> "${log}"\nenv | grep -E '^(AWS_|CHECKPOINT_DISABLE|TF_VAR_|GITHUB_TOKEN)' | sed 's/^/  env /' >> "${log}"\n` +
    `[ "$1" = show ] || exit 9\nf="$4"\ngrep -q SLEEP "$f" && sleep 5\ngrep -q FAIL "$f" && { echo "Error: Failed to load plugin schemas" >&2; exit 1; }\ntail -n +2 "$f"\n`);
  // fake kubectl: diff prints KUBE_DIFF_OUT and exits 1; --dry-run=server prints KUBE_NAMES; any other call exits 7
  writeFileSync(join(bin, "kubectl"), `#!/bin/sh\necho "kubectl $*" >> "${log}"\ncase " $* " in\n  *" diff "*) printf '%s' "$KUBE_DIFF_OUT"; exit \${KUBE_DIFF_EXIT:-1};;\n` +
    `  *" --dry-run=server "*) printf '%s' "$KUBE_NAMES"; exit 0;;\nesac\nexit 7\n`);
  chmodSync(join(bin, "terraform"), 0o755); chmodSync(join(bin, "kubectl"), 0o755);
  const env = {PATH: `relative/bin:${bin}:/usr/bin:/bin`, HOME: tmp, AWS_SECRET_ACCESS_KEY: "never-passed", TF_VAR_db_password: "never-passed", GITHUB_TOKEN: "never-passed"};
  const put = (dir, name, json, mtime) => {
    mkdirSync(dir, {recursive: true});
    writeFileSync(join(dir, name), `PK\x03\x04\n${json}`);
    if (mtime) utimesSync(join(dir, name), mtime, mtime);
  };
  const gate = (command, cwd, over = {}, prod = () => false, e = env) => planGate({command, cwd, settings: {...INFRA_DEFAULTS, ...over}, prod, pipelines, shellWords, env: e});
  try {
    // counting
    assert.deepEqual(countPlan(fixture("clean")), {create: 1, update: 1, delete: 0, replace: 0, stateful: [], destroyed: []}, "clean: no-op and data reads are not changes");
    assert.equal(countPlan(fixture("destroy")).delete, 1);
    assert.equal(countPlan(fixture("replace")).replace, 1);
    assert.deepEqual(countPlan(fixture("stateful")).stateful, ["aws_db_instance.main", "aws_s3_bucket.logs", "module.data.aws_dynamodb_table.events"]);
    assert.deepEqual(countPlan(fixture("empty")), {create: 0, update: 0, delete: 0, replace: 0, stateful: [], destroyed: []}, "an empty plan");
    assert.equal(countPlan('{"format_version":"1.0","values":{}}'), null, "a state file is not a plan");
    assert.equal(countPlan(JSON.stringify({...JSON.parse(fixture("clean")), errored: true})), null, "an errored plan is not read");
    assert.equal(countPlan(JSON.stringify({...JSON.parse(fixture("clean")), resource_changes: [{mode: "managed", type: "x", change: {actions: ["obliterate"]}}]})), null, "an unknown action is not harmless");
    assert.equal(countPlan("not json"), null);
    assert.ok(statefulType("aws_rds_cluster") && statefulType("azurerm_mssql_database") && statefulType("kubernetes_persistent_volume_claim_v1") &&
      !statefulType("aws_s3_bucket_policy") && !statefulType("aws_instance"), "stateful types");
    // parsing
    const tfa = c => terraformApply(shellWords(c));
    assert.deepEqual(tfa("terraform apply tfplan"), {chdir: null, plan: "tfplan", exact: true});
    assert.deepEqual(tfa("terraform -chdir=envs/dev apply -auto-approve -lock-timeout=30s -input=false tfplan"), {chdir: "envs/dev", plan: "tfplan", exact: true});
    assert.deepEqual(tfa("terraform apply -auto-approve -var env=dev -var-file dev.tfvars"), {chdir: null, plan: null, exact: false});
    for (const c of ["./terraform apply tfplan", "bin/../terraform apply tfplan", "terraform apply --destroy tfplan", "terraform apply -target=x tfplan",
                     "terraform apply -state-out=x tfplan", "terraform apply -exclude tfplan", "terraform -version apply tfplan"])
      assert.equal(tfa(c).exact, false, `not exact: ${c}`);
    assert.equal(tfa("terraform apply a b").unreadable, "more than one plan file");
    assert.equal(tfa("terraform plan -out=tfplan"), null);
    assert.equal(tfa("terraform show tfplan"), null);
    assert.equal(kubectlChange(shellWords("kubectl -n web --context dev apply -f k8s/")).verb, "apply");
    assert.equal(kubectlChange(shellWords("kubectl get pods")), null);
    assert.equal(kubectlChange(shellWords("kubectl apply edit-last-applied deploy/x")), null, "apply's editor subcommands are not read");

    // terraform, end to end with the fake binary
    const w = join(tmp, "w");
    put(w, "clean.plan", fixture("clean"));
    let g = gate("terraform apply clean.plan", w);
    assert.equal(g.outcome, "pass", JSON.stringify(g));
    assert.match(g.rule, /verified saved plan: 1 create, 1 update, 0 delete, 0 replace/);
    assert.deepEqual([g.plan.create, g.plan.update, g.plan.delete, g.plan.replace, g.plan.kind], [1, 1, 0, 0, "terraform"]);
    assert.equal(gate("cd w && terraform apply clean.plan", tmp).outcome, "pass", "a cd before the apply is followed");
    assert.equal(gate("rtk proxy timeout 60 terraform apply -auto-approve clean.plan", w).outcome, "pass", "wrappers");
    assert.equal(gate("sudo -u deploy env TF_LOG=info terraform apply", w).id, "plan-missing", "sudo and env wrappers");
    // review round 1: nothing passes unless what runs is exactly the plan that was read
    put(w, "tfplan", fixture("destroy"));
    put(join(w, "sub"), "tfplan", fixture("clean"));
    for (const c of ["cd sub | terraform apply tfplan", "cd sub & terraform apply tfplan", "cd sub || terraform apply tfplan"])
      assert.notEqual(gate(c, w).outcome, "pass", `a cd that does not carry over: ${c}`);
    assert.equal(gate("cd sub && terraform apply tfplan", w).outcome, "pass", "a cd across && is followed");
    assert.equal(gate("cd sub; terraform apply tfplan", w).outcome, "pass", "and across ;");
    assert.equal(gate("cd ~bob && terraform apply tfplan", w).id, "plan-unreadable", "~name is another user's home");
    for (const c of ["./terraform apply clean.plan", "PATH=. terraform apply clean.plan", "TF_CLI_ARGS_apply='-destroy' terraform apply clean.plan",
                     "env --chdir=/ terraform apply clean.plan", "env -i terraform apply clean.plan", "sudo terraform apply clean.plan", "nice terraform apply clean.plan",
                     "terraform apply --destroy clean.plan", "terraform apply -target=x clean.plan", "terraform apply -state-out=x clean.plan", "timeout --foo 5 terraform apply clean.plan"]) {
      const r = gate(c, w);
      assert.ok(r && r.outcome !== "pass" && r.plan?.create === 1, `no pass, the counts kept: ${c} ${JSON.stringify(r)}`);
    }
    assert.equal(gate("terraform apply clean.plan", w, {}, () => false, {...env, TF_CLI_ARGS_apply: "-destroy"}).outcome, null, "TF_CLI_ARGS in the hook's environment");
    // review round 2: words the shell expands before terraform sees them
    put(w, "[t]fplan", fixture("clean"));
    for (const c of ["terraform apply [t]fplan", "terraform apply {clean,x}.plan", "terraform apply ~/w/clean.plan", "terraform apply =clean.plan", "cd [s]ub && terraform apply tfplan"])
      assert.notEqual(gate(c, w)?.outcome, "pass", `an expanded word: ${c}`);
    assert.equal(gate("cd sub && terraform apply tfplan", w, {}, () => false, {...env, CDPATH: "/elsewhere"}).id, "plan-unreadable", "CDPATH in the hook's environment");
    // symlinks: the physical path is what Terraform opens; production by the physical directory
    symlinkSync(join(w, "sub"), join(w, "lnk"));
    mkdirSync(join(w, "far/deep"), {recursive: true}); put(join(w, "far"), "clean.plan", fixture("destroy")); symlinkSync(join(w, "far/deep"), join(w, "lnk2"));
    assert.equal(gate("terraform apply lnk2/../clean.plan", w).outcome, null, "a .. through a symlink: Terraform opens far/clean.plan, no pass");
    assert.equal(gate("terraform -chdir=lnk2/.. apply clean.plan", w).outcome, null, "-chdir with ..");
    assert.equal(gate("cd lnk2/.. && terraform apply clean.plan", w).outcome, null, "cd with ..");
    assert.equal(gate("cd lnk && terraform apply tfplan", w).outcome, "pass", "a symlinked directory without ..: the same file either way");
    assert.equal(gate("cd lnk && terraform apply tfplan", w, {}, d => d.endsWith("/sub")).outcome, "ask", "production by the physical directory");
    // code that runs at apply: provisioners, deferred external reads, actions
    const withRuns = extra => JSON.stringify({...JSON.parse(fixture("clean")), ...extra});
    put(w, "prov.plan", withRuns({configuration: {root_module: {module_calls: {m: {module: {resources: [{address: "null_resource.x", provisioners: [{type: "local-exec"}]}]}}}}}}));
    assert.equal(gate("terraform apply prov.plan", w).id, "plan-runs-code", "a provisioner in a module");
    put(w, "ext.plan", withRuns({resource_changes: [{address: "data.external.x", mode: "data", type: "external", name: "x", change: {actions: ["read"]}}]}));
    assert.equal(gate("terraform apply ext.plan", w).outcome, null, "a data external read at apply");
    put(w, "act.plan", withRuns({action_invocations: [{address: "action.x"}]}));
    assert.equal(gate("terraform apply act.plan", w).outcome, null, "actions");
    g = gate("terraform apply clean.plan && rm -rf build", w);
    assert.ok(g.outcome === null && g.plan.create === 1, "anything else in the command: the counts only, no pass");
    assert.equal(gate("terraform apply clean.plan | tee out.log", w).outcome, null);
    assert.equal(gate("terraform apply clean.plan", w, {}, () => true).outcome, "ask", "production: a clean plan still asks");
    assert.match(gate("terraform apply clean.plan", w, {}, () => true).rule, /production apply of a verified saved plan \(1 create/);
    put(w, "empty.plan", fixture("empty"));
    assert.equal(gate("terraform apply empty.plan", w).outcome, "pass", "an empty plan");
    put(w, "destroy.plan", fixture("destroy"));
    g = gate("terraform apply destroy.plan", w);
    assert.ok(g.outcome === "deny" && g.id === "plan-destroy" && g.rule === "plan destroys 1: aws_instance.old", JSON.stringify(g));
    assert.equal(gate("terraform apply destroy.plan", w, {destroy: "ask"}).outcome, "ask", "infra.destroy: ask");
    put(w, "replace.plan", fixture("replace"));
    assert.equal(gate("terraform apply replace.plan", w).rule, "plan destroys 1: aws_launch_template.web (1 replace)");
    put(w, "stateful.plan", fixture("stateful"));
    assert.equal(gate("terraform apply stateful.plan", w).rule,
      "plan destroys 4: aws_db_instance.main, aws_s3_bucket.logs, module.data.aws_dynamodb_table.events, aws_iam_role.ci (1 replace); stateful: aws_db_instance.main, aws_s3_bucket.logs, module.data.aws_dynamodb_table.events");
    assert.equal(gate("terraform apply stateful.plan", w).plan.stateful.length, 3);
    assert.equal(gate("terraform apply clean.plan && terraform -chdir=. apply destroy.plan", w).outcome, "deny", "two applies: the worse one");
    // -chdir: the plan path is relative to that directory
    put(join(tmp, "envs/dev"), "tfplan", fixture("destroy"));
    assert.equal(gate("terraform -chdir=envs/dev apply tfplan", tmp).id, "plan-destroy", "-chdir");
    assert.equal(gate("terraform -chdir=envs/dev apply tfplan", tmp, {}, d => d.endsWith("/envs/dev")).outcome, "deny");
    // no plan, unreadable plans: ask, with the fix
    g = gate("terraform apply -auto-approve", w);
    assert.ok(g.outcome === "ask" && g.id === "plan-missing" && /terraform plan -out=tfplan/.test(g.rule), JSON.stringify(g));
    assert.equal(gate("terraform apply", w, {require_plan_in_prod: true}, () => true).outcome, "deny", "a saved plan required in production");
    assert.equal(gate("terraform apply", w, {require_plan_in_prod: true}).outcome, "ask", "outside production it only asks");
    assert.match(gate("terraform apply nope.plan", w).rule, /^no readable saved plan \(plan file nope.plan not found\)/);
    const old = Date.now() / 1000 - 60;
    writeFileSync(join(w, "terraform.tfstate"), '{"format_version":"1.0","values":{}}');
    utimesSync(join(w, "terraform.tfstate"), old, old);
    assert.match(gate("terraform apply terraform.tfstate", w).rule, /not a saved plan/, "a state file shows as JSON too: not a plan");
    put(w, "fail.plan", `FAIL ${fixture("clean")}`);
    assert.match(gate("terraform apply fail.plan", w).rule, /terraform show failed \(Error: Failed to load plugin schemas\)/);
    put(w, "sleep.plan", `SLEEP ${fixture("clean")}`);
    const t = Date.now();
    g = gate("terraform apply sleep.plan", w, {timeout_ms: 300});
    assert.ok(g.outcome === "ask" && /timed out/.test(g.rule) && Date.now() - t < 2500, `a hung show fails closed, in time: ${JSON.stringify(g)} ${Date.now() - t} ms`);
    // stale: a .tf file (or the state, or the lock file) newer than the plan
    const st = join(tmp, "stale");
    put(st, "tfplan", fixture("clean"), old);
    writeFileSync(join(st, "main.tf"), "");
    assert.match(gate("terraform apply tfplan", st).rule, /stale: main.tf changed after tfplan was written/);
    utimesSync(join(st, "main.tf"), old - 60, old - 60);
    assert.equal(gate("terraform apply tfplan", st).outcome, "pass", "older inputs: fresh");
    writeFileSync(join(st, ".terraform.lock.hcl"), "");
    assert.match(gate("terraform apply tfplan", st).rule, /stale: .terraform.lock.hcl/);
    // unknown directory, hidden text, no binary
    assert.equal(gate("terraform apply tfplan", undefined).id, "plan-unreadable");
    assert.equal(gate("cd $DIR && terraform apply tfplan", w), null, "an expansion: the usual judge decides");
    assert.match(gate("terraform apply clean.plan", w, {}, () => false, {...env, PATH: "/usr/bin:/bin"}).rule, /terraform not found on PATH/);
    assert.equal(gate("terraform apply clean.plan", w, {enabled: false}), null, "infra.enabled false: as before");
    assert.equal(gate("terraform plan -out=tfplan", w), null);
    // what the hook ran: only terraform show, without the credentials
    const calls = readFileSync(log, "utf8");
    assert.ok(calls.split("\n").filter(l => l.startsWith("terraform ")).every(l => /^terraform show -json -no-color \//.test(l)), `only show: ${calls}`);
    assert.ok(!/never-passed|AWS_SECRET|TF_VAR_|GITHUB_TOKEN/.test(calls) && /CHECKPOINT_DISABLE=1/.test(calls), "sanitized env");
    assert.ok(which("terraform", env.PATH) === join(bin, "terraform") && which("terraform", "relative/bin") === null, "absolute PATH entries only");

    // kubectl: off by default
    rmSync(log);
    assert.equal(gate("kubectl delete ns payments", w), null, "kubectl_diff off: nothing runs");
    assert.ok(!existsSync(log));
    const k = {kubectl_diff: true}, kenv = extra => ({...env, ...extra});
    g = gate("kubectl --context dev delete ns payments", w, k, () => false, kenv({KUBE_NAMES: "namespace/payments\n"}));
    assert.ok(g.outcome === "deny" && g.id === "kube-destroy" && /namespace\/payments/.test(g.rule), JSON.stringify(g));
    g = gate("kubectl delete pod web-1 web-2", w, k, () => false, kenv({KUBE_NAMES: "pod/web-1\npod/web-2\n"}));
    assert.ok(g.outcome === "ask" && g.plan.deleted === 2 && g.rule === "kubectl delete deletes 2 objects (server dry run)", JSON.stringify(g));
    const diff = "diff -u -N /tmp/LIVE-1/apps.v1.Deployment.web.api /tmp/MERGED-1/apps.v1.Deployment.web.api\n--- /tmp/LIVE-1/apps.v1.Deployment.web.api\n+++ /tmp/MERGED-1/apps.v1.Deployment.web.api\n@@ -5,7 +5,7 @@\n-  replicas: 2\n+  replicas: 3\n" +
      "diff -u -N /tmp/LIVE-1/apps.v1.StatefulSet.web.db /tmp/MERGED-1/apps.v1.StatefulSet.web.db\n--- /tmp/LIVE-1/apps.v1.StatefulSet.web.db\n+++ /tmp/MERGED-1/apps.v1.StatefulSet.web.db\n@@ -1,40 +0,0 @@\n-apiVersion: apps/v1\n";
    assert.deepEqual(countDiff(diff), {changed: 2, deleted: ["apps.v1.StatefulSet.web.db"], flagged: ["apps.v1.StatefulSet.web.db"]});
    g = gate("kubectl apply -f k8s/ --prune -l app=web", w, k, () => false, kenv({KUBE_DIFF_OUT: diff}));
    assert.ok(g.outcome === "deny" && /StatefulSet/.test(g.rule), JSON.stringify(g));
    g = gate("kubectl apply -f k8s/", w, k, () => false, kenv({KUBE_DIFF_OUT: diff.split("diff -u -N /tmp/LIVE-1/apps.v1.StatefulSet")[0]}));
    assert.ok(g.outcome === null && g.plan.changed === 1 && g.plan.deleted === 0, JSON.stringify(g));
    assert.equal(gate("kubectl apply -f k8s/", w, k, () => false, kenv({KUBE_DIFF_EXIT: "2"})), null, "diff failed: as before");
    assert.equal(gate("kubectl delete pod x --dry-run=none", w, k), null, "a --dry-run of its own: not run");
    assert.equal(gate("kubectl apply -f -", w, k), null, "stdin: not run");
    assert.equal(gate("kubectl delete --raw /api/v1/namespaces/x", w, k), null, "--raw: not run");
    const kcalls = readFileSync(log, "utf8").trim().split("\n");
    assert.ok(kcalls.every(l => (/ diff( |$)/.test(l) && !/ apply( |$)/.test(l)) || / (delete|replace|patch) --dry-run=server -o name( |$)/.test(l)), `only diff or a server dry run: ${kcalls.join(" | ")}`);
    assert.ok(kcalls.includes("kubectl --context dev delete --dry-run=server -o name ns payments"), kcalls.join(" | "));
    // review round 1: an agent flag waiting for a value cannot swallow --dry-run; no agent kubeconfig, server, token or -o
    gate("kubectl delete pod web-1 --field-manager", w, k, () => false, kenv({KUBE_NAMES: "pod/web-1\n"}));
    assert.equal(readFileSync(log, "utf8").trim().split("\n").at(-1), "kubectl delete --dry-run=server -o name pod web-1 --field-manager");
    for (const c of ["kubectl --kubeconfig ./kc delete pod x", "kubectl --server https://evil.example delete pod x", "kubectl delete pod x -o yaml",
                     "kubectl delete pod x --output=json", "kubectl --token=t delete pod x", "kubectl -shttps://evil.example delete pod x",
                     "kubectl delete pod x -shttps://evil.example", "kubectl --as-uid patch create -f x", "kubectl -v 9 delete pod x"])
      assert.equal(gate(c, w, k, () => false, kenv({KUBE_NAMES: "pod/x\n"})), null, `not run: ${c}`);
    assert.equal(gate("kubectl delete pod x", w, k, () => false, kenv({KUBE_NAMES: "pod/x\n", KUBECONFIG: join(w, "kc")})), null, "a KUBECONFIG inside the working directory");

    // settings
    assert.equal(infraError({destroy: "allow"}), 'infra.destroy must be "deny" or "ask"');
    assert.equal(infraError({timeout_ms: 6000}), "infra.timeout_ms must be 100 to 4000");
    assert.match(infraError({kubectl: true}), /unknown key/);
    assert.equal(infraError({destroy: "ask", kubectl_diff: true}), null);
    assert.equal(infraSettings({destroy: "ask"}, {destroy: "deny"}).destroy, "deny", "a team can force deny");
    assert.equal(infraSettings({enabled: false}, {require_plan_in_prod: true}).enabled, true, "a team's infra section turns the gate on");
    assert.equal(infraSettings({require_plan_in_prod: true}, null).require_plan_in_prod, true);
    console.log("infra selfcheck ok");
  } finally { rmSync(tmp, {recursive: true, force: true}); }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]) && process.argv.includes("--selfcheck"))
  selfcheck().catch(e => { console.error(e); process.exit(1); });   // not awaited: gate.mjs imports this module
