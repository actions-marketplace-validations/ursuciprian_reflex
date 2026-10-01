#!/usr/bin/env node
// Plan-aware infra gate: judge `terraform apply` and `kubectl apply|delete|replace|patch` by what they
// will change, not only by the command text. gate.mjs calls planGate() after the rules.
//
// terraform: the hook never runs `terraform plan` or `terraform apply`. Plan executes providers with
// the user's credentials, runs `data "external"` programs and is slow. With infra.terraform_show on
// (off by default), the hook reads a saved plan the agent produced, with `terraform show -json
// <planfile>`: local, no provider API calls, but it starts the provider binaries to read their
// schemas, so it runs only when those are symlinks into a plugin cache outside the working tree
// (providersSafe). A strict timeout, a sanitized environment without cloud credentials,
// CHECKPOINT_DISABLE so Terraform does not call HashiCorp's version service. Off: no plan is read,
// an apply with a plan file is judged as before, and one without still asks with the fix.
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
import {accessSync, constants, lstatSync, openSync, readFileSync, readSync, closeSync, readdirSync, realpathSync, statSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {homedir} from "node:os";
import {basename, dirname, isAbsolute, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {isMain} from "./failsafe.mjs";

// terraform_show is off by default: `terraform show` starts the provider binaries in .terraform, and an
// agent's file tools can write those (and the lock file) without passing the gate. On, it runs only when
// every provider it would load is a symlink into a plugin cache outside the working tree (providersSafe).
// helm_diff is off by default too: `helm diff` runs a helm plugin, and it calls the API server.
export const INFRA_DEFAULTS = {enabled: true, destroy: "deny", require_plan_in_prod: false, terraform_show: false, kubectl_diff: false, helm_diff: false, timeout_ms: 3000};
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
  for (const k of ["enabled", "require_plan_in_prod", "terraform_show", "kubectl_diff", "helm_diff"]) if (saved[k] !== undefined && typeof saved[k] !== "boolean") return `infra.${k} must be true or false`;
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
// XDG_CONFIG_HOME and XDG_DATA_HOME: OpenTofu finds its tofurc there, and providersSafe checked that one.
const TF_KEEP = /^(PATH|HOME|TMPDIR|LANG|LC_\w+|USER|LOGNAME|TF_DATA_DIR|TF_PLUGIN_CACHE_DIR|TF_CLI_CONFIG_FILE|XDG_CONFIG_HOME|XDG_DATA_HOME)$/;
export const tfEnv = (env = process.env) => ({...Object.fromEntries(Object.entries(env).filter(([k]) => TF_KEEP.test(k))),
  CHECKPOINT_DISABLE: "1", TF_IN_AUTOMATION: "1", TF_INPUT: "0", NO_COLOR: "1"});

// ponytail: the timeout SIGKILLs the child only; a grandchild (helm-diff under helm) can keep running
// after the hook has asked. Upgrade path: an async spawn in its own process group, killed with -pid.
const run = (bin, args, cwd, env, ms) => {
  const r = spawnSync(bin, args, {cwd, env, timeout: Math.max(1, ms), killSignal: "SIGKILL", encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024});
  return {status: r.status, out: r.stdout ?? "", err: r.stderr ?? "", timedOut: r.error?.code === "ETIMEDOUT" || r.signal === "SIGKILL", error: r.error};
};
const sha = s => createHash("sha256").update(s).digest("hex").slice(0, 16);

// The files a saved plan was made from, in its working directory: newer than the plan, it is stale.
const PLAN_INPUTS = /(\.tf|\.tf\.json|\.tofu|\.tofu\.json|\.tfvars|\.tfvars\.json)$|^\.terraform\.lock\.hcl$|^terraform\.tfstate$/;
function staleBy(dir, planMtime) {
  let names = [];
  try { names = readdirSync(dir); } catch { return null; }
  for (const n of names) if (PLAN_INPUTS.test(n)) try { if (statSync(join(dir, n)).mtimeMs > planMtime) return n; } catch { /* gone */ }
  return null;
}

// The provider binaries `terraform show` would start, as far as the working directory decides them:
// every entry under <data dir>/providers must be a symlink whose real path is inside the plugin cache
// (TF_PLUGIN_CACHE_DIR, plugin_cache_dir in the CLI config, or ~/.terraform.d/plugin-cache), under the
// home directory and outside both the directory the command runs in and the one it started in, and no
// file there may be newer than the plan. A regular file or directory of binaries in .terraform, a
// terraform.d in the working directory, dev_overrides or a reattach variable: not run. null when safe,
// else the reason. ponytail: the cache is trusted as the user's own, and an agent that can write the
// home directory outside the gate can also write the cache; the check keeps the working tree (and the
// repository around it) out. It is a check before the spawn: a process the agent left running could
// swap a link in between, the same window as for the plan file.
const insideOf = (p, root) => p === root || p.startsWith(root.endsWith("/") ? root : root + "/");
const realOr = p => { try { return realpathSync(p); } catch { return null; } };
// the tree: where the command runs and started, and the repository roots around them (an agent in
// infra/ can write the whole repository)
function treeOf(dir, cwd, home) {
  const tree = [dir, cwd].filter(Boolean).map(realOr).filter(Boolean);
  for (const t of [...tree]) for (let d = t; d !== dirname(d); d = dirname(d)) if (realOr(join(d, ".git")) && d !== home) { tree.push(d); break; }
  return tree;
}
export function providersSafe(dir, cwd, planMtime, env = process.env) {
  const home = realOr(env.HOME || homedir());
  if (!home) return "no home directory";
  const tree = treeOf(dir, cwd, home);
  if (Object.keys(env).some(k => /^TF_REATTACH_PROVIDERS$/.test(k))) return "TF_REATTACH_PROVIDERS is set";
  // the CLI config Terraform or OpenTofu loads: TF_CLI_CONFIG_FILE (absolute, outside the tree), else
  // Terraform's ~/.terraformrc and ~/.terraform.d/*.tfrc(.json), and OpenTofu's ~/.tofurc and
  // $XDG_CONFIG_HOME/opentofu/tofurc (and *.tfrc there). Both tools are checked against all of them.
  const cfg = env.TF_CLI_CONFIG_FILE;
  if (cfg && (!isAbsolute(cfg) || tree.some(t => insideOf(realOr(cfg) ?? cfg, t)))) return "TF_CLI_CONFIG_FILE is relative or inside the working tree";
  if ([env.XDG_CONFIG_HOME, env.XDG_DATA_HOME].some(v => v && !isAbsolute(v))) return "a relative XDG_CONFIG_HOME or XDG_DATA_HOME";
  const xdg = env.XDG_CONFIG_HOME || join(home, ".config");
  const rcs = d => { try { return readdirSync(d).filter(n => /\.tfrc(\.json)?$/.test(n)).map(n => join(d, n)); } catch { return []; } };
  let cli = "";
  for (const f of cfg ? [cfg] : [join(home, ".terraformrc"), join(home, ".tofurc"), join(xdg, "opentofu/tofurc"), ...rcs(join(home, ".terraform.d")), ...rcs(join(xdg, "opentofu"))]) try { cli += readFileSync(f, "utf8").slice(0, 256 * 1024) + "\n"; } catch { /* none */ }
  if (/\bdev_overrides\b/.test(cli)) return "dev_overrides in the Terraform CLI config";
  // a relative plugin_cache_dir (../cache) could name the repository: not a cache then
  const configured = cli.match(/^\s*plugin_cache_dir\s*=\s*"([^"]+)"/m)?.[1]?.replace(/^(\$HOME|\$\{HOME\}|~)(?=\/|$)/, home);
  if (configured && !isAbsolute(configured)) return "a relative plugin_cache_dir";
  if (env.TF_PLUGIN_CACHE_DIR && !isAbsolute(env.TF_PLUGIN_CACHE_DIR)) return "a relative TF_PLUGIN_CACHE_DIR";
  const caches = [env.TF_PLUGIN_CACHE_DIR, configured, join(home, ".terraform.d/plugin-cache")].filter(Boolean).map(c => realOr(resolve(dir, c))).filter(Boolean)
    .filter(c => insideOf(c, home) && c !== home && !tree.some(t => insideOf(c, t) || insideOf(t, c)));
  if (!caches.length) return "no plugin cache outside the working tree";
  if (tree.some(t => insideOf(home, t))) return "the working tree holds the home directory";
  if (realOr(join(dir, "terraform.d"))) return "a terraform.d directory in the working tree";
  const root = resolve(dir, env.TF_DATA_DIR || ".terraform", "providers");
  let seen = 0;
  const newer = (p, depth = 0) => {   // a file in the cache newer than the plan
    let st; try { st = statSync(p); } catch { return "unreadable"; }
    if (st.isFile()) return st.mtimeMs > planMtime ? p : null;
    if (!st.isDirectory()) return null;
    if (depth > 8) return "a cache nested too deep to check";
    let names; try { names = readdirSync(p); } catch { return "unreadable"; }
    for (const n of names) { if (++seen > 500) return "too many files"; const r = newer(join(p, n), depth + 1); if (r) return r; }
    return null;
  };
  const walk = (p, depth) => {
    let st; try { st = lstatSync(p); } catch { return depth === 0 ? null : "unreadable provider entry"; }
    if (st.isSymbolicLink()) {
      const real = realOr(p);
      if (!real) return `a broken provider link (${basename(p)})`;
      if (!caches.some(c => insideOf(real, c)) || tree.some(t => insideOf(real, t))) return `a provider outside the plugin cache (${basename(p)})`;
      const n = newer(real);
      return n ? `a provider in the cache is newer than the plan (${basename(n)})` : null;
    }
    if (st.isFile()) return `a provider binary inside the working tree (${basename(p)})`;
    if (!st.isDirectory()) return `an unexpected provider entry (${basename(p)})`;
    if (depth > 6) return "providers nested too deep";
    let names; try { names = readdirSync(p); } catch { return "unreadable provider directory"; }
    for (const n of names) { if (++seen > 500) return "too many provider entries"; const r = walk(join(p, n), depth + 1); if (r) return r; }
    return null;
  };
  return walk(root, 0);
}

function encryptionIn(dir) {
  let names = [];
  try { names = readdirSync(dir); } catch { return "the directory is unreadable"; }
  for (const n of names.filter(n => /\.(tf|tofu)(\.json)?$/.test(n))) {
    let t;
    try { if (statSync(join(dir, n)).size > 4 * 1024 * 1024) return `${n} is too large to check`; t = readFileSync(join(dir, n), "utf8"); } catch { return `${n} is unreadable`; }
    if (/\b(encryption|key_provider)\b/.test(t)) return `encryption or a key provider in ${n}`;
  }
  return null;
}
/** Read one saved plan. {plan} or {why} (why the plan cannot be trusted). */
export function readPlan(dir, file, {deadline, env = process.env, cwd = dir, tool = "terraform"} = {}) {
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
  const bin = which(tool, env.PATH);
  if (!bin) return {why: `${tool} not found on PATH`};
  // OpenTofu reads state and plan encryption from the root module in the directory, which the agent can
  // write, and a key provider can run a program (external): not run when any config file mentions it
  if (tool === "tofu") { const e = encryptionIn(dir); if (e) return {why: `tofu show not run: ${e}`}; }
  let unsafe;
  try { unsafe = providersSafe(dir, cwd, st.mtimeMs, env); } catch (e) { unsafe = `could not check the providers (${e.code ?? e.message})`; }
  if (unsafe) return {why: `${tool} show not run: ${unsafe}`};
  const left = deadline - Date.now();
  if (left < 50) return {why: "out of time"};
  const r = run(bin, ["show", "-json", "-no-color", path], dir, tfEnv(env), left);
  if (r.timedOut) return {why: `${tool} show timed out`};
  if (r.status !== 0) return {why: `${tool} show failed (${(r.err.trim().split("\n").find(l => l.trim()) ?? `exit ${r.status}`).replace(/[^\x20-\x7e]/g, "").slice(0, 80)})`};
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
// terraform|tofu [-chdir=DIR] apply [options] [PLAN]. Go's flag package: -x and --x, a value after = or as
// the next word for the options that take one. Returns {chdir, plan} or null when it is not an apply.
const TF_VALUE = new Set(["var", "var-file", "target", "replace", "lock-timeout", "parallelism", "state", "state-out", "backup"]);
// Only these options leave a saved plan apply exactly the plan; anything else (--destroy, -target,
// -state-out, -exclude, a future option) makes the command not pass on a plan.
const TF_PASS = /^--?(auto-approve|input=false|no-color|compact-warnings|json|lock-timeout=\d+[smh]?|parallelism=\d+)$/;
export function terraformApply(words) {
  const tool = words.length ? basename(words[0].value) : null;
  if (tool !== "terraform" && tool !== "tofu") return null;
  // ./terraform, bin/../tofu: an agent's own program, not the one that read the plan
  let exact = words[0].value === tool;
  let i = 1, chdir = null;
  for (; i < words.length && words[i].value.startsWith("-"); i++) {
    const m = words[i].value.match(/^--?chdir=(.*)$/);
    if (m) chdir = m[1];
    else if (/^--?chdir$/.test(words[i].value)) return {tool, unreadable: "-chdir needs -chdir=DIR"};
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
  if (positional.length > 1) return {tool, chdir, unreadable: "more than one plan file"};
  // a .. is resolved here by the text and by Terraform through the symlinks on the way: no pass on it.
  // Nor on a word the shell expands first (a glob, a brace, ~, a leading = in zsh): Reflex read the literal file.
  if ([chdir, positional[0]].some(x => x != null && /(^|\/)\.\.(\/|$)/.test(x))) exact = false;
  if (words.slice(1).some(w => !/^[\w./@:+=,-]+$/.test(w.raw) || /^=/.test(w.raw) || /^--?chdir==/.test(w.raw))) exact = false;
  const home = x => x != null && /^~\//.test(x) ? join(homedir(), x.slice(2)) : x;   // read the file the shell will name
  return {tool, chdir: home(chdir), plan: home(positional[0]) ?? null, exact};
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
  if (kubeconfigNear([dir], env)) return null;
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

// A KUBECONFIG the agent could have written: relative, inside the directory the command runs in (or
// started in), or next to it. kubectl and helm are not run then (an exec credential plugin runs code).
const kubeconfigNear = (dirs, env) => String(env.KUBECONFIG ?? "").split(":").some(f => f && (!isAbsolute(f) ||
  dirs.filter(Boolean).some(dir => (dir + "/").startsWith(resolve(f, "..") + "/") || resolve(f).startsWith(dir + "/"))));

// terragrunt [flags] apply | run-all apply | run [--all] [--] apply | stack run apply | apply-all.
// The hook never reads a terragrunt plan: terragrunt runs the before_hook, after_hook and run_cmd of
// terragrunt.hcl, which the agent can write, and picks tofu or terraform (and the directory: a
// .terragrunt-cache copy when terraform.source is set) by itself. {all, plan} or null.
const TG_VALUE = new Set(["out-dir", "json-out-dir", "working-dir", "log-level", "tf-path", "config", "queue-exclude-dir", "queue-include-dir", "parallelism",
  "download-dir", "source", "iam-assume-role", "provider-cache-dir", "feature", "filter", "terragrunt-working-dir", "terragrunt-config", "terragrunt-tfpath",
  "terragrunt-log-level", "terragrunt-parallelism", "terragrunt-download-dir", "terragrunt-source", "terragrunt-iam-role", "terragrunt-exclude-dir", "terragrunt-include-dir"]);
export function terragruntApply(words) {
  if (!words.length || basename(words[0].value) !== "terragrunt") return null;
  const args = words.slice(1).map(w => w.value), at = args.findIndex(v => v === "apply" || v === "apply-all");
  if (at < 0) return null;
  let plan = args.some(v => /^--(terragrunt-)?out-dir(=|$)/.test(v));
  for (let i = at + 1; i < args.length; i++) {
    const v = args[i];
    if (v === "--") continue;
    if (!v.startsWith("-")) { plan = true; continue; }
    const name = v.replace(/^--?/, "").split("=")[0];
    if (!v.includes("=") && (TF_VALUE.has(name) || TG_VALUE.has(name))) i++;
  }
  return {all: args[at] === "apply-all" || args.slice(0, at).some(v => v === "run-all" || v === "--all" || v === "stack"), plan};
}

// helm [globals] upgrade|install ...: cobra flags anywhere, a value after = (or attached to a
// shorthand: -nweb) or as the next word for the flags that take one.
const HELM_VALUE = new Set(["-n", "--namespace", "--kube-context", "--kubeconfig", "--kube-apiserver", "--kube-as-user", "--kube-as-group", "--kube-ca-file", "--kube-token",
  "--kube-tls-server-name", "--registry-config", "--repository-cache", "--repository-config", "--burst-limit", "--qps", "--content-cache",
  "-f", "--values", "--set", "--set-string", "--set-json", "--set-file", "--set-literal", "--version", "--repo", "--timeout", "--description", "--history-max",
  "--max-history", "--post-renderer", "--post-renderer-args", "--username", "--password", "--cert-file", "--key-file", "--ca-file", "--keyring", "-o", "--output",
  "-l", "--labels", "--name-template"]);
export function helmChange(words) {
  if (!words.length || basename(words[0].value) !== "helm") return null;
  const args = words.slice(1).map(w => w.value), pos = [], flags = [];
  for (let i = 0; i < args.length; i++) {
    const v = args[i];
    if (v === "--") { pos.push(...args.slice(i + 1)); break; }
    if (!v.startsWith("-") || v === "-") { pos.push(v); continue; }
    const short = !v.startsWith("--") && v.match(/^(-[a-zA-Z])=?(.+)$/);
    if (short) { flags.push([short[1], short[2]]); continue; }
    const name = v.split("=")[0];
    flags.push([name, v.includes("=") ? v.slice(name.length + 1) : HELM_VALUE.has(name) ? args[++i] ?? "" : null]);
  }
  const verb = pos[0];
  if (verb !== "upgrade" && verb !== "install") return null;
  const last = names => flags.filter(([n]) => names.includes(n)).at(-1)?.[1] ?? null;
  const named = verb === "upgrade" || pos.length > 2;
  return {verb, release: named ? pos[1] ?? null : null, chart: named ? pos[2] ?? null : pos[1] ?? null, extra: pos.length > 3,
    namespace: last(["-n", "--namespace"]), context: last(["--kube-context"]), install: verb === "install" || flags.some(([n]) => n === "-i" || n === "--install"), flags};
}
// `helm diff upgrade` with the command's own chart, release and values, or null (not run) when the
// command has a flag that could change what runs or where it connects, or one this does not know.
const HELM_FORWARD = new Map([["-f", "--values"], ["--values", "--values"], ["--set", "--set"], ["--set-string", "--set-string"], ["--set-json", "--set-json"],
  ["--set-file", "--set-file"], ["--set-literal", "--set-literal"], ["--version", "--version"], ["--repo", "--repo"], ["-n", "--namespace"],
  ["--namespace", "--namespace"], ["--kube-context", "--kube-context"]]);
const HELM_BOOL = new Set(["--devel", "--reuse-values", "--reset-values", "--reset-then-reuse-values", "--disable-openapi-validation", "--skip-schema-validation",
  "--enable-dns", "--take-ownership", "--no-hooks"]);
// what only changes how the upgrade waits, records or reports itself, not what it renders
const HELM_DROP = new Set(["-i", "--install", "--atomic", "--wait", "--wait-for-jobs", "--create-namespace", "--cleanup-on-fail", "--timeout", "--history-max",
  "--max-history", "--description", "--debug", "--hide-notes", "--render-subchart-notes", "--skip-crds", "--rollback-on-failure", "-l", "--labels"]);
export function helmDiffArgs(h) {
  if (!h.release || !h.chart || h.extra || /^-/.test(h.release) || /^-/.test(h.chart)) return null;
  const out = [];
  for (const [n, v] of h.flags) {
    if (HELM_FORWARD.has(n) && v != null) out.push(`${HELM_FORWARD.get(n)}=${v}`);
    else if (HELM_BOOL.has(n) && (v == null || v === "true")) out.push(n);
    else if (!HELM_DROP.has(n)) return null;   // --kubeconfig, --kube-apiserver, --kube-token, --post-renderer, --dry-run, --force, -o, anything else
  }
  return ["diff", "upgrade", h.release, h.chart, ...out, ...(h.install ? ["--allow-unreleased"] : []), "--output", "structured", "--no-color", "--suppress-secrets"];
}

// The helm plugins `helm diff` could start: helm-diff itself, and a downloader plugin for a chart or
// values URL. They are code on disk that an agent's file tools could write, so helm diff runs only
// when every plugin directory (HELM_PLUGINS, else HELM_DATA_HOME, $XDG_DATA_HOME/helm or the
// platform's helm data directory, /plugins) is under the home directory and outside the working tree,
// every file and link there (through the links a local `helm plugin install` makes) is outside the
// tree and not changed after the trusted mark, and the diff plugin runs only a program inside its own
// directory. The mark is the Reflex config.json, where the user turned helm_diff on: after a plugin
// update, saving config.json again trusts the new files. The change time (ctime) counts too, which
// touch -t cannot set back. null when helm-diff is not installed, {why} when unsafe, else {dir}.
// ponytail: like the provider check, a check before the spawn; the same window.
export function helmPlugins(dir, cwd, env = process.env) {
  const home = realOr(env.HOME || homedir());
  if (!home) return {why: "no home directory"};
  if ([env.HELM_PLUGINS, env.HELM_DATA_HOME, env.XDG_DATA_HOME].some(v => v && v.split(":").some(x => x && !isAbsolute(x)))) return {why: "a relative HELM_PLUGINS, HELM_DATA_HOME or XDG_DATA_HOME"};
  const data = env.HELM_DATA_HOME || join(env.XDG_DATA_HOME || (process.platform === "darwin" ? join(home, "Library") : join(home, ".local/share")), "helm");
  const roots = (env.HELM_PLUGINS ? env.HELM_PLUGINS.split(":") : [join(data, "plugins")]).filter(Boolean);
  // every plugin: helm diff can start a downloader plugin too, and helm may resolve `diff` to another one
  const plugins = [];
  for (const r of roots) {
    let names = [];
    try { names = readdirSync(r); } catch { continue; }
    for (const n of names) {
      let st;
      try { st = statSync(join(r, n, "plugin.yaml")); } catch { continue; }   // not a plugin
      if (st.size > 64 * 1024) return {why: `a helm plugin.yaml too large to check (${n})`};
      let y;
      try { y = readFileSync(join(r, n, "plugin.yaml"), "utf8"); } catch { return {why: `an unreadable helm plugin.yaml (${n})`}; }
      plugins.push({dir: join(r, n), yaml: y, diff: /^name:\s*["']?diff["']?\s*(#.*)?$/m.test(y)});
    }
  }
  if (!plugins.some(p => p.diff)) return null;
  const tree = treeOf(dir, cwd, home);
  if (tree.some(t => insideOf(home, t))) return {why: "the working tree holds the home directory"};
  let mark;
  try { mark = statSync(join(env.XDG_CONFIG_HOME || join(home, ".config"), "reflex/config.json")).mtimeMs; } catch { return {why: "no Reflex config.json to date the helm plugins by"}; }
  for (const r of roots) {
    const real = realOr(r);
    if (real && (!insideOf(real, home) || real === home || tree.some(t => insideOf(real, t) || insideOf(t, real)))) return {why: `a helm plugin directory outside the home directory or in the working tree (${basename(r)})`};
  }
  let seen = 0;
  const walk = (p, depth) => {
    let l, st;
    try { l = lstatSync(p); st = statSync(p); } catch { return `an unreadable plugin entry (${basename(p)})`; }
    const real = realOr(p);
    if (!real || tree.some(t => insideOf(real, t))) return `a helm plugin in the working tree (${basename(p)})`;
    if (Math.max(l.mtimeMs, l.ctimeMs, st.mtimeMs, st.ctimeMs) > mark) return `${basename(p)} changed after the Reflex config.json was saved`;
    if (!st.isDirectory()) return null;
    if (depth > 8) return "helm plugins nested too deep";
    let names;
    try { names = readdirSync(p); } catch { return "an unreadable plugin directory"; }
    for (const n of names) { if (++seen > 2000) return "too many helm plugin files"; const w = walk(join(p, n), depth + 1); if (w) return w; }
    return null;
  };
  for (const r of roots) if (realOr(r)) { const w = walk(r, 0); if (w) return {why: w}; }
  // what each plugin runs (command, platformCommand, downloaders; not the install hooks): a program in
  // its own directory, ${HELM_PLUGIN_DIR}/x or a relative x, with plain arguments, in every entry not for Windows
  const own = /^(\$(\{HELM_PLUGIN_DIR\}|HELM_PLUGIN_DIR)\/)?(?!\/)[\w.-][\w./-]*( [\w./=-]+)*$/;
  for (const p of plugins) {
    const cmds = p.yaml.split(/^(?=\s*-\s)/m).filter(c => !/\bos:\s*["']?windows\b/.test(c))
      .flatMap(c => [...c.matchAll(/\bcommand:\s*["']?([^"'\n#]*)/g)].map(m => m[1].trim()));
    if ((p.diff && !cmds.length) || cmds.some(c => !own.test(c) || /(^|[\/ ])\.\.(\/|$| )/.test(c))) return {why: `the ${basename(p.dir)} plugin runs a program outside its own directory`};
  }
  return {dir: plugins.find(p => p.diff).dir};
}

/** What `helm diff upgrade --output structured` says: objects changed (added, modified, removed) and removed. null: not that output. */
const HELM_FLAG = /^(Namespace|PersistentVolumeClaim|PersistentVolume|StatefulSet|CustomResourceDefinition)$/;
export function countHelm(out) {
  let j;
  try { j = JSON.parse(out); } catch { return null; }
  if (!Array.isArray(j)) return null;
  const objs = [];
  for (const e of j) {
    if (!e || typeof e !== "object") return null;
    let {kind, namespace = "", name} = e;
    // an entry helm-diff could not structure carries only its key: "namespace, name, Kind (group)"
    if (!kind) { const m = String(name ?? "").match(/^([^,]*), ([^,]+), ([\w.-]+) \(/); if (!m) return null; [, namespace, name, kind] = m; }
    if (!["ADD", "MODIFY", "MODIFY_SUPPRESSED", "OWNERSHIP", "REMOVE"].includes(e.changeType)) return null;   // a change this parser does not know is not read as harmless
    objs.push({id: `${kind}/${namespace ? `${namespace}/` : ""}${name}`, kind: String(kind), removed: e.changeType === "REMOVE"});
  }
  const removed = objs.filter(o => o.removed);
  return {changed: objs.length, removed: removed.map(o => o.id), flagged: removed.filter(o => HELM_FLAG.test(o.kind)).map(o => o.id)};
}

// helm diff for one helm upgrade or install: null when it cannot speak to it (not on, not installed, a
// flag or kubeconfig of the command's own), {why} when it should have and could not (unsafe plugins,
// failed, timed out: the caller asks), else the counts.
const HELM_KEEP = /^(PATH|HOME|TMPDIR|LANG|LC_\w+|USER|LOGNAME|KUBECONFIG|XDG_\w+|HELM_(PLUGINS|DATA_HOME|CONFIG_HOME|CACHE_HOME|NAMESPACE|KUBECONTEXT|REGISTRY_CONFIG|REPOSITORY_CONFIG|REPOSITORY_CACHE)|AWS_\w+|GOOGLE_\w+|CLOUDSDK_\w+|AZURE_\w+|(HTTPS?|NO)_PROXY|(https?|no)_proxy)$/;
function helmCheck(h, dir, cwd, deadline, env) {
  const a = helmDiffArgs(h);
  if (!a || kubeconfigNear([dir, cwd], env)) return null;
  const bin = which("helm", env.PATH);
  if (!bin) return null;
  const p = helmPlugins(dir, cwd, env);
  if (!p) return null;
  if (p.why) return {why: `helm diff not run: ${p.why}`};
  if (deadline - Date.now() < 50) return {why: "helm diff not run: out of time"};
  // an allowlist: what helm needs to find its plugins, config and cluster, and what an exec credential
  // plugin (aws eks get-token, gke-gcloud-auth-plugin) needs. Not HELM_DIFF_* (an external diff tool,
  // a template file, another output), HELM_KUBEAPISERVER, HELM_KUBETOKEN or other connection overrides.
  const henv = Object.fromEntries(Object.entries(env).filter(([k]) => HELM_KEEP.test(k)));
  const r = run(bin, a, dir, henv, deadline - Date.now());
  if (r.timedOut) return {why: "helm diff timed out"};
  if (r.status !== 0) return {why: `helm diff failed (${(r.err.trim().split("\n").find(l => l.trim()) ?? `exit ${r.status}`).replace(/[^\x20-\x7e]/g, "").slice(0, 80)})`};
  const d = countHelm(r.out);
  if (!d) return {why: "helm diff output did not read as a structured diff (helm-diff 3.15 or later)"};
  return {kind: "helm", changed: d.changed, deleted: d.removed.length, flagged: d.flagged, names: d.removed, digest: sha(r.out)};
}

const list = (xs, n = 5) => xs.slice(0, n).join(", ") + (xs.length > n ? ", ..." : "");
const RANK = {pass: 0, ask: 1, deny: 2};
const FIX = (t = "terraform") => `run \`${t} plan -out=tfplan\` and apply the plan file (${t} apply tfplan)`;

/**
 * The plan gate for one command. null: no infra change it can speak to (the gate goes on as before).
 * Otherwise {outcome, id, rule, plan}: outcome ask or deny is a rule; "pass" means every part of the
 * command was a verified clean plan (allow-eligible); null outcome carries only the counts.
 * `prod(dir)`: whether the command, run in dir, is production (the gate's markers).
 */
export function planGate({command, cwd, settings: s, settingsAt = () => s, prod, pipelines, shellWords, env = process.env}) {
  if (!s?.enabled || !/\b(terraform|tofu|terragrunt|kubectl|helm)\b/.test(command)) return null;
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
      const tf = terraformApply(w), tg = !tf && terragruntApply(w), helm = !tf && !tg && helmChange(w), kube = !tf && !tg && !helm && s.kubectl_diff ? kubectlChange(w) : null;
      if (!tf && !tg && !helm && !kube) { other = true; continue; }
      const here = tf?.chdir != null ? (dir ? resolve(dir, tf.chdir) : null) : dir;
      parts.push({tf, tg, helm, kube, dir: here, prod: prod(here ?? cwd ?? ""), strict: w.strict && !!tf?.exact && !tfArgs && !dotdot && segs.length === 1});
    }
  }
  if (!parts.length) return null;
  const results = parts.map(({tf, tg, helm, kube, dir, prod, strict}) => {
    const sd = dir ? settingsAt(dir) : s;
    if (helm) {
      const what = `${prod ? "production " : ""}helm ${helm.verb}${helm.install && helm.verb === "upgrade" ? " --install" : ""}`;
      const where = `release ${helm.release ?? "(a generated name)"} in namespace ${helm.namespace ?? "(the context's default)"}${helm.context ? `, kube context ${helm.context}` : ""}`;
      const d = s.helm_diff && dir ? helmCheck(helm, dir, cwd, deadline, env) : null;
      if (d?.why) return {outcome: "ask", id: "helm-diff-unreadable", rule: `${what} of ${where}: ${d.why}`};
      const plan = d && {kind: "helm", changed: d.changed, deleted: d.deleted, flagged: d.flagged, digest: d.digest};
      if (d?.flagged.length) return {outcome: sd.destroy, id: "helm-destroy", plan, rule: `${what} of ${where} removes ${d.deleted}: ${list(d.flagged)} (namespace, volume, statefulset or CRD)`};
      if (d?.deleted) return {outcome: "ask", id: "helm-delete", plan, rule: `${what} of ${where} removes ${d.deleted} object${d.deleted === 1 ? "" : "s"}: ${list(d.names)} (helm diff)`};
      const counts = d ? ` (helm diff: ${d.changed} object${d.changed === 1 ? "" : "s"} changed, 0 removed)` : "";
      if (prod) return {outcome: "ask", id: "helm-prod", plan, rule: `${what} of ${where}${counts}`};
      return d ? {outcome: null, id: "helm-diff", plan, rule: `${what} of ${where}${counts}`} : null;
    }
    if (tg) {
      if (!tg.plan) return {outcome: prod && sd.require_plan_in_prod ? "deny" : "ask", id: "plan-missing", rule: `terragrunt ${tg.all ? "run --all " : ""}apply without a saved plan: ` +
        "run `terragrunt plan -out=tfplan` (a stack: `terragrunt run --all --out-dir DIR plan`) and apply that plan"};
      return {outcome: "ask", id: "terragrunt-plan", rule: `${prod ? "production " : ""}terragrunt apply of a saved plan: not read (terragrunt.hcl hooks and run_cmd run at apply, and terragrunt picks tofu or terraform); review it with terragrunt show first`};
    }
    if (kube) {
      const k = dir ? kubeCheck(kube, dir, s, deadline, env) : null;
      if (!k) return null;
      if (k.flagged.length) return {outcome: sd.destroy, id: "kube-destroy", plan: k, rule: `kubectl ${kube.verb} deletes ${k.deleted}: ${list(k.flagged)} (namespace, volume, statefulset or CRD)`};
      if (k.deleted) return {outcome: "ask", id: "kube-delete", plan: k, rule: `kubectl ${kube.verb} deletes ${k.deleted} object${k.deleted === 1 ? "" : "s"} (server dry run)`};
      return {outcome: null, id: "kube-diff", plan: k, rule: `kubectl ${kube.verb} changes ${k.changed} object${k.changed === 1 ? "" : "s"} (server dry run)`};
    }
    const noPlan = prod && sd.require_plan_in_prod ? "deny" : "ask";
    const fix = FIX(tf.tool);
    if (tf.unreadable) return {outcome: noPlan, id: "plan-unreadable", rule: `no readable saved plan (${tf.unreadable}): ${fix}`};
    if (!tf.plan) return {outcome: noPlan, id: "plan-missing", rule: `${tf.tool} apply without a saved plan: ${fix}`};
    if (!dir) return {outcome: noPlan, id: "plan-unreadable", rule: `no readable saved plan (the directory it runs in is unknown): ${fix}`};
    // off by default: the command is judged as before (the rules, then the usual judge)
    if (!s.terraform_show) return {outcome: null, id: "plan-not-read", rule: "saved plan not read (infra.terraform_show is off)"};
    const r = readPlan(dir, tf.plan, {deadline, env, cwd, tool: tf.tool});
    if (!r.plan) return {outcome: noPlan, id: "plan-unreadable", rule: `no readable saved plan (${r.why}): ${fix}`};
    const p = r.plan, counts = `${p.create} create, ${p.update} update, ${p.delete} delete, ${p.replace} replace`;
    const plan = {kind: tf.tool, create: p.create, update: p.update, delete: p.delete, replace: p.replace, stateful: p.stateful, digest: p.digest};
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
  // a kubectl or helm check that could not run: that part is judged as before, and nothing passes on it
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
