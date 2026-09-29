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
const HELM_PASS = new Map([["-f", "--values"], ["--values", "--values"], ["--set", "--set"], ["--set-string", "--set-string"], ["--set-json", "--set-json"],
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
    if (HELM_PASS.has(n) && v != null) out.push(`${HELM_PASS.get(n)}=${v}`);
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
  const home = realpathSync(mkdtempSync(join(tmpdir(), "reflex-infra-home-"))), cache = join(home, ".terraform.d/plugin-cache");   // HOME below: the user's plugin cache, outside the trees
  mkdirSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64"), {recursive: true});
  writeFileSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64/terraform-provider-aws_v5.0.0"), "");
  utimesSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64/terraform-provider-aws_v5.0.0"), 1e9, 1e9);
  // fake terraform: `show -json -no-color <plan>` prints the plan's JSON (after the zip marker line);
  // a plan naming SLEEP hangs, one naming FAIL fails. Every call and its environment are logged.
  writeFileSync(join(bin, "terraform"), `#!/bin/sh\necho "terraform $*" >> "${log}"\nenv | grep -E '^(AWS_|CHECKPOINT_DISABLE|TF_VAR_|GITHUB_TOKEN)' | sed 's/^/  env /' >> "${log}"\n` +
    `[ "$1" = show ] || exit 9\nf="$4"\ngrep -q SLEEP "$f" && sleep 5\ngrep -q FAIL "$f" && { echo "Error: Failed to load plugin schemas" >&2; exit 1; }\ntail -n +2 "$f"\n`);
  // fake kubectl: diff prints KUBE_DIFF_OUT and exits 1; --dry-run=server prints KUBE_NAMES; any other call exits 7
  writeFileSync(join(bin, "kubectl"), `#!/bin/sh\necho "kubectl $*" >> "${log}"\ncase " $* " in\n  *" diff "*) printf '%s' "$KUBE_DIFF_OUT"; exit \${KUBE_DIFF_EXIT:-1};;\n` +
    `  *" --dry-run=server "*) printf '%s' "$KUBE_NAMES"; exit 0;;\nesac\nexit 7\n`);
  chmodSync(join(bin, "terraform"), 0o755); chmodSync(join(bin, "kubectl"), 0o755);
  const env = {PATH: `relative/bin:${bin}:/usr/bin:/bin`, HOME: home, AWS_SECRET_ACCESS_KEY: "never-passed", TF_VAR_db_password: "never-passed", GITHUB_TOKEN: "never-passed"};
  const put = (dir, name, json, mtime) => {
    mkdirSync(dir, {recursive: true});
    writeFileSync(join(dir, name), `PK\x03\x04\n${json}`);
    if (mtime) utimesSync(join(dir, name), mtime, mtime);
  };
  const gate = (command, cwd, over = {}, prod = () => false, e = env) => planGate({command, cwd, settings: {...INFRA_DEFAULTS, terraform_show: true, ...over}, prod, pipelines, shellWords, env: e});
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
    assert.deepEqual(tfa("terraform apply tfplan"), {tool: "terraform", chdir: null, plan: "tfplan", exact: true});
    assert.deepEqual(tfa("terraform -chdir=envs/dev apply -auto-approve -lock-timeout=30s -input=false tfplan"), {tool: "terraform", chdir: "envs/dev", plan: "tfplan", exact: true});
    assert.deepEqual(tfa("terraform apply -auto-approve -var env=dev -var-file dev.tfvars"), {tool: "terraform", chdir: null, plan: null, exact: false});
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
    // terraform_show off (the default): nothing is run, the command is judged as before; no plan still asks
    rmSync(log, {force: true});
    g = gate("terraform apply destroy.plan", w, {terraform_show: false});
    assert.ok(g.outcome === null && g.id === "plan-not-read" && !g.plan && !existsSync(log), `off: not read, not run: ${JSON.stringify(g)}`);
    assert.equal(gate("terraform apply -auto-approve", w, {terraform_show: false}).id, "plan-missing", "off: an apply without a plan still asks with the fix");
    assert.equal(INFRA_DEFAULTS.terraform_show, false, "off by default");
    // the provider binaries show would start: only symlinks into the plugin cache, older than the plan
    const pv = join(tmp, "pv"), prov = join(pv, ".terraform/providers/registry.terraform.io/hashicorp/aws/5.0.0");
    put(pv, "tfplan", fixture("clean"));
    mkdirSync(prov, {recursive: true});
    symlinkSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64"), join(prov, "darwin_arm64"));
    assert.equal(gate("terraform apply tfplan", pv).outcome, "pass", "a provider linked into the plugin cache");
    utimesSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64/terraform-provider-aws_v5.0.0"), Date.now() / 1000 + 60, Date.now() / 1000 + 60);
    assert.match(gate("terraform apply tfplan", pv).rule, /terraform show not run: a provider in the cache is newer than the plan/);
    utimesSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64/terraform-provider-aws_v5.0.0"), 1e9, 1e9);
    mkdirSync(join(prov, "linux_amd64"));
    writeFileSync(join(prov, "linux_amd64/terraform-provider-aws_v5.0.0"), "#!/bin/sh\n");
    g = gate("terraform apply tfplan", pv);
    assert.ok(g.outcome === "ask" && /terraform show not run: a provider binary inside the working tree/.test(g.rule), `a planted binary: ${JSON.stringify(g)}`);
    rmSync(join(prov, "linux_amd64"), {recursive: true});
    mkdirSync(join(pv, "planted"));
    symlinkSync(join(pv, "planted"), join(prov, "linux_amd64"));
    assert.match(gate("terraform apply tfplan", pv).rule, /a provider outside the plugin cache/, "a link back into the tree");
    rmSync(join(prov, "linux_amd64"));
    // a provider linked into a TF_PLUGIN_CACHE_DIR inside the tree (or the repository): that cache does not count.
    // HOME is the tree's parent, so only the tree rule can refuse the in-tree cache; its own cache is empty.
    mkdirSync(join(tmp, ".terraform.d/plugin-cache"), {recursive: true});
    const inTreeCache = (c, why) => {
      const bin = join(c, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64");
      mkdirSync(bin, {recursive: true});
      writeFileSync(join(bin, "terraform-provider-aws_v5.0.0"), "#!/bin/sh\n");
      utimesSync(join(bin, "terraform-provider-aws_v5.0.0"), 1e9, 1e9);
      rmSync(join(prov, "darwin_arm64"));
      symlinkSync(bin, join(prov, "darwin_arm64"));
      const r = gate("terraform apply tfplan", pv, {}, () => false, {...env, HOME: tmp, TF_PLUGIN_CACHE_DIR: c});
      assert.ok(r.outcome === "ask" && /terraform show not run: a provider outside the plugin cache \(darwin_arm64\)/.test(r.rule), `${why}: ${JSON.stringify(r)}`);
      rmSync(join(prov, "darwin_arm64"));
      symlinkSync(join(cache, "registry.terraform.io/hashicorp/aws/5.0.0/darwin_arm64"), join(prov, "darwin_arm64"));
      rmSync(c, {recursive: true});
    };
    inTreeCache(join(pv, "cache"), "a cache inside the tree does not count");
    mkdirSync(join(pv, "terraform.d"));
    assert.match(gate("terraform apply tfplan", pv).rule, /a terraform.d directory in the working tree/);
    rmSync(join(pv, "terraform.d"), {recursive: true});
    writeFileSync(join(home, ".terraformrc"), 'provider_installation {\n  dev_overrides { "hashicorp/aws" = "/x" }\n}\n');
    assert.match(gate("terraform apply tfplan", pv).rule, /dev_overrides/);
    rmSync(join(home, ".terraformrc"));
    assert.match(gate("terraform apply tfplan", pv, {}, () => false, {...env, TF_REATTACH_PROVIDERS: "{}"}).rule, /TF_REATTACH_PROVIDERS/);
    assert.match(gate("terraform apply tfplan", pv, {}, () => false, {...env, HOME: pv}).rule, /no plugin cache outside the working tree|holds the home/, "cwd is the home directory");
    assert.match(gate("terraform apply tfplan", pv, {}, () => false, {...env, TF_CLI_CONFIG_FILE: "rc"}).rule, /TF_CLI_CONFIG_FILE is relative/);
    writeFileSync(join(pv, "in.tfrc"), "");
    assert.match(gate("terraform apply tfplan", pv, {}, () => false, {...env, TF_CLI_CONFIG_FILE: join(pv, "in.tfrc")}).rule, /inside the working tree/);
    mkdirSync(join(home, ".terraform.d"), {recursive: true});
    writeFileSync(join(home, ".terraform.d/extra.tfrc"), 'provider_installation { dev_overrides { "a/b" = "/x" } }');
    assert.match(gate("terraform apply tfplan", pv).rule, /dev_overrides/, "a ~/.terraform.d/*.tfrc counts");
    rmSync(join(home, ".terraform.d/extra.tfrc"));
    writeFileSync(join(home, ".terraformrc"), 'plugin_cache_dir = "../cache"\n');
    assert.match(gate("terraform apply tfplan", pv).rule, /a relative plugin_cache_dir/);
    rmSync(join(home, ".terraformrc"));
    mkdirSync(join(pv, ".git"));
    inTreeCache(join(pv, "sub"), "a cache inside the repository");
    rmSync(join(pv, ".git"), {recursive: true});
    assert.equal(gate("terraform apply tfplan", pv).outcome, "pass", "and back to safe");
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

    // OpenTofu: the same plan gate with `tofu show -json`, the same provider guard
    rmSync(log, {force: true});
    writeFileSync(join(bin, "tofu"), readFileSync(join(bin, "terraform"), "utf8").replace('echo "terraform $*"', 'echo "tofu $*"'));
    chmodSync(join(bin, "tofu"), 0o755);
    assert.deepEqual(tfa("tofu -chdir=envs/dev apply -auto-approve tfplan"), {tool: "tofu", chdir: "envs/dev", plan: "tfplan", exact: true});
    assert.equal(tfa("./tofu apply tfplan").exact, false, "an agent's own tofu");
    g = gate("tofu apply clean.plan", w);
    assert.ok(g.outcome === "pass" && g.plan.kind === "tofu" && g.plan.create === 1, `tofu: a clean plan: ${JSON.stringify(g)}`);
    g = gate("tofu apply -auto-approve", w);
    assert.ok(g.outcome === "ask" && g.id === "plan-missing" && /^tofu apply without a saved plan: run `tofu plan -out=tfplan`/.test(g.rule), `tofu: no plan asks with the fix: ${JSON.stringify(g)}`);
    assert.equal(gate("tofu apply", w, {require_plan_in_prod: true}, () => true).outcome, "deny", "tofu: a saved plan required in production");
    assert.equal(gate("tofu apply destroy.plan", w).id, "plan-destroy", "tofu: a destroying plan");
    assert.equal(gate("tofu apply clean.plan", w, {}, () => true).id, "plan-prod", "tofu: production asks");
    assert.match(gate("tofu apply sleep.plan", w, {timeout_ms: 300}).rule, /tofu show timed out/, "tofu: a hung show fails closed");
    assert.match(gate("tofu apply clean.plan", w, {}, () => false, {...env, PATH: "/usr/bin:/bin"}).rule, /tofu not found on PATH/);
    assert.equal(gate("tofu apply clean.plan", w, {terraform_show: false}).id, "plan-not-read", "tofu: off by default, not read");
    assert.equal(gate("tofu apply tfplan", pv).outcome, "pass", "tofu: a provider linked into the plugin cache");
    writeFileSync(join(home, ".tofurc"), 'provider_installation {\n  dev_overrides { "opentofu/aws" = "/x" }\n}\n');
    assert.match(gate("tofu apply tfplan", pv).rule, /tofu show not run: dev_overrides/, "~/.tofurc counts");
    rmSync(join(home, ".tofurc"));
    mkdirSync(join(home, "xdg/opentofu"), {recursive: true});
    writeFileSync(join(home, "xdg/opentofu/tofurc"), 'provider_installation { dev_overrides { "a/b" = "/x" } }');
    assert.match(gate("tofu apply tfplan", pv, {}, () => false, {...env, XDG_CONFIG_HOME: join(home, "xdg")}).rule, /dev_overrides/, "$XDG_CONFIG_HOME/opentofu/tofurc counts");
    rmSync(join(home, "xdg"), {recursive: true});
    // review round 1: tofu gets XDG_CONFIG_HOME, so it reads the tofurc that was checked; a relative one is refused
    gate("tofu apply tfplan", pv, {}, () => false, {...env, XDG_CONFIG_HOME: join(home, "xdg")});
    writeFileSync(join(bin, "tofu"), readFileSync(join(bin, "tofu"), "utf8").replace("'^(AWS_", "'^(XDG_CONFIG_HOME|AWS_"));
    gate("tofu apply tfplan", pv, {}, () => false, {...env, XDG_CONFIG_HOME: join(home, "xdg")});
    assert.match(readFileSync(log, "utf8"), /env XDG_CONFIG_HOME=/, "XDG_CONFIG_HOME reaches tofu");
    assert.match(gate("tofu apply tfplan", pv, {}, () => false, {...env, XDG_CONFIG_HOME: "rel"}).rule, /a relative XDG_CONFIG_HOME/);
    // review round 1: OpenTofu encryption in the root module (a key provider can run a program): not run
    writeFileSync(join(pv, "enc.tf"), 'terraform {\n  encryption {\n    key_provider "external" "x" { command = ["./x"] }\n  }\n}\n');
    utimesSync(join(pv, "enc.tf"), 1e9, 1e9);
    const logBefore = readFileSync(log, "utf8");
    g = gate("tofu apply tfplan", pv);
    assert.ok(g.outcome === "ask" && /tofu show not run: encryption or a key provider in enc.tf/.test(g.rule) && readFileSync(log, "utf8") === logBefore, `encryption config: not run: ${JSON.stringify(g)}`);
    assert.equal(gate("terraform apply tfplan", pv).outcome, "pass", "terraform has no encryption block: unchanged");
    rmSync(join(pv, "enc.tf"));
    const st2 = join(tmp, "stale-tofu");
    put(st2, "tfplan", fixture("clean"), old);
    writeFileSync(join(st2, "main.tofu"), "");
    assert.match(gate("tofu apply tfplan", st2).rule, /stale: main.tofu changed/, "a .tofu file newer than the plan");
    const tcalls = readFileSync(log, "utf8").split("\n").filter(l => /^tofu /.test(l));
    assert.ok(tcalls.length && tcalls.every(l => /^tofu show -json -no-color \//.test(l)), `only tofu show: ${tcalls.join(" | ")}`);
    assert.ok(!/never-passed/.test(readFileSync(log, "utf8")), "tofu: sanitized env");

    // Terragrunt: an apply always asks (nothing is read or run); without a saved plan with the fix
    rmSync(log, {force: true});
    writeFileSync(join(bin, "terragrunt"), `#!/bin/sh\necho "terragrunt $*" >> "${log}"\nexit 7\n`);
    chmodSync(join(bin, "terragrunt"), 0o755);
    for (const c of ["terragrunt apply", "terragrunt apply -auto-approve", "terragrunt run-all apply", "terragrunt run --all apply", "terragrunt run --all -- apply",
                     "terragrunt run -- apply", "terragrunt --log-level debug apply", "terragrunt apply-all", "terragrunt stack run apply", "terragrunt run --all apply --working-dir live"]) {
      g = gate(c, w);
      assert.ok(g?.outcome === "ask" && g.id === "plan-missing" && /terragrunt plan -out=tfplan/.test(g.rule), `terragrunt without a plan: ${c} ${JSON.stringify(g)}`);
    }
    assert.match(gate("terragrunt run-all apply", w).rule, /^terragrunt run --all apply without a saved plan/);
    for (const c of ["terragrunt apply tfplan", "terragrunt run -- apply tfplan", "terragrunt run --all apply --out-dir /tmp/plans", "terragrunt apply -auto-approve tfplan"]) {
      g = gate(c, w);
      assert.ok(g?.outcome === "ask" && g.id === "terragrunt-plan" && /not read/.test(g.rule), `terragrunt with a plan still asks: ${c} ${JSON.stringify(g)}`);
    }
    assert.equal(gate("terragrunt apply", w, {require_plan_in_prod: true}, () => true).outcome, "deny", "terragrunt: a saved plan required in production");
    assert.equal(gate("terragrunt apply tfplan", w, {require_plan_in_prod: true}, () => true).outcome, "ask", "terragrunt: a saved plan in production asks");
    assert.equal(gate("terragrunt plan -out=tfplan", w), null, "terragrunt plan: not an apply");
    assert.equal(gate("terragrunt apply", w, {enabled: false}), null);
    assert.ok(!existsSync(log), "terragrunt: nothing run");

    // the rules: tofu and terragrunt destroy like terraform destroy, helm uninstall, delete and rollback;
    // prodTier: tofu and terragrunt workspaces and directories, helm's --kube-context and --namespace
    const {precheck, prodTier} = await import("./gate.mjs");
    const ruleId = (c, ctx = {}) => precheck(c, "/repo/infra", ctx)?.id;
    for (const [c, id] of [["tofu destroy -auto-approve", "destroy"], ["tofu -chdir=envs/prod destroy", "prod-destroy"], ["tofu state rm aws_instance.a", "destroy"],
      ["tofu apply -destroy", "destroy"], ["tofu workspace select live && tofu destroy", "prod-destroy"], ["TF_WORKSPACE=live tofu destroy", "prod-destroy"],
      ["terragrunt destroy", "destroy"], ["terragrunt run-all destroy", "destroy"], ["terragrunt run --all destroy", "destroy"], ["terragrunt run -- destroy", "destroy"],
      ["terragrunt destroy-all", "destroy"], ["terragrunt run-all destroy --working-dir live", "prod-destroy"], ["terragrunt run --all destroy --terragrunt-working-dir envs/prod", "prod-destroy"],
      ["terragrunt run-all apply -destroy", "destroy"], ["cd envs/live && terragrunt run-all destroy", "prod-destroy"],
      ["helm uninstall api -n web", "destroy"], ["helm delete api", "destroy"], ["helm rollback api 3 -n web", "destroy"], ["helm --kube-context prod-eu uninstall api", "prod-destroy"],
      ["helm rollback api 3 --kube-context production", "prod-destroy"], ["helm -n live uninstall api", "prod-destroy"], ["helm uninstall api -n=live", "prod-destroy"],
      ["helm uninstall api --namespace=live", "prod-destroy"], ["HELM_NAMESPACE=live helm uninstall api", "prod-destroy"], ["HELM_KUBECONTEXT=live helm rollback api 2", "prod-destroy"],
      ["helm --debug --kube-context live delete api", "prod-destroy"], ["tofu -no-color -chdir=envs/prod destroy", "prod-destroy"], ["helm -nprod uninstall api", "prod-destroy"], ["kubectl -nlive delete pod x", "prod-destroy"], ["helm -nweb uninstall api", "destroy"], ["helm uninstall api --kube-context pre-prod", "destroy"]])
      assert.equal(ruleId(c), id, `rule for ${c}`);
    assert.equal(ruleId("helm uninstall api", {kube_context: "eks-live-1"}), "prod-destroy", "the current kube context");
    assert.equal(ruleId("tofu destroy", {tf_workspace: "live"}), "prod-destroy", "a tofu workspace in the context");
    for (const c of ["terragrunt plan -destroy", "tofu plan -destroy", "helm upgrade api ./c --set mode=delete", "helm history api"])
      assert.notEqual(ruleId(c), "destroy", `not a destroy: ${c}`);
    for (const c of ["tofu workspace select live && tofu apply", "terragrunt apply --working-dir live", "helm upgrade --install api ./c -n=live", "helm upgrade api ./c --kube-context live",
                     "HELM_NAMESPACE=live helm upgrade api ./c", "helm upgrade --install api ./c --namespace production"])
      assert.equal(prodTier(c, "/repo/infra", {}).prod, true, `prodTier: ${c}`);
    assert.equal(prodTier("helm upgrade --install api ./c -n web --kube-context staging", "/repo/infra", {}).prod, false, "prodTier: staging is not production");

    // helm: production upgrade asks with the release and namespace; helm diff only with helm_diff
    rmSync(log, {force: true});
    // fake helm: `diff upgrade ...` prints FAKE_HELM_OUT (exit FAKE_HELM_EXIT), FAKE_HELM_SLEEP hangs it; anything else exits 7.
    // helm gets an allowlisted environment, so the fake reads them from files next to it (hEnv writes them).
    writeFileSync(join(bin, "helm"), `#!/bin/sh\necho "helm $*" >> "${log}"\nenv | grep -E '^(HELM_DIFF_|HELM_KUBETOKEN)' | sed 's/^/  env /' >> "${log}"\n` +
      `[ "$1 $2" = "diff upgrade" ] || exit 7\n. "${bin}/helm.vars"\n[ -n "$FAKE_HELM_SLEEP" ] && sleep "$FAKE_HELM_SLEEP"\nprintf '%s' "$FAKE_HELM_OUT"\nexit \${FAKE_HELM_EXIT:-0}\n`);
    chmodSync(join(bin, "helm"), 0o755);
    const up = "helm upgrade --install api ./chart -n web --kube-context dev -f values.yaml --set image.tag=v2 --atomic --wait --timeout 5m";
    assert.equal(gate(up, w), null, "helm_diff off, not production: as before");
    g = gate("helm upgrade --install api ./chart -n web --kube-context prod-eu", w, {}, () => true);
    assert.ok(g.outcome === "ask" && g.id === "helm-prod" && g.rule === "production helm upgrade --install of release api in namespace web, kube context prod-eu", `helm prod: ${JSON.stringify(g)}`);
    assert.match(gate("helm install api ./chart", w, {}, () => true).rule, /^production helm install of release api in namespace \(the context's default\)/);
    assert.match(gate("helm --namespace=web upgrade -i api ./chart", w, {}, () => true).rule, /helm upgrade --install of release api in namespace web/);
    assert.equal(gate("helm upgrade api ./chart", w, {require_plan_in_prod: true}, () => true).outcome, "ask", "helm in production asks, never more");
    assert.ok(!existsSync(log), "helm_diff off: nothing run");
    const hk = {helm_diff: true};
    const hconf = join(home, ".config/reflex");
    const pluginsDir = process.platform === "darwin" ? join(home, "Library/helm/plugins") : join(home, ".local/share/helm/plugins");
    const q = v => `'${String(v).replace(/'/g, "'\\''")}'`;
    const hEnv = ({FAKE_HELM_OUT = "", FAKE_HELM_EXIT = "", FAKE_HELM_SLEEP = "", ...extra}) => {
      writeFileSync(join(bin, "helm.vars"), `FAKE_HELM_OUT=${q(FAKE_HELM_OUT)}\nFAKE_HELM_EXIT=${q(FAKE_HELM_EXIT)}\nFAKE_HELM_SLEEP=${q(FAKE_HELM_SLEEP)}\n`);
      return {...env, HELM_DIFF_TOOL: "/tmp/evil", HELM_DIFF_OUTPUT: "template", HELM_KUBETOKEN: "never-passed", ...extra};
    };
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})), null, "helm-diff not installed: as before");
    assert.ok(!existsSync(log), "not installed: helm is not run");
    // the plugin, then the mark (config.json) after it
    const plug = join(pluginsDir, "helm-diff");
    mkdirSync(join(plug, "bin"), {recursive: true});
    writeFileSync(join(plug, "plugin.yaml"), 'name: diff\nversion: "3.15.15"\nplatformCommand:\n  - command: ${HELM_PLUGIN_DIR}/bin/diff\nplatformHooks:\n  install:\n    - command: ${HELM_PLUGIN_DIR}/install-binary.sh\n    - os: windows\n      command: pwsh\n      args:\n        - -Command\n');
    writeFileSync(join(plug, "bin/diff"), "#!/bin/sh\n");
    mkdirSync(hconf, {recursive: true});
    writeFileSync(join(hconf, "config.json"), "{}");
    const markAt = t => utimesSync(join(hconf, "config.json"), t, t);
    markAt(Date.now() / 1000 + 3600);
    const entry = (kind, name, changeType, namespace = "web") => ({apiVersion: "v1", kind, namespace, name, changeType, resourceStatus: {oldExists: changeType !== "ADD", newExists: changeType !== "REMOVE"}});
    const out = (...es) => JSON.stringify(es);
    g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: out(entry("Deployment", "api", "MODIFY"), entry("ConfigMap", "api-config", "ADD"))}));
    assert.ok(g.outcome === null && g.id === "helm-diff" && g.plan.kind === "helm" && g.plan.changed === 2 && g.plan.deleted === 0 &&
      g.rule === "helm upgrade --install of release api in namespace web, kube context dev (helm diff: 2 objects changed, 0 removed)", `helm diff: changes only: ${JSON.stringify(g)}`);
    const hl = readFileSync(log, "utf8").trim().split("\n");
    assert.equal(hl[0], "helm diff upgrade api ./chart --namespace=web --kube-context=dev --values=values.yaml --set=image.tag=v2 --allow-unreleased --output structured --no-color --suppress-secrets",
      `the diff command, without the upgrade's own --install, --atomic, --wait and --timeout: ${hl[0]}`);
    g = gate(up, w, hk, () => true, hEnv({FAKE_HELM_OUT: out(entry("Deployment", "api", "MODIFY"))}));
    assert.ok(g.outcome === "ask" && g.id === "helm-prod" && /\(helm diff: 1 object changed, 0 removed\)$/.test(g.rule), `helm diff in production: ${JSON.stringify(g)}`);
    g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: out(entry("Deployment", "api", "MODIFY"), entry("StatefulSet", "db", "REMOVE"), entry("ConfigMap", "old", "REMOVE"))}));
    assert.ok(g.outcome === "deny" && g.id === "helm-destroy" && /removes 2: StatefulSet\/web\/db \(namespace, volume, statefulset or CRD\)$/.test(g.rule), `a statefulset removed: ${JSON.stringify(g)}`);
    assert.equal(gate(up, w, {...hk, destroy: "ask"}, () => false, hEnv({FAKE_HELM_OUT: out(entry("PersistentVolumeClaim", "data-db-0", "REMOVE"))})).outcome, "ask", "infra.destroy: ask");
    g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: out({name: ", widgets.example.com, CustomResourceDefinition (apiextensions.k8s.io)", changeType: "REMOVE"})}));
    assert.ok(g.outcome === "deny" && /CustomResourceDefinition\/widgets.example.com/.test(g.rule), `a CRD by its key: ${JSON.stringify(g)}`);
    g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: out(entry("ConfigMap", "old", "REMOVE"), entry("Service", "api", "MODIFY"))}));
    assert.ok(g.outcome === "ask" && g.id === "helm-delete" && /removes 1 object: ConfigMap\/web\/old \(helm diff\)$/.test(g.rule), `another removal asks: ${JSON.stringify(g)}`);
    for (const [o, why] of [[out(entry("Deployment", "api", "OBLITERATE")), "an unknown change"], ["not json", "not JSON"], ['{"a":1}', "not a list"]]) {
      g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: o}));
      assert.ok(g.outcome === "ask" && g.id === "helm-diff-unreadable" && /did not read as a structured diff/.test(g.rule), `${why}: ${JSON.stringify(g)}`);
    }
    g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "", FAKE_HELM_EXIT: "1"}));
    assert.ok(g.outcome === "ask" && /helm diff failed/.test(g.rule), `a failed diff asks: ${JSON.stringify(g)}`);
    const t0 = Date.now();
    g = gate(up, w, {...hk, timeout_ms: 300}, () => false, hEnv({FAKE_HELM_OUT: "[]", FAKE_HELM_SLEEP: "5"}));
    assert.ok(g.outcome === "ask" && /helm diff timed out/.test(g.rule) && Date.now() - t0 < 2500, `a hung helm diff fails closed, in time: ${JSON.stringify(g)} ${Date.now() - t0} ms`);
    // not run: a kubeconfig, server or token of the command's own, a post-renderer, a flag it does not know, a KUBECONFIG in the tree
    const before = readFileSync(log, "utf8");
    for (const c of ["helm upgrade api ./chart --kubeconfig ./kc", "helm --kube-apiserver https://evil.example upgrade api ./chart", "helm upgrade api ./chart --kube-token=t",
                     "helm upgrade api ./chart --post-renderer ./render.sh", "helm upgrade api ./chart --dry-run", "helm upgrade api ./chart --force", "helm upgrade api ./chart --frobnicate",
                     "helm upgrade api ./chart -o json", "helm upgrade api ./chart --repository-config ./repos.yaml", "helm install ./chart --generate-name"])
      assert.equal(gate(c, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})), null, `not run: ${c}`);
    assert.equal(gate("helm upgrade api ./chart", w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]", KUBECONFIG: join(w, "kc")})), null, "a KUBECONFIG inside the working directory");
    assert.equal(gate("helm upgrade api ./chart", w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]", KUBECONFIG: "kc"})), null, "a relative KUBECONFIG");
    assert.equal(readFileSync(log, "utf8"), before, "none of them ran helm");
    // the plugins: not newer than the mark, outside the tree, running only their own program
    const planted = why => { const r = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})); assert.ok(r.outcome === "ask" && r.id === "helm-diff-unreadable" && /helm diff not run/.test(r.rule), `${why}: ${JSON.stringify(r)}`); };
    markAt(Date.now() / 1000 - 3600);
    planted("a plugin changed after the mark");
    markAt(Date.now() / 1000 + 3600);
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})).id, "helm-diff", "and back");
    // an old mtime does not hide a new ctime: a mark after every plugin file, then only bin/diff rewritten and backdated
    const tMark = Date.now() / 1000;
    await new Promise(r => setTimeout(r, 50));
    markAt(tMark);
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})).id, "helm-diff", "a mark after the plugin files");
    writeFileSync(join(plug, "bin/diff"), "#!/bin/sh\necho planted\n"); utimesSync(join(plug, "bin/diff"), 1e9, 1e9);
    planted("touch -t cannot set the change time back");
    markAt(Date.now() / 1000 + 3600);
    mkdirSync(join(w, "evil-plugin"));
    writeFileSync(join(w, "evil-plugin/plugin.yaml"), "name: evil\ncommand: ${HELM_PLUGIN_DIR}/run\n");
    symlinkSync(join(w, "evil-plugin"), join(pluginsDir, "evil"));
    planted("a plugin linked into the working tree");
    rmSync(join(pluginsDir, "evil"));
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]", HELM_PLUGINS: join(w, "plugins")})), null, "an empty HELM_PLUGINS: not installed");
    mkdirSync(join(w, "plugins/helm-diff"), {recursive: true});
    writeFileSync(join(w, "plugins/helm-diff/plugin.yaml"), readFileSync(join(plug, "plugin.yaml")));
    g = gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]", HELM_PLUGINS: join(w, "plugins")}));
    assert.ok(g.outcome === "ask" && /in the working tree/.test(g.rule), `HELM_PLUGINS inside the tree: ${JSON.stringify(g)}`);
    assert.match(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]", HELM_PLUGINS: "plugins"})).rule, /a relative HELM_PLUGINS/);
    const yaml = readFileSync(join(plug, "plugin.yaml"), "utf8");
    writeFileSync(join(plug, "plugin.yaml"), yaml.replace("${HELM_PLUGIN_DIR}/bin/diff", join(w, "diff")));
    markAt(Date.now() / 1000 + 3600);
    planted("the diff plugin's command outside its directory");
    writeFileSync(join(plug, "plugin.yaml"), yaml);
    markAt(Date.now() / 1000 + 3600);
    rmSync(join(hconf, "config.json"));
    planted("no config.json to date the plugins by");
    writeFileSync(join(hconf, "config.json"), "{}"); markAt(Date.now() / 1000 + 3600);
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})).id, "helm-diff", "and back to safe");
    const hcalls = readFileSync(log, "utf8").split("\n").filter(l => l.startsWith("helm "));
    assert.ok(hcalls.length && hcalls.every(l => /^helm diff upgrade .* --output structured --no-color --suppress-secrets$/.test(l)), `only helm diff upgrade: ${hcalls.join(" | ")}`);
    assert.ok(!/  env HELM_(DIFF_|KUBETOKEN)/.test(readFileSync(log, "utf8")), "HELM_DIFF_TOOL, HELM_DIFF_OUTPUT and HELM_KUBETOKEN are not passed");
    // review round 1: every plugin's command is checked, a plugin.yaml too large to read asks, a helm-s3 style downloader passes
    mkdirSync(join(pluginsDir, "helm-s3"));
    writeFileSync(join(pluginsDir, "helm-s3/plugin.yaml"), 'name: "s3"\ncommand: "$HELM_PLUGIN_DIR/bin/helm-s3"\ndownloaders:\n- command: "bin/helm-s3 download"\n  protocols:\n    - "s3"\nhooks:\n  install: "cd $HELM_PLUGIN_DIR; ./hack/install.sh"\n');
    markAt(Date.now() / 1000 + 3600);
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})).id, "helm-diff", "a downloader plugin that runs its own program");
    writeFileSync(join(pluginsDir, "helm-s3/plugin.yaml"), 'name: "s3"\ndownloaders:\n- command: "/tmp/elsewhere/get"\n  protocols: ["s3"]\n');
    markAt(Date.now() / 1000 + 3600);
    planted("another plugin that runs a program outside its directory");
    writeFileSync(join(pluginsDir, "helm-s3/plugin.yaml"), `name: s3\n#${"x".repeat(70 * 1024)}\ncommand: /tmp/elsewhere/get\n`);
    markAt(Date.now() / 1000 + 3600);
    planted("a plugin.yaml too large to check");
    rmSync(join(pluginsDir, "helm-s3"), {recursive: true});
    markAt(Date.now() / 1000 + 3600);
    assert.equal(gate(up, w, hk, () => false, hEnv({FAKE_HELM_OUT: "[]"})).id, "helm-diff", "and back");
    assert.deepEqual(helmDiffArgs(helmChange(shellWords("helm install api ./c -nweb"))), ["diff", "upgrade", "api", "./c", "--namespace=web", "--allow-unreleased", "--output", "structured", "--no-color", "--suppress-secrets"]);
    assert.equal(helmChange(shellWords("helm uninstall api")), null, "uninstall is the rules'");

    // settings
    assert.equal(infraError({destroy: "allow"}), 'infra.destroy must be "deny" or "ask"');
    assert.equal(infraError({timeout_ms: 6000}), "infra.timeout_ms must be 100 to 4000");
    assert.match(infraError({kubectl: true}), /unknown key/);
    assert.equal(infraError({destroy: "ask", kubectl_diff: true}), null);
    assert.equal(infraSettings({destroy: "ask"}, {destroy: "deny"}).destroy, "deny", "a team can force deny");
    assert.equal(infraSettings({enabled: false}, {require_plan_in_prod: true}).enabled, true, "a team's infra section turns the gate on");
    assert.equal(infraSettings({require_plan_in_prod: true}, null).require_plan_in_prod, true);
    console.log("infra selfcheck ok");
  } finally { rmSync(tmp, {recursive: true, force: true}); rmSync(home, {recursive: true, force: true}); }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]) && process.argv.includes("--selfcheck"))
  selfcheck().catch(e => { console.error(e); process.exit(1); });   // not awaited: gate.mjs imports this module
