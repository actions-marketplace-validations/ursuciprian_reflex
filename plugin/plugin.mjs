// Claude Code plugin mode: what the gate reads when the Claude Code plugin runs it (hooks/hooks.json
// passes --plugin; .mcp.json and the plugin's commands set REFLEX_PLUGIN=1 or pass --plugin).
//
// The plugin takes its settings from two places only: the options the user set for the plugin in
// Claude Code (plugin.json userConfig; Claude Code gives hooks each one as CLAUDE_PLUGIN_OPTION_<KEY>,
// and .mcp.json hands the same names to the MCP server) and Reflex's own config files
// (~/.config/reflex/). Never the macOS Keychain, never a key that is already in the environment
// (no *_API_KEY or *_API_TOKEN variable, the providers' included), never the REFLEX_* overrides (only
// REFLEX_DATA_DIR, where the logs go, is kept). The plugin's commands run through the Bash tool,
// which gets no plugin options: they read config.json only. The allow gate
// is off: a plugin hook only tightens, it never answers "allow" and never rewrites a tool's input.
//
// gate.mjs imports this module first (guard.mjs, instructions.mjs and status.mjs too), so every module
// after it sees the cleaned environment, and so does every child it starts. The Codex CLI plugin
// (--codex hooks) is not this: it keeps reading the environment as before.

const E = process.env, argv = process.argv;
export const PLUGIN_FLAG = argv.includes("--plugin");
export const PLUGIN_MODE = E.REFLEX_PLUGIN === "1" || (PLUGIN_FLAG && !argv.some(a => /^--codex(-|$)/.test(a)));
/** What a source that may let a command skip the agent's prompt answers (a calibrated Jev answer,
 *  a System 2 approval, a human's queue approval, the workspace allowlist). The plugin never allows,
 *  so there it is a plain pass at the source. Outside the plugin it is "allow", which gate.mjs
 *  allowSetting keeps only with REFLEX_ALLOW on in enforce mode. */
export let APPROVED = "pass";
/** The option the user set in Claude Code, trimmed; undefined when unset or empty. */
export const option = key => E[`CLAUDE_PLUGIN_OPTION_${key}`]?.trim() || undefined;
// What the plugin must not take from the environment: every REFLEX_* setting (engine, mode, allow,
// endpoint, policy directory, guard, judge, queue...) but where its logs go, every JEV_* variable,
// and every variable a key is read from.
export const KEY_VAR = /_API_(KEY|TOKEN)$|^CLOUDFLARE_ACCOUNT_ID$/;   // every provider key variable and the System 2 ones (test.mjs checks)
const KEEP = new Set(["REFLEX_PLUGIN", "REFLEX_DATA_DIR"]);
// REFLEX_NOTIFY=off can only silence the webhook (the doctor's probes set it), so it stays too.
const scrubbed = k => (KEY_VAR.test(k) && !k.startsWith("CLAUDE_PLUGIN_OPTION_")) || k.startsWith("JEV_") || (k.startsWith("REFLEX_") && !KEEP.has(k) && !(k === "REFLEX_NOTIFY" && E[k] === "off"));
/** Hooks get every option as CLAUDE_PLUGIN_OPTION_<KEY>; a command Claude runs with the Bash tool gets none. */
export const OPTIONS_VISIBLE = Object.keys(E).some(k => k.startsWith("CLAUDE_PLUGIN_OPTION_"));
export const PLUGIN_ENGINES = ["local", "jev"];
export let PLUGIN_ERROR = null;
if (PLUGIN_MODE) {
  for (const k of Object.keys(E)) if (scrubbed(k)) delete E[k];
  E.REFLEX_PLUGIN = "1";
  E.REFLEX_ALLOW = "off";
  const engine = option("ENGINE"), provider = option("PROVIDER"), mode = option("MODE");
  if (engine && !PLUGIN_ENGINES.includes(engine)) PLUGIN_ERROR = "plugin option engine must be local or jev";
  if (engine) E.REFLEX_ENGINE = engine;
  if (provider) E.REFLEX_PROVIDER = provider;
  if (mode) E.REFLEX_MODE = mode;
  // Each CLI parses its own arguments; --plugin is this module's, so they never see it.
  if (PLUGIN_FLAG) argv.splice(argv.indexOf("--plugin"), 1);
}
/** The Jev API key from the plugin options, or null. Only in plugin mode. */
export const pluginKey = () => PLUGIN_MODE ? option("JEV_API_KEY") ?? null : null;
/** The System 2 key from the plugin options, or null. Only in plugin mode. */
export const pluginJudgeKey = () => PLUGIN_MODE ? option("JUDGE_API_KEY") ?? null : null;
