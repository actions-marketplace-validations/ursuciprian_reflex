# Reflex for Claude Code

Reflex is a pre-execution gate for Claude Code. Before a Bash command or a subagent spawn runs, it
judges where the command points and what it would change, then lets it through, asks you, or blocks
it. It also screens web, MCP and Read results and your prompts for prompt injection.

This directory is the Claude Code plugin, generated from the Reflex repository by
`node scripts/build-plugin.mjs`. Do not edit it by hand.

## What the plugin does

- PreToolUse on Bash, Task, Agent, the file tools and MCP tools: the gate answers ask or deny, or
  stays silent. It never answers allow and never rewrites a tool's input, so Claude Code's own
  permission rules still decide everything it does not block.
- PostToolUse on web, MCP, Read and Bash results: the injection guard adds a warning next to a result
  that tries to instruct the agent. It never rewrites the result.
- UserPromptSubmit: the instruction layer and the pasted-credential check.
- Commands: `/reflex:check`, `/reflex:status`, `/reflex:report`, `/reflex:replay`, `/reflex:suggest`
  and `/reflex:queue`, all read-only. Each runs a plain shell script in `scripts/` that refuses any
  argument the command does not list, then runs one module with node.
- An MCP server with the same read-only tools.

## For reviewers

- The plugin never launches another agent session and never pre-answers a permission prompt; System 2
  in the plugin is API-only via the judge_api_key option. The only processes it starts are `node`
  (its own modules), `git`, `sed --version`, and the `terraform`, `tofu`, `kubectl` or `helm` found on
  `PATH` to read a saved plan or a dry-run diff. A System 2 approval is a plain pass: the hook stays
  silent and Claude Code's own permission prompt decides. A `judge.backend` of `cli` in
  `~/.config/reflex/config.json` (what `reflex setup` may pick) is off in the plugin, and
  `/reflex:status` says so. The build fails when the bundle names a flag or setting that turns an
  agent's prompts or hooks off, or starts any other program.
- The hooks, the MCP server and the command scripts run the plugin's own modules with `node`. Nothing
  is downloaded or installed, and the plugin has no dependencies.
- Text such as a download piped to a shell appears only inside detection patterns (the rules and the
  injection detectors in `setup/`), which Reflex matches against commands and tool results. Nothing
  runs it.
- Keys come only from the plugin options: the Jev API key goes to the Jev provider chosen in the
  options (each named provider's key to its own host only; `compatible` to the URL in config.json),
  the System 2 API key only to the System 2 endpoint named in
  `~/.config/reflex/config.json` (Anthropic's API for the `anthropic` backend). The hooks remove every
  `*_API_KEY` and `*_API_TOKEN` variable from their environment and never read the Keychain.
- Files the gate reads to judge where a command points, never sent anywhere: the kube context name
  from the kubeconfig, `dev_overrides` and `plugin_cache_dir` from the Terraform and OpenTofu CLI
  config, whether `~/.npmrc` sets a script shell, Claude Code's and Codex's settings (to stand down
  when `reflex setup` hooks exist), and Reflex's own files under `~/.config/reflex/`.

## Settings

Set them in `/plugin`, then reflex, then Configure:

- engine: `local` (rules only, no key, nothing leaves the machine) or `jev` (hosted classification).
- provider: the Jev provider, `typesafe` by default.
- Jev API key: stored in your system's secure storage. The plugin reads its key from this option
  only, never from the Keychain or an environment variable.
- mode: `off`, `shadow` (the default: logs, while deterministic rules still ask and deny) or `enforce`.
- System 2 API key: optional, for a System 2 judge configured in `~/.config/reflex/config.json`
  with backend `anthropic` or `openai-compatible`. The `cli` backend is not used by the plugin.

Other settings come from `~/.config/reflex/config.json`. Decision logs go to
`~/.local/state/reflex` (or `REFLEX_DATA_DIR`).

## More

Documentation, the rules and the source: https://github.com/ursuciprian/reflex

License: MIT
