# Reflex for Claude Code

Reflex is a pre-execution gate for Claude Code. Before a Bash command or a subagent spawn runs, it
judges where the command points and what it would change, then lets it through, asks you, or blocks
it. It also screens web, MCP and Read results and your prompts for prompt injection.

This directory is the Claude Code plugin, generated from the Reflex repository by
`node scripts/build-plugin.mjs`. Do not edit it by hand.

## What the plugin does

- PreToolUse on Bash, Task and Agent: the gate answers ask or deny, or stays silent. It never
  answers allow and never rewrites a tool's input, so Claude Code's own permission rules still decide
  everything it does not block.
- PostToolUse on web, MCP, Read and Bash results: the injection guard adds a warning next to a result
  that tries to instruct the agent. It never rewrites the result.
- UserPromptSubmit: the instruction layer and the pasted-credential check.
- Commands: `/reflex:check`, `/reflex:status`, `/reflex:report`, `/reflex:replay`, `/reflex:suggest`
  and `/reflex:queue`, all read-only.
- An MCP server with the same read-only tools.

## Settings

Set them in `/plugin`, then reflex, then Configure:

- engine: `local` (rules only, no key, nothing leaves the machine) or `jev` (hosted classification).
- provider: the Jev provider, `typesafe` by default.
- Jev API key: stored in your system's secure storage. The plugin reads its key from this option
  only, never from the Keychain or an environment variable.
- mode: `off`, `shadow` (the default: logs, while deterministic rules still ask and deny) or `enforce`.
- System 2 API key: optional, for a System 2 judge configured in `~/.config/reflex/config.json`.

Other settings come from `~/.config/reflex/config.json`. Decision logs go to
`~/.local/state/reflex` (or `REFLEX_DATA_DIR`).

## More

Documentation, the rules and the source: https://github.com/ursuciprian/reflex

License: MIT
