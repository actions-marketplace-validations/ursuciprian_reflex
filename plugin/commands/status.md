---
description: Show whether the Reflex gate is active, its mode and engine, and whether the plugin or reflex setup runs the hooks
allowed-tools: Bash(node "${CLAUDE_PLUGIN_ROOT}/status.mjs" --plugin --status), Bash(node "${CLAUDE_PLUGIN_ROOT}/status.mjs" --plugin --status --json)
---

Run `node "${CLAUDE_PLUGIN_ROOT}/status.mjs" --plugin --status` with the Bash tool and report the
result to the user in a few lines: the mode, the engine, which install path runs the hooks of each
agent (a plugin, or the `reflex setup` hooks), and every `Error:` and `Note:` line as written.

Do not change any setting, mode or file. If the user wants to change the mode, the engine or the key,
tell them to set it in the plugin's options (`/plugin`, then reflex, then Configure) instead.

If the script path above is not an absolute path (Codex CLI does not fill in the plugin root), use
`reflex status` instead.
