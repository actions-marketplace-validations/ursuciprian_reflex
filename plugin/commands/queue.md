---
description: List the Reflex approval queue (commands parked for a human decision)
argument-hint: "[show <id>]"
allowed-tools: Bash("${CLAUDE_PLUGIN_ROOT}/scripts/queue.sh" list)
---

Run `"${CLAUDE_PLUGIN_ROOT}/scripts/queue.sh" list` with the Bash tool, or
`"${CLAUDE_PLUGIN_ROOT}/scripts/queue.sh" show <id>` when the user gave `show <id>`.
Report each pending item: its id, the command, why it was parked and when it expires.

This is read-only, and the script takes nothing else. Never try to approve, deny or clear an item:
the queue exists so that a human decides. Tell the user to run `reflex queue approve <id>` or
`reflex queue deny <id>` in their own terminal.

If the script path above is not an absolute path (Codex CLI does not fill in the plugin root), use
`reflex queue list` instead.
