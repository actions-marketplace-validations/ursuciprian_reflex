---
description: List the Reflex approval queue (commands parked for a human decision)
argument-hint: "[show <id>]"
allowed-tools: Bash(reflex queue list)
---

Run `reflex queue list` with the Bash tool, or `reflex queue show <id>` when the user gave
`show <id>`. Report each pending item: its id, the command, why it was parked and when it expires.

This is read-only. Never run `reflex queue approve`, `deny` or `clear`: the queue exists so that a
human decides. Tell the user to run `reflex queue approve <id>` or `reflex queue deny <id>` in their
own terminal.
