---
description: Suggest fast-lane entries for safe commands that keep asking (read-only preview, writes nothing)
argument-hint: "[--since 30d] [--min N]"
allowed-tools: Bash("${CLAUDE_PLUGIN_ROOT}/scripts/suggest.sh")
---

Run `"${CLAUDE_PLUGIN_ROOT}/scripts/suggest.sh" $ARGUMENTS` with the Bash tool (with no arguments,
the last 30 days of Claude Code sessions). The script takes only `--since` and `--min` with their
values and refuses anything else; it never writes. Drop `--write` and `--yes` if the user's arguments
contain them, and say that writing fastlane.json is for the user to do in their own terminal.

Show the suggested entries and the commands each would let through, and point out any that look too
broad. To apply them, tell the user to run `reflex suggest claude --write` in their own terminal,
where it shows the entries and asks before it writes.
