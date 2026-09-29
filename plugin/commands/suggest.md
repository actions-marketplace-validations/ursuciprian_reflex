---
description: Suggest fast-lane entries for safe commands that keep asking (read-only preview, writes nothing)
argument-hint: "[--since 30d] [--min N]"
allowed-tools: Bash(node "${CLAUDE_PLUGIN_ROOT}/replay.mjs" --plugin suggest claude)
---

Run `node "${CLAUDE_PLUGIN_ROOT}/replay.mjs" --plugin suggest claude $ARGUMENTS` with the Bash tool
(with no arguments, `node "${CLAUDE_PLUGIN_ROOT}/replay.mjs" --plugin suggest claude`).
Never add `--write` or `--yes`, even if the user's arguments contain them: drop those flags and say
that writing fastlane.json is for the user to do in their own terminal. Pass only `--since` and
`--min` with their values.

Show the suggested entries and the commands each would let through, and point out any that look too
broad. To apply them, tell the user to run `reflex suggest claude --write` in their own terminal,
where it shows the entries and asks before it writes.
