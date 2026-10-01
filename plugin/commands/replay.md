---
description: Replay past Claude Code sessions through the Reflex gate to see what it would have denied or asked (nothing runs)
argument-hint: "[claude|codex|opencode|pi|all] [--since 7d] [--engine local|jev]"
allowed-tools: Bash("${CLAUDE_PLUGIN_ROOT}/scripts/replay.sh")
---

Run `"${CLAUDE_PLUGIN_ROOT}/scripts/replay.sh" $ARGUMENTS` with the Bash tool (with no arguments it
replays `claude --since 7d`).
Replay reads past session transcripts and judges each command again; it never runs a command.
The script takes only an agent name, `--since` and `--engine local` or `--engine jev`, and refuses
anything else: if the arguments contain anything else, run it without arguments and say so.
`--engine jev` sends redacted commands to the Jev provider; tell the user before you run it.

Summarize for the user: how many commands were replayed, how many the gate would have denied or
asked, the rules behind them, and a few example commands quoted exactly. Suggest `/reflex:suggest`
when the same safe commands keep asking. This is read-only: do not change any setting or file.
