---
description: Replay past Claude Code sessions through the Reflex gate to see what it would have denied or asked (nothing runs)
argument-hint: "[claude|codex|opencode|pi|all] [--since 7d] [--engine local|jev]"
allowed-tools: Bash(node "${CLAUDE_PLUGIN_ROOT}/replay.mjs" --plugin replay claude --since 7d)
---

Run `node "${CLAUDE_PLUGIN_ROOT}/replay.mjs" --plugin replay $ARGUMENTS` with the Bash tool (with no
arguments, `node "${CLAUDE_PLUGIN_ROOT}/replay.mjs" --plugin replay claude --since 7d`).
Replay reads past session transcripts and judges each command again; it never runs a command.
Pass only replay arguments the user gave (an agent name, `--since`, `--engine local` or `--engine jev`);
if the arguments contain anything else, run the default and say so. `--engine jev` sends redacted
commands to the Jev provider; tell the user before you run it.

Summarize for the user: how many commands were replayed, how many the gate would have denied or
asked, the rules behind them, and a few example commands quoted exactly. Suggest `/reflex:suggest`
when the same safe commands keep asking. This is read-only: do not change any setting or file.
