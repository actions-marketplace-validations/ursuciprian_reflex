---
description: Replay past Claude Code sessions through the Reflex gate to see what it would have denied or asked (nothing runs)
argument-hint: "[claude|codex|opencode|pi|all] [--since 7d] [--engine local|jev|laya]"
allowed-tools: Bash(reflex replay claude --since 7d)
---

Run `reflex replay $ARGUMENTS` with the Bash tool (with no arguments, `reflex replay claude --since 7d`).
Replay reads past session transcripts and judges each command again; it never runs a command.
Pass only replay arguments the user gave; if the arguments contain anything else, run the default
and say so. `--engine jev` sends redacted commands to TypeSafe; tell the user before you run it.

Summarize for the user: how many commands were replayed, how many the gate would have denied or
asked, the rules behind them, and a few example commands quoted exactly. Suggest `/reflex:suggest`
when the same safe commands keep asking. This is read-only: do not change any setting or file.
