---
description: Summarize what the Reflex gate decided recently (denies, asks, passes, rules that fired)
argument-hint: "[--since 30] [--list ask|deny|pass] [--calibration]"
allowed-tools: Bash(reflex report)
---

Run `reflex report $ARGUMENTS` with the Bash tool (with no arguments, the last 7 days). Pass only
`--since <days>`, `--list <outcome>` and `--calibration` from the user's arguments.
Never pass `--push`, which sends metrics out; drop anything else and say so.

Summarize for the user: how many commands were judged, how many were denied or asked, which rules
fired most, and anything the report flags as unusual. Quote rule names and commands exactly.
This is read-only: do not change any setting or file.
