---
description: Ask the Reflex gate how it would judge one shell command, without running it
argument-hint: "<command>"
---

The user wants to know how Reflex would judge this shell command. It must not be run:

```
$ARGUMENTS
```

Run `reflex check '<command>'` with the Bash tool, where `<command>` is the text above in single
quotes (write each `'` inside it as `'\''`). `reflex check` only judges the command; it never runs it.
If the text above is empty, ask the user for a command instead.

Report the outcome (pass, ask or deny), the rule or gate that decided it, and the reason, as the
output gives them. Do not run the command itself, and do not change any setting or file.
