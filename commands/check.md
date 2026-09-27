---
description: Ask the Reflex gate how it would judge one shell command, without running it
argument-hint: "<command>"
allowed-tools: Bash(reflex check *)
---

The user wants to know how Reflex would judge this shell command. It must not be run:

```
$ARGUMENTS
```

Run `reflex check '<command>'` with the Bash tool, where `<command>` is the text above in single
quotes (write each `'` inside it as `'\''`). `reflex check` only judges the command; it never runs it.
If the text above is empty, ask the user for a command instead.

The output is JSON: report `decision` (pass, ask or deny), `rule` and `source` as given. If the Bash
call itself was blocked by a hook, `reflex check` did not run: say so, and give the user the
`reflex check` command to run in their own terminal. Do not run the command itself, and do not
change any setting or file.
