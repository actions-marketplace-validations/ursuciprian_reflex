---
description: Ask the Reflex gate how it would judge one shell command, without running it
argument-hint: "<command>"
allowed-tools: Bash(node "${CLAUDE_PLUGIN_ROOT}/gate.mjs" --plugin --check *)
---

The user wants to know how Reflex would judge this shell command. It must not be run:

```
$ARGUMENTS
```

Run `node "${CLAUDE_PLUGIN_ROOT}/gate.mjs" --plugin --check '<command>'` with the Bash tool, where
`<command>` is the text above in single quotes (write each `'` inside it as `'\''`). It only judges
the command; it never runs it. With the `jev` engine it sends the redacted command to the Jev
provider for the judgment, as the gate does for every command.
If the text above is empty, ask the user for a command instead.

The output is JSON: report `decision` (pass, ask or deny), `rule` and `source` as given. If the Bash
call itself was blocked by a hook, the check did not run: say so. Do not run the command itself, and
do not change any setting or file.
