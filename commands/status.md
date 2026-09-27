---
description: Show whether the Reflex gate is active, its mode and engine, and whether the plugin or reflex setup runs the hooks
allowed-tools: Bash(reflex status), Bash(reflex status --json)
---

Run `reflex status` with the Bash tool and report the result to the user in a few lines:
the mode, the engine, which install path runs the Claude Code hooks (the plugin, or `reflex setup`
hooks in settings.json), and every `Error:` and `Note:` line as written.

`reflex` is on the Bash PATH while this plugin is enabled. Do not change any setting, mode or file.
If the user wants to change the mode or the engine, show the command for them to run in their own
terminal (for example `reflex setup --mode enforce`) instead of running it.
