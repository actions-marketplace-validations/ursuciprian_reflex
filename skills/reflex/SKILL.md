---
name: reflex
description: How to work with the Reflex pre-execution gate in Claude Code. Use when a Bash command was denied or asked by Reflex, when unsure whether a shell command is risky before running it, or when the user asks what Reflex would have blocked in past sessions.
---

Reflex judges every Bash command and subagent spawn before it runs (PreToolUse hook) and screens
web, MCP and Read results and user prompts for prompt injection. `reflex` is on the Bash PATH while
this plugin is enabled.

When to use which command:

- `reflex check '<command>'`: before running a shell command whose risk is unclear (a delete, a push,
  a deploy, anything touching production or credentials), ask the gate how it would judge it. It only
  judges; it never runs the command. Quote the command in single quotes.
- `reflex replay claude --since 7d`: when the user asks what Reflex would have blocked or asked in past
  sessions, or before switching from shadow to enforce mode. It reads transcripts; nothing runs.
- `reflex status`: when the user asks whether Reflex is on, which mode it is in, or whether the plugin
  or `reflex setup` runs the hooks.
- `reflex report`: what the gate decided recently.

When Reflex denies or asks for a command:

- Read the reason in the hook message. Do not retry the same command with small changes to get past a
  rule, and do not wrap it in a script, `eval`, `sh -c` or a different tool to avoid the gate.
- Explain the decision to the user and offer a safer alternative, or let the user run it themselves.

Never change Reflex's own configuration: do not edit `~/.config/reflex/`, the Claude Code settings
files or the plugin's files, and do not run `reflex setup`, `reflex install`, `reflex uninstall`,
`reflex queue approve|deny|clear` or `reflex suggest --write`. Those are the user's decisions; show
the user the command to run in their own terminal instead.
