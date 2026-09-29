# Reflex security policy: reporting vulnerabilities and known limits

Report a vulnerability by opening a [private security advisory](https://github.com/ursuciprian/reflex/security/advisories/new).
Do not open a public issue for an exploitable weakness. You get an acknowledgement within 5 working
days and a fix or a written position within 30.

## What Reflex is

A filter that sits in a coding agent's pre-execution hook and can only make the agent ask or stop.
It is not a sandbox and not a substitute for IAM, network controls or least-privilege credentials.
Read [docs/GUIDE.md → Safety properties and limits](docs/GUIDE.md#safety-properties-and-limits)
before triaging a report.

Two properties bound the attack surface:

- By default the gate never emits `allow`, so a wrong decision adds a prompt; it cannot remove one
  your agent's own permission rules require. `REFLEX_ALLOW=on` is opt-in and, if miscalibrated, can.
- In enforce mode a Jev failure, timeout or internal error yields the policy fallback (`ask`),
  never a pass.

## In scope

- A command that reaches a hook and is passed (`pass`) instead of asked or denied, where the
  command actually mutates outside the working tree, exfiltrates, or targets production. Include the
  exact command, the working directory, the environment context and `reflex check "<cmd>" --cwd <dir>`
  output.
- A secret that leaves the machine unredacted in a Jev request or in a log line
  (`~/.local/state/reflex/`), or a credentials file such as `.env` being read and sent.
- A hook that fails open in enforce mode: an error path that returns a pass instead of the policy
  fallback.
- Write access to Reflex's own state (`~/.local/state/reflex/`, its cache, `setup/*.json`, the
  instruction fragments it injects) that lets an agent steer a later decision, given the permission
  rules `install.mjs` installs for it.
- The cache: a decision reused for a command that is materially different from what was judged.
- Script inspection: a launcher `gate.mjs` recognises that runs code Jev never saw, beyond the
  documented two-level and 256 KB limits.
- A way to make an adapter (`adapters/pi.ts`, `adapters/opencode.js`, `scripts/reflex-sh`) run a command
  without calling the gate.

## Out of scope

- Bypasses that need shell semantics Reflex documents as pattern matching rather than a parser:
  variable indirection set outside the script, more than two levels of launcher nesting, danger past
  256 KB in one file, aliases or functions defined in a persistent shell. These fail towards `ask
  Jev`; the residual risk is stated in the limits section.
- Anything the agent can do through a tool Reflex does not gate: file-edit tools, MCP tools,
  `eval`, `execute_code`, network from inside a permitted process. Each agent's own permissions
  govern those; the tool router is the only component that gates its own MCP calls.
- Prompt injection that only changes the agent's *stated* intent so the command looks on-task. Jev
  answers `on_task` and `injection` as signals into a policy; neither is an enforcement boundary.
- Attacks on the agent itself, its provider, or your provider's account.
- Findings that need the victim to have installed with `--context` or the tool router and are
  specific to those opt-ins are still welcome, but say so: both are experimental.

## Third party

With the Jev engine, judging is done by TypeSafe's hosted Jev model, so judged data does leave the machine: exactly what
is sent, and what is redacted first, is listed in
[docs/GUIDE.md → Data handling](docs/GUIDE.md#data-handling). TypeSafe's
[data processing agreement](https://typesafe.ai/legal/data-processing) applies; Reflex has no
control over their retention.

Local mode makes no TypeSafe calls. `reflex run` executes in the human's terminal after the same
checks; it never issues an approval token to an agent. Its terminal is not an authentication boundary
against software that controls that terminal. Hook health records are diagnostics, not attestation.
