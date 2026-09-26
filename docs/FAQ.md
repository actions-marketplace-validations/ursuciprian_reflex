# Reflex FAQ: guardrails and command approval for Claude Code, Codex CLI and other AI coding agents

Answers to the questions people ask about Reflex, each checked against the code and the other
docs. The short version of this page is the [FAQ section of the README](../README.md#faq).

- [What is Reflex?](#what-is-reflex)
- [How do I stop Claude Code from running dangerous commands?](#how-do-i-stop-claude-code-from-running-dangerous-commands)
- [How is Reflex different from Claude Code permission prompts and allowlists?](#how-is-reflex-different-from-claude-code-permission-prompts-and-allowlists)
- [Can I use Reflex with --dangerously-skip-permissions?](#can-i-use-reflex-with---dangerously-skip-permissions)
- [Do I still need a devcontainer or a sandbox if I use Reflex?](#do-i-still-need-a-devcontainer-or-a-sandbox-if-i-use-reflex)
- [What guardrails can I add to Codex CLI, and how does Reflex work with the Codex sandbox?](#what-guardrails-can-i-add-to-codex-cli-and-how-does-reflex-work-with-the-codex-sandbox)
- [How is Reflex different from abide?](#how-is-reflex-different-from-abide)
- [Which AI coding agents does Reflex support?](#which-ai-coding-agents-does-reflex-support)
- [Does Reflex need an API key, an account or LiteLLM?](#does-reflex-need-an-api-key-an-account-or-litellm)
- [What is TypeSafe Jev (System One)?](#what-is-typesafe-jev-system-one)
- [Jev vs Laya: which engine should I use?](#jev-vs-laya-which-engine-should-i-use)
- [How much does Reflex cost to run?](#how-much-does-reflex-cost-to-run)
- [How much latency does Reflex add?](#how-much-latency-does-reflex-add)
- [Does Reflex send my code anywhere?](#does-reflex-send-my-code-anywhere)
- [What happens when Jev is down or slow?](#what-happens-when-jev-is-down-or-slow)
- [Does Reflex protect coding agents against prompt injection?](#does-reflex-protect-coding-agents-against-prompt-injection)
- [How do I reduce permission prompts in Claude Code and approve agent commands automatically but safely?](#how-do-i-reduce-permission-prompts-in-claude-code-and-approve-agent-commands-automatically-but-safely)
- [Can Reflex run autonomous coding agents with no human watching?](#can-reflex-run-autonomous-coding-agents-with-no-human-watching)
- [How do I try Reflex safely before enforcing it?](#how-do-i-try-reflex-safely-before-enforcing-it)
- [How do I uninstall Reflex?](#how-do-i-uninstall-reflex)

## What is Reflex?

Reflex is an open-source (MIT) pre-execution risk gate and prompt injection guard for AI coding
agents such as Claude Code, Codex CLI, opencode and pi. It hooks into the agent and decides, for
every shell command the agent wants to run, whether it runs, needs a human's approval, or is
blocked; it also scans what the agent reads for prompt injection. Decisions come from local rules
first, then from the engine you pick: `local` (no key), TypeSafe Jev (a hosted System One model)
or Laya (experimental, on your machine). It is published on npm as `@ursuciprian/reflex`.

See: [README](../README.md), [how a command is decided](../README.md#how-a-command-is-decided).

## How do I stop Claude Code from running dangerous commands?

Install Reflex, which adds a Claude Code `PreToolUse` hook that checks every Bash command before it
runs: `npx @ursuciprian/reflex setup`. Its deterministic rules deny `rm -rf ~`, destructive
operations on production and force pushes to `main`, and ask before reads of SSH private keys,
`~/.aws/credentials`, `.netrc`, `.pgpass`, `.env` files or Kubernetes secrets; the rules block in
shadow mode too. Commands the rules do not cover are asked about (local engine) or judged by Jev
in context (AWS profile, kube context, Terraform workspace, git branch, the script the command
runs). After a shadow period, `reflex setup --mode enforce` puts those judgments in front of the
agent.

See: [docs/SETUP.md](SETUP.md), [real-world scenarios with outputs](../README.md#real-world-scenarios-with-outputs).

## How is Reflex different from Claude Code permission prompts and allowlists?

Claude Code's permission rules match tools and command prefixes; Reflex judges each shell command
by what it does and where it points. It reads the local script, make target or package script a
command runs, and knows the AWS profile, kube context, Terraform workspace and git branch. By
default Reflex only emits `ask` or `deny` and leaves `pass` to your permission settings, so your
allowlist keeps working. Claude Code's own rules cover file edits, web fetches and MCP tools, which
Reflex does not gate.

See: [compared with other AI coding agent guardrails](../README.md#compared-with-other-ai-coding-agent-guardrails).

## Can I use Reflex with --dangerously-skip-permissions?

Yes: with prompts turned off, Reflex's rule denies still apply. In the autonomous profile, a
command that needs a human is parked in the approval queue and returned to the agent as a deny with
a queue id, so the run continues while the command waits for you. Only shell commands (and
subagent spawns) are gated, so file edits and MCP calls run unchecked in that mode.

See: [comparison table](../README.md#compared-with-other-ai-coding-agent-guardrails),
[GUIDE: the approval queue](GUIDE.md#the-approval-queue).

## Do I still need a devcontainer or a sandbox if I use Reflex?

Keep one if you have one: a sandbox limits what any command can reach, Reflex decides per command,
and the two work together. A container still holds whatever cloud credentials, kube configs and
SSH keys are mounted into it, and those reach production from inside; Reflex judges the commands
that use them and scans what the agent reads. Keep IAM, network controls and least-privilege
credentials as well.

See: [comparison table](../README.md#compared-with-other-ai-coding-agent-guardrails),
[GUIDE: safety properties and limits](GUIDE.md#safety-properties-and-limits).

## What guardrails can I add to Codex CLI, and how does Reflex work with the Codex sandbox?

Reflex adds Codex hooks (`PreToolUse` and `PostToolUse` in `~/.codex/hooks.json`) that judge each
Bash command inside whatever sandbox mode and approval policy Codex runs with; those stay in
charge. Codex hooks cannot show a prompt or approve, so a Reflex `ask` blocks with a reason, and the
human runs the exact command with `reflex run "command" --cwd /path` in their own terminal. The
injection guard reads Bash and MCP results in Codex (web search is not hookable). Hooks must be
trusted once in Codex's `/hooks` before they run.

See: [supported agents](../README.md#supported-agents-claude-code-hooks-codex-hooks-and-more),
[docs/SETUP.md: install the hooks](SETUP.md#3-install-the-hooks-shadow-mode).

## How is Reflex different from abide?

[abide](https://github.com/coldteadotai/abide) checks the code an agent writes against your
`AGENTS.md` or project rules, using Jev; Reflex gates shell commands and scans tool results before
the agent acts on them. They are complementary, and both can run on the same agent.

See: [comparison table](../README.md#compared-with-other-ai-coding-agent-guardrails).

## Which AI coding agents does Reflex support?

Claude Code, Codex CLI, pi, oh-my-pi, opencode and Hermes, each through its own hook system; any
other agent can use `bin/reflex-sh` as its shell. Setup hooks every supported agent it finds, or
the ones you name with `--agents claude,codex`. Reflex needs Node.js 18+ on macOS or Linux,
including WSL; native Windows is not supported yet.

See: [supported agents](../README.md#supported-agents-claude-code-hooks-codex-hooks-and-more),
[docs/SETUP.md](SETUP.md).

## Does Reflex need an API key, an account or LiteLLM?

No. New installs use the local engine: rules, the read-only list and the fast lane, with no
account, no key and no network calls. A TypeSafe API key is needed only for `--engine jev`; the
experimental Laya engine runs on 127.0.0.1 with no key (it needs Python 3.10+). LiteLLM is needed
only for the optional model routing hook, and the gate never uses it. Some optional features need
Jev: subgoal dedup, semantic instruction selection, model routing and the context layer.

See: [docs/SETUP.md: start locally](SETUP.md#1-start-locally-or-enable-hosted-classification).

## What is TypeSafe Jev (System One)?

Jev is TypeSafe's small System One model: it answers typed questions (probabilities, scores and
choices) about a piece of state, through TypeSafe's System One API. For each command the rules do
not settle, Reflex sends one request with six questions (`mutates`, `blast`, `env`, `exfil`,
`on_task`, `injection`; eight with a task envelope), and your `policy.json` turns the answers into
pass, ask or deny. The pinned model is `jev-1.13.0`; on the tool gate golden set it labelled all 97
commands as expected with 0 misses. Keys come from the [TypeSafe console](https://console.typesafe.ai/keys).

See: [how a command is decided](../README.md#how-a-command-is-decided),
[TypeSafe docs](https://docs.typesafe.ai).

## Jev vs Laya: which engine should I use?

Use Jev for decisions; Laya is experimental and measured below Jev on every golden set. Laya runs a
[Laya checkpoint](https://huggingface.co/convaiinnovations/laya) on 127.0.0.1, so nothing leaves
the machine and a call costs nothing, with a tool gate p50 of 125 ms on an Apple M5 Max against
Jev's 300 to 330 ms over the network. On the tool gate golden set Laya got 64 of 97 commands right
with 33 over-strict (Jev 97, 0, 0), and on the injection golden set precision 54 % against 97 %. Use
Laya to run fully offline in shadow mode; for keyless enforcement, the local engine is the
recommended choice.

See: [Jev vs Laya, head to head](../README.md#measured-results),
[GUIDE: measured against Jev](GUIDE.md#measured-against-jev).

## How much does Reflex cost to run?

Reflex is free and MIT licensed, and the local and Laya engines cost nothing per call. With Jev, a
command the rules leave open costs about 1k input tokens; TypeSafe publishes no price list, so
replay estimates spend at $0.04 per million input tokens (set `REFLEX_JEV_USD_PER_MTOK` to your
price). On one engineer's week of 13,743 Claude Code commands, that estimate was about $0.47.
Read-only, rule and fast-lane commands need no API call, and identical commands in the same context
are cached for 24 hours. In the autonomous profile a System 2 call with the `claude` CLI measured
$0.004 to $0.016 at API prices, capped by default at 200 calls and $5 a day (300 calls keyless).

See: [cost and latency](../README.md#cost-and-latency), [GUIDE: System 2](GUIDE.md#system-2).

## How much latency does Reflex add?

Commands settled by the read-only list, the rules or the fast lane make no network call. A Jev call
took 0.35 to 0.42 s in the README scenarios (the GUIDE's figure is about 0.7 s in enforce mode),
with a 3 s budget after which the policy's fallback applies. In shadow mode Jev runs in a detached
background process, so the agent does not wait. A System 2 escalation with the `claude` CLI takes 3
to 4 s; Laya answered the tool gate in 125 ms p50 on an Apple M5 Max, but a CPU-only machine can
exceed the 3 s budget. `reflex bench` measures it on your machine.

See: [cost and latency](../README.md#cost-and-latency), [GUIDE: replay and bench](GUIDE.md#replay-and-bench).

## Does Reflex send my code anywhere?

Not with the default local engine: nothing leaves the machine. With Jev, only commands that reach
Jev send data to TypeSafe: the command with secrets redacted, the working directory path,
environment names (AWS profile, region, kube context, Terraform workspace, git branch), the agent's
last message and last five commands (redacted and truncated), and the first 16 KB of a local script
the command runs (redacted, never a credentials file such as `.env`). With the injection guard on
Jev, up to 8 redacted chunks of 3,000 characters of an inspected tool result are sent. The Laya
engine sends to 127.0.0.1 only, and System 2 sends a redacted case of at most 1,500 tokens to the
backend you chose.

See: [GUIDE: data handling](GUIDE.md#data-handling).

## What happens when Jev is down or slow?

The policy's fallback applies, which is `ask`: in enforce mode a human reviews the command, and
nothing is auto-approved. The rules, the read-only list and the fast lane run locally and keep
working. In shadow mode Jev only logs from a background process, so the agent is not affected. In
the autonomous profile those asks go to System 2, and a breaker pauses System 2 when more than 30 %
of judged commands escalate within an hour, so an outage fills the approval queue instead of the
bill. A Laya server that is down behaves the same way.

See: [GUIDE: safety properties and limits](GUIDE.md#safety-properties-and-limits),
[GUIDE: System 2](GUIDE.md#system-2).

## Does Reflex protect coding agents against prompt injection?

Yes, as a filter: the injection guard scans tool results from the web, MCP servers, files outside
the project and network commands for text written to steer the agent (hidden Unicode, instructions
in HTML comments or hidden elements, text addressed to an AI, markdown image exfiltration, encoded
payloads). In enforce mode it warns the agent or removes the text, then makes the rest of the
session stricter: network egress asks and nothing is auto-approved. In enforce mode it also blocks
prompts that contain a pasted credential. On a 62-case golden set Jev reached 97 % precision and 100 % recall,
the local detectors 81 % and 79 %; an injection written as ordinary prose can pass the local
detectors.

See: [GUIDE: injection guard](GUIDE.md#injection-guard); try it with `reflex scan page.html`.

## How do I reduce permission prompts in Claude Code and approve agent commands automatically but safely?

Use calibrated allow with the Jev engine: in enforce mode with `--allow on`, commands Jev judges
clearly safe (low blast radius at high confidence, low mutation, exfiltration and injection scores,
on task, local environment) skip Claude Code's permission prompt. Rule outcomes, commands without a
stated intent, code Jev did not see in full, commands run from the home directory or `/`, and
cached answers are never allowed, and Claude Code's own deny and ask rules still apply. Start with
`--allow shadow`: `reflex report` then recommends thresholds from the commands you approved. On the
tool gate golden set it allowed 6 of 7 allow-eligible commands with 0 misses.

See: [GUIDE: calibrated allow](GUIDE.md#calibrated-allow),
[docs/SETUP.md: let clearly safe commands through](SETUP.md#6-optional-let-clearly-safe-commands-through).

## Can Reflex run autonomous coding agents with no human watching?

Yes, with the autonomous profile (`reflex setup --profile autonomous`): System 1 (rules and Jev)
resolves most commands, uncertain ones go to a stronger model (System 2: the `claude` CLI, `codex
exec`, the Anthropic API or an OpenAI-compatible endpoint), and the rest wait in an approval queue
while the agent continues with other work. Production changes, IAM changes, writing secrets,
destructive deletes, billing APIs and every rule outcome always go to a human, and a System 2
error, timeout or spent budget goes to a human too, never to an approval. On the 41-command ladder
golden set it made 0 unsafe approvals. Without a TypeSafe key the profile runs keyless, with
System 2 judging what the rules do not cover.

See: [GUIDE: autonomous agents](GUIDE.md#autonomous-agents),
[docs/SETUP.md: the autonomous profile](SETUP.md#7-optional-the-autonomous-profile).

## How do I try Reflex safely before enforcing it?

Install it as is: new installs run in shadow mode, where deterministic rules still block and every
other decision is only logged. `reflex replay claude --since 7d` runs the commands from your past
Claude Code, Codex, opencode or pi sessions through the gate; it executes nothing and writes
nothing. `reflex check "command"` judges one command, `reflex setup --dry-run` previews
configuration changes, and `REFLEX_MODE=enforce claude` tries enforce for one session. After a week,
read `reflex report`, then run `reflex setup --mode enforce`.

See: [replay on a real week](../README.md#replay-what-it-would-have-done-on-a-real-week),
[GUIDE: rolling out](GUIDE.md#rolling-out-shadow-tune-enforce).

## How do I uninstall Reflex?

Run `reflex uninstall`: it removes the hooks from every agent, the package in
`~/.local/share/reflex` and the `reflex` link, and stops a Laya server if one was set up. It keeps
your settings and policy in `~/.config/reflex` and your logs in `~/.local/state/reflex`; delete the
logs with `rm -rf ~/.local/state/reflex`. Without the command on `PATH`, use
`curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash -s -- --uninstall`.

See: [docs/SETUP.md: uninstall](SETUP.md#uninstall).
