# Reflex FAQ: guardrails and command approval for Claude Code, Codex CLI and other AI coding agents

Answers to the questions people ask about Reflex, each checked against the code and the other
docs. The short version of this page is the [FAQ section of the README](../README.md#faq).

- [What is Reflex?](#what-is-reflex)
- [How do I stop Claude Code from running dangerous commands?](#how-do-i-stop-claude-code-from-running-dangerous-commands)
- [How do I install Reflex as a Claude Code plugin?](#how-do-i-install-reflex-as-a-claude-code-plugin)
- [How do I install Reflex as a Codex CLI plugin?](#how-do-i-install-reflex-as-a-codex-cli-plugin)
- [How do I install Reflex as an opencode plugin?](#how-do-i-install-reflex-as-an-opencode-plugin)
- [How do I block destructive MCP tool calls, like an AWS MCP server deleting production?](#how-do-i-block-destructive-mcp-tool-calls-like-an-aws-mcp-server-deleting-production)
- [How is Reflex different from Claude Code permission prompts and allowlists?](#how-is-reflex-different-from-claude-code-permission-prompts-and-allowlists)
- [Can I use Reflex with --dangerously-skip-permissions?](#can-i-use-reflex-with---dangerously-skip-permissions)
- [Do I still need a devcontainer or a sandbox if I use Reflex?](#do-i-still-need-a-devcontainer-or-a-sandbox-if-i-use-reflex)
- [What guardrails can I add to Codex CLI, and how does Reflex work with the Codex sandbox?](#what-guardrails-can-i-add-to-codex-cli-and-how-does-reflex-work-with-the-codex-sandbox)
- [How is Reflex different from abide?](#how-is-reflex-different-from-abide)
- [Which AI coding agents does Reflex support?](#which-ai-coding-agents-does-reflex-support)
- [Does Reflex work in Claude Desktop or Cursor?](#does-reflex-work-in-claude-desktop-or-cursor)
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
- [How do I share Reflex rules with my team, like Claude Code team settings?](#how-do-i-share-reflex-rules-with-my-team-like-claude-code-team-settings)
- [How do I set a deploy freeze or change window for AI coding agents?](#how-do-i-set-a-deploy-freeze-or-change-window-for-ai-coding-agents)
- [How do I audit AI agent commands for SOC 2 or ISO 27001?](#how-do-i-audit-ai-agent-commands-for-soc-2-or-iso-27001)
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

## How do I install Reflex as a Claude Code plugin?

Add the marketplace in this repository and install the plugin, inside Claude Code:
`/plugin marketplace add ursuciprian/reflex`, then `/plugin install reflex@reflex` (or, from a
shell, `claude plugin marketplace add ursuciprian/reflex` and `claude plugin install reflex@reflex`).
The plugin wires the same Claude Code hooks as `reflex setup`: the `PreToolUse` command gate on
Bash and subagent spawns, the post-tool records, conditional instructions and the prompt injection
guard. It adds read-only commands (`/reflex:status`, `/reflex:check <command>`, `/reflex:report`,
`/reflex:replay`, `/reflex:queue`, `/reflex:suggest`). It needs Node.js 18+ on the `PATH` and no
build step, npm install or API key; with no saved settings it runs the local engine in shadow mode.
If `reflex setup` hooks are also in `~/.claude/settings.json`, the plugin's hooks stand down so
nothing is judged twice, and `reflex doctor` shows which one is active. Use `reflex setup` for
other agents, the autonomous profile, or the permission rules that guard Reflex's own files.

See: [README: Claude Code plugin](../README.md#claude-code-plugin), [docs/SETUP.md: Claude Code plugin](SETUP.md#claude-code-plugin).

## How do I install Reflex as a Codex CLI plugin?

Add the marketplace in this repository and install the plugin from a shell:
`codex plugin marketplace add ursuciprian/reflex`, then `codex plugin add reflex@reflex`. Open
`codex`, run `/hooks` and trust the Reflex entries: Codex runs no plugin hook it has not been told to
trust. The plugin wires the same Codex hooks as `reflex setup --agent codex`: the `PreToolUse`
command gate on Bash and `spawn_agent`, the post-tool records, conditional instructions and the
prompt injection guard on Bash and MCP results and on prompts. It needs Node.js 18+ on the `PATH`
and no build step or API key; with no saved settings it runs the local engine in shadow mode. If
`reflex setup` hooks are also in `~/.codex/hooks.json`, the plugin's hooks stand down so nothing is
judged twice, and `reflex doctor` shows which one is active.

See: [README: Codex CLI plugin](../README.md#codex-cli-plugin), [docs/SETUP.md: Codex CLI plugin](SETUP.md#codex-cli-plugin).

## How do I install Reflex as an opencode plugin?

Add `"plugin": ["@ursuciprian/reflex"]` to `~/.config/opencode/opencode.json` (or a project's
`opencode.json`). opencode installs the npm package with Bun at its next start and loads
`adapters/opencode.js`, the same plugin `reflex setup --agent opencode` copies into
`~/.config/opencode/plugins/reflex.js`: the gate on `tool.execute.before` for `bash` and `task`,
conditional instructions on `chat.message`, and the injection guard on tool results and prompts. It
runs the gate with `node` from the `PATH`, so it needs Node.js 18+ there. If the setup file is also
in `~/.config/opencode/plugins/`, the npm plugin registers no hooks, and `reflex status` shows which
one is active.

See: [README: opencode plugin](../README.md#opencode-plugin), [docs/SETUP.md: opencode plugin](SETUP.md#opencode-plugin).

## How do I stop an AI agent from destroying infrastructure with terraform apply?

`terraform destroy` is a rule: it asks, and denies in production. An apply without a saved plan asks
with the fix: run `terraform plan -out=tfplan` and apply the file. To judge an apply by what it will
change, turn on `infra.terraform_show` and use a provider plugin cache (`TF_PLUGIN_CACHE_DIR` or
`plugin_cache_dir`). The hook then reads the plan with `terraform show -json tfplan` (local, no
provider API calls, a 3 s timeout, no cloud credentials in its environment) and counts creates,
updates, deletes and replaces. Any delete or replace is denied, with the addresses in the reason and
stateful types such as `aws_db_instance`, `aws_s3_bucket` and `google_sql_database_instance` named
first. A clean plan is allow-eligible outside production and still asks in production. It is off by
default because `terraform show` starts the provider binaries in `.terraform`, which an agent can
write with its file tools; on, it runs only when every provider there is a symlink into a plugin cache
outside the working tree and older than the plan. The hook never runs `terraform plan` or
`terraform apply` itself. For kubectl, the optional `infra.kubectl_diff` setting adds a `kubectl diff`
or server dry run that flags deletes of namespaces, PVCs, statefulsets and CRDs. See
[GUIDE: plan-aware terraform gate](GUIDE.md#plan-aware-terraform-gate-stop-ai-agents-from-destroying-infrastructure).

## How do I block destructive MCP tool calls, like an AWS MCP server deleting production?

Reflex gates MCP tool calls as well as shell commands (MCP server guardrails, AWS MCP safety). In
Claude Code, Codex CLI, opencode, pi and Hermes, each MCP tool call goes through
`setup/tool-gate/mcp.json` before it runs: a tool whose name says delete, destroy, drop, terminate,
remove, purge, truncate, force, reset, rollback or uninstall asks, and so do a scale to zero, a
bucket policy, security group or IAM change, destructive SQL and an HTTP DELETE. Any of them is
denied when an argument (a stack, cluster, context, profile, database or account name) or the
server name points at production, by the same markers the shell rules use and a team policy's
`prod` list. A shell command passed to an MCP tool, such as the AWS MCP server's `call_aws`, goes
through the shell rules. Read-like tools (get, list, describe, search, a SELECT-only query) pass
without a prompt. An unknown tool is logged keyless and judged by Jev with a key, or asks with
`"mcp": {"unknown": "ask"}`; keyless, an unknown tool on an infrastructure server (aws, kubernetes,
terraform, a database, github and the like, or a server name containing prod) asks. On 30 days of real Claude Code sessions, none of 475 MCP calls asked.
File tools are gated too: a write to `.github/workflows/`, production Terraform, agent settings or
shell startup files asks. See [Gate MCP tool calls](GUIDE.md#gate-mcp-tool-calls) and
[Protected files](GUIDE.md#protected-files).

## How is Reflex different from Claude Code permission prompts and allowlists?

Claude Code's permission rules match tools and command prefixes; Reflex judges each shell command
by what it does and where it points. It reads the local script, make target or package script a
command runs, and knows the AWS profile, kube context, Terraform workspace and git branch. By
default Reflex only emits `ask` or `deny` and leaves `pass` to your permission settings, so your
allowlist keeps working. Claude Code's own rules cover file edits, web fetches and MCP tools, which
Reflex does not gate.

See: [compared with other AI coding agent guardrails](../README.md#compared-with-other-ai-coding-agent-guardrails).

## How do I reduce permission prompts without giving up prod safety?

Reflex is human-last: a model decides, and you are the last rung. When System 1 (Jev, or the local
rules keyless) is unsure, System 2 decides before you are asked. `reflex setup` turns System 2 on
when it finds the `claude` CLI or `ANTHROPIC_API_KEY`, in the supervised profile too. You are still
asked for the always-human class (production mutations, IAM, secrets writes, destructive deletes,
billing), a rule's ask, a change freeze, the runaway guard and whatever System 2 hands up.
`reflex status` shows which rungs are active and why a human would still be asked. `"judge": "off"`
in `config.json` opts out.

On 300 recent commands from the author's sessions, humans per 100 fell from 55.0 to 13.0 keyless and
from 15.0 to 13.3 with Jev. The keyless workspace allowlist (`mkdir -p`, `touch`, `sed -i` on a
tracked file, `cp` or `mv` to a new path) is strict on purpose and passed none of them: agents chain
commands or use absolute paths, and those go to the engine. `reflex learn` and `reflex suggest` add
fast-lane entries from what you already approve. See
[Human-last](GUIDE.md#human-last-how-reflex-decides-without-you).

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
other agent can use `scripts/reflex-sh` as its shell. Setup hooks every supported agent it finds (for
Hermes it prints a block to paste into `config.yaml`), or the ones you name with
`--agents claude,codex`. Reflex needs Node.js 18+ on macOS or Linux,
including WSL; native Windows is not supported yet.

See: [supported agents](../README.md#supported-agents-claude-code-hooks-codex-hooks-and-more),
[docs/SETUP.md](SETUP.md).

## Does Reflex work in Claude Desktop or Cursor?

Yes, as advice, not as a gate. Claude Desktop and Cursor have no pre-execution hook Reflex can
install, so Reflex runs there as an MCP server for AI agent safety: `reflex mcp` (or
`npx -y @ursuciprian/reflex mcp` in the host's MCP config) gives the agent `reflex_check`,
`reflex_scan`, `reflex_status`, `reflex_audit` and `reflex_explain`. The agent can ask what the gate
decides for a command (`git push --force origin main` is `deny`, rule `force-push-main`) or screen a
fetched page for prompt injection before it acts. These Claude Desktop guardrails depend on the model
calling the tool and following the answer: an MCP server cannot stop a client from running a command.
The tools are read-only, never change Reflex's configuration and redact what they return. Where the
agent has hooks (Claude Code, Codex CLI, opencode, pi, Hermes), the hooks enforce and the MCP tools
are an extra check.

See: [GUIDE: Reflex MCP server](GUIDE.md#reflex-mcp-server-ask-before-acting-claude-desktop-cursor-cowork),
[SETUP: MCP server](SETUP.md#mcp-server-claude-desktop-cursor-codex).

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

None for most commands: those settled by the read-only list, the rules or the fast lane make no
network call. A Jev call adds 0.35 to 0.42 s in the README scenarios (the GUIDE's figure is about
0.7 s in enforce mode), with a 3 s budget after which the policy's fallback applies. In shadow mode Jev runs in a detached
background process, so the agent does not wait. A System 2 escalation with the `claude` CLI takes 3
to 4 s; Laya answered the tool gate in 125 ms p50 on an Apple M5 Max, but a CPU-only machine can
exceed the 3 s budget. `reflex bench --engine jev` (or `--engine laya`) measures it on your machine.

See: [cost and latency](../README.md#cost-and-latency), [GUIDE: replay and bench](GUIDE.md#replay-and-bench).

## Does Reflex send my code anywhere?

Not with the default local engine: nothing leaves the machine. With Jev, a command the rules leave
open sends TypeSafe the command with secrets redacted, the working directory path,
environment names (AWS profile, region, kube context, Terraform workspace, git branch), the agent's
last message and last five commands (redacted and truncated), and the first 16 KB of a local script
the command runs (redacted, never a credentials file such as `.env`). With the injection guard on
Jev, up to 8 redacted chunks of 3,000 characters of an inspected tool result are sent, with the
tool name, a redacted origin and, in Claude Code, the last 1,000 characters of your prompt.
Conditional instructions and subgoal dedup, when used, send their own redacted context. The Laya
engine sends to 127.0.0.1 only, and System 2 sends a redacted case of at most 1,500 tokens to the
backend you chose.

See: [GUIDE: data handling](GUIDE.md#data-handling).

## What happens when Jev is down or slow?

The policy's fallback applies, which is `ask`: in enforce mode with the supervised profile a human
reviews the command. The rules, the read-only list and the fast lane run locally and keep
working. In shadow mode Jev only logs from a background process, so the agent is not affected. In
the autonomous profile those asks go to System 2, which may approve them as a pass (never an
allow), and a breaker pauses System 2 when more than 30 %
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

Two ways, both opt-in. `reflex suggest` reads your past sessions and proposes project-scoped
fast-lane entries for the build, test and lint commands your agents keep asking about, never for
deletes, pushes, deploys, installs, network calls, secrets or production, and shows the asks per
100 commands before and after; `--write` adds them after you confirm. Calibrated allow (Jev engine,
`--mode enforce --allow on`) lets commands Jev judges clearly safe skip Claude Code's permission
prompt; rule outcomes, commands without a stated intent, code Jev did not see in full and cached
answers are never allowed, and Claude Code's own deny and ask rules still apply. Start it with
`--allow shadow`, and `reflex report` recommends thresholds from the commands you approved; on the
tool gate golden set it allowed 6 of 7 allow-eligible commands with 0 misses.

See: [GUIDE: suggest fewer permission prompts](GUIDE.md#suggest-fewer-permission-prompts),
[GUIDE: calibrated allow](GUIDE.md#calibrated-allow),
[docs/SETUP.md: let clearly safe commands through](SETUP.md#6-optional-let-clearly-safe-commands-through).

## Can Reflex learn from the commands I approve and ask less over time?

Yes, when you ask it to. `reflex learn` reads your own answers only (approval queue items you
approved or denied, and asks shown at the agent's prompt that then ran or were refused; never a
System 1 allow or a System 2 verdict) and proposes a project-scoped fast-lane entry for a shape you
approved at least 3 times in at least 2 sessions and never refused. It uses the same templates and
safety proof as `reflex suggest`, so destructive, production, secret, tamper, always-human and MCP
commands are never learned, however often you approved them. It shows the humans per 100 commands
before and after on your own history, and writes nothing until you run `reflex learn --write` and
confirm on the terminal; an agent running that gets a tamper ask. Each entry records where it came
from; `reflex learn --list`, `--forget <id>` and `--prune` (entries unused for 60 days, which
`reflex doctor` flags) review and remove them, and `--team` prints a team policy snippet instead.

See: [GUIDE: reflex learn, fewer prompts from your own approvals](GUIDE.md#reflex-learn-fewer-prompts-from-your-own-approvals).

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

## How do I share Reflex rules with my team, like Claude Code team settings?

Commit `.reflex/policy.json` at the repository root (`reflex policy init` writes a starter). Every
teammate's Reflex applies it while Claude Code, Codex CLI or another supported agent works in that
repository: extra ask and deny rules, always-human patterns, production markers and a mode floor
such as `enforce`. These team guardrails for AI coding agents can only make Reflex stricter. A team
fast lane, the one part that loosens, applies only after each teammate runs `reflex trust .` in
their own terminal, and only while the file keeps the hash they trusted. An agent shell command
that edits `.reflex/` or runs `reflex trust` gets a tamper ask, and a `.reflex/` in a directory
without `.git` is never read. Other agents' file tools are not gated, so protect `.reflex/` in code
review as you would CI settings.

See: [GUIDE: team policy](GUIDE.md#team-policy-share-reflex-rules-across-a-repo).

## How do I set a deploy freeze or change window for AI coding agents?

Add a `freeze` list to `~/.config/reflex/config.json`, or to the team policy
(`.reflex/policy.json`) so the whole team gets it: weekly windows such as
`{"days": ["fri"], "after": "15:00", "tz": "Europe/Bucharest"}` and date ranges such as
`{"from": "2026-12-20", "to": "2027-01-03", "outcome": "deny"}`. During a window, a command that
is not read-only and touches production (by the working directory, AWS profile, kube context,
Terraform workspace, git branch, the command or a team prod marker) asks a human or is denied, with
a reason such as `change freeze: Friday after 15:00 (Europe/Bucharest)`. It works in shadow and
enforce mode, System 2 never approves it, and it can only tighten: a rule deny stays a deny, and an
invalid window is an error rather than a smaller window. `reflex status` shows whether a freeze is
active now. This is change management for Claude Code, Codex CLI and the other supported agents,
for their shell commands.

See: [GUIDE: change freeze for AI coding agents](GUIDE.md#change-freeze-for-ai-coding-agents).

## How do I audit AI agent commands for SOC 2 or ISO 27001?

Run `reflex audit --since 90d > agent-commands.csv`. It writes one row per decision the gate
logged: time, agent, session, working directory, production or not and why, the command with
secrets redacted, the decision, the rule and who approved it (a human in the approval queue,
System 2, or the agent's own prompt). `--prod-only`, `--agent` and `--format json|jsonl` narrow and
shape it. It only reads Reflex's local logs, so it is evidence for a change management control
(SOC 2 CC8.1, ISO 27001 Annex A 8.32), not tamper-proof storage; read-only commands are not logged.
To keep decisions outside the machine, set `notify` in `config.json` to an https webhook (Slack or
json): it posts redacted denies, asks or production decisions from a detached process and never
delays the agent.

See: [GUIDE: audit log for AI agent commands](GUIDE.md#audit-log-for-ai-agent-commands-soc-2).

## How do I try Reflex safely before enforcing it?

Install it as is: new installs run in shadow mode, where deterministic rules still block and every
other decision is only logged. `reflex replay all --since 7d` runs the commands from your past
Claude Code, Codex, opencode or pi sessions through the gate; it executes nothing and writes
nothing. `reflex check "command"` judges one command, `reflex setup --dry-run` previews
configuration changes, and `REFLEX_MODE=enforce claude` tries enforce for one session. After a week,
read `reflex report`, then run `reflex setup --mode enforce`.

See: [replay on a real week](../README.md#replay-what-it-would-have-done-on-a-real-week),
[GUIDE: rolling out](GUIDE.md#rolling-out-shadow-tune-enforce).

## How do I uninstall Reflex?

Run `reflex uninstall`: it removes the hooks from every agent except Hermes (it prints the entries
to delete from each profile's `config.yaml`), the package in
`~/.local/share/reflex` and the `reflex` link, and stops a Laya server if one was set up. It keeps
your settings and policy in `~/.config/reflex` and your logs in `~/.local/state/reflex`; delete the
logs with `rm -rf ~/.local/state/reflex`. Without the command on `PATH`, use
`curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash -s -- --uninstall`.

See: [docs/SETUP.md: uninstall](SETUP.md#uninstall).

## Why does `npx @ursuciprian/reflex setup` say "reflex: command not found"?

You ran it inside a checkout of the Reflex repository. There npx resolves the package to the local folder instead of downloading it, and the local folder has no installed `reflex` binary. Run it from any other directory (`cd ~ && npx @ursuciprian/reflex@latest setup`), or from inside the checkout run the local copy with `node scripts/reflex setup`.
