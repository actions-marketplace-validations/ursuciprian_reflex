# Reflex setup: install the hooks for Claude Code, Codex CLI, pi, opencode and Hermes

You need Node 18+ on macOS or Linux (including WSL) and at least one supported agent: Claude Code, Codex CLI,
pi, oh-my-pi (omp), opencode or Hermes.

Claude Code, Codex CLI or opencode only? The [Claude Code plugin](#claude-code-plugin), the
[Codex CLI plugin](#codex-cli-plugin) and the [opencode plugin](#opencode-plugin) are the shortest
installs. For every other agent, or for the autonomous profile, follow the numbered steps.

## Claude Code plugin

This repository is a Claude Code plugin marketplace (`.claude-plugin/marketplace.json`) that lists
one plugin, `reflex`, at the repository root. Claude Code clones it and runs the hooks from the
clone with `node`: no build step, no `node_modules`, no npx at hook time.

```text
/plugin marketplace add ursuciprian/reflex        # inside Claude Code
/plugin install reflex@reflex
```

```sh
claude plugin marketplace add ursuciprian/reflex  # or from your shell
claude plugin install reflex@reflex
claude plugin update reflex@reflex                 # later, for a new release
```

Then restart the session or run `/reload-plugins`. To try it for one session without installing,
clone the repository and run `claude --plugin-dir /path/to/reflex`.

What the plugin adds:

| Part | What it is |
|---|---|
| `hooks/hooks.json` | the same Claude Code events, matchers and timeouts as `install.mjs --agent claude` (see step 3): `PreToolUse` on `Bash\|Task\|Agent` (10 s), `PostToolUse`, `PostToolUseFailure` and `PermissionDenied` records (5 s), `PermissionRequest` (5 s), `UserPromptSubmit` instructions (10 s) and prompt guard (5 s), and the injection guard on `PostToolUse` for `^(WebFetch\|WebSearch\|Read\|Bash)$\|^mcp__` (15 s). Each runs `node "${CLAUDE_PLUGIN_ROOT}/<script>.mjs" <flag> --plugin`; a test keeps the file in step with `install.mjs` |
| `commands/` | `/reflex:status`, `/reflex:check <command>`, `/reflex:report`, `/reflex:replay`, `/reflex:queue`, `/reflex:suggest`. All read-only: Claude runs the plugin's own script with the Bash tool (`node "${CLAUDE_PLUGIN_ROOT}/<script>.mjs" --plugin ...`, never a `reflex` from `PATH`), through the gate like any other command, and never with `--write`, `approve` or `--push` |
| `skills/reflex` | tells Claude when to check a command and replay past sessions, and not to work around a deny |
| `.mcp.json` | the Reflex MCP server (`node "${CLAUDE_PLUGIN_ROOT}/mcp.mjs"`, the plugin options in its `env`): read-only, advisory tools `reflex_check`, `reflex_scan`, `reflex_status`, `reflex_audit` and `reflex_explain` ([MCP server](#mcp-server-claude-desktop-cursor-codex)). A local server: it runs in Claude Code and Cowork, not in claude.ai chat |

The plugin puts nothing on the Bash `PATH` (the CLI lives in `scripts/`, not a top-level `bin/`,
which claude.ai and Cowork refuse to install), and nothing it runs downloads or installs anything:
the Laya setup, `install.sh` and npx are for `reflex setup` only.

### Plugin options

Claude Code asks for these when you enable the plugin; change them later with `/plugin`, then
reflex, then Configure, or under `pluginConfigs` in `settings.json`. Each one may stay empty.

| Option | Values | Empty means |
|---|---|---|
| `engine` | `local` (rules only, no key, nothing leaves the machine) or `jev` | `engine` in `config.json`, else `jev` when the Jev API key is set, else `local` |
| `provider` | `typesafe`, `openrouter`, `cloudflare`, `vercel` or `compatible` | `provider` in `config.json`, else `typesafe` |
| `jev_api_key` | the key for that provider (sensitive: kept in the system's secure storage) | no Jev: the engine stays local |
| `mode` | `off`, `shadow` or `enforce` | `mode` in `config.json`, else `shadow` |
| `judge_api_key` | the key for a System 2 judge with backend `anthropic` or `openai-compatible` (sensitive) | no key for System 2 |

Claude Code hands the options to the hooks as `CLAUDE_PLUGIN_OPTION_<KEY>` and to the MCP server
through its `env` in `.mcp.json`. In the plugin those options and Reflex's own config files
(`~/.config/reflex/config.json`, `fastlane.json`, the policy under `~/.config/reflex/tool-gate/`) are
the only settings the hooks, commands and MCP server read. They never ask the macOS Keychain, never
read `TYPESAFE_API_KEY` or another provider's key variable, `ANTHROPIC_API_KEY` or the `judge.key_env`
variable, and ignore `REFLEX_ENGINE`, `REFLEX_PROVIDER`, `REFLEX_MODE`, `REFLEX_ALLOW`,
`REFLEX_API_URL`, `REFLEX_MODEL`, `REFLEX_KEYCHAIN_SERVICE`, `JEV_PROVIDER`, `JEV_API_BASE_URL` and
`CLOUDFLARE_ACCOUNT_ID` (set `cloudflare_account_id` or `provider_url` in `config.json` instead).
The Codex CLI plugin below keeps reading the environment and the Keychain as `reflex setup` does.

Two more differences from `reflex setup`, both from the plugin directory's policy:

- The allow gate is off: a plugin hook never answers `allow` (what setup would allow is a silent
  pass, so Claude Code's own permission rules decide) and never rewrites a tool's input.
- The injection guard does not replace a tool result. A result it would block reaches Claude with
  the guard's warning next to it (`additionalContext`), and the session is checked more strictly
  from then on, as after any block. `reflex setup` removes the injected text instead.

With no options and no saved settings the gate runs the local engine in shadow mode, which is also
where a fresh `reflex setup` starts. The plugin writes no settings. Logs go to
`~/.local/state/reflex` as usual.

Hooks run with the `PATH` Claude Code was started with. If `node` is not on it (for example Claude
Code started from a desktop launcher with a minimal `PATH`), the hook command fails, Claude Code
treats that as a non-blocking hook error and the command runs ungated. `reflex doctor` from the same
environment, or a denied `/reflex:check git push --force origin main`, confirms the gate is live.

**Plugin and `reflex setup` together.** Both install the same hooks. When `reflex setup` (or
`install.mjs --agent claude`) has written Reflex hooks into `~/.claude/settings.json`, every plugin
hook sees them and exits at once without reading its input or writing a log line, so each call is
judged and counted once, by the settings hooks. The plugin checks the user settings file Claude
Code reads: `$CLAUDE_CONFIG_DIR/settings.json` when that variable is set. `install.mjs` always
writes `~/.claude/settings.json`, so with `CLAUDE_CONFIG_DIR` set the setup hooks do not run in
Claude Code and the plugin stays active. A settings hook whose script no longer exists (a deleted
checkout) does not count: it gates nothing, so the plugin keeps running, and `reflex status` reports
it as an error. `reflex status` and `reflex doctor` print which path is active
(`Claude Code hooks: ...`); doctor also probes the plugin's own gate when the plugin is the active
one. To switch to the plugin only, remove the Claude Code hooks with the copy that installed them:
`node ~/.local/share/reflex/lib/node_modules/@ursuciprian/reflex/install.mjs --agent claude --uninstall`
after `reflex setup`, or `node <checkout>/install.mjs --agent claude --uninstall` for a clone
(`reflex uninstall` removes the hooks of every agent and the package). To switch to setup only,
`claude plugin uninstall reflex@reflex`.

What only `reflex setup` does, because a plugin cannot change settings:

- the `permissions.ask` rules that make Claude Code ask before its edit tools change the Reflex
  checkout, its logs, `~/.config/reflex` or `~/.claude/settings*.json`. With the plugin alone, add
  them yourself if you want them (shell commands that write there, and `claude plugin disable`,
  `uninstall` or `marketplace remove`, are still asked by the gate's `tamper` rule), for example in `~/.claude/settings.json`:
  `"permissions": {"ask": ["Edit(~/.config/reflex/**)", "Edit(~/.local/state/reflex/**)", "Edit(~/.claude/plugins/**)", "Edit(~/.claude/settings*.json)"]}`
- a `PreToolUse` timeout sized to System 2. The plugin's is 10 s, the same as `reflex setup`
  without System 2; with the autonomous profile a slow judge call runs past it and the hook fails
  open, so use `reflex setup --profile autonomous` there. `reflex status` warns about this.

To remove the plugin: `claude plugin uninstall reflex@reflex`, and
`claude plugin marketplace remove reflex` for the marketplace. Your settings and logs stay, as with
`reflex uninstall`.

## Codex CLI plugin

The same repository is a Codex plugin marketplace (`.agents/plugins/marketplace.json`) that lists
the `reflex` plugin at the repository root. Codex reads `.codex-plugin/plugin.json` there, which
points at `hooks/codex.json`, not at the Claude Code `hooks/hooks.json`. Codex copies the plugin to
`$CODEX_HOME/plugins/cache/reflex/reflex/<version>/` and runs the hooks from that copy with `node`.

```sh
codex plugin marketplace add ursuciprian/reflex
codex plugin add reflex@reflex
codex plugin marketplace upgrade reflex             # later, for a new release,
codex plugin add reflex@reflex                      # then add it again to copy the new version
```

Inside Codex, `/plugins` shows the same marketplace. Then open `codex`, run `/hooks` and trust the
Reflex entries: Codex runs no plugin hook it has not been told to trust, and it asks again when a
new release changes one.

| Part | What it is |
|---|---|
| `hooks/codex.json` | the same Codex events, matchers and timeouts as `install.mjs --agent codex` (see step 3): `PreToolUse` on `^(Bash\|spawn_agent)$` (15 s), `PostToolUse` records on `^(Bash\|spawn_agent)$` (5 s), the injection guard on `PostToolUse` for `^Bash$\|^mcp__` (15 s), `UserPromptSubmit` instructions (10 s) and prompt guard (5 s). Each runs `node "$PLUGIN_ROOT/<script>.mjs" <flag> --plugin` (an environment variable Codex sets; the form works in sh, bash, zsh and fish); a test keeps the file in step with `install.mjs` |
| `skills/reflex` | tells the agent when to use `reflex check` and `reflex replay`, and not to work around a deny |

Codex loads `skills/` by default and turns two of the Claude Code commands (`status`, `queue`) into skills (checked with Codex 0.157: they appear under `.codex-plugin/migrated-command-skills/` in the installed copy). The `reflex` CLI
is not put on the `PATH` by Codex; install the package (`npm install -g @ursuciprian/reflex`) if you
want those skills and `reflex status` to work. Configuration, defaults and logs are the same as for
`reflex setup`: `config.json`, the environment and, for Jev, the key variable or the Keychain item
(the Claude Code plugin options above do not apply to Codex).

**Plugin and `reflex setup` together.** Codex runs every matching hook from every source, so both
would judge each call. When `reflex setup` (or `install.mjs --agent codex`) has written Reflex hooks
into `~/.codex/hooks.json`, every plugin hook exits at once without reading its input or writing a
log line. The plugin checks the file Codex reads, `$CODEX_HOME/hooks.json` when `CODEX_HOME` is set.
A hook whose script no longer exists does not count, and `reflex status` reports it as an error.
`reflex status` and `reflex doctor` print which path is active (`Codex CLI hooks: ...`); doctor
also runs the plugin's installed `PreToolUse` command through `$SHELL -lc`, as Codex does, when the plugin is the active one. Codex runs a `hooks.json` entry only after you trust it, but the plugin stands down for it either way; `reflex status` warns when setup hooks silence the plugin and none of them has run yet. To switch to the plugin only:
`node <copy that installed them>/install.mjs --agent codex --uninstall`; to switch to setup only:
`codex plugin remove reflex@reflex`. The plugin's gate timeout is 15 s, the same as `reflex setup`
without System 2; with the autonomous profile use `reflex setup --profile autonomous`.

To remove the plugin: `codex plugin remove reflex@reflex`, and
`codex plugin marketplace remove reflex` for the marketplace. The gate's `tamper` rule asks before
the agent runs either of them.

## opencode plugin

The npm package is an opencode plugin: `package.json` `main` is `adapters/opencode.js`, the same
file `reflex setup --agent opencode` copies into `~/.config/opencode/plugins/reflex.js`. Add it to
`~/.config/opencode/opencode.json` (or a project's `opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["@ursuciprian/reflex"]
}
```

opencode installs it with Bun at startup into `~/.cache/opencode/node_modules/` and loads it into
its own process. The plugin runs `gate.mjs`, `instructions.mjs` and `guard.mjs` from the installed
package with `node` from the `PATH` opencode was started with (opencode itself runs on Bun), so it
needs Node.js 18+ there. It registers the same hooks as the setup file: the gate on
`tool.execute.before` for `bash` and `task`, instructions on `chat.message` and
`experimental.chat.system.transform`, the injection guard on `tool.execute.after` and `chat.message`.
The gate reads the mode and allow on every call from `REFLEX_MODE` / `REFLEX_ALLOW` or
`$XDG_CONFIG_HOME/reflex/config.json` (default `~/.config`), else shadow and off, so a change applies
without restarting opencode. Pin a version with `"@ursuciprian/reflex@0.13.0"`; this needs a release that ships
the plugin (0.13.0 or later).

**Plugin and `reflex setup` together.** opencode loads both. When the plugin file
`reflex setup` writes is in opencode's global plugins directory (`$XDG_CONFIG_HOME/opencode/plugins/reflex.js`,
by default `~/.config/opencode/plugins/reflex.js`) and its gate exists, the npm plugin registers no
hooks, so each call is judged once. `reflex status` prints which one is active
(`opencode plugin: ...`). To switch to the npm plugin only:
`node <copy that installed it>/install.mjs --agent opencode --uninstall`; to switch to setup only, remove the entry
from `plugin`.

## 1. Start locally, or enable hosted classification

New `reflex setup` installations use the local engine: no account, API key, or TypeSafe requests.
Rules and deterministic instruction matches work locally. Unknown commands ask in enforce mode;
in shadow mode that recommendation is logged while the host's permissions apply. Hard rules still
enforce in shadow. Subgoal classification, semantic instruction selection, model routing and
context classification require Jev. Native Windows setup is unsupported; run both the agent and
Reflex inside WSL.

For hosted classification, choose `reflex setup --engine jev` and get a TypeSafe API key:

Reflex calls TypeSafe's System One API with the Jev model. From the
[official quick start](https://docs.typesafe.ai/introduction/quickstart):

1. Sign in to the TypeSafe console: <https://console.typesafe.ai/playground>
2. Create an API key on the keys page: <https://console.typesafe.ai/keys>
3. Check it works:

   ```sh
   export TYPESAFE_API_KEY=...   # paste the key; do not commit it anywhere
   curl -s -X POST https://api.typesafe.ai/v1/systemone \
     -H "Authorization: Bearer $TYPESAFE_API_KEY" -H "Content-Type: application/json" \
     -d '{"state": "rm -rf build/", "model": "jev-1.13.0",
          "questions": {"destructive": {"type": "noul", "instructions": "Does this shell command delete data?"}}}'
   ```

   You should get `{"model": "...", "answers": {"destructive": {"type": "noul", "noul": 0.9...}}, "usage": {...}}`.
   `401` means the key is wrong; `429` / `529` mean rate-limited or overloaded (retry shortly).

Reference: [HTTP API](https://docs.typesafe.ai/api), [models and limits](https://docs.typesafe.ai/models)
(currently `jev-1.13.0`, 64k tokens per request, 1,200 requests/minute),
[legal / data processing](https://docs.typesafe.ai/legal).

### Where to keep the key

Hooks and plugins inherit the environment the agent was started with. Either:

- **Environment**: `export TYPESAFE_API_KEY=...` in the shell profile you start Claude Code from
  (or load it from your password manager there); or
- **macOS Keychain** (no key in any file):

  ```sh
  security add-generic-password -s typesafe-api-key -a "$USER" -w   # prompts for the key
  ```

  Reflex reads the item named in `REFLEX_KEYCHAIN_SERVICE` (default `typesafe-api-key`).

Never put the key in `settings.json`, the repo, or shell history.

## 2. Install

```sh
curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash
```

or with any package runner (same result):

```sh
npx @ursuciprian/reflex setup
pnpm dlx @ursuciprian/reflex setup
bunx @ursuciprian/reflex setup
yarn dlx @ursuciprian/reflex setup     # yarn 2+
```

Either way `reflex setup` runs, which:

- previews the selected agents and configuration changes;
- copies the package to `~/.local/share/reflex`, so clearing a package runner's cache cannot break hooks;
- links `reflex` into `~/.local/bin`;
- with `--engine jev`, offers to store a missing key in macOS Keychain (hidden input, passed on stdin);
- hooks the selected agents, initially with local classification, shadow mode and allow off;
- saves engine, mode, allow, installations and Keychain item name in `~/.config/reflex/config.json`;
- seeds `~/.config/reflex/tool-gate/policy.json`, preserving any previous policy;
- records Node's path so hooks work outside an interactive shell.

Re-running setup preserves saved choices unless explicitly changed. Environment overrides still
apply at runtime. `reflex setup --dry-run` previews changes without writing files. The curl bootstrap
must still download the package; use a package runner or existing installation for a setup preview.

The `curl` script checks Node 18+, runs `npm install` into that directory (with the npm registry
set explicitly for `@ursuciprian`, so a stale entry in `~/.npmrc` cannot redirect it) and then runs
`reflex setup`.

Options go after `bash -s --`, or after `setup`:

| Option | Default | |
|---|---|---|
| `--agents claude,codex,…` | `all` found | which agents to hook |
| `--mode shadow\|enforce\|off` | `shadow` | |
| `--engine local\|jev\|laya` | saved choice, otherwise `local` | local rules, optional hosted classification, or experimental local Laya ([GUIDE](GUIDE.md#laya-local-system-1)) |
| `--dry-run` | | preview setup changes |
| `--allow off\|shadow\|on` | `off` | see step 6 |
| `--keychain NAME` | `typesafe-api-key` | Keychain item holding the key |
| `--node PATH` | `node` on `PATH` | the Node the hooks run with |
| `--version X` | latest | package version (`curl` only; with a runner use `@ursuciprian/reflex@X`) |
| `--prefix DIR` | `~/.local/share/reflex` | where the package lives (`REFLEX_PREFIX` for `setup`) |
| `--package SPEC` | | an npm spec or a local `.tgz` (`curl` only, for testing) |
| `--uninstall` | | remove hooks, package and link; preserve user settings, policy and logs (`curl` only; otherwise `reflex uninstall`) |

Rerunning any install path upgrades in place; hook paths don't change.

Check it:

```sh
reflex check "git push --force origin main"          # a rule, no API call
reflex check "aws iam attach-role-policy --role-name ci --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
```

`reflex check` prints the decision, the rule that fired, where it came from (`read-only`, `rule`,
`fast-lane`, `jev`, `fallback`) and Jev's raw answers. If a Jev call fails it prints the error and
the policy's fallback decision (`ask`). Other commands: `reflex report`, `reflex install`,
`reflex uninstall`, `reflex test`, `reflex eval`, `reflex version`.

To work on Reflex itself, clone the repo, run `npm test`, and install that checkout with
`node install.mjs --agent all` instead.

### Publishing a release (maintainers)

Once: add the `NPM_TOKEN` repository secret (an npm access token with publish rights on the
`@ursuciprian` scope). Then per release: bump `version` in `package.json`, `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json`,
and the `@ursuciprian/reflex@<version>` pins in `action.yml`
(`npm test` fails when they differ; plugin users receive a release only when this version changes) and
`CHANGELOG.md`, merge,
and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. `.github/workflows/publish.yml` checks the tag
matches `package.json`, runs the self-checks and runs `npm publish --access public --provenance`.
npm versions cannot be withdrawn after 72 hours, so tag deliberately.

## 3. Install the hooks (shadow mode)

```sh
node install.mjs --agent all                 # every supported agent found on this machine
node install.mjs --agent claude,codex        # or pick
```

Every file it edits is backed up next to itself first (`*.bak-<timestamp>`). Re-running replaces
Reflex's own entries only; other hooks and plugins are left alone. The hook commands use the
absolute path of the Node that ran `install.mjs`; pass `--node /path/to/node` to pin another.

| Agent | What `install.mjs` does | After installing |
|---|---|---|
| Claude Code | `~/.claude/settings.json`: `PreToolUse` hook on `Bash\|Task\|Agent` (`gate.mjs --claude`; `Task\|Agent` is subgoal dedup), `PostToolUse` / `PostToolUseFailure` / `PermissionDenied` hooks on the same tools (`--claude-post`), a `PermissionRequest` hook on the same tools (`--claude-prompted`, which only records that Claude Code showed its own dialog; it never answers it), a `UserPromptSubmit` hook for conditional instructions (`instructions.mjs --claude`), the injection guard (`guard.mjs --claude` on `PostToolUse` for web, MCP, `Read` and `Bash` results; `guard.mjs --claude-prompt` on `UserPromptSubmit`), and permission rules that make Claude Code ask before editing the Reflex checkout, its logs, your personal instruction fragments (`~/.config/reflex`) or its own settings | restart sessions |
| Codex CLI | `~/.codex/hooks.json` (`$CODEX_HOME/hooks.json` when set): `PreToolUse` + `PostToolUse` on `^(Bash\|spawn_agent)$` (`spawn_agent` is subgoal dedup), `UserPromptSubmit` (`instructions.mjs --codex`), and the injection guard (`guard.mjs --codex` on `PostToolUse` for `^Bash$\|^mcp__`, `guard.mjs --codex-prompt` on `UserPromptSubmit`) | open Codex, run `/hooks` and **trust** the Reflex hooks; untrusted hooks do not run |
| pi | `~/.pi/agent/extensions/reflex.ts` (gate on `tool_call`, instructions on `before_agent_start`, injection guard on `tool_result` and `input`) | restart pi |
| oh-my-pi | `~/.omp/agent/extensions/reflex.ts` (same file) | restart omp |
| opencode | `~/.config/opencode/plugins/reflex.js` (under `$XDG_CONFIG_HOME` when set) (gate on `tool.execute.before`, instructions on `chat.message` + `experimental.chat.system.transform`, injection guard on `tool.execute.after` and `chat.message`) | restart opencode |
| Hermes | prints a `hooks:` block with `pre_tool_call`, `post_tool_call` (gate records and the injection guard) and `pre_llm_call` (instructions and the guard's notes) (Hermes config is YAML, so you paste it) | add it to each profile's `config.yaml`, then `hermes hooks list` to accept it |

The injection guard follows the installed mode: in shadow it only logs (`guard.jsonl`). To enforce it
while the gate stays in shadow, or the other way round, set `"guard": "enforce"` (or `"shadow"`,
`"off"`) in `~/.config/reflex/config.json`, or `REFLEX_GUARD` for one session. See
[GUIDE: injection guard](GUIDE.md#injection-guard) for what each agent can do with a finding.

The instruction hooks do nothing until you add fragments (`.reflex/instructions/*.md` in a repo, or
`~/.config/reflex/instructions/`); see [GUIDE: conditional instructions](GUIDE.md#conditional-instructions).

**Optional, pi and oh-my-pi only: the context layer.** `node install.mjs --agent pi,omp --context` also
writes `~/.{pi,omp}/agent/extensions/reflex-context.ts` (see the GUIDE's *Context layer*);
`--no-context` removes it, and a plain re-install keeps it only where it is already installed. It
sends redacted excerpts of tool output to TypeSafe, so turn it on deliberately. To try it for one session
without installing: `pi -e /path/to/reflex/adapters/pi-context.ts` with
`REFLEX_CONTEXT=/path/to/reflex/context.mjs` in the environment (same for `omp -e`).

For an agent with no hook system, point its shell setting at `scripts/reflex-sh`: it behaves like
`bash`, but judges every `-c` command first. Set `REFLEX_AGENT=<name>` so the logs say which agent
it was.

## 4. Verify in a real session

Run `reflex doctor` first. It checks local configuration and feeds read-only and hard-deny examples
to installed native hooks or the shared gate without executing those commands or calling TypeSafe.
`reflex doctor --json` and `reflex status --json` provide structured output and exit nonzero on broken
configuration. Missing binaries, manual Hermes setup and unobserved hooks are reported explicitly.

Restart the agent, complete its trust steps, and ask it to run `git status` in a repository.
`reflex status` should show a pre-execution event observed since the latest installation. This is
operational evidence, not a security attestation. Doctor cannot establish host trust or show a native
approval dialog; those require a real session.

When Codex or opencode blocks an `ask`, a chat confirmation cannot unblock it. The human can review
and execute the exact command in their own terminal with `reflex run 'command' --cwd /path/to/work`.
It always enforces, displays the command and directory, requires terminal confirmation for an ask,
and refuses hard denies. Give the result back to the agent; do not retry or disable the blocked hook.

The following classification check needs the Jev engine:


In a new agent session ask it to run something harmless but mutating, e.g.
`npm install left-pad` in a scratch directory. Then:

```sh
node report.mjs            # should show 1 judged command, source "jev", mode "shadow"
node report.mjs --list pass
```

Logs live in `~/.local/state/reflex/` (`trace.jsonl`, `feedback.jsonl`, `instructions.jsonl`, `cache.json`).

To see what the injection guard makes of a page or a file, without an agent:

```sh
reflex scan ~/Downloads/page.html          # exit 0 pass, 1 warn, 2 block
curl -s https://example.com | reflex scan - --rewrite
```

`reflex doctor` also feeds each installed agent's guard hook a synthetic injected result and a
prompt with a fake AWS key (guard enforced for the probe, local engine), and expects both blocked.

A quick check that a rule blocks in each agent, even in shadow mode: in an empty scratch
directory ask the agent to run `git push --force origin main`. It must be refused with
`reflex (rule): force push or delete of main/master`.

## 5. Switch to enforce (after the shadow period)

```sh
node install.mjs --agent all --mode enforce     # or --mode off to disable everything, rules included
```

`REFLEX_MODE` in the environment overrides the installed mode for one session, e.g.
`REFLEX_MODE=enforce claude` to try enforce without changing the install.

## 6. Optional: let clearly safe commands through

```sh
node install.mjs --agent all --mode enforce --allow shadow   # log would_allow, change nothing
node report.mjs                                              # calibration section, after a while
node install.mjs --agent all --mode enforce --allow on       # skip the agent's prompt for them
```

See [Calibrated allow](GUIDE.md#calibrated-allow). `REFLEX_ALLOW` overrides the installed value.

## 7. Optional: the autonomous profile

For agents that should not wait for you on every uncertain command. Read
[GUIDE: autonomous agents](GUIDE.md#autonomous-agents) first.

```sh
reflex setup --profile autonomous --dry-run   # the effective settings; nothing is written
reflex setup --profile autonomous             # engine jev (local without a key), enforce, allow on, System 2, queue, checkpoints
```

**Without a TypeSafe key** setup picks the local engine and says so (keyless autonomy): commands the
local rules do not cover go to System 2 instead of Jev, System 2 alone may allow only short commands
whose effects stay in the working directory, and its budget defaults to 300 calls a day with no breaker, since it is asked far more
often. See [GUIDE: keyless autonomy](GUIDE.md#keyless-autonomy). `--engine jev` or `--engine local`
beside the profile picks one yourself; rerun setup after adding a key to move to Jev.

**System 2.** Setup picks a backend and prints which:

- the `claude` CLI, when it is on `PATH`: no extra key, it uses your existing sign-in. It runs with
  no tools, hooks, MCP servers or CLAUDE.md, in an empty directory, with Reflex off for that process,
  and a pinned model (`sonnet` unless you pass `--judge-model`). Measured: about 3,100 input tokens
  (mostly cached after the first call), ~300 output tokens, 3 to 4 s, $0.004 to $0.016 a call at API
  prices; see [GUIDE](GUIDE.md#system-2) for the numbers and why Haiku is not a default.
- else `anthropic` when `ANTHROPIC_API_KEY` is set (the Messages API, model `claude-sonnet-5`, the steadiest judge in live tests);
- else `none`: uncertain commands go straight to the approval queue.

Pick one yourself with `--judge`:

```sh
reflex setup --judge cli --judge-cli claude [--judge-model sonnet]
reflex setup --judge cli --judge-cli codex                 # heavier: codex sends its base instructions with every call
reflex setup --judge anthropic [--judge-model claude-sonnet-5] [--judge-key-env ANTHROPIC_API_KEY | --judge-keychain ITEM]
reflex setup --judge openai-compatible --judge-url http://localhost:11434 --judge-model llama3.1      # Ollama
reflex setup --judge openai-compatible --judge-url https://api.openai.com --judge-model MODEL --judge-key-env OPENAI_API_KEY
reflex setup --judge openai-compatible --judge-url http://localhost:4000 --judge-model MODEL --judge-key-env LITELLM_KEY  # a LiteLLM gateway
reflex setup --judge none
```

Keys are read from the environment variable named by `--judge-key-env` (its name is saved, never the
key) or the macOS Keychain item named by `--judge-keychain`. `--judge-timeout SECONDS` (20),
`--judge-budget-calls N` (200 a day; 300 keyless) and `--judge-budget-usd X` ($5 a day) set limits; with System 2
on, setup gives the Claude Code, Codex and Hermes gate hooks the judge's timeout plus 30 s, so a slow
answer never makes a hook time out (which would let the command through). Further settings live in
`judge` in `config.json`:

```json
"judge": {"backend": "anthropic", "model": "claude-sonnet-5", "max_input_tokens": 1500, "max_tokens": 100,
          "thinking": "disabled", "min_confidence": 0.8, "cache_ttl_hours": 12,
          "tiers": null,
          "budget": {"calls": 200, "usd": 5, "session_calls": 40, "session_usd": 1},
          "price": {"input": 5, "output": 25},
          "breaker": {"rate": 0.3, "window_minutes": 60, "min_decisions": 20}}
```

`tiers` asks models in order, cheapest first, for example
`[{"model": "a-small-model", "min_confidence": 0.9}, {}]` (each entry overrides the settings above;
`{}` is the configured model). Add a small model only after `npm run eval-ladder` passes with it:
in measurement Haiku ignored the JSON-only instruction and misread a simple case. `price` is USD per million tokens, for the cost estimate; set it for your
model. Check with `reflex status`: it shows the backend, whether it is reachable (a GET of the model
list, or that the CLI is installed; never a paid call), the budget left and the breaker.

**The approval queue.** A decision that needs you is refused with a queue id, and the agent moves on:

```sh
reflex queue                                 # what waits
reflex queue approve <id> [--ttl 2h]         # the agent's identical retry runs, once
reflex queue deny <id> --reason "why"
reflex setup --queue-ttl 8 --notify 'terminal-notifier -title reflex -message "$REFLEX_QUEUE_ID"'
```

`--notify` runs a command for each new item, with `REFLEX_QUEUE_ID`, `REFLEX_QUEUE_REASON` and
`REFLEX_QUEUE_AGENT` in its environment. `--queue off` makes a human decision an `ask` in the agent
again.

**Task envelope.** Say what the agent may touch; work inside it resolves without escalation:

```sh
reflex envelope set "may modify this repo and the dev AWS account (profile dev); nothing in prod" --ttl 8h
reflex envelope show
```

A `.reflex/envelope.md` in a repository can only narrow yours.

**Checkpoints.** `reflex checkpoints` lists the recovery points taken before mutating commands in a
git repository; `reflex checkpoints restore <name>` brings the tracked files back (untracked files,
other directories and remote systems are not covered). `--checkpoints off` turns them off.

**Watch it.** `reflex report` shows human interventions per 100 commands, System 2's escalation
rate, verdicts, tokens and cost, cache hits, queue waits and fast-lane candidates.

## GitHub Action: check the team policy and commands in CI

`action.yml` at the root of this repository is a composite action for teams. It runs the published
package, pinned to the same version as the action (`npx @ursuciprian/reflex@<version>`), and:

1. validates the repository's `.reflex/policy.json` (`reflex policy --json`) and fails on any error,
   so a broken team policy does not reach the main branch;
2. judges each command you list with `reflex check`, keyless (`REFLEX_ENGINE=local`) and with an
   empty config directory, so on a clean runner the result depends on the rules and the team policy,
   and fails when one is denied. The commands are
   data: `reflex check` never runs them. A table of decisions goes to the job summary;
3. optionally runs the golden set (`reflex eval`), which calls Jev for each case the rules do not
   settle and so needs a TypeSafe key.

```yaml
# .github/workflows/reflex.yml
name: reflex
on:
  pull_request:
    paths: [".reflex/**", "ops/reflex-commands.txt"]
permissions:
  contents: read
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ursuciprian/reflex@v0.16.0   # a release tag or a commit SHA
        with:
          commands: |
            make deploy-staging
            terraform plan -out=tfplan
          commands-file: ops/reflex-commands.txt   # optional, relative to the workspace, # for comments
          fail-on: deny                            # or ask: also fail when a command needs a human
          # golden-eval: "true"
          # typesafe-api-key: ${{ secrets.TYPESAFE_API_KEY }}
```

The action is in releases from 0.16.0. Inputs: `directory` (default `.`, a git checkout),
`require-policy` (default `true`; `false` skips validation when there is no policy file),
`commands`, `commands-file`, `fail-on` (`deny` or `ask`), `golden-eval`, `golden-file` (a golden
set for `reflex eval --golden`) and `typesafe-api-key`. Outputs: `denied` and `asked`, the counts.
List the commands your CI, runbooks or agents are expected to run: a policy change that would deny
one of them fails the pull request before it reaches a teammate's agent. `reflex check` sees the
runner's own context (AWS profile, kube context, git branch), so keep production credentials out of
this job. It needs Node.js 18+ on `PATH`, which GitHub-hosted runners
have.

## Configuration

All optional.

| Variable | Default | Meaning |
|---|---|---|
| `REFLEX_ENGINE` | saved choice; otherwise `jev` when `TYPESAFE_API_KEY` is set or a Keychain item or an agent install is recorded in `config.json`, else `local` | `local` disables hosted classification; new setup saves `local` |
| `TYPESAFE_API_KEY` | none | API key (or use the Keychain item) |
| `REFLEX_MODE` | installed `--mode`, else `shadow` | `off` · `shadow` (rules enforce, Jev logs only) · `enforce` |
| `REFLEX_ALLOW` | installed `--allow`, else `off` | `off` · `shadow` (log `would_allow`) · `on` (clearly safe commands skip the agent's prompt; enforce mode only) |
| `REFLEX_MODEL` | `jev-1.13.0` | Pinned model; `jev-latest` follows TypeSafe's current version |
| `REFLEX_TIMEOUT_MS` | `3000` | Budget for one Jev call, retry included; on timeout the policy fallback applies |
| `REFLEX_SETUP_DIR` | `./setup/tool-gate` | Directory with rules / questions / policy / golden |
| `REFLEX_DATA_DIR` | `~/.local/state/reflex` | Trace, feedback, cache, eval results |
| `REFLEX_KEYCHAIN_SERVICE` | `typesafe-api-key` | macOS Keychain item holding the key |
| `REFLEX_API_URL` | TypeSafe System One endpoint | Override for a proxy |
| `REFLEX_NOTIFY` | unset | `off` sends no decision webhook for this session (`reflex doctor` sets it for its probes) |
| `REFLEX_GUARD` | `"guard"` in `config.json`, else the gate's mode | Injection guard mode: `off` · `shadow` (log only) · `enforce` (warn, rewrite, taint, block credential prompts) |
| `REFLEX_GUARD_TIMEOUT_MS` | `8000` | Budget for the guard's one Jev request per result; on timeout the detectors decide |
| `REFLEX_INJECTION_DIR` | `./setup/injection` | Directory with the guard's detectors / questions / policy / golden; a file missing there comes from the next place |
| `REFLEX_JUDGE` | the saved `judge.backend` | `off` turns System 2 off for this session (autonomous profile) |
| `REFLEX_QUEUE` | saved `queue` | `on` · `off`: park human decisions in the approval queue, or ask in the agent |
| `REFLEX_CHECKPOINTS` | saved `checkpoints` | `on` · `off`: git recovery points before mutating commands |
| `REFLEX_INSTRUCTIONS_THRESHOLD` | `0.5` | Jev probability at which a conditional instruction fragment is injected |
| `REFLEX_INSTRUCTIONS_MAX_CHARS` | `6000` | Most fragment text injected per prompt; whole fragments are dropped, never cut |
| `XDG_CONFIG_HOME` | `~/.config` | Personal fragments are read from `$XDG_CONFIG_HOME/reflex/instructions/`; they win over a repo fragment with the same id |

Runtime precedence is environment, explicit hook flags, saved settings, then defaults. Direct
`node install.mjs` retains the legacy Jev default until an engine is selected. User overrides in
`$XDG_CONFIG_HOME/reflex/tool-gate/` (default `~/.config/reflex/tool-gate/`) win over bundled files;
`REFLEX_SETUP_DIR` takes precedence over both. Setup seeds only `policy.json`; you can also place
`rules.json`, `questions.json` and `subgoals.json` there. The injection guard reads
`$XDG_CONFIG_HOME/reflex/injection/` the same way (`detectors.json`, `questions.json`, `policy.json`,
whose `sources` pick which tool results are inspected); `REFLEX_INJECTION_DIR` wins over both. Each setup adds to your `policy.json` copies (tool gate and, if you made one, injection guard) the gates, params and flags a new version bundles, without changing or reordering yours. Invalid configuration asks instead of silently
enabling hosted calls. Inspect active paths with `reflex status`.

A standalone LiteLLM process reads the same engine setting at startup. If its container cannot read
this configuration directory, set `REFLEX_ENGINE=local` there too to disable its Jev calls.

## MCP server (Claude Desktop, Cursor, Codex)

`reflex mcp` runs Reflex as a stdio MCP server with five read-only, advisory tools
(`reflex_check`, `reflex_scan`, `reflex_status`, `reflex_audit`, `reflex_explain`). They let an
agent ask before acting; they do not enforce anything. What each tool returns and what it
guarantees: [GUIDE: Reflex MCP server](GUIDE.md#reflex-mcp-server-ask-before-acting-claude-desktop-cursor-cowork).
It reads the same `~/.config/reflex/config.json` as the hooks and writes nothing.

Every host below takes the same command. `npx` fetches the package on first start; after
`reflex setup`, `~/.local/bin/reflex mcp` starts faster and works offline. Desktop apps start with a
minimal `PATH`, so if the host cannot find `npx` or `node`, give the absolute path
(`command -v npx`, or `/Users/you/.local/bin/reflex` with `"args": ["mcp"]`).

**Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS
(`%APPDATA%\Claude\claude_desktop_config.json` on Windows), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "reflex": {"command": "npx", "args": ["-y", "@ursuciprian/reflex", "mcp"]}
  }
}
```

**Cursor**: `~/.cursor/mcp.json` for every project, or `.cursor/mcp.json` in one repository:

```json
{
  "mcpServers": {
    "reflex": {"command": "npx", "args": ["-y", "@ursuciprian/reflex", "mcp"]}
  }
}
```

**Codex CLI**: `~/.codex/config.toml` (also in
[examples/mcp/codex-config.toml](../examples/mcp/codex-config.toml)):

```toml
[mcp_servers.reflex]
command = "npx"
args = ["-y", "@ursuciprian/reflex", "mcp"]
```

**Claude Code**: the plugin declares the server in its `.mcp.json`, so it is there once the plugin
is installed. Without the plugin: `claude mcp add reflex -- npx -y @ursuciprian/reflex mcp`.

Check it by hand; the reply is the tool list:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | reflex mcp
```

## Optional: the tool router

An MCP server that gives the agent three tools (`find_tools`, `describe_tool`, `run`) in front of
built-in read-only shell tools and any MCP servers you list; Jev picks the tool and its arguments.
How it works: [GUIDE → Tool router](GUIDE.md#tool-router).

```sh
node router/server.mjs --selfcheck                              # offline, also part of npm test
node router/server.mjs --check "show the last 5 commits" --run  # one live Jev round trip
npm run eval-router                                             # router/golden.json through live Jev; nothing runs; exit 1 only on unsafe
node install.mjs --router                                       # prints the registration for every agent
node install.mjs --router --agent codex --mode enforce          # one agent; --mode is the gate's mode for the router's calls
```

`--router` only prints: registering an MCP server writes the agent's global config (`~/.claude.json`,
`~/.codex/config.toml`, …), so you run the printed command or paste the snippet yourself. If the key
lives in the Keychain under a non-default name, run it with `REFLEX_KEYCHAIN_SERVICE` set and the
snippets carry it in their `env`. To route other MCP servers, move their entries from the agent's
config into `router/config.json` (`mcpServers`, `.mcp.json` shape; stdio only).

| Variable | Default | Meaning |
|---|---|---|
| `REFLEX_ROUTER_CONFIG` | `router/config.json` | Downstream MCP servers |
| `REFLEX_ROUTER_MIN_CONFIDENCE` | `0.5` | Below this probability for the tool or any argument, `run` returns candidates instead of running |
| `REFLEX_ROUTER_TIMEOUT_MS` | `30000` | Per shell command and per downstream request |

Selections are logged to `router.jsonl` in `REFLEX_DATA_DIR`.

## Optional: model routing in a LiteLLM proxy

`routing/reflex_router.py` runs inside the LiteLLM proxy process (tested against LiteLLM
1.100.1). It uses only the Python standard library, plus `certifi` when present (LiteLLM ships it)
for TLS on Python builds without a CA bundle.

1. Check it offline, then against the live API:

   ```sh
   python3 routing/reflex_router.py --selfcheck
   npm run eval-routing                            # 27 labelled prompts, ~1k input tokens each
   ```

2. Edit `routing/policy.json` for your gateway: one family per set of interchangeable model groups
   (their `model_name`s in LiteLLM's `model_list`), each model's `tier`, `price_in` (USD per
   million input tokens) and tags (`first_party`, `frontier`, `tools`).
3. Put the module next to the proxy's `config.yaml` (copy, symlink, or a Docker bind mount of the
   file next to `/app/config.yaml`) and add the callback; see `routing/litellm-config.example.yaml`.
   A copy or a mount also needs `policy.json`, `questions.json` and `setup/redact.json` mounted and
   named by the variables below; a symlink into this repo finds them itself:

   ```yaml
   litellm_settings:
     callbacks: ["reflex_router.proxy_handler_instance"]
   ```

   If `callbacks` already lists something (e.g. `"prometheus"`), add it to that list.
4. Give the proxy the environment below and restart it. Start in `shadow`; after a week, read
   `routing.jsonl` (`chosen` vs `applied`, `violation`, `action: block`, `source: fallback`) before
   `enforce`. For stickiness across several workers, share LiteLLM's key cache through Redis
   (`litellm_settings.enable_redis_auth_cache: true`); the router then keeps each conversation's
   model there too.

| Variable | Default | Meaning |
|---|---|---|
| `REFLEX_ROUTING_MODE` | `shadow` | `off` · `shadow` (log only, no added latency) · `enforce` (rewrite the model) |
| `REFLEX_ROUTING_POLICY` | `routing/policy.json` next to the module | Families, pools, tiers, stickiness, latency budget, cache TTL, fallback |
| `REFLEX_ROUTING_QUESTIONS` | `routing/questions.json` next to the module | The three Jev questions |
| `REFLEX_REDACT` | `setup/redact.json` beside the module's directory | Secret patterns shared with the gate; without it routing is skipped (requests keep their model) |
| `REFLEX_DATA_DIR` | `~/.local/state/reflex` | Where `routing.jsonl` is written (inside Docker, mount a volume) |
| `TYPESAFE_API_KEY` / `REFLEX_KEYCHAIN_SERVICE` | none / `typesafe-api-key` | Same key lookup as the gate; the Keychain is not reachable from a container, so use the variable there |
| `REFLEX_MODEL`, `REFLEX_API_URL` | as the gate | Jev model and endpoint |

## Optional: context layer (pi and oh-my-pi)

Installed with `node install.mjs --agent pi,omp --context` (see step 3). What it does, and what it
sends to TypeSafe, is in [GUIDE → Context layer](GUIDE.md#context-layer-pi-and-oh-my-pi). Its
variables:

| Variable | Default | Meaning |
|---|---|---|
| `REFLEX_CONTEXT_TIMEOUT_MS` | `8000` | Budget for one context-layer Jev call (up to 24 questions), capped at 25000 (omp gives a handler 30 s); on timeout the context is left as it was |
| `REFLEX_CHUNK_DAYS` / `REFLEX_CHUNK_MB` | `7` / `200` | Context-layer chunk store: delete chunks unused for this many days, then the least recently used beyond this size |
| `REFLEX_CACHE_READ` / `REFLEX_CACHE_WRITE` | `0.1` / `1.25` | Prompt-cache read and write price as a fraction of uncached input, for the rebuild-or-keep decision |
| `REFLEX_CONTEXT` | set by `install.mjs` | Path to `context.mjs` for the pi / omp context extension |
| `REFLEX_REVIEWER` | none | Reviewer command for `scripts/reflex-review`, e.g. `codex exec -s read-only -` |

## Optional: Grafana

Push a snapshot of the metrics to a Prometheus Pushgateway, e.g. every five minutes from cron:

```sh
*/5 * * * * cd /path/to/reflex && /usr/local/bin/node report.mjs --push http://localhost:9091 >/dev/null
```

Import `dashboards/reflex.json` into Grafana (it asks for the Prometheus data source) or drop it
into a provisioned dashboards folder. Metrics carry a `user` label, so one Pushgateway can serve a
team.

## Uninstall

```sh
reflex uninstall                    # hooks, package and link; keep user settings, policy and logs
#   or: curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash -s -- --uninstall
#   or, from a checkout:  node install.mjs --agent all --uninstall
rm -rf ~/.local/state/reflex        # optional: logs, the context layer's chunk store, bundles, reviews
```
