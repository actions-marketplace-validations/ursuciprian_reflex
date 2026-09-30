# Contributing to Reflex

Changes land through a pull request against `main`; nothing is pushed to `main` directly.

## Before you open a PR

```sh
npm test          # offline self-checks: no network, no API key, a few seconds
```

`npm test` runs the self-checks of every component (`policy`, `gate`, `instructions`, `install`,
`guard`, `judge2`, `autonomy`, `context`, `router`, the LiteLLM router) plus the isolated onboarding journeys (supervised and autonomous, with a stub judge and fake `claude` / `codex` CLIs) in `test.mjs`, and is what CI runs on every PR.
No PR may be opened before the full offline suite passes. Record the results and any live-client
verification limits in the PR. The integration checks cover setup previews, invalid configuration,
upgrades, durable policy, diagnostics, local privacy, native hooks, plugin approvals and uninstall.
The pi event harness uses Node 22's built-in TypeScript stripping; CI includes Node 22 coverage.

The `eval` scripts are different: they call the live Jev API and cost tokens.

```sh
npm run eval              # setup/tool-gate/golden.json: 90 labelled commands
npm run eval-router       # router/golden.json: tool and argument choice, nothing is executed
npm run eval-routing      # routing/golden.json: model choice for 27 prompts
npm run eval-context      # setup/context/golden.json: what the visibility ladder keeps visible
npm run eval-instructions # examples/instructions/golden.json: which fragments load
npm run eval-injection    # setup/injection/golden.json: 43 tool results, injection or not
npm run eval-ladder       # setup/tool-gate/ladder.json: the escalation ladder, Jev live, stub System 2
npm run eval-ladder -- --engine local   # the same keyless: no Jev, offline, only unsafe approvals scored
```

They need `TYPESAFE_API_KEY`, they are non-deterministic (Jev's answers vary run to run), and they
are not run in CI. Run the one matching what you touched and paste the summary in the PR.

## Behaviour lives in JSON, not in code

`setup/tool-gate/` holds the rules, the questions, the policy thresholds, the subgoal rules and the
golden set; `setup/redact.json` the secret patterns; `routing/` and `router/` the routing and tool
catalogues. Most changes that alter a decision are a JSON edit, not a code edit.

When you change rules, questions, policy or redaction:

1. Add a case to `setup/tool-gate/golden.json` for the behaviour you want, before changing anything.
   `expect` is the outcome we want, not what the current policy does; `allow: true` marks a command
   that should be allow-eligible, `allow: false` one that must never be auto-allowed.
2. Run `npm run eval`. A `MISS` (a risky command judged too softly) fails the run and blocks the PR;
   an `over` (stricter than wanted) is friction to fix when it is common.
3. A surprising decision you see in a trace, in your own use or in an issue, becomes a golden case.

## Invariants a reviewer will hold you to

- **The guard only adds friction, never permission.** A finding can add a note, remove text, taint a
  session or block a prompt; nothing it does makes the gate looser, and any error passes.
- **The gate can only tighten.** Nothing new may emit `allow` outside the calibrated allow gate, and
  that gate stays as narrow as the checks in `jev.mjs` and `gate.mjs` make it: unseen code, unsandboxed retries,
  plan mode, commands without a stated intent, redacted commands and code Jev did not see never
  allow. The autonomous profile adds exactly two sources of `allow`, System 2's approve and a
  human's queue approval (`view()` in `gate.mjs`), both behind the same held prompts, and neither
  for a rule outcome, the always-human class or a tainted session's egress.
- **System 2 never approves by accident.** Anything but a strictly valid verdict (an error, a timeout,
  a refusal, prose, a spent budget, an open breaker) is `human`; the always-human class is data in
  `setup/tool-gate/escalation.json`, and `autonomy.mjs --selfcheck` proves it with a judge that
  approves everything.
- **Errors fail towards `ask`.** In enforce mode every failure path (Jev down, timeout, unreadable
  setup file, incomplete answer, adapter crash) ends in the policy fallback, never in a pass.
- **Nothing unread is allowed.** A script a command runs is inspected before the command is judged;
  code the judge never saw is never allow-eligible.
- **Judged data is redacted first, and the redaction is shared.** `setup/redact.json` is read by
  both the gate (`config.mjs`) and `routing/reflex_router.py`; its `corpus` is asserted by both self-checks, so
  add a pattern *and* a corpus line together. Patterns must mean the same in JavaScript and Python.
- **A new agent integration is a new adapter, not a new decision path.** It calls the same core with
  the same rules, questions, policy and logs, and documents in the README table what `ask` and
  `allow` mean on a hook that cannot prompt.

## House rules

- No dependencies. Node 18+ stdlib for the `.mjs`, Python 3.9+ stdlib for the LiteLLM hook (a real
  dependency would have to be argued for in the PR).
- `npm test` stays offline, keyless and under a minute; it may use a throwaway `HOME` and a fake Jev
  server on localhost, never the network.
- Comments name the limitation instead of hiding it (what a pattern does not cover, what is
  heuristic). Match that style.
- The docs are three files with different jobs: README (what it is, install), `docs/SETUP.md`
  (install, configure, verify), `docs/GUIDE.md` (how it works, test, tune, limits). Update all three
  when a flag, a default or a limit changes.
- Do not rewrite git history: `setup/context/golden.json` pins commit `b41c8c1`, and
  `npm run eval-context` breaks if it stops existing.
- A script does its work only when started: put it under `if (isMain(import.meta))` (`failsafe.mjs`),
  so importing the file runs nothing. `test.mjs` imports every file with a scratch HOME and fails on a
  write or a started process.
- Keep the working tree free of generated state: logs, cache, chunk stores and bundles go under
  `~/.local/state/reflex` (`REFLEX_DATA_DIR`), never in the repo.

## Repository layout

| File | What it is |
|---|---|
| `gate.mjs` | The decision core and CLI: `precheck` (the order of the rule, tamper, script and fast-lane checks), the prod tier, freezes, `judge`, `decide`, the tool gate, logs, and the Claude Code / Codex / Hermes hook adapters. Re-exports what the modules below define, so other files import from `gate.mjs` |
| `config.mjs` | The gate's settings: `config.json`, the environment and the hook flags, `CONFIG`, `configurationError()` and its checks, secret redaction. Imports no other gate module |
| `shell.mjs` | Shell reading: `maskQuotes`, `shellWords`, data heredocs, and the other spellings the rules read (`ruleSpelling`, `wordSpelling`, `gitPlain`, `awsPlain`) |
| `scripts.mjs` | The local scripts a command runs (`localScripts`) and their lines for the script rules |
| `readonly.mjs` | Read-only detection: `readOnlyLegacy`, `readOnlySimple`, their tables and flag allowlists, and `pipelines()` |
| `rules.mjs` | The setup files (`load`), `checkRules`, `rulesHit`, the fast lane, and the deny rules on a command too large to check (`largeDeny`) |
| `tamper.mjs` | What a command changes of Reflex itself: the cd tracking (`cdDirs`, `writesView`), the checkout, data and config directories in any spelling (`touchesOwn`), a nested checkout (`staysNested`), the files it protects inside the checkout, read from the checkout (`namesOwnFile`, `OWN_DIRS`; the gate selfcheck fails on a file it does not cover), the reflex CLI forms that change Reflex, the plugin's own commands |
| `jev.mjs` | Jev: the call's context, the provider's key and where it may go, `ask`, the answer cache and `jevJudge` |
| `selfcheck.mjs` | `node gate.mjs --selfcheck`: the gate's offline self-check (not in the plugin bundle) |
| `autonomy.mjs` | The escalation ladder (autonomous profile): the always-human class, System 2 escalation, the verdict cache key and the breaker, the approval queue, task envelopes, checkpoints, and `reflex queue` / `envelope` / `checkpoints` |
| `judge2.mjs` | System 2: the `cli`, `anthropic` and `openai-compatible` backends, the lean case under a token cap, strict verdict parsing, the verdict cache, tiers, budgets; the stub judge and fake CLIs for the tests |
| `eval-ladder.mjs` | Runs `setup/tool-gate/ladder.json` through the autonomous profile with Jev live (or keyless, `--engine local`) and an approve-everything stub System 2 |
| `guard.mjs` | Injection guard: detectors, one Jev request per tool result, the policy, rewriting, taint, credential checks on prompts, the Claude Code / Codex / Hermes hook adapters, `--scan` / `--prompt` for the plugins, `--check` (`reflex scan`) and `--eval` |
| `setup/injection/` | `detectors.json`, `questions.json`, `policy.json` (including `sources`: which tool results are inspected), `golden.json` |
| `instructions.mjs` | Conditional instructions: fragment discovery, path / keyword matching, one Jev request per prompt, and the Claude Code / Codex / Hermes prompt hooks |
| `eval-instructions.mjs` | Scores fragment selection against `examples/instructions/golden.json` with the live API |
| `examples/instructions/` | Example fragments (front end, billing, Terraform) in a fixture repo, and the golden set |
| `adapters/` | `pi.ts` (pi and oh-my-pi extension), `pi-context.ts` (pi / oh-my-pi context layer), `opencode.js` (opencode plugin) |
| `context.mjs` | Context layer core: visibility ladder, chunk store, per-request assembly and cache decision, `/fresh` recall, retrieval bundles |
| `scripts/reflex` | The CLI: `setup` (what `curl` / `npx` / `pnpm dlx` / `bunx` run), `check`, `report`, `install`, `uninstall`, `test`, `eval`, `version` |
| `scripts/reflex-sh` | Drop-in `bash -c` for agents without hooks |
| `scripts/reflex-review` | Background cross-model review that consumes a retrieval bundle |
| `policy.mjs` | Policy evaluator: ordered gates over answers, no `eval`, no domain knowledge |
| `setup/tool-gate/` | `rules.json`, `questions.json`, `policy.json`, `golden.json`, `subgoals.json`, `escalation.json` (the always-human class and System 2's prompt), `ladder.json` (the escalation golden set): all behaviour lives here; `fixtures/` holds the scripts the golden set runs |
| `setup/redact.json` | The credential shapes and `KEY=` / `--password` patterns redacted before anything is judged or logged; shared by the gate and the model router, with a corpus both self-checks assert |
| `eval.mjs` | Runs the golden set through the real gate; exits 1 on any missed risk |
| `router/server.mjs` | Tool router: stdio MCP server (`find_tools`, `describe_tool`, `run`), Jev tool selection and argument filling, schema validation, gated shell execution, downstream MCP proxy |
| `router/mcp.mjs` | Newline-delimited JSON-RPC over stdio, server and client side (no SDK) |
| `router/commands.json` | Built-in command tools: name, description, argument schema, argv template |
| `router/config.json` | Downstream stdio MCP servers whose tools join the catalog (`mcpServers`, same shape as `.mcp.json`) |
| `router/golden.json` | Labelled intents for `npm run eval-router` (tool and arguments chosen by real Jev; nothing runs) |
| `router/test/` | Fake downstream MCP server and stubbed Jev for `npm test` |
| `install.mjs` | Adds / removes Reflex in each agent's config (`--agent claude,codex,pi,omp,opencode,hermes,all`; `--mode`, `--allow`, `--keychain`; `--context` / `--no-context` adds / removes the pi / omp context layer; `--router` prints how to register the tool router in each agent) |
| `install.sh` | The `curl` installer: fetches the package from npm and runs `reflex setup` |
| `report.mjs` | Summary, replay under a candidate policy, allow calibration from your approvals, Prometheus Pushgateway export |
| `dashboards/reflex.json` | Grafana dashboard for the pushed metrics |
| `examples/policies/` | Team policy packs (`aws`, `eks`, `terraform`, `startup-default`) for `reflex policy init --pack` |
| `action.yml` | The GitHub Action: validates `.reflex/policy.json` and fails on a denied command, with the npm package pinned to this version |
| `site/build.mjs` | Builds the docs website from README.md and docs/ into `site/dist` (`node site/build.mjs`); `.github/workflows/pages.yml` deploys it |
| `routing/` | LiteLLM pre-call hook for security- and cost-aware model routing (`reflex_router.py`, `questions.json`, `policy.json`, `golden.json`, an example LiteLLM config) |
