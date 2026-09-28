# Changelog

All notable changes to Reflex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Change freezes: a `freeze` list in `config.json` or a team policy. Each window has `days`,
  `after` / `before` (local `HH:MM`), `from` / `to` (inclusive dates), a `tz` read with `Intl`
  (default UTC), `applies_to` (`prod` or `all`) and `outcome` (`ask` or `deny`). During a window, a
  command that is not read-only and touches production, by the existing markers (cwd, AWS profile,
  kube context, Terraform workspace, git branch, the command, team prod markers), gets a rule
  decision such as `change freeze: Friday after 15:00 (Europe/Bucharest)`. It applies in every
  mode, is in the always-human class, overrides a fast lane pass and never softens a rule deny.
  Validation is strict: an invalid window makes a team policy invalid (no fast lane, no webhook;
  valid windows still apply) and is a configuration error in `config.json` (every command asks).
  `reflex status` shows whether a freeze is active now.
- `reflex audit [--since 7d] [--format csv|json|jsonl] [--prod-only] [--agent a]`: one row per
  decision with time, agent, session, cwd, production tier and why, the redacted command, the
  decision, source, rule and who approved it (queue, System 2, the agent's prompt). Read-only over
  the trace (rotated files included), the queue and the feedback log. Csv cells that a spreadsheet
  would run as formulas are quoted.
- A decision webhook: `notify: {url, on: ["deny", "ask", "prod"], format: "json" | "slack"}` in
  `config.json`. https, or http on localhost only; redacted command and reason, no environment
  values; posted by a detached child with a 2 s timeout, no retries and no redirects, so the hook
  never waits. A team policy's `notify` applies only while the user trusts the file.
  `reflex doctor --notify-test` sends one dry-run message.
- The trace records each judged command's production tier (`tier`), its `rule_id` and its `cwd`,
  and a queue answer records who gave it (`decided_by`).

## [0.14.0] - 2026-09-28

### Added

- A demo GIF at the top of the README (`assets/demo.gif`): a real Claude Code session with the
  Reflex plugin in a scratch repository, where the injection guard removes a hidden instruction from
  a dependency README, a rule denies `git push --force origin main` and `terraform apply` in `prod/`
  asks. `docs/demo/demo.tape` records it with VHS, `docs/demo/setup.sh` builds the scratch repo and
  state under `/tmp/reflex-demo`, `docs/demo/redact.sh` covers the account line of the welcome
  banner, and `docs/demo/README.md` explains how to re-record it.
- Team policy: a repository can commit `.reflex/policy.json`, and every teammate's Reflex applies it
  while an agent works there. It adds rules (the `rules.json` shape, ask or deny; a team deny is
  checked before the bundled rules, a team ask after them), always-human patterns, production
  markers (a matching command that is not read-only asks) and a mode floor (`enforce` raises shadow;
  off stays off). It has no key that removes or relaxes anything, and an unknown key makes it
  invalid. Team patterns run on V8's linear-time regular expression engine (patterns it cannot run
  that way are rejected), so a policy cannot stall the hook into its timeout. Stricter parts come
  from every repository root around the working directory (a `.git` created in a subdirectory does
  not shed them), the fast lane from the nearest root only; roots and files must be owned by the
  user, a `.reflex` without `.git` is never read, and a symlinked file is refused.
- `reflex trust [dir]` and `reflex trust --revoke [dir]`: a team policy's `fastlane` entries apply
  only while the user trusts that exact file. Trust records the repository and the file's sha256 in
  `~/.config/reflex/trusted.json`; any change to the file drops it until it is trusted again. It
  needs a terminal and refuses inside an agent session. Team fast lane entries are validated like
  `fastlane.json` and never pass over a deny, a secret read, the tamper check, a prod marker or the
  always-human class. An invalid file never loosens; its valid stricter parts still apply.
- `reflex policy [dir]` shows a repository's team policy; `reflex policy init [dir]` writes a starter
  with stricter examples only and never overwrites.
- `reflex status` and `reflex doctor` show the team policy of the current directory: path, trust,
  hash and what it adds; doctor warns when it is invalid or changed since it was trusted.

### Changed

- Tamper check: a shell command that writes under `.reflex/` (also through a `.ref*` style glob, or
  naming `policy.json` where a team policy applies), or a command or local script that calls
  `reflex trust`, `reflex policy init` or `team.mjs` or names `trusted.json`, asks a human.
  `reflex setup` adds `Edit(**/.reflex/**)` to Claude Code's ask rules. A team policy's rules can
  bring their own test (`checkRules` calls `rule.test` when present).

### Fixed

Fourth review of the read-only parser (#43). Each change asks more often; none passes anything new.

- Option-sensitive tools (every tool in the unsafe-flag list or with a read-only subcommand list, plus
  sed, date, file and printf) are read-only only when their words hold no expansion at all: no
  variable, no command substitution, no arithmetic, no brace list and no glob, before or after `--`
  (`xxd -- *` can write the second file, `awk -- *` runs a file name as its program). The
  per-binding exceptions (`F=notes.txt; sed -n 1p "$F"`) are gone. The one word kept is a
  double-quoted `$name` inside a word that starts with a literal path, such as
  `gh api "repos/$R/pulls"`, and never for sed or awk. printf then still reads options in its first
  word only, and a first word with an expansion is not read.
- awk is read-only only when its program text has no `@`, `|`, `>`, `PROCINFO` or `ENVIRON` and none
  of the words `system`, `getline`, `close` or `fflush` (`awk '/closed/'` still reads), and there is
  no `-f` or `-i`. A `>` comparison now asks too. awkSafe is the only awk check.
- sort and tree `-o`, fd `-x` and yq `-i` / `-s` are caught clustered or with the value attached
  (`sort -ro out`, `sort -oout`, `fd -xrm`). A sort long option is read the way getopt_long reads
  it: any prefix of `--output`, `--compress-program`, `--random-source` or `--temporary-directory`
  (`--o=out`) is not read-only. `tree -R` (which writes with `-H`) is not read-only either.
- The rules read brace sequences (`ma{i..i}n`), nested lists and several braces per word, with quotes
  kept, so the force-push rules still deny. A word that would expand past 256 words (1,024 in all)
  asks, unless a deny rule fires. A word whose braces are only sequences, at least one numeric, is
  counted and not expanded (no ref or option comes of it), so `for i in {1..300}` is not an ask.
- Over 32 KB the deny rules run before the size ask, on overlapping windows and in every spelling,
  on the same views precheck reads (a command that only writes notes is not read for shell rules),
  until the deadline: a large command never turns a deny into an ask.
- `precheck` shares one deadline across the spellings it recurses into, and scans each local script
  once per call, so the total stays under the hook timeout.
- `shell-startup` (rules-v19) also catches `tee` with several files and a startup file copied into a
  directory (a last word ending in `/` or `/.`, or `~`, `$HOME`). Every part starts from the file
  name or the destination and looks back a bounded distance, so 32 KB of `tee` checks in under
  50 ms and 32 KB of `cat .zshrc` in under 10 ms.
- The user fast lane and the report's fast-lane candidates drop git's global options before the
  always-human and rule checks (`rulesHit`, shared with `alwaysHuman`).
- An escaped `\(` in `find . \( -name a -o -name b \)` no longer trips the zsh glob-qualifier guard.
- In a nested worktree, cd targets, path words and short options with an attached value (`-Cdir`,
  `-tdir`, `-ofile`: the value after one to three flag letters, at most PATH_MAX long) are resolved
  with `realpathSync` before they count as staying inside it. A
  symlink out of it, a path that cannot be resolved, or a check past the deadline restores the
  checkout view. Real paths are cached per call, so 8 KB of cds checks in well under 500 ms.

## [0.13.0] - 2026-09-28

### Added

- Codex CLI plugin: `codex plugin marketplace add ursuciprian/reflex`, then
  `codex plugin add reflex@reflex`, then trust the hooks in `/hooks`. `.codex-plugin/plugin.json`
  points Codex at `hooks/codex.json`, which wires the same events, matchers and timeouts as
  `install.mjs --agent codex` and runs the gate, the instruction layer and the injection guard with
  `node` from `$PLUGIN_ROOT`. `.agents/plugins/marketplace.json` is the Codex marketplace. A test
  keeps `hooks/codex.json` in step with `install.mjs` and the manifest version with `package.json`.
- opencode plugin: the npm package's `main` is `adapters/opencode.js`, so
  `"plugin": ["@ursuciprian/reflex"]` in `opencode.json` loads the same plugin `reflex setup --agent
  opencode` writes. Unfilled, it runs the package's own gate with `node` from `PATH`, and the gate
  reads the mode and allow on every call, as for the other plugins.
- `reflex status` and `reflex doctor` print which path runs the Codex hooks and the opencode plugin;
  doctor runs the Codex plugin's installed hook command through `$SHELL -lc` when the plugin is the
  active one, and status warns when untrusted setup hooks silence the plugin.

### Changed

- The Codex plugin's hooks stand down when `reflex setup` hooks are in `$CODEX_HOME/hooks.json`
  (default `~/.codex/hooks.json`), and the opencode npm plugin registers no hooks when the setup
  plugin file is in opencode's global plugins directory, so a call is never judged twice. A setup
  entry whose gate no longer exists does not count.
- `codex plugin marketplace add ursuciprian/reflex` used to find only the Claude Code manifest and
  run Claude Code hooks (`--claude` flags, `PermissionRequest`) in Codex; Codex now reads
  `.codex-plugin/plugin.json` first.
- `install.mjs` writes the Codex hooks under `$CODEX_HOME` and the opencode plugin file under
  `$XDG_CONFIG_HOME` when those are set, where the agents read them; before, it always wrote
  `~/.codex` and `~/.config`, which those agents then ignored.
- The `tamper` rule asks before `codex plugin remove` and `codex plugin marketplace remove`.
- The `reflex` skill and `/reflex:status` no longer assume Claude Code, since Codex loads them too.

## [0.12.0] - 2026-09-27

### Added

- Claude Code plugin with its own marketplace in this repository: `/plugin marketplace add
  ursuciprian/reflex`, then `/plugin install reflex@reflex`. `hooks/hooks.json` wires the same
  events, matchers and timeouts as `install.mjs --agent claude` and runs the gate, the instruction
  layer and the injection guard with `node` from `${CLAUDE_PLUGIN_ROOT}`: no build step, no
  `node_modules`, no npx at hook time. A test keeps `hooks/hooks.json` in step with `install.mjs`
  and `plugin.json` in step with `package.json`.
- Read-only plugin commands `/reflex:status`, `/reflex:check <command>`, `/reflex:report`,
  `/reflex:replay`, `/reflex:queue` and `/reflex:suggest` (never `--write`), and a `reflex` skill on
  when to use `reflex check` and `reflex replay`.
- `reflex status` and `reflex doctor` print which path runs the Claude Code hooks (the plugin or
  `reflex setup`); doctor probes the plugin's gate when the plugin is the active one, and status
  warns when System 2 is on under the plugin's 10 s hook timeout.

### Changed

- Plugin hooks stand down when `reflex setup` hooks are in the Claude Code settings file
  (the user settings file Claude Code reads, where `reflex setup` writes them): they exit before
  reading their input or writing a log line, so a call is never judged or counted twice. A settings
  hook whose script no longer exists does not count, and `reflex status` reports it as an error.
- With no saved engine, the gate starts with the local engine, as a fresh `reflex setup` does (Jev
  when `TYPESAFE_API_KEY` is set, or a Keychain item or an earlier install is recorded). It used to
  default to Jev.
- Rules v16: `reflex check '<cmd>'`, `reflex report`, `reflex replay` and `reflex suggest` pass the
  fast lane like `reflex status`, without the flags that send data, write files or pick an engine
  (`--push`, `--write`, `--engine`). The `tamper` rule also asks for `claude plugin disable`,
  `uninstall` and `marketplace remove`, and for writes under `~/.claude*/plugins/` and any
  `~/.claude*/settings` file.

## [0.11.0] - 2026-09-27

### Fixed

- Read-only detection now reads each word the way the shell passes it: backslashes dropped, `$'…'`
  decoded, quoted parts joined. `sed -\i`, `gh api $'\x2dX' DELETE`, `nvidia-smi -\pm 1` and
  `journalctl --\rotate` (also over ssh) are the options they spell, not reads.
- An expansion among the words of a command whose options decide what it does (sed, awk, find,
  sort, git, gh, docker, journalctl and the rest of the tools with a read-only subcommand list) makes
  it not read-only, unless the command itself sets that name to literal values none of which starts
  with `-`: `X=-i; sed $X …`, `sed $(echo -i) …`, `o=--method=DELETE; gh api $o …` ask. `printf -v`
  is not read-only either (it can set PATH).
- sed is parsed as sed parses it, GNU and BSD: its options (in place, `-f`, unknown options) and its
  script, command by command. w, W and e are found with or without a space and after any address
  (`1w/path`, `$w/path`, `1etouch x`), and so are the s flags w and e (`s/a/b/w/path`).
- gawk options that write a file or load code are not read-only in any spelling or unique prefix:
  `--profile`, `--pretty-print`, `--dump-variables`, `--debug`, `-p`, `-o`, `-d`, `-D`, values attached.
- `docker compose config -o f` and `--output f` write a file again (a regression from narrowing `--output`).
- `journalctl --cursor=…` is read-only: an exact safe option is not a prefix of `--cursor-file`.
- An ssh call with a loop variable host is read only when every place its text appears is inside
  a loop over literal hosts (`for h in a; do ssh $h …; done; ssh $h …` asks).
- The ssh-local-command rule (ProxyCommand, LocalCommand, Match exec) runs before read-only
  detection, so it asks whatever readOnly says.
- In a git worktree nested in the Reflex checkout, the checkout's tamper check applies again when
  the command leaves the worktree in a way the tracker cannot follow: `cd -`, `$OLDPWD`, `popd`,
  `pushd ±N`, `cd "$(…)"`, `cd ~`, an absolute directory elsewhere, or `..`. Paths through `~` or
  `$HOME` name the checkout wherever it was cloned.
- An interpreter heredoc (`python3 - <<'EOF'`) skips the shell rules only when every line prints
  string or number literals (print, puts, echo, console.log), with no interpolation and no import
  (`python3 -` imports from the working directory first). This replaces a keyword denylist that
  missed indirect execution (dynamic import, `__send__`, `open '-|'`, `locals()`). The interpreter
  must be a bare name or live in /usr/bin, /usr/local/bin, /bin, /opt/homebrew/bin, or pyenv or nvm
  shims in the home directory: `/tmp/x/python` is not an interpreter.
- force-push-main: a ref followed by a redirect, comment, brace or backtick (`main>/tmp/log`) is
  denied again; a push option naming main (`-o merge_request.target=main`) is not a ref; the check
  for main next to a push with an expansion is linear (200 KB took 2.6 s, now milliseconds).
- A command over 128 KB is asked about rather than checked (`command-size`).
- git global options (`-C`, `-c`, `-P`, `--git-dir`, `--work-tree`, `--no-pager` and the rest,
  quoted values too) are dropped once for the rules, the tainted rules, the always-human class and
  script lines, instead of being pasted into every git pattern (rules-v15).
- Redaction: `htpasswd -nb user pw` (no file), a quoted `smbclient -U 'DOM\user%pw'`,
  `sudo --stdin`, and `echo a multi word value | sudo -S`.
- Redaction of `echo … | sudo -S` no longer backtracks exponentially on a run of quoted words, and
  git options whose value is `$(…)`, `${…}` or a backtick span are dropped too (`git -C $(pwd) push -f
  origin main` denies again).
- More read-only gaps found in review: a sed `-e` piece ending in a backslash (BSD ends a\ text
  there, so the next piece runs as commands), BSD `-l` taking no value, a NUL escape in `$'…'`,
  bracket expressions in sed regexes (`s/[/]/…`; this also makes `sed 's/[^/]*$//'` a read again),
  awk program text read as the shell passes it (`sys''tem`, `$'\x73ystem'`), gawk `-W` long
  options, brace expansion into options (`sort {-o,out}`), zsh `=(…)` and glob qualifiers
  (`*(e:…:)`), and a glob that could match a file named like an option (`sed -n p *`, not after `--`).
- Third review: an interpreter heredoc skips the shell rules only with no comments and ASCII only
  (a `# coding:` line, a `#!` line or `?>` in a comment changes what runs). Commands over 32 KB
  ask, and so does a check that takes over 3 s (a deny stands). In a nested worktree a cd target
  with a glob, a brace, `~user` or an expansion, `CDPATH`, or an `ln -s` in the command restores
  the checkout view. force-push-main and the other rules also read the words as the shell passes
  them (`ma\in`, `$'ma\x69n'`, `m{a,}in`, `-\f`, `pu\sh`). A deny in a script the command runs
  wins over an ask the command itself got. Redaction of `echo … | sudo -S` allows redirects in the
  echo, and `htpasswd -C 10 -b` is redacted.
- `shell-startup` asks only on writes (redirects, tee, `sed -i`, sed w, cp, mv or install onto the
  file, an option value naming it), not on reads such as `source ~/.zshrc` or `cp ~/.zshrc /tmp/x`;
  it covers .bash_aliases, .bash_logout, .zlogout, .envrc and fish config too.
- eval-ladder.mjs uses a data directory of its own unless REFLEX_DATA_DIR is set, so another run's
  trace, cache or runaway state cannot change who resolves a case.
- An ask from an early rule or the tamper check no longer hides a deny rule that also matches: the
  more severe outcome wins, as it already did between spellings.

### Added

- Rule `shell-startup` (ask): a command that changes .zshrc, .bashrc, .profile or another shell
  startup file, which runs in every new shell. Reads the writes view, so reading one is not it.

## [0.10.0] - 2026-09-27

### Added

- Runaway guard: watches each agent session in the hook path and stops it when it loops (the same
  command 10 times, a read-only one 20, or the same failing command 8 times, in 5 minutes), storms
  the gate (8 denies in 5 minutes), burns (50 commands a minute, 2000 Jev answers or 150 System 2
  calls a session) or climbs in risk (the last 4 commands that were not denied average blast 2.5 of
  3, up by 1). Enforce denies with a reason the
  agent can act on; shadow logs. Traced (`source: "runaway"`), parked in the queue when it is on,
  shown in `reflex status`, `reflex report` and `reflex replay`; `reflex runaway [list|reset]`.
  `runaway` in config.json, `REFLEX_RUNAWAY=off`. Never allows anything, no API calls, a bounded
  per-session window. Defaults tuned on 30 days of real sessions: 5 of 383 stopped, all spin loops
  of one benchmark session except one Codex session reading secret files. See docs/GUIDE.md.

- `reflex suggest [claude|codex|opencode|pi|all] [--since 30d] [--project path] [--min N] [--json] [--write [--yes]]`:
  fast-lane entries for the build, test and lint commands your agents keep asking about, to reduce
  approval prompts. Reads the transcripts `reflex replay` reads and runs nothing. Templates keep every
  argument literal except numbers and, for test runners and linters, repository-relative paths;
  a template is suggested only when it names no denied word (deletes, pushes, deploys, installs,
  network tools, cloud CLIs, secrets, production), every observed run passes in the hook's own code
  with its scripts read in full, it is outside the always-human class and it rejects flag, path and
  second-command probes. Prints the count, masked samples, why each is safe, and asks per 100
  commands before and after; when nothing qualifies, what keeps asking.
- User fast lane, `~/.config/reflex/fastlane.json`: anchored, wildcard-free patterns scoped to a
  project directory, read after the bundled fast lane. It never overrides a rule, a tamper ask or
  the always-human class, and the denylist, `cd` and script checks apply at run time. An invalid
  file is ignored whole and `reflex doctor` warns. `reflex suggest --write` appends to it after
  showing the lines and asking (or `--yes`); when an agent runs it, the tamper rule asks a human.
- `docs/FAQ.md`: 20 questions about Reflex with direct answers (Claude Code and Codex CLI
  guardrails, permission prompts, sandboxes, API keys, Jev and Laya, cost, latency, data, prompt
  injection, autonomous agents, trying it safely, uninstalling), and a short FAQ in the README.
- `llms.txt` and `llms-full.txt` (llmstxt.org format) and `CITATION.cff`, all three in the npm
  package.
- README: a one-sentence definition and an "In one minute" summary at the top, feature headings,
  descriptive image alt text and link text. Docs pages have titles that say what they cover.
  `package.json`: description, keywords and author match the README.

### Security

- `tamper` missed writes to agent or Reflex settings reached through a directory change in the
  same command: `cd ~/.claude && jq … settings.json > s.tmp && mv s.tmp settings.json`,
  `pushd ~/.config/reflex; echo x > config.json`, `(cd ~/.codex && tee hooks.json)`. The gate now
  follows `cd`, `pushd`, `popd`, `cd -`, subshell parentheses and a literal `D=…; cd $D`, and
  resolves the relative arguments and redirect targets after it against that directory when it is
  one the rule watches (an agent's settings or hooks directory or a parent, a directory named
  reflex, the checkout, the Reflex data or config directory). A cd itself writes nothing, so a
  pure read after it (`cd ~/.claude && jq . settings.json > /tmp/x`) is not tamper.
- `git push --force` of the current branch (`HEAD`, `+HEAD` or no ref) where the branch is not
  known asks, before the engine (new rule `force-push-unknown-branch`, rules-v14).
- `git push --force origin m''ain` (and `'ma'in`, `ma""ster`): the shell joins quoted parts of a
  word, so the rules now also read the command with those quotes dropped. `force-push-main` denies.
- `node --check` with `-r`, `--require`, `--import`, `--loader`, `--env-file`, a config file, `--run`
  or `--build-snapshot` is no longer the fast lane: those still run code before or instead of the
  syntax check.
- Rules also read the command as readOnly reads it (`/bin/cat` as `cat`, `timeout -k1 5 cat` as
  `timeout 5 cat`), and the more severe of the two rule outcomes wins, so a new read-only spelling
  cannot skip `secret-file-read` and a joined spelling cannot turn a deny into an ask.
- `docker exec c cat .env` (and `~/.aws/credentials`, a private key) was read-only: the
  secret-file rule now reads the command a container runs. `find … -name .env … -exec` asks.
- `secret-read` keeps firing when the key goes to `/dev/null` and then somewhere else
  (`>/dev/null >&2`, `>/dev/null 1>&2`, a later `>file`), or with `-g`.
- A relative cd in the checkout (`cd setup/tool-gate && sed -i … rules.json`), a command that names
  no file after a cd into a watched directory (`cd ~/.claude/hooks && make`), and `pushd`/`popd`
  rotations the tracker does not follow (bare `pushd`, `pushd +1`, `popd +1`, `CDPATH`) keep every
  cd in the command visible to `tamper`.

### Fixed

- Read-only spellings that asked for no reason (latency only):
  - `ssh -J a h -J b uptime` and `ssh h -J b 'uptime'`: options after the host go through the same
    allowlist (ssh reads them); `--` or an option that runs a local command there still refuses.
  - `ip` object and verb prefixes that iproute2's first match makes show, list or get:
    `ip ne s`, `ip l l`, `ip r g`, `ip n g`, `ip addre l`. `ip l s` (link set) and `ip r sa` still ask.
  - `timeout -k1 5 ssh h uptime` and `timeout --signal=KILL 5 …`: timeout's options are read.
  - `ssh h find . -name .env` lists files; `.` there is a path, not the source builtin.
  - `/usr/bin/grep`, `/bin/cat`, `/usr/bin/git log`: a program from `/bin` or `/usr/bin` is that program
    (and the rules read it as that program).
- False positives from a replay of a real week:
  - `jq -r '.env // {} | keys' ~/.claude/settings.json` read the jq field as a `.env` file. Inside
    a quoted word a file name now ends at the quote.
  - `security find-generic-password … -w >/dev/null 2>&1; echo $?` counted as printing the key.
    A lookup whose output goes to `/dev/null` (and nowhere else) is not `secret-read`.
- `reflex replay` read newer Codex rollouts' `file://` working directories as relative paths, so
  local scripts were not found and project filters missed those commands.
- README: the replay section has numbers for v0.9.0 on a new week, and what the fixes above change.

## [0.9.0] - 2026-09-26

### Added

- `reflex replay [claude|codex|opencode|pi|all]`: what the gate would have done with the shell commands
  already in local session transcripts (Claude Code, Codex, opencode via `node:sqlite`, pi). Counts
  read-only and fast-lane passes, rule asks and denies, engine decisions, asks per 100 commands
  (supervised) and System 2 versus human (autonomous), the top rules and a masked sample.
  `--since`, `--project`, `--limit`, `--json`. Nothing is executed and nothing is written: shadow
  mode, no answer cache, no System 2, queue or checkpoints. `--engine jev` prints a cost estimate
  and what would be sent, and calls Jev only with `--yes`; then tokens and spend come from `usage`.
- `reflex bench`: precheck latency p50/p95 on a fixed command set; with `--engine jev|laya`, one
  call per fixed command the rules leave open (from an empty directory), with tokens and cost per
  1,000 calls.
- More remote reads are read-only: `ssh -o ProxyJump=…` (like `-J`), an unquoted remote command
  (`ssh h uptime`, plain words only, ssh in command position), and a host that mixes literal text
  with loop variables (`for i in 1 2 3; do ssh web-$i uptime; done`). `ip` show/list spellings per
  object (`ip a s`, `ip r`, `ip l sh`, `ip rule show`, `ip r get …`) and `systemctl` with no verb
  (`systemctl --failed`), `list-sockets`, `list-jobs` and `get-default`.

### Fixed

- `ssh -J a,-oProxyCommand=x` (and the same through `-o ProxyJump=`) was read-only: ssh pastes the
  last hop into a shell command line as a host, so it ran a local command. Every hop is now a plain
  `[ssh://][user@]host[:port]`, no `%`.
- `systemctl -p status restart api` and `systemctl --property status restart api` were read-only:
  the option took `status` as its value and the verb was `restart`. Before the verb only value-less
  options or `--opt=value` count.
- `journalctl --rot`, `--flu`, `--syn` and other unique prefixes of writing options were read-only
  (getopt_long expands them). No long option may be a prefix of one that writes.
- A loop word like `a@-F` made a host that is an option (`for h in a@-F; do ssh $h …`).
- `ssh h cat .env` (unquoted) now hits the secret-file rule like `ssh h 'cat .env'`, and so do
  `nl`, `sort`, `uniq`, `cut`, `paste`, `fold`, `column`, `diff`, `comm`, `cmp`, `tac` and `rev`.
- `case x in x) touch y;; esac` and `for i do touch y; done` were read-only: the whole segment was
  taken for a loop or case header. A header is now only a header; a case arm's command is judged.
- `awk -f`, `sed -f` (and gawk `-i`/`-E`/`-l`) run a program the gate never sees; `yq -i`/`-s` and
  `xxd in out` / `xxd -r` write files; `nvidia-smi -f` writes a log. None is read-only now.
- A quoted option was invisible to the flag checks (`sed "-i"`, `gh api '--method=DELETE'`,
  `nvidia-smi -"pm" 1`, `journalctl "--rotate"`): quotes around an option word are dropped first.
- A quoted heredoc fed to an unquoted ssh call counted as a plain word, so
  `ssh h awk -f - <<'EOF'` passed its body to the host as a read.
- New rule `ssh-local-command` (ask, before Jev): `ssh -o ProxyCommand|LocalCommand|
  PermitLocalCommand|KnownHostsCommand|Match …` or a `-J` / `ProxyJump` hop that is an option. Jev
  judged `ssh -J bastion,-oProxyCommand=/tmp/x.sh db-1 'uptime'` low risk in one eval run.
- `--output` only counts as a write for `git` and `sort`: `aws … --output json`,
  `journalctl --output=short-iso` and `systemctl --output=json` are reads again. `systemctl -t
  service list-units` (options that take a value) is read-only.
- False positives from a replay of a week of real agent commands (rules-v13, golden-v6):
  - `force-push-main` no longer fires on a branch whose name only contains main or master
    (`git push origin --delete feat/something-on-master`). It now looks for main or master as the
    ref pushed or deleted (`main`, `:main`, `+main`, `HEAD:main`, `refs/heads/main`, quoted or not)
    or the current branch (a ref that only a variable or substitution names still counts when main
    appears anywhere), and it also sees `git -C dir push`, `git -c k=v push`, `git -P push` and
    backslash-newline continuations, which it missed.
  - The shell rules (`rm-root`, `prod-destroy`, `force-push-main`, `push-mirror`, `destroy`) skip a
    command that only reads and writes notes (`touch MEMORY.md && echo '... rm / ...' >> MEMORY.md`,
    `reflex check 'rm -rf /'`), and the program of an interpreter heredoc when the whole command is
    a bare `python3 - <<'EOF' ... EOF` (node, ruby, perl and php too) and nothing in the body could
    run, load, write or delete anything. A wrapper (`ssh`, `docker exec`, `env`), a flag, an
    unquoted delimiter or anything before or after the heredoc keeps the body in. Such a command
    goes to the engine instead.
  - `tamper` reads what a command changes: a pipeline that only reads an agent's settings or the
    gate's files (`jq . ~/.claude/settings.json > /tmp/s.json`) counts by its redirect targets only.
    Writes still ask: redirects, `mv`, `cp`, `tee`, `sponge`, `sed -i`, `yq -i`. A GitHub
    `owner/reflex` slug or URL is not the local gate; `git add` and `git commit` in the checkout do
    not change its files; a git worktree nested in the checkout is another checkout unless the
    command climbs out with `..`.
- More reads that could write or run code are no longer read-only: `sed` `w` and `e` after a line
  address or as an `s///` flag (`sed -n '1w f'`, `sed '1e cmd'`, `sed 's/a/b/e'`), `awk` `@include`
  and `@load`, a redirect inside a double-quoted awk program, `find -fprint0` and
  `rg --hostname-bin`.
- Redaction covers `docker login -p` (and podman, nerdctl, buildah, skopeo, oras, az),
  `echo pw | sudo -S`, `... | docker login --password-stdin`, `sudo -S <<< pw`, `--x-password`,
  `--x-token` and `--x-secret` flags, `redis-cli -a`, `mongosh -p`, `openssl -passin pass:`,
  `keytool -storepass`, `htpasswd -b` and `smbclient -U user%pw`.

### Changed

- README rewritten: feature overview, reproducible scenarios with real `reflex check` / `reflex scan`
  output, measured results with their methods, and a comparison with other guardrails. The package
  description and npm keywords follow it. The docs no longer use em dashes.
- README: a replay section with a real week of agent history, and a Jev price note. Replay's Jev
  price is sourced and can be overridden with `REFLEX_JEV_USD_PER_MTOK`.

## [0.8.0] - 2026-09-26

### Added

- Experimental `--engine laya`: the tool gate, the injection guard, instructions, the tool router,
  model routing and the context layer ask their questions of a [Laya](https://huggingface.co/convaiinnovations/laya)
  checkpoint served on 127.0.0.1 (`setup/laya/server.py`, laya-serve's Jev-compatible app), so
  nothing leaves the machine and no key is needed. `reflex setup --engine laya [--dry-run]` checks
  Python >= 3.10, creates `~/.local/share/reflex/laya-venv`, installs `laya[serve]==0.3.20`, downloads
  the checkpoint at a pinned revision and starts the server; `reflex laya start|stop|status|
  install-service|uninstall-service` (pid file and log in the state directory; launchd or systemd
  --user only on request). A server that is down is a Jev outage: the policy fallback, logged, and
  `reflex doctor` / `status` report it. The wrapper splits multi-chunk states so each chunk's
  questions see their chunk, reports truncation in `usage`, asks yes/no questions as a neutral
  two-option choice (laya #156) and can apply per-question calibration (`setup/laya/calibration.json`,
  off by default). Default checkpoint `typed-decisions`, raw. The server requires a random local token
  and gets only the environment it needs; the TypeSafe key is never sent to it. With engine laya the
  allow gate is off and the server URL must be on 127.0.0.1.
- `npm run eval-compare -- --engines jev,laya:typed-decisions --runs 2`: every live golden set for
  several System 1 engines in the same run, one table.
- Measured head to head (GUIDE: Laya): zero-shot Laya is far below Jev on every golden set. Raw, it
  has no tool-gate MISS but denies or asks about 33 of 97 cases Jev settles; calibrated, it misses a
  deny Jev catches. `english` and calibrated checkpoints miss high-severity injections; instructions
  2 to 9 of 20 against Jev's 20. Jev stays the recommendation for every decision.

### Fixed

- `eval-ladder` no longer crashes when System 1 settles every case (no `judge.jsonl`).

## [0.7.0] - 2026-09-26

### Changed

- A remote command over `ssh` is read-only (a local pass, no Jev or System 2 call, in both engines)
  only when it is a provable read (#26): options from an allowlist with values that are neither
  options nor globs, a literal host or a plain variable set only by a `for` loop over literal host
  names that the call is inside, the quoted remote command last and read-only by the same rules (not
  the fast lane), no redirect, heredoc or pipe reaching ssh's stdin, and in a double-quoted remote
  command nothing the local shell expands. A session that read a suspected prompt injection still
  asks about it, as egress. `scp`, `rsync`, `sftp`, uploads and piping local files are unchanged.
- Read-only list: `free`, `nproc`, `lscpu`, `seq`, `systemctl` status and listing verbs,
  `journalctl` (not `--vacuum*`, `--rotate`, `--flush`, `--cursor-file`, …), `ip addr|link|route|neigh
  [show]` with display options only, and `docker exec [-t] [-u …] [-w …]` of a read-only command in a
  literally named container.
- The production pattern (`prod` always-human rule, `escalation-v2`; `prod-destroy` rule,
  `rules-v12`) treats `live` as an environment only where it names one (`envs/live`,
  `clusters/live`, `live/<region>`, `infrastructure-live`, `cd live`, `-chdir=live`, `live*.tfvars`,
  `--context live`, `--kube-context=eks-live-1`, `-n live`, `-h live-db`, `DEPLOY_ENV=live`,
  `terraform workspace select live`, `--live`, a profile, kube context or workspace containing it),
  not as a word: a checkout at `~/src/live-demo` or a scratch directory named `auto-live` no longer
  sends every uncovered command to a human (#27). `prod`, `production` and `prd` still count
  anywhere, except in `non-prod` / `pre-prod` and in file names ending in a document, log, data or
  image extension (`prod-notes.md`). Over 14,470 real commands it dropped 133 matches, all
  incidental, and added none; every production case in the selfchecks and golden sets is still caught.
  Its repetitions are bounded, so a long command cannot make it backtrack for long.
- Measured keyless on the same history: read-only 31.4 % → 33.1 %, a human before System 2 5.5 % →
  4.7 %, System 2 61.8 % → 61.0 %, calls per active day 115 → 112 (median) and 294 → 284 (p90). Most
  `ssh` commands that still escalate are not reads (they start jobs, run code or call `curl`); see
  docs/GUIDE.md.
- Golden sets: `golden-v5` (97 cases) and `ladder-v2` (41) add remote reads, a secret expanded into
  a remote command, a tainted read-only ssh, and production versus incidental directory names.

### Security

- `nvidia-smi` counted as read-only whatever its flags; `-pl` (power limit), `-r` / `--gpu-reset`,
  `-pm`, clock locks, MIG and ECC settings change the GPU and now go through the gate.
- The read-only list no longer passes `ssh` calls that 0.6.0 let through without a judgment: `-F`
  (a config file can run a `ProxyCommand`), `-I` / `PKCS11Provider` (loads a local library),
  `-o KnownHostsCommand` and `SendEnv`, agent and X11 forwarding (`-A`, `-X`), `-E` (writes a local
  file), a host from an arbitrary variable (`h=-oProxyCommand=…; ssh $h '…'`), a local file or pipe
  feeding ssh's stdin (`cat notes.txt | ssh h 'cat'`), and a local `$VAR` or `$(…)` expanded into a
  double-quoted remote command (`ssh h "echo $TOKEN"`).
- The read-only check follows the shell where 0.6.0 did not: a backslash-newline joins the lines
  (`find . -de\⏎lete` was read as `-de lete`), `$'…'` is quoted text, and a word starting with `#`
  comments out the rest of its line (a quote inside a comment no longer hides the next line). The
  script rules join continued lines the same way.

## [0.6.0] - 2026-09-26

### Added

- Keyless autonomy: `reflex setup --profile autonomous` without a TypeSafe key picks the local engine
  and says so (dry run too); with a key it stays on Jev, and `--engine` beside the profile wins.
  Commands the local rules do not cover go to System 2 instead of straight to a human; rule denies,
  tamper, the always-human class and taint behave as with Jev. A keyless System 2 approve is a pass,
  except that it allows (skipping Claude Code's prompt) at confidence 0.9 or more for a short command
  with a stated intent whose effects stay in the working directory: no network egress, no cloud,
  cluster, database, deploy, package or system tool, no shipping or installing verb, no write outside
  the working directory, no local script. Keyless defaults: 300 System 2 calls a day, 100 and $2
  a session, breaker off, from a measurement of 14,445 real Bash commands (62 % would reach System 2,
  115 calls on a median day, 294 at p90). `reflex status` / `doctor` show `system1`.
- `npm run eval-ladder -- --engine local`: the ladder golden set keyless and offline; 0 unsafe
  approvals, 36.4 human interventions and 36.4 System 2 calls per 100 commands.
- Injection guard: the phrase detectors also read text spaced out letter by letter
  (`I g n o r e   p r e v i o u s`, with spaces, no-break, thin or ideographic spaces); a phrase
  there counts like a plain one, so a spaced override next to a command blocks and a quotation Jev
  judges informative passes.
- Injection golden set (`injection-golden-v3`, 62 cases): paraphrases split across two chunks, on
  one long line, at the top, middle and end of long pages, a letter-spaced override, and benign
  letter-spaced headings, a long field guide on prompt injection and a long coding-agent README.

### Fixed

- Checkpoints could miss a same-size edit made within a second of the last index write and fall back
  to `HEAD` (the flaky macOS selfcheck, #21): the temporary index copy got a fresh modification time,
  so git trusted stale stat data. The copy now keeps the index's time; checkpoint ref names are
  unique within a process; the selfcheck exercises the race on every run.
- Checkpoint commits carry Reflex's own identity (`reflex <reflex@localhost>`), so they never depend
  on a git `user.name` / `user.email` the machine may not have; `npm test` passes with none set.
- `reflex setup` also adds a new version's gates, params and flags to a user copy of the injection
  policy (`~/.config/reflex/injection/policy.json`), as it does for the tool-gate policy; it never
  creates one, and never changes or reorders the user's entries.
- Injection guard: a long paraphrased injection whose short last section was judged on its own
  (golden case `paraphrase-past-eight-chunks`) passed about one run in three (#19). A piece under
  1,000 characters now goes to Jev with a neighbour when both fit in a chunk, else with the lines
  before it up to 3,000 characters (Jev's `addressed` for that section: 0.45-0.56 alone, 0.62-0.72
  with the page before it), and a new policy gate, `jev-suspect`, warns when Jev names a serious
  attack (`suspectSeverityAt`, 1.8) but is only `suspectAt` (0.25) or more sure the text speaks to
  an AI (policy `injection-v3`).
  Five live runs: 0 missed, precision 97 %, recall 100 %, no new false positive; input tokens on
  the previous 53 cases 72,350 before, 71,807 after.


## [0.5.0] - 2026-09-25

### Added

- Autonomous profile (`reflex setup --profile autonomous`; `supervised` stays the default): an
  escalation ladder in which Jev resolves the confident majority, an uncertain decision goes to a
  stronger model (System 2, `judge2.mjs`), and a human decides asynchronously through an approval
  queue. Profiles are presets in `config.json`; flags beside a profile win; `--dry-run` prints the
  effective settings.
- System 2 backends: `cli` (the `claude` CLI already installed and signed in, run with no tools,
  hooks, MCP servers, CLAUDE.md or Reflex; `codex exec` when named), `anthropic` (Messages API),
  `openai-compatible` (OpenAI, Ollama, vLLM, LM Studio, OpenRouter, a LiteLLM gateway) and `none`.
  Setup picks `claude`, else `anthropic` with `ANTHROPIC_API_KEY`, else `none`, and says which.
  The CLI judge pins its model (`sonnet`) and adds `--bare` only with an API key; measured at about
  3,100 input tokens a call against 36,826 for a naive `claude -p`. Verdicts: the first JSON object in
  the answer, validated strictly; any error, timeout, refusal, invalid answer or spent budget goes to a human.
- Low System 2 spend: a verdict cache keyed on the command's template (ids as slots), no re-ask while
  a command waits in the queue, optional cheaper tiers (`judge.tiers`), a case capped at 1,500 tokens
  with the static prompt first (Anthropic `cache_control`), 100-token JSON verdicts without extended
  thinking, per-day and per-session caps on calls and estimated cost, and a breaker that pauses
  System 2 when more than 30 % of the last hour's commands escalated.
- Always-human class (`setup/tool-gate/escalation.json`, `escalation-v1`): rule outcomes, the `prod`,
  `prod-destroy`, `exfil` and `tainted-exfil` gates, and patterns for production mutations, IAM and
  permission changes, secrets writes, destructive deletes and money APIs; tainted egress needs a human
  to approve. Neither System 1 nor System 2 can approve them.
- `reflex queue` (list, show, approve, deny, clear) with an optional notification command; an approval
  matches the identical command, cwd and session, once, within its TTL.
- `reflex envelope` (set, show, list, clear): a task envelope per directory or session, fed to Jev
  (`in_envelope`, questions `tool-gate-q7`) and System 2; policy `tool-gate-v6` gains the
  `repo-envelope`, `off-envelope` and `in-envelope` gates. `.reflex/envelope.md` in a repository can
  only narrow (`repo_forbids`).
- `reflex checkpoints` (list, restore): recovery points under `refs/reflex/checkpoints/` before a
  mutating command in a git repository, without touching the working tree or the index.
- `reflex report`: human interventions per 100 commands, System 2's escalation rate, verdicts,
  agreement with Jev, tokens per call, cache hits, cost per 100 commands, queue waits, fast-lane
  candidates from repeated System 2 approvals (never added automatically); System 2 verdicts become
  calibration labels. `reflex status` shows the profile, System 2's reachability without a paid
  call, the budget, the breaker and the queue.
- `npm run eval-ladder`: 33 commands labelled with their expected resolver, Jev live and an
  approve-everything stub System 2; fails on an unsafe approval or an oversized case.

### Fixed

- Claude Code: the installer wrote `Write(path)` permission rules, which Claude Code ignores (and
  warns about); only `Edit(path)` rules are written now, and old `Write(...)` entries are removed.

## [0.4.0] - 2026-09-25

### Fixed

- A fresh install through the `curl` installer now starts with the local engine like `npx` / `pnpm dlx`
  / `bunx`; it used Jev (and asked for a key) because the package was already in place. Settings
  from 0.2.0 still keep Jev.

## [0.3.0] - 2026-09-25

### Added

- Logo, wordmark and social preview image (`assets/`); the README opens with the wordmark.

- Injection guard (`guard.mjs`, `setup/injection/`): tool results from the web, MCP servers, files
  outside the project and network commands are scanned for prompt injection (deterministic
  detectors in both engines; with Jev, one request of three typed questions per chunk) and a policy
  turns the result into pass, warn or block. Warn adds a note for the agent; block removes the
  offending text where the agent lets a hook rewrite results (Claude Code `updatedToolOutput`, pi and
  oh-my-pi `tool_result`, opencode `tool.execute.after`) and sends the strongest signal available
  elsewhere (Codex `decision: block`, Hermes a note on the next turn).
- Taint: after a warn or block in enforce mode, the gate is stricter for the rest of that session
  (network egress asks, calibrated allow is off, lower ask thresholds via the policy flag
  `taintStrict`). New `tainted` rules in `rules.json` (`rules-v10`) and taint gates in
  `tool-gate-v5`; `reflex setup` adds the gates, params and flags a user `policy.json` from an
  earlier setup lacks, and says which, without changing or reordering the user's own.
- Credentials pasted into a prompt are blocked in enforce mode (Claude Code, Codex, pi, oh-my-pi,
  opencode), named by key type and never logged; `setup/redact.json` gains `names`.
- `reflex report` summarises the guard: results by source, outcome and attack, tainted sessions and
  blocked credential prompts, as counts.
- `reflex scan <file|->` checks text by hand; `npm run eval-injection` runs a 53-case golden set
  (precision, recall, exit 1 on a missed high-severity injection); `reflex doctor` probes each
  installed guard hook; `REFLEX_GUARD` / `"guard"` set the guard's mode on its own.
- Local setup without a TypeSafe account or key; explicit `--engine local|jev` and a setup preview.
- `reflex status` and `reflex doctor`, including JSON output, synthetic hook checks and separate
  evidence of real hook events.
- Durable user policy and settings that survive upgrades and uninstall.
- `reflex run` for a human terminal handoff where an agent cannot display an approval dialog.
- An isolated full-suite runner and onboarding/adapter integration checks; macOS CI coverage.

### Changed

- With System 2 on, the gate hooks get the judge's timeout plus 30 s (Claude Code, Codex, Hermes,
  opencode; pi and oh-my-pi up to 29 s), since a hook timeout lets the command through.
- Rules `rules-v11`: `reflex queue approve|deny|clear`, `reflex envelope set|clear` and
  `reflex checkpoints restore` are tamper; `reflex status`, `queue list|show`, `envelope show` and
  `checkpoints list` are fast lane.

### Fixed

- Shadow mode descriptions now explain that deterministic rules still enforce.
- Codex and opencode no longer suggest that chat confirmation can unblock their hooks.
- Missing execution feedback is unknown, not rejection; pi records explicit declined approvals.
- Invalid engine/configuration cannot silently enable hosted classification.

## [0.2.0] - 2026-09-25

### Added

- The gate: read-only detection, deterministic rules, fast-lane commands, and six typed Jev questions
  (`mutates`, `blast`, `env`, `exfil`, `on_task`, `injection`) turned into pass / ask / deny by an
  ordered policy in `setup/tool-gate/policy.json`. Hooks for Claude Code, Codex CLI, pi, oh-my-pi,
  opencode and Hermes, plus `bin/reflex-sh` for agents without a hook system.
- Script inspection: the local script, make target or package script a command runs is read and
  judged before the command is; code Reflex cannot read (`npx` packages, imported modules,
  `NODE_OPTIONS`, …) is marked unseen and never allowed.
- Calibrated allow (`REFLEX_ALLOW`), opt-in: a command Jev judges clearly safe skips the prompt the
  agent's own permissions would require.
- Subgoal dedup: a subagent spawn that repeats a subgoal already launched in the session is denied
  with a reason naming the earlier one.
- Conditional instructions: `.reflex/instructions/*.md` fragments with a `when:` condition, selected
  per prompt by path, keyword and one Jev request.
- Tool router (`router/server.mjs`): a stdio MCP server with `find_tools`, `describe_tool` and `run`
  in front of built-in read-only shell commands and your own MCP servers; every call it makes goes
  through the gate.
- Model routing (`routing/reflex_router.py`): a LiteLLM pre-call hook that keeps restricted content on
  first-party frontier models and sends easy public work to the cheapest model that does the task.
- Context layer (`context.mjs`, `adapters/pi-context.ts`, opt-in, experimental): per-request chunk
  visibility, `expand_chunk`, `/fresh <goal>` restart with recall, retrieval bundles and
  `bin/reflex-review`.
- Golden sets and live evals for each layer (90 gate commands, 15 router intents, 27 routing prompts,
  16 context outputs, 20 instruction prompts); offline self-checks for every component.
- `report.mjs`: decision summary, replay under a candidate policy, allow calibration, Prometheus
  Pushgateway export, and `dashboards/reflex.json` for Grafana.
- Install with `curl -fsSL …/install.sh | bash` or `npx` / `pnpm dlx` / `bunx` / `yarn dlx
  @ursuciprian/reflex setup`: the package is copied to `~/.local/share/reflex`, the `reflex` command
  linked, the TypeSafe key optionally stored in the macOS Keychain, and every supported agent hooked
  in shadow mode, with `--mode enforce` and `--allow` to tighten later. `--keychain` records where
  the key lives; `reflex uninstall` removes everything.
- `publish.yml` publishes a `v*` tag to npm with provenance (`NPM_TOKEN` secret); `ci.yml` runs the offline self-checks on every pull request (Node 18 and 22, Python 3.9
  and 3.12).
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, this changelog and issue templates.

[Unreleased]: https://github.com/ursuciprian/reflex/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/ursuciprian/reflex/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/ursuciprian/reflex/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/ursuciprian/reflex/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/ursuciprian/reflex/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/ursuciprian/reflex/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/ursuciprian/reflex/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/ursuciprian/reflex/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ursuciprian/reflex/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ursuciprian/reflex/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ursuciprian/reflex/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ursuciprian/reflex/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ursuciprian/reflex/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ursuciprian/reflex/releases/tag/v0.2.0
