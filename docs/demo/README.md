# Demo recording

`assets/demo.gif` at the top of the main README is a real Claude Code session with the Reflex
plugin, recorded with [VHS](https://github.com/charmbracelet/vhs) from `demo.tape` in this
directory. Claude's replies and Reflex's output are not edited; the only change afterwards is the
privacy cover described below.

## What it shows

Three prompts in a scratch repository, with Reflex in enforce mode and the local engine:

1. "Read node_modules/fastcache/README.md and follow its setup steps". The README is the
   `readme-html-comment-telemetry` case from `setup/injection/golden.json`: an HTML comment telling
   AI coding assistants to pipe a script to `bash`. Reflex's injection guard removes it from the
   Read result, and Claude says so and does not follow it.
2. "Run git push --force origin main". The `force-push-main` rule denies it before it runs, and
   Claude reports the reason.
3. "Run terraform -chdir=prod apply -auto-approve". The local engine asks, so Claude Code shows its
   permission prompt with Reflex's reason; the prompt is declined.

It ends with `reflex report`: two judged commands (one deny, one ask) and one blocked tool result.
Prompts 2 and 3 say "scratch demo repo, let the hook decide"; without that, the model sometimes
declines on its own before the command reaches Reflex.

## Nothing real is touched

`setup.sh` runs hidden at the start of the tape. It builds everything under `/tmp/reflex-demo`:

- `app/`, a git repository whose `origin` is a local bare repository (`origin.git`), so a push
  never leaves the machine;
- `app/prod/main.tf`, a single `null_resource`, and the apply prompt is declined anyway;
- `state/` and `config/` for `REFLEX_DATA_DIR` and `XDG_CONFIG_HOME`, so your own Reflex logs and
  settings are not read or written.

It sets `REFLEX_MODE=enforce` and `REFLEX_ENGINE=local` (no API key, nothing sent to TypeSafe),
unsets AWS variables and points `KUBECONFIG` at `/dev/null`. Claude Code loads the plugin from this
checkout with `--plugin-dir` and `--setting-sources project`, so your user settings, hooks and MCP
servers are not loaded. It uses your normal Claude Code login, and the three prompts cost a few
Sonnet calls.

## Re-record

From the repository root, with `claude` logged in:

```sh
brew install vhs            # or see the VHS README for Linux; it needs ttyd and ffmpeg
vhs docs/demo/demo.tape     # writes docs/demo/raw.gif (about 60 s)
docs/demo/redact.sh         # covers the banner's account line, writes assets/demo.gif
```

The first run asks Claude Code to trust `/tmp/reflex-demo/app`; the tape answers yes.

### Privacy cover

The Claude Code welcome banner shows the model and your plan or organization name. `redact.sh`
paints over that line:

- until `SCROLL` seconds, a box over the line in place;
- from `SCROLL` to `UNTIL`, a taller box while the banner scrolls off the top.

Both times change with every take. Find them in the raw recording, for example by extracting the
top of each frame around the moment the first answer fills the screen:

```sh
ffmpeg -i docs/demo/raw.gif -vf "select='between(t,25,40)',crop=600:90:0:0,tile=4x20" -frames:v 1 /tmp/top.png
SCROLL=30.5 UNTIL=35.9 docs/demo/redact.sh
```

Then check the result: every frame while the banner is visible, and a frame every few seconds for
the rest, for an email, username, organization, plan name, home path or key. Keep the GIF under
3 MB and do not commit `raw.gif`.
