#!/bin/sh
# /reflex:replay in the Claude Code plugin: past sessions judged again by the gate. Nothing runs.
# Takes only an agent name, --since <N>d|h|m and --engine local|jev. With nothing: claude --since 7d.
here=$(cd "$(dirname "$0")/.." && pwd) || exit 1
usage() { echo "usage: replay.sh [claude|codex|opencode|pi|all] [--since 7d] [--engine local|jev]" >&2; exit 2; }
[ "$#" -gt 0 ] || exec node "$here/replay.mjs" --plugin replay claude --since 7d
expect=
for a in "$@"; do
  case "$expect" in
    since) case "$a" in [0-9]*[dhm]) case "${a%?}" in *[!0-9]*) usage ;; esac ;; *) usage ;; esac; expect=; continue ;;
    engine) case "$a" in local|jev) ;; *) usage ;; esac; expect=; continue ;;
  esac
  case "$a" in
    claude|codex|opencode|pi|all) ;;
    --since) expect=since ;;
    --engine) expect=engine ;;
    *) usage ;;
  esac
done
[ -z "$expect" ] || usage
exec node "$here/replay.mjs" --plugin replay "$@"
