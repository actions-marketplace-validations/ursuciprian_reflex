#!/bin/sh
# /reflex:suggest in the Claude Code plugin: fast-lane entries for safe Claude Code commands that keep
# asking, as a preview. It writes nothing: takes only --since <N>d|h|m and --min <N>, never --write or --yes.
here=$(cd "$(dirname "$0")/.." && pwd) || exit 1
usage() { echo "usage: suggest.sh [--since 30d] [--min N]" >&2; exit 2; }
expect=
for a in "$@"; do
  case "$expect" in
    since) case "$a" in [0-9]*[dhm]) case "${a%?}" in *[!0-9]*) usage ;; esac ;; *) usage ;; esac; expect=; continue ;;
    min) case "$a" in ''|*[!0-9]*) usage ;; esac; expect=; continue ;;
  esac
  case "$a" in
    --since) expect=since ;;
    --min) expect=min ;;
    *) usage ;;
  esac
done
[ -z "$expect" ] || usage
exec node "$here/replay.mjs" --plugin suggest claude "$@"
