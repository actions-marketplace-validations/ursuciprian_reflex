#!/bin/sh
# /reflex:queue in the Claude Code plugin: the approval queue, read-only. Takes `list` or
# `show <id>`; approving, denying and clearing stay with the user, in their own terminal.
here=$(cd "$(dirname "$0")/.." && pwd) || exit 1
usage() { echo "usage: queue.sh list | queue.sh show <id>" >&2; exit 2; }
case "$#:${1-}" in
  1:list) exec node "$here/autonomy.mjs" --plugin queue list ;;
  2:show) case "$2" in q-[0-9a-f]*) case "${2#q-}" in *[!0-9a-f]*) usage ;; esac ;; *) usage ;; esac
          exec node "$here/autonomy.mjs" --plugin queue show "$2" ;;
  *) usage ;;
esac
