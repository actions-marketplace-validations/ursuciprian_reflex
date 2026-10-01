#!/bin/sh
# /reflex:status in the Claude Code plugin: whether the gate is active, its mode and engine, and
# which install path runs the hooks. Read-only. Takes nothing, or --json.
here=$(cd "$(dirname "$0")/.." && pwd) || exit 1
case "$#:${1-}" in
  0:) exec node "$here/status.mjs" --plugin --status ;;
  1:--json) exec node "$here/status.mjs" --plugin --status --json ;;
  *) echo "usage: status.sh [--json]" >&2; exit 2 ;;
esac
