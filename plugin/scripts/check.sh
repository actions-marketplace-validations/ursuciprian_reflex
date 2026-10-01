#!/bin/sh
# /reflex:check in the Claude Code plugin: how the gate would judge one shell command. It only
# judges the command and never runs it. Takes exactly one argument, the command.
here=$(cd "$(dirname "$0")/.." && pwd) || exit 1
if [ "$#" -ne 1 ] || [ -z "$1" ]; then echo "usage: check.sh '<command>'" >&2; exit 2; fi
exec node "$here/gate.mjs" --plugin --check "$1"
