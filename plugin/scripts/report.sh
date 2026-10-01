#!/bin/sh
# /reflex:report in the Claude Code plugin: what the gate decided recently. Read-only.
# Takes only --since <days>, --list ask|deny|pass and --calibration; never --push, which sends metrics out.
here=$(cd "$(dirname "$0")/.." && pwd) || exit 1
usage() { echo "usage: report.sh [--since <days>] [--list ask|deny|pass] [--calibration]" >&2; exit 2; }
expect=
for a in "$@"; do
  case "$expect" in
    since) case "$a" in ''|*[!0-9]*) usage ;; esac; expect=; continue ;;
    list) case "$a" in ask|deny|pass) ;; *) usage ;; esac; expect=; continue ;;
  esac
  case "$a" in
    --since) expect=since ;;
    --list) expect=list ;;
    --calibration) ;;
    *) usage ;;
  esac
done
[ -z "$expect" ] || usage
exec node "$here/report.mjs" --plugin "$@"
