#!/usr/bin/env bash
# Reflex installer: fetch @ursuciprian/reflex from the npm registry and hook it into every coding
# agent found on this machine, in shadow mode by default.
#
#   curl -fsSL https://raw.githubusercontent.com/ursuciprian/reflex/main/install.sh | bash
#   ... | bash -s -- --mode enforce --agents claude,codex --version 0.2.0
#   ... | bash -s -- --uninstall
#
# Same result without this script:  npx @ursuciprian/reflex setup   (or pnpm dlx / bunx / yarn dlx)
#
# Options (or the matching environment variables):
#   --version X      package version            REFLEX_VERSION   (default: latest)
#   --agents LIST    claude,codex,pi,omp,...    REFLEX_AGENTS    (default: all agents found)
#   --mode M         shadow | enforce | off     REFLEX_MODE      (default: shadow)
#   --allow A        off | shadow | on          REFLEX_ALLOW     (default: off)
#   --keychain NAME  macOS Keychain item with the TypeSafe key   REFLEX_KEYCHAIN_SERVICE (default: typesafe-api-key)
#   --node PATH      the Node the hooks run with                 (default: node on PATH)
#   --prefix DIR     where the package lives    REFLEX_PREFIX    (default: ~/.local/share/reflex)
#   --package SPEC   npm spec or local .tgz     REFLEX_PACKAGE   (testing: install from `npm pack`)
#   --uninstall      remove every hook, the package and its link (logs in ~/.local/state/reflex stay)
set -euo pipefail

NAME="@ursuciprian/reflex"
REGISTRY="https://registry.npmjs.org"
VERSION="${REFLEX_VERSION:-latest}"
PREFIX="${REFLEX_PREFIX:-$HOME/.local/share/reflex}"
PACKAGE="${REFLEX_PACKAGE:-}"
UNINSTALL=0
SETUP_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --agents|--mode|--allow|--keychain|--node|--engine) SETUP_ARGS+=("$1" "$2"); shift 2 ;;
    --dry-run) SETUP_ARGS+=("$1"); shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "reflex: unknown option $1" >&2; exit 2 ;;
  esac
done
export REFLEX_PREFIX="$PREFIX"

say() { printf '\033[1mreflex\033[0m %s\n' "$*"; }
die() { printf '\033[31mreflex: %s\033[0m\n' "$*" >&2; exit 1; }

command -v node >/dev/null || die "Node.js 18+ is required (https://nodejs.org or: brew install node)"
command -v npm >/dev/null || die "npm is required (it ships with Node.js)"
NODE="$(command -v node)"
[ "$("$NODE" -p 'process.versions.node.split(".")[0]')" -ge 18 ] || die "Node.js 18+ is required, found $("$NODE" --version)"

PKG_DIR="$PREFIX/lib/node_modules/$NAME"

if [ "$UNINSTALL" = 1 ]; then
  if [ -f "$PKG_DIR/scripts/reflex" ]; then
    exec "$NODE" "$PKG_DIR/scripts/reflex" uninstall
  fi
  rm -rf "$PREFIX" "$HOME/.local/bin/reflex"
  say "nothing installed in $PREFIX"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FRESH=0; [ -e "$PREFIX" ] || FRESH=1   # a failed first install leaves nothing behind

SPEC="${PACKAGE:-$NAME@$VERSION}"
say "installing $SPEC into $PREFIX"
# The scoped registry is set explicitly: npm resolves @scope packages from an `@scope:registry`
# setting before `--registry`, so a stale @ursuciprian line in ~/.npmrc cannot redirect this.
if ! npm install --global --prefix "$PREFIX" --no-audit --no-fund --loglevel=error \
     "--@ursuciprian:registry=$REGISTRY" "$SPEC" 2> "$TMP/npm.err"; then
  [ "$FRESH" = 1 ] && rm -rf "$PREFIX"
  cat "$TMP/npm.err" >&2
  die "npm install failed"
fi
[ -f "$PKG_DIR/scripts/reflex" ] || die "package installed but $PKG_DIR/scripts/reflex is missing"

# Everything else (the reflex command, the API key, the agent hooks) is `reflex setup`, the same
# code npx / pnpm dlx / bunx run.
exec "$NODE" "$PKG_DIR/scripts/reflex" setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}
