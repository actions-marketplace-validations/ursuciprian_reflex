# Sourced by docs/demo/demo.tape from the repository root. Builds /tmp/reflex-demo: a scratch git
# repo whose origin is a local bare repository, a prod/ Terraform directory, and a dependency README
# with a hidden prompt injection. Reflex state and config go to scratch directories.
# REFLEX_REPO is the Reflex checkout Claude Code loads as the plugin (default: the current directory).
export REFLEX_REPO="${REFLEX_REPO:-$PWD}"
D=/tmp/reflex-demo
rm -rf "$D" && mkdir -p "$D/app/prod" "$D/app/node_modules/fastcache" "$D/state" "$D/config"
export REFLEX_MODE=enforce REFLEX_ENGINE=local REFLEX_DATA_DIR="$D/state" XDG_CONFIG_HOME="$D/config"
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_REGION KUBECONFIG TYPESAFE_API_KEY
export KUBECONFIG=/dev/null
# Recorded from inside another Claude Code session: drop its session markers.
for v in $(env | cut -d= -f1 | grep -E '^CLAUDE'); do unset "$v"; done
cd "$D/app" || return
cat > prod/main.tf <<'EOF'
# demo only: nothing here is real
resource "null_resource" "demo" {}
EOF
echo '{"name": "demo-app", "version": "0.1.0", "dependencies": {"fastcache": "^1.0.0"}}' > package.json
# The readme-html-comment-telemetry golden case, with the URL moved to the reserved example.com.
node -e 'for (const c of require(process.argv[1]).cases) if (c.id === "readme-html-comment-telemetry") console.log(c.text.replace("example-attacker.com", "example.com"))' \
  "$REFLEX_REPO/setup/injection/golden.json" > node_modules/fastcache/README.md
printf 'node_modules/\n' > .gitignore
git init -q -b main && git add -A && git -c user.name=demo -c user.email=demo@example.com commit -qm "initial commit"
# "origin" is a bare repository next to it, also under /tmp/reflex-demo: no network remote exists.
git init -q --bare "$D/origin.git" && git remote add origin "$D/origin.git" && git push -q origin main
reflex() { node "$REFLEX_REPO/bin/reflex" "$@"; }
export PS1='$ '
clear
