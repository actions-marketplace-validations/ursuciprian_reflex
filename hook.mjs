#!/usr/bin/env node
// The entry of every Reflex hook: node hook.mjs <gate|guard|instructions>.mjs <flags>.
// failsafe.mjs installs the error handlers, then loads the script with a dynamic import, so no error
// while it loads can end the hook without an answer (docs/GUIDE.md, "Reflex fails closed").
try { await (await import("./failsafe.mjs")).run(); }
catch (e) {
  // failsafe.mjs itself did not load (stdlib only, so this means a broken install): exit 2 blocks in Claude Code and Codex.
  process.stderr.write(`reflex error: ${String(e?.message ?? e).split("\n")[0].slice(0, 160)}; a human must review\n`);
  process.exit(2);
}
