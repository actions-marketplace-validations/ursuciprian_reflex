#!/usr/bin/env node
// The entry of every Reflex hook: node hook.mjs <gate|guard|instructions>.mjs <flags>.
// failsafe.mjs installs the error handlers, then loads the script with a dynamic import, so no error
// while it loads can end the hook without an answer (docs/GUIDE.md, "Reflex fails closed").
// Only when started as the script (failsafe.mjs isMain, inlined: nothing here may fail to load);
// an import of this file runs nothing.
import {realpathSync} from "node:fs";
import {fileURLToPath} from "node:url";
let main = import.meta.main === true;
try { main ||= !!process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]); } catch { /* not the script */ }
if (main) try { await (await import("./failsafe.mjs")).run(); }
catch (e) {
  // failsafe.mjs itself did not load (stdlib only, so this means a broken install): exit 2 blocks in Claude Code and Codex.
  process.stderr.write(`reflex error: ${String(e?.message ?? e).split("\n")[0].slice(0, 160)}; a human must review\n`);
  process.exit(2);
}
