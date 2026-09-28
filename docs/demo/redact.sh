#!/usr/bin/env bash
# Covers the account line of the Claude Code welcome banner (model and plan name) in the raw
# recording, then writes assets/demo.gif. Run from the repository root after vhs docs/demo/demo.tape.
#   SCROLL  seconds until the banner starts to scroll up (the line is covered in place until then)
#   UNTIL   seconds until the banner has left the screen (a taller box covers it while it scrolls)
# Both change with every take: find them by looking at the raw frames, and check the result.
set -euo pipefail
IN=${IN:-docs/demo/raw.gif} OUT=${OUT:-assets/demo.gif}
SCROLL=${SCROLL:-30.5} UNTIL=${UNTIL:-35.9}
ffmpeg -v error -y -i "$IN" -filter_complex \
  "drawbox=x=110:y=46:w=240:h=20:color=0x1e1e2e:t=fill:enable='lt(t,$SCROLL)',drawbox=x=110:y=14:w=260:h=52:color=0x1e1e2e:t=fill:enable='between(t,$SCROLL,$UNTIL)',split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
  "$OUT"
ls -l "$OUT"
