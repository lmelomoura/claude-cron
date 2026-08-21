#!/bin/bash
# Builds the Security area into bin/static/. The OUTPUT IS COMMITTED: whoever
# installs claude-cron needs jq, python3 and curl -- never Node. Run this in
# the same change as any edit under ui/, or the selftest refuses the tree.
set -euo pipefail
cd "$(dirname "$0")/.."
npx --yes esbuild@0.25.0 ui/security/index.js \
  --bundle --format=iife --target=safari15 \
  --outfile=bin/static/security.js
# What it was built FROM, so the selftest can tell a current bundle from one
# somebody forgot to rebuild. A plain comment on the last line: valid JavaScript,
# ignored by every browser, and greppable without parsing anything.
printf '// ui-sources: %s\n' "$(bash build/ui-digest.sh)" >> bin/static/security.js
echo "built bin/static/security.js"
