#!/bin/bash
# Builds the Security area into bin/static/. The OUTPUT IS COMMITTED: whoever
# installs claude-cron needs jq, python3 and curl -- never Node. Run this in
# the same change as any edit under ui/, or the selftest refuses the tree.
set -euo pipefail
cd "$(dirname "$0")/.."
npx --yes esbuild@0.25.0 ui/security/index.js \
  --bundle --format=iife --target=safari15 \
  --outfile=bin/static/security.js
# TWO stamps, because there are two ways a committed build artifact goes wrong
# and one of them used to be invisible. `ui-bundle` is the hash of the bundle's
# own body, taken here BEFORE either stamp is appended, so the selftest can
# tell whether the committed bytes are still the ones this build produced --
# nothing hashed them before, and code injected straight into the committed
# file passed the check with every source untouched. `ui-sources` is what it
# was built FROM, so the selftest can tell a current bundle from one somebody
# forgot to rebuild. Plain comments on the last two lines: valid JavaScript,
# ignored by every browser, and greppable without parsing anything -- and
# exactly one of each, which build/ui-bundle-digest.sh enforces on the way back
# in.
printf '// ui-bundle: %s\n' "$(bash build/ui-bundle-digest.sh bin/static/security.js)" \
  >> bin/static/security.js
printf '// ui-sources: %s\n' "$(bash build/ui-digest.sh)" >> bin/static/security.js
echo "built bin/static/security.js"
