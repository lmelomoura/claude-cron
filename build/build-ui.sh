#!/bin/bash
# Builds the Security area into bin/static/. The OUTPUT IS COMMITTED: whoever
# installs claude-cron needs jq, python3 and curl -- never Node. Run this in
# the same change as any edit under ui/, or the selftest refuses the tree.
set -euo pipefail
cd "$(dirname "$0")/.."
npx --yes esbuild@0.25.0 ui/security/index.js \
  --bundle --format=iife --target=safari15 \
  --outfile=bin/static/security.js
# The stylesheet is CONCATENATED, not bundled: it has no imports and no
# module graph, so running it through esbuild would buy nothing and add a
# minifier's opinions to a diff that should stay readable. Order matters --
# tokens first, because everything below reads them; components before pages,
# so a page rule wins a tie against the component it specialises.
cat ui/css/tokens.css ui/css/components.css ui/css/pages.css > bin/static/app.css
# Every built artifact carries the same two stamps: what it was built FROM,
# and what it IS. Written in one loop rather than three pairs of printfs, so
# a fourth artifact is one word in this list.
#
# TWO stamps, because there are two ways a committed build artifact goes wrong
# and one of them used to be invisible. `ui-bundle` is the hash of the
# artifact's own body, taken here BEFORE either stamp is appended, so the
# selftest can tell whether the committed bytes are still the ones this build
# produced -- nothing hashed them before, and code injected straight into the
# committed file passed the check with every source untouched. `ui-sources`
# is what it was built FROM, so the selftest can tell a current artifact from
# one somebody forgot to rebuild. Block comments on the last two lines: valid
# in JavaScript AND in CSS, ignored by every browser, and greppable without
# parsing anything -- and exactly one of each, which build/ui-bundle-digest.sh
# enforces on the way back in.
for art in bin/static/security.js bin/static/app.css; do
  printf '/* ui-bundle: %s */\n' "$(bash build/ui-bundle-digest.sh "$art")" >> "$art"
  printf '/* ui-sources: %s */\n' "$(bash build/ui-digest.sh)" >> "$art"
done
echo "built bin/static/security.js, bin/static/app.css"
