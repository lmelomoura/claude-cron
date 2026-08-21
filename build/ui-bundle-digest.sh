#!/bin/bash
# The fingerprint of a built bundle's OWN BODY, printed on stdout — every
# byte of bin/static/security.js except the stamp lines build/build-ui.sh
# appends to it.
#
# WHY THIS EXISTS, alongside build/ui-digest.sh. That script fingerprints what
# the bundle was built FROM; this one fingerprints what the bundle IS. Only the
# first of the two existed, and it could not detect a MODIFIED bundle at all:
# nothing hashed the committed bytes, so code injected straight into
# bin/static/security.js — with every source and every toolchain file left
# untouched — passed the freshness check unremarked. The honest-mistake case
# (somebody edits ui/ and forgets to rebuild) was always caught; the case the
# selftest's own sentence claims to prevent, a committed build artifact that
# does not match anything anybody wrote, was not. A mangled merge conflict
# inside a 90 KB generated file is exactly that shape, and nobody reads a
# generated file to find one.
#
# Together the two answer the two halves: `// ui-sources:` says "these are the
# sources it came from", `// ui-bundle:` says "and this is still it".
#
# EXACTLY ONE STAMP OF EACH KIND, refused otherwise. The selftest used to read
# the source stamp with `sed ... | tail -1`, so appending a SECOND
# `// ui-sources:` line carrying a freshly computed digest satisfied it while
# the real stamp — the one describing the bytes above it — sat ignored one line
# up. A trailing comment is the cheapest thing in the world to append to a
# file, so the reader has to refuse an ambiguous stamp rather than pick one.
set -euo pipefail

bundle="${1:-}"
if [ -z "$bundle" ]; then
  echo "usage: ui-bundle-digest.sh <bundle.js>" >&2
  exit 2
fi
if [ ! -f "$bundle" ]; then
  echo "ui-bundle-digest: no such file: $bundle" >&2
  exit 2
fi

for kind in ui-sources ui-bundle; do
  # `|| true`: grep -c prints 0 and exits 1 when nothing matches, which is the
  # ordinary case for a bundle esbuild has only just written.
  n="$(grep -c "^// $kind: " "$bundle" || true)"
  if [ "${n:-0}" -gt 1 ]; then
    echo "ui-bundle-digest: $bundle carries $n '// $kind:' stamps — exactly" \
         "one is expected, and a second one hides whatever the first says" >&2
    exit 1
  fi
done

# The body: the file with both stamp kinds removed. build/build-ui.sh hashes
# the bundle BEFORE it appends either, so stripping them here reproduces those
# exact bytes — esbuild's output ends in a newline and every appended line is
# whole, so nothing else has to be trimmed.
{ grep -v -e '^// ui-sources: ' -e '^// ui-bundle: ' "$bundle" || true; } \
  | shasum -a 256 | awk '{print $1}'
