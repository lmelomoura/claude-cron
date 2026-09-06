#!/bin/bash
# The fingerprint of a built bundle's OWN BODY AND NAME, printed on stdout —
# every byte of, say, bin/static/security.js except the stamp lines
# build/build-ui.sh appends to it, plus the one word "security.js" identifying
# whose body this is supposed to be.
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
# THE NAME IS PART OF THE FINGERPRINT for the same reason. A digest of the
# body alone answers "is this still the bytes SOMETHING was built into" —
# not "is this still the bytes THIS FILE was built into". `cp bin/static/
# app.js bin/static/app.css` carries app.js's own correct ui-bundle stamp
# along with its body, and a body-only digest recomputed on app.css matches
# that stamp perfectly, because the body it is hashing is, byte for byte,
# the body the stamp was written for — the JavaScript bundle now sitting
# under app.css's name checks out as fine. Mixing the artifact's own name
# into the hash means app.css's stamp only ever verifies against a body
# that was stamped AS app.css; app.js's body under app.css's name is a
# mismatch on both sides of that pairing, not just a coincidence that
# happened to hash the same.
#
# THE BASENAME, not the full path handed in on argv. build/build-ui.sh calls
# this script with a path relative to the repo root (`bin/static/app.js`,
# after its own `cd`); check_ui_artifact in bin/agentloop calls it with
# that same file under `$BASE_DIR`, which is wherever THIS install happens to
# live and will not match the path the artifact was built under on whatever
# machine ran build-ui.sh. Hashing the raw argument would make every
# committed stamp fail to verify anywhere except the one checkout it was
# built in. The basename is the one part of the argument both call sites
# already agree on, and it is exactly the identity that needs binding: two
# artifacts live side by side in the same bin/static/, so their basenames
# are already what tells them apart.
#
# Together the two scripts answer the two halves: `/* ui-sources: ... */`
# says "these are the sources it came from", `/* ui-bundle: ... */` says
# "and this is still ITSELF".
#
# EXACTLY ONE STAMP OF EACH KIND, refused otherwise. The selftest used to read
# the source stamp with `sed ... | tail -1`, so appending a SECOND
# `/* ui-sources: ... */` line carrying a freshly computed digest satisfied it
# while the real stamp — the one describing the bytes above it — sat ignored
# one line up. A trailing comment is the cheapest thing in the world to append
# to a file, so the reader has to refuse an ambiguous stamp rather than pick
# one.
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

# ONE stamp form for every built artifact. bin/static/ holds JavaScript and
# CSS, and CSS has no `//` comment -- a line form for one and a block form for
# the other is two spellings for every reader here, in build-ui.sh and in the
# selftest, and one of them to forget. `/* ... */` is valid in both languages,
# so there is exactly one form to write and one to strip.
for kind in ui-sources ui-bundle; do
  n="$(grep -c "^/\* $kind: [0-9a-f]\{64\} \*/\$" "$bundle" || true)"
  if [ "${n:-0}" -gt 1 ]; then
    echo "ui-bundle-digest: $bundle carries $n '$kind' stamps — exactly" \
         "one is expected, and a second one hides whatever the first says" >&2
    exit 1
  fi
done

# The captured value is anchored to the SHA-256 shape -- exactly 64 lowercase
# hex characters -- not `.*`. A block comment, unlike the `//` line form it
# replaced, can be CLOSED AND REOPENED mid-line: a single physical line like
# `/* ui-bundle: <real hash> */<injected code>/* ui-bundle: <fake hash> */`
# used to satisfy the greedy pattern end to end, so `grep -v` deleted the
# whole line -- injected code included -- and the exactly-one check above
# never saw more than one stamp because it was one physical line. A line
# carrying anything beyond the stamp itself now fails to match at all, so it
# stays in the body and the ordinary hash-mismatch path catches it instead.
#
# The name goes in as its own first line, ahead of the body, not appended to
# it or hashed separately and concatenated after the fact -- one call to
# shasum over one stream, so there is only ever one digest to keep in step
# with the one this same script recomputes at check time (see this file's
# own banner comment on why the basename, not the raw argument, is what goes
# in here).
name="$(basename "$bundle")"
{ printf '%s\n' "$name"
  grep -v -e '^/\* ui-sources: [0-9a-f]\{64\} \*/$' \
          -e '^/\* ui-bundle: [0-9a-f]\{64\} \*/$' \
    "$bundle" || true; } | shasum -a 256 | awk '{print $1}'
