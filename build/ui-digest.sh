#!/bin/bash
# The fingerprint of everything that determines the bundle's OUTPUT, printed
# on stdout: the UI sources, and the files that decide how they get turned
# into bin/static/security.js and how that result is checked.
#
# One definition used from two sides: build/build-ui.sh stamps it into the
# bundle it writes, and `claude-cron selftest` recomputes it to prove the
# committed bundle was built from the committed sources. Written twice these
# would be two things to keep in step, and the day they drifted the check would
# be reporting on nothing. Its sibling build/ui-bundle-digest.sh answers the
# other half of the question -- whether the committed bytes are still the ones
# that build produced -- and the two stamps live side by side in the bundle.
#
# build/build-ui.sh, build/ui-bundle-digest.sh and package.json are hashed
# alongside the sources because they are just as much an input to the committed
# artifact as the sources are: a changed `--target`, a changed `--format`, or a
# bumped esbuild pin changes what the committed bytes should be without
# touching a single file under ui/. Hashing sources only would let any of those
# land, forgotten to rebuild, under a green "matches its sources" -- a bundle
# built by a different toolchain than the fingerprint claims.
# ui-bundle-digest.sh is in that list even though it cannot change a single
# byte esbuild writes: it decides what the OTHER stamp means, so a change to it
# has to be reported as "stale, rebuild" -- which is true and actionable --
# rather than surfacing one command later as "this bundle has been modified",
# which would be neither.
#
# EVERY FILE UNDER ui/, not `-name '*.js'`. esbuild bundles whatever
# ui/security/index.js reaches by import, and its own default resolution
# reaches .ts, .tsx, .jsx, .json and .css as readily as .js -- so a
# `-name '*.js'` glob fingerprints a subset of what the build actually
# consumes, and any other input could change the committed bytes without
# changing the digest that is supposed to describe them. A wider net costs
# nothing here: everything under ui/ is either an input or does not exist.
#
# ...EXCEPT what git is ignoring. A stray untracked, ignored file under ui/ --
# a scratch .js, an editor backup, a .DS_Store -- is not an input to anything
# and is not in anybody else's checkout, but it used to change this digest, so
# the selftest went red over a tree `git status` called clean and the only way
# out was to find and delete a file nothing had mentioned. `--others --ignored
# --exclude-standard` is precisely "untracked AND ignored", so a TRACKED file
# can never be dropped from the fingerprint by an over-broad ignore pattern.
# Outside a git checkout nothing is filtered, and nothing needs to be: an
# ignored file is by construction not in the distributed tree.
#
# CONTENT, not mtime. Mtimes cannot answer this question: git does not record
# them, and a checkout writes paths in index order -- every `bin/...` before
# every `ui/...` -- so on a fresh clone the sources are ALWAYS newer than the
# bundle built from them. An mtime rule would fail for every person who had
# changed nothing at all, which is the fastest way to teach everyone to ignore
# a selftest.
set -euo pipefail
cd "$(dirname "$0")/.."

_inputs() {
  find ui -type f
  find build/build-ui.sh build/ui-bundle-digest.sh package.json \
       -maxdepth 0 -type f 2>/dev/null
}

_list="$(mktemp)"; _ignored="$(mktemp)"; _kept="$(mktemp)"
trap 'rm -f "$_list" "$_ignored" "$_kept"' EXIT
_inputs | LC_ALL=C sort > "$_list"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # `|| true`: git exits non-zero when there is nothing to list.
  git ls-files --others --ignored --exclude-standard -- ui > "$_ignored" 2>/dev/null || true
  if [ -s "$_ignored" ]; then
    grep -v -x -F -f "$_ignored" "$_list" > "$_kept" || true
    mv "$_kept" "$_list"
  fi
fi

# One line per file: its path, and a hash OF its content -- not the content
# itself. Concatenating `path\n` + raw bytes, which is what this did, has no
# boundary between one file's content and the next file's path line, so a file
# whose last byte is not a newline runs straight into it: two different trees
# can produce the identical byte stream and therefore the identical
# fingerprint (`{a.js: "", b.js: "Z\n"}` and `{a.js: "ui/b.js\nZ\n"}` both
# stream as "ui/a.js\nui/b.js\nZ\n"). A per-file digest is fixed-width and
# newline-free by construction, so no content can ever be mistaken for
# structure -- a stronger answer than a delimiter, which is only as good as
# the guarantee that no file contains it.
#
# The path is hashed as well as the bytes: a file added, renamed or deleted has
# to change the answer even when the total content has not.
while IFS= read -r f; do
  printf '%s %s\n' "$f" "$(shasum -a 256 "$f" | awk '{print $1}')"
done < "$_list" | shasum -a 256 | awk '{print $1}'
