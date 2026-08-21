#!/bin/bash
# The fingerprint of everything that determines the bundle's OUTPUT, printed
# on stdout: the UI sources, and the two files that decide how they get turned
# into bin/static/security.js.
#
# One definition used from two sides: build/build-ui.sh stamps it into the
# bundle it writes, and `claude-cron selftest` recomputes it to prove the
# committed bundle was built from the committed sources. Written twice these
# would be two things to keep in step, and the day they drifted the check would
# be reporting on nothing.
#
# build/build-ui.sh and package.json are hashed alongside ui/**/*.js because
# they are just as much an input to the bundle as the sources are: a changed
# `--target`, a changed `--format`, or a bumped esbuild pin in either file
# changes what the committed bytes should be without touching a single file
# under ui/. Hashing sources only would let any of those land, forgotten to
# rebuild, under a green "matches its sources" -- a bundle built by a
# different toolchain than the one the fingerprint claims.
#
# CONTENT, not mtime. Mtimes cannot answer this question: git does not record
# them, and a checkout writes paths in index order -- every `bin/...` before
# every `ui/...` -- so on a fresh clone the sources are ALWAYS newer than the
# bundle built from them. An mtime rule would fail for every person who had
# changed nothing at all, which is the fastest way to teach everyone to ignore
# a selftest.
set -euo pipefail
cd "$(dirname "$0")/.."
# The path is hashed as well as the bytes: a file added, renamed or deleted has
# to change the answer even when the total content has not.
{
  find ui -name '*.js' -type f
  find build/build-ui.sh package.json -maxdepth 0 -type f 2>/dev/null
} | LC_ALL=C sort | while read -r f; do
  printf '%s\n' "$f"
  cat "$f"
done | shasum -a 256 | awk '{print $1}'
