#!/bin/bash
# The fingerprint of the UI SOURCES, printed on stdout.
#
# One definition used from two sides: build/build-ui.sh stamps it into the
# bundle it writes, and `claude-cron selftest` recomputes it to prove the
# committed bundle was built from the committed sources. Written twice these
# would be two things to keep in step, and the day they drifted the check would
# be reporting on nothing.
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
find ui -name '*.js' -type f | LC_ALL=C sort | while read -r f; do
  printf '%s\n' "$f"
  cat "$f"
done | shasum -a 256 | awk '{print $1}'
