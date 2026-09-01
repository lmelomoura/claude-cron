"""One reading of `ignore_paths`, shared by every deterministic phase.

`ignore_paths` is a promise about the ANALYSIS, not about one scanner: a
fixtures directory full of deliberately fake credentials must not become a
finding whether the scanner that opened it was the working-tree sweep, the
history sweep or the hygiene pass. This lived as a private `_ignored` inside
secrets.py, so the other two phases quietly disagreed with it -- the same
glob excluded a file from one report and not from the next.

Deliberately NOT used by deps.inventory: a lockfile under an ignored glob
still declares dependencies this project ships, so the SBOM this project
hands out stays complete wherever the file sits. The FINDINGS from that
lockfile are a different question, and they are filtered -- in
`cli._scan_dependencies`, for whichever producer ran. Filtering only the
engine's output would make an operator's globs suppress a CVE on a machine
with Trivy installed and not on one without, which is a report that changes
by machine.
"""

import fnmatch


def ignored(rel: str, patterns) -> bool:
    """True when the repo-relative path `rel` matches any of `patterns`.

    Each pattern is matched twice: literally, and with a trailing `/*`
    appended to its directory part, so `tests/fixtures` and
    `tests/fixtures/**` both exclude everything under that directory rather
    than only the directory entry itself.
    """
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/*") + "/*")
               for p in (patterns or ()))
