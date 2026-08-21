"""Secret detection without a binary: shaped patterns plus an entropy gate.

Two rules govern this file. The value never leaves it -- not into a return
value, not into a log, not masked. And a pattern must have a SHAPE: entropy
alone flags every hash, UUID and minified bundle in the repo, which is how a
secret scanner becomes something people turn off.
"""

import math
import re
import subprocess
from pathlib import Path

from .fingerprint import secret_fingerprint
from .ignores import ignored

# Each rule is (name, severity, compiled pattern, minimum entropy of group 1).
# Entropy 0 means the shape alone is conclusive.
_RULES = [
    ("aws_access_key", "critical", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 0.0),
    ("github_token", "critical", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"), 0.0),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), 0.0),
    ("stripe_key", "critical", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), 0.0),
    ("openai_key", "critical", re.compile(r"\b(sk-[A-Za-z0-9]{32,})\b"), 0.0),
    ("private_key", "critical", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"), 0.0),
    ("google_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 0.0),
    # The one generic rule, and the only one that needs the entropy gate and
    # the placeholder gate below.
    ("generic_secret", "medium",
     re.compile(r"(?i)(?:password|passwd|secret|token|api_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+_-]{20,})['\"]?"),
     3.5),
]

_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
_MAX_BYTES = 2 * 1024 * 1024

# The generic rule matches on shape alone (password/token/secret = <blob>),
# and a real credential's entropy margin over a bad placeholder is thin (see
# _entropy). Placeholders are instead rejected by what they say -- an
# explicit, small list of giveaways -- which is complementary to, not a
# replacement for, the entropy gate.
_PLACEHOLDER_MARKERS = (
    "changeme", "password", "example", "placeholder", "your_", "yourkey",
    "dummy", "insertkey", "xxxx", "redacted", "notarealkey", "s3cret", "secret",
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((n / len(s)) * math.log2(n / len(s))
                for n in (s.count(c) for c in set(s)))


def _is_placeholder(value: str) -> bool:
    """True for an obvious stand-in value, never a real credential.

    Catches the literal giveaways ("changeme", "your_key", ...) and the
    single-character-class case: a value that is all digits, or is one
    character repeated, is a template a human typed, not a generator's
    output.
    """
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if value.isdigit():
        return True
    if len(set(value)) == 1:
        return True
    return False


def _hits(text: str):
    """Yield (rule, severity, line_number) for every match. The value stays here."""
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, severity, pattern, min_entropy in _RULES:
            for m in pattern.finditer(line):
                candidate = m.group(1)
                if name == "generic_secret" and _is_placeholder(candidate):
                    continue
                if min_entropy and _entropy(candidate) < min_entropy:
                    continue
                yield name, severity, lineno


def _finding(rule, severity, path, lines, historical, commit_count=None):
    """Build one finding for `rule` found at `path`.

    `lines` is every line where this (rule, path) pair was matched -- it
    becomes the finding's occurrences, so two hits of the same credential
    type in one file are ONE finding with two occurrences, not two findings.
    The fingerprint identifies a finding by (rule, path) alone -- never by a
    position within the file, which would shift whenever an unrelated line
    moved and falsely resurrect an untouched, already-triaged secret as
    "new" while its old fingerprint vanished as "fixed".

    `commit_count`, when given, is the number of distinct commits a history
    finding was seen in: a credential committed, rotated to a different
    value, and committed again at the same path is still one (rule, path)
    pair -- the value is deliberately never inspected, so "same value
    re-added" cannot be told apart from "a second, different credential" --
    but the reader still needs to know there were two exposures, not one
    silently swallowed by dedup.
    """
    where = "in the git history" if historical else "in the working tree"
    rationale = (f"A credential of type {rule} was found {where}. Its value is "
                 "deliberately not recorded anywhere in this report.")
    if commit_count is not None and commit_count > 1:
        rationale += f" Seen in {commit_count} commits in the history."
    return {
        "fingerprint": secret_fingerprint(rule, path),
        "category": "secret", "rule": rule, "severity": severity,
        "title": f"{rule.replace('_', ' ')} committed to the repository",
        "rationale": rationale,
        "remediation": ("Rotate the credential at the provider first -- it must be "
                        "assumed compromised. Removing it from the file is not enough "
                        "while it remains reachable in the history."),
        "occurrences": [{"file": path, "line": line, "snippet_hash": ""} for line in lines],
        "historical": historical,
    }


def _skip_note(too_big, unreadable):
    """One sentence for the files the tree sweep never opened, or "".

    A file skipped for being 3 MB of minified bundle and a file skipped for
    being a JPEG are both places this scan cannot claim to have looked. The
    skips are individually correct and collectively a coverage gap, and the
    report has exactly one channel for a coverage gap: the note. Counted, not
    listed -- naming every skipped path would turn one line into a directory
    listing, and the reader only needs to know the sweep was not total.
    """
    parts = []
    if too_big:
        parts.append(f"{too_big} larger than {_MAX_BYTES // (1024 * 1024)} MB")
    if unreadable:
        parts.append(f"{unreadable} not readable as UTF-8 text")
    if not parts:
        return ""
    total = too_big + unreadable
    return (f"The secret scan did not read {total} file"
            f"{'' if total == 1 else 's'} ({', '.join(parts)}).")


def scan_tree(root, ignore):
    """(findings, note, lines) for the working tree.

    The note is the same channel `scan_history` and `osv.query` use: whatever
    this sweep could not do is stated, never swallowed. An IGNORED file is not
    in it -- being ignored is a decision the operator made, not a gap.

    `lines` is the number of lines in every file this sweep actually opened --
    a by-product of the read already happening here, not a second walk. A file
    that is skipped (too big, unreadable, ignored) contributes nothing to it,
    so the count describes what was analysed, not what exists on disk. It is
    a count, never the text itself: nothing about it can put a file's
    contents into the ledger, a report or a log.
    """
    root = Path(root)
    out, lines = [], 0
    too_big = unreadable = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        rel = str(p.relative_to(root))
        if ignored(rel, ignore):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                too_big += 1
                continue
        except OSError:
            unreadable += 1
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            unreadable += 1
            continue
        lines += text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        # One finding per credential TYPE per file -- not per match. The
        # fingerprint (type + path) cannot depend on a position, so several
        # matches of one type collapse into one finding with several
        # occurrences (dict preserves first-seen order, so output stays
        # deterministic).
        by_rule = {}
        for rule, severity, line in _hits(text):
            group = by_rule.setdefault(rule, {"severity": severity, "lines": []})
            group["lines"].append(line)
        for rule, group in by_rule.items():
            out.append(_finding(rule, group["severity"], rel, group["lines"], False))
    return out, _skip_note(too_big, unreadable), lines


_DIFF_HEADER_PREFIX = "diff --git a/"


def _path_from_diff_header(line: str):
    """Return the b-side path from a `diff --git a/X b/X` header, or None.

    This line is never prefixed with `+`/`-`/` ` -- unlike every content
    line in the patch, so it cannot be confused with the file's own content,
    even content that happens to read like a diff header. That is what
    replaces the old `line.startswith("+++ b/")` path tracking: a committed
    file whose own content has a line starting `++ b/decoy` is emitted by
    git as the patch line `+++ b/decoy` (one more `+` for the diff, on top
    of the two already in the content) -- indistinguishable from a real
    `+++ b/<path>` file header to a scanner that tracks path that way, and
    that is exactly what let a real finding get mislabelled with a bogus
    path parsed out of the file's own content.

    For the add/modify case this module scans (--diff-filter=AM excludes
    renames), the a-side and b-side paths are identical, which is what
    makes recovering a path containing spaces possible without a full
    diff-header parser: find a " b/" splitting the remainder into two equal
    halves.
    """
    if not line.startswith(_DIFF_HEADER_PREFIX):
        return None
    rest = line[len(_DIFF_HEADER_PREFIX):]
    marker = " b/"
    idx = rest.find(marker)
    while idx != -1:
        candidate = rest[:idx]
        if rest[idx + len(marker):] == candidate:
            return candidate
        idx = rest.find(marker, idx + 1)
    # No exact a/b split found (unusual quoting, or a genuine rename slipping
    # through) -- fall back to the last " b/" as a best effort.
    idx = rest.rfind(marker)
    return rest[idx + len(marker):] if idx != -1 else rest


_COMMIT_HEADER = re.compile(r"^commit ([0-9a-f]{7,40})")


_HISTORY_GAP = ("The git history sweep did not complete ({reason}) — history "
                "findings may be missing: a credential committed and later "
                "deleted would not appear in this report.")


def scan_history(root, since_sha, ignore=()):
    """(findings, note): every secret ever committed, even if the file no
    longer has it.

    A key deleted in a later commit is still readable by anyone with a clone,
    so it is still compromised. This is git plumbing and plain Python: it costs
    no tokens, which is why EVERY analysis can afford to do it.

    The note is the point of the tuple. This used to `return []` on a timeout
    or an OSError, which is the same value as "this repository's history is
    clean" -- so the one failure mode that hides the findings this function
    exists to produce was reported as the best possible news. A gap that is
    stated is useful; this one was silent.
    """
    rev = f"{since_sha}..HEAD" if since_sha else "HEAD"
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "-p", "--no-color", "--no-merges",
             "--diff-filter=AM", rev],
            capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return [], _HISTORY_GAP.format(reason="it timed out after 300s")
    except OSError as exc:
        return [], _HISTORY_GAP.format(reason=f"git could not be run: {exc}")
    if proc.returncode != 0:
        # A non-zero git is not an exception -- `check=False` -- and it was
        # swallowed exactly like one. The overwhelmingly common cause is a
        # root that is not a git checkout at all, which is worth saying: the
        # analysis then covers the working tree only, and nothing on the page
        # would otherwise distinguish that from a repository with a clean
        # history. Only git's FIRST stderr line is quoted; the rest is
        # advice addressed to a human at a terminal.
        reason = (proc.stderr or "").strip().splitlines()
        return [], _HISTORY_GAP.format(
            reason=reason[0] if reason else f"git exited {proc.returncode}")
    blob = proc.stdout

    # (rule, path) -> {"severity": ..., "commits": set-of-sha}. Keyed the
    # same way as the finding itself, with the set of commits the pair was
    # seen in standing in for "how many times": the value is never
    # inspected, so "same value re-added" cannot be told apart from "a
    # second, different credential" -- but the exposures can still be
    # counted. `git log`'s default format indents the commit message body
    # by four spaces, so a message that happens to start with the word
    # "commit" can never be mistaken for this header, which always starts
    # at column zero.
    groups = {}
    path = ""
    skip_path = False
    commit_sha = None
    for line in blob.splitlines():
        commit_match = _COMMIT_HEADER.match(line)
        if commit_match is not None:
            commit_sha = commit_match.group(1)
            continue
        header_path = _path_from_diff_header(line)
        if header_path is not None:
            path = header_path
            # The same globs the tree sweep obeys, applied to the same
            # repo-relative paths. Without this, a fixtures directory full of
            # deliberately fake credentials was excluded from the working-tree
            # findings and reported in full from the history -- the operator
            # set `ignore_paths` and got the noise anyway, one report later.
            skip_path = ignored(path, ignore)
            continue
        if skip_path:
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for rule, severity, _ in _hits(line[1:]):
            key = (rule, path)
            group = groups.setdefault(key, {"severity": severity, "commits": set()})
            if commit_sha is not None:
                group["commits"].add(commit_sha)

    out = []
    for (rule, path), group in groups.items():
        out.append(_finding(rule, group["severity"], path, [0], True,
                             commit_count=len(group["commits"])))
    return out, ""
