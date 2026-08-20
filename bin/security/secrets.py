"""Secret detection without a binary: shaped patterns plus an entropy gate.

Two rules govern this file. The value never leaves it -- not into a return
value, not into a log, not masked. And a pattern must have a SHAPE: entropy
alone flags every hash, UUID and minified bundle in the repo, which is how a
secret scanner becomes something people turn off.
"""

import fnmatch
import math
import re
import subprocess
from pathlib import Path

from .fingerprint import secret_fingerprint

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


def _ignored(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/*") + "/*")
               for p in patterns)


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


def _finding(rule, severity, path, lines, historical):
    """Build one finding for `rule` found at `path`.

    `lines` is every line where this (rule, path) pair was matched -- it
    becomes the finding's occurrences, so two hits of the same credential
    type in one file are ONE finding with two occurrences, not two findings.
    The fingerprint identifies a finding by (rule, path) alone -- never by a
    position within the file, which would shift whenever an unrelated line
    moved and falsely resurrect an untouched, already-triaged secret as
    "new" while its old fingerprint vanished as "fixed".
    """
    where = "in the git history" if historical else "in the working tree"
    return {
        "fingerprint": secret_fingerprint(rule, path),
        "category": "secret", "rule": rule, "severity": severity,
        "title": f"{rule.replace('_', ' ')} committed to the repository",
        "rationale": f"A credential of type {rule} was found {where}. Its value is "
                     "deliberately not recorded anywhere in this report.",
        "remediation": ("Rotate the credential at the provider first -- it must be "
                        "assumed compromised. Removing it from the file is not enough "
                        "while it remains reachable in the history."),
        "occurrences": [{"file": path, "line": line, "snippet_hash": ""} for line in lines],
        "historical": historical,
    }


def scan_tree(root, ignore):
    root = Path(root)
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        rel = str(p.relative_to(root))
        if _ignored(rel, ignore) or p.stat().st_size > _MAX_BYTES:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
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
    return out


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


def scan_history(root, since_sha):
    """Every secret ever committed, even if the file no longer has it.

    A key deleted in a later commit is still readable by anyone with a clone,
    so it is still compromised. This is git plumbing and plain Python: it costs
    no tokens, which is why the baseline can afford to do it.
    """
    rev = f"{since_sha}..HEAD" if since_sha else "HEAD"
    try:
        blob = subprocess.run(
            ["git", "-C", str(root), "log", "-p", "--no-color", "--no-merges",
             "--diff-filter=AM", rev],
            capture_output=True, text=True, timeout=300, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []

    out, path, seen = [], "", set()
    for line in blob.splitlines():
        header_path = _path_from_diff_header(line)
        if header_path is not None:
            path = header_path
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for rule, severity, _ in _hits(line[1:]):
            key = (rule, path)
            if key in seen:
                continue
            seen.add(key)
            out.append(_finding(rule, severity, path, [0], True))
    return out
