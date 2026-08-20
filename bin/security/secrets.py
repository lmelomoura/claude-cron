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
    # The one generic rule, and the only one that needs the entropy gate.
    ("generic_secret", "medium",
     re.compile(r"(?i)(?:password|passwd|secret|token|api_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+_-]{20,})['\"]?"),
     3.5),
]

_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
_MAX_BYTES = 2 * 1024 * 1024


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((n / len(s)) * math.log2(n / len(s))
                for n in (s.count(c) for c in set(s)))


def _ignored(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/*") + "/*")
               for p in patterns)


def _hits(text: str):
    """Yield (rule, severity, line_number) for every match. The value stays here."""
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, severity, pattern, min_entropy in _RULES:
            for m in pattern.finditer(line):
                if min_entropy and _entropy(m.group(1)) < min_entropy:
                    continue
                yield name, severity, lineno


def _finding(rule, severity, path, ordinal, line, historical):
    where = "in the git history" if historical else "in the working tree"
    return {
        "fingerprint": secret_fingerprint(rule, path, ordinal),
        "category": "secret", "rule": rule, "severity": severity,
        "title": f"{rule.replace('_', ' ')} committed to the repository",
        "rationale": f"A credential of type {rule} was found {where}. Its value is "
                     "deliberately not recorded anywhere in this report.",
        "remediation": ("Rotate the credential at the provider first -- it must be "
                        "assumed compromised. Removing it from the file is not enough "
                        "while it remains reachable in the history."),
        "occurrences": [{"file": path, "line": line, "snippet_hash": ""}],
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
        for ordinal, (rule, severity, line) in enumerate(_hits(text)):
            out.append(_finding(rule, severity, rel, ordinal, line, False))
    return out


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
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for rule, severity, _ in _hits(line[1:]):
            key = (rule, path)
            if key in seen:
                continue
            seen.add(key)
            out.append(_finding(rule, severity, path, len(seen), 0, True))
    return out
