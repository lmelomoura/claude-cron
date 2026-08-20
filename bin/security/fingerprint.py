"""Stable identity for a finding.

The fingerprint is what lets a second analysis say "this is the same finding"
instead of reporting everything as new. It deliberately excludes the line
number: a finding that moved because someone added an import above it is the
same finding, and anchoring on the line would resurrect the whole report on
every reformat.
"""

import hashlib
import re

_WHITESPACE = re.compile(r"\s+")


def _normalise(snippet: str) -> str:
    return _WHITESPACE.sub(" ", snippet).strip()


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def fingerprint(category: str, rule: str, path: str, snippet: str) -> str:
    """Identity of a non-secret finding."""
    return _digest(category, rule, path, _normalise(snippet))


def secret_fingerprint(secret_type: str, path: str, ordinal: int) -> str:
    """Identity of a secret finding.

    The secret's value is not a parameter. Hashing it would put an oracle for
    the secret in the ledger -- weak, but real -- so identity comes from where
    it is and which occurrence in that file it is, never from what it says.
    """
    return _digest("secret", secret_type, path, str(ordinal))
