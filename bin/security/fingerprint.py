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


def secret_fingerprint(secret_type: str, path: str) -> str:
    """Identity of a secret finding.

    The secret's value is not a parameter. Hashing it would put an oracle for
    the secret in the ledger -- weak, but real -- so identity comes from the
    credential's TYPE and the FILE it lives in, never from what it says and
    never from a position within that file. A position -- an ordinal, a line
    number -- moves whenever an unrelated line is added or removed above it,
    which would make an untouched, already-triaged secret look "fixed" (its
    old fingerprint vanishes) and "new" (a fresh one appears) on the very
    next analysis. Several matches of the same type in the same file are one
    finding with several occurrences, not several findings -- see
    `bin/security/secrets.py`.
    """
    return _digest("secret", secret_type, path)
