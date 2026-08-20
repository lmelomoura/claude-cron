"""Things that are wrong about the repository itself, not about its code."""

import fnmatch
from pathlib import Path

from .fingerprint import fingerprint

_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks")
_ENV_ALLOWED = ("*.example", "*.sample", "*.template", "*.dist")


def _finding(rule, severity, title, rationale, remediation, rel):
    return {
        "fingerprint": fingerprint("hygiene", rule, rel, rule),
        "category": "hygiene", "rule": rule, "severity": severity,
        "title": title, "rationale": rationale, "remediation": remediation,
        "occurrences": [{"file": rel, "line": 0, "snippet_hash": ""}],
    }


def scan(root):
    root = Path(root)
    out = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel_path = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel_path.parts):
            continue
        rel, name = str(rel_path), path.name

        if name.startswith(".env") and not any(
                fnmatch.fnmatch(name, pat) for pat in _ENV_ALLOWED):
            out.append(_finding(
                "committed_env_file", "high", f"{rel} is committed",
                "Environment files hold configuration that is meant to differ per "
                "machine, and routinely hold credentials.",
                "Remove it from the repository, add it to .gitignore, and rotate "
                "anything it contained.", rel))

        if name.endswith(_KEY_SUFFIXES):
            out.append(_finding(
                "committed_key_file", "critical", f"{rel} looks like a key file",
                "Key material in a repository is readable by everyone with a clone.",
                "Remove it, rotate the key, and keep it out of the tree.", rel))

        if path.stat().st_mode & 0o002:
            out.append(_finding(
                "world_writable_file", "medium", f"{rel} is world-writable",
                "Any local user can rewrite this file, including before it runs.",
                f"chmod o-w {rel}", rel))
    return out
