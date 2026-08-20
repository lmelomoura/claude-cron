"""Things that are wrong about the repository itself, not about its code."""

import fnmatch
from pathlib import Path

from .fingerprint import fingerprint

_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
_KEY_TEXT_SUFFIXES = (".pem", ".key")
_KEY_BINARY_SUFFIXES = (".p12", ".pfx", ".jks")
_KEY_SNIFF_BYTES = 4096
_ENV_ALLOWED = ("*.example", "*.sample", "*.template", "*.dist")
# .envrc is a direnv config -- a script that sets up a shell environment, not
# an env file -- and it is routinely and correctly committed. It only trips
# the `.env` prefix check by coincidence of naming.
_ENV_EXCLUDED_NAMES = frozenset({".envrc"})


def _finding(rule, severity, title, rationale, remediation, rel):
    return {
        # Identity is (rule, path) alone, deliberately -- same rationale as
        # secret_fingerprint (see fingerprint.py): the fourth argument below
        # is a constant, not the file's content, so a finding's fingerprint
        # never shifts with wording, formatting, or position in the file.
        "fingerprint": fingerprint("hygiene", rule, rel, rule),
        "category": "hygiene", "rule": rule, "severity": severity,
        "title": title, "rationale": rationale, "remediation": remediation,
        "occurrences": [{"file": rel, "line": 0, "snippet_hash": ""}],
    }


def _looks_like_private_key(path):
    """True unless the head of a text key file proves it holds no private key.

    Reads only the first _KEY_SNIFF_BYTES bytes -- a PEM marker always sits
    at the very start of the block it introduces, so the rest of the file
    (which may be arbitrarily large) never needs to be read. Decoding is
    best-effort (utf-8, invalid bytes ignored): this function only needs to
    find or fail to find two ASCII markers, not to produce a faithful
    transcript.

    Returns True (keep the finding) whenever the file cannot be read, or
    contains neither marker. That is the conservative side on purpose: a
    .pem/.key this scanner cannot make sense of is exactly the case where
    staying quiet would be the false negative, not the false positive this
    function exists to remove.
    """
    try:
        with path.open("rb") as f:
            head = f.read(_KEY_SNIFF_BYTES).decode("utf-8", errors="ignore")
    except OSError:
        return True
    if "PRIVATE KEY" in head:
        return True
    if "CERTIFICATE" in head:
        return False
    return True


def _is_key_material(path, name):
    """True if `path` should be reported as committed key material.

    Text formats (.pem, .key) are sniffed by content: a public certificate
    chain (fullchain.pem, ca-bundle.pem, ...) is routinely and correctly
    committed, and reporting it as "key material... readable by everyone"
    is exactly the false positive that gets a rule switched off. A file
    that contains an actual private key marker still gets the critical
    finding; the secrets module's content pattern (see secrets.py,
    `private_key`) independently catches a private key embedded anywhere,
    so nothing is lost by letting a pure certificate through here.

    Binary containers (.p12, .pfx, .jks) keep the old suffix-only
    behaviour, unlike .pem/.key above: sniffing them for a meaningful
    marker is not cheap, and the secrets scanner cannot open them either,
    so suffix is the only signal available.
    """
    if name.endswith(_KEY_TEXT_SUFFIXES):
        return _looks_like_private_key(path)
    return name.endswith(_KEY_BINARY_SUFFIXES)


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

        if (name.startswith(".env") and name not in _ENV_EXCLUDED_NAMES
                and not any(fnmatch.fnmatch(name, pat) for pat in _ENV_ALLOWED)):
            out.append(_finding(
                "committed_env_file", "high", f"{rel} is committed",
                "Environment files hold configuration that is meant to differ per "
                "machine, and routinely hold credentials.",
                "Remove it from the repository, add it to .gitignore, and rotate "
                "anything it contained.", rel))

        if _is_key_material(path, name):
            out.append(_finding(
                "committed_key_file", "critical", f"{rel} looks like a key file",
                "Key material in a repository is readable by everyone with a clone.",
                "Remove it, rotate the key, and keep it out of the tree.", rel))

        if path.stat().st_mode & 0o002:
            # git tracks only the executable bit -- never group/other write
            # permissions -- so a fresh checkout cannot produce this finding
            # on its own. This rule exists for what a BUILD or PROVISION
            # step leaves behind on disk after checkout, not for the clone
            # itself; it is not dead code even though it can never fire in
            # a worktree that was only ever `git clone`'d.
            out.append(_finding(
                "world_writable_file", "medium", f"{rel} is world-writable",
                "Any local user can rewrite this file, including before it runs.",
                f"chmod o-w {rel}", rel))
    return out
