"""Things that are wrong about the repository itself, not about its code."""

from pathlib import Path

from . import ignores
from .fingerprint import fingerprint
from .ignores import ignored
# THE shared engine scope, not a copy of it -- see `deps.py`, which imported
# the same set for the same reason. `secrets.SKIP_DIRS` is public precisely
# because it is no longer one module's business: it is what every scanner,
# built-in or engine, is told an analysis covers.
from .secrets import SKIP_DIRS as _SKIP_DIRS
_KEY_TEXT_SUFFIXES = (".pem", ".key")
_KEY_BINARY_SUFFIXES = (".p12", ".pfx", ".jks")
_KEY_SNIFF_BYTES = 4096
# The template suffixes this rule has always allowed are matched by
# `ignores.sample_suffix` -- the one place they are written down, and now the
# one matcher too. This rule and the secret scan's are about the same fact --
# a committed template of a configuration file is the documented, correct
# thing to ship -- and a repository where the two disagreed would report
# `.env.dist` in one section of the report and not in the other. The local
# `fnmatch` copy that used to live here disagreed about `.ENV.EXAMPLE`, which
# is what moved the matcher rather than only the list.
#
# NOT gated on `ignores.defaults_apply`: this exclusion predates the default
# noise filter and is not part of it. `!defaults` says "scan my fixtures and
# my templates for CREDENTIALS"; it has never meant "and start telling me
# that committing a .env.example is a leak".
#
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


def _looks_like_private_key(path, proof_required=False):
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

    `proof_required` INVERTS that default, and only for a file whose name says
    it is a template (`server.key.example`). The conservative side is chosen
    by which error is more likely, and for a template it is the other one: a
    `.key.example` is expected to hold a placeholder, so "neither marker" is
    the normal case there rather than the suspicious one. Under proof the
    finding is made only when the PEM marker is actually present -- which is
    exactly the case that matters, and the case a real `openssl genrsa` key
    committed as `server.key.example` produces.
    """
    try:
        with path.open("rb") as f:
            head = f.read(_KEY_SNIFF_BYTES).decode("utf-8", errors="ignore")
    except OSError:
        return not proof_required
    if "PRIVATE KEY" in head:
        return True
    if proof_required:
        return False
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

    A TEMPLATE SUFFIX IS LOOKED PAST BEFORE THE SUFFIX TEST. `server.key`
    was sniffed and `server.key.example` was not even considered key
    material, so a real 2048-bit RSA key committed under the second name was
    reported by no rule in this project at all. The name a template is a
    template OF is what this rule is about (`ignores.sample_stem`), and the
    sniff then runs under proof: the template is reported only when it
    genuinely holds a private key, so nothing new is reported for the
    placeholder `server.key.example` this treatment exists to tolerate.

    Binary containers (.p12, .pfx, .jks) get the same template treatment as
    the suffix above -- `stem`, not `name` -- but none of the proof: there is
    no meaningful marker to sniff in a binary container, the secrets scanner
    cannot open one either, so suffix is the only signal this rule has ever
    had, template or not. `keystore.jks.example` is therefore reported
    exactly as `keystore.jks` already is -- by name alone, unproven -- which
    is not a new guess, only the existing one no longer stopped at the door
    by a suffix it does not recognise. The alternative (matching `name`, not
    `stem`) was tried first and is the shape of the `.key.example` hole this
    block was written to close, one layer up: a real key committed under a
    template name reported by nothing, and `!defaults` unable to bring it
    back because the file never reaches the rule at all.
    """
    stem = ignores.sample_stem(name)
    if stem.endswith(_KEY_TEXT_SUFFIXES):
        return _looks_like_private_key(path, proof_required=stem != name)
    return stem.endswith(_KEY_BINARY_SUFFIXES)


def scan(root, ignore=()):
    """Every hygiene finding in the tree, minus what `ignore_paths` excludes.

    The globs are the same ones the secret sweeps obey, read through the same
    helper. Before this parameter existed a project could exclude
    `tests/fixtures/**` from the secret scan and still be told, every single
    analysis, that `tests/fixtures/id_rsa` "looks like a key file" -- the
    setting said what it meant and one phase of three ignored it.
    """
    root = Path(root)
    out = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel_path = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel_path.parts):
            continue
        rel, name = str(rel_path), path.name
        if ignored(rel, ignore):
            continue

        if (name.startswith(".env") and name not in _ENV_EXCLUDED_NAMES
                and not ignores.sample_suffix(name)):
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

    # Advisory, not a defect: nothing is leaking yet. It is how the next .env
    # gets committed, which is why it is recorded at all -- and why it is info.
    #
    # Gated on `.git` existing at all, not just on scan() being called: the
    # rule's own rationale is about things being COMMITTED, which only means
    # something in a repository. `scan()` runs on any directory it is pointed
    # at, and in production that is always a `git worktree` checkout, where
    # `.git` is a FILE that points at the real repo, not a directory --
    # `.exists()` is true for both that file and an ordinary clone's `.git`
    # directory, where `.is_dir()` would silently miss the worktree case.
    if (root / ".git").exists() and not (root / ".gitignore").is_file():
        out.append(_finding(
            "missing_gitignore", "info", "This repository has no .gitignore",
            "Without one, the first .env, key or credential file someone adds "
            "is committed by default.",
            "Add a .gitignore covering .env files, key material and local "
            "build output.", ".gitignore"))
    return out
