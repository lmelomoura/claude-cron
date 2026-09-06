"""The rename to agentloop is complete only when nothing in the shipped tree
spells the old name. This test is the definition of "complete".

Three names are checked: the product (`claude-cron`, `CLAUDE_CRON_*`), the
run-environment prefix (`CC_*`, and the `cc_port` family of helpers) and the
identifiers that were derived from it (`CCApp`, `CCSecurity`, the page's `CC`
state object, `cc_server`, `X-CC-Token`). A one-release transition keeps the
old names working, and every line that exists for that purpose is either
PAIRED with its new name on the same line (a fallback read, a dual export, the
dual header, an alias) or listed in ALLOWED below. Removing the transition
later means emptying ALLOWED and deleting the paired halves — this test then
keeps them from coming back.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# What is scanned: everything shipped. Not scanned: CHANGELOG.md (history is
# written in the name of its day), docs/ (dated specs and plans), the raw
# scanner captures under tests/security/fixtures/ and the stream samples under
# test/fixtures/ (real samples of a tree that had the old name when they were
# taken), and this file.
SCANNED = [
    "bin", "ui", "skills", "build", "test", "tests", ".github",
    "install.sh", "uninstall.sh", "README.md", "CONTRIBUTING.md",
    "package.json", ".gitignore",
    "config/jobs.example.json", "config/prechecks/example-hello.sh",
    "config/provision/example-hello.up.sh",
]
SKIP_DIRS = {"__pycache__", ".pytest_cache", "node_modules", "fixtures"}
SKIP_FILES = {Path(__file__).name}

OLD = re.compile(
    r"(?i:claude-cron)"
    r"|\bCLAUDE_CRON\b"
    r"|CLAUDE_CRON_[A-Z_]+"
    r"|\bCC_[A-Z_]+"
    r"|\bcc_(?:port|env_set|env_ports|copy_ignored)\b"
    r"|CCApp|CCSecurity|cc_server|X-CC-Token"
    r"|\bCC\.[A-Za-z_]|\bCC\s*=[^=]"
)

# Lines allowed to carry the old name, by (path, substring). Each one exists
# for the transition or for the migration, and each says why.
ALLOWED = [
    # the migration constants: the only place the old labels and names are spelled
    ("bin/agentloop", 'LEGACY_PLIST_LABEL="com.claude-cron.tick"'),
    ("bin/agentloop", 'LEGACY_SERVER_LABEL="com.claude-cron.server"'),
    ("bin/agentloop", 'LEGACY_CLI_NAME="claude-cron"'),
    ("bin/agentloop", 'LEGACY_ENV_PREFIX="CLAUDE_CRON_"'),
    ("bin/agentloop", 'LEGACY_RUN_PREFIX="CC_"'),
    ("uninstall.sh", 'LEGACY_CLI_NAME="claude-cron"'),
    # the server binds its config dirs at import time, before any shim could run
    ("bin/agentloop-server", 'LEGACY_ENV_PREFIX = "CLAUDE_CRON_"'),
    # the security package reads its switch and its marker straight from the environment
    ("bin/security/adapters.py", 'LEGACY_ENGINES_ENV = "CC_SECURITY_ENGINES"'),
    # comments and assertions that name a path INSIDE a scanner capture taken before the rename
    ("bin/security/adapters.py", "taken before the rename"),
    ("bin/security/engines.py", "taken before the rename"),
    ("tests/security/test_adapters.py", "taken before the rename"),
    ("tests/security/test_engines.py", "taken before the rename"),
]


def _files():
    for entry in SCANNED:
        p = REPO / entry
        if p.is_file():
            yield p
            continue
        for f in sorted(p.rglob("*")):
            if not f.is_file():
                continue
            if SKIP_DIRS & set(f.relative_to(REPO).parts):
                continue
            if f.name in SKIP_FILES:
                continue
            yield f


def _paired(line, token):
    """A transition line carries BOTH spellings: the old one is tolerated only
    next to the new one it falls back from, as a whole token."""
    def has(new):
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(new) + r"(?![A-Za-z0-9_])", line) is not None
    if token.startswith("CLAUDE_CRON_"):
        return has("AGENTLOOP_" + token[len("CLAUDE_CRON_"):])
    if token.startswith("CC_"):
        return has("AL_" + token[len("CC_"):])
    if token.startswith("cc_"):
        return has("al_" + token[len("cc_"):])
    if token == "X-CC-Token":
        return "X-AL-Token" in line
    return False


def _readme_upgrade_section(text):
    """The README's own upgrade notes have to say what the old names were.
    They live under one heading, and only there."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if l.startswith("### Upgrading from claude-cron")), None)
    if start is None:
        return set()
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("## ") or lines[i].startswith("### ")), len(lines))
    return set(range(start, end))


def test_nothing_shipped_spells_the_old_name():
    offenders = []
    for path in _files():
        rel = path.relative_to(REPO).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        exempt = _readme_upgrade_section(text) if rel == "README.md" else set()
        for n, line in enumerate(text.splitlines()):
            if n in exempt:
                continue
            for m in OLD.finditer(line):
                if _paired(line, m.group(0)):
                    continue
                if any(rel == p and s in line for p, s in ALLOWED):
                    continue
                offenders.append(f"{rel}:{n + 1}: {m.group(0)}  |  {line.strip()[:110]}")
    assert not offenders, (f"{len(offenders)} old-name spellings survive:\n"
                           + "\n".join(offenders[:200]))
