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
from .ignores import ignored, sample_suppressed

# Each rule is (name, severity, compiled pattern, minimum entropy of group 1).
# Entropy 0 means the shape alone is conclusive.
_RULES = [
    ("aws_access_key", "critical", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 0.0),
    ("github_token", "critical", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"), 0.0),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), 0.0),
    ("stripe_key", "critical", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), 0.0),
    ("openai_key", "critical", re.compile(r"\b(sk-[A-Za-z0-9]{32,})\b"), 0.0),
    # The header alone is not a finding: `_hits` requires key material to
    # follow it, on the same line or the next -- see `_pem_body_follows`.
    ("private_key", "critical", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"), 0.0),
    ("google_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 0.0),
    # The one generic rule, and the only one that needs the entropy gate and
    # the placeholder gate below.
    ("generic_secret", "medium",
     re.compile(r"(?i)(?:password|passwd|secret|token|api_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+_-]{20,})['\"]?"),
     3.5),
]

# PUBLIC because it is no longer only this module's business. Gitleaks scans
# the filesystem and knows nothing about caches, vendored trees or build
# output; `adapters.gitleaks_config` turns this set into the engine's scope, so
# whichever scanner runs, both agree on where an analysis looks.
#
# AN ENTRY MAY BE A PATH, NOT ONLY A NAME. `skipped()` below is the one
# matcher every reader goes through: a single-segment entry means that
# component at any depth (the old convention, see `ignores.DEFAULT_IGNORE_DIRS`
# for the same one), a multi-segment entry means that exact run of components.
#
# `.superpowers` was added after a measurement on the Minerva checkout
# (dev-knowledge-platform) turned up 22 `generic_secret` hits from
# `.superpowers/` alone, none of them a leak. It is git-ignored and is where
# this repository's own agents write review diffs and run reports -- not the
# analysed project, but routinely full of credential-shaped text (a captured
# key in a review diff, a planted secret in a transcript).
#
# `data/logs` -- where this repository's run transcripts land -- is the same
# kind of noise, and it is SPELLED IN FULL. A bare `logs` was tried first,
# because at the time every reader could only express a bare component; it
# would have exempted EVERY directory named `logs`, in any analysed project,
# from every phase -- the secret sweep, the hygiene key-file and
# committed-`.env` checks, the dependency inventory and all four engine
# scopes. On Minerva that is `martis-app/storage/logs/`, Laravel's real
# application-log directory: a classic place for a stack trace to spill a
# database password, and precisely the untracked material this scanner walks
# the raw filesystem to reach. It also bought nothing -- Minerva has no
# `data/logs`, so the entire measured 57 -> 35 was `.superpowers`. The
# matcher was widened instead; a scanner does not widen its blind spot to fit
# its matching code.
#
# This lines up with the earlier measurement recorded in
# `adapters.gitleaks_config`'s module docstring: before that config's scope
# existed, gitleaks reported 17 findings on this repository, 15 of them
# under `.superpowers/`, `__pycache__/` and `data/logs/`.
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build",
             ".superpowers", "data/logs"}


def skipped(rel) -> bool:
    """True when `rel` is, or lies under, a `SKIP_DIRS` entry.

    THE ONE MATCHER, and it is public for the same reason `SKIP_DIRS` is.
    Every reader used to carry its own `any(part in SKIP_DIRS for part in
    ...)`, which can only ever express a bare component -- and that is how a
    bare `logs` came to be preferred over `data/logs`, exempting an analysed
    project's real application-log directory from every phase because the
    matcher could not say the narrower thing.

    ANY DEPTH, FOR ONE SEGMENT AND FOR MANY. A single-segment entry matches
    that component wherever it appears, exactly as before. A multi-segment
    entry matches its segments as a CONTIGUOUS RUN, also wherever it appears:
    `data/logs` covers `data/logs/x/f` and `sub/data/logs/f`, and never
    `storage/logs/f`. Any-depth is not a taste; it is the only reading the
    engines can be held to. `adapters.scope_patterns` emits
    `(^|/)data/logs/`, and trivy, syft and semgrep are each handed
    `**/data/logs` -- every one of them an any-depth matcher. A root-anchored
    predicate here would leave the built-in sweep reading a tree the engines
    are told to skip, so the same repository would report differently
    depending on which binaries the machine has installed: the exact
    divergence this shared set exists to prevent.
    """
    parts = Path(rel).parts
    for entry in SKIP_DIRS:
        segments = tuple(s for s in str(entry).split("/") if s)
        if not segments:
            continue
        span = len(segments)
        if any(parts[i:i + span] == segments
               for i in range(len(parts) - span + 1)):
            return True
    return False


_MAX_BYTES = 2 * 1024 * 1024
# The same ceiling, in the unit gitleaks' flag takes (`--max-target-megabytes`,
# see `adapters.gitleaks_scan`). Derived from `_MAX_BYTES` rather than written
# twice: the two scanners' findings are merged by fingerprint, so a file only
# one of them reads is a credential only one of them can ever see -- and the
# "N larger than 2 MB" sentence `_skip_note` writes is true of the phase as a
# whole only while both stop at the same size.
MAX_TARGET_MEGABYTES = _MAX_BYTES // (1024 * 1024)

# ONE sentence, whichever scanner found the credential -- `adapters` emits it
# too. The advice is identical because the fact is: a credential that reached
# a repository is compromised, and the file it sits in is not where it lives.
REMEDIATION = ("Rotate the credential at the provider first -- it must be "
               "assumed compromised. Removing it from the file is not enough "
               "while it remains reachable in the history.")

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


# A run of base64 long enough to be key material and too long to be a word.
# Real PEM body lines are 64 characters (OpenSSH writes 70); 40 leaves room for
# the short final line of a body without admitting an ellipsis, a `<redacted>`
# or a variable name.
_PEM_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _pem_body_follows(rest_of_line: str, next_line: str) -> bool:
    """Whether key material follows a PEM header -- the shape of a KEY, not
    of a mention of one.

    Measured on Minerva: three `private_key` findings, every one a lone header
    -- in an adversarial test, a conformance harness and two planning documents
    -- and not one of them a gitleaks finding, whose `private-key` rule wants
    the body. Once both scanners' findings were merged by fingerprint (see
    `cli._scan_secrets`) those came back as findings only this scanner saw, so
    the requirement moved here, to the source.

    Two places the body can be: the NEXT physical line, which is where a PEM
    file puts it, and the REST OF THE SAME line, which is where a `.env` or a
    JSON value puts it -- the whole key on one line with `\\n` where the line
    breaks were. The second is not a corner case; it is how real keys are
    stored in the files this scanner most needs to read.
    """
    return bool(_PEM_BODY.search(rest_of_line) or _PEM_BODY.search(next_line))


def _hits(text: str):
    """Yield (rule, severity, line_number) for every match. The value stays here.

    The lines are read together rather than one at a time because one rule
    needs to see past the line it matched on: a PEM header is a finding only
    when its body follows (`_pem_body_follows`), and in a PEM file the body is
    the next line.
    """
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for name, severity, pattern, min_entropy in _RULES:
            for m in pattern.finditer(line):
                candidate = m.group(1)
                if name == "generic_secret" and _is_placeholder(candidate):
                    continue
                if name == "private_key" and not _pem_body_follows(
                        line[m.end():], lines[lineno] if lineno < len(lines) else ""):
                    continue
                if min_entropy and _entropy(candidate) < min_entropy:
                    continue
                yield name, severity, lineno


def looks_like_a_secret(text: str):
    """The rule NAME of the first shaped credential pattern in `text`, or
    None. This is the door's gate on free text an agent WRITES -- a
    finding's title, rationale, remediation, partial_note -- not the
    scanner's own corpus, but the shapes a credential can take do not change
    depending on who typed the surrounding text.

    Walks `_RULES` -- the same list `_hits` walks, not a second copy of it.
    This repository has been bitten twice by a second copy of a rule list
    drifting from the first (see the module docstring), so the patterns have
    exactly one home and this function is just another reader of it. The
    same placeholder gate `_is_placeholder` already applies to the generic
    rule applies here too, so an agent writing `password = "changeme12345"`
    to describe what it found is not refused for quoting an obvious
    stand-in. So does the body requirement `_hits` puts on a PEM header, over
    the rest of the text: a header an agent quotes to name what it found is
    not refused; a header with the key behind it is.

    Returns the RULE NAME ONLY. It never returns, logs, or stores the
    matched text itself -- the one property every function in this module
    guarantees, and the one this function's only caller (the report-finding
    door) depends on to refuse a finding without ever repeating what it
    refused.
    """
    for name, severity, pattern, min_entropy in _RULES:
        for m in pattern.finditer(text):
            candidate = m.group(1)
            if name == "generic_secret" and _is_placeholder(candidate):
                continue
            if name == "private_key" and not _pem_body_follows(text[m.end():], ""):
                continue
            if min_entropy and _entropy(candidate) < min_entropy:
                continue
            return name
    return None


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

    `rule` is the name the finding is MINTED under, which is this scanner's
    own name for the type or -- when the caller passed a `rename` map, see
    `scan_tree` -- the engine's name for it. Either spelling reads as words in
    the title.
    """
    where = "in the git history" if historical else "in the working tree"
    rationale = (f"A credential of type {rule} was found {where}. Its value is "
                 "deliberately not recorded anywhere in this report.")
    if commit_count is not None and commit_count > 1:
        rationale += f" Seen in {commit_count} commits in the history."
    return {
        "fingerprint": secret_fingerprint(rule, path),
        "category": "secret", "rule": rule, "severity": severity,
        "title": f"{rule.replace('_', ' ').replace('-', ' ')} committed to the repository",
        "rationale": rationale,
        "remediation": REMEDIATION,
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
        parts.append(f"{too_big} larger than {MAX_TARGET_MEGABYTES} MB")
    if unreadable:
        parts.append(f"{unreadable} not readable as UTF-8 text")
    if not parts:
        return ""
    total = too_big + unreadable
    return (f"The secret scan did not read {total} file"
            f"{'' if total == 1 else 's'} ({', '.join(parts)}).")


def _readable_files(root, ignore, unread):
    """Yield (relative path, text) for every file a sweep may read.

    The walk `scan_tree` reads, kept apart from the matching so that what was
    and was not opened has one home. It used to be shared with a second
    caller, `count_lines`, which counted `lines_of_code` for the analyses an
    engine scanned instead of this module; the built-in sweep now runs beside
    the engine on every analysis (see `cli._scan_secrets`), so the count is
    once again a by-product of the read that is happening anyway. `unread` is
    a mutable dict the walk reports into, because a generator's return value
    is not reachable through a `for`. It counts only the files this walk
    OPENED AND COULD NOT READ -- a path excluded by `skipped` or by `ignore`
    was never in scope and is not a coverage gap to declare.
    """
    root = Path(root)
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if skipped(p.relative_to(root)):
            continue
        rel = str(p.relative_to(root))
        if ignored(rel, ignore):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                unread["too_big"] += 1
                continue
        except OSError:
            unread["unreadable"] += 1
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            unread["unreadable"] += 1
            continue
        yield rel, text


def _lines_in(text: str) -> int:
    return text.count("\n") + (0 if text.endswith("\n") or not text else 1)


def scan_tree(root, ignore, rename=None):
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

    `rename` maps this scanner's rule names onto the names the findings are
    MINTED under. `cli._scan_secrets` passes the secret entries of
    `taxonomy.RULE_RENAMES` when gitleaks runs beside this scanner, so the two
    scanners' readings of one credential type share one fingerprint and merge
    into one finding. Applied AFTER the template rule, which is keyed on this
    scanner's own names, and BEFORE the finding is built, so the identity, the
    title and the rationale all carry the minted name. None -- the fallback
    path, when this scanner runs alone -- mints this scanner's own names,
    exactly as it always has: `migrate-rules` stays the deliberate step from
    one vocabulary to the other on a machine that gains the engine.
    """
    rename = rename or {}
    out, lines = [], 0
    unread = {"too_big": 0, "unreadable": 0}
    for rel, text in _readable_files(root, ignore, unread):
        lines += _lines_in(text)
        # One finding per credential TYPE per file -- not per match. The
        # fingerprint (type + path) cannot depend on a position, so several
        # matches of one type collapse into one finding with several
        # occurrences (dict preserves first-seen order, so output stays
        # deterministic).
        by_rule = {}
        for rule, severity, line in _hits(text):
            # A committed TEMPLATE of a configuration file is read like any
            # other file -- it counts towards `lines`, because this sweep did
            # open it -- and the two rules that over-fire on a template are
            # dropped from it. PER RULE and not per file: this used to skip
            # the whole file, and a real `openssl genrsa` key in
            # `certs/server.key.example` was then reported by nothing at all.
            # See `ignores.SAMPLE_SUPPRESSED_RULES`.
            if sample_suppressed(rel, rule, ignore):
                continue
            rule = rename.get(rule, rule)
            group = by_rule.setdefault(rule, {"severity": severity, "lines": []})
            group["lines"].append(line)
        for rule, group in by_rule.items():
            out.append(_finding(rule, group["severity"], rel, group["lines"], False))
    return out, _skip_note(unread["too_big"], unread["unreadable"]), lines


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


# PUBLIC: one sentence for one blind spot, whichever scanner hit it. The
# engine path in `adapters.gitleaks_scan` fills the same template, so a reader
# is never asked to learn two vocabularies for "the history was not read".
HISTORY_GAP = ("The git history sweep did not complete ({reason}) — history "
               "findings may be missing: a credential committed and later "
               "deleted would not appear in this report.")

# What it costs to have run this scanner instead of an engine. Counted from
# the rule list itself so the number cannot drift away from the rules, and
# said out loud because "secrets were scanned" is a different claim depending
# on who did the scanning -- eight shaped rules is not gitleaks' rule set, and
# a reader judging this report's blind spots needs to know which they got.
FALLBACK_NOTE = (f"Secrets were scanned by the built-in pattern scanner and "
                 f"its {len(_RULES)} shaped rules, not by gitleaks: a "
                 "credential whose shape is outside those rules would not "
                 "have been found.")


def scan_history(root, since_sha, ignore=(), rename=None):
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

    `rename` is `scan_tree`'s: the names to mint under, applied after the
    template rule and before the finding is built, None for this scanner's
    own.
    """
    rev = f"{since_sha}..HEAD" if since_sha else "HEAD"
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "-p", "--no-color", "--no-merges",
             "--diff-filter=AM", rev],
            capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return [], HISTORY_GAP.format(reason="it timed out after 300s")
    except OSError as exc:
        return [], HISTORY_GAP.format(reason=f"git could not be run: {exc}")
    if proc.returncode != 0:
        # A non-zero git is not an exception -- `check=False` -- and it was
        # swallowed exactly like one. The overwhelmingly common cause is a
        # root that is not a git checkout at all, which is worth saying: the
        # analysis then covers the working tree only, and nothing on the page
        # would otherwise distinguish that from a repository with a clean
        # history. Only git's FIRST stderr line is quoted; the rest is
        # advice addressed to a human at a terminal.
        reason = (proc.stderr or "").strip().splitlines()
        return [], HISTORY_GAP.format(
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
    rename = rename or {}
    path = ""
    skip_path = False
    commit_sha = None
    # The `+` lines of the current (commit, path), read TOGETHER when the next
    # header arrives rather than one at a time: `_hits` has to see the line
    # after a PEM header to know whether a body follows it, and a single diff
    # line cannot show it one. A path the sweep skips adds nothing here, so
    # the buffer is never more than one file's additions in one commit.
    added = []

    def sweep():
        for rule, severity, _ in _hits("\n".join(added)):
            if sample_suppressed(path, rule, ignore):
                continue
            rule = rename.get(rule, rule)
            key = (rule, path)
            group = groups.setdefault(key, {"severity": severity, "commits": set()})
            if commit_sha is not None:
                group["commits"].add(commit_sha)
        added.clear()

    for line in blob.splitlines():
        commit_match = _COMMIT_HEADER.match(line)
        if commit_match is not None:
            sweep()
            commit_sha = commit_match.group(1)
            continue
        header_path = _path_from_diff_header(line)
        if header_path is not None:
            sweep()
            path = header_path
            # The same globs the tree sweep obeys, applied to the same
            # repo-relative paths. Without this, a fixtures directory full of
            # deliberately fake credentials was excluded from the working-tree
            # findings and reported in full from the history -- the operator
            # set `ignore_paths` and got the noise anyway, one report later.
            # The default filter rides in the same decision for the same
            # reason: a default honoured by one of the two sweeps and not the
            # other reopens exactly that hole. The TEMPLATE rule rides one
            # level down, per rule, exactly as `scan_tree` applies it -- so a
            # private key committed in a `.example` file is reported from the
            # history too, and only the two template-noisy rules are not.
            skip_path = ignored(path, ignore)
            continue
        if skip_path:
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added.append(line[1:])
    sweep()

    out = []
    for (rule, path), group in groups.items():
        out.append(_finding(rule, group["severity"], path, [0], True,
                             commit_count=len(group["commits"])))
    return out, ""
