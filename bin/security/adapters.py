"""One translator per engine, from purged JSON to this project's findings.

`engines.py` runs someone else's program and throws away the fields that
carry what it matched. This module is the other half: it decides what a
finding MEANS. Nothing here copies an engine's record into a finding --
every field is built from scratch, so a key a future version of the engine
adds cannot ride into the ledger because nobody thought to exclude it.

TWO RULES GOVERN THE GITLEAKS ADAPTER, AND BOTH ARE EXPENSIVE TO GET WRONG.

IDENTITY IS OURS. Gitleaks emits its own `Fingerprint`, `path:rule:line`.
It is right there in the report and it is not usable: a secret's identity in
this system is `fingerprint.secret_fingerprint(rule, path)` -- the credential
TYPE and the FILE, never the value and never a position. Adopting the
engine's recipe would re-identify every secret finding already recorded and
orphan the `accepted` / `false_positive` decisions a human took against them;
and anchoring on a line number resurrects an untouched, already-triaged
secret as "new" the moment an unrelated line is added above it.

SCOPE IS OURS TOO. Gitleaks scans the FILESYSTEM, not the versioned tree,
and it knows nothing about `secrets.SKIP_DIRS` or the project's
`ignore_paths`. Measured on this repository before the configuration below
existed: 17 findings, 15 of them under `.superpowers/`, `__pycache__/` and
`data/logs/`. Without `gitleaks_config` reaching the binary, swapping the
hand-written scanner for the engine makes the report NOISIER than the thing
it replaced. That is why the scope is built here and passed as `--config`,
and not left to whatever the engine's defaults happen to skip.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path

from . import engines, secrets
from .fingerprint import secret_fingerprint
from .ignores import ignored

# Gitleaks emits no severity of its own -- it reports that a pattern matched
# and leaves the judgement to the caller. These are the judgements
# `secrets._RULES` already made, carried across to the engine's names for the
# same credential types, so the swap does not silently re-grade a repository's
# whole secret backlog. Anything not listed is DEFAULT_SEVERITY.
SEVERITY_BY_RULE = {
    # secrets._RULES: aws_access_key, critical
    "aws-access-token": "critical",
    # secrets._RULES: github_token, critical -- one rule of ours, five of theirs
    "github-pat": "critical",
    "github-fine-grained-pat": "critical",
    "github-oauth": "critical",
    "github-app-token": "critical",
    "github-refresh-token": "critical",
    # secrets._RULES: stripe_key, critical
    "stripe-access-token": "critical",
    # secrets._RULES: openai_key, critical
    "openai-api-key": "critical",
    # secrets._RULES: private_key, critical
    "private-key": "critical",
    # secrets._RULES: slack_token, high
    "slack-bot-token": "high",
    "slack-user-token": "high",
    "slack-app-token": "high",
    "slack-config-access-token": "high",
    "slack-legacy-bot-token": "high",
    "slack-legacy-token": "high",
    "slack-webhook-url": "high",
    # secrets._RULES: google_api_key, high
    "gcp-api-key": "high",
    # secrets._RULES: generic_secret, medium. The one rule on either side that
    # matches on shape alone rather than on a vendor's prefix, and the one that
    # produces most of the false positives -- graded accordingly on both.
    "generic-api-key": "medium",
}

# Gitleaks ships around 180 rules and gains more with every release. An
# unmapped one is a shaped, vendor-specific credential pattern -- the same
# kind of match as everything graded `critical` or `high` above -- so it is
# reported as `high` rather than dropped or left without a severity the
# report cannot count. Grading it DOWN would be the dangerous default: a new
# rule for a new cloud provider's root key would arrive as `info`.
DEFAULT_SEVERITY = "high"

# Named so the reader of a report knows which scanner's rule set produced it,
# and honest about which of the two sweeps actually ran.
ENGINE_NOTE = "Secrets were scanned by {version}, over {scope}."

# What `{scope}` says about the history half, and why there are two spellings.
# "the full git history" is a CLAIM, and on a shallow clone it is false: a
# depth-1 clone carries one commit, `gitleaks git` reads exactly that, and a
# credential committed and deleted before the cut-off is absent from the
# report with nothing saying so. Measured: a depth-1 clone of a repository
# whose secret lives only in a deleted file reports zero history findings.
FULL_HISTORY = "the full git history"
SHALLOW_HISTORY = "the commits this shallow clone carries"

# The shallow clone's gap, said in the same shape as every other gap here:
# the sweep RAN, so this is not `HISTORY_GAP`, but what it could see was
# bounded by the clone rather than by the repository.
SHALLOW_GAP = ("This is a shallow clone, so the history sweep saw only the "
               "commits it carries — a credential committed before the "
               "clone's cut-off would not appear in this report.")

# Why the history pass was skipped, when git itself cannot read the history.
# Written as a whole sentence because it is used two ways: on its own when
# NEITHER pass produced a report, and inside `HISTORY_GAP`'s parentheses when
# the tree pass survived.
HISTORY_UNREADABLE = "gitleaks was not asked to read the history: {reason}"

# `gitleaks_config` extends a `.gitleaks.toml` the analysed project ships,
# which is gitleaks' own default and defensible -- that file is the project
# telling the tool what it considers noise. What is NOT defensible is
# extending it silently: a repository can write `[allowlist] regexes=['.*']`
# and turn the whole secret phase off, and the coverage note would still say
# the tree and the history were scanned. Measured on a planted tree: 2
# findings without the file, 0 with it, and the same note both times. A
# reader has to be able to tell "we found nothing" from "the repository told
# the scanner not to look".
PROJECT_CONFIG_NOTE = ("The repository's own .gitleaks.toml was extended, so "
                       "a rule or allowlist it defines may have suppressed "
                       "secrets this report would otherwise show.")

# The working tree's half of `secrets.HISTORY_GAP`, and the same shape: a
# sweep that did not run has to be said, because "found nothing" and "never
# looked" are the same silence in a report otherwise.
TREE_GAP = ("The working-tree secret scan did not complete ({reason}) — a "
            "credential sitting in a file right now may be missing from this "
            "report.")

# The one environment variable that turns the external engines off without
# uninstalling them. A parser is written against a FORMAT: when an engine's
# output stops matching what this module expects, an operator needs a way
# back to the built-in scanner that does not involve removing a binary the
# rest of the machine shares. It is also what lets the test suite pin which
# scanner runs, instead of depending on what happens to be on PATH.
ENGINES_ENV = "CC_SECURITY_ENGINES"
_OFF = {"off", "0", "no", "false", "none"}


def engine_path(name: str):
    """The engine's binary, or None when it is absent OR switched off."""
    if os.environ.get(ENGINES_ENV, "").strip().lower() in _OFF:
        return None
    return engines.find(name)


# --------------------------------------------------------------- the scope

def _glob_to_regexp(glob: str) -> str:
    """One `ignore_paths` glob as a pattern Go's RE2 will accept.

    NOT `fnmatch.translate`: it emits `(?s:...)\\Z`, and RE2 has no `\\Z` --
    gitleaks would refuse the whole config, which is a scan that does not
    run rather than a scan that ignores one glob. The semantics are
    fnmatch's, the same ones `ignores.ignored` applies, so a `*` crosses `/`
    exactly as it does there.

    Character classes are escaped rather than translated. A `[` in a path
    glob is vanishingly rare, and the failure modes are not symmetric: an
    over-escaped class excludes nothing extra, while a malformed class
    breaks the config for every other pattern in it.
    """
    return "".join(".*" if c == "*" else "." if c == "?" else re.escape(c)
                   for c in glob)


def scope_patterns(skip_dirs=None, ignore_paths=()) -> list[str]:
    """The path patterns gitleaks must not report from.

    Two sources, and they mean different things. `skip_dirs` are directories
    no analysis has ever looked inside -- caches, vendored trees, build
    output -- matched at any depth. `ignore_paths` is the operator's own
    decision, matched the way `ignores.ignored` matches it: literally, and
    with everything underneath it, so `tests/fixtures` and
    `tests/fixtures/**` both exclude the directory's contents.
    """
    if skip_dirs is None:
        skip_dirs = secrets.SKIP_DIRS
    patterns = [rf"(^|/){re.escape(d)}/" for d in sorted(skip_dirs)]
    for glob in ignore_paths or ():
        glob = (glob or "").strip()
        if not glob:
            continue
        patterns.append(f"^{_glob_to_regexp(glob)}$")
        patterns.append(f"^{_glob_to_regexp(glob.rstrip('/*'))}/.*$")
    return patterns


def project_config(root):
    """The analysed project's own `.gitleaks.toml`, or None.

    One reader for a file that is consulted twice: `gitleaks_config` extends
    it, and `gitleaks_scan` has to SAY that it did. Two separate `is_file()`
    checks would be free to disagree -- a note that names a file the config
    did not actually extend is worse than no note.
    """
    if root is None:
        return None
    own = Path(root) / ".gitleaks.toml"
    try:
        return own if own.is_file() else None
    except OSError:
        return None


def gitleaks_config(root=None, ignore_paths=(), skip_dirs=None) -> str:
    """A gitleaks TOML that keeps its rules and adds our scope.

    `--config` REPLACES the file gitleaks would otherwise have found for
    itself, including a `.gitleaks.toml` the scanned project ships. A
    project that wrote one has already told the tool what it considers
    noise, so ours extends it instead of discarding it; with no such file we
    extend the default rule set.

    Honouring the project's file is gitleaks' own default and is deliberate.
    It is also a hole a repository can drive through -- an `[allowlist]`
    matching everything silences the phase -- so `gitleaks_scan` declares
    the extension in the coverage note (`PROJECT_CONFIG_NOTE`). The decision
    stays; the silence does not.
    """
    own = project_config(root)
    lines = ["[extend]"]
    lines.append(f"path = '''{own}'''" if own is not None
                 else "useDefault = true")
    lines += ["", "[allowlist]",
              'description = "the scope claude-cron analyses: SKIP_DIRS and '
              'the project\'s ignore_paths"',
              "paths = ["]
    # An apostrophe would close the TOML literal string it sits in and break
    # the whole config -- which costs the SCAN, not the one pattern. Dropping
    # such a pattern costs only the pre-filter: `gitleaks()` applies
    # `ignores.ignored` to what comes back regardless, so the operator's globs
    # are still honoured even when they cannot be expressed to the engine.
    lines += [f"  '''{p}''',"
              for p in scope_patterns(skip_dirs, ignore_paths) if "'" not in p]
    lines.append("]")
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------- the parser

def _relative(path: str, root) -> str:
    """The engine's path as this ledger stores paths: relative to the root.

    The fingerprint contains the path, so `/tmp/run-4171/app.env` and
    `app.env` would be two identities for one secret -- and the worktree an
    analysis runs in is named after the run, so every run would mint a new
    one.
    """
    path = path.strip()
    try:
        return str(Path(path).relative_to(Path(root)))
    except (ValueError, OSError):
        pass
    return path[2:] if path.startswith("./") else path


def _finding(rule, path, lines, historical, commits):
    where = "in the git history" if historical else "in the working tree"
    rationale = (f"A credential of type {rule} was found {where}. Its value is "
                 "deliberately not recorded anywhere in this report.")
    if historical and commits > 1:
        rationale += f" Seen in {commits} commits in the history."
    return {
        "fingerprint": secret_fingerprint(rule, path),
        "category": "secret",
        "rule": rule,
        "severity": SEVERITY_BY_RULE.get(rule, DEFAULT_SEVERITY),
        "title": f"{rule.replace('-', ' ')} committed to the repository",
        "rationale": rationale,
        # secrets.py's sentence, not a second copy of it: a credential found
        # by the engine and one found by the built-in scanner are the same
        # emergency, and two wordings for it would drift.
        "remediation": secrets.REMEDIATION,
        "occurrences": [{"file": path, "line": line, "snippet_hash": ""}
                        for line in lines],
        "historical": historical,
    }


def _out_of_scope(path: str, ignore_paths) -> bool:
    """Whether a path the engine reported is one this analysis never looks at.

    The SECOND lock on the scope, and the one that does not depend on another
    program. `gitleaks_config` asks the engine not to read these paths, which
    is the cheap way round; this is the correct way round. A pattern the
    config could not carry, a gitleaks version that reads `[allowlist]`
    differently, or a rule with an allowlist of its own would each quietly
    turn `ignore_paths` back into a suggestion -- and `ignore_paths` is a
    promise about the ANALYSIS, not about one scanner's command line.
    """
    return (any(part in secrets.SKIP_DIRS for part in Path(path).parts)
            or ignored(path, ignore_paths))


def gitleaks(data, root, historical: bool = False, ignore_paths=()) -> list[dict]:
    """Gitleaks' JSON report as findings, grouped the way secrets.py groups.

    ONE finding per (rule, file), with an occurrence per hit -- never one per
    hit. The fingerprint is (rule, path) and admits no more than one finding
    per pair, so two matches of the same credential type in one file are one
    finding with two occurrences.

    Every field is CONSTRUCTED, never copied. `engines.purge` has already
    dropped `Match` and `Secret`; building the record from scratch is the
    second lock, and the one that still holds when a future gitleaks adds a
    field nobody here has heard of. It is also why the engine's `Author`,
    `Email` and `Message` -- a commit message can say anything -- never reach
    the ledger.

    A record this parser cannot read costs that record, not the phase: an
    analysis that loses one malformed finding is worth more than one that
    dies and reports no secrets at all.
    """
    if not isinstance(data, list):
        return []
    groups = {}
    for record in data:
        if not isinstance(record, dict):
            continue
        rule = str(record.get("RuleID") or "").strip()
        path = str(record.get("File") or "").strip()
        if not rule or not path:
            continue
        path = _relative(path, root)
        if _out_of_scope(path, ignore_paths):
            continue
        group = groups.setdefault((rule, path), {"lines": [], "commits": set()})
        line = record.get("StartLine")
        line = int(line) if isinstance(line, (int, float)) and not isinstance(
            line, bool) else 0
        if line not in group["lines"]:
            group["lines"].append(line)
        commit = str(record.get("Commit") or "").strip()
        if commit:
            group["commits"].add(commit)
    return [_finding(rule, path, g["lines"], historical, len(g["commits"]))
            for (rule, path), g in groups.items()]


# ------------------------------------------------------------- the whole run

# The three states a repository's history can be in, as far as any honest
# sentence about a sweep of it goes.
HISTORY_OK = "ok"          # git walked it; whatever gitleaks reports is complete
HISTORY_SHALLOW = "shallow"  # git walked what there is, and there is not all of it
HISTORY_GONE = "gone"      # git cannot walk it at all; the sweep must not run


def _git(root, *args):
    """`git -C root ...`, or None when git will not run at all."""
    try:
        return subprocess.run(["git", "-C", str(root), *args],
                              capture_output=True, text=True, errors="replace",
                              timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def history_state(root) -> tuple[str, str]:
    """(state, reason): whether the history can actually be READ here.

    Asked BEFORE the engine runs, because the engine will not say. Pointed at
    a history it cannot read, `gitleaks git` logs `fatal: ...` to stderr,
    exits 0 under `--exit-code 0`, and writes a report containing `[]` -- the
    identical answer it gives for a repository whose history is clean. That
    silence is the exact failure this project already has a scar from:
    `scan_history` used to return `[]` on error, so the one failure mode that
    hides the findings it exists to produce was reported as the best possible
    news.

    THE QUESTION IS "CAN THE HISTORY BE READ", NOT "IS THERE A .git". This
    used to run `rev-parse --git-dir`, which answers the second one -- so a
    real checkout whose objects were unreadable passed the guard, `gitleaks
    git` exited 0 with `[]`, and the coverage note went on claiming the full
    history had been scanned. Reproduced on a repository with a secret in a
    deleted file and `.git/objects` emptied: `git log` exits 128 with "fatal:
    bad object HEAD", the old guard said True, and the history finding was
    lost under a note that said it had been looked for. The same door is open
    to a broken ref, an unreadable `.git`, and git being absent altogether.

    `rev-list -n1 --all` is the question asked instead: it WALKS the refs, so
    it fails on exactly the repositories whose history cannot be read, and it
    is the cheapest walk that does -- `-n1` stops at the first commit. It also
    draws the boundary in the right place: a repository with no commits yet
    exits 0 with empty output, because an unborn history is not a gap. There
    is nothing to miss, and reporting one would be a false alarm on every
    freshly-initialised checkout.

    Shallow is its own answer, not an error. A depth-1 clone reads cleanly
    and carries one commit, so the sweep runs and the report is real -- it is
    only the word "full" that has to go (see `SHALLOW_GAP`).

    Fails CLOSED. Anything that stops git from answering is HISTORY_GONE,
    which costs a note saying the sweep did not run instead of a report that
    quietly claims it did.
    """
    walked = _git(root, "rev-list", "-n1", "--all")
    if walked is None:
        return HISTORY_GONE, "git could not be run"
    if walked.returncode != 0:
        # Only git's FIRST stderr line, the same way `secrets.scan_history`
        # quotes it: the rest is advice addressed to a human at a terminal.
        first = (walked.stderr or "").strip().splitlines()
        return HISTORY_GONE, (first[0] if first
                              else f"git exited {walked.returncode}")
    shallow = _git(root, "rev-parse", "--is-shallow-repository")
    if shallow is not None and shallow.returncode == 0 \
            and shallow.stdout.strip() == "true":
        return HISTORY_SHALLOW, ""
    return HISTORY_OK, ""


def gitleaks_scan(root, ignore_paths=()):
    """Every secret gitleaks can find in `root`, tree and history.

    Returns `(findings, notes)`. `findings` is None when NEITHER pass
    produced a report -- the caller's signal that the built-in scanner
    should do the work after all. It may only do so while the engine has
    contributed nothing: two scanners in one category report one hole under
    two fingerprints, and the checklist then shows the same secret as two
    entries that contradict each other.

    THE HISTORY IS NOT OPTIONAL. A credential that was ever committed stays
    compromised however thoroughly the file was later deleted, which is what
    this finding's remediation says and what the hand-written sweep reads
    `git log -p` for.

    THE ORDER OF THE TWO `run_json` CALLS IS THE MECHANISM, not a detail.
    The history pass runs FIRST so that a secret present in both is recorded
    by the tree pass LAST: the two readings share one fingerprint,
    `record_finding` upserts, and the tree's is the reading a human can act
    on -- it says "in the working tree" and points at the line the credential
    is on right now, where the history's points into a commit. Swap these two
    lines and every co-located secret becomes a report about the past, with
    nothing red anywhere to say so. Pinned by
    test_the_tree_reading_wins_over_its_history_twin_on_either_scanner.

    EVERY CLAIM IN `notes` IS SPELLED FROM WHAT WAS ACTUALLY DONE. The scope
    sentence is assembled from `history_state` and from which passes returned
    a report -- never from an assumption that pointing gitleaks at a checkout
    means its history was read. `gitleaks git` exits 0 and writes `[]` for a
    history it could not read, so a note built on "we ran the command" would
    be a note that cannot tell a clean repository from a broken one.
    """
    root = Path(root)
    notes = []
    state, why = history_state(root)
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "scope.toml"
        config.write_text(gitleaks_config(root=root, ignore_paths=ignore_paths))
        common = ["--config", str(config), "--report-format", "json",
                  "--report-path", "{out}", "--no-banner",
                  # A leak is not an error here: the findings are the output,
                  # and a non-zero exit would read as a failed phase.
                  "--exit-code", "0",
                  # Nothing this engine prints is read, and its info lines
                  # name the files it is scanning.
                  "--log-level", "error"]
        history, history_note = (
            (None, HISTORY_UNREADABLE.format(reason=why))
            if state == HISTORY_GONE
            else engines.run_json("gitleaks", ["git", ".", *common], root))
        tree, tree_note = engines.run_json("gitleaks", ["dir", ".", *common], root)

    if history is None and tree is None:
        # BOTH reasons, not just the tree's. They are routinely different --
        # an unreadable history and a tree pass that crashed are two separate
        # facts -- and `history_note` used to be dropped on the floor here, so
        # the one sentence that survived was about whichever pass happened to
        # be second. Deduplicated because the commonest case by far (the
        # binary is absent, or will not report a version) fails both passes
        # with the identical sentence, and saying it twice reads like two
        # faults. Not wrapped in the gap templates: nothing is missing yet --
        # `_scan_secrets` reads a None here as "the engine contributed
        # nothing" and runs the built-in scanner over both halves instead.
        notes += [n for n in dict.fromkeys((history_note, tree_note)) if n]
        return None, notes

    findings = []
    if history is None:
        # The same sentence the built-in sweep uses for the same gap, so a
        # reader is not asked to learn two vocabularies for one blind spot.
        notes.append(secrets.HISTORY_GAP.format(reason=history_note.rstrip(".")))
    else:
        findings += gitleaks(history, root, historical=True,
                             ignore_paths=ignore_paths)
        if state == HISTORY_SHALLOW:
            notes.append(SHALLOW_GAP)
    if tree is None:
        notes.append(TREE_GAP.format(reason=tree_note.rstrip(".")))
    else:
        findings += gitleaks(tree, root, historical=False,
                             ignore_paths=ignore_paths)
    # The history half of the claim is spelled from what git said, never
    # assumed: "the full git history" is a promise, and on a shallow clone it
    # is a false one.
    history_scope = (SHALLOW_HISTORY if state == HISTORY_SHALLOW
                     else FULL_HISTORY)
    scope = " and ".join(
        [s for s in ("the working tree" if tree is not None else "",
                     history_scope if history is not None else "") if s])
    notes.append(ENGINE_NOTE.format(
        version=engines.version_of("gitleaks") or "gitleaks", scope=scope))
    # Said after the scan is described, because it qualifies that description:
    # the sweep ran, and the analysed repository had a say in what it looked
    # for.
    if project_config(root) is not None:
        notes.append(PROJECT_CONFIG_NOTE)
    return findings, notes
