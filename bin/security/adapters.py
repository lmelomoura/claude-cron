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
from pathlib import Path, PurePosixPath

from . import deps, engines, ignores, osv, report, secrets, taxonomy
from .fingerprint import fingerprint, secret_fingerprint
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
    no analysis has ever looked inside -- caches, vendored trees, build output
    -- matched at any depth, and the default noise filter's fixture
    directories (`ignores.default_dirs`) join them because that is what they
    are; they drop out entirely when the project switched the default off.
    `ignore_paths` is the operator's own decision, matched the way
    `ignores.ignored` matches it: literally, and with everything underneath
    it, so `tests/fixtures` and `tests/fixtures/**` both exclude the
    directory's contents.

    THE SAMPLE SUFFIXES ARE NOT HERE ANY MORE, and their absence is the fix
    rather than an omission. A gitleaks `[allowlist] paths` entry silences
    EVERY rule for the file it matches, so `\\.example$` in this list stopped
    the engine reporting a real `openssl genrsa` key in
    `certs/server.key.example` -- the exact material the template default was
    never allowed to hide. Whether a template's finding is noise depends on
    WHICH RULE matched, which a path allowlist cannot express, so the decision
    moved wholly to `ignores.sample_suppressed` over what comes back.

    Both remaining sources are the CHEAP way round -- the engine never reads
    the file -- and neither is the guarantee. `gitleaks()` puts everything
    that comes back through the same filters again, for the reason
    `_out_of_scope` gives.
    """
    if skip_dirs is None:
        skip_dirs = secrets.SKIP_DIRS
    directories = sorted(set(skip_dirs) | set(ignores.default_dirs(ignore_paths)))
    patterns = [rf"(^|/){re.escape(d)}/" for d in directories]
    for glob in ignores.globs(ignore_paths):
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
              'description = "the scope claude-cron analyses: SKIP_DIRS, the '
              'default noise filter and the project\'s ignore_paths"',
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

    `ignores.ignored` carries the DEFAULT noise filter as well as the
    operator's globs, so this is also where a fixtures directory an
    unconfigured project never asked about stops being reported. That has to
    happen on this side of the engine and not only in the config: a default
    only the built-in scanner honoured would make the same repository report
    differently depending on which binaries the machine has installed.
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
        # The template rule is applied HERE and not inside `_out_of_scope`,
        # because `_out_of_scope` is the filter every category shares and
        # this rule belongs to the secret category alone: a CVE against
        # `package-lock.json.example` or a world-writable
        # `config.yml.template` is a true statement about a file that really
        # is in the repository.
        #
        # And it is applied PER RULE, through the same `sample_suppressed` the
        # built-in scanner reads. Gitleaks' `private-key` on a
        # `certs/server.key.example` holding a real `openssl genrsa` key is
        # not the wrong reading of a template; `generic-api-key` and
        # `aws-access-token` on the same file are. A file-level skip could not
        # tell those apart and dropped both.
        if _out_of_scope(path, ignore_paths) or ignores.sample_suppressed(
                path, rule, ignore_paths):
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
    only the word "full" that has to go (see `SHALLOW_GAP`). Asked by
    `_is_shallow`, which does not take a git too old to understand the
    question as a vote for "not shallow": the version that cannot answer
    would otherwise be the one making the strongest claim.

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
    if _is_shallow(root):
        return HISTORY_SHALLOW, ""
    return HISTORY_OK, ""


def _is_shallow(root) -> bool:
    """Whether this checkout carries only part of its history.

    ASKED TWO WAYS, because the first one is younger than the claim it
    guards. `rev-parse --is-shallow-repository` landed in git 2.15 (2017),
    and `rev-parse` ECHOES a dashed argument it does not recognise instead
    of failing: on an older git this exits 0 and prints
    `--is-shallow-repository` back. Read as "not true", that is a silent
    vote for HISTORY_OK -- and HISTORY_OK is what makes the coverage note
    say "the full git history", so the one machine that cannot answer the
    question would be the one making the strongest claim about it.

    So only a literal `true`/`false` counts as an answer. Anything else --
    the echo, a non-zero exit, git missing -- falls through to the marker
    file every shallow clone has had since the feature existed: `shallow`
    inside the git directory, which `--git-dir` locates on any version.
    Relative output (`.git`, the usual answer from the top level) is
    resolved against `root`, and a worktree or submodule whose `.git` is a
    FILE is handled too, because `--git-dir` follows it to the real
    directory rather than being told to guess.

    Fails towards SHALLOW only on evidence, never on doubt: with neither
    question answered the caller keeps HISTORY_OK, which is the pre-existing
    behaviour and not a new claim.
    """
    asked = _git(root, "rev-parse", "--is-shallow-repository")
    answer = (asked.stdout.strip()
              if asked is not None and asked.returncode == 0 else "")
    if answer in ("true", "false"):
        return answer == "true"
    located = _git(root, "rev-parse", "--git-dir")
    if located is None or located.returncode != 0:
        return False
    gitdir = located.stdout.strip()
    if not gitdir or gitdir.startswith("-"):
        return False
    marker = Path(gitdir)
    if not marker.is_absolute():
        marker = Path(root) / marker
    return (marker / "shallow").exists()


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

    THE ORDER OF THE TWO RECORDING BLOCKS IS THE MECHANISM, not a detail --
    the two `if history is None:` / `if tree is None:` blocks below, where
    each pass's report is appended to `findings`. The history is recorded
    FIRST so that a secret present in both is recorded by the tree pass LAST:
    the two readings share one fingerprint, `record_finding` upserts, and the
    tree's is the reading a human can act on -- it says "in the working tree"
    and points at the line the credential is on right now, where the
    history's points into a commit. Swap those two blocks and every
    co-located secret becomes a report about the past, with nothing red
    anywhere to say so. Pinned by
    test_the_tree_reading_wins_over_its_history_twin_on_either_scanner.

    NOT the order of the two `run_json` CALLS, which this comment used to
    name. Swapping those is a measured no-op: each writes to its own temp
    report file and neither touches `findings`, so the whole suite passes
    with them in either order. Naming the wrong pair is worse than naming
    none -- a maintainer moving the recording blocks ("report the tree first,
    it's more relevant") would read this warning, see it was about the calls,
    and make the dangerous change believing it was covered.

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


# ------------------------------------------------------- the dependency scan
#
# Trivy replaces `deps.inventory` + `osv.query` on the same terms as above:
# ONE producer per category, never both -- see `cli._scan_dependencies`,
# which is where that choice is actually made. Everything here is the
# translator, not the switch.
#
# THE IDENTITY IS OSV'S, AND SO ARE ITS INPUTS. `osv._finding` already had
# the recipe -- `fingerprint("dependency", vuln_id, source,
# f"{name}@{version}")` -- before Trivy existed in this module, and copying
# the recipe is the easy half. The hard half is that the same hash over
# DIFFERENT INPUTS is a different identity, and Trivy spells three of those
# inputs its own way. Measured, all three:
#
#   * composer.lock `symfony/http-kernel`: `deps._composer` strips the `v`
#     Packagist writes, Trivy's `InstalledVersion` keeps it -- `5.4.0` vs
#     `v5.4.0`, and `v`-prefixed is the Packagist NORM, not the exception.
#   * Go: `deps._gosum` reads `go.sum` and strips the `v`; Trivy reads
#     `go.mod`. Both the `source` and the `version` move at once.
#   * a monorepo pinning one package in two lockfiles: `deps.inventory`
#     dedupes by `(ecosystem, name, version)` ACROSS files, Trivy reports
#     once per `Target` -- one identity against two.
#
# Each of those is a finding reported `fixed` (the old identity vanished)
# AND `new` (a fresh one appeared) in one report, with the human decision on
# the old one stranded and NO WAY BACK: `ledger._REFINGERPRINT` has no
# `dependency` entry, so `rename_rule` refuses the category outright. And it
# flips per machine -- whether Trivy happens to be installed. So the inputs
# are normalised here, through `deps.normalise_version` itself rather than a
# second copy of the same rule, before anything is hashed.
#
# THE FOURTH INPUT IS `vuln_id`, AND IT IS NOT A LOST CAUSE. Trivy's headline
# `VulnerabilityID` is a CVE id where OSV.dev names the same advisory by the
# id of whichever database published it, so the two used to share nothing at
# all. This comment used to say no offline mapping between the vocabularies
# existed. IT DOES EXIST, AND IT IS IN TRIVY'S OWN RECORD -- the very example
# quoted here as proof of the gap carries it. Measured over one tree holding
# gin 1.6.3, lodash 4.17.20, certifi 2024.2.2 and symfony/http-kernel 5.4.0:
#
#   go.mod             CVE-2020-28483  VendorIDs=[GHSA-h395-qcrw-5vmq]
#   go.mod             CVE-2023-26125  VendorIDs=[GHSA-3vp4-m3rf-835h]
#   go.mod             CVE-2023-29401  VendorIDs=[GHSA-2c4m-59x9-fr2g]
#   package-lock.json  CVE-2021-23337  VendorIDs=[GHSA-35jh-r3h4-6jhm]
#   poetry.lock        CVE-2024-39689  VendorIDs=[GHSA-248v-346w-9cwc]
#   composer.lock      CVE-2022-24894  VendorIDs=None, DataSource=php-...
#
# Those GHSA ids are exactly what OSV.dev answers for the same components:
# nine of the ten findings on that tree matched on `VendorIDs` alone, and the
# tenth -- the composer one, whose PHP data source publishes no vendor id --
# carries `.../security/advisories/GHSA-h7vf-5wrv-9fhv` in `References`,
# which is precisely the id OSV.dev returned. So `_trivy_advisory_id` reads
# the alias instead of declaring the gap, and the fingerprint is built from
# it. Shared identities over that tree: 0 of 10 before, 10 of 10 after.
#
# WHAT REMAINS CANNOT BE ALIASED, and `DEP_ID_NOTE` now says THAT instead.
# OSV.dev mints one record per publishing database; Trivy mints one per hole.
# For gin 1.6.3 that is five OSV ids against three Trivy findings --
# GO-2021-0052 and GO-2023-1737 have no Trivy counterpart to alias onto --
# and certifi adds PYSEC-2024-230 beside the GHSA that does match. No
# mapping reconciles a residue that exists because one side counts
# differently from the other. Those findings are reported `pending` on the
# run the source changes -- not `fixed`: `diff._proven` asks whether the
# producer that MINTED them ran again, and it did not -- while the same hole
# arrives under the other side's id as a separate row. That is stated rather
# than hidden.

# Trivy's own severity words, mapped to ours. The default for a word Trivy
# did not send -- `UNKNOWN`, or a future grade this table has never heard of
# -- is `osv.DEFAULT_SEVERITY` itself, not a fresh "medium" typed a second
# time here: swapping which source scans a project's dependencies must not
# also change what a shared severity word means. An advisory neither source
# has assessed is a CVE nobody has graded, not one that does not matter, and
# grading it `info` would let it slip under the default `min_severity` floor
# as though it had never been found.
_TRIVY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                   "LOW": "low"}

# `FixedVersion` empty is Trivy's own way of saying nobody has published a
# fix yet -- not a gap in this parser to paper over. A CVE with nowhere to
# upgrade to is still a CVE, so the remediation SAYS that instead of pointing
# at a version that does not exist; the finding is reported either way.
_NO_FIX = ("No fixed version has been published yet for {vuln_id} in {name} "
           "{version}. Track the advisory and upgrade as soon as one ships.")
# NOT "past {fixed}". `osv._finding` says "past {version}" -- past the version
# you HAVE -- and this line was written by keeping that preposition while
# substituting the version that CONTAINS the fix, which told the reader to
# skip the only release that helps them: "Upgrade certifi past 2024.7.4",
# where 2024.7.4 IS the fix. This is the one actionable sentence in a
# dependency finding.
_FIX = "Upgrade {name} to {fixed} or later."

# Trivy's `Type` for a lockfile -> the ecosystem name `deps.inventory` gives
# the packages it reads out of the SAME file. Used for two things and nothing
# else: which version strings need `deps.normalise_version`'s handling, and
# which two records are the same component when two lockfiles pin it. Several
# Trivy types collapse onto one ecosystem on purpose -- `requirements.txt` and
# `poetry.lock` are `pip` and `poetry` to Trivy but both `PyPI` to
# `deps.inventory`, which dedupes a package pinned in both. A type absent
# here (cargo, pom, jar, ...) is one `deps.inventory` never read, so there is
# no prior identity to preserve and the version is left as Trivy spelled it.
#
# EVERY ABSENT TYPE MAPS TO ONE BUCKET, `""`, and that is the dedupe key's
# second element as well as the version rule's. Cargo, pom and jar therefore
# share a bucket: two packages of DIFFERENT unknown ecosystems with the same
# name AND the same version would collapse into one finding, attributed to
# whichever lockfile sorts first. Left as it is on purpose. A collision needs
# an identical name and an identical version across two ecosystems that
# genuinely do not share a namespace, and none was found; splitting the
# bucket by raw `Type` instead would break the case this table exists for --
# `pip` and `poetry` are two Trivy types for the one `PyPI` ecosystem
# `deps.inventory` dedupes across, and keying on the raw type would report
# that package twice. If a real collision ever turns up, the fix is a bucket
# per unmapped type (`f"trivy:{type}"`), not a return to the raw type.
_TRIVY_ECOSYSTEM = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
    "pip": "PyPI", "poetry": "PyPI", "pipenv": "PyPI", "uv": "PyPI",
    "composer": "Packagist", "composer-vendor": "Packagist",
    "gomod": "Go", "golang": "Go", "gobinary": "Go",
    "bundler": "RubyGems", "gemspec": "RubyGems",
}

# The Trivy `Type`s whose analyser was MEASURED to mark development
# dependencies, against trivy 0.74.0 with `--include-dev-deps`. For a type in
# this set, `Dev` absent on the package means `runtime`; for every other type
# -- including every type absent from `_TRIVY_ECOSYSTEM` above -- it means
# `unknown`, because Trivy reports the absence of the field identically whether
# the package ships or whether its analyser has no notion of a dev dependency
# at all.
#
# KEYED ON THE RAW `Type`, NOT ON THE ECOSYSTEM `_TRIVY_ECOSYSTEM` maps it to,
# and the split matters: `pip` and `poetry` are both `PyPI` there, and only
# `poetry` can answer this. Collapsing them first would let a requirements.txt
# finding inherit poetry's ability to say `runtime`.
#
# WHAT WAS MEASURED, one tree per type, each pinning one vulnerable runtime
# package and one vulnerable dev-only package:
#
#   npm        package-lock.json  `Dev: true` on the `"dev": true` entry.
#   yarn       yarn.lock          `Dev: true` (read from package.json beside it).
#   composer   composer.lock      `Dev: true` on the `packages-dev` entry.
#   poetry     poetry.lock        `Dev: true` from `category` or `groups`.
#
# And what was measured NOT to answer, which is why the set is not wider:
# `pip` (requirements.txt: no field, and no `PkgID` on its records either),
# `gomod` (no such concept), `bundler` (Gemfile.lock carries no group), and
# `pnpm` -- which reported no dev package at all over a hand-written
# lockfileVersion 6 file even with the flag, so whether its analyser marks
# `Dev` is UNPROVEN here and it is left out rather than guessed in. Adding a
# type to this set means running the tool over such a tree first.
_TRIVY_DEV_AWARE = frozenset({"npm", "yarn", "composer", "poetry"})

# Named so a reader of a report knows which scanner produced its dependency
# findings, the same reason `ENGINE_NOTE` exists above for secrets. Spelled
# out as "Trivy ({version})" rather than "{version}" alone: unlike
# gitleaks' own `--version` banner (which prints its own name), Trivy's
# first line is bare ("Version: 0.74.0"), so a note built the same way
# `ENGINE_NOTE` is would silently stop naming the tool -- and the bare label
# is stripped by `trivy_scan` so the sentence does not read "Trivy (Version:
# 0.74.0)".
DEP_ENGINE_NOTE = "Dependencies were scanned for known CVEs by Trivy ({version})."

# The RESIDUE the section comment above describes -- not the whole divergence
# any more, which `_trivy_advisory_id` closes wherever Trivy publishes the
# alias. Said only when this scan actually produced dependency findings (see
# `trivy_scan`): with none, there is nothing whose identity could have moved
# and this is 480 characters of coverage note about a transition that cannot
# be happening. Honest in BOTH directions on purpose: it must not go back to
# claiming the two vocabularies never meet, and it must not start claiming
# they always do.
DEP_ID_NOTE = ("Trivy names an advisory by the publishing database's own id "
               "wherever its record carries one, so a dependency finding "
               "recorded while OSV.dev was the source usually keeps its "
               "identity. Not always: OSV.dev mints one record per "
               "publishing database where Trivy mints one per hole, so an "
               "OSV.dev id with no Trivy counterpart (measured: "
               "GO-2021-0052, PYSEC-2024-230) is listed as pending — not "
               "re-checked, because the source that found it did not run "
               "here — while the same hole arrives under Trivy's own id, and "
               "any decision on the OSV.dev id does not follow onto it. An "
               "advisory with no database id of its own keeps its CVE id. "
               "That choice is made from the "
               "record Trivy holds TODAY, and Trivy refreshes its database "
               "continuously: a record that gains its first vendor id, or a "
               "second one sorting ahead of the first, is renamed by the "
               "refresh alone — the same hole is then listed as fixed and as "
               "new in one report, and a decision recorded against the old "
               "name does not follow it. Unlike a secret or a hygiene rule, "
               "a dependency finding cannot be migrated back by hand.")

# The SBOM and the findings deliberately come from two different readers, and
# a reader comparing them has to be told. `cli.cmd_prepare` builds the SBOM
# from `deps.inventory` (five lockfile formats) whatever scans for CVEs; see
# `trivy_vulns` for why reading the inventory twice is worse than this.
DEP_SBOM_NOTE = ("The SBOM lists the five lockfile formats this project's own "
                 "inventory reads, while these findings come from every "
                 "format Trivy reads, so a CVE here can name a package the "
                 "SBOM does not list.")

# Trivy's Go analyser reads `go.mod`. `deps.inventory` has only ever read
# `go.sum`, and the two are not interchangeable: a module directory with a
# `go.sum` and no `go.mod` produced Go findings before and produces NOTHING
# from Trivy. Unfixable from here -- Trivy will not read `go.sum` -- so it is
# counted and stated rather than left as a silent hole.
# The counterpart of `deps.SCOPE_NOTE`, said by whichever producer actually
# ran. Two notes rather than one shared sentence because the two producers do
# not answer the same set of formats, and a single sentence would have to be
# vague enough to be true of both -- which is how a coverage note stops being
# worth reading. Said whenever Trivy produced the dependency findings, not only
# when some of them are `dev`: "no development dependency was flagged" is a
# result a reader needs to be able to trust, and it is only trustworthy if the
# formats that could not answer are named.
DEP_SCOPE_NOTE = ("Whether a vulnerable dependency is development-only was "
                  "read from Trivy's own per-package flag, which its npm, "
                  "yarn, composer and poetry analysers set. It is reported as "
                  "unknown — never as runtime — for every other format Trivy "
                  "reads, including requirements.txt, go.mod and Gemfile.lock, "
                  "whose analysers do not mark it.")

GO_SUM_ONLY_GAP = ("{count} {directories} in this repository {have} a go.sum "
                   "but no go.mod: Trivy reads go.mod, so the Go "
                   "dependencies pinned there were NOT checked for known "
                   "CVEs.")


# GitHub's own id shape: `GHSA-` and three four-character groups. Bounded by
# lookarounds rather than `\b` because `\b` would happily match the first
# three groups of a longer hyphenated token and hand back an id that is not
# the one written down. Only this one vocabulary is extracted from prose: a
# GHSA id is unambiguous wherever it appears, where a bare `GO-2021-0052` or
# `PYSEC-2024-230` is not worth guessing at from a URL.
_GHSA_RE = re.compile(
    r"(?<![-\w])GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}(?![-\w])")


def _trivy_advisory_id(vuln) -> str:
    """The id OSV.dev would have named this advisory by, or Trivy's own
    `VulnerabilityID` when the record carries no alias to it.

    THIS IS AN IDENTITY DECISION, not a label: `vuln_id` is hashed into the
    fingerprint, so what this returns is what a human's `accepted` /
    `false_positive` decision hangs off. Three sources, in descending order
    of how much they are actually claiming:

    1. `VendorIDs` -- EXACT AND STRUCTURED. Trivy's own field for "the id the
       publishing database gave this advisory", which is precisely what
       OSV.dev names a record by. Nine of the ten findings on the tree
       measured in the section comment above matched OSV.dev on this alone.

    2. a GHSA id in `References` -- A HEURISTIC, and treated as one. It is
       prose scraped out of a URL, so it is accepted ONLY when the whole
       reference list yields exactly ONE distinct well-formed GHSA id. That
       restriction is measured, not defensive: lodash's CVE-2026-4800 lists
       `GHSA-35jh-r3h4-6jhm` FIRST and its own `GHSA-r5fr-rjxr-66jc` second,
       so "the first GHSA in References" would have aliased that finding onto
       a DIFFERENT advisory's identity. Ambiguity here is not a tie to break;
       it is a reason to fall through to 3.

    3. `VulnerabilityID` -- the CVE id, unchanged. Not a failure: an advisory
       whose publisher mints no id of its own has no OSV.dev identity to
       preserve, and the CVE is the honest name for it.

    WHY `VendorIDs` IS SORTED RATHER THAN INDEXED. It is a list, and Trivy
    documents no order for it, so `[0]` would let a database refresh that
    merely reorders the field re-identify a finding -- the exact bug this
    whole section exists to prevent. Sorting makes the choice depend on the
    SET, not on the order it arrived in. Taking one of several rather than
    refusing to alias at all is deliberate too: when Trivy folds N vendor
    advisories into one record, OSV.dev minted N findings and this producer
    mints one, so at most one of those identities can survive whatever we do.
    Preserving one beats preserving none. Every record measured so far
    carries exactly one vendor id; this is the tie-break, not the common
    path.

    AND SORTING DOES NOT MAKE THE CHOICE STABLE OVER TIME -- it makes it
    independent of ARRIVAL ORDER, which is a smaller guarantee. The answer
    still depends on the SET, and Trivy refreshes its database continuously:
    a record with no `VendorIDs` today (id = the CVE) and one tomorrow
    (id = a GHSA), or one that gains a second GHSA sorting ahead of the
    first, is re-identified by the refresh alone. `rename_rule` refuses
    `dependency` (see `ledger._REFINGERPRINT`), so there is no way back --
    the finding is reported fixed and new in one report and its decision
    strands. Unfixable from here, exactly as `GO_SUM_ONLY_GAP` is, so it is
    STATED instead: `DEP_ID_NOTE` now carries the clause. The `iac` section
    documents the same exposure for Trivy's check ids.
    """
    if not isinstance(vuln, dict):
        return ""
    vendor = vuln.get("VendorIDs")
    if isinstance(vendor, list):
        ids = sorted({v.strip() for v in vendor
                      if isinstance(v, str) and v.strip()})
        if ids:
            return ids[0]
    references = vuln.get("References")
    if isinstance(references, list):
        found = set()
        for reference in references:
            if isinstance(reference, str):
                found.update(_GHSA_RE.findall(reference))
        if len(found) == 1:
            return found.pop()
    return str(vuln.get("VulnerabilityID") or "").strip()


def _trivy_component(vuln, ecosystem: str):
    """`(name, version)` spelled the way `deps.inventory` would have spelled
    them for the same package, or None when the record names no package this
    parser can identify.

    The version goes through `deps.normalise_version` -- the function the
    lockfile readers themselves call, not a second copy of its rule -- so the
    two producers cannot drift apart again by one of them being edited.
    """
    if not isinstance(vuln, dict):
        return None
    name = str(vuln.get("PkgName") or "").strip()
    version = deps.normalise_version(
        ecosystem, str(vuln.get("InstalledVersion") or "").strip())
    return (name, version) if name and version else None


def _trivy_scope(result, root):
    """`(source, ecosystem)` for one `Results[]` entry.

    `source` is an INPUT TO THE FINGERPRINT, so which file this project calls
    a Go module's lockfile is an identity decision, not a label. THE CHOICE,
    MADE HERE: `go.sum`, whenever one sits beside the `go.mod` Trivy
    reported. `deps.inventory` has only ever read `go.sum`, so anchoring on
    `go.mod` would re-identify every Go finding already in a ledger. The
    probe is real rather than assumed -- a `go.mod` with no `go.sum` beside
    it keeps Trivy's own target, because naming a file that is not there in
    an occurrence sends a human to a path that does not exist. It is also the
    only case where the two producers could not have collided anyway: with no
    `go.sum`, `deps.inventory` read no Go packages at all.
    """
    source = str(result.get("Target") or "").strip()
    ecosystem = _TRIVY_ECOSYSTEM.get(
        str(result.get("Type") or "").strip().lower(), "")
    if ecosystem == "Go" and PurePosixPath(source).name == "go.mod":
        sibling = PurePosixPath(source).with_name("go.sum")
        try:
            if root is not None and (Path(root) / str(sibling)).is_file():
                source = str(sibling)
        except OSError:
            pass
    return source, ecosystem


def _go_sum_without_go_mod(root, ignore_paths=()) -> int:
    """How many in-scope directories hold a `go.sum` with no `go.mod` beside
    it -- the Go packages Trivy cannot see at all. See `GO_SUM_ONLY_GAP`."""
    try:
        paths = sorted(Path(root).rglob("go.sum"))
    except OSError:
        return 0
    count = 0
    for path in paths:
        try:
            rel = str(path.relative_to(Path(root)))
        except ValueError:
            continue
        if _out_of_scope(rel, ignore_paths):
            continue
        try:
            if not (path.parent / "go.mod").is_file():
                count += 1
        except OSError:
            continue
    return count


def _trivy_severity(record) -> str:
    """Trivy's own `Severity` word, mapped to ours -- shared by a
    vulnerability record and a misconfiguration record alike (`_trivy_
    finding` below and `_iac_finding` in the IaC section further down), so
    the two categories cannot grade the same word differently by one of them
    drifting from a copy of this table."""
    return _TRIVY_SEVERITY.get(str(record.get("Severity") or "").upper(),
                               osv.DEFAULT_SEVERITY)


def _trivy_dev_scope(result) -> dict:
    """`{(ecosystem, name, version): scope}` for ONE `Results[]` entry.

    THE MARKER IS NOT ON THE VULNERABILITY. Measured over trivy 0.74.0: a
    `Vulnerabilities[]` record carries 21 fields and none of them is `Dev` --
    the flag lives on `Results[].Packages[]`, so the scope of a CVE is only
    reachable by joining back to the package that carries it. The join key here
    is the component tuple rather than `PkgID`/`PkgIdentifier.UID`, on purpose:
    it is the SAME key `trivy_vulns` already dedupes on and the same one
    `deps.inventory` builds, `PkgID` is absent entirely on pip records
    (measured), and a second key would be a second thing to keep in agreement.

    `Version` is normalised through `deps.normalise_version`, the function the
    lockfile readers themselves call, for the reason `_trivy_component` gives:
    a `Packages[]` entry spelling a Go module `v1.6.3` where the vulnerability
    record's component key says `1.6.3` would simply never join, and the
    finding would silently read `unknown`.
    """
    dev_aware = str(result.get("Type") or "").strip().lower() in _TRIVY_DEV_AWARE
    ecosystem = _TRIVY_ECOSYSTEM.get(
        str(result.get("Type") or "").strip().lower(), "")
    packages = result.get("Packages")
    if not isinstance(packages, list):
        return {}
    out = {}
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("Name") or "").strip()
        version = deps.normalise_version(
            ecosystem, str(pkg.get("Version") or "").strip())
        if not name or not version:
            continue
        if not dev_aware:
            scope = deps.SCOPE_UNKNOWN
        else:
            # `is True`, not truthiness. Trivy omits the key entirely for a
            # package that ships, and writes `true` for one that does not;
            # anything else arriving in that slot is not a claim this code
            # should read as either answer.
            scope = (deps.SCOPE_DEV if pkg.get("Dev") is True
                     else deps.SCOPE_RUNTIME)
        key = (ecosystem, name, version)
        out[key] = deps.merge_scope(out[key], scope) if key in out else scope
    return out


def _trivy_finding(source: str, vuln, ecosystem: str = "",
                   scope: str = deps.SCOPE_UNKNOWN):
    component = _trivy_component(vuln, ecosystem)
    # OSV.dev's name for this advisory when Trivy's record carries it, the
    # CVE id otherwise -- see `_trivy_advisory_id`. It replaces the CVE
    # EVERYWHERE the id appears, not just inside the hash: `rule` is what
    # `fingerprint()` is fed, so a finding whose rule and fingerprint were
    # built from two different ids could not be re-derived from its own
    # fields, and the two producers would agree on the hash while disagreeing
    # on the row a human reads.
    vuln_id = _trivy_advisory_id(vuln)
    cve = (str(vuln.get("VulnerabilityID") or "").strip()
           if isinstance(vuln, dict) else "")
    if component is None or not vuln_id:
        # No id, no package name, no installed version: this parser cannot
        # build an identity for any of the three. Costs this one record, not
        # the phase -- see `trivy_vulns`.
        return None
    name, version = component
    severity = _trivy_severity(vuln)
    fixed = str(vuln.get("FixedVersion") or "").strip()
    remediation = (_FIX.format(name=name, fixed=fixed) if fixed
                   else _NO_FIX.format(vuln_id=vuln_id, name=name,
                                       version=version))
    url = str(vuln.get("PrimaryURL") or "").strip()
    if url:
        remediation += f" See {url}"
    # The same precedence `osv._finding` reads `summary` and `details` with:
    # a short one-line description first (`Title`, Trivy's equivalent of
    # OSV's `summary`), a truncated long one second (`Description`, Trivy's
    # `details`), and the bare id only if neither is present.
    rationale = (str(vuln.get("Title") or "").strip()
                 or str(vuln.get("Description") or "").strip()[:200]
                 or vuln_id)
    if cve and cve != vuln_id:
        # The CVE is not part of the identity any more, and it must not
        # simply vanish from the report: it is the id a human searches for,
        # and dropping it to gain the fingerprint parity above would be a
        # regression traded for a fix. `rationale` is not a fingerprint
        # input, so saying it here costs nothing an identity depends on.
        rationale += f" (Trivy matched this advisory as {cve}.)"
    finding = {
        "fingerprint": fingerprint("dependency", vuln_id, source,
                                   f"{name}@{version}"),
        "category": "dependency",
        "rule": vuln_id,
        "severity": severity,
        "title": f"{name} {version}: {vuln_id}",
        "rationale": rationale,
        "remediation": remediation,
        # Joined from `Results[].Packages[]` by the caller -- see
        # `_trivy_dev_scope`. Normalised through the shared `merge_scope` so
        # that a value this parser did not produce cannot reach the ledger,
        # and so that "no answer" lands on `unknown` rather than `runtime`.
        "scope": deps.merge_scope(scope),
        "occurrences": [{"file": source, "line": 0, "snippet_hash": ""}],
    }
    # The dependency category has no closed vocabulary -- its rule is the
    # CVE id -- so `CweIDs` is metadata to carry when Trivy sent it, not
    # something to validate the way `taxonomy.py` does for SAST rules. Left
    # unset (never an empty string) when Trivy sent nothing to classify.
    cwe_ids = vuln.get("CweIDs")
    if isinstance(cwe_ids, list):
        cwe = ", ".join(c for c in cwe_ids if isinstance(c, str) and c)
        if cwe:
            finding["cwe"] = cwe
    return finding


def trivy_vulns(data, root=None) -> list[dict]:
    """Trivy's `fs` report as dependency findings, one per (CVE, package).

    Reads `Results[].Vulnerabilities[]` only. `Results[].Packages[]` -- the
    full inventory Trivy also reports for a lockfile it recognises -- is not
    read here: the SBOM this project hands out is still built from
    `deps.inventory` (see `cli.cmd_prepare`), and reading the inventory
    twice, from two sources, would give the two paths two chances to
    disagree about what this repository depends on. `DEP_SBOM_NOTE` states
    the consequence rather than hiding it.

    Every field is CONSTRUCTED, never copied -- the same reason `gitleaks`
    above gives: a future Trivy release adding a field nobody here has read
    must not be able to ride into the ledger unexamined.

    A record this parser cannot use (no id, no package name, no installed
    version -- see `_trivy_finding`) costs that record, not the phase: one
    malformed entry must not cost every dependency finding in the report.

    `root` is what lets `_trivy_scope` tell a Go module with a `go.sum` from
    one without; `trivy_scan` always passes it, and a caller that parses a
    report detached from its tree gets Trivy's own `go.mod` target.

    THE SORT AND THE DEDUPE ARE ABOUT IDENTITY, not tidiness: targets are
    visited in sorted order, and a component already reported from an earlier
    lockfile is not reported again from a later one.
    `deps.inventory` walks `sorted(root.rglob("*"))` and dedupes by
    `(ecosystem, name, version)` ACROSS files, so a monorepo pinning lodash
    in two lockfiles yields ONE finding from that producer, attributed to the
    first file. Reporting it once per `Target` here would be two identities
    against that one.
    """
    if not isinstance(data, dict):
        return []
    results = data.get("Results")
    if not isinstance(results, list):
        return []
    ordered = sorted((r for r in results if isinstance(r, dict)),
                     key=lambda r: str(r.get("Target") or ""))

    # SCOPE IS RESOLVED ACROSS EVERY TARGET BEFORE ANY FINDING IS BUILT, which
    # is what makes it agree with `deps.inventory` over a monorepo. The dedupe
    # below keeps the FIRST lockfile that pinned a component and drops the
    # rest, so a package that is a dev dependency in the first lockfile and a
    # runtime one in the second would read `dev` if scope were read only from
    # the owning target. `deps.inventory` merges the scope of every duplicate
    # it drops for exactly this reason; two passes here is the same rule, and
    # `merge_scope` is literally the same function.
    scope_by_component = {}
    for result in ordered:
        for key, scope in _trivy_dev_scope(result).items():
            scope_by_component[key] = (
                deps.merge_scope(scope_by_component[key], scope)
                if key in scope_by_component else scope)

    out, owner = [], {}
    for result in ordered:
        source, ecosystem = _trivy_scope(result, root)
        vulns = result.get("Vulnerabilities")
        if not source or not isinstance(vulns, list):
            # No `Vulnerabilities` key at all is the shape a lockfile with
            # nothing wrong in it actually produces (Trivy still lists it
            # under `Packages`) -- not a malformed record.
            continue
        for vuln in vulns:
            component = _trivy_component(vuln, ecosystem)
            scope = deps.SCOPE_UNKNOWN
            if component is not None:
                first = owner.setdefault((ecosystem, *component), source)
                if first != source:
                    continue  # a later lockfile pinning what this one already did
                # A vulnerability whose package is not in `Packages[]` at all
                # leaves `unknown` standing: nothing said this one ships.
                scope = scope_by_component.get((ecosystem, *component),
                                               deps.SCOPE_UNKNOWN)
            finding = _trivy_finding(source, vuln, ecosystem, scope)
            if finding is not None:
                out.append(finding)
    return out


def trivy_skip_dirs(ignore_paths=()) -> list[str]:
    """The `--skip-dirs` values for a scan of this project's scope.

    EVERY SKIP_DIR TWICE, bare and as `**/name`, because bare names match the
    TOP LEVEL ONLY. Measured against `deps.inventory`, which skips them at
    ANY depth:

        src/vendor/thing/package-lock.json   deps: []   trivy: reported
        a/b/dist/package-lock.json           deps: []   trivy: reported

    -- which is the swap making the report NOISIER, the regression this
    module's docstring warns about for Gitleaks. `**/name` alone covers the
    top level in Trivy 0.74's matcher; the bare name is kept beside it so a
    matcher that ever stops doing so does not reopen the hole silently.

    The default noise filter's fixture directories go down the same way and
    for the same reason -- they are directory names matched at any depth, not
    globs -- and they disappear from the list entirely when the project
    switched the default off, so a decision the operator took is not undone
    by a command line.

    `ignore_paths` is passed down too, the cheap way round -- the files are
    then never read at all. It is not the guarantee: `trivy_scan` filters
    what comes back through `_out_of_scope` as well, for the reason that
    function's own docstring gives.
    """
    out = []
    for name in sorted(set(secrets.SKIP_DIRS)
                       | set(ignores.default_dirs(ignore_paths))):
        out += [name, f"**/{name}"]
    for glob in ignores.globs(ignore_paths):
        glob = (glob or "").strip().rstrip("/*")
        # A comma is the separator Trivy splits this list on, so a glob
        # containing one cannot be expressed here. It is dropped from the
        # command line only -- the post-filter still honours it.
        if glob and "," not in glob:
            out.append(glob)
    return out


def trivy_scan(root, ignore_paths=()):
    """Every dependency vulnerability Trivy's filesystem scanner finds in
    `root`, within the scope this analysis actually looks at.

    Returns `(findings, notes)`. `findings` is None when Trivy produced no
    report at all -- absent, unversioned, timed out, or writing a format
    this parser cannot read -- which is `cli._scan_dependencies`'s signal to
    fall back to `deps.inventory` + `osv.query`. It may only do so while
    Trivy has contributed nothing: see `trivy_vulns` for why the two must
    never both produce findings for the same repository. An empty `Results`
    section is a real, completed report -- `findings` is `[]`, not `None`,
    and no fallback follows it.

    `--scanners vuln` keeps Trivy's own secret and misconfiguration scanners
    off: this project already has an engine for secrets (`gitleaks_scan`
    above), and this call exists only to replace the dependency category's
    fallback pair, not to add a second producer for a different one.

    THE SCOPE IS LOCKED TWICE, exactly as it is for Gitleaks above.
    `trivy_skip_dirs` asks the engine not to read these paths, which is the
    cheap way round; `_out_of_scope` over what comes back is the correct way
    round. Trivy reads formats `deps.inventory` never opened -- yarn.lock,
    pnpm, Gemfile.lock, Cargo.lock, pom.xml, vendored jars -- so the class of
    finding an operator's `ignore_paths` has to be able to suppress got
    materially larger with this swap, and a promise about the ANALYSIS that
    holds only while another program accepted our command line is not a
    promise.
    """
    # `--include-dev-deps` IS NOT A FLAG FOR THE `scope` COLUMN, it is what
    # makes this producer's coverage comparable with the one it replaces.
    # Measured on trivy 0.74.0: WITHOUT it, a development dependency is not in
    # the report at all -- a package-lock.json pinning a vulnerable lodash and
    # a vulnerable dev-only minimist yielded five findings and no mention of
    # minimist, and composer.lock and poetry.lock behave the same way.
    # `deps.inventory` has ALWAYS read development dependencies (`_composer`
    # merged `packages-dev` from the day it was written), so leaving the flag
    # off meant a repository reported one set of dependency findings on a
    # machine with Trivy and a larger set on a machine without -- the
    # per-machine divergence `_scan_dependencies` spends a page arguing
    # against. A dev-only CVE is not noise to be dropped; it is a finding to be
    # ranked, which is what `scope` is for.
    #
    # The flag reached Trivy in 0.50.0. An older binary rejects it, exits
    # non-zero without writing a report, and `engines.run_json` turns that into
    # (None, note) -- so the dependency phase falls back to OSV.dev and SAYS it
    # did, which is the same declared degradation any unreadable report
    # already produces. It does not fail silently.
    args = ["fs", ".", "--format", "json", "--output", "{out}",
            "--scanners", "vuln", "--quiet", "--include-dev-deps",
            "--skip-dirs", ",".join(trivy_skip_dirs(ignore_paths))]
    data, note = engines.run_json("trivy", args, root)
    if data is None:
        return None, [note] if note else []
    findings = [f for f in trivy_vulns(data, root)
                if not _out_of_scope(f["occurrences"][0]["file"], ignore_paths)]
    # `removeprefix`, because Trivy's first `--version` line is the bare
    # "Version: 0.74.0" -- without it the note reads "by Trivy (Version:
    # 0.74.0)", with the label said twice.
    version = (engines.version_of("trivy") or "trivy").removeprefix("Version: ")
    notes = [DEP_ENGINE_NOTE.format(version=version)]
    if findings:
        # ONLY WHEN THERE IS SOMETHING TO TRANSITION. `DEP_ID_NOTE` describes
        # what happens to a dependency finding whose identity was minted
        # while OSV.dev was the source; with no dependency findings in this
        # report there is no such finding to describe, and the note is 480
        # characters a reader has to get past to reach the gaps that ARE
        # real. Kept as a property of the report rather than of the machine:
        # a repository that grows its first CVE gets the note back the same
        # run.
        notes.append(DEP_ID_NOTE)
        # Beside `DEP_ID_NOTE` and gated the same way: with no dependency
        # finding in the report there is no `scope` on anything, and a
        # paragraph explaining a column nobody can see is a paragraph between
        # the reader and the gaps that are real.
        notes.append(DEP_SCOPE_NOTE)
    notes.append(DEP_SBOM_NOTE)
    go_only = _go_sum_without_go_mod(root, ignore_paths)
    if go_only:
        notes.append(GO_SUM_ONLY_GAP.format(
            count=go_only,
            directories="directory" if go_only == 1 else "directories",
            have="has" if go_only == 1 else "have"))
    return findings, notes


# --------------------------------------------- the IaC misconfiguration scan
#
# `iac`, the first finding category this module has added since it was
# built. Trivy's misconfiguration scanner reads Dockerfiles, Terraform,
# Kubernetes manifests, Helm charts and CloudFormation templates for
# known-bad patterns -- nothing in this project has ever scanned for this,
# so there is no built-in fallback the way `osv.query` is for `trivy_vulns`:
# `trivy_iac_scan` returning `None` costs the whole phase, not a producer
# swap. See `cli._scan_iac`.
#
# THE REPORT SHAPE IS `trivy_vulns`'s OWN SIBLING. Trivy's `fs` report nests
# both categories under the identical `Results[]` array -- `Vulnerabilities`
# for a lockfile, `Misconfigurations` for a Dockerfile or a manifest -- so
# `trivy_misconfigs` reads it the way `trivy_vulns` reads its own half: one
# record costs itself, not the phase, and `engines.PURGE["trivy"]` already
# strips `Content`/`Highlighted` at any depth -- which is exactly where they
# sit here too, one level further down under `Misconfigurations[].
# CauseMetadata.Code.Lines[]` rather than under a secret's own `Match`
# (measured; see `test_purge_strips_the_source_lines_from_a_trivy_
# misconfiguration` in test_engines.py, which predates this task and needed
# no change for it).
#
# A SEPARATE INVOCATION, not a second read of the JSON `trivy_scan` fetches
# for dependencies. `trivy_scan` returns `(findings, notes)`, a shape
# `cli._scan_dependencies` and every test in the section above already
# depends on; folding a second category's findings into that return would
# touch every one of them for a category with nothing to do with
# dependencies. `trivy_iac_scan` asks for `--scanners misconfig` alone, so
# the extra process this costs on a machine with Trivy installed does not
# also re-walk the dependency graph a second time.
#
# ONE FINDING PER (CHECK, FILE), MEASURED RATHER THAN ASSUMED -- exactly
# `gitleaks()`'s and `semgrep_findings()`'s own grouping, and NOT `trivy_
# vulns`'s. A Terraform module or a Kubernetes manifest routinely defines
# several resources in one file, and Trivy evaluates each one against every
# check: two Pods in one manifest both missing a security control produced
# TWO `Misconfigurations[]` ENTRIES under the identical `ID` and the
# identical `Target`, one per resource, each with its own `CauseMetadata.
# StartLine` (measured against a planted two-Pod manifest: `KSV-0001` twice,
# at lines 7 and 17). There is no separate per-resource identity to preserve
# the way `trivy_vulns` preserves one per (package, version) -- only per
# (check, file) -- so `trivy_misconfigs` groups on exactly that pair and
# folds every `StartLine` into one finding's occurrences.
#
# THE IDENTITY IS CHOSEN FROM SCRATCH. There is no prior `iac` finding
# anywhere to match, unlike the Trivy dependency swap above, which had to
# reproduce an identity `osv._finding` already minted. `(check id, file)` is
# the whole of it -- the same shape `hygiene._finding` uses and for the
# identical reason: stable across runs (a check id does not move when the
# code does) and across machines (it is Trivy's own vocabulary, not a path
# this machine happened to invoke the scan from), and never built from a
# StartLine or a per-instance `Message` naming one specific resource, either
# of which would mint a fresh identity the moment an unrelated resource was
# added above it in the file. Unlike `sast`'s check-id-as-fourth-argument
# (this module's SAST section, above), which stands in for a code snippet
# the ledger can never store, `iac`'s identity does not need a code snippet
# at all -- a misconfiguration is a property of the FILE, not of a matched
# line -- so nothing is lost by making it fully derivable from (rule, path)
# alone. THAT DERIVABILITY DOES NOT EARN IT A `ledger._REFINGERPRINT` ENTRY,
# though, and deliberately: unlike hygiene's four rule names, which are OUR
# OWN literals, a check id here is Trivy's own vocabulary, verbatim -- the
# identical relationship `dependency`'s GHSA/CVE id already has to that
# table. See `_REFINGERPRINT`'s own comment for why "can the fingerprint be
# rebuilt" is necessary but not sufficient on its own.

IAC_ENGINE_NOTE = ("Infrastructure-as-code misconfigurations (Dockerfile, "
                   "Kubernetes, Terraform, CloudFormation and Helm) were "
                   "scanned by Trivy ({version}).")

# The gap, in the same shape as `SAST_GAP`: unlike the secret and dependency
# categories, `iac` has no built-in scanner to fall back to, so a Trivy this
# analysis could not use costs the WHOLE phase -- and that has to be said,
# the same reason every other gap in this module is. "found nothing" and
# "never looked" must not be the same silence in a report.
IAC_GAP = ("The infrastructure-as-code misconfiguration scan did not run "
           "({reason}) -- there is no built-in scanner for this category, so "
           "a Dockerfile, Terraform module, Kubernetes manifest, Helm chart "
           "or CloudFormation template committed to this repository was not "
           "checked at all this run.")


def _misconfig_line(record) -> int:
    cause = record.get("CauseMetadata")
    line = cause.get("StartLine") if isinstance(cause, dict) else None
    if isinstance(line, bool) or not isinstance(line, (int, float)):
        return 0
    return int(line)


def _iac_finding(check_id: str, target: str, record, lines) -> dict:
    # `Title`/`Description`/`Resolution`/`Severity`/`PrimaryURL` are
    # properties of the CHECK, not of the resource it fired on -- every
    # `Misconfigurations[]` entry this finding groups agrees on them (they
    # come from the same Rego policy), so reading them off one representative
    # record is not the tie-break `semgrep_findings`' severity pick is: there
    # is nothing here for two occurrences of one check to disagree about.
    severity = _trivy_severity(record)
    title = str(record.get("Title") or "").strip() or check_id
    description = str(record.get("Description") or "").strip()
    rationale = description[:200] if description else title
    resolution = str(record.get("Resolution") or "").strip()
    remediation = resolution or f"Review {check_id} and fix it in {target}."
    url = str(record.get("PrimaryURL") or "").strip()
    if url:
        remediation += f" See {url}"
    return {
        # Identity is (check id, file) alone -- see the section comment
        # above, and `ledger._REFINGERPRINT`'s own comment for why this
        # recipe, though it is exactly `hygiene._finding`'s shape, still does
        # not make the category renameable. The fourth argument is the check
        # id again, the same constant-not-content choice `hygiene._finding`
        # makes and for the identical reason: nothing here may shift with
        # wording, formatting, or which resource in the file happened to be
        # scanned first.
        "fingerprint": fingerprint("iac", check_id, target, check_id),
        "category": "iac",
        "rule": check_id,
        "severity": severity,
        "title": f"{target}: {title}",
        "rationale": rationale,
        "remediation": remediation,
        "occurrences": [{"file": target, "line": line, "snippet_hash": ""}
                        for line in sorted(lines)],
    }


def trivy_misconfigs(data) -> list[dict]:
    """Trivy's `fs` report as `iac` findings, one per (check id, file).

    Reads `Results[].Misconfigurations[]` only -- `trivy_vulns`'s own
    sibling, reading the other key a `Results[]` entry can carry. A `Target`
    with no `Misconfigurations` key at all is the shape a file with nothing
    wrong in it actually produces (Trivy still lists it, under
    `MisconfSummary` alone -- measured against a clean Terraform module: the
    entry for `Target: "."` carries `MisconfSummary: {Successes: 53,
    Failures: 0}` and no `Misconfigurations` key whatsoever), not a
    malformed record -- exactly `test_a_result_with_no_vulnerabilities_is_
    not_an_error`'s own shape on the dependency side.

    `Status` is checked for `"FAIL"` defensively: this project never passes
    `--include-non-failures`, so nothing measured has ever produced anything
    else in this array, and the check costs nothing against the day someone
    adds that flag.

    NO `root` PARAMETER, unlike `trivy_vulns`. That function takes one to
    resolve a Go module's `go.sum` sibling -- a dependency-only ambiguity
    with nothing to match here: a misconfiguration's `Target` is already the
    file Trivy fired on, exactly as reported, with no second producer's own
    name for the same file to reconcile against.

    Every field is CONSTRUCTED, never copied, for the reason `trivy_vulns`'s
    own docstring gives: a future Trivy release must not be able to put a
    field nobody here has read into the ledger unexamined.

    A record this parser cannot use (no `ID`, no `Target`) costs that record,
    not the phase.
    """
    if not isinstance(data, dict):
        return []
    results = data.get("Results")
    if not isinstance(results, list):
        return []
    groups = {}
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "").strip()
        misconfigs = result.get("Misconfigurations")
        if not target or not isinstance(misconfigs, list):
            continue
        for record in misconfigs:
            if not isinstance(record, dict):
                continue
            if str(record.get("Status") or "").upper() != "FAIL":
                continue
            check_id = str(record.get("ID") or "").strip()
            if not check_id:
                continue
            key = (check_id, target)
            group = groups.setdefault(key, {"record": record, "lines": set()})
            group["lines"].add(_misconfig_line(record))
    return [_iac_finding(check_id, target, group["record"], group["lines"])
            for (check_id, target), group in groups.items()]


def trivy_iac_scan(root, ignore_paths=()):
    """Every infrastructure-as-code misconfiguration Trivy's filesystem
    scanner finds in `root`, within the scope this analysis actually looks
    at.

    Returns `(findings, notes)`. `findings` is `None` when Trivy produced no
    report at all -- absent, unversioned, timed out, or writing a format
    this parser cannot read -- and unlike `trivy_scan`'s and `gitleaks_
    scan`'s own `None`, there is nothing for `cli._scan_iac` to fall back to:
    `iac` has no built-in scanner, so `None` costs the whole phase. An empty
    `Results` section (or one with nothing but `MisconfSummary` in it) is a
    real, completed report -- `findings` is `[]`, never `None`.

    `--scanners misconfig` ALONE, not `vuln,misconfig`: see the section
    comment above for why this is a separate invocation from `trivy_scan`
    rather than a second read of its report.

    THE SCOPE IS LOCKED TWICE, exactly as `trivy_scan` locks it for
    dependencies: `trivy_skip_dirs` -- reused, not reimplemented, since the
    scope this analysis honours does not change by category -- asks the
    engine not to read these paths, and `_out_of_scope` over what comes back
    is the correct way round.
    """
    args = ["fs", ".", "--format", "json", "--output", "{out}",
            "--scanners", "misconfig", "--quiet",
            "--skip-dirs", ",".join(trivy_skip_dirs(ignore_paths))]
    data, note = engines.run_json("trivy", args, root)
    if data is None:
        return None, [note] if note else []
    findings = [f for f in trivy_misconfigs(data)
                if not _out_of_scope(f["occurrences"][0]["file"], ignore_paths)]
    version = (engines.version_of("trivy") or "trivy").removeprefix("Version: ")
    return findings, [IAC_ENGINE_NOTE.format(version=version)]


# ------------------------------------------------------------------ the SBOM
#
# Syft replaces `deps.inventory` + `deps.sbom` on the same terms Trivy
# replaces `deps.inventory` + `osv.query` above: ONE producer, never both --
# see `cli._scan_sbom`, which is where that choice is made. Syft emits
# CycloneDX directly (`-o cyclonedx-json`), the exact format `deps.sbom`
# builds by hand, so this adapter really is mostly a passthrough: there is no
# per-field reconstruction the way `gitleaks()` and `trivy_vulns()` do it.
# `THE VALUE NEVER ARRIVES`, this module's opening claim for the other two
# categories, does not need defending here either: an SBOM is not
# fingerprinted (`ledger.store_sbom` keeps only a branch's most recent
# document, never a per-component identity a human accepts or dismisses), and
# a component's own name, version and licence ARE the report -- not
# something an engine matched inside a file that this adapter must keep out.
#
# ONE THING IS DROPPED, AND IT IS MEASURED, NOT GUESSED AT. Syft's directory
# scan reports each recognised lockfile TWICE: once as the `type: "library"`
# component an SBOM actually means (name, version, purl, a root-relative
# `syft:location:*:path`), and once more as a `type: "file"` component that
# carries nothing but a SHA digest and -- unlike every other path in the same
# document -- the scan root's OWN ABSOLUTE PATH with the relative part
# appended. Captured verbatim in this module's fixture:
# `/Users/lfmoura/Projects/claude-cron/tests/security/fixtures/composer.lock`,
# not `/tests/security/fixtures/composer.lock` the way the library entry for
# the SAME file names it, two entries later in the identical array. Stored
# and handed out through the same download route as every other SBOM in this
# ledger, that field would put the operator's home directory and username
# into a document meant for whoever asked for this project's dependency list
# -- and it carries no `version` at all, which is what a reader assuming
# every SBOM component names one (this module's own tests included) would
# trip on the moment Syft is what built the document. `syft_document` drops
# every `type: "file"` entry for exactly this reason; nothing else is
# touched.
#
# WHY THIS DOES NOT HONOUR `ignore_paths`. `deps.inventory` -- the producer
# this one replaces -- never has: it walks the whole tree bar its own
# `_SKIP_DIRS` and was never given the operator's `ignore_paths` to filter
# by, because an SBOM is a different promise than a findings list.
# `gitleaks_scan` and `trivy_scan` apply `ignore_paths` because it is a
# promise about what THIS ANALYSIS reports as WRONG with the project -- noise
# an operator has decided not to see in a findings list. A software bill of
# materials is a promise about what the project actually SHIPS, and a
# dependency does not stop shipping because an operator finds it noisy to
# read about there; filtering it out of the SBOM on the same grounds would
# make the inventory describe a project that does not exist. Keeping Syft on
# `deps.inventory`'s own terms here means the two producers cannot disagree
# about scope depending on which one happens to be installed -- only the
# `secrets.SKIP_DIRS`-equivalent noise below is excluded on either path,
# exactly as it always was.

SYFT_ENGINE_NOTE = "The SBOM was produced by {version}."

# Said whenever Syft's document -- not `deps.sbom` -- is what got stored, so
# a reader knows the SBOM's coverage changed along with its producer.
# `cli.cmd_prepare` is also what this note lets `adapters.DEP_SBOM_NOTE`
# (Task 3's note, said whenever Trivy runs) stop being true the moment it
# appears: that one claims the SBOM lists the five lockfile formats
# `deps.inventory` reads, which only holds while `deps.sbom` built it. See
# `cli.cmd_prepare` for how the two notes are kept from contradicting each
# other.
SYFT_SBOM_NOTE = ("This SBOM was produced by Syft, which reads far more "
                  "ecosystems than either dependency-CVE source this "
                  "analysis can run: a component it lists may not have been "
                  "checked for known vulnerabilities at all.")

# Syft's own CycloneDX writer omits `components` ENTIRELY for a checkout
# where its catalogers recognised nothing -- not an empty list. Measured
# against an empty directory: the key is simply absent from the document.
# `syft_document` treats that the same as a report this parser cannot read,
# because `cli._scan_sbom` needs the difference between "malformed" and
# "genuinely nothing to list" to collapse: `deps.sbom` is a complete, honest
# answer for a project with nothing Syft's catalogers recognise, and it must
# not be shadowed by a report this adapter cannot even confirm the shape of.
SYFT_NO_COMPONENTS_NOTE = ("Syft wrote a document naming no `components`, "
                           "so it was not used.")


def syft_document(data):
    """Syft's own CycloneDX document, its file-digest noise dropped, or None
    when it is not a document this adapter can use.

    MOSTLY A PASSTHROUGH, deliberately: Syft already emits the format
    `deps.sbom` builds by hand, so there is no field-by-field translation to
    do the way `gitleaks()` and `trivy_vulns()` do it. The two checks that
    matter: `components` present and a list (see `SYFT_NO_COMPONENTS_NOTE`
    for why its absence is not "zero dependencies"), and every `type:
    "file"` entry removed (see the section comment above for the leak that
    closes).

    A NON-DICT ENTRY IN `components` COSTS THAT ENTRY, NOT THE DOCUMENT --
    the same rule `gitleaks()` and `trivy_vulns()` apply to a record they
    cannot read.
    """
    if not isinstance(data, dict) or not isinstance(data.get("components"), list):
        return None
    components = [c for c in data["components"]
                 if isinstance(c, dict) and c.get("type") != "file"]
    return {**data, "components": components}


def syft_sbom(root):
    """(document, notes): the CycloneDX SBOM Syft's directory scan produces
    for `root`, or (None, notes) when it could not.

    `None` is `cli._scan_sbom`'s signal to fall back to `deps.sbom` -- the
    same shape `gitleaks_scan` and `trivy_scan` return for the same reason:
    absent, unversioned, timed out, writing a report `run_json` cannot
    parse, or (here) one `syft_document` will not use.

    THE SCOPE IS `secrets.SKIP_DIRS`, EXPRESSED THE WAY SYFT WANTS IT: one
    `--exclude '**/name'` per entry, matched at any depth without also
    needing the bare name Trivy's matcher required (see `trivy_skip_dirs`) --
    measured with a `package-lock.json` planted at the TOP LEVEL of a
    `vendor/` directory, `--exclude '**/vendor'` alone excludes it. Not
    `ignore_paths`: see the section comment above for why an SBOM does not
    take it.
    """
    args = ["scan", "dir:.", "-o", "cyclonedx-json={out}", "-q"]
    for name in sorted(secrets.SKIP_DIRS):
        args += ["--exclude", f"**/{name}"]
    data, note = engines.run_json("syft", args, root)
    if data is None:
        return None, [note] if note else []
    document = syft_document(data)
    if document is None:
        return None, [SYFT_NO_COMPONENTS_NOTE]
    version = engines.version_of("syft") or "syft"
    return document, [SYFT_ENGINE_NOTE.format(version=version), SYFT_SBOM_NOTE]


# ------------------------------------------------------------ the SAST pre-pass
#
# SEMGREP REPLACES NOTHING, and that is what makes this section different from
# the three above it. Gitleaks, Trivy and Syft each take a category over from a
# producer this project wrote; Semgrep does not, because the measurement says
# it cannot. On this repository, `p/owasp-top-ten` LOADED 244 rules over 89
# files in 6 seconds -- semgrep's own summary line says "Rules run: 223" for the
# same scan, and `semgrep_languages` explains where the 21 sit -- and the split
# by language was:
#
#     python 147    javascript 65    json 3    bash 1    html 1
#
# (61 `javascript` rule ids plus the 4 `typescript` ones semgrep's own table
# folds into the "js" row it prints.)
#
# ONE RULE FOR SHELL, and the core of this product is 8,263 lines of bash. So
# the agent's SAST pass stays primary and this is a PRE-PASS whose output it
# triages -- `cli._scan_sast` adds these findings, it never swaps anything out,
# and the coverage note carries the per-language spread because "Semgrep ran"
# is true here and misleading.
#
# THE IDENTITY CANNOT BE SHARED WITH THE PASS THAT FOLLOWS, AND THAT IS
# DECLARED RATHER THAN FAKED. A SAST finding's identity is
# `fingerprint("sast", rule, path, snippet)` and the fourth argument is THE
# CODE -- which `engines.purge` drops out of `extra.lines` before this module
# ever sees it, deliberately, because a rule that fires on a hardcoded
# credential returns the credential there. There is no way back: the ledger
# stores an opaque `snippet_hash` and nothing else, and `ledger.rename_rule`
# refuses the `sast` category outright for exactly this reason (`_REFINGERPRINT`
# has no entry for it), so a wrong identity minted here could never be migrated
# afterwards. The fourth argument is therefore Semgrep's own `check_id`, chosen
# for what it has to do rather than for looking like the recipe:
#
#   * stable run to run -- the check id does not move when the code does,
#     which a line number would;
#   * it keeps two checks in one file apart. `""` would not: every unmapped
#     finding in a file collapses onto ONE `other` row whose rationale names
#     whichever was parsed last, merging unrelated problems.
#
# What it does NOT do is match what the SAST pass mints for the same weakness.
# One hole found by both is listed twice, under two identities, and a decision
# taken on one does not reach the other. `SAST_IDENTITY_NOTE` says so in the
# report; the previous task in this block shipped a divergence by assuming a
# recipe carried over, and the fix for this one is to state it, not to hash
# something that merely looks right.

# The published rule pack this pre-pass runs. Pinned rather than configurable:
# `taxonomy.py`'s OWASP codes are the 2021 Top Ten because that is the edition
# this pack targets, and a different pack would quietly break that alignment.
SEMGREP_CONFIG = "p/owasp-top-ten"

# Semgrep's own severity words, mapped to ours -- and NONE of them reaches
# `critical`. That is the deliberate part. Semgrep's severity is a property of
# the RULE (how confident its author is that the pattern is worth flagging),
# not of this repository's exposure: an `ERROR` from a linter says the pattern
# matched cleanly, never that anything reaches the code it matched. Measured
# here: all three findings on this repository are false positives of the kind
# only context resolves -- cache keys and ETags, one beside a comment that
# literally reads "cheap fingerprint of the file head". `critical` is what the
# report's headline counts and the default `min_severity` floor are built
# around, so a pattern match nobody has read the surrounding code for may not
# open one on its own. The triage that follows can RAISE any of these, and that
# is a judgement somebody made.
_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}

# For a word Semgrep did not send, or a future grade this table has never heard
# of. NOT `info`, which sits below the default floor: an ungraded finding is one
# nobody has assessed, not one that does not matter, and filing it out of sight
# is the same mistake `_TRIVY_SEVERITY`'s default exists to avoid.
SAST_DEFAULT_SEVERITY = "medium"

# CWE -> the one rule in our closed vocabulary that carries it. A REVERSE of
# `taxonomy.SAST_RULES`, built here rather than stored there so the vocabulary
# stays the single source: adding a rule to `taxonomy.py` teaches this lookup
# without a second edit. `other` is excluded by the empty-CWE test -- it is the
# escape hatch, and it carries no CWE precisely so an unclassified finding is
# visibly unclassified.
#
# Two rules sharing a CWE would collapse silently into whichever was written
# last. Pinned by `test_every_cwe_in_the_vocabulary_names_exactly_one_rule`.
_RULE_BY_CWE = {cwe: rule for rule, (cwe, _owasp) in taxonomy.SAST_RULES.items()
                if cwe}

# `CWE-327` out of `"CWE-327: Use of a Broken or Risky Cryptographic
# Algorithm"`. `\d+` is greedy, which is what stops a longer identifier being
# truncated into a shorter one that happens to be in the vocabulary: `CWE-327`
# is never read as the `CWE-32` nothing reported.
_CWE_RE = re.compile(r"CWE-\d+")

# The 2021 entry out of `["A03:2017 - ...", "A02:2021 - ...", "A04:2025 -
# ...']`. THE EDITION MATTERS: `taxonomy.py` maps the 2021 Top Ten, and the
# names repeat across editions with different meanings -- "Sensitive Data
# Exposure" was A3:2017 and the 2021 revision reused the phrase for the
# narrower cryptographic-failures category. Taking `[0]` would file a finding
# under a code from a Top Ten this project does not speak.
_OWASP_2021_RE = re.compile(r"A\d{2}:2021")

SAST_ENGINE_NOTE = ("The SAST pre-pass was run by Semgrep {version} {files}, "
                    "with {rules} rules loaded from {config}.")

# The same sentence for a report that does not say how many rules loaded --
# `--time` not given, or a Semgrep that has stopped filling the block in.
# `semgrep_languages` promises "the breakdown is lost, never the phase", and
# the COUNT went with the breakdown: summing an empty breakdown printed "with 0
# rules loaded from p/owasp-top-ten" over a scan that had loaded 244 of them.
# Zero rules loaded and an unknown number of rules loaded are opposite facts --
# the first one says nothing was checked at all -- and the single sentence this
# whole pass exists for may not report the second as the first. The clause is
# dropped and the loss is stated instead.
SAST_ENGINE_NOTE_NO_RULES = (
    "The SAST pre-pass was run by Semgrep {version} {files}, from {config} — "
    "this report does not say how many rules that loaded.")

# The file count, as a phrase, for the same reason and with the same rule: a
# number that is in the report, or a clause that says it is not. "over 0 files"
# was printed for a `paths` block this parser could not read -- the identical
# lie the rule count told, one clause earlier.
SAST_FILES_PHRASE = "over {count} {files}"
SAST_FILES_UNKNOWN = "over a set of files this report does not count"

# The sentence this whole section exists for. Semgrep's coverage is not even
# across languages and the report has to say by how much, or a repository whose
# logic lives in shell reads a clean pre-pass as a clean bill of health.
#
# "loaded", not "ran", in both sentences -- see `semgrep_languages` for the
# measurement behind that word.
SAST_LANGUAGE_NOTE = ("Those rules are not spread evenly across the languages "
                      "this tree holds — the number loaded for each was "
                      "{breakdown} — so a language near the end of that list "
                      "was barely examined, however little this report shows "
                      "for it.")

# The rules that loaded under a namespace no file here is written in. They are
# NOT presented as coverage and they are NOT hidden either -- see
# `semgrep_breakdown` for why both halves matter.
SAST_UNPLACED_NOTE = ("A further {count} {rules} loaded under namespaces no "
                      "file in this tree is written in ({breakdown}): Semgrep's "
                      "pack loads a floor of rules over any directory at all, "
                      "including an empty one, so those are not coverage of "
                      "anything here.")

# A file Semgrep could not parse was not analysed, whatever the rule count says
# about its language. The engine's own message for it is NEVER quoted back:
# that message is the file's source (see `engines.PURGE`).
SAST_PARSE_NOTE = ("{count} {files} could not be fully parsed by Semgrep, so "
                   "part of what {they} {hold} was not analysed at all.")

SAST_PREPASS_NOTE = ("Semgrep is a pre-pass here, not the SAST pass: it "
                     "matched patterns, and the analysis that follows is what "
                     "reads the surrounding code and decides what they mean.")

# Said only when this pre-pass actually produced findings -- the same rule
# `DEP_ID_NOTE` follows: with nothing found there is no identity that could
# have diverged, and this is characters a reader has to get past to reach the
# gaps that ARE real.
SAST_IDENTITY_NOTE = ("A finding from this pre-pass is identified by the rule, "
                      "the file and Semgrep's own check id — never by the code "
                      "it matched, which this analysis deliberately never "
                      "records. The SAST pass identifies its own findings BY "
                      "that code, so one weakness found by both is listed "
                      "twice, under two identities, and a decision taken on "
                      "one does not reach the other.")

# The gap, in the same shape as `TREE_GAP` and `HISTORY_GAP`: a pass that did
# not run has to be said, because "found nothing" and "never looked" are the
# same silence in a report otherwise. It is also the one gap in this module
# that is NOT a hole in the category: the SAST pass has always been this
# category's primary source, and it is unaffected.
SAST_GAP = ("The SAST pre-pass did not run ({reason}) — the SAST pass itself "
            "is unaffected, since it has always been this category's primary "
            "source.")

# What `semgrep_failure` hands back as the reason. It names the error TYPES
# semgrep gave and nothing else -- `errors[].message` is the file semgrep could
# not read, and it is purged before this module sees it -- and
# `_semgrep_error_type` is what makes "and nothing else" true by construction
# rather than merely intended.
SAST_FAILED = ("semgrep reported an error of its own ({types}), so the report "
               "it wrote describes a scan that did not really run")

# How a report says, in its own numbers rather than in an `errors[]` entry,
# that it looked at nothing. See `semgrep_empty_scan`.
SAST_NO_FILES = ("semgrep scanned no file at all, so the report it wrote "
                 "describes a scan that did not really run")


def semgrep_excludes(ignore_paths=()) -> list[str]:
    """The `--exclude` values for a scan of this project's scope.

    EVERY SKIP_DIR TWICE, bare and as `**/name` -- and here that is
    REDUNDANCY, not necessity, which is the opposite of what the same pair
    means in `trivy_skip_dirs`. Measured against a tree holding the same
    weakness at `keep/x.py`, `a/b/keep/x.py` and `top.py`: Semgrep reports all
    three unexcluded, and `--exclude keep` ALONE or `--exclude '**/keep'`
    ALONE leaves only `top.py`. Both forms already match at any depth, where
    Trivy's bare name matched the top level only. That is what `SKIP_DIRS`
    wants -- `_out_of_scope` drops those names at any depth too -- so the pair
    is kept because it costs nothing and neither form can then be the one a
    future matcher narrows, but nobody should read it here as a hole.

    THE OPERATOR'S GLOBS ARE ANCHORED, AND THE `rstrip("/*")` THAT USED TO BE
    HERE WAS A NARROWING. It was copied from `trivy_skip_dirs`, where it is
    near-correct because Trivy's bare name matches the TOP LEVEL only. Semgrep
    matches a bare name at ANY DEPTH, so `docs/**` became `docs` and took
    `src/docs/b.py` with it -- a file `ignores.ignored("src/docs/b.py",
    ["docs/**"])` answers `False` for, i.e. one this analysis considers IN
    SCOPE. `_out_of_scope` cannot put it back; it only ever removes more. The
    scan was quietly narrower than the operator asked for and nothing said so.

    Measured, semgrep 1.175.0, against `docs/a.py`, `src/docs/b.py`, `top.py`:

        --exclude docs        scanned: top.py                 <- the bug
        --exclude ./docs      scanned: src/docs/b.py top.py
        --exclude ./docs/**   scanned: src/docs/b.py top.py

    A pattern containing `/` is matched against the path from the scan root; a
    pattern without one matches any component at any depth. So every glob goes
    down with a `./` in front of it, which is the form that says "from the root
    of this scan" in both cases.

    THE ERROR THAT REMAINS RUNS THE SAFE WAY. A glob whose wildcard crosses `/`
    in `fnmatch` -- `*.md`, which `ignores.ignored` matches at any depth --
    anchors to the top level here, so semgrep still READS `sub/note.md`. That
    costs engine time and nothing else: `semgrep_findings` puts everything that
    comes back through `_out_of_scope`, which applies `ignores.ignored`
    itself, so the finding is dropped anyway. Excluding LESS than the analysis
    ignores is recoverable; excluding more is the loss this docstring opens
    with, and there is nothing to declare in the coverage note because no file
    the analysis wants is skipped any more.
    """
    out = []
    # The default noise filter's fixture directories join `SKIP_DIRS` here
    # rather than the operator's globs below, because that is what they are:
    # directory names matched at any depth, not paths from the scan root. The
    # anchoring rule that follows would narrow them exactly the way it used to
    # narrow `docs/**`. They drop out when the project switched the default
    # off, so an operator's decision is never undone by a command line.
    for name in sorted(set(secrets.SKIP_DIRS)
                       | set(ignores.default_dirs(ignore_paths))):
        out += [name, f"**/{name}"]
    for glob in ignores.globs(ignore_paths):
        glob = (glob or "").strip()
        # A leading `/` or `./` is stripped before the `./` goes back on, so
        # an operator writing `/docs` or `./docs` does not produce `.//docs`
        # -- a pattern semgrep matches nothing with, which would silently
        # widen the scan instead of narrowing it. Paths in `ignore_paths` are
        # repository-relative by definition, so a leading `/` means the root
        # of the repository and not the root of the filesystem.
        while glob.startswith("./"):
            glob = glob[2:]
        glob = glob.lstrip("/")
        if glob:
            out.append(f"./{glob}")
    return out


def _semgrep_metadata(record) -> dict:
    extra = record.get("extra")
    metadata = extra.get("metadata") if isinstance(extra, dict) else None
    return metadata if isinstance(metadata, dict) else {}


def _semgrep_cwes(record) -> list[str]:
    """Every CWE identifier the record names, in the order Semgrep wrote them.

    Order is preserved for the RATIONALE only. Nothing that decides the rule
    depends on it -- see `semgrep_rule`.
    """
    listed = _semgrep_metadata(record).get("cwe")
    if isinstance(listed, str):
        listed = [listed]
    if not isinstance(listed, list):
        return []
    out = []
    for entry in listed:
        if not isinstance(entry, str):
            continue
        found = _CWE_RE.search(entry)
        if found and found.group(0) not in out:
            out.append(found.group(0))
    return out


def semgrep_owasp(record) -> str:
    """The 2021 OWASP code Semgrep put on this rule, or "".

    NOT the first entry: `extra.metadata.owasp` carries several editions at
    once (`A03:2017`, `A02:2021`, `A04:2025` on the very rule this
    repository's own capture fired), and 2021 is the edition `taxonomy.py`
    maps. Sorted rather than indexed for the same reason `_trivy_advisory_id`
    sorts `VendorIDs`: the answer must depend on the SET, not on the order it
    arrived in.
    """
    listed = _semgrep_metadata(record).get("owasp")
    if isinstance(listed, str):
        listed = [listed]
    if not isinstance(listed, list):
        return ""
    codes = sorted({found.group(0) for entry in listed
                    if isinstance(entry, str)
                    for found in [_OWASP_2021_RE.search(entry)] if found})
    return codes[0] if codes else ""


def semgrep_rule(record) -> str:
    """The rule name from OUR closed vocabulary, mapped by CWE.

    `report-finding` refuses a SAST rule outside `taxonomy.SAST_RULES`, and
    `cmd_prepare` writes straight to the ledger without passing that door --
    so a name invented here would land as a rule no filter selects, no
    `taxonomy.classify` can grade, and no agent can ever re-report.

    NOT `cwe[0]`. The field is a list, the rule is a FINGERPRINT INPUT, and
    indexing it would let a registry refresh that merely reorders the field
    re-identify the finding -- the trap `_trivy_advisory_id` documents for
    `VendorIDs`. Every entry is read instead, and the answer depends on the
    SET:

      one vocabulary rule named   -> that rule, whatever position it was in;
      none                        -> `other`;
      TWO OR MORE                 -> `other` as well, and deliberately. Two
        different rules in one record is genuine ambiguity, and picking one
        (even deterministically) relabels the finding as something it is half
        not, in the one field a human's decision hangs off. `other` is the
        escape hatch `taxonomy.py` documents for exactly this: an unclassified
        finding must be VISIBLY unclassified rather than quietly mislabelled,
        and the rationale names every CWE the record carried.
    """
    named = {_RULE_BY_CWE[cwe] for cwe in _semgrep_cwes(record)
             if cwe in _RULE_BY_CWE}
    return named.pop() if len(named) == 1 else "other"


def _semgrep_severity(record) -> str:
    extra = record.get("extra")
    word = extra.get("severity") if isinstance(extra, dict) else ""
    return _SEMGREP_SEVERITY.get(str(word or "").strip().upper(),
                                 SAST_DEFAULT_SEVERITY)


def _semgrep_line(record) -> int:
    start = record.get("start")
    line = start.get("line") if isinstance(start, dict) else 0
    if isinstance(line, bool) or not isinstance(line, (int, float)):
        return 0
    return int(line)


def _sast_finding(path, check, rule, severity, lines, cwes, owasp) -> dict:
    short = check.rsplit(".", 1)[-1]
    rationale = (f"Semgrep's {check} matched here. This is a pre-pass finding: "
                 "the pattern fired, and nothing has yet read the surrounding "
                 "code to say whether it is really exposed.")
    if rule == "other":
        # The escape hatch has to stay actionable, so everything that WOULD
        # have classified it is written out: the check id above, the CWEs
        # nothing in the vocabulary carries, and the 2021 OWASP category
        # Semgrep itself put it in. `cwe` and `owasp` stay empty on the row --
        # they are `taxonomy.classify`'s to fill, and a row whose columns
        # disagreed with its rule would be two sources of truth in one line.
        named = ", ".join(cwes) if cwes else "no CWE at all"
        rationale += (f" No rule in this project's vocabulary carries "
                      f"{named}, so it is filed as `other`")
        rationale += (f"; Semgrep places it under OWASP {owasp}." if owasp
                      else ".")
    remediation = (
        "Read the code at each location and decide whether the pattern "
        "Semgrep matched is a real weakness here — it matched syntax, not a "
        "path it proved anything reaches. If it is real, close it at every "
        "location listed. The rule is documented at "
        # BUILT, not copied out of `extra.metadata.source`, which is this
        # exact URL. Nothing an engine wrote reaches a finding here, and the
        # rule that keeps that true is worth more than one saved f-string.
        f"https://semgrep.dev/r/{check}")
    cwe, owasp_code = taxonomy.classify(rule)
    return {
        # The check id, not the code -- see this section's opening comment for
        # why the recipe's fourth argument cannot be what it names here.
        "fingerprint": fingerprint("sast", rule, path, check),
        "category": "sast",
        "rule": rule,
        "severity": severity,
        "title": f"{rule.replace('-', ' ')}: {short} in {path}",
        "rationale": rationale,
        "remediation": remediation,
        # `cwe`/`owasp` are DERIVED from the rule, exactly as
        # `cmd_report_finding` derives them -- never read from the engine's
        # own metadata, which would give one row two classifications.
        "cwe": cwe,
        "owasp": owasp_code,
        "occurrences": [{"file": path, "line": line, "snippet_hash": ""}
                        for line in lines],
    }


def semgrep_findings(data, root=None, ignore_paths=()) -> list[dict]:
    """Semgrep's JSON report as `sast` findings, one per (file, check id).

    ONE FINDING PER CHECK PER FILE, with an occurrence per hit. Without the
    matched code there is no per-hit identity to give -- see this section's
    opening comment -- so several matches of one check in one file are one
    finding with several occurrences, the same grouping `gitleaks()` uses for
    the same reason. Measured on this repository: three md5 calls in
    `bin/claude-cron-server`, one finding, three occurrences.

    Every field is CONSTRUCTED, never copied. `engines.purge` has already
    dropped `lines`, the metavariable bindings, the autofix, the dataflow
    trace and `message`; building the record from scratch is the second lock,
    and the one that still holds when a future Semgrep puts the matched source
    in a field nobody here has heard of.

    A record this parser cannot read costs that record, not the phase.
    """
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []
    groups = {}
    for record in results:
        if not isinstance(record, dict):
            continue
        check = str(record.get("check_id") or "").strip()
        path = str(record.get("path") or "").strip()
        if not check or not path:
            continue
        path = _relative(path, root) if root is not None else path
        if _out_of_scope(path, ignore_paths):
            continue
        group = groups.setdefault((path, check), {
            "lines": [], "rule": semgrep_rule(record),
            "cwes": _semgrep_cwes(record), "owasp": semgrep_owasp(record),
            "severities": set()})
        line = _semgrep_line(record)
        if line not in group["lines"]:
            group["lines"].append(line)
        group["severities"].add(_semgrep_severity(record))
    out = []
    for (path, check), group in groups.items():
        # Every hit of one check shares one rule and one severity, so this is
        # a tie-break that should never fire -- taken by SET rather than by
        # arrival order so that it cannot depend on which hit was parsed
        # first if a future Semgrep ever grades two matches of one rule
        # differently. Most severe wins.
        severity = min(group["severities"],
                       key=lambda s: report.SEVERITIES.index(s))
        out.append(_sast_finding(path, check, group["rule"], severity,
                                 sorted(group["lines"]), group["cwes"],
                                 group["owasp"]))
    return out


def semgrep_languages(data) -> list[tuple[str, int]]:
    """`[(language, rules loaded), ...]`, most rules first.

    Read out of `time.rules`, which `--time` fills with the id of every rule
    Semgrep loaded for this tree -- and a registry rule id is namespaced by its
    language (`python.lang.security…`, `bash.curl…`), so the first component IS
    the language. Verified against Semgrep's own per-language table on this
    repository: python 147, javascript 61 + typescript 4 = the 65 it prints for
    "js", bash 1, json 3, html 1. Every language row matches exactly.

    "LOADED" AND NOT "RAN", because the two numbers differ and the report must
    not quietly pick the flattering one. Semgrep's own summary line for the
    same scan says "Rules run: 223" where `time.rules` holds 244, and the whole
    21 sits in the namespaces that are not languages: its table folds them into
    one `<multilang> 6` row, while the ids carry `generic` (15),
    `package_managers` (5) and the pattern-mode `java`/`scala`/`ruby` rules (7)
    that load whatever the tree contains -- 26 of them load over an empty
    directory. No language row is affected, and the word says which count this
    is.

    THE TABLE ITSELF IS NOT AVAILABLE. Semgrep prints it on STDERR, and
    `engines.run_json` never hands stderr back -- an engine that fails while
    reading a file puts that file's bytes in it, which is the whole reason that
    rule exists. `time.rules` is the machine-readable equivalent, and `--time`
    is what fills it.

    Semgrep filters the pack by the languages it finds: 560 rules in
    `p/owasp-top-ten` became 244 here and 26 over an empty directory -- which
    is why a namespace can appear with a handful of rules and no file of that
    language anywhere.

    An empty list when `time.rules` is absent: the breakdown is lost, never the
    phase. `semgrep_rule_count` says which of the two happened, because an
    empty breakdown and a breakdown of zeroes are opposite facts.

    RAW, and filtered by nobody. What reaches the note goes through
    `semgrep_breakdown` first, which is where "this namespace is a language
    this tree is actually written in" is decided. This function stays the
    measurement.
    """
    counts = {}
    for rule_id in _semgrep_rule_ids(data) or ():
        language = rule_id.split(".", 1)[0]
        counts[language] = counts.get(language, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _semgrep_rule_ids(data):
    """The rule ids `time.rules` holds, or None when there is no such block.

    None and `[]` are different answers -- see `semgrep_rule_count`.
    """
    rules = data.get("time") if isinstance(data, dict) else None
    rules = rules.get("rules") if isinstance(rules, dict) else None
    if not isinstance(rules, list):
        return None
    return [r for r in rules if isinstance(r, str) and r.strip()]


def semgrep_rule_count(data):
    """How many rules Semgrep loaded, or None when the report does not say.

    NONE IS NOT ZERO, and this function exists because summing the breakdown
    could not tell them apart: `sum(n for _, n in semgrep_languages(data))` is
    `0` both for a scan that loaded nothing and for a report that never said,
    and it printed "with 0 rules loaded from p/owasp-top-ten" over a scan that
    had loaded 244.

    A ZERO FROM SEMGREP IS NEVER EVIDENCE THAT ZERO RULES LOADED. Measured,
    1.175.0, same tree, six files: WITHOUT `--time` semgrep still writes a
    `time` block and still writes `time.rules` -- as `[]`. So the engine itself
    conflates "no rule" with "not asked", and nothing downstream can undo that.
    Hence the rule this module follows: only a POSITIVE count is a fact the
    note may print (`semgrep_notes`), and the report that genuinely scanned
    nothing is caught by what it scanned rather than by what it loaded
    (`semgrep_empty_scan`).
    """
    ids = _semgrep_rule_ids(data)
    return None if ids is None else len(ids)


# A registry rule id's first component is a NAMESPACE, and this is what a file
# of that namespace looks like on disk.
#
# WHY THE TABLE EXISTS. The namespace alone is not evidence of anything.
# `p/owasp-top-ten` loads a FLOOR of rules over any directory at all --
# measured on a directory holding one `.txt` file: `java 3`, `scala 3`,
# `ruby 1`, `generic 15`, `package_managers 4` -- and the shipped note printed
# them as languages. "Semgrep loaded 3 Java rules" on a repository with no Java
# misleads in the one direction this note exists to prevent, since the whole
# sentence is read as a statement about how much of THIS tree was examined.
#
# THREE KINDS OF ENTRY, and the third is why this is a table and not an `if`:
#
#   mapped to extensions   a language. The row is shown as coverage only when
#                          a scanned file carries one of them. A BARE NAME in
#                          that tuple (`dockerfile`, `gemfile`) is matched
#                          against the filename instead, for the languages
#                          whose canonical file has no extension at all.
#   mapped to ()           NOT a language: `generic` is Semgrep's
#                          language-agnostic matching mode and
#                          `package_managers` is its lockfile pack. Neither can
#                          ever be evidenced by a file, and neither is a
#                          language a reader could be written in.
#   not named here         SHOWN as coverage. Absence cannot be proven from a
#                          table nobody has updated: a namespace this project
#                          has never heard of is one whose files this project
#                          cannot recognise either, and dropping its row would
#                          hide a language that WAS barely examined -- the
#                          dangerous direction. A new namespace costs a row
#                          that is merely unfiltered.
_NAMESPACE_FILES = {
    "generic": (), "package_managers": (),
    "python": (".py", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".vue"),
    "typescript": (".ts", ".tsx", ".mts", ".cts"),
    "java": (".java",),
    "scala": (".scala", ".sc"),
    "ruby": (".rb", ".rake", ".gemspec", "gemfile", "rakefile"),
    "go": (".go",),
    "php": (".php", ".phtml", ".php5", ".php7"),
    "csharp": (".cs",),
    "kotlin": (".kt", ".kts"),
    "swift": (".swift",),
    "rust": (".rs",),
    "c": (".c", ".h"),
    "cpp": (".cc", ".cpp", ".cxx", ".hpp", ".hh"),
    "bash": (".sh", ".bash", ".zsh", ".ksh"),
    "html": (".html", ".htm"),
    "json": (".json",),
    "yaml": (".yaml", ".yml"),
    "terraform": (".tf", ".tfvars"),
    "dockerfile": (".dockerfile", "dockerfile"),
    "solidity": (".sol",),
    "elixir": (".ex", ".exs"),
    "ocaml": (".ml", ".mli"),
    "lua": (".lua",),
    "dart": (".dart",),
    "clojure": (".clj", ".cljs", ".cljc"),
}


def semgrep_breakdown(data):
    """`(coverage, unplaced)` -- the language rows, split by what this tree holds.

    `coverage` is the part of `semgrep_languages` a file in the scanned set
    evidences; `unplaced` is the rest. Both are `[(namespace, rules), ...]`,
    most rules first, and together they are exactly `semgrep_languages`.

    NOTHING IS DROPPED, and that is deliberate. The obvious fix for `java 3` on
    a repository with no Java is to delete the row, and it opens a worse hole
    than it closes: this tree's own shell lives in `bin/claude-cron`, which has
    NO EXTENSION -- Semgrep reads its shebang and this table cannot -- so a
    repository whose shell is all extensionless would lose `bash 1` from a note
    whose entire purpose is to say that shell got one rule. A row that is
    hidden teaches nothing; a row that is stated and labelled as not-coverage
    teaches the reader both facts. So the unevidenced rows are printed too, in
    a sentence that says what they are (`SAST_UNPLACED_NOTE`).

    The evidence is the SCANNED SET, not the repository: `paths.scanned` is the
    files Semgrep actually opened, so a language that lives entirely under an
    excluded directory is correctly not counted as coverage of this scan.
    """
    languages = semgrep_languages(data)
    paths = data.get("paths") if isinstance(data, dict) else None
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    # The extension, or the bare filename when there is none -- so a scanned
    # `Dockerfile` evidences `dockerfile` the way `main.py` evidences `python`.
    marks = {Path(p).suffix.lower() or Path(p).name.lower() for p in scanned
             if isinstance(p, str)} if isinstance(scanned, list) else set()
    coverage, unplaced = [], []
    for namespace, count in languages:
        known = _NAMESPACE_FILES.get(namespace)
        placed = known is None or bool(marks.intersection(known))
        (coverage if placed else unplaced).append((namespace, count))
    return coverage, unplaced


def _semgrep_unparsed(data) -> int:
    """How many distinct files Semgrep reported an error against.

    The PATHS are counted, never the messages: `errors[].message` quotes the
    file it could not parse (see `engines.PURGE`), which is why the note says
    a number and not a reason.
    """
    errors = data.get("errors") if isinstance(data, dict) else None
    if not isinstance(errors, list):
        return 0
    return len({e.get("path") for e in errors
                if isinstance(e, dict) and isinstance(e.get("path"), str)
                and e.get("path").strip()})


# The `errors[].level` words that mean Semgrep RECOVERED and kept scanning.
# Listed rather than listing their opposite, so that a word this table has
# never heard of -- and an entry carrying no level at all -- refuses the
# report instead of passing as harmless. See `semgrep_failure`.
_SEMGREP_RECOVERABLE_LEVELS = ("warn", "warning", "info")

# What an error TYPE is allowed to look like before it is quoted into the
# coverage note: a name. A letter, then letters, digits, spaces, `_` or `-`,
# and at most 64 characters -- which "SemgrepError" and "Syntax error" both
# are, and which no filesystem path can be, since a path needs a `/` or a `.`
# to be one. That is the point: see `_semgrep_error_type`.
_ERROR_TYPE_RE = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,63}\Z")


def _semgrep_error_type(entry) -> str:
    """One `errors[]` entry's TYPE, as a name and never as a structure.

    `SAST_FAILED` promises the note names "the error types and nothing else",
    and `str(entry.get("type"))` did not keep that promise. THE FIELD IS NOT
    ALWAYS A STRING: real semgrep writes

        "type": ["PartialParsing", [{"path": "bin/claude-cron", …}]]

    for a file it could only partly parse, and `str()` of that puts the
    repository's own file paths into the coverage note -- through the one field
    `engines.PURGE` cannot help with, since a path is not matched content and
    is not stripped. It is not reachable at `level: "error"` in 1.175.0, where
    a partial parse is a `warn`; the promise was still an over-claim, and a
    promise that holds only while another program keeps grading its own errors
    the way it does today is the kind this module does not make.

    UNREACHABLE BY CONSTRUCTION, not by knowing the shape. The leading element
    is taken when the field is a list, because that is where semgrep puts the
    name -- but what is RETURNED is only ever something `_ERROR_TYPE_RE`
    accepts, and a filesystem path cannot be, whatever shape a future version
    invents. Anything else becomes the literal `error`: this sentence exists to
    say the report is refused, and it says that with or without a name.
    """
    kind = entry.get("type")
    if isinstance(kind, list) and kind:
        kind = kind[0]
    kind = kind.strip() if isinstance(kind, str) else ""
    return kind if _ERROR_TYPE_RE.match(kind) else "error"


def semgrep_failure(data) -> str:
    """Why this report describes a scan that did not really run, or "".

    THE SAME SCAR THIS PROJECT ALREADY CARRIES ON THE OTHER ENGINE, and here
    the trigger is a normal state rather than an exotic one. `gitleaks git`
    outside a repository writes `[]` and exits 0 -- the identical answer it
    gives for a clean history -- which is why `history_state` exists. Semgrep
    does it too: pointed at a rule pack it cannot fetch it writes a
    well-formed report with `results: []` and `paths.scanned: []` and exits 7.
    Measured, verbatim, against a pack that does not exist:

        {"errors": [{"code": 2, "level": "error", "type": "SemgrepError",
                     "message": "Failed to download configuration from
                                 https://semgrep.dev/c/… HTTP 404."}, …],
         "results": [], "paths": {"scanned": []}}

    `run_json` checks that a report was WRITTEN, not what the exit code said,
    so without this that lands as a clean pre-pass -- and the pack is fetched
    from the registry, so any machine without a network reaches it the moment
    nobody passes `--offline`.

    THE LINE IS `level`, and semgrep draws it where this needs it: a file it
    could not parse is `warn` (three of them in this repository's own capture,
    with 86 files still scanned around them), and `error` is kept for what
    stopped it. So a `warn` costs only the note `SAST_PARSE_NOTE` makes of it.

    IT IS THE `warn` SIDE THAT IS LISTED, not the `error` side, and that is the
    fail-closed half. Testing `level == "error"` let every OTHER word through
    as harmless -- an entry with no `level` at all, and a `fatal` or `critical`
    a future Semgrep introduces, would each have been read as recoverable and
    the report taken as clean. `_SEMGREP_RECOVERABLE_LEVELS` names the words
    that are known to mean "kept going"; anything else, including nothing,
    refuses the report. A report this module cannot vouch for is a declared
    gap, never a clean bill of health.
    """
    errors = data.get("errors") if isinstance(data, dict) else None
    if not isinstance(errors, list):
        return ""
    types = sorted({_semgrep_error_type(e) for e in errors
                    if isinstance(e, dict)
                    and str(e.get("level") or "").strip().lower()
                    not in _SEMGREP_RECOVERABLE_LEVELS})
    return SAST_FAILED.format(types=", ".join(types)) if types else ""


def semgrep_empty_scan(data) -> str:
    """Why this report describes a scan that looked at nothing, or "".

    THE SIBLING `semgrep_failure` DOES NOT CATCH, and the one that arrives with
    nothing in `errors[]` to give it away. That guard closed the exit-7 route:
    an unfetchable pack writes `results: []` and `paths.scanned: []` AND an
    `errors[]` entry at `level: "error"`. Its neighbour writes the first two
    and NOT the third. Measured, verbatim, semgrep 1.175.0 against a pack that
    is well-formed YAML and parses to no rule (`rules: []`), over a tree with
    six files in it:

        exit 0
        {"errors": [], "results": [], "paths": {"scanned": []},
         "time": {"rules": [], …}}

    -- which `semgrep_failure` answers `""` for, and which then lands as a
    clean pre-pass. It is the same silence this project has already been bitten
    by twice: `gitleaks git` outside a repository writing `[]` (see
    `history_state`), and the exit-7 report above. "Found nothing" and "never
    looked" are the same silence in a report, and this module's rule is that
    the second one has to say so.

    THE NUMBER READ IS WHAT WAS SCANNED, NOT WHAT WAS LOADED, and that is a
    correction the measurement forced. `time.rules: []` looks like the more
    direct evidence -- no rule loaded, nothing checked -- and it is not
    evidence at all: semgrep writes `time.rules: []` whenever `--time` was not
    passed, over a tree it scanned perfectly well (measured, six files). A
    guard on it would refuse a healthy scan the day a flag moved. What semgrep
    does NOT do is claim to have scanned files it did not, so `paths.scanned`
    is the number that can be trusted in this direction, and a pack with no
    rule in it selects no target: `scanned: []` is the shape it lands in.

    `paths.scanned` must be PRESENT and a LIST to be read as zero. A `paths`
    block this parser cannot read costs the file count and not the phase (see
    `semgrep_notes`), so an absent or malformed one is never read as a zero.
    An empty repository reaches this honestly, and a declared gap is the right
    answer there too: nothing was examined.
    """
    if not isinstance(data, dict):
        return ""
    paths = data.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    return SAST_NO_FILES if isinstance(scanned, list) and not scanned else ""


def semgrep_notes(data, version: str, findings) -> list[str]:
    """Everything this pre-pass has to declare about its own coverage.

    Split out of `semgrep_scan` so the sentences are testable without the
    binary: pinned only inside a `@needs_semgrep` test, they could be deleted
    outright and the suite would stay green on a machine without Semgrep --
    the failure `test_the_coverage_notes_are_returned_without_the_binary`
    exists for one section up.

    EVERY NUMBER HERE IS ONE THE REPORT ACTUALLY CARRIES. Where it does not
    carry one, the clause goes and the loss is stated -- the number is never
    filled in with a zero, which is a different claim entirely: "over 0 files,
    with 0 rules loaded" was printed for a scan of 89 files with 244 rules,
    because both counts fell back to the length of something that was missing.
    A zero rule count is never a fact here even when semgrep writes one -- see
    `semgrep_rule_count` -- so only a POSITIVE count is printed.
    """
    paths = data.get("paths") if isinstance(data, dict) else None
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    files = (SAST_FILES_PHRASE.format(
        count=len(scanned), files="file" if len(scanned) == 1 else "files")
        if isinstance(scanned, list) else SAST_FILES_UNKNOWN)
    rules = semgrep_rule_count(data) or None
    engine = SAST_ENGINE_NOTE if rules else SAST_ENGINE_NOTE_NO_RULES
    notes = [engine.format(version=version, files=files, rules=rules,
                           config=SEMGREP_CONFIG)]
    coverage, unplaced = semgrep_breakdown(data)
    if coverage:
        notes.append(SAST_LANGUAGE_NOTE.format(
            breakdown=", ".join(f"{lang} {n}" for lang, n in coverage)))
    if unplaced:
        total = sum(n for _, n in unplaced)
        notes.append(SAST_UNPLACED_NOTE.format(
            count=total, rules="rule" if total == 1 else "rules",
            breakdown=", ".join(f"{lang} {n}" for lang, n in unplaced)))
    unparsed = _semgrep_unparsed(data)
    if unparsed:
        notes.append(SAST_PARSE_NOTE.format(
            count=unparsed, files="file" if unparsed == 1 else "files",
            they="it" if unparsed == 1 else "they",
            hold="holds" if unparsed == 1 else "hold"))
    notes.append(SAST_PREPASS_NOTE)
    if findings:
        notes.append(SAST_IDENTITY_NOTE)
    return notes


def semgrep_scan(root, ignore_paths=()):
    """Every weakness Semgrep's OWASP pack matches in `root`, as pre-pass
    findings, plus what has to be said about how little that is.

    Returns `(findings, notes)`, and `findings` is None when Semgrep produced
    no report at all -- absent, unversioned, timed out, or writing a format
    this parser cannot read. UNLIKE the three sections above, that is not a
    signal to fall back to anything: nothing here was replaced, so the only
    consequence is the gap `cli._scan_sast` declares.

    `--time` is what fills `time.rules`, and the language breakdown is the
    point of this pass being honest -- see `semgrep_languages`. It costs
    output: Semgrep writes one timing per (file, rule) pair, half a megabyte
    for this repository's 89 files, and it grows with both. Paid because the
    alternative is a report that says "Semgrep ran" over a shell repository and
    lets a reader take it for a clean bill of health.

    THE SCOPE IS LOCKED TWICE, exactly as it is for Gitleaks and Trivy above:
    `--exclude` so the files are never read, and `_out_of_scope` over what
    comes back, because `ignore_paths` is a promise about the ANALYSIS and not
    about one scanner's command line.
    """
    args = ["--config", SEMGREP_CONFIG, "--metrics=off", "--json", "--time",
            "--output", "{out}", "--quiet",
            # Nothing here reads the banner, and the check is a network call an
            # analysis has no use for.
            "--disable-version-check"]
    for pattern in semgrep_excludes(ignore_paths):
        args += ["--exclude", pattern]
    args.append(".")
    data, note = engines.run_json("semgrep", args, root)
    if data is None:
        return None, [note] if note else []
    # Before anything is parsed: semgrep writes a well-formed, EMPTY report
    # when it could not fetch its rule pack, and an empty report is what a
    # clean repository also produces. See `semgrep_failure`.
    #
    # BOTH GUARDS, because they catch different reports. `semgrep_failure`
    # reads `errors[]`; `semgrep_empty_scan` reads the numbers, and a pack that
    # parses to no rule at all exits 0 with an EMPTY `errors[]` -- so the first
    # one answers "" for it and it would land as a clean pre-pass. The failure
    # is asked first because it can say WHY, where the second can only say that
    # nothing was looked at.
    failure = semgrep_failure(data) or semgrep_empty_scan(data)
    if failure:
        return None, [failure]
    findings = semgrep_findings(data, root, ignore_paths)
    version = engines.version_of("semgrep") or "semgrep"
    return findings, semgrep_notes(data, version, findings)
