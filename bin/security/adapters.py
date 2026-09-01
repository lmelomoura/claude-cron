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

from . import deps, engines, osv, secrets
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
# ONE DIVERGENCE CANNOT BE CLOSED and is therefore DECLARED, in `DEP_ID_NOTE`
# below: `vuln_id`. Trivy names an advisory by its CVE id, OSV.dev by the id
# of whichever database published it. Measured on `github.com/gin-gonic/gin
# 1.6.3`: OSV.dev answers GHSA-2c4m-59x9-fr2g, GHSA-3vp4-m3rf-835h,
# GHSA-h395-qcrw-5vmq, GO-2021-0052, GO-2023-1737; Trivy answers
# CVE-2020-28483, CVE-2023-26125, CVE-2023-29401. Zero overlap, and no
# offline mapping between the two vocabularies exists to build one from.

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
_TRIVY_ECOSYSTEM = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
    "pip": "PyPI", "poetry": "PyPI", "pipenv": "PyPI", "uv": "PyPI",
    "composer": "Packagist", "composer-vendor": "Packagist",
    "gomod": "Go", "golang": "Go", "gobinary": "Go",
    "bundler": "RubyGems", "gemspec": "RubyGems",
}

# Named so a reader of a report knows which scanner produced its dependency
# findings, the same reason `ENGINE_NOTE` exists above for secrets. Spelled
# out as "Trivy ({version})" rather than "{version}" alone: unlike
# gitleaks' own `--version` banner (which prints its own name), Trivy's
# first line is bare ("Version: 0.74.0"), so a note built the same way
# `ENGINE_NOTE` is would silently stop naming the tool -- and the bare label
# is stripped by `trivy_scan` so the sentence does not read "Trivy (Version:
# 0.74.0)".
DEP_ENGINE_NOTE = "Dependencies were scanned for known CVEs by Trivy ({version})."

# The divergence the section comment above says cannot be closed. Said on
# every Trivy-scanned report, because it is a property of the producer rather
# than of any one repository, and because the report where it matters most is
# the FIRST one after the engine appears -- the one that lists every OSV.dev
# finding as fixed.
DEP_ID_NOTE = ("Trivy names an advisory by its CVE id, where OSV.dev names "
               "the same advisory by the id of whichever database published "
               "it (GHSA, GO, PYSEC). A dependency finding reported while "
               "OSV.dev was the source therefore appears here under a "
               "different identity: it is listed as fixed and its "
               "replacement as new, and any decision recorded against the "
               "old one does not follow it.")

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
GO_SUM_ONLY_GAP = ("{count} {directories} in this repository {have} a go.sum "
                   "but no go.mod: Trivy reads go.mod, so the Go "
                   "dependencies pinned there were NOT checked for known "
                   "CVEs.")


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


def _trivy_finding(source: str, vuln, ecosystem: str = ""):
    component = _trivy_component(vuln, ecosystem)
    vuln_id = (str(vuln.get("VulnerabilityID") or "").strip()
               if isinstance(vuln, dict) else "")
    if component is None or not vuln_id:
        # No id, no package name, no installed version: this parser cannot
        # build an identity for any of the three. Costs this one record, not
        # the phase -- see `trivy_vulns`.
        return None
    name, version = component
    severity = _TRIVY_SEVERITY.get(str(vuln.get("Severity") or "").upper(),
                                   osv.DEFAULT_SEVERITY)
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
    finding = {
        "fingerprint": fingerprint("dependency", vuln_id, source,
                                   f"{name}@{version}"),
        "category": "dependency",
        "rule": vuln_id,
        "severity": severity,
        "title": f"{name} {version}: {vuln_id}",
        "rationale": rationale,
        "remediation": remediation,
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
    out, owner = [], {}
    for result in sorted((r for r in results if isinstance(r, dict)),
                         key=lambda r: str(r.get("Target") or "")):
        source, ecosystem = _trivy_scope(result, root)
        vulns = result.get("Vulnerabilities")
        if not source or not isinstance(vulns, list):
            # No `Vulnerabilities` key at all is the shape a lockfile with
            # nothing wrong in it actually produces (Trivy still lists it
            # under `Packages`) -- not a malformed record.
            continue
        for vuln in vulns:
            component = _trivy_component(vuln, ecosystem)
            if component is not None:
                first = owner.setdefault((ecosystem, *component), source)
                if first != source:
                    continue  # a later lockfile pinning what this one already did
            finding = _trivy_finding(source, vuln, ecosystem)
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

    `ignore_paths` is passed down too, the cheap way round -- the files are
    then never read at all. It is not the guarantee: `trivy_scan` filters
    what comes back through `_out_of_scope` as well, for the reason that
    function's own docstring gives.
    """
    out = []
    for name in sorted(secrets.SKIP_DIRS):
        out += [name, f"**/{name}"]
    for glob in ignore_paths or ():
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
    args = ["fs", ".", "--format", "json", "--output", "{out}",
            "--scanners", "vuln", "--quiet",
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
    notes = [DEP_ENGINE_NOTE.format(version=version), DEP_ID_NOTE,
             DEP_SBOM_NOTE]
    go_only = _go_sum_without_go_mod(root, ignore_paths)
    if go_only:
        notes.append(GO_SUM_ONLY_GAP.format(
            count=go_only,
            directories="directory" if go_only == 1 else "directories",
            have="has" if go_only == 1 else "have"))
    return findings, notes


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
