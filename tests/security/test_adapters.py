"""Turning an engine's own JSON into this project's findings.

Two properties are load-bearing here and everything else is detail.

THE VALUE NEVER ARRIVES. `engines.purge` drops `Match` and `Secret` at the
parse, and this adapter builds every field of a finding itself rather than
copying the engine's record -- so a field gitleaks adds in a future version
cannot ride into the ledger unnoticed.

THE IDENTITY IS OURS, NOT THE ENGINE'S. Gitleaks emits a `Fingerprint` of
its own (`path:rule:startline`). Adopting it would change the identity of
every secret finding already recorded and orphan the human decisions taken
against them -- and it anchors on a line number, which moves whenever an
unrelated line is added above it. Identity stays `secret_fingerprint(rule,
path)`: the credential's type and the file it lives in.

The fixture is a REAL gitleaks 8.30.1 capture of this repository, purged
through `engines.purge` before it was written. A fixture typed from the
documentation makes the parser and the test agree with each other while both
disagree with the tool.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from security import adapters, engines, fingerprint, osv, secrets

FIX = Path(__file__).parent / "fixtures" / "engines"
REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"

HAVE_GITLEAKS = engines.find("gitleaks") is not None
needs_gitleaks = pytest.mark.skipif(
    not HAVE_GITLEAKS, reason="gitleaks is not installed on this machine")

HAVE_TRIVY = engines.find("trivy") is not None
needs_trivy = pytest.mark.skipif(
    not HAVE_TRIVY, reason="trivy is not installed on this machine")

# Assembled at runtime so this file is not itself a credential a scanner has
# to flag. The shape is a real one: gitleaks allowlists AWS's own
# documentation key (AKIAIOSFODNN7EXAMPLE), so a fixture built from that
# would silently test nothing.
AWS_KEY = "AKIA" + "QYLPMN5HNXMEFRTG"


# --------------------------------------------------------------- the parser

def test_gitleaks_findings_become_secret_findings():
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    out = adapters.gitleaks(data, root=".")
    assert out, "the captured fixture must contain at least one finding"
    f = out[0]
    assert f["category"] == "secret"
    assert f["severity"] in ("critical", "high", "medium", "low", "info")
    assert len(f["fingerprint"]) == 64


def test_a_gitleaks_finding_carries_no_value_anywhere():
    """THE promise of this module, asserted against a record that still has
    the value in it.

    This test used to read the PURGED fixture and grep the output for the
    strings "Secret" and "Match" -- the engine's KEY NAMES, in a blob built
    from a record those keys had already been stripped from. It could not
    fail: it would have passed unchanged if the adapter had copied
    `record["Match"]` into a field called `snippet`.

    So the record here arrives UNPURGED, exactly as gitleaks writes it before
    `engines.purge` runs, and the assertion is about the credential's VALUE.
    `adapters.gitleaks` builds every field of a finding from scratch, which is
    the second lock behind the purge and the one that still holds when a
    future gitleaks moves the value into a field nobody here has heard of --
    `Snippet` below stands for exactly that field.

    No binary needed, so it runs on every machine. The one real value
    assertion this file had lived in a `@needs_gitleaks` test and was skipped
    wherever gitleaks is absent -- which is precisely where nothing else was
    checking the parser's guarantee.
    """
    data = [{
        "RuleID": "aws-access-token", "File": "prod.env", "StartLine": 4,
        "Commit": "a" * 40,
        # The three fields that carry the matched text, populated the way the
        # real tool populates them.
        "Match": f"AWS_ACCESS_KEY_ID={AWS_KEY}",
        "Secret": AWS_KEY,
        "Snippet": f"export AWS_ACCESS_KEY_ID={AWS_KEY}",
        # And the metadata a commit's author can write anything into.
        "Author": "Ada", "Email": "ada@example.com",
        "Message": f"oops, committing {AWS_KEY}",
    }]
    out = adapters.gitleaks(data, root=".")
    assert out, "the record must still parse into a finding"
    blob = json.dumps(out)
    assert AWS_KEY not in blob, "the credential itself reached the finding"
    assert "AWS_ACCESS_KEY_ID" not in blob, "the matched line reached the finding"
    assert "ada@example.com" not in blob and "Ada" not in blob
    assert "oops" not in blob, "a commit message can say anything"
    # The finding is real, not empty -- an adapter that dropped the record
    # entirely would satisfy every assertion above.
    assert out[0]["rule"] == "aws-access-token"
    assert out[0]["occurrences"][0]["file"] == "prod.env"
    assert out[0]["occurrences"][0]["line"] == 4


def test_the_purge_and_the_adapter_are_two_locks_not_one():
    """The containment side of the test above: the value must not survive
    EITHER door on its own.

    `engines.purge` drops `Match` and `Secret` at the parse; the adapter
    rebuilds every field rather than copying. The test above proves the
    adapter alone is enough. This proves the purge alone is enough for the
    fields it names -- so a future refactor that leans on one of them has the
    other still standing, and a regression in either is a red test rather
    than a silent halving of the guarantee.
    """
    raw = [{"RuleID": "aws-access-token", "File": "prod.env", "StartLine": 4,
            "Match": f"AWS_ACCESS_KEY_ID={AWS_KEY}", "Secret": AWS_KEY}]
    purged = engines.purge("gitleaks", raw)
    assert AWS_KEY not in json.dumps(purged)
    assert purged[0]["RuleID"] == "aws-access-token"


def test_the_fingerprint_matches_our_own_recipe():
    # A secret's identity is type + path, computed by fingerprint.py --
    # NOT gitleaks' own `Fingerprint` field, which has a different recipe
    # and would break every decision recorded before this change.
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    f = adapters.gitleaks(data, root=".")[0]
    assert f["fingerprint"] == fingerprint.secret_fingerprint(
        f["rule"], f["occurrences"][0]["file"])


def test_several_hits_of_one_rule_in_one_file_are_one_finding():
    data = [
        {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 3, "Entropy": 4.5},
        {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 9, "Entropy": 4.5},
    ]
    out = adapters.gitleaks(data, root=".")
    assert len(out) == 1
    assert sorted(o["line"] for o in out[0]["occurrences"]) == [3, 9]


def test_the_engines_own_fingerprint_is_never_reused():
    """The single most expensive mistake available here.

    Gitleaks' `Fingerprint` is `path:rule:startline`. It is in the fixture,
    it is 'free', and adopting it would re-identify every secret already in
    the ledger -- orphaning the `accepted` and `false_positive` decisions a
    human recorded against the old identities.
    """
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    engine_fingerprints = {r["Fingerprint"] for r in data}
    ours = {f["fingerprint"] for f in adapters.gitleaks(data, root=".")}
    assert not (ours & engine_fingerprints)


def test_two_rules_in_one_file_stay_two_findings():
    """One finding per credential TYPE per file, exactly as secrets.py
    groups: the fingerprint is (rule, path), so collapsing by path alone
    would give two different holes one identity."""
    data = [
        {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 3},
        {"RuleID": "private-key", "File": "a.env", "StartLine": 4},
    ]
    assert len(adapters.gitleaks(data, root=".")) == 2


def test_an_absolute_path_is_recorded_relative_to_the_root():
    """The fingerprint contains the path, so a run that reported
    `/tmp/worktree-1/app.env` and a run that reported `app.env` would be two
    identities for one secret -- and the worktree's name changes every run."""
    data = [{"RuleID": "aws-access-token", "File": "/srv/checkout/app.env",
             "StartLine": 1}]
    out = adapters.gitleaks(data, root="/srv/checkout")
    assert out[0]["occurrences"][0]["file"] == "app.env"
    assert out[0]["fingerprint"] == fingerprint.secret_fingerprint(
        "aws-access-token", "app.env")


def test_a_record_the_parser_cannot_use_is_dropped_not_fatal():
    """A version bump that renames a field must cost the analysis that
    record, not the whole secret phase."""
    data = [{"nothing": "useful"},
            {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 1},
            "not even a dict"]
    assert len(adapters.gitleaks(data, root=".")) == 1


def test_a_report_that_is_not_a_list_is_no_findings_not_a_crash():
    assert adapters.gitleaks({"unexpected": "shape"}, root=".") == []
    assert adapters.gitleaks(None, root=".") == []


# ------------------------------------------------------------ the severities

def test_the_rules_we_already_had_keep_the_severity_we_gave_them():
    """`secrets._RULES` is the source of truth for what these credential
    types are worth. Gitleaks emits no severity at all, so the map here has
    to reproduce those judgements rather than invent new ones."""
    ours = {name: severity for name, severity, _p, _e in secrets._RULES}
    equivalent = {
        "aws-access-token": "aws_access_key",
        "github-pat": "github_token",
        "slack-bot-token": "slack_token",
        "stripe-access-token": "stripe_key",
        "openai-api-key": "openai_key",
        "private-key": "private_key",
        "gcp-api-key": "google_api_key",
        "generic-api-key": "generic_secret",
    }
    for engine_rule, our_rule in equivalent.items():
        assert adapters.SEVERITY_BY_RULE[engine_rule] == ours[our_rule], engine_rule


def test_a_rule_the_map_has_never_heard_of_still_gets_a_severity():
    """Gitleaks ships ~180 rules and gains more with every release. An
    unmapped one must not arrive with an empty severity the report cannot
    count -- it is a shaped, vendor-specific credential pattern, so it is
    graded like one."""
    out = adapters.gitleaks(
        [{"RuleID": "some-rule-added-next-year", "File": "a.env", "StartLine": 1}],
        root=".")
    assert out[0]["severity"] in ("critical", "high", "medium", "low", "info")


def test_the_remediation_says_rotate_not_delete():
    """A credential that reached a repository is compromised. The report has
    exactly one chance to say that deleting the line is not the fix."""
    out = adapters.gitleaks(
        [{"RuleID": "aws-access-token", "File": "a.env", "StartLine": 1}], root=".")
    remediation = out[0]["remediation"].lower()
    assert "rotate" in remediation
    assert "not enough" in remediation or "is not" in remediation


def test_a_history_finding_says_it_is_in_the_history():
    out = adapters.gitleaks(
        [{"RuleID": "aws-access-token", "File": "a.env", "StartLine": 1,
          "Commit": "a" * 40},
         {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 1,
          "Commit": "b" * 40}],
        root=".", historical=True)
    assert out[0]["historical"] is True
    assert "git history" in out[0]["rationale"]
    # Two commits, one (rule, path): the exposures are counted even though
    # the value is never inspected and "re-added" cannot be told from "a
    # second, different credential".
    assert "2 commits" in out[0]["rationale"]


# ----------------------------------------------------------------- the scope

def test_the_scope_config_excludes_what_the_hand_written_sweep_skips():
    """Gitleaks scans the FILESYSTEM. Measured on this repository: 17
    findings, 15 of them under `.superpowers/`, `__pycache__/` and
    `data/logs/`. Without this the engine swap makes the noise worse."""
    toml = adapters.gitleaks_config()
    for directory in secrets.SKIP_DIRS:
        assert re.escape(directory) in toml or directory in toml, directory


def test_the_scope_config_carries_the_projects_ignore_paths():
    toml = adapters.gitleaks_config(ignore_paths=["tests/fixtures/**"])
    assert "tests/fixtures" in toml


def test_a_glob_becomes_a_pattern_the_engines_regexp_can_compile():
    """Gitleaks is Go, and Go's RE2 rejects `\\Z` and the lookarounds
    Python's `fnmatch.translate` is happy to emit. A config it cannot parse
    is a scan that does not run."""
    patterns = adapters.scope_patterns(
        {"__pycache__"}, ["tests/fix tures-*/**", "docs/*.md", "a+b/**"])
    joined = "\n".join(patterns)
    assert "\\Z" not in joined
    assert "(?s:" not in joined
    assert "(?=" not in joined and "(?!" not in joined
    for pattern in patterns:
        re.compile(pattern)  # a superset of RE2; a syntax error fails here


def test_the_scope_extends_a_project_that_ships_its_own_gitleaks_config(tmp_path):
    """A project with a `.gitleaks.toml` has already told gitleaks what it
    considers noise. Passing `--config` overrides that file, so ours has to
    extend it rather than silently discard it."""
    (tmp_path / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
    toml = adapters.gitleaks_config(root=tmp_path)
    assert "useDefault" not in toml
    assert str(tmp_path / ".gitleaks.toml") in toml


def test_the_scope_falls_back_to_the_default_rule_set(tmp_path):
    assert "useDefault = true" in adapters.gitleaks_config(root=tmp_path)


def test_a_glob_that_cannot_be_written_into_the_config_does_not_break_it():
    """An apostrophe closes the TOML literal string the pattern sits in. A
    config gitleaks cannot parse costs the whole scan, so a pattern carrying
    one is left out of the config -- and caught by the parser instead."""
    toml = adapters.gitleaks_config(ignore_paths=["it's/**", "tests/fixtures/**"])
    assert "it's" not in toml
    assert "tests/fixtures" in toml


def test_an_ignored_path_is_dropped_even_when_the_engine_reports_it():
    """The second lock. `ignore_paths` is a promise about the ANALYSIS, and a
    promise that holds only while another program's command line was accepted
    is not one -- a rule with an allowlist of its own, or a config the engine
    read differently, would turn it back into a suggestion."""
    data = [{"RuleID": "aws-access-token", "File": "tests/fixtures/fake.env",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "__pycache__/c.env",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "app.env", "StartLine": 1}]
    out = adapters.gitleaks(data, root=".", ignore_paths=["tests/fixtures/**"])
    assert [f["occurrences"][0]["file"] for f in out] == ["app.env"]


# ------------------------------------------- the scope, against the real tool

def plant(root, key=AWS_KEY):
    """A tree with one real secret and two the analysis has been told to
    ignore: one under a directory the hand-written sweep skips, one under a
    glob the operator set."""
    (root / "__pycache__").mkdir(parents=True, exist_ok=True)
    (root / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
    (root / "app.env").write_text(f"AWS_ACCESS_KEY_ID={key}\n")
    (root / "__pycache__" / "cached.env").write_text(f"AWS_ACCESS_KEY_ID={key}\n")
    (root / "tests" / "fixtures" / "fake.env").write_text(
        f"AWS_ACCESS_KEY_ID={key}\n")
    return root


def raw_gitleaks(root, config=None):
    """What the tool reports, with and without our configuration -- the
    before/after this task is accepted on."""
    report = root / "gl.json"
    args = ["gitleaks", "dir", ".", "--report-format", "json",
            "--report-path", str(report), "--no-banner", "--exit-code", "0",
            "--log-level", "error"]
    if config is not None:
        args += ["--config", str(config)]
    subprocess.run(args, cwd=str(root), capture_output=True, text=True, check=False)
    found = json.loads(report.read_text()) if report.exists() else []
    report.unlink(missing_ok=True)
    return found


@needs_gitleaks
def test_the_scope_actually_narrows_what_the_engine_reports(tmp_path):
    """THE acceptance test of this change, run against the real binary.

    Gitleaks knows nothing about `_SKIP_DIRS` and nothing about
    `ignore_paths`. If the configuration does not reach it, replacing the
    hand-written scanner makes the report noisier than the thing it replaced
    -- which is the one outcome that would make this task a regression.
    """
    root = plant(tmp_path / "repo")
    before = raw_gitleaks(root)
    config = root / "scope.toml"
    config.write_text(adapters.gitleaks_config(
        root=root, ignore_paths=["tests/fixtures/**"]))
    after = raw_gitleaks(root, config)

    assert len(before) == 3, [f["File"] for f in before]
    assert len(after) == 1, [f["File"] for f in after]
    assert after[0]["File"] == "app.env"


@needs_gitleaks
def test_the_engine_reads_the_history_a_deleted_file_no_longer_has(tmp_path):
    """A credential that was ever committed stays compromised. The
    hand-written sweep reads `git log -p` for exactly this, and the engine
    has to keep doing it or the swap loses the finding whose remediation
    says deleting the file is not enough."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    (root / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "add")
    (root / "prod.env").unlink()
    git(root, "add", "-A")
    git(root, "commit", "-qm", "remove")

    findings, notes = adapters.gitleaks_scan(root)
    assert findings is not None, notes
    historical = [f for f in findings if f["historical"]]
    assert historical, f"the history sweep found nothing: {notes}"
    assert historical[0]["rule"] == "aws-access-token"
    assert historical[0]["occurrences"][0]["file"] == "prod.env"
    assert AWS_KEY not in json.dumps(findings)


@needs_gitleaks
def test_a_root_that_is_not_a_checkout_costs_the_history_not_the_scan(tmp_path):
    """`gitleaks git` on a directory that is not a repository fails. That is
    a gap in the report, not a reason to lose the working-tree findings --
    and it has to be SAID, because "no history findings" and "the history
    was never read" are the same silence otherwise."""
    root = plant(tmp_path / "loose")
    findings, notes = adapters.gitleaks_scan(root)
    assert findings is not None
    assert any(f["rule"] == "aws-access-token" for f in findings)
    assert any("history sweep did not complete" in n for n in notes), notes


def git(root, *args):
    subprocess.run(["git", *args], cwd=str(root), check=True,
                   capture_output=True, text=True)


# ------------------------------------------- the history has to be READABLE
#
# `is_git_checkout` asked git `rev-parse --git-dir` -- "is this a repository"
# -- and every OTHER way of failing to read a history sailed past it. Inside a
# real checkout `gitleaks git` then exits 0, writes `[]`, and is
# indistinguishable from a clean history, while the coverage note goes on
# claiming the full history was scanned. Reproduced on a repository with a
# secret in a deleted file and `.git/objects` emptied: `git log` exits 128
# with "fatal: bad object HEAD", the old guard said True, the finding was
# lost, and the note said it had been looked for.
#
# `history_state` asks whether the history can be WALKED instead. One probe
# per route below, plus the two controls that matter: a healthy repository
# still claims the full history, and a repository with no commits yet is NOT
# reported as a gap -- an unborn history has nothing to miss, and a rule that
# cried gap on every freshly-initialised checkout would be broken the other
# way.

def history_repo(root):
    """A checkout whose only secret is in a file that was later deleted --
    findable in the history and nowhere else, so a history sweep that did not
    really run reports zero and looks clean."""
    root.mkdir(parents=True)
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    (root / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "add")
    (root / "prod.env").unlink()
    git(root, "add", "-A")
    git(root, "commit", "-qm", "remove")
    return root


def break_objects(root):
    """Empty `.git/objects`. The reviewer's own reproduction: the refs still
    name commits, and not one of them can be read."""
    for child in (root / ".git" / "objects").iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    return root


def break_ref(root):
    """Point the checked-out branch at a sha that was never written."""
    head = (root / ".git" / "HEAD").read_text().strip()
    ref = head.split(" ", 1)[1] if head.startswith("ref: ") else "refs/heads/main"
    (root / ".git" / ref).write_text("d" * 40 + "\n")
    return root


def notes_say_history_gap(notes):
    return any("history sweep did not complete" in n for n in notes)


def notes_claim_full_history(notes):
    return any(adapters.FULL_HISTORY in n for n in notes)


@pytest.mark.parametrize("break_it", [break_objects, break_ref],
                         ids=["unreadable-objects", "broken-ref"])
def test_a_history_git_cannot_walk_is_not_a_readable_history(tmp_path, break_it):
    """The unit the guard is built on, asked without any binary at all."""
    root = break_it(history_repo(tmp_path / "repo"))
    state, reason = adapters.history_state(root)
    assert state == adapters.HISTORY_GONE, (state, reason)
    assert reason, "a declared gap has to carry git's own reason"


def test_an_unreadable_git_directory_is_not_a_readable_history(tmp_path):
    root = history_repo(tmp_path / "repo")
    (root / ".git").chmod(0o000)
    try:
        state, _reason = adapters.history_state(root)
    finally:
        (root / ".git").chmod(0o755)
    assert state == adapters.HISTORY_GONE


def test_a_directory_that_is_no_repository_at_all_is_not_a_readable_history(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir()
    assert adapters.history_state(loose)[0] == adapters.HISTORY_GONE


def test_a_shallow_clone_is_readable_but_not_full(tmp_path):
    """Its own state, not a failure: the sweep runs and what it reports is
    real. Only the word "full" has to go."""
    deep = history_repo(tmp_path / "deep")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{deep}",
                    str(shallow)], check=True, capture_output=True, text=True)
    assert adapters.history_state(shallow)[0] == adapters.HISTORY_SHALLOW
    assert adapters.history_state(deep)[0] == adapters.HISTORY_OK


def test_a_repository_with_no_commits_yet_is_a_readable_history(tmp_path):
    """THE containment probe for this whole guard.

    Widening "is there a .git" to "can the history be walked" is a widening,
    and the nearest thing on the other side of the new boundary is a
    repository that was just `git init`-ed. `git log` fails there ("does not
    have any commits yet") -- so a guard written on `git log`'s return code
    would declare a history gap on every new checkout, a blind spot that does
    not exist. `rev-list --all` exits 0 with empty output instead, which is
    the honest answer: the history is readable and there is none of it.
    """
    root = tmp_path / "fresh"
    root.mkdir()
    git(root, "init", "-q")
    (root / "app.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    assert adapters.history_state(root)[0] == adapters.HISTORY_OK


@needs_gitleaks
@pytest.mark.parametrize("break_it", [break_objects, break_ref],
                         ids=["unreadable-objects", "broken-ref"])
def test_an_unreadable_history_is_a_declared_gap_not_a_clean_report(tmp_path,
                                                                   break_it):
    """The end-to-end shape of the regression, through the real binary.

    Before the fix: `gitleaks git` exits 0 with `[]`, the history finding is
    lost, and the note says "over the working tree and the full git history".
    A reader cannot tell that from a repository whose history is genuinely
    clean -- which is the exact silence `secrets.scan_history` was fixed for,
    reopened through a neighbouring door.
    """
    root = break_it(history_repo(tmp_path / "repo"))
    findings, notes = adapters.gitleaks_scan(root)
    assert findings is not None, notes
    assert notes_say_history_gap(notes), notes
    assert not notes_claim_full_history(notes), notes


@needs_gitleaks
def test_a_shallow_clone_never_claims_the_full_history(tmp_path):
    """A depth-1 clone carries one commit. `gitleaks git` reads exactly that,
    reports nothing, and exits 0 -- and the note used to call it the full
    history. Verified: the deleted-file secret is genuinely absent here."""
    deep = history_repo(tmp_path / "deep")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{deep}",
                    str(shallow)], check=True, capture_output=True, text=True)
    findings, notes = adapters.gitleaks_scan(shallow)
    assert findings is not None, notes
    assert not notes_claim_full_history(notes), notes
    assert any("shallow clone" in n for n in notes), notes


@needs_gitleaks
def test_a_readable_history_still_says_it_read_the_full_history(tmp_path):
    """The control for every probe above. The fix widened what counts as a
    gap, and a guard that now declares one everywhere would be broken the
    other way -- silently, because a gap note reads like diligence."""
    root = history_repo(tmp_path / "repo")
    findings, notes = adapters.gitleaks_scan(root)
    assert findings is not None, notes
    assert [f for f in findings if f["historical"]], f"the finding is gone: {notes}"
    assert notes_claim_full_history(notes), notes
    assert not notes_say_history_gap(notes), notes
    assert not any("shallow clone" in n for n in notes), notes


@needs_gitleaks
def test_a_repository_with_no_commits_declares_no_history_gap(tmp_path):
    """The containment probe again, this time through the whole scan: a
    freshly-initialised checkout must not be told its history is a blind
    spot."""
    root = plant(tmp_path / "fresh")
    git(root, "init", "-q")
    findings, notes = adapters.gitleaks_scan(root)
    assert findings is not None, notes
    assert any(f["rule"] == "aws-access-token" for f in findings)
    assert not notes_say_history_gap(notes), notes


@needs_gitleaks
def test_an_unreadable_history_still_keeps_the_working_tree_findings(tmp_path):
    """A gap in one half is not a reason to lose the other half."""
    root = break_objects(history_repo(tmp_path / "repo"))
    (root / "app.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    findings, notes = adapters.gitleaks_scan(root)
    assert findings is not None, notes
    assert any(not f["historical"] and f["occurrences"][0]["file"] == "app.env"
               for f in findings), findings
    assert notes_say_history_gap(notes), notes


def test_when_neither_pass_ran_both_reasons_are_reported(monkeypatch, tmp_path):
    """`history_note` used to be dropped on the floor here: when both passes
    failed only the TREE's sentence was appended, so a run whose history was
    unreadable AND whose tree pass could not run reported one of the two
    faults -- whichever happened to be second."""
    root = break_objects(history_repo(tmp_path / "repo"))
    # The tree pass fails for its own, different reason.
    monkeypatch.setattr(engines, "run_json",
                        lambda *a, **k: (None, "gitleaks is not installed."))
    findings, notes = adapters.gitleaks_scan(root)
    assert findings is None, findings
    blob = " ".join(notes)
    assert "not installed" in blob, notes
    assert "fatal" in blob or "history" in blob, notes


def test_neither_pass_ran_says_one_reason_once(monkeypatch, tmp_path):
    """The containment side: the commonest failure by far is the binary being
    absent, which fails BOTH passes with the identical sentence. Saying it
    twice reads like two separate faults."""
    root = history_repo(tmp_path / "repo")
    monkeypatch.setattr(engines, "run_json",
                        lambda *a, **k: (None, "gitleaks is not installed."))
    _findings, notes = adapters.gitleaks_scan(root)
    assert notes.count("gitleaks is not installed.") == 1, notes


# ------------------------------------- the analysed repository's own config

@needs_gitleaks
def test_a_project_config_that_silences_the_scan_is_declared(tmp_path):
    """`gitleaks_config` extends the analysed project's own `.gitleaks.toml`,
    which is gitleaks' own default and is a defensible decision. The
    over-claim was not: a repository can write an allowlist matching
    everything and turn the whole secret phase off, and the note went on
    saying the tree and the history were scanned.

    Measured both ways here, in one test, so the pair cannot drift: the same
    tree with and without the file, and the note has to tell them apart.
    """
    root = plant(tmp_path / "repo")
    loud, loud_notes = adapters.gitleaks_scan(root)
    assert loud, "the planted tree must be noisy without the project's config"
    assert not any("gitleaks.toml" in n for n in loud_notes), loud_notes

    (root / ".gitleaks.toml").write_text(
        "[extend]\nuseDefault = true\n\n"
        "[allowlist]\nregexes = ['''.*''']\npaths = ['''.*''']\n")
    quiet, quiet_notes = adapters.gitleaks_scan(root)
    assert quiet == [], f"the project's own allowlist should have silenced it: {quiet}"
    assert any("gitleaks.toml" in n for n in quiet_notes), (
        f"a repository that told the scanner not to look must be declared, "
        f"otherwise 'we found nothing' and 'we were told not to look' read "
        f"identically: {quiet_notes}")


def test_the_config_note_names_the_file_that_was_actually_extended(tmp_path):
    """The note and the config read the same file through one function, so a
    note claiming an extension that did not happen is not expressible."""
    root = tmp_path / "repo"
    root.mkdir()
    assert adapters.project_config(root) is None
    assert "useDefault = true" in adapters.gitleaks_config(root=root)

    own = root / ".gitleaks.toml"
    own.write_text("[extend]\nuseDefault = true\n")
    assert adapters.project_config(root) == own
    assert str(own) in adapters.gitleaks_config(root=root)


# ------------------------------------------------------- one engine, or none

def open_analysis(db):
    return cli_json(db, "open-analysis", "--project", "web", "--repo", "web",
                    "--branch", "main", "--commit", "abc", "--profile", "quick",
                    "--run-id", "r1")["analysis_id"]


def cli_json(db, *args, env=None):
    out = subprocess.run([sys.executable, str(CLI), *args, "--db", str(db)],
                         capture_output=True, text=True, check=False, env=env)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout) if out.stdout.strip() else None


def prepare(tmp_path, engines_on):
    """`prepare` over a planted tree, with the engines switched on or off."""
    root = plant(tmp_path / f"repo-{engines_on}")
    db = tmp_path / f"security-{engines_on}.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "on" if engines_on else "off"}
    aid = open_analysis(db)
    note = cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
                    "--offline", env=env)["coverage_note"]
    return cli_json(db, "findings", "--analysis", str(aid), env=env), note


@needs_gitleaks
def test_prepare_runs_the_engine_and_not_the_hand_written_scanner(tmp_path):
    """Two engines in one category report one hole under two fingerprints,
    and the checklist then shows the same secret as two entries that
    contradict each other. Whichever scanner runs, it runs alone."""
    findings, note = prepare(tmp_path, engines_on=True)
    secret_rules = {f["rule"] for f in findings if f["category"] == "secret"}
    assert secret_rules == {"aws-access-token"}, secret_rules
    assert "aws_access_key" not in secret_rules
    assert "gitleaks" in note


@needs_gitleaks
def test_the_engine_obeys_the_ignore_paths_prepare_was_given(tmp_path):
    """`ignore_paths` is a promise about the ANALYSIS. It reached the tree
    sweep, the history sweep and the hygiene pass; it has to reach the
    engine too, or the operator sets the option and gets the noise anyway
    one report later.

    The POSITIVE CONTROL comes first, and it is the half that makes the
    assertion mean anything: `== []` on its own passes identically on the
    fallback path, on a broken engine, and on an analysis that scanned
    nothing at all. The same tree, same engine, no globs, must be noisy --
    and noisy with the ENGINE's rule id, which is what proves the engine ran.
    """
    root = plant(tmp_path / "repo")
    db = tmp_path / "security.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "on"}

    loud = open_analysis(db)
    cli_json(db, "prepare", "--analysis", str(loud), "--root", str(root),
             "--offline", env=env)
    noisy = [f for f in cli_json(db, "findings", "--analysis", str(loud), env=env)
             if f["category"] == "secret"]
    assert {f["rule"] for f in noisy} == {"aws-access-token"}, noisy
    # `plant` writes three copies of one key. Two survive without the globs --
    # the third is under `__pycache__`, which SKIP_DIRS excludes on every run.
    assert {f["occurrences"][0]["file"] for f in noisy} == {
        "app.env", "tests/fixtures/fake.env"}, noisy

    quiet = open_analysis(db)
    cli_json(db, "prepare", "--analysis", str(quiet), "--root", str(root),
             "--offline", "--ignore", "app.env,tests/fixtures/**", env=env)
    findings = cli_json(db, "findings", "--analysis", str(quiet), env=env)
    assert [f for f in findings if f["category"] == "secret"] == []


# ---------------------------------------- the lifecycle, on BOTH scanner paths
#
# Three properties this project already holds the built-in scanner to
# (tests/security/test_cli.py, "the history sweep, every run") had no
# engine-path equivalent, and tests/security/conftest.py pins the whole suite
# to CC_SECURITY_ENGINES=off -- so on a machine with gitleaks installed, which
# is production going forward, the suite proved none of them.
#
# The third one is the reason this is not merely tidiness. "The tree reading
# wins over its history twin" is guaranteed ONLY by the order of the two
# `run_json` calls in adapters.gitleaks_scan: swap those two lines and every
# co-located secret becomes a report about the past, with nothing red
# anywhere. Parametrised over both scanners, both orders are now pinned.

ENGINE_MATRIX = [False, pytest.param(True, marks=needs_gitleaks)]


def analysis_with(db, root, engines_on, aid=None):
    """One `prepare` over `root` with the scanner switched explicitly."""
    env = {**os.environ, "CC_SECURITY_ENGINES": "on" if engines_on else "off"}
    aid = open_analysis(db) if aid is None else aid
    cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
             "--offline", env=env)
    return aid, env


def secret_states(db, aid, env):
    checklist = cli_json(db, "checklist", "--analysis", str(aid), env=env)
    return {f["state"] for f in checklist["findings"] if f["category"] == "secret"}


@pytest.mark.parametrize("engines_on", ENGINE_MATRIX)
def test_a_history_secret_stays_open_on_either_scanner(tmp_path, engines_on):
    """THE scenario the history sweep exists for, now on both paths.

    A key was committed on Monday and the file deleted on Tuesday. It must
    stay OPEN run after run -- never `fixed`, which would congratulate the
    operator for the exact act the finding's own remediation calls
    insufficient.
    """
    root = history_repo(tmp_path / f"repo-{engines_on}")
    db = tmp_path / f"life-{engines_on}.db"

    first, env = analysis_with(db, root, engines_on)
    cli_json(db, "finish", "--analysis", str(first), "--state", "done", env=env)
    assert secret_states(db, first, env) == {"new"}

    second, _ = analysis_with(db, root, engines_on)
    cli_json(db, "finish", "--analysis", str(second), "--state", "done", env=env)
    assert secret_states(db, second, env) == {"open"}

    third, _ = analysis_with(db, root, engines_on)
    cli_json(db, "finish", "--analysis", str(third), "--state", "done", env=env)
    assert secret_states(db, third, env) == {"open"}

    carried = cli_json(db, "findings", "--analysis", str(third), env=env)
    assert any("git history" in f["rationale"] for f in carried), carried
    assert AWS_KEY not in json.dumps(carried)


@pytest.mark.parametrize("engines_on", ENGINE_MATRIX)
def test_rotating_and_accepting_closes_it_on_either_scanner(tmp_path, engines_on):
    """The other half of the lifecycle. Because the sweep never stops finding
    it, the only honest close is a human saying the credential was rotated --
    and that decision has to win over the derived `open` on both paths."""
    root = history_repo(tmp_path / f"repo-{engines_on}")
    db = tmp_path / f"close-{engines_on}.db"

    first, env = analysis_with(db, root, engines_on)
    secret = [f for f in cli_json(db, "findings", "--analysis", str(first), env=env)
              if f["category"] == "secret"]
    assert len(secret) == 1, secret
    cli_json(db, "finish", "--analysis", str(first), "--state", "done", env=env)
    cli_json(db, "decide", "--project", "web",
             "--fingerprint", secret[0]["fingerprint"], "--state", "accepted",
             "--reason", "rotated at the provider on Tuesday", env=env)

    second, _ = analysis_with(db, root, engines_on)
    cli_json(db, "finish", "--analysis", str(second), "--state", "done", env=env)
    assert secret_states(db, second, env) == {"accepted"}


@pytest.mark.parametrize("engines_on", ENGINE_MATRIX)
def test_the_tree_reading_wins_over_its_history_twin_on_either_scanner(
        tmp_path, engines_on):
    """A secret in the tree AND in the history is ONE finding: same rule, same
    path, therefore one fingerprint, and `record_finding` upserts.

    The two readings disagree, and the tree's is the one a reader can act on:
    it says "in the working tree" and carries the line the secret is on RIGHT
    NOW, where the history's says "in the git history" and points into a
    commit. So the history is recorded FIRST and the tree wins the upsert.

    On the engine path that ordering is two adjacent lines in
    `adapters.gitleaks_scan` and nothing else. This is the test that fails if
    they are ever swapped -- the wording AND the line number, because a
    history reading of a co-located secret carries a plausible-looking line
    of its own and asserting only on the line would not catch the swap.
    """
    root = tmp_path / f"repo-{engines_on}"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    # Two lines of padding, so the tree's line number (3) is one no history
    # reading of this file would produce by coincidence.
    (root / "prod.env").write_text(f"# header\n# header\nAWS_ACCESS_KEY_ID={AWS_KEY}\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "add")

    aid, env = analysis_with(db := tmp_path / f"twin-{engines_on}.db", root,
                             engines_on)
    secret = [f for f in cli_json(db, "findings", "--analysis", str(aid), env=env)
              if f["category"] == "secret"]
    assert len(secret) == 1, "the tree and history readings must be one row"
    assert "in the working tree" in secret[0]["rationale"], secret[0]["rationale"]
    assert "git history" not in secret[0]["rationale"], secret[0]["rationale"]
    assert [o["line"] for o in secret[0]["occurrences"]] == [3], secret[0]


def test_prepare_falls_back_to_the_hand_written_scanner_and_says_which_ran(tmp_path):
    """The other half. With no engine the analysis still scans for secrets,
    and the coverage note names the scanner that did it: eight shaped rules
    is a different claim from an engine's full rule set, and a reader
    judging the report's blind spots needs to know which they got."""
    findings, note = prepare(tmp_path, engines_on=False)
    secret_rules = {f["rule"] for f in findings if f["category"] == "secret"}
    assert secret_rules == {"aws_access_key"}, secret_rules
    assert "built-in pattern scanner" in note


def test_prepare_still_counts_the_lines_it_analysed(tmp_path):
    """`lines_of_code` is a by-product of the hand-written sweep's read. An
    engine that does the scanning instead must not cost the project header
    its size -- it renders `0` as an em dash, indistinguishable from an
    analysis that predates the column."""
    import sqlite3
    for engines_on in ((True, False) if HAVE_GITLEAKS else (False,)):
        root = plant(tmp_path / f"repo-loc-{engines_on}")
        db = tmp_path / f"loc-{engines_on}.db"
        env = {**os.environ, "CC_SECURITY_ENGINES": "on" if engines_on else "off"}
        aid = open_analysis(db)
        cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
                 "--offline", env=env)
        conn = sqlite3.connect(str(db))
        lines = conn.execute("SELECT lines_of_code FROM analysis WHERE id=?",
                             (aid,)).fetchone()[0]
        conn.close()
        assert lines > 0, f"engines_on={engines_on}"


def test_the_engines_can_be_switched_off_without_uninstalling_them(monkeypatch):
    """An off switch that does not depend on `PATH`. A parser is written
    against a format; when an engine's output stops matching it, the
    operator needs a way to fall back that does not involve removing a
    binary other tools on the machine share.

    Checked for both engines this module knows about: the switch is a
    single environment variable read by `engine_path` itself, not something
    each caller has to wire up on its own."""
    monkeypatch.setenv("CC_SECURITY_ENGINES", "off")
    assert adapters.engine_path("gitleaks") is None
    assert adapters.engine_path("trivy") is None
    monkeypatch.setenv("CC_SECURITY_ENGINES", "on")
    assert (adapters.engine_path("gitleaks") is not None) == HAVE_GITLEAKS
    assert (adapters.engine_path("trivy") is not None) == HAVE_TRIVY
    monkeypatch.delenv("CC_SECURITY_ENGINES")
    assert (adapters.engine_path("gitleaks") is not None) == HAVE_GITLEAKS
    assert (adapters.engine_path("trivy") is not None) == HAVE_TRIVY


# ------------------------------------------------------- the dependency scan
#
# Trivy replaces `deps.inventory` + `osv.query` on the same terms the
# Gitleaks section above replaces the built-in secret sweep: THE VALUE NEVER
# ARRIVES is not at stake here (a CVE id is public, not a secret), but THE
# IDENTITY IS OURS still is. `osv._finding` already had the recipe --
# `fingerprint("dependency", vuln_id, source, f"{name}@{version}")` -- before
# Trivy existed in this module, and `trivy_vulns` has to build the identical
# hash for the identical (CVE, package, version) or every dependency finding
# OSV.dev ever reported grows a second identity the moment Trivy reports it
# too, orphaning whatever a human decided about the first one.

def test_trivy_vulnerabilities_become_dependency_findings():
    data = json.loads((FIX / "trivy-fs.json").read_text())
    out = adapters.trivy_vulns(data)
    assert out
    f = out[0]
    assert f["category"] == "dependency"
    assert f["severity"] in ("critical", "high", "medium", "low", "info")


def test_a_cve_without_a_published_fix_is_marked_not_hidden():
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x",
            "InstalledVersion": "1.0", "Severity": "HIGH", "Status": "affected",
            "Title": "t"}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert "no fixed version" in f["remediation"].lower()


def test_the_severity_words_map_to_ours():
    for trivy, ours in (("CRITICAL", "critical"), ("HIGH", "high"),
                        ("MEDIUM", "medium"), ("LOW", "low"),
                        ("UNKNOWN", "medium")):
        data = {"Results": [{"Target": "t", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
             "Severity": trivy, "Title": "t"}]}]}
        assert adapters.trivy_vulns(data)[0]["severity"] == ours


def test_the_default_severity_is_osvs_own_not_a_second_one_invented_here():
    """`UNKNOWN` above is one way to reach the default; a `Severity` word
    Trivy has never sent before (a future release, a distro-specific grade)
    is another. Both have to fall on the exact constant `osv.py` already
    uses -- not a fresh "medium" typed a second time here -- or the two
    sources start disagreeing about what an unassessed CVE is worth."""
    data = {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
         "Title": "t"}]}]}  # no Severity at all
    assert adapters.trivy_vulns(data)[0]["severity"] == osv.DEFAULT_SEVERITY


def test_the_fingerprint_matches_osvs_own_recipe():
    data = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-1", "PkgName": "requests",
         "InstalledVersion": "2.31.0", "Severity": "HIGH", "Title": "t"}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert f["fingerprint"] == fingerprint.fingerprint(
        "dependency", "CVE-2024-1", "requirements.txt", "requests@2.31.0")


def test_cwe_ids_become_the_findings_cwe_field():
    """The dependency category has no closed vocabulary -- its rule is the
    CVE id -- so `CweIDs` is metadata to carry, not something to validate
    against a table the way `taxonomy.py` does for SAST rules."""
    data = {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t", "CweIDs": ["CWE-94", "CWE-77"]}]}]}
    assert adapters.trivy_vulns(data)[0]["cwe"] == "CWE-94, CWE-77"


def test_a_vulnerability_with_no_cwe_ids_leaves_the_field_unset():
    """`CweIDs` may be an empty list or absent altogether -- both are Trivy
    telling us nothing was classified, not a parser failure, so nothing
    fabricates a value the report would then have to explain."""
    data = {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t", "CweIDs": []},
        {"VulnerabilityID": "CVE-2", "PkgName": "y", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t"}]}]}
    for f in adapters.trivy_vulns(data):
        assert "cwe" not in f


def test_a_record_missing_a_required_field_is_dropped_not_fatal():
    """No id, no package name, no installed version: this parser cannot
    build an identity for any of the three, and a malformed record must cost
    only itself, not the whole dependency phase."""
    data = {"Results": [{"Target": "t", "Vulnerabilities": [
        {"PkgName": "x", "InstalledVersion": "1", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-1", "InstalledVersion": "1", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2", "PkgName": "x", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-3", "PkgName": "x", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t"},
    ]}]}
    out = adapters.trivy_vulns(data)
    assert [f["rule"] for f in out] == ["CVE-3"]


def test_a_result_without_a_target_is_dropped():
    data = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t"}]}]}
    assert adapters.trivy_vulns(data) == []


def test_a_report_that_is_not_an_object_is_no_findings_not_a_crash():
    for bogus in ([], "not json", None, 42):
        assert adapters.trivy_vulns(bogus) == []


def test_results_that_is_not_a_list_is_no_findings_not_a_crash():
    assert adapters.trivy_vulns({"Results": "nope"}) == []


def test_a_result_that_is_not_an_object_is_skipped_not_fatal():
    data = {"Results": [None, "nope", {"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t"}]}]}
    assert [f["rule"] for f in adapters.trivy_vulns(data)] == ["CVE-1"]


def test_a_result_with_no_vulnerabilities_is_not_an_error():
    """The shape a lockfile with nothing wrong in it actually produces: a
    `Target` and a `Packages` list, no `Vulnerabilities` key at all."""
    data = json.loads((FIX / "trivy-fs.json").read_text())
    composer = next(r for r in data["Results"] if r["Target"] == "composer.lock")
    assert "Vulnerabilities" not in composer
    assert adapters.trivy_vulns({"Results": [composer]}) == []


@needs_trivy
def test_trivy_scan_runs_the_real_engine_and_finds_a_known_cve(tmp_path):
    """The one test in this section that runs the actual binary, the same
    way the Gitleaks section above does for secrets. `package-lock.json`
    here is this repository's own fixture -- lodash 4.17.20, which carries
    CVE-2021-23337 -- copied alone into an empty tree so the result cannot
    be confused with anything else Trivy might find scanning this repo."""
    root = tmp_path / "repo"
    root.mkdir()
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (root / "package-lock.json").write_text(lockfile.read_text())
    findings, notes = adapters.trivy_scan(root)
    assert findings is not None
    rules = {f["rule"] for f in findings}
    assert "CVE-2021-23337" in rules
    assert any(f["occurrences"][0]["file"] == "package-lock.json" for f in findings)
    assert any("trivy" in n.lower() for n in notes)


@needs_trivy
def test_trivy_scan_reports_no_findings_when_there_is_nothing_to_scan(tmp_path):
    """An empty tree is a real report with an empty `Results`, not a failure
    -- `findings` must be `[]`, never `None`, so `_scan_dependencies` does
    not mistake "found nothing" for "the engine could not run" and fall back
    to OSV.dev on top of a Trivy pass that already completed."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    findings, notes = adapters.trivy_scan(root)
    assert findings == []
    assert any("trivy" in n.lower() for n in notes)


@needs_trivy
def test_trivy_scan_skips_the_same_directories_deps_inventory_always_has(tmp_path):
    """`deps.inventory` never reads inside `secrets.SKIP_DIRS` (`node_modules`,
    `vendor`, ...). Swapping to the engine must not start reporting a
    vendored copy of a vulnerable lockfile the built-in inventory always
    ignored -- that would make the report NOISIER for what is supposed to be
    a like-for-like swap, the exact regression `adapters.py`'s own module
    docstring warns about for Gitleaks."""
    root = tmp_path / "repo"
    root.mkdir()
    vendored = root / "node_modules" / "some-dep"
    vendored.mkdir(parents=True)
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (vendored / "package-lock.json").write_text(lockfile.read_text())
    findings, _ = adapters.trivy_scan(root)
    assert findings == []
