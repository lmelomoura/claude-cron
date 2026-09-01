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

from security import (adapters, deps, engines, fingerprint, ignores, osv,
                      report, secrets, taxonomy)
from security import cli as security_cli

FIX = Path(__file__).parent / "fixtures" / "engines"
REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"

HAVE_GITLEAKS = engines.find("gitleaks") is not None
needs_gitleaks = pytest.mark.skipif(
    not HAVE_GITLEAKS, reason="gitleaks is not installed on this machine")

HAVE_TRIVY = engines.find("trivy") is not None
needs_trivy = pytest.mark.skipif(
    not HAVE_TRIVY, reason="trivy is not installed on this machine")

HAVE_SYFT = engines.find("syft") is not None
needs_syft = pytest.mark.skipif(
    not HAVE_SYFT, reason="syft is not installed on this machine")

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


# ------------------------------------------------- the default noise filter
#
# The ENGINE half of Task 7. Every assertion here has a twin in
# test_secrets.py driving the same case through the built-in scanner: a
# default only one of the two honours is a repository whose report changes
# with whichever binaries the machine happens to have, which is the
# per-machine divergence this block has already had to fix twice.

def test_the_engine_drops_a_fixture_finding_with_no_ignore_paths_set():
    data = [{"RuleID": "aws-access-token", "File": "tests/fixtures/fake.env",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "pkg/testdata/dump.env",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "app.env", "StartLine": 1}]
    out = adapters.gitleaks(data, root=".")
    assert [f["occurrences"][0]["file"] for f in out] == ["app.env"]


def test_the_engine_drops_a_secret_reported_from_a_sample_file():
    """A4.14 on the engine path. Gitleaks has no idea that `.env.example` is
    a template, and the file-level rule has to be ours on both paths or the
    same `.env.example` is a finding on one laptop and not on the next."""
    data = [{"RuleID": "aws-access-token", "File": ".env.example",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "k8s/values.yaml.template",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": "app.env", "StartLine": 1}]
    out = adapters.gitleaks(data, root=".")
    assert [f["occurrences"][0]["file"] for f in out] == ["app.env"]


def test_the_engine_reports_them_again_once_the_project_turns_the_default_off():
    data = [{"RuleID": "aws-access-token", "File": "tests/fixtures/fake.env",
             "StartLine": 1},
            {"RuleID": "aws-access-token", "File": ".env.example",
             "StartLine": 1}]
    out = adapters.gitleaks(data, root=".", ignore_paths=[ignores.DEFAULTS_OFF])
    assert sorted(f["occurrences"][0]["file"] for f in out) == [
        ".env.example", "tests/fixtures/fake.env"]


def test_the_scope_config_carries_the_default_fixture_directories():
    """The cheap way round, so the engine never reads them at all. It is not
    the guarantee -- `gitleaks()` filters what comes back regardless -- but
    an engine that reads them anyway is engine time spent on findings this
    analysis is going to throw away."""
    toml = adapters.gitleaks_config()
    for directory in ignores.DEFAULT_IGNORE_DIRS:
        assert directory in toml, directory
    assert "example" in toml


def test_the_scope_config_drops_the_defaults_when_the_project_turns_them_off():
    """Otherwise the engine's command line would go on suppressing what the
    operator just asked to see -- a decision undone by a pre-filter."""
    toml = adapters.gitleaks_config(ignore_paths=[ignores.DEFAULTS_OFF])
    assert "testdata" not in toml
    assert "example" not in toml


def test_the_engine_pre_filters_all_carry_the_default_fixture_directories():
    """Three engines, three command-line dialects, one scope. Trivy needs the
    bare name AND `**/name` (its bare name matches the top level only);
    semgrep matches either form at any depth."""
    for name in ignores.DEFAULT_IGNORE_DIRS:
        assert f"**/{name}" in adapters.trivy_skip_dirs()
        assert f"**/{name}" in adapters.semgrep_excludes()


# ------------------------------------------- the scope, against the real tool

def plant(root, key=AWS_KEY):
    """A tree with one real secret and two the analysis has been told to
    ignore: one under a directory the hand-written sweep skips, one under a
    glob the operator set.

    `tests/planted/`, NOT `tests/fixtures/`, which is what this helper used
    to write. `ignores.DEFAULT_IGNORE_DIRS` now suppresses a `fixtures`
    directory with no configuration at all, so the operator-glob half of
    every test below would have gone on passing with `ignore_paths` deleted
    -- the vacuous positive. The default's own coverage is up in "the default
    noise filter"; this helper is for the globs."""
    (root / "__pycache__").mkdir(parents=True, exist_ok=True)
    (root / "tests" / "planted").mkdir(parents=True, exist_ok=True)
    (root / "app.env").write_text(f"AWS_ACCESS_KEY_ID={key}\n")
    (root / "__pycache__" / "cached.env").write_text(f"AWS_ACCESS_KEY_ID={key}\n")
    (root / "tests" / "planted" / "fake.env").write_text(
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
        root=root, ignore_paths=["tests/planted/**"]))
    after = raw_gitleaks(root, config)

    assert len(before) == 3, [f["File"] for f in before]
    assert len(after) == 1, [f["File"] for f in after]
    assert after[0]["File"] == "app.env"


@needs_gitleaks
def test_the_default_narrows_the_real_engine_with_nothing_configured(tmp_path):
    """The acceptance test of TASK 7, against the real binary and with an
    EMPTY `ignore_paths` -- which is what almost every project actually has.

    Both halves of the default in one tree: a fixtures directory, and a
    committed template of a configuration file. Gitleaks reports all three
    keys; the analysis reports the one that is really a leak. The `before`
    half is the control -- `== ["app.env"]` on its own would pass on an
    engine that had crashed and reported nothing at all."""
    root = tmp_path / "repo"
    (root / "tests" / "fixtures").mkdir(parents=True)
    (root / "app.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    (root / "tests" / "fixtures" / "fake.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    (root / ".env.example").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")

    assert len(raw_gitleaks(root)) == 3, "the tree must be noisy to the engine"

    loud, _ = adapters.gitleaks_scan(root, [ignores.DEFAULTS_OFF])
    assert sorted(f["occurrences"][0]["file"] for f in loud) == [
        ".env.example", "app.env", "tests/fixtures/fake.env"], loud

    quiet, notes = adapters.gitleaks_scan(root)
    assert [f["occurrences"][0]["file"] for f in quiet] == ["app.env"], quiet
    assert notes, "the scan still has to describe itself"


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


def test_a_git_too_old_to_answer_still_does_not_claim_the_full_history(
        tmp_path, monkeypatch):
    """`rev-parse --is-shallow-repository` landed in git 2.15, and `rev-parse`
    ECHOES a dashed argument it does not know rather than failing -- so on an
    older git the question comes back as its own text, exit 0. Read as "not
    true", that silently votes for HISTORY_OK, and HISTORY_OK is what makes
    the coverage note promise "the full git history": the one machine that
    cannot answer would be the one making the strongest claim.

    Simulated by intercepting exactly that one question, which is what an old
    git changes and all it changes; every other `git` call is the real one.
    """
    deep = history_repo(tmp_path / "deep")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{deep}",
                    str(shallow)], check=True, capture_output=True, text=True)

    real = adapters._git

    def old_git(root, *args):
        if args[:2] == ("rev-parse", "--is-shallow-repository"):
            # Verbatim pre-2.15 behaviour: the flag echoed back, exit 0.
            return subprocess.CompletedProcess(
                args=list(args), returncode=0,
                stdout="--is-shallow-repository\n", stderr="")
        return real(root, *args)

    monkeypatch.setattr(adapters, "_git", old_git)

    # The marker file inside the git directory is the fallback, and it is as
    # old as the feature -- so the answer is unchanged on both repositories.
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
        "app.env", "tests/planted/fake.env"}, noisy

    quiet = open_analysis(db)
    cli_json(db, "prepare", "--analysis", str(quiet), "--root", str(root),
             "--offline", "--ignore", "app.env,tests/planted/**", env=env)
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
# RECORDING blocks in adapters.gitleaks_scan -- the `if history is None:` /
# `if tree is None:` pair that appends each report to `findings`: swap those
# two blocks and every co-located secret becomes a report about the past, with
# nothing red anywhere. Not the two `run_json` calls above them, which this
# comment used to name: each writes to its own temp report file and neither
# touches `findings`, so swapping them is a measured no-op the whole suite
# passes. Parametrised over both scanners, both orders are now pinned.

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

    On the engine path that ordering is the two RECORDING blocks in
    `adapters.gitleaks_scan` -- the `if history is None:` / `if tree is None:`
    pair that appends each report to `findings` -- and nothing else. This is
    the test that fails if they are ever swapped (verified: swapping them
    fails this test's engine parametrisation on the rationale assertion
    below). It is specifically NOT the two `run_json` calls above them, which
    the comments here used to point at: they write to separate temp files and
    swapping them passes the whole suite.

    Asserts the wording AND the line number, because a history reading of a
    co-located secret carries a plausible-looking line of its own and
    asserting only on the line would not catch the swap.
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
    """THE RECIPE ONLY. This test hand-writes the inputs and re-derives the
    formula from the same literals, so it cannot fail while the recipe is
    copied correctly -- and copying the recipe was never the hard part. What
    the INPUTS to it are is checked by
    `test_both_producers_mint_the_same_identity_for_one_package` below, which
    runs both producers over one real tree instead of typing the answer."""
    data = {"Results": [{"Target": "requirements.txt", "Type": "pip",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-1", "PkgName": "requests",
         "InstalledVersion": "2.31.0", "Severity": "HIGH", "Title": "t"}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert f["fingerprint"] == fingerprint.fingerprint(
        "dependency", "CVE-2024-1", "requirements.txt", "requests@2.31.0")


# ------------------------------------------- the identity, input by input
#
# The recipe was copied correctly and the INPUTS TO IT were not, which is a
# different bug with the same consequence: the same vulnerability gets a
# different identity depending on whether Trivy happens to be installed. Each
# affected finding is then reported `fixed` (its old identity is gone) AND
# `new` (a fresh one appeared) in one report, and the human
# `accepted`/`false_positive` decision against the old one strands for good --
# `ledger._REFINGERPRINT` has no `dependency` entry, so `rename_rule` refuses
# the category outright and there is no migration path to write.

# A composer.lock whose one vulnerable package carries the `v` prefix that is
# the Packagist NORM (Symfony, Doctrine, Monolog, most of Laravel), plus a Go
# module -- the two ecosystems where `deps.py` normalises and Trivy does not.
_COMPOSER_LOCK = json.dumps({
    "packages": [{"name": "symfony/http-kernel", "version": "v5.4.0"}],
    "packages-dev": [],
})
_GO_MOD = "module example.com/proof\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.3\n"
_GO_SUM = (
    "github.com/gin-gonic/gin v1.6.3 h1:ahKqKTFpO5KTPHxWZjEdPScmYaGtLo8Y4DMHoEsnp14=\n"
    "github.com/gin-gonic/gin v1.6.3/go.mod h1:75u5sXoLsGZoRN5Sgbi1eraJ4GU3++wFwWzhwvtwp4M=\n")


def _v_prefixed_tree(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "composer.lock").write_text(_COMPOSER_LOCK)
    (root / "go.mod").write_text(_GO_MOD)
    (root / "go.sum").write_text(_GO_SUM)
    return root


@needs_trivy
def test_both_producers_mint_the_same_identity_for_one_package(tmp_path):
    """BOTH PRODUCERS, ONE TREE, COMPARED AS SETS.

    `deps.inventory` + `osv._finding` on one side, `trivy_scan` on the other,
    over a tree carrying the two shapes that used to diverge: a Packagist
    package pinned `v5.4.0` and a Go module. No network: OSV's identity for
    an advisory is minted by `osv._finding` itself, from the component
    `deps.inventory` actually produced, and compared against the identity
    Trivy's own report produced for the same advisory.

    Measured before the fix, on this exact tree:
        symfony/http-kernel  osv='5.4.0'  trivy='v5.4.0'   -> two identities
        gin-gonic/gin        osv source='go.sum'  trivy source='go.mod'
                             osv='1.6.3'          trivy='v1.6.3'
    Zero of the four Trivy findings shared an identity with OSV's recipe.
    """
    root = _v_prefixed_tree(tmp_path)
    components = deps.inventory(root)
    by_name = {c["name"]: c for c in components}
    findings, notes = adapters.trivy_scan(root)
    assert findings, "trivy found nothing to compare -- the fixture is stale"

    # What OSV.dev's producer WOULD have minted for each advisory Trivy
    # named, from its own component and its own function.
    expected = set()
    for f in findings:
        component = by_name.get(f["title"].split(" ", 1)[0])
        assert component is not None, (
            f"{f['title']} names a package deps.inventory never saw")
        expected.add(osv._finding(component, f["rule"], None)["fingerprint"])
    assert {f["fingerprint"] for f in findings} == expected

    # The advisory id was the input this test used to call unfixable. It is
    # not: Trivy's own record carries the publishing database's id, so what
    # gets hashed here is the GHSA OSV.dev would have named, not the CVE
    # OSV.dev never uses. See `test_the_advisory_id_is_osvs_own_when_trivy_
    # publishes_it` for the alias itself.
    assert [f["rule"] for f in findings if f["rule"].startswith("GHSA-")], (
        [f["rule"] for f in findings])
    # What remains is DECLARED rather than left for a reader to discover from
    # a diff full of fixed/new pairs: OSV.dev also mints GO-2021-0052 and
    # GO-2023-1737 for this same gin, and no alias can conjure a Trivy
    # counterpart for a record Trivy never split out.
    assert adapters.DEP_ID_NOTE in notes, notes


def test_the_composer_v_prefix_is_stripped_the_way_deps_strips_it():
    """`deps._composer` does `lstrip("v")`; Trivy's `InstalledVersion` keeps
    the prefix. The committed `composer.lock` fixture has carried the
    counter-example all along -- `evenement/evenement` at `v3.0.2`, recorded
    in `trivy-fs.json` as `"Version": "v3.0.2"` -- and only failed to fire
    because that package has no CVE."""
    data = {"Results": [{"Target": "composer.lock", "Type": "composer",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2022-24894", "PkgName": "symfony/http-kernel",
         "InstalledVersion": "v5.4.0", "Severity": "HIGH", "Title": "t"}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert f["fingerprint"] == fingerprint.fingerprint(
        "dependency", "CVE-2022-24894", "composer.lock",
        "symfony/http-kernel@5.4.0")
    assert "v5.4.0" not in f["title"]


def test_a_go_module_is_identified_by_the_go_sum_beside_its_go_mod(tmp_path):
    """Trivy reads `go.mod`; `deps.inventory` has only ever read `go.sum`.
    BOTH inputs moved at once -- the source and the version -- so a Go CVE
    got a fresh identity the moment the engine arrived."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.mod").write_text(_GO_MOD)
    (root / "go.sum").write_text(_GO_SUM)
    data = {"Results": [{"Target": "go.mod", "Type": "gomod",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-28483",
         "PkgName": "github.com/gin-gonic/gin", "InstalledVersion": "v1.6.3",
         "Severity": "HIGH", "Title": "t"}]}]}
    f = adapters.trivy_vulns(data, root)[0]
    assert f["occurrences"][0]["file"] == "go.sum"
    assert f["fingerprint"] == fingerprint.fingerprint(
        "dependency", "CVE-2020-28483", "go.sum",
        "github.com/gin-gonic/gin@1.6.3")


def test_a_go_mod_with_no_go_sum_beside_it_keeps_trivys_own_target(tmp_path):
    """The probe is real, not assumed. With no `go.sum` there was no Go
    component in the inventory either, so there is no identity to preserve --
    and naming a file that is not there would send a reader to a path that
    does not exist."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.mod").write_text(_GO_MOD)
    data = {"Results": [{"Target": "go.mod", "Type": "gomod",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "github.com/gin-gonic/gin",
         "InstalledVersion": "v1.6.3", "Severity": "HIGH", "Title": "t"}]}]}
    assert adapters.trivy_vulns(data, root)[0]["occurrences"][0]["file"] == "go.mod"


@needs_trivy
def test_a_go_sum_with_no_go_mod_is_declared_not_silently_dropped(tmp_path):
    """The divergence that CANNOT be closed from here: Trivy will not read
    `go.sum`, so a module directory holding one with no `go.mod` produced Go
    findings under OSV.dev and produces none at all under Trivy. Stated in
    the coverage note, because a gap nobody is told about reads exactly like
    a clean result."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.sum").write_text(_GO_SUM)
    findings, notes = adapters.trivy_scan(root)
    assert findings == []
    assert any("go.sum" in n and "go.mod" in n and "NOT checked" in n
               for n in notes), notes


def test_one_package_pinned_in_two_lockfiles_is_one_identity_not_two():
    """`deps.inventory` dedupes by `(ecosystem, name, version)` ACROSS files
    and attributes the component to the first lockfile in sorted order; Trivy
    reports once per `Target`. A monorepo pinning lodash twice was one
    identity from one producer and two from the other."""
    vuln = {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash",
            "InstalledVersion": "4.17.20", "Severity": "HIGH", "Title": "t"}
    data = {"Results": [
        {"Target": "web/package-lock.json", "Type": "npm",
         "Vulnerabilities": [dict(vuln)]},
        {"Target": "api/package-lock.json", "Type": "npm",
         "Vulnerabilities": [dict(vuln)]},
    ]}
    out = adapters.trivy_vulns(data)
    assert [f["occurrences"][0]["file"] for f in out] == ["api/package-lock.json"]


def test_two_python_lockfiles_pinning_one_package_collapse_the_way_deps_does():
    """`requirements.txt` is `pip` to Trivy and `poetry.lock` is `poetry`,
    but both are `PyPI` to `deps.inventory`, which therefore dedupes across
    them. Keyed on Trivy's raw `Type` this would have stayed two findings."""
    vuln = {"VulnerabilityID": "CVE-2024-39689", "PkgName": "certifi",
            "InstalledVersion": "2024.2.2", "Severity": "LOW", "Title": "t"}
    data = {"Results": [
        {"Target": "requirements.txt", "Type": "pip",
         "Vulnerabilities": [dict(vuln)]},
        {"Target": "poetry.lock", "Type": "poetry",
         "Vulnerabilities": [dict(vuln)]},
    ]}
    assert len(adapters.trivy_vulns(data)) == 1


# ------------------------------------------------ the advisory id, aliased
#
# The fourth input, and the one this section used to declare unfixable on the
# stated grounds that no offline mapping between the two vocabularies exists.
# IT DOES, AND TRIVY SHIPS IT IN THE RECORD ITSELF: `VendorIDs` is the
# publishing database's own id, which is exactly what OSV.dev names a record
# by. Measured over one tree holding gin 1.6.3, lodash 4.17.20, certifi
# 2024.2.2 and symfony/http-kernel 5.4.0, running BOTH producers for real:
# 0 of 10 Trivy findings shared an identity with OSV.dev's before, 10 of 10
# after. The committed `trivy-fs.json` fixture has carried an instance all
# along -- `"VendorIDs": ["GHSA-35jh-r3h4-6jhm"]` on CVE-2021-23337 -- so
# most of this is provable without the binary.

def test_the_advisory_id_is_osvs_own_when_trivy_publishes_it():
    """`VendorIDs` first: exact, structured, and Trivy's own field for the
    id the publishing database gave this advisory. The identity built from
    it is byte-for-byte the one `osv._finding` mints for the same package."""
    data = json.loads((FIX / "trivy-fs.json").read_text())
    by_rule = {f["rule"]: f for f in adapters.trivy_vulns(data)}
    assert "GHSA-35jh-r3h4-6jhm" in by_rule, sorted(by_rule)
    assert "CVE-2021-23337" not in by_rule, sorted(by_rule)
    component = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                 "source": "package-lock.json"}
    assert by_rule["GHSA-35jh-r3h4-6jhm"]["fingerprint"] == osv._finding(
        component, "GHSA-35jh-r3h4-6jhm", None)["fingerprint"]


def test_the_cve_survives_in_the_prose_when_it_is_no_longer_the_identity():
    """Gaining fingerprint parity must not cost the reader the id they
    actually search for. The CVE is not a fingerprint input, so saying it in
    the rationale costs nothing an identity depends on."""
    data = json.loads((FIX / "trivy-fs.json").read_text())
    f = next(f for f in adapters.trivy_vulns(data)
             if f["rule"] == "GHSA-35jh-r3h4-6jhm")
    assert "CVE-2021-23337" in f["rationale"]


def test_a_ghsa_in_the_references_is_used_when_there_is_no_vendor_id():
    """The measured second source. `composer.lock`'s CVE-2022-24894 comes
    from `php-security-advisories`, which publishes no `VendorIDs` at all --
    and its one reference is
    `.../security/advisories/GHSA-h7vf-5wrv-9fhv`, precisely the id OSV.dev
    returned for symfony/http-kernel 5.4.0."""
    data = {"Results": [{"Target": "composer.lock", "Type": "composer",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2022-24894", "PkgName": "symfony/http-kernel",
         "InstalledVersion": "v5.4.0", "Severity": "HIGH", "Title": "t",
         "References": [
             "https://symfony.com/blog/chc",
             "https://github.com/symfony/symfony/security/advisories/GHSA-h7vf-5wrv-9fhv",
         ]}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert f["rule"] == "GHSA-h7vf-5wrv-9fhv"
    assert f["fingerprint"] == fingerprint.fingerprint(
        "dependency", "GHSA-h7vf-5wrv-9fhv", "composer.lock",
        "symfony/http-kernel@5.4.0")


def test_an_ambiguous_reference_list_falls_back_rather_than_guessing():
    """THE REASON THE REFERENCE SOURCE IS A HEURISTIC AND IS TREATED AS ONE.
    Measured on lodash 4.17.20: Trivy's CVE-2026-4800 record lists
    `GHSA-35jh-r3h4-6jhm` FIRST -- a DIFFERENT advisory, the one belonging to
    CVE-2021-23337 -- and its own `GHSA-r5fr-rjxr-66jc` second. "First GHSA
    in References" would have aliased this finding onto another hole's
    identity, which is worse than not aliasing it at all. Two distinct ids
    means fall through to the CVE."""
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-4800", "PkgName": "lodash",
         "InstalledVersion": "4.17.20", "Severity": "HIGH", "Title": "t",
         "References": [
             "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
             "https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc",
         ]}]}]}
    assert adapters.trivy_vulns(data)[0]["rule"] == "CVE-2026-4800"


def test_the_same_ghsa_repeated_across_references_is_not_ambiguous():
    """The containment side of the rule above: it counts DISTINCT ids, so an
    advisory linked twice (GitHub's own page and the project's) still
    aliases. This is the shape certifi's real record has."""
    data = {"Results": [{"Target": "poetry.lock", "Type": "poetry",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-39689", "PkgName": "certifi",
         "InstalledVersion": "2024.2.2", "Severity": "LOW", "Title": "t",
         "References": [
             "https://github.com/advisories/GHSA-248v-346w-9cwc",
             "https://github.com/certifi/python-certifi/security/advisories/GHSA-248v-346w-9cwc",
         ]}]}]}
    assert adapters.trivy_vulns(data)[0]["rule"] == "GHSA-248v-346w-9cwc"


def test_a_vendor_id_beats_a_reference_that_disagrees_with_it():
    """Precedence, asserted where the two sources would answer differently:
    the structured field wins over the id scraped out of prose."""
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "VendorIDs": ["GHSA-aaaa-bbbb-cccc"],
         "PkgName": "x", "InstalledVersion": "1", "Severity": "HIGH",
         "Title": "t",
         "References": ["https://github.com/advisories/GHSA-dddd-eeee-ffff"]}]}]}
    assert adapters.trivy_vulns(data)[0]["rule"] == "GHSA-aaaa-bbbb-cccc"


def test_several_vendor_ids_are_resolved_by_the_set_not_by_arrival_order():
    """`VendorIDs` is a list and Trivy documents no order for it. Indexing
    `[0]` would let a database refresh that merely REORDERS the field
    re-identify the finding -- which is the exact bug this whole section
    exists to prevent, arriving by a new route. The choice therefore depends
    on the SET, so the two orderings below have to agree."""
    def rule_for(ids):
        data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
            "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "VendorIDs": ids, "PkgName": "x",
             "InstalledVersion": "1", "Severity": "HIGH", "Title": "t"}]}]}
        return adapters.trivy_vulns(data)[0]["rule"]

    forwards = rule_for(["GHSA-dddd-eeee-ffff", "GHSA-aaaa-bbbb-cccc"])
    assert forwards == rule_for(["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"])
    # And one of the candidates is kept rather than none: when Trivy folds N
    # vendor advisories into one record, OSV.dev minted N findings and this
    # producer mints one, so at most one identity can survive either way --
    # preserving one beats preserving none.
    assert forwards in ("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff")


def test_an_advisory_with_no_database_id_keeps_its_cve():
    """Not a failure. A publisher that mints no id of its own left OSV.dev
    nothing to name the record by either, so the CVE is the honest identity
    -- and the note says so rather than implying every id now agrees."""
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-28500", "PkgName": "x",
         "InstalledVersion": "1", "Severity": "HIGH", "Title": "t",
         "References": ["https://nvd.nist.gov/vuln/detail/CVE-2020-28500"]}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert f["rule"] == "CVE-2020-28500"
    # No alias means no addendum: the id in the prose would be the id in the
    # title, said twice.
    assert "matched this advisory as" not in f["rationale"]


@pytest.mark.parametrize("vendor", [[], [""], ["   "], "GHSA-aaaa-bbbb-cccc",
                                    None, [None, 42]])
def test_a_vendor_ids_field_that_is_not_a_list_of_ids_falls_through(vendor):
    """`VendorIDs` absent, empty, blank, or the wrong shape entirely: each
    one costs the alias, never the finding. A bare string is included on
    purpose -- it is iterable, so a loop over it would alias onto the letter
    `G`."""
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "VendorIDs": vendor, "PkgName": "x",
         "InstalledVersion": "1", "Severity": "HIGH", "Title": "t"}]}]}
    assert adapters.trivy_vulns(data)[0]["rule"] == "CVE-1"


@pytest.mark.parametrize("reference", [
    "https://github.com/advisories/GHSA-aaa-bbbb-cccc",       # short group
    "https://github.com/advisories/GHSA-aaaa-bbbb-cccc-dddd",  # a group too many
    "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC",       # not how they are minted
    "https://example.com/ghsa-aaaa-bbbb-cccc",                 # lowercased prefix
    "https://example.com/xGHSA-aaaa-bbbb-cccc",                # glued to a token
])
def test_only_a_well_formed_ghsa_id_is_taken_out_of_a_reference(reference):
    """The heuristic accepts GitHub's own id shape and nothing that merely
    resembles it. The four-group case matters most: a `\\b` boundary would
    have matched the first three groups of a longer token and handed back an
    id nobody wrote down."""
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
         "Severity": "HIGH", "Title": "t", "References": [reference]}]}]}
    assert adapters.trivy_vulns(data)[0]["rule"] == "CVE-1"


def test_a_references_field_that_is_not_a_list_of_strings_falls_through():
    for references in (None, "GHSA-aaaa-bbbb-cccc", 42, [None, 7, {}]):
        data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
            "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "x",
             "InstalledVersion": "1", "Severity": "HIGH", "Title": "t",
             "References": references}]}]}
        assert adapters.trivy_vulns(data)[0]["rule"] == "CVE-1", references


def test_the_remediation_names_the_release_that_fixes_it():
    """`osv._finding` says "past {version}" -- past the version you HAVE.
    Keeping that preposition while substituting `FixedVersion` told the
    reader to skip the one release that helps them: "Upgrade certifi past
    2024.7.4", where 2024.7.4 IS the fix. This is the only actionable
    sentence a dependency finding has."""
    data = json.loads((FIX / "trivy-fs.json").read_text())
    remediations = {f["title"].split(" ", 1)[0]: f["remediation"]
                    for f in adapters.trivy_vulns(data)}
    assert remediations["certifi"].startswith(
        "Upgrade certifi to 2024.7.4 or later.")
    assert "past 2024.7.4" not in remediations["certifi"]


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
    be confused with anything else Trivy might find scanning this repo.

    The advisory is named GHSA-35jh-r3h4-6jhm, not CVE-2021-23337: that is
    the id OSV.dev gives the same hole, and Trivy publishes it in the same
    record. The CVE stays visible in the prose, because it is what a human
    searches for even when it is not what the ledger keys on."""
    root = tmp_path / "repo"
    root.mkdir()
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (root / "package-lock.json").write_text(lockfile.read_text())
    findings, notes = adapters.trivy_scan(root)
    assert findings is not None
    rules = {f["rule"] for f in findings}
    assert "GHSA-35jh-r3h4-6jhm" in rules, rules
    assert "CVE-2021-23337" not in rules, rules
    assert any("CVE-2021-23337" in f["rationale"] for f in findings), findings
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
@pytest.mark.parametrize("where", ["src/vendor/thing", "a/b/dist",
                                   "node_modules/some-dep"])
def test_trivy_scan_skips_the_same_directories_deps_inventory_always_has(
        tmp_path, where):
    """`deps.inventory` never reads inside `secrets.SKIP_DIRS`
    (`node_modules`, `vendor`, ...) AT ANY DEPTH. Swapping to the engine must
    not start reporting a vendored copy of a vulnerable lockfile the built-in
    inventory always ignored -- that would make the report NOISIER for what
    is supposed to be a like-for-like swap, the exact regression
    `adapters.py`'s own module docstring warns about for Gitleaks.

    NESTED, and that is the whole point. This test used to plant a
    `node_modules` at the TOP LEVEL -- the one directory Trivy skips on its
    own -- and passed with `--skip-dirs` deleted outright. Measured with the
    bare names the flag used to carry:

        src/vendor/thing/package-lock.json   deps: []   trivy: reported
        a/b/dist/package-lock.json           deps: []   trivy: reported
    """
    root = tmp_path / "repo"
    vendored = root / where
    vendored.mkdir(parents=True)
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (vendored / "package-lock.json").write_text(lockfile.read_text())
    assert deps.inventory(root) == [], "the fixture is not out of scope at all"
    findings, _ = adapters.trivy_scan(root)
    assert findings == []


@needs_trivy
def test_ignore_paths_suppress_a_trivy_finding(tmp_path):
    """THE SECOND LOCK, the one `gitleaks()` has and this path did not.
    `trivy_skip_dirs` asks the engine not to read these paths; that is
    another program's command line, and finding after finding has shown it
    leaking. `ignore_paths` is a promise about the ANALYSIS."""
    root = tmp_path / "repo"
    (root / "examples").mkdir(parents=True)
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (root / "examples" / "package-lock.json").write_text(lockfile.read_text())
    assert adapters.trivy_scan(root)[0], "the fixture stopped being vulnerable"
    findings, _ = adapters.trivy_scan(root, ignore_paths=["examples"])
    assert findings == []


@needs_trivy
def test_the_engine_note_does_not_say_the_version_label_twice(tmp_path):
    """Trivy's first `--version` line is the bare "Version: 0.74.0", so a
    note built from it verbatim reads "by Trivy (Version: 0.74.0)"."""
    root = tmp_path / "repo"
    root.mkdir()
    _, notes = adapters.trivy_scan(root)
    assert any(re.search(r"Trivy \(\d", n) for n in notes), notes
    assert not any("Version: " in n for n in notes)


# ------------------------------------------- the coverage notes, unskippable
#
# `DEP_ID_NOTE` and `DEP_SBOM_NOTE` were pinned only inside `@needs_trivy`
# tests, so on a machine without the binary NOTHING asserted `trivy_scan`
# returns them -- the suite went green while the two sentences a report's
# honesty rests on could have been deleted outright. `run_json` is the one
# door the engine comes through (see `engines.py`), so stubbing it exercises
# the real `trivy_scan` with no binary anywhere.

def _stub_trivy(monkeypatch, data):
    monkeypatch.setattr(engines, "run_json", lambda *a, **k: (data, ""))
    monkeypatch.setattr(engines, "version_of", lambda name: "Version: 0.74.0")


def test_the_coverage_notes_are_returned_without_the_binary(monkeypatch,
                                                            tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _stub_trivy(monkeypatch, json.loads((FIX / "trivy-fs.json").read_text()))
    findings, notes = adapters.trivy_scan(root)
    assert findings, "the fixture stopped producing findings"
    assert adapters.DEP_ID_NOTE in notes, notes
    assert adapters.DEP_SBOM_NOTE in notes, notes
    assert adapters.DEP_ENGINE_NOTE.format(version="0.74.0") in notes, notes


def test_the_id_note_is_not_said_when_there_is_nothing_to_transition(
        monkeypatch, tmp_path):
    """`DEP_ID_NOTE` describes what happens to a dependency finding whose
    identity was minted while OSV.dev was the source. With no dependency
    findings in the report there is no such finding to describe, and on a
    two-lockfile toy repo the coverage note was already running to 1100
    characters. The SBOM note stays: it is about what the SBOM lists, which
    is true whether or not anything was found wrong."""
    root = tmp_path / "repo"
    root.mkdir()
    _stub_trivy(monkeypatch, {"SchemaVersion": 2, "Results": []})
    findings, notes = adapters.trivy_scan(root)
    assert findings == []
    assert adapters.DEP_ID_NOTE not in notes, notes
    assert adapters.DEP_SBOM_NOTE in notes, notes


def test_the_id_note_comes_back_the_run_a_repository_grows_its_first_cve(
        monkeypatch, tmp_path):
    """A property of the REPORT, not of the machine: the note is not
    suppressed for good once a clean run has been recorded."""
    root = tmp_path / "repo"
    root.mkdir()
    _stub_trivy(monkeypatch, {"SchemaVersion": 2, "Results": []})
    assert adapters.DEP_ID_NOTE not in adapters.trivy_scan(root)[1]
    _stub_trivy(monkeypatch, json.loads((FIX / "trivy-fs.json").read_text()))
    assert adapters.DEP_ID_NOTE in adapters.trivy_scan(root)[1]


def test_the_id_note_no_longer_claims_the_mapping_does_not_exist():
    """The finding this note was rewritten for. It used to say the two
    producers name an advisory from different databases FULL STOP, on the
    stated grounds that no offline mapping existed -- while Trivy shipped the
    mapping in `VendorIDs`. It must not go back to that, and it must not
    swing the other way into claiming the identities always agree now."""
    note = adapters.DEP_ID_NOTE
    assert "publishing database's own id" in note
    assert "one record per publishing database" in note, note
    assert "Not always" in note, note
    for overclaim in ("no offline mapping", "no mapping", "therefore appears "
                      "here under a different identity"):
        assert overclaim not in note, note


def test_ignore_paths_that_cannot_reach_the_command_line_still_filter():
    """A glob containing a comma cannot be expressed in `--skip-dirs`, which
    Trivy splits on commas. Dropping it from the flag is safe only because
    the post-filter is what actually enforces the scope."""
    assert "a,b" not in adapters.trivy_skip_dirs(["a,b"])
    assert adapters._out_of_scope("a,b/package-lock.json", ["a,b"])


# --------------------------------------------- the IaC misconfiguration scan
#
# `iac`, the first finding category this module has added since it was
# built. Trivy's misconfiguration scanner reads Dockerfiles, Terraform,
# Kubernetes manifests, Helm charts and CloudFormation templates for
# known-bad patterns -- nothing in this project has ever scanned for this,
# so `trivy_misconfigs` has no built-in twin the way `trivy_vulns` has
# `osv._finding`, and no fallback the way `_scan_dependencies` has OSV.dev.
#
# THE FIXTURE IS A REAL TRIVY 0.74.0 CAPTURE, not typed from documentation --
# this module's own guardrail, quoted in its opening docstring, for exactly
# this trap. Built from a throwaway Dockerfile written to violate five real
# Aqua Security checks (a ':latest' tag, the 'root' user, port 22 exposed, no
# HEALTHCHECK, apt-get without --no-install-recommends), scanned with
# `trivy fs . --scanners misconfig`, purged through `engines.purge` before it
# was written -- the same discipline `trivy-fs.json` above follows.

def test_trivy_misconfigurations_become_iac_findings():
    data = json.loads((FIX / "trivy-misconfig.json").read_text())
    out = adapters.trivy_misconfigs(data)
    assert len(out) == 5, [f["rule"] for f in out]
    for f in out:
        assert f["category"] == "iac"
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert f["occurrences"][0]["file"] == "Dockerfile"
    assert {f["rule"] for f in out} == {
        "DS-0001", "DS-0002", "DS-0004", "DS-0026", "DS-0029"}


def test_an_iac_title_names_the_file_and_the_checks_own_title():
    data = json.loads((FIX / "trivy-misconfig.json").read_text())
    f = next(f for f in adapters.trivy_misconfigs(data) if f["rule"] == "DS-0002")
    assert f["title"] == "Dockerfile: Image user should not be 'root'"


def test_the_remediation_uses_trivys_own_resolution_and_link():
    data = json.loads((FIX / "trivy-misconfig.json").read_text())
    f = next(f for f in adapters.trivy_misconfigs(data) if f["rule"] == "DS-0004")
    assert "Remove 'EXPOSE 22'" in f["remediation"]
    assert "https://avd.aquasec.com/misconfig/ds-0004" in f["remediation"]


def test_the_iac_severity_words_map_to_ours():
    """The exact table `trivy_vulns` uses -- see `test_the_default_iac_
    severity_is_reused_not_reinvented` below for the shared function itself,
    `_trivy_severity`."""
    for trivy, ours in (("CRITICAL", "critical"), ("HIGH", "high"),
                        ("MEDIUM", "medium"), ("LOW", "low"),
                        ("UNKNOWN", "medium")):
        data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "X-1", "Status": "FAIL", "Severity": trivy, "Title": "t"}]}]}
        assert adapters.trivy_misconfigs(data)[0]["severity"] == ours


def test_the_default_iac_severity_is_reused_not_reinvented():
    """No `Severity` at all has to fall on the exact constant `osv.py`
    already uses, reused by `_trivy_severity` rather than a fresh "medium"
    typed a second time for this category -- see `_trivy_finding`'s own use
    of the identical helper for a vulnerability."""
    data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "X-1", "Status": "FAIL", "Title": "t"}]}]}
    assert adapters.trivy_misconfigs(data)[0]["severity"] == osv.DEFAULT_SEVERITY


def test_the_iac_fingerprint_recipe():
    """Chosen from scratch -- there is no prior `iac` finding anywhere to
    match. (check id, file) alone, the same shape `hygiene._finding` uses for
    the identical reason: both are stable across runs and across machines,
    and neither shifts with a StartLine or a Message that names a specific
    resource. See `ledger._REFINGERPRINT`'s own comment for why this shape,
    though it matches hygiene's, still does not make `iac` renameable --
    unlike hygiene's four literals, a check id here is Trivy's own
    vocabulary, verbatim."""
    data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "DS-0002", "Status": "FAIL", "Severity": "HIGH", "Title": "t"}]}]}
    f = adapters.trivy_misconfigs(data)[0]
    assert f["fingerprint"] == fingerprint.fingerprint(
        "iac", "DS-0002", "Dockerfile", "DS-0002")


def test_multiple_resources_failing_one_check_become_one_finding():
    """MEASURED, not assumed. A two-Pod Kubernetes manifest failing the same
    check produced two `Misconfigurations[]` entries under the identical
    `ID` and the identical `Target`, one per resource -- `KSV-0001` twice,
    at lines 7 and 17 -- not one entry Trivy had already folded together.
    `trivy_misconfigs` has to group that back into one finding the way
    `gitleaks()` groups several hits of one rule in one file, or a
    two-resource manifest reports the SAME hole as two rows a human's
    decision on one never reaches. Confirmed against the real engine by
    `test_trivy_iac_scan_groups_a_real_multi_resource_manifest` below."""
    data = {"Results": [{"Target": "two-pods.yaml", "Misconfigurations": [
        {"ID": "KSV-0001", "Status": "FAIL", "Severity": "MEDIUM", "Title": "t",
         "CauseMetadata": {"StartLine": 7, "EndLine": 10}},
        {"ID": "KSV-0001", "Status": "FAIL", "Severity": "MEDIUM", "Title": "t",
         "CauseMetadata": {"StartLine": 17, "EndLine": 20}},
    ]}]}
    out = adapters.trivy_misconfigs(data)
    assert len(out) == 1, out
    assert [o["line"] for o in out[0]["occurrences"]] == [7, 17]


def test_a_target_with_no_misconfigurations_key_is_not_an_error():
    """The shape a clean file actually produces -- measured against a
    Terraform module with zero failures: the `Target` entry carries only
    `MisconfSummary` and no `Misconfigurations` key at all, the identical
    shape `test_a_result_with_no_vulnerabilities_is_not_an_error` pins for
    a clean lockfile on the dependency side."""
    data = {"Results": [{"Target": ".", "Type": "terraform",
                         "MisconfSummary": {"Successes": 53, "Failures": 0}}]}
    assert adapters.trivy_misconfigs(data) == []


def test_a_misconfiguration_with_no_id_is_dropped_not_fatal():
    data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"Status": "FAIL", "Severity": "HIGH", "Title": "t"},
        {"ID": "DS-0002", "Status": "FAIL", "Severity": "HIGH", "Title": "t"},
    ]}]}
    out = adapters.trivy_misconfigs(data)
    assert len(out) == 1
    assert out[0]["rule"] == "DS-0002"


def test_a_non_failing_status_is_not_reported():
    """Defensive rather than observed: this project never passes
    `--include-non-failures`, so nothing measured has ever produced anything
    but `FAIL` in this array. The check costs nothing against the day
    someone adds that flag."""
    data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "DS-0001", "Status": "PASS", "Severity": "LOW", "Title": "t"}]}]}
    assert adapters.trivy_misconfigs(data) == []


def test_a_misconfiguration_with_no_startline_defaults_to_line_zero():
    """Measured: `DS-0002` ("Image user should not be 'root'") carries a
    `CauseMetadata` with no `StartLine` at all in the real capture -- there
    is no single line that names a missing `USER` statement."""
    data = json.loads((FIX / "trivy-misconfig.json").read_text())
    f = next(f for f in adapters.trivy_misconfigs(data) if f["rule"] == "DS-0002")
    assert f["occurrences"] == [{"file": "Dockerfile", "line": 0, "snippet_hash": ""}]


def test_a_misconfigurations_report_that_is_not_a_list_is_no_findings_not_a_crash():
    assert adapters.trivy_misconfigs({"Results": "nope"}) == []
    assert adapters.trivy_misconfigs("nope") == []
    assert adapters.trivy_misconfigs(None) == []


def test_a_misconfiguration_record_that_is_not_an_object_is_dropped_not_fatal():
    data = {"Results": [{"Target": "Dockerfile",
                         "Misconfigurations": ["not-a-dict", None]}]}
    assert adapters.trivy_misconfigs(data) == []


@needs_trivy
def test_trivy_iac_scan_runs_the_real_engine_and_finds_a_known_misconfiguration(
        tmp_path):
    """The one test in this section that runs the actual binary, on the same
    model as `test_trivy_scan_runs_the_real_engine_and_finds_a_known_cve`
    above: a throwaway Dockerfile that violates a real, well-known Aqua
    Security check (the 'root' user), scanned for real rather than simulated."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update\nCMD [\"/bin/bash\"]\n")
    findings, notes = adapters.trivy_iac_scan(root)
    assert findings is not None
    rules = {f["rule"] for f in findings}
    assert "DS-0002" in rules, rules
    assert all(f["category"] == "iac" for f in findings)
    assert any(f["occurrences"][0]["file"] == "Dockerfile" for f in findings)
    assert any("trivy" in n.lower() for n in notes)


@needs_trivy
def test_trivy_iac_scan_reports_no_findings_when_there_is_nothing_to_scan(tmp_path):
    """An empty tree is a real report with nothing wrong in it, not a
    failure -- `findings` must be `[]`, never `None`, so `cli._scan_iac`
    does not mistake "found nothing" for "the engine could not run"."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    findings, notes = adapters.trivy_iac_scan(root)
    assert findings == []
    assert any("trivy" in n.lower() for n in notes)


@needs_trivy
def test_trivy_iac_scan_groups_a_real_multi_resource_manifest(tmp_path):
    """The real engine, not a simulated shape: two Pods in one manifest
    failing the same check must still land as ONE finding with several
    occurrences -- closing the loop `test_multiple_resources_failing_one_
    check_become_one_finding` above only simulates."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "two-pods.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-one\nspec:\n"
        "  containers:\n    - name: app\n      image: nginx:latest\n"
        "      securityContext:\n        privileged: true\n"
        "---\n"
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-two\nspec:\n"
        "  containers:\n    - name: app\n      image: nginx:latest\n"
        "      securityContext:\n        privileged: true\n")
    findings, _ = adapters.trivy_iac_scan(root)
    assert findings, "the fixture stopped being vulnerable"
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)
    for rule, group in by_rule.items():
        assert len(group) == 1, (
            f"{rule} landed as {len(group)} findings, not grouped into one: "
            f"{group}")
    multi = [f for f in findings if len(f["occurrences"]) >= 2]
    assert multi, "no check fired on both pods -- the fixture is stale"
    assert [o["line"] for o in multi[0]["occurrences"]] == sorted(
        o["line"] for o in multi[0]["occurrences"])


@needs_trivy
def test_ignore_paths_suppress_a_trivy_iac_finding(tmp_path):
    """THE SECOND LOCK, exactly the one `test_ignore_paths_suppress_a_trivy_
    finding` pins for dependencies: `trivy_skip_dirs` is another program's
    command line, and `ignore_paths` is a promise about the ANALYSIS."""
    root = tmp_path / "repo"
    (root / "examples").mkdir(parents=True)
    (root / "examples" / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nCMD [\"/bin/bash\"]\n")
    assert adapters.trivy_iac_scan(root)[0], "the fixture stopped being vulnerable"
    findings, _ = adapters.trivy_iac_scan(root, ignore_paths=["examples"])
    assert findings == []


@needs_trivy
def test_trivy_iac_scan_skips_the_same_directories_deps_inventory_always_has(
        tmp_path):
    root = tmp_path / "repo"
    vendored = root / "src" / "vendor" / "thing"
    vendored.mkdir(parents=True)
    (vendored / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nCMD [\"/bin/bash\"]\n")
    findings, _ = adapters.trivy_iac_scan(root)
    assert findings == []


@needs_trivy
def test_the_iac_engine_note_names_trivy(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _, notes = adapters.trivy_iac_scan(root)
    assert any(re.search(r"Trivy \(\d", n) for n in notes), notes
    assert not any("Version: " in n for n in notes)


def test_trivy_iac_scan_returns_none_when_the_engine_cannot_answer(
        monkeypatch, tmp_path):
    """`None` here costs the WHOLE phase, unlike `trivy_scan`'s own `None`:
    there is no built-in scanner for `iac` to fall back to."""
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(engines, "run_json", lambda *a, **k: (
        None, "trivy did not finish within 600s and was stopped."))
    findings, notes = adapters.trivy_iac_scan(root)
    assert findings is None
    assert notes == ["trivy did not finish within 600s and was stopped."]


def test_trivy_iac_scan_reports_empty_results_as_no_findings_not_none(
        monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _stub_trivy(monkeypatch, {"SchemaVersion": 2, "Results": []})
    findings, notes = adapters.trivy_iac_scan(root)
    assert findings == []
    assert any("trivy" in n.lower() for n in notes)


# --------------------------------------------------------------- the SBOM
#
# The fixture is a REAL syft 1.51.1 capture of this repository
# (`syft scan dir:. -o cyclonedx-json`, this module's own `--exclude` flags
# applied), on the same model as `trivy-fs.json` and `gitleaks-dir.json`
# above: a fixture typed from the documentation makes the parser and the
# test agree with each other while both disagree with the tool. It still
# carries the leak `syft_document` exists to close -- see the two
# `type: "file"` entries whose `name` is this machine's own absolute path --
# because a fixture that had already been fixed by hand would not prove the
# fix does anything.

def _syft_fixture():
    return json.loads((FIX / "syft-cyclonedx.json").read_text())


def test_syft_document_keeps_only_the_library_components():
    document = adapters.syft_document(_syft_fixture())
    names = {c["name"]: c["version"] for c in document["components"]}
    assert names == {"certifi": "2024.2.2", "evenement/evenement": "v3.0.2",
                     "lodash": "4.17.20", "six": "1.16.0"}


def test_syft_document_drops_the_absolute_path_the_file_entries_carry():
    """The leak this adapter exists to close, proven against the real
    capture rather than a hand-built one: measured on this repository,
    Syft's OWN `type: "file"` entries name the scan root's absolute path,
    while every other path in the identical document (`syft:location:*:path`)
    is already root-relative. Stored and downloaded as-is, that field would
    put the operator's home directory and username into a document handed to
    whoever asked for this project's dependency list."""
    document = adapters.syft_document(_syft_fixture())
    assert not any(c.get("type") == "file" for c in document["components"])
    assert "/Users/" not in json.dumps(document)


def test_a_document_missing_components_entirely_is_not_usable():
    """Syft's own CycloneDX writer omits `components` ALTOGETHER for a
    checkout where nothing was recognised -- not an empty list. Measured
    against an empty directory. Treated as unusable here so `cli._scan_sbom`
    reads it as "fall back to deps.sbom", never as "an SBOM with zero
    components is the honest answer"."""
    assert adapters.syft_document({"bomFormat": "CycloneDX",
                                   "specVersion": "1.5"}) is None


def test_a_document_that_is_not_an_object_is_not_usable():
    assert adapters.syft_document(["not", "a", "document"]) is None
    assert adapters.syft_document("nope") is None


def test_components_that_is_not_a_list_is_not_usable():
    assert adapters.syft_document({"components": "oops"}) is None


def test_a_non_dict_component_is_dropped_not_fatal():
    """A record this parser cannot read costs that record, not the whole
    document -- the same rule `gitleaks()` and `trivy_vulns()` apply."""
    document = adapters.syft_document({"components": [
        {"type": "library", "name": "x", "version": "1.0"}, "garbage", None]})
    assert [c["name"] for c in document["components"]] == ["x"]


@needs_syft
def test_syft_sbom_runs_the_real_engine_and_finds_a_known_component(tmp_path):
    """The one test in this section that runs the actual binary, the same
    way the Gitleaks and Trivy sections above do. `package-lock.json` here is
    this repository's own fixture -- lodash 4.17.20 -- copied alone into an
    empty tree so the result cannot be confused with anything else Syft
    might find scanning this repo."""
    root = tmp_path / "repo"
    root.mkdir()
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (root / "package-lock.json").write_text(lockfile.read_text())
    document, notes = adapters.syft_sbom(root)
    assert document is not None
    names = {c["name"]: c["version"] for c in document["components"]}
    assert names.get("lodash") == "4.17.20"
    assert any("syft" in n.lower() for n in notes)


@needs_syft
def test_syft_sbom_drops_the_leak_on_the_real_engine_too(tmp_path):
    """The unit test above proves the parser closes the leak against a
    fixture; this proves the real binary's output goes through the same
    door. A `str(root)` anywhere in the stored document would put this exact
    machine's directory layout into a downloadable artefact."""
    root = tmp_path / "repo"
    root.mkdir()
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (root / "package-lock.json").write_text(lockfile.read_text())
    document, _ = adapters.syft_sbom(root)
    assert str(root) not in json.dumps(document)


@needs_syft
def test_syft_sbom_reports_none_when_nothing_is_found(tmp_path):
    """No lockfile anywhere: Syft's own writer omits `components`, which
    `syft_document` treats as unusable rather than "zero dependencies" --
    see that function's docstring for why the difference matters to
    `cli._scan_sbom`."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    document, notes = adapters.syft_sbom(root)
    assert document is None
    assert notes == [adapters.SYFT_NO_COMPONENTS_NOTE]


@needs_syft
@pytest.mark.parametrize("where", ["src/vendor/thing", "a/b/dist",
                                   "node_modules/some-dep"])
def test_syft_sbom_skips_the_same_directories_deps_inventory_always_has(
        tmp_path, where):
    """The same regression `adapters.py`'s module docstring warns about for
    Gitleaks and `test_trivy_scan_skips_the_same_directories_deps_inventory_
    always_has` pins for Trivy: a vendored copy of a lockfile `deps.inventory`
    has never read must not start appearing in the SBOM just because the
    producer changed."""
    root = tmp_path / "repo"
    vendored = root / where
    vendored.mkdir(parents=True)
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (vendored / "package-lock.json").write_text(lockfile.read_text())
    assert deps.inventory(root) == [], "the fixture is not out of scope at all"
    document, _ = adapters.syft_sbom(root)
    assert document is None


# ------------------------------------------------------------ the SAST pre-pass
#
# The fixture is a REAL semgrep 1.175.0 capture of this repository
# (`semgrep --config=p/owasp-top-ten --metrics=off --json --time`), on the same
# model as the three above -- and unlike them it is committed UNPURGED. The
# tests below put it through `engines.purge` exactly as production does, so the
# purge is proven to remove something rather than assumed to have been applied
# by hand before the file was written.
#
# TRIMMED IN TWO PLACES, both recorded here so nobody reads the file as
# verbatim: one of the three parse errors is kept and its `message` cut after
# 220 characters (each of the three is ~2kB of this repository's own source --
# see `test_the_capture_carries_this_repositorys_own_source`), and
# `time.targets` is emptied, because it is one float per (file, rule) pair and
# nothing in this module reads it.
#
# SEMGREP DOES NOT REPLACE THE SAST PASS, which is what makes this section
# different from the three above it. Measured on this repository: 223 rules ran,
# 147 of them for Python, 65 for JavaScript and ONE for shell -- and the core of
# this product is 8,263 lines of bash. "Semgrep ran" is true here and
# misleading, so the coverage note carries the spread.

HAVE_SEMGREP = engines.find("semgrep") is not None
needs_semgrep = pytest.mark.skipif(
    not HAVE_SEMGREP, reason="semgrep is not installed on this machine")

# What `semgrep_excludes` emits for `SKIP_DIRS` alone, whatever globs it is
# also given -- the part the operator's globs are checked against by
# subtraction, so a test about anchoring cannot accidentally pass by matching
# one of these.
_SKIP_DIR_EXCLUDES = frozenset(adapters.semgrep_excludes())


def _semgrep_raw():
    """The capture exactly as semgrep wrote it -- NOT purged."""
    return json.loads((FIX / "semgrep-owasp.json").read_text())


def _semgrep_fixture():
    """The capture as the adapter actually receives it: through the one door."""
    return engines.purge("semgrep", _semgrep_raw())


# The three editions the real capture carries, in the real order -- the 2021
# one is neither first nor last, which is the whole point of it being here.
OWASP_EDITIONS = ["A03:2017 - Sensitive Data Exposure",
                  "A02:2021 - Cryptographic Failures",
                  "A04:2025 - Cryptographic Failures"]
CWE_327 = "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"


def _result(check_id="python.lang.security.x.insecure-thing", path="app.py",
            line=3, severity="WARNING", cwe=(CWE_327,), owasp=OWASP_EDITIONS,
            **extra):
    """One `results[]` entry in the shape the real capture has."""
    return {"check_id": check_id, "path": path,
            "start": {"line": line, "col": 1}, "end": {"line": line, "col": 9},
            "extra": {"severity": severity,
                      "metadata": {"cwe": list(cwe), "owasp": list(owasp)},
                      **extra}}


def _report(*results):
    return {"results": list(results), "paths": {"scanned": ["app.py"]}}


def test_semgrep_results_become_sast_findings():
    out = adapters.semgrep_findings(_semgrep_fixture(), root=".")
    assert out, "the captured fixture must contain at least one finding"
    f = out[0]
    assert f["category"] == "sast"
    assert f["severity"] in report.SEVERITIES
    assert len(f["fingerprint"]) == 64
    assert f["occurrences"][0]["file"] == "bin/claude-cron-server"


def test_every_rule_this_adapter_mints_is_in_the_closed_vocabulary():
    """`report-finding` refuses a SAST rule outside `taxonomy.SAST_RULES`, and
    `cmd_prepare` writes straight to the ledger WITHOUT passing that door -- so
    a name this adapter invented would land in the ledger as a rule no filter
    selects, no `classify` can grade, and no agent can ever re-report."""
    for f in adapters.semgrep_findings(_semgrep_fixture(), root="."):
        assert taxonomy.is_valid_rule(f["rule"]), f["rule"]


def test_the_rule_is_looked_up_by_the_cwe_semgrep_reported():
    out = adapters.semgrep_findings(_semgrep_fixture(), root=".")
    assert {f["rule"] for f in out} == {"weak-cryptography"}


def test_the_cwe_and_owasp_come_from_our_taxonomy_not_from_semgrep():
    """One source of truth per row. `report-finding` DERIVES both fields from
    the rule and ignores anything the caller sends; a finding written straight
    into the ledger has to arrive already agreeing with that, or the same rule
    carries two classifications depending on who reported it."""
    f = adapters.semgrep_findings(_semgrep_fixture(), root=".")[0]
    assert (f["cwe"], f["owasp"]) == taxonomy.classify(f["rule"])
    assert (f["cwe"], f["owasp"]) == ("CWE-327", "A02:2021")


def test_a_cwe_our_vocabulary_does_not_carry_is_filed_as_other():
    """`other` is the escape hatch taxonomy.py documents: an unclassified
    finding must be VISIBLY unclassified, never quietly filed under the
    nearest wrong name. The check id goes in the rationale so the row is
    still actionable."""
    data = _report(_result(check_id="js.express.cookie-missing-httponly",
                           cwe=["CWE-1004: Sensitive Cookie Without HttpOnly"]))
    f = adapters.semgrep_findings(data, root=".")[0]
    assert f["rule"] == "other"
    assert "js.express.cookie-missing-httponly" in f["rationale"]
    assert (f["cwe"], f["owasp"]) == ("", "")


def test_the_owasp_edition_taken_is_2021_not_whichever_came_first():
    """`extra.metadata.owasp` carries SEVERAL editions -- A03:2017, A02:2021
    and A04:2025 on the very rule this repository's own capture fired.
    `taxonomy.py` maps the 2021 Top Ten, so `[0]` would file the finding
    under a code from an edition this project does not speak."""
    data = _report(_result(cwe=["CWE-9999: nothing we carry"]))
    f = adapters.semgrep_findings(data, root=".")[0]
    assert "A02:2021" in f["rationale"], f["rationale"]
    assert "A03:2017" not in f["rationale"]
    assert "A04:2025" not in f["rationale"]


def test_the_order_of_the_cwe_list_does_not_decide_the_rule():
    """`cwe` is a LIST and the rule is a FINGERPRINT INPUT, so `[0]` would let
    a registry refresh that merely reorders the field re-identify the finding
    -- the same trap `_trivy_advisory_id` documents for `VendorIDs`."""
    both = ["CWE-1004: Sensitive Cookie Without HttpOnly", CWE_327]
    a = adapters.semgrep_findings(_report(_result(cwe=both)), root=".")[0]
    b = adapters.semgrep_findings(_report(_result(cwe=both[::-1])), root=".")[0]
    assert a["rule"] == b["rule"] == "weak-cryptography"
    assert a["fingerprint"] == b["fingerprint"]


def test_a_record_naming_two_of_our_rules_is_other_not_a_coin_flip():
    """Two DIFFERENT vocabulary rules in one record is genuine ambiguity, and
    picking one relabels the finding as something it is half not -- silently,
    in the one field a human's decision hangs off. `other` says so instead,
    and the rationale names both CWEs."""
    data = _report(_result(cwe=[CWE_327, "CWE-89: SQL Injection"]))
    f = adapters.semgrep_findings(data, root=".")[0]
    assert f["rule"] == "other"
    assert "CWE-327" in f["rationale"] and "CWE-89" in f["rationale"]


def test_a_record_with_no_cwe_at_all_is_other_not_a_crash():
    f = adapters.semgrep_findings(_report(_result(cwe=[])), root=".")[0]
    assert f["rule"] == "other"
    f = adapters.semgrep_findings(_report(_result(cwe="oops")), root=".")[0]
    assert f["rule"] == "other"


def test_every_cwe_in_the_vocabulary_names_exactly_one_rule():
    """The lookup is a REVERSE of `taxonomy.SAST_RULES`. Built as a dict, two
    rules sharing a CWE would collapse into whichever was written last, and
    every Semgrep finding carrying that CWE would be filed under a rule
    nobody chose -- silently, and only for as long as nobody looked."""
    cwes = [cwe for cwe, _ in taxonomy.SAST_RULES.values() if cwe]
    assert len(cwes) == len(set(cwes))


# ------------------------------------------------------- the value never lands

def test_the_capture_carries_this_repositorys_own_source():
    """MEASURED, not anticipated. Semgrep puts the FILE'S CONTENT into the
    message of a parse error -- ~2kB of `bin/claude-cron` in this capture --
    and it interpolates a rule's metavariables into `extra.message`, which for
    a rule that fires ON a hardcoded credential IS the credential. Neither is
    `extra.lines`, and neither was in the purge table before this adapter
    existed."""
    raw = json.dumps(_semgrep_raw())
    assert "#!/bin/bash" in raw, "the fixture is no longer the raw capture"
    assert "durable local scheduler" in raw
    clean = json.dumps(_semgrep_fixture())
    assert "#!/bin/bash" not in clean
    assert "durable local scheduler" not in clean


SEMGREP_SECRET = "sk-live-" + "THEACTUALVALUEHERE"


def _leaky_report():
    """Every field of a semgrep result that can carry what it matched,
    populated the way the real tool populates them."""
    return _report(_result(
        check_id="python.lang.security.hardcoded-key",
        lines=f"KEY = '{SEMGREP_SECRET}'",
        message=f"Hardcoded credential {SEMGREP_SECRET} detected",
        fix=f"os.environ['KEY']  # was {SEMGREP_SECRET}",
        rendered_fix=f"KEY = {SEMGREP_SECRET!r}",
        metavars={"$KEY": {"start": {"line": 3}, "abstract_content": SEMGREP_SECRET,
                           "propagated_value": {
                               "svalue_abstract_content": SEMGREP_SECRET}}},
        dataflow_trace={"taint_source": ["CliLoc", {"path": "app.py"},
                                         f"KEY = '{SEMGREP_SECRET}'"]}))


def test_a_semgrep_finding_carries_no_code_anywhere():
    """The production path: purge, then parse."""
    out = adapters.semgrep_findings(engines.purge("semgrep", _leaky_report()),
                                    root=".")
    assert out, "the record must still parse into a finding"
    blob = json.dumps(out)
    assert SEMGREP_SECRET not in blob
    assert "KEY" not in blob, "the matched line reached the finding"


def test_the_purge_and_the_adapter_are_two_locks_on_semgrep_too():
    """Each door is enough ON ITS OWN, so a refactor that leans on one still
    has the other standing. Above: the purge ran. Here: it did not, and every
    field of a finding is CONSTRUCTED rather than copied, so nothing rides in."""
    blob = json.dumps(adapters.semgrep_findings(_leaky_report(), root="."))
    assert SEMGREP_SECRET not in blob
    assert "KEY" not in blob
    assert SEMGREP_SECRET not in json.dumps(engines.purge("semgrep",
                                                          _leaky_report()))


# ---------------------------------------------------------------- the identity

def test_three_hits_of_one_check_in_one_file_are_one_finding():
    """No snippet means no per-hit identity, so several matches of one check in
    one file are ONE finding with several occurrences -- the same grouping
    `gitleaks()` uses for the same reason. This repository's capture is
    exactly that case: three md5 calls in `bin/claude-cron-server`."""
    out = adapters.semgrep_findings(_semgrep_fixture(), root=".")
    assert len(out) == 1, out
    assert [o["line"] for o in out[0]["occurrences"]] == [351, 656, 1845]


def test_two_different_checks_in_one_file_stay_two_findings():
    """Both of these map to `weak-cryptography` at the same path: without the
    check id in the identity they would be ONE row whose rationale names
    whichever was parsed last, and every unmapped finding in a file would
    collapse onto a single `other`."""
    data = _report(_result(check_id="python.x.md5"),
                   _result(check_id="python.x.des"))
    out = adapters.semgrep_findings(data, root=".")
    assert len(out) == 2
    assert len({f["fingerprint"] for f in out}) == 2


def test_the_identity_does_not_move_when_the_code_moves_down_the_file():
    a = adapters.semgrep_findings(_report(_result(line=3)), root=".")[0]
    b = adapters.semgrep_findings(_report(_result(line=930)), root=".")[0]
    assert a["fingerprint"] == b["fingerprint"]


def test_a_semgrep_identity_is_the_check_id_and_says_so():
    """THE decision of this task, written down. `fingerprint("sast", rule,
    path, snippet)` takes the CODE as its fourth argument, and `engines.purge`
    drops the code before this module ever sees it -- deliberately, because a
    rule firing on a hardcoded credential returns the credential there. There
    is no way back: the ledger keeps only an opaque `snippet_hash`, and
    `ledger.rename_rule` refuses `sast` for exactly this reason. So the fourth
    argument is Semgrep's own check id: stable run to run, and it keeps two
    checks in one file apart."""
    data = _report(_result(check_id="python.x.md5", path="app.py"))
    f = adapters.semgrep_findings(data, root=".")[0]
    assert f["fingerprint"] == fingerprint.fingerprint(
        "sast", "weak-cryptography", "app.py", "python.x.md5")
    # And it is NOT what the SAST pass mints for the same weakness, whatever
    # snippet it passes -- including none at all.
    for snippet in ("hashlib.md5(body)", ""):
        assert f["fingerprint"] != fingerprint.fingerprint(
            "sast", "weak-cryptography", "app.py", snippet)


# ---------------------------------------------------------------- the severity

@pytest.mark.parametrize("word,ours", [("ERROR", "high"), ("WARNING", "medium"),
                                       ("INFO", "info")])
def test_the_semgrep_severity_words_map_to_ours(word, ours):
    f = adapters.semgrep_findings(_report(_result(severity=word)), root=".")[0]
    assert f["severity"] == ours


def test_no_semgrep_severity_alone_can_mint_a_critical():
    """An ERROR from a linter is a statement about the RULE's confidence, not
    about this repository's exposure. Measured here: all three of Semgrep's
    findings on this repository are false positives of the kind only context
    resolves. `critical` is what the report's headline counts and the default
    `min_severity` floor are built around, so the pre-pass may not open a
    finding at the top of the report on its own -- the triage that follows can
    raise it, and that is a judgement somebody made."""
    for word in ("ERROR", "WARNING", "INFO", "SOMETHING-NEW", ""):
        f = adapters.semgrep_findings(_report(_result(severity=word)),
                                      root=".")[0]
        assert f["severity"] != "critical", word


def test_a_severity_word_we_have_never_heard_of_is_not_hidden_below_the_floor():
    """`info` sits below the default floor, so grading an ungraded finding
    there files it out of sight -- the same argument `_TRIVY_SEVERITY`'s
    default makes."""
    f = adapters.semgrep_findings(_report(_result(severity="CATASTROPHE")),
                                  root=".")[0]
    assert f["severity"] == adapters.SAST_DEFAULT_SEVERITY == "medium"


# ------------------------------------------------------------------- the scope

def test_an_ignored_path_is_dropped_even_when_semgrep_reports_it():
    data = _report(_result(path="tests/fixtures/sample.py"))
    assert adapters.semgrep_findings(
        data, root=".", ignore_paths=["tests/fixtures/**"]) == []


def test_a_skipped_directory_is_dropped_even_when_semgrep_reports_it():
    data = _report(_result(path="node_modules/thing/index.js"))
    assert adapters.semgrep_findings(data, root=".") == []


def test_the_exclusions_carry_the_skip_dirs_and_the_operators_globs():
    excludes = adapters.semgrep_excludes(["docs/**"])
    for name in secrets.SKIP_DIRS:
        assert name in excludes and f"**/{name}" in excludes
    assert "./docs/**" in excludes


def test_an_operators_glob_is_never_handed_over_as_a_bare_name():
    """THE NARROWING THIS TEST EXISTS FOR. `glob.rstrip("/*")` turned `docs/**`
    into `docs`, and semgrep matches a bare `--exclude` at ANY DEPTH -- so
    `src/docs/b.py` was never read, while `ignores.ignored("src/docs/b.py",
    ["docs/**"])` answers False, i.e. the analysis considers it IN SCOPE.
    `_out_of_scope` cannot put it back; it only ever removes more.

    It was copied from `trivy_skip_dirs`, where it is near-correct because
    Trivy's bare name matches the top level only."""
    for glob in ("docs/**", "docs", "docs/", "./docs", "/docs", "tests/fixtures/**"):
        for pattern in adapters.semgrep_excludes([glob]):
            if pattern in _SKIP_DIR_EXCLUDES:
                continue
            assert pattern.startswith("./"), (glob, pattern)
            assert not pattern.startswith(".//"), (glob, pattern)


def test_the_skip_dirs_still_go_down_at_any_depth():
    """The anchoring above is for the OPERATOR's globs only. `SKIP_DIRS` are
    matched at any depth by `_out_of_scope` itself, so anchoring them would be
    the mirror-image bug: the engine reading `a/b/node_modules` on every run
    for findings that are then thrown away."""
    excludes = adapters.semgrep_excludes()
    assert "node_modules" in excludes and "**/node_modules" in excludes
    assert "./node_modules" not in excludes


@needs_semgrep
def test_the_real_engine_is_not_narrowed_below_what_the_operator_asked_for(
        tmp_path):
    """The reproduction, against the binary. `docs/**` must cost `docs/a.py`
    and NOT `src/docs/b.py` -- the file the analysis's own reading of the same
    glob keeps."""
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "src" / "docs").mkdir(parents=True)
    weak = ("import hashlib\n\n\ndef etag(body):\n"
            "    return hashlib.md5(body).hexdigest()\n")
    for rel in ("docs/a.py", "src/docs/b.py", "top.py"):
        (root / rel).write_text(weak)
    # What the ANALYSIS says about the same three paths, which is the standard
    # the engine's command line has to meet.
    assert not ignores.ignored("src/docs/b.py", ["docs/**"])
    assert ignores.ignored("docs/a.py", ["docs/**"])
    findings, _ = adapters.semgrep_scan(root, ignore_paths=["docs/**"])
    assert {f["occurrences"][0]["file"] for f in findings} == {
        "src/docs/b.py", "top.py"}


# ----------------------------------------------------------- the coverage note

def test_the_note_says_how_many_rules_ran_for_each_language():
    languages = dict(adapters.semgrep_languages(_semgrep_fixture()))
    assert languages["python"] == 147
    assert languages["javascript"] == 61
    assert languages["bash"] == 1


def test_a_shell_repository_cannot_read_like_a_python_one():
    """"Semgrep ran" is true here and misleading: the core of this product is
    8,263 lines of bash, and the OWASP ruleset carries ONE rule for it against
    147 for Python. Without the spread in the note, a clean shell report reads
    as a clean bill of health."""
    note = " ".join(adapters.semgrep_notes(_semgrep_fixture(), "1.175.0", []))
    assert "python 147" in note, note
    assert "bash 1" in note, note
    assert "javascript 61" in note, note


def test_a_language_this_tree_holds_no_file_of_is_not_shown_as_coverage():
    """The whole note is read as a statement about how much of THIS tree was
    examined, and `p/owasp-top-ten` loads a FLOOR of rules over any directory
    at all -- measured, a directory holding one `.txt` file loads `java 3`,
    `scala 3`, `ruby 1`. The shipped note printed them beside `python 147` on
    a repository with no Java, no Scala and no Ruby in it."""
    coverage, unplaced = adapters.semgrep_breakdown(_semgrep_fixture())
    assert dict(coverage) == {"python": 147, "javascript": 61, "json": 3,
                              "bash": 1, "html": 1}
    assert dict(unplaced) == {"generic": 15, "package_managers": 5,
                              "typescript": 4, "java": 3, "scala": 3,
                              "ruby": 1}
    # Together they are still exactly the measurement: the split moves rows
    # between two sentences, it never loses one.
    assert sorted(coverage + unplaced) == sorted(
        adapters.semgrep_languages(_semgrep_fixture()))


def test_an_unevidenced_row_is_labelled_rather_than_deleted():
    """Deleting the row is the obvious fix and it opens a worse hole: this
    tree's own shell lives in `bin/claude-cron`, which has NO EXTENSION --
    Semgrep reads its shebang and this table cannot -- so a repository whose
    shell is all extensionless would lose `bash 1` from the one note that
    exists to say shell got a single rule. Stated and labelled teaches both
    facts; hidden teaches neither."""
    note = " ".join(adapters.semgrep_notes(_semgrep_fixture(), "1.175.0", []))
    assert "java 3" in note, note
    assert "no file in this tree is written in" in note, note
    # And it is NOT in the sentence that lists coverage.
    coverage_sentence = next(n for n in adapters.semgrep_notes(
        _semgrep_fixture(), "1.175.0", []) if "not spread evenly" in n)
    # "java 3" and not "java": `javascript 61` is in this sentence and must be.
    assert "java 3" not in coverage_sentence, coverage_sentence
    assert "javascript 61" in coverage_sentence, coverage_sentence


def test_a_namespace_this_project_has_never_heard_of_is_left_alone():
    """Absence cannot be proven from a table nobody has updated. A namespace
    with no entry is SHOWN, because dropping it would hide a language that was
    barely examined -- the dangerous direction."""
    data = {"paths": {"scanned": ["a.py"]},
            "time": {"rules": ["python.a.b", "brandnewlang.a.b"]}}
    coverage, unplaced = adapters.semgrep_breakdown(data)
    assert ("brandnewlang", 1) in coverage
    assert unplaced == []


def test_the_note_counts_the_files_semgrep_could_not_parse():
    """A file Semgrep could not parse was not analysed, whatever the rule
    count says about its language. It is a gap, so it is stated -- and the
    engine's own message for it is NOT quoted back, because that message is
    the file's source."""
    note = " ".join(adapters.semgrep_notes(_semgrep_fixture(), "1.175.0", []))
    assert "1 file" in note, note
    assert "parse" in note, note
    assert "#!/bin/bash" not in note


def test_the_identity_note_is_said_only_when_there_is_something_to_identify():
    """The same rule `DEP_ID_NOTE` follows: with nothing found, there is no
    finding whose identity could diverge, and the sentence is characters a
    reader has to get past to reach the gaps that ARE real."""
    empty = adapters.semgrep_notes(_semgrep_fixture(), "1.175.0", [])
    found = adapters.semgrep_notes(_semgrep_fixture(), "1.175.0", [{"a": 1}])
    assert adapters.SAST_IDENTITY_NOTE not in empty
    assert adapters.SAST_IDENTITY_NOTE in found


def test_the_identity_note_says_the_two_passes_do_not_share_an_identity():
    """The previous task in this block shipped a fingerprint divergence by
    assuming a recipe carried over. This one cannot be closed -- the snippet
    is gone by design -- so it is DECLARED rather than papered over with a
    hash that merely looks right."""
    note = adapters.SAST_IDENTITY_NOTE
    assert "twice" in note
    assert "check id" in note or "check_id" in note


def test_the_note_says_semgrep_does_not_replace_the_sast_pass():
    assert adapters.SAST_PREPASS_NOTE in adapters.semgrep_notes(
        _semgrep_fixture(), "1.175.0", [])


# -------------------------------------------------------------- the robustness

def test_a_semgrep_report_that_is_not_an_object_is_no_findings_not_a_crash():
    assert adapters.semgrep_findings(["nope"], root=".") == []
    assert adapters.semgrep_findings(None, root=".") == []


def test_semgrep_results_that_are_not_a_list_is_no_findings_not_a_crash():
    assert adapters.semgrep_findings({"results": "oops"}, root=".") == []


def test_a_semgrep_record_this_parser_cannot_use_is_dropped_not_fatal():
    data = {"results": ["garbage", None, {"path": "a.py"}, {"check_id": "c"},
                        _result()]}
    assert len(adapters.semgrep_findings(data, root=".")) == 1


def test_a_report_with_no_time_block_still_produces_a_note():
    """`--time` is what fills `time.rules`, and a semgrep that stops emitting
    it must cost the language breakdown, not the whole phase.

    THE ASSERTION USED TO BE "a note exists", AND IT PASSED ON A LIE. The
    count came from `sum(n for _, n in languages)`, so a lost breakdown printed
    "with 0 rules loaded from p/owasp-top-ten" -- captured verbatim, on a scan
    that had loaded 244 -- in the one sentence this whole pass exists for. A
    note existed, so the test was green."""
    notes = adapters.semgrep_notes(
        {"results": [], "paths": {"scanned": ["a.py"] * 89}}, "1.175.0", [])
    assert notes
    assert adapters.SAST_PREPASS_NOTE in notes
    note = " ".join(notes)
    assert "0 rules" not in note, note
    assert "does not say how many rules" in note, note
    # The file count is a number the report DID carry, so it is still there.
    assert "over 89 files" in note, note


def test_the_rule_count_is_dropped_rather_than_reported_as_zero():
    """A zero from semgrep is never evidence that zero rules loaded: measured,
    1.175.0 writes `time.rules: []` WITHOUT `--time`, over a tree it scanned
    perfectly well. Zero rules loaded and an unknown number of rules loaded are
    opposite facts -- the first says nothing was checked -- so only a positive
    count is printed."""
    for time_block in ({}, {"rules": []}, {"rules": "oops"}, {"rules": [""]}):
        note = " ".join(adapters.semgrep_notes(
            {"paths": {"scanned": ["a.py"]}, "time": time_block},
            "1.175.0", []))
        assert "0 rules" not in note, (time_block, note)
        assert "does not say how many rules" in note, (time_block, note)


def test_a_file_count_the_report_does_not_carry_is_not_printed_as_zero():
    """The same lie one clause earlier: a `paths` block this parser cannot
    read printed "over 0 files". The sentence costs the number, never invents
    one."""
    for broken in ({"paths": "oops"}, {"paths": {"scanned": "oops"}},
                   {"paths": ["a"]}, {}):
        note = " ".join(adapters.semgrep_notes(broken, "1.175.0", []))
        assert "over 0 files" not in note, note
        assert "does not count" in note, note


# --------------------------------------------- the pre-pass, against the tool

@needs_semgrep
def test_semgrep_scan_runs_the_real_engine_and_finds_a_planted_weakness(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "import hashlib\n\n\ndef etag(body):\n"
        "    return hashlib.md5(body).hexdigest()\n")
    findings, notes = adapters.semgrep_scan(root)
    assert findings is not None, notes
    assert [f["rule"] for f in findings] == ["weak-cryptography"], findings
    assert findings[0]["occurrences"][0]["file"] == "app.py"
    assert any("Semgrep" in n for n in notes), notes


@needs_semgrep
def test_the_real_engine_never_hands_back_the_line_it_matched(tmp_path):
    """The unit tests above prove the parser drops the value; this proves the
    real binary's output goes through the same door -- including the notes,
    which are the one thing here that is printed."""
    root = tmp_path / "repo"
    root.mkdir()
    key = "sk-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    (root / "app.py").write_text(
        f"import hashlib\nAPI_KEY = {key!r}\n\n"
        "def etag(body):\n    return hashlib.md5(body).hexdigest()\n")
    findings, notes = adapters.semgrep_scan(root)
    assert findings is not None
    assert key not in json.dumps(findings)
    assert key not in " ".join(notes)


@needs_semgrep
def test_the_real_engine_declares_how_little_it_runs_for_shell(tmp_path):
    """The measurement this whole section exists for, re-taken on a tree that
    is nothing but shell."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "run.sh").write_text("#!/bin/bash\nset -eu\necho \"$1\"\n")
    findings, notes = adapters.semgrep_scan(root)
    assert findings is not None, notes
    note = " ".join(notes)
    assert "bash 1" in note, note
    assert "python" not in note, note


@needs_semgrep
def test_the_real_engine_is_not_asked_to_read_what_is_out_of_scope(tmp_path):
    """The scope is locked twice here too: `--exclude` so the files are never
    read, and `_out_of_scope` over what comes back, because a promise about
    the ANALYSIS that holds only while another program accepted our command
    line is not a promise."""
    root = tmp_path / "repo"
    (root / "node_modules" / "dep").mkdir(parents=True)
    (root / "docs").mkdir()
    weak = ("import hashlib\n\n\ndef etag(body):\n"
            "    return hashlib.md5(body).hexdigest()\n")
    (root / "app.py").write_text(weak)
    (root / "node_modules" / "dep" / "vendored.py").write_text(weak)
    (root / "docs" / "sample.py").write_text(weak)
    findings, _ = adapters.semgrep_scan(root, ignore_paths=["docs/**"])
    assert {f["occurrences"][0]["file"] for f in findings} == {"app.py"}


# ------------------------------------------------- the pre-pass, through prepare

@needs_semgrep
def test_prepare_records_the_pre_pass_as_sast_findings(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "import hashlib\n\n\ndef etag(body):\n"
        "    return hashlib.md5(body).hexdigest()\n")
    db = tmp_path / "security.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "on"}
    aid = open_analysis(db)
    note = cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
                    env=env)["coverage_note"]
    findings = cli_json(db, "findings", "--analysis", str(aid), env=env)
    sast = [f for f in findings if f["category"] == "sast"]
    assert [f["rule"] for f in sast] == ["weak-cryptography"], findings
    assert sast[0]["cwe"] == "CWE-327" and sast[0]["owasp"] == "A02:2021"
    assert "Semgrep" in note


def test_prepare_declares_the_pre_pass_it_did_not_run(tmp_path):
    """"Found nothing" and "never looked" are the same silence in a report,
    and a missing pre-pass must not read as a clean SAST result."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "off"}
    aid = open_analysis(db)
    note = cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
                    env=env)["coverage_note"]
    assert "SAST pre-pass did not run" in note, note


def test_the_pre_pass_does_not_run_offline(tmp_path):
    """The rule set is fetched from Semgrep's registry. An analysis told not
    to touch the network must not reach for it, and must say why it did not
    -- the same shape `--offline` already takes for dependency CVEs."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "on"}
    aid = open_analysis(db)
    note = cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
                    "--offline", env=env)["coverage_note"]
    assert security_cli.OFFLINE_SAST_NOTE in note, note
    assert adapters.SAST_PREPASS_NOTE not in note, note


def test_a_malformed_paths_block_costs_the_file_count_not_the_phase():
    """Every claim in the note is read out of the report, and a report shaped
    differently from the one this parser expects must cost the sentence, not
    the analysis."""
    for broken in ({"paths": "oops"}, {"paths": {"scanned": "oops"}},
                   {"paths": ["a"]}, {}):
        notes = adapters.semgrep_notes(broken, "1.175.0", [])
        assert adapters.SAST_PREPASS_NOTE in notes


def test_the_note_says_rules_LOADED_and_not_rules_that_ran():
    """The two numbers differ and the report must not quietly pick the
    flattering one. Semgrep's own summary for the scan this fixture came from
    says "Rules run: 223" where `time.rules` holds 244 -- the 21 are the
    namespaces its table folds into one `<multilang>` row. Every language row
    matches exactly, so the breakdown stands; only the word for the total has
    to be the honest one."""
    note = " ".join(adapters.semgrep_notes(_semgrep_fixture(), "1.175.0", []))
    assert "244 rules loaded" in note, note
    assert "244 rules ran" not in note


# ---------------------------------- a report of a scan that did not happen

# VERBATIM, from `semgrep --config=p/<a pack that does not exist> --json
# --time --output=… .` on a tree holding one Python file. Semgrep exits 7 and
# still WRITES a well-formed report: `results: []`, `paths.scanned: []`. That
# is the identical answer it gives for a tree with nothing wrong in it -- and
# it is what a machine with no network produces when nobody passed
# `--offline`, because the rule pack is fetched from the registry. `run_json`
# checks that a report was written, not what the engine's exit code said, so
# without a guard this lands as a clean SAST pre-pass.
SEMGREP_404 = {
    "version": "1.175.0", "results": [],
    "errors": [
        {"code": 2, "level": "error", "type": "SemgrepError",
         "message": "Failed to download configuration from "
                    "https://semgrep.dev/c/p/nope HTTP 404."},
        {"code": 7, "level": "error", "type": "SemgrepError",
         "message": "invalid configuration file found (1 configs were invalid)"}],
    "paths": {"scanned": []}, "engine_requested": "OSS", "skipped_rules": [],
    "profiling_results": []}


def test_a_report_semgrep_wrote_while_failing_is_not_a_clean_pre_pass(
        monkeypatch, tmp_path):
    """The scar this project already carries once, on the other engine:
    `gitleaks git` outside a repository writes `[]` and exits 0, which is the
    same answer it gives for a clean history. Semgrep does it too, and worse
    -- an unreachable registry is a NORMAL state, not an exotic one."""
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(engines, "run_json",
                        lambda *a, **k: (engines.purge("semgrep", SEMGREP_404), ""))
    monkeypatch.setattr(engines, "version_of", lambda name: "1.175.0")
    findings, notes = adapters.semgrep_scan(root)
    assert findings is None, findings
    assert notes and "did not really" in notes[0], notes


def test_a_file_semgrep_could_not_parse_does_not_condemn_the_whole_report():
    """Semgrep grades a recoverable problem `warn` and keeps the reason for
    `error`. All three parse errors in this repository's own capture are
    warnings, and the 86 files that DID parse are a real result -- refusing
    them would throw away the pass over one unparseable shell script."""
    assert adapters.semgrep_failure(_semgrep_fixture()) == ""
    assert adapters.semgrep_findings(_semgrep_fixture(), root=".")


def test_the_failure_reason_never_quotes_the_engines_own_message():
    """`errors[].message` is the file semgrep could not read -- it is purged
    before this module sees it, and the reason is built from `level` and
    `type` so it could not be quoted even if it were not."""
    reason = adapters.semgrep_failure(SEMGREP_404)
    assert "HTTP 404" not in reason
    assert "SemgrepError" in reason


# ------------------------------- the same silence, with no errors[] to read
#
# VERBATIM, from `semgrep --config=<a pack that is `rules: []`> --json --time
# --output=… .` over a tree of six files. Exit 0. `errors` is EMPTY, which is
# what makes this the sibling `semgrep_failure` cannot see: a pack that loads
# and parses to no rule selects no target, so it writes the identical
# `results: []` / `paths.scanned: []` a clean repository produces and says
# nothing at all about why.
SEMGREP_ZERO_RULES = {
    "version": "1.175.0", "results": [], "errors": [],
    "paths": {"scanned": []}, "time": {"rules": [], "targets": []},
    "engine_requested": "OSS", "skipped_rules": []}


def test_a_report_of_a_scan_that_looked_at_nothing_is_not_a_clean_pre_pass(
        monkeypatch, tmp_path):
    """Exit 7 was closed and its zero-rules sibling was not. `errors: []` means
    `semgrep_failure` answers "" for this, and it landed as a clean pre-pass
    over a tree with six files in it -- the third time this project has met the
    shape (`history_state`, the gitleaks `[]` scar, and the exit-7 report
    above). "Found nothing" and "never looked" are the same silence."""
    assert adapters.semgrep_failure(SEMGREP_ZERO_RULES) == ""
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(engines, "run_json", lambda *a, **k: (
        engines.purge("semgrep", SEMGREP_ZERO_RULES), ""))
    monkeypatch.setattr(engines, "version_of", lambda name: "1.175.0")
    findings, notes = adapters.semgrep_scan(root)
    assert findings is None, findings
    assert notes and "did not really" in notes[0], notes
    assert "scanned no file" in notes[0], notes


def test_the_empty_scan_guard_reads_what_was_scanned_not_what_was_loaded():
    """`time.rules: []` looks like the more direct evidence and is not evidence
    at all: measured, semgrep writes it whenever `--time` was not passed, over
    a tree it scanned perfectly well. A guard on it would refuse a healthy scan
    the day a flag moved."""
    scanned_without_time = {"paths": {"scanned": ["a.py", "b.py"]},
                            "time": {"rules": []}, "results": []}
    assert adapters.semgrep_empty_scan(scanned_without_time) == ""
    assert adapters.semgrep_empty_scan({"paths": {"scanned": []}}) != ""


def test_a_paths_block_this_parser_cannot_read_is_not_read_as_a_zero():
    """A malformed `paths` block costs the file count and not the phase, so an
    absent or unreadable one must not reach the refusal above as "no file was
    scanned" -- that is a claim only a well-formed empty list can make."""
    for shape in ({}, {"paths": "oops"}, {"paths": {"scanned": "oops"}},
                  {"paths": ["a"]}, {"paths": {}}):
        assert adapters.semgrep_empty_scan(shape) == "", shape


@needs_semgrep
def test_the_real_engine_writing_an_empty_report_is_declared_not_swallowed(
        tmp_path):
    """The reproduction, against the binary: a rule pack that is well-formed
    YAML and parses to no rule."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "import hashlib\n\n\ndef etag(body):\n"
        "    return hashlib.md5(body).hexdigest()\n")
    pack = tmp_path / "empty-pack.yaml"
    pack.write_text("rules: []\n")
    findings, notes = _semgrep_scan_with_config(root, str(pack))
    assert findings is None, findings
    assert notes and "did not really" in notes[0], notes


def _semgrep_scan_with_config(root, config):
    """`semgrep_scan` against a different rule pack, for the one test that
    needs a pack this project does not ship. `SEMGREP_CONFIG` is pinned rather
    than configurable on purpose -- `taxonomy.py`'s OWASP codes are the edition
    that pack targets -- so this swaps the constant rather than adding an
    argument nothing in production would ever pass."""
    saved = adapters.SEMGREP_CONFIG
    adapters.SEMGREP_CONFIG = config
    try:
        return adapters.semgrep_scan(root)
    finally:
        adapters.SEMGREP_CONFIG = saved


# ---------------------------------------------- what the reason may contain

def test_an_error_level_this_parser_has_never_heard_of_refuses_the_report():
    """The list is of the words that mean semgrep RECOVERED, not of the words
    that mean it failed. Testing `level == "error"` let every other word
    through as harmless: a `fatal` or `critical` a future version introduces,
    and an entry carrying no level at all, were each read as recoverable."""
    for level in ("fatal", "critical", "", None):
        entry = {"type": "SemgrepError", "message": "x"}
        if level is not None:
            entry["level"] = level
        assert adapters.semgrep_failure({"errors": [entry]}) != "", level
    for level in ("warn", "WARN", "warning", "info"):
        assert adapters.semgrep_failure(
            {"errors": [{"level": level, "type": "Syntax error"}]}) == "", level


def test_a_structured_error_type_cannot_put_a_path_into_the_note():
    """`SAST_FAILED` promises the note names the error TYPES and nothing else,
    and `str(entry["type"])` did not keep it: real semgrep writes
    `["PartialParsing", [{"path": …}]]`, whose `str()` carries this
    repository's own file paths -- through a field `engines.PURGE` cannot help
    with, since a path is not matched content. Not reachable at `level:
    "error"` in 1.175.0; closed by construction rather than by knowing that."""
    reason = adapters.semgrep_failure({"errors": [{
        "level": "error",
        "type": ["PartialParsing", [{"path": "bin/claude-cron",
                                     "start": {"line": 1}}]]}]})
    assert "PartialParsing" in reason, reason
    assert "bin/claude-cron" not in reason, reason
    assert "path" not in reason, reason


@pytest.mark.parametrize("kind", [
    "/etc/passwd", "bin/claude-cron", "a.py", {"path": "x"}, 7, None, "",
    ["/etc/passwd"], [["nested"]], "x" * 200])
def test_an_error_type_that_is_not_a_name_becomes_the_word_error(kind):
    """Whatever shape a future version invents, what reaches the note is
    something `_ERROR_TYPE_RE` accepts -- a name -- and a filesystem path
    cannot be one, since it needs a `/` or a `.` to be a path. The report is
    still refused: the sentence says so with or without a name."""
    reason = adapters.semgrep_failure(
        {"errors": [{"level": "error", "type": kind}]})
    assert reason != ""
    assert "(error)" in reason, reason


def test_prepare_declares_a_pre_pass_that_failed_rather_than_recording_nothing(
        tmp_path, monkeypatch):
    monkeypatch.setattr(adapters.engines, "run_json",
                        lambda *a, **k: (engines.purge("semgrep", SEMGREP_404), ""))
    monkeypatch.setattr(adapters, "engine_path", lambda name: "/usr/bin/semgrep"
                        if name == "semgrep" else None)
    findings, notes = security_cli._scan_sast(tmp_path, offline=False)
    assert findings == []
    assert len(notes) == 1 and notes[0].startswith("The SAST pre-pass did not run")
