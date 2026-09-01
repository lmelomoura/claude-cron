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
import subprocess
import sys
from pathlib import Path

import pytest

from security import adapters, engines, fingerprint, secrets

FIX = Path(__file__).parent / "fixtures" / "engines"
REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"

HAVE_GITLEAKS = engines.find("gitleaks") is not None
needs_gitleaks = pytest.mark.skipif(
    not HAVE_GITLEAKS, reason="gitleaks is not installed on this machine")

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
    # The promise, asserted over the whole record rather than field by
    # field: nothing this adapter emits may contain the matched text.
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    blob = json.dumps(adapters.gitleaks(data, root="."))
    assert "Secret" not in blob and "Match" not in blob


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
    one report later."""
    root = plant(tmp_path / "repo")
    db = tmp_path / "security.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "on"}
    aid = open_analysis(db)
    cli_json(db, "prepare", "--analysis", str(aid), "--root", str(root),
             "--offline", "--ignore", "app.env,tests/fixtures/**", env=env)
    findings = cli_json(db, "findings", "--analysis", str(aid), env=env)
    assert [f for f in findings if f["category"] == "secret"] == []


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
    binary other tools on the machine share."""
    monkeypatch.setenv("CC_SECURITY_ENGINES", "off")
    assert adapters.engine_path("gitleaks") is None
    monkeypatch.setenv("CC_SECURITY_ENGINES", "on")
    assert (adapters.engine_path("gitleaks") is not None) == HAVE_GITLEAKS
    monkeypatch.delenv("CC_SECURITY_ENGINES")
    assert (adapters.engine_path("gitleaks") is not None) == HAVE_GITLEAKS
