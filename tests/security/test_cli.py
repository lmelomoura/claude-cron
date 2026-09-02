"""The one door between the engine and the ledger.

Everything an analysis does -- opening the row, the deterministic phases, the
agent's own findings, closing it, the checklist, the reports -- goes through
`bin/security/cli.py`. These tests drive it as a subprocess, the same way the
agent and bash do, because the process boundary IS the contract: an exit code
and a line of JSON on stdout.

One test group near the bottom (the ledger-write-failure tests) is the
exception: it needs to monkeypatch `ledger.record_event` mid-call, which a
subprocess boundary cannot see, so it imports `security.cli` directly and
calls `main()` in-process instead.
"""

import inspect
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from security.fingerprint import fingerprint as compute_fingerprint, secret_fingerprint
from security import cli as security_cli
from security import ledger as security_ledger
from security import taxonomy as security_taxonomy

REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"

# What `cmd_security_analyze` exports into the analysis run, and therefore what
# every command the agent types from its own tool shell arrives with.
AS_AGENT = {**os.environ, "CC_SECURITY_AGENT": "1"}


def run(db, *args, stdin=None, env=None):
    out = subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, input=stdin, check=False, env=env)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout) if out.stdout.strip() else None


def fails(db, *args, stdin=None, env=None):
    return subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, input=stdin, check=False, env=env)


def raw(db, *args, env=None):
    """Like `run`, but for a verb whose stdout is not JSON -- `fingerprint`
    prints a bare hex string so it can be captured directly in `$(...)`."""
    out = subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, check=False, env=env)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def open_analysis(db, project="web", repo="web", branch="main", commit="abc",
                  profile="quick", run_id="r1"):
    return run(db, "open-analysis", "--project", project, "--repo", repo,
               "--branch", branch, "--commit", commit, "--profile", profile,
               "--run-id", run_id)["analysis_id"]


def prepared_analysis(db, tmp_path, **kw):
    """An analysis whose deterministic phases have actually run.

    `finish --state done` is DOWNGRADED to `capped` for an analysis that never
    ran `prepare` (see cmd_finish), so a test about what a close does has to
    start from a prepared row or it is quietly testing that guard instead of
    the thing it names.
    """
    aid = open_analysis(db, **kw)
    root = tmp_path / f"repo-{aid}"
    root.mkdir(parents=True, exist_ok=True)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    return aid


def test_prepare_then_report_then_finish(tmp_path):
    """The whole shape of one analysis, on EITHER scanner.

    The planted key is scaffolding -- this test is about prepare -> report ->
    finish -> checklist, not about secret detection -- but scaffolding a
    lifecycle test on material only one scanner reports means proving the
    lifecycle in only one configuration. It used to plant AWS's own
    documentation key (AKIAIOSFODNN7EXAMPLE), which gitleaks deliberately
    allowlists: `findings >= 1` below was true on the built-in scanner and
    false on the engine, so with `CC_SECURITY_ENGINES=on` -- what a real
    analysis runs with -- this test failed on its second line and proved
    nothing about the four verbs it names. The key here is shaped like a live
    one and assembled at runtime, the way test_adapters.py's is and for the
    same reason, so both scanners report it and the lifecycle is proved twice.
    """
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (root / "prod.env").write_text("AWS_ACCESS_KEY_ID=AKIA" + "QYLPMN5HNXMEFRTG\n")
    db = tmp_path / "security.db"

    aid = open_analysis(db)
    prepared = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
                   "--offline")
    assert prepared["findings"] >= 1

    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "b" * 64, "category": "sast", "rule": "sql-injection",
        "severity": "high", "title": "t", "rationale": "r", "remediation": "m",
        "occurrences": [{"file": "app.py", "line": 1, "snippet_hash": "h"}]}))
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "0.5")

    checklist = run(db, "checklist", "--analysis", str(aid))
    states = {f["state"] for f in checklist["findings"]}
    assert states == {"new"}


def test_the_agent_cannot_report_a_finding_without_a_fingerprint(tmp_path):
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = open_analysis(db, commit="a", run_id="r")
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    out = fails(db, "report-finding", "--analysis", str(aid),
                stdin=json.dumps({"rule": "x"}))
    assert out.returncode != 0
    assert "fingerprint" in out.stderr


def test_a_fingerprint_that_is_not_a_string_is_refused(tmp_path):
    """SQLite's type affinity would store a numeric fingerprint as a number,
    and compare it as one -- it could never match the same finding recorded
    as text by an earlier analysis, so the checklist would report it `fixed`
    and `new` again on every single run."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": 12345, "category": "sast", "rule": "r",
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "fingerprint" in out.stderr


def test_the_agent_cannot_invent_a_severity(tmp_path):
    """`report-finding` is the agent's only door, and the agent is not
    deterministic: a severity outside the contract would land in the ledger
    and be silently dropped from every report's severity table."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "c" * 64, "category": "sast", "rule": "r",
        "severity": "catastrophic", "title": "t"}))
    assert out.returncode != 0
    assert "severity" in out.stderr


def _finding_row(db, analysis_id):
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM finding WHERE analysis_id=?",
                        (analysis_id,)).fetchone()


def test_report_finding_refuses_a_sast_rule_outside_the_vocabulary(tmp_path):
    """The rule name is part of the fingerprint's identity (see
    taxonomy.py's own docstring): a SAST rule outside the closed vocabulary
    is refused before it ever reaches the ledger, and the error names the
    vocabulary entry the agent should have used instead."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "d" * 64, "category": "sast", "rule": "sqli",
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "sqli" in out.stderr
    assert "sql-injection" in out.stderr  # tells the agent what to use instead
    # The escape hatch has to be IN the refusal, not only in the docstring:
    # an agent that found something real and unlisted reads this sentence and
    # nothing else, and a refusal it cannot act on costs a whole paid run.
    # Backticks, not the bare word: `other` is also a member of the joined
    # vocabulary list, so asserting on the bare word would stay green even if
    # the sentence that TELLS the agent it may use it were deleted.
    assert "`other`" in out.stderr


def test_report_finding_accepts_other_as_the_escape_hatch(tmp_path):
    """The refusal above advertises `other`; this is the proof it works.

    `other` carries no CWE and no OWASP class on purpose (see taxonomy.py):
    an unlisted finding is visibly unclassified rather than quietly filed
    under the nearest wrong rule."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "4" * 64, "category": "sast", "rule": "other",
        "severity": "high", "title": "t",
        "rationale": "Nothing in the vocabulary fits: it is a logic flaw in "
                     "the refund path."}))
    row = _finding_row(db, aid)
    assert row["rule"] == "other"
    assert row["cwe"] == ""
    assert row["owasp"] == ""


def test_report_finding_refuses_a_category_outside_the_closed_set(tmp_path):
    """The vocabulary gate keys off `category == "sast"`, so an unvalidated
    category was one character away from skipping it entirely: `"Sast"` fell
    through to the deterministic branch and landed a free-text rule with a
    blank classification in the ledger -- the identity instability the
    vocabulary exists to prevent, reached by the one route around it."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    for bogus in ("Sast", "sast ", "sasT", "secrets"):
        out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
            "fingerprint": "5" * 64, "category": bogus, "rule": "sqli",
            "severity": "high", "title": "t"}))
        assert out.returncode != 0, f"{bogus!r} was accepted"
        assert "sast" in out.stderr and "hygiene" in out.stderr
    # Nothing reached the ledger under any of the four spellings.
    assert _finding_row(db, aid) is None


def test_report_finding_does_not_echo_an_unscanned_rule_that_looks_like_a_key(tmp_path):
    """The vocabulary refusal QUOTES the rule it rejected, and `rule` is not
    one of the free-text fields the secret scanner already covers. stderr from
    `report-finding` is kept in the run log, so a rule carrying a credential
    would be written to disk by the very refusal meant to keep it out."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "6" * 64, "category": "sast", "rule": AWS,
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "rule" in out.stderr
    assert AWS not in out.stdout
    assert AWS not in out.stderr


def test_report_finding_does_not_echo_an_unscanned_category_that_looks_like_a_key(tmp_path):
    """`category` is quoted back by its own vocabulary refusal exactly as
    `rule` is (see the test above and cmd_report_finding's own comment on
    why both are scanned before either gate can quote them): a credential
    pasted into `category` would otherwise be written to the run log by the
    very refusal meant to keep it out."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "8" * 64, "category": AWS, "rule": "r",
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "category" in out.stderr
    assert AWS not in out.stdout
    assert AWS not in out.stderr


def test_report_finding_refuses_a_deterministic_rule_that_carries_a_credential(tmp_path):
    """`rule` is agent-written for EVERY category, deterministic ones
    included -- it is stored verbatim and rendered on the report page. The
    "cannot leak by construction" guarantee was only ever true of the
    occurrence columns, never of this one."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "7" * 64, "category": "hygiene", "rule": AWS,
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert AWS not in out.stdout
    assert AWS not in out.stderr
    assert _finding_row(db, aid) is None


def test_report_finding_derives_the_classification_from_the_rule(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "e" * 64, "category": "sast", "rule": "sql-injection",
        "severity": "high", "title": "t"}))
    row = _finding_row(db, aid)
    assert row["cwe"] == "CWE-89"
    assert row["owasp"] == "A03:2021"


def test_report_finding_ignores_a_classification_sent_by_the_agent(tmp_path):
    """Two sources of truth in one row is how a CWE ends up disagreeing with
    the rule beside it. The vocabulary wins, always -- whatever the agent
    sends for `cwe`/`owasp` is overwritten by what the rule derives to."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "f" * 64, "category": "sast", "rule": "sql-injection",
        "severity": "high", "title": "t",
        "cwe": "CWE-79", "owasp": "A01:2021"}))
    row = _finding_row(db, aid)
    assert row["cwe"] == "CWE-89"
    assert row["owasp"] == "A03:2021"


def test_report_finding_ignores_a_scope_sent_by_the_agent(tmp_path):
    """`scope` is read from a LOCKFILE by whichever dependency producer ran.
    The agent reads no lockfile, so anything it sends under this name is a
    guess sitting in a column a reader takes for a measurement. Dropped rather
    than refused, so that Job 2's re-report of a dependency finding still
    works -- and `record_finding`'s upsert leaves the column alone, so the
    value the dependency phase established survives that re-report."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "d" * 64, "category": "dependency", "rule": "CVE-1",
        "severity": "high", "title": "t", "scope": "runtime"}))
    assert _finding_row(db, aid)["scope"] == ""


def test_report_finding_accepts_a_deterministic_rule_unchanged(tmp_path):
    """The vocabulary is for SAST only. A hygiene rule name is produced by our
    own Python and must not be forced through a vocabulary written for the
    agent."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "0" * 64, "category": "hygiene",
        "rule": "committed_env_file", "severity": "high", "title": "t"}))
    row = _finding_row(db, aid)
    assert row["cwe"] == ""
    assert row["owasp"] == ""


def test_the_agent_cannot_report_into_an_analysis_that_does_not_exist(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "report-finding", "--analysis", "999", stdin=json.dumps({
        "fingerprint": "d" * 64, "category": "hygiene", "rule": "r",
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "999" in out.stderr


AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def test_a_finding_whose_rationale_contains_a_live_looking_key_is_refused(tmp_path):
    """The deterministic categories cannot leak a value by construction --
    no column, no return, no argument for it. A SAST finding's free text used
    to be validated for shape only (required keys, severity, MAX_TEXT), never
    for content, so nothing at the door stopped an agent from writing a
    matched credential straight into a rationale. The refusal must name the
    field and the rule, and the key's text must appear NOWHERE in stdout or
    stderr -- a refusal that echoes the secret back would defeat itself."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "e" * 64, "category": "sast", "rule": "hardcoded-credentials",
        "severity": "high", "title": "t",
        "rationale": f"Found a live credential: {AWS}"}))
    assert out.returncode != 0
    assert "rationale" in out.stderr
    assert "aws_access_key" in out.stderr
    assert AWS not in out.stdout
    assert AWS not in out.stderr


def test_a_finding_whose_title_contains_a_live_looking_key_is_refused(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "f" * 64, "category": "sast", "rule": "hardcoded-credentials",
        "severity": "high", "title": f"Key exposed: {AWS}"}))
    assert out.returncode != 0
    assert "title" in out.stderr
    assert AWS not in out.stdout
    assert AWS not in out.stderr


def test_a_finding_whose_remediation_contains_a_live_looking_key_is_refused(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "1" * 64, "category": "sast", "rule": "hardcoded-credentials",
        "severity": "high", "title": "t", "rationale": "r",
        "remediation": f"Rotate {AWS} immediately"}))
    assert out.returncode != 0
    assert "remediation" in out.stderr
    assert AWS not in out.stdout
    assert AWS not in out.stderr


def test_a_finding_that_describes_a_credential_instead_of_quoting_it_is_accepted(tmp_path):
    """The control: the check must not make the tool unusable for the normal
    case of writing ABOUT a credential without reproducing it."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "2" * 64, "category": "sast", "rule": "hardcoded-credentials",
        "severity": "high", "title": "Hardcoded AWS key",
        "rationale": "An AWS access key is hardcoded in config/prod.env at line 12."}))


def test_a_finding_whose_rationale_names_an_obvious_placeholder_is_accepted(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "3" * 64, "category": "sast", "rule": "hardcoded-credentials",
        "severity": "high", "title": "t",
        "rationale": 'Default credential left in place: '
                     'password = "changeme12345678901234"'}))


def test_the_agent_cannot_send_something_that_is_not_json(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin="not json")
    assert out.returncode != 0
    assert "JSON" in out.stderr


def test_offline_mode_declares_the_gap(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db, commit="a", run_id="r")
    prepared = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
                   "--offline")
    assert "OSV" in prepared["coverage_note"]


def test_finishing_does_not_erase_the_coverage_note(tmp_path):
    """`finish_analysis` writes coverage_note unconditionally, and neither
    caller of `finish` carries it: the agent never saw it, and the engine's
    close-out knows only the run's status and cost. An empty --note must
    therefore keep what `prepare` recorded, or the one line of the report
    that says what was NOT looked at disappears at the last step."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    assert note
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "0")
    rendered = json.loads(run_text(db, "render", "--analysis", str(aid),
                                   "--format", "json"))
    # `coverage.notes` is what the JSON report's `coverage` key used to BE, in
    # the same order -- the structured `coverage.phases` was added BESIDE the
    # prose, and this assertion is here to catch the day somebody decides the
    # table has made the paragraph redundant. It has not: the paragraph is
    # what every analysis written before the `coverage` column carries, and it
    # is where the reasons live.
    assert note in rendered["coverage"]["notes"]


def run_text(db, *args):
    out = subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    return out.stdout


def test_a_note_given_explicitly_is_added_to_the_stored_one(tmp_path):
    """The coverage note is the list of this report's blind spots, and the two
    callers of `finish` each know a different one: `prepare` recorded that
    OSV.dev was never asked, and the close-out knows the agent stopped early.
    Substituting one for the other publishes a report that names half of what
    it did not look at -- so the note is APPENDED, never replaced."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = open_analysis(db)
    stored = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
                 "--offline")["coverage_note"]
    assert stored
    run(db, "finish", "--analysis", str(aid), "--state", "failed",
        "--note", "the agent never reached the SAST phase")
    row = run(db, "list", "--project", "web")[0]
    assert row["coverage_note"] == f"{stored} the agent never reached the SAST phase"


def test_the_same_note_twice_is_not_stored_twice(tmp_path):
    """A row can be closed more than once (the agent, then the engine). The
    note must not grow a copy of itself every time."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "failed",
        "--note", "the run never started")
    run(db, "finish", "--analysis", str(aid), "--state", "failed",
        "--note", "the run never started")
    row = run(db, "list", "--project", "web")[0]
    assert row["coverage_note"] == "the run never started"


def test_finish_if_running_does_not_reopen_a_closed_analysis(tmp_path):
    """The engine sweeps for a row left `running` by a run that never reached
    its close-out (the slot gate, a missing cwd). That sweep must be a no-op
    for the ordinary case where the run really happened and already closed
    the row -- otherwise every analysis would end up `failed`."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "1.25")
    run(db, "finish", "--analysis", str(aid), "--state", "failed", "--if-running")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert row["spend_usd"] == 1.25


def test_finish_if_running_closes_a_row_the_run_never_reached(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "failed", "--if-running",
        "--note", "the run never started")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "failed"


def test_a_malformed_spend_does_not_lose_the_close(tmp_path):
    """The spend arrives from the run's own cost field, which the engine
    already treats as untrusted text elsewhere. A row left `running` for
    ever is a far worse outcome than a cost recorded as zero."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "n/a")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert row["spend_usd"] == 0


def test_render_produces_all_three_formats(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db, commit="a", run_id="r")
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "0")
    for fmt in ("json", "md", "html"):
        out = subprocess.run(
            [sys.executable, str(CLI), "render", "--analysis", str(aid),
             "--format", fmt, "--db", str(db)],
            capture_output=True, text=True, check=False)
        assert out.returncode == 0 and out.stdout.strip()


def test_the_db_flag_is_accepted_before_the_subcommand_too(tmp_path):
    """bash passes it first (`security_py finish --analysis N`), the agent and
    these tests pass it last. Both have to work, or one of the two callers
    breaks the moment the other's form is the one that was tested."""
    db = tmp_path / "security.db"
    out = subprocess.run(
        [sys.executable, str(CLI), "--db", str(db), "open-analysis",
         "--project", "web", "--repo", "web", "--branch", "main",
         "--commit", "a", "--profile", "quick", "--run-id", "r"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["analysis_id"] == 1


def test_no_db_at_all_is_refused_rather_than_guessed(tmp_path):
    out = subprocess.run(
        [sys.executable, str(CLI), "list", "--project", "web"],
        capture_output=True, text=True, check=False)
    assert out.returncode != 0
    assert "--db" in out.stderr


# ---------------------------------------------------------------- the checklist

def two_analyses(db, before, after):
    """One finding, reported with `before`'s occurrences and then with
    `after`'s, and the checklist state the second analysis gives it."""
    finding = {"fingerprint": "e" * 64, "category": "hygiene", "rule": "r",
               "severity": "high", "title": "t", "occurrences": before}
    first = open_analysis(db, run_id="r1")
    run(db, "report-finding", "--analysis", str(first), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(first), "--state", "done")

    finding["occurrences"] = after
    second = open_analysis(db, commit="def", run_id="r2")
    run(db, "report-finding", "--analysis", str(second), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(second), "--state", "done")
    return [f["state"] for f in run(db, "checklist", "--analysis", str(second))["findings"]]


def test_a_finding_that_lost_a_file_is_partial_not_open(tmp_path):
    """`diff.classify` takes `closed_occurrences` as its OBJECTIVE half of
    the partial signal -- the anchor two runs cannot disagree about. Nothing
    persists that number, and the checklist is the only place the two analyses
    meet, so it is computed there or the branch is dead and `partial` can only
    ever come from the agent's own note."""
    assert two_analyses(tmp_path / "security.db",
                        [{"file": "a.py", "line": 1}, {"file": "b.py", "line": 2}],
                        [{"file": "a.py", "line": 1}]) == ["partial"]


def test_a_finding_that_did_not_shrink_is_open(tmp_path):
    assert two_analyses(tmp_path / "security.db",
                        [{"file": "a.py", "line": 1}],
                        [{"file": "a.py", "line": 1}]) == ["open"]


def test_progress_is_measured_in_files_closed_not_in_hits_counted(tmp_path):
    """Both directions of the same mistake -- subtracting two counts.

    Two hits in one file dropping to one is NOT progress: the file still
    holds the hole, and someone deleting a duplicate line would be reported
    as a partial fix nobody made. And one hit in `auth.py` becoming one hit
    in `admin.py` IS progress on one place (and a new place opened), which a
    count of 1 against a count of 1 cannot see at all.
    """
    assert two_analyses(tmp_path / "one-file.db",
                        [{"file": "a.py", "line": 1}, {"file": "a.py", "line": 9}],
                        [{"file": "a.py", "line": 1}]) == ["open"]
    assert two_analyses(tmp_path / "moved.db",
                        [{"file": "auth.py", "line": 1}],
                        [{"file": "admin.py", "line": 1}]) == ["partial"]


def test_a_decision_is_refused_without_a_reason(tmp_path):
    db = tmp_path / "security.db"
    # Closed first: `decide` refuses outright while an analysis is running (see
    # cmd_decide), and a test about the REASON must not be answered by that.
    run(db, "finish", "--analysis", str(open_analysis(db)), "--state", "failed")
    out = fails(db, "decide", "--project", "web", "--fingerprint", "f" * 64,
                "--state", "accepted", "--reason", "   ", "--by", "me")
    assert out.returncode != 0
    assert "reason" in out.stderr


def test_a_decision_wins_over_the_derived_state(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "a" * 64, "category": "hygiene", "rule": "r",
        "severity": "high", "title": "t"}))
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "false_positive", "--reason", "the sink is parameterised",
        "--by", "luiz")
    checklist = run(db, "checklist", "--analysis", str(aid))
    assert checklist["findings"][0]["state"] == "false_positive"


def test_findings_lists_what_the_deterministic_phase_left_for_the_agent(tmp_path):
    """PINNED to the built-in scanner, because the fixture is one only it
    reports: a PEM header with `xx` where the key material goes. Gitleaks is
    right to ignore that -- its private-key rule wants a body -- so under the
    engine `found` came back empty, `any(...)` failed and, worse,
    `all("occurrences" in f ...)` passed vacuously over the empty list.

    The `any(...)` is what stops the `all(...)` after it being vacuous here
    too, so the two lines are a pair and neither may be dropped. The engine's
    half of this verb is exercised in test_adapters.py, whose engine-path
    tests read `findings` through this same CLI door."""
    env = {**os.environ, "CC_SECURITY_ENGINES": "off"}
    root = tmp_path / "repo"
    root.mkdir()
    (root / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nxx\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline",
        env=env)
    found = run(db, "findings", "--analysis", str(aid), env=env)
    assert any(f["category"] == "secret" for f in found)
    assert all("occurrences" in f for f in found)


# ------------------------------------------------------- renaming a project

def test_renaming_a_project_carries_its_history(tmp_path):
    """The ledger keys an analysis by the project NAME it was opened under.
    `claude-cron project-rename` changes that name in the config, and without
    this every past analysis, every accepted risk and the SBOM would stay
    behind under a name no project has any more."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    aid = open_analysis(db, project="web")
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "internal only", "--by", "luiz")

    moved = run(db, "rename-project", "--from", "web", "--to", "web-two")
    assert moved["analyses"] == 1

    assert run(db, "list", "--project", "web") == []
    assert len(run(db, "list", "--project", "web-two")) == 1
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT count(*) FROM decision WHERE project='web-two'"
                        ).fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM sbom WHERE project='web-two'"
                        ).fetchone()[0] == 1


def test_a_decision_left_behind_by_a_deleted_project_does_not_block_the_rename(tmp_path):
    """(project, fingerprint) is the decision table's primary key, and rows
    outlive the project they were made under -- `project-delete` leaves them.
    Renaming a live project onto that dead name must not fail on the
    conflict, and the live project's own judgement is the one that survives."""
    db = tmp_path / "security.db"
    run(db, "decide", "--project", "gone", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "an old call nobody owns", "--by", "x")
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "false_positive", "--reason", "the live project's call",
        "--by", "luiz")
    run(db, "rename-project", "--from", "web", "--to", "gone")
    conn = sqlite3.connect(str(db))
    rows = conn.execute("SELECT state, reason FROM decision WHERE project='gone'"
                        ).fetchall()
    assert rows == [("false_positive", "the live project's call")]


def test_renaming_a_project_with_no_history_is_a_no_op(tmp_path):
    db = tmp_path / "security.db"
    moved = run(db, "rename-project", "--from", "web", "--to", "web-two")
    assert moved == {"analyses": 0, "decisions": 0, "sboms": 0}


# ------------------------------------------- the agent does not judge itself

def test_the_agent_cannot_dismiss_the_finding_it_just_reported(tmp_path):
    """`decide` writes a permanent, project-wide suppression that outlives
    every future analysis -- and the agent reaches it through the identical
    command an operator does. Reproduced before this guard: from the agent's
    own cwd, `security decide --state false_positive` retired a committed AWS
    key and signed the ledger's `decided_by` as "security team"."""
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
                "--state", "false_positive", "--reason", "I checked it myself",
                "--by", "security team", env=AS_AGENT)
    assert out.returncode != 0
    assert "CC_SECURITY_AGENT" in out.stderr
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT count(*) FROM decision").fetchone()[0] == 0


def test_the_agent_cannot_move_the_ledger_out_from_under_the_project(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db, project="web")
    out = fails(db, "rename-project", "--from", "web", "--to", "mine",
                env=AS_AGENT)
    assert out.returncode != 0
    assert len(run(db, "list", "--project", "web")) == 1


def test_the_agent_cannot_open_an_analysis_the_engine_will_never_close(tmp_path):
    """The engine opens the row before the run and closes it after; a row the
    agent minted itself has no run behind it and nothing to close it, so it
    sits `running` for ever and blocks every later baseline."""
    db = tmp_path / "security.db"
    out = fails(db, "open-analysis", "--project", "web", "--repo", "web",
                "--branch", "main", "--commit", "a", "--profile", "quick",
                "--run-id", "r", env=AS_AGENT)
    assert out.returncode != 0
    assert run(db, "list", "--project", "web") == []


def test_the_work_the_agent_is_there_to_do_still_works_under_the_flag(tmp_path):
    """The flag is on for the WHOLE run, including `security_close_analysis`,
    which runs inside run_job after the agent. Refusing more than the three
    named verbs would break the analysis it is supposed to protect."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline",
        env=AS_AGENT)
    run(db, "report-finding", "--analysis", str(aid), env=AS_AGENT,
        stdin=json.dumps({"fingerprint": "b" * 64, "category": "hygiene",
                          "rule": "r", "severity": "high", "title": "t"}))
    run(db, "findings", "--analysis", str(aid), env=AS_AGENT)
    run(db, "checklist", "--analysis", str(aid), env=AS_AGENT)
    run(db, "finish", "--analysis", str(aid), "--state", "done", env=AS_AGENT)
    assert run(db, "list", "--project", "web")[0]["state"] == "done"


# ------------------------------------------------ closing an analysis once

def test_a_close_never_upgrades_a_capped_analysis_to_done(tmp_path):
    """The agent's `finish --state capped` is the one honest thing it can say
    about a run it knows was cut short. The engine closes the same row again
    with the RUN's verdict, and `success` there means only that the process
    exited cleanly -- overwriting `capped` with `done` published a truncated
    analysis as a finished one and made it the next run's baseline."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "capped",
        "--note", "I stopped before the SAST phase")
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "2.5")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "capped"
    # The verdict is refused; the run's real cost is still a fact.
    assert row["spend_usd"] == 2.5


def test_a_close_never_upgrades_a_failed_analysis_to_done(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "failed")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    assert run(db, "list", "--project", "web")[0]["state"] == "failed"


def test_a_close_may_still_lower_a_done_analysis(tmp_path):
    """The direction that has to keep working: the agent claims it finished,
    and the engine -- which can see that the run was cut off mid-sentence --
    downgrades it. That claim is the one fact here nothing can verify."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "finish", "--analysis", str(aid), "--state", "capped")
    assert run(db, "list", "--project", "web")[0]["state"] == "capped"
    second = open_analysis(db, commit="def", run_id="r2")
    run(db, "finish", "--analysis", str(second), "--state", "done")
    run(db, "finish", "--analysis", str(second), "--state", "failed")
    assert run(db, "list", "--project", "web")[0]["state"] == "failed"


def test_a_running_analysis_accepts_any_verdict(tmp_path):
    db = tmp_path / "security.db"
    for state in ("done", "capped", "failed"):
        aid = prepared_analysis(db, tmp_path, commit=state)
        run(db, "finish", "--analysis", str(aid), "--state", state)
        rows = {r["id"]: r for r in run(db, "list", "--project", "web")}
        assert rows[aid]["state"] == state


# ------------------------------------------- writing into a closed analysis

def test_a_closed_analysis_refuses_a_new_finding(tmp_path):
    """A closed analysis is the baseline the NEXT one is diffed against.
    A finding written into it after the fact rewrites what the previous run
    is remembered as having found."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "a" * 64, "category": "hygiene", "rule": "r",
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "closed" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_a_closed_analysis_refuses_a_second_prepare(tmp_path):
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    (root / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nxx\n")
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "failed")
    out = fails(db, "prepare", "--analysis", str(aid), "--root", str(root),
                "--offline")
    assert out.returncode != 0
    assert "closed" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


# --------------------------------------------------- the baseline's history

def test_a_failed_first_attempt_does_not_make_everything_regressed(tmp_path):
    """`latest_analysis` refuses a failed analysis as a baseline, so the
    checklist's `history` -- what separates `new` from "fixed and came back"
    -- has to refuse it too. Without the filter, the first analysis after a
    failed one reports every finding the failed attempt happened to reach as
    `regressed`: news that a hole was fixed and returned, about a hole that
    never left."""
    db = tmp_path / "security.db"
    finding = {"fingerprint": "e" * 64, "category": "hygiene", "rule": "r",
               "severity": "high", "title": "t",
               "occurrences": [{"file": "a.py", "line": 1}]}
    first = open_analysis(db, run_id="r1")
    run(db, "report-finding", "--analysis", str(first), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(first), "--state", "failed")

    second = open_analysis(db, commit="def", run_id="r2")
    run(db, "report-finding", "--analysis", str(second), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(second), "--state", "done")

    checklist = run(db, "checklist", "--analysis", str(second))
    assert [f["state"] for f in checklist["findings"]] == ["new"]


def test_a_finding_that_really_did_come_back_is_still_regressed(tmp_path):
    """The other side of the filter: a DONE analysis still feeds history, so
    a finding that was fixed and returned is not quietly downgraded to new."""
    db = tmp_path / "security.db"
    finding = {"fingerprint": "e" * 64, "category": "hygiene", "rule": "r",
               "severity": "high", "title": "t",
               "occurrences": [{"file": "a.py", "line": 1}]}
    first = open_analysis(db, run_id="r1")
    run(db, "report-finding", "--analysis", str(first), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(first), "--state", "done")
    second = open_analysis(db, commit="def", run_id="r2")   # fixed: not reported
    run(db, "finish", "--analysis", str(second), "--state", "done")
    third = open_analysis(db, commit="ghi", run_id="r3")
    run(db, "report-finding", "--analysis", str(third), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(third), "--state", "done")
    checklist = run(db, "checklist", "--analysis", str(third))
    assert [f["state"] for f in checklist["findings"]] == ["regressed"]


# ------------------------------------------------- the shape of a finding

def test_a_fingerprint_that_is_not_a_sha256_is_refused(tmp_path):
    """The fingerprint is the identity a later analysis matches this finding
    on. One the agent invents ("aws-key-in-prod-env") is a fresh identity on
    every run: the same hole is reported `new` for ever, never `open`, never
    `fixed`, and a decision recorded against it never matches again."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    for bad in ("aws-key-in-prod-env", "A" * 64, "abc123", "f" * 63, "f" * 65,
                " " + "f" * 63):
        out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
            "fingerprint": bad, "category": "hygiene", "rule": "r",
            "severity": "high", "title": "t"}))
        assert out.returncode != 0, bad
        assert "fingerprint" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_a_finding_cannot_paste_a_whole_file_into_the_ledger(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    for key in ("title", "rationale", "remediation", "partial_note"):
        payload = {"fingerprint": "a" * 64, "category": "hygiene", "rule": "r",
                   "severity": "high", "title": "t", key: "x" * 10001}
        out = fails(db, "report-finding", "--analysis", str(aid),
                    stdin=json.dumps(payload))
        assert out.returncode != 0, key
        assert key in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_a_line_number_too_large_to_be_one_is_a_sentence_not_a_traceback(tmp_path):
    """`1e999` parses as JSON infinity, and `int(inf)` raises OverflowError,
    which is not a ValueError: the agent got a Python traceback and no
    sentence telling it what was wrong with its finding."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "a" * 64, "category": "hygiene", "rule": "r",
        "severity": "high", "title": "t",
        "occurrences": [{"file": "a.py", "line": 1e999}]}))
    assert out.returncode != 0
    assert "Traceback" not in out.stderr
    assert "report-finding" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_deeply_nested_json_on_stdin_gives_a_sentence_not_a_traceback_for_report_finding(tmp_path):
    """A deeply nested JSON body raises RecursionError; the door must catch it
    and exit with a sentence rather than a Python traceback."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    # Create a deeply nested structure (~20000 levels) that triggers RecursionError
    malformed = '{"a":' * 20000 + "1" + "}" * 20000
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=malformed)
    assert out.returncode != 0
    assert "Traceback" not in out.stderr
    assert "report-finding" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_deeply_nested_json_on_stdin_gives_a_sentence_not_a_traceback_for_filters_save(tmp_path):
    """Same guard for `filters save`: deeply nested JSON raises RecursionError."""
    db = tmp_path / "security.db"
    # Create a deeply nested structure that triggers RecursionError
    malformed = '{"a":' * 20000 + "1" + "}" * 20000
    out = fails(db, "filters", "save", "--project", "web", "--name", "test",
                stdin=malformed)
    assert out.returncode != 0
    assert "Traceback" not in out.stderr
    assert "filters save" in out.stderr


def test_report_finding_refuses_stdin_over_the_byte_cap(tmp_path):
    """A body over MAX_STDIN_BYTES is refused before parsing."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    # Create a body larger than 1MB
    oversized = "x" * (1_000_001)
    out = fails(db, "report-finding", "--analysis", str(aid), stdin=oversized)
    assert out.returncode != 0
    assert "1000000" in out.stderr or "1_000_000" in out.stderr.replace("_", "")
    assert "Traceback" not in out.stderr


def test_filters_save_refuses_stdin_over_the_byte_cap(tmp_path):
    """A body over MAX_STDIN_BYTES is refused before parsing."""
    db = tmp_path / "security.db"
    # Create a body larger than 1MB
    oversized = "x" * (1_000_001)
    out = fails(db, "filters", "save", "--project", "web", "--name", "test",
                stdin=oversized)
    assert out.returncode != 0
    assert "1000000" in out.stderr or "1_000_000" in out.stderr.replace("_", "")
    assert "Traceback" not in out.stderr


def test_report_finding_with_normal_body_still_works(tmp_path):
    """The control: small, normal JSON still parses and works."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "a" * 64, "category": "hygiene", "rule": "r",
        "severity": "high", "title": "t"}))
    found = run(db, "findings", "--analysis", str(aid))
    assert any(f["rule"] == "r" for f in found)


def test_filters_save_with_normal_body_still_works(tmp_path):
    """The control: small, normal JSON still parses and works."""
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "test",
        stdin=json.dumps({"category": "sast", "severity": "high"}))
    saved = run(db, "filters", "list", "--project", "web")
    assert any(f["name"] == "test" for f in saved)


def test_prepare_refuses_to_scan_the_whole_machine(tmp_path):
    """`--root` is typed by the agent, from inside a worktree it did not
    choose. Pointed at `/` or at $HOME, the deterministic phases read every
    file the operator owns -- ssh keys, other people's repositories -- and
    file them as findings OF THIS PROJECT in a ledger the report publishes."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    for root in ("/", str(Path.home()), str(Path.home() / "." / ""), "/srv/../"):
        out = fails(db, "prepare", "--analysis", str(aid), "--root", root,
                    "--offline")
        assert out.returncode != 0, root
        assert "--root" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


# ---------------------------------- --root is anchored to the run's own worktree

def _isolated_env(manifest_path):
    """What `run_job` exports into an isolated run (see bin/claude-cron and
    bin/worktree-lib.sh:wt_setup) -- CC_SECURITY_AGENT marks the whole run as
    the agent under review, and CC_RUN_MANIFEST names that run's own
    `.run.json`, written into the run's own directory before the agent ever
    starts."""
    return {**os.environ, "CC_SECURITY_AGENT": "1",
            "CC_RUN_MANIFEST": str(manifest_path)}


def test_prepare_root_outside_the_runs_worktree_is_refused_when_isolated(tmp_path):
    """Reproduced before the guard: an agent pointing `--root` at ANY other
    valid checkout on the machine got a clean scan of code nobody asked about,
    `prepare` marked the row `prepared=1`, and the analysis closed `done` with
    clean findings having never looked at its own scope at all."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run_dir = tmp_path / "run-dir"
    run_dir.mkdir()
    manifest = run_dir / ".run.json"
    manifest.write_text("{}")
    elsewhere = tmp_path / "some-other-checkout"
    elsewhere.mkdir()
    out = fails(db, "prepare", "--analysis", str(aid), "--root", str(elsewhere),
                "--offline", env=_isolated_env(manifest))
    assert out.returncode != 0
    assert "own worktree" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_prepare_root_prefix_collision_with_the_run_dir_is_still_refused(tmp_path):
    """The nearest neighbour to the boundary just closed: a SIBLING directory
    whose name merely starts with the run dir's own name (`run-dir-evil`
    starts with `run-dir`). A check written as a string prefix comparison
    would wrongly accept it; path containment must be exact."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run_dir = tmp_path / "run-dir"
    run_dir.mkdir()
    manifest = run_dir / ".run.json"
    manifest.write_text("{}")
    sibling = tmp_path / "run-dir-evil"
    sibling.mkdir()
    out = fails(db, "prepare", "--analysis", str(aid), "--root", str(sibling),
                "--offline", env=_isolated_env(manifest))
    assert out.returncode != 0
    assert "own worktree" in out.stderr


def test_prepare_root_inside_the_runs_worktree_is_accepted(tmp_path):
    """The control: the genuine case -- `--root` naming the checkout the
    engine actually built for this run -- must still work."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run_dir = tmp_path / "run-dir"
    checkout = run_dir / "web"
    checkout.mkdir(parents=True)
    manifest = run_dir / ".run.json"
    manifest.write_text("{}")
    out = run(db, "prepare", "--analysis", str(aid), "--root", str(checkout),
              "--offline", env=_isolated_env(manifest))
    assert out["findings"] == 0


def test_prepare_root_check_is_unchanged_without_the_run_manifest(tmp_path):
    """A human running `prepare` by hand, outside any run, carries neither
    CC_SECURITY_AGENT nor CC_RUN_MANIFEST -- the anchor must refuse nothing
    new for that case."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    anywhere = tmp_path / "any-checkout-at-all"
    anywhere.mkdir()
    env = {k: v for k, v in os.environ.items()
           if k not in ("CC_SECURITY_AGENT", "CC_RUN_MANIFEST")}
    out = run(db, "prepare", "--analysis", str(aid), "--root", str(anywhere),
              "--offline", env=env)
    assert out["findings"] == 0


def test_prepare_root_check_is_unchanged_when_agent_flag_is_set_without_a_manifest(tmp_path):
    """CC_SECURITY_AGENT alone (no CC_RUN_MANIFEST) is what
    `test_the_work_the_agent_is_there_to_do_still_works_under_the_flag`
    already exercises for a normal analysis; this pins the same for an
    arbitrary root, so the new guard is provably keyed on BOTH variables, not
    either one alone."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    anywhere = tmp_path / "any-checkout-at-all"
    anywhere.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "CC_RUN_MANIFEST"}
    env["CC_SECURITY_AGENT"] = "1"
    out = run(db, "prepare", "--analysis", str(aid), "--root", str(anywhere),
              "--offline", env=env)
    assert out["findings"] == 0


# ---------------------------------------------------- the fingerprint verb

def test_fingerprint_matches_the_library_for_a_sast_finding(tmp_path):
    """The agent must never hand-compute a fingerprint (see FINGERPRINT_RE's
    comment): this verb is the one place it can get a real one instead, so it
    has to agree with the exact function `report-finding` is validated
    against, not merely produce something 64 hex characters long."""
    db = tmp_path / "security.db"
    got = raw(db, "fingerprint", "--category", "sast", "--rule", "sql-injection",
              "--path", "app/db.py", "--snippet", "cursor.execute(query)")
    assert got == compute_fingerprint("sast", "sql-injection", "app/db.py",
                                      "cursor.execute(query)")


def test_fingerprint_defaults_the_snippet_to_empty(tmp_path):
    db = tmp_path / "security.db"
    got = raw(db, "fingerprint", "--category", "hygiene", "--rule", "world-writable",
              "--path", "deploy.sh")
    assert got == compute_fingerprint("hygiene", "world-writable", "deploy.sh", "")


def test_fingerprint_of_a_secret_uses_secret_fingerprint_semantics(tmp_path):
    """No snippet, no value: a secret's identity is its type and its file,
    never what it says -- see secret_fingerprint's own docstring."""
    db = tmp_path / "security.db"
    got = raw(db, "fingerprint", "--category", "secret", "--rule", "aws_access_key",
              "--path", "config/prod.env")
    assert got == secret_fingerprint("aws_access_key", "config/prod.env")


def test_fingerprint_of_a_secret_ignores_a_snippet_if_one_is_given(tmp_path):
    """A caller looping over occurrences uniformly may pass --snippet for
    every category; a secret's identity must not change because of it."""
    db = tmp_path / "security.db"
    with_snippet = raw(db, "fingerprint", "--category", "secret", "--rule", "aws_access_key",
                       "--path", "config/prod.env", "--snippet", "AKIAIOSFODNN7EXAMPLE")
    without_snippet = raw(db, "fingerprint", "--category", "secret", "--rule", "aws_access_key",
                          "--path", "config/prod.env")
    assert with_snippet == without_snippet == secret_fingerprint("aws_access_key", "config/prod.env")


def test_fingerprint_is_allowed_under_the_agent_environment(tmp_path):
    """It never opens the database -- there is nothing for CC_SECURITY_AGENT
    to protect here, only a computation the agent would otherwise have to
    reproduce by hand and get wrong."""
    db = tmp_path / "security.db"
    got = raw(db, "fingerprint", "--category", "sast", "--rule", "sql-injection",
              "--path", "p", env=AS_AGENT)
    assert got == compute_fingerprint("sast", "sql-injection", "p", "")


def test_fingerprint_refuses_a_sast_rule_outside_the_vocabulary(tmp_path):
    """The same door as report-finding, saying the same thing at the same
    time (see `cmd_fingerprint`): an agent that got a well-formed fingerprint
    for `sqli` would build a whole payload around an identity `report-finding`
    then refuses to store."""
    db = tmp_path / "security.db"
    out = fails(db, "fingerprint", "--category", "sast", "--rule", "sqli",
               "--path", "app/db.py", "--snippet", "x")
    assert out.returncode != 0
    assert "sql-injection" in out.stderr


def test_fingerprint_still_serves_deterministic_categories(tmp_path):
    """The sast-only vocabulary gate must not reach a category whose rule
    names come from our own scanners, not from the agent -- `aws_access_key`
    is not a SAST rule name and must still fingerprint cleanly."""
    db = tmp_path / "security.db"
    got = raw(db, "fingerprint", "--category", "secret", "--rule",
              "aws_access_key", "--path", "config/prod.env")
    assert len(got) == 64


def test_fingerprint_does_not_echo_an_unscanned_rule_that_looks_like_a_key(tmp_path):
    """The same door as report-finding's rule refusal, scanned for the same
    reason (see cmd_fingerprint's own docstring): this verb's SAST-rule
    refusal quotes `args.rule` back into stderr, and that stderr lands in
    the same run log report-finding's does. A rule shaped like a live
    credential must be refused before that refusal can quote it."""
    db = tmp_path / "security.db"
    out = fails(db, "fingerprint", "--category", "sast", "--rule", AWS,
               "--path", "app/db.py")
    assert out.returncode != 0
    assert AWS not in out.stdout
    assert AWS not in out.stderr


def test_fingerprint_refuses_a_category_outside_the_closed_set(tmp_path):
    """`--category` has had `choices=FINDING_CATEGORIES` since the argparse
    constraint was added: before it existed, `--category Secret` (a
    spelling one character off from the real `secret`) fell through to the
    snippet-hashing path in `cmd_fingerprint`'s `else` branch, hashing a
    credential's value into the fingerprint -- the exact thing
    `secret_fingerprint` exists to avoid. argparse itself enforces the
    closed set here, with its own usage message, not one of ours."""
    db = tmp_path / "security.db"
    out = fails(db, "fingerprint", "--category", "Secret", "--rule", "r",
               "--path", "app.py")
    assert out.returncode == 2
    assert "invalid choice" in out.stderr


# --------------------------------------------- the history sweep, every run

def git_repo(root, commits):
    """A throwaway repo. `commits` is a list of (message, {path: text|None});
    None deletes the file.

    Carries its own `.gitignore` from the start -- these fixtures are not
    about the `missing_gitignore` advisory (see hygiene.py), and without one
    every one of them would trip it, adding an unrelated finding to tests
    that assert exact finding counts or exact checklist state maps.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / ".gitignore").write_text(".env\n")
    run_git = lambda *a: subprocess.run(a, cwd=root, check=True, capture_output=True)
    run_git("git", "init", "-q")
    run_git("git", "config", "user.email", "t@example.com")
    run_git("git", "config", "user.name", "t")
    for message, files in commits:
        for rel, text in files.items():
            target = root / rel
            if text is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
        run_git("git", "add", "-A")
        run_git("git", "commit", "-qm", message)
    return root


# AWS's own documentation key, which gitleaks allowlists on purpose. That is
# exactly why it is still here: every test below that uses it is PINNED to the
# built-in scanner and asserts the built-in scanner's rule names, and a fixture
# the engine reports too would invite somebody to unpin one of them. The
# detectable shape lives in test_adapters.py (`AKIA` + `QYLPMN5HNXMEFRTG`) and
# in `test_prepare_then_report_then_finish`, which is engine-neutral.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


# THREE TESTS THAT USED TO SIT HERE NOW LIVE IN test_adapters.py, parametrised
# over `ENGINE_MATRIX` so each is proved on the built-in scanner AND on
# gitleaks:
#
#   test_a_history_secret_survives_the_second_and_third_analysis
#     -> test_a_history_secret_stays_open_on_either_scanner
#   test_rotating_and_accepting_is_how_a_history_finding_closes
#     -> test_rotating_and_accepting_closes_it_on_either_scanner
#   test_the_working_tree_reading_wins_over_its_history_twin
#     -> test_the_tree_reading_wins_over_its_history_twin_on_either_scanner
#
# The copies here were not a second opinion, they were the same opinion in a
# vocabulary only one scanner speaks: they planted the documentation key above
# and asserted `aws_access_key`, while inheriting a `CC_SECURITY_ENGINES=off`
# default they never declared. Run the suite the way production runs -- engines
# ON -- and all three went red on a fixture gitleaks is right to ignore, having
# proved the built-in half twice and the engine half never. The parametrised
# versions assert the STATE and the wording rather than the rule name, which is
# what made covering both paths possible at all.


def test_ignore_paths_reach_the_tree_the_history_and_the_hygiene_pass(tmp_path):
    """`ignore_paths` is a promise about the ANALYSIS, not about one phase.

    A fixtures directory holding a deliberately fake key was excluded from the
    working-tree sweep and reported in full by the history sweep and by the
    hygiene pass -- so the operator set the option, saw the noise disappear
    from one section of the report and stay in two others.

    Planted in `tests/planted/` and NOT in the `tests/fixtures/` this test
    used to use: `ignores.DEFAULT_IGNORE_DIRS` now suppresses a `fixtures`
    directory with no configuration at all, so the old path would make the
    `== []` below pass without `--ignore` ever being read. The default has
    its own coverage in `test_the_default_noise_filter_reaches_every_
    deterministic_phase` above; this test is about the OPERATOR's globs and
    has to keep being about only them.

    PINNED to the built-in scanner, and NOT retired in favour of the engine's
    version. `test_adapters.test_the_engine_obeys_the_ignore_paths_prepare_
    was_given` covers the same globs on the engine path, but it filters to
    `category == "secret"` over a tree that is not a git checkout -- so it is
    the SECRET phase's half and only that. This test is the one that keeps the
    promise about the HISTORY sweep and the HYGIENE pass: the bare `== []`
    covers every phase, and the `committed_key_file` in the positive control
    is the proof that the hygiene pass really had something to suppress. Those
    two phases are the same code on both paths; the rule names are not.
    """
    env = {**os.environ, "CC_SECURITY_ENGINES": "off"}
    root = git_repo(tmp_path / "repo", [
        ("fixtures", {"tests/planted/fake.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
                      "tests/planted/fake.pem": "-----BEGIN RSA PRIVATE KEY-----\nx\n"}),
        ("delete the env", {"tests/planted/fake.env": None}),
    ])
    db = tmp_path / "security.db"

    noisy = open_analysis(db)
    run(db, "prepare", "--analysis", str(noisy), "--root", str(root), "--offline",
        env=env)
    rules = {f["rule"] for f in run(db, "findings", "--analysis", str(noisy),
                                    env=env)}
    assert {"aws_access_key", "private_key", "committed_key_file"} <= rules, (
        f"the fixture must be noisy without the globs: {sorted(rules)}")
    run(db, "finish", "--analysis", str(noisy), "--state", "done", env=env)

    quiet = open_analysis(db)
    run(db, "prepare", "--analysis", str(quiet), "--root", str(root), "--offline",
        "--ignore", "tests/planted/**", env=env)
    assert run(db, "findings", "--analysis", str(quiet), env=env) == []


def test_the_default_noise_filter_is_declared_in_the_coverage_note(tmp_path):
    """A default suppression a reader cannot see is a report that cannot be
    read: "nothing was found in the fixtures" and "the fixtures were never
    looked at" are the same silence otherwise. The sentence also has to carry
    the way back out, because the reader who needs it is the one who just
    discovered the filter exists."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    assert "default noise filter" in note
    assert "!defaults" in note


def test_the_note_goes_away_when_the_project_turns_the_default_off(tmp_path):
    """Nothing was suppressed, so there is no gap to declare -- and a note
    that kept claiming one would be the mirror image of the bug above."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline", "--ignore", "!defaults")["coverage_note"]
    assert "default noise filter" not in note


def test_a_mistyped_switch_is_named_in_the_coverage_note(tmp_path):
    """`!defaults` is an exact token, and it used to fail in the UNSAFE
    direction: `!Defaults` compared unequal, the default silently stayed on,
    and the entry went on to three engine command lines as a path to exclude.
    A project that keeps real credentials in a fixture and typed the switch
    believed it was being scanned. `!Defaults` now IS the switch; `!default`
    is not, and cannot be guessed at -- so it is said."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline", "--ignore", "!default")["coverage_note"]
    assert "!default" in note
    assert "STILL IN EFFECT" in note
    assert "default noise filter" in note, (
        "and the filter really is still on, which is what the note claims")


def test_a_capitalised_switch_simply_works(tmp_path):
    """There is no information in the sentinel's capitalisation and there was
    a great deal of damage in requiring it."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline", "--ignore", "!Defaults")["coverage_note"]
    assert "default noise filter" not in note
    assert "STILL IN EFFECT" not in note


def test_the_sbom_says_what_an_absent_dependency_finding_does_not_mean(tmp_path):
    """`deps.inventory` deliberately does not read `ignore_paths`, so the SBOM
    lists a lockfile the dependency phase never looked up. That used to need
    an operator to write `ignore_paths`, and they knew what they had written;
    with the fixtures default it is what every unconfigured project gets. A
    consumer reading the published SBOM beside the report would see "this
    project ships lodash 4.17.20" and "no dependency findings"."""
    root = tmp_path / "repo"
    (root / "tests" / "fixtures").mkdir(parents=True)
    (root / "tests" / "fixtures" / "package-lock.json").write_text(json.dumps(
        {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    assert "tests/fixtures/package-lock.json" in note
    assert "not a clean bill of health" in note


def test_nothing_is_said_when_the_sbom_and_the_analysis_agree(tmp_path):
    """Measured, not standing policy: a project with no lockfile under a
    filtered path never reads that sentence."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package-lock.json").write_text(json.dumps(
        {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    assert "not a clean bill of health" not in note


def test_the_default_noise_filter_reaches_every_deterministic_phase(tmp_path):
    """One filter, every phase -- the promise `ignore_paths` already made,
    now made without anybody having to write the globs. The positive control
    is the same tree with the default switched off: `== []` on its own passes
    identically on an analysis that scanned nothing at all.

    PINNED to the built-in scanner rather than left to the machine, because
    the rule names below are the built-in scanner's. The ENGINE's half of
    the same default is
    `test_adapters.test_the_default_narrows_the_real_engine_with_nothing_
    configured`, which drives the real gitleaks binary -- a default only one
    of the two honoured is the per-machine divergence this whole block keeps
    having to fix."""
    env = {**os.environ, "CC_SECURITY_ENGINES": "off"}
    root = git_repo(tmp_path / "repo", [
        ("fixtures", {
            "tests/fixtures/fake.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
            "tests/fixtures/fake.pem": "-----BEGIN RSA PRIVATE KEY-----\nx\n",
            ".env.example": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"}),
        ("delete the env", {"tests/fixtures/fake.env": None}),
    ])
    db = tmp_path / "security.db"

    loud = open_analysis(db)
    run(db, "prepare", "--analysis", str(loud), "--root", str(root), "--offline",
        "--ignore", "!defaults", env=env)
    rules = {f["rule"] for f in run(db, "findings", "--analysis", str(loud), env=env)}
    assert {"aws_access_key", "private_key", "committed_key_file"} <= rules, (
        f"the tree must be noisy with the default switched off: {sorted(rules)}")
    run(db, "finish", "--analysis", str(loud), "--state", "done", env=env)

    quiet = open_analysis(db)
    run(db, "prepare", "--analysis", str(quiet), "--root", str(root), "--offline",
        env=env)
    assert run(db, "findings", "--analysis", str(quiet), env=env) == []


def test_a_history_sweep_that_could_not_run_says_so_in_the_coverage_note(tmp_path):
    """`scan_history` used to answer a failure with `[]` -- the identical
    value it answers "this history is clean" with. The one failure mode that
    hides the findings it exists to produce was reported as the best news
    available. Here the root is not a git checkout at all, which is the
    commonest way for the sweep to produce nothing."""
    root = tmp_path / "not-a-repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    assert "history sweep did not complete" in note
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    rendered = run_text(db, "render", "--analysis", str(aid), "--format", "md")
    assert "history sweep did not complete" in rendered


def test_every_phase_gap_reaches_the_one_coverage_note(tmp_path):
    """The note is a single channel with several writers. A run that could not
    sweep the history AND could not ask OSV.dev has two blind spots, and a
    reader who is told about one of them is worse off than one told about
    both."""
    root = tmp_path / "not-a-repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    assert "history sweep did not complete" in note
    assert "OSV.dev" in note


# --------------------------- the dependency engine, Trivy vs OSV.dev, never both
#
# `osv.query` makes a real HTTP call to api.osv.dev, and this suite must never
# depend on that network being reachable (test_osv.py itself never lets a real
# request through -- every test there monkeypatches `osv._http`). These tests
# drive `security_cli.main()` IN-PROCESS rather than through the `run`/`fails`
# subprocess helpers for exactly that reason: the point is to stub
# `security_cli.osv.query` and `security_cli.adapters` mid-call, which a
# subprocess boundary cannot see (the same exception the module docstring
# already names for the ledger-write-failure tests below).

def _dep_finding(rule="CVE-9999"):
    return {"fingerprint": "f" * 64, "category": "dependency", "rule": rule,
            "severity": "high", "title": "t", "rationale": "r",
            "remediation": "m", "occurrences": []}


def test_prepare_prefers_trivy_and_never_calls_osv(tmp_path, monkeypatch, capsys):
    """Two producers in the `dependency` category would report one CVE under
    two fingerprints. `osv.query` raising proves it was never even called --
    a plain call-counter could pass by accident if an early return happened
    to skip it for an unrelated reason."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_scan",
                        lambda root, ignore_paths=(): (
                            [_dep_finding()],
                            ["Dependencies were scanned for known CVEs by "
                             "trivy 0.74.0."]))

    def must_not_run(*_a, **_kw):
        raise AssertionError("osv.query must not run once Trivy has answered")
    monkeypatch.setattr(security_cli.osv, "query", must_not_run)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    printed = json.loads(capsys.readouterr().out)
    assert printed["findings"] >= 1
    findings = run(db, "findings", "--analysis", str(aid))
    dep_rules = {f["rule"] for f in findings if f["category"] == "dependency"}
    assert dep_rules == {"CVE-9999"}
    row = run(db, "list", "--project", "web")[0]
    assert "trivy" in row["coverage_note"].lower()


def test_prepare_falls_back_to_osv_when_trivy_is_not_installed(tmp_path, monkeypatch):
    """The mirror of the test above: with no engine on the machine, OSV.dev
    still does the work -- the fallback pair this task replaces, not
    removes."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path", lambda name: None)
    calls = []

    def fake_query(components, detail_cache=None, timeout=30):
        calls.append(components)
        return [], ""
    monkeypatch.setattr(security_cli.osv, "query", fake_query)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    assert calls, "osv.query was never called"


def test_prepare_falls_back_to_osv_when_trivy_produces_no_report(tmp_path, monkeypatch):
    """Trivy is on the machine but could not answer -- absent a version,
    timed out, whatever `adapters.trivy_scan` signals with `None`. That is
    safe to fall back from precisely because it produced nothing: there is
    no engine finding for OSV.dev's to collide with."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_scan",
                        lambda root, ignore_paths=(): (
                            None, ["trivy did not finish within 600s and was "
                                   "stopped."]))
    calls = []

    def fake_query(components, detail_cache=None, timeout=30):
        calls.append(components)
        return [], ""
    monkeypatch.setattr(security_cli.osv, "query", fake_query)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    assert calls, "osv.query must run when Trivy contributed nothing"
    row = run(db, "list", "--project", "web")[0]
    assert "did not finish" in row["coverage_note"]


def test_the_osv_fallback_note_is_not_said_for_a_repository_with_no_lockfiles(
        tmp_path, monkeypatch):
    """The note claims dependencies "were checked against OSV.dev's own
    database". With no components, `osv.query` returns before it opens a
    socket, and saying it anyway describes a lookup that never happened."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path", lambda name: None)
    monkeypatch.setattr(security_cli.osv, "query",
                        lambda components, detail_cache=None, timeout=30: ([], ""))

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    note = run(db, "list", "--project", "web")[0]["coverage_note"]
    assert "OSV.dev's own database" not in note

    # ... and it IS said the moment there is something to check, or nobody
    # learns which of the two producers scanned their dependencies.
    (root / "package-lock.json").write_text(
        (Path(__file__).parent / "fixtures" / "package-lock.json").read_text())
    second = open_analysis(db)
    security_cli.main(["prepare", "--analysis", str(second), "--root", str(root),
                       "--db", str(db)])
    notes = [r["coverage_note"] for r in run(db, "list", "--project", "web")]
    assert any("OSV.dev's own database" in n for n in notes)


def test_ignore_paths_reach_the_dependency_phase_whichever_producer_ran(
        tmp_path, monkeypatch):
    """`ignore_paths` is a promise about the ANALYSIS. Honouring it on the
    engine path alone would make an operator's globs suppress a CVE on a
    machine with Trivy installed and not on one without -- a report that
    changes by machine, which is the same class of bug as the fingerprint
    divergence. The inventory is untouched: the SBOM still lists the
    lockfile."""
    root = tmp_path / "repo"
    (root / "examples").mkdir(parents=True)
    (root / "examples" / "package-lock.json").write_text(
        (Path(__file__).parent / "fixtures" / "package-lock.json").read_text())
    db = tmp_path / "security.db"

    def one_cve(components, detail_cache=None, timeout=30):
        return [dict(_dep_finding(), occurrences=[
            {"file": c["source"], "line": 0, "snippet_hash": ""}])
            for c in components], ""
    monkeypatch.setattr(security_cli.adapters, "engine_path", lambda name: None)
    monkeypatch.setattr(security_cli.osv, "query", one_cve)

    aid = open_analysis(db)
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    assert [f for f in run(db, "findings", "--analysis", str(aid))
            if f["category"] == "dependency"]

    scoped = open_analysis(db)
    security_cli.main(["prepare", "--analysis", str(scoped), "--root", str(root),
                       "--ignore", "examples", "--db", str(db)])
    assert not [f for f in run(db, "findings", "--analysis", str(scoped))
                if f["category"] == "dependency"]


def test_offline_skips_trivy_as_well_as_osv(tmp_path, monkeypatch):
    """`--offline` turns off BOTH: a vulnerability database, Trivy's own or
    OSV.dev's, does not exist unless somebody publishes it, and this
    analysis was told not to reach the network. Both stubs raise, so a
    regression that let either one run mid-flight fails the test instead of
    quietly making a real network call."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    def must_not_run(*_a, **_kw):
        raise AssertionError("neither engine may run while --offline")
    monkeypatch.setattr(security_cli.adapters, "trivy_scan", must_not_run)
    monkeypatch.setattr(security_cli.osv, "query", must_not_run)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--offline", "--db", str(db)])
    row = run(db, "list", "--project", "web")[0]
    assert "OSV" in row["coverage_note"]
    assert "Trivy" in row["coverage_note"]


# ------------------------- the IaC misconfiguration phase, Trivy-only, no fallback

def _iac_finding(rule="DS-0002"):
    return {"fingerprint": "i" * 64, "category": "iac", "rule": rule,
            "severity": "high", "title": "t", "rationale": "r",
            "remediation": "m", "occurrences": [{"file": "Dockerfile", "line": 0}]}


def test_iac_is_in_the_deterministic_and_finding_category_sets():
    """The two ledgers this project keeps of its own finding categories have
    to agree, or a category the ledger accepts is one the checklist cannot
    classify. `cli.FINDING_CATEGORIES` is DERIVED from `diff.
    DETERMINISTIC_CATEGORIES`, so asserting both is checking the derivation
    still holds, not duplicating the fact."""
    assert "iac" in security_cli.diff.DETERMINISTIC_CATEGORIES
    assert "iac" in security_cli.FINDING_CATEGORIES


def test_prepare_reports_iac_findings_from_trivy(tmp_path, monkeypatch, capsys):
    """`iac` has no built-in scanner and no fallback -- Trivy on, or nothing
    this run. Mirrors `test_prepare_prefers_trivy_and_never_calls_osv`'s own
    shape for the dependency phase."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_iac_scan",
                        lambda root, ignore_paths=(): (
                            [_iac_finding()],
                            ["Infrastructure-as-code misconfigurations were "
                             "scanned by Trivy (0.74.0)."]))

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    printed = json.loads(capsys.readouterr().out)
    assert printed["findings"] >= 1
    findings = run(db, "findings", "--analysis", str(aid))
    iac_rules = {f["rule"] for f in findings if f["category"] == "iac"}
    assert iac_rules == {"DS-0002"}
    row = run(db, "list", "--project", "web")[0]
    assert "trivy" in row["coverage_note"].lower()


def test_iac_declares_a_gap_when_trivy_is_not_installed(tmp_path):
    """No built-in scanner exists for `iac`, unlike secrets or dependencies --
    so the absence has to be SAID, not silently reported as zero findings."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    assert not [f for f in run(db, "findings", "--analysis", str(aid))
                if f["category"] == "iac"]
    row = run(db, "list", "--project", "web")[0]
    assert "infrastructure-as-code" in row["coverage_note"].lower()


def test_iac_gap_is_declared_when_trivy_produces_no_report(tmp_path, monkeypatch):
    """Trivy is on the machine but could not answer -- `adapters.
    trivy_iac_scan` signals that with `None`, exactly as `trivy_scan` does
    for dependencies. There is nothing to fall back to, so the gap is what
    the report shows instead of a silent zero."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_iac_scan",
                        lambda root, ignore_paths=(): (
                            None, ["trivy did not finish within 600s and was "
                                   "stopped."]))

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    row = run(db, "list", "--project", "web")[0]
    assert "did not finish" in row["coverage_note"]


# 64 lowercase hex, so `report-finding` will accept it back: the re-report
# test below goes through the agent's own door, which checks the SHAPE of a
# fingerprint even for a finding `prepare` minted.
_IAC_FP = "d1ac" + "0" * 60


def _only_trivy(monkeypatch):
    """A machine with Trivy and nothing else, and neither real binary run.

    `engine_path("trivy")` gates the dependency phase as well as the IaC one,
    so `trivy_scan` has to be stubbed too or these tests shell out to the
    actual scanner.
    """
    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_scan",
                        lambda root, ignore_paths=(): ([], []))
    monkeypatch.setattr(
        security_cli.adapters, "trivy_iac_scan",
        lambda root, ignore_paths=(): (
            [dict(_iac_finding(), fingerprint=_IAC_FP)], []))


def test_a_run_without_trivy_never_declares_an_iac_finding_fixed(
        tmp_path, monkeypatch):
    """THE BLOCKING DEFECT, end to end, on the path the spec calls NORMAL.

    Analysis 1 runs with Trivy and records a Dockerfile misconfiguration;
    analysis 2 reads the SAME untouched checkout on a machine without it. The
    checklist used to say `fixed` -- in the same report whose coverage note
    says the Dockerfile "was not checked at all this run" -- because `iac` sat
    in DETERMINISTIC_CATEGORIES, where `prepare` finishing counts as proof.
    `iac` has no fallback by design, so `[]` from that phase has only ever
    meant "nobody looked".
    """
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"

    _only_trivy(monkeypatch)
    first = open_analysis(db, commit="a1", run_id="r1")
    security_cli.main(["prepare", "--analysis", str(first), "--root", str(root),
                       "--db", str(db)])
    run(db, "finish", "--analysis", str(first), "--state", "done")

    # The same checkout, a machine with no engines at all.
    monkeypatch.setattr(security_cli.adapters, "engine_path", lambda name: None)
    second = open_analysis(db, commit="a2", run_id="r2")
    security_cli.main(["prepare", "--analysis", str(second), "--root", str(root),
                       "--db", str(db)])
    run(db, "finish", "--analysis", str(second), "--state", "done")

    checklist = run(db, "checklist", "--analysis", str(second))
    iac = [f for f in checklist["findings"] if f["category"] == "iac"]
    assert [f["state"] for f in iac] == ["pending"], (
        "the IaC scan did not run, so it proved nothing -- and the report "
        "that says the Dockerfile was never checked must not also say its "
        "misconfiguration is fixed")


def test_the_same_engine_running_again_does_close_an_iac_finding(
        tmp_path, monkeypatch):
    """The other direction of the same rule, and the reason it is a producer
    and not a blanket `pending`: Trivy running and finding nothing IS proof,
    so a genuinely fixed Dockerfile closes on the very next analysis."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"

    _only_trivy(monkeypatch)
    first = open_analysis(db, commit="a1", run_id="r1")
    security_cli.main(["prepare", "--analysis", str(first), "--root", str(root),
                       "--db", str(db)])
    run(db, "finish", "--analysis", str(first), "--state", "done")

    # Trivy is still here; the misconfiguration is gone.
    monkeypatch.setattr(security_cli.adapters, "trivy_iac_scan",
                        lambda root, ignore_paths=(): ([], []))
    second = open_analysis(db, commit="a2", run_id="r2")
    security_cli.main(["prepare", "--analysis", str(second), "--root", str(root),
                       "--db", str(db)])
    run(db, "finish", "--analysis", str(second), "--state", "done")

    checklist = run(db, "checklist", "--analysis", str(second))
    iac = [f for f in checklist["findings"] if f["category"] == "iac"]
    assert [f["state"] for f in iac] == ["fixed"]


def test_prepare_records_which_producers_actually_ran(tmp_path, monkeypatch):
    """`prepared` says the deterministic half ran; `produced` says WHAT ran,
    and only the second can tell a clean Dockerfile from an unread one."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"

    _only_trivy(monkeypatch)
    aid = open_analysis(db)
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT produced FROM analysis WHERE id=?", (aid,)).fetchone()
    produced = set(row["produced"].split(","))
    # Trivy answered for both of its phases, the built-in scanner for secrets,
    # and hygiene always runs. Semgrep and Syft are not on this machine.
    assert {"trivy", "trivy-iac", "secrets", "hygiene"} <= produced
    assert "semgrep" not in produced and "gitleaks" not in produced

    producer = {f["rule"]: f["producer"]
                for f in run(db, "findings", "--analysis", str(aid))}
    assert producer["DS-0002"] == "trivy-iac"


def test_an_agents_re_report_does_not_steal_a_deterministic_producer(
        tmp_path, monkeypatch):
    """Triage is the agent's JOB (Job 2 in the skill): it re-reports a
    deterministic finding with a corrected severity and rationale. If that
    re-report restamped `producer` as `agent`, the finding's absence-proof
    would move to the analysis closing `done` -- reintroducing the false
    `fixed` through the one door meant to improve a finding."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"

    _only_trivy(monkeypatch)
    aid = open_analysis(db)
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])

    run(db, "report-finding", "--analysis", str(aid),
        stdin=json.dumps({**_iac_finding(), "fingerprint": _IAC_FP,
                          "severity": "low",
                          "rationale": "the base image is pinned"}))

    rows = {f["rule"]: f for f in run(db, "findings", "--analysis", str(aid))}
    assert rows["DS-0002"]["severity"] == "low", "the re-report must still land"
    assert rows["DS-0002"]["producer"] == "trivy-iac", (
        "the producer records who MINTED the identity, never who wrote the "
        "row last")


def test_offline_skips_iac_scanning_too(tmp_path, monkeypatch):
    """`--offline` turns Trivy's misconfiguration scan off exactly as it
    turns the dependency and SAST phases off: its checks bundle is fetched
    from Trivy's own registry, and this analysis was told not to reach the
    network."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    def must_not_run(*_a, **_kw):
        raise AssertionError("trivy_iac_scan must not run while --offline")
    monkeypatch.setattr(security_cli.adapters, "trivy_iac_scan", must_not_run)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--offline", "--db", str(db)])
    row = run(db, "list", "--project", "web")[0]
    assert "infrastructure-as-code" in row["coverage_note"].lower()


def test_ignore_paths_reach_the_iac_phase(tmp_path, monkeypatch):
    """The same promise `ignore_paths` makes to every other phase: it is
    about the ANALYSIS, and `_scan_iac` has to pass it down."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    seen = {}

    def fake_scan(root, ignore_paths=()):
        seen["ignore_paths"] = ignore_paths
        return [], []
    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_iac_scan", fake_scan)

    aid = open_analysis(db)
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--ignore", "examples,dist", "--db", str(db)])
    assert seen["ignore_paths"] == ["examples", "dist"]


def test_report_finding_accepts_the_iac_category(tmp_path):
    """The vocabulary gate is for `sast` only -- an `iac` rule is Trivy's own
    check id, produced by our own Python during `prepare`, not the agent's
    `report-finding` door in the ordinary run. Still has to be usable through
    it: an operator debugging a stuck analysis, or a future manual repair,
    types the same command every other category already accepts."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "d" * 64, "category": "iac", "rule": "DS-0002",
        "severity": "high", "title": "t"}))
    row = _finding_row(db, aid)
    assert row["category"] == "iac"
    assert row["rule"] == "DS-0002"
    assert row["cwe"] == "" and row["owasp"] == ""


# ------------------------------- an analysis that never ran its own phases

def test_finishing_done_without_prepare_is_downgraded_to_capped(tmp_path):
    """Nothing engine-side runs `prepare`: it is the agent's first command,
    named in the prompt and in the skill, and an agent that simply skipped it
    exited cleanly and had its row closed `done`. The result was a report with
    zero findings, an empty coverage note and no banner anywhere saying the
    repository had never been scanned -- and that report then became the
    BASELINE the next analysis is diffed against, so everything the next run
    legitimately found arrived as `new`."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "finish", "--analysis", str(aid), "--state", "done")
    assert out.returncode == 0, out.stderr
    assert "never ran `prepare`" in out.stderr
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "capped"
    assert "deterministic phases never ran" in row["coverage_note"]


def test_the_downgrade_reaches_the_report_as_an_incomplete_banner(tmp_path):
    """`capped` is what the report already prints its INCOMPLETE banner for,
    which is the reason the guard downgrades rather than refusing: the reader
    of the downloaded file learns it from the file itself."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    rendered = run_text(db, "render", "--analysis", str(aid), "--format", "md")
    assert "INCOMPLETE" in rendered
    assert "deterministic phases never ran" in rendered


def test_an_analysis_that_did_prepare_still_closes_done(tmp_path):
    """The control. A guard that downgraded every close would be indis-
    tinguishable, from the page, from one that worked."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "deterministic phases never ran" not in row["coverage_note"]


def test_prepare_marks_the_row_only_after_its_findings_are_stored(tmp_path):
    """`prepared` has to mean "the deterministic phases ran AND their findings
    are in the ledger", not "prepare was invoked"."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = open_analysis(db)
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    assert conn.execute("SELECT prepared FROM analysis WHERE id=?",
                        (aid,)).fetchone()["prepared"] == 0
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    assert conn.execute("SELECT prepared FROM analysis WHERE id=?",
                        (aid,)).fetchone()["prepared"] == 1


def test_the_downgrade_note_is_not_stored_twice_when_the_row_closes_twice(tmp_path):
    """A row is closed twice by design -- the agent, then the engine with the
    run's real verdict and cost. Both closes hit the guard."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "1.5")
    row = run(db, "list", "--project", "web")[0]
    assert row["coverage_note"].count("deterministic phases never ran") == 1
    assert row["spend_usd"] == 1.5


def test_the_prepared_column_is_added_to_a_database_that_predates_it(tmp_path):
    """The feature has never shipped, so there is no installed base -- but the
    branch's own dev databases exist, and `CREATE TABLE IF NOT EXISTS` does
    nothing to a table that is already there. connect() adds the column with
    ALTER TABLE, guarded by PRAGMA table_info."""
    db = tmp_path / "security.db"
    old = sqlite3.connect(str(db))
    old.executescript(
        "CREATE TABLE analysis (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " project TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,"
        " commit_sha TEXT NOT NULL, profile TEXT NOT NULL,"
        " started INTEGER NOT NULL, ended INTEGER, state TEXT NOT NULL,"
        " spend_usd REAL NOT NULL DEFAULT 0, run_id TEXT NOT NULL DEFAULT '',"
        " coverage_note TEXT NOT NULL DEFAULT '');")
    old.execute("INSERT INTO analysis (project, repo, branch, commit_sha, profile,"
                " started, state) VALUES ('web','web','main','abc','quick',1,'done')")
    old.commit()
    old.close()

    rows = run(db, "list", "--project", "web")
    assert len(rows) == 1
    assert rows[0]["prepared"] == 0, "a row from before the column is unprepared"


# ------------------------------- an analysis that never read what it produced
#
# The design of this module rests on ONE argument: the deterministic phases are
# noisy on purpose and the noise is not filtered by heuristics -- the agent
# reads the surrounding code and triages. That is Job 2 of the skill, asked for
# in two pages of it. In analysis 9 and again in analysis 10 on Minerva the
# agent triaged ZERO of the ~40 deterministic findings waiting for it, spent
# the whole budget on its own SAST pass, and both runs closed `done` with a
# clean-looking report. Asking is what failed, so the close verifies instead.

def _scanner_finding(db, aid, *, rule, severity, category="dependency",
                     producer="trivy", file="yarn.lock"):
    """A finding as `prepare` writes one: minted by a SCANNER, not the agent.

    Written through `ledger.record_finding` -- the same function `prepare`
    itself calls, with the same `producer` stamp `_produced_by` applies --
    rather than by planting files and running the real phase, because these
    tests are about what the CLOSE does with a scanner's finding and not about
    what any one scanner finds. A fixture built on planted files would also
    prove the gate in only one of the two scanner configurations this suite
    runs in. `test_finishing_done_with_an_untriaged_scanner_finding...` below
    is the end-to-end counterpart, on a real hygiene finding.
    """
    conn = security_ledger.connect(db)
    fp = compute_fingerprint(category, rule, file, rule)
    security_ledger.record_finding(conn, aid, {
        "fingerprint": fp, "category": category, "rule": rule,
        "severity": severity, "title": f"{rule} in {file}",
        "rationale": "the scanner's own reading", "producer": producer,
        "occurrences": [{"file": file, "line": 0, "snippet_hash": ""}]})
    conn.close()
    return fp


def _triage(db, aid, fp, *, rule, category="dependency", severity="low",
            file="yarn.lock",
            rationale="read the call site: it is not reachable from a request"):
    """What Job 2 looks like from the ledger's side: the agent re-reporting a
    deterministic finding under its own severity, rationale and occurrences.

    THE OCCURRENCES ARE NOT DECORATION HERE. `ledger.record_finding` refuses a
    re-report that carries no rationale of its own, echoes the producer's back
    verbatim, or names no location -- the three shapes a rubber stamp takes --
    so a helper that omitted them would be modelling the payload the gate is
    built to reject and calling it triage.
    """
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": fp, "category": category, "rule": rule,
        "severity": severity, "title": f"{rule}, read in context",
        "rationale": rationale,
        "occurrences": [{"file": file, "line": 0, "snippet_hash": ""}]}),
        env=AS_AGENT)


def test_finishing_done_with_an_untriaged_scanner_finding_is_downgraded_to_capped(tmp_path):
    """End to end, on a finding a real deterministic phase produced.

    `capped` rather than a refusal, for the same reason the `prepare` guard
    downgrades rather than refusing: an analysis stuck `running` for ever is
    worse than an honest incomplete, and `capped` is the state the report
    already prints its INCOMPLETE banner for."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".env").write_text("DATABASE_URL=postgres://localhost/app\n")
    aid = open_analysis(db)
    prepared = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
                   "--offline")
    assert prepared["findings"] >= 1

    out = fails(db, "finish", "--analysis", str(aid), "--state", "done")
    assert out.returncode == 0, out.stderr
    assert "never triaged" in out.stderr

    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "capped"
    note = row["coverage_note"]
    assert "never triaged" in note
    assert "committed_env_file" in note, note
    assert ".env" in note, "the note names the file, or the reader cannot find it"


def test_the_note_names_the_count_and_the_first_three(tmp_path):
    """A number alone is a scold. The reader of the report has to be able to
    go and look at what was skipped, which means the rule and the file."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _scanner_finding(db, aid, rule="CVE-2", severity="medium")
    _scanner_finding(db, aid, rule="DS-0002", severity="critical",
                     category="iac", producer="trivy-iac", file="Dockerfile")
    _scanner_finding(db, aid, rule="CVE-4", severity="high", file="pom.xml")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    note = run(db, "list", "--project", "web")[0]["coverage_note"]
    assert "4 deterministic findings" in note, note
    # Ordered by severity, so the three that get named are the worst three and
    # not whichever three were written first.
    assert "DS-0002 (Dockerfile)" in note
    assert "CVE-1 (yarn.lock)" in note
    assert "CVE-4 (pom.xml)" in note
    assert "CVE-2" not in note, "three, not the whole list"


def test_triaging_every_scanner_finding_lets_the_close_stand(tmp_path):
    """The control, and the point: an analysis that DID the job closes `done`.
    A gate that downgraded every close would be indistinguishable, from the
    report, from one that worked."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    cve = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    iac = _scanner_finding(db, aid, rule="DS-0002", severity="medium",
                           category="iac", producer="trivy-iac", file="Dockerfile")
    _triage(db, aid, cve, rule="CVE-1")
    _triage(db, aid, iac, rule="DS-0002", category="iac", severity="medium")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "triaged" not in row["coverage_note"]


def test_an_untriaged_low_or_info_does_not_block_the_close(tmp_path):
    """The floor is `medium`. A budget spent proving that an `info` hygiene
    note was read is a budget not spent on the critical above it -- and a gate
    nobody can ever satisfy is a gate that gets switched off."""
    db = tmp_path / "security.db"
    assert security_cli.TRIAGE_FLOOR == "medium"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-9", severity="low")
    _scanner_finding(db, aid, rule="missing_gitignore", severity="info",
                     category="hygiene", producer="hygiene", file=".gitignore")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "triaged" not in row["coverage_note"]


def test_an_analysis_with_no_scanner_findings_closes_done_with_no_gate_noise(tmp_path):
    """A clean repository must not be told it skipped anything."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "triaged" not in row["coverage_note"]


def test_the_agents_own_findings_are_never_counted_as_untriaged(tmp_path):
    """`sast` rows are the agent's OWN work, not a scanner's output waiting to
    be read -- and counting them would make the gate unsatisfiable by
    construction: reporting a finding would create the very debt reporting it
    is supposed to discharge. The run this gate was written after did nothing
    but produce these."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "c" * 64, "category": "sast", "rule": "sql-injection",
        "severity": "critical", "title": "String-built SQL",
        "occurrences": [{"file": "app/db.py", "line": 12}]}), env=AS_AGENT)

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "triaged" not in row["coverage_note"]


def test_the_untriaged_note_is_not_stored_twice_when_the_row_closes_twice(tmp_path):
    """A row is closed twice by design -- the agent, then the engine with the
    run's real verdict and cost -- and the second close re-reads the note the
    first one wrote."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="high")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "1.5")
    row = run(db, "list", "--project", "web")[0]
    assert row["coverage_note"].count("never triaged") == 1
    assert row["spend_usd"] == 1.5


def test_the_untriaged_downgrade_reaches_the_report_as_an_incomplete_banner(tmp_path):
    """The whole reason the gate lowers the verdict instead of refusing: the
    reader of the downloaded file learns it from the file itself."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="high")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    rendered = run_text(db, "render", "--analysis", str(aid), "--format", "md")
    assert "INCOMPLETE" in rendered
    assert "never triaged" in rendered


def test_a_rubber_stamp_through_the_real_door_neither_marks_nor_strips(tmp_path):
    """The gate's cheapest bypass, driven end to end through `report-finding`.

    A payload echoing the scanner's own rule, severity and title back -- with
    no rationale and no occurrences -- used to set `triaged=1` and close
    `done`. It also left the row with NO occurrences, because the upsert
    replaces them, so the note the gate writes about a skipped finding could
    not even name the file. Both halves are asserted here: the close is still
    downgraded, and the note still names `yarn.lock`, which only exists if the
    scanner's occurrence survived the stamp."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")

    stamp = fails(db, "report-finding", "--analysis", str(aid),
                  stdin=json.dumps({
                      "fingerprint": fp, "category": "dependency",
                      "rule": "CVE-1", "severity": "high",
                      "title": "CVE-1 in yarn.lock"}), env=AS_AGENT)
    assert stamp.returncode != 0, stamp.stdout
    assert "rubber stamp" in stamp.stderr, stamp.stderr

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "capped"
    assert "CVE-1 (yarn.lock)" in row["coverage_note"], (
        "the stamp must not have taken the finding's only location with it")


def test_a_re_report_that_agrees_with_the_scanner_still_satisfies_the_gate(tmp_path):
    """The control for the refusal above, and the case it must never catch: an
    agent that read the code and concluded the scanner was right. The severity
    it sends is the scanner's own -- only the rationale is new -- and that is a
    triage."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _triage(db, aid, fp, rule="CVE-1", severity="high",
            rationale="reachable from the upload handler; high is right")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "triaged" not in row["coverage_note"]


def test_a_finding_no_producer_claims_does_not_block_the_close(tmp_path):
    """`_untriaged`'s `f.producer<>''` clause, which no other test touches --
    deleting it leaves the whole triage suite green while downgrading every
    honest `done` on a ledger written before the `producer` column existed.

    Those rows carry `producer=''`, and "an unknown scanner produced this and
    nobody read it" is an accusation the query has no evidence for. It is also
    half of an interlock: together with the `producer<>?` exclusion of the
    agent's own rows, and with `record_finding` refusing an agent write onto an
    unread scanner row, it is what lets `cmd_finish` build its note from `rule`
    and `file` WITHOUT running it past `_refuse_if_secret`. Every row this
    query can return was written by a producer, so no agent free text can reach
    the note. Relax any one of the three and that stops being true."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="critical", producer="")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "triaged" not in row["coverage_note"]


def _decide(db, fingerprint, *, project="web", state="accepted",
            reason="rotated at the provider; the commit stays in history"):
    """A human's decision, written straight into the ledger.

    NOT through `security decide`, which refuses while any analysis of the
    project is `running` -- and the analysis under test is, right up to the
    `finish` these tests are about. That guard is a real one (see `cmd_decide`)
    and is tested where it lives; here it would only force the decision to be
    recorded after the close it is supposed to affect.
    """
    conn = security_ledger.connect(db)
    security_ledger.set_decision(conn, project, fingerprint, state, reason,
                                 "luiz")
    conn.close()


def test_a_finding_the_operator_has_decided_on_does_not_block_the_close(tmp_path):
    """A DECISION IS A STRONGER READING THAN A RE-REPORT, and the gate has to
    honour it or it contradicts the operator for ever.

    `diff.classify` lets a project decision override every state a finding
    could otherwise be in, and the skill sends the agent past those rows: an
    `accepted` finding is not its to re-report. The canonical case is the one
    the skill describes -- a credential in git history, `secret`, high,
    re-found by every sweep for as long as the commit exists, whose only
    closure is a human rotating it and accepting the risk. Without this
    exclusion that repository's every future analysis closes `capped` naming
    the finding its operator already ruled on, and nothing an agent could do
    would ever clear it."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="aws_secret_key", severity="high",
                          category="secret", producer="secrets",
                          file="config/legacy.env")
    _decide(db, fp)

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert "never triaged" not in row["coverage_note"], row["coverage_note"]


def test_an_undecided_sibling_still_lowers_the_close_and_is_the_one_named(tmp_path):
    """The control for the exclusion above, in the SAME analysis: it must
    subtract exactly the decided row and nothing else. A gate that stopped
    counting the moment any decision existed would be indistinguishable, from
    the report, from one that had been switched off."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    decided = _scanner_finding(db, aid, rule="CVE-1", severity="critical")
    _scanner_finding(db, aid, rule="CVE-2", severity="high", file="pom.xml")
    _decide(db, decided)

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "capped"
    note = row["coverage_note"]
    assert "1 deterministic finding was never triaged" in note, note
    assert "It is: CVE-2 (pom.xml)." in note, note
    assert "CVE-1" not in note, "the decided row is not a debt: " + note


def test_a_decision_in_another_project_exempts_nothing_here(tmp_path):
    """The `decision` table is keyed (project, fingerprint) on purpose --
    dismissing a false positive on one repository must not silently dismiss the
    identical fingerprint on another -- and the gate is scoped the same way. A
    query that dropped the project term would let one operator's judgement on
    their own repository close every other repository's runs."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _decide(db, fp, project="other", state="false_positive",
            reason="not the same dependency tree at all")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "capped"
    assert "CVE-1 (yarn.lock)" in row["coverage_note"]


def test_the_note_says_it_is_when_exactly_one_finding_was_skipped(tmp_path):
    """Singular all the way through -- "1 deterministic finding WAS never
    triaged ... IT IS". The n=4 wording is what every other test here
    exercises, and a note that said "1 findings were" over the one thing
    somebody has to go and look at reads as a bug in the report rather than a
    fact about the analysis."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="high")

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    note = run(db, "list", "--project", "web")[0]["coverage_note"]
    assert "1 deterministic finding was never triaged" in note, note
    assert "It is: CVE-1 (yarn.lock)." in note, note


def test_the_note_says_they_are_and_names_all_of_them_below_four(tmp_path):
    """Two and three take the middle wording: plural, but the whole list, not
    "the first three" of three. The `> 3` boundary is the one an off-by-one
    lands on, and it is invisible at n=4."""
    db = tmp_path / "security.db"
    two = prepared_analysis(db, tmp_path)
    _scanner_finding(db, two, rule="CVE-1", severity="high")
    _scanner_finding(db, two, rule="CVE-2", severity="medium", file="pom.xml")
    run(db, "finish", "--analysis", str(two), "--state", "done")
    note = run(db, "list", "--project", "web")[0]["coverage_note"]
    assert "2 deterministic findings were never triaged" in note, note
    assert "They are: CVE-1 (yarn.lock); CVE-2 (pom.xml)." in note, note

    three = prepared_analysis(db, tmp_path, run_id="r2")
    _scanner_finding(db, three, rule="CVE-3", severity="critical")
    _scanner_finding(db, three, rule="CVE-4", severity="high", file="pom.xml")
    _scanner_finding(db, three, rule="CVE-5", severity="medium", file="go.sum")
    run(db, "finish", "--analysis", str(three), "--state", "done")
    note = [r for r in run(db, "list", "--project", "web")
            if r["id"] == three][0]["coverage_note"]
    assert "3 deterministic findings were never triaged" in note, note
    assert "The first three" not in note, "three IS all of them"
    assert "They are: CVE-3 (yarn.lock); CVE-4 (pom.xml); CVE-5 (go.sum)." \
        in note, note


def test_the_blocking_severities_are_the_slice_at_and_above_the_floor():
    """`TRIAGE_BLOCKING` is a SLICE of `report.SEVERITIES`, so it is only
    correct while that tuple stays ordered worst first. Reordering it -- or
    inserting a severity between two existing ones -- silently changes which
    findings can hold a `done` open, and nothing else in this suite would
    notice: the derived tuple itself was never asserted, only the floor it is
    derived from."""
    assert security_cli.report.SEVERITIES == (
        "critical", "high", "medium", "low", "info"), (
        "the slice below reads this order; changing it changes the gate")
    assert security_cli.TRIAGE_FLOOR == "medium"
    assert security_cli.TRIAGE_BLOCKING == ("critical", "high", "medium")


# ------------------------------------------ the coverage note gains structure
#
# `coverage_note` is one paragraph built by concatenating 27 `*_NOTE`
# constants across six modules -- ~2,000 characters on a real analysis, every
# sentence of it true and the block of them unreadable. The `coverage` column
# carries the SAME sentences with the phase that produced them attached, and
# the reports and the screen print that first. These tests pin the two claims
# that make it safe: the structure is what the scanners RETURNED (never a
# reading of the prose), and the prose itself is untouched.

def _coverage_phases(db, aid, project="web"):
    """(the analysis row, its structured phases).

    Read through `analysis --id`, not `list`: the list verb deliberately drops
    the `coverage` column, because it feeds a hundred-row table polled every
    four seconds and neither half of the coverage is on it. See `cmd_list`.
    """
    row = run(db, "analysis", "--id", str(aid))
    return row, json.loads(row["coverage"])["phases"]


def test_prepare_records_one_phase_per_deterministic_pass(tmp_path):
    """Seven rows, in the order every renderer prints them. `--offline`
    refuses the network, so the three phases that need it are `skipped` --
    and `skipped` is what the scanner function RETURNED, not something read
    back out of a sentence."""
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    row, phases = _coverage_phases(db, aid)
    by_name = {p["name"]: p for p in phases}
    assert [p["name"] for p in phases] == [
        "scope", "secrets", "hygiene", "dependencies", "sbom", "iac",
        "sast-prepass"]
    # `--offline` disables OSV.dev, Trivy's database, Trivy's misconfiguration
    # checks and Semgrep's rule pack. Nothing looked, and the table says so in
    # the one word that means it.
    assert by_name["dependencies"]["status"] == "skipped"
    assert by_name["dependencies"]["by"] is None
    assert by_name["iac"]["status"] == "skipped"
    assert by_name["sast-prepass"]["status"] == "skipped"
    # Hygiene is our own walk over the tree: no engine, no fallback, so it
    # runs in every configuration this suite has.
    assert by_name["hygiene"] == {"name": "hygiene", "status": "ran",
                                  "by": "hygiene", "note": ""}
    # And the secret phase always has a producer -- there is no configuration
    # in which neither scanner runs.
    assert by_name["secrets"]["by"] in ("gitleaks", "secrets")
    assert by_name["secrets"]["status"] in ("ran", "warning")
    assert row["coverage_note"]


def test_the_runs_list_does_not_ship_the_structured_coverage(tmp_path):
    """`list` feeds the Runs TABLE, which is polled every four seconds while
    an analysis is live and answers with up to a hundred rows. The structured
    coverage is the same ~2,000 characters `coverage_note` already carries,
    split by phase -- shipping both would double a payload no column of that
    table reads. The screen gets it from `checklist`, for the one analysis
    actually on screen, and `analysis --id` has it for anything else."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    listed = run(db, "list", "--project", "web")[0]
    assert "coverage" not in listed
    # And `coverage_note` is still there: bin/claude-cron's selftest and
    # test/e2e.test.sh both read it from this verb.
    assert "coverage_note" in listed
    assert json.loads(run(db, "analysis", "--id", str(aid))["coverage"])["phases"]
    checklist = run(db, "checklist", "--analysis", str(aid))
    assert json.loads(checklist["analysis"]["coverage"])["phases"]


def test_every_phases_prose_is_a_substring_of_the_paragraph(tmp_path):
    """BESIDE, NOT INSTEAD, and this is what that means byte for byte. Three
    reports and three screens have always read `coverage_note`, and every
    analysis written before the `coverage` column has only that. The
    structured half re-uses the SAME strings -- nothing reworded, nothing
    summarised -- so a phase's WHOLE note is always one contiguous run of the
    paragraph a reader can still read whole.

    STAGED ON THE CASE THAT USED TO BREAK IT. A lockfile under a directory the
    default filter excludes gives the SBOM a component the dependency phase
    never looked up, so `SBOM_UNFILTERED_NOTE` fires -- and the SBOM has a
    sentence of its own. That sentence used to be emitted AFTER the SBOM's,
    while the dependency row carried it right after its own notes: the row
    was not a substring of the paragraph, and the only test of the property
    put the lockfile at the root, where the sentence is never said at all.
    Asserted for every phase `prepare` files -- all of `PHASE_ORDER` but the
    two the close adds -- and then again after the close, for the two it adds.

    THE ONE DELIBERATE EXCEPTION is the triage row's two summary sentences
    (`TRIAGE_NOTHING_NOTE`, `TRIAGE_ALL_READ_NOTE`): they describe what the
    agent did, not a gap, and the paragraph is the list of gaps. The row's
    other sentences -- findings never read, a decision that exempted one, a
    `prepare` that never ran -- are gaps, and the close writes each of them
    into the paragraph too.
    """
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    (root / "fixtures").mkdir(parents=True)
    (root / "fixtures" / "requirements.txt").write_text("requests==2.31.0\n")
    aid = open_analysis(db)
    note = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
               "--offline")["coverage_note"]
    _, phases = _coverage_phases(db, aid)
    by_name = {p["name"]: p for p in phases}
    # The case is reached: the unfiltered sentence is said once, filed under
    # both rows, and the SBOM row has a sentence of its own beside it --
    # whichever producer built the document in this configuration.
    unfiltered = "No vulnerability was looked up for"
    assert note.count(unfiltered) == 1, note
    assert unfiltered in by_name["dependencies"]["note"]
    assert unfiltered in by_name["sbom"]["note"]
    assert any(own in by_name["sbom"]["note"] for own in (
        security_cli.deps.SBOM_FALLBACK_NOTE,
        security_cli.adapters.SYFT_SBOM_NOTE)), by_name["sbom"]["note"]
    # Every phase `prepare` writes, and each one's whole prose.
    assert [p["name"] for p in phases] == \
        list(security_cli.coverage.PHASE_ORDER[:-2])
    for p in phases:
        assert p["note"] in note, \
            f"{p['name']}'s note is not in the paragraph: {p['note']!r}"

    run(db, "finish", "--analysis", str(aid), "--state", "done",
        "--note", "I stopped before the SAST phase")
    row, phases = _coverage_phases(db, aid)
    assert [p["name"] for p in phases] == list(security_cli.coverage.PHASE_ORDER)
    for p in phases:
        if p["name"] == "triage":
            assert p["note"] == security_cli.TRIAGE_NOTHING_NOTE.format(
                floor=security_cli.TRIAGE_FLOOR)
            continue
        assert p["note"] in row["coverage_note"], \
            f"{p['name']}'s note is not in the paragraph: {p['note']!r}"


def test_the_close_adds_a_triage_phase_carrying_the_count(tmp_path):
    """The ninth phase, and the one no deterministic pass can report on
    itself: whether anybody READ what the scanners produced. `warning` with
    the same sentence the downgrade already writes -- the count and the first
    three by rule and file."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _scanner_finding(db, aid, rule="CVE-2", severity="critical", file="pom.xml")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"][0]
    assert phases[-1]["name"] == "triage", "triage is the last row of the table"
    assert triage["status"] == "warning"
    assert triage["by"] == "agent"
    assert "2 deterministic findings were never triaged" in triage["note"]
    assert triage["note"] in row["coverage_note"]


def test_a_triaged_analysis_gets_a_triage_phase_that_says_how_many_were_read(tmp_path):
    """The control. A table that only ever showed the failure would say
    nothing about the run that did the job -- and "ran" over an analysis with
    nothing to read would be praise for work that never happened, which is
    why the two are worded apart."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _triage(db, aid, fp, rule="CVE-1")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    _, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"][0]
    assert triage["status"] == "ran"
    # Counted with NO severity floor, deliberately: `_triage` above re-reports
    # the finding at a corrected `low`, so a count taken over the floored set
    # would shrink as a result of the very triage it is reporting and print
    # "nothing was waiting" over an analysis where something was read.
    assert "The agent re-reported 1 deterministic finding and left none at " \
        "medium or above unread" in triage["note"]

    empty = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(empty), "--state", "done")
    _, phases = _coverage_phases(db, empty)
    nothing = [p for p in phases if p["name"] == "triage"][0]
    assert nothing["status"] == "ran"
    assert "No deterministic finding at medium or above was waiting" \
        in nothing["note"]


def test_a_close_that_never_reached_the_triage_check_files_it_as_skipped(tmp_path):
    """`capped` from the caller means `done`'s precondition was never
    evaluated, so nothing knows whether the findings were read. `skipped` --
    the same word every deterministic phase uses for "nothing looked" -- and
    never `ran`."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    _scanner_finding(db, aid, rule="CVE-1", severity="high")
    run(db, "finish", "--analysis", str(aid), "--state", "capped")
    _, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"][0]
    assert triage["status"] == "skipped"
    assert triage["by"] is None


def test_the_engines_second_close_never_overwrites_a_triage_the_agent_earned(tmp_path):
    """A row is closed TWICE by design -- the agent, then the engine with the
    run's own verdict. The engine's close may lower the state to `capped`,
    which skips the triage check entirely; a `skipped` written there would
    erase the `ran` the agent's own close had verified, and the table would
    end up less true than it was a second earlier. `merge` also has to
    REPLACE rather than append, or the second close leaves two triage rows
    disagreeing with each other."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _triage(db, aid, fp, rule="CVE-1")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "finish", "--analysis", str(aid), "--state", "capped", "--spend", "2")
    row, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"]
    assert len(triage) == 1, f"the table grew a second triage row: {phases}"
    assert triage[0]["status"] == "ran"
    assert row["state"] == "capped" and row["spend_usd"] == 2


def test_a_sentence_about_two_phases_is_filed_under_both(tmp_path, monkeypatch,
                                                         capsys):
    """TWO OF THE 27 NOTES DESCRIBE TWO PHASES AT ONCE, and the cost of
    picking one home for them is that the other half of what they say becomes
    invisible from the row that states it.

    `DEP_SBOM_NOTE` is appended by the DEPENDENCY producer (Trivy) and every
    word of it is about the SBOM -- what it lists, and which lockfile formats
    that covers. `SBOM_UNFILTERED_NOTE` is, in its own docstring's words,
    "about the gap BETWEEN them": what the published SBOM lists against what
    the dependency phase actually looked up, which is the contradiction a
    consumer reading the two side by side used to hit ("this project ships
    lodash 4.17.20" beside "no dependency findings").

    So both are filed under `dependencies` AND under `sbom`. The paragraph is
    unchanged -- each still appears in it exactly once, in the same place --
    which is the other half of what "beside, not instead" has to mean.

    Driven in-process for the reason the group above gives: this needs Trivy
    present and Syft absent at once, which a subprocess boundary cannot stage.
    """
    root = tmp_path / "repo"
    (root / "fixtures").mkdir(parents=True)
    # Under a DEFAULT-ignored directory, so the dependency phase's filter hides
    # it while `deps.inventory` -- which deliberately does not read
    # `ignore_paths` -- still lists it in the SBOM. That gap is the note.
    (root / "fixtures" / "requirements.txt").write_text("requests==2.31.0\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    # A sentence BEFORE the SBOM one, as the real `trivy_scan` always has: the
    # boundary assertion below is vacuous against a one-note dependency phase.
    monkeypatch.setattr(security_cli.adapters, "trivy_scan",
                        lambda root, ignore_paths=(): (
                            [], [security_cli.adapters.DEP_ENGINE_NOTE.format(
                                     version="0.74.0"),
                                 security_cli.adapters.DEP_SBOM_NOTE]))
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    note = json.loads(capsys.readouterr().out)["coverage_note"]
    _, phases = _coverage_phases(db, aid)
    by_name = {p["name"]: p["note"] for p in phases}

    # The note's own opening clause, from ignores.SBOM_UNFILTERED_NOTE's
    # format string -- the counts and the file list in it are measured per
    # repository, so the stable half is what this anchors on.
    unfiltered = "No vulnerability was looked up for"
    assert security_cli.adapters.DEP_SBOM_NOTE in by_name["dependencies"]
    assert security_cli.adapters.DEP_SBOM_NOTE in by_name["sbom"]
    assert unfiltered in by_name["dependencies"], by_name["dependencies"]
    assert unfiltered in by_name["sbom"], by_name["sbom"]
    # And the paragraph still says each of them exactly once. Filing a
    # sentence under two phases must not duplicate it in the text three
    # reports and three screens have always read.
    assert note.count(security_cli.adapters.DEP_SBOM_NOTE) == 1
    assert note.count(unfiltered) == 1
    # BOTH ROWS ARE WHOLE SUBSTRINGS AT ONCE, which is only possible because
    # the two shared sentences sit on the boundary between them: the paragraph
    # reads `dep notes | SBOM sentence, unfiltered | SBOM's own notes`. This
    # is the assertion the test above makes for the OSV path, on the Trivy
    # path, where the dependency producer is the one saying the SBOM sentence.
    for name, prose in by_name.items():
        assert prose in note, f"{name}'s note is not in the paragraph: {prose!r}"
    assert (note.index(security_cli.adapters.DEP_ENGINE_NOTE.format(version="0.74.0"))
            < note.index(security_cli.adapters.DEP_SBOM_NOTE)
            < note.index(unfiltered)
            < note.index(security_cli.deps.SBOM_FALLBACK_NOTE)), note


def test_the_sbom_sentence_disappears_from_both_phases_when_there_is_no_sbom(
        tmp_path, monkeypatch, capsys):
    """The other half of filing a sentence under two phases: it has to LEAVE
    both when `cmd_prepare` drops it. `DEP_SBOM_NOTE` asserts what "the SBOM"
    lists, and with no document stored that is a sentence about a file the
    reader cannot download -- which is why the phase note is read back out of
    the swapped list rather than off the constant."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(security_cli.adapters, "trivy_scan",
                        lambda root, ignore_paths=(): (
                            [], [security_cli.adapters.DEP_SBOM_NOTE]))
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    note = json.loads(capsys.readouterr().out)["coverage_note"]
    _, phases = _coverage_phases(db, aid)
    by_name = {p["name"]: p for p in phases}
    assert security_cli.adapters.DEP_SBOM_NOTE not in by_name["dependencies"]["note"]
    assert security_cli.adapters.DEP_SBOM_NOTE not in by_name["sbom"]["note"]
    assert security_cli.adapters.DEP_SBOM_NOTE not in note
    # No lockfile anywhere, so neither producer had a component to list.
    assert by_name["sbom"]["status"] == "skipped"
    assert security_cli.NO_SBOM_NOTE in by_name["sbom"]["note"]


def test_the_downloaded_report_opens_with_the_phase_table(tmp_path):
    """End to end, through the same door the download uses. The table is what
    a reader meets first; the paragraph is still under it, unchanged."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    md = run_text(db, "render", "--analysis", str(aid), "--format", "md")
    assert "| Phase | Status | By |" in md
    assert md.index("| Phase | Status | By |") < md.index("## Checklist")
    assert "| iac | skipped | — |" in md
    assert "| sast | ran | agent |" in md
    assert "| triage | ran | agent |" in md
    assert md.index("| sast | ran | agent |") < md.index("| triage | ran | agent |")
    doc = json.loads(run_text(db, "render", "--analysis", str(aid),
                              "--format", "json"))
    assert [p["name"] for p in doc["coverage"]["phases"]][-1] == "triage"


# -------------------------------- the two rows the close writes, and when not

def test_a_never_prepared_close_files_the_agents_rows_skipped_and_nothing_ran(tmp_path):
    """THE MINERVA 9/10 SHAPE, on the table. An analysis whose `prepare` never
    ran closes `capped` under a paragraph saying nothing ran -- and its triage
    row used to read `ran`, because the row was built from `_untriaged`'s
    answer BEFORE the `prepared` guard asked its question, and a ledger with
    no scanner rows has nothing waiting. Both agent-side rows are `skipped`,
    under the paragraph's own sentence, and no row in the table reads `ran`."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row, phases = _coverage_phases(db, aid)
    by_name = {p["name"]: p for p in phases}
    assert row["state"] == "capped"
    assert by_name["triage"]["status"] == "skipped"
    assert by_name["sast"]["status"] == "skipped"
    assert by_name["triage"]["by"] is None and by_name["sast"]["by"] is None
    assert not [p for p in phases if p["status"] == "ran"], phases
    for name in ("triage", "sast"):
        assert "deterministic phases never ran" in by_name[name]["note"]
        assert by_name[name]["note"] in row["coverage_note"]
    # The engine's second close -- `capped`, with the spend -- keeps both rows
    # and both sentences: it brings no note of its own and must not blank
    # theirs.
    run(db, "finish", "--analysis", str(aid), "--state", "capped", "--spend", "1")
    row, phases = _coverage_phases(db, aid)
    assert {p["status"] for p in phases} == {"skipped"}, phases
    assert all("deterministic phases never ran" in p["note"] for p in phases), phases


def test_the_close_files_the_agents_own_sast_pass_by_the_verdict(tmp_path):
    """The eighth row: the agent's own SAST pass had a row for its Semgrep
    PRE-pass and none for itself, so the table said nothing about the primary
    source of the `sast` category. `ran` on `done`, `warning` on `capped` --
    the verdict is the only evidence there is about the pass -- and its prose
    is the agent's own `--note`, the one sentence about its coverage the close
    already carries into the paragraph."""
    db = tmp_path / "security.db"
    done = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(done), "--state", "done")
    _, phases = _coverage_phases(db, done)
    assert [p["name"] for p in phases] == list(security_cli.coverage.PHASE_ORDER)
    sast = [p for p in phases if p["name"] == "sast"][0]
    assert sast == {"name": "sast", "status": "ran", "by": "agent", "note": ""}

    capped = prepared_analysis(db, tmp_path)
    run(db, "finish", "--analysis", str(capped), "--state", "capped",
        "--note", "I stopped before the SAST phase")
    row, phases = _coverage_phases(db, capped)
    sast = [p for p in phases if p["name"] == "sast"][0]
    assert sast["status"] == "warning" and sast["by"] == "agent"
    assert sast["note"] == "I stopped before the SAST phase"
    assert sast["note"] in row["coverage_note"]


def test_the_engines_capped_lowers_the_sast_row_and_leaves_the_triage_row(tmp_path):
    """The one asymmetry between the two rows the close writes, and it is
    deliberate. The triage check is a fact about the ledger, and the engine's
    `capped` says nothing about whether the findings were read -- so that row
    keeps the `ran` the agent's close earned (pinned above). The agent's SAST
    pass is the opposite case: the engine's `capped` is precisely the
    statement that the run making the `done` claim was cut short, so its row
    is lowered to `warning`. The agent's sentence is carried forward, because
    the engine's close brings none of its own."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _triage(db, aid, fp, rule="CVE-1")
    run(db, "finish", "--analysis", str(aid), "--state", "done",
        "--note", "the SAST pass covered every entry point")
    run(db, "finish", "--analysis", str(aid), "--state", "capped", "--spend", "2")
    row, phases = _coverage_phases(db, aid)
    by_name = {p["name"]: p for p in phases}
    assert row["state"] == "capped"
    assert by_name["sast"]["status"] == "warning"
    assert by_name["sast"]["note"] == "the SAST pass covered every entry point"
    assert by_name["triage"]["status"] == "ran"
    assert len([p for p in phases if p["name"] == "sast"]) == 1, phases


def test_the_triage_row_says_when_a_decision_and_not_absence_left_nothing_waiting(tmp_path):
    """`_untriaged` rightly excludes a fingerprint the operator decided on --
    and the triage row then read "No deterministic finding at medium or above
    was waiting to be triaged". One was. It was exempted by a human, not
    absent, and the two are different facts about the same close."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="aws_secret_key", severity="high",
                          category="secret", producer="secrets",
                          file="config/legacy.env")
    _decide(db, fp)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"][0]
    assert row["state"] == "done"
    assert triage["status"] == "ran"
    assert triage["note"] == ("1 deterministic finding at medium or above "
                              "carried an operator decision and was not counted.")
    assert "was waiting to be triaged" not in triage["note"]
    assert triage["note"] in row["coverage_note"]


def test_the_triage_row_names_the_undecided_one_and_counts_the_decided_one(tmp_path):
    """The sibling: one decided, one not. The close lowers to `capped` for the
    undecided row and names it; the decided count rides beside that sentence
    rather than replacing it, and both are in the paragraph."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    decided = _scanner_finding(db, aid, rule="CVE-1", severity="critical")
    _scanner_finding(db, aid, rule="CVE-2", severity="high", file="pom.xml")
    _decide(db, decided)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    row, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"][0]
    assert row["state"] == "capped"
    assert triage["status"] == "warning"
    assert "1 deterministic finding was never triaged" in triage["note"]
    assert "CVE-2 (pom.xml)" in triage["note"]
    assert "CVE-1" not in triage["note"]
    assert ("1 deterministic finding at medium or above carried an operator "
            "decision and was not counted.") in triage["note"]
    assert triage["note"] in row["coverage_note"]


def test_a_decided_row_the_agent_also_read_is_counted_as_read_not_as_decided(tmp_path):
    """`triaged=0` in `_decided_count` is load-bearing: a decided row the agent
    re-reported anyway -- here at its original severity, so the floor alone
    would not drop it -- is in `_triaged_count`, and "was not counted" would
    be false of it."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    fp = _scanner_finding(db, aid, rule="CVE-1", severity="high")
    _decide(db, fp)
    _triage(db, aid, fp, rule="CVE-1", severity="high")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    _, phases = _coverage_phases(db, aid)
    triage = [p for p in phases if p["name"] == "triage"][0]
    assert "re-reported 1 deterministic finding" in triage["note"]
    assert "operator decision" not in triage["note"]


# ------------------------------ the secret row is earned by the history sweep
#
# In-process, like the Trivy group above: the gitleaks path has to be staged
# without depending on the binary, and the adapter's own third return value is
# what is being threaded through here. The adapter is proved against real
# repositories in tests/security/test_adapters.py.

@pytest.mark.parametrize("history, gap", [
    (security_cli.adapters.HISTORY_SHALLOW, security_cli.adapters.SHALLOW_GAP),
    (security_cli.adapters.HISTORY_GONE,
     security_cli.secrets.HISTORY_GAP.format(reason="fatal: bad object HEAD")),
], ids=["shallow", "gone"])
def test_the_secret_row_is_a_warning_when_the_history_was_not_swept_in_full(
        tmp_path, monkeypatch, capsys, history, gap):
    """`_scan_secrets` used to answer `ran` on the gitleaks path whatever the
    history sweep had covered, so a shallow clone -- or a history git could not
    walk at all -- got a green row over a paragraph saying the sweep saw only
    part of the history, or none of it. The row reads `warning` for anything
    short of the full history, beside the very sentence the paragraph carries
    for that gap."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    engine_note = security_cli.adapters.ENGINE_NOTE.format(
        version="gitleaks 8.21.0", scope="the working tree")
    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(security_cli.adapters, "gitleaks_scan",
                        lambda root, ignore_paths=(): ([], [gap, engine_note], history))
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db), "--offline"])
    note = json.loads(capsys.readouterr().out)["coverage_note"]
    _, phases = _coverage_phases(db, aid)
    secret = [p for p in phases if p["name"] == "secrets"][0]
    assert secret["status"] == "warning"
    assert secret["by"] == "gitleaks"
    assert gap in secret["note"]
    assert secret["note"] in note


def test_the_secret_row_is_ran_only_when_the_full_history_was_swept(
        tmp_path, monkeypatch, capsys):
    """The control: the engine over a full clone, and the one state that earns
    the row a `ran`."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    engine_note = security_cli.adapters.ENGINE_NOTE.format(
        version="gitleaks 8.21.0",
        scope=f"the working tree and {security_cli.adapters.FULL_HISTORY}")
    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(security_cli.adapters, "gitleaks_scan",
                        lambda root, ignore_paths=(): (
                            [], [engine_note], security_cli.adapters.HISTORY_OK))
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db), "--offline"])
    capsys.readouterr()
    _, phases = _coverage_phases(db, aid)
    secret = [p for p in phases if p["name"] == "secrets"][0]
    assert secret["status"] == "ran"
    assert secret["by"] == "gitleaks"


def test_the_fallback_sbom_names_the_inventory_that_built_it(tmp_path, monkeypatch,
                                                            capsys):
    """`warning | —` over a document that exists said "somebody built this
    and nobody will say who", while the sentence beside it named this
    project's own inventory. The row names it too. In-process with every
    engine absent, so the fallback is what runs in both configurations of
    this suite."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    monkeypatch.setattr(security_cli.adapters, "engine_path", lambda name: None)
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db), "--offline"])
    capsys.readouterr()
    _, phases = _coverage_phases(db, aid)
    sbom = [p for p in phases if p["name"] == "sbom"][0]
    assert sbom["status"] == "warning"
    assert sbom["by"] == security_cli.PRODUCER_INVENTORY == "inventory"
    assert security_cli.deps.SBOM_FALLBACK_NOTE in sbom["note"]


# ------------------------------- a decision is not taken while a run is live

def test_decide_is_refused_while_the_projects_latest_analysis_is_running(tmp_path):
    """The environment guard is a guardrail against MISTAKE: CC_SECURITY_AGENT
    lives in the agent's own environment and the agent has a shell, so
    `env -u CC_SECURITY_AGENT ...` walks past it. This check does not depend on
    the environment at all -- while an analysis of the project is `running`, an
    agent of that project is alive, and that is exactly the window in which a
    decision would be one."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    out = fails(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
                "--state", "accepted", "--reason", "I checked it", "--by", "luiz")
    assert out.returncode != 0
    assert "still running" in out.stderr
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT count(*) FROM decision").fetchone()[0] == 0

    # And it is the ANALYSIS, not the environment, that closed the door.
    out = fails(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
                "--state", "accepted", "--reason", "I checked it", "--by", "luiz",
                env={k: v for k, v in os.environ.items() if k != "CC_SECURITY_AGENT"})
    assert out.returncode != 0
    assert "still running" in out.stderr

    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "I checked it", "--by", "luiz")
    assert conn.execute("SELECT count(*) FROM decision").fetchone()[0] == 1


def test_a_run_on_another_project_does_not_block_a_decision(tmp_path):
    """Keyed on the project being decided about. A fleet analysing four
    projects at once must not freeze everybody's triage."""
    db = tmp_path / "security.db"
    open_analysis(db, project="other", repo="other")
    run(db, "finish", "--analysis", str(open_analysis(db, project="web")),
        "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "unreachable in production", "--by", "luiz")
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT count(*) FROM decision").fetchone()[0] == 1


def test_an_older_running_analysis_still_blocks_a_decision(tmp_path):
    """ANY analysis of the project, not only the latest one.

    This used to be keyed on the project's latest analysis alone, which had a
    two-command bypass: open a SECOND analysis of the same project and close
    it, and the latest analysis reads `done` while an older one -- the one an
    agent might still be alive inside of -- sits `running`, unseen by a query
    that only ever looked at the newest row. See
    `test_the_agent_cannot_dismiss_its_finding_via_a_second_analysis` for the
    exact bypass reproduced end to end. A row left `running` by a run that
    genuinely died is not a permanent lock either: the engine's own preflight
    sweep (`cmd_security_analyze` in bin/claude-cron) closes those before the
    project's next analysis opens."""
    db = tmp_path / "security.db"
    open_analysis(db)                       # older, still says running
    run(db, "finish", "--analysis", str(open_analysis(db, commit="def")),
        "--state", "done")
    out = fails(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
                "--state", "accepted", "--reason", "reviewed by hand", "--by", "luiz")
    assert out.returncode != 0
    assert "still running" in out.stderr
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT count(*) FROM decision").fetchone()[0] == 0


def test_the_agent_cannot_dismiss_its_finding_via_a_second_analysis(tmp_path):
    """The merge-verification pass's exact bypass of the running-analysis
    refusal above. `decide`'s check used to look only at the project's LATEST
    analysis: from its own shell (the CC_SECURITY_AGENT flag only ever guards
    `decide`, `rename-project` and `open-analysis`, never `finish` or a second
    `open-analysis` run once the flag is off -- see `_refuse_if_agent`), the
    agent could `open-analysis` a second analysis of the SAME project and
    `finish` it right away. The project's latest analysis then read `done`
    while the ORIGINAL analysis -- the one whose finding it wants to dismiss --
    was still `running`, and the old latest-row-only query never saw it."""
    db = tmp_path / "security.db"
    original = open_analysis(db, project="web", commit="orig", run_id="r1")
    second = open_analysis(db, project="web", commit="def", run_id="r2")
    run(db, "finish", "--analysis", str(second), "--state", "done")
    # The bypass's premise: the project's LATEST analysis is now closed --
    # `done` if it had run `prepare`, `capped` here since it did not (see
    # cmd_finish's own `prepared` guard), either way NOT `running`, which is
    # all the old latest-row-only check ever looked at.
    assert run(db, "list", "--project", "web")[0]["state"] != "running"
    out = fails(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
                "--state", "false_positive", "--reason", "I checked it myself",
                "--by", "the agent")
    assert out.returncode != 0
    assert "still running" in out.stderr
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT count(*) FROM decision").fetchone()[0] == 0
    # The original, still-running analysis is the one that must be named --
    # not the closed second one that made the latest row look clear.
    assert f"analysis {original} of 'web'" in out.stderr


# --------------------------------------------------- the SBOM is downloadable

def test_render_sbom_hands_back_the_stored_cyclonedx(tmp_path):
    """`prepare` built an SBOM on every analysis with a lockfile in it and
    nothing anywhere could read it back -- not the CLI, not the API, not the
    page. An inventory nobody can download does not exist for the one job an
    SBOM has, which is being handed to somebody else."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\nurllib3==2.0.7\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(aid), "--state", "done")

    doc = json.loads(run_text(db, "render", "--analysis", str(aid), "--format", "sbom"))
    assert doc["bomFormat"] == "CycloneDX"
    names = {c["name"]: c["version"] for c in doc["components"]}
    assert names == {"requests": "2.31.0", "urllib3": "2.0.7"}


def test_render_sbom_says_so_when_there_is_none_rather_than_printing_nothing(tmp_path):
    """A project with no lockfile the inventory can read stores no SBOM. An
    empty stdout there is a zero-byte download and a puzzle; the refusal names
    the formats that would have produced one."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    out = fails(db, "render", "--analysis", str(aid), "--format", "sbom")
    assert out.returncode != 0
    assert "no SBOM recorded" in out.stderr
    assert "package-lock.json" in out.stderr
    assert out.stdout.strip() == ""


def test_render_sbom_refuses_an_analysis_that_does_not_exist(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "render", "--analysis", "999", "--format", "sbom")
    assert out.returncode != 0
    assert "no such analysis" in out.stderr


# ------------------------------------------------- Syft replaces `deps.sbom`

needs_syft = pytest.mark.skipif(
    shutil.which("syft") is None, reason="syft is not installed on this machine")


def test_prepare_prefers_syft_and_never_calls_deps_sbom(tmp_path, monkeypatch):
    """Two producers for one SBOM is not the two-fingerprint problem
    `_scan_secrets`/`_scan_dependencies` guard against -- an SBOM is not
    fingerprinted at all -- but it is still ONE producer, not two: calling
    `deps.sbom` after Syft already answered would silently overwrite Syft's
    document with a narrower one for no reason. `deps.sbom` raising proves it
    was never called, not merely that its result was discarded."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/syft" if name == "syft" else None)
    monkeypatch.setattr(
        security_cli.adapters, "syft_sbom",
        lambda root: ({"bomFormat": "CycloneDX", "specVersion": "1.5",
                       "components": [{"type": "library", "name": "left-pad",
                                       "version": "1.3.0",
                                       "purl": "pkg:npm/left-pad@1.3.0"}]},
                      ["The SBOM was produced by syft 1.51.1.",
                       security_cli.adapters.SYFT_SBOM_NOTE]))

    def must_not_run(*_a, **_kw):
        raise AssertionError("deps.sbom must not run once Syft has answered")
    monkeypatch.setattr(security_cli.deps, "sbom", must_not_run)

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--offline", "--db", str(db)])
    document = json.loads(run_text(db, "render", "--analysis", str(aid),
                                   "--format", "sbom"))
    assert document["components"][0]["name"] == "left-pad"
    row = run(db, "list", "--project", "web")[0]
    assert "Syft" in row["coverage_note"]


def test_prepare_falls_back_to_deps_sbom_when_syft_finds_nothing_useful(
        tmp_path, monkeypatch):
    """The mirror of the test above: a project with a lockfile `deps.inventory`
    reads, on a machine where Syft is installed but answers with nothing this
    adapter can use, still gets the SBOM the pre-Syft behaviour always gave
    it -- the fallback pair this task replaces, not removes."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(security_cli.adapters, "engine_path",
                        lambda name: "/usr/bin/syft" if name == "syft" else None)
    monkeypatch.setattr(security_cli.adapters, "syft_sbom",
                        lambda root: (None, ["syft did not finish within "
                                             "600s and was stopped."]))

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--offline", "--db", str(db)])
    document = json.loads(run_text(db, "render", "--analysis", str(aid),
                                   "--format", "sbom"))
    assert {c["name"]: c["version"] for c in document["components"]} == {
        "requests": "2.31.0"}
    row = run(db, "list", "--project", "web")[0]
    assert "did not finish" in row["coverage_note"]
    assert "own inventory" in row["coverage_note"]


def test_the_sbom_note_is_replaced_not_duplicated_when_syft_and_trivy_both_run(
        tmp_path, monkeypatch):
    """Task 3's `adapters.DEP_SBOM_NOTE` says the SBOM lists the five
    lockfile formats `deps.inventory` reads -- true only while `deps.sbom`
    built it. The moment Syft supplies the document instead, that specific
    claim is false: Syft reads far more than five formats. `cmd_prepare` is
    the one place that knows both which producer found the CVEs and which
    one built the SBOM, so it has to swap the two notes rather than let the
    report contradict itself."""
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(
        security_cli.adapters, "engine_path",
        lambda name: f"/usr/bin/{name}" if name in ("trivy", "syft") else None)
    monkeypatch.setattr(
        security_cli.adapters, "trivy_scan",
        lambda root, ignore_paths=(): (
            [], [security_cli.adapters.DEP_ENGINE_NOTE.format(version="trivy 0.74.0"),
                 security_cli.adapters.DEP_ID_NOTE,
                 security_cli.adapters.DEP_SBOM_NOTE]))
    monkeypatch.setattr(
        security_cli.adapters, "syft_sbom",
        lambda root: ({"bomFormat": "CycloneDX", "specVersion": "1.5",
                       "components": [{"type": "library", "name": "x",
                                       "version": "1.0",
                                       "purl": "pkg:generic/x@1.0"}]},
                      ["The SBOM was produced by syft 1.51.1.",
                       security_cli.adapters.SYFT_SBOM_NOTE]))

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])
    note = run(db, "list", "--project", "web")[0]["coverage_note"]
    assert security_cli.adapters.DEP_SBOM_NOTE not in note
    assert security_cli.adapters.SYFT_SBOM_NOTE in note
    assert "Trivy" in note


def test_the_sbom_notes_are_dropped_when_no_SBOM_IS_STORED_AT_ALL(
        tmp_path, monkeypatch):
    """The case the swap above fell straight through.

    `trivy_scan` appends `DEP_SBOM_NOTE` unconditionally, and `cmd_prepare`
    only swapped it out when `SYFT_SBOM_NOTE` was present. But `_scan_sbom`
    returns `(None, notes)` for a checkout with no lockfile `deps.inventory`
    reads and a Syft that answered with nothing usable -- so NOTHING is
    stored, `render --format sbom` answers "no SBOM recorded", and the note
    still read "The SBOM lists the five lockfile formats ..." beside "Syft
    wrote a document naming no `components`, so it was not used" -- the
    second implying a fallback that never happened.
    """
    root = tmp_path / "repo"          # no lockfile of any kind
    root.mkdir()
    db = tmp_path / "security.db"
    aid = open_analysis(db)

    monkeypatch.setattr(
        security_cli.adapters, "engine_path",
        lambda name: f"/usr/bin/{name}" if name in ("trivy", "syft") else None)
    monkeypatch.setattr(
        security_cli.adapters, "trivy_scan",
        lambda root, ignore_paths=(): (
            [], [security_cli.adapters.DEP_SBOM_NOTE]))
    monkeypatch.setattr(
        security_cli.adapters, "syft_sbom",
        lambda root: (None, [security_cli.adapters.SYFT_NO_COMPONENTS_NOTE]))
    monkeypatch.setattr(security_cli.adapters, "trivy_iac_scan",
                        lambda root, ignore_paths=(): ([], []))

    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db)])

    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT COUNT(*) FROM sbom").fetchone()[0] == 0

    note = run(db, "list", "--project", "web")[0]["coverage_note"]
    assert security_cli.adapters.DEP_SBOM_NOTE not in note, (
        "no SBOM was stored, so nothing may describe what it lists")
    assert security_cli.NO_SBOM_NOTE in note, (
        "and the reader has to be told there is no SBOM, or "
        "`SYFT_NO_COMPONENTS_NOTE`'s 'it was not used' still implies a "
        "fallback that never happened")


@needs_syft
def test_prepare_stores_syfts_sbom_and_it_survives_the_download_round_trip(
        tmp_path):
    """The one test that matters beyond the parser: whichever producer built
    the SBOM, `ledger.store_sbom` has to accept it and `render --format sbom`
    has to hand it back unharmed. `test_render_sbom_hands_back_the_stored_
    cyclonedx` above already proves this for `deps.sbom` (the suite's own
    `CC_SECURITY_ENGINES=off` default keeps Syft out of that one); this is
    the same round trip for the real Syft binary."""
    root = tmp_path / "repo"
    root.mkdir()
    lockfile = REPO / "tests" / "security" / "fixtures" / "package-lock.json"
    (root / "package-lock.json").write_text(lockfile.read_text())
    db = tmp_path / "security.db"
    env = {**os.environ, "CC_SECURITY_ENGINES": "on"}
    aid = open_analysis(db)

    prepared = run(db, "prepare", "--analysis", str(aid), "--root", str(root),
                   "--offline", env=env)
    assert "Syft" in prepared["coverage_note"]
    run(db, "finish", "--analysis", str(aid), "--state", "done", env=env)

    document = json.loads(run_text(db, "render", "--analysis", str(aid),
                                   "--format", "sbom"))
    assert document["bomFormat"] == "CycloneDX"
    assert not any(c.get("type") == "file" for c in document["components"])
    names = {c["name"]: c["version"] for c in document["components"]}
    assert names.get("lodash") == "4.17.20"


def test_checklist_of_an_analysis_that_does_not_exist_exits_with_the_old_sentence(tmp_path):
    """`queries.checklist` now raises `AnalysisNotFound` instead of calling
    `sys.exit` itself (a library must not exit the process -- a future
    server route needs to catch this and answer 404, not go down with it).
    `cmd_checklist` catches it and must still exit non-zero with the exact
    sentence the command line always printed, byte for byte -- driven as a
    subprocess, the same way the agent and bash call this command."""
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "checklist", "--analysis", "999")
    assert out.returncode != 0
    assert out.stderr.strip() == "no such analysis: 999"
    assert out.stdout.strip() == ""


def test_render_of_an_analysis_that_does_not_exist_exits_with_the_old_sentence(tmp_path):
    """Same guarantee as `checklist` above, for `render`'s non-sbom path
    (which also calls `queries.checklist`) -- `render --format sbom` has its
    own refusal (tested above) that never goes through `queries.checklist`
    at all, so it needed no change and is untouched by this fix."""
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "render", "--analysis", "999", "--format", "md")
    assert out.returncode != 0
    assert out.stderr.strip() == "no such analysis: 999"
    assert out.stdout.strip() == ""


def test_the_door_accepts_info_as_a_severity(tmp_path):
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = run(db, "open-analysis", "--project", "web", "--repo", "web",
              "--branch", "main", "--commit", "a", "--profile", "quick",
              "--run-id", "r")["analysis_id"]
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "c" * 64, "category": "hygiene", "rule": "observation",
        "severity": "info", "title": "worth knowing", "rationale": "r",
        "remediation": "none needed", "occurrences": []}))


# ------------------------------------------------------------ the event log

def test_opening_and_finishing_an_analysis_files_events(tmp_path):
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = run(db, "open-analysis", "--project", "web", "--repo", "web",
              "--branch", "main", "--commit", "a", "--profile", "quick",
              "--run-id", "r")["analysis_id"]
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    kinds = [e["kind"] for e in run(db, "events", "--project", "web")]
    assert "analysis_started" in kinds
    assert "analysis_finished" in kinds


def test_a_decision_files_an_event_carrying_its_reason(tmp_path):
    db = tmp_path / "security.db"
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "reviewed with the team")
    ev = [e for e in run(db, "events", "--project", "web")
          if e["kind"] == "decision_made"]
    assert len(ev) == 1
    assert "reviewed with the team" in ev[0]["detail"]


# ---------------------------------------- activity-data, the Activity screen

def test_activity_data_does_not_create_a_ledger_that_does_not_exist(tmp_path):
    """Read-only, via `queries.read_only` -- same reasoning `index-data`/
    `project-data`/`findings-page` already follow: a screen that only LOOKS
    must not conjure the ledger file it is asking about into existence."""
    db = tmp_path / "security.db"
    out = run(db, "activity-data")
    assert out == {"events": [], "summary": {k: 0 for k in security_ledger.EVENT_KINDS},
                   "projects": [], "page": 1, "per_page": 25}
    assert not db.exists()


def test_activity_data_bundles_events_summary_and_projects(tmp_path):
    db = tmp_path / "security.db"
    run(db, "event", "--project", "web", "--kind", "analysis_started",
        "--detail", "quick on main", "--related", "1")
    run(db, "event", "--project", "web", "--kind", "decision_made",
        "--detail", "accepted: reviewed", "--related", "abc123def456")
    run(db, "event", "--project", "api", "--kind", "settings_changed")

    out = run(db, "activity-data", "--since", "0")
    kinds = [e["kind"] for e in out["events"]]
    assert set(kinds) == {"analysis_started", "decision_made", "settings_changed"}
    assert out["summary"]["analysis_started"] == 1
    assert out["summary"]["decision_made"] == 1
    assert out["summary"]["settings_changed"] == 1
    assert out["summary"]["report_exported"] == 0
    assert {p["project"]: p["count"] for p in out["projects"]} == {"web": 2, "api": 1}


def test_activity_data_kind_narrows_the_events_only(tmp_path):
    """The sidebar's per-kind counts and the most-active-projects list both
    describe the WHOLE period, regardless of which kind the table is
    filtered to -- narrowing the table to one tab must not also zero out
    the sidebar's other counts (see cmd_activity_data's own docstring)."""
    db = tmp_path / "security.db"
    run(db, "event", "--project", "web", "--kind", "analysis_started")
    run(db, "event", "--project", "web", "--kind", "decision_made")

    out = run(db, "activity-data", "--since", "0", "--kind", "decision_made")
    assert [e["kind"] for e in out["events"]] == ["decision_made"]
    # The summary is NOT narrowed to the same kind -- both counts are real.
    assert out["summary"]["analysis_started"] == 1
    assert out["summary"]["decision_made"] == 1
    assert {p["project"] for p in out["projects"]} == {"web"}


def test_activity_data_project_narrows_every_panel(tmp_path):
    """Unlike `kind`, `project` is a real scope change and narrows the
    events, the summary AND the projects list alike."""
    db = tmp_path / "security.db"
    run(db, "event", "--project", "web", "--kind", "analysis_started")
    run(db, "event", "--project", "api", "--kind", "decision_made")

    out = run(db, "activity-data", "--since", "0", "--project", "web")
    assert [e["project"] for e in out["events"]] == ["web"]
    assert out["summary"]["analysis_started"] == 1
    assert out["summary"]["decision_made"] == 0
    assert [p["project"] for p in out["projects"]] == ["web"]


def test_activity_data_refuses_an_unknown_kind_at_the_cli_edge(tmp_path):
    """`--kind` carries `choices=` for the same reason `findings-page`'s own
    severity/state/category do: CLI-direct use gets the identical validation
    the server's own route independently performs."""
    db = tmp_path / "security.db"
    out = fails(db, "activity-data", "--kind", "findings_viewed")
    assert out.returncode != 0
    assert "invalid choice" in out.stderr


# --------------------------------------- findings-page's own --fingerprint
#
# Its siblings -- --severity, --state, --category -- get shape validation for
# free from argparse's own `choices=`: a closed set, refused with "invalid
# choice" the instant a typo reaches it. --fingerprint cannot use `choices=`
# (it is a PREFIX -- 1 to 64 lowercase hex characters, not one value out of a
# fixed set), so before this it accepted anything at all: a mistyped value
# silently matched zero rows instead of refusing with a sentence, the exact
# failure this module's own docstring says every verb here exists to avoid.
# The server's own route (`security_findings`, bin/claude-cron-server) already
# validates this shape at its edge -- these two tests are the CLI's own,
# independent copy of that guard, the same relationship
# test_activity_data_refuses_an_unknown_kind_at_the_cli_edge above has to
# `security_activity`'s.

def test_findings_page_refuses_a_malformed_fingerprint_at_the_cli_edge(tmp_path):
    db = tmp_path / "security.db"
    out = fails(db, "findings-page", "--project", "web", "--fingerprint", "not-hex!")
    assert out.returncode != 0
    assert "fingerprint" in out.stderr
    assert "lowercase hex" in out.stderr


def test_findings_page_refuses_a_fingerprint_over_64_characters(tmp_path):
    db = tmp_path / "security.db"
    out = fails(db, "findings-page", "--project", "web", "--fingerprint", "a" * 65)
    assert out.returncode != 0
    assert "fingerprint" in out.stderr


def test_findings_page_accepts_a_genuine_fingerprint_prefix(tmp_path):
    """Containment probe: a real prefix -- lowercase hex, any length from 1
    to 64 -- must still be accepted. Exactly what the Activity screen's own
    deep link sends: the first 12 characters of a decision's fingerprint
    (see ui/security/activity-screen.js's own file comment)."""
    db = tmp_path / "security.db"
    out = run(db, "findings-page", "--project", "web", "--fingerprint", "abc123def456")
    assert out["rows"] == []
    assert out["total"] == 0


def test_activity_data_paginates_with_page_and_per_page(tmp_path):
    db = tmp_path / "security.db"
    for i in range(3):
        run(db, "event", "--project", "web", "--kind", "analysis_started",
            "--detail", f"run {i}")
    page1 = run(db, "activity-data", "--since", "0", "--page", "1", "--per-page", "2")
    page2 = run(db, "activity-data", "--since", "0", "--page", "2", "--per-page", "2")
    assert len(page1["events"]) == 2
    assert len(page2["events"]) == 1
    assert page1["page"] == 1 and page2["page"] == 2
    ids = {e["detail"] for e in page1["events"]} | {e["detail"] for e in page2["events"]}
    assert ids == {"run 0", "run 1", "run 2"}


def test_activity_data_since_zero_summarises_the_whole_history(tmp_path):
    """A bare `--since 0` (no lower bound, `ledger.events_for`'s own default)
    only reaches this verb from a direct command-line call -- the server
    always resolves a real timestamp first. The summary must still answer
    with a real count rather than a day window that excludes an event
    recorded a moment ago."""
    db = tmp_path / "security.db"
    run(db, "event", "--project", "web", "--kind", "report_exported")
    out = run(db, "activity-data", "--since", "0")
    assert out["summary"]["report_exported"] == 1


def test_activity_data_events_carry_no_user_or_ip_field(tmp_path):
    db = tmp_path / "security.db"
    run(db, "event", "--project", "web", "--kind", "settings_changed")
    out = run(db, "activity-data", "--since", "0")
    assert "user" not in out["events"][0]
    assert "ip" not in out["events"][0]


# -------------------------------------------- a ledger hiccup is never fatal

def test_open_analysis_survives_a_ledger_write_failure(tmp_path, monkeypatch, capsys):
    """Reproduced before the guard: `record_event` used to run unguarded in
    `cmd_open_analysis`. The kind passed there is a literal, so `ValueError`
    can never fire -- but the INSERT can still raise `sqlite3.OperationalError`
    (`security.db` is shared across every project, and `connect()` takes the
    default 5s busy timeout), and `main()` has no top-level guard, so that
    propagated as a traceback with NO stdout. The `running` row above is
    already committed by the time it happens, so the worst case was real:
    `cmd_security_analyze`'s `| jq -r '.analysis_id'` read empty, `aid` became
    "", and `security analyze` died with "could not open an analysis" while
    the ledger held an orphaned `running` row for an analysis that, in fact,
    had opened.

    Driven in-process (not via the `run`/`fails` subprocess helpers) because
    the point is to monkeypatch `record_event` mid-call, which a subprocess
    boundary cannot see."""
    db = tmp_path / "security.db"

    def boom(*_a, **_kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(security_ledger, "record_event", boom)
    security_cli.main([
        "open-analysis", "--project", "web", "--repo", "web", "--branch", "main",
        "--commit", "a", "--profile", "quick", "--run-id", "r", "--db", str(db)])
    printed = json.loads(capsys.readouterr().out)
    assert printed["analysis_id"] == 1
    # Not merely the printed id: the row itself is real, checked over a fresh
    # subprocess so the still-broken monkeypatch above cannot mask a failure.
    row = run(db, "list", "--project", "web")[0]
    assert row["id"] == 1
    assert row["state"] == "running"


def test_finish_survives_a_ledger_write_failure(tmp_path, monkeypatch):
    """Same failure, second call site: `finish_analysis` above already closed
    the row with its real verdict and spend when `record_event` raises, and
    that close must not be undone by a hiccup recording it happened."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)

    def boom(*_a, **_kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(security_ledger, "record_event", boom)
    security_cli.main(["finish", "--analysis", str(aid), "--state", "done",
                       "--spend", "1.5", "--db", str(db)])
    row = run(db, "list", "--project", "web")[0]
    assert row["state"] == "done"
    assert row["spend_usd"] == 1.5


def test_decide_survives_a_ledger_write_failure(tmp_path, monkeypatch):
    """Third call site: the decision itself is the thing that must survive a
    ledger hiccup recording it -- a suppression that silently failed to save
    because its OWN audit trail could not be written would be worse than one
    that saved and went unrecorded."""
    db = tmp_path / "security.db"
    run(db, "finish", "--analysis", str(open_analysis(db)), "--state", "done")

    def boom(*_a, **_kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(security_ledger, "record_event", boom)
    security_cli.main(["decide", "--project", "web", "--fingerprint", "a" * 64,
                       "--state", "accepted", "--reason", "reviewed",
                       "--by", "luiz", "--db", str(db)])
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT state FROM decision WHERE fingerprint=?",
                        ("a" * 64,)).fetchone()[0] == "accepted"


# ------------------------------------------- the agent cannot forge an event

def test_the_agent_cannot_write_an_event_by_hand(tmp_path):
    """`event` is the standalone write into the one record of what actually
    happened. Both audit-worthy things the agent causes are already filed as
    side effects -- `analysis_started` by `open-analysis` (which it cannot
    call) and `analysis_finished` by `finish` (which files the event itself)
    -- so the agent has no legitimate use for this verb, while a forged
    `settings_changed` or `decision_made` would corrupt the ledger's own
    audit trail."""
    db = tmp_path / "security.db"
    # open_analysis's own analysis_started already puts one row in `event`,
    # so the assertion below is a before/after count, not "the table is
    # empty" -- otherwise this test would fail for a reason that has nothing
    # to do with the refusal it names.
    open_analysis(db)
    conn = sqlite3.connect(str(db))
    before = conn.execute("SELECT count(*) FROM event").fetchone()[0]
    out = fails(db, "event", "--project", "web", "--kind", "settings_changed",
                "--detail", "forged", env=AS_AGENT)
    assert out.returncode != 0
    assert "CC_SECURITY_AGENT" in out.stderr
    assert conn.execute("SELECT count(*) FROM event").fetchone()[0] == before


def test_the_agent_can_still_read_events(tmp_path):
    """`events` is read-only and stays allowed under the flag -- the control
    for the refusal above: there is nothing here for CC_SECURITY_AGENT to
    protect, only a query the agent may legitimately want to see."""
    db = tmp_path / "security.db"
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "reviewed")
    out = run(db, "events", "--project", "web", env=AS_AGENT)
    assert any(e["kind"] == "decision_made" for e in out)


# --------------------------------------------- the analysis verb: one row only

def test_analysis_prints_the_row_and_nothing_else(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db, project="web", commit="a", run_id="r")
    row = run(db, "analysis", "--id", str(aid))
    assert row["id"] == aid
    assert row["project"] == "web"
    assert row["state"] == "running"


def test_analysis_refuses_an_unknown_id(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "analysis", "--id", "999")
    assert out.returncode != 0
    assert "999" in out.stderr


def test_analysis_is_allowed_under_the_agent_environment(tmp_path):
    """Read-only, like `findings`, `list` and `checklist`: nothing here for
    CC_SECURITY_AGENT to protect."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    row = run(db, "analysis", "--id", str(aid), env=AS_AGENT)
    assert row["id"] == aid


# ------------------------------------------------------------ saved filters

def test_filters_save_then_list_round_trips(tmp_path):
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "criticals only",
        stdin=json.dumps({"severity": "critical"}))
    got = run(db, "filters", "list", "--project", "web")
    assert len(got) == 1
    assert got[0]["name"] == "criticals only"
    assert got[0]["query"] == {"severity": "critical"}


def test_filters_save_replaces_a_filter_of_the_same_name(tmp_path):
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "mine",
        stdin=json.dumps({"severity": "critical"}))
    run(db, "filters", "save", "--project", "web", "--name", "mine",
        stdin=json.dumps({"severity": "high"}))
    got = run(db, "filters", "list", "--project", "web")
    assert len(got) == 1
    assert got[0]["query"] == {"severity": "high"}


def test_filters_list_is_scoped_to_its_project(tmp_path):
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "mine",
        stdin=json.dumps({"severity": "critical"}))
    assert run(db, "filters", "list", "--project", "other") == []


def test_filters_delete_reports_whether_it_existed(tmp_path):
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "mine",
        stdin=json.dumps({}))
    assert run(db, "filters", "delete", "--project", "web",
              "--name", "mine")["deleted"] is True
    assert run(db, "filters", "delete", "--project", "web",
              "--name", "mine")["deleted"] is False


def test_filters_save_refuses_a_blank_name(tmp_path):
    db = tmp_path / "security.db"
    out = fails(db, "filters", "save", "--project", "web", "--name", "   ",
                stdin=json.dumps({}))
    assert out.returncode != 0
    assert "name" in out.stderr


def test_filters_save_refuses_stdin_that_is_not_json(tmp_path):
    db = tmp_path / "security.db"
    out = fails(db, "filters", "save", "--project", "web", "--name", "mine",
                stdin="not json")
    assert out.returncode != 0
    assert "JSON" in out.stderr


def test_filters_save_accepts_a_name_of_exactly_80_characters(tmp_path):
    db = tmp_path / "security.db"
    name = "x" * 80
    run(db, "filters", "save", "--project", "web", "--name", name,
        stdin=json.dumps({}))
    got = run(db, "filters", "list", "--project", "web")
    assert got[0]["name"] == name


def test_filters_save_refuses_a_name_over_80_characters(tmp_path):
    """The root-cause fix: `save_filter` used to truncate a name over 80
    characters to `name[:80]` before the primary key ever saw it, so a name
    this long could be saved but never deleted by what the user actually
    typed. It is now refused outright, naming the limit."""
    db = tmp_path / "security.db"
    out = fails(db, "filters", "save", "--project", "web", "--name", "x" * 81,
                stdin=json.dumps({}))
    assert out.returncode != 0
    assert "80" in out.stderr
    assert run(db, "filters", "list", "--project", "web") == []


def test_filters_save_refuses_json_that_is_not_an_object(tmp_path):
    """`cmd_filters` used to catch only a parse error, never the shape --
    unlike `report-finding`'s `isinstance(payload, dict)` check. A number, a
    bare list, `null` and a string all parse as valid JSON and would have
    been stored as `query` untouched, which the page's filter-spreading logic
    would then choke on."""
    db = tmp_path / "security.db"
    for bad in ("5", "null", "[1, 2]", '"just a string"'):
        out = fails(db, "filters", "save", "--project", "web", "--name", "mine",
                    stdin=bad)
        assert out.returncode != 0, bad
        assert "JSON object" in out.stderr, bad
    assert run(db, "filters", "list", "--project", "web") == []


# ------------------------ the agent works from its own view, never edits it

def test_the_agent_cannot_save_a_filter(tmp_path):
    """A saved filter is a working set a human curates -- not something an
    analysis decides to leave behind for whoever opens the page next."""
    db = tmp_path / "security.db"
    out = fails(db, "filters", "save", "--project", "web", "--name", "mine",
                stdin=json.dumps({"severity": "critical"}), env=AS_AGENT)
    assert out.returncode != 0
    assert "CC_SECURITY_AGENT" in out.stderr
    assert run(db, "filters", "list", "--project", "web") == []


def test_the_agent_cannot_delete_a_filter(tmp_path):
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "mine",
        stdin=json.dumps({}))
    out = fails(db, "filters", "delete", "--project", "web", "--name", "mine",
                env=AS_AGENT)
    assert out.returncode != 0
    assert "CC_SECURITY_AGENT" in out.stderr
    assert len(run(db, "filters", "list", "--project", "web")) == 1


def test_the_agent_can_still_list_filters(tmp_path):
    """`filters list` is read-only, the same reasoning that keeps `findings`,
    `events` and `analysis` open under the flag -- there is nothing here for
    CC_SECURITY_AGENT to protect, only a view the agent may legitimately
    want."""
    db = tmp_path / "security.db"
    run(db, "filters", "save", "--project", "web", "--name", "mine",
        stdin=json.dumps({"severity": "high"}))
    got = run(db, "filters", "list", "--project", "web", env=AS_AGENT)
    assert got[0]["name"] == "mine"


# ------------------------------------------------ the dispatch generalises

def test_main_computes_the_agent_key_with_no_hardcoded_special_case():
    """The whole point of moving `filters` to `dest="action"` (see
    AGENT_FORBIDDEN's docstring and `main`'s dispatch key) is that the NEXT
    nested verb following the same convention needs no code change here --
    only a tuple entry. A structural assertion, not a behavioural one: it is
    what stops a future edit from reintroducing `if key == "filters"` (or any
    other verb) as a one-off special case that the next nested verb then
    silently fails to get, exactly the failure mode the reviewer named.
    """
    src = inspect.getsource(security_cli.main)
    assert 'if key == "' not in src
    assert "args.filters_action" not in src


# ------------------------------------------------------------ the index screen

def finished_analysis(db, tmp_path, project, branch, severity="high", rule="r",
                      category="hygiene"):
    """A `done` analysis of `project`/`branch` carrying one reported finding.

    `category` defaults to a deterministic one, not `sast` -- most callers
    pass an opaque placeholder `rule` that means nothing beyond "some rule
    string", and the closed SAST vocabulary would refuse it. A caller that
    wants a real SAST rule (to exercise the classification it derives) passes
    `category="sast"` together with a rule the vocabulary actually has.

    Uses `prepared_analysis` so `finish --state done` is not silently
    downgraded to `capped` (see `cmd_finish`) -- a test about current posture
    has to start from a row the close actually accepted as done."""
    aid = prepared_analysis(db, tmp_path, project=project, repo=project, branch=branch)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": fingerprint_for(project, branch, rule), "category": category,
        "rule": rule, "severity": severity, "title": "t", "rationale": "r"}))
    run(db, "finish", "--analysis", str(aid), "--state", "done", "--spend", "0.5")
    return aid


def capped_analysis(db, tmp_path, project, branch, severity="high", rule="r",
                    category="hygiene"):
    """A `capped` analysis of `project`/`branch` -- it stopped before covering
    its whole scope, carrying one reported finding from before it stopped.

    Uses `prepared_analysis` for the same reason `finished_analysis` does --
    `finish --state capped` is the agent's own honest statement that it ran
    out of room, not a downgrade `cmd_finish` applies on its behalf, and a
    test about how the index screen treats this state has to start from a
    row that really carries it."""
    aid = prepared_analysis(db, tmp_path, project=project, repo=project, branch=branch)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": fingerprint_for(project, branch, rule), "category": category,
        "rule": rule, "severity": severity, "title": "t", "rationale": "r"}))
    run(db, "finish", "--analysis", str(aid), "--state", "capped", "--spend", "0.3")
    return aid


def fingerprint_for(*parts):
    return compute_fingerprint("sast", "-".join(parts), "app.py", "")


def test_index_data_survives_a_ledger_that_does_not_exist_yet(tmp_path):
    """Nobody has run an analysis of anything -- `index-data` must not create
    the ledger file just to answer the index screen, and the screen it hands
    back is empty with a sentence, not a 500."""
    db = tmp_path / "security.db"
    assert not db.exists()
    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": "d"}]))
    assert not db.exists()
    assert out["summary"] == {"projects": 1, "analyses": 0, "critical": 0,
                              "high": 0, "capped_projects": 0,
                              "fell_back_projects": 0, "success_rate": None}
    assert out["projects"] == [{
        "name": "web", "description": "d", "branch": "main",
        "branch_fell_back": False,
        "posture": {"critical": 0, "high": 0, "medium": 0, "low": 0,
                    "info": 0, "total": 0},
        "profile": "", "last_started": 0, "last_duration": 0, "last_state": "",
        "analyses": 0, "trend": []}]
    assert out["recent"] == {"rows": [], "total": 0}
    assert out["donut"] == {"critical": 0, "high": 0, "medium": 0, "low": 0,
                            "info": 0, "total": 0}
    assert out["categories"] == []


def test_index_data_reports_current_posture_for_the_projects_given(tmp_path):
    db = tmp_path / "security.db"
    aid = finished_analysis(db, tmp_path, "web", "main", severity="high",
                            rule="sql-injection", category="sast")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": "d"}]))

    assert out["summary"] == {"projects": 1, "analyses": 1, "critical": 0,
                              "high": 1, "capped_projects": 0,
                              "fell_back_projects": 0, "success_rate": 1.0}
    row = out["projects"][0]
    assert row["name"] == "web"
    assert row["branch"] == "main"
    assert row["branch_fell_back"] is False
    assert row["posture"]["high"] == 1
    assert row["analyses"] == 1
    assert [r["id"] for r in out["recent"]["rows"]] == [aid]
    assert out["recent"]["total"] == 1
    assert out["recent"]["rows"][0]["open"] == 1
    assert out["recent"]["rows"][0]["severities"] == \
        {"critical": 0, "high": 1, "medium": 0}
    assert out["donut"]["high"] == 1
    assert out["donut"]["total"] == 1
    assert out["categories"] == [{"rule": "sql-injection", "count": 1, "category": "sast"}]


def test_index_data_shows_the_branch_it_fell_back_to(tmp_path):
    """The project's declared base (`main`) was never analysed -- only
    `develop` was. The row must carry `develop`, the branch it actually
    fell back to, and say so, rather than silently showing one branch's
    posture as if it belonged to another."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "develop", severity="critical")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]))

    row = out["projects"][0]
    assert row["branch"] == "develop"
    assert row["branch_fell_back"] is True
    assert row["posture"]["critical"] == 1
    # The declared base (`main`) has no history of its own -- the sparkline
    # has no cell to say "fell back to develop" the way this row's own
    # `branch_fell_back` does for its posture, so it shows nothing rather
    # than silently plot `develop`'s history under `main`'s name.
    assert row["trend"] == []


def test_index_data_marks_a_project_row_whose_latest_analysis_is_capped(tmp_path):
    """A capped analysis is a PARTIAL read of the repository -- the identical
    notice `secPaint` already gives on the analysis screen ("critical: 0"
    there means "none found before it stopped," not "none"). The index
    screen used to render that posture with no cue at all, because the row
    data it painted from never carried the state to begin with -- this is
    that data-layer half; the rendering half lives in
    tests/test_page_contract.py."""
    db = tmp_path / "security.db"
    capped_analysis(db, tmp_path, "web", "main", severity="critical")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]))

    row = out["projects"][0]
    assert row["last_state"] == "capped", f"row does not carry the capped state: {row}"
    assert row["posture"]["critical"] == 1
    assert out["summary"]["capped_projects"] == 1, \
        "the KPI cards' contributing-project count did not see the capped analysis"


def test_index_data_summary_is_scoped_to_the_projects_given(tmp_path):
    """Two projects have analyses in the ledger, but only one is passed in
    `--projects` -- every panel must count only that one, not everything the
    ledger has ever recorded (see queries.index_summary's own docstring).

    `donut`, `categories` and `recent` used to be the three panels left
    reading the WHOLE ledger while `summary`/`projects` were already scoped:
    `gone`'s critical finding, on a distinct rule, surfaced in all three even
    though the other half of this very screen already says `gone` does not
    exist. This fixture was already exactly the one that would catch that --
    it only ever asserted on `summary`."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="high")
    aid_gone = finished_analysis(db, tmp_path, "gone", "main", severity="critical",
                                 rule="hardcoded-secret")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]))

    assert out["summary"]["projects"] == 1
    assert out["summary"]["analyses"] == 1
    assert out["summary"]["critical"] == 0
    assert out["summary"]["high"] == 1
    assert [p["name"] for p in out["projects"]] == ["web"]
    assert out["donut"]["critical"] == 0, "gone's critical finding leaked into the donut"
    assert out["donut"]["high"] == 1
    assert [c["rule"] for c in out["categories"]] == ["r"], \
        "gone's rule leaked into the category rollup: " + repr(out["categories"])
    assert aid_gone not in [a["id"] for a in out["recent"]["rows"]], \
        "gone's analysis leaked into the recent-analyses feed"


def test_index_data_days_narrows_the_donut_and_categories(tmp_path):
    """`--days` (default 30 when omitted) reaches `queries.severity_totals`/
    `top_categories` for real now -- see those functions' own docstrings.
    An analysis backdated to 60 days ago must vanish from a narrower window
    and reappear once the window widens back past it, proving the CLI flag
    is actually wired through rather than accepted and dropped."""
    db = tmp_path / "security.db"
    aid = finished_analysis(db, tmp_path, "web", "main", severity="critical",
                            rule="hardcoded-credentials", category="sast")
    conn = sqlite3.connect(str(db))
    sixty_days_ago = int(time.time()) - 60 * 86400
    conn.execute("UPDATE analysis SET started=?, ended=? WHERE id=?",
                 (sixty_days_ago, sixty_days_ago, aid))
    conn.commit()
    conn.close()

    narrow = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]), "--days", "30")
    wide = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]), "--days", "90")

    assert narrow["donut"]["critical"] == 0, \
        "a 30-day window must not see an analysis 60 days old"
    assert narrow["categories"] == []
    assert wide["donut"]["critical"] == 1, \
        "widening past the analysis's own age must restore it"
    assert wide["categories"] == [{"rule": "hardcoded-credentials", "count": 1, "category": "sast"}]


def test_index_data_recent_page_pages_server_side_with_a_true_total(tmp_path):
    """`--recent-page` (default 1) pages `recent_analyses` in the database
    itself -- see that function's own docstring for why. Seven analyses,
    five per page: page 1 carries the five newest, page 2 carries the
    remaining two, and `total` says 7 on both pages."""
    db = tmp_path / "security.db"
    ids = [finished_analysis(db, tmp_path, "web", "main") for _ in range(7)]
    newest_first = list(reversed(ids))

    page1 = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]), "--recent-page", "1")
    page2 = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]), "--recent-page", "2")

    assert [r["id"] for r in page1["recent"]["rows"]] == newest_first[0:5]
    assert page1["recent"]["total"] == 7
    assert [r["id"] for r in page2["recent"]["rows"]] == newest_first[5:7]
    assert page2["recent"]["total"] == 7


def test_index_data_refuses_projects_that_is_not_json(tmp_path):
    db = tmp_path / "security.db"
    out = fails(db, "index-data", "--projects", "not json")
    assert out.returncode != 0
    assert "JSON" in out.stderr


def test_index_data_refuses_projects_that_is_not_a_list_of_objects(tmp_path):
    db = tmp_path / "security.db"
    for bad in ("5", "null", '"just a string"', "[1, 2]"):
        out = fails(db, "index-data", "--projects", bad)
        assert out.returncode != 0, bad
        assert "--projects" in out.stderr, bad


def test_index_data_is_read_only_and_reachable_by_the_agent(tmp_path):
    """Not in AGENT_FORBIDDEN -- the same reasoning as `findings`, `list`,
    `analysis` and `checklist`: it opens the ledger read-only and writes
    nothing, so there is nothing here for CC_SECURITY_AGENT to guard."""
    db = tmp_path / "security.db"
    out = run(db, "index-data", "--projects", "[]", env=AS_AGENT)
    assert out["summary"]["projects"] == 0


# ---------------------------------------------------------- project-data

def test_project_data_survives_a_ledger_that_does_not_exist_yet(tmp_path):
    """Nobody has run an analysis of anything -- `project-data` must not
    create the ledger file just to answer the project screen, and the screen
    it hands back is empty with a sentence, not a 500."""
    db = tmp_path / "security.db"
    assert not db.exists()
    out = run(db, "project-data", "--project", "web", "--base", "main",
             "--default-profile", "deep")
    assert not db.exists()
    assert out["project"] == "web"
    assert out["header"] == {"profile": "deep", "branch": "main",
                             "branch_fell_back": False, "lines_of_code": 0,
                             "last_analysis": 0}
    assert out["tabs"]["overview"]["posture"] == {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    assert out["tabs"]["overview"]["state"] == ""
    assert out["tabs"]["overview"]["attempted"] is False, \
        "nothing has ever been analysed -- attempted must be false, not just state==''"
    assert out["tabs"]["runs"] == []
    assert out["tabs"]["branches"] == []
    assert out["tabs"]["reports"] == []
    assert out["sidebar"]["donut"]["total"] == 0
    assert out["sidebar"]["categories"] == []
    assert out["sidebar"]["activity"] == []
    assert out["sidebar"]["branch_count"] == 0


def test_project_data_defaults_the_profile_when_none_is_declared(tmp_path):
    db = tmp_path / "security.db"
    out = run(db, "project-data", "--project", "web", "--base", "", "--default-profile", "")
    assert out["header"]["profile"] == "standard"
    assert out["header"]["branch"] == ""


def test_project_data_reports_current_posture_and_checklist_counts(tmp_path):
    db = tmp_path / "security.db"
    aid = finished_analysis(db, tmp_path, "web", "main", severity="high",
                            rule="sql-injection", category="sast")

    out = run(db, "project-data", "--project", "web", "--base", "main",
             "--default-profile", "standard")

    assert out["header"]["branch"] == "main"
    assert out["header"]["branch_fell_back"] is False
    assert out["header"]["last_analysis"] > 0
    assert out["tabs"]["overview"]["posture"]["high"] == 1
    assert out["tabs"]["overview"]["state"] == "done"
    # First analysis of this branch: nothing to compare against, so the one
    # finding it reported is "new" and every other state is empty.
    assert out["tabs"]["overview"]["checklist"]["new"] == 1
    assert sum(out["tabs"]["overview"]["checklist"].values()) == 1
    assert [r["id"] for r in out["tabs"]["runs"]] == [aid]
    assert out["tabs"]["runs"][0]["findings"] == 1
    assert out["sidebar"]["donut"]["high"] == 1
    assert out["sidebar"]["categories"] == [{"rule": "sql-injection", "count": 1, "category": "sast"}]
    assert out["sidebar"]["branch_count"] == 1
    assert out["tabs"]["overview"]["attempted"] is True


def test_project_data_lines_of_code_is_a_property_of_the_latest_analysis(tmp_path):
    """Every analysis before the column existed carries 0 -- the CLI hands
    that raw number back untouched; the dash for "not counted" is the page's
    own call (see ui/security/project-screen.js), not this verb's."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main")
    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")
    assert out["header"]["lines_of_code"] == 0


def test_project_data_shows_the_branch_it_fell_back_to(tmp_path):
    """The project's declared base (`main`) was never analysed -- only
    `develop` was. The header must carry `develop`, the branch it actually
    fell back to, and say so."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "develop", severity="critical")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert out["header"]["branch"] == "develop"
    assert out["header"]["branch_fell_back"] is True
    assert out["tabs"]["overview"]["posture"]["critical"] == 1


def test_project_data_marks_the_overview_state_when_latest_analysis_is_capped(tmp_path):
    """A capped analysis is a PARTIAL read of the repository -- the identical
    notice the index screen and the old analysis screen already give. The
    Overview tab has to carry the state so the screen can show the same cue,
    not silently present a partial posture as a finished one."""
    db = tmp_path / "security.db"
    capped_analysis(db, tmp_path, "web", "main", severity="critical")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert out["tabs"]["overview"]["state"] == "capped"
    assert out["tabs"]["overview"]["posture"]["critical"] == 1


def test_project_data_serves_the_overview_cards_beyond_the_posture(tmp_path):
    """ProjectOverview.png's own cards ride the same payload: `trend` (last
    7 days of the SHOWN branch, one point per finished analysis, each with a
    per-severity breakdown), `categories` and `top_findings` (projections of
    the SAME checklist `posture` reads -- one branch, one scope, so the KPI
    total, the donut centre and the Top findings rows can never disagree),
    and `previous` (the posture one finished analysis earlier)."""
    db = tmp_path / "security.db"
    aid1 = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main")
    run(db, "report-finding", "--analysis", str(aid1), stdin=json.dumps({
        "fingerprint": fingerprint_for("web", "main", "leak"), "category": "secret",
        "rule": "private-key-committed", "severity": "high", "title": "Key leak",
        "rationale": "r",
        "occurrences": [{"file": "conf/id_rsa", "line": 1, "snippet_hash": "h"}]}))
    run(db, "finish", "--analysis", str(aid1), "--state", "done", "--spend", "0.1")

    aid2 = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main")
    run(db, "report-finding", "--analysis", str(aid2), stdin=json.dumps({
        "fingerprint": fingerprint_for("web", "main", "leak"), "category": "secret",
        "rule": "private-key-committed", "severity": "high", "title": "Key leak",
        "rationale": "r",
        "occurrences": [{"file": "conf/id_rsa", "line": 1, "snippet_hash": "h"}]}))
    run(db, "report-finding", "--analysis", str(aid2), stdin=json.dumps({
        "fingerprint": fingerprint_for("web", "main", "sqli"), "category": "sast",
        "rule": "sql-injection", "severity": "critical", "title": "SQL injection",
        "rationale": "r",
        "occurrences": [{"file": "app/db.py", "line": 40, "snippet_hash": "h"},
                        {"file": "app/api.py", "line": 7, "snippet_hash": "h"}]}))
    run(db, "finish", "--analysis", str(aid2), "--state", "done", "--spend", "0.1")

    out = run(db, "project-data", "--project", "web", "--base", "main",
             "--default-profile", "")
    ov = out["tabs"]["overview"]

    # trend: one point per finished analysis, oldest first, each carrying the
    # per-severity split of its own open count.
    assert [p["analysis_id"] for p in ov["trend"]] == [aid1, aid2]
    assert ov["trend"][0]["open"] == 1
    assert ov["trend"][1]["open"] == 2
    assert ov["trend"][1]["by_severity"]["critical"] == 1
    assert ov["trend"][1]["by_severity"]["high"] == 1
    assert sum(ov["trend"][1]["by_severity"].values()) == ov["trend"][1]["open"]

    # previous: the posture as of aid1 -- the high alone.
    assert ov["previous"]["total"] == 1
    assert ov["previous"]["high"] == 1
    assert ov["previous"]["critical"] == 0

    # categories: rule buckets of the CURRENT checklist's open findings.
    assert {c["rule"]: c["count"] for c in ov["categories"]} == {
        "private-key-committed": 1, "sql-injection": 1}

    # top findings: severity rank first (critical before high), each row
    # carrying the fields the card renders -- location from the first
    # occurrence, a count of the rest, the attesting analysis and first_seen.
    assert [f["rule"] for f in ov["top_findings"]] == [
        "sql-injection", "private-key-committed"]
    sqli = ov["top_findings"][0]
    assert sqli["file"] == "app/db.py" and sqli["line"] == 40 and sqli["more"] == 1
    assert sqli["analysis_id"] == aid2
    assert sqli["first_seen"] > 0
    # The high was first seen by aid1 even though aid2 is what attests it now.
    leak = ov["top_findings"][1]
    assert leak["analysis_id"] == aid2
    listed = run(db, "list", "--project", "web")
    aid1_started = next(r["started"] for r in listed if r["id"] == aid1)
    assert leak["first_seen"] == aid1_started


def test_project_data_previous_is_none_not_zeros_without_a_prior_analysis(tmp_path):
    """One finished analysis: there is nothing to compare against, and the
    page must be able to say "no previous analysis" -- a zero-filled posture
    here would render as a 0% delta that no comparison ever produced."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="critical")
    out = run(db, "project-data", "--project", "web", "--base", "main",
             "--default-profile", "")
    assert out["tabs"]["overview"]["previous"] is None
    assert out["tabs"]["overview"]["trend"] != []


def test_project_data_overview_cards_follow_the_fallen_back_branch(tmp_path):
    """The trend/categories/top_findings scope is the SHOWN branch -- the
    one the header names, fallen back or not -- unlike the index sparkline
    (`trend_series`), which never falls back because it has nowhere to say
    so. This screen does say so (the header's own fell-back chip), so its
    cards follow it rather than rendering empty beside a posture that did."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "develop", severity="critical",
                      rule="sql-injection")
    out = run(db, "project-data", "--project", "web", "--base", "main",
             "--default-profile", "")
    assert out["header"]["branch_fell_back"] is True
    ov = out["tabs"]["overview"]
    assert len(ov["trend"]) == 1 and ov["trend"][0]["open"] == 1
    assert ov["categories"][0]["rule"] == "sql-injection"
    assert ov["top_findings"][0]["severity"] == "critical"


def test_project_data_runs_tab_matches_the_list_verb(tmp_path):
    """The Runs tab is `cmd_list`'s own query -- same rows, same order --
    plus a `findings` count folded in, so it can be checked directly against
    `claude-cron security list --project <name>`."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", rule="a")
    open_analysis(db, project="web", repo="web", branch="develop", run_id="r2")

    listed = run(db, "list", "--project", "web")
    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert [r["id"] for r in out["tabs"]["runs"]] == [r["id"] for r in listed]
    assert [r["state"] for r in out["tabs"]["runs"]] == [r["state"] for r in listed]
    # The running row (no finished baseline) reports no findings count yet.
    running = next(r for r in out["tabs"]["runs"] if r["state"] == "running")
    assert running["findings"] is None


def test_project_data_sidebar_activity_carries_the_projects_own_events(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db, project="web", repo="web", branch="main", run_id="r1")
    run(db, "event", "--project", "web", "--kind", "decision_made",
        "--detail", "accepted: reviewed", "--related", "abc")
    run(db, "event", "--project", "other", "--kind", "decision_made",
        "--detail", "accepted: unrelated", "--related", "xyz")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    kinds = [e["kind"] for e in out["sidebar"]["activity"]]
    details = [e["detail"] for e in out["sidebar"]["activity"]]
    assert "analysis_started" in kinds
    assert "decision_made" in kinds
    assert "accepted: unrelated" not in details, "another project's event leaked into the sidebar"


def test_project_data_is_read_only_and_reachable_by_the_agent(tmp_path):
    """Not in AGENT_FORBIDDEN -- the same reasoning as `index-data`: it opens
    the ledger read-only through `queries.read_only` and writes nothing."""
    db = tmp_path / "security.db"
    out = run(db, "project-data", "--project", "web", "--base", "", "--default-profile", "",
             env=AS_AGENT)
    assert out["project"] == "web"


# ---- review fix: two different "posture" numbers on one screen, with
# nothing saying why they differ. The Overview posture is ONE branch
# (default_branch_posture's own choice); the sidebar donut/categories span
# EVERY analysed branch. `branch_count` is the number the sidebar's own
# caption names.

def test_project_data_sidebar_names_how_many_branches_it_spans(tmp_path):
    """A two-branch project: the Overview posture (main) and the sidebar
    donut (both branches) are DIFFERENT, equally true totals -- this asserts
    the number that lets the page say so, rather than the two panels
    disagreeing with nothing on screen explaining why."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="critical", rule="a")
    finished_analysis(db, tmp_path, "web", "develop", severity="low", rule="b")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert out["header"]["branch"] == "main"
    assert out["tabs"]["overview"]["posture"] == {
        "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1}
    assert out["sidebar"]["donut"] == {
        "critical": 1, "high": 0, "medium": 0, "low": 1, "info": 0, "total": 2}
    assert out["sidebar"]["branch_count"] == 2


def test_project_data_sidebar_branch_count_is_one_for_a_single_branch_project(tmp_path):
    """Containment probe: a project with only one analysed branch must not
    report a count that could be misread as spanning more than it does."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="high", rule="a")
    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")
    assert out["sidebar"]["branch_count"] == 1


# ---- review fix: the Runs table's FINDINGS column used to cost one
# checklist() call per done/capped row (findings_of x2, a history scan,
# decisions_for) -- scaling with total findings across every historical
# analysis. It is now a plain COUNT(*), grouped once for the whole project
# (queries.finding_counts_by_analysis) -- which also means the number is no
# longer filtered by is_open, only by what the ledger actually recorded.

def test_project_data_findings_count_is_a_raw_total_not_an_open_filter(tmp_path):
    """Before this fix, the Runs tab's count came from checklist()'s
    is_open filter -- so accepting a finding's risk made an already-closed
    analysis's own historical row silently shrink its findings count, even
    though nothing about what that run recorded had changed. FAILS before
    the fix (the old `open` computation drops to 0 once the decision is
    recorded) and PASSES after (a plain COUNT(*) never moves)."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="high", rule="r")

    before = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")
    assert before["tabs"]["runs"][0]["findings"] == 1

    fp = fingerprint_for("web", "main", "r")
    run(db, "decide", "--project", "web", "--fingerprint", fp,
        "--state", "accepted", "--reason", "risk accepted")

    after = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")
    assert after["tabs"]["runs"][0]["findings"] == 1, \
        "the run's own findings count must not shrink because a later decision accepted it"
    # The Overview's checklist counts, by contrast, DO move -- proving this
    # is a deliberate split (findings vs. current posture), not a broken
    # decision flow.
    assert after["tabs"]["overview"]["checklist"]["accepted"] == 1


def test_project_data_runs_findings_count_is_per_analysis_not_shared(tmp_path):
    """Two separate done analyses of the SAME branch, each with its own
    findings recorded directly against its own row -- `findings` must be
    each analysis's OWN count, not the grouped query bleeding a later
    analysis's rows into an earlier one's total."""
    db = tmp_path / "security.db"
    a1 = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main", run_id="r1")
    run(db, "report-finding", "--analysis", str(a1), stdin=json.dumps({
        "fingerprint": fingerprint_for("web", "main", "r1a"), "category": "hygiene",
        "rule": "r1a", "severity": "high", "title": "t"}))
    run(db, "report-finding", "--analysis", str(a1), stdin=json.dumps({
        "fingerprint": fingerprint_for("web", "main", "r1b"), "category": "hygiene",
        "rule": "r1b", "severity": "low", "title": "t"}))
    run(db, "finish", "--analysis", str(a1), "--state", "done")

    a2 = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main", run_id="r2")
    run(db, "report-finding", "--analysis", str(a2), stdin=json.dumps({
        "fingerprint": fingerprint_for("web", "main", "r1a"), "category": "hygiene",
        "rule": "r1a", "severity": "high", "title": "t"}))
    run(db, "finish", "--analysis", str(a2), "--state", "done")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")
    by_id = {r["id"]: r["findings"] for r in out["tabs"]["runs"]}
    assert by_id[a1] == 2, f"a1 recorded 2 findings: {by_id}"
    assert by_id[a2] == 1, f"a2 recorded 1 finding (r1b was fixed): {by_id}"

    # The Runs tab's own per-severity sub-line rides on the same rows, gated
    # the same way, and sums back to the plain total above -- see
    # queries.finding_severity_by_analysis's own docstring for why this is a
    # second field, not a reshape of `findings`.
    by_sev = {r["id"]: r["findings_by_severity"] for r in out["tabs"]["runs"]}
    assert by_sev[a1] == {"high": 1, "low": 1}, by_sev
    assert by_sev[a2] == {"high": 1}, by_sev
    assert sum(by_sev[a1].values()) == by_id[a1]
    assert sum(by_sev[a2].values()) == by_id[a2]


def test_project_data_runs_findings_by_severity_is_null_for_an_unfinished_analysis(tmp_path):
    """The breakdown must not look like a real (empty) answer for a run that
    has not finished recording findings yet -- the same `None`, not `{}`,
    gate `findings` itself already uses."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main")
    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")
    row = next(r for r in out["tabs"]["runs"] if r["id"] == aid)
    assert row["findings"] is None
    assert row["findings_by_severity"] is None, \
        "a running analysis must not report a (misleadingly empty) breakdown"


# ---- review fix (MINOR): "Never analysed" was shown to a project whose
# analyses all failed, even though its own Runs tab plainly lists the
# attempts. `attempted` distinguishes never-attempted from
# attempted-and-never-finished; `header.last_analysis` falls back to the
# most recent attempt of any state when there is no finished baseline.

def test_project_data_marks_a_project_as_attempted_when_every_analysis_failed(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db, project="web", repo="web", branch="main", run_id="r1")
    run(db, "finish", "--analysis", str(aid), "--state", "failed")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert out["tabs"]["overview"]["state"] == "", \
        "no finished analysis exists -- state must stay empty"
    assert out["tabs"]["overview"]["attempted"] is True, \
        "a failed analysis is still an attempt, not silence"
    assert out["header"]["last_analysis"] > 0, \
        "the header must show WHEN the failed attempt happened, not read as never analysed"
    assert [r["id"] for r in out["tabs"]["runs"]] == [aid]


def test_project_data_a_project_with_no_analyses_of_its_own_is_not_marked_attempted(tmp_path):
    """Containment probe: a DIFFERENT project having analyses in the same
    ledger must not make this one look attempted."""
    db = tmp_path / "security.db"
    aid = open_analysis(db, project="other", repo="other", branch="main", run_id="r1")
    run(db, "finish", "--analysis", str(aid), "--state", "failed")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert out["tabs"]["overview"]["attempted"] is False
    assert out["header"]["last_analysis"] == 0
    assert out["tabs"]["runs"] == []


# ---- Task 10: the Branches and Reports tabs. `tabs.branches` is exactly
# `queries.branch_rows`'s own rows (already proven against `posture`/`trend`
# in tests/security/test_queries.py); these two pin the CLI's own JSON
# contract, since test_security_api.py's own coverage of `security_project`
# only ever mocks `cc` and never runs this verb for real.

def test_project_data_branches_tab_matches_branch_rows(tmp_path):
    """Two branches of the same project, each with its own posture and its
    own analysis count -- `branches` must carry both, newest last-analysed
    first, with each row's own open counts (not the sidebar's cross-branch,
    fingerprint-deduplicated total)."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="low", rule="a")
    finished_analysis(db, tmp_path, "web", "develop", severity="critical", rule="b")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    branches = out["tabs"]["branches"]
    assert [r["branch"] for r in branches] == ["develop", "main"], \
        "develop was analysed more recently (higher analysis id) and must sort first"
    develop = next(r for r in branches if r["branch"] == "develop")
    main = next(r for r in branches if r["branch"] == "main")
    assert develop["open"]["critical"] == 1
    assert main["open"]["low"] == 1
    assert develop["analyses"] == 1 and main["analyses"] == 1
    assert develop["last_analysis"] > 0 and main["last_analysis"] > 0
    assert "trend" in develop and "trend" in main


def test_project_data_branches_tab_lists_every_branch_ever_analysed_not_only_the_default(tmp_path):
    """Containment probe: `branches` is not scoped to the project's declared
    base the way the Overview posture is -- a branch never declared as the
    base still gets its own row once it has been analysed."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "feature/x", severity="medium", rule="a")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert out["header"]["branch"] == "feature/x", "the header itself falls back to it"
    assert [r["branch"] for r in out["tabs"]["branches"]] == ["feature/x"]


def test_project_data_reports_tab_is_one_row_per_analysis(tmp_path):
    """`reports` gathers the four downloads that used to be reachable only
    from whichever single analysis was on screen -- one row per analysis,
    same set and same order as `runs` (newest first), projected down to just
    what a download needs: which analysis, which branch, when, and its
    state (a running or failed analysis still gets a row -- the single
    analysis view already lets you download over either, see secPaint)."""
    db = tmp_path / "security.db"
    done_id = finished_analysis(db, tmp_path, "web", "main", rule="a")
    running_id = open_analysis(db, project="web", repo="web", branch="develop", run_id="r2")

    out = run(db, "project-data", "--project", "web", "--base", "main", "--default-profile", "")

    assert [r["id"] for r in out["tabs"]["runs"]] == [r["analysis_id"] for r in out["tabs"]["reports"]]
    by_id = {r["analysis_id"]: r for r in out["tabs"]["reports"]}
    assert by_id[done_id]["branch"] == "main"
    assert by_id[done_id]["state"] == "done"
    assert by_id[done_id]["started"] > 0
    assert by_id[running_id]["branch"] == "develop"
    assert by_id[running_id]["state"] == "running"


def test_project_data_reports_tab_is_built_from_runs_not_a_second_query(tmp_path):
    """Structural: `cmd_project_data`'s own source must build `reports` by
    projecting the `runs` rows it already fetched -- not a second `SELECT *
    FROM analysis` -- the same reuse `_CachingConnection` gives `checklist()`
    within one request (see tests/security/test_queries.py), applied here to
    a plain Python loop instead of a cache."""
    src = inspect.getsource(security_cli.cmd_project_data)
    assert src.count("FROM analysis WHERE project=?") == 1, \
        "reports must not run a second SELECT over the analysis table: " + src
    assert "for r in runs" in src, \
        "reports must be derived from the runs rows already in hand, not refetched"


# ---- final whole-branch review, CRITICAL 1: the index screen's two halves
# resolved DIFFERENT branches. `cmd_index_data` stripped `base` out of the
# project dicts before calling `index_summary`, so the cards' own
# `default_branch_posture(conn, name, None)` ALWAYS took the fallback path
# while `project_rows`, handed the dicts whole, honoured the declared base.
# Every existing `index_summary` fixture is single-branch, which is exactly
# why nothing here caught it -- this one is deliberately not.

def test_index_data_cards_and_table_resolve_the_same_branch(tmp_path):
    """`web` declares `main` as its base. `main`'s latest analysis is
    `capped` and carries a high finding; `develop` was analysed later and
    found nothing. The cards used to read "High 0" (develop, the fallback)
    while the table three inches below read "High 1" on `main` with an
    `incomplete` badge -- and `capped_projects` resolved develop too, so the
    undercount warning never fired even though the base branch's latest
    analysis IS capped."""
    db = tmp_path / "security.db"
    capped_analysis(db, tmp_path, "web", "main", severity="high", rule="a")
    finished_analysis(db, tmp_path, "web", "develop", severity="low", rule="b")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]))

    row = out["projects"][0]
    assert row["branch"] == "main", "the table honours the declared base"
    assert row["posture"]["high"] == 1
    assert out["summary"]["high"] == row["posture"]["high"], (
        "the cards and the table disagree about the same project: "
        f"summary={out['summary']} row={row}")
    assert out["summary"]["capped_projects"] == 1, (
        "the base branch's latest analysis is capped and the undercount "
        f"warning would not fire: {out['summary']}")


def test_index_data_summary_says_when_it_had_to_fall_back(tmp_path):
    """The table names a fallback branch out loud (`branch_fell_back`); the
    cards, summing the same postures, said nothing -- and the spec requires
    a fallback branch never be silent. `fell_back_projects` is that count."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "develop", severity="critical", rule="a")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]))

    assert out["projects"][0]["branch_fell_back"] is True
    assert out["summary"]["fell_back_projects"] == 1, (
        "the cards sum a branch nobody declared and say nothing: "
        f"{out['summary']}")
    assert out["summary"]["critical"] == 1


def test_index_data_summary_reports_no_fallback_when_the_base_was_analysed(tmp_path):
    """Containment probe for the counter above: a project whose declared base
    really was analysed must not be reported as fallen back."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="high", rule="a")

    out = run(db, "index-data", "--projects", json.dumps(
        [{"name": "web", "base": "main", "description": ""}]))

    assert out["summary"]["fell_back_projects"] == 0
    assert out["projects"][0]["branch_fell_back"] is False


# ---- final whole-branch review, CRITICAL 3: the Branches tab could not
# express `capped` at all. `branch_rows` selected `state IN ('done','capped')`
# and returned no state, so a branch whose last analysis stopped early showed
# its PARTIAL posture as a finished one -- on the single screen whose whole
# purpose is per-branch posture.

def test_project_data_branches_tab_carries_the_state_its_posture_came_from(tmp_path):
    db = tmp_path / "security.db"
    capped_analysis(db, tmp_path, "web", "main", severity="high", rule="a")
    finished_analysis(db, tmp_path, "web", "develop", severity="low", rule="b")

    out = run(db, "project-data", "--project", "web", "--base", "main",
              "--default-profile", "")

    by_branch = {r["branch"]: r for r in out["tabs"]["branches"]}
    assert by_branch["main"]["state"] == "capped", (
        "a branch whose last analysis stopped early presents as finished: "
        f"{by_branch['main']}")
    assert by_branch["develop"]["state"] == "done"
    assert [p.get("state") for p in by_branch["main"]["trend"]] == ["capped"], (
        "the trend points carry no state, so the trend line cannot refuse a "
        f"direction across a capped endpoint: {by_branch['main']['trend']}")


# ---- final whole-branch review, CRITICAL 2: the Findings tab showed a green
# all-clear for a project never analysed. `findings-page` carried no
# never-analysed signal at all, so the strip rendered "nothing matches" in
# the ok-green clean pill beside `0 total` and the table blamed filters the
# reader never set. Overview and Branches both draw the distinction from
# `tabs.overview.attempted`, one module away.

def test_findings_page_says_a_project_was_never_analysed(tmp_path):
    db = tmp_path / "security.db"
    out = run(db, "findings-page", "--project", "web")
    assert out["attempted"] is False, f"no never-analysed signal in the payload: {out}"
    assert out["analysed"] is False
    assert out["total"] == 0


def test_findings_page_tells_attempted_apart_from_never_analysed(tmp_path):
    """The same two-way distinction Overview and Branches already draw: a
    project whose every analysis failed is not a project nobody ever
    touched."""
    db = tmp_path / "security.db"
    aid = open_analysis(db, project="web", repo="web", branch="main", run_id="r1")
    run(db, "finish", "--analysis", str(aid), "--state", "failed")

    out = run(db, "findings-page", "--project", "web")

    assert out["attempted"] is True, f"a failed attempt is still an attempt: {out}"
    assert out["analysed"] is False, "nothing has finished, so nothing was read"


def test_findings_page_of_an_analysed_project_is_analysed(tmp_path):
    """Containment probe: a project with a finished analysis must report
    both flags true, or the screens above would draw a never-analysed
    notice over a real, genuinely empty result."""
    db = tmp_path / "security.db"
    finished_analysis(db, tmp_path, "web", "main", severity="high", rule="a")
    out = run(db, "findings-page", "--project", "web")
    assert out["attempted"] is True and out["analysed"] is True
    assert out["total"] == 1


def test_findings_page_of_a_ledger_that_does_not_exist_is_never_analysed(tmp_path):
    """The `read_only is None` branch has to answer the same shape, or the
    screen falls back to the green all-clear on the very install where
    nothing has ever run."""
    db = tmp_path / "security.db"
    out = run(db, "findings-page", "--project", "web")
    assert not db.exists()
    assert out["attempted"] is False and out["analysed"] is False


# ---- final whole-branch review, IMPORTANT 8: the findings strip carried no
# capped cue, unlike the rows and cards beside it.

def test_findings_page_counts_branches_whose_latest_analysis_is_capped(tmp_path):
    db = tmp_path / "security.db"
    capped_analysis(db, tmp_path, "web", "main", severity="high", rule="a")
    finished_analysis(db, tmp_path, "web", "develop", severity="low", rule="b")

    out = run(db, "findings-page", "--project", "web")

    assert out["capped_branches"] == 1, (
        "the strip has no way to say one of these branches was read only "
        f"partially: {out}")


def test_project_data_sidebar_counts_branches_whose_latest_analysis_is_capped(tmp_path):
    """The sidebar donut spans every analysed branch, so it needs the same
    cue the Overview panel already gives its one branch."""
    db = tmp_path / "security.db"
    capped_analysis(db, tmp_path, "web", "main", severity="high", rule="a")

    out = run(db, "project-data", "--project", "web", "--base", "main",
              "--default-profile", "")

    assert out["sidebar"]["capped_branches"] == 1, (
        f"the sidebar cannot say its donut is a partial read: {out['sidebar']}")


# ---- final whole-branch review, IMPORTANT 7: Activity printed raw state
# tokens. `cmd_decide` built the event detail as f"{state}: {reason}", so the
# Activity screen showed `false_positive: duplicate...` where every other
# screen in the area shows `False positive`.

def test_decide_files_its_event_with_the_state_word_a_reader_sees(tmp_path):
    db = tmp_path / "security.db"
    fp = "d" * 64
    run(db, "decide", "--project", "web", "--fingerprint", fp,
        "--state", "false_positive", "--reason", "duplicate of the other one")

    events = run(db, "events", "--project", "web")
    detail = events[0]["detail"]
    assert "false_positive" not in detail, (
        f"the raw state token reached the audit trail: {detail!r}")
    assert detail.startswith("False positive: "), detail
    assert "duplicate of the other one" in detail


def test_decide_files_an_accepted_event_with_the_same_vocabulary(tmp_path):
    db = tmp_path / "security.db"
    fp = "e" * 64
    run(db, "decide", "--project", "web", "--fingerprint", fp,
        "--state", "accepted", "--reason", "risk accepted for Q3")
    events = run(db, "events", "--project", "web")
    assert events[0]["detail"].startswith("Accepted: "), events[0]["detail"]


# ---- final whole-branch review, IMPORTANT 2: `decide --fingerprint` had no
# shape validation at all, so a malformed fingerprint wrote BOTH a decision
# row and a `decision_made` event reading "accepted: risk accepted for Q3" --
# Activity telling the operator the risk was accepted while the finding stays
# open, since nothing will ever match that identity.

def test_decide_refuses_a_fingerprint_that_is_not_the_identity_shape(tmp_path):
    db = tmp_path / "security.db"
    for bad in ("aws-key in prod.env", "ABC123", "a" * 63, "a" * 65, "", "  "):
        out = fails(db, "decide", "--project", "web", "--fingerprint", bad,
                    "--state", "accepted", "--reason", "risk accepted for Q3")
        assert out.returncode != 0, f"{bad!r} was accepted: {out.stdout}"
        assert "64 lowercase hex" in out.stderr, out.stderr
    # ...and neither the decision nor its event was written.
    assert run(db, "events", "--project", "web") == []


def test_decide_still_accepts_a_real_fingerprint(tmp_path):
    """Containment probe: the shape check must not refuse the identity
    `report-finding` actually mints."""
    db = tmp_path / "security.db"
    fp = compute_fingerprint("sast", "r", "app.py", "")
    run(db, "decide", "--project", "web", "--fingerprint", fp,
        "--state", "accepted", "--reason", "known and accepted")
    assert len(run(db, "events", "--project", "web")) == 1


# ---- final whole-branch review, IMPORTANT 1: `finish --note` was the one
# agent-writable free-text channel with no `looks_like_a_secret` guard on it,
# even though the near-identically-named `partial_note` is covered and
# `finish` is deliberately allowed to the agent. A credential written there
# reaches all four report formats and the page.

def test_finish_refuses_a_note_that_looks_like_a_live_credential(tmp_path):
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main")
    out = fails(db, "finish", "--analysis", str(aid), "--state", "done",
                "--note", "could not scan with AKIAIOSFODNN7EXAMPLE in the env",
                env=AS_AGENT)
    assert out.returncode != 0, "the note was accepted"
    assert "live credential" in out.stderr, out.stderr
    assert "AKIAIOSFODNN7EXAMPLE" not in out.stderr, \
        "the refusal echoed the secret back, defeating itself"
    assert "AKIAIOSFODNN7EXAMPLE" not in out.stdout


def test_a_refused_note_leaves_the_analysis_open_rather_than_half_closed(tmp_path):
    """The refusal happens BEFORE `finish_analysis`, so nothing is written --
    the agent can close again with a note that says the same thing without
    quoting the credential."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main")
    fails(db, "finish", "--analysis", str(aid), "--state", "done",
          "--note", "leaked AKIAIOSFODNN7EXAMPLE", env=AS_AGENT)
    rows = run(db, "list", "--project", "web")
    assert rows[0]["state"] == "running", rows[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in (rows[0]["coverage_note"] or "")

    run(db, "finish", "--analysis", str(aid), "--state", "done",
        "--note", "an AWS access key is hardcoded in the env file")
    rows = run(db, "list", "--project", "web")
    assert rows[0]["state"] == "done"


def test_finish_still_accepts_an_ordinary_coverage_note(tmp_path):
    """Containment probe: the guard must not refuse the notes the engine and
    the agent legitimately write."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path, project="web", repo="web", branch="main")
    run(db, "finish", "--analysis", str(aid), "--state", "capped",
        "--note", "I stopped before the SAST phase")
    rows = run(db, "list", "--project", "web")
    assert "I stopped before the SAST phase" in rows[0]["coverage_note"]


# ---- final whole-branch review, IMPORTANT 4: the skill -- which is what the
# AGENT reads -- still listed three of the six refused verbs. The README had
# been updated to all six and the skill had not, so an agent meeting `event`,
# `filters save` or `filters delete` met a hard mid-run exit its own
# instructions told it could not happen. Pinned against the tuple itself so
# the two cannot drift apart again in either direction.

def test_the_skill_names_every_verb_the_door_refuses_the_agent(tmp_path):
    skill = (REPO / "skills" / "security-analysis" / "SKILL.md").read_text()
    for verb in security_cli.AGENT_FORBIDDEN:
        assert f"`{verb}`" in skill, (
            f"the agent's own instructions never mention `{verb}`, which the "
            "door refuses it mid-run")


def test_the_skill_does_not_claim_a_read_verb_is_refused(tmp_path):
    """Containment probe: `events` and `filters list` are deliberately NOT in
    AGENT_FORBIDDEN, and telling the agent otherwise costs it a query it may
    legitimately want."""
    skill = (REPO / "skills" / "security-analysis" / "SKILL.md").read_text()
    for verb in ("events", "filters list"):
        assert verb not in security_cli.AGENT_FORBIDDEN
        assert f"`{verb}`" in skill, \
            f"the skill does not say `{verb}` stays reachable"


# ---- migrate-rules: applying taxonomy.RULE_RENAMES to the ledger.
#
# The shipped map now carries the six secret pairings, so the verb is a no-op
# against a ledger that holds no findings under the old names rather than a
# no-op by construction. The tests that need a rename to actually happen
# monkeypatch the map and drive `main()` in-process, the same exception this
# file's docstring already makes for the ledger-write-failure group: a
# subprocess cannot see a monkeypatch.
#
# EVERY TEST THAT GETS PAST THE GUARDS NEEDS `gitleaks` VISIBLE. The verb
# refuses a machine where `adapters.engine_path("gitleaks")` is falsy while
# the map holds a `secret` entry, and this suite pins CC_SECURITY_ENGINES=off
# (see conftest.py) -- so without the two helpers below every one of these
# would be testing the refusal instead of what it was written for.


def _gitleaks_stub(tmp_path):
    """A directory holding an executable file called `gitleaks`, and nothing
    more.

    `adapters.engine_path` is `shutil.which` behind an env switch, and
    `migrate-rules` never RUNS the engine -- it asks only whether the NEXT
    analysis would find one, because a machine without it re-mints the old
    snake_case names and undoes the migration. So a stub is not a shortcut
    here, it is the honest fixture: requiring the real binary would make
    these tests pass or fail on whether the reviewer had run `brew install`.
    """
    binroot = tmp_path / "stub-bin"
    binroot.mkdir(exist_ok=True)
    stub = binroot / "gitleaks"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    return binroot


def with_gitleaks(tmp_path, base=None):
    """Env for a SUBPROCESS run that has to get past the gitleaks guard."""
    base = os.environ if base is None else base
    return {**base, "CC_SECURITY_ENGINES": "on",
            "PATH": f"{_gitleaks_stub(tmp_path)}{os.pathsep}{base['PATH']}"}


def pretend_gitleaks_is_installed(monkeypatch, tmp_path):
    """The same, for the tests that drive `main()` IN-PROCESS."""
    monkeypatch.setenv("CC_SECURITY_ENGINES", "on")
    monkeypatch.setenv(
        "PATH", f"{_gitleaks_stub(tmp_path)}{os.pathsep}{os.environ['PATH']}")


def test_migrate_rules_reports_nothing_when_there_is_nothing_to_rename(tmp_path):
    """A ledger holding no findings under any old name must still leave the
    verb runnable and saying so -- an operator running it after pulling a
    release should get a plain "nothing moved", not an error and not
    silence."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    # Closed first: the verb refuses while any analysis is running, and this
    # test is about the empty result, not about that guard.
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    out = run(db, "migrate-rules", env=with_gitleaks(tmp_path))
    assert out == {"renamed": [], "findings": 0}


def test_migrate_rules_is_refused_without_gitleaks(tmp_path):
    """The failure this verb EXISTS to prevent, reached through its own front
    door.

    Every secret rename moves findings from the built-in pattern scanner's
    snake_case names onto gitleaks' kebab-case ones. Run it on a machine with
    no gitleaks -- or with the engines switched off -- and `_scan_secrets`
    falls back to that same built-in scanner on the very next analysis and
    mints the old names again. The migrated row is then reported `fixed`
    (nothing produces its new name) and the re-minted one `new`, in ONE
    report, and the human decision on each side strands: precisely the
    double-identity damage `migrate-rules` was written to stop.

    Refused before the ledger is opened, like the category check and for the
    same reason -- it needs nothing from the ledger, so it cannot leave a map
    half-applied.
    """
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")

    # CC_SECURITY_ENGINES=off, STATED here rather than inherited from
    # conftest's default. `engine_path` consults the switch before it consults
    # PATH, so an engine that is off is an engine that is absent as far as the
    # next analysis is concerned -- which is the machine this refusal is about,
    # and it is the same machine on a laptop with gitleaks and on CI without
    # it. Inheriting the default instead made this test pass only while nobody
    # ran the suite in production's configuration: with the engines on and
    # gitleaks really installed, `migrate-rules` correctly proceeded and the
    # refusal this test is named for was never reached.
    env_off = {**os.environ, "CC_SECURITY_ENGINES": "off"}
    out = fails(db, "migrate-rules", env=env_off)
    assert out.returncode != 0
    assert "gitleaks is not available" in out.stderr
    assert "nothing was migrated" in out.stderr.lower()
    # It names the damage, not just the missing binary: an operator who is
    # told only "gitleaks not found" installs nothing and runs it anyway.
    assert "fixed AND new" in out.stderr

    # And the same machine with the engine visible gets through to the work.
    assert run(db, "migrate-rules", env=with_gitleaks(tmp_path)) == {
        "renamed": [], "findings": 0}


def test_migrate_rules_refuses_a_machine_with_the_engines_switched_off(tmp_path):
    """`CC_SECURITY_ENGINES=off` is not a lesser version of "not installed":
    it is the same machine as far as the next analysis is concerned, because
    `engine_path` consults the switch before it consults PATH. An operator who
    installed gitleaks and left the switch off would otherwise migrate onto
    names their own analyses will never mint."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")

    # gitleaks IS on PATH here -- only the switch is off.
    env = {**with_gitleaks(tmp_path), "CC_SECURITY_ENGINES": "off"}
    out = fails(db, "migrate-rules", env=env)
    assert out.returncode != 0 and "gitleaks is not available" in out.stderr


def test_migrate_rules_carries_findings_and_decisions_to_the_new_name(
        tmp_path, monkeypatch, capsys):
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    path = "config/prod.env"
    old_fp = secret_fingerprint("aws_access_key", path)
    new_fp = secret_fingerprint("aws-access-token", path)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": old_fp, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}]}))
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", old_fp,
        "--state", "accepted", "--reason", "rotated already", "--by", "luiz")

    monkeypatch.setattr(security_taxonomy, "RULE_RENAMES",
                        {("secret", "aws_access_key"): "aws-access-token"})
    pretend_gitleaks_is_installed(monkeypatch, tmp_path)
    security_cli.main(["migrate-rules", "--db", str(db)])
    printed = json.loads(capsys.readouterr().out)

    assert printed == {"renamed": [{"category": "secret", "from": "aws_access_key",
                                    "to": "aws-access-token", "findings": 1}],
                       "findings": 1}
    # Checked over a fresh subprocess, so the monkeypatch above cannot mask it.
    moved = [f for f in run(db, "findings", "--analysis", str(aid))
             if f["category"] == "secret"]
    assert [f["rule"] for f in moved] == ["aws-access-token"]
    assert [f["fingerprint"] for f in moved] == [new_fp]
    conn = sqlite3.connect(str(db))
    assert conn.execute("SELECT fingerprint FROM decision").fetchall() == [(new_fp,)]


def test_migrate_rules_is_safe_to_run_twice(tmp_path, monkeypatch, capsys):
    """It is a migration an operator may run on every deploy, and a second run
    has to be a no-op rather than a second rewrite of the same rows."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    path = "config/prod.env"
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": secret_fingerprint("aws_access_key", path),
        "category": "secret", "rule": "aws_access_key", "severity": "critical",
        "title": "t", "rationale": "r", "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}]}))
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    monkeypatch.setattr(security_taxonomy, "RULE_RENAMES",
                        {("secret", "aws_access_key"): "aws-access-token"})
    pretend_gitleaks_is_installed(monkeypatch, tmp_path)

    security_cli.main(["migrate-rules", "--db", str(db)])
    assert json.loads(capsys.readouterr().out)["findings"] == 1
    security_cli.main(["migrate-rules", "--db", str(db)])
    assert json.loads(capsys.readouterr().out) == {"renamed": [], "findings": 0}


def test_migrate_rules_carries_the_decision_event_to_the_new_fingerprint(
        tmp_path, monkeypatch, capsys):
    """End-to-end over the real `decide`, which is the point: `cmd_decide`
    files the `decision_made` event with `fingerprint[:12]` and the Activity
    screen deep-links from that prefix by LIKE-match into the findings browser.
    `rename_rule` has to produce the identical slice of the new fingerprint or
    the audit record of the human's call links to zero findings while still
    saying the risk was accepted. Driven through the CLI so the two `[:12]`s
    are compared as they actually run, not as this test imagines them."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    path = "config/prod.env"
    old_fp = secret_fingerprint("aws_access_key", path)
    new_fp = secret_fingerprint("aws-access-token", path)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": old_fp, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}]}))
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", old_fp,
        "--state", "accepted", "--reason", "rotated already", "--by", "luiz")
    conn = sqlite3.connect(str(db))
    assert conn.execute(
        "SELECT related FROM event WHERE kind='decision_made'").fetchall() == [
            (old_fp[:12],)]

    monkeypatch.setattr(security_taxonomy, "RULE_RENAMES",
                        {("secret", "aws_access_key"): "aws-access-token"})
    pretend_gitleaks_is_installed(monkeypatch, tmp_path)
    security_cli.main(["migrate-rules", "--db", str(db)])
    capsys.readouterr()

    related = conn.execute(
        "SELECT related FROM event WHERE kind='decision_made'").fetchone()[0]
    assert related == new_fp[:12]
    # The query the Activity screen's link actually runs, and it has to come
    # back with the finding rather than empty.
    assert conn.execute("SELECT fingerprint FROM finding WHERE fingerprint LIKE ?",
                        (related + "%",)).fetchall() == [(new_fp,)]


def test_migrate_rules_names_the_entries_it_already_applied_when_one_fails(
        tmp_path, monkeypatch):
    """The mid-map failure the docstring must not claim is impossible. Only the
    CATEGORY of every entry is pre-flighted; a finding with no path is found by
    WALKING, so the entry that hits it rolls back alone while everything before
    it in the map stays committed. The operator therefore has to be told WHICH
    entries landed -- a count leaves them diffing the ledger against the map to
    find out where it stopped."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    path = "config/prod.env"
    good_fp = secret_fingerprint("aws_access_key", path)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": good_fp, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}]}))
    # Occurrences are optional to `report-finding`, so this is a payload the
    # agent can really send -- and a finding with no path cannot be renamed.
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "e" * 64, "category": "secret", "rule": "github_token",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate", "occurrences": []}))
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    monkeypatch.setattr(security_taxonomy, "RULE_RENAMES", {
        ("secret", "aws_access_key"): "aws-access-token",
        ("secret", "github_token"): "gh-token",
    })
    pretend_gitleaks_is_installed(monkeypatch, tmp_path)

    with pytest.raises(SystemExit) as exc:
        security_cli.main(["migrate-rules", "--db", str(db)])

    message = str(exc.value.code)
    assert "secret/github_token -> gh-token failed" in message
    # The entry that DID land, named -- not counted.
    assert "secret/aws_access_key -> aws-access-token (1 finding(s))" in message
    # And it really did land: the run was not all-or-nothing, which is exactly
    # what the message has to make true rather than deny.
    moved = [f for f in run(db, "findings", "--analysis", str(aid))
             if f["rule"] == "aws-access-token"]
    assert [f["fingerprint"] for f in moved] == [
        secret_fingerprint("aws-access-token", path)]


def test_migrate_rules_refuses_the_whole_map_before_applying_any_of_it(
        tmp_path, monkeypatch):
    """A map with an unapplicable entry is refused as a unit. Applying the
    entries up to the bad one and then dying leaves the ledger half-migrated
    -- the exact state `rename_rule`'s own transaction exists to prevent, put
    back one level up."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    path = "config/prod.env"
    old_fp = secret_fingerprint("aws_access_key", path)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": old_fp, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}]}))
    monkeypatch.setattr(security_taxonomy, "RULE_RENAMES", {
        ("secret", "aws_access_key"): "aws-access-token",
        ("sast", "sql-injection"): "sqli",
    })

    with pytest.raises(SystemExit) as exc:
        security_cli.main(["migrate-rules", "--db", str(db)])
    assert "sast" in str(exc.value.code)

    # The good entry that came FIRST in the map must not have been applied.
    still = [f for f in run(db, "findings", "--analysis", str(aid))
             if f["category"] == "secret"]
    assert [f["fingerprint"] for f in still] == [old_fp]


def test_migrate_rules_is_not_refused_the_agent(tmp_path):
    """Containment probe, the same reasoning as `fingerprint`'s absence from
    AGENT_FORBIDDEN: the verb takes no arguments. It can only ever apply the
    map the repository itself declares, so an agent running it produces
    exactly what a human running it produces -- there is no target for it to
    choose and nothing here for the flag to protect. What DOES stop an agent
    running it at the moment it would do damage is the running-analysis guard
    below, which does not depend on the flag -- so this asserts the agent
    reaches the verb once no analysis is live, not that it may run it during
    one."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    assert "migrate-rules" not in security_cli.AGENT_FORBIDDEN
    assert run(db, "migrate-rules",
               env=with_gitleaks(tmp_path, base=AS_AGENT)) == {
        "renamed": [], "findings": 0}


def test_migrate_rules_is_refused_while_an_analysis_is_running(tmp_path):
    """`decide` refuses while an analysis is live and this rewrites far more
    than `decide` does. Mid-analysis, findings the agent has already recorded
    get NEW fingerprints while it still holds the old ones: its next re-report
    of one -- the triage pass's whole job -- misses the `(analysis_id,
    fingerprint)` upsert key and INSERTs a second row, so one hole becomes two
    contradictory checklist entries. That UNIQUE constraint exists to prevent
    exactly that."""
    db = tmp_path / "security.db"
    aid = prepared_analysis(db, tmp_path)
    # gitleaks visible throughout, so what is being measured here is the
    # running-analysis guard and not the engine guard ahead of it.
    env = with_gitleaks(tmp_path)

    out = fails(db, "migrate-rules", env=env)

    assert out.returncode != 0
    assert f"analysis {aid}" in out.stderr and "still running" in out.stderr
    assert "nothing was migrated" in out.stderr.lower()
    # The refusal is not scoped to a project: this verb takes none and walks
    # every row in the ledger, so an analysis of ANOTHER project is still a
    # live analysis it could pull the ground out from under.
    other = open_analysis(db, project="api", repo="api", run_id="r2")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    out = fails(db, "migrate-rules", env=env)
    assert out.returncode != 0 and f"analysis {other}" in out.stderr

    run(db, "finish", "--analysis", str(other), "--state", "done")
    assert run(db, "migrate-rules", env=env) == {"renamed": [], "findings": 0}
