"""The one door between the engine and the ledger.

Everything an analysis does -- opening the row, the deterministic phases, the
agent's own findings, closing it, the checklist, the reports -- goes through
`bin/security/cli.py`. These tests drive it as a subprocess, the same way the
agent and bash do, because the process boundary IS the contract: an exit code
and a line of JSON on stdout.
"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"


def run(db, *args, stdin=None):
    out = subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, input=stdin, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout) if out.stdout.strip() else None


def fails(db, *args, stdin=None):
    return subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, input=stdin, check=False)


def open_analysis(db, project="web", repo="web", branch="main", commit="abc",
                  profile="quick", run_id="r1"):
    return run(db, "open-analysis", "--project", project, "--repo", repo,
               "--branch", branch, "--commit", commit, "--profile", profile,
               "--run-id", run_id)["analysis_id"]


def test_prepare_then_report_then_finish(tmp_path):
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (root / "prod.env").write_text("AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE\n")
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


def test_the_agent_cannot_report_into_an_analysis_that_does_not_exist(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "report-finding", "--analysis", "999", stdin=json.dumps({
        "fingerprint": "d" * 64, "category": "sast", "rule": "r",
        "severity": "high", "title": "t"}))
    assert out.returncode != 0
    assert "999" in out.stderr


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
    assert note in rendered["coverage"]


def run_text(db, *args):
    out = subprocess.run(
        [sys.executable, str(CLI), *args, "--db", str(db)],
        capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    return out.stdout


def test_a_note_given_explicitly_replaces_the_stored_one(tmp_path):
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(aid), "--state", "failed",
        "--note", "the agent never reached the SAST phase")
    row = run(db, "list", "--project", "web")[0]
    assert row["coverage_note"] == "the agent never reached the SAST phase"


def test_finish_if_running_does_not_reopen_a_closed_analysis(tmp_path):
    """The engine sweeps for a row left `running` by a run that never reached
    its close-out (the slot gate, a missing cwd). That sweep must be a no-op
    for the ordinary case where the run really happened and already closed
    the row -- otherwise every analysis would end up `failed`."""
    db = tmp_path / "security.db"
    aid = open_analysis(db)
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
    aid = open_analysis(db)
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

def test_a_finding_that_shrank_is_partial_not_open(tmp_path):
    """`diff.classify` takes `closed_occurrences` as its OBJECTIVE half of
    the partial signal -- the anchor two runs cannot disagree about. Nothing
    persists that number, and this is the only place the two analyses meet,
    so it is computed here or the branch is dead and `partial` can only ever
    come from the agent's own note."""
    db = tmp_path / "security.db"
    finding = {"fingerprint": "e" * 64, "category": "sast", "rule": "r",
               "severity": "high", "title": "t",
               "occurrences": [{"file": "a.py", "line": 1},
                               {"file": "b.py", "line": 2}]}
    first = open_analysis(db, run_id="r1")
    run(db, "report-finding", "--analysis", str(first), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(first), "--state", "done")

    finding["occurrences"] = [{"file": "a.py", "line": 1}]
    second = open_analysis(db, commit="def", run_id="r2")
    run(db, "report-finding", "--analysis", str(second), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(second), "--state", "done")

    checklist = run(db, "checklist", "--analysis", str(second))
    assert [f["state"] for f in checklist["findings"]] == ["partial"]


def test_a_finding_that_did_not_shrink_is_open(tmp_path):
    db = tmp_path / "security.db"
    finding = {"fingerprint": "e" * 64, "category": "sast", "rule": "r",
               "severity": "high", "title": "t",
               "occurrences": [{"file": "a.py", "line": 1}]}
    first = open_analysis(db, run_id="r1")
    run(db, "report-finding", "--analysis", str(first), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(first), "--state", "done")
    second = open_analysis(db, commit="def", run_id="r2")
    run(db, "report-finding", "--analysis", str(second), stdin=json.dumps(finding))
    run(db, "finish", "--analysis", str(second), "--state", "done")
    checklist = run(db, "checklist", "--analysis", str(second))
    assert [f["state"] for f in checklist["findings"]] == ["open"]


def test_a_decision_is_refused_without_a_reason(tmp_path):
    db = tmp_path / "security.db"
    open_analysis(db)
    out = fails(db, "decide", "--project", "web", "--fingerprint", "f" * 64,
                "--state", "accepted", "--reason", "   ", "--by", "me")
    assert out.returncode != 0
    assert "reason" in out.stderr


def test_a_decision_wins_over_the_derived_state(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "a" * 64, "category": "sast", "rule": "r",
        "severity": "high", "title": "t"}))
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "false_positive", "--reason", "the sink is parameterised",
        "--by", "luiz")
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    checklist = run(db, "checklist", "--analysis", str(aid))
    assert checklist["findings"][0]["state"] == "false_positive"


def test_findings_lists_what_the_deterministic_phase_left_for_the_agent(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nxx\n")
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    found = run(db, "findings", "--analysis", str(aid))
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
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "accepted", "--reason", "internal only", "--by", "luiz")
    run(db, "finish", "--analysis", str(aid), "--state", "done")

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
