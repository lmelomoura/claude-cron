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

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from security.fingerprint import fingerprint as compute_fingerprint, secret_fingerprint
from security import cli as security_cli
from security import ledger as security_ledger

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
    finding = {"fingerprint": "e" * 64, "category": "sast", "rule": "r",
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
        "fingerprint": "a" * 64, "category": "sast", "rule": "r",
        "severity": "high", "title": "t"}))
    run(db, "finish", "--analysis", str(aid), "--state", "done")
    run(db, "decide", "--project", "web", "--fingerprint", "a" * 64,
        "--state", "false_positive", "--reason", "the sink is parameterised",
        "--by", "luiz")
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
        stdin=json.dumps({"fingerprint": "b" * 64, "category": "sast",
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
        "fingerprint": "a" * 64, "category": "sast", "rule": "r",
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
    finding = {"fingerprint": "e" * 64, "category": "sast", "rule": "r",
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
    finding = {"fingerprint": "e" * 64, "category": "sast", "rule": "r",
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
            "fingerprint": bad, "category": "sast", "rule": "r",
            "severity": "high", "title": "t"}))
        assert out.returncode != 0, bad
        assert "fingerprint" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


def test_a_finding_cannot_paste_a_whole_file_into_the_ledger(tmp_path):
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    for key in ("title", "rationale", "remediation", "partial_note"):
        payload = {"fingerprint": "a" * 64, "category": "sast", "rule": "r",
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
        "fingerprint": "a" * 64, "category": "sast", "rule": "r",
        "severity": "high", "title": "t",
        "occurrences": [{"file": "a.py", "line": 1e999}]}))
    assert out.returncode != 0
    assert "Traceback" not in out.stderr
    assert "report-finding" in out.stderr
    assert run(db, "findings", "--analysis", str(aid)) == []


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
    got = raw(db, "fingerprint", "--category", "sast", "--rule", "r",
              "--path", "p", env=AS_AGENT)
    assert got == compute_fingerprint("sast", "r", "p", "")


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


AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def states_by_rule(checklist):
    return {f["rule"]: f["state"] for f in checklist["findings"]}


def test_a_history_secret_survives_the_second_and_third_analysis(tmp_path):
    """THE scenario the whole history sweep exists for.

    A key was committed on Monday and the file deleted on Tuesday. The value
    is still readable by anyone with a clone, which is why the finding's own
    remediation says deleting the file is not enough -- rotate first.

    The sweep used to run only on a branch's FIRST analysis, so nothing
    re-emitted the finding afterwards: `classify` saw it in the previous
    analysis and not in this one and reported it `fixed` -- congratulating the
    operator for the exact act the remediation calls insufficient -- and by
    the third analysis it had dropped out of the report entirely. It must stay
    OPEN, run after run, until somebody rotates the credential and DECIDES it.
    """
    root = git_repo(tmp_path / "repo", [
        ("add", {"prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"}),
        ("remove", {"prod.env": None}),
    ])
    db = tmp_path / "security.db"

    first = open_analysis(db)
    run(db, "prepare", "--analysis", str(first), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(first), "--state", "done")
    assert states_by_rule(run(db, "checklist", "--analysis", str(first))) == {
        "aws_access_key": "new"}

    # Nothing changed in the repository between the analyses. The finding is
    # not new (it was here last time) and it is emphatically not fixed.
    second = open_analysis(db)
    run(db, "prepare", "--analysis", str(second), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(second), "--state", "done")
    assert states_by_rule(run(db, "checklist", "--analysis", str(second))) == {
        "aws_access_key": "open"}

    # And the third run still knows about it: the old behaviour lost it here
    # altogether -- neither the previous analysis nor this one carried it, so
    # it was in no checklist at all.
    third = open_analysis(db)
    run(db, "prepare", "--analysis", str(third), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(third), "--state", "done")
    assert states_by_rule(run(db, "checklist", "--analysis", str(third))) == {
        "aws_access_key": "open"}
    carried = run(db, "findings", "--analysis", str(third))
    assert "git history" in carried[0]["rationale"]
    assert AWS_KEY not in json.dumps(carried)


def test_rotating_and_accepting_is_how_a_history_finding_closes(tmp_path):
    """The other half of the lifecycle. Because the sweep never stops finding
    it, a history finding cannot be closed by changing the code -- the only
    honest close is a human saying the credential was rotated and the exposure
    accepted. That decision must win over the derived `open`."""
    root = git_repo(tmp_path / "repo", [
        ("add", {"prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"}),
        ("remove", {"prod.env": None}),
    ])
    db = tmp_path / "security.db"
    first = open_analysis(db)
    run(db, "prepare", "--analysis", str(first), "--root", str(root), "--offline")
    fp = run(db, "findings", "--analysis", str(first))[0]["fingerprint"]
    run(db, "finish", "--analysis", str(first), "--state", "done")

    run(db, "decide", "--project", "web", "--fingerprint", fp,
        "--state", "accepted", "--reason", "rotated at the provider on Tuesday")

    second = open_analysis(db)
    run(db, "prepare", "--analysis", str(second), "--root", str(root), "--offline")
    run(db, "finish", "--analysis", str(second), "--state", "done")
    assert states_by_rule(run(db, "checklist", "--analysis", str(second))) == {
        "aws_access_key": "accepted"}


def test_the_working_tree_reading_wins_over_its_history_twin(tmp_path):
    """A secret in the tree AND in the history is ONE finding: same rule, same
    path, therefore one fingerprint, and record_finding upserts.

    The two readings disagree about the wording and the line: the tree knows
    the real line number and says "in the working tree", the history says line
    0 and "in the git history". The tree's is the one a reader can act on, so
    it must be recorded LAST and win the upsert. The history sweep used to be
    appended after the tree, which overwrote a live, locatable secret with a
    line-0 report about the past.
    """
    root = git_repo(tmp_path / "repo", [
        ("add", {"prod.env": f"# header\nAWS_ACCESS_KEY_ID={AWS_KEY}\n"}),
    ])
    db = tmp_path / "security.db"
    aid = open_analysis(db)
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    found = run(db, "findings", "--analysis", str(aid))
    secret = [f for f in found if f["rule"] == "aws_access_key"]
    assert len(secret) == 1, "the tree and history readings must be one row"
    assert "in the working tree" in secret[0]["rationale"]
    assert [o["line"] for o in secret[0]["occurrences"]] == [2]


def test_ignore_paths_reach_the_tree_the_history_and_the_hygiene_pass(tmp_path):
    """`ignore_paths` is a promise about the ANALYSIS, not about one phase.

    A fixtures directory holding a deliberately fake key was excluded from the
    working-tree sweep and reported in full by the history sweep and by the
    hygiene pass -- so the operator set the option, saw the noise disappear
    from one section of the report and stay in two others.
    """
    root = git_repo(tmp_path / "repo", [
        ("fixtures", {"tests/fixtures/fake.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
                      "tests/fixtures/fake.pem": "-----BEGIN RSA PRIVATE KEY-----\nx\n"}),
        ("delete the env", {"tests/fixtures/fake.env": None}),
    ])
    db = tmp_path / "security.db"

    noisy = open_analysis(db)
    run(db, "prepare", "--analysis", str(noisy), "--root", str(root), "--offline")
    rules = {f["rule"] for f in run(db, "findings", "--analysis", str(noisy))}
    assert {"aws_access_key", "private_key", "committed_key_file"} <= rules, (
        f"the fixture must be noisy without the globs: {sorted(rules)}")
    run(db, "finish", "--analysis", str(noisy), "--state", "done")

    quiet = open_analysis(db)
    run(db, "prepare", "--analysis", str(quiet), "--root", str(root), "--offline",
        "--ignore", "tests/fixtures/**")
    assert run(db, "findings", "--analysis", str(quiet)) == []


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


def test_the_door_accepts_info_as_a_severity(tmp_path):
    db = tmp_path / "security.db"
    root = tmp_path / "repo"
    root.mkdir()
    aid = run(db, "open-analysis", "--project", "web", "--repo", "web",
              "--branch", "main", "--commit", "a", "--profile", "quick",
              "--run-id", "r")["analysis_id"]
    run(db, "prepare", "--analysis", str(aid), "--root", str(root), "--offline")
    run(db, "report-finding", "--analysis", str(aid), stdin=json.dumps({
        "fingerprint": "c" * 64, "category": "sast", "rule": "observation",
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
