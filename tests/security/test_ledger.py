import pytest
from security import ledger


@pytest.fixture
def conn(tmp_path):
    return ledger.connect(tmp_path / "security.db")


def _finding(**over):
    base = {
        "fingerprint": "a" * 64, "category": "sast", "rule": "sql-injection",
        "severity": "high", "title": "String-built SQL", "rationale": "why",
        "remediation": "use parameters",
        "occurrences": [{"file": "app/db.py", "line": 12, "snippet_hash": "h1"}],
    }
    base.update(over)
    return base


def test_a_finding_round_trips_with_its_occurrences(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding())
    ledger.finish_analysis(conn, aid, "done", 1.25)

    got = ledger.findings_of(conn, aid)
    assert len(got) == 1
    assert got[0]["rule"] == "sql-injection"
    assert got[0]["occurrences"][0]["file"] == "app/db.py"


def test_a_decision_belongs_to_the_project_not_the_branch(conn):
    ledger.set_decision(conn, "web", "a" * 64, "false_positive", "test fixture", "luiz")
    assert ledger.decisions_for(conn, "web")["a" * 64]["state"] == "false_positive"
    assert ledger.decisions_for(conn, "other") == {}


def test_a_decision_requires_a_reason(conn):
    with pytest.raises(ValueError):
        ledger.set_decision(conn, "web", "a" * 64, "accepted", "   ", "luiz")


def test_latest_analysis_is_scoped_to_repo_and_branch(conn):
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.finish_analysis(conn, a1, "done")
    a2 = ledger.start_analysis(conn, "web", "web", "develop", "c2", "standard", "r2")
    ledger.finish_analysis(conn, a2, "done")

    assert ledger.latest_analysis(conn, "web", "web", "main")["id"] == a1
    assert ledger.latest_analysis(conn, "web", "web", "develop")["id"] == a2
    assert ledger.latest_analysis(conn, "web", "web", "nope") is None


def test_a_running_analysis_is_not_the_baseline_for_the_next_one(conn):
    """Only a finished analysis is something to compare against."""
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.finish_analysis(conn, a1, "done")
    ledger.start_analysis(conn, "web", "web", "main", "c2", "standard", "r2")
    assert ledger.latest_analysis(conn, "web", "web", "main")["id"] == a1


def test_before_returns_the_analysis_strictly_before_it_not_the_latest(conn):
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.finish_analysis(conn, a1, "done")
    a2 = ledger.start_analysis(conn, "web", "web", "main", "c2", "standard", "r2")
    ledger.finish_analysis(conn, a2, "done")
    a3 = ledger.start_analysis(conn, "web", "web", "main", "c3", "standard", "r3")
    ledger.finish_analysis(conn, a3, "done")

    assert ledger.latest_analysis(conn, "web", "web", "main", before=a2)["id"] == a1
    # A regression to `<=` would let the middle one see itself as its own
    # baseline instead of the one before it.
    assert ledger.latest_analysis(conn, "web", "web", "main", before=a2)["id"] != a2


def test_finish_analysis_rejects_an_invalid_state(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    with pytest.raises(ValueError):
        ledger.finish_analysis(conn, aid, "bogus")


def test_set_decision_rejects_an_invalid_state(conn):
    with pytest.raises(ValueError):
        ledger.set_decision(conn, "web", "a" * 64, "bogus", "a real reason", "luiz")


def test_reporting_the_same_fingerprint_twice_upserts_a_single_row(conn):
    """The deterministic phase records a finding, then the agent re-reports
    the same fingerprint with a corrected severity and rationale -- that is
    the designed triage flow, not a bug, and it must not leave two rows for
    one vulnerability."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(severity="medium", rationale="deterministic guess"))
    ledger.record_finding(conn, aid, _finding(
        severity="critical", rationale="agent triage: exploitable via admin API",
        occurrences=[{"file": "app/db.py", "line": 99, "snippet_hash": "h2"}]))

    got = ledger.findings_of(conn, aid)
    assert len(got) == 1
    assert got[0]["severity"] == "critical"
    assert got[0]["rationale"] == "agent triage: exploitable via admin API"
    assert [o["line"] for o in got[0]["occurrences"]] == [99]


def test_reporting_the_same_fingerprint_in_different_analyses_is_not_a_conflict(conn):
    """The UNIQUE constraint is scoped to one analysis -- the same
    vulnerability recorded in two different analyses (two different runs)
    is two legitimate rows, not a collision."""
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    a2 = ledger.start_analysis(conn, "web", "web", "main", "c2", "standard", "r2")
    ledger.record_finding(conn, a1, _finding())
    ledger.record_finding(conn, a2, _finding())

    assert len(ledger.findings_of(conn, a1)) == 1
    assert len(ledger.findings_of(conn, a2)) == 1


def test_record_finding_is_atomic_a_bad_occurrence_leaves_no_finding_row(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    finding = _finding(occurrences=[{"file": "app/db.py", "line": "not-a-number",
                                      "snippet_hash": "h1"}])

    with pytest.raises(ValueError):
        ledger.record_finding(conn, aid, finding)

    # A later, unrelated commit on the same connection must not resurrect
    # the finding row that was left uncommitted by the failed insert above.
    conn.commit()

    rows = conn.execute("SELECT * FROM finding").fetchall()
    assert rows == []


def test_lines_of_code_round_trips(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc", "quick", "r1")
    ledger.set_lines_of_code(conn, aid, 1234)
    row = conn.execute("SELECT lines_of_code FROM analysis WHERE id=?", (aid,)).fetchone()
    assert row["lines_of_code"] == 1234


def test_lines_of_code_defaults_to_zero_for_an_older_analysis(conn):
    """The column arrives by additive migration; rows written before it exist
    read as 0, and the page shows a dash rather than inventing a number."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc", "quick", "r1")
    row = conn.execute("SELECT lines_of_code FROM analysis WHERE id=?", (aid,)).fetchone()
    assert row["lines_of_code"] == 0


def test_an_event_round_trips(conn):
    ledger.record_event(conn, "web", "analysis_started", "quick on main", "3")
    rows = ledger.events_for(conn, project="web")
    assert len(rows) == 1
    assert rows[0]["kind"] == "analysis_started"
    assert rows[0]["detail"] == "quick on main"
    assert rows[0]["related"] == "3"
    assert rows[0]["at"] > 0


def test_an_unknown_kind_is_refused(conn):
    """The kinds are a closed set: a typo must fail loudly rather than file an
    event no filter will ever match."""
    with pytest.raises(ValueError):
        ledger.record_event(conn, "web", "findings_viewed", "no")


def test_events_come_back_newest_first_and_scoped_to_their_project(conn):
    ledger.record_event(conn, "web", "analysis_started", "one")
    ledger.record_event(conn, "web", "analysis_finished", "two")
    ledger.record_event(conn, "other", "analysis_started", "elsewhere")
    kinds = [e["kind"] for e in ledger.events_for(conn, project="web")]
    assert kinds == ["analysis_finished", "analysis_started"]
    assert len(ledger.events_for(conn)) == 3


def test_events_filter_by_kind_and_paginate(conn):
    for i in range(5):
        ledger.record_event(conn, "web", "analysis_started", f"n{i}")
    ledger.record_event(conn, "web", "decision_made", "accepted something")
    assert len(ledger.events_for(conn, project="web", kinds=("decision_made",))) == 1
    page = ledger.events_for(conn, project="web", limit=2, offset=2)
    assert len(page) == 2


def test_a_failed_re_report_does_not_leave_the_finding_with_half_its_occurrences(conn):
    """The upsert path deletes the old occurrences before inserting the new
    ones. If that insert then fails partway, the whole re-report -- the field
    update, the deletion, and the partial insert -- must roll back together,
    leaving the original finding exactly as it was."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _finding(severity="medium", rationale="original"))

    bad = _finding(severity="critical", rationale="broken re-report",
                   occurrences=[{"file": "app/db.py", "line": "not-a-number",
                                 "snippet_hash": "h2"}])
    with pytest.raises(ValueError):
        ledger.record_finding(conn, aid, bad)
    conn.commit()

    got = ledger.findings_of(conn, aid)
    assert len(got) == 1
    assert got[0]["severity"] == "medium"
    assert got[0]["rationale"] == "original"
    assert [o["line"] for o in got[0]["occurrences"]] == [12]


# ------------------------------------------------------------ saved filters

def test_a_saved_filter_round_trips(conn):
    ledger.save_filter(conn, "web", "criticals only", {"severity": "critical"})
    got = ledger.saved_filters(conn, "web")
    assert len(got) == 1
    assert got[0]["name"] == "criticals only"
    assert got[0]["query"] == {"severity": "critical"}


def test_saving_the_same_name_twice_replaces_it(conn):
    ledger.save_filter(conn, "web", "mine", {"severity": "critical"})
    ledger.save_filter(conn, "web", "mine", {"severity": "high"})
    got = ledger.saved_filters(conn, "web")
    assert len(got) == 1
    assert got[0]["query"] == {"severity": "high"}


def test_filters_are_scoped_to_their_project(conn):
    ledger.save_filter(conn, "web", "mine", {"severity": "critical"})
    assert ledger.saved_filters(conn, "other") == []


def test_deleting_reports_whether_it_existed(conn):
    ledger.save_filter(conn, "web", "mine", {})
    assert ledger.delete_filter(conn, "web", "mine") is True
    assert ledger.delete_filter(conn, "web", "mine") is False


def test_a_blank_name_is_refused(conn):
    with pytest.raises(ValueError):
        ledger.save_filter(conn, "web", "   ", {})
