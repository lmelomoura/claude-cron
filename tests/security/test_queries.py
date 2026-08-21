import pytest
from security import ledger, queries


@pytest.fixture
def conn(tmp_path):
    return ledger.connect(tmp_path / "security.db")


def _analysis(conn, branch, state="done", project="web", findings=(), prepared=True):
    aid = ledger.start_analysis(conn, project, project, branch, "sha", "quick", "r")
    for i, (sev, cat) in enumerate(findings):
        ledger.record_finding(conn, aid, {
            "fingerprint": f"{sev[0]}{cat[0]}{i:062d}", "category": cat,
            "rule": f"{cat}-rule", "severity": sev, "title": f"{sev} {cat}",
            "occurrences": [{"file": "a.py", "line": 1, "snippet_hash": "h"}]})
    if prepared:
        ledger.mark_prepared(conn, aid)
    if state != "running":
        ledger.finish_analysis(conn, aid, state)
    return aid


def test_read_only_refuses_to_write(tmp_path):
    """The guarantee is enforced by SQLite, not by everyone remembering."""
    ledger.connect(tmp_path / "security.db").close()
    ro = queries.read_only(tmp_path / "security.db")
    import sqlite3
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("INSERT INTO event (project,kind,detail,related,at)"
                   " VALUES ('x','decision_made','','',1)")


def test_read_only_on_a_database_that_does_not_exist_is_none(tmp_path):
    """Nobody has ever run an analysis. That is an empty screen, not a 500."""
    assert queries.read_only(tmp_path / "nope.db") is None


def test_posture_counts_open_findings_of_the_latest_finished_analysis(conn):
    _analysis(conn, "main", findings=[("critical", "secret"), ("low", "hygiene")])
    _analysis(conn, "main", findings=[("critical", "secret")])
    p = queries.posture(conn, "web", "main")
    assert p["critical"] == 1
    assert p["low"] == 0, "the older analysis must not be counted"


def test_pending_counts_as_open(conn):
    """A finding not re-checked is exposure not yet closed. Filing it with the
    resolved would be the same lie as a premature `fixed`."""
    assert queries.is_open("pending") is True
    assert queries.is_open("open") is True
    assert queries.is_open("fixed") is False
    assert queries.is_open("accepted") is False
    assert queries.is_open("false_positive") is False


def test_a_running_analysis_is_never_the_posture(conn):
    _analysis(conn, "main", findings=[("high", "sast")])
    _analysis(conn, "main", state="running", findings=[])
    assert queries.posture(conn, "web", "main")["high"] == 1


def test_the_default_branch_falls_back_and_says_so(conn):
    _analysis(conn, "develop", findings=[("critical", "secret")])
    branch, posture, fell_back = queries.default_branch_posture(conn, "web", "main")
    assert branch == "develop"
    assert fell_back is True
    assert posture["critical"] == 1

    _analysis(conn, "main", findings=[("low", "hygiene")])
    branch, posture, fell_back = queries.default_branch_posture(conn, "web", "main")
    assert branch == "main"
    assert fell_back is False


def test_success_rate_counts_finished_analyses_only(conn):
    _analysis(conn, "main", state="done")
    _analysis(conn, "main", state="capped")
    _analysis(conn, "main", state="failed")
    _analysis(conn, "main", state="running")
    s = queries.index_summary(conn, ["web"])
    assert s["analyses"] == 4, "the total is every analysis"
    assert s["success_rate"] == pytest.approx(1 / 3), "done over done+capped+failed"


def test_top_categories_group_by_rule(conn):
    _analysis(conn, "main", findings=[("high", "sast"), ("high", "sast"),
                                      ("low", "hygiene")])
    cats = queries.top_categories(conn, "web")
    assert cats[0]["rule"] == "sast-rule"
    assert cats[0]["count"] == 2


def test_branch_rows_one_per_branch_newest_first(conn):
    _analysis(conn, "main", findings=[("low", "hygiene")])
    _analysis(conn, "develop", findings=[("critical", "secret")])
    rows = queries.branch_rows(conn, "web")
    assert [r["branch"] for r in rows] == ["develop", "main"]
    assert rows[0]["open"]["critical"] == 1
