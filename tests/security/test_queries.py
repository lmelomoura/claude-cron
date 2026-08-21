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


def test_checklist_is_memoised_per_analysis_id_on_a_read_only_connection(tmp_path):
    """`branch_rows` calls `posture` and `trend` for every branch, and `trend`
    itself calls `checklist` once per analysis in its window -- the SAME
    analysis id (a branch's own latest finished one) is asked for more than
    once inside one project-detail payload. A `read_only` connection must
    answer the second ask from its own cache rather than recomputing it --
    checked here by identity, not just equality, so a genuine recomputation
    (which would build a new tuple) cannot pass by accident."""
    db = tmp_path / "security.db"
    conn = ledger.connect(db)
    aid = _analysis(conn, "main", findings=[("high", "sast")])
    conn.close()

    ro = queries.read_only(db)
    first = queries.checklist(ro, aid)
    second = queries.checklist(ro, aid)
    assert second is first, "the second call must be the cached result"
    ro.close()


def test_two_read_only_connections_do_not_share_a_checklist_cache(tmp_path):
    """The cache lives on the connection object itself -- an ordinary
    instance attribute, not a module-level dict some other request's
    connection could reach into. It must not leak between two separate
    `read_only()` connections (two separate requests), and `close()` must
    drop it eagerly rather than leaving it to whenever GC gets around to the
    object."""
    db = tmp_path / "security.db"
    conn = ledger.connect(db)
    aid = _analysis(conn, "main", findings=[("high", "sast")])
    conn.close()

    ro1 = queries.read_only(db)
    ro2 = queries.read_only(db)
    assert ro1._checklist_cache is not ro2._checklist_cache

    queries.checklist(ro1, aid)
    assert aid in ro1._checklist_cache
    assert aid not in ro2._checklist_cache, \
        "one connection's cache must not be visible through another"

    ro1.close()
    assert ro1._checklist_cache is None, "close() must drop the cache eagerly"
    ro2.close()


def test_checklist_raises_analysisnotfound_instead_of_exiting(conn):
    """`queries.py` is a library the dashboard server calls with an id that
    comes straight from a URL -- `sys.exit()` on a bad id would take the
    whole control server down with it instead of answering 404. This must
    be a catchable exception, not a process exit."""
    with pytest.raises(queries.AnalysisNotFound, match="999"):
        queries.checklist(conn, 999)


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
    aid = _analysis(conn, "develop", findings=[("critical", "secret")])
    branch, posture, fell_back, latest = queries.default_branch_posture(conn, "web", "main")
    assert branch == "develop"
    assert fell_back is True
    assert posture["critical"] == 1
    assert latest["id"] == aid, "the row posture was computed from, handed back"

    _analysis(conn, "main", findings=[("low", "hygiene")])
    branch, posture, fell_back, _latest = queries.default_branch_posture(conn, "web", "main")
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


def test_index_summary_ignores_analyses_of_untracked_projects(conn):
    """Nothing prunes the ledger when a project is renamed or removed from
    projects.json -- its old analyses stay in the table forever. Scoping only
    `critical`/`high` and not `analyses`/`success_rate` would let a project no
    longer on screen keep inflating both."""
    _analysis(conn, "main", project="web", state="done",
              findings=[("critical", "secret")])
    _analysis(conn, "main", project="web", state="failed")
    # "gone" is not in project_names below -- a renamed or deleted project.
    _analysis(conn, "main", project="gone", state="done")
    _analysis(conn, "main", project="gone", state="done")
    _analysis(conn, "main", project="gone", state="done")

    s = queries.index_summary(conn, ["web"])
    assert s["analyses"] == 2, "only web's own two analyses, not gone's three"
    assert s["success_rate"] == pytest.approx(1 / 2), \
        "1 done of 2 finished for web -- gone's 3 done must not count"
    assert s["critical"] == 1


def test_index_summary_of_no_projects_is_an_explicit_empty_summary(conn):
    """Not `WHERE project IN ()` happening to mean nothing -- an empty
    `project_names` must read as an empty summary regardless of how many
    analyses exist for projects nobody asked about."""
    _analysis(conn, "main", project="web", state="done",
              findings=[("critical", "secret")])
    s = queries.index_summary(conn, [])
    assert s == {"projects": 0, "analyses": 0, "critical": 0, "high": 0,
                 "success_rate": None}


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


def test_trend_query_carries_the_id_tiebreak_in_its_order_by(conn):
    """Replaces `test_trend_orders_by_id_when_two_analyses_tie_on_started`,
    which forced a real tie on `started` and asserted the resulting order --
    but that order held with or without `, id` in the `ORDER BY`. Removing
    the tiebreak from the source and re-running that test at row counts from
    2 up to 5000 never made it fail: SQLite's own tie resolution happened to
    put the older row first regardless. A test that passes either way proves
    nothing and reads as if it does -- the same false-coverage trap the SQL
    itself was already bitten by.

    Assert the SQL text carries the guarantee instead of the outcome,
    captured via `sqlite3.Connection.set_trace_callback` -- the same
    technique used for this task's cost measurement. This fails immediately
    if `, id` is removed from `trend`'s `ORDER BY`, independent of how
    SQLite happens to resolve ties on any given build or row count."""
    _analysis(conn, "main", findings=[("high", "sast")])
    statements = []
    conn.set_trace_callback(statements.append)
    try:
        queries.trend(conn, "web", "main")
    finally:
        conn.set_trace_callback(None)
    select = next(s for s in statements if s.startswith("SELECT id, started FROM analysis"))
    assert "ORDER BY started, id" in select, \
        "the tiebreak belongs in the SQL text, not in however the engine breaks a tie"


def test_project_rows_reports_branch_posture_and_trend(conn):
    """A project with two branches, one of them the declared base. The row
    must reflect the base branch's own posture and trend, not either
    branch's blindly, and `analyses` counts the whole project."""
    aid_main = _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "feature-x", findings=[("low", "hygiene")])

    rows = queries.project_rows(
        conn, [{"name": "web", "base": "main", "description": "Web app"}])

    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "web"
    assert row["branch"] == "main", "the declared base, not the other branch"
    assert row["branch_fell_back"] is False
    assert row["posture"]["critical"] == 1
    assert row["analyses"] == 2, "both branches count toward the project total"
    assert [t["analysis_id"] for t in row["trend"]] == [aid_main], \
        "trend must be the base branch's own history"
    assert row["trend"][0]["open"] == 1


def test_recent_analyses_newest_first_open_only_for_finished(conn):
    aid_old = _analysis(conn, "main", findings=[("high", "sast")])
    aid_running = _analysis(conn, "main", state="running", findings=[])

    rows = queries.recent_analyses(conn, limit=5)

    assert [r["id"] for r in rows] == [aid_running, aid_old], "newest first"
    assert rows[0]["open"] is None, "a running analysis has no posture yet"
    assert rows[1]["open"] == 1, "a finished analysis reports its open count"


def test_severity_totals_sums_branches_and_excludes_resolved(conn):
    """Open findings by severity across the latest analysis of every branch --
    summed, and a resolved (accepted/false_positive) finding does not count."""
    _analysis(conn, "main", findings=[("critical", "secret"), ("high", "sast")])
    aid_dev = _analysis(conn, "develop", findings=[("high", "sast")])
    fp = ledger.findings_of(conn, aid_dev)[0]["fingerprint"]
    ledger.set_decision(conn, "web", fp, "accepted", "known risk, tracked", "tester")

    totals = queries.severity_totals(conn, "web")

    assert totals["critical"] == 1, "main's only"
    assert totals["high"] == 1, "main's high counts; develop's high is resolved"
    assert totals["total"] == 2


def test_activity_summary_counts_per_kind_seeded_from_event_kinds(conn):
    """Counts per kind, seeded from EVENT_KINDS -- an absent kind reads 0
    rather than being missing from the dict entirely."""
    ledger.record_event(conn, "web", "analysis_started")
    ledger.record_event(conn, "web", "analysis_started")
    ledger.record_event(conn, "web", "decision_made")

    summary = queries.activity_summary(conn, "web")

    assert set(summary) == set(ledger.EVENT_KINDS)
    assert summary["analysis_started"] == 2
    assert summary["decision_made"] == 1
    assert summary["settings_changed"] == 0
    assert summary["report_exported"] == 0


def test_the_browser_unions_the_latest_analysis_of_every_branch(conn):
    _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "develop", findings=[("high", "sast")])
    got = queries.finding_rows(conn, "web")
    assert got["total"] == 2
    assert {r["branch"] for r in got["rows"]} == {"main", "develop"}


def test_resolved_findings_are_hidden_unless_asked_for(conn):
    a1 = _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "main", findings=[])          # the secret is gone -> fixed
    assert queries.finding_rows(conn, "web")["total"] == 0
    shown = queries.finding_rows(conn, "web", {"show_resolved": True})
    assert [r["state"] for r in shown["rows"]] == ["fixed"]


def test_unique_counts_fingerprints_not_rows(conn):
    """189 findings across branches can be 93 problems. The two numbers answer
    different questions and the screen shows both."""
    fp = "d" * 64
    for br in ("main", "develop"):
        aid = ledger.start_analysis(conn, "web", "web", br, "s", "quick", "r")
        ledger.record_finding(conn, aid, {
            "fingerprint": fp, "category": "secret", "rule": "aws_access_key",
            "severity": "critical", "title": "t", "occurrences": []})
        ledger.mark_prepared(conn, aid)
        ledger.finish_analysis(conn, aid, "done")
    got = queries.finding_rows(conn, "web")
    assert got["total"] == 2
    assert got["unique"] == 1


def test_first_seen_is_the_oldest_analysis_carrying_the_fingerprint(conn):
    a1 = _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "main", findings=[("critical", "secret")])
    row = queries.finding_rows(conn, "web")["rows"][0]
    first = conn.execute("SELECT started FROM analysis WHERE id=?", (a1,)).fetchone()
    assert row["first_seen"] == first["started"]


def test_filters_narrow_the_set(conn):
    _analysis(conn, "main", findings=[("critical", "secret"), ("low", "hygiene")])
    assert queries.finding_rows(conn, "web", {"severity": ["critical"]})["total"] == 1
    assert queries.finding_rows(conn, "web", {"category": ["hygiene"]})["total"] == 1
    assert queries.finding_rows(conn, "web", {"q": "hygiene"})["total"] == 1


def test_an_unknown_sort_column_is_refused(conn):
    """The values are parameters; the sort column is interpolated by nature, so
    it is the one route parameters cannot protect."""
    _analysis(conn, "main", findings=[("critical", "secret")])
    with pytest.raises(ValueError):
        queries.finding_rows(conn, "web", sort="severity; DROP TABLE finding")


def test_page_size_is_capped(conn):
    _analysis(conn, "main", findings=[("low", "hygiene")] * 5)
    got = queries.finding_rows(conn, "web", per_page=10_000)
    assert got["per_page"] <= queries.MAX_PER_PAGE
