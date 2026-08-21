import time

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
    s = queries.index_summary(conn, [{"name": "web", "base": "main"}])
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

    s = queries.index_summary(conn, [{"name": "web", "base": "main"}])
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
                 "capped_projects": 0, "fell_back_projects": 0,
                 "success_rate": None}


def test_index_summary_counts_projects_whose_latest_analysis_is_capped(conn):
    """A `capped` analysis is a PARTIAL read of the repository -- its
    contribution to `critical`/`high` above means "none found before it
    stopped," not "none" (the identical notice `secPaint` gives on the
    analysis screen). `capped_projects` is what lets the KPI cards say the
    fleet total may be an undercount instead of presenting it as complete."""
    _analysis(conn, "main", project="capped-proj", state="capped",
              findings=[("critical", "secret")])
    _analysis(conn, "main", project="done-proj", state="done",
              findings=[("high", "sast")])

    s = queries.index_summary(conn, [{"name": "capped-proj", "base": "main"},
                                 {"name": "done-proj", "base": "main"}])
    assert s["capped_projects"] == 1, "only capped-proj's latest analysis is capped"

    # A project not in project_names must not count, exactly like every other
    # field index_summary already scopes.
    s_scoped = queries.index_summary(conn, [{"name": "done-proj", "base": "main"}])
    assert s_scoped["capped_projects"] == 0


def test_index_summary_and_project_rows_resolve_the_same_branch(conn):
    """Final whole-branch review, CRITICAL 1. `index_summary` takes the SAME
    project dicts `project_rows` does, so both halves of the index screen
    pick a project's branch the same way. Given only names it could never
    honour a declared base, and `default_branch_posture(conn, name, None)`
    ALWAYS took the fallback path -- the cards summing one branch while the
    table three inches below described another.

    Deliberately MULTI-BRANCH: every other `index_summary` fixture here has
    one branch, which is exactly why nothing caught this. `main` is the
    declared base and stopped early holding a high finding; `develop` was
    analysed afterwards (so it wins the fallback) and is clean."""
    projects = [{"name": "web", "base": "main", "description": ""}]
    _analysis(conn, "main", state="capped", findings=[("high", "sast")])
    _analysis(conn, "develop", state="done")

    s = queries.index_summary(conn, projects)
    row = queries.project_rows(conn, projects)[0]

    assert row["branch"] == "main"
    assert s["high"] == row["posture"]["high"] == 1, \
        f"the cards and the table describe different branches: {s} vs {row}"
    assert s["capped_projects"] == 1, \
        "the base branch's latest analysis is capped and the cards did not notice"


def test_index_summary_counts_projects_read_off_a_branch_nobody_declared(conn):
    """The table names a fallback branch out loud per row; the cards, summing
    those same postures, said nothing at all -- and a fallback branch is
    never silent in this area."""
    projects = [{"name": "web", "base": "main", "description": ""}]
    _analysis(conn, "develop", findings=[("critical", "secret")])

    s = queries.index_summary(conn, projects)

    assert queries.project_rows(conn, projects)[0]["branch_fell_back"] is True
    assert s["fell_back_projects"] == 1, f"the cards say nothing: {s}"
    assert s["critical"] == 1


def test_top_categories_group_by_rule(conn):
    _analysis(conn, "main", findings=[("high", "sast"), ("high", "sast"),
                                      ("low", "hygiene")])
    cats = queries.top_categories(conn, "web")
    assert cats[0]["rule"] == "sast-rule"
    assert cats[0]["count"] == 2


def test_top_categories_accepts_a_list_of_projects_and_excludes_others(conn):
    """`categories` used to read the whole ledger regardless of `--projects`
    -- the same gap `recent_analyses`/`severity_totals` had. Ranking must
    happen across the given projects TOGETHER (not each project's own top
    `limit` merged afterwards), which is exactly what summing all of them
    into one `counts` dict before ranking already does."""
    _analysis(conn, "main", project="web", findings=[("high", "sast")])
    _analysis(conn, "main", project="gone", findings=[("critical", "secret")])

    cats = queries.top_categories(conn, project=["web"])

    assert [c["rule"] for c in cats] == ["sast-rule"], \
        "gone's rule leaked into the rollup: " + repr(cats)


def test_top_categories_with_no_project_argument_stays_fleet_wide(conn):
    """Containment probe: the default must still rank across the whole
    ledger, which every other caller of this function relies on."""
    _analysis(conn, "main", project="web", findings=[("high", "sast")])
    _analysis(conn, "main", project="gone", findings=[("critical", "secret")])
    cats = queries.top_categories(conn)
    assert {c["rule"] for c in cats} == {"sast-rule", "secret-rule"}


def test_branch_rows_one_per_branch_newest_first(conn):
    _analysis(conn, "main", findings=[("low", "hygiene")])
    _analysis(conn, "develop", findings=[("critical", "secret")])
    rows = queries.branch_rows(conn, "web")
    assert [r["branch"] for r in rows] == ["develop", "main"]
    assert rows[0]["open"]["critical"] == 1


def test_branch_rows_carry_the_state_their_posture_was_read_from(conn):
    """Final whole-branch review, CRITICAL 3. `branch_rows` selected
    `state IN ('done','capped')` and returned no state, so the one screen
    whose entire purpose is per-branch posture was the only posture surface
    in the area that could not say a read was partial. The trend points
    carry it too, or the trend line asserts a direction across a run that
    simply stopped before finding anything."""
    _analysis(conn, "main", state="capped", findings=[("high", "sast")])
    _analysis(conn, "develop", findings=[("low", "hygiene")])

    rows = {r["branch"]: r for r in queries.branch_rows(conn, "web")}

    assert rows["main"]["state"] == "capped", \
        f"a partial read presents as a finished one: {rows['main']}"
    assert rows["develop"]["state"] == "done"
    assert [p["state"] for p in rows["main"]["trend"]] == ["capped"]
    assert [p["state"] for p in rows["develop"]["trend"]] == ["done"]


def test_capped_branch_count_is_the_rollup_cue_for_every_analysed_branch(conn):
    """The sidebar donut and the findings strip roll every analysed branch
    into one number, so neither can carry the per-row `incomplete` badge the
    index table and the Overview panel already use. This is that cue as a
    count -- and it reads exactly the analyses those two rollups read, the
    latest finished one per analysed scope."""
    _analysis(conn, "main", state="capped", findings=[("high", "sast")])
    _analysis(conn, "develop", findings=[("low", "hygiene")])
    assert queries.capped_branch_count(conn, "web") == 1

    # A LATER done analysis of the same branch replaces the capped one as
    # what the rollup reads, so the cue has to go away with it.
    _analysis(conn, "main", findings=[("high", "sast")])
    assert queries.capped_branch_count(conn, "web") == 0


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
    select = next(s for s in statements
                  if s.startswith("SELECT id, started, state FROM analysis"))
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
    assert row["last_state"] == "done", "the row must carry the state posture was computed from"


def test_project_rows_carries_the_capped_state_for_an_incomplete_analysis(conn):
    """A `capped` analysis is a PARTIAL read of the repository -- the same
    notice `secPaint` gives on the analysis screen. `last_state` is what
    lets the index screen's project row say so instead of rendering the
    posture as if the analysis had finished."""
    _analysis(conn, "main", state="capped", findings=[("critical", "secret")])
    rows = queries.project_rows(
        conn, [{"name": "web", "base": "main", "description": ""}])
    assert rows[0]["last_state"] == "capped"


def test_project_rows_of_a_never_analysed_project_carries_no_state(conn):
    rows = queries.project_rows(
        conn, [{"name": "nothing-yet", "base": "main", "description": ""}])
    assert rows[0]["last_state"] == ""


# ---- review fix (MINOR): "Never analysed" was shown to a project whose
# analyses all failed. `most_recent_started` is the shared fallback that lets
# `project_rows` (index screen) and `cmd_project_data` (project screen) both
# tell "never touched" apart from "attempted, never finished" with the same
# one-line `or most_recent_started(...)`.

def test_most_recent_started_of_a_project_with_no_analyses_is_zero(conn):
    assert queries.most_recent_started(conn, "nothing-yet") == 0


def test_most_recent_started_reads_a_failed_analysis(conn):
    """`default_branch_posture`'s own `latest` only ever considers
    done/capped rows, so a project whose every analysis failed reads as
    though it had never been analysed at all through that alone -- this is
    the fallback that tells the two apart."""
    aid = _analysis(conn, "main", state="failed", findings=[])
    row = conn.execute("SELECT started FROM analysis WHERE id=?", (aid,)).fetchone()
    assert queries.most_recent_started(conn, "web") == row["started"]


def test_most_recent_started_is_scoped_to_the_project(conn):
    """Containment probe: another project's analysis must not leak in."""
    _analysis(conn, "main", state="failed", project="other", findings=[])
    assert queries.most_recent_started(conn, "web") == 0


def test_project_rows_last_started_falls_back_to_a_failed_attempt(conn):
    """The rendering-facing half: `last_started` must carry the failed
    attempt's own time rather than 0, which secIndexProjectRow's else-branch
    would otherwise render as `fmtAgo(0)` ("never") right beside the
    project's own analyses count saying there WAS one."""
    aid = _analysis(conn, "main", state="failed", findings=[])
    row = conn.execute("SELECT started FROM analysis WHERE id=?", (aid,)).fetchone()

    rows = queries.project_rows(conn, [{"name": "web", "base": "main", "description": ""}])

    assert rows[0]["last_started"] == row["started"]
    assert rows[0]["last_state"] == "", "no finished analysis -- last_state stays empty"
    assert rows[0]["analyses"] == 1


# ---- review fix (IMPORTANT): the Runs table's FINDINGS column used to cost
# one checklist() call per done/capped row. finding_counts_by_analysis is a
# plain, grouped COUNT(*) -- one query for the whole project, never one per
# row, and never filtered by state.

def test_finding_counts_by_analysis_is_one_query_for_the_whole_project(conn):
    """Regression guard for the measured cost: five done analyses on one
    branch used to mean five separate checklist() calls (findings_of x2, a
    history scan, decisions_for, EACH) from the Runs-tab loop. This is one
    grouped query, however many analyses exist."""
    for _ in range(5):
        _analysis(conn, "main", findings=[("high", "sast"), ("low", "hygiene")])
    statements = []
    conn.set_trace_callback(statements.append)
    try:
        counts = queries.finding_counts_by_analysis(conn, "web")
    finally:
        conn.set_trace_callback(None)
    assert len(statements) == 1, \
        f"expected exactly one grouped query, got {len(statements)}: {statements}"
    assert len(counts) == 5 and all(c == 2 for c in counts.values()), counts


def test_finding_counts_by_analysis_is_scoped_to_the_project(conn):
    _analysis(conn, "main", project="web", findings=[("high", "sast")])
    aid_other = _analysis(conn, "main", project="other", findings=[("critical", "secret")] * 3)
    counts = queries.finding_counts_by_analysis(conn, "web")
    assert aid_other not in counts, "another project's analysis leaked into the count"


def test_finding_counts_by_analysis_counts_a_running_analysiss_partial_findings_too(conn):
    """The function itself gates on nothing -- `cmd_project_data` is what
    decides a running/failed row shows no number yet (see its own comment);
    this is a plain COUNT(*), so it must count whatever is actually in the
    ledger for an id, regardless of the analysis's own state."""
    aid = _analysis(conn, "main", state="running", findings=[("high", "sast")])
    counts = queries.finding_counts_by_analysis(conn, "web")
    assert counts[aid] == 1


def test_the_runs_row_count_and_the_checklist_total_legitimately_disagree(conn):
    """Reproduction for the Runs table's own review finding (IMPORTANT): a row
    can say "Findings: 1" while that same analysis's checklist chips total 2,
    and BOTH are right.

    Analysis #1 records two findings on `main`. Analysis #2 re-reports only
    one of them (the "secret" fingerprint repeats; the "hygiene" one is not
    recorded again). `finding_counts_by_analysis` answers "how many did THIS
    run record" -- 1, a fact about analysis #2 alone. `checklist()` answers
    "what is open right now" for #2 -- it also carries the missing "hygiene"
    finding forward as `fixed` (a deterministic category, proven the moment
    `prepare` completed), so its own total is 2.

    This is not a bug to reconcile -- see finding_counts_by_analysis's own
    docstring and the Runs table header's title -- it is pinned here so a
    later "fix" does not quietly make one number swallow the other."""
    _analysis(conn, "main", findings=[("high", "secret"), ("low", "hygiene")])
    aid2 = _analysis(conn, "main", findings=[("high", "secret")])

    row_count = queries.finding_counts_by_analysis(conn, "web")[aid2]
    _analysis_row, checklist_findings = queries.checklist(conn, aid2)

    assert row_count == 1, f"the Runs row should report what #2 itself recorded: {row_count}"
    assert len(checklist_findings) == 2, \
        f"the checklist must still carry the missing finding forward: {checklist_findings}"
    assert row_count != len(checklist_findings), \
        "the row count and the checklist total must be free to disagree"
    states = {f["fingerprint"]: f["state"] for f in checklist_findings}
    assert len(states) == 2
    fixed = [fp for fp, s in states.items() if s == "fixed"]
    assert len(fixed) == 1, f"the carried-forward finding must show as fixed: {states}"


# ---- review fix (IMPORTANT): two different "posture" numbers on one screen.
# analysed_branch_count is the number the project screen's sidebar caption
# names, so a two-branch project and a one-branch project never look alike.

def test_analysed_branch_count_counts_distinct_finished_branches(conn):
    _analysis(conn, "main", findings=[("high", "sast")])
    _analysis(conn, "develop", findings=[("low", "hygiene")])
    assert queries.analysed_branch_count(conn, "web") == 2


def test_analysed_branch_count_ignores_a_branch_with_no_finished_analysis(conn):
    """Containment probe: a branch that only ever failed must not inflate
    the count the sidebar caption reports -- `severity_totals`/
    `top_categories` never roll up anything from it either."""
    _analysis(conn, "main", findings=[("high", "sast")])
    _analysis(conn, "develop", state="failed", findings=[])
    assert queries.analysed_branch_count(conn, "web") == 1


def test_analysed_branch_count_of_an_unanalysed_project_is_zero(conn):
    assert queries.analysed_branch_count(conn, "nothing-yet") == 0


def test_recent_analyses_newest_first_open_only_for_finished(conn):
    aid_old = _analysis(conn, "main", findings=[("high", "sast")])
    aid_running = _analysis(conn, "main", state="running", findings=[])

    rows = queries.recent_analyses(conn, limit=5)

    assert [r["id"] for r in rows] == [aid_running, aid_old], "newest first"
    assert rows[0]["open"] is None, "a running analysis has no posture yet"
    assert rows[1]["open"] == 1, "a finished analysis reports its open count"


def test_recent_analyses_scoped_to_a_project_list_excludes_others(conn):
    """The index screen's `recent` feed used to read the whole ledger while
    `summary`/`projects` were already scoped to `--projects` -- a project
    disabled or removed from projects.json still surfaced here. `projects=`
    is the fix: given a list, only analyses of those projects come back."""
    aid_web = _analysis(conn, "main", project="web", findings=[("high", "sast")])
    _analysis(conn, "main", project="gone", findings=[("critical", "secret")])

    rows = queries.recent_analyses(conn, projects=["web"])

    assert [r["id"] for r in rows] == [aid_web]


def test_recent_analyses_of_an_empty_project_list_is_explicitly_empty(conn):
    """An empty list must mean "no projects", not "no filter" -- the same
    explicit-empty reasoning `index_summary` already applies. Left to
    however `WHERE project IN ()` behaves, this would silently fall back to
    the OLD unscoped behaviour finding 2 exists to close."""
    _analysis(conn, "main", project="web", findings=[("high", "sast")])
    assert queries.recent_analyses(conn, projects=[]) == []


def test_recent_analyses_with_no_projects_argument_stays_fleet_wide(conn):
    """The default (`projects=None`) must keep its old unscoped behaviour --
    the containment probe for the fix above: scoping `index-data`'s call
    must not quietly narrow every OTHER caller of this function too."""
    aid_web = _analysis(conn, "main", project="web", findings=[("high", "sast")])
    aid_gone = _analysis(conn, "main", project="gone", findings=[("critical", "secret")])
    ids = {r["id"] for r in queries.recent_analyses(conn, limit=10)}
    assert {aid_web, aid_gone} <= ids


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


def test_severity_totals_accepts_a_list_of_projects_and_excludes_others(conn):
    """`donut` used to read the whole ledger regardless of `--projects` --
    the same gap `recent_analyses` had. A list of names sums each named
    project's own totals (already correctly merged across ITS branches by
    `posture`) without folding in a project that was never asked for."""
    _analysis(conn, "main", project="web", findings=[("high", "sast")])
    _analysis(conn, "main", project="gone", findings=[("critical", "secret")])

    totals = queries.severity_totals(conn, project=["web"])

    assert totals["high"] == 1
    assert totals["critical"] == 0, "gone's critical finding must not leak in"
    assert totals["total"] == 1


def test_severity_totals_with_no_project_argument_stays_fleet_wide(conn):
    """Containment probe: the default must still answer for the whole
    ledger, the behaviour every other caller of this function relies on."""
    _analysis(conn, "main", project="web", findings=[("high", "sast")])
    _analysis(conn, "main", project="gone", findings=[("critical", "secret")])
    totals = queries.severity_totals(conn)
    assert totals["high"] == 1
    assert totals["critical"] == 1


def test_severity_totals_and_top_categories_count_one_fingerprint_once_across_branches(conn):
    """The reviewer's exact reproduction. A fingerprint never includes the
    branch, so the same committed secret open on `main` AND `develop` is ONE
    problem needing one rotation -- exactly what `finding_rows`'s own
    total/unique split already says elsewhere on this same screen (189
    findings can be 93 problems). Summing each branch's posture -- what both
    functions used to do -- counted it twice, on both the donut and the
    category rollup that feeds off the same numbers."""
    fp = "e" * 64
    for br in ("main", "develop"):
        aid = ledger.start_analysis(conn, "web", "web", br, "s", "quick", "r")
        ledger.record_finding(conn, aid, {
            "fingerprint": fp, "category": "secret", "rule": "aws_access_key",
            "severity": "critical", "title": "t", "occurrences": []})
        ledger.mark_prepared(conn, aid)
        ledger.finish_analysis(conn, aid, "done")

    totals = queries.severity_totals(conn, "web")
    assert totals["critical"] == 1, "one secret on two branches is one critical, not two"
    assert totals["total"] == 1

    cats = queries.top_categories(conn, "web")
    assert cats == [{"rule": "aws_access_key", "count": 1}]


def test_severity_totals_and_top_categories_do_not_collapse_distinct_fingerprints(conn):
    """The containment probe for the fix above. Two DIFFERENT secrets, each
    open on its own branch, sharing the SAME rule -- the nearest case a
    fingerprint-based fix could wrongly sweep up if it deduped by rule or
    category instead of by fingerprint. Two genuinely distinct problems must
    still be reported as two; a fix that made this one collapse to one would
    be broken the other way."""
    for br, fp in (("main", "a" * 64), ("develop", "b" * 64)):
        aid = ledger.start_analysis(conn, "web", "web", br, "s", "quick", "r")
        ledger.record_finding(conn, aid, {
            "fingerprint": fp, "category": "secret", "rule": "aws_access_key",
            "severity": "critical", "title": "t", "occurrences": []})
        ledger.mark_prepared(conn, aid)
        ledger.finish_analysis(conn, aid, "done")

    totals = queries.severity_totals(conn, "web")
    assert totals["critical"] == 2, "two distinct secrets must not collapse into one"

    cats = queries.top_categories(conn, "web")
    assert cats == [{"rule": "aws_access_key", "count": 2}]


def test_posture_rollups_take_no_time_window(conn):
    """Both of these used to accept a `days=30` they never read, and neither
    caller ever passed it -- a signature promising a filter the body does not
    apply. Whoever eventually wrote `days=7` would have got an all-time answer
    that looked like a weekly one, with nothing failing to say so.

    The parameter is gone rather than implemented, because a POSTURE number is
    as-of-now by construction: it is read off each branch's LATEST finished
    analysis, and a critical finding does not stop being open because nobody
    re-analysed that branch this month. A window here would not narrow the
    answer, it would drop quiet branches out of it and report them clean.

    Pinned as a probe, not as trivia: re-adding an ignored `days` is exactly
    the kind of change that reads as harmless in a diff. Proved below by an
    analysis that is far older than any window anybody would pick -- it must
    still be counted."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "sha", "quick", "r")
    ledger.record_finding(conn, aid, {
        "fingerprint": "a" * 64, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "occurrences": []})
    ledger.mark_prepared(conn, aid)
    ledger.finish_analysis(conn, aid, "done")
    # A year ago -- older than 30 days, older than any period the Activity
    # screen offers, and still open.
    long_ago = int(time.time()) - 365 * 86400
    conn.execute("UPDATE analysis SET started=?, ended=? WHERE id=?",
                 (long_ago, long_ago, aid))
    conn.commit()

    assert queries.severity_totals(conn, "web")["critical"] == 1
    assert queries.top_categories(conn, "web") == [
        {"rule": "aws_access_key", "count": 1}]

    with pytest.raises(TypeError):
        queries.severity_totals(conn, "web", days=7)
    with pytest.raises(TypeError):
        queries.top_categories(conn, "web", days=7)


def test_severity_totals_keeps_the_more_severe_of_two_branches(conn):
    """The agent can re-triage a finding's severity between runs, so the same
    fingerprint can legitimately carry a different severity on two branches'
    latest analyses. The MORE severe one must win: a posture summary that
    under-reports the worst assessment ever made of a finding is the wrong
    way to be wrong -- an operator reading "high" while one branch's own
    analysis called it "critical" is worse served than one reading
    "critical" for a finding a later run downgraded."""
    fp = "c" * 64
    for br, sev in (("main", "high"), ("develop", "critical")):
        aid = ledger.start_analysis(conn, "web", "web", br, "s", "quick", "r")
        ledger.record_finding(conn, aid, {
            "fingerprint": fp, "category": "secret", "rule": "aws_access_key",
            "severity": sev, "title": "t", "occurrences": []})
        ledger.mark_prepared(conn, aid)
        ledger.finish_analysis(conn, aid, "done")

    totals = queries.severity_totals(conn, "web")
    assert totals["critical"] == 1, "the more severe assessment must win"
    assert totals["high"] == 0, "must not also be counted a second time as the lesser severity"
    assert totals["total"] == 1


def test_a_fingerprint_resolved_on_one_branch_and_open_on_another_counts_once_as_open(conn):
    """The choice made explicit: OPEN wins over RESOLVED. Same fingerprint,
    fixed on `main` (it dropped out of main's own latest scan) but still open
    critical on both `develop` and `hotfix`. The resolved branch must not
    make the finding disappear from the rollup.

    TWO open branches are used rather than one, deliberately: a lone
    resolved/open PAIR already sums to 1 on the pre-fix code by coincidence
    -- `posture()` already excludes a resolved finding from its OWN branch's
    count, so with only one branch left open, "sum every branch's posture"
    and "dedupe by fingerprint" agree by accident, and a test built from just
    that pair would pass before this fix too, proving nothing. Adding the
    third, also-open branch is what actually exercises the double-counting
    bug this fix closes, while still keeping one branch genuinely resolved
    to prove that resolved-elsewhere does not suppress the still-open
    finding."""
    fp = "d" * 64
    aid_main1 = ledger.start_analysis(conn, "web", "web", "main", "s1", "quick", "r")
    ledger.record_finding(conn, aid_main1, {
        "fingerprint": fp, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "occurrences": []})
    ledger.mark_prepared(conn, aid_main1)
    ledger.finish_analysis(conn, aid_main1, "done")
    # A second, later analysis of `main` records nothing -> the fingerprint
    # is gone from main's own latest scan, so `checklist` marks it "fixed".
    aid_main2 = ledger.start_analysis(conn, "web", "web", "main", "s2", "quick", "r")
    ledger.mark_prepared(conn, aid_main2)
    ledger.finish_analysis(conn, aid_main2, "done")

    for br in ("develop", "hotfix"):
        aid = ledger.start_analysis(conn, "web", "web", br, "s", "quick", "r")
        ledger.record_finding(conn, aid, {
            "fingerprint": fp, "category": "secret", "rule": "aws_access_key",
            "severity": "critical", "title": "t", "occurrences": []})
        ledger.mark_prepared(conn, aid)
        ledger.finish_analysis(conn, aid, "done")

    _an, main_findings = queries.checklist(conn, aid_main2)
    assert main_findings[0]["state"] == "fixed", "the setup must actually resolve it on main"

    totals = queries.severity_totals(conn, "web")
    assert totals["critical"] == 1, \
        "resolved-on-main must not hide it, and open-on-two-branches must still be one"
    assert totals["total"] == 1

    cats = queries.top_categories(conn, "web")
    assert cats == [{"rule": "aws_access_key", "count": 1}]


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


def test_fixed_by_severity_lets_the_hidden_count_exempt_a_fixed_finding(conn):
    """The findings browser (ui/security/findings-screen.js) exempts a FIXED
    finding from its severity floor, the same exemption `secVisible` already
    gives the single-analysis checklist -- and its own "N hidden" count needs
    this field to keep agreeing with that: `by_severity` alone cannot tell a
    fixed low-severity finding apart from an OPEN one sitting in the very
    same bucket, which is exactly what a floor-hidden count that just
    subtracted the wrong thing would do."""
    # "high sast" sits at index 0 in both calls -> same fingerprint, stays
    # open. "low secret" only exists in the first call -> gone from the
    # second -> checklist marks it fixed.
    _analysis(conn, "main", findings=[("high", "sast"), ("low", "secret")])
    _analysis(conn, "main", findings=[("high", "sast")])
    got = queries.finding_rows(conn, "web", {"show_resolved": True})
    assert got["by_severity"]["low"] == 1
    assert got["fixed_by_severity"]["low"] == 1, "the closed low finding must count as fixed"
    assert got["fixed_by_severity"]["high"] == 0, "the still-open high finding must not"


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


def test_first_seen_ignores_a_failed_analysis_and_uses_the_done_one(conn):
    """A finding recorded by a FAILED analysis before it fell over, then
    recorded again by a DONE analysis later, must report the done one's
    timestamp -- the failed run never proved the finding held, so its earlier
    sighting must not make the finding look older than any successful
    analysis ever confirmed. Moving the failed row's own `started` earlier
    (rather than relying on wall-clock ordering) makes this fail on the
    current code deterministically: without the `state IN ('done','capped')`
    filter, MIN(started) picks the failed run's earlier timestamp instead."""
    a1 = _analysis(conn, "main", state="failed", findings=[("critical", "secret")])
    conn.execute("UPDATE analysis SET started = started - 1000 WHERE id=?", (a1,))
    conn.commit()
    a2 = _analysis(conn, "main", findings=[("critical", "secret")])

    row = queries.finding_rows(conn, "web")["rows"][0]
    second = conn.execute("SELECT started FROM analysis WHERE id=?", (a2,)).fetchone()
    assert row["first_seen"] == second["started"], \
        "the failed analysis's earlier timestamp must not count as first_seen"


def test_filters_narrow_the_set(conn):
    _analysis(conn, "main", findings=[("critical", "secret"), ("low", "hygiene")])
    assert queries.finding_rows(conn, "web", {"severity": ["critical"]})["total"] == 1
    assert queries.finding_rows(conn, "web", {"category": ["hygiene"]})["total"] == 1
    assert queries.finding_rows(conn, "web", {"q": "hygiene"})["total"] == 1


def test_branch_filter_narrows_to_the_named_branch(conn):
    _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "develop", findings=[("high", "sast")])
    got = queries.finding_rows(conn, "web", {"branch": ["develop"]})
    assert got["total"] == 1
    assert got["rows"][0]["branch"] == "develop"


def test_analysis_filter_narrows_to_the_named_analysis_id(conn):
    a1 = _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "develop", findings=[("high", "sast")])
    got = queries.finding_rows(conn, "web", {"analysis": [a1]})
    assert got["total"] == 1
    assert got["rows"][0]["analysis_id"] == a1


def test_fingerprint_filter_matches_a_prefix(conn):
    """The Activity screen's own deep link (Task 12) carries only the first
    12 characters of a fingerprint -- `related` on a `decision_made` event is
    truncated by `cmd_decide` -- so this filter has to match a PREFIX, not
    the exact 64-character string `report-finding` requires at its own door."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "s", "quick", "r")
    fp_a = "a" * 64
    fp_b = "b" * 64
    ledger.record_finding(conn, aid, {
        "fingerprint": fp_a, "category": "secret", "rule": "r1",
        "severity": "critical", "title": "one", "occurrences": []})
    ledger.record_finding(conn, aid, {
        "fingerprint": fp_b, "category": "secret", "rule": "r2",
        "severity": "critical", "title": "two", "occurrences": []})
    ledger.mark_prepared(conn, aid)
    ledger.finish_analysis(conn, aid, "done")

    got = queries.finding_rows(conn, "web", {"fingerprint": fp_a[:12]})
    assert got["total"] == 1
    assert got["rows"][0]["fingerprint"] == fp_a

    assert queries.finding_rows(conn, "web", {"fingerprint": "nope"})["total"] == 0
    # An empty filter is the same as no filter at all -- narrows nothing.
    assert queries.finding_rows(conn, "web", {"fingerprint": ""})["total"] == 2


def test_state_filter_selects_only_the_named_state(conn):
    _analysis(conn, "main", findings=[("critical", "secret")])
    _analysis(conn, "main", findings=[])            # the secret is now fixed
    _analysis(conn, "develop", findings=[("high", "sast")])  # still new

    fixed = queries.finding_rows(conn, "web", {"show_resolved": True, "state": ["fixed"]})
    assert [r["state"] for r in fixed["rows"]] == ["fixed"]

    new_only = queries.finding_rows(conn, "web", {"state": ["new"]})
    assert [r["state"] for r in new_only["rows"]] == ["new"]
    assert new_only["rows"][0]["branch"] == "develop"


def test_path_filter_matches_case_insensitively_on_both_sides(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "s", "quick", "r")
    ledger.record_finding(conn, aid, {
        "fingerprint": "f" * 64, "category": "secret", "rule": "r",
        "severity": "critical", "title": "t",
        "occurrences": [{"file": "src/Auth/Login.PY", "line": 1, "snippet_hash": "h"}]})
    ledger.mark_prepared(conn, aid)
    ledger.finish_analysis(conn, aid, "done")

    assert queries.finding_rows(conn, "web", {"path": "auth/login"})["total"] == 1, \
        "a lowercase needle must match a mixed-case path"
    assert queries.finding_rows(conn, "web", {"path": "AUTH/LOGIN"})["total"] == 1, \
        "an uppercase needle must match too"
    assert queries.finding_rows(conn, "web", {"path": "nope"})["total"] == 0


def test_q_filter_matches_case_insensitively_on_both_sides(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "s", "quick", "r")
    ledger.record_finding(conn, aid, {
        "fingerprint": "g" * 64, "category": "secret", "rule": "aws_KEY",
        "severity": "critical", "title": "Hardcoded AWS Secret", "occurrences": []})
    ledger.mark_prepared(conn, aid)
    ledger.finish_analysis(conn, aid, "done")

    assert queries.finding_rows(conn, "web", {"q": "hardcoded"})["total"] == 1
    assert queries.finding_rows(conn, "web", {"q": "AWS SECRET"})["total"] == 1
    assert queries.finding_rows(conn, "web", {"q": "nonexistent"})["total"] == 0


def test_an_unknown_sort_column_is_refused(conn):
    """The values are parameters; the sort column is interpolated by nature, so
    it is the one route parameters cannot protect."""
    _analysis(conn, "main", findings=[("critical", "secret")])
    with pytest.raises(ValueError):
        queries.finding_rows(conn, "web", sort="severity; DROP TABLE finding")


def test_an_unknown_direction_is_refused(conn):
    _analysis(conn, "main", findings=[("critical", "secret")])
    with pytest.raises(ValueError):
        queries.finding_rows(conn, "web", direction="sideways")


def test_sort_by_severity_desc_is_critical_first(conn):
    """`desc` means "most severe first" -- critical, not the alphabetically
    last severity name. No test asserted actual row order before this one, so
    an edit flipping the sort's reverse expression would have passed the
    whole suite while silently inverting triage order for an operator."""
    _analysis(conn, "main", findings=[("low", "hygiene"), ("critical", "secret"),
                                      ("medium", "sast")])
    got = queries.finding_rows(conn, "web", sort="severity", direction="desc")
    assert [r["severity"] for r in got["rows"]] == ["critical", "medium", "low"]


def test_sort_by_severity_asc_is_critical_last(conn):
    _analysis(conn, "main", findings=[("low", "hygiene"), ("critical", "secret"),
                                      ("medium", "sast")])
    got = queries.finding_rows(conn, "web", sort="severity", direction="asc")
    assert [r["severity"] for r in got["rows"]] == ["low", "medium", "critical"]


def test_sort_by_title_ascending_and_descending(conn):
    _analysis(conn, "main", findings=[("low", "hygiene"), ("critical", "secret"),
                                      ("medium", "sast")])
    # titles are "{severity} {category}": "low hygiene", "critical secret",
    # "medium sast" -- alphabetically "critical..." < "low..." < "medium...".
    asc = queries.finding_rows(conn, "web", sort="title", direction="asc")
    assert [r["title"] for r in asc["rows"]] == \
        ["critical secret", "low hygiene", "medium sast"]

    desc = queries.finding_rows(conn, "web", sort="title", direction="desc")
    assert [r["title"] for r in desc["rows"]] == \
        ["medium sast", "low hygiene", "critical secret"]


def test_sort_by_first_seen_ascending_and_descending(conn):
    a_old = _analysis(conn, "old", findings=[("critical", "secret")])
    a_mid = _analysis(conn, "mid", findings=[("high", "dependency")])
    a_new = _analysis(conn, "new", findings=[("low", "hygiene")])
    # Pinned rather than relying on wall-clock spacing: `started` has
    # 1-second resolution and three analyses opened back-to-back routinely
    # land in the same second.
    conn.execute("UPDATE analysis SET started=100 WHERE id=?", (a_old,))
    conn.execute("UPDATE analysis SET started=200 WHERE id=?", (a_mid,))
    conn.execute("UPDATE analysis SET started=300 WHERE id=?", (a_new,))
    conn.commit()

    asc = queries.finding_rows(conn, "web", sort="first_seen", direction="asc")
    assert [r["branch"] for r in asc["rows"]] == ["old", "mid", "new"]

    desc = queries.finding_rows(conn, "web", sort="first_seen", direction="desc")
    assert [r["branch"] for r in desc["rows"]] == ["new", "mid", "old"]


def test_page_size_is_capped(conn):
    _analysis(conn, "main", findings=[("low", "hygiene")] * 5)
    got = queries.finding_rows(conn, "web", per_page=10_000)
    assert got["per_page"] <= queries.MAX_PER_PAGE


def test_page_zero_and_negative_serve_page_one_and_report_it(conn):
    """An invalid page must not silently serve page 1 while echoing the
    invalid number back -- a pager trusting the echoed `page` would then show
    a number that disagrees with the rows under it."""
    _analysis(conn, "main", findings=[("low", "hygiene")] * 5)
    baseline = queries.finding_rows(conn, "web", per_page=2, page=1)
    for bad in (0, -3):
        got = queries.finding_rows(conn, "web", per_page=2, page=bad)
        assert got["page"] == 1, f"page={bad} must report the page actually served"
        assert got["rows"] == baseline["rows"], f"page={bad} must serve page 1's rows"


def test_page_two_serves_the_second_slice_and_reports_it(conn):
    _analysis(conn, "main", findings=[("low", "hygiene")] * 5)
    page1 = queries.finding_rows(conn, "web", per_page=2, page=1)
    got = queries.finding_rows(conn, "web", per_page=2, page=2)
    assert got["page"] == 2
    assert got["rows"] != page1["rows"]
    assert len(got["rows"]) == 2


def test_non_numeric_page_is_refused(conn):
    """The same refusal `sort` gets: a bad page must raise, not be coerced
    into some silent default."""
    _analysis(conn, "main", findings=[("low", "hygiene")])
    with pytest.raises(ValueError):
        queries.finding_rows(conn, "web", page="two")
