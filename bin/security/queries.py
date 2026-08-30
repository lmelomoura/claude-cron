# bin/security/queries.py
"""Every read of the ledger the dashboard serves.

The connection is opened READ-ONLY -- `mode=ro` in the URI, so a SELECT with a
typo cannot write to the ledger even by accident. Writes stay behind cli.py:
that door exists to protect the ledger from a non-deterministic agent, and the
agent never reaches the server.

Findings' states are NOT recomputed here in SQL. `checklist()` is the one state
machine, moved out of cli.py so both callers share it; a second copy written as
a CASE expression would drift from it the first time either one changed.
"""

import sqlite3
import time
from pathlib import Path

from . import diff, ledger

# Everything that is not resolved. `pending` is open: a finding nobody has
# re-checked is exposure nobody has closed, and filing it with the resolved
# would be the same lie as a premature `fixed`.
RESOLVED_STATES = ("fixed", "accepted", "false_positive")
FINISHED_STATES = ("done", "capped", "failed")


def is_open(state) -> bool:
    return state not in RESOLVED_STATES


class AnalysisNotFound(LookupError):
    """Raised by `_analysis_row` when the id is not in the ledger.

    A library must not exit the process -- and this docstring's own opening
    line calls `queries.py` "the read layer the dashboard serves". A
    `sys.exit()` here was harmless while only `cli.py` called it (the process
    leaving IS the right answer to a typo on the command line), but the
    plan's later tasks wire server routes to `checklist()` with ids that
    come straight from a URL. A bad id must 404, not take the whole control
    server down with it. `cli.py` catches this at its two call sites
    (`cmd_checklist`, `cmd_render`) and turns it back into the identical
    `sys.exit(...)` sentence the command line always printed, so nothing
    about `security checklist` / `security render` on the command line
    changes.
    """


class _CachingConnection(sqlite3.Connection):
    """A read-only connection that memoises `checklist()` for its own
    lifetime, and only its own lifetime.

    `_checklist_cache` is an ordinary instance attribute, not a module-level
    dict keyed by `id(conn)`. The latter would need clearing by hand on
    close to stop a LATER, unrelated connection from reusing the same
    (recycled) id and inheriting a stranger's cached findings -- a real risk
    since CPython ids are just recycled memory addresses. An instance
    attribute needs none of that bookkeeping: it lives and dies with the
    connection object itself, so it cannot outlive the request that opened
    this connection through `read_only()`. `close()` also drops it eagerly
    rather than waiting on GC, so a connection held open a moment longer
    than expected cannot go on serving a stale entry once the caller has
    said it is done with it.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._checklist_cache = {}

    def close(self):
        self._checklist_cache = None
        super().close()


def read_only(path):
    """A read-only handle, or None when no analysis has ever run."""
    path = Path(path)
    if not path.exists():
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                           factory=_CachingConnection)
    conn.row_factory = sqlite3.Row
    return conn


def _analysis_row(conn, analysis_id):
    """The row, or a refusal. Every command that names an analysis goes
    through this: `UPDATE ... WHERE id=?` on an id that does not exist
    changes nothing and reports success, which is how a typo in the agent's
    command line becomes a report with no findings and no explanation."""
    row = conn.execute("SELECT * FROM analysis WHERE id=?", (analysis_id,)).fetchone()
    if row is None:
        raise AnalysisNotFound(f"no such analysis: {analysis_id}")
    return row


def checklist(conn, analysis_id):
    """MOVED FROM cli.py, at heart unchanged: still the single owner of
    finding states. Memoised per analysis id for the life of one connection
    -- see `_CachingConnection` -- because `branch_rows` calls both
    `posture` and `trend` for every branch, and `trend` itself calls this
    once per analysis in its window, so one project-detail payload asks for
    the SAME analysis id (a branch's latest finished one) two or more times
    over. Measured in `.superpowers/sdd/task-5-report.md`. A plain writable
    connection (what `cli.py` opens via `ledger.connect`) carries no such
    cache and is never memoised against -- `getattr(..., None)` reads that
    absence as "no caching here", not as an error.
    """
    cache = getattr(conn, "_checklist_cache", None)
    if cache is not None and analysis_id in cache:
        return cache[analysis_id]

    row = _analysis_row(conn, analysis_id)
    analysis = dict(row)
    current = ledger.findings_of(conn, analysis_id)
    prev = ledger.latest_analysis(conn, analysis["project"], analysis["repo"],
                                  analysis["branch"], before=analysis_id)
    previous = ledger.findings_of(conn, prev["id"]) if prev else []

    # The objective half of the `partial` signal (see diff._is_partial): how
    # many of a finding's places are gone since last time. Nothing persists
    # it -- it is a property of a PAIR of analyses, not of a finding -- and
    # this is the only place the two ever meet, so it is computed here or
    # `partial` can only ever come from the agent's own note.
    #
    # A set difference over the FILES, not a subtraction of two counts. Counts
    # answer the wrong question in both directions: three hits in one file
    # dropping to two is the same file still holding the same hole (someone
    # deleted a duplicate line), while one hit in `auth.py` moving to one hit
    # in `admin.py` is a place genuinely closed and a new one opened -- and
    # `before - now` calls the first of those partial progress and the second
    # nothing at all.
    prev_occurrences = {f["fingerprint"]: {o["file"] for o in f["occurrences"]}
                        for f in previous}
    for f in current:
        before = prev_occurrences.get(f["fingerprint"])
        if before is not None:
            f["closed_occurrences"] = len(before - {o["file"] for o in f["occurrences"]})

    # done/capped only, exactly as `latest_analysis` requires of a baseline. A
    # FAILED analysis is a run that fell over holding a partial set of
    # findings; letting its fingerprints into `history` means the first
    # successful analysis after a failed one reports everything the failed
    # attempt happened to reach as `regressed` -- "this was fixed and came
    # back" -- about findings that were never fixed and never left.
    history = {r["fingerprint"] for r in conn.execute(
        "SELECT DISTINCT f.fingerprint FROM finding f JOIN analysis a ON a.id=f.analysis_id"
        " WHERE a.project=? AND a.repo=? AND a.branch=? AND a.id < ?"
        " AND a.state IN ('done','capped')",
        (analysis["project"], analysis["repo"], analysis["branch"],
         prev["id"] if prev else analysis_id))}
    decisions = ledger.decisions_for(conn, analysis["project"])
    # Absence is only evidence when the looking finished: mid-run (or capped)
    # a baseline finding missing from `current` is `pending`, never `fixed`.
    result = analysis, diff.classify(
        current, previous, history, decisions,
        analysis_state=analysis.get("state", "done"),
        prepared=bool(analysis.get("prepared", 0)))
    if cache is not None:
        cache[analysis_id] = result
    return result


def finding_counts_by_analysis(conn, project):
    """How many findings each analysis of `project` recorded, keyed by
    analysis id -- a plain `COUNT(*)`, never `checklist()`'s diff/decision
    state machine.

    This backs the Runs table's FINDINGS column, which asks a much smaller
    question than `checklist()` answers: not "how many of this project's
    findings are open RIGHT NOW" (which needs the previous analysis, the
    fingerprint history and every recorded decision), only "how many findings
    did THIS run record" -- a fact about one closed analysis that a later
    decision or a later run can never change. Before this, the Runs tab called
    `checklist()` once per done/capped row to get that number and then
    filtered it down with `is_open` -- so a project's history page recomputed
    the full diff for every historical analysis on every load, and again on
    every 4-second poll of a live run (see cmd_project_data's own review
    fix). One grouped query replaces all of that: O(1) round trips instead of
    O(analyses), and the result no longer moves when somebody accepts a risk
    or marks a false positive after the fact -- see
    `.superpowers/sdd/task-9-report.md` for the measured before/after.
    """
    return {r["analysis_id"]: r["c"] for r in conn.execute(
        "SELECT f.analysis_id, COUNT(*) c FROM finding f"
        " JOIN analysis a ON a.id = f.analysis_id"
        " WHERE a.project=? GROUP BY f.analysis_id", (project,))}


def _latest_finished(conn, project, branch, since=None):
    """The branch's newest finished analysis -- or, when `since` is given
    (a unix timestamp), the newest one that ALSO started at or after it.

    The `>=` boundary matches `trend`'s own (`AND started >= ?`) rather than
    inventing a second one: an analysis started exactly at the cutoff second
    counts as inside the window in both places. `since=None` (every existing
    caller before this one gained one) is not "a window starting at time
    zero" -- it is no filter at all, the identical query this function ran
    before `since` existed, kept as its own branch rather than folded into
    `AND started >= COALESCE(?, -1)` so a caller reading the SQL never has to
    wonder whether some large-but-finite epoch could defeat it."""
    if since is None:
        row = conn.execute(
            "SELECT * FROM analysis WHERE project=? AND branch=?"
            " AND state IN ('done','capped') ORDER BY id DESC LIMIT 1",
            (project, branch)).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM analysis WHERE project=? AND branch=?"
            " AND state IN ('done','capped') AND started >= ?"
            " ORDER BY id DESC LIMIT 1",
            (project, branch, since)).fetchone()
    return dict(row) if row else None


def most_recent_started(conn, project):
    """The started-at time of `project`'s most recent analysis, ANY branch,
    ANY state -- unlike `default_branch_posture`'s own `latest`, which only
    ever looks at `done`/`capped` rows because posture needs a finished
    baseline. A project whose every analysis is `running` or `failed` has no
    such baseline, so `latest` comes back `None` and every caller of
    `default_branch_posture` used to read that as "0", the same falsy value
    a project that has NEVER been analysed produces -- "Never analysed" shown
    to a project that plainly has attempts sitting in its Runs tab.

    Callers fall back to this only when they already have nothing (`or
    most_recent_started(...)`), so it costs a query exactly when there is no
    finished analysis to report a time from -- never on the common path."""
    row = conn.execute(
        "SELECT started FROM analysis WHERE project=? ORDER BY id DESC LIMIT 1",
        (project,)).fetchone()
    return row["started"] if row else 0


def _empty_posture():
    return {s: 0 for s in ("critical", "high", "medium", "low", "info")} | {"total": 0}


def posture(conn, project, branch, latest=None):
    """`latest`, when given, is the already-fetched `_latest_finished` row --
    callers that have one (`default_branch_posture` does) pass it through
    instead of making this re-run the same query for the same row."""
    a = latest if latest is not None else _latest_finished(conn, project, branch)
    if not a:
        return _empty_posture()
    _analysis, findings = checklist(conn, a["id"])
    out = _empty_posture()
    for f in findings:
        if not is_open(f["state"]):
            continue
        if f["severity"] in out:
            out[f["severity"]] += 1
        out["total"] += 1
    return out


def default_branch_posture(conn, project, preferred):
    """The project's own branch when it has been analysed; otherwise the most
    recently analysed one, and a flag saying so -- postures of different
    branches must never be confused in silence.

    Returns (branch, posture, fell_back, latest) -- `latest` is the same
    analysis row `posture` was computed from, handed back so a caller like
    `project_rows` (which also wants its `started`/`ended`/`profile`) does not
    have to fetch the identical row a second time."""
    if preferred:
        a = _latest_finished(conn, project, preferred)
        if a:
            return preferred, posture(conn, project, preferred, latest=a), False, a
    # The single latest finished analysis of the project, whatever branch it
    # is on. Its own branch column IS that branch's latest finished analysis
    # too -- nothing with a higher id and the same branch can exist, since
    # this row already has the highest id project-wide -- so one query gets
    # both the fallback branch and the row `posture` needs, instead of a
    # second round trip through `_latest_finished` for the same thing.
    row = conn.execute(
        "SELECT * FROM analysis WHERE project=? AND state IN ('done','capped')"
        " ORDER BY id DESC LIMIT 1", (project,)).fetchone()
    if not row:
        return (preferred or ""), _empty_posture(), False, None
    a = dict(row)
    return a["branch"], posture(conn, project, a["branch"], latest=a), True, a


def index_summary(conn, projects):
    """Header stats for the index screen, scoped to exactly `projects`.

    `projects` is the SAME list of `{name, base, description}` dicts
    `project_rows` is handed, NOT a list of names. That is the whole point of
    this signature: the cards above the table and the table itself have to
    resolve the same branch for the same project, and the branch is chosen by
    `default_branch_posture(conn, name, preferred)` -- so a caller that
    strips `base` out on the way in here makes the cards ALWAYS take the
    fallback path while the table honours the declared base. The two halves
    of one screen then quietly describe different branches: "High 0" on the
    cards over "High 1" on `main` three inches below, and a `capped_projects`
    count resolved from a branch that is not the one the table flagged
    `incomplete`. Nothing about the SQL below needs `base`, but everything
    about the loop does, and one shape for both callers is what stops the
    two from drifting again.

    Nothing prunes `analysis` when a project is renamed or removed from
    projects.json -- the ledger keeps every row forever. `critical`/`high`
    were always scoped (via `default_branch_posture`, called once per project
    below); `total`/`counts` were NOT, so the moment the ledger held even one
    analysis for a project no longer configured, "analyses" and
    `success_rate` silently counted work that belongs to nothing on screen.

    An empty `projects` is an empty summary -- made explicit below rather
    than left to however SQLite happens to treat `WHERE project IN ()`;
    relying on that would make the "no projects" case correct by accident of
    the engine, not by the code saying what it means.

    `capped_projects` counts, among `projects`, how many have their latest
    finished analysis in `capped` state -- a PARTIAL read of the repository,
    whose contribution to `critical`/`high` above means "none found before it
    stopped," not "none" (the identical notice `secPaint` already gives on
    the analysis screen). The index screen's KPI cards use this count to say
    the fleet total may be an undercount, rather than presenting it as
    complete.

    `fell_back_projects` is the same idea for the OTHER way these totals can
    mislead: how many of them were read off a branch nobody declared, because
    the declared base has never been analysed. The project table already
    names that per row (`branch_fell_back`, rendered beside the branch's own
    name); the cards summed those postures and said nothing, and this area's
    standing rule is that a fallback branch is never silent.
    """
    projects = [dict(p) for p in projects]
    names = [p.get("name", "") for p in projects]
    counts = {s: 0 for s in FINISHED_STATES}
    total = 0
    if names:
        placeholders = ",".join("?" * len(names))
        total = conn.execute(
            f"SELECT COUNT(*) c FROM analysis WHERE project IN ({placeholders})",
            names).fetchone()["c"]
        for r in conn.execute(
                f"SELECT state, COUNT(*) c FROM analysis"
                f" WHERE project IN ({placeholders}) GROUP BY state",
                names):
            if r["state"] in counts:
                counts[r["state"]] = r["c"]
    finished = sum(counts.values())
    crit = high = capped = fell_back = 0
    for proj in projects:
        # `proj.get("base")`, exactly as `project_rows` passes it -- see this
        # function's own docstring for what stripping it costs.
        _br, p, fb, last = default_branch_posture(
            conn, proj.get("name", ""), proj.get("base"))
        crit += p["critical"]
        high += p["high"]
        if last and last["state"] == "capped":
            capped += 1
        if fb:
            fell_back += 1
    return {"projects": len(projects), "analyses": total,
            "critical": crit, "high": high, "capped_projects": capped,
            "fell_back_projects": fell_back,
            # None, not 0.0: no finished analysis is not a zero-percent success
            # rate, and the card shows a dash for it.
            "success_rate": (counts["done"] / finished) if finished else None}


def project_rows(conn, projects):
    """One row per project. `projects` carries name, base and description,
    read from projects.json by the caller -- the ledger does not know them.

    Carries `trend` again, via `trend_series(conn, proj)` -- see `8c0eaf8`
    for why it was dropped (no cell of the table read it; a later task adds
    one) and `trend_series`'s own docstring for how this reading differs
    from the one that commit deleted. That one read `branch`, the
    FALLBACK-resolved column right below, so a project whose declared base
    had never been analysed would have plotted another branch's history
    under it, silently. `trend_series` reads `proj` -- the declared base
    alone -- and returns `[]` rather than do that: the same discipline
    `branch_fell_back` already enforces for the row's own posture, just with
    no cell of its own to say so out loud."""
    out = []
    for proj in projects:
        name = proj["name"]
        branch, p, fell_back, last = default_branch_posture(conn, name, proj.get("base"))
        out.append({
            "name": name, "description": proj.get("description", ""),
            "branch": branch, "branch_fell_back": fell_back, "posture": p,
            "profile": (last or {}).get("profile", ""),
            # Falls back to `most_recent_started` only when there is no
            # finished baseline (`last` is None) -- a project whose every
            # analysis is `running` or `failed` used to read `0` here, the
            # same falsy value a project that has NEVER been analysed
            # produces, and `secIndexProjectRow`'s "Last analysis" cell
            # rendered "never" for both alike even though its own `analyses`
            # count (below) already knew the two apart.
            "last_started": (last or {}).get("started", 0) or most_recent_started(conn, name),
            "last_duration": (max(0, (last["ended"] or 0) - (last["started"] or 0))
                              if last else 0),
            # The state `posture` was computed from -- "" when nothing has ever
            # been analysed. `capped` is a PARTIAL read (see `index_summary`'s
            # own docstring and `secPaint`'s identical notice on the analysis
            # screen): the row's counts mean "none found before it stopped,"
            # not "none," and the screen has to say so rather than render them
            # as if the analysis had finished.
            "last_state": (last or {}).get("state", ""),
            "analyses": conn.execute(
                "SELECT COUNT(*) c FROM analysis WHERE project=?", (name,)
            ).fetchone()["c"],
            # `proj`, not `name`/`branch`: `trend_series` reads the DECLARED
            # base off the record itself, never the fallback branch resolved
            # two lines above -- see its own docstring and `8c0eaf8`.
            "trend": trend_series(conn, proj)})
    return out


def trend(conn, project, branch, days=30):
    """Each point carries the STATE its `open` count was read from, not just
    the count. A `capped` analysis stopped before covering the whole scope,
    so its "3 open" means "3 found before it stopped" -- and a trend line
    that reads a direction across such a point can say "falling" off a run
    that simply ran out of room. The renderer needs the state to refuse that
    (ui/security/branches-tab.js's `secBranchTrendText`); it cannot infer it
    from a number.
    """
    since = int(time.time()) - days * 86400
    out = []
    for a in conn.execute(
            "SELECT id, started, state FROM analysis WHERE project=? AND branch=?"
            " AND state IN ('done','capped') AND started >= ?"
            # `id` as the tiebreak: `started` has 1-second resolution, and two
            # analyses of the SAME branch routinely land in the same second
            # (the engine can open a row and fail it moments later) -- the
            # exact ambiguity `branch_rows` was already fixed for. Without
            # this, "oldest first" is not guaranteed for a tied pair, and the
            # trend line can silently plot them out of order.
            " ORDER BY started, id", (project, branch, since)):
        _an, findings = checklist(conn, a["id"])
        out.append({"analysis_id": a["id"], "started": a["started"],
                    "state": a["state"],
                    "open": sum(1 for f in findings if is_open(f["state"]))})
    return out


def trend_series(conn, project, days=30):
    """The open-findings count at each finished analysis of `project`'s OWN
    DECLARED branch, oldest first -- the sparkline the index screen's Trend
    column needs. This is the reading `8c0eaf8` deleted (it computed one per
    project on every index load and nothing rendered it); a later task adds
    the renderer, and this is that renderer's data, built new rather than by
    un-deleting `8c0eaf8`'s own line.

    `project` is the same `{name, base, ...}` record `project_rows` and
    `index_summary` are handed per item, not a bare name: the question this
    answers ("what did this project's OWN branch look like over time") only
    makes sense against the branch the project DECLARES. Unlike
    `default_branch_posture` -- which falls back to the most recently
    analysed branch so the posture cards are never blank, and says so via
    `branch_fell_back` -- this never falls back. An analysis on any branch
    other than the declared one contributes NOTHING here, even when the
    declared branch has no finished analysis at all: a sparkline is a bare
    list of integers with no cell of its own to carry a "fell back to
    develop" caveat, so rather than silently plot another branch's history
    under the declared branch's name, it shows nothing. No declared branch
    at all (`project.get("base")` empty) is the same "nothing to show",
    answered without a query.

    Delegates entirely to `trend()` for the actual reading -- same window,
    same `done`/`capped` treatment (a `capped` analysis is a PARTIAL read,
    exactly as `posture`/`default_branch_posture` already treat it: counted,
    not excluded, with the incomplete badge carried elsewhere), same
    `is_open()` -- and keeps only the `open` count from each point, since
    the sparkline needs relative heights and nothing else. Restating
    `trend`'s SQL or its open-state predicate here would be a fourth
    duplicated vocabulary in this module (see its own opening docstring);
    this is the first time it is a thin wrapper instead.

    Cost: one extra SQL query per project (`trend`'s own SELECT) plus one
    `checklist()` per finished analysis actually inside the window -- but
    `project_rows` already computes and caches `checklist()` for the
    declared branch's LATEST finished analysis via `posture()`, on the SAME
    connection, and that is also the newest point in this series whenever
    the branch has not fallen back. So the common case (one analysis in the
    last 30 days) costs zero additional `checklist()` calls, and a busier
    project pays once per analysis actually in the window -- never once per
    analysis in the ledger's full history, which is the cost `8c0eaf8`
    removed for having no reader.
    """
    branch = project.get("base")
    if not branch:
        return []
    name = project.get("name", "")
    return [point["open"] for point in trend(conn, name, branch, days=days)]


def recent_analyses(conn, limit=5, offset=0, projects=None):
    """The most recent analyses, newest first, ONE PAGE of them -- returns
    `{"rows": [...], "total": N}`, `total` counting every analysis the same
    scope matches, not just the page requested, so the index screen's footer
    can say "Showing 1 to 5 of 12 analyses" without a second round trip.

    Paged server-side (`LIMIT`/`OFFSET` in the SQL itself), not fetched whole
    and sliced in Python: the index screen polls this every 5 seconds, and
    each row in the page actually returned costs one `checklist()` call
    (below) -- fetching up to `MAX_PER_PAGE` rows on every poll just so a
    reader COULD page past row 5 would multiply that cost by however large
    the cap is, paid on every tick whether or not anyone ever pages. Serving
    exactly the page asked for keeps the common case (page 1, nobody has
    clicked Next) exactly as cheap as before this function could page at
    all: `limit` (5 by default, matching the mockup) checklist() calls, not
    50.

    `projects`, when given, is an iterable of names to scope to -- the index
    screen's `summary` and `projects` panels have always been scoped to
    exactly the fleet as configured (see `index_summary`'s own docstring),
    and this feed used to be the one panel left reading the whole ledger: a
    project disabled or removed from projects.json still surfaced here, on a
    screen whose other panels say it does not exist. `None` keeps the old
    fleet-wide behaviour for any other caller; an empty iterable is an
    explicit "nothing to show," the same reasoning `index_summary` and
    `_analysed_scopes` apply to an empty project list, rather than whatever
    `WHERE project IN ()` happens to do.

    Each finished row also carries `severities` -- `{critical, high, medium}`
    tallied from the SAME `checklist()` call `open` already makes, no second
    query -- so the index's Recent-analyses table can show the mockup's own
    three severity chips per row instead of one undifferentiated count. Both
    `open` and `severities` are `None` for a `running`/`failed` analysis: it
    has not finished recording findings yet, and a `None` reads as an honest
    dash rather than a fabricated zero (the same distinction every other
    "not counted yet" cell on this screen already draws).
    """
    where, args, names = "", [], None
    if projects is not None:
        names = list(projects)
        if not names:
            return {"rows": [], "total": 0}
        placeholders = ",".join("?" * len(names))
        where = f" WHERE project IN ({placeholders})"
        args = list(names)

    total = conn.execute(f"SELECT COUNT(*) c FROM analysis{where}", args).fetchone()["c"]

    limit = max(1, min(int(limit), 50))
    offset = max(0, int(offset))
    rows = []
    for a in conn.execute(
            f"SELECT * FROM analysis{where} ORDER BY started DESC, id DESC LIMIT ? OFFSET ?",
            args + [limit, offset]):
        d = dict(a)
        if a["state"] in ("done", "capped"):
            _an, findings = checklist(conn, a["id"])
            sev = {"critical": 0, "high": 0, "medium": 0}
            open_n = 0
            for f in findings:
                if not is_open(f["state"]):
                    continue
                open_n += 1
                if f["severity"] in sev:
                    sev[f["severity"]] += 1
            d["open"] = open_n
            d["severities"] = sev
        else:
            d["open"] = None       # a running/failed analysis has no posture yet
            d["severities"] = None
        rows.append(d)
    return {"rows": rows, "total": total}


def _analysed_scopes(conn, project=None):
    """`project` is either a single name, an iterable of names, or `None` for
    the whole ledger. A given iterable that is empty means "no projects" --
    made explicit rather than left to `WHERE project IN ()`, the same
    reasoning `index_summary` already applies to an empty `project_names`."""
    sql = ("SELECT DISTINCT project, branch FROM analysis"
           " WHERE state IN ('done','capped')")
    args = []
    if isinstance(project, str):
        if project:
            sql += " AND project = ?"
            args.append(project)
    elif project is not None:
        names = list(project)
        if not names:
            return []
        placeholders = ",".join("?" * len(names))
        sql += f" AND project IN ({placeholders})"
        args.extend(names)
    return list(conn.execute(sql, args))


def analysed_branch_count(conn, project):
    """How many distinct branches of `project` have at least one finished
    (`done`/`capped`) analysis -- exactly the scopes `_analysed_scopes`
    returns, and therefore exactly what `severity_totals`/`top_categories`
    roll their numbers up over. `project` is always a single name here (this
    backs one project's own screen, not a fleet-wide rollup), unlike
    `_analysed_scopes`'s own broader signature.

    The project screen's Overview posture describes ONE branch
    (`default_branch_posture`'s own choice); the sidebar donut and category
    rollup describe EVERY analysed branch. Two different, equally true
    answers that used to sit side by side with nothing saying so -- this is
    the number the sidebar's own caption names, so a project with two
    analysed branches and one with only one never look alike."""
    return len(_analysed_scopes(conn, project))


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _open_findings_by_fingerprint(conn, project, since=None):
    """The open findings across every scope `_analysed_scopes` returns for
    `project`, collapsed from one entry per (branch, fingerprint) to one
    entry per FINGERPRINT -- shared by `severity_totals` and
    `top_categories`, which both used to sum a project's branches by adding
    each branch's own posture/rule counts together.

    A fingerprint never includes the branch, so the same committed secret
    reachable on `main` and `develop` is ONE problem needing one rotation,
    not two -- `finding_rows` already draws exactly this line between
    `total` (rows) and `unique` (fingerprints), in the spec's own words 189
    findings can be 93 problems. Summing per-branch postures, which is what
    this repository's own two callers used to do, counted that one problem
    twice -- on the donut AND the category rollup fed from the same numbers
    -- so the index screen's "critical" meant something different from
    `finding_rows`'s `unique`, one screen away, using the same word.

    Only OPEN occurrences are collected. A finding resolved (fixed, accepted,
    false_positive) on one branch but still open on another is exposure that
    has not actually gone away, so it still counts, using the still-open
    branch's own record of it; a fingerprint with no open occurrence in any
    scope is absent from the result entirely, exactly like `posture` already
    treats a finding resolved everywhere.

    When a fingerprint is open on more than one branch and the two analyses
    disagree about its severity -- possible, since the agent can re-triage a
    finding's severity between runs -- the MORE severe occurrence wins. A
    posture summary that under-reports the worst assessment ever made of a
    finding is the wrong way to be wrong: an operator seeing "medium" while
    one branch's own analysis called it "critical" is worse served than one
    seeing "critical" for a finding a later run downgraded.

    `since`, when given, is passed straight to `_latest_finished`: a scope
    whose newest finished analysis falls outside the window contributes
    NOTHING here, not a stale reading from further back. This is "findings
    whose analyses fall in the period," not "findings visible as of now,
    reported only if a project happened to run recently" -- a branch with no
    analysis in the window has nothing to say about the period, the same way
    it has nothing to say about `trend`'s own windowed series. Costs no extra
    `checklist()` calls versus the unwindowed read: still exactly one per
    analysed scope, `_latest_finished`'s own SQL predicate narrowed, not a
    second pass over more analyses.
    """
    by_fingerprint = {}
    for r in _analysed_scopes(conn, project):
        a = _latest_finished(conn, r["project"], r["branch"], since=since)
        if not a:
            continue
        _an, findings = checklist(conn, a["id"])
        for f in findings:
            if not is_open(f["state"]):
                continue
            fp = f["fingerprint"]
            current = by_fingerprint.get(fp)
            if current is None or (_SEV_RANK.get(f["severity"], 9)
                                    < _SEV_RANK.get(current["severity"], 9)):
                by_fingerprint[fp] = f
    return by_fingerprint


def severity_totals(conn, project=None, days=0):
    """Open findings by severity across every scope `_analysed_scopes`
    returns for `project` -- a single name, an iterable of names, or `None`
    for the whole ledger. Counted by DISTINCT FINGERPRINT (see
    `_open_findings_by_fingerprint`'s own docstring for why): the same
    finding open on two branches of one project is one problem, not two, so
    it must contribute to this total exactly once.

    `days` USED to be accepted, ignored, and never passed by either caller --
    a signature promising a filter the body did not apply, worse than no
    parameter at all: the first person to pass `days=7` got a 30-day-looking
    answer that was really an all-time one, with nothing failing. It is real
    now: truthy, it narrows every scope to the finished analysis (per branch)
    that is itself newest AND started within the last `days` days, via
    `_latest_finished`'s own `since` -- a scope with nothing that recent
    contributes NOTHING, not a stale reading from further back. Falsy (the
    default, `0`) is UNCHANGED from before this parameter did anything: no
    window at all, the as-of-now posture every existing caller (the project
    sidebar's own donut, chiefly) still gets without asking, read off each
    branch's LATEST finished analysis whether that ran an hour ago or last
    spring -- a critical finding does not stop being open because nobody
    re-analysed the branch this month, and windowing THAT reading would not
    narrow the answer, it would delete quiet branches from it and report
    them clean. The default stays that safe reading on purpose, unlike
    `trend`/`activity_summary`'s own `days=30`: those two are ALWAYS
    windowed by what they answer (a series over time, a count of events in a
    period); this one is not, for every caller that has never asked
    otherwise. Only the index screen's own Findings-overview card asks for a
    real window today (`cmd_index_data`, `--days 30` by default) -- see
    CHANGELOG.md for the fuller history, including the reasoning this
    supersedes."""
    since = (int(time.time()) - int(days) * 86400) if days else None
    out = _empty_posture()
    for f in _open_findings_by_fingerprint(conn, project, since=since).values():
        if f["severity"] in out:
            out[f["severity"]] += 1
        out["total"] += 1
    return out


def top_categories(conn, project=None, limit=5, days=0):
    """The rules producing the most open findings, ranked across every scope
    `_analysed_scopes` returns for `project` -- a single name, an iterable of
    names, or `None` for the whole ledger. Counted by DISTINCT FINGERPRINT
    (see `_open_findings_by_fingerprint`), so a rule's count is how many
    distinct problems it produced, not how many branches happen to still
    carry one of them. Counts are accumulated across all scopes before
    ranking, so `limit` slices the TRUE top rules for the given projects
    together, not each project's own top `limit` merged afterwards -- which
    could drop a rule that only ranks highly once several projects' counts
    are combined.

    `days`: the identical parameter `severity_totals` now carries, for the
    identical reason -- see that function's own docstring. Falsy (default)
    ranks every scope's current state, unwindowed; truthy narrows each scope
    to its newest finished analysis that started within the window."""
    since = (int(time.time()) - int(days) * 86400) if days else None
    counts = {}
    cats = {}
    for f in _open_findings_by_fingerprint(conn, project, since=since).values():
        counts[f["rule"]] = counts.get(f["rule"], 0) + 1
        # The rule's own category rides along so the page's label/icon
        # resolver reads it instead of inferring one from the id's shape --
        # kebab-vs-snake told sast and hygiene apart only by accident of
        # naming convention, and an agent is free to write a snake_case sast
        # rule tomorrow. A rule id lives in exactly one category in practice;
        # if two ever disagree, the newest read wins and the disagreement is
        # a ledger oddity, not something this ranking should crash on.
        cats[f["rule"]] = f.get("category") or ""
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"rule": k, "count": v, "category": cats.get(k, "")}
            for k, v in ranked[:limit]]


def branch_rows(conn, project):
    """One row per branch that has ever finished an analysis.

    `state` is the state of the analysis each row's `open` posture was
    actually read from -- `done` or `capped`, the two this function's own
    `WHERE` already admits. It used to be dropped on the floor: the rows said
    `state IN ('done','capped')` and then returned no state at all, so a
    branch whose last analysis stopped early presented its PARTIAL posture as
    a finished one. That is worse here than anywhere else in the area,
    because the Branches tab is the ONE screen whose entire purpose is
    per-branch posture -- every other surface that shows a capped read
    (`project_rows`'s `last_state`, `index_summary`'s `capped_projects`,
    `secPaint`'s own banner) already says so, and this was the only posture
    surface that could not.
    """
    out = []
    # `MAX(id) DESC` as the tiebreak, not just `last DESC`: two branches of the
    # same project routinely get analysed within the same wall-clock second
    # (`started` has 1-second resolution), and without a tiebreak the newer
    # branch can sort BEHIND the older one -- the same reason `recent_analyses`
    # orders `started DESC, id DESC` rather than `started DESC` alone.
    for r in conn.execute(
            "SELECT branch, MAX(started) last, COUNT(*) n FROM analysis"
            " WHERE project=? AND state IN ('done','capped')"
            " GROUP BY branch ORDER BY last DESC, MAX(id) DESC", (project,)):
        # Fetched once and handed to `posture`, rather than letting it run the
        # identical `_latest_finished` query a second time for the same row --
        # exactly what `default_branch_posture` already does with its own.
        latest = _latest_finished(conn, project, r["branch"])
        out.append({"branch": r["branch"], "last_analysis": r["last"],
                    "analyses": r["n"],
                    "state": (latest or {}).get("state", ""),
                    "open": posture(conn, project, r["branch"], latest=latest),
                    "trend": trend(conn, project, r["branch"])})
    return out


def capped_branch_count(conn, project):
    """How many of `project`'s analysed branches have their LATEST finished
    analysis in `capped` state -- the per-project twin of `index_summary`'s
    own `capped_projects`, for the two surfaces that roll every branch up
    into one number and so cannot use a per-row badge: the sidebar donut
    (`severity_totals`) and the findings browser's strip (`finding_rows`).

    Both of those read exactly the scopes `_analysed_scopes` returns and
    exactly the analysis `_latest_finished` picks per scope, which is what
    this counts -- so the cue and the numbers it qualifies are computed from
    the same rows, not from two independently-chosen sets of analyses.
    """
    n = 0
    for r in _analysed_scopes(conn, project):
        a = _latest_finished(conn, r["project"], r["branch"])
        if a and a["state"] == "capped":
            n += 1
    return n


SORTABLE = ("severity", "title", "category", "branch", "first_seen", "state")
MAX_PER_PAGE = 100


def finding_rows(conn, project, filters=None, sort="severity",
                 direction="desc", page=1, per_page=25):
    """The findings browser: one checklist per branch -- the latest finished
    analysis of each -- unioned. That union is what lets the browser show a
    state at all: it is the state that branch's newest analysis gives the
    finding, not a column stored anywhere.

    Filtering happens here in Python, after `checklist()`, rather than as SQL
    predicates. That is deliberate, not laziness: a finding's state is not a
    column to filter on, it is computed by comparing an analysis with the
    previous one of the same branch, and `checklist()` is the one place that
    comparison happens. Rebuilding it as a SQL CASE expression would be a
    second copy of a state machine this repository has already been bitten by
    duplicating twice (see the module docstring and `checklist`'s own). With
    hundreds of findings this is instant; if it ever becomes thousands, that
    is a measured problem with a materialised-state answer -- not a presumed
    one today.

    `sort` and `direction` are an allowlist, not a best-effort default: filter
    VALUES travel as SQL parameters, but a sort column is interpolated by
    nature -- it is the one route parameters cannot protect -- so an
    unrecognised column raises rather than silently falling back to
    `severity`.

    `filters["fingerprint"]`, when present, is a PREFIX match (added for
    Task 12's Activity screen, which links a fingerprint straight into this
    browser): an event's `related` only ever carries the first 12 characters
    of a fingerprint (`cmd_decide` truncates it before recording), so exact
    equality could never match anything a real caller would ask for.

    The returned `by_severity` counts EVERY row the current filters match
    (before pagination), and `fixed_by_severity` is the same count restricted
    to `state == "fixed"` -- so the browser can say "N findings below the
    floor are hidden" while still exempting a fixed one from that count, the
    same exemption `secVisible` (ui/security/vocabulary.js) already gives the
    single-analysis checklist. Both are counted from the whole filtered set,
    not the page on screen, for the reason `by_severity` alone always was.

    `attempted`/`analysed` are the never-analysed signal this payload used to
    lack entirely, and the reason it mattered: with no way to tell "no rows
    because nothing was ever read" from "no rows because the filters exclude
    them", the browser rendered a project that has never been analysed as an
    ok-green "nothing matches" beside `0 total`, and blamed filters the
    reader never set. `attempted` is true the moment ANY analysis of this
    project exists in any state; `analysed` is true only once one has reached
    `done` or `capped`. Exactly the two-way distinction
    `cmd_project_data`'s `tabs.overview.attempted` already gives the Overview
    and Branches tabs -- computed here rather than passed in, because this
    verb answers a screen that also mounts outside the project screen (the
    Activity screen's fingerprint dialog) and cannot borrow another payload's
    flag.

    `capped_branches` is the same cue `project_rows`/`index_summary` already
    give a partial read, for the one number here that rolls every branch into
    one: how many of the branches these rows were unioned from had their
    latest finished analysis stop early. "0 critical" over such a branch
    means "none found before it stopped," not "none."

    `branches`/`analyses` are the findings browser's own Branch / Analysis
    run picker OPTIONS (AllFindings.png), not more findings -- every branch
    with a finished analysis, and that branch's own latest finished analysis
    (id/profile/started), both read off values this function already had in
    hand for the main loop above. No second query: a picker whose options
    come from a scope other than "what `rows` was unioned from" could offer
    a branch or analysis id that then matches nothing.
    """
    if sort not in SORTABLE:
        raise ValueError(f"sort must be one of {SORTABLE}")
    if direction not in ("asc", "desc"):
        raise ValueError("direction must be asc or desc")
    f = dict(filters or {})
    per_page = max(1, min(int(per_page), MAX_PER_PAGE))
    # Clamped, not coerced: `int(page)` still raises on non-numeric input --
    # the same refusal `sort` gets above -- but an out-of-range value (0, a
    # negative number) used to be silently steered to page 1's rows while the
    # `page` field below echoed the raw value back, so a pager built on that
    # field showed a number that disagreed with the rows under it. The value
    # returned must always describe the rows actually served.
    page = max(1, int(page))

    branches = [r["branch"] for r in conn.execute(
        "SELECT DISTINCT branch FROM analysis WHERE project=?"
        " AND state IN ('done','capped')", (project,))]

    rows, first_seen, capped_branches = [], {}, 0
    # The Analysis run / Branch picker options (AllFindings.png) -- collected
    # from the SAME `_latest_finished` call this loop already makes per
    # branch, not a second query: one analysis row per branch that has one,
    # `id`/`profile`/`started` read off it while it is already in hand. This
    # is deliberately every branch's LATEST finished analysis, not every
    # analysis that ever ran -- the same scope `rows` itself is built from,
    # so a value the Analysis run picker offers is always one this endpoint's
    # own `analysis` filter can actually match a row against.
    analyses_available = []
    for br in branches:
        a = _latest_finished(conn, project, br)
        if not a:
            continue
        if a["state"] == "capped":
            capped_branches += 1
        analyses_available.append({"id": a["id"], "profile": a["profile"],
                                    "branch": br, "started": a["started"]})
        _an, findings = checklist(conn, a["id"])
        for finding in findings:
            row = dict(finding)
            row["branch"] = br
            row["analysis_id"] = a["id"]
            rows.append(row)

    # The oldest DONE/CAPPED analysis carrying each fingerprint, in one query
    # rather than one per row -- filtered exactly like `_latest_finished`,
    # this function's own `branches` query above, and `checklist`'s own
    # `history` query (see its comment): a crashed or still-running analysis
    # can record a finding before dying, and letting that count as "first
    # seen" would make a finding look older than any successful analysis ever
    # confirmed it.
    for r in conn.execute(
            "SELECT f.fingerprint AS fp, MIN(a.started) AS first FROM finding f"
            " JOIN analysis a ON a.id = f.analysis_id WHERE a.project=?"
            " AND a.state IN ('done','capped') GROUP BY f.fingerprint", (project,)):
        first_seen[r["fp"]] = r["first"]
    for r in rows:
        # `rows` itself is only ever built from a done/capped analysis --
        # `a` above is `_latest_finished`, and `checklist`'s own `previous`
        # comparison reads through `latest_analysis`, equally filtered -- so
        # every fingerprint reaching this loop is always in the GROUP BY
        # above too. The `0` default is a defensive fallback, not an
        # expression of "seen only in unfinished analyses": that case cannot
        # reach `rows` at all.
        r["first_seen"] = first_seen.get(r["fingerprint"], 0)

    if not f.get("show_resolved"):
        rows = [r for r in rows if is_open(r["state"])]
    for key in ("severity", "state", "category", "branch"):
        if f.get(key):
            rows = [r for r in rows if r.get(key) in f[key]]
    if f.get("fingerprint"):
        # A PREFIX match, not equality: the Activity screen's own deep link
        # (Task 12) only ever has the first 12 characters of a fingerprint --
        # `related` on a `decision_made` event is truncated by `cmd_decide` --
        # so the one caller of this filter could never match on the full
        # 64-character string.
        needle = f["fingerprint"]
        rows = [r for r in rows if r["fingerprint"].startswith(needle)]
    if f.get("analysis"):
        rows = [r for r in rows if r["analysis_id"] in f["analysis"]]
    if f.get("path"):
        needle = f["path"].lower()
        rows = [r for r in rows
                if any(needle in o["file"].lower() for o in r.get("occurrences", []))]
    if f.get("q"):
        needle = f["q"].lower()
        rows = [r for r in rows if needle in " ".join([
            r.get("title", ""), r.get("rule", ""), r.get("rationale", ""),
            " ".join(o["file"] for o in r.get("occurrences", []))]).lower()]

    by_severity = {s: 0 for s in _SEV_RANK}
    # A FIXED finding below the floor is exempted from being hidden by
    # `secVisible` (ui/security/vocabulary.js) in the single-analysis
    # checklist, and the findings browser now carries the same exemption
    # (ui/security/findings-screen.js's own `secFindTableSection`) -- so the
    # browser's own "N findings below the floor are hidden" count has to
    # subtract exactly the fixed ones out of each severity bucket, or that
    # count and the table underneath it would openly disagree about the same
    # row. Counted here, from the whole filtered set before pagination, for
    # the same reason `by_severity` itself is: the browser may be showing
    # page 2 of 5, and the count has to be exact regardless.
    fixed_by_severity = {s: 0 for s in _SEV_RANK}
    for r in rows:
        if r["severity"] in by_severity:
            by_severity[r["severity"]] += 1
            if r["state"] == "fixed":
                fixed_by_severity[r["severity"]] += 1

    if sort == "severity":
        keyf = lambda r: _SEV_RANK.get(r["severity"], 9)
        # Rank 0 is "critical", the most severe -- ascending rank order
        # already puts critical first, which is what `desc` (most severe
        # first) means for this column. So `desc` maps to reverse=False
        # here, the opposite of every other sortable column below.
        reverse = direction != "desc"
    else:
        # `.get(sort, "")`, not `.get(sort) or ""`: every SORTABLE column
        # except `first_seen` is a NOT NULL string, but `first_seen` is an
        # int that can legitimately be 0 -- `or ""` would silently turn that
        # 0 into a string and mix str/int keys mid-sort, raising TypeError.
        # `.get(key, "")` only substitutes when the key is missing outright,
        # which never happens for a SORTABLE column.
        keyf = lambda r: r.get(sort, "")
        reverse = direction == "desc"
    rows.sort(key=keyf, reverse=reverse)

    total, unique = len(rows), len({r["fingerprint"] for r in rows})
    start = (page - 1) * per_page
    # `branches` above is already "every branch with a finished analysis", so
    # `analysed` costs nothing extra; `attempted` is the one fact this
    # function did not already have in hand, and it is a single EXISTS.
    attempted = conn.execute(
        "SELECT 1 FROM analysis WHERE project=? LIMIT 1", (project,)).fetchone()
    return {"rows": rows[start:start + per_page], "total": total,
            "unique": unique, "by_severity": by_severity,
            "fixed_by_severity": fixed_by_severity,
            "attempted": attempted is not None, "analysed": bool(branches),
            "capped_branches": capped_branches,
            # Picker options for the filter bar (AllFindings.png's Branch /
            # Analysis run pickers) -- both free, off `analyses_available`
            # above and the `branches` list already built for the main loop.
            # Newest analysis first: the one a reader most likely wants is
            # the one nearest the top of the list they open.
            "branches": sorted(branches),
            "analyses": sorted(analyses_available, key=lambda a: a["id"], reverse=True),
            "page": page, "per_page": per_page}


def activity_summary(conn, project=None, days=30):
    since = int(time.time()) - days * 86400
    sql = "SELECT kind, COUNT(*) c FROM event WHERE at >= ?"
    args = [since]
    if project:
        sql += " AND project = ?"
        args.append(project)
    sql += " GROUP BY kind"
    out = {k: 0 for k in ledger.EVENT_KINDS}
    for r in conn.execute(sql, args):
        out[r["kind"]] = r["c"]
    return out
