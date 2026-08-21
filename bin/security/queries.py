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


def _latest_finished(conn, project, branch):
    row = conn.execute(
        "SELECT * FROM analysis WHERE project=? AND branch=?"
        " AND state IN ('done','capped') ORDER BY id DESC LIMIT 1",
        (project, branch)).fetchone()
    return dict(row) if row else None


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


def index_summary(conn, project_names):
    """Header stats for the index screen, scoped to exactly `project_names`.

    Nothing prunes `analysis` when a project is renamed or removed from
    projects.json -- the ledger keeps every row forever. `critical`/`high`
    were always scoped (via `default_branch_posture`, called once per name
    below); `total`/`counts` were NOT, so the moment the ledger held even one
    analysis for a project no longer in `project_names`, "analyses" and
    `success_rate` silently counted work that belongs to nothing on screen.

    An empty `project_names` is an empty summary -- made explicit below
    rather than left to however SQLite happens to treat `WHERE project IN
    ()`; relying on that would make the "no projects" case correct by
    accident of the engine, not by the code saying what it means.
    """
    project_names = list(project_names)
    counts = {s: 0 for s in FINISHED_STATES}
    total = 0
    if project_names:
        placeholders = ",".join("?" * len(project_names))
        total = conn.execute(
            f"SELECT COUNT(*) c FROM analysis WHERE project IN ({placeholders})",
            project_names).fetchone()["c"]
        for r in conn.execute(
                f"SELECT state, COUNT(*) c FROM analysis"
                f" WHERE project IN ({placeholders}) GROUP BY state",
                project_names):
            if r["state"] in counts:
                counts[r["state"]] = r["c"]
    finished = sum(counts.values())
    crit = high = 0
    for name in project_names:
        _br, p, _fb, _last = default_branch_posture(conn, name, None)
        crit += p["critical"]
        high += p["high"]
    return {"projects": len(project_names), "analyses": total,
            "critical": crit, "high": high,
            # None, not 0.0: no finished analysis is not a zero-percent success
            # rate, and the card shows a dash for it.
            "success_rate": (counts["done"] / finished) if finished else None}


def project_rows(conn, projects):
    """One row per project. `projects` carries name, base and description,
    read from projects.json by the caller -- the ledger does not know them."""
    out = []
    for proj in projects:
        name = proj["name"]
        branch, p, fell_back, last = default_branch_posture(conn, name, proj.get("base"))
        out.append({
            "name": name, "description": proj.get("description", ""),
            "branch": branch, "branch_fell_back": fell_back, "posture": p,
            "profile": (last or {}).get("profile", ""),
            "last_started": (last or {}).get("started", 0),
            "last_duration": (max(0, (last["ended"] or 0) - (last["started"] or 0))
                              if last else 0),
            "analyses": conn.execute(
                "SELECT COUNT(*) c FROM analysis WHERE project=?", (name,)
            ).fetchone()["c"],
            "trend": trend(conn, name, branch) if branch else []})
    return out


def trend(conn, project, branch, days=30):
    since = int(time.time()) - days * 86400
    out = []
    for a in conn.execute(
            "SELECT id, started FROM analysis WHERE project=? AND branch=?"
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
                    "open": sum(1 for f in findings if is_open(f["state"]))})
    return out


def recent_analyses(conn, limit=5):
    rows = []
    for a in conn.execute(
            "SELECT * FROM analysis ORDER BY started DESC, id DESC LIMIT ?",
            (max(1, min(int(limit), 50)),)):
        d = dict(a)
        if a["state"] in ("done", "capped"):
            _an, findings = checklist(conn, a["id"])
            d["open"] = sum(1 for f in findings if is_open(f["state"]))
        else:
            d["open"] = None      # a running analysis has no posture yet
        rows.append(d)
    return rows


def _analysed_scopes(conn, project=None):
    sql = ("SELECT DISTINCT project, branch FROM analysis"
           " WHERE state IN ('done','capped')")
    args = []
    if project:
        sql += " AND project = ?"
        args.append(project)
    return list(conn.execute(sql, args))


def severity_totals(conn, project=None, days=30):
    """Open findings by severity across the latest analysis of every branch."""
    out = _empty_posture()
    for r in _analysed_scopes(conn, project):
        p = posture(conn, r["project"], r["branch"])
        for k in out:
            out[k] += p[k]
    return out


def top_categories(conn, project=None, days=30, limit=5):
    counts = {}
    for r in _analysed_scopes(conn, project):
        a = _latest_finished(conn, r["project"], r["branch"])
        if not a:
            continue
        _an, findings = checklist(conn, a["id"])
        for f in findings:
            if is_open(f["state"]):
                counts[f["rule"]] = counts.get(f["rule"], 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"rule": k, "count": v} for k, v in ranked[:limit]]


def branch_rows(conn, project):
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
        out.append({"branch": r["branch"], "last_analysis": r["last"],
                    "analyses": r["n"],
                    "open": posture(conn, project, r["branch"]),
                    "trend": trend(conn, project, r["branch"])})
    return out


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
