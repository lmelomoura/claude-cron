"""Everything that touches data/security.db.

SQLite rather than JSON files because every question the area asks is a query
-- filter by severity, diff two analyses, aggregate posture -- and because the
deterministic phase writes while the page is already reading.
"""

import json
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,
  commit_sha TEXT NOT NULL, profile TEXT NOT NULL,
  started INTEGER NOT NULL, ended INTEGER,
  state TEXT NOT NULL, spend_usd REAL NOT NULL DEFAULT 0,
  run_id TEXT NOT NULL DEFAULT '',
  coverage_note TEXT NOT NULL DEFAULT '',
  -- 1 once `prepare` has actually run the deterministic phases over this
  -- analysis. It is the only thing that can tell an analysis that found
  -- nothing from one that never looked: nothing engine-side runs `prepare`,
  -- so an agent that skipped its first command used to close `done` with a
  -- clean report, an empty coverage note and no banner -- and that report
  -- became the baseline every later analysis is diffed against. See
  -- `cmd_finish`, which refuses to record `done` without it.
  prepared INTEGER NOT NULL DEFAULT 0);

CREATE INDEX IF NOT EXISTS analysis_by_scope ON analysis(project, repo, branch);

CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analysis(id),
  fingerprint TEXT NOT NULL, category TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
  partial_note TEXT NOT NULL DEFAULT '',
  -- The deterministic phase (cmd_prepare) and the agent's report-finding
  -- command can both record the same fingerprint into one analysis -- the
  -- agent's triage job is explicitly to RE-REPORT a deterministic finding
  -- with a corrected severity and rationale. Without this constraint that
  -- produces two rows for one vulnerability, which classify() then reports
  -- as two contradictory checklist entries. record_finding() upserts on it.
  --
  -- NOTE: this whole block runs through executescript() with IF NOT EXISTS,
  -- which does NOT retrofit a constraint onto a table that already exists --
  -- it only affects table creation. This is safe today because this feature
  -- has never shipped and no database exists in the wild. If that stops
  -- being true, adding this constraint needs an actual migration, not a
  -- change to this string.
  UNIQUE(analysis_id, fingerprint));
CREATE INDEX IF NOT EXISTS finding_by_analysis ON finding(analysis_id);
CREATE INDEX IF NOT EXISTS finding_by_fp ON finding(fingerprint);

CREATE TABLE IF NOT EXISTS occurrence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL REFERENCES finding(id),
  file TEXT NOT NULL, line INTEGER NOT NULL DEFAULT 0,
  snippet_hash TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS occurrence_by_finding ON occurrence(finding_id);

-- Keyed by project, not by branch: dismissing a false positive on develop and
-- watching it resurrect on main would make the feature unusable.
CREATE TABLE IF NOT EXISTS decision (
  project TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, reason TEXT NOT NULL,
  decided_by TEXT NOT NULL DEFAULT '', decided_at INTEGER NOT NULL,
  PRIMARY KEY (project, fingerprint));

CREATE TABLE IF NOT EXISTS sbom (
  project TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,
  analysis_id INTEGER NOT NULL, document TEXT NOT NULL,
  PRIMARY KEY (project, repo, branch));

-- What happened, in order. No user column and no IP: this install has one
-- operator, enforced by app.db's own CHECK (id = 1), and a column that can
-- only ever hold one value teaches nothing.
CREATE TABLE IF NOT EXISTS event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL, kind TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '', related TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS event_by_project_time ON event(project, at DESC);

-- A named set of filters per project -- the view somebody works from every
-- day, one click instead of six. Keyed (project, name): saving under a name
-- that already exists is a REPLACE, not a second row, so re-saving "mine"
-- after tweaking it updates the filter in place rather than leaving the old
-- version behind under the same name.
CREATE TABLE IF NOT EXISTS saved_filter (
  project TEXT NOT NULL, name TEXT NOT NULL,
  query TEXT NOT NULL, saved_at INTEGER NOT NULL,
  PRIMARY KEY (project, name));
"""

DECISION_STATES = ("accepted", "false_positive")
ANALYSIS_END_STATES = ("done", "failed", "capped")

# A closed set. A typo must fail loudly rather than file an event that no
# filter will ever match and no screen will ever show.
EVENT_KINDS = ("analysis_started", "analysis_finished", "decision_made",
               "settings_changed", "report_exported")


# Columns added to `analysis` after the table's first shape, as
# (name, DDL fragment). `executescript(_SCHEMA)` runs CREATE TABLE IF NOT
# EXISTS, which does NOTHING to a table that already exists -- so a column
# added to the string above reaches a fresh database and no other. This
# feature has never shipped, so there is no installed base to migrate; what
# DOES exist is the dev database on the branch's own machines, and an engine
# that crashed with "no such column" against it would be a bad way to find
# that out. Handled by ALTER TABLE, guarded by PRAGMA table_info, rather than
# by a migration framework this repository does not have and does not need for
# one column.
_ANALYSIS_COLUMNS = (
    ("prepared", "INTEGER NOT NULL DEFAULT 0"),
    # The size of what was analysed. 0 means "not counted" -- every analysis
    # written before this column existed -- and the page shows a dash for it
    # rather than a zero that reads as an empty repository.
    ("lines_of_code", "INTEGER NOT NULL DEFAULT 0"),
)


def connect(path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    have = {r["name"] for r in conn.execute("PRAGMA table_info(analysis)")}
    for name, ddl in _ANALYSIS_COLUMNS:
        if name not in have:
            # No user input reaches this string: both halves are literals in
            # the tuple above, and PRAGMA table_info has already said the
            # column is absent.
            conn.execute(f"ALTER TABLE analysis ADD COLUMN {name} {ddl}")
    conn.commit()
    return conn


def mark_prepared(conn, analysis_id) -> None:
    """Record that the deterministic phases ran over this analysis."""
    conn.execute("UPDATE analysis SET prepared=1 WHERE id=?", (analysis_id,))
    conn.commit()


def set_lines_of_code(conn, analysis_id, lines) -> None:
    """Record the size of what was actually analysed, in lines."""
    with conn:
        conn.execute("UPDATE analysis SET lines_of_code=? WHERE id=?",
                     (int(lines), analysis_id))


def start_analysis(conn, project, repo, branch, commit_sha, profile, run_id) -> int:
    cur = conn.execute(
        "INSERT INTO analysis (project, repo, branch, commit_sha, profile,"
        " started, state, run_id) VALUES (?,?,?,?,?,?,'running',?)",
        (project, repo, branch, commit_sha, profile, int(time.time()), run_id))
    conn.commit()
    return cur.lastrowid


def finish_analysis(conn, analysis_id, state, spend_usd=0.0, coverage_note="") -> None:
    if state not in ANALYSIS_END_STATES:
        raise ValueError(f"bad analysis state: {state}")
    conn.execute(
        "UPDATE analysis SET ended=?, state=?, spend_usd=?, coverage_note=? WHERE id=?",
        (int(time.time()), state, spend_usd, coverage_note, analysis_id))
    conn.commit()


def record_finding(conn, analysis_id, finding: dict) -> None:
    # A finding and its occurrences are one unit: without this transaction
    # boundary, an occurrence that fails to insert midway (a non-numeric
    # line, say) would leave the finding row committed by whatever later
    # commit() happens on this connection -- a checklist entry with no
    # evidence for why it was flagged.
    #
    # A finding is identified within one analysis by (analysis_id, fingerprint)
    # -- see the UNIQUE constraint on `finding`. Re-recording the same pair
    # (the agent re-reporting a deterministic finding with a corrected
    # severity and rationale) is an UPSERT, not a second row: the finding's
    # fields are replaced with the new values, and its occurrences are
    # REPLACED (old ones deleted, new ones inserted), not appended -- an
    # append would double them on every re-report. This all stays inside the
    # same `with conn:` block as the insert path, so a failed re-report
    # (occurrences fail to insert) rolls back the field update and the
    # deletion too, instead of leaving the finding with half its occurrences.
    with conn:
        existing = conn.execute(
            "SELECT id FROM finding WHERE analysis_id=? AND fingerprint=?",
            (analysis_id, finding["fingerprint"])).fetchone()
        if existing is not None:
            fid = existing["id"]
            conn.execute(
                "UPDATE finding SET category=?, rule=?, severity=?, title=?,"
                " rationale=?, remediation=?, partial_note=? WHERE id=?",
                (finding["category"], finding["rule"], finding["severity"], finding["title"],
                 finding.get("rationale", ""), finding.get("remediation", ""),
                 finding.get("partial_note", ""), fid))
            conn.execute("DELETE FROM occurrence WHERE finding_id=?", (fid,))
        else:
            cur = conn.execute(
                "INSERT INTO finding (analysis_id, fingerprint, category, rule, severity,"
                " title, rationale, remediation, partial_note) VALUES (?,?,?,?,?,?,?,?,?)",
                (analysis_id, finding["fingerprint"], finding["category"], finding["rule"],
                 finding["severity"], finding["title"], finding.get("rationale", ""),
                 finding.get("remediation", ""), finding.get("partial_note", "")))
            fid = cur.lastrowid
        for occ in finding.get("occurrences", []):
            conn.execute(
                "INSERT INTO occurrence (finding_id, file, line, snippet_hash) VALUES (?,?,?,?)",
                (fid, occ.get("file", ""), int(occ.get("line", 0)), occ.get("snippet_hash", "")))


def findings_of(conn, analysis_id) -> list:
    rows = conn.execute(
        "SELECT * FROM finding WHERE analysis_id=? ORDER BY id", (analysis_id,)).fetchall()
    out = []
    for r in rows:
        occ = conn.execute(
            "SELECT file, line, snippet_hash FROM occurrence WHERE finding_id=? ORDER BY id",
            (r["id"],)).fetchall()
        d = dict(r)
        d["occurrences"] = [dict(o) for o in occ]
        out.append(d)
    return out


def set_decision(conn, project, fingerprint, state, reason, decided_by) -> None:
    if state not in DECISION_STATES:
        raise ValueError(f"bad decision state: {state}")
    if not (reason or "").strip():
        # A decision without a written reason is indistinguishable from a
        # mistake three months later, and it outlives every future analysis.
        raise ValueError("a decision needs a reason")
    conn.execute(
        "INSERT INTO decision (project, fingerprint, state, reason, decided_by, decided_at)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(project, fingerprint) DO UPDATE SET"
        " state=excluded.state, reason=excluded.reason,"
        " decided_by=excluded.decided_by, decided_at=excluded.decided_at",
        (project, fingerprint, state, reason.strip(), decided_by, int(time.time())))
    conn.commit()


def decisions_for(conn, project) -> dict:
    rows = conn.execute("SELECT * FROM decision WHERE project=?", (project,)).fetchall()
    return {r["fingerprint"]: dict(r) for r in rows}


def latest_analysis(conn, project, repo, branch, before=None):
    """The most recent FINISHED analysis of this repo+branch.

    A running analysis is not a baseline: comparing against a half-written set
    of findings would report everything the agent has not reached yet as fixed.
    """
    sql = ("SELECT * FROM analysis WHERE project=? AND repo=? AND branch=?"
           " AND state IN ('done','capped')")
    args = [project, repo, branch]
    if before is not None:
        sql += " AND id < ?"
        args.append(before)
    sql += " ORDER BY id DESC LIMIT 1"
    row = conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def store_sbom(conn, project, repo, branch, analysis_id, document: dict) -> None:
    conn.execute(
        "INSERT INTO sbom (project, repo, branch, analysis_id, document) VALUES (?,?,?,?,?)"
        " ON CONFLICT(project, repo, branch) DO UPDATE SET"
        " analysis_id=excluded.analysis_id, document=excluded.document",
        (project, repo, branch, analysis_id, json.dumps(document)))
    conn.commit()


def record_event(conn, project, kind, detail="", related="") -> None:
    if kind not in EVENT_KINDS:
        raise ValueError(f"unknown event kind: {kind}")
    with conn:
        conn.execute(
            "INSERT INTO event (project, kind, detail, related, at)"
            " VALUES (?,?,?,?,?)",
            (project, kind, str(detail)[:500], str(related)[:120],
             int(time.time())))


def events_for(conn, project=None, kinds=(), since=0, limit=100, offset=0):
    sql = "SELECT * FROM event WHERE at >= ?"
    args = [int(since)]
    if project:
        sql += " AND project = ?"
        args.append(project)
    if kinds:
        sql += " AND kind IN (" + ",".join("?" * len(kinds)) + ")"
        args.extend(kinds)
    sql += " ORDER BY at DESC, id DESC LIMIT ? OFFSET ?"
    args.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
    return [dict(r) for r in conn.execute(sql, args)]


MAX_FILTER_NAME = 80


def save_filter(conn, project, name, query) -> None:
    """Save (or replace) a named filter for a project.

    Keyed (project, name): saving under a name that already exists is an
    UPSERT, not a second row -- re-saving "mine" after tweaking it updates
    the filter in place, the same way `set_decision` replaces rather than
    accumulates.

    A name over MAX_FILTER_NAME characters is REFUSED, not truncated. This
    used to truncate to `name[:80]` before the primary key ever saw it, which
    produced two separate bugs from one root cause: a name over the limit
    could never be deleted by what the user actually typed (`delete_filter`
    matches the full string, so it always missed the truncated row that sat
    in its place), and two different names sharing their first 80 characters
    silently overwrote each other, because truncation ran before `(project,
    name)` had a chance to tell them apart. Refusing instead of truncating
    fixes both: the key stored is always exactly what was asked for, so
    `delete_filter` is correct without itself being touched, and no two
    distinct inputs can ever collide into one row.
    """
    name = (name or "").strip()
    if not name:
        # A filter with no name is one nobody could ever pick back out of the
        # list -- the same reasoning `set_decision` refuses a blank reason.
        raise ValueError("a saved filter needs a name")
    if len(name) > MAX_FILTER_NAME:
        raise ValueError(
            f"a saved filter name is limited to {MAX_FILTER_NAME} characters, "
            f"got {len(name)}")
    with conn:
        conn.execute(
            "INSERT INTO saved_filter (project, name, query, saved_at)"
            " VALUES (?,?,?,?) ON CONFLICT(project, name) DO UPDATE SET"
            " query=excluded.query, saved_at=excluded.saved_at",
            (project, name, json.dumps(query), int(time.time())))


def saved_filters(conn, project):
    out = []
    for r in conn.execute(
            "SELECT * FROM saved_filter WHERE project=? ORDER BY name",
            (project,)):
        d = dict(r)
        try:
            d["query"] = json.loads(d["query"])
        except ValueError:
            # A filter nobody can parse is a filter nobody can apply. Keep the
            # row visible so it can be deleted, with an empty query rather than
            # a crash that takes the whole list with it.
            d["query"] = {}
        out.append(d)
    return out


def delete_filter(conn, project, name) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM saved_filter WHERE project=? AND name=?",
                           (project, name))
    return cur.rowcount > 0
