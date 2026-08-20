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
  coverage_note TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analysis(id),
  fingerprint TEXT NOT NULL, category TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
  partial_note TEXT NOT NULL DEFAULT '');
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
"""

DECISION_STATES = ("accepted", "false_positive")
ANALYSIS_END_STATES = ("done", "failed", "capped")


def connect(path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


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
    conn.commit()


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
