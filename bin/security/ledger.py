"""Everything that touches data/security.db.

SQLite rather than JSON files because every question the area asks is a query
-- filter by severity, diff two analyses, aggregate posture -- and because the
deterministic phase writes while the page is already reading.
"""

import json
import sqlite3
import time
from pathlib import Path

# Aliased on the way in: `fingerprint` is a PARAMETER name throughout this
# module (`set_decision`, `record_finding`'s payload key), so importing the
# function under its own name would be shadowed inside exactly the functions
# most likely to want it.
from .fingerprint import fingerprint as compute_fingerprint, secret_fingerprint
# The producer name the agent's own door stamps. Re-exported rather than
# re-spelled: `record_finding` below has to recognise an agent re-report to
# mark it as a triage, and a second literal "agent" in this file is a rule that
# silently stops firing the day the name changes in one place and not the
# other. It lives in diff.py because that is where the rule that READS the
# column lives; diff.py imports nothing at all, so there is no cycle here.
from .diff import AGENT

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,
  commit_sha TEXT NOT NULL, profile TEXT NOT NULL,
  started INTEGER NOT NULL, ended INTEGER,
  state TEXT NOT NULL, spend_usd REAL NOT NULL DEFAULT 0,
  run_id TEXT NOT NULL DEFAULT '',
  coverage_note TEXT NOT NULL DEFAULT '',
  -- THE SAME COVERAGE, STRUCTURED -- a JSON document `{"phases": [...]}` (see
  -- security/coverage.py) written BESIDE the prose above and never instead of
  -- it. `coverage_note` is ~2,000 characters assembled from 27 note constants
  -- and is unreadable as one paragraph; this is one row per phase, with the
  -- status and the producer, which is what the reports and the analysis screen
  -- print FIRST. '' is the honest value for every analysis written before this
  -- column existed, and every renderer draws the prose alone for it.
  coverage TEXT NOT NULL DEFAULT '',
  -- 1 once `prepare` has actually run the deterministic phases over this
  -- analysis. It is the only thing that can tell an analysis that found
  -- nothing from one that never looked: nothing engine-side runs `prepare`,
  -- so an agent that skipped its first command used to close `done` with a
  -- clean report, an empty coverage note and no banner -- and that report
  -- became the baseline every later analysis is diffed against. See
  -- `cmd_finish`, which refuses to record `done` without it.
  prepared INTEGER NOT NULL DEFAULT 0,
  -- WHICH PRODUCERS ACTUALLY RAN in this analysis's `prepare`, comma
  -- separated (see `mark_prepared`). `prepared` says the deterministic half
  -- ran; this says WHAT ran, which is a different fact and the one
  -- `diff._proven` needs. Trivy absent means the `iac` phase produced
  -- nothing because nobody looked, and `prepared` alone cannot tell that
  -- from a Dockerfile that is genuinely clean.
  produced TEXT NOT NULL DEFAULT '');

CREATE INDEX IF NOT EXISTS analysis_by_scope ON analysis(project, repo, branch);

CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analysis(id),
  fingerprint TEXT NOT NULL, category TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
  partial_note TEXT NOT NULL DEFAULT '',
  -- The classification, derived from the rule name by taxonomy.classify()
  -- and never accepted from the agent -- see cmd_report_finding. Empty for
  -- every deterministic category, which has no SAST rule to classify, and
  -- for the `other` escape hatch, whose whole point is to be visibly
  -- unclassified rather than quietly mislabelled.
  cwe TEXT NOT NULL DEFAULT '', owasp TEXT NOT NULL DEFAULT '',
  -- WHICH PRODUCER MINTED THIS IDENTITY -- 'trivy', 'osv', 'gitleaks',
  -- 'secrets', 'hygiene', 'trivy-iac', 'semgrep', or 'agent'. Read by
  -- `diff._proven` against the analysis's own `produced` above: only the
  -- producer that could re-find a finding can prove it gone. Never the LAST
  -- writer -- see `record_finding`, where a re-report deliberately leaves
  -- this column alone.
  producer TEXT NOT NULL DEFAULT '',
  -- WHETHER A VULNERABLE DEPENDENCY SHIPS -- 'runtime', 'dev', 'unknown', or
  -- '' on any finding that is not a dependency at all. Set by whichever of the
  -- two dependency producers ran, from one shared rule (deps.merge_scope), and
  -- never accepted from the agent -- see cmd_report_finding, for the reason
  -- cwe/owasp are not accepted either. 'unknown' is a real answer and is NOT
  -- the same as '': it means a producer read the lockfile and the format could
  -- not say. Deliberately NOT a fingerprint input, so it can be corrected
  -- without re-identifying anything: ledger._REFINGERPRINT has no `dependency`
  -- entry, and a change to that category's identity is unrecoverable.
  scope TEXT NOT NULL DEFAULT '',
  -- WHETHER ANYBODY EVER READ THIS FINDING. 1 once the AGENT has re-reported
  -- a finding a SCANNER minted -- Job 2 of skills/security-analysis/SKILL.md,
  -- the triage this module's whole design rests on: the deterministic phases
  -- are noisy on purpose and the noise is meant to be sorted by an agent that
  -- reads the surrounding code, not by heuristics.
  --
  -- WRITTEN AS AN EVENT, NEVER READ FROM A PAYLOAD (see `record_finding`): a
  -- finding is triaged because a re-report with its own severity and
  -- rationale landed on it, which is the only trace the reading leaves. A
  -- `triaged: true` field the agent could send would be exactly the same
  -- unverified claim as the `done` that `cmd_finish` reads this column to
  -- check. Measured cost of not having it: analyses 9 and 10 on Minerva each
  -- closed `done` having triaged ZERO of the ~40 deterministic findings
  -- waiting for them, and the reports said nothing about it.
  triaged INTEGER NOT NULL DEFAULT 0,
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
    # The producers that ran. See the column's own comment in _SCHEMA.
    ("produced", "TEXT NOT NULL DEFAULT ''"),
    # The coverage note's structure. See the column's own comment in _SCHEMA.
    # Additive in the strongest sense the table has: nothing derives a state
    # from it, and '' -- what every existing row gets -- is what the renderers
    # already treat as "print the prose and no table", so an unmigrated row is
    # not merely tolerated, it renders exactly as it did yesterday.
    ("coverage", "TEXT NOT NULL DEFAULT ''"),
)


# Columns added to `finding` after the table's first shape. Same mechanism,
# same reason, as _ANALYSIS_COLUMNS above: executescript() does nothing to a
# table that already exists, and the dev databases on the branch's machines
# already have `finding`.
_FINDING_COLUMNS = (
    ("cwe", "TEXT NOT NULL DEFAULT ''"),
    ("owasp", "TEXT NOT NULL DEFAULT ''"),
    # Who minted this identity. See the column's own comment in _SCHEMA.
    ("producer", "TEXT NOT NULL DEFAULT ''"),
    # Whether the vulnerable dependency ships. See the column's own comment in
    # _SCHEMA. Additive in the same way `cwe` and `owasp` were: no existing row
    # becomes wrong for carrying the '' default, only less annotated, and
    # nothing derives a state from it.
    ("scope", "TEXT NOT NULL DEFAULT ''"),
    # Whether the agent ever read this finding. See the column's own comment in
    # _SCHEMA. Additive exactly as the four above are, and the 0 default is the
    # honest reading for every row written before the column existed: nothing
    # recorded that anybody looked.
    ("triaged", "INTEGER NOT NULL DEFAULT 0"),
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
    have = {r["name"] for r in conn.execute("PRAGMA table_info(finding)")}
    for name, ddl in _FINDING_COLUMNS:
        if name not in have:
            # Same guarantee as the analysis loop above: both halves are
            # literals in the tuple, and PRAGMA has said the column is absent.
            conn.execute(f"ALTER TABLE finding ADD COLUMN {name} {ddl}")
    conn.commit()
    return conn


def mark_prepared(conn, analysis_id, produced=()) -> None:
    """Record that the deterministic phases ran over this analysis, and WHICH
    producers among them actually ran.

    ONE STATEMENT for both columns, deliberately. `prepared` is what lets
    `finish` record `done`, and `produced` is what lets `diff._proven` tell a
    phase that found nothing from a phase that never looked -- an analysis
    holding one without the other is a ledger that can still make the false
    remediation claim this column was added to end. Written last in
    `cmd_prepare`, after the findings are in, for the reason that call site
    gives.

    `produced` is stored comma separated because it is a small closed set of
    identifiers this module writes and reads back -- no producer name contains
    a comma, `_producers` is what turns it back into a set, and a JSON array
    would buy nothing but a parse.
    """
    conn.execute("UPDATE analysis SET prepared=1, produced=? WHERE id=?",
                 (",".join(sorted({p for p in produced if p})), analysis_id))
    conn.commit()


def producers_of(row) -> set:
    """The `produced` column of an analysis row, as a set.

    A function rather than a `.split(",")` at each call site: `""` splits to
    `[""]`, and a stray empty string in that set would make a finding whose
    `producer` is somehow empty read as proven -- exactly the wrong direction
    to fail in.
    """
    raw = (row["produced"] if "produced" in row.keys() else "") or ""
    return {p for p in raw.split(",") if p}


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


def finish_analysis(conn, analysis_id, state, spend_usd=0.0, coverage_note="",
                    coverage="") -> None:
    """Close the row, and write BOTH halves of the coverage together.

    `coverage` is the structured twin of `coverage_note` (see
    security/coverage.py). It is written in the SAME statement and on the same
    terms as the prose -- what the caller passes replaces what is stored -- so
    the two can never end up describing different analyses. `cmd_finish` is
    the only caller that has anything to say here, and it merges the stored
    document before passing it back, exactly as it already does for the note.
    """
    if state not in ANALYSIS_END_STATES:
        raise ValueError(f"bad analysis state: {state}")
    conn.execute(
        "UPDATE analysis SET ended=?, state=?, spend_usd=?, coverage_note=?,"
        " coverage=? WHERE id=?",
        (int(time.time()), state, spend_usd, coverage_note, coverage, analysis_id))
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
    #
    # `producer` IS THE ONE COLUMN THE UPSERT DOES NOT TOUCH, and that is the
    # whole point of it. It records who MINTED this identity, not who wrote
    # the row last -- and the agent's triage job (Job 2 in the skill) is
    # explicitly to re-report a deterministic finding with a corrected
    # severity and rationale. Letting that re-report stamp `agent` over
    # `trivy-iac` would hand the finding's absence-proof to the analysis
    # closing `done`, which is precisely the false `fixed` `diff._proven`
    # exists to prevent -- reintroduced through the one door that is supposed
    # to improve a finding. `prepare` always runs before the agent (see
    # `cmd_finish`'s `prepared` guard), so the first writer is always the
    # minting one.
    #
    # `scope` IS THE SECOND SUCH COLUMN, left alone by the upsert for the same
    # reason plus one of its own. It is a fact about the LOCKFILE, established
    # by the producer that read it; the agent never reads a lockfile and
    # `cmd_report_finding` does not accept the field, so a re-report carries no
    # value for it. Updating it anyway would write '' over a `dev` the
    # dependency phase had correctly established, and the row would come out of
    # triage LESS annotated than it went in -- again through the one door whose
    # whole purpose is to improve a finding.
    #
    # `triaged` IS THE ONE COLUMN THE UPSERT WRITES THAT THE PAYLOAD CANNOT
    # NAME. The re-report described two paragraphs up is not merely a better
    # row: it is the only evidence that exists that anybody READ the scanner's
    # finding before the analysis closed, and `cmd_finish` refuses to record
    # `done` without it. So the mark is derived here, from who minted the row
    # against who is writing it now, rather than accepted as a field -- a
    # `triaged: true` an agent could send would be the same unverified claim as
    # the `done` it is checked against.
    #
    # Three conditions, each one a case that must NOT count as triage:
    #   - the writer is the agent. `prepare` writes through this same function,
    #     and a second deterministic phase landing on a fingerprint the first
    #     one recorded has read a file, not a finding.
    #   - the row was minted by somebody else. An agent re-reporting its own
    #     `sast` row is revising its own work; counting it would make the gate
    #     satisfiable without ever opening a scanner's output.
    #   - the minting producer is known at all. '' is a row from before the
    #     `producer` column existed, and "somebody unknown looked" is not a
    #     fact this column is allowed to invent.
    # MAX(triaged, ?) rather than a plain assignment, because a row is written
    # more than twice in a real analysis and a later write that happens not to
    # qualify must not erase the reading that already happened.
    with conn:
        existing = conn.execute(
            "SELECT id, producer FROM finding WHERE analysis_id=? AND fingerprint=?",
            (analysis_id, finding["fingerprint"])).fetchone()
        if existing is not None:
            fid = existing["id"]
            minted_by = (existing["producer"] or "").strip()
            written_by = (finding.get("producer") or "").strip()
            triaged = int(written_by == AGENT and minted_by not in ("", AGENT))
            conn.execute(
                "UPDATE finding SET category=?, rule=?, severity=?, title=?,"
                " rationale=?, remediation=?, partial_note=?, cwe=?, owasp=?,"
                " triaged=MAX(triaged, ?)"
                " WHERE id=?",
                (finding["category"], finding["rule"], finding["severity"], finding["title"],
                 finding.get("rationale", ""), finding.get("remediation", ""),
                 finding.get("partial_note", ""), finding.get("cwe", ""),
                 finding.get("owasp", ""), triaged, fid))
            conn.execute("DELETE FROM occurrence WHERE finding_id=?", (fid,))
        else:
            cur = conn.execute(
                "INSERT INTO finding (analysis_id, fingerprint, category, rule, severity,"
                " title, rationale, remediation, partial_note, cwe, owasp, producer,"
                " scope)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (analysis_id, finding["fingerprint"], finding["category"], finding["rule"],
                 finding["severity"], finding["title"], finding.get("rationale", ""),
                 finding.get("remediation", ""), finding.get("partial_note", ""),
                 finding.get("cwe", ""), finding.get("owasp", ""),
                 finding.get("producer", ""), finding.get("scope", "")))
            fid = cur.lastrowid
        for occ in finding.get("occurrences", []):
            conn.execute(
                "INSERT INTO occurrence (finding_id, file, line, snippet_hash) VALUES (?,?,?,?)",
                (fid, occ.get("file", ""), int(occ.get("line", 0)), occ.get("snippet_hash", "")))


# How to rebuild a finding's fingerprint after its rule has been renamed, per
# category. The fourth argument to `fingerprint()` differs by source, and it
# is what decides whether a rename is possible at all -- so the recipe lives
# here, beside the list of categories that HAVE one, rather than in an `if`
# somewhere downstream that could drift from the source that mints them:
#
#   secret      `secret_fingerprint(rule, path)` -- there is no fourth
#               argument (fingerprint.py). Derivable from rule + path.
#   hygiene     `fingerprint("hygiene", rule, rel, rule)` -- the fourth
#               argument IS the rule (hygiene.py). Derivable from rule + path.
#               NOTE it is the RULE, not the occurrence's `snippet_hash`:
#               hygiene occurrences carry an empty hash, so using it here
#               would mint a fingerprint hygiene.py can never emit.
#   dependency  `f"{name}@{version}"` (osv.py) -- recoverable only by parsing
#               the title back, and the `rule` is a GHSA/CVE id that nobody
#               renames. No case to serve, and a fragile way to serve it.
#   sast        the actual code snippet -- which the ledger NEVER stores. The
#               `occurrence.snippet_hash` column is "" from every
#               deterministic source and an opaque digest when the agent
#               sends one; neither can be turned back into the text
#               `fingerprint()` normalises. NOT derivable.
#   iac         TECHNICALLY derivable -- `fingerprint("iac", rule, target,
#               rule)` (built in adapters.py's `_iac_finding`, called from
#               `trivy_misconfigs`) is exactly hygiene's shape, rule + path
#               and nothing else -- and DELIBERATELY left out all the same.
#               Hygiene's four rule names are OUR OWN literals, sitting in
#               hygiene.py; a rename there is us changing our own vocabulary,
#               and RULE_RENAMES exists for exactly that (its six live entries
#               are secret's own move from snake_case names to gitleaks'
#               kebab-case ones). An `iac` rule is never that: it is Trivy's
#               own check id, verbatim -- the identical relationship
#               `dependency`'s GHSA/CVE id already has to this table, which is
#               why that comment reads "nobody renames" rather than "cannot be
#               rebuilt" alone. Nothing here curates which check ids Trivy can
#               emit the way `adapters.SEVERITY_BY_RULE` curates a subset of
#               gitleaks' -- there is no vocabulary a rename target could be
#               checked against -- so adding an entry would pass every test
#               this table has today and still open a route with no real
#               caller and no way to validate one. If Trivy ever renumbers a
#               check id, the ledger reports the old finding `fixed` and the
#               new one `new` once, the same tolerated cost `dependency`'s own
#               entries already accept from Trivy and OSV.dev -- not a case
#               this table exists to smooth over. This is not hypothetical:
#               Aqua has done it before (`DS002` became `DS-0002`, `KSV001`
#               became `KSV-0001`), and the check-id space is versioned by
#               whichever check bundle a given Trivy build ships -- so a fleet
#               running mixed Trivy versions across its projects mints TWO
#               identities for the same hole the moment one machine upgrades
#               and another does not -- the concrete way this exposure
#               arrives, not a hypothetical invented for this comment.
_REFINGERPRINT = {
    "secret": lambda rule, path: secret_fingerprint(rule, path),
    "hygiene": lambda rule, path: compute_fingerprint("hygiene", rule, path, rule),
}

# Derived from the recipes above, deliberately: a category becomes renameable
# by someone writing down how its fingerprint is rebuilt, never by being added
# to a list.
RENAMEABLE_CATEGORIES = tuple(sorted(_REFINGERPRINT))


def rename_rule(conn, category: str, old: str, new: str) -> int:
    """Move every `category` finding from rule `old` to rule `new`, keeping
    its identity and the human decision attached to it.

    The rule name is an INPUT TO THE FINGERPRINT, so renaming the rule without
    recomputing the fingerprint leaves a finding whose stored identity no
    longer matches what the scanner will produce for it: the next analysis
    reports the same hole `fixed` (the old identity vanished) and `new` (a
    fresh one appeared) in one report, and the old row is never matched again.

    The `decision` table is keyed by fingerprint, and that is why this is not
    a one-line UPDATE: a human's `accepted`/`false_positive` call -- permanent,
    project-wide, and carrying a written reason it was mandatory to type --
    has to follow the finding to its new identity or it is silently lost. The
    update is NOT scoped to a project: the same fingerprint can be decided in
    several projects, and they all move together.

    The `decision_made` EVENT moves too, for the same reason one step further
    on: the decision is the fact, and the event is the record that a human took
    it about this finding. Its `related` column holds the fingerprint's first
    12 characters and the Activity screen deep-links from that prefix into the
    findings browser, so a rename that moved the decision and not the event
    would leave an audit trail whose one link resolves to nothing.

    Returns the number of findings moved. Idempotent: a second run finds
    nothing under `old` and returns 0.

    ONE TRANSACTION, for the reason `record_finding` uses one. A rename that
    stopped halfway is a ledger where some findings answer to the new name
    and some to the old, with decisions stranded between them -- worse than
    one that never ran. Two collisions can abort it, and both leave the
    ledger untouched rather than half-migrated: renaming onto a name the same
    analysis already holds at the same path violates
    `UNIQUE(analysis_id, fingerprint)`, and moving a decision onto a
    fingerprint the same project has already decided violates
    `decision`'s primary key. Both are the "merging two rules that meant
    different things" case, which RULE_RENAMES' own comment forbids, and
    SQLite refusing loudly is the right answer to it.

    Refuses any category whose fingerprint cannot be rebuilt from what the
    ledger stores -- see `_REFINGERPRINT` above. A rename that silently
    produced a wrong fingerprint would orphan the finding and leave its human
    decision pointing at an identity no future analysis will ever produce
    again: worse than refusing, because nothing would tell anyone it happened.
    """
    recompute = _REFINGERPRINT.get(category)
    if recompute is None:
        raise ValueError(
            f"cannot rename a {category!r} rule: its fingerprint cannot be "
            f"rebuilt from the ledger. Only {', '.join(RENAMEABLE_CATEGORIES)} "
            "derive their identity from the rule and the path alone -- a "
            "dependency rule is a vulnerability id nobody renames, and a sast "
            "fingerprint is built from the code snippet itself, which the "
            "ledger never stores (only an opaque snippet_hash). Renaming one "
            "anyway would write an identity no future analysis can reproduce, "
            "orphaning the finding and pointing its decision at a fingerprint "
            "nothing will ever match again.")
    with conn:
        rows = conn.execute(
            "SELECT id, fingerprint FROM finding WHERE category=? AND rule=?"
            " ORDER BY id", (category, old)).fetchall()
        for row in rows:
            # The FIRST occurrence's file. Both renameable categories put the
            # path in their identity and can only ever have occurrences in the
            # one file that identity names -- several matches of one secret
            # type in one file are one finding with several occurrences (see
            # secret_fingerprint), and a hygiene finding is about a single
            # path.
            occ = conn.execute(
                "SELECT file FROM occurrence WHERE finding_id=? ORDER BY id LIMIT 1",
                (row["id"],)).fetchone()
            if occ is None or not occ["file"]:
                # NO occurrence, or an occurrence with an EMPTY path: the same
                # thing for this purpose, because the path is half of the
                # identity. Both are reachable. `report-finding` treats
                # occurrences as optional, and it validates only that each one
                # is an object -- `{"line": 3}` passes that check, and
                # `record_finding` stores its `file` as `occ.get("file", "")`.
                # Testing only for the missing ROW would let the empty PATH
                # through to `secret_fingerprint(new, "")`: a well-formed
                # identity no scanner will ever emit, minted silently by the
                # branch two lines below the guard that refuses to guess it.
                # Refusing is the same call as refusing `sast`.
                raise ValueError(
                    f"finding {row['id']} ({category}/{old}) has no occurrence "
                    "carrying a file path -- and the path is half of its "
                    "identity. Its fingerprint cannot be rebuilt; renaming it "
                    "would orphan it.")
            new_fp = recompute(new, occ["file"])
            conn.execute("UPDATE finding SET rule=?, fingerprint=? WHERE id=?",
                         (new, new_fp, row["id"]))
            # Keyed off the STORED fingerprint, not a recomputed one: that is
            # what any decision was filed against, even if the row's identity
            # was minted by hand rather than by the scanner.
            conn.execute("UPDATE decision SET fingerprint=? WHERE fingerprint=?",
                         (new_fp, row["fingerprint"]))
            # The decision moved, so the audit record of the decision moves
            # with it. `cmd_decide` files a `decision_made` event whose
            # `related` column holds the fingerprint's first 12 characters, and
            # the Activity screen deep-links from that prefix into the findings
            # browser (`secActOpenFinding`). Left behind, it is a row saying a
            # human accepted this risk that now matches no finding at all: the
            # decision survives the rename and the evidence that it was taken
            # about THIS finding does not. The same `[:12]` slice as
            # `cmd_decide`, deliberately -- it is what makes the two agree.
            # Scoped to `decision_made` because that is the only kind whose
            # `related` is a fingerprint prefix; the other three carry an
            # analysis id.
            conn.execute(
                "UPDATE event SET related=? WHERE kind='decision_made' AND related=?",
                (new_fp[:12], row["fingerprint"][:12]))
    return len(rows)


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
