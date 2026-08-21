# Security Area Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** turn the Security area from one screen into four — index, project detail, findings browser, activity — showing what the ledger already knows and never an invented number.

**Architecture:** the server reads `data/security.db` **read-only** through a new `bin/security/queries.py`; every write stays behind `bin/security/cli.py`. The area's JavaScript moves out of `dashboard.html` into `ui/security/`, bundled by a pinned `esbuild` into a **committed** `bin/static/security.js` and served by a new static route — so installing still needs only jq, python3 and curl.

**Tech Stack:** Python 3 stdlib, SQLite, bash 3.2, vanilla ES modules + esbuild, the dashboard's existing CSS.

**Spec:** `docs/superpowers/specs/2026-08-21-security-area-redesign-design.md` — read it before Task 1.

## Global Constraints

- **Python 3 standard library only** in `bin/`. No pip. `esbuild` is a dev dependency of the UI build, never of the install.
- **The install promise holds:** `bash install.sh` must keep working with only jq, python3 and curl. The bundle is committed; nothing builds at install time.
- **The server never writes to `security.db`.** Its connection is opened `mode=ro`. Every mutation shells out to `bin/security/cli.py`.
- **Nothing outside the Security area changes.** Overview, Jobs, Runs and Projects stay as they are.
- **Every string that came from analysed code reaches the DOM through `textContent`** — never `innerHTML`, `insertAdjacentHTML`, `outerHTML` or `setAttribute("on…")`.
- **Numbers are current posture, not all-time sums.** "Open" = not `fixed`, `accepted` or `false_positive` — **`pending` counts as open**. "Success rate" = `done` ÷ (`done`+`capped`+`failed`).
- **A secret's value never reaches the ledger, a report, a log or the page.**
- Code, identifiers, docstrings, comments and commit messages in **English**; the specs and plans in this repo are the only pt-PT prose.
- `CHANGELOG.md` in the same commit as any change under `bin/`, `ui/`, `skills/` or `test/`.

## File Structure

| File | Responsibility |
|---|---|
| `bin/security/queries.py` | every read of the ledger the server serves; read-only connection |
| `bin/security/ledger.py` | schema: new `event`, `saved_filter` tables, `lines_of_code` column |
| `bin/security/cli.py` | new verbs: `event`, `filters`, and the wiring that records events |
| `bin/security/secrets.py` | counts lines while it already walks the tree |
| `bin/security/hygiene.py` | the advisory `.gitignore` rule that produces `info` |
| `bin/claude-cron-server` | `/static/*` route, the Security API endpoints |
| `bin/claude-cron` | CLI dispatch for the new verbs; selftest assertions |
| `ui/security/*.js` | one module per screen, plus `api.js` and `render.js` |
| `bin/static/security.js` | the committed bundle |
| `build/build-ui.sh` | the esbuild invocation, pinned |

---

## Task 1: Lines of code, counted where the tree is already walked

**Files:**
- Modify: `bin/security/ledger.py` (`_ANALYSIS_COLUMNS`, new `set_lines_of_code`)
- Modify: `bin/security/secrets.py` (`scan_tree` returns a line count)
- Modify: `bin/security/cli.py` (`cmd_prepare` stores it)
- Test: `tests/security/test_secrets.py`, `tests/security/test_ledger.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `scan_tree(root, ignore) -> (findings, note, lines)` — a THIRD element; `ledger.set_lines_of_code(conn, analysis_id, lines) -> None`; the `analysis.lines_of_code` column.

- [ ] **Step 1: Write the failing tests**

```python
# tests/security/test_secrets.py — append
def test_scan_tree_counts_the_lines_it_already_read(tmp_path):
    """The deterministic phase opens every versioned text file anyway; the
    count is a by-product, not a second walk."""
    (tmp_path / "a.py").write_text("one\ntwo\nthree\n")
    (tmp_path / "b.js").write_text("only one\n")
    _findings, _note, lines = scan_tree(tmp_path, [])
    assert lines == 4


def test_the_line_count_skips_what_the_scan_skips(tmp_path):
    (tmp_path / "keep.py").write_text("a\nb\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendored.js").write_text("x\ny\nz\n")
    (tmp_path / "ignored.py").write_text("1\n2\n3\n4\n")
    _f, _n, lines = scan_tree(tmp_path, ["ignored.py"])
    assert lines == 2
```

```python
# tests/security/test_ledger.py — append
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/security/test_secrets.py tests/security/test_ledger.py -q`
Expected: FAIL — `scan_tree` returns 2 values, not 3; `set_lines_of_code` does not exist.

- [ ] **Step 3: Implement**

In `bin/security/ledger.py`, extend the additive migration tuple and add the setter:

```python
_ANALYSIS_COLUMNS = (
    ("prepared", "INTEGER NOT NULL DEFAULT 0"),
    # The size of what was analysed. 0 means "not counted" -- every analysis
    # written before this column existed -- and the page shows a dash for it
    # rather than a zero that reads as an empty repository.
    ("lines_of_code", "INTEGER NOT NULL DEFAULT 0"),
)


def set_lines_of_code(conn, analysis_id, lines) -> None:
    with conn:
        conn.execute("UPDATE analysis SET lines_of_code=? WHERE id=?",
                     (int(lines), analysis_id))
```

In `bin/security/secrets.py`, `scan_tree` already opens each file — count while it is there. Add a counter beside the existing `out` list, increment it for every file whose text is read, and return it as a third element:

```python
    out, lines, skipped = [], 0, 0
    # ... inside the loop, immediately after `text = p.read_text(...)` succeeds:
        lines += text.count("\n") + (0 if text.endswith("\n") or not text else 1)
    # ... and at the end:
    return out, note, lines
```

In `bin/security/cli.py`'s `cmd_prepare`, take the third value and store it:

```python
    tree_findings, tree_note, tree_lines = secrets.scan_tree(root, ignore)
    # ... after the findings are recorded:
    ledger.set_lines_of_code(conn, aid, tree_lines)
```

- [ ] **Step 4: Run the tests and the suite**

Run: `pytest tests/security/ -q`
Expected: all pass, including the four new ones.

- [ ] **Step 5: Commit**

```bash
git add bin/security/ledger.py bin/security/secrets.py bin/security/cli.py tests/security/ CHANGELOG.md
git commit -m "feat(security): record how much code an analysis actually read

Counted while the deterministic phase already walks the tree, so it costs
no second pass, and skipped files are skipped from the count too -- the
number describes what was analysed, not what exists. An analysis from
before the column reads 0, which the page renders as a dash: a repository
with no code and a count nobody took must not look the same."
```

**CHANGELOG entry** (same commit, under `## [Unreleased]` / `### Added`):

```markdown
- **An analysis records how much code it read.** Counted during the walk the
  deterministic phase already does, with the same files skipped, so the number
  says what was analysed rather than what happens to be in the directory.
```

---

## Task 2: The `info` severity, with producers that emit it

**Files:**
- Modify: `bin/security/report.py` (`SEVERITIES`)
- Modify: `bin/security/cli.py` (severity validation at the door)
- Modify: `bin/security/hygiene.py` (the advisory `.gitignore` rule)
- Modify: `skills/security-analysis/SKILL.md` (when the agent may use it)
- Test: `tests/security/test_hygiene.py`, `tests/security/test_report.py`, `tests/security/test_cli.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `"info"` as a valid severity everywhere `SEVERITIES` is consulted; `hygiene.scan` emits rule `missing_gitignore` at severity `info`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/security/test_hygiene.py — append
def test_a_repository_with_no_gitignore_gets_an_advisory_finding(tmp_path):
    """Nothing is wrong yet -- which is why it is info, not a warning. It is
    how the next .env gets committed."""
    (tmp_path / "app.py").write_text("x = 1\n")
    found = [f for f in scan(tmp_path) if f["rule"] == "missing_gitignore"]
    assert len(found) == 1
    assert found[0]["severity"] == "info"


def test_a_repository_with_a_gitignore_gets_none(tmp_path):
    (tmp_path / ".gitignore").write_text(".env\n")
    assert [f for f in scan(tmp_path) if f["rule"] == "missing_gitignore"] == []
```

```python
# tests/security/test_report.py — append
def test_info_is_a_severity_and_sorts_below_low():
    assert "info" in report.SEVERITIES
    assert report.SEVERITIES.index("info") > report.SEVERITIES.index("low")
```

```python
# tests/security/test_cli.py — append
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/security/test_hygiene.py tests/security/test_report.py tests/security/test_cli.py -q`
Expected: FAIL — no `missing_gitignore` rule; `"info"` not in `SEVERITIES`; the door rejects the severity.

- [ ] **Step 3: Implement**

`bin/security/report.py`:

```python
# Ordered most severe first. `info` is last on purpose: it is below the default
# min_severity floor, so an informational finding is recorded and stays out of
# the way until somebody lowers the floor to look for it.
SEVERITIES = ("critical", "high", "medium", "low", "info")
```

`bin/security/hygiene.py` — add to `scan`, after the per-file loop (it is a
property of the repository, not of a file):

```python
    # Advisory, not a defect: nothing is leaking yet. It is how the next .env
    # gets committed, which is why it is recorded at all -- and why it is info.
    if not (root / ".gitignore").is_file():
        out.append(_finding(
            "missing_gitignore", "info", "This repository has no .gitignore",
            "Without one, the first .env, key or credential file someone adds "
            "is committed by default.",
            "Add a .gitignore covering .env files, key material and local "
            "build output.", ".gitignore"))
```

`bin/security/cli.py` already validates against `report.SEVERITIES`, so the door
accepts `info` the moment the tuple grows. Verify no second copy of the severity
list exists:

```bash
grep -rn '"critical", "high", "medium", "low"' bin/ ui/ 2>/dev/null
```

Any hit outside `report.py` is a second copy and must be replaced with an import
from `report`.

`skills/security-analysis/SKILL.md` — in the reporting section, add:

```markdown
`info` is for something worth recording that needs no action — a defensive
gap that is not reachable, a pattern worth knowing about before the code
grows. It sits below the default severity floor, so it is filed without
adding noise. Do not use it to soften a finding you are unsure about: an
unsure finding is a finding, at the severity you would give it if it were
real, with your doubt written in the rationale.
```

- [ ] **Step 4: Run the tests**

Run: `pytest tests/security/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add bin/security/report.py bin/security/hygiene.py skills/security-analysis/SKILL.md tests/security/ CHANGELOG.md
git commit -m "feat(security): an info severity, and two things that emit it

A fifth level below low, under the default floor: recorded, out of the
way until somebody lowers the floor to look. It ships with producers
rather than as an empty column -- an advisory rule for a repository with
no .gitignore (nothing is leaking yet; it is how the next .env gets
committed) and the agent, for observations worth knowing that need no
action.

Deliberately NOT used for OSV advisories that arrive with no severity:
those stay medium, because demoting them would push a real CVE below the
floor. A CVE of unknown severity is one nobody has assessed, not one that
does not matter."
```

**CHANGELOG entry:**

```markdown
- **A fifth severity, `info`, for findings worth recording that need no action.**
  It sits below the default floor, so it files without adding noise, and it
  arrives with producers rather than as an always-zero column: a repository
  with no `.gitignore`, and the agent's own observations.
```

---

## Task 3: The event log

**Files:**
- Modify: `bin/security/ledger.py` (the `event` table, `record_event`, `events_for`)
- Modify: `bin/security/cli.py` (verb `event`; records at open-analysis, finish, decide)
- Modify: `bin/claude-cron` (`cmd_project_set` records a settings change)
- Modify: `bin/claude-cron-server` (the report route records an export)
- Test: `tests/security/test_ledger.py`, `tests/security/test_cli.py`

**Interfaces:**
- Consumes: `ledger.connect` (Task 1's schema mechanism).
- Produces: `ledger.record_event(conn, project, kind, detail, related="") -> None`; `ledger.events_for(conn, project=None, kinds=(), since=0, limit=100, offset=0) -> list[dict]`; CLI `security event --project --kind --detail [--related]` and `security events --project [--kind] [--since] [--limit] [--offset]`.
- Event kinds, and nothing else is valid: `analysis_started`, `analysis_finished`, `decision_made`, `settings_changed`, `report_exported`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/security/test_ledger.py — append
import pytest


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
```

```python
# tests/security/test_cli.py — append
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/security/test_ledger.py tests/security/test_cli.py -q`
Expected: FAIL — `record_event` does not exist; the `events` verb is unknown.

- [ ] **Step 3: Implement**

`bin/security/ledger.py` — add to `_SCHEMA`:

```sql
-- What happened, in order. No user column and no IP: this install has one
-- operator, enforced by app.db's own CHECK (id = 1), and a column that can
-- only ever hold one value teaches nothing.
CREATE TABLE IF NOT EXISTS event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL, kind TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '', related TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS event_by_project_time ON event(project, at DESC);
```

and the functions:

```python
# A closed set. A typo must fail loudly rather than file an event that no
# filter will ever match and no screen will ever show.
EVENT_KINDS = ("analysis_started", "analysis_finished", "decision_made",
               "settings_changed", "report_exported")


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
```

`bin/security/cli.py`:

- in `cmd_open_analysis`, after the row exists:
  `ledger.record_event(conn, args.project, "analysis_started", f"{args.profile} on {args.branch}", str(aid))`
- in `cmd_finish`, after the state is written, using the state actually stored:
  `ledger.record_event(conn, row["project"], "analysis_finished", f"{stored_state} · {args.profile if False else row['profile']} on {row['branch']}", str(args.analysis))`
  — read `row` from the analysis before writing so the project and branch are the row's own, never a flag's.
- in `cmd_decide`, after the decision:
  `ledger.record_event(conn, args.project, "decision_made", f"{args.state}: {args.reason}", args.fingerprint[:12])`
- two new subparsers:

```python
    ev = sub.add_parser("event"); ev.set_defaults(fn=cmd_event)
    for flag in ("project", "kind"):
        ev.add_argument(f"--{flag}", required=True)
    ev.add_argument("--detail", default="")
    ev.add_argument("--related", default="")

    es = sub.add_parser("events"); es.set_defaults(fn=cmd_events)
    es.add_argument("--project", default="")
    es.add_argument("--kind", action="append", default=[])
    es.add_argument("--since", type=int, default=0)
    es.add_argument("--limit", type=int, default=100)
    es.add_argument("--offset", type=int, default=0)
```

```python
def cmd_event(args):
    try:
        ledger.record_event(_conn(args), args.project, args.kind,
                            args.detail, args.related)
    except ValueError as exc:
        sys.exit(f"event: {exc}")


def cmd_events(args):
    print(json.dumps(ledger.events_for(
        _conn(args), project=args.project or None, kinds=tuple(args.kind),
        since=args.since, limit=args.limit, offset=args.offset), indent=2))
```

`cmd_event` and `cmd_events` are **allowed** under `CC_SECURITY_AGENT` — the agent
recording that it started is not a human-authority act.

`bin/claude-cron` — in `cmd_project_set`, after the write succeeds, when the
project has security enabled:

```bash
  if security_enabled "$name"; then
    security_py event --project "$name" --kind settings_changed \
      --detail "project settings saved" >/dev/null 2>&1 || true
  fi
```

`bin/claude-cron-server` — in the report route, after a successful render:

```python
            cc(["security", "event", "--project", project,
                "--kind", "report_exported",
                "--detail", f"{fmt} report for analysis {int(analysis_id)}",
                "--related", str(int(analysis_id))])
```

- [ ] **Step 4: Run everything**

Run: `pytest tests/ -q` and `bin/claude-cron selftest 2>&1 | tail -1`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add bin/security/ledger.py bin/security/cli.py bin/claude-cron bin/claude-cron-server tests/ CHANGELOG.md
git commit -m "feat(security): an event log of what actually happened

Analyses started and finished, decisions with their reason, settings
changed, reports exported. The kinds are a closed set, so a typo fails
loudly instead of filing an event no filter will match.

No user column and no IP: this install has one operator, enforced by the
schema, and a column that can only hold one value teaches nothing. No
'findings viewed' either -- recording every page view is surveilling
yourself, and it would outnumber every real event on the screen it is
supposed to fill."
```

**CHANGELOG entry:**

```markdown
- **The Security area records what happened.** Analyses started and finished,
  decisions with the reason behind them, settings changed, reports exported —
  the history a security posture needs to be auditable at all. Without a user
  column or an IP: this install has one operator, and a column that can only
  hold one value teaches nothing.
```

---

## Task 4: Saved filters

**Files:**
- Modify: `bin/security/ledger.py` (`saved_filter` table + three functions)
- Modify: `bin/security/cli.py` (verb `filters`)
- Test: `tests/security/test_ledger.py`, `tests/security/test_cli.py`

**Interfaces:**
- Consumes: `ledger.connect`.
- Produces: `ledger.save_filter(conn, project, name, query) -> None`, `ledger.saved_filters(conn, project) -> list[dict]`, `ledger.delete_filter(conn, project, name) -> bool`; CLI `security filters list|save|delete`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/security/test_ledger.py — append
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/security/test_ledger.py -q`
Expected: FAIL — `save_filter` does not exist.

- [ ] **Step 3: Implement**

`_SCHEMA` gains:

```sql
CREATE TABLE IF NOT EXISTS saved_filter (
  project TEXT NOT NULL, name TEXT NOT NULL,
  query TEXT NOT NULL, saved_at INTEGER NOT NULL,
  PRIMARY KEY (project, name));
```

```python
def save_filter(conn, project, name, query) -> None:
    name = (name or "").strip()
    if not name:
        raise ValueError("a saved filter needs a name")
    with conn:
        conn.execute(
            "INSERT INTO saved_filter (project, name, query, saved_at)"
            " VALUES (?,?,?,?) ON CONFLICT(project, name) DO UPDATE SET"
            " query=excluded.query, saved_at=excluded.saved_at",
            (project, name[:80], json.dumps(query), int(time.time())))


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
```

CLI subparser `filters` with `list`, `save` (`--name`, `--query` JSON on stdin)
and `delete` (`--name`), all requiring `--project`. `save` and `delete` are
**refused under `CC_SECURITY_AGENT`**: a saved filter is a human's working set,
not something an analysis decides. Add them to `AGENT_FORBIDDEN`.

- [ ] **Step 4: Run the tests**

Run: `pytest tests/security/ -q` — all pass.

- [ ] **Step 5: Commit**

```bash
git add bin/security/ledger.py bin/security/cli.py tests/security/ CHANGELOG.md
git commit -m "feat(security): saved filters for the findings browser

A named set of filters per project, so the view somebody works from every
day is one click rather than six. Saving and deleting are refused to the
agent's environment: a working set is a human's, not something an
analysis decides."
```

---

## Task 5: `queries.py` — the read layer and its aggregations

**Files:**
- Create: `bin/security/queries.py`
- Modify: `bin/security/cli.py` (`_checklist` MOVES here; cli imports it)
- Test: `tests/security/test_queries.py`

**Interfaces:**
- Consumes: `ledger`, `diff` (Tasks 1–4).
- Produces:
  - `read_only(path) -> sqlite3.Connection | None` — `mode=ro`; `None` when the file does not exist
  - `checklist(conn, analysis_id) -> (analysis: dict, findings: list[dict])` — moved from `cli.py`, unchanged behaviour
  - `is_open(state) -> bool`
  - `posture(conn, project, branch) -> dict` — `{critical, high, medium, low, info, total}` of OPEN findings in that branch's latest finished analysis
  - `default_branch_posture(conn, project, preferred) -> (branch: str, posture: dict, fell_back: bool, latest_row: dict | None)` — the fourth element is the analysis row already fetched, threaded out so callers do not re-query the same row (Task 5's review found it fetched three times)
  - `index_summary(conn, project_names) -> dict` — `{projects, analyses, critical, high, success_rate}`
  - `project_rows(conn, projects) -> list[dict]`
  - `trend(conn, project, branch, days=30) -> list[dict]` — `{analysis_id, started, open}` oldest first
  - `recent_analyses(conn, limit=5) -> list[dict]`
  - `severity_totals(conn, project=None, days=30) -> dict`
  - `top_categories(conn, project=None, days=30, limit=5) -> list[dict]` — `{rule, count}`
  - `branch_rows(conn, project) -> list[dict]`
  - `activity_summary(conn, project=None, days=30) -> dict` — counts per event kind

**The one design rule of this task.** The findings' states are NOT recomputed in
SQL. `checklist()` moves here whole and every screen calls it: the state machine
already exists, is tested, and a second copy expressed as a `CASE` expression
would drift from it the first time either changed. Aggregations sum what
`checklist()` returns.

- [ ] **Step 1: Write the failing tests**

```python
# tests/security/test_queries.py (new)
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/security/test_queries.py -q`
Expected: FAIL — `No module named 'security.queries'`.

- [ ] **Step 3: Implement**

Create `bin/security/queries.py`. Move `_checklist` out of `cli.py` verbatim,
rename it `checklist`, and in `cli.py` replace the body with
`from security import queries` plus `analysis, findings = queries.checklist(conn, analysis_id)`.

```python
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


def read_only(path):
    """A read-only handle, or None when no analysis has ever run."""
    path = Path(path)
    if not path.exists():
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def checklist(conn, analysis_id):
    """MOVED FROM cli.py, unchanged. The single owner of finding states."""
    # (the body of cli.py's former _checklist, verbatim)


def _latest_finished(conn, project, branch):
    row = conn.execute(
        "SELECT * FROM analysis WHERE project=? AND branch=?"
        " AND state IN ('done','capped') ORDER BY id DESC LIMIT 1",
        (project, branch)).fetchone()
    return dict(row) if row else None


def _empty_posture():
    return {s: 0 for s in ("critical", "high", "medium", "low", "info")} | {"total": 0}


def posture(conn, project, branch):
    a = _latest_finished(conn, project, branch)
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
    branches must never be confused in silence."""
    if preferred and _latest_finished(conn, project, preferred):
        return preferred, posture(conn, project, preferred), False
    row = conn.execute(
        "SELECT branch FROM analysis WHERE project=? AND state IN ('done','capped')"
        " ORDER BY id DESC LIMIT 1", (project,)).fetchone()
    if not row:
        return (preferred or ""), _empty_posture(), False
    return row["branch"], posture(conn, project, row["branch"]), True
```

The rest, in full:

```python
def index_summary(conn, project_names):
    counts = {s: 0 for s in FINISHED_STATES}
    total = conn.execute("SELECT COUNT(*) c FROM analysis").fetchone()["c"]
    for r in conn.execute("SELECT state, COUNT(*) c FROM analysis GROUP BY state"):
        if r["state"] in counts:
            counts[r["state"]] = r["c"]
    finished = sum(counts.values())
    crit = high = 0
    for name in project_names:
        _br, p, _fb = default_branch_posture(conn, name, None)
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
        branch, p, fell_back = default_branch_posture(conn, name, proj.get("base"))
        last = _latest_finished(conn, name, branch) if branch else None
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
            " AND state IN (\'done\',\'capped\') AND started >= ?"
            " ORDER BY started", (project, branch, since)):
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
           " WHERE state IN (\'done\',\'capped\')")
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
    for r in conn.execute(
            "SELECT branch, MAX(started) last, COUNT(*) n FROM analysis"
            " WHERE project=? AND state IN (\'done\',\'capped\')"
            " GROUP BY branch ORDER BY last DESC", (project,)):
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
```

Two rules they all obey: a `running` analysis is never a posture, and
`success_rate` excludes running analyses from both sides.

- [ ] **Step 4: Run the tests, and add the indexes the queries need**

Run: `pytest tests/security/test_queries.py -q` — all pass.

Then measure before adding anything:

```bash
python3 - <<'PY'
import sys, time; sys.path.insert(0, "bin")
from security import queries
c = queries.read_only("data/security.db")
t = time.time(); queries.project_rows(c, [{"name": "Minerva", "base": "develop"}])
print(f"project_rows: {(time.time()-t)*1000:.1f} ms")
PY
```

Add an index only for a pattern that measures slow, and say in the commit which
number moved. `analysis_by_scope` already covers `(project, repo, branch)`.

- [ ] **Step 5: Commit**

```bash
git add bin/security/queries.py bin/security/cli.py tests/security/test_queries.py CHANGELOG.md
git commit -m "feat(security): a read layer the dashboard can query

Read-only by URI, so a SELECT with a typo cannot write to the ledger even
by accident -- the door for writes stays cli.py.

The state machine is not recomputed in SQL. _checklist moves out of cli.py
into queries.py so both callers share the one implementation: a second copy
written as a CASE expression would drift the first time either changed,
which is exactly how report.STATES became a third copy of a list nobody
kept in step."
```

---

## Task 6: The findings browser query

**Files:**
- Modify: `bin/security/queries.py` (`finding_rows`)
- Test: `tests/security/test_queries.py`

**Interfaces:**
- Consumes: `queries.checklist`, `queries.is_open` (Task 5).
- Produces: `finding_rows(conn, project, filters=None, sort="severity", direction="desc", page=1, per_page=25) -> dict` returning `{"rows": [...], "total": int, "unique": int, "by_severity": {...}}`. Each row carries `fingerprint, severity, title, rationale, category, rule, state, branch, analysis_id, first_seen, occurrences`.
- `SORTABLE = ("severity", "title", "category", "branch", "first_seen", "state")`, `MAX_PER_PAGE = 100`.

**Where the rows come from.** One checklist per branch — the latest finished
analysis of each — unioned. That is why the browser can show a state at all: it
is the state that branch's newest analysis gives the finding. Findings resolved
in that analysis are included only when `show_resolved` is on.

- [ ] **Step 1: Write the failing tests**

```python
# tests/security/test_queries.py — append
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/security/test_queries.py -q`
Expected: FAIL — `finding_rows` does not exist.

- [ ] **Step 3: Implement**

```python
SORTABLE = ("severity", "title", "category", "branch", "first_seen", "state")
MAX_PER_PAGE = 100
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding_rows(conn, project, filters=None, sort="severity",
                 direction="desc", page=1, per_page=25):
    if sort not in SORTABLE:
        raise ValueError(f"sort must be one of {SORTABLE}")
    if direction not in ("asc", "desc"):
        raise ValueError("direction must be asc or desc")
    f = dict(filters or {})
    per_page = max(1, min(int(per_page), MAX_PER_PAGE))

    branches = [r["branch"] for r in conn.execute(
        "SELECT DISTINCT branch FROM analysis WHERE project=?"
        " AND state IN ('done','capped')", (project,))]

    rows, first_seen = [], {}
    for br in branches:
        a = _latest_finished(conn, project, br)
        if not a:
            continue
        _an, findings = checklist(conn, a["id"])
        for finding in findings:
            row = dict(finding)
            row["branch"] = br
            row["analysis_id"] = a["id"]
            rows.append(row)

    # The oldest analysis carrying each fingerprint, in one query rather than
    # one per row.
    for r in conn.execute(
            "SELECT f.fingerprint AS fp, MIN(a.started) AS first FROM finding f"
            " JOIN analysis a ON a.id = f.analysis_id WHERE a.project=?"
            " GROUP BY f.fingerprint", (project,)):
        first_seen[r["fp"]] = r["first"]
    for r in rows:
        r["first_seen"] = first_seen.get(r["fingerprint"], 0)

    if not f.get("show_resolved"):
        rows = [r for r in rows if is_open(r["state"])]
    for key in ("severity", "state", "category", "branch"):
        if f.get(key):
            rows = [r for r in rows if r.get(key) in f[key]]
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
    for r in rows:
        if r["severity"] in by_severity:
            by_severity[r["severity"]] += 1

    keyf = ((lambda r: _SEV_RANK.get(r["severity"], 9)) if sort == "severity"
            else (lambda r: r.get(sort) or ""))
    rows.sort(key=keyf, reverse=(direction == "desc") == (sort != "severity"))

    total, unique = len(rows), len({r["fingerprint"] for r in rows})
    start = max(0, (int(page) - 1) * per_page)
    return {"rows": rows[start:start + per_page], "total": total,
            "unique": unique, "by_severity": by_severity,
            "page": int(page), "per_page": per_page}
```

Filtering in Python rather than SQL is deliberate: the states come from
`checklist()`, so they do not exist as columns to filter on. With hundreds of
findings this is instant. If it ever becomes thousands, that is a measured
problem with a materialised-state answer — not a presumed one today.

- [ ] **Step 4: Run the tests**

Run: `pytest tests/security/ -q` — all pass.

- [ ] **Step 5: Commit**

```bash
git add bin/security/queries.py tests/security/test_queries.py CHANGELOG.md
git commit -m "feat(security): the findings browser's query

One checklist per branch -- the latest finished analysis of each -- unioned,
which is what lets the browser show a state at all. Resolved findings are
out unless asked for, unique counts fingerprints while total counts rows
(189 findings can be 93 problems), and first_seen is the oldest analysis
carrying the fingerprint.

The sort column is an allowlist: filter VALUES are parameters, but a sort
column is interpolated by nature and is the one route parameters cannot
protect. Page size is capped so one request cannot ask for the table."
```

---

## Task 7: The static route, the build, and moving the area out of the page

**Files:**
- Create: `build/build-ui.sh`, `package.json`, `ui/security/index.js` (+ the modules the move produces), `bin/static/security.js` (built, committed)
- Modify: `bin/claude-cron-server` (`/static/*` route), `bin/dashboard.html` (drop the area's JS, load the bundle), `bin/claude-cron` (selftest: bundle freshness), `.gitignore` (`node_modules/`)
- Modify: `tests/test_page_contract.py` (the innerHTML scan follows the code)
- Test: `tests/test_static_route.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `GET /static/security.js` served with `application/javascript`; `bash build/build-ui.sh` rebuilding `bin/static/security.js`.

**This task changes no behaviour.** The Security area must work exactly as it
does now, from a different file. That is what makes the four screens after it
small, and what makes this task reviewable: any behaviour difference is a bug.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_static_route.py (new)
def test_the_bundle_is_served_as_javascript(srv):
    body, ctype = srv.static_asset("security.js")
    assert ctype.startswith("application/javascript")
    assert body


def test_a_traversing_path_is_refused(srv):
    """The one thing a static route must never do."""
    for bad in ("../claude-cron-server", "..%2Fclaude-cron-server",
                "sub/dir.js", "/etc/passwd"):
        assert srv.static_asset(bad) == (None, None)


def test_an_unknown_asset_is_a_miss_not_a_crash(srv):
    assert srv.static_asset("nope.js") == (None, None)
```

```python
# tests/test_page_contract.py — replace the dashboard-block scan
def test_the_security_ui_never_builds_dom_from_html_strings():
    """The scan follows the code. It used to read a block of dashboard.html;
    the area now lives in ui/security/, and a scan left pointing at the old
    place would have kept passing while watching nothing."""
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent
    sinks = ("innerHTML", "insertAdjacentHTML", "outerHTML",
             "createContextualFragment", "DOMParser", 'setAttribute("on')
    for src in sorted((repo / "ui" / "security").glob("*.js")):
        text = src.read_text()
        for sink in sinks:
            assert sink not in text, f"{src.name} reaches the DOM through {sink}"
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/test_static_route.py tests/test_page_contract.py -q`
Expected: FAIL — `static_asset` does not exist; `ui/security/` does not exist.

- [ ] **Step 3: Implement**

`package.json` (dev only, esbuild pinned):

```json
{
  "name": "claude-cron-ui",
  "private": true,
  "scripts": { "build": "bash build/build-ui.sh" },
  "devDependencies": { "esbuild": "0.25.0" }
}
```

`build/build-ui.sh`:

```bash
#!/bin/bash
# Builds the Security area into bin/static/. The OUTPUT IS COMMITTED: whoever
# installs claude-cron needs jq, python3 and curl -- never Node. Run this in
# the same change as any edit under ui/, or the selftest refuses the tree.
set -euo pipefail
cd "$(dirname "$0")/.."
npx --yes esbuild@0.25.0 ui/security/index.js \
  --bundle --format=iife --target=safari15 \
  --outfile=bin/static/security.js
echo "built bin/static/security.js"
```

`bin/claude-cron-server` — a module-level helper plus a route:

```python
STATIC_DIR = BIN_DIR / "static"
STATIC_TYPES = {".js": "application/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8"}


def static_asset(name):
    """One flat directory, one segment, known extensions. No traversal, no
    subdirectories, nothing clever -- a static route is not the place to be
    clever."""
    if "/" in name or "\\" in name or name.startswith(".") or ".." in name:
        return None, None
    path = STATIC_DIR / name
    ctype = STATIC_TYPES.get(path.suffix)
    if not ctype or not path.is_file():
        return None, None
    try:
        return path.read_text(), ctype
    except OSError:
        return None, None
```

In `do_GET`, before the `/api/` gate — the bundle is not secret, and gating it
would leave the login screen unable to load its own code:

```python
        if path.startswith("/static/"):
            body, ctype = static_asset(path[len("/static/"):])
            if body is None:
                return self._send(404, {"error": "not found"})
            return self._send(200, body, ctype)
```

`bin/dashboard.html` — cut every Security function and constant out of the inline
`<script>` into `ui/security/`, split by screen, and add before `</body>`:

```html
<script src="/static/security.js?v=BUILD"></script>
```

using the page's existing `BUILD` substitution so a new bundle is not served
from cache. Anything the modules need from the page (`api`, `toast`, `$`,
`fmtAgo`, `esc`, `openLog`) is passed in through one explicit `window.CC` object
the page defines before the tag — an interface, rather than the modules reaching
into globals.

`bin/claude-cron` selftest:

```bash
  # The bundle is committed, so it can be stale, and a stale bundle is a page
  # that silently runs last week's code. Structural: mtime, not content.
  newest_src="$(find "$SCRIPT_DIR/../ui" -name '*.js' -newer "$SCRIPT_DIR/static/security.js" 2>/dev/null | head -1)"
  [ -z "$newest_src" ] \
    && ok "the committed UI bundle is newer than every source it was built from" \
    || bad "bin/static/security.js is older than $newest_src — run build/build-ui.sh"
```

`.gitignore` gains `node_modules/`. `bin/static/` must NOT be ignored.

- [ ] **Step 4: Build, run everything, and check the page by hand**

```bash
bash build/build-ui.sh
pytest tests/ -q
bin/claude-cron selftest 2>&1 | tail -1
```

Then open the dashboard and confirm the Security area behaves exactly as before:
the project list paints, opening a project loads its branches, Analyse still
refuses a second concurrent run readably, and the downloads still produce files.
A behaviour difference here is a bug in the move, not a feature.

- [ ] **Step 5: Commit**

```bash
git add package.json build/build-ui.sh ui/ bin/static/ bin/claude-cron-server bin/dashboard.html bin/claude-cron .gitignore tests/ CHANGELOG.md
git commit -m "refactor(security): the area moves out of the page, behaviour unchanged

dashboard.html was 7,323 lines and the Security area was 2,300 of them,
with four screens still to come. The area is now ES modules under ui/,
bundled by a pinned esbuild into bin/static/security.js and served by a
new static route.

The bundle is COMMITTED: developing the UI needs Node, installing
claude-cron still needs only jq, python3 and curl. A selftest assertion
refuses a bundle older than its sources, because a stale committed bundle
is a page silently running last week's code.

The innerHTML scan follows the code into ui/. Left pointing at the old
block it would have kept passing while watching nothing -- which is how a
guard becomes decoration."
```

---

## Task 8: The index screen

**Files:**
- Create: `ui/security/index-screen.js`
- Modify: `bin/claude-cron-server` (`GET /api/security/index`), `bin/security/cli.py` (verb `index-data`), `ui/security/index.js` (routing)
- Test: `tests/test_security_api.py`, `tests/security/test_cli.py`

**Interfaces:**
- Consumes: `queries.index_summary`, `project_rows`, `recent_analyses`, `severity_totals`, `top_categories` (Task 5).
- Produces: `GET /api/security/index` → `{summary, projects, recent, donut, categories}`; the screen renders it.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_api.py — append
def test_the_index_answers_with_every_panel_the_screen_draws(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "summary": {"projects": 2, "analyses": 12, "critical": 4,
                    "high": 18, "success_rate": 0.75},
        "projects": [], "recent": [], "donut": {}, "categories": []})))
    code, payload = srv.security_index()
    assert code == 200
    assert set(payload) == {"summary", "projects", "recent", "donut", "categories"}


def test_the_index_survives_a_ledger_that_does_not_exist_yet(srv, monkeypatch):
    """Nobody has run an analysis. That is an empty screen with a sentence,
    not a 500."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "summary": {"projects": 0, "analyses": 0, "critical": 0, "high": 0,
                    "success_rate": None},
        "projects": [], "recent": [], "donut": {}, "categories": []})))
    code, payload = srv.security_index()
    assert code == 200
    assert payload["summary"]["success_rate"] is None
```

- [ ] **Step 2: Run it and watch it fail**

Run: `pytest tests/test_security_api.py -q`
Expected: FAIL — `security_index` does not exist.

- [ ] **Step 3: Implement**

`bin/security/cli.py` gains `index-data --projects <json>` (the project list and
each one's declared base come from `projects.json`, which the CLI reads and the
ledger does not know). It prints the five panels as one document; the server
calls it once per screen load rather than twice per project, which is what the
old shape cost.

`bin/claude-cron-server`:

```python
def security_index():
    ok, out = cc(["security", "index-data", "--projects", json.dumps(_security_projects())])
    if not ok:
        return 500, {"error": out}
    try:
        return 200, json.loads(out)
    except ValueError as exc:
        return 500, {"error": f"index data was not readable: {exc}"}
```

`ui/security/index-screen.js` renders: the five cards, the project table (one
row per project, its default branch's posture, and **the branch name shown
whenever it fell back**), recent analyses, the donut and the categories. Every
string through `textContent`; every number formatted by the page's existing
helpers.

The success-rate card shows a dash, not `0%`, when `success_rate` is `null` —
no finished analyses is not a zero-percent success rate.

- [ ] **Step 4: Run the tests and look at the screen**

Run: `pytest tests/ -q` and rebuild with `bash build/build-ui.sh`.
Then open the dashboard: the five cards carry real numbers, the project rows
match `claude-cron security list --project <name>` for each project, and a
project whose default branch was never analysed shows the branch it fell back to.

- [ ] **Step 5: Commit**

```bash
git add ui/security/index-screen.js bin/static/security.js bin/claude-cron-server bin/security/cli.py tests/ CHANGELOG.md
git commit -m "feat(security): the Security index

Five cards, the projects and their posture, recent analyses, and the
severity donut with the rules that produced it. One request per screen
load, where the old shape cost two subprocesses per project.

The numbers are current posture, never all-time sums: 'critical' is what
is open in each project's latest analysis, not everything ever found,
which only grows and says nothing. A project whose default branch was
never analysed shows the branch it fell back to, because postures of
different branches must not be confused in silence. No finished analyses
shows a dash, not 0% -- those are different facts."
```

---

## Task 9: The project detail screen — header, tabs, Overview and Runs

**Files:**
- Create: `ui/security/project-screen.js`
- Modify: `bin/claude-cron-server` (`GET /api/security/project`), `bin/security/cli.py` (verb `project-data`), `ui/security/index.js`
- Test: `tests/test_security_api.py`

**Interfaces:**
- Consumes: `queries.posture`, `trend`, `severity_totals`, `top_categories`, `activity_summary`, and the existing analyses list.
- Produces: `GET /api/security/project?project=<name>` → `{project, header, tabs: {overview, runs}, sidebar}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_api.py — append
def test_the_project_screen_refuses_an_unknown_project(srv):
    code, payload = srv.security_project("")
    assert code == 400
    assert "project" in payload["error"]


def test_the_project_screen_carries_its_header_and_both_tabs(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "project": "web",
        "header": {"profile": "deep", "branch": "develop",
                   "lines_of_code": 1842331, "last_analysis": 1787290000},
        "tabs": {"overview": {}, "runs": []},
        "sidebar": {"donut": {}, "categories": [], "activity": []}})))
    code, payload = srv.security_project("web")
    assert code == 200
    assert payload["header"]["lines_of_code"] == 1842331
    assert "runs" in payload["tabs"]
```

- [ ] **Step 2: Run it and watch it fail**

Run: `pytest tests/test_security_api.py -q`
Expected: FAIL — `security_project` does not exist.

- [ ] **Step 3: Implement**

The header strip: default profile and branch from `projects.json`, lines of code
from the latest analysis (a dash when 0), last analysis time. `Project settings`
links to the existing project editor — the form is not duplicated.

Tabs are a nav plus panes, following `viewtabs`/`pane` as the Overview page
already does. **Overview** shows the posture and what changed since the previous
analysis (the checklist counts). **Runs** is the analyses table — run id, profile,
branch, commit, duration, findings, state, date — with the filters and the
`Run new analysis` button, which calls the SAME `security_analyze` op as today.

The sidebar carries the donut, the categories, and the last few activity events
with a link to the Activity screen.

- [ ] **Step 4: Run the tests and look at the screen**

Run: `pytest tests/ -q`, rebuild, and open a project: the Runs tab must list
exactly what `claude-cron security list --project <name>` lists, and starting an
analysis from here must behave as it does from the current screen.

- [ ] **Step 5: Commit**

```bash
git add ui/security/project-screen.js bin/static/security.js bin/claude-cron-server bin/security/cli.py tests/ CHANGELOG.md
git commit -m "feat(security): the project screen, with Overview and Runs

A header that says what this project analyses and how big it is, and the
run history behind tabs instead of one long column. Settings is a link to
the project editor that already exists rather than a second copy of the
same form."
```

---

## Task 10: The Branches and Reports tabs

**Files:**
- Create: `ui/security/branches-tab.js`, `ui/security/reports-tab.js`
- Modify: `bin/security/cli.py` (`project-data` gains `branches` and `reports`), `ui/security/project-screen.js`
- Test: `tests/security/test_queries.py` (already covers `branch_rows`), `tests/test_security_api.py`

**Interfaces:**
- Consumes: `queries.branch_rows` (Task 5).
- Produces: the two tabs; `reports` lists each analysis with its four download links.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_api.py — append
def test_the_project_payload_carries_branches_and_reports(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "project": "web", "header": {},
        "tabs": {"overview": {}, "runs": [],
                 "branches": [{"branch": "main", "open": {"critical": 1},
                               "last_analysis": 1787290000, "analyses": 3}],
                 "reports": [{"analysis_id": 7, "branch": "main",
                              "started": 1787290000, "state": "done"}]},
        "sidebar": {}})))
    code, payload = srv.security_project("web")
    assert payload["tabs"]["branches"][0]["branch"] == "main"
    assert payload["tabs"]["reports"][0]["analysis_id"] == 7
```

- [ ] **Step 2: Run it and watch it fail**

Run: `pytest tests/test_security_api.py -q` — FAIL: the payload has no `branches`.

- [ ] **Step 3: Implement**

**Branches** — one row per branch that has ever been analysed: last analysis,
open findings by severity, how many analyses, and the trend. Every number from
`queries.branch_rows`, which uses the same `checklist()` as everything else.

**Reports** — one row per analysis with the four formats (Markdown, JSON, HTML,
SBOM). The download goes through `fetch` + `Blob` because every GET carries the
token header, exactly as the current screen does; a bare `<a href>` cannot
carry it. The row states what the SBOM actually is: **the latest document for
that branch, not a snapshot of that analysis** — the table is keyed by branch,
and saying so is cheaper than a schema change nobody needs yet.

- [ ] **Step 4: Run the tests and check both tabs**

Run: `pytest tests/ -q`, rebuild, open a project with more than one analysed
branch, and confirm the branch rows agree with the per-branch numbers on the
index.

- [ ] **Step 5: Commit**

```bash
git add ui/security/branches-tab.js ui/security/reports-tab.js bin/static/security.js bin/security/cli.py tests/ CHANGELOG.md
git commit -m "feat(security): the Branches and Reports tabs

Branches answers the question the single-branch view could not: where is
this project actually exposed, given main and develop have different
answers. Reports gathers the four downloads that were scattered across
individual analyses, and says out loud that the SBOM is the branch's
latest document rather than a snapshot of the analysis you clicked from."
```

---

## Task 11: The findings browser screen

**Files:**
- Create: `ui/security/findings-screen.js`
- Modify: `bin/claude-cron-server` (`GET /api/security/findings`, ops `security_filter_save` / `security_filter_delete`), `bin/security/cli.py` (verb `findings-page`), `ui/security/index.js`
- Test: `tests/test_security_api.py`

**Interfaces:**
- Consumes: `queries.finding_rows` (Task 6), `ledger.saved_filters` (Task 4).
- Produces: `GET /api/security/findings?project=&page=&per_page=&sort=&dir=&…` → `{rows, total, unique, by_severity, page, per_page, filters}`; and `renderFindings(host, project)` exported from `findings-screen.js`.

**One screen, two homes.** The project screen's **Findings** tab and the
standalone browser are the same module: `project-screen.js` mounts
`renderFindings` into its tab pane, and the standalone route mounts it into the
page. Two copies of a filterable table would drift in exactly the way a second
copy of the state machine already taught us — this is the fifth tab the spec
lists for the project, and it is not built twice.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_security_api.py — append
def test_the_findings_route_refuses_an_unknown_sort_at_the_edge(srv):
    """The CLI refuses it too. Refusing here as well means the page gets a 400
    with a sentence instead of a 500 carrying a stack trace."""
    code, _ = srv.security_findings({"project": "web", "sort": "; DROP TABLE"})
    assert code == 400


def test_the_findings_route_caps_page_size(srv, monkeypatch):
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 1, "per_page": 100})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_findings({"project": "web", "per_page": "99999"})
    assert "99999" not in seen["args"]


def test_saving_a_filter_without_a_name_is_refused(srv):
    code, payload = srv.security_filter_save({"project": "web", "name": "  "})
    assert code == 400
    assert "name" in payload["error"]
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/test_security_api.py -q`
Expected: FAIL — `security_findings` does not exist.

- [ ] **Step 3: Implement**

The route validates before it shells out: `sort` in `queries.SORTABLE`,
`direction` in `("asc","desc")`, `per_page` clamped to `MAX_PER_PAGE`, `page` an
int ≥ 1. Severity, state and category values are checked against their known
sets; free text (`q`, `path`) travels as one argv element, never as shell.

The screen draws the severity strip (the five levels plus *unique issues*), the
filter bar, the table, and the pager. Two things it must say out loud:

- when the project's `min_severity` hides rows, the count that is hidden and
  why — a number that is missing is otherwise indistinguishable from a number
  that was never found;
- that **downloads always contain every recorded finding**, whatever the floor
  shows.

Row actions are the ones that exist: *Accept risk* and *False positive*, both
through the existing `security_decide` op with its mandatory reason, and both
refused while an analysis of that project is running — the CLI already says so
and the page shows the sentence.

Saved filters: a select of the project's filters, plus save and delete. Saving
sends the current filter set; the name is required at the edge and again in the
ledger.

- [ ] **Step 4: Run the tests and work the screen**

Run: `pytest tests/ -q`, rebuild, then on a project with findings: filter by
severity and confirm the count matches the strip, switch pages and confirm no
row appears twice, save a filter and reopen it, and accept a risk and watch the
row change state without a reload.

- [ ] **Step 5: Commit**

```bash
git add ui/security/findings-screen.js bin/static/security.js bin/claude-cron-server bin/security/cli.py tests/ CHANGELOG.md
git commit -m "feat(security): the findings browser

Every finding of a project in one filterable, paginated table, with the
state each one has in the latest analysis of its branch -- a list that
crosses analyses has to say which one it is speaking about.

The floor's effect is stated rather than silent: the page says how many
rows min_severity is hiding, and that downloads carry every recorded
finding regardless. Sort column, direction and page size are validated at
the edge as well as in the query, so a bad value is a sentence rather
than a stack trace."
```

---

## Task 12: The Activity screen

**Files:**
- Create: `ui/security/activity-screen.js`
- Modify: `bin/claude-cron-server` (`GET /api/security/activity`), `bin/security/cli.py` (verb `activity-data`), `ui/security/index.js`
- Test: `tests/test_security_api.py`

**Interfaces:**
- Consumes: `ledger.events_for` (Task 3), `queries.activity_summary` (Task 5).
- Produces: `GET /api/security/activity?project=&kind=&since=&page=` → `{events, summary, projects, page, per_page}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_security_api.py — append
def test_activity_refuses_an_unknown_event_kind(srv):
    code, payload = srv.security_activity({"kind": ["findings_viewed"]})
    assert code == 400


def test_activity_carries_events_and_a_summary(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "events": [{"kind": "analysis_started", "detail": "deep on develop",
                    "project": "web", "related": "4", "at": 1787290000}],
        "summary": {"analysis_started": 12, "analysis_finished": 11},
        "projects": [{"project": "web", "count": 23}],
        "page": 1, "per_page": 25})))
    code, payload = srv.security_activity({})
    assert payload["events"][0]["kind"] == "analysis_started"
    assert payload["summary"]["analysis_started"] == 12


def test_the_activity_payload_has_no_user_or_ip_field(srv, monkeypatch):
    """One operator. A column that can only ever hold one value teaches
    nothing, and an IP column on a loopback-only server teaches less."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "events": [{"kind": "decision_made", "detail": "accepted: reviewed",
                    "project": "web", "related": "abc", "at": 1}],
        "summary": {}, "projects": [], "page": 1, "per_page": 25})))
    _code, payload = srv.security_activity({})
    assert "user" not in payload["events"][0]
    assert "ip" not in payload["events"][0]
```

- [ ] **Step 2: Run them and watch them fail**

Run: `pytest tests/test_security_api.py -q`
Expected: FAIL — `security_activity` does not exist.

- [ ] **Step 3: Implement**

The route validates each requested `kind` against `ledger.EVENT_KINDS` and
refuses anything else at the edge. The screen has the tabs the mockup shows,
minus *Users*: **All activity**, **Analyses** (`analysis_started`,
`analysis_finished`), **Findings** (`decision_made`), **Settings**
(`settings_changed`, `report_exported`). Each tab is the same table with a kind
filter.

The table: time, event, detail, project, and what it relates to — an analysis id
links to that analysis, a fingerprint prefix links into the findings browser
filtered to it. No user column, no IP column.

The sidebar: the period's counts per kind, and the most active projects. No
*top active users*: with one operator that is a list of one, which is not an
insight.

Empty state: "No activity recorded in this period" with the range that was
searched, so an empty screen is legibly empty rather than possibly broken.

- [ ] **Step 4: Run the tests and read the screen**

Run: `pytest tests/ -q`, rebuild, then confirm against reality: run an analysis,
accept a risk, download a report, and watch the three events appear with the
right details.

- [ ] **Step 5: Commit**

```bash
git add ui/security/activity-screen.js bin/static/security.js bin/claude-cron-server bin/security/cli.py tests/ CHANGELOG.md
git commit -m "feat(security): the Activity screen

What happened and when, filterable by kind, with each event linking to
what it was about. No user column and no IP: one operator, and a loopback
server. No 'top active users' either -- with one operator that is a list
of one, which is not an insight."
```

---

## Task 13: Documentation

**Files:**
- Modify: `README.md` (the `## Security analysis` section), `CHANGELOG.md`

- [ ] **Step 1: Update the README**

The section documents behaviour, so it needs the parts that changed:

- the four screens and what each is for;
- that numbers are **current posture**, and the exact definitions of *open*
  (includes `pending`) and *success rate* (`done` over finished);
- the `info` severity, what emits it, and that it sits below the default floor;
- lines of code — counted during the deterministic walk, a dash when never counted;
- the event log: what is recorded, and that there is no user or IP column
  because the install has one operator;
- saved filters;
- **the build**: `ui/` is the source, `bin/static/security.js` is committed, and
  `bash build/build-ui.sh` must run in the same change as any UI edit — with the
  selftest assertion named, so the rule has a visible enforcer;
- that installing still needs only jq, python3 and curl.

- [ ] **Step 2: Verify every documented claim against the code**

```bash
grep -n 'lines_of_code' bin/security/ledger.py bin/security/cli.py
grep -n '"info"' bin/security/report.py bin/security/hygiene.py
grep -n 'EVENT_KINDS' bin/security/ledger.py
grep -n 'build-ui.sh' bin/claude-cron README.md
bin/claude-cron selftest 2>&1 | tail -1
pytest tests/ -q 2>&1 | tail -1
```

Every field, verb and flag named in the README must appear in that output.

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: the Security area's four screens, and the UI build"
```

---

## Definition of done

- [ ] `pytest tests/ -q` passes with no regressions
- [ ] `bin/claude-cron selftest` passes, including the bundle-freshness assertion
- [ ] `bash test/e2e.test.sh` passes
- [ ] `bash build/build-ui.sh` produces a bundle identical to the committed one
      (run it, then `git diff --exit-code bin/static/`)
- [ ] A fresh clone with **no Node installed** still serves the dashboard
- [ ] Every screen renders against the real ledger, and every number on it
      matches what the CLI reports for the same scope
- [ ] A project with no analyses, a branch with one analysis, and a missing
      `security.db` each produce a legible empty state, never a 500
- [ ] No file under `ui/security/` contains `innerHTML`, `insertAdjacentHTML`,
      `outerHTML`, `createContextualFragment`, `DOMParser` or `setAttribute("on`
- [ ] Overview, Jobs, Runs and Projects are untouched by the whole branch
