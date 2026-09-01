import sqlite3

import pytest
from security import fingerprint as fp_mod
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


def test_a_finding_keeps_its_classification(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(cwe="CWE-89", owasp="A03:2021"))

    got = ledger.findings_of(conn, aid)
    assert got[0]["cwe"] == "CWE-89"
    assert got[0]["owasp"] == "A03:2021"


def test_a_finding_without_a_classification_stores_empty_strings(conn):
    # Deterministic findings (secret/dependency/hygiene) have no SAST rule
    # and therefore no CWE from the vocabulary. They must still record.
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(category="hygiene", rule="committed_env_file"))

    got = ledger.findings_of(conn, aid)
    assert got[0]["cwe"] == ""
    assert got[0]["owasp"] == ""


def test_a_re_report_replaces_the_classification(conn):
    # The agent's triage job re-reports a finding with corrected fields.
    # The classification is one of them.
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(rule="other", cwe="", owasp=""))
    ledger.record_finding(conn, aid, _finding(rule="sql-injection", cwe="CWE-89", owasp="A03:2021"))

    got = ledger.findings_of(conn, aid)
    assert len(got) == 1
    assert got[0]["cwe"] == "CWE-89"


def test_a_database_without_the_columns_gains_them(tmp_path):
    # The dev databases on the branch's machines predate these columns.
    # connect() must migrate them, exactly as it does for `analysis`.
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(str(path))
    old.executescript("""
      CREATE TABLE finding (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        fingerprint TEXT NOT NULL, category TEXT NOT NULL, rule TEXT NOT NULL,
        severity TEXT NOT NULL, title TEXT NOT NULL,
        rationale TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
        partial_note TEXT NOT NULL DEFAULT '',
        UNIQUE(analysis_id, fingerprint));
    """)
    old.commit()
    old.close()

    conn = ledger.connect(path)
    have = {r["name"] for r in conn.execute("PRAGMA table_info(finding)")}
    assert "cwe" in have and "owasp" in have


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


def test_a_name_of_exactly_80_characters_is_accepted(conn):
    """The boundary itself: 80 is the limit, not the first refused length."""
    name = "x" * 80
    ledger.save_filter(conn, "web", name, {})
    got = ledger.saved_filters(conn, "web")
    assert len(got) == 1
    assert got[0]["name"] == name


def test_a_name_of_81_characters_is_refused_naming_the_limit(conn):
    """The fix for the root cause: a name over the limit used to be silently
    truncated to `name[:80]` before the primary key ever saw it. Refusing
    instead means the stored key is always exactly what was typed, so
    `delete_filter` -- which was never touched -- is correct by construction."""
    with pytest.raises(ValueError, match="80"):
        ledger.save_filter(conn, "web", "x" * 81, {})
    assert ledger.saved_filters(conn, "web") == []


def test_two_names_sharing_their_first_80_characters_no_longer_collide(conn):
    """Before the fix, truncation ran before `(project, name)` could tell two
    over-limit names apart, so the second save silently overwrote the first
    under the same truncated key. Now both are refused outright rather than
    one winning."""
    with pytest.raises(ValueError):
        ledger.save_filter(conn, "web", "x" * 80 + "a", {"which": "first"})
    with pytest.raises(ValueError):
        ledger.save_filter(conn, "web", "x" * 80 + "b", {"which": "second"})
    assert ledger.saved_filters(conn, "web") == []


def test_a_name_of_80_spaces_plus_one_character_is_a_one_character_name(conn):
    """The `.strip()` happens BEFORE the length check, so padding a name with
    leading/trailing whitespace cannot itself trigger the length refusal --
    only the meaningful content counts."""
    ledger.save_filter(conn, "web", " " * 80 + "x", {})
    got = ledger.saved_filters(conn, "web")
    assert len(got) == 1
    assert got[0]["name"] == "x"


def test_a_saved_name_round_trips_through_delete_unchanged(conn):
    """The exact bug the truncation caused: a name saved under its full text
    must be deletable by that same full text, with nothing silently shortened
    along the way."""
    name = "x" * 80
    ledger.save_filter(conn, "web", name, {})
    assert ledger.delete_filter(conn, "web", name) is True
    assert ledger.saved_filters(conn, "web") == []


def test_an_unparseable_saved_filter_stays_visible_and_deletable(conn):
    """`saved_filters` catches the `ValueError` `json.loads` raises on a
    malformed `query` column and returns the row with an empty query instead
    of letting one bad row take the whole list down -- a filter nobody can
    parse is a filter nobody can apply, but it must still be visible enough
    to delete. Written directly into the table because `save_filter` now
    validates its input and could never produce a row like this itself."""
    conn.execute(
        "INSERT INTO saved_filter (project, name, query, saved_at)"
        " VALUES (?,?,?,?)", ("web", "corrupted", "{not valid json", 0))
    conn.commit()
    got = ledger.saved_filters(conn, "web")
    assert len(got) == 1
    assert got[0]["name"] == "corrupted"
    assert got[0]["query"] == {}
    assert ledger.delete_filter(conn, "web", "corrupted") is True
    assert ledger.saved_filters(conn, "web") == []


# ---- renaming a rule without losing the history behind it.
#
# The fingerprint is sha256(category + rule + path + <fourth argument>), so the
# rule name IS part of a finding's identity. Renaming a rule and leaving the
# fingerprint alone leaves a row whose stored identity no analysis will ever
# produce again: the same hole is reported `fixed` (the old identity vanished)
# and `new` (a fresh one appeared) in one report, and the human decision keyed
# to the old fingerprint matches nothing for ever after.

def _secret_finding(rule, path="config/prod.env"):
    return {
        "fingerprint": fp_mod.secret_fingerprint(rule, path),
        "category": "secret", "rule": rule, "severity": "critical",
        "title": f"{rule} in {path}", "rationale": "r", "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}],
    }


def _hygiene_finding(rule, path=".env"):
    # hygiene.py:26 passes the RULE as the fourth fingerprint argument.
    return {
        "fingerprint": fp_mod.fingerprint("hygiene", rule, path, rule),
        "category": "hygiene", "rule": rule, "severity": "high",
        "title": f"{path} is committed", "rationale": "r",
        "remediation": "remove it",
        "occurrences": [{"file": path, "line": 0, "snippet_hash": ""}],
    }


def test_renaming_a_secret_rule_carries_the_finding_and_its_decision(conn):
    old_fp = fp_mod.secret_fingerprint("aws_access_key", "config/prod.env")
    new_fp = fp_mod.secret_fingerprint("aws-access-token", "config/prod.env")

    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key"))
    ledger.set_decision(conn, "web", old_fp, "accepted", "rotated, kept for audit", "luiz")

    moved = ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    assert moved == 1
    row = ledger.findings_of(conn, aid)[0]
    assert row["rule"] == "aws-access-token"
    assert row["fingerprint"] == new_fp
    # The whole point: the human's call survives the rename.
    assert ledger.decisions_for(conn, "web")[new_fp]["state"] == "accepted"
    assert ledger.decisions_for(conn, "web")[new_fp]["reason"] == "rotated, kept for audit"
    assert old_fp not in ledger.decisions_for(conn, "web")


def test_renaming_a_hygiene_rule_recomputes_from_the_rule_not_the_snippet_hash(conn):
    """hygiene's fourth fingerprint argument is the RULE ITSELF (hygiene.py:26),
    so the new identity is fully derivable -- but only if it is rebuilt the way
    hygiene builds it. Passing the occurrence's `snippet_hash` there instead
    (it is "" for every hygiene finding) is the plausible near-miss: it
    produces a well-formed fingerprint that hygiene.py will never emit, so the
    finding is orphaned exactly as thoroughly as if nothing had been recomputed
    at all. Both halves are asserted so the near-miss cannot pass."""
    old_fp = fp_mod.fingerprint("hygiene", "committed_env_file", ".env",
                                "committed_env_file")
    new_fp = fp_mod.fingerprint("hygiene", "committed-env-file", ".env",
                                "committed-env-file")
    near_miss = fp_mod.fingerprint("hygiene", "committed-env-file", ".env", "")

    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _hygiene_finding("committed_env_file"))
    assert ledger.findings_of(conn, aid)[0]["fingerprint"] == old_fp

    assert ledger.rename_rule(conn, "hygiene", "committed_env_file",
                              "committed-env-file") == 1
    got = ledger.findings_of(conn, aid)[0]["fingerprint"]
    assert got == new_fp
    assert got != near_miss


def test_renaming_a_sast_rule_is_refused(conn):
    """A SAST fingerprint is computed from the code snippet, which the ledger
    never stores -- only `snippet_hash`, which is "" for every deterministic
    source and opaque when the agent sends one. Recomputing is impossible, and
    a rename that silently produced a wrong identity would orphan the finding
    and point its decision at a dead fingerprint."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _finding(rule="sql-injection"))

    with pytest.raises(ValueError, match="sast"):
        ledger.rename_rule(conn, "sast", "sql-injection", "sqli")


def test_renaming_a_dependency_rule_is_refused(conn):
    """osv.py:102 puts `name@version` in the fourth slot -- recoverable only by
    parsing the title back -- and the `rule` is a GHSA/CVE id, which nobody
    renames. There is no case to serve and a fragile way to serve it."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _finding(
        category="dependency", rule="GHSA-xxxx", fingerprint="d" * 64))

    with pytest.raises(ValueError, match="dependency"):
        ledger.rename_rule(conn, "dependency", "GHSA-xxxx", "CVE-2026-1")


def test_a_refused_rename_writes_nothing(conn):
    """The refusal has to land before the first UPDATE, not partway through."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _finding(rule="sql-injection"))

    with pytest.raises(ValueError):
        ledger.rename_rule(conn, "sast", "sql-injection", "sqli")

    row = ledger.findings_of(conn, aid)[0]
    assert row["rule"] == "sql-injection"
    assert row["fingerprint"] == "a" * 64


def test_renaming_leaves_other_rules_alone(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("github_token"))

    assert ledger.rename_rule(conn, "secret", "aws_access_key",
                              "aws-access-token") == 0

    assert ledger.findings_of(conn, aid)[0]["rule"] == "github_token"


def test_renaming_only_touches_the_category_it_was_asked_about(conn):
    """The rule name is unique only WITHIN a category -- `secrets._RULES` and
    hygiene's literals are two separate namespaces, and the recompute recipe
    differs between them. A rename that matched on the rule name alone would
    rewrite the other category's finding with the wrong recipe."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("private_key"))
    ledger.record_finding(conn, aid, _hygiene_finding("private_key", "id_rsa"))
    untouched = fp_mod.fingerprint("hygiene", "private_key", "id_rsa", "private_key")

    assert ledger.rename_rule(conn, "secret", "private_key", "private-key") == 1

    by_category = {f["category"]: f for f in ledger.findings_of(conn, aid)}
    assert by_category["secret"]["rule"] == "private-key"
    assert by_category["hygiene"]["rule"] == "private_key"
    assert by_category["hygiene"]["fingerprint"] == untouched


def test_renaming_is_idempotent(conn):
    """Running the migration twice must not corrupt anything: the second run
    finds nothing under the old name and does nothing."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key"))
    ledger.set_decision(conn, "web", fp_mod.secret_fingerprint(
        "aws_access_key", "config/prod.env"), "accepted", "known", "luiz")

    assert ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token") == 1
    after_first = ledger.findings_of(conn, aid)[0]
    decisions = ledger.decisions_for(conn, "web")

    assert ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token") == 0
    assert ledger.findings_of(conn, aid)[0] == after_first
    assert ledger.decisions_for(conn, "web") == decisions


def test_renaming_moves_the_finding_in_every_analysis_that_has_it(conn):
    """The rename is a fact about the vocabulary, not about one run: the
    history it has to keep matchable is every analysis in the ledger."""
    old_fp = fp_mod.secret_fingerprint("aws_access_key", "config/prod.env")
    new_fp = fp_mod.secret_fingerprint("aws-access-token", "config/prod.env")
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    a2 = ledger.start_analysis(conn, "web", "web", "main", "c2", "standard", "r2")
    ledger.record_finding(conn, a1, _secret_finding("aws_access_key"))
    ledger.record_finding(conn, a2, _secret_finding("aws_access_key"))

    assert ledger.rename_rule(conn, "secret", "aws_access_key",
                              "aws-access-token") == 2

    for aid in (a1, a2):
        assert ledger.findings_of(conn, aid)[0]["fingerprint"] == new_fp
    assert old_fp != new_fp


def test_a_decision_follows_the_finding_in_every_project_that_made_one(conn):
    """`decision` is keyed (project, fingerprint) and the same fingerprint can
    be decided in more than one project -- two repositories under two projects
    can hold the same credential type in the same path. Scoping the decision
    update to one project would strand the others."""
    old_fp = fp_mod.secret_fingerprint("aws_access_key", "config/prod.env")
    new_fp = fp_mod.secret_fingerprint("aws-access-token", "config/prod.env")
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key"))
    ledger.set_decision(conn, "web", old_fp, "accepted", "rotated", "luiz")
    ledger.set_decision(conn, "api", old_fp, "false_positive", "a fixture", "ana")

    ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    assert ledger.decisions_for(conn, "web")[new_fp]["state"] == "accepted"
    assert ledger.decisions_for(conn, "api")[new_fp]["state"] == "false_positive"
    assert ledger.decisions_for(conn, "api")[new_fp]["reason"] == "a fixture"


def test_the_decision_event_follows_the_decision_to_the_new_identity(conn):
    """`cmd_decide` files a `decision_made` event whose `related` is the
    fingerprint's first 12 characters, and the Activity screen deep-links from
    that prefix into the findings browser. A rename that moved the decision and
    left the event behind keeps the human's call and destroys the record that
    it was taken about this finding: the link resolves to zero findings while
    the row still says the risk was accepted."""
    old_fp = fp_mod.secret_fingerprint("aws_access_key", "config/prod.env")
    new_fp = fp_mod.secret_fingerprint("aws-access-token", "config/prod.env")
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key"))
    ledger.set_decision(conn, "web", old_fp, "accepted", "rotated", "luiz")
    ledger.record_event(conn, "web", "decision_made", "Accepted: rotated",
                        old_fp[:12])
    # An event of another kind whose `related` is an analysis id, to prove the
    # update is scoped to the one kind that carries a fingerprint prefix.
    ledger.record_event(conn, "web", "analysis_finished", "done", str(aid))

    ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    events = {e["kind"]: e for e in ledger.events_for(conn, "web")}
    assert events["decision_made"]["related"] == new_fp[:12]
    assert events["analysis_finished"]["related"] == str(aid)
    # The link the Activity screen follows resolves to the finding again.
    linked = conn.execute(
        "SELECT fingerprint FROM finding WHERE fingerprint LIKE ?",
        (events["decision_made"]["related"] + "%",)).fetchall()
    assert [r["fingerprint"] for r in linked] == [new_fp]


def test_a_finding_with_no_occurrence_is_refused_rather_than_guessed(conn):
    """`report-finding` accepts a finding with no occurrences (they are
    optional there), and the path is half of a secret's identity. With no
    occurrence there is no path, and `secret_fingerprint(rule, "")` is an
    identity no scanner will ever emit. Refusing loudly is the same call as
    refusing `sast`: the alternative is a silent orphan."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, {
        "fingerprint": "e" * 64, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate", "occurrences": []})

    with pytest.raises(ValueError, match="occurrence"):
        ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    assert ledger.findings_of(conn, aid)[0]["fingerprint"] == "e" * 64


def test_an_occurrence_with_no_file_is_refused_the_same_as_no_occurrence(conn):
    """The near-miss of the test above, and the one that actually gets through
    a guard written as `if occ is None`. `report-finding` validates only that
    each occurrence is an OBJECT, and `record_finding` writes
    `occ.get("file", "")` -- so `{"line": 3}` is a reachable, accepted payload
    that produces an occurrence ROW with an empty path. The row exists, so the
    no-occurrence branch does not fire, and the recompute one line later mints
    `secret_fingerprint(new, "")`: exactly the identity no scanner will ever
    emit that the guard above refuses to guess, arrived at silently."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, {
        "fingerprint": "e" * 64, "category": "secret", "rule": "aws_access_key",
        "severity": "critical", "title": "t", "rationale": "r",
        "remediation": "rotate", "occurrences": [{"line": 3}]})
    # The payload really did reach the ledger as a row with an empty path --
    # otherwise this test would be asserting about a state that cannot exist.
    assert ledger.findings_of(conn, aid)[0]["occurrences"] == [
        {"file": "", "line": 3, "snippet_hash": ""}]

    with pytest.raises(ValueError, match="occurrence"):
        ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    row = ledger.findings_of(conn, aid)[0]
    assert row["fingerprint"] == "e" * 64
    assert row["rule"] == "aws_access_key"
    # Named explicitly: the value a silent guess would have written.
    assert row["fingerprint"] != fp_mod.secret_fingerprint("aws-access-token", "")


def test_a_colliding_rename_rolls_the_whole_thing_back(conn):
    """One transaction, for the reason `record_finding` uses one: a rename that
    stopped halfway is a ledger where some findings answer to the new name and
    some to the old, which is worse than one that never ran. `finding` is
    UNIQUE(analysis_id, fingerprint), so renaming onto a name the same analysis
    already holds at the same path is refused by SQLite -- and the finding
    already moved before the collision must come back."""
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key", "a.env"))
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key", "b.env"))
    ledger.record_finding(conn, aid, _secret_finding("aws-access-token", "b.env"))

    with pytest.raises(sqlite3.IntegrityError):
        ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    rules = sorted(f["rule"] for f in ledger.findings_of(conn, aid))
    assert rules == ["aws-access-token", "aws_access_key", "aws_access_key"]


def test_the_renameable_categories_are_the_two_with_a_derivable_identity(conn):
    """Pinned as a set, both ways. Adding a category here without a recompute
    recipe that matches how that category actually builds its fingerprint is
    the one mistake this whole function exists to prevent."""
    assert set(ledger.RENAMEABLE_CATEGORIES) == {"secret", "hygiene"}
