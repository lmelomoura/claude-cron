# tests/security/test_report.py
import json

import pytest

from security import coverage, report

AWS = "AKIA" + "IOSFODNN7EXAMPLE"

ANALYSIS = {"id": 7, "project": "web", "repo": "web", "branch": "main",
            "commit_sha": "abc1234", "profile": "standard", "started": 1770000000,
            "ended": 1770000600, "state": "done", "spend_usd": 1.5}

FINDINGS = [
    {"fingerprint": "a" * 64, "category": "secret", "rule": "aws_access_key",
     "severity": "critical", "title": "aws access key committed",
     "rationale": "found in the working tree", "remediation": "rotate it",
     "occurrences": [{"file": "prod.env", "line": 3, "snippet_hash": ""}],
     "state": "new"},
    {"fingerprint": "b" * 64, "category": "sast", "rule": "sql-injection",
     "severity": "high", "title": "string-built SQL", "rationale": "r",
     "remediation": "use parameters",
     "occurrences": [{"file": "app/db.py", "line": 12, "snippet_hash": "h"}],
     "state": "fixed"},
]


def test_the_json_report_carries_the_checklist():
    doc = json.loads(report.as_json(ANALYSIS, FINDINGS, ""))
    assert doc["analysis"]["branch"] == "main"
    assert doc["summary"]["by_state"]["new"] == 1
    assert doc["summary"]["by_state"]["fixed"] == 1


def test_a_coverage_note_is_impossible_to_miss():
    for text in (report.as_markdown(ANALYSIS, FINDINGS, "OSV was not reached"),
                 report.as_html(ANALYSIS, FINDINGS, "OSV was not reached")):
        assert "OSV was not reached" in text


def test_a_capped_analysis_says_so_in_every_format():
    capped = dict(ANALYSIS, state="capped")
    assert "capped" in report.as_json(capped, FINDINGS, "")
    assert "incomplete" in report.as_markdown(capped, FINDINGS, "").lower()
    assert "incomplete" in report.as_html(capped, FINDINGS, "").lower()


def test_a_capped_report_does_not_claim_a_spending_cap_when_it_never_ran():
    """Since the `prepared` guard in `cmd_finish` (bin/security/cli.py),
    `capped` also covers a `done` close downgraded because the deterministic
    phases never ran at all -- and for THAT case, `coverage_note` carries "The
    deterministic phases never ran for this analysis: ...". The old wording
    said, unconditionally, that the analysis "reached its spending cap", which
    is simply false for this cause and produced two adjacent, contradicting
    lines in the same report. The fixed wording must say only what is true of
    every `capped` report, whatever the cause -- the cause itself is the
    coverage note's job, not this line's."""
    capped = dict(ANALYSIS, state="capped")
    note = ("The deterministic phases never ran for this analysis: no secret "
            "sweep, no dependency inventory, no hygiene pass.")
    for text in (report.as_markdown(capped, FINDINGS, note),
                 report.as_html(capped, FINDINGS, note)):
        assert "spending cap" not in text.lower()
        assert "incomplete" in text.lower()
        assert note in text


def test_html_escapes_a_finding_title():
    hostile = [dict(FINDINGS[0], title="<script>alert(1)</script>")]
    html = report.as_html(ANALYSIS, hostile, "")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_no_report_format_can_ever_carry_a_secret_value():
    """The adversarial test. A finding is built the way secrets.py builds one --
    with the value deliberately absent -- and every format is searched for it."""
    leaky = [dict(FINDINGS[0], rationale=f"found in the working tree")]
    for text in (report.as_json(ANALYSIS, leaky, ""),
                 report.as_markdown(ANALYSIS, leaky, ""),
                 report.as_html(ANALYSIS, leaky, "")):
        assert AWS not in text


def test_an_unknown_state_is_not_dropped_from_the_checklist():
    """`by_state` accepts any state string; the MD/HTML checklists must not
    silently drop one that falls outside STATES -- data must never disappear
    between formats. The known "new" count is asserted alongside it as a
    control: the fix must not disturb counting of the states it already knew."""
    findings = [FINDINGS[0], dict(FINDINGS[0], fingerprint="c" * 64,
                                   state="some_future_state")]
    md = report.as_markdown(ANALYSIS, findings, "")
    htm = report.as_html(ANALYSIS, findings, "")
    assert "new: 1" in md and "some_future_state: 1" in md
    assert "new: 1" in htm and "some_future_state: 1" in htm


def test_accepted_risk_is_disclosed_in_the_severity_block():
    findings = [dict(FINDINGS[0], state="accepted")]
    doc = json.loads(report.as_json(ANALYSIS, findings, ""))
    assert doc["summary"]["accepted_in_severity"] == 1
    md = report.as_markdown(ANALYSIS, findings, "")
    htm = report.as_html(ANALYSIS, findings, "")
    assert "1 accepted risk" in md
    assert "1 accepted risk" in htm


def test_no_accepted_disclosure_when_nothing_is_accepted():
    """Control for the disclosure above: with no accepted finding, none of the
    three formats mention accepted risks at all -- the note must not become
    noise printed unconditionally."""
    doc = json.loads(report.as_json(ANALYSIS, FINDINGS, ""))
    assert doc["summary"]["accepted_in_severity"] == 0
    md = report.as_markdown(ANALYSIS, FINDINGS, "")
    htm = report.as_html(ANALYSIS, FINDINGS, "")
    assert "accepted risk" not in md
    assert "accepted risk" not in htm


def test_html_escapes_a_hostile_occurrence_line():
    """Every current producer coerces `line` to int before it reaches report.py
    (see ledger.py), so this is not reachable today -- but report.py must not
    rely on its callers forever."""
    hostile = [dict(FINDINGS[0], occurrences=[
        {"file": "prod.env", "line": '12" onmouseover="x', "snippet_hash": ""}])]
    htm = report.as_html(ANALYSIS, hostile, "")
    assert 'onmouseover="x' not in htm
    assert "&quot;" in htm


def test_by_severity_excludes_terminal_states_and_counts_open_and_accepted():
    findings = [
        dict(FINDINGS[0], fingerprint="c" * 64, state="open", severity="critical"),
        dict(FINDINGS[0], fingerprint="d" * 64, state="accepted", severity="critical"),
        dict(FINDINGS[0], fingerprint="e" * 64, state="fixed", severity="critical"),
        dict(FINDINGS[0], fingerprint="f" * 64, state="false_positive", severity="critical"),
    ]
    s = report._summary(findings)
    assert s["by_severity"]["critical"] == 2  # open + accepted only


def test_empty_findings_render_in_every_format_without_crashing():
    doc = json.loads(report.as_json(ANALYSIS, [], ""))
    assert doc["summary"]["total"] == 0
    assert all(v == 0 for v in doc["summary"]["by_state"].values())
    assert all(v == 0 for v in doc["summary"]["by_severity"].values())
    assert doc["summary"]["accepted_in_severity"] == 0
    md = report.as_markdown(ANALYSIS, [], "")
    htm = report.as_html(ANALYSIS, [], "")
    assert "## Findings" in md
    assert "<h2>Findings</h2>" in htm


def test_a_finding_with_no_occurrences_renders_without_crashing():
    findings = [dict(FINDINGS[0], occurrences=[])]
    report.as_json(ANALYSIS, findings, "")
    report.as_markdown(ANALYSIS, findings, "")
    report.as_html(ANALYSIS, findings, "")


def test_html_escapes_rationale_not_just_title():
    hostile = [dict(FINDINGS[0], rationale="<script>alert(1)</script>")]
    htm = report.as_html(ANALYSIS, hostile, "")
    assert "<script>alert(1)</script>" not in htm
    assert "&lt;script&gt;" in htm


def test_the_report_names_exactly_the_states_the_engine_can_produce():
    """A THIRD copy of the vocabulary.

    `diff.DERIVED_STATES` is what classify() attaches, `ledger.DECISION_STATES`
    is what a human can record, and `report.STATES` is what the Markdown and
    HTML checklists iterate. The page's own list is already bound to the first
    two (tests/test_page_contract.py); this binds the third, which is the one
    that decides whether a state SHOWS UP in a downloaded report at all. A
    state added to the engine and forgotten here is a bucket of findings the
    checklist section silently never counts -- _unknown_states() catches it at
    runtime, but only as an unnamed extra line, and only if somebody reads it.

    Order-insensitive on purpose: STATES is ordered for a reader (worst news
    first), not to mirror either tuple.
    """
    from security import diff, ledger, report
    assert set(report.STATES) == set(diff.DERIVED_STATES) | set(ledger.DECISION_STATES), (
        f"report.STATES={sorted(report.STATES)} "
        f"engine={sorted(set(diff.DERIVED_STATES) | set(ledger.DECISION_STATES))}")
    assert len(report.STATES) == len(set(report.STATES)), "a state is listed twice"


def test_info_is_a_severity_and_sorts_below_low():
    assert "info" in report.SEVERITIES
    assert report.SEVERITIES.index("info") > report.SEVERITIES.index("low")


def test_json_carries_the_classification():
    findings = [dict(FINDINGS[1], cwe="CWE-89", owasp="A03:2021")]
    doc = json.loads(report.as_json(ANALYSIS, findings, ""))
    assert doc["findings"][0]["cwe"] == "CWE-89"
    assert doc["findings"][0]["owasp"] == "A03:2021"


def test_markdown_shows_the_classification():
    findings = [dict(FINDINGS[1], cwe="CWE-89", owasp="A03:2021")]
    out = report.as_markdown(ANALYSIS, findings, "")
    assert "CWE-89" in out
    assert "A03:2021" in out


def test_an_unclassified_finding_says_nothing_rather_than_an_empty_label():
    # A hygiene finding has no CWE. Rendering "CWE: " with nothing after it
    # reads as a missing value the reader should chase.
    findings = [dict(FINDINGS[0], category="hygiene", rule="committed_env_file",
                      cwe="", owasp="")]
    out = report.as_markdown(ANALYSIS, findings, "")
    assert "CWE" not in out


def test_html_shows_the_classification():
    findings = [dict(FINDINGS[1], cwe="CWE-89", owasp="A03:2021")]
    out = report.as_html(ANALYSIS, findings, "")
    assert "CWE-89" in out
    assert "A03:2021" in out


def test_an_unclassified_finding_shows_no_classification_markup_in_html():
    # Every deterministic finding (secret, dependency, hygiene) has an empty
    # cwe/owasp. Emitting the classification wrapper with nothing inside it
    # reads as a missing value the reader should chase -- so the whole
    # <p class="cls"> block must be absent, not just empty. Narrowed to the
    # attribute itself, not the bare substring "cls": `_CSS` carries a
    # `.cls` rule, which also appears in the `<style>` block this renders
    # into, and a substring check over the whole document would fail for a
    # reason that has nothing to do with what this test asserts.
    findings = [dict(FINDINGS[0], category="hygiene", rule="committed_env_file",
                      cwe="", owasp="")]
    out = report.as_html(ANALYSIS, findings, "")
    assert 'class="cls"' not in out


def test_html_escapes_the_classification_fields():
    """The adversarial test for the classification block. `cwe` and `owasp`
    come from analysed code same as any other finding field, and report.py's
    only defence is the `e()` (html.escape) wrapper -- nothing else would
    catch a future edit that dropped it from this one block."""
    findings = [dict(FINDINGS[1], cwe="<script>alert(1)</script>",
                      owasp='A03" onmouseover="x')]
    htm = report.as_html(ANALYSIS, findings, "")
    assert "<script>alert(1)</script>" not in htm
    assert "&lt;script&gt;" in htm
    assert 'onmouseover="x' not in htm
    assert "&quot;" in htm


# ------------------------------------------------------------------- `scope`
#
# Rendered the way `cwe`/`owasp` are: nothing at all when the value is absent
# (every non-dependency finding carries ''), and expanded into a sentence
# fragment when it is present, because the bare word invites the wrong reading
# in both directions -- "dev" reads as "ignore me" and "unknown" reads as
# "probably fine".

DEP = {"fingerprint": "c" * 64, "category": "dependency", "rule": "CVE-2021-44906",
       "severity": "high", "title": "minimist 1.2.5: CVE-2021-44906",
       "rationale": "prototype pollution", "remediation": "upgrade",
       "occurrences": [{"file": "package-lock.json", "line": 0, "snippet_hash": ""}],
       "state": "new", "scope": "dev"}


def test_json_always_carries_the_scope_key():
    """The two human formats render nothing when it is absent, so they cannot
    be parsed for it. This one can: something reading the JSON has to tell "the
    analysis predates the column" from "this finding is not a dependency"
    without special-casing a missing key."""
    doc = json.loads(report.as_json(ANALYSIS, FINDINGS + [DEP], ""))
    by_rule = {f["rule"]: f for f in doc["findings"]}
    assert by_rule["CVE-2021-44906"]["scope"] == "dev"
    assert by_rule["aws_access_key"]["scope"] == "", (
        "the key is present on a finding that has no scope, not missing")


def test_markdown_and_html_name_the_scope_and_say_what_it_means():
    md = report.as_markdown(ANALYSIS, [DEP], "")
    html_out = report.as_html(ANALYSIS, [DEP], "")
    assert "Scope: dev — a development-only dependency, not shipped" in md
    assert "Scope: dev — a development-only dependency, not shipped" in html_out


def test_unknown_renders_as_unknown_and_never_as_runtime():
    """The whole point of the third value: a reader must not take "not marked
    dev" for "ships"."""
    md = report.as_markdown(ANALYSIS, [{**DEP, "scope": "unknown"}], "")
    assert "does not say whether it ships" in md
    assert "runtime" not in md


def test_a_finding_with_no_scope_renders_no_scope_line_at_all():
    """Every secret, hygiene, iac and sast finding carries '', and a column of
    "Scope: —" on all of them is a line a reader learns to skip."""
    assert "Scope:" not in report.as_markdown(ANALYSIS, FINDINGS, "")
    assert "Scope:" not in report.as_html(ANALYSIS, FINDINGS, "")


def test_a_scope_value_this_module_does_not_know_is_shown_not_dropped():
    """A vocabulary this renderer has not been taught is still a fact the
    ledger holds. Hiding it would be the silent difference one level down."""
    md = report.as_markdown(ANALYSIS, [{**DEP, "scope": "vendored"}], "")
    assert "Scope: vendored" in md


def test_html_escapes_the_scope_field():
    html_out = report.as_html(ANALYSIS, [{**DEP, "scope": "<img src=x>"}], "")
    assert "<img src=x>" not in html_out
    assert "&lt;img src=x&gt;" in html_out


# ---------------------------------------------- the structured coverage note
#
# `coverage_note` is ~2,000 characters of prose on a real analysis, built by
# concatenating 27 `*_NOTE` constants across six modules (cmd_prepare). Every
# sentence is true; the block is unreadable. The `coverage` column carries the
# SAME sentences attributed to the phase that produced them, and every
# renderer prints that table BEFORE the prose. These tests pin the two halves
# that make it worth having: the table cannot slide below the paragraph, and
# an analysis that has no table renders exactly as it did before the column
# existed.

PHASES = coverage.encode([
    coverage.phase(coverage.SCOPE, coverage.RAN, note="fixtures were skipped"),
    coverage.phase(coverage.SECRETS, coverage.RAN, "gitleaks"),
    coverage.phase(coverage.DEPENDENCIES, coverage.WARNING, "osv",
                   "OSV.dev reads five lockfile formats"),
    coverage.phase(coverage.IAC, coverage.SKIPPED,
                   note="trivy is not available to this analysis"),
])
WITH_PHASES = dict(ANALYSIS, coverage=PHASES)


def test_the_json_report_always_carries_the_phases_key():
    """`coverage.phases` is ALWAYS a key, the same rule a finding's `scope`
    follows: the two formats a human reads print nothing when there is nothing
    to print, so they cannot be parsed for an absence. A consumer has to be
    able to tell "this analysis predates the column" (an empty list) from
    "this is an older report format" (no key) without special-casing either.
    And `coverage.notes` is what this key used to BE -- the prose, unchanged,
    beside the structure rather than replaced by it."""
    doc = json.loads(report.as_json(WITH_PHASES, FINDINGS, "OSV was not reached"))
    names = [p["name"] for p in doc["coverage"]["phases"]]
    assert names == ["scope", "secrets", "dependencies", "iac"]
    assert doc["coverage"]["phases"][3]["status"] == "skipped"
    assert doc["coverage"]["phases"][3]["by"] is None
    assert "OSV was not reached" in doc["coverage"]["notes"]

    old = json.loads(report.as_json(ANALYSIS, FINDINGS, ""))
    assert old["coverage"]["phases"] == []


def test_markdown_opens_with_the_phase_table_before_the_prose():
    """THE ORDER IS THE FEATURE. The paragraph below is every gap this
    analysis has, sentence by sentence, and it is what made a real report
    unreadable; the table is what a reader can answer "who looked?" from in
    one glance. A table printed after the prose is a table nobody reaches."""
    md = report.as_markdown(WITH_PHASES, FINDINGS, "OSV was not reached")
    table = md.index("| Phase | Status | By |")
    assert table < md.index("OSV was not reached"), \
        "the phase table must come BEFORE the coverage prose, not after it"
    assert table < md.index("## Checklist")
    assert "| secrets | ran | gitleaks |" in md
    assert "| iac | skipped | — |" in md


def test_the_phase_table_keeps_the_order_the_ledger_stored():
    """One row per phase, in the stored order, and every phase present.
    `coverage.encode` is the single place that orders them (scope first
    because it qualifies everything below it, triage last because it is the
    only one `finish` writes), so a renderer that sorted for itself would be
    a second opinion that could differ from the JSON's."""
    md = report.as_markdown(WITH_PHASES, FINDINGS, "")
    rows = [line for line in md.splitlines()
            if line.startswith("| ") and not line.startswith("| --- ")]
    assert [r.split(" | ")[0].removeprefix("| ") for r in rows] == \
        ["Phase", "scope", "secrets", "dependencies", "iac"]


def test_a_skipped_phase_is_named_even_with_no_prose_of_its_own():
    """A phase whose sentence somebody deleted is still a phase that did not
    run, and the row is what says so. This is the whole reason the status
    comes off the scanner's own return value and not off the presence of a
    note: the two can disagree, and when they do the fact is the status.

    THE HTML ASSERTION IS ON A CELL. It used to be `"skipped" in html`, which
    passed on a page with no such row: the word was in the stylesheet, as the
    class `.cov .skipped`. The class is now spelled differently from the
    status (`_STATUS_CLASS`), and what is asserted is the rendered `<td>`."""
    silent = dict(ANALYSIS, coverage=coverage.encode(
        [coverage.phase(coverage.IAC, coverage.SKIPPED)]))
    md = report.as_markdown(silent, FINDINGS, "")
    assert "| iac | skipped | — |" in md
    html = report.as_html(silent, FINDINGS, "")
    assert '<td class="cov-gap">skipped</td>' in html
    # And the word appears ONLY in that cell: strip the cell and it is gone.
    assert "skipped" not in html.replace('<td class="cov-gap">skipped</td>', "")


def test_no_status_class_spells_the_status_it_colours():
    """The rule that keeps the assertion above honest for good: a test that
    finds a status word in the HTML has found it in a cell, never in a class
    name. Every status has a class, and a status this table does not know
    renders as a bare word with no class at all -- nothing for a hostile value
    to ride into an attribute on."""
    assert set(report._STATUS_CLASS) == set(coverage.STATUSES)
    for status, cls in report._STATUS_CLASS.items():
        assert status not in cls, (status, cls)
    odd = dict(ANALYSIS, coverage=json.dumps({"phases": [
        {"name": "iac", "status": "quantum", "by": None, "note": ""}]}))
    assert "<td>quantum</td>" in report.as_html(odd, FINDINGS, "")


def test_html_opens_with_the_phase_table_before_the_prose():
    """The HTML twin of the Markdown test above, and it was missing: the table
    could be moved below the paragraph with every test still green. Pinned on
    the TAGS' positions -- the table's opening tag before the first prose
    element's -- not on a word that could appear in either."""
    html = report.as_html(WITH_PHASES, FINDINGS, "OSV was not reached")
    table = html.index('<table class="cov">')
    assert table < html.index('<p class="note">'), \
        "the phase table must come BEFORE the coverage prose, not after it"
    assert table < html.index("<h2>Checklist</h2>")
    assert '<td class="cov-ok">ran</td>' in html
    assert '<td class="cov-warn">warning</td>' in html


def test_the_agents_own_sast_pass_has_a_row_between_the_pre_pass_and_the_triage():
    """Nine rows, not eight. The Semgrep pre-pass is an ADDITION to the
    agent's own SAST pass (see `cli._scan_sast`), so a table with a row for
    the pre-pass and none for the pass said nothing about the primary source
    of the `sast` category. The row is named for that category, and it sits
    where the pass happens: after everything `prepare` filed, before the
    triage that closes the analysis."""
    order = coverage.PHASE_ORDER
    assert len(order) == 9
    assert coverage.SAST_AGENT == "sast"
    assert order.index(coverage.SAST_AGENT) == order.index(coverage.SAST_PREPASS) + 1
    assert order[-1] == coverage.TRIAGE


def test_an_analysis_with_no_structured_coverage_renders_exactly_as_before():
    """EVERY analysis written before the `coverage` column carries '' in it,
    and three reports plus three screens have always read the prose alone.
    Nothing about them may change: no empty table, no header for a section
    with no rows, no placeholder."""
    for text in (report.as_markdown(ANALYSIS, FINDINGS, "OSV was not reached"),
                 report.as_html(ANALYSIS, FINDINGS, "OSV was not reached")):
        assert "Coverage" not in text
        assert "Phase" not in text
        assert "OSV was not reached" in text


def test_a_coverage_document_this_module_cannot_read_never_breaks_a_download():
    """A report is not the place to discover that a column got corrupted, and
    the prose beside it is still true. Anything unreadable renders as an
    analysis with no structure at all -- never a traceback inside a download,
    never a half-drawn table."""
    for broken in ("not json at all", "[]", '{"phases": "secrets"}', "null"):
        analysis = dict(ANALYSIS, coverage=broken)
        assert "| Phase |" not in report.as_markdown(analysis, FINDINGS, "")
        doc = json.loads(report.as_json(analysis, FINDINGS, ""))
        assert doc["coverage"]["phases"] == []


def test_html_escapes_a_phase_row():
    """The status is the row's CSS class as well as its text, and both come
    off a database column. A class attribute is exactly as much of a sink as
    the text beside it."""
    hostile = dict(ANALYSIS, coverage=json.dumps({"phases": [
        {"name": "<img src=x>", "status": '"><script>alert(1)</script>',
         "by": "<b>", "note": ""}]}))
    out = report.as_html(hostile, FINDINGS, "")
    assert "<img src=x>" not in out
    assert "<script>alert(1)</script>" not in out
    assert "&lt;img src=x&gt;" in out


def test_a_phase_name_carrying_a_pipe_cannot_eat_the_markdown_row():
    """These values come from a closed vocabulary this project writes, but
    they are read back out of a column -- and a stray pipe would silently
    swallow the rest of the row rather than showing up as the odd value it
    is."""
    piped = dict(ANALYSIS, coverage=json.dumps({"phases": [
        {"name": "a | b", "status": "ran", "by": None, "note": ""}]}))
    md = report.as_markdown(piped, FINDINGS, "")
    assert "| a \\| b | ran | — |" in md


def test_the_phase_builder_refuses_a_name_or_status_it_does_not_know():
    """A typo'd phase would sort to the end of the table and read as a phase
    this project does not have; a typo'd status would render as a word with no
    colour and no meaning. Both are refused where they are written, which is
    the only place the mistake is still cheap."""
    with pytest.raises(ValueError):
        coverage.phase("secrests", coverage.RAN)
    with pytest.raises(ValueError):
        coverage.phase(coverage.SECRETS, "ok")


def test_encode_orders_the_phases_and_keeps_an_unknown_one():
    """Ordered ONCE, here, so no renderer has to sort and none of them can
    sort differently. A name this module has not been taught goes to the end
    rather than being dropped -- the same rule `_unknown_states` follows for a
    state outside the contract."""
    doc = json.loads(coverage.encode([
        coverage.phase(coverage.TRIAGE, coverage.RAN, "agent"),
        {"name": "quantum", "status": "ran", "by": None, "note": ""},
        coverage.phase(coverage.SCOPE, coverage.RAN),
    ]))
    assert [p["name"] for p in doc["phases"]] == ["scope", "triage", "quantum"]


def test_merge_replaces_a_phase_rather_than_appending_a_second_one():
    """`finish` runs TWICE on one analysis -- the agent closes it, then the
    engine closes the same row again with the run's own verdict. A triage
    phase appended each time would give the table two contradicting triage
    lines by the second close, which is the structured version of the bug the
    prose's own `part not in note` guard exists to stop."""
    first = [coverage.phase(coverage.TRIAGE, coverage.WARNING, "agent", "12 unread")]
    again = coverage.merge(first, [coverage.phase(coverage.TRIAGE, coverage.RAN,
                                                  "agent", "all read")])
    assert len(again) == 1 and again[0]["note"] == "all read"
