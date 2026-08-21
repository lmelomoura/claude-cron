# tests/security/test_report.py
import json
from security import report

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
