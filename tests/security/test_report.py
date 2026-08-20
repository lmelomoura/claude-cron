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
