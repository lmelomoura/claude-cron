# tests/security/test_osv.py
import urllib.error
from pathlib import Path

import pytest
from security import osv

FIXTURES = Path(__file__).parent / "fixtures"
COMPONENT = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
             "source": "package-lock.json"}


def _serve(monkeypatch):
    """Answer both endpoints from the captured responses."""
    batch = (FIXTURES / "osv-querybatch.json").read_text()
    detail = (FIXTURES / "osv-vuln-detail.json").read_text()
    calls = []

    def fake(url, body=None, timeout=30):
        calls.append(url)
        return batch if url.endswith("/querybatch") else detail

    monkeypatch.setattr(osv, "_http", fake)
    return calls


def test_it_turns_a_real_osv_response_into_findings(monkeypatch):
    _serve(monkeypatch)
    findings, note = osv.query([COMPONENT])
    assert note == ""
    assert findings
    assert findings[0]["category"] == "dependency"
    assert findings[0]["rule"].startswith("GHSA-")
    assert findings[0]["occurrences"][0]["file"] == "package-lock.json"


def test_the_severity_comes_from_database_specific_not_the_cvss_list(monkeypatch):
    """The captured detail has database_specific.severity == MODERATE and a
    top-level `severity` that is a list of CVSS vectors. Reading the list as a
    string is the silent bug this asserts against."""
    _serve(monkeypatch)
    findings, _ = osv.query([COMPONENT])
    moderate = [f for f in findings if f["rule"] == "GHSA-29mw-wpgm-hmr9"]
    assert moderate and moderate[0]["severity"] == "medium"


def test_the_summary_reaches_the_finding(monkeypatch):
    _serve(monkeypatch)
    findings, _ = osv.query([COMPONENT])
    match = [f for f in findings if f["rule"] == "GHSA-29mw-wpgm-hmr9"][0]
    assert "ReDoS" in match["rationale"] or "Denial of Service" in match["rationale"]


def test_a_cached_detail_is_not_fetched_twice(monkeypatch):
    calls = _serve(monkeypatch)
    cache = {}
    osv.query([COMPONENT], detail_cache=cache)
    first = len([c for c in calls if "/vulns/" in c])
    assert first > 0
    osv.query([COMPONENT], detail_cache=cache)
    assert len([c for c in calls if "/vulns/" in c]) == first


def test_the_network_being_down_never_raises(monkeypatch):
    def boom(url, body=None, timeout=30):
        raise urllib.error.URLError("no route to host")
    monkeypatch.setattr(osv, "_http", boom)
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert "OSV" in note


def test_a_detail_lookup_failing_still_reports_the_vulnerability(monkeypatch):
    """Knowing a CVE applies is most of the value. Losing the whole finding
    because its prose could not be fetched would be the worse trade."""
    batch = (FIXTURES / "osv-querybatch.json").read_text()

    def half(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            return batch
        raise urllib.error.URLError("detail unavailable")

    monkeypatch.setattr(osv, "_http", half)
    findings, note = osv.query([COMPONENT])
    assert findings
    assert findings[0]["severity"] == "medium"
    assert note


def test_no_components_means_no_call_and_no_note(monkeypatch):
    monkeypatch.setattr(osv, "_http",
                        lambda *a, **k: pytest.fail("must not call"))
    assert osv.query([]) == ([], "")


def test_a_malformed_batch_response_is_a_declared_gap_not_a_crash(monkeypatch):
    monkeypatch.setattr(osv, "_http", lambda url, body=None, timeout=30: "not json")
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert note


def test_a_wrongly_shaped_batch_response_is_a_declared_gap_not_a_crash(monkeypatch):
    """`"[]"` is valid JSON -- it parses cleanly, unlike "not json" above.
    Before the fix, `.get("results", [])` was called on whatever json.loads
    returned with no type check, so a top-level list raised AttributeError
    straight out of query(), uncaught by the surrounding except."""
    monkeypatch.setattr(osv, "_http", lambda url, body=None, timeout=30: "[]")
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert note


def test_a_truthy_non_dict_detail_is_treated_as_a_failed_lookup(monkeypatch):
    """`'["x"]'` also parses cleanly. Before the fix, _finding's `if detail:`
    check is True for a non-empty list (only a FALSY non-dict degraded
    gracefully by accident), so _severity_of(detail) called .get() on the
    list and raised AttributeError, uncaught anywhere in the call chain."""
    batch = (FIXTURES / "osv-querybatch.json").read_text()

    def truthy_non_dict(url, body=None, timeout=30):
        return batch if url.endswith("/querybatch") else '["x"]'

    monkeypatch.setattr(osv, "_http", truthy_non_dict)
    findings, note = osv.query([COMPONENT])
    assert findings
    assert all(f["severity"] == osv.DEFAULT_SEVERITY for f in findings)
    assert str(len(findings)) in note


def test_a_non_dict_results_entry_is_skipped_not_crashed(monkeypatch):
    """A results entry that is a bare string instead of an object. Before
    the fix, `(result or {}).get("vulns", [])` only guarded FALSY non-dict
    values -- a truthy string bypassed the `or {}` and raised AttributeError
    from calling .get() on a str."""
    monkeypatch.setattr(
        osv, "_http",
        lambda url, body=None, timeout=30: '{"results": ["oops"]}')
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert note == ""
