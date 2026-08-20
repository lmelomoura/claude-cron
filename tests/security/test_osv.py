# tests/security/test_osv.py
import http.client
import json
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


def test_severity_of_reads_database_specific_not_the_top_level_severity_list():
    """A direct unit test of _severity_of, bypassing query() entirely.

    The integration test above cannot actually distinguish a correct read
    from the bug it is meant to guard against: the fixture's MODERATE maps
    to "medium", which IS DEFAULT_SEVERITY, so a buggy implementation that
    always falls back to the default would pass it too. This detail's
    database_specific.severity is HIGH (not the default) while its
    top-level `severity` is the usual CVSS-vector list; reading that list as
    a string instead would produce DEFAULT_SEVERITY, not "high" -- the two
    implementations disagree here, which is the whole point.
    """
    detail = {
        "database_specific": {"severity": "HIGH"},
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    }
    assert osv._severity_of(detail) == "high"


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


def test_a_successful_but_empty_detail_is_not_reported_as_a_failed_fetch(monkeypatch):
    """`_detail` returning `{}` is a SUCCESS (valid JSON, right container)
    that simply has nothing useful inside -- not a failure. Before the fix,
    _finding's `if detail:` treated the falsy empty dict exactly like a
    `None` (failed) detail, so the finding's rationale wrongly claimed the
    fetch had failed even though it had not."""
    batch = (FIXTURES / "osv-querybatch.json").read_text()

    def empty_detail(url, body=None, timeout=30):
        return batch if url.endswith("/querybatch") else "{}"

    monkeypatch.setattr(osv, "_http", empty_detail)
    findings, note = osv.query([COMPONENT])
    assert findings
    assert all("could not be fetched" not in f["rationale"] for f in findings)
    assert "could not be described" not in note


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
    the shape-check fix, `(result or {}).get("vulns", [])` only guarded
    FALSY non-dict values -- a truthy string bypassed the `or {}` and raised
    AttributeError from calling .get() on a str.

    This entry IS paired by zip -- OSV.dev did answer for this component --
    just not usably, so it must count the same way a component `zip`
    truncated off the tail would: named in the coverage note, not a silent
    gap."""
    monkeypatch.setattr(
        osv, "_http",
        lambda url, body=None, timeout=30: '{"results": ["oops"]}')
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert "1 of 1" in note
    assert "not checked" in note


def test_a_non_list_vulns_field_counts_as_unchecked_too(monkeypatch):
    """A result entry that IS a dict, but whose `vulns` is not a list (e.g.
    a bare string). Shape-wrong in a different spot than the test above, but
    the same kind of gap: OSV.dev answered, just not usably, so it must be
    named in the coverage note rather than silently skipped."""
    monkeypatch.setattr(
        osv, "_http",
        lambda url, body=None, timeout=30: '{"results": [{"vulns": "oops"}]}')
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert "1 of 1" in note
    assert "not checked" in note


def test_fewer_results_than_queries_names_the_unchecked_count(monkeypatch):
    """OSV.dev's querybatch response is positionally paired with the query --
    fewer `results` entries than queried components means the tail was
    silently never checked. zip() correctly stops at the shorter sequence
    (that part is not the bug); the gap it creates must still be named, not
    swallowed."""
    other = {"ecosystem": "npm", "name": "other-pkg", "version": "2.0.0",
             "source": "package-lock.json"}
    batch = '{"results": [{"vulns": [{"id": "GHSA-first-first-firs"}]}]}'

    def fake(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            return batch
        return '{"summary": "x", "database_specific": {"severity": "LOW"}}'

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT, other])
    assert len(findings) == 1
    assert findings[0]["rule"] == "GHSA-first-first-firs"
    assert "1 of 2" in note
    assert "not checked" in note


def test_a_non_dict_vuln_entry_is_skipped_not_crashed(monkeypatch):
    """A vulns list entry that is a bare string instead of an object.
    `vuln.get("id")` would raise AttributeError on a str with no isinstance
    guard. This case had no dedicated test before -- it was only ever
    exercised incidentally, if at all."""
    batch = ('{"results": [{"vulns": ['
             '"not-a-dict", {"id": "GHSA-real-real-real"}'
             ']}]}')

    def fake(url, body=None, timeout=30):
        return batch if url.endswith("/querybatch") else '{"summary": "ok"}'

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT])
    assert len(findings) == 1
    assert findings[0]["rule"] == "GHSA-real-real-real"


def test_a_non_string_vuln_id_is_skipped_not_crashed(monkeypatch):
    """`{"id": 123}` is truthy and survives a bare `if not vuln_id: continue`
    guard, then reaches fingerprint("dependency", 123, ...), whose _digest
    does `"\\x00".join(parts)` -- a TypeError, since join requires every
    part to be a str. Only a str id can ever be looked up on OSV.dev or
    linked to an advisory page, so anything else is skipped, not crashed
    on."""
    batch = '{"results": [{"vulns": [{"id": 123}]}]}'

    def fake(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            return batch
        return pytest.fail("a non-string id must never reach a detail lookup")

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT])
    assert findings == []
    assert note == ""


def test_an_unhashable_vuln_id_does_not_crash_the_cache_probe(monkeypatch):
    """A list id is truthy (surviving the old bare guard) and, unlike a
    number, is also unhashable: `vuln_id in cache` raises TypeError for a
    list, since membership testing on a dict needs to hash the candidate.
    That line is only reached when `cache` is an actual dict -- the tests'
    usual implicit `detail_cache=None` short-circuits `cache is not None`
    and never evaluates it, which is exactly why this crash went unseen.
    The isinstance(str) guard added for the non-string id above closes this
    too, but only because it runs before _detail is ever called."""
    batch = '{"results": [{"vulns": [{"id": ["not", "a", "string"]}]}]}'

    def fake(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            return batch
        return pytest.fail("an unhashable id must never reach a detail lookup")

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT], detail_cache={})
    assert findings == []
    assert note == ""


def test_a_hostile_vuln_id_does_not_crash_the_real_urlopen(monkeypatch):
    """A CR/LF in a vuln id, concatenated unencoded into the detail URL,
    makes the REAL urlopen raise http.client.InvalidURL before any socket
    opens -- a purely local, offline check inside http.client, confirmed by
    hand, not a network failure. InvalidURL is an HTTPException, not a
    URLError, so before the fix it propagated straight out of _detail and
    out of query(), uncaught by either's except tuple.

    _VULN_URL is pointed at a refusing local port so the REAL _http/urlopen
    runs end to end without needing actual internet access: once percent-
    encoding neutralises the CR/LF, urlopen gets as far as a real (and
    instantly refused) connection attempt, which the ORIGINAL except tuple
    already handled -- this test is about the crash before that point, not
    about the network."""
    monkeypatch.setattr(osv, "_VULN_URL", "http://127.0.0.1:1/vulns/")
    real_http = osv._http
    hostile_id = "evil\r\nX-Injected: yes"
    batch = json.dumps({"results": [{"vulns": [{"id": hostile_id}]}]})

    def fake(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            return batch
        return real_http(url, body, timeout)

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT], detail_cache={}, timeout=2)
    assert findings
    assert findings[0]["rule"] == hostile_id


def test_detail_catches_http_client_exceptions_too(monkeypatch):
    """The widened except tuple is the backstop for the percent-encoding fix
    above: even if some input ever reached urlopen unencoded (or a later
    change dropped the encoding), an HTTPException raised locally must still
    cost only this vulnerability's prose, not the whole query. Isolated from
    the encoding fix by raising the exception directly, regardless of what
    URL _detail builds."""
    def boom(url, body=None, timeout=30):
        raise http.client.InvalidURL("URL can't contain control characters")
    monkeypatch.setattr(osv, "_http", boom)
    detail, failed = osv._detail("GHSA-xxxx-xxxx-xxxx", {}, 30)
    assert detail is None
    assert failed == "GHSA-xxxx-xxxx-xxxx"


def test_a_malformed_component_is_skipped_not_crashed(monkeypatch):
    """A component missing "version" (and "source"), and a bare None, would
    each raise before or inside query()'s own try -- KeyError building the
    batch query body for the first, TypeError from indexing None for the
    second. Real components come from deps.inventory(), which always
    supplies every key, so this is belt-and-braces -- but the contract is
    unconditional: query() must not crash on a malformed component, so both
    are filtered out up front and named, together, in the coverage note."""
    _serve(monkeypatch)
    broken = {"ecosystem": "npm", "name": "left-pad"}
    findings, note = osv.query([COMPONENT, broken, None])
    assert findings  # the one well-formed component is still checked
    assert "2 malformed inventory entries" in note


def test_a_batch_exception_partway_keeps_the_findings_already_collected(monkeypatch):
    """Two components, chunked one at a time (_BATCH patched to 1): the
    first chunk's request succeeds and produces a real finding, the second
    chunk's request raises. Every other early return in query() keeps what
    it already found and states the gap -- before the fix, this was the one
    exception, discarding the first component's real finding and claiming
    nothing had been checked at all."""
    monkeypatch.setattr(osv, "_BATCH", 1)
    batch = (FIXTURES / "osv-querybatch.json").read_text()
    detail = (FIXTURES / "osv-vuln-detail.json").read_text()
    other = {"ecosystem": "npm", "name": "other-pkg", "version": "2.0.0",
             "source": "package-lock.json"}
    calls = {"batches": 0}

    def fake(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            calls["batches"] += 1
            if calls["batches"] == 1:
                return batch
            raise urllib.error.URLError("no route to host")
        return detail

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT, other])
    assert findings  # the first chunk's findings survive
    assert findings[0]["occurrences"][0]["file"] == "package-lock.json"
    assert "1 of 2" in note
    assert "NOT checked" in note


def test_a_batch_shape_failure_partway_keeps_the_findings_already_collected(monkeypatch):
    """Same setup as above, but the second chunk's response parses cleanly
    as JSON and is the wrong shape (`"[]"` instead of an object) rather than
    raising. The same properties must hold: the first chunk's finding
    survives, and the note names the unchecked remainder."""
    monkeypatch.setattr(osv, "_BATCH", 1)
    batch = (FIXTURES / "osv-querybatch.json").read_text()
    detail = (FIXTURES / "osv-vuln-detail.json").read_text()
    other = {"ecosystem": "npm", "name": "other-pkg", "version": "2.0.0",
             "source": "package-lock.json"}
    calls = {"batches": 0}

    def fake(url, body=None, timeout=30):
        if url.endswith("/querybatch"):
            calls["batches"] += 1
            return batch if calls["batches"] == 1 else "[]"
        return detail

    monkeypatch.setattr(osv, "_http", fake)
    findings, note = osv.query([COMPONENT, other])
    assert findings
    assert findings[0]["occurrences"][0]["file"] == "package-lock.json"
    assert "1 of 2" in note
    assert "NOT checked" in note


def test_a_component_missing_source_defaults_to_empty_not_a_crash(monkeypatch):
    """`source` is the one field allowed to be filled in by a `.get`
    default -- every real component from deps.inventory() has it, but the
    filter must not reject (or crash on) one that doesn't, since it is only
    ever used to label a finding, never to query OSV.dev."""
    _serve(monkeypatch)
    no_source = {"ecosystem": "npm", "name": "left-pad", "version": "1.0.0"}
    findings, note = osv.query([no_source])
    assert findings
    assert findings[0]["occurrences"][0]["file"] == ""
    assert "malformed" not in note
