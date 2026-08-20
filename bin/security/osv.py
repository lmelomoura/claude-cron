# bin/security/osv.py
"""Known vulnerabilities for the inventory, from the OSV.dev public API.

The one thing here that cannot be done offline: a vulnerability database does
not exist unless somebody publishes it. Only package names and versions leave
the machine; no code does.

Two endpoints, because one is not enough. /v1/querybatch answers with bare
identifiers -- no summary, no severity -- so each distinct id needs a
/v1/vulns/<id> lookup for anything readable. And the readable severity is in
`database_specific.severity`; the top-level `severity` is a list of CVSS
vectors, which read as a string matches nothing and silently classifies every
vulnerability as medium for ever.

Every failure mode returns a COVERAGE NOTE instead of raising. A gap that is
stated is useful; a gap that is silent makes you trust a report that never
looked at your dependencies.
"""

import json
import urllib.error
import urllib.request

from .fingerprint import fingerprint

_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/"
_BATCH = 500
_SEVERITY = {"CRITICAL": "critical", "HIGH": "high",
             "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
DEFAULT_SEVERITY = "medium"


def _http(url, body=None, timeout=30):
    if body is None:
        req = urllib.request.Request(url, method="GET")
    else:
        req = urllib.request.Request(
            url, data=body.encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _severity_of(detail) -> str:
    """`database_specific.severity` or nothing.

    Deliberately does NOT read the top-level `severity`: that is a list of
    CVSS vector objects, and treating it as a severity word is the mistake
    that makes every finding medium without ever failing.
    """
    raw = str((detail.get("database_specific") or {}).get("severity", "")).upper()
    return _SEVERITY.get(raw, DEFAULT_SEVERITY)


def _detail(vuln_id, cache, timeout):
    """The vulnerability's prose and severity. Cached: a published
    vulnerability does not change, and two projects sharing a dependency
    should not each pay for the same lookup."""
    if cache is not None and vuln_id in cache:
        return cache[vuln_id], ""
    try:
        detail = json.loads(_http(_VULN_URL + vuln_id, timeout=timeout))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError,
            AttributeError, TypeError, KeyError):
        # Broad on purpose: any confusion over the response must cost only
        # this vulnerability's prose, never crash the whole query.
        return None, vuln_id
    if not isinstance(detail, dict):
        # Valid JSON, wrong container (e.g. a bare list) -- treated exactly
        # like a failed lookup: the finding survives, only its prose is lost.
        return None, vuln_id
    if cache is not None:
        cache[vuln_id] = detail
    return detail, ""


def _finding(component, vuln_id, detail):
    if detail:
        summary = (detail.get("summary")
                   or (detail.get("details") or "")[:200] or vuln_id)
        severity = _severity_of(detail)
    else:
        summary = (f"{vuln_id} affects this version. Details could not be "
                   "fetched; see the link below.")
        severity = DEFAULT_SEVERITY
    return {
        "fingerprint": fingerprint("dependency", vuln_id, component["source"],
                                   f"{component['name']}@{component['version']}"),
        "category": "dependency",
        "rule": vuln_id,
        "severity": severity,
        "title": f"{component['name']} {component['version']}: {vuln_id}",
        "rationale": summary,
        "remediation": (f"Upgrade {component['name']} past {component['version']}. "
                        f"See https://osv.dev/vulnerability/{vuln_id}"),
        "occurrences": [{"file": component["source"], "line": 0, "snippet_hash": ""}],
    }


def query(components, detail_cache=None, timeout=30):
    if not components:
        return [], ""

    findings, undetailed = [], []
    for start in range(0, len(components), _BATCH):
        chunk = components[start:start + _BATCH]
        body = json.dumps({"queries": [
            {"package": {"name": c["name"], "ecosystem": c["ecosystem"]},
             "version": c["version"]} for c in chunk]})
        try:
            parsed = json.loads(_http(_BATCH_URL, body, timeout))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError,
                AttributeError, TypeError, KeyError) as exc:
            # Broad on purpose: any confusion over the response must become
            # this stated gap, never an uncaught crash.
            return [], ("Dependency CVEs were NOT checked: the OSV.dev lookup did "
                        f"not complete ({type(exc).__name__}). Everything else in "
                        "this report is complete.")
        if not isinstance(parsed, dict):
            # Valid JSON, wrong container ([] instead of {...}, a bare
            # string, a number) -- the same declared gap as a parse failure.
            return [], ("Dependency CVEs were NOT checked: the OSV.dev lookup did "
                        f"not complete ({type(parsed).__name__} instead of an "
                        "object). Everything else in this report is complete.")
        results = parsed.get("results", [])
        if not isinstance(results, list):
            results = []
        for component, result in zip(chunk, results):
            if not isinstance(result, dict):
                continue  # a non-dict entry is skipped, not fatal to the batch
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = vuln.get("id")
                if not vuln_id:
                    continue
                # A failed detail lookup loses the prose, not the finding:
                # knowing a CVE applies is most of the value.
                detail, failed = _detail(vuln_id, detail_cache, timeout)
                if failed:
                    undetailed.append(failed)
                findings.append(_finding(component, vuln_id, detail))

    note = ""
    if undetailed:
        note = (f"{len(undetailed)} vulnerabilit"
                f"{'y' if len(undetailed) == 1 else 'ies'} could not be described: "
                "OSV.dev answered the batch query but not the detail lookup, so "
                f"severity fell back to {DEFAULT_SEVERITY}.")
    return findings, note
