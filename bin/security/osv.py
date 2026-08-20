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

import http.client
import json
import urllib.error
import urllib.parse
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
        url = _VULN_URL + urllib.parse.quote(vuln_id, safe="")
        detail = json.loads(_http(url, timeout=timeout))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError,
            AttributeError, TypeError, KeyError, http.client.HTTPException):
        # Broad on purpose: any confusion over the response must cost only
        # this vulnerability's prose, never crash the whole query. Percent-
        # encoding the id closes the main route here -- an un-encoded CR/LF
        # reaches urlopen raw and raises http.client.InvalidURL, entirely
        # offline, before any socket opens -- and the widened except is the
        # backstop for whatever the encoding does not anticipate.
        return None, vuln_id
    if not isinstance(detail, dict):
        # Valid JSON, wrong container (e.g. a bare list) -- treated exactly
        # like a failed lookup: the finding survives, only its prose is lost.
        return None, vuln_id
    if cache is not None:
        cache[vuln_id] = detail
    return detail, ""


def _finding(component, vuln_id, detail):
    if detail is not None:
        # `is not None`, not truthiness: a successful lookup that happens to
        # return `{}` is falsy too, and must not be reported as though the
        # fetch had failed.
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


def _clean_components(components):
    """Keep only components query() can safely act on.

    Every real component comes from deps.inventory(), which always supplies
    all four keys as non-empty strings -- this is belt-and-braces, not a
    response to any known caller. But the batch body below reads c["name"]
    etc. BEFORE the try that guards the network call, and _finding reads
    component["source"] inside the per-result loop: a missing or
    wrong-typed key in either spot raises past every safeguard this module
    otherwise has. The contract is unconditional, so malformed entries are
    dropped, counted, and named in the coverage note instead of crashing.

    `source` alone may be filled in by a `.get` default rather than being
    required: it is never sent to OSV.dev (only name/ecosystem/version are),
    it only labels where a finding was found, and every surviving component
    is renormalised here so later code can keep using plain ["source"]
    access without risking a KeyError on the rare one that omits it.
    """
    clean = []
    for c in components:
        if not isinstance(c, dict):
            continue
        if not (isinstance(c.get("name"), str) and c["name"]):
            continue
        if not (isinstance(c.get("ecosystem"), str) and c["ecosystem"]):
            continue
        if not (isinstance(c.get("version"), str) and c["version"]):
            continue
        source = c.get("source", "")
        if not isinstance(source, str):
            continue
        clean.append({"name": c["name"], "ecosystem": c["ecosystem"],
                      "version": c["version"], "source": source})
    return clean, len(components) - len(clean)


def _notes(skip_note, gap, unchecked, total, undetailed):
    """Assemble the coverage note from its parts, in a fixed order.

    `gap` is the one part that varies by caller: empty on the normal
    completion path, or a stated reason for stopping early when a batch
    request to OSV.dev failed outright.
    """
    return " ".join(n for n in (
        skip_note,
        gap,
        (f"{unchecked} of {total} components did not answer usably and "
         "were not checked.") if unchecked else "",
        (f"{len(undetailed)} vulnerabilit"
         f"{'y' if len(undetailed) == 1 else 'ies'} could not be described: "
         "OSV.dev answered the batch query but not the detail lookup, so "
         f"severity fell back to {DEFAULT_SEVERITY}.") if undetailed else "",
    ) if n)


def _batch_stopped(findings, unchecked, undetailed, skip_note, checked, total,
                    reason):
    """A batch request to OSV.dev failed outright -- an exception, or a
    response that parsed but was the wrong shape -- partway through
    `query()`'s chunk loop.

    Every other early return in this function keeps whatever findings it
    already collected and states the gap; this was the one exception,
    discarding real findings from earlier successful chunks and claiming
    nothing at all had been checked. `checked` counts the components from
    chunks that got a usable response before this one failed; whatever is
    left (this chunk onward) was not checked.
    """
    if findings:
        gap = (f"OSV.dev stopped answering partway ({reason}): {checked} of "
               f"{total} components were checked and their findings are "
               f"included; the remaining {total - checked} were NOT checked.")
    else:
        gap = (f"Dependency CVEs were NOT checked: the OSV.dev lookup did "
               f"not complete ({reason}). Everything else in this report "
               "is complete.")
    return findings, _notes(skip_note, gap, unchecked, total, undetailed)


def query(components, detail_cache=None, timeout=30):
    if not components:
        return [], ""

    components, skipped = _clean_components(components)
    skip_note = ""
    if skipped:
        skip_note = (f"{skipped} malformed inventory entr"
                     f"{'y' if skipped == 1 else 'ies'} "
                     f"{'was' if skipped == 1 else 'were'} skipped.")
    if not components:
        return [], skip_note

    findings, undetailed = [], []
    unchecked, total = 0, len(components)
    for start in range(0, total, _BATCH):
        chunk = components[start:start + _BATCH]
        body = json.dumps({"queries": [
            {"package": {"name": c["name"], "ecosystem": c["ecosystem"]},
             "version": c["version"]} for c in chunk]})
        try:
            parsed = json.loads(_http(_BATCH_URL, body, timeout))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError,
                AttributeError, TypeError, KeyError) as exc:
            # Broad on purpose: any confusion over the response must become
            # this stated gap, never an uncaught crash. Earlier chunks in
            # this same call may already have produced real findings --
            # those are returned too, not discarded just because a later
            # chunk stopped answering.
            return _batch_stopped(findings, unchecked, undetailed, skip_note,
                                   start, total, type(exc).__name__)
        if not isinstance(parsed, dict):
            # Valid JSON, wrong container ([] instead of {...}, a bare
            # string, a number) -- the same declared gap as a parse failure,
            # and it keeps earlier chunks' findings the same way.
            return _batch_stopped(
                findings, unchecked, undetailed, skip_note, start, total,
                f"{type(parsed).__name__} instead of an object")
        results = parsed.get("results", [])
        if not isinstance(results, list):
            results = []
        # zip() correctly stops at the shorter sequence -- but a `results`
        # list shorter than `chunk` means OSV.dev never answered for the
        # tail components at all, and that gap must be counted, not just
        # silently dropped by pairing fewer entries.
        unchecked += max(0, len(chunk) - len(results))
        for component, result in zip(chunk, results):
            if not isinstance(result, dict):
                # Paired by zip -- OSV.dev did answer for this component --
                # just not usably. The same gap as truncation above, reached
                # a different way; it counts the same way too.
                unchecked += 1
                continue
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                unchecked += 1
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue  # a non-dict entry is skipped, not fatal to the batch
                vuln_id = vuln.get("id")
                if not isinstance(vuln_id, str) or not vuln_id:
                    # Only a str id can ever be looked up on OSV.dev or
                    # linked to an advisory page. Anything else (a bare
                    # number, a list, ...) would otherwise reach
                    # fingerprint() -- which joins it into a string and
                    # crashes on anything but a str -- or _detail()'s cache
                    # probe, which crashes on anything unhashable.
                    continue
                # A failed detail lookup loses the prose, not the finding:
                # knowing a CVE applies is most of the value.
                detail, failed = _detail(vuln_id, detail_cache, timeout)
                if failed:
                    undetailed.append(failed)
                findings.append(_finding(component, vuln_id, detail))

    return findings, _notes(skip_note, "", unchecked, total, undetailed)
