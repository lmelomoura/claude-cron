# bin/security/report.py
"""Markdown, JSON and HTML, generated on download from the ledger.

Reports are never written to disk. A risk accepted after the analysis ran
should appear as accepted in the file you download -- a stored artefact would
instead hand you a frozen document that disagrees with the page you have open.
"""

import html
import json
import time

from . import coverage

STATES = ("new", "regressed", "open", "partial", "pending", "fixed", "accepted", "false_positive")
# Ordered most severe first. `info` is last on purpose: it is below the default
# min_severity floor, so an informational finding is recorded and stays out of
# the way until somebody lowers the floor to look for it.
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _summary(findings):
    by_state = {s: 0 for s in STATES}
    by_severity = {s: 0 for s in SEVERITIES}
    accepted_in_severity = 0
    for f in findings:
        by_state[f["state"]] = by_state.get(f["state"], 0) + 1
        if f["state"] not in ("fixed", "false_positive"):
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            if f["state"] == "accepted":
                accepted_in_severity += 1
    return {"by_state": by_state, "by_severity": by_severity, "total": len(findings),
            "accepted_in_severity": accepted_in_severity}


def _unknown_states(by_state):
    """States present in the data but outside the STATES contract.

    `_summary` counts these into `by_state` unconditionally (dict.get with a
    default), so they are never lost from the JSON report. The MD and HTML
    checklists iterate the fixed STATES tuple instead of by_state's keys, so
    without this they would silently drop any such count from the two formats
    a human actually reads.
    """
    return [s for s in by_state if s not in STATES]


# `scope` reads as a bare word in the ledger and as a sentence fragment in a
# report, and the gap between the two is where a reader guesses wrong. "dev"
# alone invites "so I can ignore it"; "unknown" alone invites "so it is
# probably fine". Both are expanded here, in the one place all three formats
# read, so the two a human downloads cannot describe the column differently.
#
# A value not in this table renders as itself rather than being dropped: a
# vocabulary this module has not been taught is still a fact the ledger holds,
# and hiding it would be the silent-difference failure one level down.
_SCOPE_LABELS = {
    "dev": "dev — a development-only dependency, not shipped",
    "runtime": "runtime — this dependency ships",
    "unknown": "unknown — this lockfile format does not say whether it ships",
}


def _scope_label(scope: str) -> str:
    return _SCOPE_LABELS.get(scope, scope)


def _coverage(analysis, coverage_note):
    """What this report did NOT look at. Printed before anything else.

    `capped` no longer means only "it reached its spending cap" -- since the
    `prepared` guard in `cmd_finish` (bin/security/cli.py), it also covers a
    `done` close downgraded because the deterministic phases never ran at
    all. Naming a spending cap here would be a flat lie for that second case,
    and this line cannot tell the two apart -- the wording therefore says
    only what is true of BOTH: the analysis is incomplete and stopped short
    of the whole scope. The specific cause belongs to `coverage_note`, printed
    right after, which is where `cmd_finish` puts it ("The deterministic
    phases never ran for this analysis: ..."). Kept word-for-word identical to
    the sentence `bin/dashboard.html` prints for the same state, so the
    downloaded file and the screen never disagree.
    """
    parts = []
    if analysis["state"] == "capped":
        parts.append("This analysis is INCOMPLETE: it stopped before "
                     "covering the whole scope.")
    elif analysis["state"] == "failed":
        parts.append("This analysis is INCOMPLETE: it did not finish.")
    if coverage_note:
        parts.append(coverage_note)
    return parts


# The `by` column of a phase that had no producer -- `scope`, or any phase
# where nothing looked. An em dash and not an empty cell: a blank there reads
# as a value the renderer failed to print, where "—" reads as the fact that
# there was nobody to name.
_NO_PRODUCER = "—"


def _phase_rows(analysis):
    """(name, status, by) per phase, ready to print, or [] for an analysis
    that has no structured coverage.

    `[]` IS THE WHOLE COMPATIBILITY STORY. Every analysis written before the
    `coverage` column existed has '' in it, and every renderer below draws
    nothing whatsoever for an empty list -- so an old report is byte-identical
    to what it was, and a new one gains a table above prose that was going to
    be printed anyway. See security/coverage.py's own `decode`, which answers
    `[]` for a malformed document too rather than raising inside a download.
    """
    return [(str(p.get("name", "")), str(p.get("status", "")),
             str(p.get("by") or _NO_PRODUCER))
            for p in coverage.phases_of(analysis)]


def as_json(analysis, findings, coverage_note):
    """The machine-readable format, and the one place `scope` is ALWAYS a key.

    The two formats a human reads render nothing when the value is absent, so
    they cannot be parsed for it. This one is: something consuming the JSON has
    to be able to tell "this analysis predates the column" from "this finding
    is not a dependency" without special-casing a missing key, so the key is
    always present and the empty string carries that distinction. Rows read
    from the ledger have it already (the column is NOT NULL with a '' default);
    the `setdefault` is for a caller assembling findings some other way.
    """
    rows = []
    for f in findings:
        row = dict(f)
        row.setdefault("scope", "")
        rows.append(row)
    return json.dumps({
        "analysis": dict(analysis),
        # AN OBJECT, and `phases` is ALWAYS a key in it -- the same rule
        # `scope` follows on a finding above, for the same reason. The two
        # formats a human reads print nothing when there is nothing to print,
        # so they cannot be parsed for an absence; this one has to let a
        # consumer tell "this analysis predates the column" (an empty list)
        # from "this consumer is reading an older report format" (no key at
        # all) without special-casing either. `notes` is what this key used to
        # BE -- the prose, unchanged, in the same order.
        "coverage": {"notes": _coverage(analysis, coverage_note),
                     "phases": coverage.phases_of(analysis)},
        "summary": _summary(findings),
        "findings": rows,
    }, indent=2, sort_keys=True)


def as_markdown(analysis, findings, coverage_note):
    s = _summary(findings)
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(analysis["started"]))
    out = [f"# Security analysis — {analysis['project']} / {analysis['repo']}",
           "",
           f"- **Branch:** `{analysis['branch']}` at `{analysis['commit_sha'][:12]}`",
           f"- **Profile:** {analysis['profile']}",
           f"- **Run at:** {when}",
           ""]
    # THE TABLE COMES FIRST, AND THAT ORDER IS THE POINT OF IT. The prose
    # below is every gap this analysis has, sentence by sentence, and on a
    # real run it is about two thousand characters of it -- true throughout
    # and unreadable as a block. Nine lines of "who looked, who did not, and
    # with what" answer the question a reader actually opens the file with;
    # the paragraph is then there for the one who asks why.
    rows = _phase_rows(analysis)
    if rows:
        out += ["## Coverage", "",
                "| Phase | Status | By |", "| --- | --- | --- |"]
        # `|` escaped, not stripped: these three values come from a closed
        # vocabulary this module writes, but they are read back out of a
        # database column, and a stray pipe would silently eat the rest of a
        # row rather than showing up as the odd value it is.
        out += ["| " + " | ".join(c.replace("|", "\\|") for c in row) + " |"
                for row in rows]
        out.append("")
    for note in _coverage(analysis, coverage_note):
        out += [f"> **{note}**", ""]
    out += ["## Checklist", ""]
    out += [f"- {state}: {s['by_state'][state]}" for state in STATES]
    out += [f"- {state}: {s['by_state'][state]}" for state in _unknown_states(s["by_state"])]
    out += ["", "## Open findings by severity", ""]
    out += [f"- {sev}: {s['by_severity'][sev]}" for sev in SEVERITIES]
    if s["accepted_in_severity"]:
        n = s["accepted_in_severity"]
        out += ["", f"_(includes {n} accepted risk{'s' if n != 1 else ''})_"]
    out += ["", "## Findings", ""]
    for f in findings:
        out += [f"### [{f['severity']}] {f['title']} — `{f['state']}`", "",
                f"**Rule:** `{f['rule']}` ({f['category']})"]
        if f.get("cwe"):
            out.append(f"  - Class: {f['cwe']}"
                       + (f" · OWASP {f['owasp']}" if f.get("owasp") else ""))
        if f.get("scope"):
            out.append(f"  - Scope: {_scope_label(f['scope'])}")
        out.append("")
        for occ in f["occurrences"]:
            out.append(f"- `{occ['file']}`" + (f":{occ['line']}" if occ["line"] else ""))
        out += ["", f["rationale"], "", f"**Remediation:** {f['remediation']}", ""]
    return "\n".join(out)


_CSS = """body{font:15px/1.55 -apple-system,system-ui,sans-serif;max-width:60rem;
margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1,h2,h3{line-height:1.25}.note{background:#fff4e5;border-left:4px solid #d97706;
padding:.75rem 1rem;margin:1rem 0}.f{border:1px solid #e5e5e5;border-radius:6px;
padding:1rem;margin:1rem 0}.critical{border-left:4px solid #dc2626}
.high{border-left:4px solid #ea580c}.medium{border-left:4px solid #ca8a04}
.low{border-left:4px solid #6b7280}.info{border-left:4px solid #9ca3af}
.cls{color:#4b5563;font-size:.9em}
code{background:#f4f4f5;padding:.1em .35em;
border-radius:3px}@media print{.f{break-inside:avoid}}
.cov{border-collapse:collapse;margin:1rem 0}
.cov th,.cov td{border:1px solid #e5e5e5;padding:.3rem .6rem;text-align:left}
.cov th{background:#f4f4f5;font-weight:600}
.cov .cov-ok{color:#15803d}.cov .cov-warn{color:#b45309}.cov .cov-gap{color:#b91c1c}"""

# The CSS class a status cell carries, DELIBERATELY NOT SPELLED LIKE THE
# STATUS. The class used to be the status word itself, and the test that
# checked a `skipped` row was rendered passed on a page with no such row --
# the word was in the stylesheet's `.cov .skipped`. None of these three
# contains the status it colours, so a test that finds the word in the output
# has found it in a cell. A status this table does not know gets no class at
# all: a word with no colour is what an unknown status should look like, and
# a class attribute built from an unknown value would be a second sink beside
# the text.
_STATUS_CLASS = {coverage.RAN: "cov-ok", coverage.WARNING: "cov-warn",
                 coverage.SKIPPED: "cov-gap"}


def as_html(analysis, findings, coverage_note):
    e = html.escape
    s = _summary(findings)
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(analysis["started"]))
    parts = [f"<!doctype html><meta charset=utf-8><title>Security analysis — "
             f"{e(analysis['project'])}</title><style>{_CSS}</style>",
             f"<h1>Security analysis — {e(analysis['project'])} / {e(analysis['repo'])}</h1>",
             f"<p>Branch <code>{e(analysis['branch'])}</code> at "
             f"<code>{e(analysis['commit_sha'][:12])}</code> · profile "
             f"{e(analysis['profile'])} · {e(when)}</p>"]
    # Before the prose, for the reason `as_markdown` gives at length -- and
    # pinned there by test_html_opens_with_the_phase_table_before_the_prose,
    # which reads the two tags' positions rather than trusting this comment.
    # The status picks the cell's class through `_STATUS_CLASS`, so a reader
    # scanning the table sees three colours rather than three words, and the
    # class is one of three literals this module owns rather than a value
    # read out of a database column.
    rows = _phase_rows(analysis)
    if rows:
        parts.append('<h2>Coverage</h2><table class="cov">'
                     "<tr><th>Phase</th><th>Status</th><th>By</th></tr>")
        for name, status, by in rows:
            cls = _STATUS_CLASS.get(status)
            cell = (f'<td class="{cls}">{e(status)}</td>' if cls
                    else f"<td>{e(status)}</td>")
            parts.append(f"<tr><td>{e(name)}</td>{cell}<td>{e(by)}</td></tr>")
        parts.append("</table>")
    for note in _coverage(analysis, coverage_note):
        parts.append(f'<p class="note">{e(note)}</p>')
    parts.append("<h2>Checklist</h2><ul>")
    parts += [f"<li>{st}: {s['by_state'][st]}</li>" for st in STATES]
    parts += [f"<li>{e(st)}: {s['by_state'][st]}</li>" for st in _unknown_states(s["by_state"])]
    parts.append("</ul><h2>Open findings by severity</h2><ul>")
    parts += [f"<li>{sev}: {s['by_severity'][sev]}</li>" for sev in SEVERITIES]
    parts.append("</ul>")
    if s["accepted_in_severity"]:
        n = s["accepted_in_severity"]
        parts.append(f'<p class="note">Includes {n} accepted risk{"s" if n != 1 else ""}.</p>')
    parts.append("<h2>Findings</h2>")
    for f in findings:
        locs = "".join(
            f"<li><code>{e(o['file'])}{':' + e(str(o['line'])) if o['line'] else ''}</code></li>"
            for o in f["occurrences"])
        cls = (f'<p class="cls">{e(f["cwe"])}'
               + (f" · OWASP {e(f['owasp'])}" if f.get("owasp") else "")
               + "</p>") if f.get("cwe") else ""
        # Absent renders NOTHING, exactly as `cwe` does above: every
        # non-dependency finding carries '' here, and a "Scope: —" line on all
        # of them would be a column of dashes a reader learns to skip.
        scope = (f'<p class="cls">Scope: {e(_scope_label(f["scope"]))}</p>'
                 if f.get("scope") else "")
        parts.append(
            f'<div class="f {e(f["severity"])}">'
            f"<h3>[{e(f['severity'])}] {e(f['title'])} — {e(f['state'])}</h3>"
            f"<p>Rule <code>{e(f['rule'])}</code> ({e(f['category'])})</p>"
            f"{cls}{scope}"
            f"<ul>{locs}</ul><p>{e(f['rationale'])}</p>"
            f"<p><strong>Remediation:</strong> {e(f['remediation'])}</p></div>")
    return "".join(parts)
