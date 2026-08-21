# bin/security/report.py
"""Markdown, JSON and HTML, generated on download from the ledger.

Reports are never written to disk. A risk accepted after the analysis ran
should appear as accepted in the file you download -- a stored artefact would
instead hand you a frozen document that disagrees with the page you have open.
"""

import html
import json
import time

STATES = ("new", "regressed", "open", "partial", "pending", "fixed", "accepted", "false_positive")
SEVERITIES = ("critical", "high", "medium", "low")


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


def as_json(analysis, findings, coverage_note):
    return json.dumps({
        "analysis": dict(analysis),
        "coverage": _coverage(analysis, coverage_note),
        "summary": _summary(findings),
        "findings": [dict(f) for f in findings],
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
                f"**Rule:** `{f['rule']}` ({f['category']})", ""]
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
.low{border-left:4px solid #6b7280}code{background:#f4f4f5;padding:.1em .35em;
border-radius:3px}@media print{.f{break-inside:avoid}}"""


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
        parts.append(
            f'<div class="f {e(f["severity"])}">'
            f"<h3>[{e(f['severity'])}] {e(f['title'])} — {e(f['state'])}</h3>"
            f"<p>Rule <code>{e(f['rule'])}</code> ({e(f['category'])})</p>"
            f"<ul>{locs}</ul><p>{e(f['rationale'])}</p>"
            f"<p><strong>Remediation:</strong> {e(f['remediation'])}</p></div>")
    return "".join(parts)
