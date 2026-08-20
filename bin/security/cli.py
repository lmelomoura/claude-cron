#!/usr/bin/env python3
# bin/security/cli.py
"""The only door between the engine and the ledger.

The agent reaches the database exclusively through `report-finding`, which
validates before it writes. The agent is non-deterministic; the integrity of
the history that produces the checklist cannot depend on it having written the
right JSON.

Every failure here exits non-zero with a sentence on stderr. Nothing in this
file writes to the database on a path that has not first said what it is
writing about -- an analysis that does not exist, a severity outside the
contract and a body that is not JSON at all are all refused before a
connection is used for anything.

The door also checks WHO is knocking, not only what they brought. The agent
and the operator reach this file through the identical command, so the three
verbs an agent must never reach -- `decide`, `rename-project`,
`open-analysis` -- are refused whenever CC_SECURITY_AGENT is set (see
`_refuse_if_agent`).
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security import deps, diff, hygiene, ledger, osv, report, secrets  # noqa: E402

REQUIRED_FINDING_KEYS = ("fingerprint", "category", "rule", "severity", "title")

# The identity two analyses match a finding on -- lowercase sha256 hex, as
# `security/fingerprint.py` mints it. Shape-checked at the door because the
# agent types this string itself: a fingerprint of its own invention ("aws-key
# in prod.env") is a NEW identity on every run, so the same hole is reported
# `new` for ever, never `open`, never `fixed`, and no decision ever sticks to
# it. The recipe is not enforceable here -- only the shape is.
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

# A finding is a paragraph, not a document. Without a cap the agent can paste
# a whole file into `rationale`, and every later analysis pays to read it back
# out of the ledger and renders it into the report page.
MAX_TEXT = 10000
TEXT_KEYS = ("title", "rationale", "remediation", "partial_note")

# What the agent under review may NOT do, even though it reaches this file
# through the same command the operator does. See `_refuse_if_agent`.
AGENT_FORBIDDEN = ("decide", "rename-project", "open-analysis")


def _refuse_if_agent(cmd):
    """The door validates the SHAPE of what is written; this validates WHO.

    `cmd_security_analyze` exports CC_SECURITY_AGENT=1 into the analysis run,
    so every `claude-cron security ...` the agent types -- from its own tool
    shell, inside the worktree -- arrives here with that flag set. Three verbs
    have to be refused there:

      decide          a permanent, project-wide suppression. An agent that can
                      call it can retire the finding it just reported (and the
                      ledger records a `decided_by` it typed itself).
      rename-project  moves the whole history onto another name, out from
                      under the project being analysed.
      open-analysis   mints rows the engine never opened and will never close.

    `finish` is deliberately NOT in the list: `security_close_analysis` runs
    inside run_job, AFTER the agent and still under the same exported flag,
    and closing the row is the one thing that must always work.
    """
    if os.environ.get("CC_SECURITY_AGENT", "").strip():
        sys.exit(
            f"security {cmd}: refused inside a security analysis "
            "(CC_SECURITY_AGENT is set) — the agent that reports a finding "
            "does not get to dismiss it, rename the ledger out from under it "
            "or open analyses of its own; ask a human to run this.")


def _conn(args):
    return ledger.connect(args.db)


def _analysis(conn, analysis_id):
    """The row, or a refusal. Every command that names an analysis goes
    through this: `UPDATE ... WHERE id=?` on an id that does not exist
    changes nothing and reports success, which is how a typo in the agent's
    command line becomes a report with no findings and no explanation."""
    row = conn.execute("SELECT * FROM analysis WHERE id=?", (analysis_id,)).fetchone()
    if row is None:
        sys.exit(f"no such analysis: {analysis_id}")
    return row


def _running(conn, analysis_id):
    """The row, refused unless the analysis is still open.

    A closed analysis is the BASELINE the next one is diffed against. Writing
    into it after the fact -- a finding reported into last week's row, a
    second `prepare` re-running the deterministic phases over it -- rewrites
    what the previous run is remembered as having found, and the checklist
    then reports `fixed` and `regressed` about a past that changed under it.
    An agent that has already closed its analysis and keeps typing (or a
    hand-typed id that lands on the wrong row) must be told, not obeyed.
    """
    row = _analysis(conn, analysis_id)
    if row["state"] != "running":
        sys.exit(f"analysis {analysis_id} is closed ({row['state']}): it is the "
                 "baseline the next analysis is compared against, and writing "
                 "into it now would change what that comparison means.")
    return row


def _spend(value):
    """The spend arrives from the run's own cost field, which is text the CLI
    produced and nothing has validated. A row left `running` for ever is a
    far worse outcome than a cost recorded as zero, so an unreadable number
    must never abort the close."""
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def cmd_open_analysis(args):
    """Create the analysis row BEFORE the run starts.

    If `prepare` created it, an agent that died on launch would leave no
    analysis at all, and the page would have nothing -- not even a failed
    run -- to show for a button the user pressed.
    """
    conn = _conn(args)
    aid = ledger.start_analysis(conn, args.project, args.repo, args.branch,
                                args.commit, args.profile, args.run_id)
    print(json.dumps({"analysis_id": aid}))


def cmd_prepare(args):
    """The deterministic phases, run inside the worktree by the agent's first
    command. Seconds, and no tokens."""
    conn = _conn(args)
    # Resolved before it is judged: `--root ~/..` and `--root /srv/../..` both
    # reach the filesystem root while looking like a checkout.
    root = Path(args.root).expanduser().resolve()
    # The agent types this path itself, from inside a worktree it did not
    # choose. Pointed at `/` or at $HOME the deterministic phases walk every
    # file the operator owns -- ssh keys, browser profiles, other people's
    # repositories -- and file what they find as findings OF THIS PROJECT,
    # in a ledger the report page publishes. No analysis has a reason to
    # start above a checkout.
    if root == Path(root.anchor) or root == Path.home().expanduser().resolve():
        sys.exit(f"prepare: --root must be a repository checkout, not {root}: "
                 "scanning the filesystem root or your home directory would "
                 "read every file you own and record it as this project's.")
    ignore = [p for p in (args.ignore or "").split(",") if p]

    aid = args.analysis
    row = _running(conn, aid)
    project, repo, branch = row["project"], row["repo"], row["branch"]

    findings = secrets.scan_tree(root, ignore) + hygiene.scan(root)
    # The history sweep is a baseline-only cost: on later analyses the earlier
    # commits have already been read, and re-reading them would find the same
    # already-recorded secrets at a growing price in wall-clock.
    #
    # Appended LAST on purpose. A secret that is both in the working tree and
    # in the history shares one fingerprint (rule + path, see
    # secret_fingerprint), so record_finding upserts the two into one row and
    # the last writer's wording is the one that survives. The history reading
    # is the one worth keeping: it is what says the credential is compromised
    # even after the file is cleaned, which is the difference between "delete
    # the line" and "rotate the key".
    if ledger.latest_analysis(conn, project, repo, branch, before=aid) is None:
        findings += secrets.scan_history(root, None)

    components = deps.inventory(root)
    if args.offline:
        # Names OSV.dev, not just "CVEs". The coverage note is the one line a
        # reader has to judge the report's blind spots by, and "dependency
        # CVEs were not checked" leaves them guessing whether some other
        # source covered them; naming the source that did not answer says
        # exactly which question this report cannot be asked.
        note = ("Dependency CVEs were NOT checked against OSV.dev: this "
                "analysis ran with networking disabled.")
    else:
        # One cache for the whole call: several components of one project
        # routinely share an advisory, and osv.query never raises -- whatever
        # it could not reach comes back as prose in `note`, not as an
        # exception that would lose the secrets and hygiene findings above.
        cve_findings, note = osv.query(components, detail_cache={})
        findings += cve_findings

    if components:
        ledger.store_sbom(conn, project, repo, branch, aid, deps.sbom(components))
    for f in findings:
        ledger.record_finding(conn, aid, f)

    conn.execute("UPDATE analysis SET coverage_note=? WHERE id=?", (note, aid))
    conn.commit()
    print(json.dumps({"coverage_note": note, "findings": len(findings)}))


def cmd_findings(args):
    conn = _conn(args)
    _analysis(conn, args.analysis)
    print(json.dumps(ledger.findings_of(conn, args.analysis), indent=2))


def cmd_report_finding(args):
    try:
        payload = json.load(sys.stdin)
    except ValueError as exc:
        sys.exit(f"report-finding: stdin is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        sys.exit("report-finding: expected one finding as a JSON object")
    # Strings, not merely present. A fingerprint that arrives as a NUMBER is
    # stored by SQLite's type affinity as one and compared as one, so it would
    # never match the same finding recorded as text by an earlier analysis --
    # the checklist would report it `fixed` and `new` on every run for ever.
    missing = [k for k in REQUIRED_FINDING_KEYS
               if not isinstance(payload.get(k), str) or not payload[k].strip()]
    if missing:
        sys.exit("report-finding: missing or non-string required key(s): "
                 + ", ".join(missing))
    if not FINGERPRINT_RE.match(payload["fingerprint"]):
        sys.exit("report-finding: fingerprint must be 64 lowercase hex "
                 "characters (sha256) — it is the identity the next analysis "
                 "matches this finding on, and one the agent invents per run "
                 "is reported `new` for ever and can never be decided on")
    if payload["severity"] not in report.SEVERITIES:
        sys.exit(f"report-finding: severity must be one of {report.SEVERITIES}")
    for key in TEXT_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and len(value) > MAX_TEXT:
            sys.exit(f"report-finding: {key} is {len(value)} characters and the "
                     f"limit is {MAX_TEXT} — a finding is a paragraph the report "
                     "page renders, not a file to paste into the ledger")
    occurrences = payload.get("occurrences", [])
    if not isinstance(occurrences, list) or any(
            not isinstance(o, dict) for o in occurrences):
        sys.exit("report-finding: occurrences must be a list of objects")
    conn = _conn(args)
    _running(conn, args.analysis)
    try:
        ledger.record_finding(conn, args.analysis, payload)
    # OverflowError is here for the same reason ValueError is: it comes out of
    # `int(occ["line"])` on a number too large to be one (`1e999` parses as
    # JSON infinity), and it is not a ValueError -- the agent got a traceback
    # and no sentence saying what was wrong with its finding.
    except (ValueError, TypeError, OverflowError, sqlite3.Error) as exc:
        # record_finding wraps the finding and its occurrences in one
        # transaction, so a rejected line number rolls the whole thing back --
        # the agent has to be told, or it moves on believing it reported.
        sys.exit(f"report-finding: could not record it: {exc}")


def cmd_finish(args):
    """Close the analysis. The verdict can be lowered, never raised.

    Two callers, and they disagree on purpose: the AGENT says `--state done`
    when it believes it finished, and the ENGINE
    (`security_close_analysis`) closes the same row again with the run's own
    verdict and real cost. Precedence, in this order:

      1. `--if-running` (the engine's sweep for a run that never started) is
         a no-op on any row that is already closed -- every other run closed
         its own row with a real verdict, and re-closing it would replace
         that with a guess.
      2. A stored `capped` or `failed` is NEVER overwritten with `done`. The
         agent's own `finish --state capped` is an honest statement that it
         ran out of room, and the engine's `success` -- which only means the
         PROCESS exited cleanly -- used to overwrite it: the truncated
         analysis then became the baseline, and everything the agent had not
         reached read as `fixed` that run and `regressed` the next.
      3. Otherwise the caller's state wins, INCLUDING a downgrade of a stored
         `done` to `capped`/`failed`. That direction is the whole point of
         closing twice: the agent's claim that it finished is the one fact
         here that nothing can verify, and the run it made that claim from
         may have been cut off mid-sentence.

    Whatever the state ends up being, the SPEND and the note are still
    written: the run's real cost is a fact even when its verdict is refused.
    """
    conn = _conn(args)
    row = _analysis(conn, args.analysis)
    if args.if_running and row["state"] != "running":
        return
    state = args.state
    if state == "done" and row["state"] in ("capped", "failed"):
        print(f"finish: analysis {args.analysis} is already {row['state']} — a "
              "close never upgrades a truncated or failed analysis to done",
              file=sys.stderr)
        state = row["state"]
    # finish_analysis writes coverage_note unconditionally, and neither caller
    # of `finish` carries the note `prepare` printed: the agent never saw it,
    # and the engine's close-out knows only the run's status and cost. An
    # empty --note therefore keeps what is stored, or the one line of the
    # report that says what was NOT looked at is erased at the last step.
    #
    # A note that IS given is APPENDED, never substituted: "the agent never
    # reached the SAST phase" and "dependency CVEs were not checked against
    # OSV.dev" are two different blind spots, and the reader needs both. The
    # equality guard keeps a row closed twice with the same sentence from
    # accumulating it twice.
    stored = row["coverage_note"] or ""
    note = args.note or ""
    if not note:
        note = stored
    elif stored and note != stored:
        note = f"{stored} {note}"
    ledger.finish_analysis(conn, args.analysis, state, _spend(args.spend), note)


def _checklist(conn, analysis_id):
    row = _analysis(conn, analysis_id)
    analysis = dict(row)
    current = ledger.findings_of(conn, analysis_id)
    prev = ledger.latest_analysis(conn, analysis["project"], analysis["repo"],
                                  analysis["branch"], before=analysis_id)
    previous = ledger.findings_of(conn, prev["id"]) if prev else []

    # The objective half of the `partial` signal (see diff._is_partial): how
    # many of a finding's places are gone since last time. Nothing persists
    # it -- it is a property of a PAIR of analyses, not of a finding -- and
    # this is the only place the two ever meet, so it is computed here or
    # `partial` can only ever come from the agent's own note.
    #
    # A set difference over the FILES, not a subtraction of two counts. Counts
    # answer the wrong question in both directions: three hits in one file
    # dropping to two is the same file still holding the same hole (someone
    # deleted a duplicate line), while one hit in `auth.py` moving to one hit
    # in `admin.py` is a place genuinely closed and a new one opened -- and
    # `before - now` calls the first of those partial progress and the second
    # nothing at all.
    prev_occurrences = {f["fingerprint"]: {o["file"] for o in f["occurrences"]}
                        for f in previous}
    for f in current:
        before = prev_occurrences.get(f["fingerprint"])
        if before is not None:
            f["closed_occurrences"] = len(before - {o["file"] for o in f["occurrences"]})

    # done/capped only, exactly as `latest_analysis` requires of a baseline. A
    # FAILED analysis is a run that fell over holding a partial set of
    # findings; letting its fingerprints into `history` means the first
    # successful analysis after a failed one reports everything the failed
    # attempt happened to reach as `regressed` -- "this was fixed and came
    # back" -- about findings that were never fixed and never left.
    history = {r["fingerprint"] for r in conn.execute(
        "SELECT DISTINCT f.fingerprint FROM finding f JOIN analysis a ON a.id=f.analysis_id"
        " WHERE a.project=? AND a.repo=? AND a.branch=? AND a.id < ?"
        " AND a.state IN ('done','capped')",
        (analysis["project"], analysis["repo"], analysis["branch"],
         prev["id"] if prev else analysis_id))}
    decisions = ledger.decisions_for(conn, analysis["project"])
    return analysis, diff.classify(current, previous, history, decisions)


def cmd_checklist(args):
    conn = _conn(args)
    analysis, findings = _checklist(conn, args.analysis)
    print(json.dumps({"analysis": analysis, "findings": findings}, indent=2))


def cmd_render(args):
    conn = _conn(args)
    analysis, findings = _checklist(conn, args.analysis)
    note = analysis.get("coverage_note", "")
    renderer = {"json": report.as_json, "md": report.as_markdown,
                "html": report.as_html}[args.format]
    print(renderer(analysis, findings, note))


def cmd_decide(args):
    try:
        ledger.set_decision(_conn(args), args.project, args.fingerprint,
                            args.state, args.reason, args.by)
    except ValueError as exc:
        sys.exit(f"decide: {exc}")


def cmd_rename_project(args):
    """Carry a project's security history onto its new name.

    An analysis, a decision and an SBOM are all keyed by the project NAME
    they were recorded under -- there is no id -- so `claude-cron
    project-rename` has to move them or the whole history stays behind under
    a name no project has any more.

    UPDATE OR REPLACE on the two tables with a (project, ...) primary key:
    rows outlive the project that made them (`project-delete` leaves them
    behind), so renaming a live project onto a dead one's name can collide.
    The live project's own judgement is the one that should survive.
    """
    conn = _conn(args)
    with conn:
        analyses = conn.execute("UPDATE analysis SET project=? WHERE project=?",
                                (args.to, getattr(args, "from"))).rowcount
        decisions = conn.execute(
            "UPDATE OR REPLACE decision SET project=? WHERE project=?",
            (args.to, getattr(args, "from"))).rowcount
        sboms = conn.execute("UPDATE OR REPLACE sbom SET project=? WHERE project=?",
                             (args.to, getattr(args, "from"))).rowcount
    print(json.dumps({"analyses": analyses, "decisions": decisions, "sboms": sboms}))


def cmd_list(args):
    rows = _conn(args).execute(
        "SELECT * FROM analysis WHERE project=? ORDER BY id DESC LIMIT 100",
        (args.project,)).fetchall()
    print(json.dumps([dict(r) for r in rows], indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(prog="claude-cron security")
    p.add_argument("--db")
    # bash puts --db BEFORE the subcommand (`security_py finish --analysis N`);
    # the agent and the tests put it after. argparse hands everything past the
    # subcommand name to the subparser, so the flag has to exist on both --
    # and with SUPPRESS as the subparser's default, so that an absent one there
    # does not overwrite the value the top-level parser already read.
    dbflag = argparse.ArgumentParser(add_help=False)
    dbflag.add_argument("--db", default=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)

    op = sub.add_parser("open-analysis", parents=[dbflag]); op.set_defaults(fn=cmd_open_analysis)
    for flag in ("project", "repo", "branch", "commit", "profile", "run-id"):
        op.add_argument(f"--{flag}", required=True, dest=flag.replace("-", "_"))

    pr = sub.add_parser("prepare", parents=[dbflag]); pr.set_defaults(fn=cmd_prepare)
    pr.add_argument("--analysis", type=int, required=True)
    pr.add_argument("--root", required=True)
    pr.add_argument("--ignore", default="")
    pr.add_argument("--offline", action="store_true")

    fi = sub.add_parser("findings", parents=[dbflag]); fi.set_defaults(fn=cmd_findings)
    fi.add_argument("--analysis", type=int, required=True)

    rf = sub.add_parser("report-finding", parents=[dbflag]); rf.set_defaults(fn=cmd_report_finding)
    rf.add_argument("--analysis", type=int, required=True)

    fn = sub.add_parser("finish", parents=[dbflag]); fn.set_defaults(fn=cmd_finish)
    fn.add_argument("--analysis", type=int, required=True)
    fn.add_argument("--state", required=True, choices=ledger.ANALYSIS_END_STATES)
    fn.add_argument("--spend", default="0")
    fn.add_argument("--note", default="")
    fn.add_argument("--if-running", action="store_true", dest="if_running")

    ck = sub.add_parser("checklist", parents=[dbflag]); ck.set_defaults(fn=cmd_checklist)
    ck.add_argument("--analysis", type=int, required=True)

    rd = sub.add_parser("render", parents=[dbflag]); rd.set_defaults(fn=cmd_render)
    rd.add_argument("--analysis", type=int, required=True)
    rd.add_argument("--format", required=True, choices=("json", "md", "html"))

    de = sub.add_parser("decide", parents=[dbflag]); de.set_defaults(fn=cmd_decide)
    for flag in ("project", "fingerprint", "reason"):
        de.add_argument(f"--{flag}", required=True)
    de.add_argument("--state", required=True, choices=ledger.DECISION_STATES)
    de.add_argument("--by", default="")

    mv = sub.add_parser("rename-project", parents=[dbflag]); mv.set_defaults(fn=cmd_rename_project)
    mv.add_argument("--from", required=True)
    mv.add_argument("--to", required=True)

    ls = sub.add_parser("list", parents=[dbflag]); ls.set_defaults(fn=cmd_list)
    ls.add_argument("--project", required=True)

    args = p.parse_args(argv)
    if not getattr(args, "db", None):
        p.error("--db is required")
    # Before the database is opened, and in ONE place rather than in each of
    # the three commands: a verb added later is refused by being added to
    # AGENT_FORBIDDEN, not by remembering to copy a guard into its function.
    if args.cmd in AGENT_FORBIDDEN:
        _refuse_if_agent(args.cmd)
    args.fn(args)


if __name__ == "__main__":
    main()
