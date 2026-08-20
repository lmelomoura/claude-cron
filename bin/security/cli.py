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

BE CLEAR ABOUT WHAT THAT IS WORTH. CC_SECURITY_AGENT is a variable in the
agent's own environment, and the agent has a shell: `env -u CC_SECURITY_AGENT
claude-cron security decide ...` walks straight past it. It is a GUARDRAIL
AGAINST MISTAKE, not a boundary against malice -- it stops a model that
genuinely believes dismissing its own finding is the helpful thing to do, which
is the failure that actually happens. It stops nothing that is trying. The one
check here that does not depend on the environment is in `cmd_decide`, which
refuses while ANY analysis of the project is still `running` -- not only the
newest one -- whoever is asking.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security import deps, diff, fingerprint, hygiene, ledger, osv, report, secrets  # noqa: E402

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

    A GUARDRAIL, NOT A BOUNDARY. The flag lives in the agent's environment and
    the agent has a shell, so `env -u CC_SECURITY_AGENT ...` is all it takes to
    be somebody else here. That is fine for what this is for: the failure that
    actually happens is a model deciding, in good faith, that retiring the
    finding it just filed is the helpful thing to do -- and this stops that
    cold. Nothing here is load-bearing against an agent that is trying, and
    nothing should be built on the assumption that it is. `cmd_decide`'s
    running-analysis refusal is the one that does not depend on the
    environment -- and even that one is protection against a mistake, not a
    lock nothing can pick: it refuses while ANY analysis of the project is
    `running`, so opening a second analysis and closing IT does not make the
    door look shut while the first is still live, but an agent with direct
    access to the ledger file could still write a decision without going
    through this door at all.
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


def _refuse_root_outside_run(root):
    """`--root` is typed by the agent, from inside a worktree it did not
    choose -- but "not choose" used to only mean "cannot point above a
    checkout" (the filesystem-root/home guard below). It said nothing about
    pointing at some OTHER valid checkout on the machine: an agent could
    `prepare --root ~/some-other-project`, get a clean scan of code nobody
    asked about, and the analysis closes `done` with clean findings having
    never looked at its own scope at all.

    When the run is isolated, `bin/claude-cron`'s `run_job` (see
    `bin/worktree-lib.sh:wt_setup`) exports `CC_RUN_MANIFEST` as the path to
    that run's own `.run.json`, written into the run's own directory before
    the agent ever starts. The directory holding that file -- not anything
    read out of its contents, which is more than this needs -- IS the run's
    own worktree. `--root` has no reason to name anywhere else, so when both
    markers are present it is required to resolve inside that directory.

    Deliberately conditioned on CC_SECURITY_AGENT too, not on the manifest
    variable alone: a human running `prepare` by hand, outside any run,
    carries neither, and must see the same behaviour as before this guard --
    this is the agent's own run being anchored to the checkout the engine
    built for it, not a new restriction on manual use.
    """
    manifest = os.environ.get("CC_RUN_MANIFEST", "").strip()
    if not (os.environ.get("CC_SECURITY_AGENT", "").strip() and manifest):
        return
    run_dir = Path(manifest).expanduser().resolve().parent
    try:
        root.relative_to(run_dir)
    except ValueError:
        sys.exit(f"prepare: --root {root} is outside this run's own worktree "
                 f"({run_dir}) -- an analysis can only prepare the checkout "
                 "its own run created, not any other checkout on the machine.")


def cmd_prepare(args):
    """The deterministic phases, run inside the worktree by the agent's first
    command. Seconds, and no tokens."""
    conn = _conn(args)
    # Resolved before it is judged: `--root ~/..` and `--root /srv/../..` both
    # reach the filesystem root while looking like a checkout.
    root = Path(args.root).expanduser().resolve()
    _refuse_root_outside_run(root)
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

    # THE WHOLE HISTORY, ON EVERY ANALYSIS. This used to run only on the
    # baseline, on the reasoning that re-reading commits already read costs
    # wall-clock for findings already recorded. The wall-clock was right and
    # the product cost was not: nothing re-emits a history finding on a later
    # run, so `classify` saw it in the previous analysis and not in this one
    # and called it `fixed` -- for the exact act (deleting the file) this
    # module's own remediation says is NOT enough -- and by the third analysis
    # it was gone from the report altogether. A history finding is not
    # something an analysis can stop finding: git history does not shrink. It
    # stays OPEN, run after run, until the credential is rotated and a human
    # closes it with `decide --state accepted`. That is the honest lifecycle,
    # and it costs seconds of git plumbing and no tokens.
    #
    # Recorded FIRST, before the working tree. A secret that is both in the
    # tree and in the history shares one fingerprint (rule + path, see
    # secret_fingerprint), so record_finding upserts the two into one row and
    # the LAST writer's wording survives. The tree reading is the one that has
    # to win: it carries the real line numbers and says "in the working tree",
    # where the history reading says line 0 and "in the git history" -- a
    # secret sitting in the file right now, reported at line 0 as a thing of
    # the past. Both readings share one remediation ("rotate first, deleting
    # the line is not enough"), so nothing is lost by letting the tree's
    # wording win.
    history_findings, history_note = secrets.scan_history(root, None, ignore)
    tree_findings, tree_note = secrets.scan_tree(root, ignore)
    findings = history_findings + tree_findings + hygiene.scan(root, ignore)
    notes = [n for n in (history_note, tree_note) if n]

    components = deps.inventory(root)
    if args.offline:
        # Names OSV.dev, not just "CVEs". The coverage note is the one line a
        # reader has to judge the report's blind spots by, and "dependency
        # CVEs were not checked" leaves them guessing whether some other
        # source covered them; naming the source that did not answer says
        # exactly which question this report cannot be asked.
        notes.append("Dependency CVEs were NOT checked against OSV.dev: this "
                     "analysis ran with networking disabled.")
    else:
        # One cache for the whole call: several components of one project
        # routinely share an advisory, and osv.query never raises -- whatever
        # it could not reach comes back as prose in `note`, not as an
        # exception that would lose the secrets and hygiene findings above.
        cve_findings, osv_note = osv.query(components, detail_cache={})
        findings += cve_findings
        if osv_note:
            notes.append(osv_note)
    # Every phase writes into ONE channel, in phase order. The reader gets one
    # paragraph naming every blind spot this analysis has, rather than
    # whichever gap the last phase to speak happened to know about.
    note = " ".join(notes)

    if components:
        ledger.store_sbom(conn, project, repo, branch, aid, deps.sbom(components))
    for f in findings:
        ledger.record_finding(conn, aid, f)

    conn.execute("UPDATE analysis SET coverage_note=? WHERE id=?", (note, aid))
    conn.commit()
    # LAST, and not before the writes above: `prepared` is what lets `finish`
    # record `done`, and it must mean "the deterministic phases ran and their
    # findings are in the ledger", not "prepare was invoked and then fell over
    # halfway".
    ledger.mark_prepared(conn, aid)
    print(json.dumps({"coverage_note": note, "findings": len(findings)}))


def cmd_findings(args):
    conn = _conn(args)
    _analysis(conn, args.analysis)
    print(json.dumps(ledger.findings_of(conn, args.analysis), indent=2))


def cmd_fingerprint(args):
    """Print the 64-hex identity of a finding -- computed, never typed.

    FINGERPRINT_RE checks the SHAPE of what `report-finding` receives, not its
    RECIPE: a string the agent invents by hand ("aws-key-in-prod-env", or even
    64 hex characters picked at random) satisfies the shape check and still
    breaks the diff, because it is a fresh identity on every run -- the same
    hole is reported `new` for ever, never `open`, never `fixed`, and no
    decision anyone makes ever sticks to it. This verb runs the actual
    recipe, so the agent never has to reproduce it by hand.

    Read-only and side-effect free: it never opens the database, so it is
    allowed under CC_SECURITY_AGENT (see AGENT_FORBIDDEN) even though it
    still requires --db, like every other subcommand here.
    """
    if args.category == "secret":
        # No snippet, no value: the identity of a secret finding is its TYPE
        # and its FILE, never what it says. See secret_fingerprint's own
        # docstring for why hashing the value is not safe either. A --snippet
        # given alongside --category secret is silently ignored, not refused
        # -- the caller may be looping over occurrences uniformly and passing
        # a snippet for all of them regardless of category.
        print(fingerprint.secret_fingerprint(args.rule, args.path))
    else:
        print(fingerprint.fingerprint(args.category, args.rule, args.path,
                                      args.snippet or ""))


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
    # `done` REQUIRES that the deterministic phases actually ran. Nothing
    # engine-side runs `prepare` -- it is the agent's first command, named in
    # the prompt and in the skill -- so an agent that simply skipped it exited
    # cleanly, the engine closed the row `done`, and the result was a report
    # with zero findings, an empty coverage note and no banner anywhere saying
    # the repository had never been scanned. Worse than useless: that report
    # becomes the BASELINE the next analysis is diffed against, so everything
    # the next run legitimately finds arrives as `new` and everything a
    # previous run had found reads as `fixed`.
    #
    # Downgraded to `capped` rather than refused outright, for the same reason
    # the close-out can only ever lower a verdict: leaving the row `running`
    # for ever is a worse outcome than an honest "incomplete", and `capped` is
    # the state the report already prints an INCOMPLETE banner for.
    unprepared_note = ""
    if state == "done" and not row["prepared"]:
        state = "capped"
        unprepared_note = (
            "The deterministic phases never ran for this analysis: no secret "
            "sweep, no dependency inventory, no hygiene pass. Nothing here was "
            "looked at by them, so an absent finding means nothing was checked.")
        print(f"finish: analysis {args.analysis} never ran `prepare` — closing "
              "it capped instead of done; a report with no deterministic "
              "phase behind it must not become the next analysis's baseline",
              file=sys.stderr)
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
    #
    # A THIRD writer, from the guard above: the reason the verdict was lowered
    # belongs in the report next to every other thing this analysis did not do.
    stored = row["coverage_note"] or ""
    note = ""
    for part in (stored, args.note or "", unprepared_note):
        part = part.strip()
        # `not in`, not `!=`: a row is closed twice (the agent, then the
        # engine) and each close re-reads the note it already wrote. Without
        # the containment check the note grows a copy of itself every time.
        if part and part not in note:
            note = f"{note} {part}".strip()
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


def _sbom_document(conn, analysis_id):
    """The stored CycloneDX document for this analysis's scope, as text.

    The SBOM was write-only: `prepare` built one on every analysis with a
    lockfile in it and `store_sbom` kept it, and nothing anywhere could read it
    back out -- not the CLI, not the API, not the page. An inventory nobody can
    download is an inventory that does not exist for the one job an SBOM has,
    which is being handed to somebody else.

    Keyed (project, repo, branch) with the most recent analysis's document, so
    asking for an OLD analysis's SBOM hands back the current one for that
    branch rather than a reconstruction of what the tree held that day. Nothing
    is stored per analysis to reconstruct from, and inventing one by re-reading
    today's lockfiles would be worse: a document that claims to describe a
    commit it never saw.
    """
    row = _analysis(conn, analysis_id)
    stored = conn.execute(
        "SELECT document FROM sbom WHERE project=? AND repo=? AND branch=?",
        (row["project"], row["repo"], row["branch"])).fetchone()
    if stored is None:
        sys.exit(f"render: no SBOM recorded for {row['project']}/{row['repo']} "
                 f"@ {row['branch']} — one is stored only when the dependency "
                 "inventory found a lockfile it can read (package-lock.json, "
                 "requirements.txt, poetry.lock, composer.lock, go.sum).")
    try:
        # Re-serialised for a human opening the file, not re-shaped: the
        # document goes out exactly as it was recorded, only indented. A stored
        # string that somehow is not JSON is handed over untouched rather than
        # lost -- the caller asked for what is in the ledger.
        return json.dumps(json.loads(stored["document"]), indent=2, sort_keys=True)
    except ValueError:
        return stored["document"]


def cmd_render(args):
    conn = _conn(args)
    if args.format == "sbom":
        # Not a report over the checklist at all -- it is the stored document,
        # byte for byte. It shares this verb because the download route already
        # speaks `render --format`, and a second verb would mean a second route.
        print(_sbom_document(conn, args.analysis))
        return
    analysis, findings = _checklist(conn, args.analysis)
    note = analysis.get("coverage_note", "")
    renderer = {"json": report.as_json, "md": report.as_markdown,
                "html": report.as_html}[args.format]
    print(renderer(analysis, findings, note))


def cmd_decide(args):
    """A permanent, project-wide judgement. Refused while an analysis is live.

    The CC_SECURITY_AGENT guard above is a guardrail against mistake -- the
    variable is in the agent's own environment and the agent has a shell. This
    check does not depend on the environment at all: while ANY analysis of the
    project says `running` -- not only the latest one -- an agent of that
    project is alive, and this is exactly the window in which a decision would
    be one. A human decides from the page after the run ends, which is also
    the only moment the decision has anything to act on: the checklist is
    rebuilt on close, so a decision recorded mid-run changes nothing about the
    run it was recorded during.

    NOT keyed on the latest row alone. That used to be the whole check, and it
    had a two-command bypass: `open-analysis` a second analysis of the same
    project (allowed once CC_SECURITY_AGENT is unset, same shell as always),
    `finish` it immediately, and the project's LATEST analysis now reads
    `done` while the original one an agent is still working inside of sits
    `running`, unseen by a query that only ever looked at the newest row.
    Querying for any `running` row closes that: the original analysis is still
    among them.

    This is protection against a MISTAKE, still not a boundary against a
    determined bypass -- an agent with direct filesystem access to the ledger
    could write a decision without going through this door at all. What it
    does stop is the ordinary case: a decision taken while the agent that
    reported the finding is alive, whether or not the operator or the agent
    has stopped to think about which analysis is "the" running one. An
    operator who really does want to accept a risk during a run is asked to
    wait the minutes it takes, which costs them nothing; a `running` row left
    behind by a run that died is not a permanent lock -- the engine's own
    preflight sweep closes those before it opens the next analysis of that
    project (see `cmd_security_analyze` in `bin/claude-cron`), so this cannot
    wedge a project's triage for ever.
    """
    conn = _conn(args)
    live = conn.execute(
        "SELECT id FROM analysis WHERE project=? AND state='running' "
        "ORDER BY id ASC LIMIT 1", (args.project,)).fetchone()
    if live is not None:
        sys.exit(f"decide: analysis {live['id']} of '{args.project}' is still "
                 "running — a decision taken while the agent that reports the "
                 "finding is alive is the one decision it must not be able to "
                 "take. Wait for the run to end; the checklist is rebuilt on "
                 "close, so nothing is lost by waiting.")
    try:
        ledger.set_decision(conn, args.project, args.fingerprint,
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

    # Deliberately absent from AGENT_FORBIDDEN: it never opens the database,
    # so there is nothing here for the agent to abuse -- only a computation
    # it would otherwise be tempted to reproduce by hand and get wrong.
    fp = sub.add_parser("fingerprint", parents=[dbflag]); fp.set_defaults(fn=cmd_fingerprint)
    fp.add_argument("--category", required=True)
    fp.add_argument("--rule", required=True)
    fp.add_argument("--path", required=True)
    fp.add_argument("--snippet", default="")

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
    rd.add_argument("--format", required=True,
                    choices=("json", "md", "html", "sbom"))

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
