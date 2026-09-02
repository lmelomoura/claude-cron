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
and the operator reach this file through the identical command, so the
verbs and actions an agent must never reach -- `decide`, `rename-project`,
`open-analysis`, `event`, and saving or deleting a saved filter -- are
refused whenever CC_SECURITY_AGENT is set (see `_refuse_if_agent`).

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
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security import adapters, deps, diff, fingerprint, hygiene, ignores, ledger, osv, queries, report, secrets, taxonomy  # noqa: E402

REQUIRED_FINDING_KEYS = ("fingerprint", "category", "rule", "severity", "title")

# The identity two analyses match a finding on -- lowercase sha256 hex, as
# `security/fingerprint.py` mints it. Shape-checked at the door because the
# agent types this string itself: a fingerprint of its own invention ("aws-key
# in prod.env") is a NEW identity on every run, so the same hole is reported
# `new` for ever, never `open`, never `fixed`, and no decision ever sticks to
# it. The recipe is not enforceable here -- only the shape is.
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

# `findings-page --fingerprint`'s own shape: a PREFIX, not the full 64-hex
# identity FINGERPRINT_RE enforces above -- see that flag's own comment for
# why (the Activity screen's deep link only ever has the first 12). Mirrors
# `security_findings`'s regex in bin/claude-cron-server exactly, so a value
# typed at the command line is held to the identical shape one arriving over
# HTTP already is -- this verb has no route in front of it refusing a typo
# before it ever reaches here (a human, or the agent, can call it directly).
FINGERPRINT_PREFIX_RE = re.compile(r"^[0-9a-f]{1,64}$")

# A finding is a paragraph, not a document. Without a cap the agent can paste
# a whole file into `rationale`, and every later analysis pays to read it back
# out of the ledger and renders it into the report page.
MAX_TEXT = 10000
TEXT_KEYS = ("title", "rationale", "remediation", "partial_note")

# The closed set of finding categories: the four the deterministic phases
# produce, plus the agent's own `sast`. ONE tuple, read by everything that
# has an opinion about this field -- `report-finding`'s door, `fingerprint`'s
# flag and `findings-page`'s filter -- because a category accepted on the way
# in that no filter can select on the way out is a row nobody can find, and a
# fingerprint computed under one spelling of a category and reported under
# another is two identities for one hole.
FINDING_CATEGORIES = diff.DETERMINISTIC_CATEGORIES + ("sast",)

# The word a reader sees for a decision state, mirroring
# `SEC_STATE_LABEL` in ui/security/vocabulary.js -- the vocabulary every
# screen in the area renders. Written INTO the event detail rather than
# translated when the Activity screen paints it, because `detail` is one free
# text column shared by five event kinds: a decision's detail is
# "<state>: <reason>", and a renderer cannot split that back apart to
# translate half of it without parsing a human's reason for a colon. So the
# one place that knows the state is a state is the place that writes it.
DECISION_LABEL = {"accepted": "Accepted", "false_positive": "False positive"}

# A safeguard against pathological JSON on stdin. Both `report-finding` and
# `filters save` read JSON bodies; a deeply nested structure raises RecursionError
# and a megabyte-scale body is far beyond any legitimate finding or filter.
MAX_STDIN_BYTES = 1_000_000

# What the agent under review may NOT do, even though it reaches this file
# through the same command the operator does. See `_refuse_if_agent`.
#
# A bare verb is keyed by its plain name ("decide", "event", ...). A verb
# with a nested action -- `filters`, whose subparser uses `dest="action"`
# (see `fl_sub` below) -- is keyed by its TWO-WORD form, "verb action",
# exactly as written here ("filters save", "filters delete"). `main()`
# computes that key the same way for every subcommand, unconditionally, from
# `args.cmd` and `getattr(args, "action", "")` -- there is no
# `if args.cmd == "filters"` or any other per-verb special case in that
# computation, and none should be added. `filters list` -- a query, not a
# write, the same read-only case as `findings` or `events` -- stays out of
# this tuple and reachable, while the two writes that mutate a human's saved
# working set are refused by name, same as every other entry.
#
# The rule for the NEXT nested verb: give its subparser `dest="action"`, and
# if a two-word form of it needs refusing, add that string to this tuple.
# Nothing else changes -- see `main()`'s dispatch key below.
AGENT_FORBIDDEN = ("decide", "rename-project", "open-analysis", "event",
                   "filters save", "filters delete")


def _refuse_if_agent(cmd):
    """The door validates the SHAPE of what is written; this validates WHO.

    `cmd_security_analyze` exports CC_SECURITY_AGENT=1 into the analysis run,
    so every `claude-cron security ...` the agent types -- from its own tool
    shell, inside the worktree -- arrives here with that flag set. These
    verbs (and, for `filters`, these specific actions) have to be refused
    there:

      decide          a permanent, project-wide suppression. An agent that can
                      call it can retire the finding it just reported (and the
                      ledger records a `decided_by` it typed itself).
      rename-project  moves the whole history onto another name, out from
                      under the project being analysed.
      open-analysis   mints rows the engine never opened and will never close.
      event           the standalone write into the audit trail. Both
                      audit-worthy things the agent causes are already filed
                      as side effects -- `analysis_started` by
                      `open-analysis` (which it cannot call) and
                      `analysis_finished` by `finish` (which it can, and
                      which files the event itself) -- so the agent has no
                      legitimate use for this verb, while a forged
                      `settings_changed` or `decision_made` corrupts the one
                      artifact whose whole purpose is to say what actually
                      happened. `events` (read-only) is deliberately NOT in
                      this list -- there is nothing here for the flag to
                      protect, only a query the agent may legitimately want.
      filters save    a named filter is a human's working set, curated across
      filters delete  sessions -- not something an analysis decides to leave
                      behind, or clear out, for whoever opens the page next.
                      `filters list` is deliberately NOT in this list, for the
                      same reason `events` is not: it reads, it writes
                      nothing, and the agent may legitimately want to see it.

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
            "does not get to dismiss it, rename the ledger out from under it, "
            "open analyses of its own, write an event by hand into the one "
            "record of what actually happened, or save/delete a saved filter "
            "-- a working set a human curates, not something an analysis "
            "decides; ask a human to run this.")


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


def _refuse_if_secret(field, value):
    """Refuse free text the agent wrote if it carries a live credential.

    ONE implementation, two doors. `report-finding` gates `title`,
    `rationale`, `remediation` and `partial_note` with this -- and `category`
    and `rule` as well, which are not free prose but ARE agent-written, are
    stored verbatim, and are quoted back by their own refusals (see
    `cmd_report_finding`). The second door is `finish --note`, which lands in
    `coverage_note`, reaches all four report formats and the analysis page,
    and is deliberately reachable by the agent (see `_refuse_if_agent`:
    closing the row is the one thing that must always work) -- it had no gate
    at all, even though it is the near-identical twin of the `partial_note`
    already covered. An agent describing what it could not scan is exactly as
    likely to quote the credential it found as one describing what it did.

    The deterministic categories cannot leak a secret's value THROUGH THEIR
    EVIDENCE by construction -- the `occurrence` table has no column for it,
    `secrets.py` never returns matched text, `secret_fingerprint` takes no
    value argument. That guarantee belongs to the columns the scanners
    fill, not to the payload the agent hands in: `rule` arrives from the
    agent under every category, deterministic ones included, which is why it
    is gated here too. Agent-written free text has no such structural
    guarantee, and until this check existed the only thing stopping a live
    credential from landing in one was a sentence in the skill telling the
    agent not to -- in exactly the scenario the feature exists for, an agent
    reading a repository whose contents it does not control.

    The message names the FIELD and the RULE, never the text that matched:
    echoing the secret back to refuse it would defeat the refusal. Refusing
    is safe on both doors because neither has written anything yet -- the
    caller re-runs with a description instead of a quotation.
    """
    if not isinstance(value, str) or not value:
        return
    matched_rule = secrets.looks_like_a_secret(value)
    if matched_rule is not None:
        sys.exit(f"{field} looks like it contains a live credential (matched "
                 f"rule '{matched_rule}') and was refused before being written "
                 "anywhere. Describe the credential's type and location "
                 "instead of quoting it -- e.g. \"an AWS access key is "
                 "hardcoded here\" -- the way a secret-category finding "
                 "already does.")


def _refuse_unknown_sast_rule(verb, rule, tail=""):
    """Refuse a `sast` rule outside the closed vocabulary -- the one message
    behind both doors that check it, `cmd_fingerprint`'s `--rule` and
    `cmd_report_finding`'s `rule` payload key, so the wording cannot drift
    between the two the way two hand-written copies eventually would.

    Runs `_refuse_if_secret` on the rule FIRST, before quoting it back in
    the refusal below -- owned HERE, not left to each call site, so a future
    third caller cannot forget the ordering the other two already got right.

    `verb` names the command doing the refusing (`fingerprint` or
    `report-finding`); `tail` lets `report-finding` append its own sentence
    pointing the agent at the rationale field, which `fingerprint` has no
    equivalent of.
    """
    _refuse_if_secret(f"{verb}: rule", rule)
    sys.exit(f"{verb}: {rule!r} is not a SAST rule name. "
             "The rule is part of the fingerprint, so a second spelling "
             "of one hole is a second identity: it reports `new` for "
             "ever and no decision ever matches it again. Use one of: "
             + ", ".join(taxonomy.RULE_NAMES)
             + " — or `other` if none of them fits" + tail)


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
    try:
        ledger.record_event(conn, args.project, "analysis_started",
                            f"{args.profile} on {args.branch}", str(aid))
    except sqlite3.Error:
        # Best-effort: the row above is already committed, and the audit
        # trail is not the thing being audited. A busy `security.db` (shared
        # across every project, default 5s busy timeout) must never turn
        # into a missing `analysis_id` here -- that is what left an orphaned
        # `running` row AND made `cmd_security_analyze`'s
        # `| jq -r '.analysis_id'` read empty, dying with "could not open an
        # analysis" over an analysis that, in fact, had opened. Only
        # `sqlite3.Error`: "analysis_started" is a literal above, so
        # `ValueError` (an unknown kind) cannot fire here -- if it somehow
        # did, that is a programming error and must still raise.
        pass
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


# THE PRODUCERS, BY NAME -- the answer to "who actually looked", which is a
# different question from "which phase was configured" and the one
# `diff._proven` asks before it will call a baseline finding `fixed`. Each
# `_scan_*` below returns whichever of these produced its findings, or "" when
# the phase did not run at all; `cmd_prepare` stamps the name onto the findings
# and records the set on the analysis row.
#
# THEY ARE AN IDENTITY VOCABULARY, not labels. A finding minted under
# `PRODUCER_TRIVY` is provable only by a later analysis that also ran Trivy, so
# renaming one of these strings orphans the proof of every baseline finding
# carrying the old spelling. That failure is not silent and not dangerous --
# an unrecognised producer renders `pending`, never a false `fixed` -- but it
# is a whole run of the checklist saying "not re-checked" about work that was
# re-checked, so a rename here needs a ledger migration the way a rule rename
# does.
#
# The two per category are the point. `secret` and `dependency` each have an
# engine and a fallback whose coverage the other does not contain -- gitleaks'
# rule set against eight shaped patterns, Trivy's lockfile formats against
# `deps.inventory`'s five -- and the checklist used to treat either one's
# silence as the category's proof.
PRODUCER_GITLEAKS = "gitleaks"
PRODUCER_SECRETS = "secrets"      # the built-in pattern scanner
PRODUCER_TRIVY = "trivy"          # Trivy's filesystem vulnerability scan
PRODUCER_OSV = "osv"              # deps.inventory + OSV.dev
PRODUCER_HYGIENE = "hygiene"
PRODUCER_TRIVY_IAC = "trivy-iac"  # Trivy's misconfiguration scan
PRODUCER_SEMGREP = "semgrep"      # the SAST pre-pass


def _produced_by(findings, producer, produced):
    """Stamp the producer that MINTED these findings, and record that it ran.

    THE ONE PLACE BOTH HALVES ARE WRITTEN, so they cannot disagree. The
    finding's `producer` column and the analysis's `produced` set are read
    together by `diff._proven` -- a phase that stamped its findings but never
    joined the set would report its own previous findings `pending` for ever,
    and a phase that joined the set without stamping would prove nothing about
    anything. Both come off one argument here.

    An empty `producer` means the phase did not run: nothing is stamped and
    nothing joins the set, which is exactly how `iac` on a machine without
    Trivy stops proving that a Dockerfile is clean.
    """
    if producer:
        produced.add(producer)
        for finding in findings:
            finding["producer"] = producer
    return findings


def _scan_secrets(root, ignore):
    """(findings, notes, lines, producer) for the secret phase -- ONE scanner,
    not two.

    Gitleaks when it is installed, the built-in pattern scanner when it is
    not, and never both. Two scanners in one category find the same hole and
    report it under two fingerprints, because the fingerprint contains the
    RULE and the two name their rules differently -- the checklist then shows
    one credential as two entries whose remediations contradict each other,
    and a human's decision about one never matches the other.

    The engine still falls back if it could not produce a report at all --
    absent, unversioned, timed out, or writing a format this code cannot
    read. That is safe precisely because it produced nothing: there is no
    engine finding for a built-in one to collide with.

    `lines` is `lines_of_code`, which used to arrive as a by-product of the
    built-in sweep's read. It is counted separately on the engine path
    (`secrets.count_lines`, the same walk over the same files) rather than
    lost -- the project header renders 0 as "not counted", which no analysis
    that actually ran should ever claim.

    `producer` is WHICH of the two scanners answered, and it is never
    "secret", the category. The two do not cover the same ground -- gitleaks
    carries its own rule set, the built-in scanner has eight shaped patterns
    and says so in `secrets.FALLBACK_NOTE` -- so a machine that loses gitleaks
    must not read the built-in scanner's silence as proof that a
    gitleaks-only credential is gone. This phase always has a producer: there
    is no configuration in which neither scanner runs.
    """
    if adapters.engine_path("gitleaks"):
        findings, notes = adapters.gitleaks_scan(root, ignore)
        if findings is not None:
            return (findings, notes, secrets.count_lines(root, ignore),
                    PRODUCER_GITLEAKS)
        # The engine is here and could not answer. Say so, and let the
        # built-in scanner do the work rather than reporting no secrets.
        notes = [*notes, secrets.FALLBACK_NOTE]
    else:
        notes = [secrets.FALLBACK_NOTE]
    history_findings, history_note = secrets.scan_history(root, None, ignore)
    tree_findings, tree_note, lines = secrets.scan_tree(root, ignore)
    return (history_findings + tree_findings,
            [history_note, tree_note, *notes], lines, PRODUCER_SECRETS)


# Named so `test_offline_mode_declares_the_gap` (and every reader of a
# downloaded report) sees which sources were never asked, not just that
# "dependency CVEs" in the abstract were skipped -- `--offline` disables
# BOTH: a vulnerability database, Trivy's own or OSV.dev's, does not exist
# unless somebody publishes it, and this analysis was told not to reach the
# network.
OFFLINE_DEPENDENCY_NOTE = ("Dependency CVEs were NOT checked against OSV.dev "
                           "or Trivy's vulnerability database: this analysis "
                           "ran with networking disabled.")


def _scan_dependencies(root, components, offline: bool, ignore_paths=()):
    """(findings, notes, producer) for the dependency phase -- ONE producer,
    not two.

    Trivy's filesystem scanner when it is installed, `osv.query` fed by
    `deps.inventory`'s output (`components`) when it is not, and never both:
    two producers in the `dependency` category would report the same CVE
    under two fingerprints, and the checklist would carry it as two rows a
    human's decision on one never reaches. The two mint the SAME identity for
    the same advisory -- see `adapters.trivy_vulns`, which normalises Trivy's
    inputs onto `deps.inventory`'s spelling, and `adapters._trivy_advisory_id`,
    which reads the publishing database's id out of Trivy's own record rather
    than hashing the CVE id OSV.dev never uses. What is left over is OSV.dev
    minting one record per database where Trivy mints one per hole, which no
    alias reconciles; `adapters.DEP_ID_NOTE` states that in the report rather
    than leaving it to be discovered from a diff.

    The engine still falls back if it could not produce a report at all --
    absent, unversioned, timed out, or writing a format this code cannot
    read. That is safe precisely because it produced nothing: there is no
    engine finding for OSV.dev's to collide with.

    `ignore_paths` reaches BOTH producers, and that is deliberate. Filtering
    only the engine's output would make an operator's globs suppress a
    finding on a machine with Trivy and not on one without -- the same
    per-machine flip that made the fingerprint divergence a bug. The
    inventory itself is untouched: the SBOM below still lists every lockfile
    in the tree.

    `components` is read by the caller regardless of `offline` or of which
    producer runs here: `deps.inventory` never touches the network, and the
    SBOM this project hands out (`ledger.store_sbom`) is built from it
    whether or not either vulnerability source ran.

    WHICH PRODUCER IS RETURNED IS NOT COSMETIC, AND "the dependency phase ran"
    IS NOT A FACT THIS FUNCTION CAN REPORT. The two producers are ONE
    CATEGORY WITH TWO COVERAGES, and neither contains the other:

      Trivy       reads yarn.lock, pnpm-lock.yaml, Gemfile.lock, Cargo.lock,
                  pom.xml, vendored jars and more, against its own database.
      OSV.dev     is asked about `deps.inventory`'s output, which reads FIVE
                  formats (`deps._READERS`) -- and about advisories Trivy's
                  database does not necessarily carry.

    Measured on a real `yarn.lock` pinning lodash 4.17.20: Trivy 5 findings,
    `deps.inventory` 0 components. So "the phase ran" reported all five fixed
    on a machine without Trivy, and `osv.FALLBACK_NOTE` -- which declares a
    gap in advisory SOURCES -- says nothing at all about the gap that actually
    bit, which is in lockfile FORMATS.

    THE DECISION: absence is proven only by the producer that MINTED the
    finding. Not by "a producer for this category", and not by a coverage
    ordering, because there is no ordering to appeal to -- calling Trivy a
    superset would be true of formats and false of advisory sources, and a
    rule that is half true is how the first version of this got written. The
    cost is bounded and it is the honest one: a machine that gains or loses
    Trivy carries its baseline dependency findings as `pending` for exactly
    one analysis, then they settle under the new producer. `pending` says
    "not re-checked", which is precisely what happened; the alternative said
    "fixed" about a lockfile nobody parsed.
    """
    if offline:
        # No producer: `--offline` refuses BOTH sources, so nothing looked and
        # nothing about this category can be proven from this analysis.
        return [], [OFFLINE_DEPENDENCY_NOTE], ""
    notes = []
    if adapters.engine_path("trivy"):
        findings, notes = adapters.trivy_scan(root, ignore_paths)
        if findings is not None:
            return findings, notes, PRODUCER_TRIVY
        # The engine is here and could not answer. Its note is kept -- that
        # is the "say so" -- and OSV.dev does the work rather than the phase
        # reporting no dependency findings.
    # Said only when there was something to check. `osv.query` returns
    # immediately for an empty inventory, and a note claiming dependencies
    # "were checked against OSV.dev's own database" describes a lookup that
    # never happened.
    if components:
        notes.append(osv.FALLBACK_NOTE)
    cve_findings, osv_note = osv.query(components, detail_cache={})
    cve_findings = [f for f in cve_findings
                    if not ignores.ignored(f["occurrences"][0]["file"],
                                           ignore_paths)]
    if osv_note:
        notes.append(osv_note)
    return cve_findings, notes, PRODUCER_OSV


def _unfiltered_sbom_note(components, ignore_paths) -> str:
    """`ignores.SBOM_UNFILTERED_NOTE` for this repository, or "".

    THE ONE PLACE THAT KNOWS BOTH HALVES OF A CONTRADICTION THE REPORT USED TO
    MAKE. `deps.inventory` deliberately does not read `ignore_paths` -- an
    SBOM is a statement about what the repository CONTAINS, and one whose
    contents changed with a settings field would answer differently for the
    same commit while being handed to consumers who cannot see that field --
    but `_scan_dependencies` above filters the FINDINGS from those same
    lockfiles. Measured on this repository: 4 of 4 SBOM components come from
    `tests/security/fixtures/`, and the dependency category goes 6 -> 0. A
    consumer reading the published SBOM beside the report saw "this project
    ships lodash 4.17.20" and "no dependency findings".

    That state used to require an operator to write `ignore_paths`, and they
    knew what they had written. With the fixtures default it is what an
    unconfigured project gets, so it is said out loud.

    MEASURED, not standing policy, which is why it is a function and not a
    constant beside `DEFAULT_NOTE`: it names a count and real paths, so a
    project with no lockfile under a filtered path never reads it. Counted
    from `deps.inventory`, the one producer whose components carry the file
    they were read from; Syft's SBOM does not filter either, so the closing
    sentence is true whichever producer built the document.
    """
    hidden = [c for c in components
              if ignores.ignored(c.get("source", ""), ignore_paths)]
    if not hidden:
        return ""
    # The FILES, not the components: three lockfiles is a readable sentence
    # where "23 components" would need a directory listing to be actionable.
    sources = sorted({c.get("source", "") for c in hidden})
    shown = ", ".join(sources[:3])
    if len(sources) > 3:
        shown += f" and {len(sources) - 3} more"
    return ignores.SBOM_UNFILTERED_NOTE.format(
        count=len(hidden), total=len(components), sources=shown)


# Semgrep's rule pack is fetched from its registry, so the pre-pass is a
# network call and `--offline` has to refuse it -- the same shape
# `OFFLINE_DEPENDENCY_NOTE` takes one phase up. Named separately rather than
# folded into that sentence because the two gaps are different facts: an
# analysis can have a dependency source and no rule pack, and a reader has to
# be able to tell which half of the report was affected.
OFFLINE_SAST_NOTE = ("The Semgrep SAST pre-pass did NOT run: its rule pack is "
                     "fetched from Semgrep's registry, and this analysis ran "
                     "with networking disabled.")


def _scan_sast(root, offline: bool, ignore_paths=()):
    """(findings, notes, producer) for the SAST pre-pass -- an ADDITION, never
    a swap.

    THE ONE PHASE HERE THAT REPLACES NOTHING. `_scan_secrets`,
    `_scan_dependencies` and `_scan_sbom` all choose ONE producer per category
    because two would report one hole under two fingerprints. This one has no
    such choice to make: the agent's own SAST pass is the primary source of
    the `sast` category and stays so, because Semgrep's coverage is not
    remotely even -- 147 rules for Python against ONE for shell, measured, and
    the core of this product is 8,263 lines of bash. So these findings are
    added beside whatever the agent reports, and `adapters.SAST_IDENTITY_NOTE`
    states in the report that a weakness found by both is listed twice.

    A missing engine costs the pre-pass and NOT the phase, which is why this
    returns `[]` rather than the `None` its three neighbours use to ask for a
    fallback: there is nothing to fall back to and nothing was lost. The gap
    is declared all the same -- "found nothing" and "never looked" are the
    same silence in a report otherwise.

    THE ADDITION IS EXACTLY WHY THIS PHASE NEEDS A PRODUCER AND NOT A
    CATEGORY. `sast` holds rows from two sources at once: the agent's own
    pass, and this pre-pass, whose identity is
    `fingerprint("sast", rule, path, check_id)` -- a check id only Semgrep
    mints. The analysis closing `done` is proof the AGENT covered its scope,
    and it used to be read as proof for every `sast` row, so a pre-pass
    finding went `fixed` the moment a run without Semgrep finished. The two
    producers now answer separately, which is also why the fix is not "mark
    the whole category pending": the agent's own findings still close on the
    agent's own evidence.
    """
    if offline:
        return [], [OFFLINE_SAST_NOTE], ""
    if not adapters.engine_path("semgrep"):
        # `engine_path` answers None for a machine without the binary AND for
        # one with `CC_SECURITY_ENGINES=off`, and the note says the same thing
        # for both on purpose: as far as this analysis goes they are the same
        # machine.
        return [], [adapters.SAST_GAP.format(
            reason="semgrep is not available to this analysis")], ""
    findings, notes = adapters.semgrep_scan(root, ignore_paths)
    if findings is None:
        reason = (notes[0] if notes else "semgrep produced no report").rstrip(".")
        return [], [adapters.SAST_GAP.format(reason=reason)], ""
    return findings, notes, PRODUCER_SEMGREP


# Said when `_scan_sbom` returns no document at all, and the ONE sentence that
# makes the rest of the SBOM paragraph safe. Every other note in that paragraph
# describes a document -- what it lists, who produced it, which of its entries
# a filter hid -- and all of them were still emitted for an analysis that
# stored nothing: `sbom` held 0 rows, `render --format sbom` answered "no SBOM
# recorded", and the coverage note said "The SBOM lists the five lockfile
# formats ...". A reader was told about a file they cannot download.
#
# Worded around the OBSERVABLE fact rather than around which producer was
# absent, because both are absent by different routes -- Syft not installed,
# Syft writing a document with no `components`, or simply no lockfile in the
# tree -- and the reader's question is the same in all three.
NO_SBOM_NOTE = ("No SBOM was recorded for this analysis: neither producer had "
                "a component to list, so there is no component inventory to "
                "download for this run.")


def _scan_sbom(root, components):
    """(document, notes) for the SBOM -- ONE producer, not two, on the same
    terms `_scan_secrets` and `_scan_dependencies` use.

    Syft's directory scan when it is installed and answers with at least one
    component; `deps.sbom` fed by `deps.inventory`'s own five-format read
    otherwise. `None` means neither producer found anything to list -- the
    pre-existing behaviour for a project with no lockfile `deps.inventory`
    can read, kept rather than replaced by an SBOM that lists zero
    components and helps nobody who downloads it.

    A STRUCTURALLY VALID BUT EMPTY SYFT ANSWER DOES NOT WIN BY DEFAULT.
    `adapters.syft_sbom` already returns `None` for a report missing
    `components` altogether -- which, measured against an empty checkout, is
    exactly how Syft's own CycloneDX writer spells "nothing found" (the key
    is absent, not `[]`). What is checked again here is `adapters.
    syft_document`'s OWN filtering: a document that validated but whose only
    entries were the file-digest noise it drops (see that function) collapses
    to the same "say nothing, fall back" outcome. Either way, `deps.sbom` is
    the one this function trusts when Syft has nothing to show for itself --
    "a malformed or empty document must not replace a good SBOM silently".
    Falling back also drops Syft's OWN notes (which claim Syft produced the
    SBOM): carrying them forward would have this function's return value
    contradict itself the moment `deps.sbom` is what actually gets stored.
    """
    notes = []
    if adapters.engine_path("syft"):
        document, syft_notes = adapters.syft_sbom(root)
        if document is not None and document.get("components"):
            return document, syft_notes
        if document is None:
            notes = syft_notes
    if not components:
        return None, notes
    return deps.sbom(components), [*notes, deps.SBOM_FALLBACK_NOTE]


# Trivy's misconfiguration checks are fetched from its own registry, the same
# shape `OFFLINE_SAST_NOTE` takes for Semgrep's rule pack -- so `--offline`
# has to refuse this phase too, named separately for the identical reason
# `OFFLINE_SAST_NOTE` is not folded into `OFFLINE_DEPENDENCY_NOTE`: a reader
# has to be able to tell which half of the report went unchecked.
OFFLINE_IAC_NOTE = ("Infrastructure-as-code misconfigurations were NOT "
                    "checked: Trivy's misconfiguration checks are fetched "
                    "from its own registry, and this analysis ran with "
                    "networking disabled.")


def _scan_iac(root, offline: bool, ignore_paths=()):
    """(findings, notes, producer) for the IaC misconfiguration phase.

    UNLIKE EVERY PHASE ABOVE IT, THERE IS NOTHING TO FALL BACK TO AND NOTHING
    TO REPLACE. `_scan_secrets` and `_scan_dependencies` each choose one
    producer because a built-in scanner already covers the category; `iac`
    has never had one -- Trivy's misconfiguration scanner is the first and
    only source this project has ever had for it. So a Trivy this analysis
    could not use costs the WHOLE phase, not a producer swap: `findings` is
    `[]` and the gap is declared, the same shape `_scan_sast` uses when
    Semgrep is unavailable, for the identical reason -- "found nothing" and
    "never looked" must not be the same silence in a report.

    AND THE CHECKLIST HAS TO HEAR THAT TOO, which is what `producer` is for.
    A category with no fallback is the one where "the phase was configured"
    and "something looked" diverge completely: `[]` from here means nobody
    looked, every time. Read as a deterministic CATEGORY -- proven the moment
    `prepare` finished -- it produced a report that said the Dockerfile "was
    not checked at all this run" and, four lines down, declared three of its
    misconfigurations fixed. The Dockerfile was untouched.
    """
    if offline:
        return [], [OFFLINE_IAC_NOTE], ""
    if not adapters.engine_path("trivy"):
        return [], [adapters.IAC_GAP.format(
            reason="trivy is not available to this analysis")], ""
    findings, notes = adapters.trivy_iac_scan(root, ignore_paths)
    if findings is None:
        reason = (notes[0] if notes else "trivy produced no report").rstrip(".")
        return [], [adapters.IAC_GAP.format(reason=reason)], ""
    return findings, notes, PRODUCER_TRIVY_IAC


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
    # to win: it says "in the working tree", where the history reading says
    # "in the git history" -- a secret sitting in the file right now, reported
    # as a thing of the past. The line differs too, and by how much depends on
    # which scanner ran: the built-in sweep files every history finding at
    # line 0 (secrets.scan_history, which reads a diff and has no line to
    # give), while gitleaks reports the commit's own StartLine -- a real
    # number, but a number in a commit rather than in the file as it stands.
    # Both readings share one remediation ("rotate first, deleting the line is
    # not enough"), so nothing is lost by letting the tree's wording win.
    #
    # ORDERING IS THE WHOLE MECHANISM, on both paths, and on each path it is a
    # different pair of statements. Here, `_scan_secrets` returns history
    # before tree. On the engine path it is the two RECORDING blocks in
    # `adapters.gitleaks_scan` -- the `if history is None:` / `if tree is
    # None:` pair that appends each report to `findings`, NOT the two
    # `run_json` calls above them, which this comment used to name and whose
    # order is a measured no-op (each writes its own temp file; the suite
    # passes either way). Swap either real pair and every co-located secret
    # becomes a report about the past. Both pairs are pinned by ONE test,
    # test_the_tree_reading_wins_over_its_history_twin_on_either_scanner
    # (tests/security/test_adapters.py), parametrised over both scanners. The
    # fallback-only copy that used to live in tests/security/test_cli.py was
    # retired with it: it asserted the built-in scanner's rule name while
    # inheriting the suite's engines-off default, so it was red in the only
    # configuration a real analysis runs in.
    # WHAT ACTUALLY LOOKED, accumulated phase by phase and written onto the
    # analysis row at the very end (see `mark_prepared`). Every phase below
    # goes through `_produced_by`, which is what keeps this set and the
    # findings' own `producer` column from ever disagreeing.
    produced = set()

    secret_findings, secret_notes, tree_lines, secret_producer = _scan_secrets(
        root, ignore)
    findings = _produced_by(secret_findings, secret_producer, produced)
    # Hygiene has no engine and no fallback -- it is our own walk over the
    # tree, so it runs in every configuration and is always its own producer.
    findings += _produced_by(hygiene.scan(root, ignore), PRODUCER_HYGIENE,
                             produced)
    notes = [n for n in secret_notes if n]

    # FIRST in the paragraph, because it qualifies every phase below it and
    # not just the one that happens to be speaking. The default noise filter
    # suppresses findings in a repository nobody has configured, which is
    # exactly the repository whose reader has no way of knowing it was
    # applied -- "we found nothing there" and "we did not look there" are the
    # same silence otherwise. Emitted whichever scanner ran, because the
    # filter is `ignores.ignored` and both of them consult it.
    if ignores.defaults_apply(ignore):
        notes.insert(0, ignores.DEFAULT_NOTE)

    # AHEAD OF EVERYTHING, including the default's own sentence: it says a
    # switch the operator typed did nothing, so it explains why the sentence
    # below it is there at all. `!defaults` is an exact token, and a project
    # that wrote `!default` or `!defaults/**` believes its fixtures are being
    # scanned. They are not, and nothing used to say so -- the entry was
    # silently kept as a path glob and shipped to three engine command lines.
    unknown_switch = ignores.unknown_switch_note(ignore)
    if unknown_switch:
        notes.insert(0, unknown_switch)
        # And on stderr too. `prepare` runs unattended inside a worktree, so
        # the note in the report is the durable channel -- but an operator who
        # has just edited the field and is running this by hand should not
        # have to open a report to find out the edit did nothing.
        print(f"prepare: {unknown_switch}", file=sys.stderr)

    # `components` is read regardless of `offline` or which vulnerability
    # source runs: `deps.inventory` never touches the network, and the SBOM
    # below is built from it whenever Syft does not.
    components = deps.inventory(root)
    dep_findings, dep_notes, dep_producer = _scan_dependencies(
        root, components, args.offline, ignore)
    findings += _produced_by(dep_findings, dep_producer, produced)

    sbom_document, sbom_notes = _scan_sbom(root, components)
    if sbom_document is None:
        # NOTHING IS STORED, so nothing may be described. `DEP_SBOM_NOTE` is
        # appended by `trivy_scan` unconditionally and asserts what "the SBOM"
        # lists; with no SBOM that is a sentence about a file the reader
        # cannot download, and `SYFT_NO_COMPONENTS_NOTE`'s "so it was not
        # used" sits beside it implying a fallback that never happened. The
        # swap below handles the two-producer case; this handles the
        # NO-producer case, which it used to fall straight through.
        dep_notes = [n for n in dep_notes if n != adapters.DEP_SBOM_NOTE]
        sbom_notes = [*sbom_notes, NO_SBOM_NOTE]
    elif adapters.SYFT_SBOM_NOTE in sbom_notes and adapters.DEP_SBOM_NOTE in dep_notes:
        # Task 3's `DEP_SBOM_NOTE` asserts the SBOM lists the five lockfile
        # formats `deps.inventory` reads -- true only while `deps.sbom` built
        # it. `_scan_sbom` just said (via `SYFT_SBOM_NOTE`) that Syft did
        # instead, which makes that specific claim false: Syft reads far more
        # than five formats. This is the one place that knows both facts at
        # once -- which producer found the CVEs, which one built the SBOM --
        # so it is what swaps the two notes rather than leaving the report to
        # contradict itself.
        dep_notes = [n for n in dep_notes if n != adapters.DEP_SBOM_NOTE]
    notes += [n for n in dep_notes if n]
    notes += [n for n in sbom_notes if n]
    # After both, because it is about the gap BETWEEN them: what the SBOM
    # lists and what the dependency phase actually looked up.
    unfiltered = _unfiltered_sbom_note(components, ignore)
    if unfiltered:
        notes.append(unfiltered)

    iac_findings, iac_notes, iac_producer = _scan_iac(root, args.offline, ignore)
    findings += _produced_by(iac_findings, iac_producer, produced)
    notes += [n for n in iac_notes if n]

    # LAST of the phases, because it is the only one that does not stand
    # alone: what it produces is a pre-pass the agent's own SAST pass then
    # triages, so its sentences read after everything the deterministic half
    # settled by itself.
    sast_findings, sast_notes, sast_producer = _scan_sast(root, args.offline,
                                                          ignore)
    findings += _produced_by(sast_findings, sast_producer, produced)
    notes += [n for n in sast_notes if n]
    # Every phase writes into ONE channel, in phase order. The reader gets one
    # paragraph naming every blind spot this analysis has, rather than
    # whichever gap the last phase to speak happened to know about.
    note = " ".join(notes)

    if sbom_document is not None:
        ledger.store_sbom(conn, project, repo, branch, aid, sbom_document)
    for f in findings:
        ledger.record_finding(conn, aid, f)
    ledger.set_lines_of_code(conn, aid, tree_lines)

    conn.execute("UPDATE analysis SET coverage_note=? WHERE id=?", (note, aid))
    conn.commit()
    # LAST, and not before the writes above: `prepared` is what lets `finish`
    # record `done`, and it must mean "the deterministic phases ran and their
    # findings are in the ledger", not "prepare was invoked and then fell over
    # halfway".
    #
    # `produced` goes down in the SAME statement, for the same reason one step
    # on: it is what the next analysis of this branch reads to decide whether
    # any of these findings' absence can ever be proven, and an analysis
    # marked prepared with an empty `produced` would report its whole
    # deterministic baseline `pending` for ever.
    ledger.mark_prepared(conn, aid, produced)
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

    The same door as `report-finding`'s SAST-rule gate, saying the same
    thing at the same time. Without this, an agent asks for a fingerprint
    for `sqli`, gets back 64 well-formed hex characters, and only discovers
    the rule is invalid when `report-finding` refuses it -- after the rest
    of the payload has already been built around an identity it can never
    store. `--category` is validated by argparse's `choices=` before this
    function ever runs; `--rule` is free text for every category (deterministic
    rule names come from our own scanners, not from a vocabulary written for
    the agent), so only the `sast` branch is checked here, exactly as
    `cmd_report_finding` checks it only for that category.
    """
    if args.category == "sast" and not taxonomy.is_valid_rule(args.rule):
        # See `_refuse_unknown_sast_rule`: it scans `args.rule` for a live
        # credential before quoting it back, for the reason
        # `_refuse_if_secret`'s docstring gives for gating `report-finding`'s
        # `category` and `rule` before their own refusals quote them --
        # echoing a secret back to refuse it would defeat the refusal by
        # writing it to disk anyway. This verb's stderr lands in the same
        # run log `report-finding`'s does, so the same care applies here.
        _refuse_unknown_sast_rule("fingerprint", args.rule, tail=".")
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
        stdin_text = sys.stdin.read()
    except Exception as exc:
        sys.exit(f"report-finding: could not read stdin: {exc}")

    if len(stdin_text.encode('utf-8')) > MAX_STDIN_BYTES:
        sys.exit(f"report-finding: stdin is {len(stdin_text.encode('utf-8'))} bytes "
                 f"and the limit is {MAX_STDIN_BYTES}")

    try:
        payload = json.loads(stdin_text)
    except (ValueError, RecursionError) as exc:
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
    # `category` and `rule` are QUOTED BACK by the two refusals below, and
    # neither field is in TEXT_KEYS, so neither has been through the scanner
    # the free-text fields go through. `report-finding`'s stderr is kept in
    # the run log: an agent that pasted a credential into one of these would
    # have the refusal itself write the secret to disk -- precisely what
    # `_refuse_if_secret`'s own docstring forbids ("the message names the
    # FIELD and the RULE, never the text that matched"). Scanning them HERE,
    # before either gate can quote one, also keeps a credential out of the
    # stored `rule` column: `rule` is agent-written for EVERY category, the
    # deterministic ones included, so "cannot leak by construction" was only
    # ever true of the columns, never of this one.
    _refuse_if_secret("report-finding: category", payload["category"])
    _refuse_if_secret("report-finding: rule", payload["rule"])
    # The category decides which of the two rule regimes below applies, and
    # an exact `== "sast"` on unvalidated text is one character away from
    # skipping the vocabulary altogether: `"Sast"`, `"sasT"` or `"sast "`
    # used to fall through to the `else` branch and land a free-text rule
    # with a blank classification in the ledger -- the identity instability
    # the vocabulary exists to prevent, reached by the one route around it.
    # The quoted value is what makes a whitespace typo visible; it is safe to
    # quote because the scan above has already cleared it.
    if payload["category"] not in FINDING_CATEGORIES:
        sys.exit(f"report-finding: {payload['category']!r} is not a finding "
                 "category. The category is part of the fingerprint and of "
                 "every filter the screens offer, so a second spelling of one "
                 "is a second identity nothing can select. Use one of: "
                 + ", ".join(FINDING_CATEGORIES))
    # SAST only. Deterministic rule names come from our own scanners, not
    # from a vocabulary written for the agent (`cmd_fingerprint`'s own
    # comment, above, says the same thing at the same door): secrets._RULES
    # and hygiene's literals are OUR OWN vocabulary, while the OSV advisory
    # id and Trivy's iac check id are a vendor's, echoed verbatim -- but none
    # of the four is agent-supplied, so forcing any of them through a gate
    # meant for the agent's free-text rule would refuse findings this
    # program itself produced. `cwe`/`owasp` are DERIVED from the rule,
    # never accepted from the payload -- an agent that could send its own
    # would end up with a CWE that disagrees with the rule beside it, two
    # sources of truth in one row.
    if payload["category"] == "sast":
        if not taxonomy.is_valid_rule(payload["rule"]):
            _refuse_unknown_sast_rule("report-finding", payload["rule"],
                                       tail=", and say why in the rationale.")
        payload["cwe"], payload["owasp"] = taxonomy.classify(payload["rule"])
    else:
        payload["cwe"] = payload["owasp"] = ""
    for key in TEXT_KEYS:
        value = payload.get(key)
        if not isinstance(value, str):
            continue
        if len(value) > MAX_TEXT:
            sys.exit(f"report-finding: {key} is {len(value)} characters and the "
                     f"limit is {MAX_TEXT} — a finding is a paragraph the report "
                     "page renders, not a file to paste into the ledger")
        # `looks_like_a_secret` runs the scanner's own shaped patterns (and
        # its placeholder gate) against this field; a match is refused here,
        # before `record_finding` ever sees it. Shared with `finish --note`,
        # the twin channel that had no such gate -- see `_refuse_if_secret`'s
        # own docstring for why the guard belongs to both doors and not to
        # this one alone.
        _refuse_if_secret(f"report-finding: {key}", value)
    occurrences = payload.get("occurrences", [])
    if not isinstance(occurrences, list) or any(
            not isinstance(o, dict) for o in occurrences):
        sys.exit("report-finding: occurrences must be a list of objects")
    # NEVER read from the payload -- `producer` is not an agent-writable
    # field, it is this door's own record of who arrived through it. An agent
    # able to send its own would be able to claim a deterministic producer for
    # a finding it invented, and `diff._proven` reads that column to decide
    # what absence proves. On a RE-REPORT this is discarded anyway
    # (`record_finding` leaves the column alone for a fingerprint the analysis
    # already holds), so it only ever lands on a finding the agent genuinely
    # minted -- which is exactly what `diff.AGENT` is proven by: the analysis
    # closing `done`.
    payload["producer"] = diff.AGENT
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
    # Before the ledger is even opened, the same moment `report-finding`
    # refuses its own four free-text fields: `--note` is written verbatim
    # into `coverage_note`, which reaches all four report formats
    # (`report.py`'s `_coverage`) and the analysis page's own notice, and it
    # is agent-writable -- `finish` is deliberately NOT in AGENT_FORBIDDEN.
    # It was the one such channel with no gate on it while its near-twin
    # `partial_note` had one. See `_refuse_if_secret`.
    _refuse_if_secret("finish: --note", args.note)
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
            "sweep, no dependency inventory, no hygiene pass, no "
            "infrastructure-as-code check, no SAST pre-pass. Nothing here was "
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
    # `row`'s own project and branch, never a flag the caller passed: `finish`
    # has two callers and neither one necessarily agrees with the row about
    # what it is closing, so the event has to come from the row itself.
    try:
        ledger.record_event(conn, row["project"], "analysis_finished",
                            f"{state} · {row['profile']} on {row['branch']}",
                            str(args.analysis))
    except sqlite3.Error:
        # Best-effort, same reasoning as cmd_open_analysis: finish_analysis
        # above already closed the row with its real verdict and spend, and
        # this function has no stdout of its own to lose -- but a busy
        # ledger must not turn a successful close into an unhandled
        # traceback either. "analysis_finished" is a literal, so this cannot
        # hide a typo'd kind.
        pass


def cmd_checklist(args):
    conn = _conn(args)
    try:
        analysis, findings = queries.checklist(conn, args.analysis)
    except queries.AnalysisNotFound as e:
        sys.exit(str(e))
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
    try:
        analysis, findings = queries.checklist(conn, args.analysis)
    except queries.AnalysisNotFound as e:
        sys.exit(str(e))
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
    # The SAME shape check `report-finding` enforces on a written
    # fingerprint, and for the same reason -- this is the identity a decision
    # is keyed to, and a value that no finding can ever carry is a decision
    # that can never apply to anything. Refused BEFORE the ledger is opened,
    # because the damage is not the useless decision row: `record_event`
    # below files a `decision_made` reading "Accepted: risk accepted for Q3"
    # into the one artifact whose whole job is to say what actually happened,
    # so Activity tells the operator the risk was accepted while the finding
    # stays open on every screen. The server's own route checked non-empty
    # and nothing else; it now applies the identical regex, but a human (or
    # the agent) reaching this verb directly has no route in front of them.
    if not FINGERPRINT_RE.match(args.fingerprint or ""):
        sys.exit("decide: fingerprint must be 64 lowercase hex characters "
                 "(sha256) — it is the identity a finding is matched on, and "
                 "a decision recorded against anything else applies to no "
                 "finding while the audit trail says it was decided")
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
    try:
        ledger.record_event(conn, args.project, "decision_made",
                            f"{DECISION_LABEL.get(args.state, args.state)}: "
                            f"{args.reason}", args.fingerprint[:12])
    except sqlite3.Error:
        # Best-effort, same reasoning as cmd_open_analysis and cmd_finish:
        # the decision above is already recorded; a ledger hiccup filing its
        # event must not turn a successful decision into a traceback.
        # "decision_made" is a literal, so this cannot hide a typo'd kind.
        pass


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


def cmd_migrate_rules(args):
    """Apply `taxonomy.RULE_RENAMES` to the ledger. Safe to run twice.

    A rule name is part of a finding's fingerprint, so renaming one in the
    scanner without moving the history behind it reports every finding under
    the old name as `fixed` AND `new` in the same report, and strands every
    human decision on an identity nothing will ever produce again. This verb
    is how the two are kept in step: the scanner changes the name, the map
    records that the two names are one rule, and this walks the ledger.

    Every entry's CATEGORY is checked before any of the map is applied, and
    that check alone is all-or-nothing: it needs nothing from the ledger, so an
    entry naming a category `rename_rule` refuses is caught before the first
    row moves rather than after the entries above it have already committed.

    Refused, for the same all-or-nothing reason, on a machine where
    `adapters.engine_path("gitleaks")` is falsy while the map holds a `secret`
    entry -- the binary absent, or the engines switched off with
    `CC_SECURITY_ENGINES`. Every secret rename moves findings from the built-in
    pattern scanner's snake_case names to gitleaks' kebab-case ones, and
    `_scan_secrets` runs the built-in scanner on exactly the machines this
    check catches. Migrating there does not merely fail to help: the next
    analysis re-mints every old name, so each secret is reported `fixed` (the
    migrated row, under a name nothing produced) AND `new` (the re-minted one)
    in one report, and both human decisions strand -- which is the precise
    failure this verb exists to prevent, reached through its own front door.

    THE REST IS NOT. `rename_rule` wraps each entry in its own transaction, and
    the two failures it can only discover while walking -- a finding with no
    path (`ValueError`) and a new fingerprint that collides with one the same
    analysis or project already holds (`IntegrityError`) -- fire mid-map. The
    failing entry itself rolls back whole, but the entries applied BEFORE it
    stay applied: this verb is atomic per entry, not per map. That is why the
    refusal below names them rather than counting them, and why a failed run
    means "read the message and fix the map", never "nothing happened".
    Pre-flighting those two would mean doing the walk to find out, which is the
    thing that cannot be undone.

    Refused while ANY analysis in the ledger is `running`, for `cmd_decide`'s
    reason applied to a bigger blast radius. `decide` writes one row keyed to
    an identity; this REWRITES identities, and mid-analysis that lands under an
    agent still holding the old ones: findings it already reported get new
    fingerprints, its re-report of one then misses the `(analysis_id,
    fingerprint)` upsert key and INSERTs a second row instead, and one hole
    becomes two contradictory checklist entries -- which is the exact outcome
    that UNIQUE constraint exists to prevent. Not scoped to a project, unlike
    `decide`'s: this verb takes no project and walks every row in the ledger,
    so any live analysis anywhere is a live analysis this could pull the ground
    out from under. A `running` row left by a run that died is not a permanent
    lock: the engine's preflight sweep closes those before it opens the next
    analysis of that project (see `cmd_security_analyze` in `bin/claude-cron`).

    Deliberately absent from AGENT_FORBIDDEN: it takes no arguments. Unlike
    `decide` or `rename-project`, there is no target for a caller to choose --
    it can only ever apply the map the repository itself declares, so an agent
    running it produces exactly what a human running it produces. The guard
    above is what actually covers the agent case, and it does not depend on the
    environment variable to do it.
    """
    renames = [(category, old, new)
               for (category, old), new in taxonomy.RULE_RENAMES.items()]
    for category, old, _new in renames:
        if category not in ledger.RENAMEABLE_CATEGORIES:
            sys.exit(f"migrate-rules: {category}/{old} cannot be migrated — "
                     "a rename is only possible where the fingerprint can be "
                     "rebuilt from what the ledger stores, which is "
                     + ", ".join(ledger.RENAMEABLE_CATEGORIES)
                     + " (see ledger.rename_rule). Nothing was migrated.")
    # Asked before the ledger is opened, like the category check above and for
    # the same reason: it needs nothing from the ledger, so it refuses before
    # the first row moves rather than halfway down the map.
    if any(category == "secret" for category, _old in taxonomy.RULE_RENAMES) \
            and not adapters.engine_path("gitleaks"):
        sys.exit("migrate-rules: gitleaks is not available here — the secret "
                 "renames move findings onto ITS rule names, and without it "
                 "the next analysis falls back to the built-in scanner and "
                 "mints the old names again. Every migrated secret would then "
                 "be reported fixed AND new in the same report, with both "
                 "human decisions stranded. Install gitleaks (and leave "
                 "CC_SECURITY_ENGINES on) before migrating; nothing was "
                 "migrated.")
    conn = _conn(args)
    live = conn.execute(
        "SELECT id, project FROM analysis WHERE state='running' "
        "ORDER BY id ASC LIMIT 1").fetchone()
    if live is not None:
        sys.exit(f"migrate-rules: analysis {live['id']} of '{live['project']}' "
                 "is still running — this rewrites the fingerprints of findings "
                 "that analysis has already recorded, while the agent is still "
                 "holding the old ones. Its next re-report of one would miss "
                 "the upsert key and file a SECOND row for the same hole. Wait "
                 "for the run to end; nothing was migrated.")
    applied, total = [], 0
    for category, old, new in renames:
        try:
            moved = ledger.rename_rule(conn, category, old, new)
        except (ValueError, sqlite3.Error) as exc:
            # Same doctrine as `report-finding`: a sentence on stderr, not a
            # traceback. `rename_rule` rolled its own transaction back, so the
            # entry that failed changed nothing -- but entries BEFORE it in the
            # map committed, and the operator has to be told WHICH, not how
            # many: a count sends them to diff the ledger against a map to work
            # out where it stopped. Entries that moved 0 findings are absent
            # because they changed nothing there is anything to undo.
            done = "; ".join(f"{a['category']}/{a['from']} -> {a['to']} "
                             f"({a['findings']} finding(s))" for a in applied)
            sys.exit(f"migrate-rules: {category}/{old} -> {new} failed: {exc}"
                     + (f" — ALREADY APPLIED and not rolled back: {done}"
                        if applied else " — nothing had been applied yet."))
        if moved:
            applied.append({"category": category, "from": old, "to": new,
                            "findings": moved})
        total += moved
    print(json.dumps({"renamed": applied, "findings": total}))


def cmd_list(args):
    rows = _conn(args).execute(
        "SELECT * FROM analysis WHERE project=? ORDER BY id DESC LIMIT 100",
        (args.project,)).fetchall()
    print(json.dumps([dict(r) for r in rows], indent=2))


def cmd_analysis(args):
    """The analysis row alone, as JSON, and nothing computed from it.

    `security_report`'s `report_exported` lookup used to read the whole
    `checklist` verb purely to reach `analysis.project` -- which runs two
    `findings_of` calls, a `latest_analysis` query, a history query across
    every prior analysis of the branch, and `decisions_for`, all to read one
    string. This verb is the row and only the row.

    Read-only, so it is allowed under CC_SECURITY_AGENT (see AGENT_FORBIDDEN)
    exactly like `findings`, `list` and `checklist` itself.
    """
    conn = _conn(args)
    row = _analysis(conn, args.id)
    print(json.dumps(dict(row)))


def cmd_index_data(args):
    """Every panel the Security index screen draws, in one call.

    `--projects` is a JSON array of `{name, base, description}` -- read from
    projects.json by the server (this file never touches that path) and
    handed here so `project_rows` has the two things the ledger does not
    know about a project: its declared base branch and its description.

    Read-only, via `queries.read_only`, deliberately NOT `ledger.connect`:
    the latter creates the ledger's schema on first use, and a screen that
    is only ever LOOKING must not conjure the file it is asking about into
    existence. `read_only` returning None is "nobody has ever run an
    analysis" -- answered here as the same empty-but-shaped document a real
    ledger with nothing in it would produce, never a crash and never a
    partially-written database file as a side effect of a page load.

    `recent`, `donut` and `categories` are scoped to `--projects` exactly as
    `summary` and `projects` are: a project disabled or removed from
    projects.json used to still surface in these three panels even though
    `summary`/`projects` already say it does not exist -- the same ledger
    `security list`/`security checklist` read without a project filter of
    their own, but this is a screen about the fleet AS CONFIGURED, not an
    unscoped activity log.

    `--days` (default 30, the mockup's own "Last 30 days") is the Findings-
    overview card's own period, passed straight to `severity_totals`/
    `top_categories` -- see their own docstrings for what a real window
    means now. `--recent-page` (default 1) pages `recent_analyses` server-
    side, five analyses at a time -- see that function's own docstring for
    why paging there rather than shipping more rows and slicing client-side.
    """
    try:
        projects = json.loads(args.projects)
    except (ValueError, RecursionError) as exc:
        sys.exit(f"index-data: --projects is not valid JSON: {exc}")
    if not isinstance(projects, list) or any(not isinstance(p, dict) for p in projects):
        sys.exit("index-data: --projects must be a JSON array of objects")

    conn = queries.read_only(args.db)
    if conn is None:
        print(json.dumps({
            "summary": {"projects": len(projects), "analyses": 0, "critical": 0,
                       "high": 0, "capped_projects": 0, "fell_back_projects": 0,
                       "success_rate": None},
            "projects": [{
                "name": p.get("name", ""), "description": p.get("description", ""),
                "branch": p.get("base", "") or "", "branch_fell_back": False,
                "posture": queries._empty_posture(), "profile": "",
                "last_started": 0, "last_duration": 0, "last_state": "",
                "analyses": 0, "trend": [],
            } for p in projects],
            "recent": {"rows": [], "total": 0},
            "donut": queries._empty_posture(), "categories": []}))
        return

    names = [p.get("name", "") for p in projects]
    recent_page = max(1, int(args.recent_page))
    print(json.dumps({
        # `projects`, NOT `names`. `index_summary` and `project_rows` both
        # pick a project's branch through `default_branch_posture`, which
        # needs the declared base to pick it -- handing one half of the
        # screen the dicts and the other half only the names made the cards
        # ALWAYS fall back while the table honoured the base, so the two read
        # different branches for the same project and disagreed in public.
        # See `queries.index_summary`'s own docstring.
        "summary": queries.index_summary(conn, projects),
        "projects": queries.project_rows(conn, projects),
        "recent": queries.recent_analyses(
            conn, limit=5, offset=(recent_page - 1) * 5, projects=names),
        "donut": queries.severity_totals(conn, project=names, days=args.days),
        "categories": queries.top_categories(conn, project=names, days=args.days),
    }))


def _empty_checklist_counts():
    """One zeroed entry per state `checklist()` can ever produce -- the eight
    values `diff.classify` (DERIVED_STATES) and `ledger.set_decision`
    (DECISION_STATES) between them, and nothing else, so a state added to
    either later shows up here too without this function changing."""
    return {s: 0 for s in diff.DERIVED_STATES + ledger.DECISION_STATES}


def cmd_project_data(args):
    """Every panel the project detail screen draws, in one call.

    `--base` and `--default-profile` are read from projects.json by the server
    (this file never touches that path) and handed here the same way
    `index-data`'s `--projects` carries each project's own base and
    description -- the ledger has no notion of a project's declared
    configuration, only of what has been recorded under its name.

    Read-only, via `queries.read_only`, deliberately NOT `ledger.connect`, for
    the same reason `index-data` uses it: a screen that only ever LOOKS must
    not conjure the ledger file it is asking about into existence.

    The header's `branch`/`lines_of_code`/`last_analysis` and the Overview
    tab's posture and checklist counts all come from the SAME analysis row --
    `default_branch_posture`'s own `latest`, the latest FINISHED analysis of
    the branch actually shown (the project's declared base, or the branch it
    fell back to) -- so the numbers on this screen never describe two
    different runs under one label. The second `queries.checklist()` call
    below, for the same id `posture()` already read through
    `default_branch_posture`, is a cache hit on the read-only connection (see
    `_CachingConnection`), not a second pass over the ledger.

    That one-branch posture is not the WHOLE story, though: `sidebar.donut`/
    `categories` roll up EVERY analysed branch (see `severity_totals`'s own
    docstring), a different, equally true answer to a different question --
    which is why `sidebar.branch_count` is handed back too, so the page can
    say how many branches its own numbers span rather than let the two
    panels' different totals read as a silent disagreement (a two-branch
    project's Overview and sidebar used to show different postures with
    nothing on screen saying why).

    `tabs.runs` is exactly `cmd_list`'s own query -- same table, same
    ordering, same LIMIT -- so the Runs tab can be checked against
    `claude-cron security list --project <name>` directly. Each row's
    `findings` count is a plain `COUNT(*)` from `finding_counts_by_analysis`
    -- ONE grouped query for the whole table, not `checklist()`'s diff/
    decision machinery run once per row. That used to cost one `checklist()`
    call (`findings_of` twice, a history scan, `decisions_for`) per
    done/capped analysis -- 169 SQL statements for Minerva's own ledger (two
    finished analyses, 108 findings total) before this fix, re-run from
    scratch by the page's own 4-second poll for the whole duration of every
    live analysis. See `.superpowers/sdd/task-9-report.md` for the measured
    before/after. `findings` still follows `recent_analyses`'s own gating
    rule -- only a `done` or `capped` analysis gets a number, a `running` or
    `failed` one gets `None`, the same "nothing to report yet" the index's
    recent-analyses feed already sends -- but the number itself is no longer
    an `is_open` filter over `checklist()`'s output: it is how many findings
    THIS analysis recorded, a fact that cannot change when a later run's
    decision resolves one of them (the Overview's `checklist` counts above
    are still where "currently open" belongs). `findings_by_severity` is that
    same total's own breakdown (`queries.finding_severity_by_analysis`),
    gated identically -- the Runs tab's per-row "64C 4H 3M 0L" sub-line, one
    more grouped query for the whole table rather than a second pass per row.

    `tabs.overview.attempted` is true the moment ANY analysis of this project
    exists, in any state -- distinct from `state` (empty unless a done/capped
    baseline exists), so the page can tell "never attempted" apart from
    "attempted, nothing has finished yet" instead of showing "Never
    analysed" over a Runs tab that plainly lists failed or running attempts.
    `header.last_analysis` gets the same treatment: it falls back to the most
    recent analysis of ANY state when there is no finished baseline, so a
    project whose only analyses failed shows when that happened rather than
    reading as if nothing had ever run.

    `tabs.branches` is exactly `queries.branch_rows`'s own rows -- one entry
    per branch that has EVER been analysed, not only the one `header`/
    `tabs.overview` show. Each row's `open` is that branch's OWN posture
    (`queries.posture`, the identical computation `default_branch_posture`
    ran for the header's one branch above) -- a different scope from
    `sidebar.donut`, which collapses every analysed branch's open findings
    into one count per FINGERPRINT project-wide (see
    `_open_findings_by_fingerprint`'s own docstring). A finding open on both
    `main` and `develop` is one problem there and two rows here contributing
    to it -- the Branches tab has to say so itself, the same way the
    Overview caption and the sidebar caption already name what THEIR two
    numbers each count.

    `tabs.reports` gathers the four downloads (Markdown, JSON, HTML, SBOM)
    that used to be reachable only from whichever single analysis happened
    to be on screen, one row per analysis. It is a plain projection of the
    `runs` rows already fetched above -- analysis id, branch, started, state
    -- not a second `SELECT * FROM analysis`, the same reuse-what-is-already-
    in-hand rule `finding_counts_by_analysis` applied to the Runs tab itself.
    A running or failed analysis still gets a row: the single-analysis view's
    own download buttons are shown for any state (see `secPaint`), and this
    tab is that same door, just gathered into one table instead of scattered
    one analysis at a time.
    """
    default_profile = args.default_profile or "standard"
    conn = queries.read_only(args.db)
    if conn is None:
        print(json.dumps({
            "project": args.project,
            "header": {"profile": default_profile, "branch": args.base or "",
                       "branch_fell_back": False, "lines_of_code": 0,
                       "last_analysis": 0},
            "tabs": {"overview": {"posture": queries._empty_posture(),
                                  "checklist": _empty_checklist_counts(),
                                  "state": "", "attempted": False,
                                  "trend": [], "previous": None,
                                  "categories": [], "top_findings": []},
                     "runs": [], "branches": [], "reports": []},
            "sidebar": {"donut": queries._empty_posture(), "categories": [],
                       "activity": [], "branch_count": 0,
                       "capped_branches": 0}}))
        return

    branch, posture, fell_back, latest = queries.default_branch_posture(
        conn, args.project, args.base or None)

    # The Overview tab's own cards beyond the posture row (ProjectOverview.png):
    # `categories` and `top_findings` are projections of the SAME checklist
    # already fetched for `checklist_counts` -- one branch, the same scope as
    # `posture` above, so the KPI total, the category donut's centre and the
    # Top findings rows can never disagree about what they count. `previous`
    # is that same posture computed one finished analysis earlier, for the
    # "vs. previous analysis" delta -- None (not an empty posture) when there
    # is no previous analysis, so the page can say "no previous analysis"
    # instead of rendering a 0% delta nothing was compared against.
    checklist_counts = _empty_checklist_counts()
    overview_categories = []
    top_findings = []
    previous = None
    if latest is not None:
        _analysis, findings = queries.checklist(conn, latest["id"])
        for f in findings:
            if f["state"] in checklist_counts:
                checklist_counts[f["state"]] += 1
        open_findings = [f for f in findings if queries.is_open(f["state"])]
        buckets = {}
        for f in open_findings:
            b = buckets.setdefault(f.get("rule") or "", {
                "rule": f.get("rule") or "", "category": f.get("category") or "",
                "count": 0})
            b["count"] += 1
        overview_categories = sorted(
            buckets.values(), key=lambda b: (-b["count"], b["rule"]))[:5]
        # Severity rank first, then newest first-seen -- "top" means "most
        # severe, then most recently introduced", the same rank order the
        # findings browser's own severity sort uses. `first_seen` comes from
        # the same shared map `finding_rows` reads, so this card and the
        # browser one tab over can never date the same finding differently.
        first_seen = queries.first_seen_map(conn, args.project)
        top = sorted(open_findings, key=lambda f: (
            queries._SEV_RANK.get(f.get("severity"), 99),
            -(first_seen.get(f.get("fingerprint", ""), 0) or 0)))[:5]
        for f in top:
            occ = f.get("occurrences") or []
            first = occ[0] if occ else {}
            top_findings.append({
                "fingerprint": f.get("fingerprint", ""),
                "severity": f.get("severity", ""),
                "title": f.get("title") or "",
                "rule": f.get("rule") or "",
                "category": f.get("category") or "",
                "file": first.get("file", ""),
                "line": first.get("line", 0) or 0,
                "more": max(0, len(occ) - 1),
                "analysis_id": latest["id"],
                "profile": latest.get("profile", ""),
                "first_seen": first_seen.get(f.get("fingerprint", ""), 0),
            })
        prev_row = queries.previous_finished(conn, args.project, branch, latest["id"])
        if prev_row is not None:
            previous = queries.posture(conn, args.project, branch, latest=prev_row)

    # ONE grouped query for the whole Runs tab, replacing what used to be one
    # checklist() call per done/capped row (see this function's own
    # docstring, and queries.finding_counts_by_analysis's). A second grouped
    # query alongside it -- finding_severity_by_analysis -- for the Runs
    # tab's own per-severity sub-line under each row's total (the mockup's
    # "64C 4H 3M 0L", shown for every row, not only the one on screen): that
    # breakdown is not derivable from anything already fetched here, and it
    # is genuinely a second question ("how many of each severity" vs "how
    # many"), not a reshape of the first -- see that function's own
    # docstring for why it is not folded into finding_counts_by_analysis
    # instead. Still O(1) round trips, never O(analyses).
    finding_counts = queries.finding_counts_by_analysis(conn, args.project)
    finding_severities = queries.finding_severity_by_analysis(conn, args.project)
    runs = []
    for row in conn.execute(
            "SELECT * FROM analysis WHERE project=? ORDER BY id DESC LIMIT 100",
            (args.project,)):
        r = dict(row)
        # Exactly `recent_analyses`'s own rule (see its comment): a running or
        # failed analysis has nothing to report here yet -- not because
        # counting its findings would be expensive (a grouped COUNT(*) never
        # was), but because a run that has not closed cleanly has not
        # finished recording them. `findings_by_severity` follows the exact
        # same gate as `findings` for the exact same reason -- one is the
        # other's own breakdown, so a row that does not get a total yet must
        # not get a partial-looking breakdown either.
        done = r["state"] in ("done", "capped")
        r["findings"] = finding_counts.get(r["id"], 0) if done else None
        r["findings_by_severity"] = finding_severities.get(r["id"], {}) if done else None
        runs.append(r)

    # A thin projection of the `runs` rows above -- not a second pass over
    # `analysis` -- into just what the Reports tab's downloads need. See this
    # function's own docstring for why a row survives for every state.
    reports = [{"analysis_id": r["id"], "branch": r["branch"],
               "started": r["started"], "state": r["state"],
               "profile": r["profile"]} for r in runs]

    print(json.dumps({
        "project": args.project,
        "header": {"profile": default_profile, "branch": branch,
                   "branch_fell_back": fell_back,
                   "lines_of_code": (latest or {}).get("lines_of_code", 0),
                   "last_analysis": (latest or {}).get("started", 0)
                                    or (runs[0]["started"] if runs else 0)},
        "tabs": {"overview": {"posture": posture, "checklist": checklist_counts,
                              "state": (latest or {}).get("state", ""),
                              "attempted": bool(runs),
                              # 7 days, fixed: ProjectOverview.png's own
                              # trend card reads "over the last 7 days" --
                              # the SHOWN branch (fell back or not; the
                              # header names it), unlike `trend_series`,
                              # which never falls back because a bare
                              # sparkline has nowhere to say so.
                              "trend": (queries.trend(conn, args.project,
                                                      branch, days=7)
                                        if branch else []),
                              "previous": previous,
                              "categories": overview_categories,
                              "top_findings": top_findings},
                 "runs": runs,
                 "branches": queries.branch_rows(conn, args.project),
                 "reports": reports},
        # `days=0`: explicitly the as-of-now posture severity_totals/
        # top_categories still default to, stated here rather than left
        # implicit -- this sidebar is a DIFFERENT screen from the index's own
        # Findings-overview card (which asks for a real window,
        # `cmd_index_data`'s own `--days`) and must never drift onto that
        # card's window just because the shared function's default changed
        # under it.
        "sidebar": {"donut": queries.severity_totals(conn, project=args.project, days=0),
                   "categories": queries.top_categories(conn, project=args.project, days=0),
                   "activity": ledger.events_for(conn, project=args.project, limit=5),
                   "branch_count": queries.analysed_branch_count(conn, args.project),
                   # The donut rolls every analysed branch into one number,
                   # so it cannot carry the per-row `incomplete` badge the
                   # Overview panel and the index table already use. This is
                   # that same cue as a count: how many of the branches
                   # behind it were only read partially.
                   "capped_branches": queries.capped_branch_count(conn, args.project)}}))


def cmd_findings_page(args):
    """Every row the findings browser draws, for one project, plus that
    project's saved filters in the same payload -- the page that draws the
    filter bar's own picker needs both in one round trip, the same reasoning
    `index-data`/`project-data` already bundle a whole screen's panels into
    one call rather than one subprocess per panel.

    Filters travel as repeated flags, not a JSON body: `queries.finding_rows`'s
    own `filters` dict has a small, fixed set of keys (show_resolved,
    severity, state, category, branch, analysis, path, q, fingerprint) --
    unlike a SAVED
    filter (see `cmd_filters`'s own docstring), which is arbitrary,
    human-curated criteria this door must not have to keep in step with by
    hand as the page grows more of them.

    `sort`/`direction` are validated twice over by the time a bad value could
    reach here -- the server's own route (`security_findings` in
    bin/claude-cron-server) already refuses one before ever shelling out --
    but `queries.finding_rows` raises on an out-of-band value regardless of
    who calls this verb (a human at the command line has no such route in
    front of them), and that raise is caught here and turned into the same
    sentence-on-stderr every other verb in this file gives a bad argument,
    rather than a stack trace. `severity`/`state`/`category` get the same
    treatment from argparse's own `choices=`; `fingerprint` cannot (it is a
    prefix, not a closed set of values), so it gets its own shape check
    against FINGERPRINT_PREFIX_RE, refusing a mistyped value with a sentence
    rather than silently returning zero rows -- a human at the command line
    has no route in front of them doing this either.

    Read-only, via `queries.read_only`, deliberately NOT `ledger.connect` --
    same reasoning as `index-data`/`project-data`: a screen that only LOOKS
    must not conjure the ledger file it is asking about into existence.
    """
    # Shape-checked here, before the database is even opened -- the same
    # moment `--severity`/`--state`/`--category` are refused, by argparse's
    # own `choices=`, for a value it does not recognise. `--fingerprint`
    # cannot use `choices=` (it is a prefix, not a closed set), so this is
    # its equivalent: a value that does not match FINGERPRINT_PREFIX_RE is a
    # mistake worth a sentence, not a filter the query below would silently
    # match zero rows against.
    if args.fingerprint and not FINGERPRINT_PREFIX_RE.match(args.fingerprint):
        sys.exit(f"findings-page: fingerprint must be lowercase hex, got {args.fingerprint!r}")

    conn = queries.read_only(args.db)
    if conn is None:
        print(json.dumps({
            "rows": [], "total": 0, "unique": 0,
            "by_severity": {s: 0 for s in report.SEVERITIES},
            "fixed_by_severity": {s: 0 for s in report.SEVERITIES},
            # No ledger file at all is the strongest possible "never
            # analysed": the browser must draw that, not the ok-green
            # "nothing matches" it used to (see `finding_rows`'s docstring).
            "attempted": False, "analysed": False, "capped_branches": 0,
            "branches": [], "analyses": [],
            "page": max(1, args.page),
            "per_page": max(1, min(args.per_page, queries.MAX_PER_PAGE)),
            "filters": []}))
        return
    filters = {
        "show_resolved": args.show_resolved,
        "severity": args.severity or [],
        "state": args.state or [],
        "category": args.category or [],
        "branch": args.branch or [],
        "analysis": args.analysis or [],
        "path": args.path,
        "q": args.q,
        "fingerprint": args.fingerprint,
    }
    try:
        result = queries.finding_rows(conn, args.project, filters,
                                      sort=args.sort, direction=args.direction,
                                      page=args.page, per_page=args.per_page)
    except ValueError as exc:
        sys.exit(f"findings-page: {exc}")
    result["filters"] = ledger.saved_filters(conn, args.project)
    print(json.dumps(result))


# Stands in for "no lower bound" (`--since 0`, `ledger.events_for`'s own
# default) when it has to be converted into a NUMBER OF DAYS for
# `queries.activity_summary`, whose signature this verb must call as-is --
# see cmd_activity_data's own docstring. Large enough that no real ledger
# (this feature has not shipped long enough for one) predates it.
_ACTIVITY_ALL_TIME_DAYS = 36500


def cmd_activity_data(args):
    """Every panel the Activity screen draws, in one call: the events
    `ledger.events_for` (Task 3) returns for the period and kind(s) asked,
    the per-kind counts `queries.activity_summary` (Task 5) gives the SAME
    period, and which projects were busiest in it.

    `kind` narrows the EVENTS list only. `project` narrows all three: a
    filter to one project's own history is a real change of scope, but
    filtering the table to (say) the Analyses tab must not also zero out
    the sidebar's Findings/Settings counts -- the sidebar's whole point is
    "here is the period, every kind", beside a table showing one slice of
    it. Splitting the two follows this file's own rule for two numbers on
    one screen that answer different questions (see `finish`'s stored-note
    handling): label what each one counts rather than force them to agree.

    `--since` follows `ledger.events_for`'s own contract: 0 means no lower
    bound. The screen itself always sends a resolved timestamp (it defaults
    to a 30-day window client-side); a bare 0 only reaches this verb from a
    direct command-line call, and the summary below answers it with
    `_ACTIVITY_ALL_TIME_DAYS` rather than inventing a day count that does
    not exist. Otherwise `days` is derived from `since` so the table and the
    summary describe the identical window without a second, independently
    supplied parameter that could disagree with it.

    Read-only, via `queries.read_only`, deliberately NOT `ledger.connect` --
    same reasoning as `index-data`/`project-data`/`findings-page`: a screen
    that only LOOKS must not conjure the ledger file it is asking about into
    existence. Minerva's own ledger has recorded no events at all (the event
    log landed after its analyses ran) -- the branch below is not a
    hypothetical, it is what every project sees until its next analysis,
    decision or export.
    """
    project = (args.project or "").strip() or None
    kinds = tuple(args.kind or [])
    page = max(1, args.page)
    per_page = max(1, min(args.per_page, 500))  # ledger.events_for's own ceiling
    since = max(0, args.since)

    conn = queries.read_only(args.db)
    if conn is None:
        print(json.dumps({
            "events": [], "summary": {k: 0 for k in ledger.EVENT_KINDS},
            "projects": [], "page": page, "per_page": per_page}))
        return

    events = ledger.events_for(conn, project=project, kinds=kinds, since=since,
                              limit=per_page, offset=(page - 1) * per_page)

    days = (_ACTIVITY_ALL_TIME_DAYS if since <= 0
            else max(1, round((int(time.time()) - since) / 86400)))
    summary = queries.activity_summary(conn, project=project, days=days)

    # Which projects were busiest in the SAME window -- scoped by `project`
    # (a real filter) but never by `kind` (see this function's own
    # docstring). Not a `queries.py` helper: this is the one place in the
    # product that needs it, the same reasoning `cmd_project_data`'s own
    # `runs` loop gives for reading `analysis` directly rather than adding a
    # single-caller function to that module.
    sql = "SELECT project, COUNT(*) c FROM event WHERE at >= ?"
    sql_args = [since]
    if project:
        sql += " AND project = ?"
        sql_args.append(project)
    sql += " GROUP BY project ORDER BY c DESC, project ASC"
    projects = [{"project": r["project"], "count": r["c"]} for r in conn.execute(sql, sql_args)]

    print(json.dumps({"events": events, "summary": summary, "projects": projects,
                      "page": page, "per_page": per_page}))


def cmd_event(args):
    try:
        ledger.record_event(_conn(args), args.project, args.kind,
                            args.detail, args.related)
    except ValueError as exc:
        sys.exit(f"event: {exc}")


def cmd_events(args):
    print(json.dumps(ledger.events_for(
        _conn(args), project=args.project or None, kinds=tuple(args.kind),
        since=args.since, limit=args.limit, offset=args.offset), indent=2))


def cmd_filters(args):
    """A named set of filters per project -- one door, three actions, so the
    query is validated (and the write actions refused to the agent, see
    AGENT_FORBIDDEN) the same way everything else here is.

    `save` reads the query as a JSON object on stdin, the same shape
    `report-finding` reads its payload in -- a filter is arbitrary,
    open-ended criteria (severity, category, free text...), not a handful of
    flags this door would have to keep in step with every filter the page
    ever grows.
    """
    conn = _conn(args)
    if args.action == "list":
        print(json.dumps(ledger.saved_filters(conn, args.project), indent=2))
        return
    if args.action == "save":
        try:
            stdin_text = sys.stdin.read()
        except Exception as exc:
            sys.exit(f"filters save: could not read stdin: {exc}")

        if len(stdin_text.encode('utf-8')) > MAX_STDIN_BYTES:
            sys.exit(f"filters save: stdin is {len(stdin_text.encode('utf-8'))} bytes "
                     f"and the limit is {MAX_STDIN_BYTES}")

        try:
            query = json.loads(stdin_text)
        except (ValueError, RecursionError) as exc:
            sys.exit(f"filters save: stdin is not valid JSON: {exc}")
        if not isinstance(query, dict):
            # Same shape check `report-finding` makes on its own JSON body:
            # a bare number, `null`, a list or a string all parse cleanly and
            # are all not a query -- the page spreads this into a filter set,
            # and a non-object here reaches it unrefused.
            sys.exit("filters save: expected the query as a JSON object")
        try:
            ledger.save_filter(conn, args.project, args.name, query)
        except ValueError as exc:
            sys.exit(f"filters save: {exc}")
        return
    # delete
    deleted = ledger.delete_filter(conn, args.project, args.name)
    print(json.dumps({"deleted": deleted}))


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
    # `choices=` for the same reason `report-finding` validates the identical
    # field: this verb MINTS the identity that verb then stores, and
    # `cmd_fingerprint` branches on `args.category == "secret"` exactly as
    # narrowly. A category the door would refuse must not be able to produce
    # a fingerprint here first -- the agent would compute an identity it can
    # never report under.
    fp.add_argument("--category", required=True, choices=FINDING_CATEGORIES)
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

    # No flags at all, deliberately -- and that is also why it is absent from
    # AGENT_FORBIDDEN: the migration it applies is `taxonomy.RULE_RENAMES`,
    # declared in this repository's own source. A `--from`/`--to` pair here
    # would turn a replayable, reviewed migration into an arbitrary rewrite of
    # any finding's identity, which is a thing `decide` and `rename-project`
    # are refused the agent for being.
    # The one `description` in this parser, because this is the one verb whose
    # PRECONDITION an operator has to know before typing it. The other verbs
    # refuse a bad call; this one refuses a bad MACHINE, and the reason is not
    # guessable from the name.
    mgr = sub.add_parser(
        "migrate-rules", parents=[dbflag],
        description="Apply taxonomy.RULE_RENAMES to the ledger. Takes no "
                    "arguments and is safe to run twice. Requires gitleaks to "
                    "be installed and CC_SECURITY_ENGINES on: the secret "
                    "renames move findings onto gitleaks' rule names, and a "
                    "machine that falls back to the built-in scanner mints "
                    "the old names again on the next analysis, reporting "
                    "every migrated secret as fixed AND new at once. Also "
                    "refused while any analysis is running.")
    mgr.set_defaults(fn=cmd_migrate_rules)

    mv = sub.add_parser("rename-project", parents=[dbflag]); mv.set_defaults(fn=cmd_rename_project)
    mv.add_argument("--from", required=True)
    mv.add_argument("--to", required=True)

    ls = sub.add_parser("list", parents=[dbflag]); ls.set_defaults(fn=cmd_list)
    ls.add_argument("--project", required=True)

    # Deliberately absent from AGENT_FORBIDDEN: read-only, same reasoning as
    # `findings`, `fingerprint`, `list` and `analysis` above -- it opens the
    # ledger through `queries.read_only` and writes nothing.
    ix = sub.add_parser("index-data", parents=[dbflag]); ix.set_defaults(fn=cmd_index_data)
    ix.add_argument("--projects", required=True)
    # The Findings-overview card's own period (mockup default "Last 30
    # days") and the Recent-analyses table's own page -- see cmd_index_data's
    # own docstring.
    ix.add_argument("--days", type=int, default=30)
    ix.add_argument("--recent-page", type=int, default=1)

    # Deliberately absent from AGENT_FORBIDDEN: same reasoning as `index-data`
    # right above -- it opens the ledger through `queries.read_only` and
    # writes nothing.
    pd = sub.add_parser("project-data", parents=[dbflag]); pd.set_defaults(fn=cmd_project_data)
    pd.add_argument("--project", required=True)
    pd.add_argument("--base", default="")
    pd.add_argument("--default-profile", default="", dest="default_profile")

    # Deliberately absent from AGENT_FORBIDDEN: same reasoning as
    # `index-data`/`project-data` above -- it opens the ledger through
    # `queries.read_only` and writes nothing.
    fpg = sub.add_parser("findings-page", parents=[dbflag]); fpg.set_defaults(fn=cmd_findings_page)
    fpg.add_argument("--project", required=True)
    fpg.add_argument("--sort", default="severity", choices=queries.SORTABLE)
    fpg.add_argument("--dir", default="desc", choices=("asc", "desc"), dest="direction")
    fpg.add_argument("--page", type=int, default=1)
    fpg.add_argument("--per-page", type=int, default=25, dest="per_page")
    fpg.add_argument("--severity", action="append", default=None, choices=report.SEVERITIES)
    fpg.add_argument("--state", action="append", default=None,
                     choices=diff.DERIVED_STATES + ledger.DECISION_STATES)
    fpg.add_argument("--category", action="append", default=None,
                     choices=FINDING_CATEGORIES)
    fpg.add_argument("--branch", action="append", default=None)
    fpg.add_argument("--analysis", action="append", type=int, default=None)
    fpg.add_argument("--q", default="")
    fpg.add_argument("--path", default="")
    fpg.add_argument("--show-resolved", action="store_true", dest="show_resolved")
    # A prefix, not the full 64-character shape `report-finding` enforces --
    # the Activity screen's own deep link only ever has the first 12 (see
    # `queries.finding_rows`'s own comment on this key). No `choices=` (it is
    # a prefix, not a closed set) -- shape-checked instead, at the top of
    # `cmd_findings_page`, against FINGERPRINT_PREFIX_RE.
    fpg.add_argument("--fingerprint", default="")

    # Deliberately absent from AGENT_FORBIDDEN: same reasoning as
    # `index-data`/`project-data`/`findings-page` above -- it opens the
    # ledger through `queries.read_only` and writes nothing. `--kind` gets
    # `choices=` for the same reason `findings-page`'s own severity/state/
    # category do: CLI-direct use gets the identical validation the
    # server's own route (`security_activity`) already performs
    # independently.
    ad = sub.add_parser("activity-data", parents=[dbflag]); ad.set_defaults(fn=cmd_activity_data)
    ad.add_argument("--project", default="")
    ad.add_argument("--kind", action="append", default=[], choices=ledger.EVENT_KINDS)
    ad.add_argument("--since", type=int, default=0)
    ad.add_argument("--page", type=int, default=1)
    ad.add_argument("--per-page", type=int, default=25, dest="per_page")

    # Deliberately absent from AGENT_FORBIDDEN: it prints one row and writes
    # nothing, the same reasoning as `fingerprint` and `findings` above.
    an = sub.add_parser("analysis", parents=[dbflag]); an.set_defaults(fn=cmd_analysis)
    an.add_argument("--id", type=int, required=True)

    # IN AGENT_FORBIDDEN (see the tuple and `_refuse_if_agent`'s docstring):
    # both audit-worthy things the agent causes are already filed as side
    # effects -- `analysis_started` by `open-analysis` (which it cannot
    # call) and `analysis_finished` by `finish` (which files the event
    # itself) -- so the agent has no legitimate reason to reach this
    # standalone write verb, while a forged entry would corrupt the one
    # record of what actually happened.
    ev = sub.add_parser("event", parents=[dbflag]); ev.set_defaults(fn=cmd_event)
    for flag in ("project", "kind"):
        ev.add_argument(f"--{flag}", required=True)
    ev.add_argument("--detail", default="")
    ev.add_argument("--related", default="")

    # `events` (read-only) stays OUT of AGENT_FORBIDDEN: nothing here for the
    # flag to protect, only a query the agent may legitimately want to see.
    es = sub.add_parser("events", parents=[dbflag]); es.set_defaults(fn=cmd_events)
    es.add_argument("--project", default="")
    es.add_argument("--kind", action="append", default=[])
    es.add_argument("--since", type=int, default=0)
    es.add_argument("--limit", type=int, default=100)
    es.add_argument("--offset", type=int, default=0)

    # ONE subcommand, `filters`, with a nested action -- `security filters
    # list|save|delete --project ...` -- rather than three top-level verbs,
    # because they share the one thing that makes them one feature: a saved
    # filter, scoped by project. `--db` is on every level (parents=[dbflag]),
    # the same reason it is on every other subparser here: it has to work
    # wherever the caller puts it, and `run()` in the tests puts it after
    # every other flag, past the innermost parser. `dest="action"` is the
    # convention every nested subparser in this file must use (see
    # AGENT_FORBIDDEN and `main`'s dispatch key below): it is what lets the
    # agent-refusal key generalise to "verb action" for any future nested
    # verb without `main()` ever naming `filters` by string.
    fl = sub.add_parser("filters", parents=[dbflag]); fl.set_defaults(fn=cmd_filters)
    fl_sub = fl.add_subparsers(dest="action", required=True)

    fl_list = fl_sub.add_parser("list", parents=[dbflag])
    fl_list.add_argument("--project", required=True)

    fl_save = fl_sub.add_parser("save", parents=[dbflag])
    fl_save.add_argument("--project", required=True)
    fl_save.add_argument("--name", required=True)

    fl_delete = fl_sub.add_parser("delete", parents=[dbflag])
    fl_delete.add_argument("--project", required=True)
    fl_delete.add_argument("--name", required=True)

    args = p.parse_args(argv)
    if not getattr(args, "db", None):
        p.error("--db is required")
    # Before the database is opened, and in ONE place rather than in each of
    # the commands: a verb added later is refused by being added to
    # AGENT_FORBIDDEN, not by remembering to copy a guard into its function.
    #
    # The key is computed the SAME way for every subcommand, with no
    # per-verb special case anywhere in this computation. A bare command has
    # no `action` attribute (every subparser except `filters`'s own nested
    # one leaves it unset), so `getattr(args, "action", "")` is "" and the
    # key is just `args.cmd`. A subcommand with a nested action -- the
    # `dest="action"` convention set on `fl_sub` above -- gets the two-word
    # "cmd action" key that AGENT_FORBIDDEN's "filters save" and
    # "filters delete" entries match, so `filters list` (a query) stays
    # reachable while the two writes are refused. Extending this to the next
    # nested verb needs NOTHING here: give its subparser `dest="action"` and
    # put its two-word form in the tuple.
    key = f"{args.cmd} {getattr(args, 'action', '')}".strip()
    if key in AGENT_FORBIDDEN:
        _refuse_if_agent(key)
    args.fn(args)


if __name__ == "__main__":
    main()
