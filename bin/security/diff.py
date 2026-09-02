# bin/security/diff.py
"""The checklist: what closed, what did not, what closed halfway, what is new.

Every state here is DERIVED from comparing this analysis with the previous one
of the same branch. None of them is stored -- storing a state would let the
ledger disagree with the findings it holds. The only persisted judgement is the
human decision, which lives in its own table and wins over all of this.
"""

DERIVED_STATES = ("new", "open", "partial", "pending", "fixed", "regressed")


def _is_partial(finding) -> bool:
    """Objective first, judgement second.

    The occurrence count is an anchor two runs cannot disagree about. The
    agent's note catches the other half: a fix that made the pattern go away
    without closing the hole.

    Meaningful ONLY for a finding that was already in the previous analysis --
    "partial" means "this shrank since last time", and there is nothing for a
    finding absent from `previous` to have shrunk from. Callers must gate on
    `fp in prev_fps` before calling this; it is not re-checked here so that
    the one guard in `classify` stays the single place this invariant lives.
    """
    if int(finding.get("closed_occurrences", 0)) > 0:
        return True
    return bool((finding.get("partial_note") or "").strip())


DETERMINISTIC_CATEGORIES = ("secret", "dependency", "hygiene", "iac")

# The producer stamped on everything the AGENT reports (`cmd_report_finding`),
# as opposed to the engine-side producers `cmd_prepare` names for each phase it
# actually ran. It is the one producer name that has to be spelled the same in
# two modules, so it lives here, next to the rule that reads it.
AGENT = "agent"

# What joins two producers that BOTH saw one finding. The secret phase runs
# gitleaks and the built-in scanner together and records `gitleaks+secrets` --
# on the analysis row, and on every finding both re-found (see
# `cli._scan_secrets`). Defined here beside `AGENT` for the same reason: the
# writer (`cli`) and the reader (`_proven`) have to spell it identically, and
# this module is the reader. Not a comma, which is what `ledger.mark_prepared`
# separates the producers of one analysis with.
PRODUCER_SEPARATOR = "+"


def atoms(producer) -> set:
    """The single scanners a producer string names: `"gitleaks+secrets"` is
    `{"gitleaks", "secrets"}`, `"trivy"` is `{"trivy"}`, `""` is `set()`."""
    return {a for a in (producer or "").split(PRODUCER_SEPARATOR) if a}


def _proven(finding, analysis_state, prepared, produced) -> bool:
    """Did something that COULD have re-found this finding actually look?

    THE ONLY QUESTION THAT SEPARATES `fixed` FROM `pending`, and it is asked
    of the PRODUCER, never of the category. A category is not a thing that
    looks; a producer is. Three ways the category answered it wrongly, all
    reproduced end to end against one ledger with the engines on for the first
    analysis and off for the second:

      `iac`         has no fallback by design -- Trivy's misconfiguration
                    scanner is the only source this project has ever had for
                    it -- so `[]` from that phase means "nobody looked". As a
                    member of DETERMINISTIC_CATEGORIES it read as "prepare
                    finished, therefore absence is proven", and one report
                    said the Dockerfile "was not checked at all this run" and
                    declared three of its misconfigurations fixed in the same
                    breath.

      `dependency`  has two producers whose coverage is INCOMPARABLE, not
                    nested: Trivy reads yarn.lock, pnpm, Gemfile.lock,
                    Cargo.lock, pom.xml and more against its own database,
                    while `deps.inventory` reads five formats and asks
                    OSV.dev. Measured on a yarn.lock pinning lodash 4.17.20:
                    Trivy 5 findings, `deps.inventory` 0 components. So the
                    fallback reported all five fixed, and `osv.FALLBACK_NOTE`
                    declares a gap in advisory SOURCES -- never one in
                    lockfile FORMATS, which is the gap that actually bit.

      `sast`        is not deterministic, so it survived as `pending` mid-run
                    and flipped to `fixed` the moment the analysis closed
                    `done` -- including the Semgrep pre-pass rows, whose
                    identity is `fingerprint("sast", rule, path, check_id)`
                    and which only Semgrep can mint. The analysis closing
                    `done` proves the AGENT looked; it says nothing about a
                    pre-pass that never ran.

    So: a baseline finding missing from `current` is `fixed` only when the
    producer that MINTED it ran again in this analysis. Anything else is
    `pending` -- not re-checked yet, a statement about this analysis and never
    about the code.

    Both directions are held. A producer that ran and found nothing DOES prove
    absence (its name is in `produced` whether it reported findings or not, so
    a genuinely fixed hole still closes on the very next run); a producer that
    did not run proves nothing. Making everything `pending` for ever would be
    the same lie pointing the other way, and `fixed` would stop meaning
    anything.

    WHERE THE LINE IS DRAWN, stated rather than discovered: "ran" means the
    producer executed and returned a report for this phase. A producer that
    ran DEGRADED -- OSV.dev answering for 400 of 600 components, Semgrep
    failing to parse a file, a lockfile whose reader threw -- still counts as
    having run. Those gaps are real and they are declared where every other
    partial-coverage fact in this area is declared, in the coverage note; they
    are not per-finding proof, and threading them here would make `fixed`
    unreachable for any repository big enough to trip one.

    `producer` is empty on rows written before the column existed. Those fall
    back to the category rule this function replaced, which is the only
    honest reading available for them: nothing recorded who looked.

    ATOM BY ATOM, AND EVERY ATOM. A producer may name two scanners at once --
    `gitleaks+secrets`, the secret phase's own since the two run together --
    and so may an entry of `produced`. Both sides are split on
    `PRODUCER_SEPARATOR` and the finding is proven only when EVERY scanner
    its producer names is among the scanners that ran. Three rules were
    possible and two of them are wrong:

      exact membership   -- what this function did before the union. A row
                            minted under `gitleaks` alone, before the two ran
                            together, meets `produced = {"gitleaks+secrets"}`
                            and is never proven again: `pending` for ever,
                            though gitleaks ran and looked for exactly it.

      any atom present   -- a row both saw, on a machine that later loses
                            gitleaks, would be sworn `fixed` by the built-in
                            scanner alone -- whose eight shaped rules are not
                            the engine's rule set. `fixed` is the verdict
                            whose false positive costs most: it tells the
                            operator a credential is gone. Preventing exactly
                            that verdict is why this function asks about
                            producers at all.

      every atom present -- chosen. Proven only when every scanner that ever
                            saw the row looked again. Over-conservative on a
                            machine that loses a scanner, and that is the
                            honest side to err on: `pending` says "not
                            re-checked", which is true of it.
    """
    producer = (finding.get("producer") or "").strip()
    if not producer:
        if finding.get("category") in DETERMINISTIC_CATEGORIES:
            return bool(prepared)
        return analysis_state == "done"
    if producer == AGENT:
        # The agent is the one producer whose "did it run" is the analysis's
        # own verdict: it has no binary to be missing, and `done` is exactly
        # the claim that it covered the declared scope.
        return analysis_state == "done"
    # Every other producer runs inside `prepare`, which is what writes
    # `produced` -- so `prepared` is implied by a non-empty membership and
    # asked anyway, because the two facts are written by one statement and a
    # future edit that separates them should fail closed. `needed` is asked
    # for the same reason: a producer that is all separators and no name is
    # a subset of anything, and must prove nothing.
    looked = set().union(*(atoms(p) for p in produced)) if produced else set()
    needed = atoms(producer)
    return bool(prepared) and bool(needed) and needed <= looked


def classify(current, previous, history, decisions,
             analysis_state="done", prepared=True, produced=()):
    """Attach a `state` to every finding, plus the ones that disappeared.

    `history` is every fingerprint seen in any analysis older than `previous`.
    It is what separates a genuinely new finding from one that was fixed and
    came back -- which is worse news, and which `new` would hide.

    `analysis_state`, `prepared` and `produced` exist because ABSENCE IS ONLY
    EVIDENCE WHEN THE LOOKING FINISHED. A checklist rendered nine seconds into
    a run used to mark the whole baseline `fixed` -- 43 findings "resolved"
    before prepare had written a byte -- and a capped run's unreached SAST
    findings got the same lie. `produced` is the third and last of them: the
    producers that actually ran in THIS analysis, which is what `_proven`
    above measures a baseline finding's own `producer` against.
    """
    prev_fps = {f["fingerprint"] for f in previous}
    produced = {p for p in (produced or ()) if p}
    out = []

    for f in current:
        fp = f["fingerprint"]
        row = dict(f)
        decision = decisions.get(fp)
        if decision:
            row["state"] = decision["state"]
            row["decision_reason"] = decision.get("reason", "")
        elif fp in prev_fps:
            # Only a finding present last time can have "shrunk" since then --
            # closed_occurrences and partial_note are meaningless for a
            # fingerprint that was not there to shrink from.
            row["state"] = "partial" if _is_partial(f) else "open"
        elif fp in history:
            row["state"] = "regressed"
        else:
            row["state"] = "new"
        out.append(row)

    seen_now = {f["fingerprint"] for f in current}
    for f in previous:
        if f["fingerprint"] not in seen_now:
            row = dict(f)
            if _proven(f, analysis_state, prepared, produced):
                row["state"] = "fixed"
            else:
                # NOT RE-CHECKED, BUT PERHAPS ALREADY RULED ON. This branch
                # used to read `pending` full stop, and before that `fixed`
                # full stop -- either way a human's `accepted`/`false_positive`
                # call on a finding this run could not re-find was dropped on
                # the floor, because the decision lookup at the top of this
                # function only ever reached findings present in `current`.
                # An accepted IaC risk on a machine without Trivy rendered as
                # a remediation claim, which is the worst of the three
                # readings: it overrode a judgement with a lie.
                #
                # Ordered under `fixed` on purpose. Proven absence is BETTER
                # news than an accepted risk and stays the answer when it is
                # available -- a hole that is actually gone should not keep
                # reading "you accepted this". The decision only fills the
                # silence where this analysis has nothing to say.
                decision = decisions.get(f["fingerprint"])
                if decision:
                    row["state"] = decision["state"]
                    row["decision_reason"] = decision.get("reason", "")
                else:
                    row["state"] = "pending"
            out.append(row)

    return out
