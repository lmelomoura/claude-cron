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


def classify(current, previous, history, decisions,
             analysis_state="done", prepared=True):
    """Attach a `state` to every finding, plus the ones that disappeared.

    `history` is every fingerprint seen in any analysis older than `previous`.
    It is what separates a genuinely new finding from one that was fixed and
    came back -- which is worse news, and which `new` would hide.

    `analysis_state` and `prepared` exist because ABSENCE IS ONLY EVIDENCE
    WHEN THE LOOKING FINISHED. A checklist rendered nine seconds into a run
    used to mark the whole baseline `fixed` -- 43 findings "resolved" before
    prepare had written a byte -- and a capped run's unreached SAST findings
    got the same lie. A baseline finding missing from `current` is `fixed`
    only when its absence is proven: deterministic categories once `prepare`
    completed, everything else only when the analysis closed `done` (full
    scope declared). Anything short of that is `pending` -- not re-checked
    yet, which is a statement about this analysis, never about the code.
    """
    prev_fps = {f["fingerprint"] for f in previous}
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
            if f.get("category") in DETERMINISTIC_CATEGORIES:
                proven = bool(prepared)
            else:
                proven = analysis_state == "done"
            row["state"] = "fixed" if proven else "pending"
            out.append(row)

    return out
