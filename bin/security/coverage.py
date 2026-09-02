# bin/security/coverage.py
"""The coverage note's STRUCTURE -- written BESIDE the prose, never instead of it.

WHAT WENT WRONG WITHOUT IT. `coverage_note` is one string, assembled by
`cmd_prepare` out of ~27 `*_NOTE` constants spread over six modules, and on a
real analysis it is about two thousand characters of unbroken prose. Every
sentence in it is true and every one of them was written because its absence
had cost something. Read together, in one paragraph, they are unreadable: the
operator who built this system read a real one and asked "what IS this alert?".
Honest per phase, incoherent as a whole.

So the paragraph is not the thing a reader meets first any more. THE SAME
SENTENCES are attributed to the phase that produced them and stored as a small
JSON document beside the prose:

    {"phases": [{"name": "iac", "status": "skipped", "by": null,
                 "note": "Infrastructure-as-code ... was NOT checked ..."}]}

A table of nine lines answers "who looked, who did not, and with what" in one
glance; the prose is still there, unchanged byte for byte, for the reader who
then asks why.

BESIDE, NOT INSTEAD, AND THAT IS LOAD-BEARING. Three report formats and the
analysis screen read `coverage_note` as text today, and every analysis written
before this column existed has ONLY that text. `decode` therefore answers `[]`
for an absent, empty, malformed or foreign document rather than raising, and
every renderer draws nothing at all for `[]` -- an old analysis renders exactly
as it did before this module existed. The structure can only ever ADD a table
above prose that was going to be printed anyway.

NOT DERIVED FROM THE PROSE. `cmd_prepare` builds this list from what its
`_scan_*` functions RETURN -- each one now answers with its own status -- and
never by looking for a sentence in a note. A status inferred from the presence
of a string would be a second, silent parser of prose written for humans, and
it would start lying the first time somebody reworded a note.
"""

import json

# THE THREE STATUSES, and the question each answers is "what does this phase's
# silence prove?".
#
#   ran      -- the phase's own primary producer looked. Nothing found means
#               nothing is there, as far as that producer can see.
#   warning  -- something looked, but not the whole of what this phase means.
#               A fallback producer with narrower coverage (the built-in secret
#               scanner against gitleaks' rule set; OSV.dev over five lockfile
#               formats against Trivy's many), or a pass that is a PRE-pass by
#               construction. Silence here proves less than it looks like.
#   skipped  -- nothing looked at all. Silence proves nothing whatsoever.
#
# Deliberately three and not two: "ran" and "did not run" collapses the middle
# case, and the middle case is the one that has actually produced false
# `fixed` verdicts in this ledger (see `diff._proven`).
RAN = "ran"
WARNING = "warning"
SKIPPED = "skipped"
STATUSES = (RAN, WARNING, SKIPPED)

# THE PHASES, in the order every renderer prints them. Scope first because it
# decides what all the others were even allowed to look at. The last two are
# the agent's -- its own SAST pass, then the triage of what the deterministic
# half produced -- and both are written by `cmd_finish`, after everything else
# has already happened: `prepare` files the first seven, the close files these.
#
# `SAST_AGENT` is spelled "sast" because that is the finding CATEGORY the
# agent's pass mints into (`cli.FINDING_CATEGORIES`), where "sast-prepass" is
# the Semgrep pass that runs ahead of it and is a `warning` by construction.
# Two rows, not one, for the reason `_scan_sast` gives at length: the pre-pass
# is an addition to the agent's pass, never a substitute for it, so a single
# row could not say which of the two looked.
#
# A CLOSED SET, checked by `phase()`. A typo'd name would sort to the end of
# the table and read as a phase this project does not have, which is a worse
# failure than a refusal at the moment somebody writes it.
SCOPE = "scope"
SECRETS = "secrets"
HYGIENE = "hygiene"
DEPENDENCIES = "dependencies"
SBOM = "sbom"
IAC = "iac"
SAST_PREPASS = "sast-prepass"
SAST_AGENT = "sast"
TRIAGE = "triage"
PHASE_ORDER = (SCOPE, SECRETS, HYGIENE, DEPENDENCIES, SBOM, IAC, SAST_PREPASS,
               SAST_AGENT, TRIAGE)


def phase(name, status, by="", note="") -> dict:
    """One row of the table.

    `by` is the PRODUCER that answered -- one of `cli.PRODUCER_*`, or two of
    them joined by `diff.PRODUCER_SEPARATOR` when a phase ran two scanners at
    once (`gitleaks+secrets`, see `cli._scan_secrets`): the same identity
    vocabulary `diff._proven` reads, atom by atom -- or None when no producer
    is involved at all (`scope` is this analysis's own configuration, not
    something a scanner did). Stored as null rather than as "" so a consumer
    never has to tell an empty producer from a missing key.

    `note` takes a string or a list of them and joins them with one space --
    the identical join `cmd_prepare` uses to build the whole paragraph. That
    join is HALF of what makes a phase's prose a character-for-character
    substring of `coverage_note`; the other half is `cmd_prepare` emitting
    each phase's sentences ADJACENTLY in the paragraph, in the order the row
    carries them -- the two sentences shared by `dependencies` and `sbom` sit
    at the boundary between the two so both rows stay contiguous. Neither
    half is enforced here (this function sees one row at a time).

    WHAT IS PINNED, PRECISELY -- not the whole table. Every phase `prepare`
    files, by test_every_phases_prose_is_a_substring_of_the_paragraph; and
    every GAP sentence the close files -- findings never read, a decision that
    exempted one, a `prepare` that never ran, the `--note` -- by the close's
    own tests, each asserting the row's note is in the paragraph. The triage
    row is the exception, by design: its summary sentences
    (`cli.TRIAGE_NOTHING_NOTE`, `cli.TRIAGE_ALL_READ_NOTE`) describe what the
    agent did rather than a gap, and `cli.TRIAGE_UNVERIFIED_NOTE` -- filed
    when the close never reached the check -- is not written into the
    paragraph either; that test's docstring names all three and says why.
    """
    if name not in PHASE_ORDER:
        raise ValueError(f"unknown coverage phase: {name}")
    if status not in STATUSES:
        raise ValueError(f"unknown coverage status: {status}")
    parts = [note] if isinstance(note, str) else list(note)
    return {"name": name, "status": status, "by": by or None,
            "note": " ".join(p.strip() for p in parts if p and p.strip())}


def encode(phases) -> str:
    """The JSON document for the `coverage` column.

    ORDERED HERE, ONCE, so no renderer has to sort and none of them can sort
    differently. A name this module does not know sorts to the end rather than
    being dropped -- the same rule `report._unknown_states` follows for a state
    outside the contract: a value the code has not been taught is still a fact
    the ledger holds.
    """
    ordered = sorted(phases, key=lambda p: (
        PHASE_ORDER.index(p["name"]) if p.get("name") in PHASE_ORDER
        else len(PHASE_ORDER)))
    return json.dumps({"phases": ordered})


def decode(stored) -> list:
    """The phases of a stored value, or `[]` for anything unreadable.

    NEVER RAISES, and that is the whole contract with the three report formats
    and the analysis screen. The column is additive: every analysis written
    before it existed carries '' here, and the renderers draw the prose alone
    for `[]` exactly as they did before this module existed. A document that
    is not JSON, not an object, or whose `phases` is not a list of named
    objects is treated identically -- a report is not the place to discover
    that a column got corrupted, and the prose beside it is still true.
    """
    if not stored:
        return []
    try:
        doc = json.loads(stored)
    except (TypeError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    rows = doc.get("phases")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("name")]


def phases_of(analysis) -> list:
    """`decode` of an analysis ROW or dict, whichever the caller holds.

    `sqlite3.Row` raises IndexError for a column it does not have and has no
    `.get`; a plain dict raises KeyError. Both mean the same thing here -- an
    analysis from before the column existed -- so both answer `[]`.
    """
    try:
        stored = analysis["coverage"]
    except (KeyError, IndexError, TypeError):
        return []
    return decode(stored)


def merge(phases, extra) -> list:
    """`extra` REPLACES a stored phase of the same name, or is appended.

    Replace and not append, because `finish` is called TWICE on one analysis --
    the agent closes it, then the engine closes the same row again with the
    run's own verdict (see `cmd_finish`) -- and a triage phase appended each
    time would give the table two contradicting triage lines by the second
    close. It is the structured twin of the `part not in note` guard the prose
    already uses for the same double call.
    """
    out = list(phases)
    for e in extra:
        for i, p in enumerate(out):
            if isinstance(p, dict) and p.get("name") == e["name"]:
                out[i] = e
                break
        else:
            out.append(e)
    return out
