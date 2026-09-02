# tests/security/test_diff.py
from security.diff import classify


def f(fp, occ=1, closed=0, partial_note=""):
    occs = [{"file": f"a{i}.py", "line": i, "snippet_hash": f"h{i}"} for i in range(occ)]
    return {"fingerprint": fp, "category": "sast", "rule": "r", "severity": "high",
            "title": "t", "occurrences": occs, "closed_occurrences": closed,
            "partial_note": partial_note}


def test_a_fingerprint_never_seen_before_is_new():
    out = classify([f("aa")], [], set(), {})
    assert out[0]["state"] == "new"


def test_a_fingerprint_that_was_there_and_still_is_is_open():
    out = classify([f("aa")], [f("aa")], {"aa"}, {})
    assert out[0]["state"] == "open"


def test_a_fingerprint_that_disappeared_is_fixed():
    out = classify([], [f("aa")], {"aa"}, {})
    assert [(o["fingerprint"], o["state"]) for o in out] == [("aa", "fixed")]


def test_some_occurrences_closed_is_partial():
    out = classify([f("aa", occ=5, closed=2)], [f("aa", occ=5)], {"aa"}, {})
    assert out[0]["state"] == "partial"


def test_the_agent_can_call_it_partial_with_a_note():
    out = classify([f("aa", partial_note="sanitised but the sink is still raw")],
                   [f("aa")], {"aa"}, {})
    assert out[0]["state"] == "partial"


def test_reappearing_after_being_fixed_is_regressed_not_new():
    """It was absent from the previous analysis but present in an older one."""
    out = classify([f("aa")], [], {"aa"}, {})
    assert out[0]["state"] == "regressed"


def test_a_decision_wins_over_the_derived_state():
    out = classify([f("aa")], [], set(),
                   {"aa": {"state": "false_positive", "reason": "fixture"}})
    assert out[0]["state"] == "false_positive"
    assert out[0]["decision_reason"] == "fixture"


def test_a_decision_wins_over_open():
    out = classify([f("aa")], [f("aa")], {"aa"},
                   {"aa": {"state": "false_positive", "reason": "fixture"}})
    assert out[0]["state"] == "false_positive"


def test_a_decision_wins_over_partial():
    out = classify([f("aa", occ=5, closed=2)], [f("aa", occ=5)], {"aa"},
                   {"aa": {"state": "false_positive", "reason": "fixture"}})
    assert out[0]["state"] == "false_positive"


def test_a_decision_wins_over_regressed():
    out = classify([f("aa")], [], {"aa"},
                   {"aa": {"state": "false_positive", "reason": "fixture"}})
    assert out[0]["state"] == "false_positive"


# `partial` compares occurrence counts against the previous analysis, so it
# only means something for a fingerprint that WAS in `previous`. A finding
# absent from `previous` -- whether it is brand new or reappearing from
# `history` -- must never come out `partial`, no matter what closed_occurrences
# or partial_note say: there is nothing for it to have shrunk from.


def test_a_regressed_finding_with_a_partial_note_is_regressed_not_partial():
    out = classify([f("aa", partial_note="sanitised but the sink is still raw")],
                   [], {"aa"}, {})
    assert out[0]["state"] == "regressed"


def test_a_regressed_finding_with_closed_occurrences_is_regressed_not_partial():
    out = classify([f("aa", occ=5, closed=2)], [], {"aa"}, {})
    assert out[0]["state"] == "regressed"


def test_a_new_finding_with_closed_occurrences_is_new_not_partial():
    out = classify([f("aa", occ=5, closed=2)], [], set(), {})
    assert out[0]["state"] == "new"


def test_absence_mid_run_is_pending_not_fixed():
    """Nine seconds into a run the whole baseline used to read `fixed` --
    43 findings "resolved" before prepare had written a byte. Absence is only
    evidence when the looking finished."""
    prev = [f("aa"), dict(f("bb"), category="secret")]
    out = classify([], prev, {"aa", "bb"}, {},
                   analysis_state="running", prepared=False)
    assert {o["fingerprint"]: o["state"] for o in out} == {"aa": "pending", "bb": "pending"}


def test_a_deterministic_absence_is_fixed_once_prepare_completed():
    prev = [dict(f("bb"), category="secret")]
    out = classify([], prev, {"bb"}, {}, analysis_state="running", prepared=True)
    assert out[0]["state"] == "fixed"


def test_a_sast_absence_stays_pending_until_the_analysis_closes_done():
    prev = [f("aa")]  # category sast
    out = classify([], prev, {"aa"}, {}, analysis_state="running", prepared=True)
    assert out[0]["state"] == "pending"
    out = classify([], prev, {"aa"}, {}, analysis_state="capped", prepared=True)
    assert out[0]["state"] == "pending", "a capped run never finished looking"
    out = classify([], prev, {"aa"}, {}, analysis_state="done", prepared=True)
    assert out[0]["state"] == "fixed"


def test_a_row_with_no_producer_still_falls_back_to_the_category_rule():
    """Rows written before the `producer` column existed.

    Nothing recorded who looked, so the category is the only reading left --
    and it is kept deliberately rather than forced to `pending`, or every
    pre-existing ledger would report its whole baseline unre-checked for ever.
    """
    prev = [dict(f("cc"), category="iac")]  # no `producer` key at all
    out = classify([], prev, {"cc"}, {}, analysis_state="running", prepared=True)
    assert out[0]["state"] == "fixed"
    out = classify([], prev, {"cc"}, {}, analysis_state="running", prepared=False)
    assert out[0]["state"] == "pending"


# ------------------------------------------- absence is proven by a PRODUCER
#
# `prepare` finishing is not evidence that anything looked at a given
# category. Reproduced end to end against one ledger, analysis 1 with the
# engines on and analysis 2 with them off: one report said the Dockerfile
# "was not checked at all this run" and declared three of its
# misconfigurations `fixed` in the same breath.


def p(fp, category, producer, **kw):
    """A baseline finding that records WHO minted it."""
    return dict(f(fp), category=category, producer=producer, **kw)


def test_a_phase_whose_engine_did_not_run_proves_nothing():
    """THE BLOCKING ONE. `iac` has no fallback by design, so `[]` from that
    phase means nobody looked -- and as a member of DETERMINISTIC_CATEGORIES
    it used to read as proof the moment `prepare` finished."""
    prev = [p("cc", "iac", "trivy-iac")]
    out = classify([], prev, {"cc"}, {}, analysis_state="done", prepared=True,
                   produced={"secrets", "hygiene", "osv"})
    assert out[0]["state"] == "pending"


def test_a_phase_whose_engine_DID_run_still_proves_absence():
    """The other direction, and it matters just as much: a producer that ran
    and found nothing closes the finding on the very next analysis. Making
    everything `pending` for ever would be the same lie pointing the other
    way."""
    prev = [p("cc", "iac", "trivy-iac")]
    out = classify([], prev, {"cc"}, {}, analysis_state="running", prepared=True,
                   produced={"trivy-iac"})
    assert out[0]["state"] == "fixed", (
        "an engine that ran and reported nothing IS proof of absence, and it "
        "does not have to wait for the analysis to close")


def test_a_narrower_dependency_producer_does_not_prove_the_wider_one_gone():
    """Trivy reads yarn.lock; `deps.inventory` reads five formats and does
    not. Measured on a yarn.lock pinning lodash 4.17.20: Trivy 5 findings,
    `deps.inventory` 0 components -- so the fallback used to report all five
    fixed, and `osv.FALLBACK_NOTE` declares a gap in advisory SOURCES, never
    one in lockfile FORMATS."""
    prev = [p("dd", "dependency", "trivy")]
    out = classify([], prev, {"dd"}, {}, analysis_state="done", prepared=True,
                   produced={"osv", "secrets", "hygiene"})
    assert out[0]["state"] == "pending"
    # ...and the same finding under the producer that CAN re-find it.
    out = classify([], prev, {"dd"}, {}, analysis_state="done", prepared=True,
                   produced={"trivy"})
    assert out[0]["state"] == "fixed"


def test_the_gitleaks_fallback_does_not_prove_a_gitleaks_finding_gone():
    """The same shape one category over: the built-in scanner has eight shaped
    rules where gitleaks carries its own set, so its silence is not proof
    about a credential only gitleaks names."""
    prev = [p("ee", "secret", "gitleaks")]
    out = classify([], prev, {"ee"}, {}, analysis_state="done", prepared=True,
                   produced={"secrets", "hygiene"})
    assert out[0]["state"] == "pending"


def test_the_semgrep_pre_pass_is_not_proven_by_the_analysis_closing_done():
    """A pre-pass identity is `fingerprint("sast", rule, path, check_id)` --
    a check id only Semgrep mints. `done` proves the AGENT covered its scope
    and says nothing about a pre-pass that never ran."""
    prev = [p("ff", "sast", "semgrep")]
    out = classify([], prev, {"ff"}, {}, analysis_state="done", prepared=True,
                   produced={"secrets", "hygiene"})
    assert out[0]["state"] == "pending"
    out = classify([], prev, {"ff"}, {}, analysis_state="done", prepared=True,
                   produced={"semgrep"})
    assert out[0]["state"] == "fixed"


def test_the_agents_own_sast_findings_still_close_on_the_agents_own_evidence():
    """Which is why the fix is a producer and not "mark the whole category
    pending": `sast` holds rows from two sources at once."""
    prev = [p("gg", "sast", "agent")]
    out = classify([], prev, {"gg"}, {}, analysis_state="done", prepared=True,
                   produced=set())
    assert out[0]["state"] == "fixed"
    out = classify([], prev, {"gg"}, {}, analysis_state="capped", prepared=True,
                   produced=set())
    assert out[0]["state"] == "pending"


# ------------------------- a producer made of two scanners, atom by atom
#
# The secret phase runs gitleaks AND the built-in scanner and records
# `gitleaks+secrets` -- on the analysis row, and on every finding both saw.
# `_proven` splits both sides into atoms and asks for a SUBSET: every scanner
# that ever saw the row has to have looked again. Exact string membership
# would leave a row minted under `gitleaks` alone, before the union, `pending`
# for ever against `{"gitleaks+secrets"}`; "any atom" would let the built-in
# alone swear a row both saw `fixed` on a machine that later lost gitleaks --
# and `fixed` is the verdict whose false positive costs most.

def test_a_row_minted_by_gitleaks_alone_is_proven_by_the_union():
    """The pre-union row: `producer="gitleaks"`, meeting an analysis whose
    `produced` spells the composite. Gitleaks ran; that is what it asked."""
    prev = [p("ua", "secret", "gitleaks")]
    out = classify([], prev, {"ua"}, {}, analysis_state="done", prepared=True,
                   produced={"gitleaks+secrets", "hygiene"})
    assert out[0]["state"] == "fixed"


def test_a_row_both_saw_is_not_proven_by_the_built_in_alone():
    """The machine that lost gitleaks. The built-in scanner ran and did not
    re-find the row; gitleaks -- which also saw it -- did not look. `pending`
    is the true statement; `fixed` would be the false remediation claim
    `_proven` exists to prevent."""
    prev = [p("ub", "secret", "gitleaks+secrets")]
    out = classify([], prev, {"ub"}, {}, analysis_state="done", prepared=True,
                   produced={"secrets", "hygiene"})
    assert out[0]["state"] == "pending"
    out = classify([], prev, {"ub"}, {}, analysis_state="done", prepared=True,
                   produced={"gitleaks", "hygiene"})
    assert out[0]["state"] == "pending"


def test_a_row_both_saw_is_proven_when_both_looked_again():
    """The control, spelled both ways `produced` can carry the two atoms:
    joined as the phase records them, and as two separate entries."""
    prev = [p("uc", "secret", "gitleaks+secrets")]
    out = classify([], prev, {"uc"}, {}, analysis_state="done", prepared=True,
                   produced={"gitleaks+secrets"})
    assert out[0]["state"] == "fixed"
    out = classify([], prev, {"uc"}, {}, analysis_state="done", prepared=True,
                   produced={"gitleaks", "secrets"})
    assert out[0]["state"] == "fixed"


def test_a_row_only_the_built_in_saw_is_proven_by_the_union():
    """The built-in ran as half of the union, so its own row's absence is
    proven -- the composite contains the atom."""
    prev = [p("ud", "secret", "secrets")]
    out = classify([], prev, {"ud"}, {}, analysis_state="done", prepared=True,
                   produced={"gitleaks+secrets"})
    assert out[0]["state"] == "fixed"


def test_a_producer_that_is_only_separators_proves_nothing():
    """Fails closed, like an unknown name: a non-empty producer with no atoms
    in it cannot be a subset of anything that ran."""
    prev = [p("ue", "secret", "+")]
    out = classify([], prev, {"ue"}, {}, analysis_state="done", prepared=True,
                   produced={"gitleaks+secrets"})
    assert out[0]["state"] == "pending"


def test_an_unknown_producer_fails_closed():
    """A producer nobody recognises renders `pending`, never `fixed` -- so a
    rename of the vocabulary costs a run of "not re-checked" and never a false
    remediation claim."""
    prev = [p("hh", "iac", "some-future-scanner")]
    out = classify([], prev, {"hh"}, {}, analysis_state="done", prepared=True,
                   produced={"trivy-iac", "semgrep", "secrets"})
    assert out[0]["state"] == "pending"


def test_an_empty_produced_entry_can_never_prove_anything():
    """`"".split(",")` is `[""]`, and a finding whose producer is somehow
    empty must not match it. See `ledger.producers_of`."""
    prev = [p("ii", "iac", "")]
    out = classify([], prev, {"ii"}, {}, analysis_state="running",
                   prepared=True, produced={""})
    # Falls through to the legacy category rule, never to a `"" in produced`
    # match: `iac` with `prepared=True` under that rule is `fixed`, so assert
    # the state the MEMBERSHIP would have produced cannot be reached from a
    # run that proves nothing.
    assert out[0]["state"] == "fixed"
    out = classify([], prev, {"ii"}, {}, analysis_state="running",
                   prepared=False, produced={""})
    assert out[0]["state"] == "pending"


def test_a_human_decision_survives_a_finding_this_run_could_not_recheck():
    """`classify` only ever consulted `decisions` for findings in `current`,
    so an accepted IaC risk on a machine without Trivy rendered as a
    remediation claim -- a lie that also overrode a human's judgement."""
    prev = [p("jj", "iac", "trivy-iac")]
    decisions = {"jj": {"state": "accepted", "reason": "base image is pinned"}}
    out = classify([], prev, {"jj"}, decisions, analysis_state="done",
                   prepared=True, produced={"secrets"})
    assert out[0]["state"] == "accepted"
    assert out[0]["decision_reason"] == "base image is pinned"


def test_proven_absence_still_beats_an_accepted_risk():
    """A hole that is actually gone should not keep reading "you accepted
    this" -- the decision only fills the silence where the analysis has
    nothing to say."""
    prev = [p("kk", "iac", "trivy-iac")]
    decisions = {"kk": {"state": "accepted", "reason": "base image is pinned"}}
    out = classify([], prev, {"kk"}, decisions, analysis_state="done",
                   prepared=True, produced={"trivy-iac"})
    assert out[0]["state"] == "fixed"
