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


def test_iac_is_deterministic_and_fixed_once_prepare_completed():
    """Trivy's misconfiguration scan runs inside `prepare`, the same as
    secrets/dependencies/hygiene -- never inside the agent's own SAST pass --
    so an `iac` finding absent from `current` is provably gone the moment
    `prepare` finished, whatever `analysis_state` the run is still in."""
    prev = [dict(f("cc"), category="iac")]
    out = classify([], prev, {"cc"}, {}, analysis_state="running", prepared=True)
    assert out[0]["state"] == "fixed"
    out = classify([], prev, {"cc"}, {}, analysis_state="running", prepared=False)
    assert out[0]["state"] == "pending"
