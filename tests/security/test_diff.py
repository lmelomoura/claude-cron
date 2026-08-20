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
