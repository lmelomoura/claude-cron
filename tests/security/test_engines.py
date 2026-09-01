import json
import pytest
from security import engines


def test_a_missing_binary_is_absent_not_an_error():
    assert engines.find("definitely-not-a-real-binary-xyz") is None


def test_purge_strips_the_forbidden_fields_from_gitleaks():
    raw = [{"RuleID": "aws-access-token", "File": "config/prod.env",
            "StartLine": 3, "Entropy": 4.5,
            "Match": "AKIA_THE_ACTUAL_VALUE", "Secret": "AKIA_THE_ACTUAL_VALUE"}]
    clean = engines.purge("gitleaks", raw)
    assert "Match" not in clean[0]
    assert "Secret" not in clean[0]
    assert clean[0]["RuleID"] == "aws-access-token"
    assert clean[0]["StartLine"] == 3


def test_purge_strips_the_code_line_from_semgrep():
    # Semgrep returns the matched source line. A finding ON a credential
    # would carry that credential in `extra.lines`.
    raw = {"results": [{"check_id": "x", "path": "a.py",
                        "start": {"line": 1}, "end": {"line": 1},
                        "extra": {"severity": "WARNING", "lines": "KEY = 'the-value'",
                                  "metadata": {"cwe": ["CWE-327: ..."]}}}]}
    clean = engines.purge("semgrep", raw)
    assert "lines" not in clean["results"][0]["extra"]
    assert clean["results"][0]["extra"]["metadata"]["cwe"] == ["CWE-327: ..."]


def test_purge_leaves_an_unknown_engine_untouched():
    assert engines.purge("nosuch", {"a": 1}) == {"a": 1}


def test_purge_survives_a_shape_it_did_not_expect():
    # A version bump can change the shape. Purge must not crash the whole
    # analysis over it -- but it must also not pass a value through.
    assert engines.purge("gitleaks", {"unexpected": "object"}) is not None
    assert engines.purge("gitleaks", []) == []


def test_run_json_reports_a_missing_binary_as_a_note_not_an_exception(tmp_path):
    data, note = engines.run_json("definitely-not-a-real-binary-xyz", [], tmp_path)
    assert data is None
    assert "definitely-not-a-real-binary-xyz" in note


def test_purge_reaches_a_forbidden_field_nested_deeper_than_the_fixtures_go():
    # The fixtures above only exercise the depths the real engines happen to
    # use today: a flat list of dicts for Gitleaks, and a fixed multi-level
    # path for Semgrep. A purge that walks only those known paths would pass
    # every test above while still leaking a credential buried somewhere a
    # version bump moved it to. Build a shape none of the fixtures cover --
    # a list inside a dict inside a list -- and prove the value is gone
    # from the *entire* serialized result, not just absent from the one key
    # we happen to check.
    secret = "AKIA_DEEPLY_NESTED_VALUE"
    raw = [                                          # list
        {                                            # dict
            "RuleID": "aws-access-token",
            "Findings": [                            # list, inside the dict above
                {"Match": secret, "Secret": secret, "Context": "kept"},
            ],
        }
    ]
    clean = engines.purge("gitleaks", raw)
    dumped = json.dumps(clean)
    assert secret not in dumped
    # The purge only drops the named fields -- it must not also destroy
    # unrelated data sitting beside them at the same depth.
    assert clean[0]["Findings"][0]["Context"] == "kept"
    assert "Match" not in clean[0]["Findings"][0]
    assert "Secret" not in clean[0]["Findings"][0]
