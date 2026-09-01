import re
from pathlib import Path

import pytest
from security import taxonomy

SKILL = (Path(__file__).resolve().parent.parent.parent
         / "skills" / "security-analysis" / "SKILL.md")


def test_a_known_rule_classifies_to_its_cwe_and_owasp():
    assert taxonomy.classify("sql-injection") == ("CWE-89", "A03:2021")


def test_an_unknown_rule_is_not_valid():
    assert taxonomy.is_valid_rule("sqli") is False
    assert taxonomy.is_valid_rule("sql-injection") is True


def test_classify_refuses_an_unknown_rule():
    # Never guess. A rule outside the vocabulary is a caller bug, and
    # returning ("", "") would put an unclassified finding in the ledger
    # under a name nothing can map back.
    with pytest.raises(KeyError):
        taxonomy.classify("made-up-rule")


def test_other_is_the_escape_hatch_and_carries_no_cwe():
    # A closed vocabulary with no escape makes the agent pick the nearest
    # wrong rule, which is worse than an honest "unclassified".
    assert taxonomy.is_valid_rule("other") is True
    assert taxonomy.classify("other") == ("", "")


def test_every_rule_name_is_lowercase_kebab_case():
    # The rule is part of the fingerprint. "SQL-Injection" and
    # "sql-injection" would be two identities for one hole.
    for name in taxonomy.RULE_NAMES:
        assert name == name.lower()
        assert " " not in name
        assert "_" not in name


def test_rule_names_are_sorted_and_unique():
    assert list(taxonomy.RULE_NAMES) == sorted(set(taxonomy.RULE_NAMES))


def test_prompt_injection_is_in_the_vocabulary():
    # The skill already tells the agent to report this rule by name; if it
    # is not in the vocabulary, report-finding refuses the one finding the
    # skill explicitly asks for.
    assert taxonomy.is_valid_rule("prompt-injection-in-source") is True
    # Pinned exactly: CWE-1427 is routinely mistaken for CWE-77 (command
    # injection). A silent revert to CWE-77 must fail this test.
    assert taxonomy.classify("prompt-injection-in-source") == ("CWE-1427", "A03:2021")


def test_sensitive_data_exposure_maps_to_broken_access_control():
    # Pinned exactly: OWASP's own mapping table lists CWE-200 under
    # A01:2021 (Broken Access Control), not A02:2021 (Cryptographic
    # Failures) -- even though "Sensitive Data Exposure" was the NAME of
    # A3:2017. A silent "correction" back to A02 must fail this test.
    assert taxonomy.classify("sensitive-data-exposure") == ("CWE-200", "A01:2021")


def test_the_skill_lists_every_rule_name():
    # The vocabulary and the document that teaches it drift apart in
    # silence otherwise: a rule added here and not there is a rule the
    # agent never uses, and one removed here but not there is an analysis
    # that fails at report time.
    #
    # A plain `name in text` substring check against the WHOLE document is
    # too weak for one entry: "other" is also ordinary English, and it
    # shows up twice in prose that predates the vocabulary block ("any
    # other installed tree", "for any other reason"). If a future edit
    # deleted the `other` entry -- and the escape-hatch guidance beside it
    # -- from the vocabulary block, those two unrelated sentences would
    # still contain the word "other" and this test would keep passing
    # while the agent silently lost its only honest way to report an
    # unclassified finding. So instead of searching the whole document,
    # pull out just the fenced block that holds the vocabulary and require
    # an exact token match inside it -- this protects every rule name
    # uniformly, not just the one that happens to collide with prose.
    text = SKILL.read_text()
    match = re.search(r"closed vocabulary.*?```\n(.*?)```", text, re.DOTALL)
    assert match, "SKILL.md has no fenced vocabulary block after 'closed vocabulary'"
    vocabulary = set(match.group(1).split())
    for name in taxonomy.RULE_NAMES:
        assert name in vocabulary, (
            f"SKILL.md's vocabulary block does not list the rule {name!r}"
        )
