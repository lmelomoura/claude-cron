import re
from pathlib import Path

import pytest
from security import ledger, taxonomy

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


# ---- RULE_RENAMES: the declared history of every rule name that changed.
#
# The map is EMPTY today and these tests are therefore vacuous today. That is
# the point of writing them now: the block that replaces the hand-written
# detectors renames every secret rule at once, and the first entry added to
# this map has to land on tests that already say what a legal entry looks
# like. Written afterwards, they would be written against whatever the
# migration happened to do.

def test_a_rename_is_keyed_by_category_and_old_rule():
    # The rule name is unique only within its category, and the recompute
    # recipe differs between categories -- so the key has to carry both.
    for key, new in taxonomy.RULE_RENAMES.items():
        assert isinstance(key, tuple) and len(key) == 2, \
            f"{key!r} is not a (category, old_rule) pair"
        category, old = key
        assert isinstance(new, str) and new.strip(), f"{key!r} renames to nothing"
        assert old != new, f"{key!r} renames a rule to itself"


def test_every_rename_is_in_a_category_the_ledger_can_actually_rename():
    # `rename_rule` refuses `sast` and `dependency` -- their fingerprints
    # cannot be rebuilt from the ledger. An entry here in one of those
    # categories is a `migrate-rules` run that dies partway through the map,
    # having already applied whatever came before it.
    for category, old in taxonomy.RULE_RENAMES:
        assert category in ledger.RENAMEABLE_CATEGORIES, (
            f"{category}/{old} is in a category the ledger refuses to rename")


def test_no_rename_source_is_still_a_valid_rule():
    # If a name is both a live rule and a rename source, the migration would
    # move findings off a name that is still in use -- the next analysis
    # reports them under the old name again and the rename undoes itself on
    # every run. `is_valid_rule` is the SAST vocabulary, which is also the one
    # category that can never appear here; the assertion is kept because a
    # rename source colliding with a live rule name is the failure it names,
    # whichever vocabulary the name comes from.
    for _, old in taxonomy.RULE_RENAMES:
        assert not taxonomy.is_valid_rule(old)


def test_renames_do_not_chain():
    # `migrate-rules` walks the map ONCE, in insertion order. With a -> b and
    # b -> c both present, a's findings land on b and are then swept on to c
    # if the entries are ordered one way, and stop at b if they are ordered
    # the other -- the result depends on dict order, which is not a thing a
    # ledger's identities should depend on. A rule renamed twice is recorded
    # as one hop from the oldest name to the current one.
    targets = {(category, new) for (category, _), new in taxonomy.RULE_RENAMES.items()}
    for key in taxonomy.RULE_RENAMES:
        assert key not in targets, (
            f"{key[1]!r} is both a rename source and a rename target in "
            f"{key[0]}: collapse the chain into one entry")
