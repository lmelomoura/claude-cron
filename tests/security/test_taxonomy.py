import ast
import re
from pathlib import Path

import pytest
from security import adapters, ledger, secrets, taxonomy

REPO = Path(__file__).resolve().parent.parent.parent
SKILL = REPO / "skills" / "security-analysis" / "SKILL.md"
HYGIENE = REPO / "bin" / "security" / "hygiene.py"


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


# ---- The skill against the gate in `cmd_finish`.
#
# CONTRIBUTING rule 1: a rule the code enforces travels with the code. The
# `done` -> `capped` downgrade for untriaged scanner findings shipped without
# either of the two documents that tell the agent what to do, and the skill
# said the OPPOSITE of what the gate measures -- "re-report it with a corrected
# severity ... or leave it alone if it stands". An agent following Job 2
# exactly, reading all ~40 findings and agreeing with ten of them, closed
# `capped` under a note asserting those ten "were never triaged". The note was
# false, and a module whose whole case is that its reports never assert what
# they cannot prove cannot ship one.
#
# Same extraction shape as `test_the_skill_lists_every_rule_name` above, and
# for the same reason: a substring search over the WHOLE document is too weak
# here. "capped", "medium" and "re-report" all appear in several sections, so a
# whole-document check would keep passing after the sentence it was written to
# pin had been deleted from the section that needs it.
#
# THAT CUTS BOTH WAYS, and this file learned it the expensive way. A slice is
# the right scope for "does this section STILL SAY the thing"; it is the wrong
# scope for "does this document ANYWHERE say the opposite". The contradiction
# the gate punishes had two halves -- Job 2's "or leave it alone if it stands"
# and Job 1's "changes nothing but its text" -- and the ban below was written
# against the Job 2 SLICE only, while the second phrase had only ever lived in
# JOB 1. Measured: restoring Job 1's old bullet verbatim left 19 passed, and so
# did dropping the literal sentence "or leave it alone if it stands" back into
# Job 1. Half the fix this file was written to hold had no pin at all. So the
# bans are document-wide (`_forbidden_hits`) and only the affirmative
# requirements stay scoped to the section that must carry them.
#
# AND A TOKEN IS NOT A CLAIM. The pins below used to be `phrase in text`
# membership tests, which a negation satisfies as happily as an assertion:
# rewriting "Ending the run" to say the analysis "is still recorded as `done`
# (never `capped`)" kept every token these tests looked for -- `medium`,
# `capped`, `first three` -- and inverted the rule they exist to state, 19
# passed. Likewise Job 2 rewritten to "a row ... is NOT still re-reported: if
# it stands, leave the scanner's row exactly as it is" matched `still
# re-reported` INSIDE its own negation and dodged the ban by spelling "leave it
# alone" differently. Both rewrites are pinned as data in
# `test_the_pins_catch_the_rewrites_that_used_to_slip_past_them` below, so a
# future weakening of either check fails on the exact text it was weakened to
# admit rather than on a reviewer noticing again.

# Every spelling of "a row that stands needs no re-report" that has actually
# got past this file, banned across the WHOLE document. `untouched` and `left
# alone` are here as bans, which is why the skill's own prose about the old
# behaviour was reworded to say "writing nothing at all onto its row" -- a
# document that may not tell the agent to leave a row alone should not be
# reaching for the words either.
FORBIDDEN_IN_SKILL = (
    r"leave it alone",
    r"changes nothing but its text",
    r"left alone",
    r"untouched",
    r"leav(?:e|es|ing)\b[^.\n]{0,80}?\bas (?:it is|they are|is)\b",
    # The affirmative pin, negated. NOTE the required `still`/`too`: "the
    # findings ... that you never re-reported" is the gate's own correct
    # description of what it counts and must stay legal.
    r"\b(?:not|never|no longer)\s+(?:still\s+re-reported|re-reported\s+too)\b",
)

# `done` -> `capped`, in that direction, in one sentence. Co-presence of the
# two words says nothing: the sentence that inverts the rule contains both.
_DOWNGRADE_DIRECTION = re.compile(
    r"`done`[^.]{0,120}?\b(?:lower(?:s|ed)?|downgrad(?:es|ed)?)\b[^.]{0,40}?`capped`",
    re.I)

# `still re-reported` / `re-reported too`, not immediately negated. The
# lookbehinds are what separate the skill's "a row whose severity you would not
# change is still re-reported" -- which carries a `not` earlier in the same
# clause and is correct -- from "... is NOT still re-reported", which is the
# rewrite that slipped through.
_RE_REPORTED_ANYWAY = (
    re.compile(r"(?<!not )(?<!never )still re-reported", re.I),
    re.compile(r"(?<!not )(?<!never )re-reported too", re.I),
)

# Job 2's decided-row clause, both halves in ONE sentence and in their
# direction: a row a human decided on is NOT the agent's to re-report, AND the
# close does NOT count it. A reviewer kept the first half and flipped the
# second -- "It is not yours to re-report, but the close still counts it
# against you" -- and the suite stayed at 21 passed, because nothing in this
# file had ever looked at the sentence. An agent reading the flipped version
# re-reports the operator's own signed call, or closes `capped` believing it
# owes a reading `_untriaged` never asks for.
_DECIDED_ROW_IS_THE_HUMANS = re.compile(
    r"not yours to re-report[^.]{0,80}?\bthe close does not count it against you",
    re.I)

# The sentence that clause replaced, restored verbatim by the same reviewer with
# the suite still green. A decided row is producer-recorded and sits outside the
# four states, so "exactly" is false -- in the one direction that matters, the
# one that sends the agent to re-report a row the operator already ruled on.
_FOUR_STATES_ARE_EXACTLY = re.compile(r"exactly the rows a producer recorded", re.I)

# "Ending the run"'s half of the same exemption, in ITS direction: the gate
# that section describes does not count a row a human decided on. The clause
# was added beside Job 2's, and deleting it left the suite green -- the only
# pin on the exemption read Job 2, while "Ending the run" is where the agent
# reads what the close will do to it. A decided row named, then a NEGATED
# `counted`, in one sentence. The verb is the section's own (the paragraph is
# about what the close COUNTS), so the pin is on the direction rather than on
# one spelling of the clause: a rewrite that keeps the sentence and drops the
# `not` fails here, and so does one that cuts the clause.
_ENDING_DOES_NOT_COUNT_A_DECIDED_ROW = re.compile(
    r"(?:decided|decision|accepted|false_positive)[^.]{0,200}?"
    r"\b(?:not|never|no longer)\s+(?:be\s+)?counted\b",
    re.I)


def _forbidden_hits(text):
    """Every banned phrase `text` contains, as (pattern, matched text)."""
    return [(pattern, m.group(0))
            for pattern in FORBIDDEN_IN_SKILL
            for m in re.finditer(pattern, text, re.I)]


def _says_a_standing_row_is_re_reported(text):
    """The affirmative sentence Job 2 turns on, or None if it is only negated."""
    for pattern in _RE_REPORTED_ANYWAY:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _states_the_downgrade_direction(text):
    """The clause saying a `done` BECOMES a `capped`, or None."""
    for m in _DOWNGRADE_DIRECTION.finditer(text):
        if not re.search(r"\b(?:not|never|no)\b", m.group(0), re.I):
            return m.group(0)
    return None


def _skill_section(start_pattern, end_pattern=None):
    """The slice of SKILL.md from one heading up to the next, or to the end.

    `end_pattern=None` means the section runs to the END OF THE FILE, and that
    is CHECKED, not assumed: no `## ` heading may follow the start. Without
    the check, "scoped to the section" was in practice "from the heading to
    the end of the file" -- exact only while the section asked for is the last
    `##`, and a section appended after it would have widened every pin that
    reads this slice, silently, to sentences from the new section.
    """
    text = SKILL.read_text()
    start = re.search(start_pattern, text, re.MULTILINE)
    assert start, f"SKILL.md has no section starting {start_pattern!r}"
    section = text[start.start():]
    if end_pattern is None:
        later = re.search(r"^## ", section[1:], re.MULTILINE)
        assert later is None, (
            f"SKILL.md's {start_pattern!r} section is no longer the last one: "
            f"{section[1 + later.start():].splitlines()[0]!r} follows it, so a "
            "slice to the end of the file would hold another section's "
            "sentences too -- pass an explicit end_pattern")
        return section
    end = re.search(end_pattern, section[1:], re.MULTILINE)
    assert end, (
        f"SKILL.md's {start_pattern!r} section never ends: no "
        f"{end_pattern!r} after it, so this slice is the rest of the file")
    return section[:1 + end.start()]


def test_nowhere_in_the_skill_says_a_row_that_stands_can_be_left_as_it_is():
    # DOCUMENT-WIDE, and that is the whole point of it: the two halves of the
    # contradiction lived in two different jobs, and a per-section ban pinned
    # one of them. It does not matter WHERE the skill tells the agent that a
    # finding it agrees with needs no re-report -- an agent reading Job 1 and
    # an agent reading Job 2 both end up producing the state `cmd_finish`
    # counts as unread, and close `capped` under a note asserting that findings
    # they actually opened were never triaged.
    hits = _forbidden_hits(SKILL.read_text())
    assert not hits, (
        "SKILL.md tells the agent, somewhere, that a finding that stands needs "
        f"no re-report: {hits!r}. The re-report IS the triage mark -- "
        "`ledger.record_finding` sets `triaged` when the agent writes onto a "
        "row another producer minted, and there is no field an agent can send "
        "instead")


def test_job_2_says_a_finding_that_stands_is_still_re_reported():
    # The affirmative half, and the one that IS section-scoped: Job 2 is the
    # procedure for every deterministic row at or above the floor, so the rule
    # has to be stated where that procedure is, not merely not-contradicted
    # somewhere else.
    #
    # `end_pattern` is Job 3's heading, and pinning Job 2's slice is not all it
    # does: it also incidentally pins the ORDER of the three jobs. Job 2 moved
    # after Job 3, or Job 3 renumbered, and this section can no longer be cut
    # out -- `_skill_section` fails loudly rather than silently widening the
    # slice to the rest of the file, which would make the assertions below pass
    # on sentences from a different job.
    section = _skill_section(r"^\*\*2\. Triage the deterministic findings\.\*\*",
                             r"^\*\*3\. ")
    lowered = section.lower()
    assert re.search(r"re-report", lowered), \
        "SKILL.md's Job 2 no longer tells the agent to re-report anything"
    assert _says_a_standing_row_is_re_reported(lowered), (
        "SKILL.md's Job 2 no longer says -- affirmatively -- that a finding "
        "whose severity you would NOT change is re-reported anyway, which is "
        "the only case the gate in cmd_finish and the old wording disagreed "
        "about. A negated form does not count: it matches the same words and "
        "states the opposite rule")


def test_ending_the_run_names_the_gate_that_lowers_done_to_capped():
    # The agent has to be able to predict the downgrade before it happens, not
    # discover it in the note afterwards. Three facts, all from `cmd_finish`:
    # the floor is TRIAGE_FLOOR, the verdict becomes `capped`, and the note
    # names the first three by rule and file.
    section = _skill_section(r"^## Ending the run$")
    for token in ("medium", "capped", "first three"):
        assert token in section.lower(), (
            f"SKILL.md's 'Ending the run' never says {token!r} -- the agent "
            "cannot predict a downgrade whose floor, verdict and note this "
            "section does not describe")
    # The tokens above are necessary and nowhere near sufficient. `done` and
    # `capped` both appear in the sentence that says the OPPOSITE of the gate,
    # so this asks for the direction: a `done` that BECOMES a `capped`, in one
    # sentence, with no negation inside it.
    assert _states_the_downgrade_direction(section), (
        "SKILL.md's 'Ending the run' names `done` and `capped` but never says "
        "which way the close moves between them. `cmd_finish` lowers a `done` "
        "to `capped` over untriaged scanner findings; a section that only "
        "mentions both words can state the reverse and still pass a token "
        "check")


def test_job_2_says_a_decided_row_is_the_humans_and_the_close_does_not_count_it():
    # The fourth exclusion in `cli._untriaged` -- a fingerprint the project
    # holds a decision for -- stated where the procedure is, and in its
    # direction. Section-scoped like the other affirmative pin: the rule has to
    # be in Job 2, not merely not-contradicted somewhere else.
    section = _skill_section(r"^\*\*2\. Triage the deterministic findings\.\*\*",
                             r"^\*\*3\. ")
    assert _DECIDED_ROW_IS_THE_HUMANS.search(section), (
        "SKILL.md's Job 2 no longer says, in one sentence, that a row the "
        "checklist shows `accepted` or `false_positive` is not the agent's to "
        "re-report AND that the close does not count it. `_untriaged` excludes "
        "decided fingerprints; a Job 2 that says otherwise sends the agent to "
        "re-report the operator's own signed call, or to close `capped` over a "
        "debt the gate never counts")
    # The sentence it replaced, banned across the WHOLE document, for the
    # reason the comment block above gives: a slice is the wrong scope for
    # "does this document ANYWHERE say the false thing".
    assert not _FOUR_STATES_ARE_EXACTLY.search(SKILL.read_text()), (
        "SKILL.md says again that the four states are 'exactly' the rows a "
        "producer recorded this analysis. A decided row is producer-recorded "
        "and sits outside them -- that sentence was replaced because it was "
        "false in that direction")


def test_ending_the_run_says_a_decided_row_is_not_counted():
    # The exemption `_untriaged`'s fourth exclusion grants, stated where the
    # agent reads what the close will do to it. Job 2 has its pin (above);
    # this is "Ending the run"'s, and the slice is the point: Job 2's own
    # sentence, earlier in the file, must not be what satisfies it.
    section = _skill_section(r"^## Ending the run$")
    assert _ENDING_DOES_NOT_COUNT_A_DECIDED_ROW.search(section), (
        "SKILL.md's 'Ending the run' no longer says that a row the operator "
        "decided on (`accepted`, `false_positive`) is not counted against the "
        "agent. `_untriaged` excludes decided fingerprints, and an agent that "
        "cannot read that here either re-reports the operator's own signed call "
        "or closes `capped` expecting a debt the gate never counts")


def test_the_pins_catch_the_rewrites_that_used_to_slip_past_them():
    # Each of these is a real edit a reviewer made to SKILL.md that inverted a
    # rule and left the suite at 19 passed. They are kept here as data so that
    # weakening either check fails on the exact text the weakening would admit.
    # Applied to the LIVE document, so a rewrite that stops being expressible
    # (because the sentence it edits is gone) fails loudly rather than passing
    # by not applying.
    #
    # WHAT THESE PINS DO NOT CATCH, and nobody should read them as more: a
    # spelling list catches spellings. An exemption written in words that are
    # not on the ban list passes every check in this file -- a later reviewer
    # measured three that did, 21/21 green each time: "can be skipped", "A
    # re-report is optional for a row you agree with", and "neither does a row
    # you read without changing it". None of them contains a banned phrase, and
    # the affirmative pins are satisfied elsewhere in the document, so the skill
    # can grant the exemption the gate punishes and this suite will not notice.
    # The only real defence is a reader who knows the rule; these tests hold the
    # sentences that have ALREADY got past one.
    text = SKILL.read_text()

    # 1. The gate, inverted, with every token the old check looked for intact.
    inverted = ("It counts the findings a SCANNER produced at severity "
                "**`medium` or above** that you never re-reported. If there is "
                "even one, the analysis is still recorded as `done` (never "
                "`capped`), and the report's coverage note gives the count and "
                "**names the first three by rule and file**.")
    assert _states_the_downgrade_direction(inverted) is None, (
        "the direction check passes on the sentence that says a `done` stays a "
        "`done`, which is the rewrite it exists to catch")

    # 2. Job 2, inverted: `still re-reported` matched inside its own negation,
    # and `leave the scanner's row exactly as it is` is not the banned literal
    # `leave it alone`.
    rewrite = ("A row whose severity you would not change is NOT still "
               "re-reported: if it stands, leave the scanner's row exactly as "
               "it is.")
    assert _says_a_standing_row_is_re_reported(rewrite) is None, (
        "the affirmative check still matches inside a negation, so Job 2 can "
        "say the opposite of the gate and pass")
    assert _forbidden_hits(rewrite), (
        "the ban misses 'leave the scanner's row exactly as it is', which is "
        "'leave it alone' spelled differently")

    # 3. The Job 1 half of the same contradiction, which had no pin at all: the
    # old bullet, and the literal trap sentence, both dropped into Job 1 rather
    # than Job 2. A section-scoped ban passes on both.
    job_1 = _skill_section(r"^\*\*1\. Re-verify what was left open\.\*\*",
                           r"^\*\*2\. ")
    for restored in (
            "Re-reporting a row the checklist already shows `open` changes "
            "nothing but its text.",
            "Re-report it with a corrected severity, or leave it alone if it "
            "stands."):
        assert _forbidden_hits(job_1 + restored), (
            f"Job 1 can carry {restored!r} and nothing fails -- the ban is "
            "scoped to Job 2 again")

    # 4. Job 2's decided-row clause with its second half flipped, and the false
    # sentence it replaced restored beside it. A reviewer applied both to the
    # live document after the clause landed and left 21 passed: neither
    # contains a banned phrase, and every older pin is satisfied elsewhere.
    flipped = ("It is not yours to re-report, but the close still counts it "
               "against you.")
    assert _DECIDED_ROW_IS_THE_HUMANS.search(flipped) is None, (
        "the decided-row pin matches a sentence saying the close DOES count "
        "the row, which is the rewrite it exists to catch")
    assert _FOUR_STATES_ARE_EXACTLY.search(
        "Those four states are exactly the rows a producer recorded in THIS "
        "analysis."), "the ban misses the very sentence that was replaced"

    # 5. "Ending the run"'s decided-row clause, cut and flipped. Cut: the
    # sentence as it read before the clause was added, which the suite
    # accepted with the clause deleted. Flipped: the clause kept, its `not`
    # gone -- every token in place, the rule inverted.
    cut = ("It counts the findings a SCANNER produced at severity **`medium` "
           "or above** that you never re-reported. If there is even one, your "
           "`done` is **lowered to `capped`**.")
    assert _ENDING_DOES_NOT_COUNT_A_DECIDED_ROW.search(cut) is None, (
        "the 'Ending the run' pin is satisfied by the sentence with the "
        "decided-row clause cut out, which is the deletion it exists to catch")
    flipped = ("that you never re-reported and that no human has decided on: a "
               "row the checklist shows `accepted` or `false_positive` is the "
               "operator's, as step 2 says, and is counted against you.")
    assert _ENDING_DOES_NOT_COUNT_A_DECIDED_ROW.search(flipped) is None, (
        "the 'Ending the run' pin matches the clause with its `not` removed, "
        "which says the close DOES count the operator's decision")

    # 6. And the live document is clean under all of it.
    assert not _forbidden_hits(text)
    assert _says_a_standing_row_is_re_reported(text)
    assert _states_the_downgrade_direction(text)
    assert _DECIDED_ROW_IS_THE_HUMANS.search(text)
    assert _FOUR_STATES_ARE_EXACTLY.search(text) is None
    assert _ENDING_DOES_NOT_COUNT_A_DECIDED_ROW.search(
        _skill_section(r"^## Ending the run$"))


def test_the_skill_forbids_subagents_and_says_why():
    # Closed at launch by the runner (--disallowedTools Task); this sentence
    # explains the absence rather than enforcing it, which is why it has to
    # name BOTH spellings: the CLI's roster calls the tool `Task`, and an agent
    # told only about `Agent` reads the missing `Task` as a broken environment.
    text = SKILL.read_text()
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
    naming = [s for s in sentences if "`Agent`" in s and "`Task`" in s]
    assert naming, (
        "no sentence in SKILL.md names both `Agent` and `Task` -- the tool is "
        "denied at launch under the name `Task`, and nothing tells the agent")
    assert any(re.search(r"closed at launch|not available|no subagents", s, re.I)
               for s in naming), (
        "SKILL.md names `Agent`/`Task` but never says it is closed: "
        f"{naming!r}")
    # The reason travels with the rule, or the next reader deletes the rule as
    # unexplained. $51.44 on six subagents that triaged nothing is the reason.
    assert "51.44" in text, \
        "SKILL.md forbids subagents without the cost that made it a rule"


# ---- RULE_RENAMES: the declared history of every rule name that changed.
#
# These were written while the map was still EMPTY, and therefore vacuous, on
# purpose: the block that replaced the hand-written detectors renamed every
# secret rule at once, and the first entries added had to land on tests that
# already said what a legal entry looks like. Written afterwards, they would
# have been written against whatever the migration happened to do. The map now
# carries the six secret pairings, so every assertion below is live.

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


# What each renameable category's LIVE producer can actually emit.
#
# Both remaining questions about an entry -- is the source still live, is the
# target a name that will ever be minted -- are asked of the CATEGORY's own
# vocabulary. `taxonomy.is_valid_rule` cannot answer either: it tests
# membership in SAST_RULES, and the test above guarantees every legal key is
# `secret` or `hygiene`, neither of which ever appears there.
#
# `secret` HAS TWO PRODUCERS, and this returns the one that is live wherever
# the engine is installed. It used to read `secrets._RULES` and say, correctly
# at the time, that "every secret finding's rule name is the first field of one
# of its entries". That stopped being true when gitleaks took the secret phase
# over: `cli._scan_secrets` runs the engine when it is present and the
# hand-written scanner only when it is not, so a secret finding's rule is a
# gitleaks RuleID on any machine that has the binary. Reading `secrets._RULES`
# here now would fail every legal entry in the map twice over -- no gitleaks
# name is in it, so no target could pass, and every source still is, so none
# could pass either -- which is a test measuring the vocabulary it was written
# against rather than the one findings are minted from.
#
# `adapters.SEVERITY_BY_RULE` is the engine vocabulary instead: this project's
# own record of the gitleaks rules it has recognised, graded and paired with
# what the hand-written scanner used to call them. It is a SUBSET of gitleaks'
# ~180 rules, which is the safe direction for a target check -- a target has to
# be a name somebody here wrote down deliberately, not merely one the engine
# might emit. The retired vocabulary is not thrown away: it is what
# `test_every_secret_rename_source_is_a_name_the_built_in_scanner_minted`
# checks the sources against.
#
# WHERE THIS GUARD'S STRENGTH COMES FROM, precisely. `SEVERITY_BY_RULE` is
# HAND-MAINTAINED, and nothing checks it against the engine -- so a typo in
# THAT list would be accepted here as a legal rename target by the very test
# built to catch typos in targets. Deliberate: verifying it would mean
# requiring the gitleaks binary in CI, and the suite pins itself to
# CC_SECURITY_ENGINES=off precisely so it does not. The choice is safe because
# the two lists are written and reviewed together and the check runs in the
# safe direction -- a subset of what the engine emits -- so what it actually
# guarantees is "this target is a name a human here wrote down on purpose",
# not "this target is a name gitleaks 8.30.1 ships". Its 18 entries were
# verified against the binary by hand when they were added; a new entry there
# deserves the same, because this test will not do it.
#
# `hygiene` has one producer and no such list. Its rule names are string
# literals passed to `_finding()` inside `scan()`, and at RUNTIME each one is
# reachable only by making that rule's own condition fire -- a world-writable
# mode bit, an absent .gitignore beside a real `.git`, a PEM marker in a
# sniffed file. Enumerating
# them by running the scanner over a fixture tree would therefore produce the
# set of rules THAT FIXTURE triggers, not the set the module can emit, and a
# correct rename of a rule the fixture cannot provoke would be failed as a
# bogus name. So they are read from the source instead, through the single
# constructor every hygiene finding goes through. That couples this helper to
# `_finding` existing and to its first argument being the rule name -- which is
# why a call site it cannot read as a literal is a loud failure below and not a
# quiet skip: a vocabulary that silently shrinks turns both tests underneath it
# vacuous, which is precisely the hole the removed
# `test_every_rename_target_is_a_real_rule` left behind.

def _hygiene_rule_names():
    names = set()
    for node in ast.walk(ast.parse(HYGIENE.read_text())):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_finding"):
            continue
        rule = node.args[0] if node.args else None
        assert isinstance(rule, ast.Constant) and isinstance(rule.value, str), (
            "hygiene.py has a _finding() call whose rule name this test cannot "
            "read as a literal, so the hygiene vocabulary below is incomplete "
            "and the rename checks that use it would pass by not looking")
        names.add(rule.value)
    assert names, "no _finding() call sites found in hygiene.py"
    return names


def _retired_secret_rule_names():
    """The built-in pattern scanner's names -- what a secret rule USED to be.

    Still reachable, not historical: `cli._scan_secrets` falls back to this
    scanner on a machine with no gitleaks. Kept separate from the live
    vocabulary because a rename's two ends belong to different producers.
    """
    return {name for name, *_ in secrets._RULES}


def _producer_vocabulary(category):
    if category == "secret":
        return set(adapters.SEVERITY_BY_RULE)
    if category == "hygiene":
        return _hygiene_rule_names()
    raise AssertionError(
        f"{category!r} is renameable but this file has no vocabulary for it -- "
        "add one beside the other two, or the two tests below stop checking "
        "anything for entries in that category")


def test_the_two_renameable_categories_both_have_a_vocabulary_here():
    # The helper above is only as complete as `RENAMEABLE_CATEGORIES`. A third
    # category becoming renameable without a vocabulary beside it would make
    # both tests below raise on its first entry -- this says so up front,
    # against the ledger's own list rather than against whatever happens to be
    # in the map.
    for category in ledger.RENAMEABLE_CATEGORIES:
        assert _producer_vocabulary(category), f"{category} has no rule names"


def test_every_rename_target_is_a_name_its_scanner_can_emit():
    # The highest-blast-radius mistake this map can hold, and the only check
    # that catches it. A typo in a TARGET migrates every finding under that
    # rule onto an identity no scanner will ever mint again: the next analysis
    # reports the same holes as `new`, the migrated rows are never matched by
    # anything, and every human decision carried across with them points at
    # nothing -- the exact orphan `rename_rule` refuses `sast` to avoid,
    # reached instead through its front door. It matters most for the block
    # this mechanism was built for, which renames every secret rule at once.
    for (category, old), new in taxonomy.RULE_RENAMES.items():
        vocabulary = _producer_vocabulary(category)
        assert new in vocabulary, (
            f"{category}/{old} renames to {new!r}, which no {category} finding "
            f"can ever carry -- {category} emits: {sorted(vocabulary)}")


def test_no_rename_source_is_still_live_in_its_own_category():
    # If a name is both a live rule and a rename source, the migration moves
    # findings off a name the scanner still emits: the next analysis reports
    # them under the old name again, and the rename undoes itself on every run.
    # Asked of the category's OWN vocabulary. This assertion used to read
    # `not is_valid_rule(old)`, which tested the SAST vocabulary -- the one
    # vocabulary a legal entry's name can never come from -- so it passed for
    # every entry that could ever exist while promising, by its name, to catch
    # this.
    #
    # For `secret` this is the ENGINE's vocabulary, and it has to be: the
    # built-in scanner still emits every source in the map, because it is still
    # the fallback for a machine with no gitleaks. That is not a defect in the
    # map, it is the boundary of what `migrate-rules` claims -- it moves a
    # ledger onto the names of the scanner that took over ON THIS MACHINE, and
    # running it somewhere the engine cannot run would indeed undo itself on
    # the next analysis. What this catches is the version of that mistake the
    # map alone can make: renaming one ENGINE rule to another.
    for category, old in taxonomy.RULE_RENAMES:
        assert old not in _producer_vocabulary(category), (
            f"{category}/{old} is still a live {category} rule: the scanner "
            "re-emits it on the next analysis and the rename undoes itself")


def test_every_secret_rename_source_is_a_name_the_built_in_scanner_minted():
    # The other end of the same entry. A secret rename moves findings from the
    # retired scanner's vocabulary to the engine's, so a source that was never
    # one of `secrets._RULES`' names cannot be describing findings that exist:
    # it is a typo, or an engine rule someone tried to rename by hand. Neither
    # is loud on its own -- `rename_rule` matches nothing and returns 0, and
    # `migrate-rules` prints a clean result for a map that did nothing -- which
    # is exactly the silence a map of promises should not be able to hold.
    retired = _retired_secret_rule_names()
    for category, old in taxonomy.RULE_RENAMES:
        if category != "secret":
            continue
        assert old in retired, (
            f"secret/{old} is not a name the built-in scanner ever minted, so "
            f"no finding carries it -- secrets._RULES has: {sorted(retired)}")


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
