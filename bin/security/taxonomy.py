"""The closed vocabulary of SAST rule names, and what each one means.

Why closed. The rule name is an INPUT TO THE FINGERPRINT (see
fingerprint.fingerprint): `sha256(category + rule + path + snippet)`. An
agent that writes `sql-injection` on Monday and `sqli` on Tuesday has
reported one hole under two identities -- it shows up as `fixed` and `new`
in the same checklist, and a human's `accepted` decision against the first
never matches the second again. Free text cannot be made stable by asking
nicely in a prompt; it is made stable by refusing the second spelling.

Why an escape hatch. A vocabulary with no `other` forces an agent that
found something real but unlisted to pick the nearest wrong name, which
corrupts the classification of everything downstream. `other` carries no
CWE precisely so that an unclassified finding is visibly unclassified
instead of quietly mislabelled.

The OWASP codes are the 2021 Top 10, which is the edition Semgrep's
`p/owasp-top-ten` ruleset targets -- the ruleset this vocabulary has to
line up with when the engines land in the next block.
"""

# rule -> (CWE, OWASP Top 10 2021)
SAST_RULES = {
    "broken-access-control":      ("CWE-862",  "A01:2021"),
    "broken-authentication":      ("CWE-287",  "A07:2021"),
    "code-injection":             ("CWE-94",   "A03:2021"),
    "command-injection":          ("CWE-78",   "A03:2021"),
    "hardcoded-credentials":      ("CWE-798",  "A07:2021"),
    "improper-input-validation":  ("CWE-20",   "A03:2021"),
    "insecure-configuration":     ("CWE-16",   "A05:2021"),
    "insecure-deserialization":   ("CWE-502",  "A08:2021"),
    "insecure-randomness":        ("CWE-338",  "A02:2021"),
    "missing-rate-limiting":      ("CWE-770",  "A04:2021"),
    "open-redirect":              ("CWE-601",  "A01:2021"),
    "path-traversal":             ("CWE-22",   "A01:2021"),
    # CWE-1427 (Improper Neutralization of Input Used for LLM Prompting)
    # was added in 2024 and is the correct identifier -- not CWE-77, which
    # is command injection and is what this gets mistaken for.
    "prompt-injection-in-source": ("CWE-1427", "A03:2021"),
    "race-condition":             ("CWE-362",  "A04:2021"),
    # A01, not A02. "Sensitive Data Exposure" was the NAME of A3:2017, and
    # the 2021 revision reused that name for the unrelated, narrower
    # cryptographic-failures category -- while CWE-200 itself stayed under
    # Broken Access Control, where OWASP's own mapping table lists it. The
    # familiar name is the trap here.
    "sensitive-data-exposure":    ("CWE-200",  "A01:2021"),
    "sql-injection":              ("CWE-89",   "A03:2021"),
    "ssrf":                       ("CWE-918",  "A10:2021"),
    "weak-cryptography":          ("CWE-327",  "A02:2021"),
    "xss":                        ("CWE-79",   "A03:2021"),
    "xxe":                        ("CWE-611",  "A05:2021"),
    # The escape hatch. Empty strings, not None: these values go straight
    # into TEXT NOT NULL DEFAULT '' columns.
    "other":                      ("",         ""),
}

RULE_NAMES = tuple(sorted(SAST_RULES))


# (category, old rule name) -> the rule's current name. Every entry here is a
# promise that a finding recorded under the old name is the SAME finding as
# one recorded under the new one, and that a human decision about it still
# applies. Do not use this to merge two rules that meant different things:
# that is a new finding, and it should be reported as one.
#
# Keyed by CATEGORY as well as name because a rule name is only unique within
# its category -- `private_key` is both a secret type and a hygiene check --
# and because the fingerprint's fourth argument, and therefore whether a
# rename is possible at all, is decided by the category. `ledger.rename_rule`
# accepts `secret` and `hygiene` and refuses the rest; see
# `ledger.RENAMEABLE_CATEGORIES` for why, and `test_taxonomy.py` for the
# invariants an entry has to satisfy.
#
# Empty until the engines block renames the deterministic rules wholesale.
# The mechanism ships first, and with tests, because writing it after the
# rename has already happened means writing it against a ledger that is
# already wrong.
RULE_RENAMES: dict[tuple[str, str], str] = {}


def is_valid_rule(rule: str) -> bool:
    return rule in SAST_RULES


def classify(rule: str) -> tuple[str, str]:
    """The (CWE, OWASP) pair for a rule. Raises KeyError if unknown.

    Deliberately raises rather than returning a default: every caller here
    has already validated, or wants to fail loudly rather than write an
    unclassifiable row.
    """
    return SAST_RULES[rule]
