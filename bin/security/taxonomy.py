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
    # Not on OWASP's own A04 CWE list. Kept here anyway, because a missing
    # rate limit is a control nobody designed in, not a control built and
    # then implemented wrong -- which is what A04 ("Insecure Design") means
    # to capture. A judgement call: there is no published CWE-770 mapping to
    # verify it against.
    "missing-rate-limiting":      ("CWE-770",  "A04:2021"),
    "open-redirect":              ("CWE-601",  "A01:2021"),
    "path-traversal":             ("CWE-22",   "A01:2021"),
    # CWE-1427 (Improper Neutralization of Input Used for LLM Prompting)
    # was added in 2024 and is the correct identifier -- not CWE-77, which
    # is command injection and is what this gets mistaken for.
    "prompt-injection-in-source": ("CWE-1427", "A03:2021"),
    # Not on OWASP's own A04 CWE list either -- the same judgement call as
    # `missing-rate-limiting`'s: a race condition is a concurrency design
    # left unresolved, not a correctly designed check implemented wrong,
    # which is what A04 ("Insecure Design") means to capture. The best fit
    # on offer, not a verified one.
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
# Keyed by CATEGORY as well as name because the category is what DECIDES the
# rename: the fingerprint's fourth argument differs by source, so the category
# picks the recipe the new identity is rebuilt with -- and picks whether a
# rename is possible at all. `ledger.rename_rule` dispatches on it (see
# `_REFINGERPRINT` there), accepting `secret` and `hygiene` and refusing the
# rest; see `ledger.RENAMEABLE_CATEGORIES` for why, and `test_taxonomy.py` for
# the invariants an entry has to satisfy.
#
# NOT to disambiguate the name -- but the naming conventions no longer keep the
# categories apart on their own, which is why the key carries the category.
# SAST rules are kebab-case (the table above), hygiene rules are snake_case
# (the literals hygiene.py passes to `_finding`), and a dependency rule is a
# GHSA/CVE id. A SECRET rule is BOTH: snake_case from the built-in pattern
# scanner (`secrets._RULES`) -- in ledgers written before the two vocabularies
# were unified, and still for its two unmapped rules -- and kebab-case from
# gitleaks, whose rule ids look exactly like the SAST table's names, and since
# `cli._scan_secrets` renames at mint, from the built-in's mapped types too.
# Gitleaks ships around 180 of those ids, gaining more with every release. Nothing
# ENFORCES that a name is unique across categories, and a key carrying the
# category never has to depend on it: `rename_rule` matches on (category, rule)
# and leaves an identically named rule in the other category untouched.
#
# THE SECRET CATEGORY HAS TWO PRODUCERS AND ONE VOCABULARY. Where gitleaks is
# installed both run; where it is not, the built-in runs alone; on EITHER path
# `cli._scan_secrets` mints the built-in scanner's findings under the names
# below BEFORE the fingerprint is computed (`secrets.scan_tree(rename=...)`),
# so no analysis on this branch mints a source name of this map into the
# ledger, and a row's identity does not depend on which scanner was on the
# machine the day it was minted. The first version renamed on the union path
# only; the first machine that then lost the engine minted `generic_secret`
# where the previous analysis held `generic-api-key`, and the checklist read
# `fixed` beside `new` for one credential. The map is what makes the union one
# finding per credential instead of two, and what keeps that finding one
# across a scanner coming and going. `migrate-rules` therefore serves ledgers
# written BEFORE this branch -- rows the built-in minted under the source
# names when it ran alone -- and nothing an analysis does today undoes it, so
# it runs on ANY machine, engine or not: the ledger it fixes is exactly the
# one a machine without gitleaks wrote, and refusing it there (as the verb
# once did, for the re-minting this paragraph describes as gone) left that
# operator with a `fixed`-beside-`new` flip and an orphaned decision. It stays
# a deliberate one-shot verb because a rename is a promise about identity: the
# operator makes it once, knowingly.
#
# Each pairing below was VERIFIED by running gitleaks 8.30.1 over a synthetic
# sample of the shapes the hand-written pattern accepts and reading the RuleID
# back -- never by matching the two names up by eye. A target the engine will
# never mint is precisely the orphan this mechanism exists to prevent: the
# findings move onto an identity no scanner can reproduce, and the human
# decisions carried across with them point at nothing for ever. Where our
# pattern is the LOOSER of the two -- where it accepts shapes the engine's
# regex rejects, so a sample can be built that ours matches and gitleaks
# reports nothing for -- the pairing is still made, and the over-match is
# written down on the entry rather than left for a reader to discover.
RULE_RENAMES: dict[tuple[str, str], str] = {
    # Both prefixes ours accepts (AKIA, ASIA) are inside gitleaks' own
    # `aws-access-token` regex. Ours over-matches the BODY, though: gitleaks
    # wants base32 (`[A-Z2-7]{16}`) where ours takes `[0-9A-Z]{16}`, so the
    # four characters base32 has no digit for -- 0, 1, 8, 9 -- are ours alone.
    # Measured: `AKIAQWERTYUIOPASDFGH` reports as `aws-access-token`, and
    # `AKIAUJZDE8GXD6NCF10E` reports as nothing at all. Mapped anyway, on
    # `openai_key`'s terms: a real AWS key id IS base32, so for every finding
    # that is one the rename is exact, and a row that never was one is swept
    # as `fixed` on the next analysis whether it was migrated or not. There is
    # no narrower target to prefer.
    ("secret", "aws_access_key"): "aws-access-token",
    # `sk_live_` and `rk_live_` -- the secret and the restricted key -- are two
    # Stripe credentials that gitleaks reports under one rule. Converging, not
    # diverging: every row under our name has exactly one place to land.
    ("secret", "stripe_key"): "stripe-access-token",
    # Ours is `sk-` + 32 or more; gitleaks pins the `T3BlbkFJ` marker a real
    # OpenAI key carries, and calls anything else `generic-api-key`. Mapped
    # anyway because both rules name ONE credential type and ours simply
    # over-matches it: for a genuine OpenAI key the rename is exact, and for an
    # `sk-` blob that was never one, the row is swept as `fixed` on the next
    # analysis whether it was migrated or not.
    ("secret", "openai_key"): "openai-api-key",
    # Every PEM header ours accepts (RSA, EC, OPENSSH, PGP, bare) reports as
    # `private-key`. BOTH scanners need the BODY: gitleaks always did, and ours
    # since the union brought Minerva's two header-only rows back as findings
    # only it saw (`secrets._pem_body_follows`; of its five `private_key` rows
    # there, the other three carry a body and stay) -- so a row minted from a
    # lone header before that is reported `fixed` once by either scanner. That
    # is the pattern fix, not the rename; there is no other name for such a
    # row to land on.
    ("secret", "private_key"): "private-key",
    # `AIza…`. Google's name for the product changed, not the credential.
    ("secret", "google_api_key"): "gcp-api-key",
    # The one rule on either side that matches on SHAPE alone -- keyword,
    # assignment, high-entropy blob -- rather than on a vendor's prefix. Every
    # keyword spelling ours accepts (password, passwd, secret, token, api_key)
    # fires gitleaks' generic rule on the same line.
    ("secret", "generic_secret"): "generic-api-key",
    # DELIBERATELY UNMAPPED, both for the same reason: one rule of ours is
    # several credential types of theirs, and a rename is a PROMISE that the
    # two names are one rule. There is no single target that is true for such a
    # row, and picking the commonest would relabel the rest as something they
    # are not -- silently, in the one field a human's decision hangs off.
    #
    #   github_token  ghp_ -> github-pat, gho_ -> github-oauth,
    #                 ghu_/ghs_ -> github-app-token, ghr_ -> github-refresh-token
    #   slack_token   xoxb -> slack-bot-token, xoxp -> slack-user-token,
    #                 xoxa/xoxr -> slack-legacy-workspace-token,
    #                 xoxs -> slack-legacy-token
    #
    # Five prefixes on four rules, not five on three: `xoxs` IS a gitleaks rule
    # (`slack-legacy-token`, keywords `xoxo`/`xoxs`), and this comment used to
    # say it was not. Measured, on the sample the earlier claim was measured
    # against being too short to fire it:
    # `xoxs-2-511111111-31111111111-d72c34ab4dbabc0f` reports as
    # `slack-legacy-token`, our own `slack_token` regex accepts that same
    # string, and the rule is graded in `adapters.SEVERITY_BY_RULE`. The fourth
    # target makes `slack_token` MORE unmappable, not less -- one more true
    # answer among four that a single rename could only pick one of.
    #
    # Both report as `new` once, under the engine's own name, which is honest.
}


def is_valid_rule(rule: str) -> bool:
    return rule in SAST_RULES


def classify(rule: str) -> tuple[str, str]:
    """The (CWE, OWASP) pair for a rule. Raises KeyError if unknown.

    Deliberately raises rather than returning a default: every caller here
    has already validated, or wants to fail loudly rather than write an
    unclassifiable row.
    """
    return SAST_RULES[rule]
