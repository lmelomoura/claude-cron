"""One reading of what an analysis is in scope for, shared by every phase.

`ignore_paths` is a promise about the ANALYSIS, not about one scanner: a
fixtures directory full of deliberately fake credentials must not become a
finding whether the scanner that opened it was the working-tree sweep, the
history sweep or the hygiene pass. This lived as a private `_ignored` inside
secrets.py, so the other two phases quietly disagreed with it -- the same
glob excluded a file from one report and not from the next.

THE SAME ARGUMENT NOW APPLIES ONE LEVEL UP, WHICH IS WHY THE DEFAULT LIVES
HERE TOO. `ignore_paths` had to be hand-written before it did anything, and
almost nobody wrote it: every project got the fake credentials in its own
fixtures reported on every single analysis until somebody noticed and
configured them away. The filter now starts from a default, and the default
has to be read by the ENGINE and by the FALLBACK through this one function,
because a default only the built-in scanner honoured would make the same
repository report differently depending on which binaries the machine
happens to have installed -- the per-machine divergence this project has
already had to fix twice.

Deliberately NOT used by deps.inventory: a lockfile under an ignored glob
still declares dependencies this project ships, so the SBOM this project
hands out stays complete wherever the file sits. The FINDINGS from that
lockfile are a different question, and they are filtered -- in
`cli._scan_dependencies`, for whichever producer ran. Filtering only the
engine's output would make an operator's globs suppress a CVE on a machine
with Trivy installed and not on one without, which is a report that changes
by machine. That exemption is now LOUD rather than merely documented: see
`SBOM_UNFILTERED_NOTE`, and the comment above it for why the SBOM was not
simply filtered to match.
"""

import fnmatch
from functools import lru_cache
from pathlib import Path

# ---------------------------------------------------------------- the default
#
# WHY THIS LIST IS SHORT, AND WHY IT IS NOT `tests/**`.
#
# The item this implements is called "tests and fixtures suppressed by
# default", and only the fixtures half is taken. A credential hard-coded in a
# test FILE is in the repository and is readable by everyone with a clone: it
# is a real leak, and a default that swallowed `tests/**` would hide it on
# every project that never configured anything -- which is precisely the
# population this default exists for. "Looks like a test" is a heuristic;
# "sits in a directory whose whole purpose is sample data" is a convention,
# and only the second one is safe to apply to a repository nobody has looked
# at yet.
#
# Each name below is a whole path COMPONENT at ANY DEPTH, matched the way a
# single-segment `secrets.SKIP_DIRS` entry is matched (that set now also takes
# multi-segment paths; these are all names) and for the same reason:
# `testdata` is Go's own reserved directory name and sits beside the package
# it belongs to, never at the top of the tree, so a top-level-only rule would
# miss every Go repository. `myfixtures/` is not `fixtures/` and is not
# touched.
DEFAULT_IGNORE_DIRS = ("__fixtures__", "fixtures", "testdata")

# Matched CASE-INSENSITIVELY, which is not tidiness. `Fixtures/` and
# `TestData/` are the .NET and Swift spelling of the identical convention, and
# a case-sensitive match told that repository's reader -- in `DEFAULT_NOTE`,
# on every report -- that its fixtures had been suppressed while they had not.
# A note that describes a filter the analysis did not apply is worse than no
# note. The ENGINE pre-filters below stay case-sensitive (a command line
# cannot enumerate casings); that costs engine time on a `Fixtures/` tree and
# nothing else, because `ignored` is applied to everything that comes back.
_DEFAULT_IGNORE_DIRS_FOLDED = frozenset(d.lower() for d in DEFAULT_IGNORE_DIRS)

# The SECRET scan's other half of the same default (A4.14). `hygiene.py` has
# excluded these four suffixes from its committed-`.env` rule since it was
# written -- this is the one list, read from here by both, rather than a
# second copy free to drift from the first.
#
# `secrets.py` filtered the VALUE through `_is_placeholder` and never the
# FILE, and `_is_placeholder` only ever guards the ONE generic rule: a
# `.env.example` carrying `AKIAIOSFODNN7EXAMPLE` matches the shaped
# `aws_access_key` rule, which has no entropy gate and no placeholder gate at
# all, and was reported as a committed AWS key. Committing a template of your
# configuration is the documented, correct thing to do; the scanner was
# reporting people for doing it.
SAMPLE_SUFFIXES = (".dist", ".example", ".sample", ".template")

# THE RULES A TEMPLATE SILENCES -- AN ALLOWLIST, AND DELIBERATELY A SHORT ONE.
#
# The first version of this default excluded a `.example` file from the secret
# scan ENTIRELY, on the reasoning that "the value in a template is a shape,
# not a secret". That reasoning is true of the two rules named below and false
# of everything else: a PEM body is never a shape. Measured, with a real
# `openssl genrsa 2048` key in `certs/server.key.example`, the file-level
# exclusion was reported by NOTHING -- not the built-in scanner, not gitleaks
# through `adapters.gitleaks`, and not `hygiene._is_key_material`, whose
# suffix test does not see past `.example` either. Gitleaks on its own
# reported it. A default that hides real key material is the one outcome this
# whole filter was not allowed to have, and this project's own argument for
# NOT suppressing `tests/**` -- "a credential hard-coded in a test file is in
# the repository and readable by everyone with a clone" -- applies to a
# template word for word.
#
# So the gate moved from the FILE to the RULE, which is where the diagnosis
# always pointed: the shaped rules have no placeholder gate. The two entries
# per scanner are the two rules that genuinely over-fire on a template -- the
# generic `password = <blob>` rule, whose whole job is shape-matching, and the
# AWS rule, which has neither an entropy gate nor a placeholder gate and is
# what `AKIAIOSFODNN7EXAMPLE` in a `.env.example` trips. Every other rule
# reports from a template exactly as it reports from anywhere else.
#
# AN ALLOWLIST AND NOT A DENYLIST, so the default direction for a rule nobody
# has thought about is to REPORT. Gitleaks ships some 200 rules and adds more;
# a denylist of "rules that still matter in a template" would silence each new
# one on the day it arrived, silently, in the one file class where silence
# already cost us a private key.
SAMPLE_SUPPRESSED_RULES = frozenset({
    # secrets.py's own rule names
    "generic_secret",
    "aws_access_key",
    # ...and gitleaks' names for the same two rules. One set rather than a
    # mapping: the two vocabularies do not collide, and each scanner looks up
    # the name it actually produced.
    "generic-api-key",
    "aws-access-token",
})

# ---------------------------------------------------------------- the way out
#
# A DEFAULT THAT CANNOT BE TURNED OFF IS A TRAP. Some projects legitimately
# keep real credentials in a fixture -- a test that exercises a live sandbox
# account, a deliberately-vulnerable training repository -- and want them
# reported. This one sentinel, written as an entry of the project's own
# `ignore_paths`, turns BOTH halves of the default off.
#
# IT IS PER-PROJECT AND NOT PER-MACHINE, WHICH IS THE WHOLE POINT OF PUTTING
# IT HERE. An environment variable would have been less code (`ENGINES_ENV`
# in adapters.py is the precedent) and would have been the wrong shape: "does
# this project want its fixtures scanned" is a fact about the repository, and
# a switch that lives on the laptop makes the report differ between two
# machines analysing the same commit. `ignore_paths` already travels with the
# project's config, is already written by the Security tab, and already
# reaches every phase -- so the switch rides in it, spelled the way
# .gitignore has trained everyone to read a leading `!`.
#
# It cancels THIS PROJECT'S OWN default and nothing else: an operator who
# also wrote `docs/**` still means it. That restriction is not tidiness, it
# is the only version that can be true -- the engines are handed the
# operator's globs as a command line and never read those files at all, so a
# re-inclusion the post-filter granted could not resurrect a finding the
# engine was never allowed to produce.
DEFAULTS_OFF = "!defaults"

# MATCHED WITHOUT REGARD TO CASE, because the sentinel is this project's own
# token and not a path: there is no information in its capitalisation, and
# there was a great deal of damage in requiring it. `!Defaults` compared
# unequal, so `defaults_apply` stayed True -- the default silently STAYED ON,
# which is the unsafe direction -- and the entry then went on to be treated as
# a path glob, reaching three command lines as `--skip-dirs '!Defaults'`,
# `--exclude './!Defaults'` and a pair of gitleaks allowlist regexes. A
# project that keeps real credentials in a fixture and typed the switch
# believed it was being scanned and was not.
#
# Anything else beginning with `!` -- `!default`, `!defaults/**`, `!tests/**`
# -- is NOT guessed at. It is dropped from every engine command line and from
# the path matcher (see `globs`) and it is said out loud (see
# `unknown_switch_note`), because the one thing it must never do is look like
# it worked.
_DEFAULTS_OFF_FOLDED = DEFAULTS_OFF.lower()

# ONE sentence, said whenever the default is in effect, so a reader can tell
# "nothing was there" from "we did not look" -- the same rule every other
# coverage note in this project follows. Said unconditionally rather than
# only when something was actually suppressed: counting the suppressions
# would mean threading a tally through five phases and two scanners, and the
# sentence describes a standing policy of the analysis, which is true whether
# or not it bit this time.
#
# It names what the template half actually does now. "Secrets in .example
# files were not reported" was the old sentence and it was a promise the
# filter is no longer allowed to keep: a private key in a template is
# reported, and a reader deciding whether to trust an empty secret section
# needs to know which of the two it got.
DEFAULT_NOTE = (
    "A default noise filter was in effect: findings under a fixtures, "
    "__fixtures__ or testdata directory were not reported, and in files "
    "ending .dist, .example, .sample or .template — committed templates of a "
    "configuration — a generic password/token value and an AWS access key "
    "were read as placeholders rather than leaks. Every other credential "
    "shape, a private key included, is still reported from a template. Add "
    f'"{DEFAULTS_OFF}" to the project\'s ignore_paths to scan all of it.')

# WHAT AN UNRECOGNISED `!` ENTRY COST, said in the report and on stderr.
#
# Not a hard error, and that is a decision rather than an omission. Refusing
# the analysis would certainly be loud, and it would also fail a scheduled run
# over a typo in a field the operator cannot see the effect of -- while the
# thing that actually needs fixing is a belief ("my fixtures are being
# scanned") that only a sentence can correct. This project's established
# channel for "the analysis did less than you think" is the coverage note, and
# the note is where the reader already looks.
UNKNOWN_SWITCH_NOTE = (
    "ignore_paths contains {entries}, which {begins} with \"!\" but {isare} "
    f'not the "{DEFAULTS_OFF}" switch. {{Subject}} ignored entirely — not '
    "applied as a path glob, and not handed to any scanner — so the default "
    "noise filter is STILL IN EFFECT. The only spelling that turns it off is "
    f'"{DEFAULTS_OFF}" (any capitalisation).')

# THE SBOM AND THE DEPENDENCY FINDINGS DISAGREE BY DESIGN, SO THE REPORT SAYS SO.
#
# `deps.inventory` does not read `ignore_paths` (module docstring above), and
# with the fixtures default that stopped being a state an operator chose. On
# this very repository, measured: 4 of 4 SBOM components come from
# `tests/security/fixtures/`, and the dependency category goes 6 -> 0. A
# consumer holding the published SBOM and the report reads "this project ships
# lodash 4.17.20" beside "no dependency findings" and concludes lodash
# 4.17.20 is clean.
#
# THE SBOM WAS NOT FILTERED TO MATCH, and the reason is the one in the module
# docstring, unchanged by the default: an SBOM is a statement about what the
# repository CONTAINS, and one whose contents depended on the analysis's noise
# filter would answer differently for the same commit depending on what
# somebody typed in a settings field -- while being handed to consumers who
# have no way to see that field. The defect is not that the SBOM is complete;
# it is that the report made an unqualified claim beside it. So the claim is
# qualified.
#
# Emitted MEASURED, unlike `DEFAULT_NOTE` above: it names a count and real
# paths, so it can only be said when it is true of this repository. A project
# with no lockfile under a filtered path never sees it.
SBOM_UNFILTERED_NOTE = (
    "No vulnerability was looked up for {count} of the {total} components "
    "this project declares: they come from {sources}, which the path filter "
    "excluded from the analysis. The SBOM is built from what the repository "
    "CONTAINS and is deliberately not filtered, so it lists them all the "
    "same — an absent dependency finding is not a clean bill of health for a "
    "component the SBOM shows.")


# ------------------------------------------------------------ the normal form
#
# HOISTED, because every answer below is the same for every path in the run
# and was being recomputed for each of them. `ignored` and `sample_file` are
# called once or twice per file across three full tree walks, and each call
# rebuilt a stripped set (`defaults_apply`) or a filtered tuple (`globs`).
# ONE cached read of the pattern list decides all three questions -- is the
# default on, which entries are paths, which `!` entries mean nothing -- so a
# per-file call is a tuple allocation and a dict lookup.
#
# `patterns` arrives as a list, which is unhashable, so the cache sits behind
# a tuple-taking helper and the public functions normalise into it. The cache
# is bounded and cannot grow with the tree: one analysis uses one pattern
# list, and the process is a CLI invocation, not a server.

class _Resolved:
    """What one `ignore_paths` list means, read once.

    `entries` is stripped and de-blanked before anything is compared: the
    globs arrive as one comma-joined string from bash and are split without
    trimming, so a project that wrote its list with spaces after the commas
    would otherwise be told its switch was a path glob that matches nothing.
    """

    __slots__ = ("defaults", "globs", "unknown")

    def __init__(self, patterns):
        entries = tuple(s for s in ((p or "").strip() for p in patterns) if s)
        self.defaults = not any(p.lower() == _DEFAULTS_OFF_FOLDED
                                for p in entries)
        self.globs = tuple(p for p in entries if not p.startswith("!"))
        self.unknown = tuple(p for p in entries if p.startswith("!")
                             and p.lower() != _DEFAULTS_OFF_FOLDED)


@lru_cache(maxsize=64)
def _cached(patterns: tuple) -> _Resolved:
    return _Resolved(patterns)


def _resolve(patterns) -> _Resolved:
    return _cached(tuple(patterns or ()))


def defaults_apply(patterns) -> bool:
    """Whether the built-in default is in effect for this analysis."""
    return _resolve(patterns).defaults


def default_dirs(patterns=()) -> tuple:
    """The fixture directory names to suppress, or () when switched off.

    Read by the ENGINE pre-filters (`adapters.scope_patterns`,
    `trivy_skip_dirs`, `semgrep_excludes`) so the binaries are not paid to
    read files whose findings are going to be dropped. Those are the cheap
    way round and never the guarantee -- `ignored` below is applied to
    everything that comes back regardless -- but they have to honour the
    switch too, or an operator who turned the default off would find it
    still in force, applied by a command line instead of by a decision.
    """
    return DEFAULT_IGNORE_DIRS if defaults_apply(patterns) else ()


def globs(patterns=()) -> tuple:
    """The operator's own path globs: every entry that is not a `!` switch.

    EVERY LEADING `!` IS TAKEN OUT, not just the one this module recognises.
    `DEFAULTS_OFF` is a decision and not a path, and so is a mistyped attempt
    at it -- but only the exact spelling used to be removed here, so
    `!Defaults` was handed to three binaries as a path to exclude:
    `--skip-dirs '!Defaults'`, `--exclude './!Defaults'`, and a pair of
    gitleaks allowlist regexes. That is a line in someone's debug output that
    means nothing, a pattern a future matcher could interpret, and -- worst --
    it looked like the switch had been accepted.

    `ignored` reads this function too, so a `!` entry can no longer match a
    path either. It never usefully could; what it could do was match
    something absurd (`ignored("!Defaults", ["!Defaults"])` was True) and
    silently narrow a scan by a name the operator meant as a switch.
    """
    return _resolve(patterns).globs


def unknown_switches(patterns=()) -> tuple:
    """Every `!` entry this module does not recognise, in the order written.

    The switch is matched without regard to case (see `_DEFAULTS_OFF_FOLDED`),
    so this is the genuinely unrecognised remainder: `!default`,
    `!defaults/**`, `!tests/**`. They do nothing, and `unknown_switch_note`
    is what stops them from doing nothing quietly.
    """
    return _resolve(patterns).unknown


def unknown_switch_note(patterns=()) -> str:
    """`UNKNOWN_SWITCH_NOTE` filled in for this project, or "" when there is
    nothing to say."""
    unknown = unknown_switches(patterns)
    if not unknown:
        return ""
    one = len(unknown) == 1
    return UNKNOWN_SWITCH_NOTE.format(
        entries=", ".join(f'"{p}"' for p in unknown),
        begins="begins" if one else "begin",
        isare="is" if one else "are",
        Subject="It was" if one else "They were")


# ------------------------------------------------------------- the file rules

def sample_suffix(name: str) -> str:
    """The template suffix `name` ends in (`.example`, ...), or "".

    CASE-INSENSITIVE, and that is a fix rather than a nicety. The matcher here
    used to be `fnmatch.fnmatch(name, "*.example")`, chosen on the argument
    that `fnmatch` normalises case through `os.path.normcase` -- which is the
    IDENTITY on every POSIX platform this runs on. So `.ENV.EXAMPLE` matched
    nothing, in the secret scan and in `hygiene`'s committed-`.env` rule
    alike, while `DEFAULT_NOTE` told that repository's reader its templates
    had been treated as templates. `str.lower()` is the function that actually
    does what the old comment claimed.

    The basename only: `examples/prod.env` is a real file in a directory, not
    a template.
    """
    lowered = name.lower()
    for suffix in SAMPLE_SUFFIXES:
        if lowered.endswith(suffix):
            return name[len(name) - len(suffix):]
    return ""


def sample_stem(name: str) -> str:
    """`server.key.example` -> `server.key`; anything else unchanged.

    What a template is a template OF. `hygiene._is_key_material` needs it
    because its suffix test (`.pem`/`.key`) does not see past `.example`, so
    `server.key.example` was never even sniffed for a private key.
    """
    suffix = sample_suffix(name)
    return name[:-len(suffix)] if suffix else name


def sample_file(rel, patterns=()) -> bool:
    """True for a committed TEMPLATE of a configuration file, by its name.

    THE SECRET SCAN'S RULE ALONE, deliberately not part of `ignored` below.
    The spec item scopes it to secrets and `hygiene.py` scopes it to its
    `.env` rule, and the difference is real: a world-writable
    `config.yml.template`, or a CVE against a `package-lock.json.example`,
    is a true statement about a file that is really in the repository.

    And it does not, on its own, suppress anything any more. Being a template
    is one half of the decision; `sample_suppressed` below is the decision,
    because which RULE matched is the other half.
    """
    return bool(defaults_apply(patterns) and sample_suffix(Path(rel).name))


def sample_suppressed(rel, rule, patterns=()) -> bool:
    """True when `rule` must not be reported from `rel` because `rel` is a
    committed template.

    THE ONE EXPRESSION, read by the built-in scanner's tree sweep, its history
    sweep and `adapters.gitleaks` -- for the reason this module exists: a
    default honoured by one scanner and not the other makes the same
    repository report differently depending on what a machine has installed.

    The set test comes first on purpose. It rejects almost every rule for the
    cost of a hash, so the path work behind `sample_file` runs only for the
    two rules that could actually be suppressed.
    """
    return rule in SAMPLE_SUPPRESSED_RULES and sample_file(rel, patterns)


def ignored(rel: str, patterns) -> bool:
    """True when the repo-relative path `rel` is outside this analysis.

    Two sources, and they answer the same question. The default above needs
    no configuration and is matched as a whole path COMPONENT at any depth,
    without regard to case; `patterns` is what the operator wrote, and each
    one is matched twice -- literally, and with a trailing `/*` appended to
    its directory part, so `tests/fixtures` and `tests/fixtures/**` both
    exclude everything under that directory rather than only the directory
    entry itself.

    A COMPONENT INCLUDES THE LAST ONE, so a plain FILE named `fixtures` (or
    `testdata`, with no extension) is outside the analysis too. That is a
    knowing acceptance rather than an oversight: a file with one of those
    three exact names and no extension is vanishingly rare next to the
    directories they name, and the alternative -- matching all but the final
    component -- would let `fixtures/` slip through whenever a path happened
    to end there.

    `!` entries never reach the glob matcher: `globs` takes them out, for the
    reasons its own docstring gives.
    """
    defaults = default_dirs(patterns)
    if defaults and any(part.lower() in _DEFAULT_IGNORE_DIRS_FOLDED
                        for part in Path(rel).parts):
        return True
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/*") + "/*")
               for p in globs(patterns))
