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
by machine.
"""

import fnmatch
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
# Each name below is a whole path COMPONENT at ANY DEPTH, matched the way
# `secrets.SKIP_DIRS` is matched and for the same reason: `testdata` is Go's
# own reserved directory name and sits beside the package it belongs to,
# never at the top of the tree, so a top-level-only rule would miss every Go
# repository. `myfixtures/` is not `fixtures/` and is not touched.
DEFAULT_IGNORE_DIRS = ("__fixtures__", "fixtures", "testdata")

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

# ONE sentence, said whenever the default is in effect, so a reader can tell
# "nothing was there" from "we did not look" -- the same rule every other
# coverage note in this project follows. Said unconditionally rather than
# only when something was actually suppressed: counting the suppressions
# would mean threading a tally through five phases and two scanners, and the
# sentence describes a standing policy of the analysis, which is true whether
# or not it bit this time.
DEFAULT_NOTE = (
    "A default noise filter was in effect: findings under a fixtures, "
    "__fixtures__ or testdata directory were not reported, and neither were "
    "secrets in files ending .dist, .example, .sample or .template. Add "
    f'"{DEFAULTS_OFF}" to the project\'s ignore_paths to scan them.')


def defaults_apply(patterns) -> bool:
    """Whether the built-in default is in effect for this analysis.

    Stripped before it is compared: the globs arrive as one comma-joined
    string from bash and are split without trimming, so a project that wrote
    its list with spaces after the commas would otherwise be told its switch
    was a path glob that matches nothing.
    """
    return DEFAULTS_OFF not in {(p or "").strip() for p in (patterns or ())}


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
    """The operator's own path globs, with the switch taken out.

    `DEFAULTS_OFF` is a decision, not a path. `ignored` below is unharmed by
    it -- `!defaults` matches no real path -- but the three functions that
    build an ENGINE's command line out of these entries would each hand a
    binary a `--exclude !defaults`, which is a line in someone's debug output
    that means nothing and a pattern a future matcher could interpret.
    """
    return tuple(p for p in (patterns or ()) if (p or "").strip() != DEFAULTS_OFF)


def sample_file(rel, patterns=()) -> bool:
    """True for a committed TEMPLATE of a configuration file, by its name.

    THE SECRET SCAN'S RULE ALONE, deliberately not part of `ignored` below.
    The spec item scopes it to secrets and `hygiene.py` scopes it to its
    `.env` rule, and the difference is real: a world-writable
    `config.yml.template`, or a CVE against a `package-lock.json.example`,
    is a true statement about a file that is really in the repository. Only
    the claim "a credential is committed here" is wrong, because the value
    in a template is a shape, not a secret.

    Matched with `fnmatch` against the basename, which is the matcher
    `hygiene.py` has always used for the identical suffix list. `endswith`
    would read better and is not the same function -- `fnmatch` normalises
    case through `os.path.normcase`, so the two would answer differently
    about `.ENV.EXAMPLE` the day this runs anywhere `normcase` is not the
    identity. One list, one matcher, one answer.
    """
    if not defaults_apply(patterns):
        return False
    name = Path(rel).name
    return any(fnmatch.fnmatch(name, f"*{suffix}") for suffix in SAMPLE_SUFFIXES)


def ignored(rel: str, patterns) -> bool:
    """True when the repo-relative path `rel` is outside this analysis.

    Two sources, and they answer the same question. The default above needs
    no configuration and is matched as a whole path component at any depth;
    `patterns` is what the operator wrote, and each one is matched twice --
    literally, and with a trailing `/*` appended to its directory part, so
    `tests/fixtures` and `tests/fixtures/**` both exclude everything under
    that directory rather than only the directory entry itself.
    """
    patterns = tuple(patterns or ())
    defaults = default_dirs(patterns)
    if defaults and any(part in defaults for part in Path(rel).parts):
        return True
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/*") + "/*")
               for p in patterns)
