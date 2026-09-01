"""The default noise filter: what an analysis skips before anyone configures it.

`ignores.ignored` used to answer one question -- "does this path match a glob
the operator wrote". It now answers the question every phase is really asking:
"is this path in the scope of this analysis". These tests pin BOTH halves of
that, and the narrowness of the default is as much the subject as its
existence: a default that hides a real credential is worse than no default.
"""

from security import ignores

AWS = "AKIA" + "IOSFODNN7EXAMPLE"


# ------------------------------------------------- the default fixture filter

def test_a_fixtures_directory_is_suppressed_without_any_configuration():
    """A4.13. Before this, a project got the fixtures noise on every analysis
    until somebody hand-wrote `ignore_paths` -- and most never did."""
    assert ignores.ignored("tests/fixtures/fake.env", [])


def test_the_default_reaches_a_fixture_directory_at_any_depth():
    """`testdata` is Go's own reserved name and sits beside the package it
    belongs to, never at the top of the tree, so a top-level-only rule would
    miss every Go repository."""
    assert ignores.ignored("pkg/store/testdata/dump.sql", [])
    assert ignores.ignored("fixtures/a.env", [])
    assert ignores.ignored("web/src/__fixtures__/user.json", [])


def test_a_directory_merely_named_LIKE_a_fixture_directory_is_not_suppressed():
    """The default matches a whole path COMPONENT, never a substring. A
    `myfixtures/` holding real configuration must not disappear because its
    name ends in the same eight letters."""
    assert not ignores.ignored("src/myfixtures/prod.env", [])
    assert not ignores.ignored("src/fixtures_helper.py", [])
    assert not ignores.ignored("testdata_loader.py", [])


def test_test_CODE_itself_is_not_suppressed():
    """THE DELIBERATE NARROWING, and the reason this test exists at all: the
    item this implements is called "tests and fixtures", and only the fixtures
    half is taken. A credential hard-coded in a test file is in the repository
    and is readable by everyone with a clone -- it is a real leak, and a
    default that swallowed `tests/**` would hide it on every project that
    never configured anything."""
    assert not ignores.ignored("tests/security/test_secrets.py", [])
    assert not ignores.ignored("spec/models/user_spec.rb", [])


def test_an_operators_own_globs_still_work_beside_the_default():
    assert ignores.ignored("docs/a.md", ["docs/**"])
    assert not ignores.ignored("src/a.py", ["docs/**"])


# ----------------------------------------------------------- the way back out

def test_a_project_can_turn_the_default_off():
    """A default that cannot be turned off is a trap: a project that keeps
    real credentials in a fixture it WANTS reported has to be able to say
    so, and to say it once, in the config that travels with the repository."""
    assert not ignores.ignored("tests/fixtures/fake.env", [ignores.DEFAULTS_OFF])


def test_turning_the_default_off_does_not_cancel_the_operators_own_globs():
    """It cancels what THIS project ships as a default, nothing else. An
    operator who wrote `docs/**` still means it."""
    assert ignores.ignored("docs/a.md", ["docs/**", ignores.DEFAULTS_OFF])


def test_the_switch_is_not_matched_as_a_path_glob():
    """`!defaults` is a sentinel, not a path. It must not accidentally start
    excluding files by matching them."""
    assert not ignores.ignored("defaults", [ignores.DEFAULTS_OFF])
    assert not ignores.ignored("config/defaults.yml", [ignores.DEFAULTS_OFF])


def test_default_dirs_is_empty_once_the_project_turns_the_default_off():
    """What the engine pre-filters build their command lines from. If it kept
    answering with the fixture names, an operator who switched the default off
    would get the files skipped by the engine anyway -- suppressed by a
    command line instead of by a decision."""
    assert ignores.default_dirs([]) != ()
    assert ignores.default_dirs([ignores.DEFAULTS_OFF]) == ()


# ------------------------------------------- the sample-file rule, secret-only

def test_a_sample_file_is_recognised_by_its_suffix():
    """A4.14. `hygiene.py` has always excluded these four; the secret scan
    filtered the VALUE through `_is_placeholder` and never the FILE, so a
    `.env.example` carrying a realistic-looking key was reported in full."""
    assert ignores.sample_file(".env.example")
    assert ignores.sample_file("config/database.yml.sample")
    assert ignores.sample_file("deploy/values.yaml.template")
    assert ignores.sample_file("app/config.php.dist")


def test_a_real_file_is_not_a_sample_file():
    assert not ignores.sample_file("prod.env")
    assert not ignores.sample_file("a.example.json")
    assert not ignores.sample_file("examples/prod.env")


def test_the_sample_rule_is_off_when_the_default_is_off():
    assert not ignores.sample_file(".env.example", [ignores.DEFAULTS_OFF])


def test_a_sample_file_is_NOT_excluded_from_the_path_filter():
    """The two halves of this default are deliberately not the same rule.
    `.example`/`.sample`/`.template`/`.dist` is a SECRET-scan exclusion --
    the spec item says so, and `hygiene.py` applies it only to its `.env`
    check. A world-writable `config.yml.template`, or a CVE against a
    `package-lock.json.example`, is still a real finding about a file that is
    really in the repository."""
    assert not ignores.ignored(".env.example", [])


# ------------------------------------------------------- what the report says

def test_the_default_announces_itself_in_one_sentence():
    """A reader has to be able to tell "nothing was there" from "we did not
    look". The note names the directories, the suffixes, and the way back."""
    note = ignores.DEFAULT_NOTE
    for word in ("fixtures", "testdata", ".example", ignores.DEFAULTS_OFF):
        assert word in note, word
