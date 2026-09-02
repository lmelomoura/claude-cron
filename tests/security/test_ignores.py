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


def test_the_default_reaches_a_fixture_directory_whatever_its_case():
    """`Fixtures/` and `TestData/` are the .NET and Swift spelling of the same
    convention. A case-sensitive match told that repository's reader, in
    `DEFAULT_NOTE` and on every report, that its fixtures had been suppressed
    while they had not -- a note describing a filter the analysis did not
    apply."""
    assert ignores.ignored("Tests/Fixtures/fake.env", [])
    assert ignores.ignored("Pkg/TestData/dump.sql", [])
    assert ignores.ignored("web/src/__FIXTURES__/user.json", [])


def test_the_default_still_matches_a_whole_component_when_folded():
    """Case-insensitivity must not turn the component match into a substring
    one: `MyFixtures/` is still not `fixtures/`."""
    assert not ignores.ignored("src/MyFixtures/prod.env", [])
    assert not ignores.ignored("src/Fixtures_helper.py", [])


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


def test_the_switch_is_recognised_whatever_its_case():
    """`!defaults` is this project's own token, not a path: there is no
    information in its capitalisation and there was a great deal of damage in
    requiring it. `!Defaults` compared unequal, so the default silently STAYED
    ON -- the unsafe direction -- and the entry was then treated as a path
    glob."""
    for spelling in ("!Defaults", "!DEFAULTS", "!defaults", " !Defaults "):
        assert not ignores.defaults_apply([spelling]), spelling
        assert not ignores.ignored("tests/fixtures/fake.env", [spelling]), spelling


# --------------------------------------------- a `!` entry that is not the one

def test_an_unrecognised_switch_never_reaches_an_engine_command_line():
    """`ignores.globs` exists so a binary is never handed `--exclude
    !defaults`, and one wrong character used to defeat it: `['!Defaults']`
    went down as `--skip-dirs '!Defaults'`, `--exclude './!Defaults'` and a
    pair of gitleaks allowlist regexes. EVERY leading `!` is taken out now,
    not just the spelling this module happens to recognise."""
    for entry in ("!default", "!defaults/**", "!tests/**", "!Defaults"):
        assert ignores.globs([entry, "docs/**"]) == ("docs/**",), entry


def test_an_unrecognised_switch_is_not_matched_as_a_path_either():
    """It never usefully could. What it could do was match something absurd
    -- `ignored("!Defaults", ["!Defaults"])` was True -- and silently narrow a
    scan by a name the operator meant as a switch."""
    assert not ignores.ignored("!default", ["!default"])
    assert not ignores.ignored("src/a.py", ["!tests/**"])


def test_an_unrecognised_switch_says_so_out_loud():
    """THE FAILURE THIS CLOSES: it fails in the unsafe direction. A project
    that keeps real credentials in a fixture and typed `!default` believes it
    is being scanned; the default is still on and nothing said so."""
    note = ignores.unknown_switch_note(["!default", "docs/**"])
    assert "!default" in note
    assert ignores.DEFAULTS_OFF in note, "it has to name the spelling that works"
    assert "STILL IN EFFECT" in note
    assert ignores.defaults_apply(["!default"]), (
        "the note describes the state, so the state had better be that one")


def test_the_recognised_switch_and_a_plain_glob_say_nothing():
    assert ignores.unknown_switch_note([]) == ""
    assert ignores.unknown_switch_note(["docs/**"]) == ""
    assert ignores.unknown_switch_note([ignores.DEFAULTS_OFF]) == ""
    assert ignores.unknown_switch_note(["!DEFAULTS"]) == ""


def test_several_unrecognised_switches_are_named_together():
    note = ignores.unknown_switch_note(["!default", "!defaults/**"])
    assert "!default" in note and "!defaults/**" in note
    assert "They were" in note, "one sentence, agreeing with itself"


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


def test_a_sample_suffix_is_matched_whatever_its_case():
    """The matcher here used to be `fnmatch`, chosen on the argument that it
    normalises case through `os.path.normcase` -- which is the IDENTITY on
    every POSIX platform this runs on. So `.ENV.EXAMPLE` matched nothing while
    `DEFAULT_NOTE` told that repository's reader its templates had been
    treated as templates."""
    assert ignores.sample_file(".ENV.EXAMPLE")
    assert ignores.sample_file("config/Database.yml.Sample")
    assert ignores.sample_suffix(".env.EXAMPLE") == ".EXAMPLE"
    assert ignores.sample_suffix("prod.env") == ""


def test_a_sample_stem_is_what_the_template_is_a_template_OF():
    """`hygiene._is_key_material`'s suffix test does not see past `.example`,
    so `server.key.example` was never even sniffed for a private key."""
    assert ignores.sample_stem("server.key.example") == "server.key"
    assert ignores.sample_stem("chain.PEM.Dist") == "chain.PEM"
    assert ignores.sample_stem("server.key") == "server.key"


# ------------------------------------------- WHICH rules a template silences

def test_a_template_silences_the_two_rules_that_over_fire_on_one():
    for rule in ("generic_secret", "aws_access_key",
                 "generic-api-key", "aws-access-token"):
        assert ignores.sample_suppressed(".env.example", rule), rule


def test_a_template_does_NOT_silence_a_private_key():
    """THE HOLE THE FILE-LEVEL RULE OPENED. "The value in a template is a
    shape, not a secret" is true of the two rules above and false of a PEM
    body, and a real `openssl genrsa` key in `certs/server.key.example` was
    reported by nothing at all."""
    for rule in ("private_key", "private-key"):
        assert not ignores.sample_suppressed("certs/server.key.example", rule), rule


def test_the_suppressed_set_is_an_allowlist_so_a_new_rule_reports():
    """Gitleaks ships some 200 rules and adds more. A denylist of "rules that
    still matter in a template" would silence each new one on the day it
    arrived, silently, in the one file class where silence already cost us a
    private key."""
    assert not ignores.sample_suppressed(".env.example", "some-rule-added-in-2027")
    assert not ignores.sample_suppressed(".env.example", "github_token")


def test_a_real_file_silences_nothing_at_all():
    assert not ignores.sample_suppressed("prod.env", "aws_access_key")


def test_the_rule_gate_is_off_when_the_default_is_off():
    assert not ignores.sample_suppressed(
        ".env.example", "aws_access_key", [ignores.DEFAULTS_OFF])


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


def test_the_note_does_not_promise_more_silence_than_the_filter_delivers():
    """The old sentence -- "Secrets in .example files were not reported" --
    is a promise the filter is no longer allowed to keep: a private key in a
    template IS reported. A reader deciding whether to trust an empty secret
    section has to know which of the two they got."""
    assert "private key" in ignores.DEFAULT_NOTE


def test_the_sbom_note_says_what_an_absent_dependency_finding_does_not_mean():
    """The SBOM is not filtered and the dependency findings are, which used to
    be an operator's own knowing choice and is now what every unconfigured
    project gets. Measured on this repository: 4 of 4 SBOM components from
    `tests/security/fixtures/`, dependency category 6 -> 0."""
    note = ignores.SBOM_UNFILTERED_NOTE.format(
        count=4, total=4, sources="tests/security/fixtures/package-lock.json")
    assert "package-lock.json" in note
    assert "not a clean bill of health" in note
