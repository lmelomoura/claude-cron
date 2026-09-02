# tests/security/test_deps.py
import json
from pathlib import Path
from security.deps import (SCOPE_DEV, SCOPE_RUNTIME, SCOPE_UNKNOWN, inventory,
                           merge_scope, sbom)

FIXTURES = Path(__file__).parent / "fixtures"


def scopes(rows):
    """`{name: scope}`, the only shape these tests compare on."""
    return {r["name"]: r["scope"] for r in rows}


def test_it_reads_an_npm_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        (FIXTURES / "package-lock.json").read_text())
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                    "source": "package-lock.json", "scope": "runtime"}]


def test_it_reads_a_requirements_file(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n# comment\n\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt", "scope": "unknown"}]


def test_an_unpinned_requirement_is_skipped(tmp_path):
    """Without a version there is nothing to ask OSV about."""
    (tmp_path / "requirements.txt").write_text("requests\nflask>=2\n")
    assert inventory(tmp_path) == []


def test_it_reads_a_poetry_lockfile(tmp_path):
    (tmp_path / "poetry.lock").write_text((FIXTURES / "poetry.lock").read_text())
    got = inventory(tmp_path)
    assert got == [
        {"ecosystem": "PyPI", "name": "certifi", "version": "2024.2.2",
         "source": "poetry.lock", "scope": "runtime"},
        {"ecosystem": "PyPI", "name": "six", "version": "1.16.0",
         "source": "poetry.lock", "scope": "runtime"},
    ]


def test_it_reads_a_composer_lockfile(tmp_path):
    """Doubles as the check that the "v" version-tag prefix is stripped
    (the fixture locks evenement/evenement at "v3.0.2")."""
    (tmp_path / "composer.lock").write_text((FIXTURES / "composer.lock").read_text())
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "Packagist", "name": "evenement/evenement",
                    "version": "3.0.2", "source": "composer.lock",
                    "scope": "runtime"}]


def test_it_reads_a_go_sum_file(tmp_path):
    """Constructed, not captured from a real `go` run: this machine has no
    `go` toolchain on PATH, and no go.sum exists anywhere on it either (both
    checked before writing this). This reproduces go.sum's documented
    two-line-per-version shape -- a content hash line paired with a
    "/go.mod" hash line for the same module and version -- so it also
    covers the pair not being double-counted, and two versions of the same
    module both surviving.
    """
    (tmp_path / "go.sum").write_text(
        "example.com/foo v1.2.3 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "example.com/foo v1.2.3/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "example.com/foo v1.3.0 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n"
        "example.com/foo v1.3.0/go.mod h1:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\n")
    got = inventory(tmp_path)
    assert got == [
        {"ecosystem": "Go", "name": "example.com/foo", "version": "1.2.3",
         "source": "go.sum", "scope": "unknown"},
        {"ecosystem": "Go", "name": "example.com/foo", "version": "1.3.0",
         "source": "go.sum", "scope": "unknown"},
    ]


def test_a_pep508_marker_does_not_corrupt_the_version(tmp_path):
    """name was already split on "[;", but version was not -- an environment
    marker used to ride along and never match anything OSV knows about."""
    (tmp_path / "requirements.txt").write_text(
        'requests==2.31.0 ; python_version < "3.12"\n')
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt", "scope": "unknown"}]


def test_arbitrary_equality_does_not_leave_a_leading_equals_sign(tmp_path):
    """pkg===1.2.3 uses PEP 440's arbitrary-equality operator; partitioning on
    the first "==" leaves a leading "=" on the version half."""
    (tmp_path / "requirements.txt").write_text("pkg===1.2.3\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "pkg", "version": "1.2.3",
                    "source": "requirements.txt", "scope": "unknown"}]


def test_a_malformed_npm_lockfile_is_skipped_not_fatal(tmp_path):
    """"packages" as a list is never real npm output, but it is not
    impossible for a crafted or corrupted file -- and it used to raise
    AttributeError from .items() on a list, which inventory() did not catch,
    aborting the whole scan instead of just this one file."""
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": ["not", "a", "dict"]}))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt", "scope": "unknown"}]


def test_a_malformed_composer_lockfile_is_skipped_not_fatal(tmp_path):
    """"packages" as a dict is never real composer output -- composer always
    writes a list -- but it used to raise TypeError from concatenating a
    dict with a list, which inventory() did not catch, aborting the whole
    scan instead of just this one file."""
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": {"not": "a list"}}))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt", "scope": "unknown"}]


def test_a_non_dict_composer_package_is_skipped_not_the_whole_file(tmp_path):
    """A single non-dict element inside "packages" used to cost the whole
    file: _composer's loop called pkg.get(...) unconditionally, so a string
    element raised AttributeError, and list(reader(path)) is all-or-nothing
    -- the exception discards every row already yielded, not just the bad
    one. The per-element isinstance guard means a stray non-dict element
    now costs only itself; its well-formed sibling survives."""
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [
            {"name": "monolog/monolog", "version": "3.0.2"},
            "not-a-dict",
        ],
    }))
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "Packagist", "name": "monolog/monolog",
                    "version": "3.0.2", "source": "composer.lock",
                    "scope": "runtime"}]


def test_a_non_dict_top_level_lockfile_is_caught_by_the_systemic_except(tmp_path):
    """The other two malformed-lockfile tests above never actually reach
    inventory()'s except: "packages" being the wrong shape is absorbed by a
    point-of-use isinstance guard inside _npm/_composer before any exception
    fires -- a regression that narrowed the except back to
    (ValueError, OSError) would pass both of them unnoticed. A
    package-lock.json whose top-level JSON is an array has no such guard:
    data.get("packages") assumes data itself is a dict, and a list has no
    .get(), so this raises AttributeError from a point no per-field check
    covers, reaching the except itself: narrowing it back to
    (ValueError, OSError) makes this specific test fail, unlike the two
    above."""
    (tmp_path / "package-lock.json").write_text("[]")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt", "scope": "unknown"}]


def test_vendored_trees_are_never_walked(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "requirements.txt").write_text("evil==1.0\n")
    assert inventory(tmp_path) == []


def test_a_scoped_npm_name_percent_encodes_the_scope_in_the_purl(tmp_path):
    """@types/node must become pkg:npm/%40types/node@20.1.0 -- the purl spec
    requires the scope's "@" percent-encoded."""
    doc = sbom([{"ecosystem": "npm", "name": "@types/node", "version": "20.1.0",
                 "source": "package-lock.json"}])
    assert doc["components"][0]["purl"] == "pkg:npm/%40types/node@20.1.0"


def test_a_build_metadata_plus_sign_is_percent_encoded_in_the_purl(tmp_path):
    """"+" is not in purl's unreserved set (letters, digits, "-._~"), so a
    semver build-metadata suffix like "+build.1" must come out as "%2B" in
    the version segment, not ride along unencoded."""
    doc = sbom([{"ecosystem": "npm", "name": "example", "version": "1.0.0+build.1",
                 "source": "package-lock.json"}])
    assert doc["components"][0]["purl"].endswith("@1.0.0%2Bbuild.1")


def test_a_composer_purl_keeps_the_slash_as_a_separator(tmp_path):
    """monolog/monolog's "/" separates vendor from package in both Packagist's
    own naming and purl's composer namespace -- quote(..., safe="/") must
    leave it alone while still being ready to encode anything that isn't,
    so the purl comes out exactly pkg:composer/monolog/monolog@3.0.2."""
    doc = sbom([{"ecosystem": "Packagist", "name": "monolog/monolog",
                 "version": "3.0.2", "source": "composer.lock"}])
    assert doc["components"][0]["purl"] == "pkg:composer/monolog/monolog@3.0.2"


def test_the_sbom_is_valid_cyclonedx(tmp_path):
    doc = sbom([{"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                 "source": "package-lock.json"}])
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["components"][0]["purl"] == "pkg:npm/lodash@4.17.20"
    json.dumps(doc)  # must be serialisable


# ------------------------------------------------------- scope (dev/runtime)
#
# What each of the five formats can and cannot answer. Every expectation here
# was measured against trivy 0.74.0 over the same file first -- see
# `adapters._TRIVY_DEV_AWARE` and `deps._poetry_scope`, which record what was
# run. The point of these tests is not that a lockfile parses; it is that this
# producer gives the SAME answer as the other one, because only one of the two
# runs per analysis and which one depends on whether a machine has Trivy.


def test_an_npm_dev_dependency_is_marked_dev_and_a_runtime_one_runtime(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/minimist": {"version": "1.2.5", "dev": True},
        },
    }))
    assert scopes(inventory(tmp_path)) == {"lodash": SCOPE_RUNTIME,
                                           "minimist": SCOPE_DEV}


def test_npm_devOptional_is_runtime_because_that_is_what_trivy_says(tmp_path):
    """`devOptional` marks a package that is a dev dependency AND an optional
    dependency of a production one -- so it can ship. Measured: trivy 0.74.0
    sets `Dev` only for `dev === true`, and reported nothing for a
    `devOptional` package. Reading it as dev here would put a `dev` label on
    what the other producer calls `runtime`, on the same file."""
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20", "devOptional": True},
        },
    }))
    assert scopes(inventory(tmp_path)) == {"lodash": SCOPE_RUNTIME}


def test_the_npm_lockfileVersion_1_shape_carries_the_same_flag(tmp_path):
    """`_npm` reads two maps -- `packages` (v2/v3) and `dependencies` (v1) --
    and the second used to be the one a scope could be silently lost from."""
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.20"},
            "minimist": {"version": "1.2.5", "dev": True},
        },
    }))
    assert scopes(inventory(tmp_path)) == {"lodash": SCOPE_RUNTIME,
                                           "minimist": SCOPE_DEV}


def test_composer_packages_dev_stops_being_thrown_away(tmp_path):
    """THE ONE PLACE THIS MODULE ALREADY HAD THE ANSWER. `_composer` read
    `packages-dev`, concatenated it onto `packages` and emitted one flat list
    with no marker, so a CVE in phpunit was indistinguishable from one in the
    HTTP client that serves traffic."""
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [{"name": "guzzlehttp/guzzle", "version": "6.5.0"}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "4.8.27"}],
    }))
    assert scopes(inventory(tmp_path)) == {"guzzlehttp/guzzle": SCOPE_RUNTIME,
                                           "phpunit/phpunit": SCOPE_DEV}


def test_poetry_lock_version_1_answers_from_category(tmp_path):
    """Poetry wrote `category = "main"` / `"dev"` per package up to lock
    version 1.1. Trivy reads the same field."""
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "jinja2"\nversion = "2.11.2"\n'
        'category = "main"\noptional = false\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n'
        'category = "dev"\noptional = false\n')
    assert scopes(inventory(tmp_path)) == {"jinja2": SCOPE_RUNTIME,
                                           "urllib3": SCOPE_DEV}


def test_poetry_lock_version_2_1_answers_from_groups(tmp_path):
    """Poetry 2.x replaced `category` with `groups`. Measured: trivy reads it
    from the lock alone, with no pyproject.toml in the tree at all."""
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "jinja2"\nversion = "2.11.2"\n'
        'groups = ["main"]\nfiles = []\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n'
        'groups = ["dev"]\nfiles = []\n')
    assert scopes(inventory(tmp_path)) == {"jinja2": SCOPE_RUNTIME,
                                           "urllib3": SCOPE_DEV}


def test_a_poetry_package_in_main_AND_dev_is_runtime(tmp_path):
    """`dev` means dev-ONLY. Measured: trivy reported no `Dev` marker for
    `groups = ["main", "dev"]`, which is the same rule from the other side."""
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n'
        'groups = ["main", "dev"]\nfiles = []\n')
    assert scopes(inventory(tmp_path)) == {"urllib3": SCOPE_RUNTIME}


def test_a_poetry_lock_version_2_0_says_unknown_not_runtime(tmp_path):
    """THE ONE DECLARED DIVERGENCE, pinned so it cannot become silent. Poetry
    1.5 to 2.0 wrote lock-version 2.0, which dropped `category` and had not
    yet gained `groups`: group membership lived only in pyproject.toml, and
    Trivy answers from there while this flat reader cannot. `unknown` is the
    honest answer and it is the SAFE direction -- this producer never claims
    `runtime` where Trivy would have said `dev`. `deps.SCOPE_NOTE` and
    `adapters.DEP_SCOPE_NOTE` both state it in the report."""
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "jinja2"\nversion = "2.11.2"\n'
        'optional = false\nfiles = []\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n'
        'optional = false\nfiles = []\n')
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.group.dev.dependencies]\nurllib3 = "1.26.4"\n')
    assert scopes(inventory(tmp_path)) == {"jinja2": SCOPE_UNKNOWN,
                                           "urllib3": SCOPE_UNKNOWN}


def test_the_poetry_reader_still_emits_the_last_package_in_the_file(tmp_path):
    """`_poetry` had to stop emitting on the `version` line -- `category` and
    `groups` are written AFTER it -- and a reader that emits at the START of
    the next `[[package]]` drops the final one unless it also flushes at EOF.
    The fixture's `six` is that last package in every other test here."""
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "only"\nversion = "1.0.0"\ngroups = ["dev"]\n')
    assert scopes(inventory(tmp_path)) == {"only": SCOPE_DEV}


def test_requirements_and_go_sum_say_unknown_rather_than_guessing(tmp_path):
    """Neither format can answer, and neither may pretend to. requirements.txt
    has no development section (the convention is a second file, which
    `_READERS` does not name and Trivy's pip analyser does not read either),
    and Go has no development-dependency concept at all. Guessing `runtime`
    here would understate nothing and overstate the confidence of everything;
    guessing `dev` would hide real risk."""
    (tmp_path / "requirements.txt").write_text("jinja2==2.11.2\n")
    (tmp_path / "go.sum").write_text(
        "example.com/foo v1.2.3 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
    assert scopes(inventory(tmp_path)) == {"jinja2": SCOPE_UNKNOWN,
                                           "example.com/foo": SCOPE_UNKNOWN}


def test_a_requirements_dev_file_is_read_by_NEITHER_producer(tmp_path):
    """Stated in `_requirements`' docstring and pinned here, because it is the
    obvious thing to reach for and it does not work: `requirements-dev.txt` is
    not in `_READERS`, so this producer never opens it -- and trivy 0.74.0
    reported only `requirements.txt` over a tree holding both, so the other
    producer does not either. The two agree by both not looking."""
    (tmp_path / "requirements.txt").write_text("jinja2==2.11.2\n")
    (tmp_path / "requirements-dev.txt").write_text("urllib3==1.26.4\n")
    assert scopes(inventory(tmp_path)) == {"jinja2": SCOPE_UNKNOWN}


def test_a_package_pinned_dev_here_and_runtime_there_is_runtime(tmp_path):
    """The dedupe keeps the FIRST lockfile and drops the rest -- so without
    merging, a monorepo's shared package would be labelled by whichever file
    sorts first. It ships somewhere, so it is runtime. `trivy_vulns` resolves
    scope across every target before building a finding for exactly this
    reason, and calls the same function."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "package-lock.json").write_text(json.dumps({
        "packages": {"node_modules/lodash": {"version": "4.17.20", "dev": True}}}))
    (tmp_path / "b" / "package-lock.json").write_text(json.dumps({
        "packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
    rows = inventory(tmp_path)
    assert scopes(rows) == {"lodash": SCOPE_RUNTIME}
    assert rows[0]["source"] == "a/package-lock.json", (
        "the merge must move the SCOPE only -- the component is still "
        "attributed to the first lockfile that pinned it")


def test_merge_scope_fails_towards_urgency():
    """`dev` is the only value that lowers how hard a reader looks, so it may
    only stand when nothing contradicts it."""
    assert merge_scope(SCOPE_DEV) == SCOPE_DEV
    assert merge_scope(SCOPE_DEV, SCOPE_RUNTIME) == SCOPE_RUNTIME
    assert merge_scope(SCOPE_RUNTIME, SCOPE_DEV) == SCOPE_RUNTIME
    assert merge_scope(SCOPE_DEV, SCOPE_UNKNOWN) == SCOPE_UNKNOWN
    assert merge_scope(SCOPE_UNKNOWN, SCOPE_RUNTIME) == SCOPE_RUNTIME


def test_merge_scope_reads_anything_it_does_not_know_as_unknown():
    """Including the empty string a finding written before the column existed
    carries. `runtime` is never the answer to "nothing said"."""
    assert merge_scope("") == SCOPE_UNKNOWN
    assert merge_scope(None) == SCOPE_UNKNOWN
    assert merge_scope("production") == SCOPE_UNKNOWN
    assert merge_scope() == SCOPE_UNKNOWN
    assert merge_scope("", SCOPE_DEV) == SCOPE_UNKNOWN


def test_the_sbom_ignores_scope_entirely(tmp_path):
    """A CycloneDX component has no such field here, and adding one uninvited
    would change a document other tools parse."""
    doc = sbom([{"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                 "source": "package-lock.json", "scope": SCOPE_DEV}])
    assert doc["components"] == [{"type": "library", "name": "lodash",
                                  "version": "4.17.20",
                                  "purl": "pkg:npm/lodash@4.17.20"}]
