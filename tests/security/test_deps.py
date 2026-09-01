# tests/security/test_deps.py
import json
from pathlib import Path
from security.deps import inventory, sbom

FIXTURES = Path(__file__).parent / "fixtures"


def test_it_reads_an_npm_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        (FIXTURES / "package-lock.json").read_text())
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                    "source": "package-lock.json"}]


def test_it_reads_a_requirements_file(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n# comment\n\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt"}]


def test_an_unpinned_requirement_is_skipped(tmp_path):
    """Without a version there is nothing to ask OSV about."""
    (tmp_path / "requirements.txt").write_text("requests\nflask>=2\n")
    assert inventory(tmp_path) == []


def test_it_reads_a_poetry_lockfile(tmp_path):
    (tmp_path / "poetry.lock").write_text((FIXTURES / "poetry.lock").read_text())
    got = inventory(tmp_path)
    assert got == [
        {"ecosystem": "PyPI", "name": "certifi", "version": "2024.2.2",
         "source": "poetry.lock"},
        {"ecosystem": "PyPI", "name": "six", "version": "1.16.0",
         "source": "poetry.lock"},
    ]


def test_it_reads_a_composer_lockfile(tmp_path):
    """Doubles as the check that the "v" version-tag prefix is stripped
    (the fixture locks evenement/evenement at "v3.0.2")."""
    (tmp_path / "composer.lock").write_text((FIXTURES / "composer.lock").read_text())
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "Packagist", "name": "evenement/evenement",
                    "version": "3.0.2", "source": "composer.lock"}]


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
         "source": "go.sum"},
        {"ecosystem": "Go", "name": "example.com/foo", "version": "1.3.0",
         "source": "go.sum"},
    ]


def test_a_pep508_marker_does_not_corrupt_the_version(tmp_path):
    """name was already split on "[;", but version was not -- an environment
    marker used to ride along and never match anything OSV knows about."""
    (tmp_path / "requirements.txt").write_text(
        'requests==2.31.0 ; python_version < "3.12"\n')
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt"}]


def test_arbitrary_equality_does_not_leave_a_leading_equals_sign(tmp_path):
    """pkg===1.2.3 uses PEP 440's arbitrary-equality operator; partitioning on
    the first "==" leaves a leading "=" on the version half."""
    (tmp_path / "requirements.txt").write_text("pkg===1.2.3\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "pkg", "version": "1.2.3",
                    "source": "requirements.txt"}]


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
                    "source": "requirements.txt"}]


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
                    "source": "requirements.txt"}]


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
                    "version": "3.0.2", "source": "composer.lock"}]


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
                    "source": "requirements.txt"}]


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
