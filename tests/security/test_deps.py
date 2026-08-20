# tests/security/test_deps.py
import json
from pathlib import Path
from security.deps import inventory, sbom

FIXTURES = Path(__file__).parent / "fixtures"


def test_it_reads_an_npm_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        (FIXTURES / "package-lock.json").read_text())
    got = inventory(tmp_path)
    assert {"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
            "source": "package-lock.json"} in got


def test_it_reads_a_requirements_file(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n# comment\n\n")
    got = inventory(tmp_path)
    assert got == [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0",
                    "source": "requirements.txt"}]


def test_an_unpinned_requirement_is_skipped(tmp_path):
    """Without a version there is nothing to ask OSV about."""
    (tmp_path / "requirements.txt").write_text("requests\nflask>=2\n")
    assert inventory(tmp_path) == []


def test_vendored_trees_are_never_walked(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "requirements.txt").write_text("evil==1.0\n")
    assert inventory(tmp_path) == []


def test_the_sbom_is_valid_cyclonedx(tmp_path):
    doc = sbom([{"ecosystem": "npm", "name": "lodash", "version": "4.17.20",
                 "source": "package-lock.json"}])
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["components"][0]["purl"] == "pkg:npm/lodash@4.17.20"
    json.dumps(doc)  # must be serialisable
