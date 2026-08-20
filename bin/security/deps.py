# bin/security/deps.py
"""What this project depends on, read from lockfiles.

Only names and versions are read. No dependency's CODE is ever opened -- it is
noise for the analysis, and it is the only place a repository the user checked
out could carry text written by someone else.
"""

import json
import re
from pathlib import Path

_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
_PURL = {"npm": "npm", "PyPI": "pypi", "Packagist": "composer",
         "Go": "golang", "RubyGems": "gem"}


def _npm(path: Path):
    data = json.loads(path.read_text())
    packages = data.get("packages")
    packages = packages if isinstance(packages, dict) else {}
    for name, meta in packages.items():
        if not name or not isinstance(meta, dict) or not meta.get("version"):
            continue
        yield "npm", name.split("node_modules/")[-1], meta["version"]
    dependencies = data.get("dependencies")
    dependencies = dependencies if isinstance(dependencies, dict) else {}
    for name, meta in dependencies.items():
        if isinstance(meta, dict) and meta.get("version"):
            yield "npm", name, meta["version"]


def _requirements(path: Path):
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if "==" not in line:
            continue  # unpinned: there is nothing to ask OSV about
        name, _, version = line.partition("==")
        name = re.split(r"[\[;]", name)[0].strip()
        version = version.split(";", 1)[0].strip()  # drop a PEP 508 environment marker
        version = version.lstrip("=")  # "===" is PEP 440 arbitrary equality
        if name and version:
            yield "PyPI", name, version


def _poetry(path: Path):
    name = None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line == "[[package]]":
            name = None
        elif line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name:
            yield "PyPI", name, line.split("=", 1)[1].strip().strip('"')
            name = None


def _composer(path: Path):
    data = json.loads(path.read_text())
    packages = data.get("packages")
    packages = packages if isinstance(packages, list) else []
    packages_dev = data.get("packages-dev")
    packages_dev = packages_dev if isinstance(packages_dev, list) else []
    for pkg in packages + packages_dev:
        if pkg.get("name") and pkg.get("version"):
            yield "Packagist", pkg["name"], pkg["version"].lstrip("v")


def _gosum(path: Path):
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            yield "Go", parts[0], parts[1].lstrip("v")


_READERS = {
    "package-lock.json": _npm,
    "requirements.txt": _requirements,
    "poetry.lock": _poetry,
    "composer.lock": _composer,
    "go.sum": _gosum,
}


def inventory(root):
    root = Path(root)
    seen, out = set(), []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        reader = _READERS.get(path.name)
        if not reader:
            continue
        source = str(path.relative_to(root))
        try:
            rows = list(reader(path))
        except (ValueError, OSError, TypeError, AttributeError, KeyError):
            # Every reader assumes the shape its format normally has (dicts
            # where the tool always writes a dict, lists where it always
            # writes a list). A crafted or merely corrupted lockfile can
            # violate that assumption in more ways than any single reader
            # guards against -- TypeError from concatenating the wrong
            # shapes, AttributeError from calling a dict/list method on
            # something else, KeyError from a key the format always has,
            # ValueError from malformed JSON, OSError from a file that can't
            # be read. Whichever one a parser trips on, it must cost only
            # this one file: a malformed lockfile is not a reason to fail
            # the whole analysis.
            continue
        for ecosystem, name, version in rows:
            key = (ecosystem, name, version)
            if key in seen:
                continue
            seen.add(key)
            out.append({"ecosystem": ecosystem, "name": name,
                        "version": version, "source": source})
    return out


def sbom(components):
    """A CycloneDX 1.5 document. Hand-built JSON -- no dependency needed."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"vendor": "claude-cron", "name": "security"}]},
        "components": [{
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": f"pkg:{_PURL.get(c['ecosystem'], c['ecosystem'].lower())}/"
                    f"{c['name']}@{c['version']}",
        } for c in components],
    }
