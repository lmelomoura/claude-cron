# bin/security/deps.py
"""What this project depends on, read from lockfiles.

Only names and versions are read. No dependency's CODE is ever opened -- it is
noise for the analysis, and it is the only place a repository the user checked
out could carry text written by someone else.
"""

import json
import re
from pathlib import Path
from urllib.parse import quote

# THE shared engine scope, not a copy of it. This was a byte-identical private
# set, as was `hygiene._SKIP_DIRS`, while `secrets.SKIP_DIRS` was already
# public and documented as the one place an analysis's scope is written down
# (five call sites read it, `adapters.gitleaks_config`, `trivy_skip_dirs` and
# `syft_sbom` among them, so that whichever scanner runs they all agree on
# where an analysis looks). Three identical sets do not disagree until somebody
# edits one; editing the public one used to leave this phase and the hygiene
# pass silently walking a different tree from every engine.
from .secrets import SKIP_DIRS as _SKIP_DIRS
_PURL = {"npm": "npm", "PyPI": "pypi", "Packagist": "composer",
         "Go": "golang", "RubyGems": "gem"}

# The ecosystems that write a leading `v` their own resolver does not treat as
# part of the version: Packagist (`v5.4.0` is the normal form for Symfony,
# Doctrine, Monolog and most of Laravel) and Go (`v1.6.3` is how a module is
# pinned). Everything else is left exactly as the lockfile spelled it.
_V_PREFIXED = {"Packagist", "Go"}


def normalise_version(ecosystem: str, version: str) -> str:
    """One reading of a version string, for EVERY producer of dependency data.

    Exported rather than kept private because it is not a detail of this
    module. A dependency finding's identity is
    `fingerprint("dependency", vuln_id, source, f"{name}@{version}")`, so a
    second producer reading the same lockfile and spelling the version
    differently -- `v5.4.0` where this one says `5.4.0` -- mints a SECOND
    identity for one vulnerability. The consequence is not cosmetic: the same
    hole is reported `fixed` (the old identity is gone) and `new` (a fresh one
    appeared) in a single report, the human `accepted`/`false_positive`
    decision recorded against the old one strands permanently, and
    `ledger._REFINGERPRINT` has no `dependency` entry, so `rename_rule`
    cannot migrate it. `adapters.trivy_vulns` calls this for that reason and
    no other.
    """
    return version.lstrip("v") if ecosystem in _V_PREFIXED else version


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
        if not isinstance(pkg, dict):
            continue
        if pkg.get("name") and pkg.get("version"):
            yield "Packagist", pkg["name"], normalise_version(
                "Packagist", pkg["version"])


def _gosum(path: Path):
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            yield "Go", parts[0], normalise_version("Go", parts[1])


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


# Named and worded the way `osv.FALLBACK_NOTE` is, and said by the same
# caller for the same reason: `cli._scan_sbom` is what decides this function
# ran instead of Syft, and it should not also be the module that explains
# what that means to a reader. Said whenever `sbom` below is what actually
# built the stored document -- not only when Syft is absent from the
# machine, the same way `secrets.FALLBACK_NOTE` fires whether gitleaks was
# never installed or merely could not answer this run.
SBOM_FALLBACK_NOTE = ("The SBOM was built from this project's own inventory "
                      "(package-lock.json, requirements.txt, poetry.lock, "
                      "composer.lock, go.sum), not by Syft: a dependency in "
                      "a format only Syft reads would not be listed.")


def sbom(components):
    """A CycloneDX 1.5 document. Hand-built JSON -- no dependency needed."""
    components_out = []
    for c in components:
        ecosystem = _PURL.get(c["ecosystem"], c["ecosystem"].lower())
        # purl requires reserved characters percent-encoded -- most notably
        # the "@" that marks an npm scope (e.g. @types/node). quote(...,
        # safe="/") does that while still treating "/" as a path separator,
        # in both the name and the version.
        name = quote(c["name"], safe="/")
        version = quote(c["version"], safe="/")
        components_out.append({
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": f"pkg:{ecosystem}/{name}@{version}",
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"vendor": "claude-cron", "name": "security"}]},
        "components": components_out,
    }
