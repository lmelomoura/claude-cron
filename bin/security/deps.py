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
#
# The MATCHER is shared for the same reason, and it is the newer half of the
# lesson: three identical `any(part in SKIP_DIRS ...)` loops could only match
# a bare component, so the set's own contents were narrowed to fit them.
from .secrets import skipped as _skipped
_PURL = {"npm": "npm", "PyPI": "pypi", "Packagist": "composer",
         "Go": "golang", "RubyGems": "gem"}

# The ecosystems that write a leading `v` their own resolver does not treat as
# part of the version: Packagist (`v5.4.0` is the normal form for Symfony,
# Doctrine, Monolog and most of Laravel) and Go (`v1.6.3` is how a module is
# pinned). Everything else is left exactly as the lockfile spelled it.
_V_PREFIXED = {"Packagist", "Go"}


# ------------------------------------------------------------ dependency scope
#
# WHETHER A VULNERABLE PACKAGE SHIPS. A CVE in a test runner is real and far
# less urgent than the same CVE in what serves traffic, and the parent spec
# lists this beside `min_severity` and `ignore_paths` as one of three levers a
# large repository has for spending its triage budget.
#
# THREE VALUES, NOT TWO, and the third is the whole design. "Not marked dev"
# is NOT the same fact as "runtime": three of the five lockfile formats below
# cannot express the distinction at all, and answering `runtime` for them
# would understate the urgency of nothing while overstating the confidence of
# everything. Answering `dev` would be worse -- it hides real risk behind a
# label that says "ignore me". `unknown` is the only honest reading of a file
# that does not carry the fact.
#
# NOT A FINGERPRINT INPUT, and it must never become one. A finding's identity
# is `fingerprint("dependency", vuln_id, source, f"{name}@{version}")`;
# `ledger._REFINGERPRINT` has no `dependency` entry and `rename_rule` refuses
# the category, so a change to what this hashes into would be unrecoverable --
# every human `accepted`/`false_positive` decision on a dependency finding
# would strand permanently. This is an annotation on an identity that already
# exists.
SCOPE_RUNTIME = "runtime"
SCOPE_DEV = "dev"
SCOPE_UNKNOWN = "unknown"
SCOPES = (SCOPE_RUNTIME, SCOPE_DEV, SCOPE_UNKNOWN)

# Precedence for a package pinned by more than one lockfile: runtime beats
# unknown beats dev. It fails TOWARDS urgency in both steps, which is the only
# safe direction here -- `dev` is the sole value that lowers how hard a reader
# looks at a row, so it may only stand when nothing contradicts it. A package
# that is a dev dependency of one service and a runtime dependency of another
# ships; and one seen once as `dev` and once from a format that cannot say is
# not a package anybody has established to be dev-only.
_SCOPE_RANK = {SCOPE_RUNTIME: 0, SCOPE_UNKNOWN: 1, SCOPE_DEV: 2}


def merge_scope(*values) -> str:
    """One reading of `scope`, for EVERY producer of dependency data.

    Exported for the same reason `normalise_version` above is, and against the
    same hazard: there are TWO producers in the `dependency` category
    (`adapters.trivy_vulns` and `osv.query` fed by `inventory` below), only one
    of them runs per analysis (`cli._scan_dependencies`), and which one runs
    depends on whether a machine has Trivy installed. Two copies of this rule
    would let the same finding read `dev` on one machine and `runtime` on the
    next -- the per-machine flip this block has already paid for three times
    (composer's `v` prefix, Go's `go.mod` vs `go.sum`, the OSV/Trivy advisory
    vocabularies). One function, called by both, cannot drift.

    Anything outside `SCOPES` -- including the empty string a row written
    before this column existed carries -- reads as `unknown`, never as
    `runtime`.
    """
    best = None
    for value in values:
        candidate = value if value in _SCOPE_RANK else SCOPE_UNKNOWN
        if best is None or _SCOPE_RANK[candidate] < _SCOPE_RANK[best]:
            best = candidate
    # No values at all is not "runtime" either: nothing was read, so nothing
    # is known.
    return best or SCOPE_UNKNOWN


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
    """`"dev": true`, and EXACTLY that -- measured against Trivy, not assumed.

    npm also writes `"devOptional": true` (a dev dependency that is ALSO an
    optional dependency of a production one). Trivy 0.74.0's npm analyser
    marks `Dev` only for `dev === true`: over a lockfile pinning lodash with
    `"devOptional": true` and minimist with `"dev": true, "optional": true`,
    it reported `Dev` on minimist and nothing on lodash. Reading `devOptional`
    as dev here would therefore call `dev` what the other producer calls
    `runtime` -- and it would be the wrong way round anyway, because a package
    reachable from a production dependency can ship.
    """
    data = json.loads(path.read_text())

    def scope_of(meta):
        return SCOPE_DEV if meta.get("dev") is True else SCOPE_RUNTIME

    packages = data.get("packages")
    packages = packages if isinstance(packages, dict) else {}
    for name, meta in packages.items():
        if not name or not isinstance(meta, dict) or not meta.get("version"):
            continue
        yield ("npm", name.split("node_modules/")[-1], meta["version"],
               scope_of(meta))
    dependencies = data.get("dependencies")
    dependencies = dependencies if isinstance(dependencies, dict) else {}
    for name, meta in dependencies.items():
        if isinstance(meta, dict) and meta.get("version"):
            # lockfileVersion 1's own shape, and it carries the same `dev`
            # flag per entry as the `packages` map above.
            yield "npm", name, meta["version"], scope_of(meta)


def _requirements(path: Path):
    """`unknown`, always. A requirements file is a flat list of pins with no
    section, marker or field that separates development from production --
    the convention is a SECOND file (`requirements-dev.txt`), which `_READERS`
    does not name and which Trivy's pip analyser does not read either
    (measured: a tree holding both reported only `requirements.txt`). So
    neither producer sees it, and neither can answer."""
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if "==" not in line:
            continue  # unpinned: there is nothing to ask OSV about
        name, _, version = line.partition("==")
        name = re.split(r"[\[;]", name)[0].strip()
        version = version.split(";", 1)[0].strip()  # drop a PEP 508 environment marker
        version = version.lstrip("=")  # "===" is PEP 440 arbitrary equality
        if name and version:
            yield "PyPI", name, version, SCOPE_UNKNOWN


def _poetry_scope(category, groups) -> str:
    """Poetry has spelled this three different ways, and only two of them are
    in the lockfile at all. Measured against Trivy 0.74.0, which is the
    producer this has to agree with:

      lock-version 1.x    `category = "main"` / `"dev"`, per package. Both
                          producers read it.
      lock-version 2.0    NEITHER field. Poetry 1.5 dropped `category` and
                          Poetry 2.0 had not yet added `groups`; group
                          membership lived only in `pyproject.toml`. Trivy
                          reads that file and propagates dev through the
                          resolved graph (measured: `py`, an INDIRECT
                          dependency of a dev-group `pytest`, came back
                          `Dev: true`). This reader has no graph and no
                          second file, so it answers `unknown` -- and
                          `SCOPE_NOTE` states the difference rather than
                          leaving it to be found in a diff.
      lock-version 2.1+   `groups = ["main"]` / `["dev"]`, per package. Both
                          producers read it, with no `pyproject.toml` needed
                          (measured over a lock alone).

    `main` present alongside `dev` is NOT dev -- `groups = ["main", "dev"]`
    came back with no `Dev` marker from Trivy, which is the same rule stated
    the other way: dev means dev-ONLY.
    """
    if groups is not None:
        return SCOPE_RUNTIME if "main" in groups else SCOPE_DEV
    if category is None:
        return SCOPE_UNKNOWN
    return SCOPE_DEV if category == "dev" else SCOPE_RUNTIME


def _poetry(path: Path):
    """EMITS AT THE END OF A BLOCK, not at its `version` line, because
    `category`/`groups` are written AFTER `version` in every Poetry release --
    a reader that yielded on `version` could never have seen them."""
    name = version = category = groups = None

    def row():
        if name and version:
            return ("PyPI", name, version, _poetry_scope(category, groups))
        return None

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line == "[[package]]":
            done = row()
            if done:
                yield done
            name = version = category = groups = None
        elif line.startswith("name = ") and name is None:
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name and version is None:
            version = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("category = ") and category is None:
            category = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("groups = ") and groups is None:
            # `groups = ["main", "dev"]` -- split rather than parsed, in
            # keeping with the rest of this hand reader. Only membership is
            # asked, so quoting and spacing are stripped per element.
            groups = [g.strip().strip('"').strip("'") for g
                      in line.split("=", 1)[1].strip().strip("[]").split(",")]
    done = row()
    if done:
        yield done


def _composer(path: Path):
    """`packages-dev` is THE ONE PLACE this module already had the answer and
    threw it away: both lists were concatenated into one flat sequence with no
    marker. Trivy reads the same two keys the same way (measured: a lock
    pinning guzzlehttp/guzzle under `packages` and phpunit/phpunit under
    `packages-dev` came back with `Dev: true` on phpunit alone)."""
    data = json.loads(path.read_text())
    packages = data.get("packages")
    packages = packages if isinstance(packages, list) else []
    packages_dev = data.get("packages-dev")
    packages_dev = packages_dev if isinstance(packages_dev, list) else []
    for pkg, scope in ([(p, SCOPE_RUNTIME) for p in packages]
                       + [(p, SCOPE_DEV) for p in packages_dev]):
        if not isinstance(pkg, dict):
            continue
        if pkg.get("name") and pkg.get("version"):
            yield ("Packagist", pkg["name"],
                   normalise_version("Packagist", pkg["version"]), scope)


def _gosum(path: Path):
    """`unknown`, always, and this one is a property of the LANGUAGE rather
    than of the file: Go has no development-dependency concept: `go.mod` has
    no `devDependencies` section, and `go.sum` records the whole module graph,
    including modules pulled in only by another module's tests. Trivy does not
    mark `Dev` for `gomod` either (measured), so both producers agree by both
    declining to answer."""
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            yield "Go", parts[0], normalise_version("Go", parts[1]), SCOPE_UNKNOWN


_READERS = {
    "package-lock.json": _npm,
    "requirements.txt": _requirements,
    "poetry.lock": _poetry,
    "composer.lock": _composer,
    "go.sum": _gosum,
}


def inventory(root):
    root = Path(root)
    seen, out = {}, []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if _skipped(path.relative_to(root)):
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
        for ecosystem, name, version, scope in rows:
            key = (ecosystem, name, version)
            if key in seen:
                # THE DUPLICATE STILL MOVES THE SCOPE, which is the one thing
                # this dedupe may not simply drop. A monorepo pinning the same
                # package as a dev dependency in one lockfile and a runtime one
                # in another yields ONE component (attributed to the first file,
                # unchanged), and `merge_scope` decides what that component's
                # scope is -- `runtime`, because it ships somewhere. Keeping the
                # first file's answer instead would make the label depend on
                # which lockfile sorts first.
                row = seen[key]
                row["scope"] = merge_scope(row["scope"], scope)
                continue
            row = {"ecosystem": ecosystem, "name": name, "version": version,
                   "source": source, "scope": merge_scope(scope)}
            seen[key] = row
            out.append(row)
    return out


# Named and worded the way `osv.FALLBACK_NOTE` is, and said by the same
# caller for the same reason: `cli._scan_sbom` is what decides this function
# ran instead of Syft, and it should not also be the module that explains
# what that means to a reader. Said whenever `sbom` below is what actually
# built the stored document -- not only when Syft is absent from the
# machine, the same way `secrets.FALLBACK_NOTE` fires whether gitleaks was
# never installed or merely could not answer this run.
# What `scope` is worth on THIS producer's five formats, said in the report
# rather than left to be inferred from a column full of "unknown". Worded as a
# statement about the FORMATS, because that is where the limit is: no amount of
# work on this module makes a requirements.txt say which of its pins ship.
#
# THE POETRY CLAUSE IS THE ONE HONEST DIFFERENCE between the two producers, and
# it is stated instead of hidden. Trivy answers `dev` for a lock-version 2.0
# file (Poetry 1.5 to 2.0) by reading `pyproject.toml`'s groups and walking the
# resolved graph; this reader has neither, so it answers `unknown` for the same
# file. Every other format the two share gives the same answer from the same
# field -- see `_npm`, `_composer` and `_poetry_scope`, each of which records
# what Trivy was measured to do.
SCOPE_NOTE = ("Whether a vulnerable dependency is development-only was read "
              "from the lockfile: package-lock.json marks it per package, "
              "composer.lock separates packages-dev, and poetry.lock carries "
              "it as `category` (lock-version 1.x) or `groups` (2.1+). It is "
              "reported as unknown — never as runtime — everywhere else: "
              "requirements.txt has no development section, go.sum has no "
              "such concept, and a poetry.lock written by Poetry 1.5 to 2.0 "
              "(lock-version 2.0) carries neither field, where Trivy would "
              "have answered from pyproject.toml.")

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
        "metadata": {"tools": [{"vendor": "agentloop", "name": "security"}]},
        "components": components_out,
    }
