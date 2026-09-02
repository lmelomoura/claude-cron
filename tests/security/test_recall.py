"""What the analysis must never stop looking at.

`secrets.SKIP_DIRS` buys quiet by giving up coverage, so every entry in it is
a blind spot somebody has to justify. The tests here are the receipts: the
directories that ARE noise stay skipped, and the ones that merely share a name
with noise are still scanned.
"""

import json

from security import adapters, deps, hygiene, ignores, secrets

# One shaped credential, high enough in entropy to clear the generic rule's
# gate and not matching any placeholder marker.
SHAPED = 'password = "Zq9tRw2mXk7pLn4vBs8yHd3fGj6c"\n'


def _plant(root, rel, text=SHAPED):
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text)


def test_agent_workspaces_are_never_scanned(tmp_path):
    # .superpowers/ is where this repository's own agents write review diffs
    # and reports; data/logs/ is where run transcripts land. Both are
    # git-ignored, both routinely contain credential-shaped text (a captured
    # AKIA... in a review diff, a planted key in a transcript), and neither is
    # the project. Measured on Minerva: 22 generic_secret hits from
    # .superpowers/ alone, none of them a leak.
    for d in (".superpowers/sdd", "data/logs/security-x", "src"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "f.txt").write_text(SHAPED)
    findings, _, _ = secrets.scan_tree(tmp_path, ())
    files = {o["file"] for f in findings for o in f["occurrences"]}
    assert files == {"src/f.txt"}, files


# ------------------------------------------- the entry is `data/logs`, not `logs`
#
# THE FINDING THIS SECTION EXISTS FOR. `data/logs` was first written as a bare
# `logs`, because every reader of `SKIP_DIRS` matched a single path component
# and nothing could express the longer path. A bare `logs` exempts EVERY
# directory of that name in an analysed project from EVERY phase. On the
# Minerva checkout that is `martis-app/storage/logs/` -- Laravel's real
# application-log directory, where a framework stack trace writes database
# passwords and tokens, and exactly the untracked material this scanner walks
# the raw filesystem to reach. It also bought nothing: Minerva has no
# `data/logs`, so the whole measured reduction was `.superpowers`.

def test_a_projects_own_log_directory_is_still_scanned(tmp_path):
    """THE ASSERTION THAT KEEPS THE BLIND SPOT CLOSED. If `SKIP_DIRS` ever
    grows a bare `logs` again, or `skipped` ever matches an entry's last
    component on its own, this fails."""
    assert not secrets.skipped("martis-app/storage/logs/laravel.log")
    _plant(tmp_path, "martis-app/storage/logs/laravel.log")
    findings, _, _ = secrets.scan_tree(tmp_path, ())
    files = {o["file"] for f in findings for o in f["occurrences"]}
    assert files == {"martis-app/storage/logs/laravel.log"}, files


def test_the_transcript_directory_is_skipped_with_everything_under_it():
    assert secrets.skipped("data/logs/x/f.txt")
    assert secrets.skipped("data/logs")


def test_a_multi_segment_entry_matches_at_any_depth_like_a_bare_one():
    """THE DECISION, and it is not a preference. A multi-segment entry matches
    its segments as a contiguous run WHEREVER that run appears, so
    `src/data/logs/f.txt` is skipped and `storage/logs/f.txt` is not.

    Anchoring it to the root instead would have been the mirror-image bug of
    the one this file is about. Every engine is handed the same scope as an
    any-depth expression -- `(^|/)data/logs/` for gitleaks, `**/data/logs` for
    trivy, syft and semgrep -- and a root-anchored predicate here would leave
    the built-in sweep reading a tree those engines are told to skip. The same
    repository would then report differently depending on which binaries the
    machine has installed, which is the one thing this shared set exists to
    prevent. The narrowing that mattered was `logs` -> `data/logs`; a nested
    `data/logs` is the same transcript directory, while `storage/logs` is not.
    """
    assert secrets.skipped("src/data/logs/f.txt")
    assert not secrets.skipped("logs/f.txt")
    assert not secrets.skipped("data/f.txt")


def test_a_single_segment_entry_keeps_its_any_depth_meaning():
    assert secrets.skipped("a/b/node_modules/pkg/index.js")
    assert secrets.skipped("__pycache__/x.pyc")
    assert not secrets.skipped("src/node_modules_helper/x.js")


def test_the_engine_scope_carries_the_whole_path_and_not_its_last_component():
    """A gitleaks allowlist built from `(^|/)logs/` would ask the engine to
    stop reading an analysed project's application logs -- a scope WIDER than
    the analysis has, which `_out_of_scope` cannot put back."""
    patterns = adapters.scope_patterns()
    assert r"(^|/)data/logs/" in patterns
    assert r"(^|/)logs/" not in patterns
    assert r"(^|/)data/logs/" in adapters.gitleaks_config()


def test_the_engine_pre_filters_carry_the_whole_path_too():
    for name in ("data/logs", ".superpowers"):
        assert f"**/{name}" in adapters.trivy_skip_dirs()
        assert f"**/{name}" in adapters.semgrep_excludes()
    assert "**/logs" not in adapters.trivy_skip_dirs()
    assert "**/logs" not in adapters.semgrep_excludes()


def test_an_engines_finding_in_a_projects_log_directory_is_kept():
    """The second lock, on the other side of the engine: `_out_of_scope` reads
    the same predicate, so a real gitleaks hit under `storage/logs/` survives
    while one under `data/logs/` does not."""
    assert not adapters._out_of_scope("martis-app/storage/logs/laravel.log", ())
    assert adapters._out_of_scope("data/logs/run/x.ndjson", ())


# --------------------------------------- the other phases read the same predicate

def test_the_dependency_inventory_honours_the_same_predicate(tmp_path):
    lock = json.dumps({"packages": {"node_modules/left-pad": {"version": "1.3.0"}}})
    _plant(tmp_path, "data/logs/run/package-lock.json", lock)
    assert deps.inventory(tmp_path) == []
    _plant(tmp_path, "martis-app/storage/logs/package-lock.json", lock)
    sources = {row["source"] for row in deps.inventory(tmp_path)}
    assert sources == {"martis-app/storage/logs/package-lock.json"}, sources


def test_the_hygiene_pass_honours_the_same_predicate(tmp_path):
    _plant(tmp_path, "data/logs/run/.env", "TOKEN=x\n")
    assert hygiene.scan(tmp_path) == []
    _plant(tmp_path, "martis-app/storage/logs/.env", "TOKEN=x\n")
    files = {o["file"] for f in hygiene.scan(tmp_path) for o in f["occurrences"]}
    assert files == {"martis-app/storage/logs/.env"}, files


def test_the_default_noise_filter_is_still_a_set_of_bare_names():
    """`ignores.DEFAULT_IGNORE_DIRS` joins `SKIP_DIRS` in every engine's
    command line, and it means directory NAMES at any depth. Nothing here
    should acquire a `/` without the reasoning `secrets.skipped` carries."""
    assert all("/" not in name for name in ignores.DEFAULT_IGNORE_DIRS)
