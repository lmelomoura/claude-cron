"""What the analysis must never stop looking at.

`secrets.SKIP_DIRS` buys quiet by giving up coverage, so every entry in it is
a blind spot somebody has to justify. The tests here are the receipts: the
directories that ARE noise stay skipped, and the ones that merely share a name
with noise are still scanned.
"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from security import (adapters, coverage, deps, engines, fingerprint, hygiene,
                      ignores, secrets)
from security import cli as security_cli

CLI = Path(__file__).resolve().parent.parent.parent / "bin" / "security" / "cli.py"

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


# ------------------------------------------- the two secret scanners add up
#
# `cli._scan_secrets` used to run ONE scanner -- gitleaks when installed, the
# built-in when not -- on the reasoning that the two name their rules
# differently and so mint two fingerprints for one credential. That stopped
# being a reason once `taxonomy.RULE_RENAMES` mapped the built-in's six mapped
# types onto gitleaks' names: minted under the engine's name BEFORE the
# fingerprint is computed, the built-in's reading of a credential IS the
# engine's identity, and the two lists merge on it. Measured on Minerva before
# the union, with the product filters applied to both: gitleaks 2 identities,
# the built-in 30, the one they shared a single fingerprint after the rename.

# A live shape, assembled at runtime so this file is not itself a credential
# a scanner has to flag -- test_adapters.py's key, for the same reason.
AWS_KEY = "AKIA" + "QYLPMN5HNXMEFRTG"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
# Sixty-four base64 characters: the shape of a PEM body line, and not a key.
PEM_BODY_LINE = "MIIEpAIBAAKCAQEA" + "7Yb3ZpQk9wVt2LmN4RsX8HcJ1FgD6KaE" + "0uWq5TzP3nBvC2rM"
PEM = (f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY_LINE}\n"
       "-----END RSA PRIVATE KEY-----\n")
COMPOSITE = "gitleaks+secrets"

HAVE_GITLEAKS = engines.find("gitleaks") is not None
needs_gitleaks = pytest.mark.skipif(
    not HAVE_GITLEAKS, reason="gitleaks is not installed on this machine")


def _git_repo(root, files):
    """A committed checkout holding `files`, so both history sweeps can run."""
    root.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        _plant(root, rel, text)
    for args in (["init", "-q"], ["config", "user.email", "t@example.com"],
                 ["config", "user.name", "t"],
                 ["config", "maintenance.auto", "false"],
                 ["add", "-A"], ["commit", "-qm", "add"]):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True)
    return root


def _engine_reading(rule, path, line=1, historical=False):
    """One finding as `adapters.gitleaks_scan` would build it."""
    return adapters._finding(rule, path, [line], historical, 0)


def _pretend_gitleaks_saw(monkeypatch, findings, notes=(), history=None, tree=None):
    """The engine path staged without the binary: `engine_path` says gitleaks
    is here and `gitleaks_scan` answers with exactly `findings`. What the
    BUILT-IN sees is not staged -- it runs for real over the tree."""
    history = adapters.HISTORY_OK if history is None else history
    tree = adapters.TREE_OK if tree is None else tree
    monkeypatch.setattr(adapters, "engine_path",
                        lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(adapters, "gitleaks_scan",
                        lambda root, ignore_paths=(): (list(findings), list(notes),
                                                       history, tree))


def _cli_json(db, *args):
    out = subprocess.run([sys.executable, str(CLI), *args, "--db", str(db)],
                         capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout) if out.stdout.strip() else None


def _open_analysis(db):
    return _cli_json(db, "open-analysis", "--project", "web", "--repo", "web",
                     "--branch", "main", "--commit", "abc", "--profile", "quick",
                     "--run-id", "r1")["analysis_id"]


def _prepare_in_process(db, aid, root, capsys):
    """`prepare` through `main()`, so the monkeypatched adapter is the one it
    calls; returns the paragraph it printed."""
    security_cli.main(["prepare", "--analysis", str(aid), "--root", str(root),
                       "--db", str(db), "--offline"])
    return json.loads(capsys.readouterr().out)["coverage_note"]


def _secret_phase(db, aid):
    row = _cli_json(db, "analysis", "--id", str(aid))
    return [p for p in json.loads(row["coverage"])["phases"]
            if p["name"] == "secrets"][0]


def test_both_secret_scanners_run_and_their_findings_merge(tmp_path, monkeypatch):
    """Plan Step 1. One planted AWS key both scanners see, one seed-shaped
    token only the built-in's generic rule sees. After the union there is ONE
    aws finding -- not two under two rule names -- carrying both producers, and
    the generic one survives under gitleaks' name for the type."""
    root = _git_repo(tmp_path / "repo", {"prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
                                         "scripts/seed.py": SHAPED})
    _pretend_gitleaks_saw(monkeypatch, [_engine_reading("aws-access-token", "prod.env")])
    findings, notes, lines, producer, status = security_cli._scan_secrets(root, [])

    aws = [f for f in findings if f["rule"] == "aws-access-token"]
    assert len(aws) == 1, sorted(f["rule"] for f in findings)
    assert set(aws[0]["seen_by"]) == {"gitleaks", "secrets"}
    assert aws[0]["producer"] == COMPOSITE
    assert aws[0]["fingerprint"] == fingerprint.secret_fingerprint(
        "aws-access-token", "prod.env")
    # The tree reading wins over its history twin on the union path too: one
    # occurrence, the line the key is on right now, worded as the present.
    assert [o["line"] for o in aws[0]["occurrences"]] == [1], aws[0]["occurrences"]
    assert "in the working tree" in aws[0]["rationale"]

    generic = [f for f in findings if f["rule"] == "generic-api-key"]
    assert len(generic) == 1
    assert generic[0]["seen_by"] == ["secrets"]
    assert generic[0]["producer"] == "secrets"
    # Nothing is minted under the built-in's own names for the mapped types.
    assert not any(f["rule"] in ("aws_access_key", "generic_secret") for f in findings)

    assert producer == COMPOSITE
    assert status == coverage.RAN
    assert lines > 0, "lines_of_code still comes off the built-in sweep's read"


@needs_gitleaks
def test_both_secret_scanners_run_for_real_and_mint_one_identity(tmp_path, monkeypatch):
    """The same, against the real binary: the engine's `aws-access-token` and
    the built-in's renamed `aws_access_key` are one row with two producers, and
    neither the credential nor the seed token reaches a finding or a note."""
    monkeypatch.setenv("CC_SECURITY_ENGINES", "on")
    seed = SHAPED.split('"')[1]
    root = _git_repo(tmp_path / "repo", {"prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
                                         "scripts/seed.py": SHAPED})
    findings, notes, _lines, producer, status = security_cli._scan_secrets(root, [])
    aws = [f for f in findings if f["rule"] == "aws-access-token"]
    assert len(aws) == 1, sorted(f["rule"] for f in findings)
    assert set(aws[0]["seen_by"]) == {"gitleaks", "secrets"}
    assert any(f["rule"] == "generic-api-key" for f in findings)
    assert producer == COMPOSITE
    assert status == coverage.RAN, notes
    blob = json.dumps(findings) + " ".join(notes)
    assert AWS_KEY not in blob and seed not in blob


def test_prepare_files_the_composite_on_the_row_and_the_atoms_on_each_finding(
        tmp_path, monkeypatch, capsys):
    """What the ledger holds after the union. The analysis row's `produced` and
    the secret phase's `by` carry the PHASE producer, `gitleaks+secrets`; each
    finding's `producer` column carries the atoms that actually saw IT. The
    two are read together by `diff._proven`, and the union's own sentences --
    how many only one saw -- are the phase's prose and a substring of the
    paragraph, like every other phase's."""
    root = _git_repo(tmp_path / "repo", {"prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n",
                                         "scripts/seed.py": SHAPED})
    db = tmp_path / "security.db"
    aid = _open_analysis(db)
    _pretend_gitleaks_saw(monkeypatch, [_engine_reading("aws-access-token", "prod.env")])
    note = _prepare_in_process(db, aid, root, capsys)

    conn = sqlite3.connect(str(db))
    produced = conn.execute("SELECT produced FROM analysis WHERE id=?", (aid,)).fetchone()[0]
    by_rule = dict(conn.execute(
        "SELECT rule, producer FROM finding WHERE analysis_id=? AND category='secret'",
        (aid,)).fetchall())
    conn.close()
    assert COMPOSITE in produced.split(","), produced
    assert by_rule == {"aws-access-token": COMPOSITE, "generic-api-key": "secrets"}, by_rule

    phase = _secret_phase(db, aid)
    assert phase["by"] == COMPOSITE
    assert phase["status"] == "ran"
    union = security_cli.UNION_NOTE.format(both=1, engine=0, builtin=1)
    assert union in phase["note"], phase["note"]
    assert phase["note"] in note
    assert AWS_KEY not in note and AWS_KEY not in db.read_bytes().decode("latin-1")


def test_an_accepted_private_key_decision_still_matches_after_the_union(
        tmp_path, monkeypatch, capsys):
    """Plan Step 4. Block 1 migrated every secret decision onto gitleaks'
    names; the union must not undo that. A decision taken on the `private-key`
    identity is honoured when only the BUILT-IN re-finds the key -- its
    `private_key` is minted under the engine's name, so the fingerprint is the
    one the human ruled on."""
    root = _git_repo(tmp_path / "repo", {"certs/server.key": PEM})
    db = tmp_path / "security.db"
    # The decision first: `decide` refuses while an analysis of the project is
    # running, so it is taken before this one is opened -- as an operator's
    # earlier ruling would have been.
    fp = fingerprint.secret_fingerprint("private-key", "certs/server.key")
    _cli_json(db, "decide", "--project", "web", "--fingerprint", fp,
              "--state", "accepted", "--reason", "rotated at the provider")
    aid = _open_analysis(db)
    _pretend_gitleaks_saw(monkeypatch, [])
    _prepare_in_process(db, aid, root, capsys)
    _cli_json(db, "finish", "--analysis", str(aid), "--state", "done")
    secret = [f for f in _cli_json(db, "checklist", "--analysis", str(aid))["findings"]
              if f["category"] == "secret"]
    assert [f["rule"] for f in secret] == ["private-key"], secret
    assert secret[0]["fingerprint"] == fp
    assert secret[0]["state"] == "accepted"
    assert PEM_BODY_LINE not in json.dumps(secret)


def test_the_two_unmapped_types_are_named_only_when_one_is_present(tmp_path, monkeypatch):
    """`github_token` and `slack_token` are deliberately not in
    `taxonomy.RULE_RENAMES` -- one rule of ours is several of theirs -- so a
    credential of either type CAN appear twice, under our name and under the
    engine's. The paragraph says so, in one sentence, exactly when such a row
    is present, and stays silent otherwise."""
    assert security_cli.UNMAPPED_SECRET_RULES == ("github_token", "slack_token")

    root = _git_repo(tmp_path / "repo", {"ci.env": f"GITHUB_TOKEN={GITHUB_TOKEN}\n"})
    _pretend_gitleaks_saw(monkeypatch, [_engine_reading("github-pat", "ci.env")])
    findings, notes, *_ = security_cli._scan_secrets(root, [])
    # Two identities for the one token, by design, until a map exists. (The
    # built-in's generic rule fires on the same `TOKEN=` line as well; that
    # row is beside the point here.)
    assert {"github_token", "github-pat"} <= {f["rule"] for f in findings}, findings
    assert security_cli.UNMAPPED_TYPES_NOTE in notes

    quiet = _git_repo(tmp_path / "quiet", {"prod.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"})
    _pretend_gitleaks_saw(monkeypatch, [_engine_reading("aws-access-token", "prod.env")])
    findings, notes, *_ = security_cli._scan_secrets(quiet, [])
    assert security_cli.UNMAPPED_TYPES_NOTE not in notes
    assert GITHUB_TOKEN not in json.dumps(findings) + " ".join(notes)


# The secret row is `ran` only when the whole of what the phase means was
# looked at: both scanners, the full history, AND a tree report from the
# engine. `gitleaks git` succeeding while `gitleaks dir` timed out used to leave
# the row `ran` beside a sentence saying the working-tree scan did not complete
# -- the table contradicting its own paragraph. Driven through `engines.run_json`,
# the one door to the binary, so it runs on every machine.

def _gitleaks_passes(monkeypatch, git, dir_):
    monkeypatch.setattr(adapters, "engine_path",
                        lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(engines, "run_json",
                        lambda name, args, cwd, **kw: git if args[0] == "git" else dir_)


@pytest.mark.parametrize("git, dir_, status, gap", [
    (([], ""), (None, "gitleaks did not finish within 600s and was stopped."),
     "warning", "working-tree secret scan did not complete"),
    ((None, "gitleaks did not finish within 600s and was stopped."), ([], ""),
     "warning", "history sweep did not complete"),
    (([], ""), ([], ""), "ran", ""),
], ids=["tree-pass-wrote-no-report", "history-pass-wrote-no-report", "both-fine"])
def test_the_secret_row_is_ran_only_when_both_engine_passes_wrote_a_report(
        tmp_path, monkeypatch, capsys, git, dir_, status, gap):
    root = _git_repo(tmp_path / "repo", {"README.md": "clean\n"})
    db = tmp_path / "security.db"
    aid = _open_analysis(db)
    _gitleaks_passes(monkeypatch, git, dir_)
    note = _prepare_in_process(db, aid, root, capsys)
    phase = _secret_phase(db, aid)
    assert phase["status"] == status, phase
    assert phase["by"] == COMPOSITE
    assert gap in phase["note"], phase["note"]
    assert phase["note"] in note


def test_the_tree_outcome_is_a_returned_value_and_not_a_sentence(tmp_path, monkeypatch):
    """`gitleaks_scan` exposes the tree pass the way it exposes the history
    state -- as the fourth value -- so `_scan_secrets` never has to look for a
    string in a note to know whether the working tree was scanned."""
    root = _git_repo(tmp_path / "repo", {"README.md": "clean\n"})
    _gitleaks_passes(monkeypatch, ([], ""), (None, "gitleaks timed out."))
    findings, _notes, history, tree = adapters.gitleaks_scan(root)
    assert findings is not None and history == adapters.HISTORY_OK
    assert tree == adapters.TREE_GONE
    _gitleaks_passes(monkeypatch, ([], ""), ([], ""))
    assert adapters.gitleaks_scan(root)[3] == adapters.TREE_OK
    _gitleaks_passes(monkeypatch, (None, "x"), (None, "x"))
    assert adapters.gitleaks_scan(root)[2:] == (adapters.HISTORY_GONE, adapters.TREE_GONE)


# Size caps must agree, or the union is over two different file sets: every
# file over the built-in's ceiling would be gitleaks-only for ever, and the
# "N larger than 2 MB" sentence would be false for the phase as a whole.

def test_gitleaks_is_handed_the_same_size_cap_as_the_built_in_sweep(tmp_path, monkeypatch):
    seen = []

    def run_json(name, args, cwd, **kw):
        seen.append(list(args))
        return [], ""

    monkeypatch.setattr(engines, "run_json", run_json)
    adapters.gitleaks_scan(_git_repo(tmp_path / "repo", {"README.md": "clean\n"}))
    assert len(seen) == 2, "one history pass, one tree pass"
    for args in seen:
        at = args.index("--max-target-megabytes")
        assert args[at + 1] == str(secrets.MAX_TARGET_MEGABYTES) == "2"


@needs_gitleaks
def test_a_file_over_the_cap_is_seen_by_neither_scanner(tmp_path, monkeypatch):
    monkeypatch.setenv("CC_SECURITY_ENGINES", "on")
    root = tmp_path / "repo"
    root.mkdir()
    filler = "# nothing to see on this line of the bundle\n"
    (root / "bundle.txt").write_text(
        filler * (secrets._MAX_BYTES // len(filler) + 2) + f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    (root / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    findings, notes, *_ = security_cli._scan_secrets(root, [])
    files = {o["file"] for f in findings for o in f["occurrences"]}
    assert files == {"prod.env"}, files
    assert any("1 larger than 2 MB" in n for n in notes), notes
