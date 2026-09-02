import inspect
import subprocess

from security import engines
from security.secrets import (HISTORY_EMPTY_NOTE, scan_tree, scan_history,
                              looks_like_a_secret)

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def test_looks_like_a_secret_names_the_rule_for_a_shaped_value():
    """The door's reusable check: given free text an agent wrote (a
    finding's title, rationale, ...), name which _RULES pattern matched --
    the SAME list `scan_tree`/`scan_history` walk, not a second copy of it."""
    assert looks_like_a_secret(f"leaked in prod.env: {AWS}") == "aws_access_key"


def test_looks_like_a_secret_returns_none_for_prose_describing_a_credential():
    """The control that keeps the door usable: a rationale that describes a
    credential by type and location, without reproducing it, must pass."""
    assert looks_like_a_secret(
        "An AWS access key is hardcoded in config/prod.env at line 12.") is None


def test_looks_like_a_secret_rejects_an_obvious_placeholder():
    """Same placeholder gate the generic rule already applies to the
    scanner's own corpus -- an agent quoting `changeme...` in a rationale
    must not be refused for it."""
    assert looks_like_a_secret(
        'password = "changeme12345678901234"') is None


def test_it_finds_an_aws_key(tmp_path):
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    found, note, lines = scan_tree(tmp_path, [])
    assert note == ""
    assert len(found) == 1
    assert found[0]["rule"] == "aws_access_key"
    assert found[0]["occurrences"][0]["file"] == "prod.env"
    assert lines == 1


def test_the_value_appears_nowhere_in_the_finding(tmp_path):
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    blob = repr(scan_tree(tmp_path, []))  # the note channel included
    assert AWS not in blob


def test_ignored_paths_are_skipped(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.env").write_text(f"KEY={AWS}\n")
    assert scan_tree(tmp_path, ["tests/**"]) == ([], "", 0)


def test_generic_rule_rejects_a_low_entropy_password_value(tmp_path):
    """The entropy gate itself: a `password=` assignment whose value does not
    look random is rejected, even though it has the right shape. (The old
    test here, `test_high_entropy_alone_is_not_enough`, fed a hex string that
    matches no rule's SHAPE at all -- it was rejected before entropy was
    ever computed, so it asserted nothing about this gate.)"""
    (tmp_path / "config.py").write_text(
        'password = "abababababababababab"\n')
    assert scan_tree(tmp_path, []) == ([], "", 1)


def test_generic_rule_reports_a_high_entropy_password_value(tmp_path):
    """The gate's other side: a `password=` assignment whose value DOES look
    random is reported. Without this, the entropy gate could be rejecting
    everything and the test suite would not notice."""
    (tmp_path / "config.py").write_text(
        'password = "Jk8pVqZ2Xz9LmWrT4hYbNc"\n')
    found, _, _ = scan_tree(tmp_path, [])
    assert len(found) == 1
    assert found[0]["rule"] == "generic_secret"


def test_generic_rule_rejects_an_obvious_placeholder(tmp_path):
    """`changeme12345678901234` measures ~4.0 bits/char -- well above the 3.5
    threshold -- so the entropy gate alone lets it through. It must still be
    rejected because it says, in plain text, that it is not a real secret.
    Raising the entropy threshold is deliberately not the fix: a real secret
    measures ~4.3-4.6 bits/char, too close to give the threshold room."""
    (tmp_path / "config.py").write_text(
        'password = "changeme12345678901234"\n')
    assert scan_tree(tmp_path, []) == ([], "", 1)


def test_history_finds_a_key_that_was_deleted(tmp_path):
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True,
                                    capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "add")
    (tmp_path / "prod.env").unlink()
    run("git", "add", "-A")
    run("git", "commit", "-qm", "remove")

    assert scan_tree(tmp_path, []) == ([], "", 0)
    hist, note, _ = scan_history(tmp_path, None)
    assert note == ""
    assert len(hist) == 1
    assert hist[0]["historical"] is True
    assert AWS not in repr(hist)


def test_fingerprint_is_stable_when_an_unrelated_secret_is_inserted_above(tmp_path):
    """The central premise of the fingerprint: a credential that never moved
    and never changed must keep the SAME fingerprint even after an unrelated
    secret is discovered above it in the same file. A fingerprint computed
    from match POSITION (an ordinal over all matches in the file) would shift
    here -- the GitHub token's old fingerprint would vanish (reported
    "fixed") and a new one would appear (reported "new"), even though nobody
    touched the token. That is the failure the fingerprint exists to
    prevent."""
    (tmp_path / "a.env").write_text(f"GITHUB_TOKEN={GITHUB}\n")
    before, _, _ = scan_tree(tmp_path, [])
    github_before = next(f for f in before if f["rule"] == "github_token")

    (tmp_path / "a.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS}\nGITHUB_TOKEN={GITHUB}\n")
    after, _, _ = scan_tree(tmp_path, [])
    github_after = next(f for f in after if f["rule"] == "github_token")

    assert github_before["fingerprint"] == github_after["fingerprint"]


def test_two_hits_of_the_same_type_in_one_file_are_one_finding_with_two_occurrences(tmp_path):
    """The data model already has the right place for "the same problem in
    several spots": occurrences. Two AWS keys in one file must be one
    finding, not two -- this is also what makes a partial "fixed one of two"
    state expressible later."""
    second_key = "AKIA" + "B" * 16
    (tmp_path / "a.env").write_text(f"A={AWS}\nB={second_key}\n")
    found, _, _ = scan_tree(tmp_path, [])
    assert len(found) == 1
    assert found[0]["rule"] == "aws_access_key"
    assert [o["line"] for o in found[0]["occurrences"]] == [1, 2]


def test_history_attributes_the_correct_file_despite_a_decoy_diff_header_in_content(tmp_path):
    """A file whose own content has a line starting `++ b/decoy` is emitted
    by git as a patch line `+++ b/decoy` -- indistinguishable from a real
    `+++ b/<path>` file header to a scanner that tracks path that way. A
    secret elsewhere in that same file must still be attributed to the
    file's real path (`decoy.txt`), not to the bogus path (`decoy`) parsed
    out of its own content."""
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True,
                                    capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (tmp_path / "decoy.txt").write_text(f"++ b/decoy\nAWS_ACCESS_KEY_ID={AWS}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "add")

    hist, _, _ = scan_history(tmp_path, None)
    assert len(hist) == 1
    assert hist[0]["occurrences"][0]["file"] == "decoy.txt"


def test_history_attributes_a_path_containing_a_space(tmp_path):
    """The diff-header parser splits `a/X b/X` into two equal halves to
    recover X -- this is the control for that rewrite: a path with a space
    in it (a real, common case, unlike the decoy above) must still come out
    whole and correct, not truncated at the space."""
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True,
                                    capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (tmp_path / "my dir").mkdir()
    (tmp_path / "my dir" / "secret file.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "add")

    hist, _, _ = scan_history(tmp_path, None)
    assert len(hist) == 1
    assert hist[0]["occurrences"][0]["file"] == "my dir/secret file.env"


def test_history_counts_distinct_commits_for_a_rotated_credential(tmp_path):
    """The module deliberately never inspects the value, so it cannot tell
    "same value re-added" from "a second, different credential" at the same
    path -- but it can count commits. A credential committed, rotated to a
    different value, and committed again at the same path must produce ONE
    finding whose rationale says there were two exposures, not one silently
    swallowed by dedup."""
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True,
                                    capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    first_key = "AKIA" + "A" * 16
    second_key = "AKIA" + "B" * 16
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={first_key}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "add")
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={second_key}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "rotate")

    hist, _, _ = scan_history(tmp_path, None)
    assert len(hist) == 1
    assert "2 commits" in hist[0]["rationale"]
    assert first_key not in repr(hist)
    assert second_key not in repr(hist)


def test_a_file_too_large_to_read_is_counted_in_the_coverage_note(tmp_path, monkeypatch):
    """A 3 MB minified bundle is skipped for good reasons and is still a place
    this scan did not look. The skip was silent, so a report could say "no
    secrets" about a tree it had only partly read."""
    monkeypatch.setattr("security.secrets._MAX_BYTES", 64)
    (tmp_path / "bundle.js").write_text("x" * 200)
    (tmp_path / "small.env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    found, note, lines = scan_tree(tmp_path, [])
    assert len(found) == 1, "the small file is still scanned"
    assert "did not read 1 file" in note
    assert "larger than" in note
    assert lines == 1, "the skipped bundle must not contribute to the count"


def test_a_file_that_is_not_utf8_is_counted_in_the_coverage_note(tmp_path):
    (tmp_path / "photo.bin").write_bytes(b"\xff\xfe\x00\x01not text at all")
    found, note, lines = scan_tree(tmp_path, [])
    assert found == []
    assert "did not read 1 file" in note
    assert "UTF-8" in note
    assert lines == 0, "an unreadable file must not contribute to the count"


def test_an_ignored_file_is_not_a_coverage_gap(tmp_path):
    """A skip the OPERATOR asked for is a decision, not a blind spot. Counting
    ignored files into the note would put a permanent warning on the report of
    every project that uses `ignore_paths` as intended."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.env").write_text(f"KEY={AWS}\n")
    assert scan_tree(tmp_path, ["tests/**"]) == ([], "", 0)


def test_the_history_sweep_obeys_the_same_ignore_globs(tmp_path):
    """`ignore_paths` excluded a fixtures directory from the tree sweep and
    the history sweep reported every fake credential in it anyway."""
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True, capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.env").write_text(f"KEY={AWS}\n")
    (tmp_path / "prod.env").write_text(f"KEY={GITHUB}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "add")

    everything, _, _ = scan_history(tmp_path, None)
    assert {f["rule"] for f in everything} == {"aws_access_key", "github_token"}

    filtered, note, _ = scan_history(tmp_path, None, ["tests/**"])
    assert note == ""
    assert [f["occurrences"][0]["file"] for f in filtered] == ["prod.env"]


def test_a_history_sweep_that_times_out_says_so_instead_of_answering_clean(tmp_path, monkeypatch):
    """`[]` is what a clean history looks like, and it is what a timeout used
    to look like too. The two must never be the same answer: the second one
    hides exactly the findings this function exists to produce."""
    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="git", timeout=600)
    monkeypatch.setattr(subprocess, "run", boom)
    findings, note, swept = scan_history(tmp_path, None)
    assert findings == []
    assert "did not complete" in note and "timed out" in note
    assert swept is False, "a sweep that did not complete must say so in the value too"


def test_a_history_sweep_that_cannot_run_git_says_so(tmp_path, monkeypatch):
    def boom(*a, **kw):
        raise OSError("no git on this machine")
    monkeypatch.setattr(subprocess, "run", boom)
    findings, note, swept = scan_history(tmp_path, None)
    assert findings == []
    assert "did not complete" in note and "no git on this machine" in note


def test_a_root_that_is_not_a_git_checkout_is_a_stated_gap(tmp_path):
    """git exits non-zero, which `check=False` turned into an empty stdout and
    therefore into "this history is clean"."""
    findings, note, swept = scan_history(tmp_path, None)
    assert findings == []
    assert "did not complete" in note
    assert swept is False


def test_a_checkout_with_no_commits_is_an_empty_history_not_a_failed_sweep(tmp_path):
    """`git log HEAD` on an unborn branch fails with "ambiguous argument
    'HEAD'" -- the shape of a broken repository -- and this sweep filed the gap
    sentence for a checkout that merely had nothing to sweep, beside gitleaks'
    own claim to have scanned the full history. Nothing failed and nothing is
    missing: the sweep is complete, the note says the history is empty, and
    the coverage row stays `ran` (see test_recall.py for the phase)."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    findings, note, swept = scan_history(tmp_path, None)
    assert findings == []
    assert note == HISTORY_EMPTY_NOTE
    assert swept is True
    assert "did not complete" not in note


def test_the_history_sweep_runs_on_the_engines_time_budget(tmp_path, monkeypatch):
    """One constant, `engines.SCAN_TIMEOUT`, for the built-in's `git log -p`
    and for every engine pass. The two used to be 300 s against 600 s, so on a
    large repository gitleaks' history pass could finish while this one timed
    out, and the secret row -- which needs both -- read `warning`."""
    seen = []

    def fake_run(cmd, **kw):
        seen.append(kw.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    scan_history(tmp_path, None)
    assert seen and set(seen) == {engines.SCAN_TIMEOUT}, seen
    assert (inspect.signature(engines.run_json).parameters["timeout"].default
            == engines.SCAN_TIMEOUT == 600)


def test_scan_tree_counts_the_lines_it_already_read(tmp_path):
    """The deterministic phase opens every versioned text file anyway; the
    count is a by-product, not a second walk."""
    (tmp_path / "a.py").write_text("one\ntwo\nthree\n")
    (tmp_path / "b.js").write_text("only one\n")
    _findings, _note, lines = scan_tree(tmp_path, [])
    assert lines == 4


def test_the_line_count_skips_what_the_scan_skips(tmp_path):
    (tmp_path / "keep.py").write_text("a\nb\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendored.js").write_text("x\ny\nz\n")
    (tmp_path / "ignored.py").write_text("1\n2\n3\n4\n")
    _f, _n, lines = scan_tree(tmp_path, ["ignored.py"])
    assert lines == 2


# ------------------------------------------------- the default noise filter
#
# The FALLBACK half of Task 7. Every assertion below has a twin in
# test_adapters.py driving the same case through gitleaks, because a default
# only one of the two scanners honours is a repository that reports
# differently depending on which binaries the machine happens to have.

def test_a_fixtures_directory_needs_no_ignore_paths_any_more(tmp_path):
    """Before this, a project that had not hand-written `ignore_paths` got
    every deliberately fake credential in its fixtures on every analysis."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixtures").mkdir()
    (tmp_path / "tests" / "fixtures" / "fake.env").write_text(f"KEY={AWS}\n")
    assert scan_tree(tmp_path, []) == ([], "", 0)


def test_the_default_suppression_can_be_turned_off_per_project(tmp_path):
    """A project that keeps real credentials in a fixture it wants reported
    says so once, in the config that travels with the repository."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixtures").mkdir()
    (tmp_path / "tests" / "fixtures" / "fake.env").write_text(f"KEY={AWS}\n")
    found, _note, _lines = scan_tree(tmp_path, ["!defaults"])
    assert [f["rule"] for f in found] == ["aws_access_key"]


def test_a_realistic_key_in_an_env_example_is_not_reported(tmp_path):
    """A4.14. `_is_placeholder` gates the VALUE and only for the generic rule,
    so `AKIAIOSFODNN7EXAMPLE` in a `.env.example` -- a shaped match with no
    entropy gate at all -- was reported as a committed AWS key. The file is
    still READ: it counts towards lines_of_code like any other file this
    analysis looked at."""
    (tmp_path / ".env.example").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    found, note, lines = scan_tree(tmp_path, [])
    assert found == []
    assert note == ""
    assert lines == 1, "the file was read; only its secrets were not reported"


def test_a_PRIVATE_KEY_in_a_sample_file_is_STILL_reported(tmp_path):
    """THE HOLE THE FIRST VERSION OF THIS DEFAULT OPENED, and the reason the
    gate is per RULE and not per FILE.

    A `.example` file used to be skipped whole, on the reasoning that "the
    value in a template is a shape, not a secret". A PEM body is never a
    shape. Measured with a real `openssl genrsa 2048` key in
    `certs/server.key.example`: reported by NOTHING -- not this scanner, not
    gitleaks through `adapters.gitleaks`, not `hygiene._is_key_material`
    (whose suffix test does not see past `.example`) -- while gitleaks on its
    own reported it. This project's own argument for not suppressing
    `tests/**` applies word for word: it is in the repository and readable by
    everyone with a clone."""
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "server.key.example").write_text(PEM)
    found, _note, _lines = scan_tree(tmp_path, [])
    assert [f["rule"] for f in found] == ["private_key"]
    assert found[0]["occurrences"][0]["file"] == "certs/server.key.example"


# ------------------------------------------ a PEM header alone is not a key
#
# Measured on Minerva: five `private_key` findings from this scanner. Two were
# a header with no body -- an adversarial test and a conformance harness, both
# test code -- and not a gitleaks finding, because gitleaks' `private-key` rule
# wants the body; three had a body behind the header (a redaction test with a
# base64 run on the next line, and two planning documents, one with that shape
# and one carrying a whole PEM on one line with `\n` escapes), and gitleaks
# reports two of those three itself. With the two scanners' findings merged by
# fingerprint, the two header-only matches came back as findings only the
# built-in saw; the fix is at the source, and the shape it now requires is the
# one a key actually has -- which the three with a body have.

# Sixty-four base64 characters -- the shape of a body line, and not a key.
PEM_BODY_LINE = "MIIEpAIBAAKCAQEA" + "7Yb3ZpQk9wVt2LmN4RsX8HcJ1FgD6KaE" + "0uWq5TzP3nBvC2rM"
PEM = (f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY_LINE}\n"
       "-----END RSA PRIVATE KEY-----\n")


def test_a_pem_header_with_no_body_is_not_a_finding(tmp_path):
    """The documentation shape: a header, an ellipsis or a placeholder where
    the material goes, a footer. Nothing to rotate."""
    (tmp_path / "plan.md").write_text(
        "The redactor must catch this:\n\n"
        "    -----BEGIN RSA PRIVATE KEY-----\n    ...\n"
        "    -----END RSA PRIVATE KEY-----\n")
    (tmp_path / "harness.js").write_text(
        'const HEADER = "-----BEGIN RSA PRIVATE KEY-----";\n'
        'const FOOTER = "-----END RSA PRIVATE KEY-----";\n')
    assert scan_tree(tmp_path, [])[0] == []
    assert looks_like_a_secret("-----BEGIN RSA PRIVATE KEY----- appears in the log") is None


def test_a_pem_header_followed_by_its_body_is_a_finding(tmp_path):
    (tmp_path / "id_rsa").write_text(PEM)
    found, _, _ = scan_tree(tmp_path, [])
    assert [f["rule"] for f in found] == ["private_key"]
    assert [o["line"] for o in found[0]["occurrences"]] == [1]
    assert PEM_BODY_LINE not in repr(found)
    assert looks_like_a_secret(f"pasted: {PEM}") == "private_key"


def test_a_one_line_pem_with_escaped_newlines_is_still_a_finding(tmp_path):
    """The `.env` and JSON shape: the whole key on one physical line with
    `\\n` where the line breaks were. The body follows the header on the SAME
    line, and that has to count -- a real key stored the way real keys are
    stored is the one shape this rule must never lose."""
    (tmp_path / ".env").write_text(
        f'SIGNING_KEY="-----BEGIN RSA PRIVATE KEY-----\\n{PEM_BODY_LINE}\\n'
        '-----END RSA PRIVATE KEY-----"\n')
    found, _, _ = scan_tree(tmp_path, [])
    assert [f["rule"] for f in found] == ["private_key"]


def test_the_history_sweep_reads_a_body_across_its_added_lines(tmp_path):
    """`scan_history` used to match each `+` line on its own, which cannot see
    a body on the line after a header. The added lines of one file in one
    commit are read together, so a key committed and later deleted is still
    found -- and a lone header committed and deleted is still not."""
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True,
                       capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (tmp_path / "deploy.key").write_text(PEM)
    (tmp_path / "notes.md").write_text("-----BEGIN RSA PRIVATE KEY-----\n...\n")
    git("add", "-A")
    git("commit", "-qm", "add")
    (tmp_path / "deploy.key").unlink()
    (tmp_path / "notes.md").unlink()
    git("add", "-A")
    git("commit", "-qm", "remove")
    found, note, swept = scan_history(tmp_path, None)
    assert note == "" and swept is True
    assert [(f["rule"], f["occurrences"][0]["file"]) for f in found] == [
        ("private_key", "deploy.key")]
    assert PEM_BODY_LINE not in repr(found)


def test_a_template_silences_ONLY_the_two_template_noisy_rules(tmp_path):
    """The set is an ALLOWLIST, so a rule nobody has thought about reports.

    One file, three shapes. The AWS rule and the generic rule are the two
    that genuinely over-fire on a template (neither has a placeholder gate
    that survives a realistic-looking value); a GitHub PAT in a committed
    template is a GitHub PAT."""
    (tmp_path / "config.yml.template").write_text(
        f"aws: {AWS}\npassword = 'hunter2hunter2hunter2xyz'\ntoken: {GITHUB}\n")
    found, _note, _lines = scan_tree(tmp_path, [])
    assert [f["rule"] for f in found] == ["github_token"]


def test_a_sample_file_is_reported_again_when_the_default_is_off(tmp_path):
    (tmp_path / ".env.example").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    found, _note, _lines = scan_tree(tmp_path, ["!defaults"])
    assert [f["rule"] for f in found] == ["aws_access_key"]


def test_the_history_sweep_obeys_the_default_too(tmp_path):
    """The scar this whole module already carries once: `ignore_paths`
    excluded a fixtures directory from the tree sweep and the history sweep
    reported every fake credential in it anyway, one report later. A default
    honoured by only one of the two sweeps reopens exactly that hole.

    BOTH HALVES, because the template rule is now per rule here too: the AWS
    key in `.env.example` is dropped and the GitHub PAT beside it is not, and
    a history sweep that disagreed with the tree sweep about either one would
    be the same bug in the other direction."""
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True,
                                    capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixtures").mkdir()
    (tmp_path / "tests" / "fixtures" / "fake.env").write_text(f"KEY={AWS}\n")
    (tmp_path / ".env.example").write_text(f"AWS={AWS}\nGH={GITHUB}\n")
    (tmp_path / "prod.env").write_text(f"KEY={GITHUB}\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "add")

    filtered, note, _ = scan_history(tmp_path, None)
    assert note == ""
    assert sorted((f["occurrences"][0]["file"], f["rule"]) for f in filtered) == [
        (".env.example", "github_token"), ("prod.env", "github_token")]

    everything, _, _ = scan_history(tmp_path, None, ["!defaults"])
    assert sorted({f["occurrences"][0]["file"] for f in everything}) == [
        ".env.example", "prod.env", "tests/fixtures/fake.env"]
