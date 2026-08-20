import subprocess
from security.secrets import scan_tree, scan_history

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def test_it_finds_an_aws_key(tmp_path):
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    found = scan_tree(tmp_path, [])
    assert len(found) == 1
    assert found[0]["rule"] == "aws_access_key"
    assert found[0]["occurrences"][0]["file"] == "prod.env"


def test_the_value_appears_nowhere_in_the_finding(tmp_path):
    (tmp_path / "prod.env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
    blob = repr(scan_tree(tmp_path, []))
    assert AWS not in blob


def test_ignored_paths_are_skipped(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.env").write_text(f"KEY={AWS}\n")
    assert scan_tree(tmp_path, ["tests/**"]) == []


def test_generic_rule_rejects_a_low_entropy_password_value(tmp_path):
    """The entropy gate itself: a `password=` assignment whose value does not
    look random is rejected, even though it has the right shape. (The old
    test here, `test_high_entropy_alone_is_not_enough`, fed a hex string that
    matches no rule's SHAPE at all -- it was rejected before entropy was
    ever computed, so it asserted nothing about this gate.)"""
    (tmp_path / "config.py").write_text(
        'password = "abababababababababab"\n')
    assert scan_tree(tmp_path, []) == []


def test_generic_rule_reports_a_high_entropy_password_value(tmp_path):
    """The gate's other side: a `password=` assignment whose value DOES look
    random is reported. Without this, the entropy gate could be rejecting
    everything and the test suite would not notice."""
    (tmp_path / "config.py").write_text(
        'password = "Jk8pVqZ2Xz9LmWrT4hYbNc"\n')
    found = scan_tree(tmp_path, [])
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
    assert scan_tree(tmp_path, []) == []


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

    assert scan_tree(tmp_path, []) == []
    hist = scan_history(tmp_path, None)
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
    before = scan_tree(tmp_path, [])
    github_before = next(f for f in before if f["rule"] == "github_token")

    (tmp_path / "a.env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS}\nGITHUB_TOKEN={GITHUB}\n")
    after = scan_tree(tmp_path, [])
    github_after = next(f for f in after if f["rule"] == "github_token")

    assert github_before["fingerprint"] == github_after["fingerprint"]


def test_two_hits_of_the_same_type_in_one_file_are_one_finding_with_two_occurrences(tmp_path):
    """The data model already has the right place for "the same problem in
    several spots": occurrences. Two AWS keys in one file must be one
    finding, not two -- this is also what makes a partial "fixed one of two"
    state expressible later."""
    second_key = "AKIA" + "B" * 16
    (tmp_path / "a.env").write_text(f"A={AWS}\nB={second_key}\n")
    found = scan_tree(tmp_path, [])
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

    hist = scan_history(tmp_path, None)
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

    hist = scan_history(tmp_path, None)
    assert len(hist) == 1
    assert hist[0]["occurrences"][0]["file"] == "my dir/secret file.env"
