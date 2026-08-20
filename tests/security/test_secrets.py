import subprocess
from security.secrets import scan_tree, scan_history

AWS = "AKIA" + "IOSFODNN7EXAMPLE"


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


def test_high_entropy_alone_is_not_enough(tmp_path):
    """A random-looking string with no key shape is noise, not a secret."""
    (tmp_path / "data.txt").write_text("d41d8cd98f00b204e9800998ecf8427e\n")
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
