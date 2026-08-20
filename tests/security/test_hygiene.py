from security.hygiene import scan


def test_a_committed_env_file_is_a_finding(tmp_path):
    (tmp_path / ".env").write_text("DB_HOST=localhost\n")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_env_file" in rules


def test_an_env_example_is_not(tmp_path):
    (tmp_path / ".env.example").write_text("DB_HOST=\n")
    assert scan(tmp_path) == []


def test_a_private_key_file_is_a_finding(tmp_path):
    (tmp_path / "server.pem").write_text("x\n")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_key_file" in rules


def test_a_world_writable_file_is_a_finding(tmp_path):
    p = tmp_path / "deploy.sh"
    p.write_text("#!/bin/sh\n")
    p.chmod(0o666)
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "world_writable_file" in rules
