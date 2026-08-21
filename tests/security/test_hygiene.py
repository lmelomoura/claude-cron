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


def test_an_env_local_file_is_a_finding(tmp_path):
    (tmp_path / ".env.local").write_text("DB_HOST=localhost\n")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_env_file" in rules


def test_an_env_production_file_is_a_finding(tmp_path):
    (tmp_path / ".env.production").write_text("DB_HOST=prod.example.com\n")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_env_file" in rules


def test_an_env_file_inside_a_skipped_dir_is_not_a_finding(tmp_path):
    nested = tmp_path / "node_modules" / "x"
    nested.mkdir(parents=True)
    (nested / ".env").write_text("DB_HOST=localhost\n")
    assert scan(tmp_path) == []


def test_an_envrc_file_is_not_a_finding(tmp_path):
    (tmp_path / ".envrc").write_text("export DB_HOST=localhost\n")
    assert scan(tmp_path) == []


def test_a_cert_only_pem_is_not_a_finding(tmp_path):
    (tmp_path / "fullchain.pem").write_text(
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n"
        "-----END CERTIFICATE-----\n")
    assert scan(tmp_path) == []


def test_a_pem_with_a_private_key_marker_is_a_finding(tmp_path):
    (tmp_path / "server.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----\n")
    findings = [f for f in scan(tmp_path) if f["rule"] == "committed_key_file"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_a_p12_file_is_a_finding_regardless_of_content(tmp_path):
    (tmp_path / "bundle.p12").write_bytes(b"\x00\x01\x02not a real pkcs12 container\xff\xfe")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_key_file" in rules


def test_ignored_paths_are_skipped(tmp_path):
    """`ignore_paths` is a promise about the whole analysis. A fixtures
    directory excluded from the secret sweeps was still reported here, so the
    setting removed the noise from one section of the report and left it in
    another."""
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / ".env").write_text("DB_HOST=localhost\n")
    (fixtures / "fake.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nx\n")
    assert [f["rule"] for f in scan(tmp_path)] != []
    assert scan(tmp_path, ["tests/fixtures/**"]) == []


def test_a_repository_with_no_gitignore_gets_an_advisory_finding(tmp_path):
    """Nothing is wrong yet -- which is why it is info, not a warning. It is
    how the next .env gets committed.

    Marked as a repository with a bare `.git` directory: the rule's own
    rationale ("committed by default") only means something inside a
    repository, and without this marker the fixture would not be testing
    that case at all -- see test_a_plain_directory_gets_no_gitignore_advisory
    for the other side."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text("x = 1\n")
    found = [f for f in scan(tmp_path) if f["rule"] == "missing_gitignore"]
    assert len(found) == 1
    assert found[0]["severity"] == "info"


def test_a_repository_with_a_gitignore_gets_none(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text(".env\n")
    assert [f for f in scan(tmp_path) if f["rule"] == "missing_gitignore"] == []


def test_a_plain_directory_gets_no_gitignore_advisory(tmp_path):
    """The mirror of the two tests above: a directory that is not a git
    repository at all -- no `.git` file or directory -- gets no advisory
    regardless of whether it has a .gitignore. The rule is about what
    happens to a COMMIT; a directory that is not a repository never has
    one."""
    (tmp_path / "app.py").write_text("x = 1\n")
    assert [f for f in scan(tmp_path) if f["rule"] == "missing_gitignore"] == []
