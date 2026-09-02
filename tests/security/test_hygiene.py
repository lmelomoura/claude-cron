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


def test_a_shouted_env_example_is_not_a_finding_either(tmp_path):
    """The suffix list was matched with `fnmatch`, chosen on the argument that
    it normalises case -- which `os.path.normcase` does not do on POSIX. So
    `.ENV.EXAMPLE` was reported as a committed env file."""
    (tmp_path / ".ENV.EXAMPLE").write_text("DB_HOST=\n")
    assert scan(tmp_path) == []


def test_a_real_key_committed_as_a_TEMPLATE_is_still_a_finding(tmp_path):
    """The suffix test did not see past `.example`, so `server.key.example`
    was never sniffed -- and with the secret scan skipping the file whole, a
    real `openssl genrsa` key committed under that name was reported by
    nothing in this project at all."""
    (tmp_path / "server.key.example").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n"
        "-----END RSA PRIVATE KEY-----\n")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_key_file" in rules


def test_a_PLACEHOLDER_key_template_is_still_not_a_finding(tmp_path):
    """And this is why the template is sniffed UNDER PROOF rather than with
    the conservative default a real `.key` gets. For `server.key` the likelier
    error is staying quiet; for `server.key.example` a placeholder body is the
    normal case, so the finding is made only when the PEM marker is really
    there."""
    (tmp_path / "server.key.example").write_text("<paste your private key here>\n")
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


def test_a_binary_key_container_committed_as_a_TEMPLATE_is_still_a_finding(tmp_path):
    """The same shape as `test_a_real_key_committed_as_a_TEMPLATE_is_still_a_
    finding`, one suffix family down: the binary branch used to test `name`,
    not `stem`, so a real keystore committed as `keystore.jks.example` was
    reported by nothing -- and `!defaults` could not bring it back, because
    the file never reached the rule at all. There is no marker to sniff in a
    binary container, so this reports on the name alone, exactly as
    `test_a_p12_file_is_a_finding_regardless_of_content` already does for a
    plain `.p12` -- the template suffix no longer hides the file from that
    same, pre-existing, unproven check."""
    (tmp_path / "keystore.jks.example").write_bytes(b"\x00\x01not a real jks\xff")
    rules = [f["rule"] for f in scan(tmp_path)]
    assert "committed_key_file" in rules


def test_an_unrelated_template_is_still_not_a_finding(tmp_path):
    """The containment case for the widened binary check above: looking past
    the template suffix must land on a real `.p12`/`.pfx`/`.jks` stem to fire
    -- it must not turn into "anything under `.example` is key material".
    `archive.zip.example` strips to `archive.zip`, which is none of the three
    binary suffixes, and stays clear."""
    (tmp_path / "archive.zip.example").write_bytes(b"PK\x03\x04not a real zip")
    assert scan(tmp_path) == []


def test_ignored_paths_are_skipped(tmp_path):
    """`ignore_paths` is a promise about the whole analysis. A fixtures
    directory excluded from the secret sweeps was still reported here, so the
    setting removed the noise from one section of the report and left it in
    another.

    Planted in `tests/planted/` and NOT in the `tests/fixtures/` this test
    used to use: `ignores.DEFAULT_IGNORE_DIRS` now suppresses a `fixtures`
    directory with no configuration at all, so the old path would make the
    `== []` below pass without the glob ever being read -- the vacuous
    positive this suite guards against everywhere else."""
    planted = tmp_path / "tests" / "planted"
    planted.mkdir(parents=True)
    (planted / ".env").write_text("DB_HOST=localhost\n")
    (planted / "fake.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nx\n")
    assert [f["rule"] for f in scan(tmp_path)] != []
    assert scan(tmp_path, ["tests/planted/**"]) == []


def test_the_default_noise_filter_reaches_the_hygiene_pass_too(tmp_path):
    """`tests/fixtures/id_rsa` "looks like a key file" was the example this
    module's own docstring gave for a setting one phase of three ignored. It
    now takes no setting at all."""
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / ".env").write_text("DB_HOST=localhost\n")
    (fixtures / "fake.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nx\n")
    assert scan(tmp_path) == []
    assert [f["rule"] for f in scan(tmp_path, ["!defaults"])] != []


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
