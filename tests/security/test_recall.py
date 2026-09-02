from security import secrets, ignores


def test_agent_workspaces_are_never_scanned(tmp_path):
    # .superpowers/ is where this repository's own agents write review diffs
    # and reports; data/logs/ is where run transcripts land. Both are
    # git-ignored, both routinely contain credential-shaped text (a captured
    # AKIA... in a review diff, a planted key in a transcript), and neither is
    # the project. Measured on Minerva: 22 generic_secret hits from
    # .superpowers/ alone, none of them a leak.
    for d in (".superpowers/sdd", "data/logs/security-x", "src"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "f.txt").write_text('password = "Zq9tRw2mXk7pLn4vBs8yHd3fGj6c"\n')
    findings, _, _ = secrets.scan_tree(tmp_path, ())
    files = {o["file"] for f in findings for o in f["occurrences"]}
    assert files == {"src/f.txt"}, files
