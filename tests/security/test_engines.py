import json
import os
import sys
import textwrap
from pathlib import Path

import pytest
from security import engines


# ------------------------------------------------------------ a fake engine
#
# These tests run a REAL child process rather than a stubbed
# `subprocess.run`. Every promise this module makes is a promise about what
# happens when SOMEBODY ELSE'S program misbehaves -- writes raw bytes on
# stderr, exits 3, never finishes, leaves a directory where a report should
# be -- and a stub only ever proves that the stub behaved the way the test
# author imagined the real thing does. The engine below is a small script
# placed on PATH under the name the module will look up, so `find`,
# `version_of` and `run_json` take exactly the path they take in production.

def fake_engine(tmp_path, monkeypatch, name, body="sys.exit(0)", *,
                version=b"fake 1.2.3\n", version_stderr=b"",
                version_flags=("--version", "version"), marker=None):
    """Put an executable `name` on PATH and return its path.

    `body` is Python source run for any invocation that is not one of
    `version_flags`; it can use `out`, the argument the module substituted
    `{out}` into (None if it never arrived). `version=None` makes the engine
    refuse to say what it is. `marker`, when given, is a file the script
    writes before it does anything else -- the way a test proves the engine
    was never executed at all.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    answer = ([f"    os.write(1, {version!r})", "    sys.exit(0)"]
              if version is not None else ["    sys.exit(1)"])
    lines = [f"#!{sys.executable}", "import json, os, sys"]
    if marker is not None:
        lines.append(f"open({str(marker)!r}, 'w').write('ran')")
    lines += [
        f"if sys.argv[1:2] in {[[f] for f in version_flags]!r}:",
        f"    os.write(2, {version_stderr!r})",
        *answer,
        'out = next((a for a in sys.argv[1:] if a.endswith("out.json")), None)',
        textwrap.dedent(body),
    ]
    script = bin_dir / name
    script.write_text("\n".join(lines) + "\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return script


# ------------------------------------------------------------------- find

def test_a_missing_binary_is_absent_not_an_error():
    assert engines.find("definitely-not-a-real-binary-xyz") is None


# -------------------------------------------------------------- version_of

def test_version_of_reports_the_first_line_the_engine_prints(tmp_path, monkeypatch):
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                version=b"v8.30.1\nbuilt from source\n")
    assert engines.version_of("gitleaks") == "v8.30.1"


def test_version_of_falls_back_to_the_bare_version_subcommand(tmp_path, monkeypatch):
    # Some engines spell it `engine version`, not `engine --version`. The
    # first flag failing is not an answer, it is a flag this engine does not
    # take -- so the fallback is tried before giving up.
    fake_engine(tmp_path, monkeypatch, "trivy", body="sys.exit(1)",
                version=b"Version: 0.60.0\n", version_flags=("version",))
    assert engines.version_of("trivy") == "Version: 0.60.0"


def test_version_of_is_none_when_the_engine_will_not_say_what_it_is(
        tmp_path, monkeypatch):
    fake_engine(tmp_path, monkeypatch, "gitleaks", version=None)
    assert engines.version_of("gitleaks") is None


def test_version_of_is_none_for_a_binary_that_is_not_installed():
    assert engines.version_of("definitely-not-a-real-binary-xyz") is None


def test_version_of_survives_raw_bytes_in_the_version_banner(
        tmp_path, monkeypatch):
    # An engine is free to put bytes that are not UTF-8 on its stderr, and
    # `text=True` used to decode them STRICTLY: the UnicodeDecodeError is a
    # ValueError, so it slipped past `except (OSError, SubprocessError)` and
    # out of a function documented to answer None. Nothing is lost by
    # decoding loosely -- stderr is never quoted back.
    fake_engine(tmp_path, monkeypatch, "gitleaks", version=b"v8.30.1\n",
                version_stderr=b"warn: read /x \xff\xfe\n")
    assert engines.version_of("gitleaks") == "v8.30.1"


# ------------------------------------------------------------------- purge

def test_purge_strips_the_forbidden_fields_from_gitleaks():
    raw = [{"RuleID": "aws-access-token", "File": "config/prod.env",
            "StartLine": 3, "Entropy": 4.5,
            "Match": "AKIA_THE_ACTUAL_VALUE", "Secret": "AKIA_THE_ACTUAL_VALUE"}]
    clean = engines.purge("gitleaks", raw)
    assert "Match" not in clean[0]
    assert "Secret" not in clean[0]
    assert clean[0]["RuleID"] == "aws-access-token"
    assert clean[0]["StartLine"] == 3


def test_purge_strips_the_code_line_from_semgrep():
    # Semgrep returns the matched source line. A finding ON a credential
    # would carry that credential in `extra.lines`.
    raw = {"results": [{"check_id": "x", "path": "a.py",
                        "start": {"line": 1}, "end": {"line": 1},
                        "extra": {"severity": "WARNING", "lines": "KEY = 'the-value'",
                                  "metadata": {"cwe": ["CWE-327: ..."]}}}]}
    clean = engines.purge("semgrep", raw)
    assert "lines" not in clean["results"][0]["extra"]
    assert clean["results"][0]["extra"]["metadata"]["cwe"] == ["CWE-327: ..."]


def test_purge_strips_the_metavariable_binding_from_semgrep():
    # `extra.lines` is not the only place the source arrives. Every
    # metavariable a rule bound carries what it matched, and for a rule that
    # fires ON a hardcoded credential that binding IS the credential.
    secret = "sk-live-THE-ACTUAL-VALUE"
    raw = {"results": [{"check_id": "hardcoded-key", "path": "a.py",
                        "extra": {"metavars": {
                            "$KEY": {"start": {"line": 1}, "end": {"line": 1},
                                     "abstract_content": secret,
                                     "propagated_value": {
                                         "svalue_abstract_content": secret,
                                         "svalue_start": {"line": 1}}}}}}]}
    dumped = json.dumps(engines.purge("semgrep", raw))
    assert secret not in dumped
    assert "hardcoded-key" in dumped


def test_purge_strips_the_autofix_semgrep_offers():
    # An autofix quotes the offending source back in order to rewrite it, so
    # the fix for "do not hardcode this" contains the hardcoded thing.
    secret = "ghp_THE_ACTUAL_VALUE"
    raw = {"results": [{"check_id": "x", "path": "a.py",
                        "extra": {"fix": f"os.environ['T']  # was {secret}",
                                  "rendered_fix": f"TOKEN = {secret!r}",
                                  "severity": "ERROR"}}]}
    clean = engines.purge("semgrep", raw)
    assert secret not in json.dumps(clean)
    assert clean["results"][0]["extra"]["severity"] == "ERROR"


def test_purge_strips_the_dataflow_trace_from_semgrep():
    # A taint finding ships a snippet for every step of the path it walked,
    # and step one is usually the literal the value came from.
    secret = "AKIA_TAINT_SOURCE_VALUE"
    raw = {"results": [{"check_id": "taint", "path": "a.py",
                        "extra": {"dataflow_trace": {
                            "taint_source": ["CliLoc", {"path": "a.py"},
                                             f"KEY = '{secret}'"]}}}]}
    assert secret not in json.dumps(engines.purge("semgrep", raw))


def test_purge_strips_the_file_content_semgrep_puts_in_an_error():
    # MEASURED on this repository, not anticipated: semgrep 1.175.0 reports a
    # file it cannot parse as an `errors[]` entry whose `message` QUOTES THE
    # FILE -- ~2kB of `bin/claude-cron` (taken before the rename) in the capture this project's fixture
    # was taken from. It is the very hazard `run_json` already refuses to
    # quote stderr for, arriving through the report instead.
    source = "PASSWORD = 'the-actual-value-in-the-file'"
    raw = {"results": [], "errors": [
        {"code": 3, "level": "warn", "type": "Syntax error",
         "path": "app.py",
         "message": f"Syntax error at line app.py:1:\n `{source}\n...`"}]}
    clean = engines.purge("semgrep", raw)
    assert source not in json.dumps(clean)
    assert clean["errors"][0]["path"] == "app.py"


def test_purge_strips_the_metavariable_semgrep_interpolated_into_a_message():
    # `extra.message` is the RULE's own sentence -- until the rule writes `$X`
    # in it, which semgrep substitutes with what the metavariable bound to. For
    # a rule that fires ON a hardcoded credential, that is the credential, in
    # the one field that reads like harmless engine prose.
    secret = "ghp_THE_ACTUAL_VALUE"
    raw = {"results": [{"check_id": "hardcoded-token", "path": "a.py",
                        "extra": {"severity": "ERROR",
                                  "message": f"Hardcoded token {secret} found"}}]}
    clean = engines.purge("semgrep", raw)
    assert secret not in json.dumps(clean)
    assert clean["results"][0]["extra"]["severity"] == "ERROR"


def test_purge_strips_the_source_lines_trivy_attaches_to_a_secret():
    # Trivy does not stop at `Match`: it attaches the surrounding source in
    # `Code.Lines[]`, as plain `Content` and again ANSI-coloured in
    # `Highlighted`. Both are the file, verbatim.
    secret = "AKIA_TRIVY_ACTUAL_VALUE"
    raw = {"Results": [{"Target": ".env", "Class": "secret", "Secrets": [
        {"RuleID": "aws-access-key-id", "Severity": "CRITICAL",
         "StartLine": 2, "Match": f"KEY={secret}",
         "Code": {"Lines": [{"Number": 2, "Content": f"KEY={secret}",
                             "Highlighted": f"\x1b[38m KEY={secret}",
                             "IsCause": True}]}}]}]}
    clean = engines.purge("trivy", raw)
    assert secret not in json.dumps(clean)
    assert clean["Results"][0]["Secrets"][0]["RuleID"] == "aws-access-key-id"
    assert clean["Results"][0]["Secrets"][0]["Code"]["Lines"][0]["Number"] == 2


def test_purge_strips_the_source_lines_from_a_trivy_misconfiguration():
    # The same `Code.Lines[]` block hangs off a misconfiguration, one level
    # deeper under `CauseMetadata` -- which is exactly why the table is
    # written as field names and not as paths.
    secret = "password_in_the_compose_file"
    raw = {"Results": [{"Target": "docker-compose.yml", "Misconfigurations": [
        {"ID": "DS002", "Severity": "HIGH", "CauseMetadata": {
            "StartLine": 7, "Code": {"Lines": [
                {"Number": 7, "Content": f"      PASS: {secret}",
                 "Highlighted": f"      PASS: {secret}"}]}}}]}]}
    clean = engines.purge("trivy", raw)
    assert secret not in json.dumps(clean)
    assert clean["Results"][0]["Misconfigurations"][0]["ID"] == "DS002"


def test_purge_refuses_an_engine_it_does_not_know():
    # This used to return `data` untouched, and that made every typo silent.
    # The Gitleaks adapter runs the engine TWICE, for the tree and for the
    # history; one misspelled name and one of the two sweeps purged nothing
    # while reporting success. "I have never heard of this engine" cannot
    # mean "then keep everything it found".
    raw = [{"Match": "AKIA_THE_ACTUAL_VALUE", "Secret": "AKIA_THE_ACTUAL_VALUE"}]
    for name in ("gitleaks-git", "Gitleaks", "nosuch", ""):
        with pytest.raises(engines.UnknownEngine):
            engines.purge(name, raw)


def test_purge_accepts_an_engine_registered_as_carrying_nothing(monkeypatch):
    # The opt-out for an engine that really does return nothing it matched
    # is an ENTRY, not an omission -- so "nothing to strip" is a decision
    # somebody recorded and a reviewer can see.
    monkeypatch.setitem(engines.PURGE, "harmless", ())
    assert engines.purge("harmless", {"a": 1}) == {"a": 1}


def test_the_purge_table_holds_field_names_not_paths():
    # `_strip` matches bare dict keys at any depth. An entry written as a
    # path -- "extra.lines", "Code.Lines[].Content" -- would match nothing,
    # and would look like protection while providing none.
    for name, fields in engines.PURGE.items():
        assert isinstance(fields, tuple), name
        for field in fields:
            assert field and not set(field) & set(".[]*$"), (name, field)


def test_purge_survives_a_shape_it_did_not_expect():
    # A version bump can change the shape. Purge must not crash the whole
    # analysis over it -- but it must also not pass a value through.
    assert engines.purge("gitleaks", {"unexpected": "object"}) is not None
    assert engines.purge("gitleaks", []) == []


def test_purge_reaches_a_forbidden_field_nested_deeper_than_the_fixtures_go():
    # The fixtures above only exercise the depths the real engines happen to
    # use today: a flat list of dicts for Gitleaks, and a fixed multi-level
    # path for Semgrep. A purge that walks only those known paths would pass
    # every test above while still leaking a credential buried somewhere a
    # version bump moved it to. Build a shape none of the fixtures cover --
    # a list inside a dict inside a list -- and prove the value is gone
    # from the *entire* serialized result, not just absent from the one key
    # we happen to check.
    secret = "AKIA_DEEPLY_NESTED_VALUE"
    raw = [                                          # list
        {                                            # dict
            "RuleID": "aws-access-token",
            "Findings": [                            # list, inside the dict above
                {"Match": secret, "Secret": secret, "Context": "kept"},
            ],
        }
    ]
    clean = engines.purge("gitleaks", raw)
    dumped = json.dumps(clean)
    assert secret not in dumped
    # The purge only drops the named fields -- it must not also destroy
    # unrelated data sitting beside them at the same depth.
    assert clean[0]["Findings"][0]["Context"] == "kept"
    assert "Match" not in clean[0]["Findings"][0]
    assert "Secret" not in clean[0]["Findings"][0]


# ---------------------------------------------------------------- run_json
#
# Seven ways out, and every one of them returns (None, note) or (data, "").
# `run_json` is the one door: a door that raises is a dead analysis, so each
# outcome gets a test rather than a comment saying it was thought about.

def test_run_json_reports_a_missing_binary_as_a_note_not_an_exception(tmp_path):
    data, note = engines.run_json("definitely-not-a-real-binary-xyz", [], tmp_path)
    assert data is None
    assert "definitely-not-a-real-binary-xyz" in note


def test_run_json_refuses_an_engine_that_is_not_in_the_purge_table(
        tmp_path, monkeypatch):
    # Installed, willing to answer, and REFUSED -- before it is executed at
    # all, because an engine whose output this module cannot strip must not
    # produce findings. The marker proves the process never started: not
    # even the version probe ran.
    marker = tmp_path / "it-ran"
    fake_engine(tmp_path, monkeypatch, "gitleaks-git", marker=marker,
                body='open(out, "w").write("[]")')
    data, note = engines.run_json("gitleaks-git", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "purge table" in note
    assert not marker.exists()


def test_run_json_skips_an_engine_that_will_not_report_a_version(
        tmp_path, monkeypatch):
    # A parser written against a format that has since changed is worse than
    # a phase that declared it did not run.
    fake_engine(tmp_path, monkeypatch, "gitleaks", version=None,
                body='open(out, "w").write("[]")')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "did not report a version" in note


def test_run_json_stops_an_engine_that_never_finishes(tmp_path, monkeypatch):
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body="import time\ntime.sleep(30)")
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path,
                                  timeout=1)
    assert data is None
    assert "did not finish within 1s" in note


def test_run_json_reports_an_engine_that_exited_without_writing(
        tmp_path, monkeypatch):
    fake_engine(tmp_path, monkeypatch, "gitleaks", body="sys.exit(3)")
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "exited 3" in note


def test_run_json_reports_a_report_that_is_not_json(tmp_path, monkeypatch):
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='open(out, "w").write("panic: goroutine 1 [running]")')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "cannot read" in note


def test_run_json_reports_a_report_it_cannot_read(tmp_path, monkeypatch):
    # The file is there and reading it fails anyway -- here because the
    # engine left a directory at the path it was given.
    fake_engine(tmp_path, monkeypatch, "gitleaks", body="os.mkdir(out)")
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "cannot read" in note


def test_run_json_reports_a_report_nested_deeper_than_the_parser_goes(
        tmp_path, monkeypatch):
    # `json.loads` raises RecursionError, which is a RuntimeError and NOT a
    # ValueError -- so this used to escape the handler as an exception. It
    # is the same "wrote something that is not JSON" outcome as the test
    # above, and it must read the same way to the caller.
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='open(out, "w").write("[" * 200000 + "]" * 200000)')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "cannot read" in note


def test_run_json_drops_a_report_that_parses_but_is_too_deep_to_purge(
        tmp_path, monkeypatch):
    # The parser is not the only thing that recurses, and it is the more
    # tolerant of the two: `json.loads` descends in C for thousands of
    # levels while `_strip` is a Python walk that stops around 995. So a
    # report can parse cleanly and still blow up on the way through the
    # purge -- one line further on, outside every handler. Dropped, because
    # the alternative is returning data that was never stripped.
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='open(out, "w").write("[" * 3000 + "]" * 3000)')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "too deeply nested to purge" in note


def test_run_json_refuses_a_report_bigger_than_the_ceiling(
        tmp_path, monkeypatch):
    """A report is read WHOLE, parsed into an object graph and then walked
    into a second one, so its peak cost is a multiple of the file -- and
    nothing bounded it. The failure that produces is a `MemoryError`, which is
    neither a ValueError, an OSError nor a RecursionError: the one exception
    the handler below the read does not name, escaping a function documented
    to return `(None, note)` for every failure.

    Semgrep's `--time` is the growth this was measured on: one timing per
    (file, rule) pair, 651 KB for this repository's 89 files, and it grows
    with both."""
    monkeypatch.setattr(engines, "MAX_REPORT_BYTES", 2048)
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='open(out, "w").write("[" + "0," * 4096 + "0]")')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "ceiling" in note, note
    # The same shape every other failure here returns, and a stated number:
    # a ceiling nobody can see is a truncation nobody can audit.
    assert "gitleaks" in note


def test_a_report_under_the_ceiling_is_read_normally(tmp_path, monkeypatch):
    """The guard is a ceiling, not a budget: the size it refuses is measured
    before the read, and everything below it goes through untouched."""
    monkeypatch.setattr(engines, "MAX_REPORT_BYTES", 2048)
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='json.dump([{"RuleID": "aws-access-token"}], open(out, "w"))')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert note == ""
    assert data == [{"RuleID": "aws-access-token"}]


def test_the_ceiling_is_checked_before_the_report_is_read(tmp_path, monkeypatch):
    """BEFORE `read_text`, which is the whole point of the guard: once the
    file is in memory the cost is already paid. Proven by making the read
    itself explode -- if the size check did not come first, this raises."""
    monkeypatch.setattr(engines, "MAX_REPORT_BYTES", 2048)

    def boom(*a, **k):
        raise AssertionError("the report was read before its size was checked")

    monkeypatch.setattr(Path, "read_text", boom)
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='open(out, "w").write(" " * 4096)')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None and "ceiling" in note


def test_run_json_survives_an_engine_that_writes_raw_bytes_to_stderr(
        tmp_path, monkeypatch):
    # The scenario the module's own comment anticipates: "an engine that
    # fails while reading a file can put that file's bytes in its error
    # message". Strict decoding turned that into a UnicodeDecodeError -- a
    # ValueError, uncaught here -- so a repository holding a binary blob or
    # a filename that is not valid UTF-8 killed the whole analysis.
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='os.write(2, b"cannot read \\xff\\xfe.env\\n")\nsys.exit(1)')
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert "exited 1" in note


def test_run_json_returns_the_parsed_report_and_an_empty_note(
        tmp_path, monkeypatch):
    fake_engine(tmp_path, monkeypatch, "gitleaks", body=(
        'json.dump([{"RuleID": "aws-access-token", "StartLine": 3}], '
        'open(out, "w"))'))
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert note == ""
    assert data == [{"RuleID": "aws-access-token", "StartLine": 3}]


def test_run_json_purges_what_the_engine_returned(tmp_path, monkeypatch):
    # The happy path is the one that carries data, so it is the one where a
    # missing purge would matter. Nothing between the parse and the return
    # may hand a credential back.
    secret = "AKIA_END_TO_END_VALUE"
    fake_engine(tmp_path, monkeypatch, "gitleaks", body=(
        'json.dump([{"RuleID": "aws-access-token", "Match": "%s", '
        '"Secret": "%s"}], open(out, "w"))' % (secret, secret)))
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert note == ""
    assert secret not in json.dumps(data)
    assert data[0]["RuleID"] == "aws-access-token"


def test_the_out_placeholder_reaches_the_engine_as_a_real_path(
        tmp_path, monkeypatch):
    # Untested, `{out}` is a string literal that has to match in two places
    # at once. A typo on either side -- `{output}` in the substitution, say
    # -- leaves every engine writing to a path nobody reads, and every
    # phase reporting "wrote no report" forever. The engine reports the
    # argv it was actually handed.
    fake_engine(tmp_path, monkeypatch, "gitleaks",
                body='json.dump({"argv": sys.argv[1:]}, open(out, "w"))')
    data, note = engines.run_json("gitleaks", ["scan", "--out", "{out}"],
                                  tmp_path)
    assert note == ""
    argv = data["argv"]
    assert argv[0] == "scan"
    assert "{out}" not in argv
    assert Path(argv[2]).is_absolute() and argv[2].endswith("out.json")


def test_run_json_never_quotes_the_engines_stderr_back(tmp_path, monkeypatch):
    # The reason stderr is dropped rather than reported: an engine's error
    # message can contain the thing it was reading. Whatever it screams
    # must reach neither the note nor the returned data -- and this holds
    # whether the run failed or succeeded.
    secret = "AKIA_SCREAMED_ON_STDERR"
    fake_engine(tmp_path, monkeypatch, "gitleaks", body=(
        'os.write(2, b"failed on %s\\n")\nsys.exit(3)' % secret))
    fake_engine(tmp_path, monkeypatch, "trivy", body=(
        'os.write(2, b"warning: %s\\n")\n'
        'json.dump({"Results": []}, open(out, "w"))' % secret))

    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert data is None
    assert secret not in note

    data, note = engines.run_json("trivy", ["--out", "{out}"], tmp_path)
    assert note == ""
    assert secret not in json.dumps(data) and secret not in note


def test_the_temporary_directory_does_not_survive_the_call(
        tmp_path, monkeypatch):
    # The other half of "output goes to a file, never to a pipe we print":
    # the file has to stop existing. A report left behind in /tmp is a
    # credential sitting on disk under whatever umask the machine has, for
    # as long as the machine keeps it.
    fake_engine(tmp_path, monkeypatch, "gitleaks", body=(
        'json.dump({"tmpdir": os.path.dirname(out), "report": out}, '
        'open(out, "w"))'))
    data, note = engines.run_json("gitleaks", ["--out", "{out}"], tmp_path)
    assert note == ""
    assert not Path(data["report"]).exists()
    assert not Path(data["tmpdir"]).exists()
