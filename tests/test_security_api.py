"""The security endpoints the dashboard's Security area calls.

Every function here is module-level and called directly, the same style as
the rest of this suite (see conftest.py) — no HTTP round trip, `cc()` (the
shell-out to the CLI) is monkeypatched with `monkeypatch.setattr` (never a
bare assignment: `srv` is a session-scoped fixture, and an assignment would
leak the fake into every test that runs after it). What matters most is what
gets refused BEFORE `cc` is ever reached: a branch name with shell
metacharacters, a leading '-', a '..' traversal or trailing newline, a bad
profile, a decision missing its reason or naming a state the ledger does not
know, a non-integer analysis id, and a missing project. Each of those is a
400 at this edge rather than a 500 built from a CLI that exited non-zero or a
traceback from int() or json.loads().

One test near the bottom (the leading-dash project invariant) deliberately
does NOT stub `cc()` — it runs the real CLI to prove argparse itself refuses
an option-shaped value, which is the whole safety net for passing `project`/
`repo`/etc. straight through as list elements rather than quoting them.
"""
import json


# --------------------------------------------------------------- report GET

def test_a_report_download_is_an_attachment(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, "# report"))
    body, headers = srv.security_report(7, "md")
    assert body == "# report"
    assert "attachment" in headers["Content-Disposition"]
    assert headers["Content-Disposition"].endswith('.md"')


def test_the_filename_carries_only_the_int_id_and_the_format(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, "{}"))
    _, headers = srv.security_report(42, "json")
    assert headers["Content-Disposition"] == \
        'attachment; filename="security-analysis-42.json"'


def test_a_failed_render_raises_instead_of_returning_broken_bytes(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "no such analysis: 7"))
    try:
        srv.security_report(7, "md")
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "no such analysis" in str(exc)


def test_a_successful_download_fires_report_exported(srv, monkeypatch):
    """Nothing asserted `report_exported`'s kind, its project source or its
    analysis id anywhere before this -- a wrong kind string, a wrong project
    source or an inverted lookup would have passed every existing suite."""
    calls = []

    def fake_cc(args, stdin=None):
        calls.append(args)
        if args[1] == "render":
            return True, "# report"
        if args[1] == "analysis":
            return True, json.dumps({"id": 7, "project": "web"})
        if args[1] == "event":
            return True, ""
        raise AssertionError(f"unexpected cc call: {args}")

    monkeypatch.setattr(srv, "cc", fake_cc)
    body, _ = srv.security_report(7, "md")
    assert body == "# report"

    event_calls = [c for c in calls if c[1] == "event"]
    assert len(event_calls) == 1
    args = event_calls[0]
    assert args[args.index("--project") + 1] == "web"
    assert args[args.index("--kind") + 1] == "report_exported"
    assert args[args.index("--related") + 1] == "7"


def test_the_project_lookup_uses_the_lightweight_analysis_verb(srv, monkeypatch):
    """The lookup exists only to read one string (`analysis.project`) and
    must go through the lightweight `analysis --id` verb, not `checklist`'s
    full diff/classify pass, to get it."""
    seen = []

    def fake_cc(args, stdin=None):
        seen.append(args)
        if args[1] == "render":
            return True, "# report"
        return True, json.dumps({"id": 7, "project": "web"})

    monkeypatch.setattr(srv, "cc", fake_cc)
    srv.security_report(7, "md")
    assert ["security", "analysis", "--id", "7"] in seen
    assert not any(c[1] == "checklist" for c in seen)


def test_a_download_with_no_resolvable_project_files_no_event(srv, monkeypatch):
    """Best-effort, and never the reason a download fails: a project the CLI
    could not name (a stray warning, a row gone between the render above and
    this lookup) must not turn a successful download into anything worse
    than a quiet skip of the audit event."""
    calls = []

    def fake_cc(args, stdin=None):
        calls.append(args)
        if args[1] == "render":
            return True, "# report"
        if args[1] == "analysis":
            return False, "no such analysis: 7"
        raise AssertionError(f"unexpected cc call: {args}")

    monkeypatch.setattr(srv, "cc", fake_cc)
    body, _ = srv.security_report(7, "md")
    assert body == "# report"
    assert not any(c[1] == "event" for c in calls)


def test_an_unknown_format_is_refused_before_it_reaches_the_cli(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_report_guard("xml")
    assert code == 400
    assert "format" in payload["error"]


def test_a_path_ish_format_is_refused_the_same_way(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_report_guard("../etc/passwd")
    assert code == 400


def test_a_valid_format_is_waved_through_with_no_error_payload(srv):
    code, payload = srv.security_report_guard("html")
    assert code == 200
    assert payload is None


# ------------------------------------------------------------- analysis ids

def test_a_non_integer_analysis_id_parses_to_none(srv):
    assert srv._analysis_id("abc") is None
    assert srv._analysis_id("") is None
    assert srv._analysis_id(None) is None
    assert srv._analysis_id("7") == 7
    assert srv._analysis_id("-3") == -3  # shape-valid; the CLI/ledger own the range check


def test_checklist_refuses_a_non_integer_analysis_before_the_cli(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_checklist("../etc/passwd")
    assert code == 400
    assert "integer" in payload["error"]


def test_checklist_passes_a_valid_int_through_to_the_cli(srv, monkeypatch):
    seen = {}

    def fake_cc(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"analysis": {"id": 7}, "findings": []})

    monkeypatch.setattr(srv, "cc", fake_cc)
    code, payload = srv.security_checklist("7")
    assert code == 200
    assert seen["args"] == ["security", "checklist", "--analysis", "7"]
    assert payload["analysis"]["id"] == 7


def test_checklist_reports_a_cli_failure_as_500_not_a_crash(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "no such analysis: 7"))
    code, payload = srv.security_checklist("7")
    assert code == 500
    assert "no such analysis" in payload["error"]


def test_checklist_is_a_500_not_an_uncaught_crash_on_rc0_chatter(srv, monkeypatch):
    """`cc()` merges stdout and stderr (see `cc`), so a CLI that exits 0 but
    printed a stray warning line alongside its JSON hands `json.loads` a
    string that is not valid JSON. Unguarded, that raised `JSONDecodeError`
    straight out of this function — a dropped connection instead of a 500."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None:
                        (True, '{"analysis": {"id": 7}, "findings": []}\n'
                               'warning: something noisy on stderr'))
    code, payload = srv.security_checklist("7")
    assert code == 500
    assert "error" in payload


# ------------------------------------------------------------------- decide

def test_a_decision_without_a_reason_is_refused(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, ""))
    code, payload = srv.security_decide({"project": "web", "fingerprint": "a" * 64,
                                         "state": "accepted", "reason": "  "})
    assert code == 400
    assert "reason" in payload["error"]


def test_a_decision_with_an_unknown_state_is_refused(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_decide({"project": "web", "fingerprint": "a" * 64,
                                         "state": "ignored", "reason": "looked at it"})
    assert code == 400
    assert "state" in payload["error"]


def test_a_decision_with_no_project_or_fingerprint_is_refused(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_decide({"project": "", "fingerprint": "a" * 64,
                                         "state": "accepted", "reason": "x"})
    assert code == 400
    code, payload = srv.security_decide({"project": "web", "fingerprint": "",
                                         "state": "accepted", "reason": "x"})
    assert code == 400


def test_decide_by_comes_from_load_user_never_the_request_body(srv, monkeypatch):
    """A body can claim to be anyone; the decided_by that lands in the ledger
    must be the signed-in operator, not whatever string the page (or a forged
    request) put in the JSON — otherwise the agent under review could sign
    its own suppression by naming itself in the body."""
    monkeypatch.setattr(srv, "load_user", lambda: {"configured": True,
                                                    "name": "Real Operator",
                                                    "email": "op@example.com",
                                                    "avatar": ""})
    seen = {}

    def fake_cc(args, stdin=None):
        seen["args"] = args
        return True, ""

    monkeypatch.setattr(srv, "cc", fake_cc)
    code, payload = srv.security_decide({"project": "web", "fingerprint": "a" * 64,
                                         "state": "accepted", "reason": "looked at it",
                                         "by": "attacker-supplied-name"})
    assert code == 200
    args = seen["args"]
    assert args[args.index("--by") + 1] == "Real Operator"


def test_decide_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "decide: bad state"))
    code, payload = srv.security_decide({"project": "web", "fingerprint": "a" * 64,
                                         "state": "accepted", "reason": "x"})
    assert code == 500


# ------------------------------------------------------------------ analyze

def test_analyze_refuses_a_branch_with_shell_metacharacters(srv):
    code, payload = srv.security_analyze({"project": "web", "repo": "web",
                                          "branch": "main; rm -rf /",
                                          "profile": "standard"})
    assert code == 400


def test_analyze_refuses_a_branch_starting_with_a_dash(srv):
    """'-x' matches BRANCH_OK's charset — '-' is an allowed character in a
    branch name — but a value starting with '-' sits in an option position
    next to plumbing, so it is refused explicitly rather than by charset
    alone."""
    code, payload = srv.security_analyze({"project": "web", "repo": "web",
                                          "branch": "-x", "profile": "standard"})
    assert code == 400


def test_analyze_refuses_a_branch_with_dot_dot(srv):
    """'..' also matches the charset ('.' is allowed) — refused by name for
    the traversal it can smuggle into a ref/path downstream."""
    code, payload = srv.security_analyze({"project": "web", "repo": "web",
                                          "branch": "release/../../etc/passwd",
                                          "profile": "standard"})
    assert code == 400


def test_branch_ok_refuses_a_trailing_newline_standalone(srv):
    """`BRANCH_OK` is `^[...]{1,255}$`, and Python's `$` matches just before a
    trailing "\\n" as well as at the true end of string — so `re.match` alone
    would accept "main\\n" as a valid branch name. `_branch_ok` must refuse it
    on its own: `security_analyze` happens to `.strip()` the branch before
    calling it, which would mask the bug at that one call site, but
    `_branch_ok` is the edge's actual gate and has to be correct by itself for
    any caller that does not strip first."""
    assert not srv._branch_ok("main\n")
    assert srv._branch_ok("main")


def test_analyze_refuses_an_unknown_profile(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_analyze({"project": "web", "repo": "web",
                                          "branch": "main", "profile": "thorough"})
    assert code == 400
    assert "profile" in payload["error"]


def test_analyze_requires_project_and_repo(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_analyze({"project": "", "repo": "web",
                                          "branch": "main"})
    assert code == 400
    code, payload = srv.security_analyze({"project": "web", "repo": "",
                                          "branch": "main"})
    assert code == 400


def test_analyze_defaults_the_profile_to_standard(srv, monkeypatch):
    seen = {}

    def fake_cc(args, stdin=None):
        seen["args"] = args
        return True, "analysis 1 — web/web @ main (abc123) — job security-web"

    monkeypatch.setattr(srv, "cc", fake_cc)
    code, payload = srv.security_analyze({"project": "web", "repo": "web", "branch": "main"})
    assert code == 200
    assert seen["args"] == ["security", "analyze", "--detach", "web", "web", "main", "standard"]


def test_analyze_passes_a_valid_branch_straight_through(srv, monkeypatch):
    seen = {}

    def fake_cc(args, stdin=None):
        seen["args"] = args
        return True, "started"

    monkeypatch.setattr(srv, "cc", fake_cc)
    code, payload = srv.security_analyze({"project": "web", "repo": "web",
                                          "branch": "release/2.1", "profile": "deep"})
    assert code == 200
    assert seen["args"] == ["security", "analyze", "--detach", "web", "web", "release/2.1", "deep"]


def test_analyze_detaches_the_run_rather_than_holding_the_request(srv, monkeypatch):
    """`cc()` gives a command 30 seconds and then SIGKILLs it, and an analysis
    is minutes of work: run inline, this route timed out, the killed shell never
    reached the close, and the analysis stayed `running` for ever — which is
    what the page reads to decide that Analyse must stay disabled for that
    project.

    And it must NOT be backgrounded wholesale (`cc(..., background=True)`):
    every refusal the CLI makes — security not enabled, no such branch, one
    already running — is a sentence this page shows, and a fire-and-forget
    Popen can only ever answer "started". `--detach` is the split that keeps
    both: the refusals and the analysis row are synchronous, only the run is
    detached.
    """
    seen = {}

    def fake_cc(args, stdin=None, background=False):
        seen["args"] = args
        seen["background"] = background
        return True, ('analysis 7 — web/web @ main (abc1234) — job security-web\n'
                      '{"analysis_id":7}')

    monkeypatch.setattr(srv, "cc", fake_cc)
    code, payload = srv.security_analyze({"project": "web", "repo": "web", "branch": "main"})
    assert code == 200
    assert "--detach" in seen["args"], "the run is held on the request thread"
    assert seen["background"] is False, \
        "the whole call was backgrounded — every refusal the CLI makes is lost"
    # The page follows the analysis by this id.
    assert '"analysis_id":7' in payload["output"]


def test_analyze_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None:
                        (False, "an analysis of 'web' is already running"))
    code, payload = srv.security_analyze({"project": "web", "repo": "web", "branch": "main"})
    assert code == 500


# ----------------------------------------------------------------- branches

def test_branches_come_from_the_checkout(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc",
                        lambda args, stdin=None: (True, "main\ndevelop\nrelease/2.1\n"))
    code, payload = srv.security_branches("web", "web")
    assert code == 200
    assert payload["branches"] == ["main", "develop", "release/2.1"]


def test_branches_reports_a_missing_checkout_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "no checkout for web/web"))
    code, payload = srv.security_branches("web", "web")
    assert code == 500
    assert "no checkout" in payload["error"]


def test_branches_is_an_empty_list_not_an_error_for_a_checkout_with_none(srv, monkeypatch):
    """A checkout that exists but carries no branches yet (a fresh `git init`
    with no commits) is `cmd_security_branches` printing nothing — `cc()`
    still reports that as ok=True with empty output (see the fix in
    bin/claude-cron, where the old `grep -v '^HEAD$'` on empty input used to
    make the whole pipeline exit 1 under `set -uo pipefail`). The route must
    answer an empty picker, not the 500 that empty output used to cause."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, ""))
    code, payload = srv.security_branches("web", "web")
    assert code == 200
    assert payload == {"branches": []}


# ---------------------------------------------------------------------- list

def test_list_passes_the_project_through_to_the_cli(srv, monkeypatch):
    seen = {}

    def fake_cc(args, stdin=None):
        seen["args"] = args
        return True, json.dumps([{"id": 1, "project": "web"}])

    monkeypatch.setattr(srv, "cc", fake_cc)
    code, payload = srv.security_list("web")
    assert code == 200
    assert seen["args"] == ["security", "list", "--project", "web"]
    assert payload == [{"id": 1, "project": "web"}]


def test_list_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "boom"))
    code, payload = srv.security_list("web")
    assert code == 500
    assert payload == {"error": "boom"}


def test_list_refuses_a_missing_project_before_the_cli(srv, monkeypatch):
    """A blank `project` used to reach the CLI as `--project ''`, which
    matches no analysis and comes back a silent `200 []` — indistinguishable
    from "this project genuinely has none". `/api/search` already 400s on a
    blank `q`; this route should refuse the same way instead of quietly
    answering an empty list for a parameter nobody supplied."""
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_list("")
    assert code == 400
    assert "project" in payload["error"]
    code, payload = srv.security_list("   ")
    assert code == 400


def test_list_is_a_500_not_an_uncaught_crash_on_rc0_chatter(srv, monkeypatch):
    """Same failure mode as checklist: `cc()` merges stdout and stderr, so a
    warning on an rc-0 run lands right next to the JSON the CLI meant to
    return, and an unguarded `json.loads` turns that into an escaped
    `JSONDecodeError` instead of a 500."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None:
                        (True, '[{"id": 1, "project": "web"}]\nwarning: noisy'))
    code, payload = srv.security_list("web")
    assert code == 500
    assert "error" in payload


# ------------------------------------------------ the leading-dash invariant

def test_a_leading_dash_project_reaches_argparse_as_a_value_not_a_flag(srv):
    """`cc()` passes `args` as a Python list straight to `subprocess.run` —
    never a shell string — which is exactly what makes a project name shaped
    like an option safe to hand through unquoted: argparse itself refuses to
    consume "-x" as `--project`'s value (it looks like another flag), rather
    than the CLI's `list` accepting it as `--project` and then some other
    flag being smuggled in, or a shell somewhere word-splitting it.

    Deliberately NOT stubbed: the whole point is what the real CLI's argparse
    does with a leading-dash value reaching it through a real argv, and a
    mocked `cc()` would never notice a refactor that broke this (e.g. one
    that switched `cc()` to build a shell string, or otherwise re-joined
    argv). `security list` needs no working ledger to prove this — argparse
    refuses the value before `cmd_list` ever opens the database."""
    code, payload = srv.security_list("-x")
    assert code == 500
    assert "expected one argument" in payload["error"]
    assert "--project" in payload["error"]


def test_the_sbom_is_a_fourth_download_and_is_named_for_its_tooling(srv, monkeypatch):
    """`.cdx.json` is the conventional CycloneDX suffix and is what the tools
    that consume one recognise; `security-analysis-7.sbom` is a file nothing
    will open."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, '{"bomFormat":"CycloneDX"}'))
    code, err = srv.security_report_guard("sbom")
    assert code == 200 and err is None
    body, headers = srv.security_report(7, "sbom")
    assert body == '{"bomFormat":"CycloneDX"}'
    assert headers["Content-Disposition"] == \
        'attachment; filename="security-analysis-7.cdx.json"'
    assert srv.REPORT_FORMATS["sbom"] == "application/json"


def test_the_sbom_download_asks_the_cli_for_that_format(srv, monkeypatch):
    seen = {}
    monkeypatch.setattr(srv, "cc",
                        lambda args, stdin=None: (seen.setdefault("args", args), (True, "{}"))[1])
    srv.security_report(3, "sbom")
    assert seen["args"] == ["security", "render", "--analysis", "3", "--format", "sbom"]


def test_every_report_format_has_a_content_type_and_a_filename(srv):
    """The route answers with REPORT_FORMATS[fmt] as the content type and
    builds the filename from REPORT_EXTENSIONS: a format added to one and
    forgotten in the other is a download with the wrong name or a KeyError
    mid-response."""
    for fmt in srv.REPORT_FORMATS:
        assert srv.REPORT_FORMATS[fmt]
        assert srv.REPORT_EXTENSIONS.get(fmt, fmt).strip()


# --------------------------------------------------------------- index GET

def test_the_index_answers_with_every_panel_the_screen_draws(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "summary": {"projects": 2, "analyses": 12, "critical": 4,
                    "high": 18, "success_rate": 0.75},
        "projects": [], "recent": [], "donut": {}, "categories": []})))
    code, payload = srv.security_index()
    assert code == 200
    assert set(payload) == {"summary", "projects", "recent", "donut", "categories"}


def test_the_index_survives_a_ledger_that_does_not_exist_yet(srv, monkeypatch):
    """Nobody has run an analysis. That is an empty screen with a sentence,
    not a 500."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "summary": {"projects": 0, "analyses": 0, "critical": 0, "high": 0,
                    "success_rate": None},
        "projects": [], "recent": [], "donut": {}, "categories": []})))
    code, payload = srv.security_index()
    assert code == 200
    assert payload["summary"]["success_rate"] is None


def test_the_index_is_a_500_when_the_cli_fails(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "boom"))
    code, payload = srv.security_index()
    assert code == 500
    assert payload == {"error": "boom"}


def test_the_index_is_a_500_on_output_that_is_not_json(srv, monkeypatch):
    """`cc()` merges stdout and stderr (see the identical guard on
    `security_list`/`security_checklist`), so a stray warning on an
    otherwise-clean run must not become an uncaught `JSONDecodeError`."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, "not json"))
    code, payload = srv.security_index()
    assert code == 500
    assert "index data was not readable" in payload["error"]


def test_the_index_asks_the_cli_for_only_the_security_enabled_projects(srv, monkeypatch, tmp_path):
    """`_security_projects()` is the one place that bridges projects.json
    (which the ledger never reads) into the CLI's `--projects` JSON. A
    project with security off, or with no `security` block at all, has
    nothing here to compute and must not be sent — the same filter the old
    per-project list applied client-side (see ui/security/vocabulary.js's
    `secEnabled`)."""
    projects_file = tmp_path / "projects.json"
    projects_file.write_text(json.dumps({"projects": [
        {"name": "web", "base": "main", "description": "d",
         "security": {"enabled": True}},
        {"name": "off", "base": "main", "security": {"enabled": False}},
        {"name": "bare"},
    ]}))
    monkeypatch.setattr(srv, "PROJECTS_FILE", projects_file)
    seen = []

    def fake_cc(args, stdin=None):
        seen.append(args)
        return True, json.dumps({"summary": {}, "projects": [], "recent": [],
                                  "donut": {}, "categories": []})
    monkeypatch.setattr(srv, "cc", fake_cc)
    code, _ = srv.security_index()
    assert code == 200
    args = seen[0]
    assert args[:2] == ["security", "index-data"]
    sent = json.loads(args[args.index("--projects") + 1])
    assert sent == [{"name": "web", "base": "main", "description": "d"}]


def test_active_runs_carries_derived_security_jobs(srv, clean_data):
    """The isolation property keeps derived jobs out of jobs.json, but their
    RUNS are as real as any other, and active_runs is the only way the page
    sees a live one. Without the union, a running analysis had no "Open the
    run" button and the dead-run warning fired against every healthy run."""
    (srv.DATA_DIR / "locks" / "security-web").mkdir(parents=True)
    srv.JOBS_FILE.write_text('{"jobs":[{"id":"real-job"}]}')
    data = srv.load_data()
    assert "security-web" in data["active_runs"]
    assert "real-job" in data["active_runs"]
