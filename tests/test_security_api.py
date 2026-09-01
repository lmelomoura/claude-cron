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

Two tests deliberately do NOT stub `cc()`: the leading-dash project
invariant near the bottom of this file, which runs the real CLI to prove
argparse itself refuses an option-shaped value; and
`test_activity_all_time_reaches_the_real_route_past_the_thirty_day_default`
in the activity section, which drives a real subprocess against a real
ledger to prove the "All time" fix at the layer the bug actually lived in --
one a mocked `cc()` cannot see, because a mock has no timestamps of its own
to get wrong.
"""
import json
import os
import sqlite3
import time
from pathlib import Path


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


def test_a_decision_with_a_malformed_fingerprint_is_refused(srv, monkeypatch):
    """Final whole-branch review, IMPORTANT 2. The route checked non-empty
    and nothing else, so a fingerprint of the agent's own invention ("aws-key
    in prod.env") wrote a decision row AND a `decision_made` event -- the
    Activity screen telling the operator the risk had been accepted while the
    finding stayed open on every other screen, because no finding can ever
    carry that identity. The shape `report-finding` already enforces
    (bin/security/cli.py's FINGERPRINT_RE) is enforced here too; the CLI
    refuses it as well, because neither door is the only one."""
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    for bad in ("aws-key in prod.env", "A" * 64, "a" * 63, "a" * 65, "a1b2"):
        code, payload = srv.security_decide(
            {"project": "web", "fingerprint": bad,
             "state": "accepted", "reason": "risk accepted for Q3"})
        assert code == 400, f"{bad!r} was accepted"
        assert "fingerprint" in payload["error"]


def test_a_decision_with_a_real_fingerprint_still_reaches_the_cli(srv, monkeypatch):
    """Containment probe for the shape check above."""
    seen = {}
    monkeypatch.setattr(srv, "cc",
                        lambda args, stdin=None: (seen.setdefault("args", args), (True, ""))[1])
    code, _payload = srv.security_decide({"project": "web", "fingerprint": "0f" * 32,
                                          "state": "accepted", "reason": "x"})
    assert code == 200
    assert seen["args"][seen["args"].index("--fingerprint") + 1] == "0f" * 32


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


def test_the_index_project_row_carries_trend_untouched(srv, monkeypatch):
    """`security_index` is a pure pass-through of whatever the CLI's
    `index-data` reports (see `_json_or_500`, and the structural test right
    below this one) -- pinned here so a project row's `trend` series (Task
    2 of Phase 4: `queries.trend_series`, served through `project_rows`)
    survives that relay exactly as the CLI produced it, a plain list of
    ints, rather than being dropped or reshaped by some future edit to this
    route. The empty list for a never-analysed project must arrive as `[]`,
    not a missing key -- the same "never null, never absent" the row's own
    `posture`/`branch` fields already guarantee."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "summary": {}, "recent": [], "donut": {}, "categories": [],
        "projects": [{"name": "web", "trend": [3, 1, 2]},
                    {"name": "never-analysed", "trend": []}]})))
    code, payload = srv.security_index()
    assert code == 200
    assert payload["projects"][0]["trend"] == [3, 1, 2]
    assert payload["projects"][1]["trend"] == [], \
        "a project with nothing to show must carry an empty list, not a missing key"


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
    otherwise-clean run must not become an uncaught `JSONDecodeError`.
    `security_index` shares `_json_or_500` with those two now instead of
    carrying its own copy of the same try/except (see its own docstring)."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, "not json"))
    code, payload = srv.security_index()
    assert code == 500
    assert "not valid JSON" in payload["error"]


def test_the_index_uses_the_shared_json_or_500_helper_not_a_second_copy(srv):
    """`security_list` and `security_checklist` already share `_json_or_500`
    for exactly this (a non-zero exit, or rc-0 output that is not valid
    JSON). `security_index` used to re-derive the identical try/except by
    hand; a structural check, not just the two behavioural tests above, so a
    future edit cannot quietly reintroduce a second copy that then drifts
    from the shared one."""
    import inspect
    src = inspect.getsource(srv.security_index)
    assert "_json_or_500(" in src, "security_index must call the shared helper"
    assert "json.loads(" not in src, "security_index still parses the CLI's JSON itself"


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


def test_the_index_days_defaults_to_30_and_passes_an_explicit_zero_through(srv, monkeypatch):
    """`days` (the Findings-overview card's own period) follows the same
    absent-vs-explicit contract `security_activity`'s own `since` already
    does: ABSENT must reach the CLI as 30 (`SECURITY_INDEX_DEFAULT_WINDOW_
    DAYS`), not `queries.severity_totals`'s own all-time default -- and an
    EXPLICIT `0` ("All time", the picker's own vocabulary) must reach it as
    `0`, not be collapsed into the same 30 an absent value gets."""
    seen = []

    def fake_cc(args, stdin=None):
        seen.append(args)
        return True, json.dumps({"summary": {}, "projects": [], "recent": [],
                                  "donut": {}, "categories": []})
    monkeypatch.setattr(srv, "cc", fake_cc)

    code, _ = srv.security_index()
    assert code == 200
    args = seen[0]
    assert args[args.index("--days") + 1] == "30", \
        "an absent days must reach the CLI as the 30-day default, not all-time"

    code, _ = srv.security_index({"days": ["0"]})
    assert code == 200
    args = seen[1]
    assert args[args.index("--days") + 1] == "0", \
        "an explicit 0 ('All time') must not be collapsed into the 30-day default"

    code, _ = srv.security_index({"days": ["7"]})
    assert code == 200
    assert seen[2][seen[2].index("--days") + 1] == "7"


def test_the_index_days_refuses_a_value_that_is_not_an_integer(srv):
    code, payload = srv.security_index({"days": ["soon"]})
    assert code == 400
    assert "days" in payload["error"]


def test_the_index_recent_page_defaults_to_1_and_forwards_an_explicit_page(srv, monkeypatch):
    """`recent_page` pages `queries.recent_analyses` server-side (see its own
    docstring) -- absent or invalid reads as page 1, the same clamp-not-
    reject treatment `security_activity` gives its own `page`."""
    seen = []

    def fake_cc(args, stdin=None):
        seen.append(args)
        return True, json.dumps({"summary": {}, "projects": [], "recent": [],
                                  "donut": {}, "categories": []})
    monkeypatch.setattr(srv, "cc", fake_cc)

    code, _ = srv.security_index()
    assert code == 200
    assert seen[0][seen[0].index("--recent-page") + 1] == "1"

    code, _ = srv.security_index({"recent_page": ["3"]})
    assert code == 200
    assert seen[1][seen[1].index("--recent-page") + 1] == "3"

    code, _ = srv.security_index({"recent_page": ["0"]})
    assert code == 200
    assert seen[2][seen[2].index("--recent-page") + 1] == "1", \
        "page 0 (or anything below 1) must clamp up to page 1, not pass through"


def test_the_project_screen_refuses_an_unknown_project(srv):
    code, payload = srv.security_project("")
    assert code == 400
    assert "project" in payload["error"]


def test_the_project_screen_carries_its_header_and_both_tabs(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "project": "web",
        "header": {"profile": "deep", "branch": "develop",
                   "lines_of_code": 1842331, "last_analysis": 1787290000},
        "tabs": {"overview": {}, "runs": []},
        "sidebar": {"donut": {}, "categories": [], "activity": []}})))
    code, payload = srv.security_project("web")
    assert code == 200
    assert payload["header"]["lines_of_code"] == 1842331
    assert "runs" in payload["tabs"]


def test_the_project_payload_carries_branches_and_reports(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "project": "web", "header": {},
        "tabs": {"overview": {}, "runs": [],
                 "branches": [{"branch": "main", "open": {"critical": 1},
                               "last_analysis": 1787290000, "analyses": 3}],
                 "reports": [{"analysis_id": 7, "branch": "main",
                              "started": 1787290000, "state": "done"}]},
        "sidebar": {}})))
    code, payload = srv.security_project("web")
    assert payload["tabs"]["branches"][0]["branch"] == "main"
    assert payload["tabs"]["reports"][0]["analysis_id"] == 7


def test_the_project_screen_passes_projects_json_through_to_the_cli(srv, monkeypatch, tmp_path):
    """`_project_meta` is the one place that bridges projects.json (which the
    ledger never reads) into the CLI's `--base`/`--default-profile` flags --
    the same bridge `_security_projects()` already is for the index screen."""
    projects_file = tmp_path / "projects.json"
    projects_file.write_text(json.dumps({"projects": [
        {"name": "web", "base": "develop",
         "security": {"enabled": True, "default_profile": "deep"}}]}))
    monkeypatch.setattr(srv, "PROJECTS_FILE", projects_file)
    seen = []

    def fake_cc(args, stdin=None):
        seen.append(args)
        return True, json.dumps({"project": "web", "header": {}, "tabs": {}, "sidebar": {}})
    monkeypatch.setattr(srv, "cc", fake_cc)
    code, _ = srv.security_project("web")
    assert code == 200
    args = seen[0]
    assert args[:2] == ["security", "project-data"]
    assert args[args.index("--project") + 1] == "web"
    assert args[args.index("--base") + 1] == "develop"
    assert args[args.index("--default-profile") + 1] == "deep"


def test_the_project_screen_defaults_to_blank_meta_for_a_project_projects_json_does_not_have(
        srv, monkeypatch, tmp_path):
    """A name projects.json does not carry (renamed away, or never
    configured) must not 500 -- the CLI already falls back to its own
    defaults for an empty `--base`/`--default-profile`."""
    projects_file = tmp_path / "projects.json"
    projects_file.write_text(json.dumps({"projects": []}))
    monkeypatch.setattr(srv, "PROJECTS_FILE", projects_file)
    seen = []

    def fake_cc(args, stdin=None):
        seen.append(args)
        return True, json.dumps({"project": "gone", "header": {}, "tabs": {}, "sidebar": {}})
    monkeypatch.setattr(srv, "cc", fake_cc)
    code, _ = srv.security_project("gone")
    assert code == 200
    args = seen[0]
    assert args[args.index("--base") + 1] == ""
    assert args[args.index("--default-profile") + 1] == ""


def test_the_project_screen_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "boom"))
    code, payload = srv.security_project("web")
    assert code == 500
    assert "boom" in payload["error"]


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


# ------------------------------------------------------------- findings GET
#
# `security_findings` validates BEFORE it shells out -- sort/direction/
# severity/state/category are refused at this edge exactly like `security_
# decide`'s reason/state and `security_analyze`'s branch/profile already are,
# so a bad value reaching the page is a 400 with a sentence, never a 500 built
# from a CLI that exited non-zero (or, for a sort column, a raw SQL fragment
# that never even reached the query -- see queries.finding_rows's own
# docstring on why that column specifically cannot be a parameter).
#
# `params` mirrors what `parse_qs()` on a real query string hands the route:
# most values arrive as a list (a repeated query parameter, or this page's own
# comma-joined checkbox filters split apart below), but several tests below
# pass a bare string for a single-value field -- both shapes must work, since
# a real GET and a simplified test call must behave identically.

def test_the_findings_route_refuses_an_unknown_sort_at_the_edge(srv):
    """The CLI refuses it too. Refusing here as well means the page gets a 400
    with a sentence instead of a 500 carrying a stack trace."""
    code, _ = srv.security_findings({"project": "web", "sort": "; DROP TABLE"})
    assert code == 400


def test_the_findings_route_refuses_an_unknown_direction(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "dir": "sideways"})
    assert code == 400
    assert "dir" in payload["error"]


def test_the_findings_route_refuses_a_blank_project(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "  "})
    assert code == 400
    assert "project" in payload["error"]


def test_the_findings_route_refuses_an_unknown_severity(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "severity": "extreme"})
    assert code == 400
    assert "severity" in payload["error"]


def test_the_findings_route_refuses_an_unknown_state(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "state": "ignored"})
    assert code == 400
    assert "state" in payload["error"]


def test_the_findings_route_refuses_an_unknown_category(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "category": "network"})
    assert code == 400
    assert "category" in payload["error"]


def test_the_findings_route_accepts_the_iac_category(srv, monkeypatch):
    """`FINDING_CATEGORIES` is this file's own duplicate of `security.diff.
    DETERMINISTIC_CATEGORIES + ("sast",)` (see that tuple's own comment) --
    a category the CLI's closed set grows must grow here too, or the
    findings-screen filter that already offers it 400s the moment somebody
    picks it."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    code, _ = srv.security_findings({"project": "web", "category": "iac"})
    assert code == 200
    assert seen["args"][seen["args"].index("--category") + 1] == "iac"


def test_the_findings_route_refuses_a_non_integer_analysis_id(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "analysis": "seven"})
    assert code == 400
    assert "analysis" in payload["error"]


def test_the_findings_route_caps_page_size(srv, monkeypatch):
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 1, "per_page": 100})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_findings({"project": "web", "per_page": "99999"})
    assert "99999" not in seen["args"]
    assert seen["args"][seen["args"].index("--per-page") + 1] == "100"


def test_the_findings_route_treats_page_zero_as_page_one(srv, monkeypatch):
    """Clamped, not refused -- the same treatment `queries.finding_rows`
    itself gives an out-of-range page (see its own docstring): a page number
    is a request for a slice, and 0/negative slides to the first one rather
    than failing a query that a non-numeric value still refuses."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_findings({"project": "web", "page": "0"})
    assert seen["args"][seen["args"].index("--page") + 1] == "1"


def test_the_findings_route_refuses_a_non_integer_page(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "page": "abc"})
    assert code == 400
    assert "page" in payload["error"]


def test_the_findings_route_passes_every_filter_through_as_repeated_flags(srv, monkeypatch):
    """Comma-joined checkbox values (the shape this page's own filter bar
    sends) are split into repeated flags -- `queries.finding_rows`'s own
    `filters` dict takes a LIST per key, and a CLI flag collected with
    `action="append"` is how that list crosses the process boundary."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 2, "per_page": 10})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_findings({
        "project": "web", "sort": "title", "dir": "asc", "page": "2", "per_page": "10",
        "severity": "critical,high", "state": "open", "category": "sast",
        "branch": "release/2.1", "path": "src/auth", "q": "token",
        "analysis": "3,4", "show_resolved": "1"})
    args = seen["args"]
    assert args[:2] == ["security", "findings-page"]
    assert args[args.index("--project") + 1] == "web"
    assert args[args.index("--sort") + 1] == "title"
    assert args[args.index("--dir") + 1] == "asc"
    assert args[args.index("--page") + 1] == "2"
    assert args[args.index("--per-page") + 1] == "10"
    assert args.count("--severity") == 2
    assert "critical" in args and "high" in args
    assert args[args.index("--state") + 1] == "open"
    assert args[args.index("--category") + 1] == "sast"
    assert args[args.index("--branch") + 1] == "release/2.1"
    assert args[args.index("--path") + 1] == "src/auth"
    assert args[args.index("--q") + 1] == "token"
    assert args.count("--analysis") == 2
    assert "3" in args and "4" in args
    assert "--show-resolved" in args


def test_the_findings_route_accepts_repeated_query_values_the_same_way(srv, monkeypatch):
    """The shape a real `?severity=critical&severity=high` produces through
    `parse_qs()` -- a list, not a comma-joined string -- must work exactly
    like the comma-joined form the test above drives."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_findings({"project": ["web"], "severity": ["critical", "high"]})
    args = seen["args"]
    assert args.count("--severity") == 2
    assert "critical" in args and "high" in args


def test_the_findings_route_refuses_a_fingerprint_that_is_not_hex(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_findings({"project": "web", "fingerprint": "not-hex!"})
    assert code == 400
    assert "fingerprint" in payload["error"]


def test_the_findings_route_passes_a_fingerprint_prefix_through(srv, monkeypatch):
    """The Activity screen's own deep link (Task 12): a fingerprint prefix,
    lowercased, reaches `findings-page` as `--fingerprint` -- not the full
    64-character shape `report-finding` enforces on a WRITE, since an
    event's `related` only ever carries the first 12 characters."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"rows": [], "total": 0, "unique": 0,
                                 "by_severity": {}, "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_findings({"project": "web", "fingerprint": "ABC123DEF456"})
    args = seen["args"]
    assert args[args.index("--fingerprint") + 1] == "abc123def456"


def test_the_findings_route_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "boom"))
    code, payload = srv.security_findings({"project": "web"})
    assert code == 500
    assert "boom" in payload["error"]


def test_the_findings_route_is_a_500_on_rc0_chatter_not_json(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None:
                        (True, '{"rows": []}\nwarning: noisy'))
    code, payload = srv.security_findings({"project": "web"})
    assert code == 500
    assert "not valid JSON" in payload["error"]


def test_the_findings_route_answers_with_the_full_shape(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "rows": [{"fingerprint": "a" * 64, "severity": "critical"}],
        "total": 1, "unique": 1,
        "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        # branches/analyses: the Branch / Analysis run pickers' own options
        # (queries.finding_rows, AllFindings.png) -- the route must relay
        # them through untouched, the same as every other field here.
        "branches": ["main"],
        "analyses": [{"id": 12, "profile": "deep", "branch": "main", "started": 1}],
        "page": 1, "per_page": 25,
        "filters": [{"project": "web", "name": "mine", "query": {}, "saved_at": 1}]})))
    code, payload = srv.security_findings({"project": "web"})
    assert code == 200
    assert set(payload) == {"rows", "total", "unique", "by_severity", "page",
                            "per_page", "filters", "branches", "analyses"}
    assert payload["filters"][0]["name"] == "mine"
    assert payload["branches"] == ["main"]
    assert payload["analyses"][0]["profile"] == "deep"


# ------------------------------------------------------------ saved filters

def test_saving_a_filter_without_a_name_is_refused(srv):
    code, payload = srv.security_filter_save({"project": "web", "name": "  "})
    assert code == 400
    assert "name" in payload["error"]


def test_saving_a_filter_without_a_project_is_refused(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_filter_save({"project": "  ", "name": "mine"})
    assert code == 400
    assert "project" in payload["error"]


def test_saving_a_filter_sends_the_query_on_stdin(srv, monkeypatch):
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        seen["stdin"] = stdin
        return True, ""
    monkeypatch.setattr(srv, "cc", fake)
    code, payload = srv.security_filter_save(
        {"project": "web", "name": "mine", "query": {"severity": ["critical"]}})
    assert code == 200
    assert payload == {"ok": True}
    args = seen["args"]
    assert args[:2] == ["security", "filters"]
    assert "save" in args
    assert args[args.index("--project") + 1] == "web"
    assert args[args.index("--name") + 1] == "mine"
    assert json.loads(seen["stdin"]) == {"severity": ["critical"]}


def test_saving_a_filter_with_no_query_sends_an_empty_object(srv, monkeypatch):
    """A caller that forgot the current filter set, or sent something that is
    not an object, must not crash the save -- it saves an empty query rather
    than reject the whole request over a field the ledger itself accepts."""
    seen = {}

    def fake(args, stdin=None):
        seen["stdin"] = stdin
        return True, ""
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_filter_save({"project": "web", "name": "mine"})
    assert json.loads(seen["stdin"]) == {}


def test_saving_a_filter_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None:
                        (False, "filters save: a saved filter needs a name"))
    code, payload = srv.security_filter_save({"project": "web", "name": "mine"})
    assert code == 500


def test_deleting_a_filter_requires_a_project_and_a_name(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_filter_delete({"project": "", "name": "mine"})
    assert code == 400
    code, payload = srv.security_filter_delete({"project": "web", "name": ""})
    assert code == 400


def test_deleting_a_filter_passes_through_and_reports_what_the_cli_says(srv, monkeypatch):
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"deleted": True})
    monkeypatch.setattr(srv, "cc", fake)
    code, payload = srv.security_filter_delete({"project": "web", "name": "mine"})
    assert code == 200
    assert payload == {"deleted": True}
    args = seen["args"]
    assert args[:2] == ["security", "filters"]
    assert "delete" in args
    assert args[args.index("--project") + 1] == "web"
    assert args[args.index("--name") + 1] == "mine"


def test_deleting_a_filter_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "boom"))
    code, payload = srv.security_filter_delete({"project": "web", "name": "mine"})
    assert code == 500


# ------------------------------------------------------------- activity GET
#
# `security_activity` validates `kind` against the closed vocabulary before
# ever shelling out, the same treatment `security_findings` gives severity/
# state/category. No user column, no IP column, anywhere in this section's
# own tests: this install has one operator (app.db's own `CHECK (id = 1)`),
# enforced at the ledger's schema (bin/security/ledger.py's `event` table),
# not at this route -- but a route that started echoing one back would be a
# regression this file has to catch.

def test_activity_refuses_an_unknown_event_kind(srv):
    code, payload = srv.security_activity({"kind": ["findings_viewed"]})
    assert code == 400
    assert "kind" in payload["error"]


def test_activity_carries_events_and_a_summary(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "events": [{"kind": "analysis_started", "detail": "deep on develop",
                    "project": "web", "related": "4", "at": 1787290000}],
        "summary": {"analysis_started": 12, "analysis_finished": 11},
        "projects": [{"project": "web", "count": 23}],
        "page": 1, "per_page": 25})))
    code, payload = srv.security_activity({})
    assert code == 200
    assert payload["events"][0]["kind"] == "analysis_started"
    assert payload["summary"]["analysis_started"] == 12


def test_the_activity_payload_has_no_user_or_ip_field(srv, monkeypatch):
    """One operator. A column that can only ever hold one value teaches
    nothing, and an IP column on a loopback-only server teaches less."""
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (True, json.dumps({
        "events": [{"kind": "decision_made", "detail": "accepted: reviewed",
                    "project": "web", "related": "abc", "at": 1}],
        "summary": {}, "projects": [], "page": 1, "per_page": 25})))
    _code, payload = srv.security_activity({})
    assert "user" not in payload["events"][0]
    assert "ip" not in payload["events"][0]


def test_activity_defaults_since_to_a_30_day_window(srv, monkeypatch):
    """A caller that asks for nothing still gets a legible, bounded period --
    not `ledger.events_for`'s own "since the beginning of time" default."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"events": [], "summary": {}, "projects": [],
                                 "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    import time as _time
    before = int(_time.time())
    srv.security_activity({})
    since = int(seen["args"][seen["args"].index("--since") + 1])
    assert 29 * 86400 <= before - since <= 30 * 86400 + 5


def test_activity_an_explicit_since_zero_is_not_rewritten_to_the_default(srv, monkeypatch):
    """The CRITICAL fix. `since=0` present on the wire is the screen's own
    "All time" period (`secActSince()`, ui/security/activity-screen.js) --
    deliberately distinct from `since` being ABSENT (the test above), which
    is the only case that still gets the 30-day rewrite. Before the fix,
    `since <= 0` was the rewrite condition regardless of whether the key was
    present at all, so this exact request -- explicit, on the wire, asking
    for everything -- silently got the same 30-day window as a caller who
    never asked for a period, with no error to say so."""
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"events": [], "summary": {}, "projects": [],
                                 "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_activity({"since": "0"})
    assert seen["args"][seen["args"].index("--since") + 1] == "0", \
        "an explicit since=0 ('All time') must reach the CLI as 0, not a rewritten 30-day timestamp"


def test_activity_all_time_reaches_the_real_route_past_the_thirty_day_default(srv):
    """The same fix proved at the ROUTE, through a real subprocess and a
    real ledger -- not `cc()` mocked away like every other test in this
    file. This is deliberate, the same reasoning as the leading-dash test
    near the bottom of this file: the finding this closes was originally
    verified by a manual check that drove `bin/security/cli.py
    activity-data` directly, which was never wrong (`cmd_activity_data`'s
    own `since=0` already means "no lower bound", `ledger.events_for`'s own
    contract) -- so that check passed while the real bug sat one layer up,
    in `security_activity`'s OWN rewrite of `since <= 0`, a layer a mocked
    `cc()` has no timestamps of its own to get wrong about either. Only a
    real round trip through the actual route can catch a regression here.
    """
    project = "route-alltime-probe"
    old_ts = int(time.time()) - 200 * 86400  # far past every period the screen offers
    ok, out = srv.cc(["security", "event", "--project", project,
                      "--kind", "analysis_started", "--detail", "ancient run"])
    assert ok, f"setup: could not record the ancient event: {out}"
    ok, out = srv.cc(["security", "event", "--project", project,
                      "--kind", "analysis_finished", "--detail", "recent run"])
    assert ok, f"setup: could not record the recent event: {out}"

    db_path = Path(os.environ["CLAUDE_CRON_DATA"]) / "security.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE event SET at=? WHERE project=? AND kind='analysis_started'",
                (old_ts, project))
    conn.commit()
    conn.close()

    # An explicit all-time request must reach back past the 30-day default
    # and return the ancient event.
    code, payload = srv.security_activity({"project": project, "since": "0"})
    assert code == 200, payload
    all_time_kinds = {e["kind"] for e in payload["events"]}
    assert "analysis_started" in all_time_kinds, \
        f"an explicit all-time request did not return an event older than 30 days: {payload}"
    assert "analysis_finished" in all_time_kinds

    # An ABSENT `since` (this is the only case that should still default)
    # must exclude that same ancient event.
    code, payload = srv.security_activity({"project": project})
    assert code == 200, payload
    default_kinds = {e["kind"] for e in payload["events"]}
    assert "analysis_started" not in default_kinds, \
        f"an absent `since` must still default to 30 days, excluding the older event: {payload}"
    assert "analysis_finished" in default_kinds


def test_activity_passes_project_and_kind_through(srv, monkeypatch):
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"events": [], "summary": {}, "projects": [],
                                 "page": 1, "per_page": 25})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_activity({"project": "web",
                           "kind": "analysis_started,analysis_finished",
                           "since": "1700000000", "page": "2", "per_page": "10"})
    args = seen["args"]
    assert args[:2] == ["security", "activity-data"]
    assert args[args.index("--project") + 1] == "web"
    assert args.count("--kind") == 2
    assert "analysis_started" in args and "analysis_finished" in args
    assert args[args.index("--since") + 1] == "1700000000"
    assert args[args.index("--page") + 1] == "2"
    assert args[args.index("--per-page") + 1] == "10"


def test_activity_caps_page_size(srv, monkeypatch):
    seen = {}

    def fake(args, stdin=None):
        seen["args"] = args
        return True, json.dumps({"events": [], "summary": {}, "projects": [],
                                 "page": 1, "per_page": 500})
    monkeypatch.setattr(srv, "cc", fake)
    srv.security_activity({"per_page": "99999"})
    assert "99999" not in seen["args"]
    assert seen["args"][seen["args"].index("--per-page") + 1] == "500"


def test_activity_refuses_a_non_integer_since(srv, monkeypatch):
    def must_not_run(args, stdin=None):
        raise AssertionError("the CLI must not be reached")
    monkeypatch.setattr(srv, "cc", must_not_run)
    code, payload = srv.security_activity({"since": "yesterday"})
    assert code == 400
    assert "since" in payload["error"]


def test_activity_reports_a_cli_failure_as_500(srv, monkeypatch):
    monkeypatch.setattr(srv, "cc", lambda args, stdin=None: (False, "boom"))
    code, payload = srv.security_activity({})
    assert code == 500
    assert "boom" in payload["error"]
