"""Checks on the dashboard page that do not need a browser.

The page is ~100 KB of JS inside the server, so a typo in it is invisible to
every other test here and only shows up as a blank dashboard. These are the
cheap guards: it parses, the elements the new code reaches for exist, and the
arithmetic it duplicates from the engine still agrees with the engine.
"""

import json
import re
import shutil
import subprocess

import pytest

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
ENGINE = REPO / "bin" / "claude-cron"


def _page(srv):
    return srv.render_page()


def _js(srv):
    return re.search(r"<script>(.*)</script>", _page(srv), re.S).group(1)


def test_the_page_renders_with_the_token_and_favicon_substituted(srv):
    page = _page(srv)
    for slot in ("__TOKEN__", "__BUILD__", "__FAVICON__", "__BOOT__"):
        assert slot not in page, f"{slot} was left in the page"
    assert srv.TOKEN in page


def test_the_page_paints_the_screen_the_session_calls_for(srv):
    """The overlays go up from JavaScript, a round-trip after the page paints,
    so a page that opens on the shell shows the dashboard flashing past before
    the login card lands. The boot class is what makes the first frame right."""
    signed_out = srv.render_page("boot-login")
    assert 'class="boot-login"' in signed_out
    # The shell must be held back, and the card it holds back for must be up —
    # both from CSS alone, with no script having run yet.
    assert ".boot-login .shell,.boot-setup .shell{display:none}" in signed_out
    assert ".boot-login #login[hidden],.boot-setup #setup[hidden]{display:flex}" in signed_out
    # ...and the signed-in page must NOT hide its own shell.
    assert 'class="boot-authed"' in srv.render_page("boot-authed")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_page_javascript_parses(srv, tmp_path):
    f = tmp_path / "page.js"
    f.write_text(_js(srv))
    p = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


def test_the_sessions_tab_is_labelled_for_what_it_shows(srv):
    """The tab lists retained run directories, kept because a session was cut
    short and might still be resumed -- "Sessions" is the word the README and
    the rest of the dashboard already use for that. It shipped this branch
    labelled "Worktrees" instead, the word for the isolation mechanism
    underneath, not the thing on screen. Pinned so it does not drift back."""
    js = _js(srv)
    assert 'I.folder + "Sessions"' in js, "the tab's own label was not renamed"
    assert '"Worktrees"' not in js, "the old tab label text is still shipping somewhere"
    # The internal wiring (id, data-tab, and by extension the dashTab value and
    # localStorage key) is deliberately untouched -- this is a label change,
    # not a restructure. test_every_element_the_script_reaches_for_exists
    # covers ids existing at all; this pins that THIS one specifically did not
    # get renamed along with its visible text.
    assert '<button class="viewtab" data-tab="worktrees" id="vt-wt">' in _page(srv), \
        "the tab's internal id/data-tab must stay stable even though its label changed"


def test_every_element_the_script_reaches_for_exists(srv):
    """$("foo") against an id the markup does not define is a silent no-op that
    turns into a TypeError the first time the code touches .value."""
    page = _page(srv)
    html = page.split("<script>")[0]
    ids = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', html))
    # ids created at runtime by innerHTML rather than present in the skeleton
    dynamic = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', page.split("<script>", 1)[1]))
    # The page's own script AND the Security area's modules. The area moved out
    # of the page; a check that kept reading only the inline script would have
    # stopped watching a thousand lines of `$("sec-…")` without failing once.
    reads = _js(srv) + "\n" + _security_js(srv)
    referenced = set(re.findall(r'\$\("([a-zA-Z0-9_-]+)"\)', reads))
    missing = referenced - ids - dynamic
    assert not missing, f"script reaches for ids that no markup defines: {sorted(missing)}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_backoff_curve_matches_the_engine(srv, tmp_path):
    """The page recomputes the engine's backoff so it can say when the next
    check really is. Two implementations of one rule drift; this is what stops
    the card promising a check the tick will not make."""
    js = _js(srv)
    fn = re.search(r"const BACKOFF_AFTER=.*?\n};", js, re.S).group(0)
    script = tmp_path / "b.js"
    script.write_text(fn + "\nconsole.log([0,1,2,3,4,5,6,7,20]"
                           ".map(backoffMultiplier).join(' '));")
    from_js = subprocess.run(["node", str(script)],
                             capture_output=True, text=True, check=True).stdout.split()

    from_bash = []
    for s in (0, 1, 2, 3, 4, 5, 6, 7, 20):
        out = subprocess.run(
            ["/bin/bash", "-c",
             f'source "{ENGINE}" >/dev/null 2>&1; backoff_multiplier {s}'],
            capture_output=True, text=True)
        from_bash.append(out.stdout.strip())

    assert from_js == from_bash, f"js={from_js} bash={from_bash}"


def _fn(js, name):
    """The source of one function, brace-matched — regex alone stops at the
    first `}` inside the body."""
    i = js.index(f"async function {name}()")
    d, j = 0, js.index("{", i)
    for k in range(j, len(js)):
        d += (js[k] == "{") - (js[k] == "}")
        if d == 0:
            return js[i:k + 1]
    raise AssertionError(f"unterminated {name}")


def _plainfn(js, name):
    """Same brace-matching as _fn, for an ordinary function -- _fn's exact
    `async function NAME()` match only reaches a zero-argument async one, and
    the helpers below are neither."""
    i = js.index(f"function {name}(")
    d, j = 0, js.index("{", i)
    for k in range(j, len(js)):
        d += (js[k] == "{") - (js[k] == "}")
        if d == 0:
            return js[i:k + 1]
    raise AssertionError(f"unterminated {name}")


def _anyfn(js, name):
    """Same brace-matching as _plainfn, but keeps a leading `async ` when the
    declaration has one -- for a function that is both async AND takes
    arguments, which neither _fn (exact zero-arg `async function NAME()`
    only) nor _plainfn (finds `function NAME(` and so drops the `async`
    keyword that precedes it) can extract whole. Extracting `await` inside a
    function missing its own `async` is a SyntaxError in Node, not a runtime
    surprise -- so this has to keep the keyword, not merely tolerate its
    absence."""
    i = js.index(f"function {name}(")
    if js[max(0, i - 6):i] == "async ":
        i -= 6
    d, j = 0, js.index("{", i)
    for k in range(j, len(js)):
        d += (js[k] == "{") - (js[k] == "}")
        if d == 0:
            return js[i:k + 1]
    raise AssertionError(f"unterminated {name}")


def _const(js, name):
    """The verbatim source of `const NAME = [...]` or `const NAME = {...}`,
    open/close matched the same way _fn/_plainfn match braces -- so a value
    is captured whole regardless of what punctuation it contains, rather
    than a regex that stops at the first `]`/`}`/`;` inside it."""
    i = js.index(f"const {name} =")
    j = js.index("=", i) + 1
    while js[j] in " \n\t":
        j += 1
    opener = js[j]
    closer = {"[": "]", "{": "}"}[opener]
    d = 0
    for k in range(j, len(js)):
        d += (js[k] == opener) - (js[k] == closer)
        if d == 0:
            return js[i:k + 1] + ";\n"
    raise AssertionError(f"unterminated {name}")


CWD = "/x/web"
ROW = {"name": "web", "path": CWD, "base": "develop"}


def _run_save(srv, tmp_path, *, multi, name="save.js"):
    """Drive the real saveProject() over a stub DOM and return what it sent."""
    harness = """
    // The two vocabularies moved out with the Security area; the project editor
    // reads them back off its interface, so the stub is that interface.
    const CCSecurity = { SEC_PROFILES: ["quick","standard","deep"],
                         SEV_ORDER: ["low","medium","high","critical"] };
    const EFFORTS = ["","low","medium","high","xhigh","max"];
    const sent = [];
    const vals = {"pj-name":"Web","pj-desc":"","pj-cwd":"%s","pj-ccd":"","pj-base":"develop",
                  "pj-wt":"auto","pj-up":"","pj-down":"already here",
                  "sec-enabled":false,"sec-model":"","sec-effort":"0","sec-perm":"bypassPermissions","sec-cfgdir":"",
                  "sec-profile-default":"standard","sec-max-budget":"","sec-daily-budget":"",
                  "sec-min-severity":"medium","sec-ignore":""};
    const $ = (id) => ({ get value(){ return vals[id]; }, set value(v){ vals[id]=v; },
                         get checked(){ return !!vals[id]; }, set checked(v){ vals[id]=v; },
                         style:{}, disabled:false, close(){} });
    let editingProject = "Web";
    let pjMulti = %s;
    let pjHooks = { up: null, down: "already here" };   // up still in flight
    const pjWiz = { forward:()=>true, validateAll:()=>true, markClean(){} };
    async function projApi(op, extra){ sent.push([op, extra]); return true; }
    const collectRepos = () => [%s], toast = () => {}, refresh = () => {};
    """ % (CWD, "true" if multi else "false",
           __import__("json").dumps(ROW) if multi else "")
    tail = "\nsaveProject().then(() => console.log(JSON.stringify(sent)));\n"
    f = tmp_path / name
    f.write_text(harness + _fn(_js(srv), "saveProject") + tail)
    out = subprocess.run(["node", str(f)], capture_output=True, text=True, check=True)
    return __import__("json").loads(out.stdout)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_saving_does_not_wipe_a_hook_that_never_loaded(srv, tmp_path):
    """The up/down hooks are fetched after the modal opens, so for a moment the
    textareas are empty while the files on disk are not. provision_set with an
    empty script DELETES the file, so a save in that window used to destroy both
    hooks — open the project, hit save, the provisioning is gone."""
    sent = _run_save(srv, tmp_path, multi=False)
    phases = [e.get("phase") for op, e in sent if op == "provision_set"]
    assert "up" not in phases, "a hook that never loaded was overwritten with an empty script"
    assert phases == ["down"], f"expected only the loaded hook to be written, got {phases}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_single_repo_project_saves_its_base_and_sheds_its_repo_row(srv, tmp_path):
    """The row a single-repo project used to need only ever carried its base —
    name and path repeated .cwd. The base now lives on the project, and the row
    has to actually go: project-set REPLACES arrays, so the empty array is what
    removes it. Leaving it behind would keep the engine reading the stale row."""
    sent = _run_save(srv, tmp_path, multi=False)
    proj = next(e["project"] for op, e in sent if op == "project_set")
    assert proj["base"] == "develop", "the project-level base was not sent"
    assert proj["repos"] == [], f"the redundant row survived the save: {proj['repos']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_multi_repo_project_keeps_its_rows_and_leaves_the_project_base_alone(srv, tmp_path):
    """With several repos each row declares its own base, so the project-level
    one means nothing — and must not be SENT, because project-set merges: an
    omitted key keeps whatever is stored, which is what lets a project switch to
    several repos and back without losing the base it had."""
    sent = _run_save(srv, tmp_path, multi=True, name="save-multi.js")
    proj = next(e["project"] for op, e in sent if op == "project_set")
    assert proj["repos"] == [ROW], f"the declared rows were not sent whole: {proj['repos']}"
    assert "base" not in proj, "a project-wide base was sent for a multi-repo project"


# ---- the project editor's Security tab. A fourth pane, same rules as the
# other three: every field it owns is always sent, whole, because project-set
# merges rather than replaces (see cmd_project_set's own selftest).

def test_the_project_editor_has_a_security_pane(srv):
    page = srv.render_page("boot-authed")
    assert 'data-pjpane="security"' in page
    for field in ("sec-enabled", "sec-model", "sec-effort", "sec-perm", "sec-cfgdir",
                  "sec-profile-default", "sec-max-budget", "sec-daily-budget",
                  "sec-min-severity", "sec-ignore"):
        assert f'id="{field}"' in page, f"the security pane has no {field} field"


def test_the_min_severity_dropdown_offers_info_as_the_lowest_option(srv):
    """The info severity sits below the default display floor, recorded but hidden,
    until somebody lowers the floor to look at it. The dropdown must offer info as
    the lowest option to make it reachable through the UI."""
    page = srv.render_page("boot-authed")
    # Extract the sec-min-severity select options
    select_match = re.search(r'<select id="sec-min-severity">(.*?)</select>', page, re.S)
    assert select_match, "sec-min-severity select not found"
    select_html = select_match.group(1)
    # Verify info option exists
    assert '<option value="info">Info</option>' in select_html, \
        "the info option is not offered in the severity dropdown"
    # Verify it is the first option (lowest)
    first_option = re.search(r'<option value="([^"]+)">', select_html)
    assert first_option.group(1) == "info", \
        f"info must be the first (lowest) option, not {first_option.group(1)}"
    # Verify medium is still the selected default
    assert 'selected>Medium</option>' in select_html or '<option value="medium" selected>Medium</option>' in select_html, \
        "medium is no longer the selected default"


def test_security_model_and_effort_use_the_job_editors_controls(srv):
    """The Security tab's model and effort are the SAME controls the job editor
    uses — a searchable combo fed by /api/models and the Faster-Smarter slider —
    not a free-text field and a bare select that let the two screens drift."""
    page = srv.render_page("boot-authed")
    # the combo: wrapper, trigger, popover with search, and the hidden input
    for part in ("sec-model-combo", "sec-model-trigger", "sec-model-val",
                 "sec-model-pop", "sec-model-search", "sec-model-opts"):
        assert f'id="{part}"' in page, f"the model combo is missing {part}"
    assert '<input type="hidden" id="sec-model">' in page
    # the slider: a range with the shared effslider class and the ends legend
    assert 'id="sec-effort" class="effslider"' in page
    assert 'id="sec-effort-label"' in page
    # the combo is created and kept in step with /api/models like the job's
    assert 'createCombo({id:"sec-model"' in page
    assert "secModelCombo.set(secModelCombo.get(), MODELS)" in page
    # and the permission mode is the job editor's combo too, with the headless
    # default that actually lets a fresh worktree run tools
    assert 'createCombo({id:"sec-perm"' in page
    assert 'id="sec-perm-combo"' in page


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_saving_always_sends_the_whole_security_block_with_a_real_boolean(srv, tmp_path):
    """`enabled` must be a JSON boolean, never the string "true" — the page and
    the derived-jobs fast path both also accept a hand-typed string, but this
    pane is not a hand-edited config and has no reason to ever write one.
    Every other field it owns rides along too, so an untouched pane on a save
    that never visited it does not quietly drop half the block — project-set
    merges, and an omitted key would keep whatever the FIRST save ever wrote,
    but only a value actually present here can ever clear one."""
    sent = _run_save(srv, tmp_path, multi=False)
    proj = next(e["project"] for op, e in sent if op == "project_set")
    sec = proj["security"]
    assert sec["enabled"] is False, f"enabled must be a real boolean, got {sec['enabled']!r}"
    assert set(sec) == {"enabled", "model", "effort", "permission_mode", "claude_config_dir",
                         "default_profile", "max_budget_usd", "daily_budget_usd",
                         "min_severity", "ignore_paths"}, f"security block: {sec}"
    assert sec["max_budget_usd"] == "", "an empty budget must clear, not vanish from the payload"
    assert sec["default_profile"] == "standard"
    assert sec["min_severity"] == "medium"


# ---- the job card's kept-session notice, and the guard it must share with
# the Runs table rather than re-derive.

def _harness_globals():
    """The globals sessionLines/resumeInFlight/keptSessionsOf read, stood up
    the same shape the real page gives them without pulling in the rest of
    the page's DOM-touching code."""
    return """
    const I = {folder:"<folder>", play:"<play>"};
    const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
      c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
    let DATA = {};
    const activeRunsOf = id => (DATA.active_runs||{})[id] || [];
    """


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_resume_in_flight_is_the_single_guard(srv, tmp_path):
    """resumeTarget (Runs table) and sessionLines (job card) both need to know
    "is a resume of this session already running" -- this pins resumeInFlight's
    own behaviour so a later change to either caller has one function to trust
    instead of two chances to disagree."""
    js = _js(srv)
    fn = _plainfn(js, "resumeInFlight")
    script = tmp_path / "rif.js"
    script.write_text(_harness_globals() + """
    DATA = {active_runs: {jobA: [{resume_of: "sess-1"}, {resume_of: "sess-2"}]}};
    """ + fn + """
    console.log(JSON.stringify([
      resumeInFlight("jobA", "sess-1"),   // this exact session, this job: busy
      resumeInFlight("jobA", "sess-9"),   // a different session: free
      resumeInFlight("jobB", "sess-1"),   // right session, wrong job: free
      resumeInFlight("jobA", ""),         // no session to check: free
    ]));
    """)
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout
    assert __import__("json").loads(out) == [True, False, False, False]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_resume_target_defers_to_resume_in_flight(srv, tmp_path):
    """Structural, not behavioural: resumeTarget's live-slot branch must call
    the shared resumeInFlight rather than keep its own `.some(a=>a.resume_of
    ===sid)` -- a second copy would still pass every behavioural test today
    and silently stop agreeing with sessionLines the next time one of them
    changes (exactly what the renderRuns comment on the `resumable` set
    describes happening once already, for a different predicate)."""
    js = _js(srv)
    body = _plainfn(js, "resumeTarget")
    assert "resumeInFlight(" in body, "resumeTarget must call the shared guard, not re-derive it"
    assert "resume_of" not in body, (
        "resumeTarget still reads .resume_of directly -- resumeInFlight is no "
        "longer the only place that knows this shape")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_job_card_shows_every_kept_session_honestly(srv, tmp_path):
    """Three rows, three different truths: no `.session` at all (held, no
    button -- there is nothing valid to resume), a session nobody is touching
    (a working Resume button carrying the real id), and a session already
    being resumed (no second button -- resumeInFlight decides this, not a
    fresh guess)."""
    js = _js(srv)
    deps = "\n".join(_plainfn(js, n) for n in
                      ("resumeInFlight", "keptSessionsOf", "sessionLines", "fmtExpiresIn"))
    script = tmp_path / "sess.js"
    script.write_text(_harness_globals() + """
    DATA = {
      retained_worktrees: [
        {job:"j1", stamp:"s1", session:"",           expires_in:3600},
        {job:"j1", stamp:"s2", session:"sess-live00", expires_in:7200},
        {job:"j1", stamp:"s3", session:"sess-busy00", expires_in:100},
        {job:"j2", stamp:"s4", session:"sess-other",  expires_in:900},
      ],
      active_runs: {j1: [{resume_of:"sess-busy00"}]},
    };
    """ + deps + """
    const html = sessionLines("j1");
    console.log(JSON.stringify({
      rowsForJ1: (html.match(/class="warnline"/g)||[]).length,
      noSessionText: html.indexOf("cannot be resumed") !== -1,
      resumeButtons: (html.match(/data-op="resume"/g)||[]).length,
      liveButtonExact: html.indexOf('data-op="resume" data-id="j1" data-session="sess-live00"') !== -1,
      busyGotAButton: html.indexOf('data-session="sess-busy00"') !== -1,
      mentionsOtherJob: html.indexOf("sess-other") !== -1,
      emptyForJobWithNothingKept: sessionLines("no-such-job") === "",
    }));
    """)
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout
    got = __import__("json").loads(out)
    assert got["rowsForJ1"] == 3, "one line per kept run dir, including the sessionless one"
    assert got["noSessionText"], "a run dir with no .session must say it cannot be resumed"
    assert got["resumeButtons"] == 1, "only the free session gets a working Resume button"
    assert got["liveButtonExact"], "the button must carry the real job id and real session id"
    assert not got["busyGotAButton"], "a session already being resumed must not get a second button"
    assert not got["mentionsOtherJob"], "sessionLines(j1) leaked another job's row"
    assert got["emptyForJobWithNothingKept"], "a job with nothing kept renders nothing"


# ---- the Runs table's own Resume button: which statuses it ever lights up
# for, distinct from the job card's sessionLines above (different data
# source, different guard already proven by test_resume_target_defers_to_...
# above) -- see the `resumable` comment in renderRuns for why this is ONE
# const read from three places rather than three separate checks.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_stopped_run_is_resumable_alongside_error_and_warning(srv, tmp_path):
    """A `stopped` run never declares an ending either, so the engine keeps
    its tree and its services exactly as it does for an error's or a
    warning's -- specifically so a resume can pick them back up (see
    "Sessions that are still open" in the README). Before this, `resumable`
    covered error and warning only: the button did not cover the one status
    whose whole run dir is sitting there, kept, for exactly this reason."""
    js = _js(srv)
    line = re.search(r"const resumable = .*?;", js).group(0)
    script = tmp_path / "resumable.js"
    script.write_text("""
    function check(s){ %s return resumable; }
    console.log(JSON.stringify(
      ["error","warning","stopped","success","idle","capped","precheck_error"].map(check)));
    """ % line)
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == [True, True, True, False, False, False, False]


def test_the_disabled_resume_tooltip_names_every_resumable_status(srv):
    """The other end of the same ladder: a status outside `resumable` falls
    to a disabled button whose tooltip used to read "Only a failed or
    warning run can be resumed" -- accurate right up until `stopped` joined
    the set above, at which point it started telling the operator something
    false about the very button it sits beside."""
    js = _js(srv)
    assert "Only a failed, warning or stopped run can be resumed" in js
    assert "Only a failed or warning run can be resumed" not in js


# ---- the run modal saying WHY a run ended, when the API is what ended it.

def _reason_harness(js):
    """stopReasonText and its two tables, standing on their own. The page reads
    these off a run's stored result_json, so the fixtures below are the shape
    the CLI actually writes."""
    tables = ""
    for name in ("API_ERRORS", "STOP_REASONS", "REASON_PREFIX"):
        i = js.index(f"const {name}={{")
        d, j = 0, js.index("{", i)
        for k in range(j, len(js)):
            d += (js[k] == "{") - (js[k] == "}")
            if d == 0:
                tables += js[i:k + 1] + ";\n"
                break
    fns = "\n".join(_plainfn(js, n) for n in
                    ("apiErrorParts", "reasonBadge", "reasonParts", "stopReasonText", "retryNote"))
    return """
    const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
      c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
    """ + tables + fns


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_api_failure_outranks_the_protocol_stop_reason(srv, tmp_path):
    """A 529 ended a 100-minute run, and the CLI reported it as
    `stop_reason: "stop_sequence"`, `subtype: "success"`, `terminal_reason:
    "completed"` -- every innocent-looking field agreeing that nothing had
    gone wrong. The modal read the innocent one and told its operator the
    model had hit a configured stop sequence: a sentence about the agent's own
    choice, on the one line whose job is to say why the run stopped, for a
    fault on the API's side. `api_error_status` is where the CLI puts the
    truth, and it has to be read FIRST."""
    script = tmp_path / "reason.js"
    script.write_text(_reason_harness(_js(srv)) + """
    const api  = {api_error_status:529, stop_reason:"stop_sequence",
                  result:"API Error: 529 Overloaded. This is a server-side issue"};
    // Recorded before the page read the field: the code survives only in the text.
    const old  = {stop_reason:"stop_sequence", result:"API Error: 529 Overloaded."};
    console.log(JSON.stringify({
      api:  stopReasonText(api, {}),
      old:  stopReasonText(old, {}),
      turn: stopReasonText({stop_reason:"end_turn"}, {}),
      seq:  stopReasonText({stop_reason:"stop_sequence"}, {}),
      note: stopReasonText({}, {note:"STOPPED: ended on purpose from the dashboard"}),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    for key in ("api", "old"):
        assert "API error 529" in out[key], f"{key}: the API's own verdict was not shown"
        assert "stop sequence" not in out[key], f"{key}: still blaming a configured stop sequence"
        assert "overloaded" in out[key], f"{key}: never says the API was overloaded"
    # A run with no API failure must be untouched -- including one that really
    # DID hit a stop sequence, which is the reading this fix could have broken.
    assert "Normal end" in out["turn"]
    assert "Stop sequence" in out["seq"] and "API error" not in out["seq"]
    assert "Stopped by you" in out["note"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_terminal_says_the_api_is_bouncing_it_rather_than_showing_nothing(srv, tmp_path):
    """A resume whose every turn was refused sat there live with an empty
    Terminal and the words "Waiting for the first turn", which is what a run
    that is merely slow to start looks like -- while the stream the panel was
    already tailing held ten `api_retry` events naming the status. It ran for
    three minutes, cost $0.00 and died at the retry ceiling with the operator
    never told why."""
    script = tmp_path / "retry.js"
    script.write_text(_reason_harness(_js(srv)) + """
    const r = {count:10, attempt:10, max_retries:10, status:529, error:"overloaded"};
    console.log(JSON.stringify({
      live: retryNote({live:true, api_retries:{...r, count:3, attempt:3}}),
      dead: retryNote({api_retries:r}),
      none: retryNote({live:true, api_retries:null}),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "529" in out["live"] and "3 of 10" in out["live"]
    assert "nothing is wrong with the run itself" in out["live"]
    assert "529" in out["dead"] and "retry ceiling" in out["dead"]
    # No retries means nothing to say -- the note must not appear over a healthy run.
    assert out["none"] == ""


def test_the_server_hands_the_page_what_the_api_did(srv):
    """Both halves above read fields the server has to actually send. It used to
    forward a fixed list that included `stop_reason` and not `api_error_status`,
    and to drop the retry events on the floor -- so the page could not have told
    the truth even if it had wanted to."""
    stream = "\n".join(json.dumps(e) for e in [
        {"type": "system", "subtype": "init", "session_id": "s1", "model": "claude-opus-5"},
        {"type": "system", "subtype": "api_retry", "attempt": 1, "max_retries": 10,
         "error_status": 529, "error": "overloaded"},
        {"type": "system", "subtype": "api_retry", "attempt": 2, "max_retries": 10,
         "error_status": 529, "error": "overloaded"},
    ])
    assert srv._api_retries(stream) == {
        "count": 2, "attempt": 2, "max_retries": 10,
        "status": 529, "error": "overloaded", "delay_ms": None}
    # A run the API never refused has nothing to report, so the page shows nothing.
    assert srv._api_retries('{"type":"assistant","message":{}}') is None
    assert srv._api_retries("") is None
    server_src = (REPO / "bin" / "claude-cron-server").read_text()
    assert '"api_error_status": data.get("api_error_status")' in server_src


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_resume_is_not_its_own_continuation(srv, tmp_path):
    """A resumed run carries the session it continued in BOTH `resumed_from` and
    `session` -- it is the same conversation. continuationsOf matched on
    resumed_from with no `start>after` guard, so a resume found ITSELF in its own
    continuations, and the Runs table greyed out its Resume button saying "this
    task was already resumed" while pointing at the very row you were looking at.
    A resume that dies young is the one most worth firing again: an API overload
    killed one at 3m37s and $0.00, and that row was the only one the dashboard
    would not let its operator touch."""
    js = _js(srv)
    script = tmp_path / "cont.js"
    script.write_text("""
    let DATA = {runs: [
      {id:"j", start:100, session:"s1", resumed_from:""},    // the original, failed
      {id:"j", start:200, session:"s1", resumed_from:"s1"},  // its resume, also failed
    ]};
    """ + _plainfn(js, "continuationsOf") + """
    console.log(JSON.stringify({
      original: continuationsOf("s1", 100).map(r=>r.start),
      resume:   continuationsOf("s1", 200).map(r=>r.start),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    # The first run really was continued, and still says so.
    assert out["original"] == [200], f"the real continuation was lost: {out['original']}"
    # The resume has nothing after it, so it stays resumable.
    assert out["resume"] == [], f"the resume counted itself: {out['resume']}"


# ---- the Security view. Its own destination in the sidebar, listing projects
# rather than jobs -- and the one page on this dashboard that renders strings
# written by analysed code, which is what most of these are about.

UI_ROOT = REPO / "ui"


def _security_sources(root=UI_ROOT):
    """Every JS module under `root`, sorted, so a scan of "the code that can
    reach the bundle" keeps meaning the whole tree as it grows a file.

    Defaults to REPO/"ui" as a WHOLE, not ui/security/ alone: build/ui-digest.sh
    fingerprints `find ui -name '*.js'` -- every file under ui/, not just
    ui/security/ -- and build/build-ui.sh bundles whatever ui/security/index.js
    reaches by import, which is free to pull from anywhere under ui/. A module
    at ui/shared/x.js is therefore hashed and bundleable while living entirely
    outside ui/security/; a scan confined to that one directory would
    fingerprint such a file and ship it without ever sink-scanning it -- the
    one guard here that would actually catch an innerHTML regression, silently
    skipping the new file. The two guards over "the code that can reach the
    bundle" have to agree on what that code is, so this walks the same root
    the digest does.

    `root` is a parameter rather than a hardcoded constant purely so a test
    can point this at a fabricated tree under `tmp_path` and prove the same
    reach without ever writing into the real, tracked ui/ directory.
    """
    return sorted(root.rglob("*.js"))


def _security_js(srv):
    """The Security area's own source -- concatenated from every module under
    ui/ (see _security_sources above), not just ui/security/, for the same
    reason: a shared module living elsewhere under ui/ is exactly as
    bundleable and exactly as unscanned otherwise.

    The whole-page checks below would pass on a page that renders a finding
    safely and a branch name unsafely twelve hundred lines away; these have to
    look at exactly the code that draws this view.

    This used to read a block of dashboard.html between two banner comments.
    The area now lives in ui/security/, and a reader left pointing at the old
    place would have gone on passing while watching nothing -- so it follows
    the code. The COMMITTED BUNDLE is deliberately not what is read: it is
    generated, and a guard that reads generated output is one build away from
    being a guard on a build artefact rather than on what anybody writes.
    """
    files = _security_sources()
    assert files, f"no JS modules under {UI_ROOT} -- this guard is reading nothing"
    return "\n".join(f.read_text() for f in files)


def test_a_nested_security_module_still_reaches_the_sink_scan(tmp_path):
    """build/ui-digest.sh walks ALL of ui/ when it fingerprints what the
    bundle was built from, and build-ui.sh bundles whatever
    ui/security/index.js reaches by import -- neither is confined to
    ui/security/ itself. A scan that only rglobbed that one directory would
    bundle and fingerprint a module living anywhere else under ui/ (a shared
    module at ui/shared/, say) without ever sink-scanning it -- exactly the
    shape four upcoming screens are about to add.

    Proves the scan's reach with a fabricated file at <root>/shared/x.js
    inside a scratch `tmp_path`, never touching the real ui/ tree -- an
    interrupted run here leaves nothing behind, unlike writing the probe
    straight into the tracked directory these guards exist to keep clean.
    """
    nested = tmp_path / "shared" / "x.js"
    nested.parent.mkdir(parents=True)
    nested.write_text("el.innerHTML = x;\n")
    assert nested in _security_sources(tmp_path), \
        "a module nested beside ui/security/ was not picked up by the scan"


def test_the_freshness_digest_covers_the_build_toolchain_not_just_ui_sources(tmp_path):
    """build/ui-digest.sh is the fingerprint `claude-cron selftest` recomputes
    to prove the committed bundle was built from the committed sources -- and
    it hashes build/build-ui.sh and package.json alongside ui/**/*.js on
    purpose, because a changed esbuild --target or a bumped esbuild pin
    changes what the committed bytes should be without touching a single file
    under ui/. Nothing in this suite ever ran the actual script, though, so a
    future edit narrowing the hash back to ui/**/*.js alone would pass every
    other test here and only show up in production as a stale bundle nobody
    was told about.

    Runs the real script against scratch COPIES of its inputs under
    `tmp_path` -- never the tracked tree -- so this cannot leave anything
    dirty even on an interrupted run. The script's own `cd
    "$(dirname "$0")/.."` makes this possible: given an absolute path to a
    copied ui-digest.sh, it resolves its "repo root" relative to itself, so a
    copy with the same relative layout (ui/, build/build-ui.sh,
    build/ui-digest.sh, package.json) is indistinguishable from the real
    tree to the script.
    """
    def _seed(root):
        shutil.copytree(REPO / "ui", root / "ui")
        (root / "build").mkdir()
        shutil.copy(REPO / "build" / "ui-digest.sh", root / "build" / "ui-digest.sh")
        shutil.copy(REPO / "build" / "build-ui.sh", root / "build" / "build-ui.sh")
        shutil.copy(REPO / "package.json", root / "package.json")

    def _digest(root):
        p = subprocess.run(["bash", str(root / "build" / "ui-digest.sh")],
                            capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        return p.stdout.strip()

    baseline_root = tmp_path / "baseline"
    _seed(baseline_root)
    baseline = _digest(baseline_root)
    assert re.fullmatch(r"[0-9a-f]{64}", baseline), \
        f"ui-digest.sh did not produce a sha256 against a clean copy: {baseline!r}"

    build_script_root = tmp_path / "changed_build_script"
    _seed(build_script_root)
    f = build_script_root / "build" / "build-ui.sh"
    f.write_text(f.read_text() + "\n# a toolchain change no ui/ file would show\n")
    assert _digest(build_script_root) != baseline, \
        "the digest did not change when build/build-ui.sh changed"

    package_json_root = tmp_path / "changed_package_json"
    _seed(package_json_root)
    f = package_json_root / "package.json"
    f.write_text(f.read_text().replace('"0.25.0"', '"0.25.1"'))
    assert _digest(package_json_root) != baseline, \
        "the digest did not change when package.json changed"


def test_the_security_view_exists_and_is_registered(srv):
    page = srv.render_page("boot-authed")
    assert 'data-view="security"' in page
    assert 'id="view-security"' in page
    # Against the VIEWS array itself, not against the page. A bare
    # `'"security"' in page` was satisfied by the nav button's own
    # `data-view="security"` a few hundred bytes earlier, so it could never
    # fail: setView() falls back to the overview for a name VIEWS does not
    # carry, and dropping it from that array would have left the nav item, the
    # panel and this assertion all in place with the view unreachable.
    views = re.search(r"const VIEWS\s*=\s*\[(.*?)\];", page).group(1)
    assert '"security"' in views, f"the Security view is not in VIEWS: {views}"


def test_every_sidenav_item_has_a_view(srv):
    """A nav button with no panel behind it is a dead click."""
    page = srv.render_page("boot-authed")
    for view in re.findall(r'class="navitem" data-view="([a-z]+)"', page):
        assert f'id="view-{view}"' in page, f"nav item {view} has no view"


def test_the_security_ui_never_builds_dom_from_html_strings():
    """The scan follows the code. It used to read a block of dashboard.html;
    the area now lives in ui/security/, and a scan left pointing at the old
    place would have kept passing while watching nothing.

    A finding's title, its file paths and — the one nobody expects — the BRANCH
    it was found on are all strings a repository chooses. Git allows '<', '>'
    and '&' in a ref name, so `feature/<img src=x onerror=…>` is a branch this
    page will list in a picker.

    The rule used to be "the only thing this block hands to innerHTML is an
    entry from the page's own icon table". Moving the area out sharpened it to
    "this area hands the HTML parser nothing at all": the icon table is the
    PAGE's, so the two helpers that inject its markup stayed in the page beside
    it (see test_the_pages_icon_helpers_only_ever_inject_an_icon), and what
    moved out has no reason to reach a sink of any kind.
    """
    sinks = ("innerHTML", "insertAdjacentHTML", "outerHTML",
             "createContextualFragment", "DOMParser", 'setAttribute("on')
    files = _security_sources()
    assert files, f"no JS modules under {UI_ROOT} -- this guard is reading nothing"
    for src in files:
        text = src.read_text()
        for sink in sinks:
            assert sink not in text, f"{src.name} reaches the DOM through {sink}"


def test_the_pages_icon_helpers_only_ever_inject_an_icon(srv):
    """Where the innerHTML the Security area used to do actually went.

    The area draws icons, the icon table is the page's, and the injection stayed
    with the table rather than travelling with the code — so `CC.icon()` and
    `CC.iconLabel()` are now the only route from the Security area to the HTML
    parser, and this is the guard the old block-scan was. Anything they are
    handed beyond an entry in `I` goes in as a TEXT NODE, which is what keeps a
    branch called `feature/<img src=x onerror=…>` inert.
    """
    js = _js(srv)
    i = js.index("const CC = {")
    block = js[i:js.index("\n};", i)]
    found = [r.strip() for r in re.findall(r"\.innerHTML\s*=\s*([^;\n]+)", block)]
    assert len(found) == 2, \
        f"expected exactly the two icon helpers to inject markup, found: {found}"
    for expr in found:
        assert expr == 'I[name] || ""', \
            f"the page's Security interface injects more than an icon: {expr}"
    assert "createTextNode(label)" in block, \
        "a label beside an icon must go in as text, not as markup"


# `X.innerHTML = …` is one door into the HTML parser. These are the others, and
# the scan above sees none of them: an edit that wanted to APPEND an icon rather
# than replace one, or to set a handler by attribute, would reach for one of
# these and pass every guard in this file. Each entry is (pattern, what to call
# it in the failure message).
HTML_SINKS = [
    (r"\.innerHTML\s*\+=", "innerHTML +="),
    (r"insertAdjacentHTML", "insertAdjacentHTML"),
    (r"outerHTML", "outerHTML"),
    (r"""\[\s*["']innerHTML["']\s*\]""", 'the ["innerHTML"] spelling'),
    (r"createContextualFragment", "createContextualFragment"),
    (r"DOMParser", "DOMParser"),
    (r"""setAttribute\(\s*["']on""", 'setAttribute("on…", …)'),
]


def _html_sinks(block):
    return [name for pat, name in HTML_SINKS if re.search(pat, block)]


def test_the_security_block_reaches_no_other_html_sink(srv):
    """The rule is "nothing from an analysis is ever handed to the HTML parser",
    not "nothing is assigned to .innerHTML". A branch name is a string a
    repository chooses and git allows '<', '>' and '&' in it, so every one of
    these is the same hole under a different name."""
    found = _html_sinks(_security_js(srv))
    assert not found, f"the Security view reaches an HTML sink: {found}"


def test_the_html_sink_denylist_would_catch_one(srv):
    """The guard above passes today because the block is clean, which is also
    what a broken guard looks like. Mutate the real block the way an edit
    actually would and check each shape is seen."""
    block = _security_js(srv)
    assert "insertAdjacentHTML" in _html_sinks(
        block + '\n  row.insertAdjacentHTML("beforeend", "<b>" + f.title + "</b>");\n')
    assert "innerHTML +=" in _html_sinks(block + "\n  host.innerHTML += f.title;\n")
    assert "outerHTML" in _html_sinks(block + "\n  row.outerHTML = f.rationale;\n")
    assert 'the ["innerHTML"] spelling' in _html_sinks(
        block + '\n  row["innerHTML"] = f.title;\n')
    assert 'setAttribute("on…", …)' in _html_sinks(
        block + '\n  b.setAttribute("onclick", "secDecide(" + f.id + ")");\n')


def test_the_severity_filter_never_hides_a_fixed_finding(srv):
    assert 'f.state === "fixed" ||' in _security_js(srv)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_severity_floor_filters_the_page_and_nothing_else(srv, tmp_path):
    """`min_severity` is a display setting, and three things fall out of that.

    A finding that CLOSED is shown at every floor: the checklist exists to say
    what went away, and a low-severity fix disappearing from the page makes a
    good outcome look like nothing happened. A severity outside the known
    vocabulary ranks above critical rather than below low — an unrecognised
    value is not a reason to drop a finding on the floor, and this filter is
    the one place that could do it without a trace. And `info`, which IS in
    the known vocabulary, ranks below everything else: it must be filterable
    like any real severity, not stuck in the above-critical fallback the way
    it shipped once already, which made it both unhideable and sorted above
    every critical finding.
    """
    block = _security_js(srv)
    src = (re.search(r"const SEV_ORDER = .*?;", block).group(0) + "\n"
           + re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
           + _plainfn(block, "secVisible"))
    script = tmp_path / "sev.js"
    script.write_text(src + """
    const findings = [
      {title:"a", severity:"low",      state:"open"},
      {title:"b", severity:"medium",   state:"open"},
      {title:"c", severity:"critical", state:"new"},
      {title:"d", severity:"low",      state:"fixed"},
      {title:"e", severity:"nonsense", state:"open"},
      {title:"f", severity:"info",     state:"open"},
    ];
    const shown = (min) => secVisible(findings, min).map(f=>f.title).join("");
    console.log(JSON.stringify({info: shown("info"), low: shown("low"),
                                medium: shown("medium"), high: shown("high"),
                                unset: shown("")}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["info"] == "abcdef", "the true floor (info) must hide nothing"
    assert out["low"] == "abcde", "the lowest SELECTABLE floor must hide nothing real -- " \
        "and must hide info, which ranks below it"
    assert out["unset"] == "abcde", "no configured floor must behave like the lowest one"
    assert out["medium"] == "bcde", f"medium floor: {out['medium']}"
    assert out["high"] == "cde", f"high floor: {out['high']}"


def test_sev_order_ranks_info_as_the_lowest_severity(srv):
    """`info` has to be the FIRST entry in SEV_ORDER, not merely present in it
    somewhere: secSevRank ranks by array index, so a vocabulary that lists
    `info` anywhere but the bottom still parses, still passes every
    behavioural test that does not happen to construct an `info` finding, and
    still ranks it above whatever comes before it in the array -- which is
    exactly how this shipped once already, with `info` simply missing from
    SEV_ORDER and falling into secSevRank's above-critical fallback instead.
    """
    block = _security_js(srv)
    order = re.findall(
        r'"([a-z]+)"', re.search(r"const SEV_ORDER = \[(.*?)\];", block).group(1))
    assert order == ["info", "low", "medium", "high", "critical"], order


def test_no_severity_list_in_the_security_block_forgets_info(srv):
    """`info` joined the vocabulary as a legitimate severity, not a corrupted
    one -- so every hardcoded list of severities in this block (the posture
    pill loops, the summary pill loop, the counts object secPosture seeds)
    has to carry it too, or that one spot quietly falls back to treating
    `info` as unrecognised data. A structural scan rather than one assertion
    per call site, so the next hardcoded severity list added here is caught
    the same way the ones that already existed were -- `SEV_ORDER` itself is
    covered by test_sev_order_ranks_info_as_the_lowest_severity above, so it
    is excluded here to keep this test about the OTHER lists, not a
    duplicate of that one.
    """
    block = _security_js(srv)
    sev_order_src = re.search(r"const SEV_ORDER = \[.*?\];", block).group(0)
    scanned = block.replace(sev_order_src, "")
    four = {"critical", "high", "medium", "low"}
    offenders = []
    # Quoted-string arrays, e.g. ["critical","high","medium","low"].
    for m in re.finditer(r'\[\s*(?:"[a-z_]+"\s*,\s*)*"[a-z_]+"\s*\]', scanned):
        items = re.findall(r'"([a-z_]+)"', m.group(0))
        if four <= set(items) and "info" not in items:
            offenders.append(m.group(0))
    # Bare-key numeric objects, e.g. {critical:0, high:0, medium:0, low:0, other:0}.
    for m in re.finditer(
            r'\{\s*(?:[a-z_]+\s*:\s*\d+\s*,\s*)*[a-z_]+\s*:\s*\d+\s*\}', scanned):
        items = re.findall(r'([a-z_]+)\s*:\s*\d+', m.group(0))
        if four <= set(items) and "info" not in items:
            offenders.append(m.group(0))
    assert not offenders, f"severity list(s) in the Security block forget info: {offenders}"


def test_the_checklist_offers_every_state_the_engine_can_produce(srv):
    """Two lists in two languages, one vocabulary.

    The page cannot show a state it does not name, and a state missing from
    the chip row is a bucket of findings with no way to reach it. Read from
    the engine's own tuples so adding a state there fails here rather than
    quietly shipping a page that cannot display it.
    """
    block = _security_js(srv)
    shown = set(re.findall(
        r'"([a-z_]+)"', re.search(r"const SEC_STATES = \[(.*?)\];", block, re.S).group(1)))
    diff_src = (REPO / "bin" / "security" / "diff.py").read_text()
    ledger_src = (REPO / "bin" / "security" / "ledger.py").read_text()
    derived = set(re.findall(
        r'"([a-z_]+)"', re.search(r"DERIVED_STATES = \((.*?)\)", diff_src, re.S).group(1)))
    decided = set(re.findall(
        r'"([a-z_]+)"', re.search(r"DECISION_STATES = \((.*?)\)", ledger_src, re.S).group(1)))
    assert shown == derived | decided, (
        f"page shows {sorted(shown)}, engine produces {sorted(derived | decided)}")
    # And every one of them is a word on screen, not a bare enum value.
    for state in shown:
        assert f"{state}:" in block or f'"{state}":' in block, f"{state} has no label"


def test_the_run_link_finds_a_run_that_is_still_going(srv):
    """Structural, not behavioural: "Open the run" was reading DATA.runs alone.

    A run reaches the journal when it ENDS, so for the whole of an analysis in
    flight — the minutes anybody most wants to watch it, and the only place on
    this screen that shows what the agent is doing — the button was simply
    absent. The page already has one answer for "the runs going right now that
    the journal has not caught up with", and the Runs list uses it for the same
    reason: a slot not yet cleared for a run already journaled is one run
    listed twice.
    """
    fn = _plainfn(_security_js(srv), "secRunFor")
    assert "unjournaledLive()" in fn, "the run link cannot see a run that is still going"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_analysis_poll_cannot_outlive_the_view(srv, tmp_path):
    """Leaving the Security view has to stop the four-second poll, and stay
    stopped.

    secLeave() clears the interval, but secSyncPoll() decided on
    project-and-running alone — so a secReload() that was already in the air
    when the operator navigated away re-armed it a moment later, and the page
    went on making two subprocess-backed GETs every four seconds from the
    Overview, the Jobs page or anywhere else for the whole length of the
    analysis. The view belongs in the condition.
    """
    block = _security_js(srv)
    src = _plainfn(block, "secStopPoll") + "\n" + _plainfn(block, "secSyncPoll")
    script = tmp_path / "poll.js"
    script.write_text("""
    let live = 0;                       // intervals currently armed
    const SEC_POLL_MS = 4000;
    let secTimer = null;
    const secReload = () => {};
    globalThis.setInterval = () => { live++; return {}; };
    globalThis.clearInterval = () => { live--; };
    // The view is the page's and it changes under this area, so the area reads
    // it live off the interface rather than through a copy taken at startup.
    // That is what the stub has to be, or this harness proves nothing about
    // the code that actually ships.
    const CC = {currentView: "security"};
    const secState = {project:"web", analyses:[{state:"running"}]};
    """ + src + """
    const out = {};
    secSyncPoll();                       out.watching = live;
    CC.currentView = "overview";
    secSyncPoll();                       out.left = live;
    secSyncPoll();                       out.lateReload = live;
    CC.currentView = "security";
    secSyncPoll();                       out.cameBack = live;
    secState.analyses = [{state:"done"}];
    secSyncPoll();                       out.finished = live;
    console.log(JSON.stringify(out));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["watching"] == 1, "an analysis in flight on screen is not being watched"
    assert out["left"] == 0, "leaving the view left the poll running"
    assert out["lateReload"] == 0, "a reload landing after the view was left re-armed the poll"
    assert out["cameBack"] == 1, "coming back to the view did not resume watching"
    assert out["finished"] == 0, "the poll outlived the analysis"


def test_an_analysis_is_only_ever_started_through_its_own_op(srv):
    """Never a bare `run` of the derived job.

    `security_analyze` writes the request file — the branch, the profile and
    the analysis id — and only then starts the job. Running the job directly
    would make it re-read whatever request was left behind by the last
    analysis, and quietly report on the wrong branch.
    """
    block = _security_js(srv)
    assert 'api("security_analyze"' in block
    # Both quotings. The page writes double quotes throughout, but this guard is
    # here to stop an edit nobody reviews closely, and `api('run', …)` is the
    # same call — a denylist that only knows one spelling of a string literal is
    # a denylist with a door in it.
    for spelling in ('api("run"', "api('run'"):
        assert spelling not in block, \
            f"the Security view can start a bare run of the derived job: {spelling}"


def test_a_report_download_carries_the_token(srv):
    """Every GET on this API is behind the X-CC-Token header, which a plain
    `<a href="/api/security/report?…">` cannot attach — the browser would send
    the navigation without it and the operator would get a 401 as a file.

    Pinned to `secDownloadReport`, the fetch+Blob mechanism actions.js's
    secDownload and reports-tab.js's per-row buttons both now share (see its
    own comment for why this used to be two near-verbatim copies) — this
    property is about the shared helper's behaviour, not about which of its
    two callers happens to be named `secDownload`."""
    html = srv.render_page("boot-authed").split("<script>")[0]
    assert 'href="/api/security/report' not in html, "the report is linked, not fetched"
    block = _security_js(srv)
    dl = _plainfn(block, "secDownloadReport")
    assert "/api/security/report" in dl
    assert '"X-CC-Token":TOKEN' in dl or '"X-CC-Token": TOKEN' in dl


def test_every_download_the_server_offers_has_a_button(srv):
    """The SBOM was built on every analysis with a lockfile in it and there was
    no way to get it out. Bound to the server's own map so a format added there
    and forgotten on the page fails here, rather than shipping an inventory
    nobody can reach."""
    page = srv.render_page("boot-authed")
    block = _security_js(srv)
    for fmt in srv.REPORT_FORMATS:
        assert f'id="sec-dl-{fmt}"' in page, f"no download button for {fmt}"
        assert f'secDownload("{fmt}")' in block, f"nothing calls secDownload for {fmt}"


def test_the_sbom_download_is_named_the_way_its_tooling_expects(srv):
    """A fetch never turns the server's Content-Disposition into a download
    name, so the page builds the filename itself and the two have to agree by
    hand — REPORT_EXTENSIONS on one side, this on the other.

    Pinned to `secDownloadReport`, the same shared helper the test above
    targets — this filename rule applies to every caller (secDownload and
    the Reports tab's own buttons alike), not to one function's name."""
    dl = _plainfn(_security_js(srv), "secDownloadReport")
    assert srv.REPORT_EXTENSIONS["sbom"] == "cdx.json"
    assert "cdx.json" in dl


def test_the_downloads_say_they_are_not_filtered_by_the_severity_floor(srv):
    """`min_severity` hides findings from the LIST; the files contain
    everything. The gap between what is on screen and what is in the file you
    hand to somebody else is exactly where a reader assumes they match."""
    block = _security_js(srv)
    assert 'id="sec-dl-note"' in srv.render_page("boot-authed")
    assert "Downloads always contain every recorded finding" in block
    assert 'sec-dl-note").innerHTML' not in block, "the note is textContent, not markup"


def test_an_incomplete_analysis_says_so_on_the_page_and_not_only_in_the_file(srv):
    """`capped` and `failed` are PARTIAL reads of the repository, and the
    numbers under them are the numbers of a partial read: `critical: 0` means
    "none found before it stopped", not "none". The downloaded report opens
    with that notice (bin/security/report.py, _coverage) and the page — the
    thing everybody actually looks at — did not."""
    page = srv.render_page("boot-authed")
    assert 'id="sec-incomplete"' in page
    paint = _plainfn(_security_js(srv), "secPaint")
    assert 'a.state === "capped"' in paint and 'a.state === "failed"' in paint
    assert "INCOMPLETE" in paint
    # Same rule as every other line of this view: text, never markup.
    assert 'sec-incomplete").innerHTML' not in paint


# ---- the index screen's own renderer. Everything above this point drives
# the JSON contract (tests/security/test_cli.py, tests/test_security_api.py)
# but never the DOM the JSON is painted into -- so a regression in, say, the
# dash-versus-percent ternary or a fallback-branch note would have passed
# every one of those tests. This stub stands in for the DOM the real browser
# gives ui/security/index-screen.js: plain objects, no jsdom dependency,
# just enough of Element/Text/Node for secEl/secIcon (dom.js) and the
# createElement/createElementNS calls the screen's own functions make.

_INDEX_DOM_HARNESS = """
class FakeNode {
  constructor(){ this.childNodes = []; }
  appendChild(c){ this.childNodes.push(c); return c; }
  get textContent(){
    return this.childNodes.map(c => c.textContent).join("");
  }
  // Real DOM: assigning .textContent REPLACES a node's children with a
  // single new Text node -- it does not just remember a string on the side
  // that a later appendChild would silently shadow. Getting this wrong (an
  // earlier version of this stub tracked a separate `_text` fallback, read
  // only while childNodes stayed empty) made secEl(tag, cls, "some text")
  // followed by a later .appendChild(...) -- secOverviewCaption's own
  // "Posture of X" + a conditional fell-back span -- lose "some text"
  // entirely the moment the second child was appended, which no browser
  // ever would.
  set textContent(v){ this.childNodes = [new FakeText(String(v))]; }
}
class FakeElement extends FakeNode {
  constructor(tag){
    super();
    this.tagName = tag; this.className = ""; this.title = ""; this.style = {};
    this.hidden = false; this.disabled = false; this._attrs = {};
  }
  setAttribute(k, v){ this._attrs[k] = String(v); }
}
class FakeText extends FakeNode {
  constructor(t){ super(); this._text = String(t); }
  get textContent(){ return this._text; }
}
const document = {
  createElement: (tag) => new FakeElement(tag),
  createElementNS: (_ns, tag) => new FakeElement(tag),
  createTextNode: (t) => new FakeText(t),
};
// dom.js's secIcon is a thin pass to the page's own icon() -- stubbed here
// rather than pulled in whole, since the page's icon table is not what these
// tests are about. fmtAgo/fmtDur are page.js bindings filled in at runtime by
// bindPage() (see its own comment) -- not functions this block can extract,
// so they are stubbed the same way, deliberately trivial: these tests are
// about the branch name, the badge and the note, not the relative-time text.
function icon(_name){ return document.createElement("span"); }
function fmtAgo(t){ return "t" + String(t); }
function fmtDur(s){ return "d" + String(s); }
// Flattens a rendered node into a list of {cls, title, text} records, one per
// element in the tree -- `text` is each element's own aggregated
// textContent, so a search for a rendered word does not need to know which
// exact element it landed on.
function collectAll(n, out){
  out.push({cls: n.className || "", title: n.title || "", text: n.textContent || ""});
  (n.childNodes || []).forEach(c => collectAll(c, out));
  return out;
}
"""


def _index_screen_deps(block, *names):
    return "\n".join(_plainfn(block, n) for n in names)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_index_kpis_render_a_dash_not_zero_percent_when_nothing_finished(srv, tmp_path):
    """`success_rate: null` means "no finished analysis yet", not a
    zero-percent success rate -- two different facts (see the comment beside
    secIndexCards). Drives the real renderer under Node so a regression in
    the dash-versus-percent ternary actually fails a test, rather than only
    the JSON-contract tests in tests/security/test_cli.py and
    tests/test_security_api.py, neither of which ever paints anything."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCard", "secIndexCards")
    script = tmp_path / "kpi-dash.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 1, analyses: 0, critical: 0, high: 0,
                                  capped_projects: 0, success_rate: null});
    console.log(JSON.stringify(collectAll(cards, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    nums = [r["text"] for r in out if r["cls"] == "secidx-num"]
    assert "—" in nums, f"no dash rendered for a null success rate: {nums}"
    assert "0%" not in nums, f"a zero-percent rendered where a dash belongs: {nums}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_fallen_back_branch_is_rendered_with_its_name_visible(srv, tmp_path):
    """Postures of different branches must never be confused in silence --
    the branch a posture actually belongs to has to stay on the page, not
    just a bare "(fell back)" note with nothing named (see the comment on
    secIndexProjectRow's own tdBranch). Drives secIndexProjectsTable end to
    end rather than the JSON contract alone."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon",
                              "secIndexPosturePills", "secIndexProjectRow",
                              "secIndexProjectsTable")
    script = tmp_path / "branch-fellback.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const table = secIndexProjectsTable([{
      name: "web", description: "", branch: "develop", branch_fell_back: true,
      posture: {critical:0,high:0,medium:0,low:0,info:0,total:0},
      profile: "quick", last_started: 0, last_duration: 0, last_state: "done",
      analyses: 1}]);
    console.log(JSON.stringify(collectAll(table, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "develop" in joined, f"the fallen-back branch's own name is not on the page: {joined}"
    assert "fell back" in joined


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_capped_analysis_marks_its_project_row_with_an_incomplete_cue(srv, tmp_path):
    """The rendering half of finding 1: `default_branch_posture` hands the
    row's own state back as its fourth element (see queries.py), and a
    project whose latest finished analysis is `capped` is a PARTIAL read of
    the repository -- the identical notice secPaint already gives on the
    analysis screen ("critical: 0" there means "none found before it
    stopped," not "none"). The index screen used to render that posture
    with no cue at all -- not even the state word. This must fail against
    the code before finding 1's fix (no `last_state` branch existed in
    secIndexProjectRow) and pass after it."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon",
                              "secIndexPosturePills", "secIndexProjectRow",
                              "secIndexProjectsTable")
    script = tmp_path / "capped-row.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const table = secIndexProjectsTable([{
      name: "web", description: "", branch: "main", branch_fell_back: false,
      posture: {critical:0,high:0,medium:0,low:0,info:0,total:0},
      profile: "quick", last_started: 0, last_duration: 0, last_state: "capped",
      analyses: 1}]);
    console.log(JSON.stringify(collectAll(table, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out).lower()
    assert "incomplete" in joined, f"no cue rendered for a capped analysis's row: {out}"
    titled = " ".join(r["title"] for r in out if r["title"]).lower()
    assert "stopped" in titled and "incomplete" in titled, \
        f"no explanatory title on the capped cue: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_row_with_a_finished_latest_analysis_gets_no_capped_cue(srv, tmp_path):
    """Containment probe for the fix above: a project whose latest analysis
    actually finished (`done`) must NOT show the incomplete badge -- a cue
    that fires regardless of state would be worse than the missing one, a
    caution shown over posture that is not in doubt."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon",
                              "secIndexPosturePills", "secIndexProjectRow",
                              "secIndexProjectsTable")
    script = tmp_path / "capped-row-control.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const table = secIndexProjectsTable([{
      name: "web", description: "", branch: "main", branch_fell_back: false,
      posture: {critical:0,high:0,medium:0,low:0,info:0,total:0},
      profile: "quick", last_started: 0, last_duration: 0, last_state: "done",
      analyses: 1}]);
    console.log(JSON.stringify(collectAll(table, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out).lower()
    assert "incomplete" not in joined, f"a finished analysis got the capped cue: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_critical_and_high_kpi_cards_flag_incomplete_contributors(srv, tmp_path):
    """The other half of finding 1: when any project's latest analysis is
    capped, the Critical/High KPI cards must say how many, instead of
    presenting a fleet-wide total that looks complete."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCard", "secIndexCards")
    script = tmp_path / "kpi-capped.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 2, analyses: 3, critical: 1, high: 2,
                                  capped_projects: 1, success_rate: 1.0});
    console.log(JSON.stringify(collectAll(cards, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    notes = [r["text"] for r in out if r["cls"].startswith("secidx-note")]
    assert any("1" in n and "stopped" in n for n in notes), \
        f"no note names the incomplete contributor: {notes}"
    assert not any(n == "Open now, in every project's latest analysis" for n in notes), \
        "the plain note still shows even though a project's latest analysis is capped"

# ---- the project screen's own renderer (ui/security/project-screen.js).
# index-screen.js has the five Node-driven DOM tests above; this module had
# none, so a regression in the dash-for-zero check, the capped notice, tab
# hiding, or the two scope captions would have passed the whole suite. Same
# harness as _INDEX_DOM_HARNESS, extended with a tiny `$(id)` registry --
# project-screen.js reaches for real DOM ids (`sec-pj-head`,
# `sec-pj-overview`, ...) the way the real page's markup provides them,
# where the index screen's own builder functions only ever return a node to
# their caller and never look one up themselves.

_PROJECT_DOM_HARNESS = _INDEX_DOM_HARNESS + """
// classList is untouched by _INDEX_DOM_HARNESS's FakeElement (nothing there
// needed it) -- secRenderTabs toggles an "active" class on the tab buttons,
// so .toggle() has to exist and not throw; these tests never inspect it.
FakeElement.prototype.classList = { toggle(){} };
// project-screen.js imports $ and these page.js bindings directly (not
// through dom.js) -- fmtWhen/openProjectEditor are stubbed the same
// deliberately trivial way _INDEX_DOM_HARNESS already stubs fmtAgo/fmtDur:
// these tests are about the branch name, the notice text and which pane is
// hidden, not relative-time formatting or the project editor.
function fmtWhen(t){ return "w" + String(t); }
function openProjectEditor(_name){}
const secState = { project: "web" };
// A registry standing in for the real page's markup: $(id) in
// project-screen.js reaches for these ids the way document.getElementById
// would on the real page.
const _els = {};
function $(id){
  if(!_els[id]) _els[id] = new FakeElement("div");
  return _els[id];
}
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_project_header_renders_a_dash_not_zero_for_lines_of_code(srv, tmp_path):
    """`lines_of_code: 0` means "not counted" (every analysis before the
    column existed, or a project never analysed) -- rendering a bare `0`
    would read as an empty repository instead."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secHeaderBit", "secRenderProjectHeader"))
    script = tmp_path / "pj-loc.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectHeader({header: {profile: "standard", branch: "main",
      branch_fell_back: false, lines_of_code: 0, last_analysis: 0}});
    console.log(JSON.stringify(collectAll(_els["sec-pj-head"], [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    texts = [r["text"] for r in out]
    assert "—" in texts, f"no dash rendered for lines_of_code: 0: {texts}"
    assert "0" not in texts, f"a bare 0 rendered where a dash belongs: {texts}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_capped_latest_analysis_renders_the_incompleteness_notice(srv, tmp_path):
    """THE SAME notice secPaint gives on the old analysis screen and the
    index screen gives on a project row -- a capped analysis is a PARTIAL
    read, so the posture underneath is what it had reached, not what is
    there."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_STATES") + _const(block, "SEC_STATE_LABEL")
             + _const(block, "SEC_STATE_HELP"))
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secIndexPosturePills", "secOverviewCaption",
                      "secRenderProjectOverview"))
    script = tmp_path / "pj-capped.js"
    script.write_text(_PROJECT_DOM_HARNESS + consts + deps + """
    secRenderProjectOverview({
      header: {branch: "main", branch_fell_back: false},
      tabs: {overview: {state: "capped", attempted: true,
        posture: {critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1},
        checklist: {new: 0, regressed: 0, open: 1, partial: 0, pending: 0,
                    fixed: 0, accepted: 0, false_positive: 0}}}});
    console.log(JSON.stringify(collectAll(_els["sec-pj-overview"], [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "INCOMPLETE" in joined, f"no incompleteness notice rendered: {joined}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_switching_project_tabs_shows_one_pane_and_hides_the_other(srv, tmp_path):
    block = _security_js(srv)
    deps = _plainfn(block, "secRenderTabs") + "\n" + _plainfn(block, "secSwitchProjectTab")
    script = tmp_path / "pj-tabs.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secProjectTab = "overview";
    """ + deps + """
    secRenderTabs();
    const initial = {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden};
    secSwitchProjectTab("runs");
    const onRuns = {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden};
    secSwitchProjectTab("overview");
    const backToOverview = {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden};
    console.log(JSON.stringify({initial, onRuns, backToOverview}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["initial"] == {"ov": False, "rn": True}, "Overview must be the default pane"
    assert out["onRuns"] == {"ov": True, "rn": False}, "switching to Runs must hide Overview"
    assert out["backToOverview"] == {"ov": False, "rn": True}, \
        "switching back must hide Runs again, not leave both visible"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_two_scope_captions_name_the_branch_and_the_branch_count(srv, tmp_path):
    """Finding 1's fix: the Overview posture is ONE branch
    (default_branch_posture's own choice); the sidebar donut/categories span
    EVERY analysed branch. Both captions have to say so, by name and by
    count, or a two-branch project's different totals read as a silent
    disagreement -- and a one-branch project's caption must not imply more
    branches exist than it has (the containment half, in the same test since
    both captions come from the same two small functions)."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secOverviewCaption", "secSidebarCaption"))
    script = tmp_path / "pj-captions.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const fellBack = secOverviewCaption({branch: "develop", branch_fell_back: true});
    const plain = secOverviewCaption({branch: "main", branch_fell_back: false});
    const two = secSidebarCaption(2);
    const one = secSidebarCaption(1);
    const none = secSidebarCaption(0);
    console.log(JSON.stringify({
      fellBack: collectAll(fellBack, []).map(r => r.text).join(" "),
      plain: collectAll(plain, []).map(r => r.text).join(" "),
      two: collectAll(two, []).map(r => r.text).join(" "),
      one: collectAll(one, []).map(r => r.text).join(" "),
      none: collectAll(none, []).map(r => r.text).join(" "),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "develop" in out["fellBack"] and "fell back" in out["fellBack"], out["fellBack"]
    assert "main" in out["plain"] and "fell back" not in out["plain"], out["plain"]
    assert "2" in out["two"] and "branches" in out["two"], out["two"]
    assert "only analysed branch" in out["one"], \
        f"a single analysed branch must say so plainly: {out['one']}"
    assert "branches" not in out["one"], \
        f"a single-branch caption must not read as spanning several: {out['one']}"
    assert "0" not in out["none"], f"zero branches must not render a bare 0: {out['none']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_overview_tells_never_analysed_apart_from_never_finished(srv, tmp_path):
    """Finding 4's fix: a project whose every analysis failed has `state:
    ""` (no finished baseline) exactly like a project that was never
    touched, but `attempted: true` -- the Overview pane must show a
    different sentence for the two, not the same "Never analysed" over a
    Runs tab that lists real attempts."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secOverviewCaption", "secRenderProjectOverview"))
    script = tmp_path / "pj-attempted.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectOverview({header: {}, tabs: {overview: {state: "", attempted: false}}});
    const untouched = _els["sec-pj-overview"].textContent;
    _els["sec-pj-overview"] = new FakeElement("div");
    secRenderProjectOverview({header: {}, tabs: {overview: {state: "", attempted: true}}});
    const failed = _els["sec-pj-overview"].textContent;
    console.log(JSON.stringify({untouched, failed}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "Never analysed" in out["untouched"]
    assert "Never analysed" not in out["failed"], \
        f"a project with only failed attempts still says Never analysed: {out['failed']}"
    assert out["untouched"] != out["failed"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_project_poll_tick_skips_a_refresh_when_nothing_could_have_changed(srv, tmp_path):
    """Finding 2's other half: the root query-count fix (see
    tests/security/test_cli.py and test_queries.py) made a single
    project-data fetch cheap, but secReload() still called
    secRefreshProject() on every 4-second poll tick, unconditionally, for the
    whole length of a live analysis -- re-fetching a payload that provably
    had not changed. A poll tick now skips it unless the project's
    running/not-running shape actually moved since the last tick; every
    other caller (opening the project, an action) still forces it by leaving
    the argument at its default."""
    block = _security_js(srv)
    src = _anyfn(block, "secReload")
    script = tmp_path / "pj-poll-narrow.js"
    script.write_text("""
    let secProjectPollWasRunning = null;
    const CC = {currentView: "security"};
    const secState = {project: "web", repo: "web", branch: "main", analysis: null, analyses: []};
    let refreshCalls = 0;
    function secRefreshProject(){ refreshCalls++; }
    function secSyncPoll(){}
    function secStopPoll(){}
    async function secShowAnalysis(_id){}
    let nextAnalyses = [];
    async function secFetch(_path){ return nextAnalyses; }
    """ + src + """
    (async () => {
      const out = {};
      nextAnalyses = [{id: 1, repo: "web", branch: "main", state: "running"}];
      await secReload(false);                 // first poll tick ever -- must refresh
      out.firstTick = refreshCalls;

      await secReload(false);                 // still running, nothing changed
      out.steadyWhileRunning = refreshCalls;

      nextAnalyses = [{id: 1, repo: "web", branch: "main", state: "done"}];
      await secReload(false);                 // the run just finished -- must refresh
      out.justFinished = refreshCalls;

      await secReload(false);                 // still done, nothing changed
      out.steadyAfterFinish = refreshCalls;

      await secReload();                      // an action-triggered call -- always forces
      out.forcedCall = refreshCalls;

      console.log(JSON.stringify(out));
    })();
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["firstTick"] == 1, "the first poll tick must still refresh once"
    assert out["steadyWhileRunning"] == 1, \
        f"a poll tick with no state change must not re-fetch: {out}"
    assert out["justFinished"] == 2, \
        f"the run finishing must trigger exactly one more refresh: {out}"
    assert out["steadyAfterFinish"] == 2, \
        f"a poll tick after the run is done, with nothing new, must not re-fetch: {out}"
    assert out["forcedCall"] == 3, "a forced (non-poll) call must always refresh"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_project_runs_header_names_what_its_own_column_recorded(srv, tmp_path):
    """Review finding (IMPORTANT): the Runs table's own FINDINGS column is
    `finding_counts_by_analysis`'s plain per-analysis COUNT(*), but clicking
    a row renders that same analysis's checklist chips from `checklist()`,
    which also carries forward findings that disappeared since the branch's
    previous analysis, marked `fixed` or `pending` -- a row's own two numbers
    can legitimately differ (see tests/security/test_queries.py's
    reproduction, and finding_counts_by_analysis's docstring). The bare,
    ambiguous "Findings" header is renamed to name the fact it counts, with
    a `title` explaining the distinction, rather than either number being
    changed to match the other."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in ("secEl", "secRunRow", "secRunsTable"))
    script = tmp_path / "pj-runs-header.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secRunsFilter = "";
    """ + deps + """
    const wrap = secRunsTable([{id: 2, profile: "quick", repo: "web", branch: "main",
      commit_sha: "abc123def456", started: 100, ended: 110, findings: 1, state: "done"}]);
    const thead = wrap.childNodes[0].childNodes[0];
    const htr = thead.childNodes[0];
    const headers = htr.childNodes.map(th => ({text: th.textContent, title: th.title}));
    console.log(JSON.stringify(headers));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    texts = [h["text"] for h in out]
    assert "Findings" not in texts, \
        f"the bare, ambiguous header must be gone, not merely supplemented: {texts}"
    findings_header = next((h for h in out if "findings" in h["text"].lower()), None)
    assert findings_header is not None, f"no findings-shaped header rendered at all: {texts}"
    assert findings_header["text"] == "Findings recorded", \
        f"the column must be renamed to say what it counts: {texts}"
    title = findings_header["title"].lower()
    assert "checklist" in title and "previous analysis" in title, \
        f"the header's title must explain why the checklist below can total more: {title!r}"


# ---- Task 10: the Branches and Reports tabs (ui/security/branches-tab.js,
# ui/security/reports-tab.js). Same reasoning as the project screen's own
# Node-driven tests above -- the JSON contract in tests/security/test_cli.py
# never paints anything, so a regression in the caption wording, the trend
# direction, the pane-hiding or the four download buttons would pass every
# test in that file.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_branches_tab_renders_one_row_per_branch_with_its_own_posture(srv, tmp_path):
    """Two branches, each with its own last-analysis time, analysis count,
    open posture and 30-day trend -- and the caption naming how a branch's
    own open count relates to the sidebar's cross-branch, deduplicated
    total, the same review-fix reasoning project-screen.js's own
    secOverviewCaption/secSidebarCaption already carry, applied here to a
    third number on the same screen."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIndexPosturePills", "secBranchesCaption",
                      "secBranchTrendText", "secBranchRow", "secBranchesTable",
                      "secRenderProjectBranches"))
    script = tmp_path / "pj-branches.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectBranches({tabs: {branches: [
      {branch: "develop", last_analysis: 1700000000, analyses: 2,
       open: {critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1},
       trend: [{analysis_id: 1, started: 1, open: 2}, {analysis_id: 2, started: 2, open: 1}]},
      {branch: "main", last_analysis: 1700000100, analyses: 1,
       open: {critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0},
       trend: []},
    ]}});
    console.log(JSON.stringify(collectAll(_els["sec-pj-branches"], [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "develop" in joined and "main" in joined, f"a branch name is missing: {joined}"
    assert "1 critical" in joined, f"the open posture pill did not render: {joined}"
    assert "nothing open" in joined, f"the clean branch's pill did not render: {joined}"
    assert "falling" in joined, f"the trend direction did not render: {joined}"
    assert "No analyses of this branch in the last 30 days" in joined, \
        f"the branch with no recent trend point got no explanation: {joined}"
    assert "sidebar's donut" in joined, \
        f"the caption explaining the scope difference from the sidebar is missing: {joined}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_branch_trend_text_names_the_direction_not_just_the_numbers(srv, tmp_path):
    """Pure and DOM-free, driven directly: 0, 1 and 2+ points each need their
    own sentence -- a bare number pair with no "rising"/"falling"/"flat"
    word would force the reader to do the comparison the page exists to do
    for them."""
    block = _security_js(srv)
    fn = _plainfn(block, "secBranchTrendText")
    script = tmp_path / "trend.js"
    script.write_text(fn + """
    console.log(JSON.stringify({
      none: secBranchTrendText([]),
      one: secBranchTrendText([{analysis_id: 1, started: 1, open: 3}]),
      falling: secBranchTrendText([{open: 5}, {open: 1}]),
      rising: secBranchTrendText([{open: 1}, {open: 5}]),
      flat: secBranchTrendText([{open: 2}, {open: 2}]),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "No analyses" in out["none"]
    assert "3" in out["one"] and "nothing yet to compare" in out["one"]
    assert "falling" in out["falling"] and "5 → 1" in out["falling"], out["falling"]
    assert "rising" in out["rising"] and "1 → 5" in out["rising"], out["rising"]
    assert "flat" in out["flat"], out["flat"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_branch_trend_text_refuses_a_direction_the_whole_series_does_not_support(srv, tmp_path):
    """Review finding 1's own reproduction. `secBranchTrendText` used to read
    only the first and last point, so a branch that spiked to 40 open
    findings and was almost entirely fixed (5, 40, 6) rendered "5 → 6 ...
    (rising)" -- the opposite of what happened -- and a branch that dipped to
    5 and climbed back to 45 from a start of 50 (50, 5, 45) rendered
    "falling". Neither direction word is true for the WHOLE three-point
    series, so neither may appear; the peak/trough the endpoints alone hide
    is what the line says instead. A three-or-more-point series that IS
    monotonic (or entirely flat) still gets its direction word, since it is
    then true for the whole series, not just its ends."""
    block = _security_js(srv)
    fn = _plainfn(block, "secBranchTrendText")
    script = tmp_path / "trend3.js"
    script.write_text(fn + """
    console.log(JSON.stringify({
      spikeThenFixed: secBranchTrendText([{open: 5}, {open: 40}, {open: 6}]),
      dipThenClimbed: secBranchTrendText([{open: 50}, {open: 5}, {open: 45}]),
      flatThree: secBranchTrendText([{open: 9}, {open: 9}, {open: 9}]),
      monotoneThree: secBranchTrendText([{open: 1}, {open: 2}, {open: 3}]),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "5 → 6" in out["spikeThenFixed"], out["spikeThenFixed"]
    assert "rising" not in out["spikeThenFixed"], \
        f"a spike that was fixed still claims to be rising: {out['spikeThenFixed']}"
    assert "peaked at 40" in out["spikeThenFixed"], \
        f"the peak the endpoints hide is not named: {out['spikeThenFixed']}"

    assert "50 → 45" in out["dipThenClimbed"], out["dipThenClimbed"]
    assert "falling" not in out["dipThenClimbed"], \
        f"a branch that dipped and climbed back still claims to be falling: {out['dipThenClimbed']}"
    assert "dipped to 5" in out["dipThenClimbed"], \
        f"the dip the endpoints hide is not named: {out['dipThenClimbed']}"

    assert "flat" in out["flatThree"], out["flatThree"]
    assert "rising" in out["monotoneThree"] and "falling" not in out["monotoneThree"], \
        f"a genuinely monotonic three-point series lost its direction word: {out['monotoneThree']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_branches_tab_tells_never_analysed_apart_from_every_attempt_failed(srv, tmp_path):
    """Review finding 3. `secBranchesTable`'s empty state used to say "No
    branch of this project has been analysed yet" whether nothing was ever
    attempted or every attempt failed, even though `secRenderProjectBranches`
    already receives `tabs.overview.attempted` in the same payload --
    the identical flag `secRenderProjectOverview` already uses (see
    project-screen.js's own comment on `ov.attempted`) to draw exactly this
    distinction one tab over. A project whose every analysis failed used to
    show two sibling tabs contradicting each other."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIndexPosturePills", "secBranchesCaption",
                      "secBranchTrendText", "secBranchRow", "secBranchesTable",
                      "secRenderProjectBranches"))
    script = tmp_path / "pj-branches-empty.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectBranches({tabs: {overview: {attempted: false}, branches: []}});
    const neverAttempted = _els["sec-pj-branches"].textContent;
    secRenderProjectBranches({tabs: {overview: {attempted: true}, branches: []}});
    const attemptedNoneFinished = _els["sec-pj-branches"].textContent;
    console.log(JSON.stringify({neverAttempted, attemptedNoneFinished}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "Never analysed" in out["neverAttempted"], out["neverAttempted"]
    assert "finished yet" in out["attemptedNoneFinished"], out["attemptedNoneFinished"]
    assert out["neverAttempted"] != out["attemptedNoneFinished"], \
        "never-attempted and attempted-but-failed render identically"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_reports_tab_renders_one_row_per_analysis_with_four_downloads(srv, tmp_path):
    """One row per analysis regardless of state (a running one still gets a
    row -- see cmd_project_data's own docstring), four download buttons
    each, and the SBOM caveat spelled out: it hands back the branch's
    CURRENT document, not a snapshot of the analysis the row is for."""
    block = _security_js(srv)
    consts = _const(block, "SEC_REPORT_FORMATS")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secReportsCaption", "secReportRow",
                      "secReportsTable", "secRenderProjectReports"))
    script = tmp_path / "pj-reports.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    function secDownloadReport(){}
    """ + consts + deps + """
    secRenderProjectReports({tabs: {reports: [
      {analysis_id: 7, branch: "main", started: 1700000000, state: "done"},
      {analysis_id: 8, branch: "develop", started: 1700000100, state: "running"},
    ]}});
    const host = _els["sec-pj-reports"];
    function countButtons(n, c){
      (n.childNodes || []).forEach(x => { if(x.tagName === "button") c.n++; countButtons(x, c); });
      return c;
    }
    console.log(JSON.stringify({
      rows: collectAll(host, []),
      buttons: countButtons(host, {n: 0}).n,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out["rows"])
    assert "#7" in joined and "#8" in joined, f"an analysis id is missing: {joined}"
    assert "main" in joined and "develop" in joined
    assert "done" in joined and "running" in joined
    assert out["buttons"] == 8, f"expected 4 download buttons per row over 2 rows: {out['buttons']}"
    assert "CURRENT document" in joined, f"the SBOM caveat is missing: {joined}"
    assert "every recorded finding" in joined, f"the severity-floor note is missing: {joined}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_switching_to_branches_or_reports_hides_the_other_three_panes(srv, tmp_path):
    """The two-tab version of this guard (test_switching_project_tabs_shows_
    one_pane_and_hides_the_other) predates these two tabs; this is the same
    proof extended to all four, so a tab added without updating secRenderTabs
    would leave two panes visible at once instead of failing here."""
    block = _security_js(srv)
    deps = _plainfn(block, "secRenderTabs") + "\n" + _plainfn(block, "secSwitchProjectTab")
    script = tmp_path / "pj-tabs-4.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secProjectTab = "overview";
    """ + deps + """
    function hidden(){
      return {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden,
              br: _els["sec-pj-branches"].hidden, rp: _els["sec-pj-reports"].hidden};
    }
    secRenderTabs();
    const initial = hidden();
    secSwitchProjectTab("branches");
    const onBranches = hidden();
    secSwitchProjectTab("reports");
    const onReports = hidden();
    secSwitchProjectTab("overview");
    const backToOverview = hidden();
    console.log(JSON.stringify({initial, onBranches, onReports, backToOverview}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["initial"] == {"ov": False, "rn": True, "br": True, "rp": True}
    assert out["onBranches"] == {"ov": True, "rn": True, "br": False, "rp": True}
    assert out["onReports"] == {"ov": True, "rn": True, "br": True, "rp": False}
    assert out["backToOverview"] == {"ov": False, "rn": True, "br": True, "rp": True}


def test_the_runs_table_observes_but_never_manages_a_security_run(srv):
    """On a security-* row only the eye and Stop stay live: resume ran on a
    consumed request, and delete erases the transcript the Security page's
    "Open the run" points at."""
    page = srv.render_page("boot-authed")
    assert 'String(r.id||"").startsWith("security-")' in page
    assert "A security analysis is never resumed" in page
    assert "the Security area owns its lifecycle" in page


# ---- Task 11: the findings browser (ui/security/findings-screen.js). Same
# reasoning as the project screen's and the Branches/Reports tabs' own
# Node-driven tests above -- the JSON contract in tests/test_security_api.py
# never paints anything, so a regression in the total-vs-unique labelling, the
# severity-floor note, the fixed-finding exemption, the sort-header click
# logic or the pager math would pass every test in that file.
#
# secSevRank/secSevKey/secStateKey and secMinSeverity are `const NAME = (...)
# => ...` arrow functions in vocabulary.js, not `function NAME(...)`
# declarations -- `_plainfn`/`_anyfn` cannot extract them (both look for the
# literal substring "function NAME("), and `_const` cannot either (it only
# handles a `[`/`{`-opening value, not `(`). secSevRank is extracted the same
# ad hoc way test_the_severity_floor_filters_the_page_and_nothing_else already
# extracts it a few hundred lines above -- a non-greedy regex up to the
# arrow's own closing "};" -- and secMinSeverity is stubbed outright: these
# tests are about THIS module's floor-handling, not about how a project's
# configured min_severity is read, the same deliberately-trivial-stub
# reasoning _INDEX_DOM_HARNESS already applies to fmtAgo/fmtDur.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_findings_row_renders_analysed_strings_as_text_never_markup(srv, tmp_path):
    """A finding's title and file path come from analysed code, and a branch
    name may legally contain '<', '>' and '&' (see vocabulary.js's own file
    comment -- the one rule this whole area exists to keep). Also proves a
    non-fixed finding gets both decision buttons."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_STATE_LABEL") + _const(block, "SEC_STATE_HELP")
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES"))
    arrows = (re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secFindRow", "secFindDecisionControls"))
    script = tmp_path / "find-row.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    const fs = {project: "web"};
    """ + consts + arrows + deps + """
    const row = secFindRow(fs, {title: "<img src=x onerror=alert(1)>", severity: "high",
      state: "new", category: "sast", branch: "feature/<b>bold</b>", first_seen: 1700000000,
      occurrences: [{file: "a.py", line: 1}, {file: "b.py", line: 2}], fingerprint: "a".repeat(64)});
    function countButtons(n, c){
      (n.childNodes || []).forEach(x => { if(x.tagName === "button") c.n++; countButtons(x, c); });
      return c;
    }
    console.log(JSON.stringify({rows: collectAll(row, []), buttons: countButtons(row, {n: 0}).n}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out["rows"])
    assert "<img src=x onerror=alert(1)>" in joined, \
        f"the raw markup must reach the page as literal TEXT, unmangled: {joined}"
    assert "feature/<b>bold</b>" in joined, f"the branch name lost its literal markup: {joined}"
    assert "a.py:1 (+1 more)" in joined, f"the occurrence summary is missing: {joined}"
    assert out["buttons"] == 2, f"a non-fixed finding must offer both decision buttons: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_fixed_finding_gets_no_decision_controls(srv, tmp_path):
    """A fixed finding is gone: there is nothing left to accept or dismiss --
    the same rule analysis.js's own secFindingRow already follows."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_STATE_LABEL") + _const(block, "SEC_STATE_HELP")
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES"))
    arrows = (re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secFindRow", "secFindDecisionControls"))
    script = tmp_path / "find-row-fixed.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    const fs = {project: "web"};
    """ + consts + arrows + deps + """
    const row = secFindRow(fs, {title: "t", severity: "low", state: "fixed", category: "sast",
      branch: "main", first_seen: 1, occurrences: [], fingerprint: "a".repeat(64)});
    function countButtons(n, c){
      (n.childNodes || []).forEach(x => { if(x.tagName === "button") c.n++; countButtons(x, c); });
      return c;
    }
    console.log(JSON.stringify({buttons: countButtons(row, {n: 0}).n}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["buttons"] == 0, f"a fixed finding must not offer Accept risk / False positive: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_strip_labels_total_and_unique_and_counts_the_floor_from_the_whole_filtered_set(
        srv, tmp_path):
    """Total vs unique must both appear, labelled distinctly -- 189 findings
    can be 93 problems, and collapsing the two into one number silently
    answers whichever question the reader was not asking. And the count of
    what the severity floor hides has to come from `by_severity` (every row
    the current filters match, computed by finding_rows BEFORE pagination),
    not from whatever slice of rows happens to be on THIS page -- a browser
    with several pages would otherwise undercount how much the floor hides."""
    block = _security_js(srv)
    consts = _const(block, "SEV_ORDER")
    deps = "\n".join(_plainfn(block, n) for n in ("secEl", "secFindHiddenByFloor", "secFindStrip"))
    script = tmp_path / "find-strip.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function secMinSeverity(_p){ return "medium"; }
    const fs = {project: "web"};
    """ + consts + deps + """
    // by_severity describes EVERY row the current filters match, across every
    // page -- 3 low + 2 info sit below the "medium" floor, even though this
    // fabricated payload carries no `rows` at all for secFindStrip to look at.
    const data = {total: 10, unique: 8,
      by_severity: {critical: 1, high: 4, medium: 0, low: 3, info: 2}, page: 1, per_page: 25};
    console.log(JSON.stringify(collectAll(secFindStrip(fs, data), [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "10 total" in joined and "8 unique issues" in joined, \
        f"total and unique must both render, distinctly labelled: {joined}"
    assert "5 findings below medium" in joined, \
        f"the hidden count must be 3 low + 2 info = 5, read from by_severity: {joined}"
    assert "every recorded finding" in joined, "the downloads-are-unfiltered sentence is missing"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_table_excludes_rows_below_the_floor_on_this_page(srv, tmp_path):
    """The display half of the same floor: a row below the configured
    min_severity must not appear in the table itself, on top of the strip's
    own count of how many are missing."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_STATE_LABEL") + _const(block, "SEC_STATE_HELP")
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES")
             + _const(block, "FIND_SORT_COLUMNS"))
    arrows = (re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
             + re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secFindRow", "secFindDecisionControls", "secFindTableSection",
                      "secVisible"))
    script = tmp_path / "find-table-floor.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    function secMinSeverity(_p){ return "high"; }
    const fs = {project: "web", sort: "severity", dir: "desc", page: 1};
    """ + consts + arrows + deps + """
    const data = {rows: [
      {title: "crit one", severity: "critical", state: "new", category: "sast", branch: "main",
       first_seen: 1, occurrences: [], fingerprint: "a".repeat(64)},
      {title: "low one", severity: "low", state: "new", category: "sast", branch: "main",
       first_seen: 1, occurrences: [], fingerprint: "b".repeat(64)},
    ], total: 2, unique: 2, page: 1, per_page: 25};
    console.log(JSON.stringify(collectAll(secFindTableSection(fs, data), [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "crit one" in joined, f"a row at or above the floor must render: {joined}"
    assert "low one" not in joined, f"a row below the floor must not appear in the table: {joined}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_fixed_finding_stays_visible_and_uncounted_below_the_floor(srv, tmp_path):
    """Review finding 3: the browser used to apply the severity floor
    uniformly, with no per-state exception -- so with "Show resolved" on, a
    low-severity finding that had just been marked FIXED disappeared under a
    medium floor exactly like an open one would, hiding the one thing this
    view exists to confirm: that the fix actually landed.
    vocabulary.js's own `secVisible` already exempts a fixed finding from
    the checklist's floor for exactly this reason (see its own comment) --
    this pins that the findings browser now shares the exemption (calling
    `secVisible` itself, not re-deriving it), and that the strip's own
    "N hidden" count (`fixed_by_severity`, queries.finding_rows's new field)
    agrees with what the table shows.

    An OPEN low-severity finding is both hidden from the table AND counted,
    the containment probe proving the fix does not blanket-exempt an entire
    severity -- only a fixed row. Must fail on the code before this fix (a
    bare severity-rank filter hid the fixed row too, and the hidden count
    read `by_severity` alone, counting BOTH low findings as hidden) and pass
    after it."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_STATE_LABEL") + _const(block, "SEC_STATE_HELP")
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES")
             + _const(block, "FIND_SORT_COLUMNS"))
    arrows = (re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
             + re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secFindHiddenByFloor", "secFindStrip", "secFindRow",
                      "secFindDecisionControls", "secFindTableSection", "secVisible"))
    script = tmp_path / "find-fixed-floor.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    function secMinSeverity(_p){ return "medium"; }
    const fs = {project: "web", sort: "severity", dir: "desc", page: 1};
    """ + consts + arrows + deps + """
    const data = {
      rows: [
        {title: "fixed low", severity: "low", state: "fixed", category: "sast",
         branch: "main", first_seen: 1, occurrences: [], fingerprint: "a".repeat(64)},
        {title: "open low", severity: "low", state: "open", category: "sast",
         branch: "main", first_seen: 1, occurrences: [], fingerprint: "b".repeat(64)},
        {title: "open medium", severity: "medium", state: "open", category: "sast",
         branch: "main", first_seen: 1, occurrences: [], fingerprint: "c".repeat(64)},
      ],
      total: 3, unique: 3,
      by_severity: {critical: 0, high: 0, medium: 1, low: 2, info: 0},
      fixed_by_severity: {critical: 0, high: 0, medium: 0, low: 1, info: 0},
      page: 1, per_page: 25,
    };
    const strip = collectAll(secFindStrip(fs, data), []);
    const table = collectAll(secFindTableSection(fs, data), []);
    console.log(JSON.stringify({strip, table}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    stripText = " ".join(r["text"] for r in out["strip"])
    tableText = " ".join(r["text"] for r in out["table"])
    assert "1 finding below medium" in stripText, \
        f"exactly one finding (the OPEN low one) must count as hidden: {stripText}"
    assert "2 findings below medium" not in stripText, \
        f"the fixed row must not inflate the hidden count: {stripText}"
    assert "fixed low" in tableText, \
        f"a FIXED finding must stay visible below the floor: {tableText}"
    assert "open medium" in tableText, f"a finding at or above the floor must render: {tableText}"
    assert "open low" not in tableText, \
        f"an OPEN finding below the floor must still be hidden -- the exemption is fixed-only: {tableText}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_clicking_a_sort_header_toggles_direction_then_switching_column_resets_it(
        srv, tmp_path):
    """Clicking the ALREADY-active column flips its direction and resets the
    page (a new sort order makes the old page number meaningless); clicking a
    DIFFERENT column switches to it with a fresh default direction, also
    resetting the page."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_STATE_LABEL") + _const(block, "SEC_STATE_HELP")
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES")
             + _const(block, "FIND_SORT_COLUMNS"))
    arrows = (re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
             + re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secFindRow", "secFindDecisionControls", "secFindTableSection",
                      "secVisible"))
    script = tmp_path / "find-sort-click.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    function secMinSeverity(_p){ return "info"; }
    const fs = {project: "web", sort: "severity", dir: "desc", page: 3};
    let refreshCalls = 0;
    function secFindRefresh(_fs){ refreshCalls++; }
    """ + consts + arrows + deps + """
    const data = {rows: [{title: "a", severity: "low", state: "new", category: "sast",
      branch: "main", first_seen: 1, occurrences: [], fingerprint: "a".repeat(64)}],
      total: 1, unique: 1, page: 3, per_page: 25};
    const section = secFindTableSection(fs, data);
    const headerRow = section.childNodes[0].childNodes[0].childNodes[0];
    const severityBtn = headerRow.childNodes[0].childNodes[0];
    const titleBtn = headerRow.childNodes[1].childNodes[0];
    severityBtn.onclick();
    const afterToggle = {sort: fs.sort, dir: fs.dir, page: fs.page, calls: refreshCalls};
    titleBtn.onclick();
    const afterSwitch = {sort: fs.sort, dir: fs.dir, page: fs.page, calls: refreshCalls};
    console.log(JSON.stringify({afterToggle, afterSwitch}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["afterToggle"] == {"sort": "severity", "dir": "asc", "page": 1, "calls": 1}, \
        out["afterToggle"]
    assert out["afterSwitch"] == {"sort": "title", "dir": "asc", "page": 1, "calls": 2}, \
        out["afterSwitch"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_pager_math_and_button_disabling_at_both_edges(srv, tmp_path):
    block = _security_js(srv)
    deps = _plainfn(block, "secEl") + "\n" + _plainfn(block, "secFindPager")
    script = tmp_path / "find-pager.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function secFindRefresh(_fs){}
    const fs = {page: 1};
    """ + deps + """
    function btns(p){
      return {prevDisabled: p.childNodes[0].disabled, nextDisabled: p.childNodes[2].disabled,
              text: p.childNodes[1].textContent};
    }
    console.log(JSON.stringify({
      first: btns(secFindPager(fs, {total: 47, per_page: 25, page: 1})),
      last: btns(secFindPager(fs, {total: 47, per_page: 25, page: 2})),
      empty: btns(secFindPager(fs, {total: 0, per_page: 25, page: 1})),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["first"]["prevDisabled"] is True and out["first"]["nextDisabled"] is False
    assert "Page 1 / 2" in out["first"]["text"] and "47 rows" in out["first"]["text"]
    assert out["last"]["prevDisabled"] is False and out["last"]["nextDisabled"] is True
    assert out["empty"]["prevDisabled"] is True and out["empty"]["nextDisabled"] is True
    assert "1 / 1" in out["empty"]["text"] and "0 rows" in out["empty"]["text"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_switching_to_findings_hides_the_other_four_panes(srv, tmp_path):
    """The five-pane version of test_switching_to_branches_or_reports_hides_
    the_other_three_panes above, extended for the tab this task adds -- a
    fifth pane added without teaching secRenderTabs about it would leave two
    panes visible at once instead of failing here. renderFindings is stubbed:
    this test is about which PANE is hidden, not about what paints inside it
    (see the tests above for that)."""
    block = _security_js(srv)
    deps = _plainfn(block, "secRenderTabs") + "\n" + _plainfn(block, "secSwitchProjectTab")
    script = tmp_path / "pj-tabs-5.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secProjectTab = "overview";
    function renderFindings(_host, _project){}
    """ + deps + """
    function hidden(){
      return {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden,
              br: _els["sec-pj-branches"].hidden, fd: _els["sec-pj-findings"].hidden,
              rp: _els["sec-pj-reports"].hidden};
    }
    secRenderTabs();
    const initial = hidden();
    secSwitchProjectTab("findings");
    const onFindings = hidden();
    secSwitchProjectTab("reports");
    const onReports = hidden();
    secSwitchProjectTab("overview");
    const backToOverview = hidden();
    console.log(JSON.stringify({initial, onFindings, onReports, backToOverview}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["initial"] == {"ov": False, "rn": True, "br": True, "fd": True, "rp": True}
    assert out["onFindings"] == {"ov": True, "rn": True, "br": True, "fd": False, "rp": True}
    assert out["onReports"] == {"ov": True, "rn": True, "br": True, "fd": True, "rp": False}
    assert out["backToOverview"] == {"ov": False, "rn": True, "br": True, "fd": True, "rp": True}


def test_the_search_field_names_what_it_actually_searches(srv):
    """Review finding 2 on Task 11: `queries.finding_rows`'s own `q` filter
    searches `title`, `rule`, `rationale` and every occurrence's file path
    (see its own code) -- but the field was labelled "Search title / rule /
    CVE / file", which both promises a "CVE" field that does not exist (for
    a dependency finding it is folded into `rule`) and never mentions
    `rationale`, the one place someone searching for remembered text is most
    likely to find it. The label must name what the filter actually reaches,
    not what a reader would guess it does."""
    block = _security_js(srv)
    assert "Search title / rule / rationale / file" in block, \
        "the search field must name rationale, the field it actually searches"
    assert "Search title / rule / CVE / file" not in block, \
        "the old label still promises a field ('CVE') that finding_rows does not search"


# ---- Review finding 1 on Task 11: the browser's own header comment claimed
# it made "no assumption about who else is on screen beside it", but every
# piece of state (host, project, filters, sort, page, the fetch generation)
# was a single module-level variable -- so two simultaneous mounts of the
# SAME project into different hosts (today: only project-screen.js's
# Findings tab mounts this; Task 12's own plan is to link a fingerprint
# straight into this browser from the Activity screen, open BESIDE it) would
# stomp each other's state, and whichever fetch answered second would fail
# its own staleness guard against a "current host" that had moved on to the
# other mount, leaving that pane frozen on "Loading…" forever. The fix keys
# every mount's state by its host in a WeakMap (`secFindStates`); the tests
# below drive the real renderFindings/secFindLoad/secFindPaint under Node,
# stubbing only the four child painters (secFindStrip/secFindFilterBar/
# secFindTableSection/secFindPager) that the other Task 11 tests above
# already exercise on their own -- these are about which HOST a fetch's
# result reaches, not what gets drawn inside it.

_FIND_MOUNT_DEPS = ("_defaultFilters", "_newFindState", "secFindQuery", "secEl", "secIcon",
                    "secFindPaint")


def _find_mount_harness(block, extra=""):
    weakmap_decl = re.search(r"const secFindStates = new WeakMap\(\);", block)
    assert weakmap_decl, "secFindStates must be declared as a WeakMap -- see the test below"
    per_page = re.search(r"const FIND_PER_PAGE = \d+;", block)
    assert per_page, "FIND_PER_PAGE not found -- secFindQuery needs it"
    deps = "\n".join(_plainfn(block, n) for n in _FIND_MOUNT_DEPS)
    render_findings = _anyfn(block, "renderFindings")
    find_load = _anyfn(block, "secFindLoad")
    return (_INDEX_DOM_HARNESS + extra + weakmap_decl.group(0) + "\n" + per_page.group(0) + "\n"
            + deps + "\n" + render_findings + "\n" + find_load)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_two_mounts_of_the_same_project_never_share_state_or_steal_each_others_paint(
        srv, tmp_path):
    """The adversarial case the finding names: mount host A, mount host B
    (same project) before A's fetch has answered, then resolve B's fetch
    FIRST and A's SECOND -- the exact interleaving that starves whichever
    mount answers later under the old, module-level code. Must fail before
    the fix (host A's own late-arriving fetch reads a module `secFindHost`
    that by then points at host B, fails its staleness guard, and A's pane
    never repaints) and pass after it (each host's own state, looked up by
    identity in the WeakMap, is untouched by the other mount)."""
    block = _security_js(srv)
    script = tmp_path / "two-mounts.js"
    script.write_text(_find_mount_harness(block, """
    // Trivial stand-ins: this test is about which host/state a fetch's
    // result reaches, not what secFindStrip/secFindFilterBar/
    // secFindTableSection/secFindPager actually draw (see the tests above
    // for that) -- each just marks the host with the data it received.
    function secFindStrip(_fs, data){ return secEl("div", "marker", "strip:" + data.marker); }
    function secFindFilterBar(_fs, _data){ return secEl("div", "fb", ""); }
    function secFindTableSection(_fs, _data){ return secEl("div", "ts", ""); }
    function secFindPager(_fs, _data){ return secEl("div", "pg", ""); }
    """) + """
    // A controllable secFetch: each call returns its own independently
    // resolvable promise, queued in call order -- so the test can resolve
    // the SECOND call before the FIRST.
    const resolvers = [];
    function secFetch(_path){
      return new Promise((resolve) => { resolvers.push(resolve); });
    }

    (async () => {
      const hostA = new FakeElement("div");
      const hostB = new FakeElement("div");
      const pA = renderFindings(hostA, "web");   // fetch #0
      const pB = renderFindings(hostB, "web");   // fetch #1
      const loadingA = hostA.textContent, loadingB = hostB.textContent;

      // B, mounted SECOND, answers FIRST.
      resolvers[1]({marker: "B", total: 1, unique: 1, by_severity: {}, page: 1, per_page: 25});
      await pB;
      const afterB = {a: hostA.textContent, b: hostB.textContent};

      // A, mounted FIRST, answers LAST -- the case that used to starve it.
      resolvers[0]({marker: "A", total: 1, unique: 1, by_severity: {}, page: 1, per_page: 25});
      await pA;
      const afterA = {a: hostA.textContent, b: hostB.textContent};

      console.log(JSON.stringify({loadingA, loadingB, afterB, afterA}));
    })();
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "Loading" in out["loadingA"] and "Loading" in out["loadingB"], \
        f"both hosts must show the loading state before either fetch answers: {out}"
    assert "strip:B" in out["afterB"]["b"], f"host B must paint its own data: {out['afterB']}"
    assert "Loading" in out["afterB"]["a"], \
        f"host A must still be waiting on its OWN fetch, untouched by B's: {out['afterB']}"
    assert "strip:A" in out["afterA"]["a"], \
        f"host A's own, later-resolving fetch must still paint it -- this is finding 1's bug: {out['afterA']}"
    assert "strip:B" in out["afterA"]["b"], \
        f"host A's late paint must not overwrite host B's own pane: {out['afterA']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_remounting_a_host_keeps_state_for_the_same_project_and_resets_for_a_different_one(
        srv, tmp_path):
    """Keying state by host must not lose the behaviour a tab switch already
    relied on: a re-mount of the SAME host for the SAME project (switching
    away from Findings and back) keeps its filters/page, and a re-mount of
    that SAME host for a DIFFERENT project resets them -- the same reset a
    project change has always done, now proven at the per-host state object
    rather than at module-level variables that no longer exist."""
    block = _security_js(srv)
    script = tmp_path / "remount.js"
    script.write_text(_find_mount_harness(block, """
    function secFindStrip(_fs, _data){ return secEl("div", "s", ""); }
    function secFindFilterBar(_fs, _data){ return secEl("div", "fb", ""); }
    function secFindTableSection(_fs, _data){ return secEl("div", "ts", ""); }
    function secFindPager(_fs, _data){ return secEl("div", "pg", ""); }
    """) + """
    // Echoes back the page it was actually asked for, the same way the real
    // endpoint does (queries.finding_rows never re-clamps `page` against the
    // total row count, only against a minimum of 1) -- a stub that always
    // answered "page 1" would silently overwrite the manually-set page below
    // the moment the SAME-project re-mount refetches, defeating this test.
    async function secFetch(path){
      const qs = new URLSearchParams(path.split("?")[1] || "");
      return {total: 0, unique: 0, by_severity: {}, page: Number(qs.get("page")) || 1, per_page: 25};
    }

    (async () => {
      const host = new FakeElement("div");
      await renderFindings(host, "web");
      const fs1 = secFindStates.get(host);
      fs1.filters.branch = "release/2.1";
      fs1.page = 3;

      await renderFindings(host, "web");            // same host, same project
      const fs2 = secFindStates.get(host);
      const keptSamePage = fs2 === fs1 && fs2.page === 3 && fs2.filters.branch === "release/2.1";

      await renderFindings(host, "other-project");   // same host, different project
      const fs3 = secFindStates.get(host);
      const resetOnSwitch = fs3.page === 1 && fs3.filters.branch === "" && fs3.project === "other-project";

      console.log(JSON.stringify({keptSamePage, resetOnSwitch}));
    })();
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["keptSamePage"], "a re-mount of the same host/project must keep its filters and page"
    assert out["resetOnSwitch"], "a re-mount of the same host for a DIFFERENT project must reset"


def test_findings_state_is_keyed_by_a_weakmap_not_a_plain_map(srv):
    """A plain Map keyed by host would hold every host this screen was EVER
    mounted into -- and everything it fetched -- alive forever, the first
    time a caller mounts into a fresh element and discards the old one
    (exactly the shape the Activity screen's planned fingerprint link will
    have). A WeakMap entry is exactly as long-lived as its host, so a
    discarded host cannot outlive it here. Pinned structurally rather than by
    forcing and observing a real GC pass: a finalisation-timing test is
    flaky by construction (V8 gives no promised deadline for it), while this
    assertion fails the instant the mechanism is swapped back to a Map."""
    block = _security_js(srv)
    assert "const secFindStates = new WeakMap();" in block, \
        "the findings browser's per-host state must live in a WeakMap, not a Map"
