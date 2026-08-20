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
    referenced = set(re.findall(r'\$\("([a-zA-Z0-9_-]+)"\)', _js(srv)))
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


CWD = "/x/web"
ROW = {"name": "web", "path": CWD, "base": "develop"}


def _run_save(srv, tmp_path, *, multi, name="save.js"):
    """Drive the real saveProject() over a stub DOM and return what it sent."""
    harness = """
    const sent = [];
    const vals = {"pj-name":"Web","pj-desc":"","pj-cwd":"%s","pj-ccd":"","pj-base":"develop",
                  "pj-wt":"auto","pj-up":"","pj-down":"already here"};
    const $ = (id) => ({ get value(){ return vals[id]; }, set value(v){ vals[id]=v; },
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

SEC_START = "/* ================================================================ security"
SEC_END = "/* ============================================================ end security */"


def _security_js(srv):
    """Just the Security block's source, between its own two banners.

    The whole-page checks below would pass on a page that renders a finding
    safely and a branch name unsafely twelve hundred lines away; these have to
    look at exactly the code that draws this view.
    """
    js = _js(srv)
    i = js.index(SEC_START)
    return js[i:js.index(SEC_END, i)]


def test_the_security_view_exists_and_is_registered(srv):
    page = srv.render_page("boot-authed")
    assert 'data-view="security"' in page
    assert 'id="view-security"' in page
    assert '"security"' in page  # the VIEWS array


def test_every_sidenav_item_has_a_view(srv):
    """A nav button with no panel behind it is a dead click."""
    page = srv.render_page("boot-authed")
    for view in re.findall(r'class="navitem" data-view="([a-z]+)"', page):
        assert f'id="view-{view}"' in page, f"nav item {view} has no view"


def test_the_security_view_never_renders_a_finding_with_innerhtml(srv):
    """Findings carry file paths and titles from analysed code. Injecting them
    as HTML would let a repository script the dashboard."""
    page = srv.render_page("boot-authed")
    block = page.split('id="view-security"', 1)[1][:20000]
    assert ".innerHTML = f." not in block
    assert "innerHTML=f." not in block


def test_the_security_block_only_ever_puts_an_icon_through_innerhtml(srv):
    """The general form of the check above, over the code rather than a window
    of the markup.

    A finding's title, its file paths and — the one nobody expects — the BRANCH
    it was found on are all strings a repository chooses. Git allows '<', '>'
    and '&' in a ref name, so `feature/<img src=x onerror=…>` is a branch this
    page will list in a picker. The rule that makes that harmless is absolute:
    the only thing this block ever assigns to innerHTML is an entry from the
    page's own icon table, optionally followed by a literal label. Everything
    else goes in as text.
    """
    block = _security_js(srv)
    found = [r.strip() for r in re.findall(r"\.innerHTML\s*=\s*([^;\n]+)", block)]
    assert found, "no innerHTML at all in the block — this guard is asserting nothing"
    allowed = re.compile(r'^I\[name\] \|\| ""$|^I\.[A-Za-z0-9]+(?: \+ "[^"]*")?$')
    bad = [r for r in found if not allowed.match(r)]
    assert not bad, f"innerHTML in the Security view carrying more than an icon: {bad}"


def test_the_severity_filter_never_hides_a_fixed_finding(srv):
    page = srv.render_page("boot-authed")
    assert 'f.state === "fixed" ||' in page


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_severity_floor_filters_the_page_and_nothing_else(srv, tmp_path):
    """`min_severity` is a display setting, and two things fall out of that.

    A finding that CLOSED is shown at every floor: the checklist exists to say
    what went away, and a low-severity fix disappearing from the page makes a
    good outcome look like nothing happened. And a severity outside the
    four-value vocabulary ranks above critical rather than below low — an
    unrecognised value is not a reason to drop a finding on the floor, and this
    filter is the one place that could do it without a trace.
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
    ];
    const shown = (min) => secVisible(findings, min).map(f=>f.title).join("");
    console.log(JSON.stringify({low: shown("low"), medium: shown("medium"),
                                high: shown("high"), unset: shown("")}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["low"] == "abcde", "the lowest floor must hide nothing"
    assert out["unset"] == "abcde", "no configured floor must behave like the lowest one"
    assert out["medium"] == "bcde", f"medium floor: {out['medium']}"
    assert out["high"] == "cde", f"high floor: {out['high']}"


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


def test_an_analysis_is_only_ever_started_through_its_own_op(srv):
    """Never a bare `run` of the derived job.

    `security_analyze` writes the request file — the branch, the profile and
    the analysis id — and only then starts the job. Running the job directly
    would make it re-read whatever request was left behind by the last
    analysis, and quietly report on the wrong branch.
    """
    block = _security_js(srv)
    assert 'api("security_analyze"' in block
    assert 'api("run"' not in block, "the Security view can start a bare run of the derived job"


def test_a_report_download_carries_the_token(srv):
    """Every GET on this API is behind the X-CC-Token header, which a plain
    `<a href="/api/security/report?…">` cannot attach — the browser would send
    the navigation without it and the operator would get a 401 as a file."""
    html = srv.render_page("boot-authed").split("<script>")[0]
    assert 'href="/api/security/report' not in html, "the report is linked, not fetched"
    block = _security_js(srv)
    dl = _plainfn(block, "secDownload")
    assert "/api/security/report" in dl
    assert '"X-CC-Token":TOKEN' in dl or '"X-CC-Token": TOKEN' in dl
