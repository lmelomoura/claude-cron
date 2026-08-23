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
    # The page now opens with a small inline theme script in <head>, ahead of
    # the main body script -- two <script> blocks where there used to be one,
    # so a single greedy match would span from the head script's opening tag
    # to the body script's closing tag and swallow the <style> block and HTML
    # between them. The main script is the last <script>...</script> block.
    return re.findall(r"<script>(.*?)</script>", _page(srv), re.S)[-1]


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
    # both from CSS alone, with no script having run yet. The rules that do
    # it now live in the served stylesheet rather than inline in the page.
    css, _ = srv.static_asset("app.css")
    assert ".boot-login .shell,.boot-setup .shell{display:none}" in css
    assert ".boot-login #login[hidden],.boot-setup #setup[hidden]{display:flex}" in css
    # ...and the signed-in page must NOT hide its own shell.
    assert 'class="boot-authed"' in srv.render_page("boot-authed")


def test_the_theme_is_resolved_before_the_first_stylesheet(srv):
    """A dark-mode user must never see a white frame. The theme is stored in
    localStorage, which only script can read, so the read has to happen in
    the head ahead of any stylesheet -- once styles are parsed the page can
    paint, and a data-theme applied after that is applied to a frame the user
    has already seen.

    Asserted by position rather than by presence: a theme script that exists
    somewhere on the page is exactly what the page had while it flashed."""
    page = srv.render_page()
    head = page[:page.index("</head>")]
    theme_at = head.index("dataset.theme")
    first_style = min(
        (head.index(m) for m in ("<style", "<link rel=\"stylesheet\"")
         if m in head), default=None)
    assert first_style is not None, "no stylesheet in the head at all"
    assert theme_at < first_style, (
        "the theme is resolved after the first stylesheet -- dark mode will "
        "paint one white frame before it corrects itself"
    )


def test_the_theme_preference_has_exactly_one_definition(srv):
    """The inline head script and themePref() must not each carry their own
    copy of "localStorage, else the media query" -- two spellings of one
    rule, and the day they disagree the page corrects its own first frame to
    the wrong theme."""
    page = srv.render_page()
    assert page.count("prefers-color-scheme: dark") == 1, (
        "the theme preference rule is written in more than one place"
    )


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_page_javascript_parses(srv, tmp_path):
    f = tmp_path / "page.js"
    f.write_text(_js(srv))
    p = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_sessions_tab_is_labelled_for_what_it_shows(srv, tmp_path):
    """The card lists retained run directories, kept because a session was cut
    short and might still be resumed -- "Sessions" is the word the README and
    the rest of the dashboard already use for that, not "Worktrees", the word
    for the isolation mechanism underneath. Pinned against the tab this label
    first shipped on, and carried over to worktreesCard (ui/app/overview.js)
    now that the tab is a card -- see
    test_the_worktrees_card_appears_only_when_there_is_something_on_disk."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "worktreesCard")
    script = tmp_path / "wt-label.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(collectAll(
      worktreesCard([{job: "x", size: "1 KB"}]), [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "Sessions" in joined, "the card's own label was not carried over"
    assert "Worktrees" not in joined, "the old tab label text is still shipping somewhere"


def test_the_overview_has_no_tabs_of_its_own(srv):
    """Jobs and Runs are pages in the sidebar. A second set of tabs
    reaching the same two lists is one navigation too many, and the one that
    silently disagreed with the sidebar about which was selected."""
    page = srv.render_page()
    assert 'id="viewtabs"' not in page
    for gone in ('id="vt-jobs"', 'id="vt-runs"', 'id="vt-wt"'):
        assert gone not in page, f"{gone} outlived the tab strip"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_worktrees_card_appears_only_when_there_is_something_on_disk(
        srv, tmp_path):
    """A directory holding the only copy of some work is a thing to deal
    with; the absence of one is not news. As a tab it was always present,
    saying there was nothing -- a permanent fixture reporting the ordinary
    case."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "worktreesCard")
    script = tmp_path / "wt.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify({
      empty: worktreesCard([]) === null,
      some:  collectAll(worktreesCard([
        {job: "qg-dev-agent", size: "184 MB"}]), []).some(
          r => r.text.includes("qg-dev-agent")),
    }));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["empty"], "an empty worktrees card was rendered anyway"
    assert got["some"], "a retained worktree was not named on the card"


def test_every_element_the_script_reaches_for_exists(srv):
    """$("foo") against an id the markup does not define is a silent no-op that
    turns into a TypeError the first time the code touches .value."""
    page = _page(srv)
    html = page.split("<script>")[0]
    ids = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', html))
    # ids created at runtime by innerHTML rather than present in the skeleton
    dynamic = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', page.split("<script>", 1)[1]))
    # The page's own script, the Security area's modules, AND the App bundle's
    # modules. Both areas moved out of the page; a check that kept reading only
    # the inline script would have stopped watching every `$("sec-…")` and, as
    # of ui/app/, every `$("jq…")` a moved jobs-domain function reaches for
    # (clearJobFilters clears the search box) without failing once.
    reads = _js(srv) + "\n" + _security_js(srv) + "\n" + _app_js(srv)
    referenced = set(re.findall(r'\$\("([a-zA-Z0-9_-]+)"\)', reads))
    missing = referenced - ids - dynamic
    assert not missing, f"script reaches for ids that no markup defines: {sorted(missing)}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_backoff_curve_matches_the_engine(srv, tmp_path):
    """The page recomputes the engine's backoff so it can say when the next
    check really is. Two implementations of one rule drift; this is what stops
    the card promising a check the tick will not make."""
    js = _js(srv)
    # backoffMultiplier is a hoisted `function` declaration, not the `const`
    # arrow it used to be (see its own comment: CCApp.init reads it by name
    # well above this line, the same temporal-dead-zone fix activeRunsOf
    # already needed) -- so its constants and its body are pulled separately
    # rather than as one `const BACKOFF_AFTER=...\n};` span.
    consts = re.search(r"const BACKOFF_AFTER=.*?;\n", js).group(0)
    fn = consts + _plainfn(js, "backoffMultiplier")
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
    than a regex that stops at the first `]`/`}`/`;` inside it.

    A bare scalar (`const NAME = 25;`) has no bracket to match, so it is
    captured up to its own terminating `;` instead -- ACT_PER_PAGE is the
    first caller that needed this, sourcing the real page size a test drives
    rather than a hand-typed number beside it that could silently drift from
    the source."""
    i = js.index(f"const {name} =")
    j = js.index("=", i) + 1
    while js[j] in " \n\t":
        j += 1
    opener = js[j]
    if opener not in ("[", "{"):
        k = js.index(";", j)
        return js[i:k + 1] + "\n"
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
    fresh guess).

    sessionLines/keptSessionsOf (bin/dashboard.html, string-returning) became
    jobCard's own sessionNotices() in ui/app/overview.js (Task 9), returning
    real Elements -- this test moved with them rather than staying pinned to
    a function that no longer exists."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "el", "sessionNotices")
    script = tmp_path / "sess.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    const CC = { DATA: { retained_worktrees: [
      {job:"j1", stamp:"s1", session:"",           expires_in:3600},
      {job:"j1", stamp:"s2", session:"sess-live00", expires_in:7200},
      {job:"j1", stamp:"s3", session:"sess-busy00", expires_in:100},
      {job:"j2", stamp:"s4", session:"sess-other",  expires_in:900},
    ] } };
    // Small, honest stand-ins for the page's own single implementations --
    // see page.js's own comment on why sessionNotices reaches for these by
    // name rather than a second copy.
    function fmtExpiresIn(n){ return n == null ? null : "in " + n + "s"; }
    function resumeInFlight(id, sid){ return id === "j1" && sid === "sess-busy00"; }
    """ + deps + """
    const findButton = (row) => (row.childNodes||[]).find(c => c && c.dataset && c.dataset.op === "resume");
    const findBadge = (row) => (row.childNodes||[]).find(c => c && c.className === "runningbadge");
    const rowsJ1 = sessionNotices("j1");
    const texts = rowsJ1.map(r => r.textContent);
    const liveBtn = rowsJ1.map(findButton).find(Boolean);
    console.log(JSON.stringify({
      rowsForJ1: rowsJ1.length,
      noSessionText: texts.some(t => t.indexOf("cannot be resumed") !== -1),
      resumeButtons: rowsJ1.filter(findButton).length,
      liveButtonExact: !!liveBtn && liveBtn.dataset.id === "j1" && liveBtn.dataset.session === "sess-live00",
      busyGotAButton: rowsJ1.some(r => { const b = findButton(r); return b && b.dataset.session === "sess-busy00"; }),
      busyGotBadge: rowsJ1.some(findBadge),
      mentionsOtherJob: texts.some(t => t.indexOf("sess-other") !== -1)
        || rowsJ1.some(r => { const b = findButton(r); return b && b.dataset.session === "sess-other"; }),
      emptyForJobWithNothingKept: sessionNotices("no-such-job").length === 0,
    }));
    """)
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout
    got = json.loads(out)
    assert got["rowsForJ1"] == 3, "one row per kept run dir, including the sessionless one"
    assert got["noSessionText"], "a run dir with no .session must say it cannot be resumed"
    assert got["resumeButtons"] == 1, "only the free session gets a working Resume button"
    assert got["liveButtonExact"], "the button must carry the real job id and real session id"
    assert not got["busyGotAButton"], "a session already being resumed must not get a second button"
    assert got["busyGotBadge"], "a session already being resumed shows the resuming… badge instead"
    assert not got["mentionsOtherJob"], "sessionNotices('j1') leaked another job's row"
    assert got["emptyForJobWithNothingKept"], "a job with nothing kept renders no rows"


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


# ---- the App bundle. ui/app/ holds the jobs domain moved out of the page's
# own script -- jobFacts and visibleJobs, read by both the Overview's cards
# and the Jobs table, plus the small helpers that go with them. It is bundled
# into bin/static/app.js by the same build/build-ui.sh call that builds
# bin/static/security.js, and scanned by the same sink-scan below because
# _security_sources() already walks all of ui/.

APP_ROOT = REPO / "ui" / "app"


def _app_js(srv):
    """The app bundle's own sources, concatenated. Mirrors _security_js: the
    tests have to read exactly the code that draws the view, not a block of
    dashboard.html that may no longer be where the code lives."""
    return "\n".join(p.read_text() for p in sorted(APP_ROOT.rglob("*.js")))


# jobFacts reads the clock directly, so it is pinned first -- "in 4 minutes"
# has to come out as a number, not a race against whatever moment the test
# happens to run at.
#
# It also reads three names the page hands it through page.js's bindPage()
# rather than compute them itself: eff() (project-inherited fields),
# backoffMultiplier() (mirrors the engine's own curve, already proven equal
# to it by test_the_backoff_curve_matches_the_engine above) and
# activeRunsOf() (live runs from CC.DATA). Extracting only jobFacts's own
# text would leave all three undefined and the very first line of the
# function -- `CC.DATA.state[j.id]` -- throwing before a single case ran, so
# they are stood up here the same way _harness_globals() above stands up
# DATA and activeRunsOf for the job-card tests: small, honest stand-ins for
# what the page would otherwise inject, not a rewrite of what jobFacts does.
_JOBS_DOMAIN_HARNESS = """
// jobFacts reads the clock; pinned so "in 4 minutes" is a number, not a race.
const NOW = 1_800_000_000;
Date.now = () => NOW * 1000;

const CC = { DATA: { state: {}, checks: {}, runs: [] } };
function eff(j, field, def){
  if(j[field] != null && j[field] !== "") return j[field];
  return def;
}
const BACKOFF_AFTER = 3, BACKOFF_MAX = 16;
function backoffMultiplier(streak){
  const s = +streak || 0;
  if(s < BACKOFF_AFTER) return 1;
  return Math.min(BACKOFF_MAX, Math.pow(2, s - BACKOFF_AFTER + 1));
}
function activeRunsOf(id){ return []; }
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_job_facts_survive_the_move_unchanged(srv, tmp_path):
    """jobFacts is the arithmetic both the Overview's cards and the Jobs
    table read -- the state, the next run, the cap, the backoff. Moving it
    out of the page must not shift a single one of those, so this pins the
    answers for a job of each shape before the move and holds them after."""
    block = _app_js(srv)
    # nextCheckAt and inWindow are jobFacts's own module-mates -- called
    # nowhere else in ui/app/ -- so they travel with it here the same way
    # test_a_job_card_shows_every_kept_session_honestly above joins several
    # _plainfn extractions rather than assume one function is self-contained.
    deps = "\n".join(_plainfn(block, n) for n in ("nextCheckAt", "inWindow", "jobFacts"))
    script = tmp_path / "facts.js"
    script.write_text(_JOBS_DOMAIN_HARNESS + deps + """
    const cases = {
      plain:    {id: "a", enabled: true,  interval_minutes: 15},
      disabled: {id: "b", enabled: false, interval_minutes: 15},
      backoff:  {id: "c", enabled: true,  interval_minutes: 15},
    };
    const out = {};
    for(const [k, j] of Object.entries(cases)){
      const f = jobFacts(j);
      out[k] = {state: f.state, disabled: !!f.disabled, capped: !!f.capped};
    }
    console.log(JSON.stringify(out));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True,
                                    check=True).stdout)
    assert out["plain"]["state"] == "enabled"
    assert out["disabled"]["disabled"] is True
    assert out["plain"]["capped"] is False


# ---- the Jobs table, pinned ahead of phase 2's redesign (Task 2). Same deal
# as the jobFacts test above: characterisation tests, so they pass on their
# first run -- the falsifiability of each one (break, red, revert) is
# recorded by hand in .superpowers/sdd/task-2-report.md rather than by a
# red-then-green cycle here. sortJobs and JOB_COLS (both new in
# ui/app/jobs-domain.js, extracted verbatim from renderJobTable/renderJobHead
# in bin/dashboard.html) are pure; visibleJobs/jobFilters and jobsEmptyNote
# already existed and are pinned again here for what the table specifically
# does with them, not duplicating the existing card-focused tests above.

def _sort_jobs_deps(block):
    """STATE_RANK and JOB_SORTERS are sortJobs's own module-private consts --
    not reachable via _plainfn, so they travel with it the same way
    _index_screen_deps above joins several _plainfn extractions."""
    return (_const(block, "STATE_RANK") + _const(block, "JOB_SORTERS")
            + _plainfn(block, "sortJobs"))


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_sorting_by_each_column_gives_the_expected_order(srv, tmp_path):
    """Every column the Jobs table can be sorted by, both directions,
    against a known four-row set with no ties and nothing missing -- ties
    and missing values are test_the_id_tiebreak_does_not_reverse_with_the_
    column's and test_rows_with_no_answer_sort_to_the_bottom_not_the_top's
    own jobs, not this one's."""
    block = _app_js(srv)
    deps = _sort_jobs_deps(block)
    script = tmp_path / "sort-columns.js"
    script.write_text(deps + """
    const rows = [
      {j:{id:"j3", project:"Charlie"}, F:{state:"enabled", st:{last_run_start:300}, nextAt:50,  spentToday:40, disabled:false}},
      {j:{id:"j1", project:"Bravo"},   F:{state:"idle",    st:{last_run_start:500}, nextAt:200, spentToday:15, disabled:false}},
      {j:{id:"j4", project:"Delta"},   F:{state:"idle",    st:{last_run_start:700}, nextAt:999, spentToday:1,  disabled:false}},
      {j:{id:"j2", project:"Alpha"},   F:{state:"running", st:{last_run_start:100}, nextAt:800, spentToday:5,  disabled:false}},
    ];
    const ids = (out) => out.map(x => x.j.id);
    const out = {};
    for(const key of ["job","project","state","last","next","today"]){
      out[key+"_asc"]  = ids(sortJobs(rows, key, 1));
      out[key+"_desc"] = ids(sortJobs(rows, key, -1));
    }
    console.log(JSON.stringify(out));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["job_asc"]      == ["j1", "j2", "j3", "j4"]
    assert out["job_desc"]     == ["j4", "j3", "j2", "j1"]
    assert out["project_asc"]  == ["j2", "j1", "j3", "j4"]   # Alpha,Bravo,Charlie,Delta
    assert out["project_desc"] == ["j4", "j3", "j1", "j2"]   # Delta,Charlie,Bravo,Alpha
    assert out["state_asc"]    == ["j2", "j3", "j1", "j4"]   # running,enabled,idle(j1<j4)
    assert out["state_desc"]   == ["j4", "j1", "j3", "j2"]   # idle(j4,j1),enabled,running
    assert out["last_asc"]     == ["j2", "j3", "j1", "j4"]   # 100,300,500,700
    assert out["last_desc"]    == ["j4", "j1", "j3", "j2"]
    assert out["next_asc"]     == ["j3", "j1", "j2", "j4"]   # 50,200,800,999
    assert out["next_desc"]    == ["j4", "j2", "j1", "j3"]
    assert out["today_asc"]    == ["j4", "j2", "j1", "j3"]   # 1,5,15,40
    assert out["today_desc"]   == ["j3", "j1", "j2", "j4"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_rows_with_no_answer_sort_to_the_bottom_not_the_top(srv, tmp_path):
    """A job that has never run has no "last run"; a disabled job has no
    "next" (see JOB_SORTERS' own `missing` comment, ui/app/jobs-domain.js).
    Both sort to the BOTTOM whichever way the arrow points -- reversing the
    column must never promote "never"/"disabled" to first, the exact
    regression the comment describes ("put seventeen disabled jobs above
    the ones actually due the moment you reversed the column")."""
    block = _app_js(srv)
    deps = _sort_jobs_deps(block)
    script = tmp_path / "sort-missing.js"
    script.write_text(deps + """
    const lastRows = [
      {j:{id:"never"}, F:{st:{last_run_start:0}}},
      {j:{id:"soon"},  F:{st:{last_run_start:100}}},
      {j:{id:"late"},  F:{st:{last_run_start:50}}},
    ];
    const nextRows = [
      {j:{id:"off"},  F:{disabled:true,  nextAt:10}},
      {j:{id:"far"},  F:{disabled:false, nextAt:500}},
      {j:{id:"soon"}, F:{disabled:false, nextAt:100}},
    ];
    console.log(JSON.stringify({
      last_asc:  sortJobs(lastRows, "last", 1).map(x => x.j.id),
      last_desc: sortJobs(lastRows, "last", -1).map(x => x.j.id),
      next_asc:  sortJobs(nextRows, "next", 1).map(x => x.j.id),
      next_desc: sortJobs(nextRows, "next", -1).map(x => x.j.id),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["last_asc"]  == ["late", "soon", "never"]
    assert out["last_desc"] == ["soon", "late", "never"]
    assert out["next_asc"]  == ["soon", "far", "off"]
    assert out["next_desc"] == ["far", "soon", "off"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_id_tiebreak_does_not_reverse_with_the_column(srv, tmp_path):
    """Sorting by project keeps two jobs of the SAME project in the same
    relative order whichever way the arrow points -- you sort by project to
    read one project's jobs together, not to scramble them (JOB_SORTERS'
    own `project` comment, ui/app/jobs-domain.js). The tiebreak is applied
    outside the `*dir` multiplication, deliberately unlike the comparator
    itself."""
    block = _app_js(srv)
    deps = _sort_jobs_deps(block)
    script = tmp_path / "sort-tiebreak.js"
    script.write_text(deps + """
    const rows = [
      {j:{id:"b-job", project:"Same"}},
      {j:{id:"a-job", project:"Same"}},
      {j:{id:"z-job", project:"Other"}},
    ];
    console.log(JSON.stringify({
      asc:  sortJobs(rows, "project", 1).map(x => x.j.id),
      desc: sortJobs(rows, "project", -1).map(x => x.j.id),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    same_only = lambda ids: [i for i in ids if i in ("a-job", "b-job")]
    assert same_only(out["asc"]) == ["a-job", "b-job"]
    assert same_only(out["desc"]) == ["a-job", "b-job"], (
        "the id tiebreak reversed along with the column -- descending gave "
        f"{out['desc']}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_three_filters_narrow_the_same_set_together(srv, tmp_path):
    """Project, status and free-text search (visibleJobs, ui/app/jobs-
    domain.js) all narrow the SAME set in sequence -- so the three combined
    can never show a job that any ONE of them alone would have hidden."""
    block = _app_js(srv)
    fn = _plainfn(block, "visibleJobs")
    script = tmp_path / "filters.js"
    script.write_text("""
    const CC = { DATA: { jobs: [
      {id:"a1", project:"Alpha", enabled:true,  description:"nightly backup"},
      {id:"a2", project:"Alpha", enabled:false, description:"weekly report"},
      {id:"b1", project:"Beta",  enabled:true,  description:"deploy"},
      {id:"b2", project:"Beta",  enabled:true,  description:"nightly cleanup"},
    ] } };
    const jobFilters = {project:"Beta", status:"enabled", query:"nightly"};
    """ + fn + """
    console.log(JSON.stringify(visibleJobs().map(j => j.id)));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out == ["b2"], (
        "the three filters did not intersect to exactly the one job that "
        f"satisfies project, status AND query at once: got {out}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("jobs,query,expect", [
    ([], "", "No jobs yet"),
    ([{"id": "a1", "project": "", "enabled": True, "description": ""}],
     "nothing-matches", "No jobs match"),
], ids=["no-jobs-at-all", "filtered-to-nothing"])
def test_the_tables_empty_state_tells_no_jobs_apart_from_none_matched(
        srv, tmp_path, jobs, query, expect):
    """The Jobs table's own empty row (renderJobTable, bin/dashboard.html)
    says one of two different things depending on WHY it is empty -- no
    jobs exist at all, or the filters narrowed a non-empty set to nothing --
    the same distinction jobsEmptyNote (ui/app/overview.js) already draws
    for the card view. This drives it through visibleJobs()/jobFilters, the
    actual inputs the table's own branch reads, rather than handing
    jobsEmptyNote a bare boolean the way the existing card-focused test
    above does."""
    block = _app_js(srv)
    deps = _plainfn(block, "visibleJobs") + _plainfn(block, "jobsEmptyNote")
    script = tmp_path / "empty-table.js"
    script.write_text(
        "const CC = { DATA: { jobs: " + json.dumps(jobs) + " } };\n"
        "const jobFilters = { project: \"\", status: \"\", query: "
        + json.dumps(query) + " };\n"
        + deps + """
    const vis = visibleJobs();
    const filtering = !!(jobFilters.project || jobFilters.status || jobFilters.query.trim());
    console.log(JSON.stringify({empty: vis.length === 0, note: jobsEmptyNote(filtering)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["empty"] is True, f"test setup did not produce an empty visible set: {out}"
    assert expect in out["note"], out["note"]


# ---- the Jobs table's own page (Phase 2 Task 3): CCApp.renderJobsPage()
# (ui/app/jobs-table.js) replaces renderJobTable/renderJobHead/
# paintJobFilters and the fork inside the old renderJobs(). Unlike sortJobs/
# jobFacts/jobsEmptyNote above, renderJobsPage is not one of the isolated,
# self-contained functions this file extracts and runs alone -- it is the
# page's own DOM builder, reaching pageHeader/kpiCard (chrome.js), jobFacts/
# visibleJobs/sortJobs (jobs-domain.js) and jobsEmptyNote (overview.js) by
# bare name, the same way jobCard does. _jobs_table_deps below joins every
# one of those, the same "join several _plainfn/_const extractions" pattern
# _sort_jobs_deps and _index_screen_deps above already use.

def _jobs_table_deps(block):
    # pageHeader (chrome.js) is NOT in this list: it destructures its params
    # directly (`function pageHeader({icon, title, subtitle, actions}){`),
    # and _plainfn's brace-matching starts at the first `{` after the name --
    # which is the DESTRUCTURING's own brace, not the body's (exactly the
    # trap kpiCard's own `opts` parameter, extracted below with no trouble,
    # exists to dodge -- see its comment in chrome.js). No prior test ever
    # extracted pageHeader this way, so nothing was pinned expecting it to
    # work; the test below stubs pageHeader instead of pulling in the real
    # one, since verifying the footer text does not need the real header to
    # run, only to not throw.
    consts = (_const(block, "STATE_RANK") + _const(block, "JOB_SORTERS")
              + _const(block, "JOB_COLS") + _const(block, "KPI_ICONS"))
    fns = ("el", "kpiCard",
           "inWindow", "nextCheckAt", "jobFacts", "visibleJobs", "sortJobs",
           "bulkOn", "bulkLabel", "jobsEmptyNote",
           "jobsHeaderSubtitle", "jobsKpis", "paintJobFilterBar",
           "renderJobsTableHead", "jobRow", "renderJobsTable", "renderJobsPage")
    return consts + "\n".join(_plainfn(block, n) for n in fns)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_jobs_page_footer_says_how_many_it_is_showing(srv, tmp_path):
    """Runs already had a pager; Jobs had none at all -- renderJobTable drew
    every visible row with nothing below the table. CCApp.renderJobsPage()
    (ui/app/jobs-table.js, Task 3's replacement) is driven whole here --
    header, KPIs, filter bar and table -- against a small fixed set of jobs,
    checking the one thing this task actually adds: a footer reading
    "Showing X to Y of N", present even on a set that fits on one page.

    Written to fail before renderJobsPage existed (no such name to extract,
    so _plainfn would raise) and to pass once it does."""
    block = _app_js(srv)
    deps = _jobs_table_deps(block)
    script = tmp_path / "jobs-footer.js"
    script.write_text(_INDEX_DOM_HARNESS + _JOBS_DOMAIN_HARNESS + """
    CC.DATA.jobs = [
      {id: "a", project: "Alpha", enabled: true},
      {id: "b", project: "Alpha", enabled: false},
      {id: "c", project: "Beta",  enabled: true},
    ];
    // The page's own static mounts -- renderJobsPage() only ever reaches
    // for ids bin/dashboard.html already defines, never builds them itself.
    const ELS = {};
    ["jobs-head", "jobs-kpis", "jactive", "jf-clear", "bulk-all",
     "jobhead", "jobrows", "jobs-pg-info", "jobs-pg-prev", "jobs-pg-next"]
      .forEach(id => { ELS[id] = document.createElement("div"); });
    const $ = (id) => ELS[id];
    // Small, honest stand-ins for the page.js bindings this module reads --
    // same spirit as fmtAgo/fmtDur above, which _INDEX_DOM_HARNESS already
    // stubs the identical way.
    function money(n){ return "$" + (n || 0).toFixed(2); }
    function fmtWhen(t){ return "when" + t; }
    function fmtIn(t){ return "in" + t; }
    function isFav(_name){ return false; }
    function paintJobPickers(){}
    // Stubbed rather than extracted -- see _jobs_table_deps's own comment on
    // why pageHeader in particular cannot go through _plainfn.
    function pageHeader(_opts){ return document.createElement("div"); }
    const jobFilters = {project: "", status: "", query: ""};
    let sortKey = "job", sortDir = 1, page = 1;
    const PAGE_SIZE = 20;
    """ + deps + """
    renderJobsPage();
    console.log(JSON.stringify({
      info: $("jobs-pg-info").textContent,
      prevDisabled: $("jobs-pg-prev").disabled,
      nextDisabled: $("jobs-pg-next").disabled,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["info"] == "Showing 1 to 3 of 3 jobs", out["info"]
    # One page only -- the pager still renders, both buttons simply disabled
    # rather than pointing nowhere. See the brief: "a pager, even when there
    # is one page".
    assert out["prevDisabled"] is True
    assert out["nextDisabled"] is True


# ---- the Overview's own arithmetic, pinned ahead of the redesign that turns
# three loose tiles and a footer strip into five KPI cards and rebuilds the
# job card from HTML strings into DOM nodes. Characterisation tests: they
# describe behaviour the page already has, so they pass on their first run --
# the falsifiability of each one is recorded by hand in
# .superpowers/sdd/task-6-report.md rather than by a red-then-green cycle
# here. pulseKpis, bandEmptyReason, spendTone, groupJobs and jobsEmptyNote
# are pure; probeVerdict and nextRunNote build DOM nodes and so need
# _INDEX_DOM_HARNESS's stub document and collectAll, the same stand-in the
# Security index screen's own DOM tests above already use.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_kpis_come_from_the_numbers_the_loop_recorded(srv, tmp_path):
    """Checks, woke, warnings, errors and today's spend, from a known
    tick.log and a known journal. Pinned before the panel is redrawn: the
    redesign moves these five out of three loose tiles and a footer strip
    into five cards, and the one thing that must not change on the way is
    what any of them says."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "kpis.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(pulseKpis({
      checks: 96, per: {woke: 23, idle: 68, blocked: 4, capped: 1},
      warn: 3, err: 1, spentToday: 9.34, spentWeek: 41.02,
      runsToday: 12, runsWeek: 58,
    })));
    """)
    got = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True,
                                    check=True).stdout)
    by = {c["label"]: c for c in got}
    assert by["Checks"]["value"] == "96"
    assert by["Woke a run"]["value"] == "23"
    assert by["Woke a run"]["sub"] == "24% of checks"
    assert by["Warnings"]["value"] == "3"
    assert by["Errors"]["value"] == "1"
    assert by["Spent today"]["value"] == "$9.34"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_percentage_of_nothing_is_a_dash_not_zero_percent(srv, tmp_path):
    """"0% error rate" over an empty denominator is a confident claim about
    a day on which the loop never ran. The rule is already in pct(); nothing
    held it.

    Tightened from a substring check (`"—" in sub`) to an exact-equality
    check on "Woke a run"'s own sub: a naive `pct(...) ? ... : "—"` around
    just the number still leaves a trailing " of checks" appended
    unconditionally outside the ternary, so the card reads "— of checks" -- a
    dash with a dangling preposition. That string still CONTAINS "—", so the
    old substring assertion passed on the very bug it was written to catch."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "pct.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(pulseKpis({
      checks: 0, per: {woke: 0}, warn: 0, err: 0,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0,
    })));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    subs = [c["sub"] for c in got]
    assert not any("0%" in s for s in subs), f"a zero percent was printed: {subs}"
    by = {c["label"]: c for c in got}
    assert by["Woke a run"]["sub"] == "—", \
        f"a percentage of nothing must be exactly a dash, not a dash with " \
        f"trailing text: {by['Woke a run']['sub']!r}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_warning_and_error_cards_lead_to_the_runs_they_count(srv, tmp_path):
    """These two are the way IN to the runs behind them -- today as chips
    carrying data-statfilter, after the redesign as cards. The navigation is
    the point of them, and a card with nothing to show must be inert rather
    than navigating to an empty filtered table."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "doors.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const some = pulseKpis({checks: 10, per: {woke: 1}, warn: 3, err: 2,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    const none = pulseKpis({checks: 10, per: {woke: 1}, warn: 0, err: 0,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    console.log(JSON.stringify({some, none}));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    some = {c["label"]: c for c in got["some"]}
    none = {c["label"]: c for c in got["none"]}
    assert some["Warnings"]["filter"] == "warning"
    assert some["Errors"]["filter"] == "error"
    assert not none["Warnings"]["filter"], "a card with nothing to show still navigates"
    assert not none["Errors"]["filter"], "a card with nothing to show still navigates"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_warnings_and_errors_name_their_window_when_there_is_something_to_read(srv, tmp_path):
    """Checks and Woke a run are 24h figures, and the band directly below the
    KPI row is titled "Last 24 hours". Warnings and Errors are 7-day figures
    sitting right beside those two 24h cards -- so at a NON-ZERO count, each
    one's own sub has to say "7 days" for itself, or an error from Monday
    reads as if it happened today. The old code said the window only in the
    EMPTY sentence ("No warnings in the last 7 days") and dropped it exactly
    when there was something to read ("Runs that failed — open them in
    Runs"), which is backwards: the zero case needs the window least, since
    there is nothing on the card to misdate."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "window.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(pulseKpis({
      checks: 10, per: {woke: 1}, warn: 3, err: 2,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0,
    })));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    by = {c["label"]: c for c in got}
    assert "7 days" in by["Warnings"]["sub"], \
        f"Warnings at a non-zero count does not name its window: {by['Warnings']['sub']!r}"
    assert "7 days" in by["Errors"]["sub"], \
        f"Errors at a non-zero count does not name its window: {by['Errors']['sub']!r}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_card_that_is_not_a_door_is_never_a_disabled_button(srv, tmp_path):
    """Checks, Woke a run and Spent today have no filter and never will --
    they are not doors into Runs, so a quiet install with every count at
    zero must not grey all three of them out as if the page were broken.
    Warnings/Errors ARE doors: a door at a zero count has nothing to
    navigate to, so THAT is the one case where `disabled` is the correct,
    meaningful reading. `filter` alone cannot tell the two apart -- it is
    empty for both a card that never navigates and a door at a zero count --
    which is why pulseKpis also hands kpiCard a `door` flag, and kpiCard has
    to act on it: a plain element (never a <button>, never `disabled`) when
    `door` is false, a real <button> (disabled only when `filter` is empty)
    when it is true."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "el", "kpiCard", "pulseKpis")
    script = tmp_path / "doorbuttons.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    function render(k){
      return pulseKpis(k).map(c => {
        const node = kpiCard({icon: null, tone: c.tone, value: c.value,
          label: c.label, sub: c.sub, filter: c.filter, door: c.door});
        return {label: c.label, tag: node.tagName, disabled: !!node.disabled,
                statfilter: node.dataset.statfilter || null};
      });
    }
    const quiet = render({checks: 0, per: {}, warn: 0, err: 0,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    const active = render({checks: 10, per: {woke: 1}, warn: 3, err: 2,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    console.log(JSON.stringify({quiet, active}));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    quiet = {c["label"]: c for c in got["quiet"]}
    active = {c["label"]: c for c in got["active"]}
    for label in ("Checks", "Woke a run", "Spent today"):
        assert quiet[label]["tag"] != "button", f"{label} rendered as a button at zero"
        assert not quiet[label]["disabled"], f"{label} rendered disabled at zero"
        assert active[label]["tag"] != "button", f"{label} rendered as a button"
        assert not active[label]["disabled"], f"{label} rendered disabled"
    assert quiet["Warnings"]["tag"] == "button" and quiet["Warnings"]["disabled"], \
        "a door with nothing behind it should be a disabled button"
    assert quiet["Errors"]["tag"] == "button" and quiet["Errors"]["disabled"], \
        "a door with nothing behind it should be a disabled button"
    assert active["Warnings"]["tag"] == "button" and not active["Warnings"]["disabled"]
    assert active["Warnings"]["statfilter"] == "warning"
    assert active["Errors"]["tag"] == "button" and not active["Errors"]["disabled"]
    assert active["Errors"]["statfilter"] == "error"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_spent_today_card_carries_the_week_in_its_sublabel(srv, tmp_path):
    """The pulse-f strip this project's own history removed used to say
    "7 days <n> runs <$y>". pulseKpis kept spentWeek as an input but dropped
    it on the floor -- "Spent today" came back with `sub: null`/`""` and the
    figure was nowhere on the page. The pinned test above only checks
    `value`, never `sub`, which is exactly how this shipped broken: the
    week's spend belongs in this card's own sublabel, not a separate strip
    -- "one number per label" applied to the pair it was always part of."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "week.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(pulseKpis({
      checks: 96, per: {woke: 23}, warn: 3, err: 1,
      spentToday: 9.34, spentWeek: 41.02, runsToday: 12, runsWeek: 58,
    })));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    by = {c["label"]: c for c in got}
    assert by["Spent today"]["sub"] == "$41.02 over 7 days"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("jobs,expected", [
    ([], "There are no jobs yet."),
    ([{"enabled": False}], "All 1 jobs are disabled."),
    ([{"enabled": False}, {"enabled": True}], "1 of 2 jobs are disabled."),
    ([{"enabled": True}], "Every job is enabled — the next tick will show up here."),
])
def test_a_band_with_no_checks_says_which_empty_it_is(srv, tmp_path, jobs, expected):
    """A fresh install, an evening with everything switched off, and a loop
    that is about to tick are three different facts. One blank chart for all
    three is the state this sentence exists to prevent."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "bandEmptyReason")
    script = tmp_path / "band.js"
    script.write_text(deps + f"""
    console.log(bandEmptyReason({json.dumps(jobs)}));
    """)
    got = subprocess.run(["node", str(script)], capture_output=True, text=True,
                         check=True).stdout.strip()
    assert got == expected


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("exit_code,expect", [
    (0, "work found"), (1, "nothing to do"), (2, "probe FAILED"),
    (127, "probe FAILED"),
])
def test_a_probe_that_could_not_run_says_so(srv, tmp_path, exit_code, expect):
    """Any exit other than 0 or 1 once rendered as the calm "nothing to do",
    so a job whose credentials had gone missing looked healthy while it
    silently never ran again. Fixed in the code, never held by a test --
    and the card is about to be rewritten."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "probeVerdict")
    script = tmp_path / "probe.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + f"""
    const n = probeVerdict({{exit: {exit_code}, output: ""}});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert any(expect in r["text"] for r in got), \
        f"exit {exit_code} did not read as {expect!r}: {[r['text'] for r in got]}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("spent,cap,expect", [
    (1.00, 5.00, ""), (3.99, 5.00, ""), (4.00, 5.00, "near"),
    (4.90, 5.00, "near"), (5.00, 5.00, "over"), (7.00, 5.00, "over"),
])
def test_the_spend_bar_warns_before_the_cap_and_says_when_it_is_reached(
        srv, tmp_path, spent, cap, expect):
    """80% is a warning and 100% is a stop, and the boundary between them is
    exactly where an off-by-one lives. Pinned at both edges."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "spendTone")
    script = tmp_path / "spend.js"
    script.write_text(deps + f"console.log(spendTone({spent}, {cap}) || '');")
    got = subprocess.run(["node", str(script)], capture_output=True, text=True,
                         check=True).stdout.strip()
    assert got == expect


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_favourite_projects_come_first_and_no_projects_means_a_flat_grid(
        srv, tmp_path):
    """The star's whole purpose: on an install with a dozen projects, the two
    you are working in stop being a scroll away. And a install with no
    projects at all gets no group chrome to scroll past."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "groupJobs")
    script = tmp_path / "group.js"
    script.write_text(deps + """
    const jobs = [{id:"a",project:"Zeta"},{id:"b",project:"Alpha"},
                  {id:"c",project:"Minerva"}];
    console.log(JSON.stringify({
      starred:   groupJobs(jobs, new Set(["Zeta"])).map(g => g.name),
      unstarred: groupJobs(jobs, new Set()).map(g => g.name),
      flat:      groupJobs([{id:"x"},{id:"y"}], new Set()).map(g => g.name),
    }));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["starred"][0] == "Zeta", "a favourite did not sort to the top"
    assert got["unstarred"] == ["Alpha", "Minerva", "Zeta"]
    assert got["flat"] == [], "jobs with no project were given group chrome"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_standalone_filter_still_gets_a_group_header(srv, tmp_path):
    """The project filter's "Standalone" option shows only jobs with no
    project -- the one filtered view guaranteed to make every visible job
    project-less. groupJobs must not read that as "this install has no
    projects anywhere" (its own two-argument "flat grid" rule, pinned
    above) and drop the group: given the unfiltered project list as a third
    argument, it still knows the install has projects elsewhere even though
    none of them are in view, and builds the standalone group instead of
    returning none at all."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "groupJobs")
    script = tmp_path / "standalone.js"
    script.write_text(deps + """
    const visible = [{id:"c"}, {id:"d"}];
    const allProjects = ["Alpha", "Zeta"];
    console.log(JSON.stringify(
      groupJobs(visible, new Set(), allProjects)
        .map(g => ({name: g.name, n: g.jobs.length}))
    ));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got == [{"name": "__standalone__", "n": 2}], \
        "a filtered view of only standalone jobs lost its group header"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("filtering,expect", [
    (False, "No jobs yet"), (True, "No jobs match"),
])
def test_an_empty_list_says_whether_a_filter_emptied_it(srv, tmp_path,
                                                         filtering, expect):
    """"Nothing here" and "nothing here MATCHING WHAT YOU TYPED" send a
    reader to two different places. Getting it wrong sends them to create a
    job they already have."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "jobsEmptyNote")
    script = tmp_path / "empty.js"
    script.write_text(deps
                      + f"console.log(jobsEmptyNote({str(filtering).lower()}));")
    got = subprocess.run(["node", str(script)], capture_output=True, text=True,
                         check=True).stdout
    assert expect in got


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_backoff_names_the_multiplier_and_the_failures_behind_it(srv, tmp_path):
    """"backing off" alone does not say for how long or why. The number of
    failed runs is what tells an operator whether to wait or to look."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "nextRunNote")
    script = tmp_path / "backoff.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const n = nextRunNote({enabled: true}, {nextAt: 1, dueAt: 1,
                                            backoff: 4, streak: 3});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    txt = " ".join(r["text"] for r in json.loads(
        subprocess.run(["node", str(script)], capture_output=True, text=True,
                       check=True).stdout))
    assert "4×" in txt and "3 failed" in txt, txt


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("job,facts,expect", [
    ({"enabled": False}, {"nextAt": None}, "disabled"),
    ({"enabled": True}, {"nextAt": None}, "no matching window"),
])
def test_no_window_and_switched_off_are_different_answers(srv, tmp_path, job,
                                                           facts, expect):
    """A job nobody enabled and a job whose window will not reopen today are
    two different things to do something about."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "nextRunNote")
    script = tmp_path / "window.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + f"""
    const n = nextRunNote({json.dumps(job)}, {json.dumps(facts)});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    txt = " ".join(r["text"] for r in json.loads(
        subprocess.run(["node", str(script)], capture_output=True, text=True,
                       check=True).stdout))
    assert expect in txt, txt


# ---- the job card, rebuilt as DOM (Task 9). jobCard and checkList were the
# last HTML-string builders in the Overview, in bin/dashboard.html --
# checkList in particular rendered the first line of an ARBITRARY PROBE
# SCRIPT'S OWN STDOUT, so this is also where that content stops reaching the
# HTML parser at all: the sink-scan above holds the RULE (no ui/ module may
# reach innerHTML/outerHTML/etc.), these two hold the CONTENT. jobCard calls
# jobFacts (jobs-domain.js), fmtDays, sessionNotices, probeVerdict,
# nextRunNote, spendTone, checkList and el, all by their bare names -- safe
# here because, unlike the pinned functions above, nothing extracts jobCard
# alone and runs it standing apart from its module (see overview.js's own
# banner comment on the isolation rule those pinned functions keep and this
# one does not need to).

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_job_card_is_built_from_nodes_and_shows_what_it_always_showed(
        srv, tmp_path):
    """The card is the densest thing on the page and the last HTML-string
    builder the Overview had left. Rewritten as nodes it must still show
    every fact the string version did -- the pinned tests above already hold
    probeVerdict/nextRunNote/spendTone's own wording, so this pins the one
    fact that is jobCard's alone to get right: the card names its own job."""
    block = _app_js(srv)
    deps = (_const(block, "DOW")
            + _index_screen_deps(block, "fmtDays", "el", "jobFacts",
                                  "nextCheckAt", "inWindow", "probeVerdict",
                                  "nextRunNote", "spendTone", "checkList",
                                  "sessionNotices", "jobCard"))
    script = tmp_path / "card.js"
    script.write_text(_INDEX_DOM_HARNESS + _JOBS_DOMAIN_HARNESS + """
    // jobCard's remaining reads off the page -- a formatter each, stood up
    // the same honest, minimal way _JOBS_DOMAIN_HARNESS stands up eff above.
    function money(n){ return "$" + n; }
    function effortLabel(v){ return v || "default"; }
    function projById(_name){ return null; }
    """ + deps + """
    const n = jobCard({id: "qg-dev-agent", project: "Quality Gate",
                       enabled: true, interval_minutes: 15});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    txt = " ".join(r["text"] for r in got)
    assert "qg-dev-agent" in txt, "the card did not name its own job"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_probe_line_containing_markup_stays_text(srv, tmp_path):
    """The first line of a probe script's stdout, rendered. `esc()` held
    this before by discipline; nodes hold it by construction."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "el", "checkList")
    script = tmp_path / "probe-markup.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const n = checkList('ready=<img src=x onerror=alert(1)> blocked=0');
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    txt = " ".join(r["text"] for r in got)
    assert "<img" in txt, "the markup was not preserved as literal text"
    assert all("onerror" not in str(r.get("cls", "")) for r in got), \
        "the markup leaked into a class name somewhere"


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


def _seed_digest_tree(root):
    """A scratch copy of exactly the tree build/ui-digest.sh reads.

    The script's own `cd "$(dirname "$0")/.."` is what makes this possible:
    given an absolute path to a copied ui-digest.sh it resolves its "repo
    root" relative to itself, so a copy with the same relative layout is
    indistinguishable from the real tree -- and nothing here can leave the
    tracked directory dirty, even on an interrupted run.
    """
    shutil.copytree(REPO / "ui", root / "ui")
    (root / "build").mkdir(parents=True, exist_ok=True)
    for name in ("ui-digest.sh", "build-ui.sh", "ui-bundle-digest.sh"):
        shutil.copy(REPO / "build" / name, root / "build" / name)
    shutil.copy(REPO / "package.json", root / "package.json")


def _run_digest(root):
    p = subprocess.run(["bash", str(root / "build" / "ui-digest.sh")],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout.strip()


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
    _seed, _digest = _seed_digest_tree, _run_digest

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

    # ui-bundle-digest.sh decides what the OTHER stamp in the bundle means, so
    # a change to it has to surface as "stale, rebuild" -- true and actionable
    # -- rather than one command later as "this bundle has been modified",
    # which would be neither.
    checker_root = tmp_path / "changed_checker"
    _seed(checker_root)
    f = checker_root / "build" / "ui-bundle-digest.sh"
    f.write_text(f.read_text() + "\n# a change to how the bundle is checked\n")
    assert _digest(checker_root) != baseline, \
        "the digest did not change when build/ui-bundle-digest.sh changed"


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


def test_the_built_ui_never_builds_dom_from_html_strings():
    """The scan follows the code, over every module under ui/. It used to read
    a block of dashboard.html; the areas now live under ui/, and a scan left
    pointing at the old place would have kept passing while watching nothing.

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
    this.hidden = false; this.disabled = false; this._attrs = {}; this.dataset = {};
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
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCard",
                              "secCappedScopeNote", "secIndexCards")
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
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCard",
                              "secCappedScopeNote", "secIndexCards")
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
    deps = (_const(block, "SEC_NEVER") + "\n".join(_plainfn(block, n) for n in
            ("secEl", "secIcon", "secHeaderBit", "secRenderProjectHeader")))
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
    deps = _const(block, "SEC_NEVER") + _const(block, "SEC_FLOOR_SCOPE_NOTE") + deps
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
    deps = _const(block, "SEC_NEVER") + deps
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
    deps = _const(block, "SEC_NEVER") + deps
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
    consts = _const(block, "SEV_ORDER") + _const(block, "ROW_PILL_TITLE")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secFindHiddenByFloor", "secFindStrip"))
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
    consts = consts + _const(block, "ROW_PILL_TITLE")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secFindHiddenByFloor", "secFindStrip",
                      "secFindRow", "secFindDecisionControls", "secFindTableSection",
                      "secVisible"))
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


# ---- the Activity screen's own renderer (ui/security/activity-screen.js).
# Same reasoning as the project screen's own Node-driven block above: the
# JSON-contract tests (tests/security/test_cli.py, tests/test_security_api.py)
# never paint anything, so a regression in the empty-state wording, the
# kind-dependent Related-column link, the per-kind sidebar counts, or the
# no-total pager heuristic would pass every one of those. `secActState` is a
# plain module-level object (not a per-host WeakMap like findings-screen.js
# -- there is exactly one #sec-activity in the page), so these harnesses
# declare it directly, the same way _PROJECT_DOM_HARNESS declares `secState`
# for project-screen.js's own module-level reads.

def _activity_deps(block, *names):
    return "\n".join(_plainfn(block, n) for n in names)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_empty_state_names_the_period_and_the_project_scope(srv, tmp_path):
    """'No activity recorded in this period', with the range that was
    searched -- the brief's own wording for why an empty screen must read as
    legibly empty rather than possibly broken. Both halves of the range
    (the day window AND, once scoped, the project) have to be nameable."""
    block = _security_js(srv)
    deps = _activity_deps(block, "secActPeriodPhrase", "secActEmptyMessage")
    script = tmp_path / "act-empty.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {project: "", days: 30};
    """ + deps + """
    const unscoped30 = secActEmptyMessage();
    secActState = {project: "", days: 0};
    const unscopedAll = secActEmptyMessage();
    secActState = {project: "web", days: 7};
    const scoped7 = secActEmptyMessage();
    console.log(JSON.stringify({unscoped30, unscopedAll, scoped7}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "30 days" in out["unscoped30"] and "for " not in out["unscoped30"], out["unscoped30"]
    assert "at any time" in out["unscopedAll"], \
        f"an all-time window must not render as '0 days': {out['unscopedAll']}"
    assert "for web" in out["scoped7"] and "7 days" in out["scoped7"], out["scoped7"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_table_is_empty_state_when_no_events_match(srv, tmp_path):
    block = _security_js(srv)
    deps = _activity_deps(block, "secEl", "secActPeriodPhrase", "secActEmptyMessage",
                          "secActRow", "secActRelatedCell", "secActTable")
    consts = _const(block, "EVENT_KIND_LABEL") + _const(block, "ACT_ANALYSIS_KINDS")
    script = tmp_path / "act-table-empty.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {project: "", days: 30};
    """ + consts + deps + """
    console.log(JSON.stringify(collectAll(secActTable({events: []}), [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "No activity recorded" in joined and "30 days" in joined, joined


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_related_column_links_differently_by_event_kind(srv, tmp_path):
    """An analysis id (analysis_started/analysis_finished/report_exported)
    must read as a link to THAT analysis; a decision's fingerprint prefix
    must read as a link into the findings browser; a kind with no `related`
    (settings_changed) must show a plain dash rather than an empty cell that
    could be mistaken for a rendering bug."""
    block = _security_js(srv)
    deps = _activity_deps(block, "secEl", "secActRow", "secActRelatedCell")
    consts = _const(block, "EVENT_KIND_LABEL") + _const(block, "ACT_ANALYSIS_KINDS")
    script = tmp_path / "act-related.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {project: "", days: 30};
    """ + consts + deps + """
    const rows = [
      {kind: "analysis_started", detail: "standard on main", project: "web",
       related: "4", at: 1},
      {kind: "decision_made", detail: "accepted: reviewed", project: "web",
       related: "abc123def456", at: 2},
      {kind: "settings_changed", detail: "project settings saved", project: "api",
       related: "", at: 3},
    ];
    console.log(JSON.stringify(rows.map(r => collectAll(secActRow(r), []).map(x => x.text).join(" | "))));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "Analysis #4" in out[0], f"an analysis id must render as a link to that analysis: {out[0]}"
    assert "Finding abc123def456…" in out[1], \
        f"a decision's fingerprint must render as a findings-browser link: {out[1]}"
    assert "settings changed" in out[2].lower() and out[2].strip().endswith("—"), \
        f"a kind with no related id must show a plain dash, not an empty cell: {out[2]}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_sidebar_summary_lists_every_kind_even_at_zero(srv, tmp_path):
    """Seeded from EVENT_KINDS the same way queries.activity_summary itself
    is seeded (Task 5) -- an absent kind must still read 0, not be missing
    from the sidebar entirely."""
    block = _security_js(srv)
    deps = _activity_deps(block, "secEl", "secIcon", "secActSummaryCard")
    consts = _const(block, "EVENT_KINDS") + _const(block, "EVENT_KIND_LABEL")
    script = tmp_path / "act-summary.js"
    script.write_text(_PROJECT_DOM_HARNESS + consts + deps + """
    const card = secActSummaryCard({analysis_started: 2});
    console.log(JSON.stringify(collectAll(card, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    for label in ("Analysis started", "Analysis finished", "Decision made",
                  "Settings changed", "Report exported"):
        assert label in joined, f"{label!r} is missing from the sidebar summary: {joined}"
    assert "2" in joined, f"the real count did not render: {joined}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_most_active_projects_is_hidden_behind_one_line_once_scoped(srv, tmp_path):
    """The one-operator reasoning the brief gives for cutting the mockup's
    Users tab, applied to this card too: once the screen is already scoped
    to one project, listing it again as "the most active project" is a
    list of one, which is not an insight."""
    block = _security_js(srv)
    deps = _activity_deps(block, "secEl", "secIcon", "secActPeriodPhrase",
                          "secActEmptyMessage", "_scopeToProject", "secActProjectsCard")
    script = tmp_path / "act-projects.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {project: "", days: 30};
    function secActLoad(){}
    """ + deps + """
    const unscoped = collectAll(
      secActProjectsCard([{project: "web", count: 3}, {project: "api", count: 1}]), []
    ).map(r => r.text).join(" | ");
    secActState.project = "web";
    const scoped = collectAll(secActProjectsCard([{project: "web", count: 3}]), [])
      .map(r => r.text).join(" | ");
    console.log(JSON.stringify({unscoped, scoped}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "web" in out["unscoped"] and "3 events" in out["unscoped"], out["unscoped"]
    assert "Scoped to one project" in out["scoped"], out["scoped"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_pager_infers_a_next_page_from_a_full_page_of_rows(srv, tmp_path):
    """No `total` travels in the payload (see cmd_activity_data's own
    docstring) -- "Next" is enabled exactly when this page came back full,
    disabled the moment it does not, and "Prev" is disabled on page 1."""
    block = _security_js(srv)
    deps = _activity_deps(block, "secEl", "secActPager")
    script = tmp_path / "act-pager.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {page: 1};
    """ + deps + """
    function pagerState(data){
      // secActPager's own, fixed child order: Prev button, the "Page N"
      // span, Next button -- indexed rather than filtered by tagName, since
      // FakeElement (unlike a real DOM) does not uppercase what was passed
      // to document.createElement.
      const p = secActPager(data);
      return {prevDisabled: p.childNodes[0].disabled, nextDisabled: p.childNodes[2].disabled};
    }
    const full = pagerState({page: 1, per_page: 25, events: new Array(25).fill(0)});
    const partial = pagerState({page: 1, per_page: 25, events: new Array(10).fill(0)});
    const page2 = pagerState({page: 2, per_page: 25, events: new Array(25).fill(0)});
    console.log(JSON.stringify({full, partial, page2}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["full"] == {"prevDisabled": True, "nextDisabled": False}, out["full"]
    assert out["partial"]["nextDisabled"], "a partial page must disable Next"
    assert not out["page2"]["prevDisabled"], "Prev must be enabled past page 1"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_switching_the_kind_tab_marks_only_that_tab_active(srv, tmp_path):
    block = _security_js(srv)
    consts = _const(block, "ACT_TABS") + _const(block, "ACT_TAB_BUTTON_ID")
    deps = _activity_deps(block, "secActRenderTabs", "secActSwitchTab")
    script = tmp_path / "act-tabs.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {tab: "", page: 1};
    function secActLoad(){}   // this test is about the active class, not the fetch
    """ + consts + deps + """
    // _PROJECT_DOM_HARNESS's own classList is a no-op SHARED across every
    // instance (fine for the tests that only ever call .toggle() and never
    // read it back) -- this test reads it back per BUTTON, so each instance
    // needs its own backing Set. A getter lazily attaches one per element,
    // rather than one shared object every instance would otherwise alias.
    Object.defineProperty(FakeElement.prototype, "classList", { get(){
      if(!this._classSet) this._classSet = new Set();
      const set = this._classSet;
      return { toggle(name, on){ if(on) set.add(name); else set.delete(name); },
               contains(name){ return set.has(name); } };
    }});
    secActSwitchTab("findings");
    const active = ["secactt-all", "secactt-analyses", "secactt-findings", "secactt-settings"]
      .filter(id => $(id).classList.contains("active"));
    console.log(JSON.stringify(active));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out == ["secactt-findings"], \
        f"switching to 'findings' must mark only its own tab active: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_activity_query_requests_the_exact_kinds_for_each_tab(srv, tmp_path):
    """`ACT_TABS` -> `kind` query parameters, via the real `secActQuery()` --
    the screen's whole filtering mechanism, and nothing before this ever
    called it. The test above (`test_switching_the_kind_tab_marks_only_that_
    tab_active`) only checks which BUTTON gets the `active` class; it stubs
    `secActLoad` to a no-op specifically so the fetch never happens, which
    means it never looks at what `secActQuery()` would have sent. Swapping
    two tabs' `kinds` lists, or renaming a kind in one list but not the
    other, would have passed all twenty-six existing tests and every tab
    would filter the wrong rows -- this is the one test that would have
    caught it."""
    block = _security_js(srv)
    consts = _const(block, "ACT_TABS") + _const(block, "ACT_PER_PAGE")
    deps = _activity_deps(block, "secActSince", "secActQuery")
    script = tmp_path / "act-query-tabs.js"
    script.write_text(consts + deps + """
    let secActState = {tab: "", project: "", days: 30, page: 1};
    function kindsFor(tabKey){
      secActState.tab = tabKey;
      return Array.from(new URLSearchParams(secActQuery()).getAll("kind"));
    }
    const result = {};
    for(const t of ACT_TABS) result[t.key || "all"] = kindsFor(t.key);
    console.log(JSON.stringify(result));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["all"] == [], \
        f"'All activity' must send no kind filter -- empty means every kind: {out['all']}"
    assert out["analyses"] == ["analysis_started", "analysis_finished"], out["analyses"]
    assert out["findings"] == ["decision_made"], out["findings"]
    assert out["settings"] == ["settings_changed", "report_exported"], out["settings"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_every_event_kind_belongs_to_exactly_one_activity_tab(srv, tmp_path):
    """Pins the completeness rule the test above cannot: every kind in
    `EVENT_KINDS` (vocabulary.js) must appear in exactly one of the named
    tabs' `kinds` lists (the "All activity" tab is deliberately excluded --
    its empty list means "every kind", not "no kind", see ACT_TABS's own
    comment). A future sixth event kind that nobody remembers to place in a
    tab would otherwise sit in NONE of them, filtered out of every tab
    forever, unnoticed -- exactly the silent-hole shape this file's fixes
    keep closing."""
    block = _security_js(srv)
    consts = _const(block, "ACT_TABS") + _const(block, "EVENT_KINDS")
    script = tmp_path / "act-tab-completeness.js"
    script.write_text(consts + """
    const named = ACT_TABS.filter(t => t.key !== "");
    const counts = {};
    EVENT_KINDS.forEach(k => { counts[k] = named.filter(t => t.kinds.includes(k)).length; });
    console.log(JSON.stringify(counts));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    missing = [k for k, c in out.items() if c == 0]
    duplicated = [k for k, c in out.items() if c > 1]
    assert not missing, f"kind(s) placed in no tab at all: {missing} ({out})"
    assert not duplicated, f"kind(s) placed in more than one tab: {duplicated} ({out})"


# ---- final whole-branch review: the rendering half of the four Critical
# findings and the screen-level Importants/Minors beside them. Each of these
# fails against the code before its own fix.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_kpi_cards_say_when_a_total_was_read_off_an_undeclared_branch(srv, tmp_path):
    """CRITICAL 1's other half. The project table names a fallback branch per
    row; the cards, summing exactly those postures, said nothing at all --
    and this area's standing rule is that postures of different branches are
    never confused in silence. `fell_back_projects` is the count and this is
    the sentence."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCard",
                              "secCappedScopeNote", "secIndexCards")
    script = tmp_path / "kpi-fellback.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 3, analyses: 4, critical: 2, high: 1,
      capped_projects: 0, fell_back_projects: 1, success_rate: 1.0});
    const clean = secIndexCards({projects: 3, analyses: 4, critical: 2, high: 1,
      capped_projects: 0, fell_back_projects: 0, success_rate: 1.0});
    console.log(JSON.stringify({
      notes: collectAll(cards, []).filter(r => r.cls.indexOf("secidx-note") === 0)
                                  .map(r => r.text),
      cleanNotes: collectAll(clean, []).filter(r => r.cls.indexOf("secidx-note") === 0)
                                       .map(r => r.text),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert any("declared base" in n for n in out["notes"]), \
        f"the cards say nothing about a fallback branch: {out['notes']}"
    assert not any(n == "Open now, in every project's latest analysis"
                   for n in out["notes"]), \
        "the plain 'this is the latest analysis' note still shows over a fallback total"
    # Containment: a fleet with no fallbacks keeps the plain note.
    assert any(n == "Open now, in every project's latest analysis"
               for n in out["cleanNotes"]), out["cleanNotes"]
    assert not any("declared base" in n for n in out["cleanNotes"]), \
        "the fallback caveat fires over a fleet that has none"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_success_rate_card_labels_its_all_time_scope(srv, tmp_path):
    """IMPORTANT 5(b). "Success rate" is an all-time ratio sitting BETWEEN two
    cards that say "open now", and beside one ("Analyses") that is explicitly
    labelled "All time — a historical total". The fifth and sixth instances
    of an unlabelled scope clash on this branch; this is the sixth."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCard",
                              "secCappedScopeNote", "secIndexCards")
    script = tmp_path / "kpi-scope.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 2, analyses: 5, critical: 0, high: 0,
      capped_projects: 0, fell_back_projects: 0, success_rate: 0.8});
    console.log(JSON.stringify(collectAll(cards, []).map(r => r.text)));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    rate_note = next((t for t in out if "completed clean" in t), None)
    assert rate_note is not None, f"no success-rate note rendered at all: {out}"
    assert "All time" in rate_note, \
        f"the all-time ratio is not labelled the way its neighbour is: {rate_note!r}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_index_donut_carries_the_same_capped_cue_the_cards_do(srv, tmp_path):
    """IMPORTANT 8. The donut is the whole fleet's posture in one figure, so
    it has no row to hang the `incomplete` badge off -- and it carried no
    cue at all while the cards and the table rows beside it both did."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon", "secCappedScopeNote",
                              "secIndexDonutSvg", "secIndexDonutLegend",
                              "secIndexCategories", "secIndexDonut")
    consts = (_const(block, "SEV_ORDER5") + _const(block, "SEV_STROKE")
              + _const(block, "DONUT_PILL_TITLE"))
    script = tmp_path / "idx-donut-capped.js"
    script.write_text(_INDEX_DOM_HARNESS + consts + deps + """
    const donut = {critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1};
    const withCue = secIndexDonut(donut, [], secCappedScopeNote(1, 2, "project"));
    const without = secIndexDonut(donut, [], "");
    console.log(JSON.stringify({
      withCue: collectAll(withCue, []).map(r => r.text).join(" "),
      without: collectAll(without, []).map(r => r.text).join(" "),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "stopped before covering" in out["withCue"], \
        f"the donut presents a partial read as a complete one: {out['withCue']}"
    assert "stopped before covering" not in out["without"], \
        "the cue fires with nothing capped behind it"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_donut_paints_info_in_a_colour_that_is_not_the_empty_track(srv, tmp_path):
    """MINOR 2. `info` was `var(--line)` -- the same token the empty track is
    painted with -- so an info segment was invisible against the ring it sat
    on while the legend went on listing its count. `.sevpill.info` and
    `.sevpill.low` are both `var(--muted)` in the stylesheet, which is the
    grouping this table exists to mirror."""
    block = _security_js(srv)
    consts = _const(block, "SEV_ORDER5") + _const(block, "SEV_STROKE")
    deps = _index_screen_deps(block, "secIndexDonutSvg")
    script = tmp_path / "donut-info-colour.js"
    script.write_text(_INDEX_DOM_HARNESS + consts + deps + """
    const svg = secIndexDonutSvg({critical: 0, high: 0, medium: 0, low: 0, info: 3});
    const track = svg.childNodes[0].style.stroke;
    const segs = svg.childNodes.slice(1).map(n => n.style && n.style.stroke).filter(Boolean);
    console.log(JSON.stringify({track, segs, info: SEV_STROKE.info}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["info"] != out["track"], \
        f"the info segment is painted the same colour as the empty track: {out}"
    assert out["segs"] and out["segs"][0] != out["track"], out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_branches_tab_marks_a_branch_whose_last_analysis_stopped_early(srv, tmp_path):
    """CRITICAL 3's rendering half. `branch_rows` now carries the state its
    posture was read from; this is the Branches tab saying so, with the cue
    Task 8 established (`secidx-capped`, "incomplete", the same explanatory
    title) plus a column of its own so a reader can scan for it."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIndexPosturePills", "secBranchesCaption",
                      "secBranchTrendText", "secBranchRow", "secBranchesTable",
                      "secRenderProjectBranches"))
    deps = _const(block, "SEC_NEVER") + _const(block, "BRANCH_CAPPED_TITLE") + deps
    script = tmp_path / "pj-branches-capped.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectBranches({tabs: {overview: {attempted: true}, branches: [
      {branch: "main", last_analysis: 1700000000, analyses: 2, state: "capped",
       open: {critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0},
       trend: [{open: 0, state: "capped"}]},
      {branch: "develop", last_analysis: 1700000100, analyses: 1, state: "done",
       open: {critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1},
       trend: [{open: 2, state: "done"}, {open: 1, state: "done"}]},
    ]}});
    console.log(JSON.stringify(collectAll(_els["sec-pj-branches"], [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    badges = [r for r in out if r["cls"] == "secidx-capped"]
    assert badges, f"a capped branch got no incomplete cue at all: {joined}"
    assert badges[0]["text"] == "incomplete", badges[0]
    assert "stopped before covering" in badges[0]["title"].lower(), badges[0]
    assert "capped" in joined and "done" in joined, \
        f"the state column did not render: {joined}"
    # Containment: exactly one badge -- the done branch must not get one.
    assert len(badges) == 1, f"the cue fired over a finished branch too: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_branch_trend_refuses_a_direction_across_a_partial_read(srv, tmp_path):
    """CRITICAL 3, the other half: a `capped` point's `open` count is what
    that run reached before it stopped, not what was there -- so "falling"
    read across one is a claim about the CODE made from a fact about the RUN.
    The numbers still show (they were recorded); the direction word does
    not, the same way this function already withholds one from a series that
    went both ways."""
    block = _security_js(srv)
    fn = _plainfn(block, "secBranchTrendText")
    script = tmp_path / "trend-capped.js"
    script.write_text(fn + """
    console.log(JSON.stringify({
      cappedEnd: secBranchTrendText([{open: 5, state: "done"}, {open: 1, state: "capped"}]),
      cappedStart: secBranchTrendText([{open: 5, state: "capped"}, {open: 1, state: "done"}]),
      allDone: secBranchTrendText([{open: 5, state: "done"}, {open: 1, state: "done"}]),
      oneCapped: secBranchTrendText([{open: 3, state: "capped"}]),
      oneDone: secBranchTrendText([{open: 3, state: "done"}]),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "falling" not in out["cappedEnd"], \
        f"a direction is claimed across a run that simply stopped: {out['cappedEnd']}"
    assert "5 → 1" in out["cappedEnd"], \
        f"the recorded numbers must still show: {out['cappedEnd']}"
    assert "stopped before covering" in out["cappedEnd"], out["cappedEnd"]
    assert "falling" not in out["cappedStart"], out["cappedStart"]
    # Containment: a series with no partial point keeps its direction word.
    assert "falling" in out["allDone"], out["allDone"]
    assert "stopped early" in out["oneCapped"], out["oneCapped"]
    assert "stopped early" not in out["oneDone"], out["oneDone"]


def test_every_never_analysed_sentence_comes_from_one_place(srv):
    """MINOR 1. Six near-variants of "never analysed" lived across four
    modules, three of them telling the reader what to do next and three not,
    twice on the same screen. They are one constant now (SEC_NEVER in
    vocabulary.js) rendered at two densities, and this is what stops a
    seventh being typed inline next time."""
    block = _security_js(srv)
    for literal in ('"Never analysed. Switch to Runs to pick a branch and start."',
                    '"No analysis of this project has finished yet — see Runs for what was attempted."',
                    '"No finished analysis yet."',
                    '"No analysis of this branch yet — press Analyse to make the first one."',
                    '"Pick a branch, or type one, and press Analyse."'):
        assert block.count(literal) <= 1, \
            f"this sentence is typed inline somewhere as well as in SEC_NEVER: {literal}"
    # ...and every one of them is reachable from the one constant.
    assert "export const SEC_NEVER" in block
    for key in ("short:", "next:", "attempted:", "branch:", "pickBranch:"):
        assert key in block, f"SEC_NEVER lost its {key} member"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_findings_strip_never_paints_a_green_all_clear_over_an_unread_project(
        srv, tmp_path):
    """CRITICAL 2. `findings-page` carried no never-analysed signal, so a
    project nobody has ever analysed rendered "nothing matches" in the
    ok-green `.sevpill.clean` beside "0 total", with the table below blaming
    filters the reader never set. Overview and Branches both draw the
    distinction one module away, from the same two facts, in the same
    words."""
    block = _security_js(srv)
    consts = (_const(block, "SEV_ORDER") + _const(block, "SEC_NEVER")
              + _const(block, "ROW_PILL_TITLE"))
    # `secVisible` is deliberately absent: every payload below carries an
    # empty `rows`, and secFindTableSection answers that before it ever
    # reaches the floor -- which is the case under test.
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secFindHiddenByFloor", "secFindStrip",
                      "secFindTableSection"))
    script = tmp_path / "find-never.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function secMinSeverity(_p){ return "low"; }
    const fs = {project: "web", filters: {}};
    """ + consts + deps + """
    const empty = {critical:0, high:0, medium:0, low:0, info:0};
    function payload(extra){
      return Object.assign({rows: [], total: 0, unique: 0, by_severity: empty,
        fixed_by_severity: empty, page: 1, per_page: 25}, extra);
    }
    const never = payload({attempted: false, analysed: false});
    const failed = payload({attempted: true, analysed: false});
    const clean = payload({attempted: true, analysed: true});
    function shot(data){
      return {strip: collectAll(secFindStrip(fs, data), []),
              table: collectAll(secFindTableSection(fs, data), [])
                       .map(r => r.text).join(" ")};
    }
    console.log(JSON.stringify({never: shot(never), failed: shot(failed),
                                clean: shot(clean)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)

    def cleanpills(shot):
        return [r for r in shot["strip"] if "clean" in r["cls"]]

    assert not cleanpills(out["never"]), \
        f"an ok-green all-clear over a project nobody analysed: {out['never']['strip']}"
    assert not cleanpills(out["failed"]), \
        f"an ok-green all-clear over a project whose analyses all failed: {out['failed']['strip']}"
    assert cleanpills(out["clean"]), \
        "a genuinely empty result on an analysed project lost its clean pill"

    never_strip = " ".join(r["text"] for r in out["never"]["strip"])
    failed_strip = " ".join(r["text"] for r in out["failed"]["strip"])
    assert "Never analysed" in never_strip, never_strip
    assert "finished yet" in failed_strip, failed_strip
    assert never_strip != failed_strip, \
        "never-analysed and every-attempt-failed render identically"

    assert "Never analysed" in out["never"]["table"], out["never"]["table"]
    assert "match these filters" not in out["never"]["table"], \
        f"the table still blames filters the reader never set: {out['never']['table']}"
    assert "match these filters" in out["clean"]["table"], \
        "an analysed project's genuinely empty table lost its filter explanation"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_findings_strip_says_when_a_branch_behind_it_stopped_early(srv, tmp_path):
    """IMPORTANT 8, the strip's half. These rows are unioned across branches;
    if one of those branches' latest analysis stopped short, the counts above
    them are what was reached, not what is there."""
    block = _security_js(srv)
    consts = (_const(block, "SEV_ORDER") + _const(block, "SEC_NEVER")
              + _const(block, "ROW_PILL_TITLE"))
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secFindHiddenByFloor", "secFindStrip"))
    script = tmp_path / "find-capped.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function secMinSeverity(_p){ return "low"; }
    const fs = {project: "web", filters: {}};
    """ + consts + deps + """
    const sev = {critical:1, high:0, medium:0, low:0, info:0};
    const base = {rows: [], total: 1, unique: 1, by_severity: sev,
      fixed_by_severity: {critical:0,high:0,medium:0,low:0,info:0},
      page: 1, per_page: 25, attempted: true, analysed: true};
    console.log(JSON.stringify({
      capped: collectAll(secFindStrip(fs, Object.assign({}, base,
        {capped_branches: 1})), []).map(r => r.text).join(" "),
      whole: collectAll(secFindStrip(fs, Object.assign({}, base,
        {capped_branches: 0})), []).map(r => r.text).join(" "),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "stopped before covering" in out["capped"], \
        f"the strip presents a partial read as a complete one: {out['capped']}"
    assert "stopped before covering" not in out["whole"], \
        "the cue fires with nothing capped behind it"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_two_kinds_of_severity_pill_each_say_what_they_count(srv, tmp_path):
    """IMPORTANT 5(a). The sidebar donut is a flex sibling of the tab panes,
    so it is on screen DURING the Findings tab: the strip's per-severity
    pills are ROW counts and the donut's are DISTINCT FINGERPRINTS, four
    inches apart, in identical markup. The strip labelled `total` vs `unique`
    and left both sets of per-severity pills bare."""
    block = _security_js(srv)
    strip_consts = (_const(block, "SEV_ORDER") + _const(block, "SEC_NEVER")
                    + _const(block, "ROW_PILL_TITLE"))
    strip_deps = "\n".join(_plainfn(block, n) for n in
                           ("secEl", "secIcon", "secFindHiddenByFloor", "secFindStrip"))
    donut_consts = _const(block, "SEV_ORDER5") + _const(block, "DONUT_PILL_TITLE")
    donut_deps = _plainfn(block, "secIndexDonutLegend")
    script = tmp_path / "pill-scopes.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function secMinSeverity(_p){ return "low"; }
    const fs = {project: "web", filters: {}};
    """ + strip_consts + strip_deps + donut_consts + donut_deps + """
    const sev = {critical: 2, high: 0, medium: 0, low: 0, info: 0};
    const strip = collectAll(secFindStrip(fs, {rows: [], total: 2, unique: 1,
      by_severity: sev, fixed_by_severity: {critical:0,high:0,medium:0,low:0,info:0},
      page: 1, per_page: 25, attempted: true, analysed: true}), []);
    const legend = collectAll(secIndexDonutLegend({critical: 1}), []);
    const pill = (rows) => rows.filter(r => r.cls === "sevpill critical")[0] || {};
    console.log(JSON.stringify({strip: pill(strip), legend: pill(legend)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["strip"].get("text") == "2 critical", out["strip"]
    assert out["legend"].get("text") == "1 critical", out["legend"]
    assert "Rows" in out["strip"].get("title", ""), \
        f"the strip's severity pill does not say it counts rows: {out['strip']}"
    assert "counts twice" in out["strip"].get("title", ""), out["strip"]
    assert "fingerprint" in out["legend"].get("title", "").lower(), \
        f"the donut's severity pill does not say it counts problems: {out['legend']}"
    assert "counts once" in out["legend"].get("title", ""), out["legend"]
    assert out["strip"]["title"] != out["legend"]["title"], \
        "two numbers answering different questions still carry the same explanation"


def test_the_severity_floors_scope_is_stated_where_the_unfloored_numbers_are(srv):
    """IMPORTANT 6. The floor was applied on two surfaces (the single-analysis
    checklist and the findings table) and ignored on six (Overview chips,
    index KPIs and posture pills, Branches "Open", both donuts) -- and only
    the two that applied it said so. The decision written down in
    vocabulary.js is that the floor is a DRILL-DOWN reading aid and never
    narrows a posture total; this pins that it is said once on each screen
    that carries an unfloored number."""
    block = _security_js(srv)
    assert "export const SEC_FLOOR_SCOPE_NOTE" in block, \
        "the decision is not written down anywhere"
    # Said on the index screen (its KPI cards, posture pills and donut are all
    # unfloored) and on the project screen (the sidebar is a flex sibling of
    # every tab pane, so one line there is readable from all five).
    for fn in ("secRenderIndex", "secSidebarCaption"):
        assert "SEC_FLOOR_SCOPE_NOTE" in _plainfn(block, fn), \
            f"{fn} shows unfloored numbers and does not say so"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_project_header_says_a_dash_means_not_counted(srv, tmp_path):
    """MINOR 4. "Lines of code: —" never said that the dash means "not
    counted" rather than zero, so a reader had no way to tell it from this
    screen claiming the repository is empty."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_NEVER") + "\n".join(_plainfn(block, n) for n in
            ("secEl", "secIcon", "secHeaderBit", "secRenderProjectHeader")))
    script = tmp_path / "pj-loc-title.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectHeader({header: {profile: "standard", branch: "main",
      branch_fell_back: false, lines_of_code: 0, last_analysis: 0}});
    const dashed = collectAll(_els["sec-pj-head"], []);
    _els["sec-pj-head"] = new FakeElement("div");
    secRenderProjectHeader({header: {profile: "standard", branch: "main",
      branch_fell_back: false, lines_of_code: 1200, last_analysis: 5}});
    const counted = collectAll(_els["sec-pj-head"], []);
    console.log(JSON.stringify({dashed, counted}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    titles = " ".join(r["title"] for r in out["dashed"] if r["title"])
    assert "Not counted" in titles, \
        f"the dash never says it means 'not counted': {titles!r}"
    assert "not a claim that the repository is empty" in titles.lower(), titles
    # ...and the never-analysed cell beside it carries the one wording's own
    # next step rather than being a dead end.
    assert "switch to Runs" in titles, titles
    counted_titles = " ".join(r["title"] for r in out["counted"] if r["title"])
    assert "Not counted" not in counted_titles, \
        "the explanation shows over a real line count"


def test_the_activity_fingerprint_dialog_titles_the_project_not_the_filter(srv):
    """MINOR 3. The dialog's title was set once, when it opened, and never
    heard about what happened inside it -- so a title naming the fingerprint
    survived "Clear filters" and read "Finding a3f9c2… in minerva" over that
    project's whole list. The fingerprint scope belongs where it disappears
    with the filter it describes, and it already lives there: secFindStrip
    renders "Filtered to fingerprint …" from `fs.filters` on every paint."""
    block = _security_js(srv)
    opener = _plainfn(block, "secActOpenFinding")
    assert '"Finding " + fingerprintPrefix' not in opener, \
        "the dialog title still names a filter that Clear filters can drop"
    assert '"Findings in " + project' in opener, opener
    # The fact itself is not lost -- it is rendered from live filter state.
    assert "Filtered to fingerprint " in _plainfn(block, "secFindStrip")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_history_list_follows_the_analysis_on_screen_not_the_picker(srv, tmp_path):
    """CRITICAL 4. "Earlier analyses of this branch" filtered on
    `secState.branch` -- the PICKER's value -- not the branch of the analysis
    being shown. Open a `develop` run from the Runs table (or from the
    Activity screen's deep link) while the picker still says `main`, and the
    status line reads `develop` while the list under it is `main`'s."""
    block = _security_js(srv)
    fn = _plainfn(block, "secEl") + _plainfn(block, "secRenderHistory")
    script = tmp_path / "history-scope.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    const _els = {};
    function $(id){ if(!_els[id]) _els[id] = new FakeElement("div"); return _els[id]; }
    function fmtWhen(t){ return "w" + t; }
    function money(n){ return "$" + n; }
    function secRunFor(_a){ return null; }
    function secShowAnalysis(){}
    const secState = {
      repo: "web", branch: "main",              // the PICKER still says main
      analysis: {id: 9, repo: "web", branch: "develop"},   // ...the pane shows develop
      analyses: [
        {id: 9, repo: "web", branch: "develop", state: "done", profile: "quick",
         commit_sha: "dddddddddddddddd", started: 2, spend_usd: 0},
        {id: 4, repo: "web", branch: "develop", state: "done", profile: "quick",
         commit_sha: "eeeeeeeeeeeeeeee", started: 1, spend_usd: 0},
        {id: 7, repo: "web", branch: "main", state: "done", profile: "quick",
         commit_sha: "aaaaaaaaaaaaaaaa", started: 3, spend_usd: 0},
      ],
    };
    """ + fn + """
    secRenderHistory();
    const listed = collectAll(_els["sec-history"], [])
      .filter(r => r.cls === "btn ghost").map(r => r.text);
    // ...and with nothing open, the picker is the only scope there is.
    secState.analysis = null;
    _els["sec-history"] = new FakeElement("div");
    secRenderHistory();
    const fromPicker = collectAll(_els["sec-history"], [])
      .filter(r => r.cls === "btn ghost").map(r => r.text);
    console.log(JSON.stringify({listed, fromPicker}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["listed"] == ["#9", "#4"], \
        f"the history followed the picker, not the analysis on screen: {out['listed']}"
    assert "#7" not in out["listed"], \
        "another branch's analysis is listed under 'Earlier analyses of this branch'"
    assert out["fromPicker"] == ["#7"], \
        f"with no analysis open the picker must still scope the list: {out['fromPicker']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_poll_does_not_replace_a_deliberately_opened_analysis(srv, tmp_path):
    """CRITICAL 4's other half. secReload recomputed the analysis to show
    from the picker on every 4-second tick, so an analysis opened on purpose
    -- a Runs row, an "#N" in the history, the Activity screen's deep link --
    was swapped out from under the reader within four seconds. It must still
    be RE-FETCHED (a pinned running analysis has to keep moving); it must
    just not be replaced by a different one."""
    block = _security_js(srv)
    src = _anyfn(block, "secReload")
    script = tmp_path / "poll-pinned.js"
    script.write_text("""
    let secProjectPollWasRunning = null;
    const CC = {currentView: "security"};
    const shown = [];
    const secState = {project: "web", repo: "web", branch: "main",
                      analysis: {id: 4, repo: "web", branch: "develop"},
                      analyses: [], pinned: true};
    function secRefreshProject(){}
    function secSyncPoll(){}
    function secStopPoll(){}
    async function secShowAnalysis(id, pinned){ shown.push([id, !!pinned]); }
    const listing = [{id: 9, repo: "web", branch: "main", state: "done"}];
    async function secFetch(_path){ return listing; }
    """ + src + """
    (async () => {
      await secReload(false);            // a poll tick over a pinned analysis
      const pinnedTick = shown.slice();
      secState.pinned = false;
      secState.analysis = {id: 4, repo: "web", branch: "develop"};
      shown.length = 0;
      await secReload(false);            // ...and one over an unpinned screen
      console.log(JSON.stringify({pinnedTick, unpinnedTick: shown}));
    })();
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["pinnedTick"] == [[4, True]], \
        f"the poll replaced a deliberately opened analysis: {out['pinnedTick']}"
    assert out["unpinnedTick"] == [[9, False]], \
        ("an unpinned screen must still follow the branch's newest analysis: "
         f"{out['unpinnedTick']}")


def test_every_deliberate_open_of_one_analysis_pins_it(srv):
    """The containment half of CRITICAL 4: the fix is only real if every
    caller that names ONE analysis passes the flag. Three do -- the Runs
    table's row button, the history list's "#N", and the Activity screen's
    deep link -- and `secSyncScope`, which resolves from the picker, must
    NOT, or a picker change could never be followed again."""
    block = _security_js(srv)
    for fn in ("secRunRow", "secActOpenAnalysis"):
        src = _anyfn(block, fn)
        assert "secShowAnalysis(" in src and ", true)" in src, \
            f"{fn} opens one analysis without pinning it: {src}"
    assert "secShowAnalysis(a.id, true)" in _plainfn(block, "secRenderHistory")
    sync = _anyfn(block, "secSyncScope")
    assert "secShowAnalysis(mine.length ? mine[0].id : null)" in sync, \
        f"the picker's own resolution must not pin: {sync}"


# ---- final whole-branch review, IMPORTANT 3 and MINORS 6/7: the freshness
# guard over the COMMITTED bundle. `bin/static/security.js` is a build output
# in git, which is the price of never needing Node to install claude-cron --
# and the selftest's own sentence claims this guard is what stops a stale or
# mangled one shipping. It could not detect a modified bundle at all.

def _bundle_digest(script, bundle):
    return subprocess.run(["bash", str(script), str(bundle)],
                          capture_output=True, text=True)


def test_the_bundles_own_body_is_hashed_not_only_its_sources(tmp_path):
    """IMPORTANT 3, reproduction one: inject code straight into
    bin/static/security.js with every source and every toolchain file left
    untouched. Nothing hashed the committed bytes, so the guard said "ok".
    The honest-mistake case (edit ui/, forget to rebuild) was always caught;
    a mangled merge conflict inside a 90 KB generated file -- which nobody
    reads to find -- was not."""
    script = REPO / "build" / "ui-bundle-digest.sh"
    real = (REPO / "bin" / "static" / "security.js").read_text()
    assert "/* ui-bundle: " in real, \
        "the committed bundle carries no body stamp at all"
    stamped = re.search(r"^/\* ui-bundle: ([0-9a-f]{64}) \*/$", real, re.M).group(1)

    # Kept under its OWN basename, security.js, in a throwaway directory of
    # its own: the stamp now binds the artifact's name as well as its body
    # (see this test's sibling, test_a_files_own_stamp_does_not_verify_
    # under_a_different_name, below) so copying this content to a
    # differently-named file would legitimately produce a different digest
    # -- that is the fix, not a bug this test should trip over.
    clean_dir = tmp_path / "clean"; clean_dir.mkdir()
    clean = clean_dir / "security.js"
    clean.write_text(real)
    p = _bundle_digest(script, clean)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == stamped, \
        "the committed bundle does not hash to its own stamp — rebuild it"

    # ...and the same file, same name, with one line of injected code in its
    # body does not.
    lines = real.splitlines(True)
    lines.insert(len(lines) - 2, "window.__pwned = 1;\n")
    tampered_dir = tmp_path / "tampered"; tampered_dir.mkdir()
    tampered = tampered_dir / "security.js"
    tampered.write_text("".join(lines))
    p = _bundle_digest(script, tampered)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() != stamped, \
        "a bundle with injected code still hashes to the stamp it carries"


def test_a_files_own_stamp_does_not_verify_under_a_different_name(tmp_path):
    """Finding B: `cp bin/static/app.js bin/static/app.css` used to pass the
    selftest with every artifact reading 'ok' -- ui-bundle hashed a file's
    own body against itself with no mention anywhere of WHICH artifact that
    body was supposed to be, so app.js's bytes, stamp included, verified
    just as cleanly sitting under app.css's name as they did under their
    own. The fix binds the artifact's basename into the same hash the body
    goes through, so a digest taken under one name cannot be replayed as
    proof for a file of another name."""
    script = REPO / "build" / "ui-bundle-digest.sh"
    body = "window.x = 1;\n"
    as_js = tmp_path / "app.js"
    as_js.write_text(body)
    as_css = tmp_path / "app.css"
    as_css.write_text(body)
    hash_js = _bundle_digest(script, as_js).stdout.strip()
    hash_css = _bundle_digest(script, as_css).stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{64}", hash_js), "could not digest app.js"
    assert re.fullmatch(r"[0-9a-f]{64}", hash_css), "could not digest app.css"
    assert hash_js != hash_css, (
        "two files with IDENTICAL bodies but different names hashed the "
        "same — a stamp computed for one would silently verify for the "
        "other after a swap"
    )


def test_a_second_stamp_line_is_refused_rather_than_silently_preferred(tmp_path):
    """IMPORTANT 3, reproduction two: the selftest read the source stamp with
    `sed ... | tail -1`, so appending a SECOND `// ui-sources:` line carrying
    a freshly computed digest satisfied it while the real stamp -- the one
    describing the bytes above it -- sat ignored one line up. A trailing
    comment is the cheapest thing in the world to append to a file, so an
    ambiguous stamp has to be refused, not resolved by picking one."""
    script = REPO / "build" / "ui-bundle-digest.sh"
    real = (REPO / "bin" / "static" / "security.js").read_text()
    for kind in ("ui-sources", "ui-bundle"):
        doubled = tmp_path / f"doubled-{kind}.js"
        doubled.write_text(real + f"/* {kind}: {'0' * 64} */\n")
        p = _bundle_digest(script, doubled)
        assert p.returncode != 0, \
            f"a second /* {kind}: ... */ stamp was accepted: {p.stdout!r}"
        assert "exactly" in p.stderr and kind in p.stderr, p.stderr


def test_the_stamp_form_is_a_block_comment_so_css_can_carry_it(tmp_path):
    """One stamp form across every built artifact. CSS has no `//` comment,
    and the alternative -- a line form for JS and a block form for CSS -- is
    two spellings for every reader to accept and one of them to forget. The
    block form is valid in both languages, so there is only ever one."""
    art = tmp_path / "app.css"
    art.write_text(":root{--bg:#fff}\n")
    body = subprocess.run(["bash", str(REPO / "build" / "ui-bundle-digest.sh"),
                           str(art)], capture_output=True, text=True,
                          check=True).stdout.strip()
    art.write_text(":root{--bg:#fff}\n"
                   f"/* ui-bundle: {body} */\n"
                   f"/* ui-sources: {'d' * 64} */\n")
    again = subprocess.run(["bash", str(REPO / "build" / "ui-bundle-digest.sh"),
                            str(art)], capture_output=True, text=True,
                           check=True).stdout.strip()
    assert again == body, (
        "the stamps were not stripped before hashing -- a stamped artifact "
        "no longer hashes to what the build recorded for it"
    )


def test_a_second_block_stamp_is_refused_in_either_language(tmp_path):
    """The exactly-one rule is what stops a freshly computed stamp being
    appended below the real one and read instead of it. It has to hold for
    the block form too, or the hole simply moved."""
    for name in ("app.css", "app.js"):
        art = tmp_path / name
        art.write_text("body{}\n"
                       f"/* ui-sources: {'a' * 64} */\n"
                       f"/* ui-sources: {'b' * 64} */\n")
        r = subprocess.run(["bash", str(REPO / "build" / "ui-bundle-digest.sh"),
                            str(art)], capture_output=True, text=True)
        assert r.returncode == 1, f"{name}: a doubled stamp was accepted"
        assert "stamps" in r.stderr, f"{name}: refused without saying why"


def test_a_stamp_cannot_be_closed_and_reopened_to_smuggle_code_past_the_hash(tmp_path):
    """CRITICAL: a block comment, unlike the `//` form it replaced, can be
    closed and reopened MID-LINE. One physical line --
    `/* ui-bundle: <real hash> */<injected code>/* ui-bundle: <fake hash> */`
    -- used to count as exactly one stamp (the "more than one" refusal never
    fired) and get stripped WHOLE by `grep -v`'s greedy `.*`, so the injected
    code between the two markers never reached the hash at all: the tampered
    artifact hashed identically to the untampered body. Anchoring the
    captured value to the fixed 64-hex-character SHA-256 shape means a line
    carrying anything extra does not match the stamp pattern at all, so it
    stays in the body and the hash mismatch catches it."""
    script = REPO / "build" / "ui-bundle-digest.sh"
    for name, body in (("app.js", "window.x = 1;\n"), ("app.css", "body{color:red}\n")):
        plain = tmp_path / name
        plain.write_text(body)
        body_hash = _bundle_digest(script, plain).stdout.strip()
        assert re.fullmatch(r"[0-9a-f]{64}", body_hash), \
            f"{name}: could not establish the untampered body's own digest"

        crammed = tmp_path / f"crammed-{name}"
        crammed.write_text(
            body +
            f"/* ui-bundle: {body_hash} */window.__pwned = 'HACKED';"
            f"/* ui-bundle: {'0' * 64} */\n"
        )
        tampered_hash = _bundle_digest(script, crammed).stdout.strip()
        assert tampered_hash != body_hash, (
            f"{name}: a stamp closed and reopened mid-line hid injected code "
            f"from the hash — the tampered artifact digests identically to "
            f"the untampered body"
        )


def test_the_selftest_reads_both_stamps_and_refuses_an_ambiguous_one():
    """Structural: the engine's own check has to ask BOTH questions and read
    each stamp with an exactly-one rule. `tail -1` on a stamp line is the
    exact shape of reproduction two above and must not come back."""
    engine = ENGINE.read_text()
    # check_ui_artifact() is the one place both questions get asked -- lifted
    # above cmd_selftest so a second and third artifact call it rather than
    # copying the block.
    block = engine[engine.index("check_ui_artifact() {"):]
    block = block[:block.index("\ncmd_selftest()")]
    # Comment lines stripped: this block EXPLAINS the `tail -1` it replaced,
    # and a guard that cannot tell an explanation from the thing it warns
    # against fails on its own documentation.
    code = "\n".join(line for line in block.splitlines()
                     if not line.strip().startswith("#"))
    assert "ui-bundle-digest.sh" in code, \
        "the selftest never recomputes the bundle's own body hash"
    assert "tail -1" not in code, \
        "a stamp is still read with tail -1, which a second stamp line defeats"
    assert "grep -c '^/\\* ui-sources: [0-9a-f]\\{64\\} \\*/$'" in code \
        and "grep -c '^/\\* ui-bundle: [0-9a-f]\\{64\\} \\*/$'" in code, \
        "the selftest does not count the stamps before trusting them"
    assert "MODIFIED" in code, \
        "a modified bundle and a stale one get the same message"
    assert ".*" not in code, (
        "a stamp is still captured with a greedy `.*` -- a block comment can "
        "be closed and reopened mid-line, so anything less than the fixed "
        "64-hex-character SHA-256 shape lets injected code between two "
        "markers hide from the hash"
    )


def test_the_digest_cannot_confuse_one_files_content_for_the_next_files_path(tmp_path):
    """MINOR 6, first half. The digest streamed `path\\n` + raw bytes with no
    boundary between one file's content and the next file's path line, so a
    file whose last byte is not a newline runs straight into it. These two
    trees are genuinely different and streamed IDENTICALLY under the old
    scheme -- `{a.js: "", b.js: "Z\\n"}` and `{a.js: "ui/b.js\\nZ\\n"}` both
    come out as "ui/a.js\\nui/b.js\\nZ\\n"."""
    def build(root, files):
        (root / "ui").mkdir(parents=True)
        (root / "build").mkdir(parents=True)
        for name in ("ui-digest.sh", "build-ui.sh", "ui-bundle-digest.sh"):
            shutil.copy(REPO / "build" / name, root / "build" / name)
        shutil.copy(REPO / "package.json", root / "package.json")
        for name, body in files.items():
            (root / "ui" / name).write_text(body)
        return _run_digest(root)

    two_files = build(tmp_path / "two", {"a.js": "", "b.js": "Z\n"})
    one_file = build(tmp_path / "one", {"a.js": "ui/b.js\nZ\n"})
    assert two_files != one_file, \
        "two different trees produce the same fingerprint — one file's content is being read as the next one's path"


def test_the_digest_covers_every_file_under_ui_not_only_dot_js(tmp_path):
    """MINOR 6, second half. esbuild bundles whatever ui/security/index.js
    reaches by import, and its own default resolution reaches .ts, .tsx,
    .jsx, .json and .css as readily as .js -- so a `-name '*.js'` glob
    fingerprinted a subset of what the build actually consumes, and any other
    input could change the committed bytes without changing the digest that
    is supposed to describe them."""
    root = tmp_path / "tree"
    _seed_digest_tree(root)
    baseline = _run_digest(root)
    for name in ("shared.json", "theme.css", "helper.ts"):
        (root / "ui" / name).write_text("x\n")
        assert _run_digest(root) != baseline, \
            f"a {name} under ui/ is bundleable and does not change the digest"
        (root / "ui" / name).unlink()
    assert _run_digest(root) == baseline, "removing them again must restore it"


def test_an_ignored_file_under_ui_does_not_redden_the_selftest(tmp_path):
    """MINOR 7. A stray untracked, ignored file under ui/ -- a scratch .js, an
    editor backup, a .DS_Store -- is not an input to anything and is in
    nobody else's checkout, yet it changed the digest: the selftest went red
    over a tree `git status` called clean, and the only way out was to find
    and delete a file nothing had mentioned.

    Driven against a real scratch `git init` (never the tracked tree), since
    the filter is `git ls-files --others --ignored --exclude-standard` and
    there is nothing honest to test without a git checkout to ask."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    _seed_digest_tree(root)
    (root / ".gitignore").write_text("*.local.js\nscratch/\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "seed"], cwd=root, check=True,
                   capture_output=True)
    baseline = _run_digest(root)

    (root / "ui" / "notes.local.js").write_text("let scratch = 1;\n")
    (root / "ui" / "scratch").mkdir()
    (root / "ui" / "scratch" / "x.js").write_text("let y = 2;\n")
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                           capture_output=True, text=True, check=True).stdout
    assert dirty.strip() == "", f"the probe files were not actually ignored: {dirty!r}"
    assert _run_digest(root) == baseline, \
        "an ignored, untracked file under ui/ still changes the fingerprint"

    # Containment: a TRACKED file must never be dropped from the fingerprint,
    # whatever an over-broad ignore pattern says about it. `--others` is what
    # guarantees that, and it is the whole reason this is not `check-ignore`.
    tracked = root / "ui" / "real.local.js"
    tracked.write_text("export const real = 1;\n")
    subprocess.run(["git", "add", "-f", str(tracked)], cwd=root, check=True,
                   capture_output=True)
    assert _run_digest(root) != baseline, \
        "a tracked file was dropped from the fingerprint by an ignore pattern"


_PLACEHOLDER_CLASS = re.compile(r"^__[A-Z]+__$")


def _classes_in_static_markup(html_text):
    """Every literal `class="..."` (or `'...'`) value in `html_text` outside
    <script> blocks, split into individual class names. `__BOOT__`,
    `__BUILD__`, `__TOKEN__` and `__FAVICON__` are template placeholders the
    server substitutes before serving (see
    test_the_page_renders_with_the_token_and_favicon_substituted) rather than
    real class names, so tokens matching that shape are excluded."""
    markup = re.sub(r"<script\b[^>]*>.*?</script>", "", html_text,
                     flags=re.S | re.I)
    used = {}
    for m in re.finditer(r'class=(?:"([^"]*)"|\'([^\']*)\')', markup):
        value = m.group(1) if m.group(1) is not None else m.group(2)
        for cls in value.split():
            if _PLACEHOLDER_CLASS.match(cls):
                continue
            used.setdefault(cls, set()).add("bin/dashboard.html")
    return used


class _NotLiteral(Exception):
    """The class expression is not a plain string, nor a `+` chain of plain
    strings and ternaries between plain strings, so its value cannot be
    known without running the page."""


def _skip_js_string(s, i):
    quote = s[i]
    i += 1
    while i < len(s) and s[i] != quote:
        i += 2 if s[i] == "\\" else 1
    return i + 1


def _matching_paren(s, i):
    depth = 0
    while i < len(s):
        c = s[i]
        if c in "\"'":
            i = _skip_js_string(s, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _NotLiteral("unbalanced parentheses")


def _split_top_level(s, sep):
    """Split `s` on `sep`, ignoring occurrences inside a string or nested
    ()/[]."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(s):
        c = s[i]
        if c in "\"'":
            j = _skip_js_string(s, i)
            cur.append(s[i:j])
            i = j
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if depth == 0 and s.startswith(sep, i):
            parts.append("".join(cur))
            cur = []
            i += len(sep)
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _literal_values(expr):
    """The set of strings a JS expression can evaluate to -- IF it is built
    only from string literals and `+`, plus ternaries whose two branches are
    themselves such expressions (`"btn " + (a.primary ? "primary" :
    "ghost")`, `"secchip" + (n ? "" : " zero") + (on ? " on" : "")`, both
    patterns this codebase actually uses). Anything else -- a bare
    identifier, a function call, a template literal -- raises _NotLiteral."""
    expr = expr.strip()
    if expr == "":
        return {""}
    values = {""}
    for term in _split_top_level(expr, "+"):
        values = {a + b for a in values for b in _literal_term(term.strip())}
    return values


def _literal_term(term):
    if not term:
        raise _NotLiteral("empty term")
    if term[0] in "\"'":
        end = _skip_js_string(term, 0)
        if end != len(term):
            raise _NotLiteral(f"trailing content after a string: {term!r}")
        return {term[1:-1]}
    if term[0] != "(":
        raise _NotLiteral(f"not a string literal or a ternary: {term!r}")
    close = _matching_paren(term, 0)
    if close != len(term) - 1:
        raise _NotLiteral(f"trailing content after ')': {term!r}")
    inner = term[1:close]
    depth, i, qpos = 0, 0, None
    while i < len(inner):
        c = inner[i]
        if c in "\"'":
            i = _skip_js_string(inner, i)
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "?" and depth == 0:
            qpos = i
            break
        i += 1
    if qpos is None:
        raise _NotLiteral(f"parenthesised term is not a ternary: {term!r}")
    depth, nested, cpos, i = 0, 0, None, qpos + 1
    while i < len(inner):
        c = inner[i]
        if c in "\"'":
            i = _skip_js_string(inner, i)
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "?" and depth == 0:
            nested += 1
        elif c == ":" and depth == 0:
            if nested == 0:
                cpos = i
                break
            nested -= 1
        i += 1
    if cpos is None:
        raise _NotLiteral(f"ternary has no matching ':': {term!r}")
    return _literal_values(inner[qpos + 1:cpos]) | _literal_values(inner[cpos + 1:])


_DOM_CALL_RE = re.compile(r"\b(?:el|secEl)\(")
_CLASSNAME_ASSIGN_RE = re.compile(r"\.className\s*=\s*([^;]+);")


def _dom_calls(text):
    """(line, cls-argument-text) for every `el(tag, cls, ...)` / `secEl(tag,
    cls, ...)` call in `text`. The two functions' own definitions
    (`function el(tag, cls, text){` / `export function secEl(tag, cls,
    text){`) match this pattern too, but their second argument is the bare
    identifier `cls`, which _literal_values rejects as non-literal -- so
    they fall out on their own rather than needing a special case here."""
    for m in _DOM_CALL_RE.finditer(text):
        i = m.end()
        depth, args, start = 1, [], i
        while depth > 0 and i < len(text):
            c = text[i]
            if c in "\"'":
                i = _skip_js_string(text, i)
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    args.append(text[start:i])
                    break
            elif c == "," and depth == 1:
                args.append(text[start:i])
                start = i + 1
            i += 1
        else:
            continue
        if len(args) >= 2:
            yield text.count("\n", 0, m.start()) + 1, args[1].strip()


def _classes_used_in_js(paths):
    """Every class name reachable, statically, from an `el()`/`secEl()` call
    or a `.className =` assignment in `paths`. Expressions _literal_values
    cannot resolve are silently dropped -- see the caller's docstring for
    what that misses."""
    used = {}
    for path in paths:
        text = path.read_text()
        rel = str(path.relative_to(REPO))
        exprs = list(_dom_calls(text))
        exprs += [(text.count("\n", 0, m.start()) + 1, m.group(1).strip())
                  for m in _CLASSNAME_ASSIGN_RE.finditer(text)]
        for line, expr in exprs:
            if expr in ("null", ""):
                continue
            try:
                values = _literal_values(expr)
            except _NotLiteral:
                continue
            for value in values:
                for cls in value.split():
                    used.setdefault(cls, set()).add(f"{rel}:{line}")
    return used


def _classes_defined_in_css(css_text):
    """Every class name that appears anywhere in a selector -- not a
    declaration body -- of a stylesheet."""
    body = re.sub(r"/\*.*?\*/", "", css_text, flags=re.S)
    classes = set()
    for selector in re.findall(r"([^{}]+)\{[^{}]*\}", body):
        if selector.strip().startswith("@"):
            continue
        classes.update(re.findall(r"\.([A-Za-z_-][A-Za-z0-9_-]*)", selector))
    return classes


# Classes the shipped UI reaches for that legitimately carry no CSS rule of
# their own. Keep this short, and justify every entry: it exists so the
# guard below can stay strict by default instead of growing exceptions.
_UNSTYLED_CLASS_ALLOWLIST = {
    # The one caveat span in secPaint()'s status line (ui/security/
    # analysis.js). Its parent, .secstat, already sets
    # color:var(--muted) for every plain child span; "note" names this one
    # sentence for the reader of the source, not for the stylesheet.
    "note",
    # Pure grouping <div>s: every child they hold (.warnline,
    # .secpj-caption, .secidx-catrow, ...) already carries its own full
    # styling. A wrapper that adds nothing of its own is deliberately left
    # unstyled rather than given an empty rule.
    "secfind-strip",
    "secidx-categories",
}


def test_no_class_the_shipped_ui_uses_lacks_a_css_rule(srv):
    """The test this replaces, test_no_css_rule_was_lost_when_the_stylesheet_
    moved_out, guarded exactly one mechanical CSS move and nothing since.
    Every later task that legitimately DELETES a rule as a page gets
    redrawn had to hand-edit its fixture in the same diff -- and at that
    point a real regression and an intentional deletion look identical: both
    are "the fixture changed to match the new build." A reviewer who cannot
    see the deleted rule's history has no way to tell them apart.

    This test needs no fixture and no per-task editing. It collects every
    class name the shipped UI actually reaches for -- literal `class="..."`
    in bin/dashboard.html's static markup, plus the class arguments of every
    `el()`/`secEl()` call and `.className =` assignment across ui/app/*.js
    and ui/security/*.js -- and checks each one against the built
    stylesheet. What it catches is not "did a rule move" but "did an element
    ship with no styling behind it": a typo'd class, a renamed one whose old
    name lingers, or a new one nobody wrote a rule for.

    What it cannot see: a class assembled at runtime from anything other
    than a string literal or a ternary between two string literals --
    `"sevpill " + sev`, `"k-" + name`, `"secstate " + secStateKey(f)`, all
    of which occur in ui/app and ui/security -- is invisible to a static
    scan and is silently skipped, not flagged. Coverage is therefore
    partial by construction. The concatenation forms it DOES resolve
    (`"btn " + (a.primary ? "primary" : "ghost")`,
    `"secchip" + (n ? "" : " zero") + (on ? " on" : "")`) are the ones this
    codebase is actually built from."""
    used = _classes_in_static_markup((REPO / "bin" / "dashboard.html").read_text())
    js_paths = (sorted((REPO / "ui" / "app").glob("*.js"))
                + sorted((REPO / "ui" / "security").glob("*.js")))
    for cls, sources in _classes_used_in_js(js_paths).items():
        used.setdefault(cls, set()).update(sources)

    css, ctype = srv.static_asset("app.css")
    assert ctype.startswith("text/css")
    have = _classes_defined_in_css(css)

    missing = {cls: sorted(sources) for cls, sources in used.items()
               if cls not in have and cls not in _UNSTYLED_CLASS_ALLOWLIST}
    assert not missing, (
        "classes the shipped UI uses have no matching rule in "
        "bin/static/app.css: "
        + "; ".join(f".{cls} (from {', '.join(sources)})"
                    for cls, sources in sorted(missing.items()))
    )


def test_the_job_disabled_pill_and_the_launchd_off_pill_use_different_classes():
    """A job nobody switched on and a scheduler service that failed to load
    are not the same fact -- one is a choice, the other is a fault -- and
    they used to share `.pill.off` (red) regardless, painting every disabled
    job as a problem. The job card (ui/app/overview.js) and the Jobs table
    (ui/app/jobs-table.js, moved out of bin/dashboard.html in Phase 2
    Task 3) now resolve a disabled job to `.pill.disabled` (grey); only the
    topbar's launchd pill (bin/dashboard.html) still uses `.pill.off` (red),
    because there it genuinely is a fault.

    This reads the three ternaries straight from source rather than the
    built bundle, so it catches a regression at the point someone would
    introduce it -- typing "off" back into either job-state ternary -- not
    just its downstream effect. A future edit that reunites the job-disabled
    class with the launchd-off class, the exact simplification the CSS
    comment in ui/css/components.css warns against, fails this test.

    The table's own ternary used to be read as a string-concatenation
    fragment (`pill '+(F.disabled?"disabled":...)`) because renderJobTable
    built the row as an HTML string; Task 3 rebuilt it as a real `const
    pillCls = ...` assignment feeding `el()`, the same shape the job card's
    own ternary already had -- so the regex below now matches jobs-table.js
    in that shape rather than dashboard.html in the old one."""
    overview_js = (REPO / "ui" / "app" / "overview.js").read_text()
    jobs_table_js = (REPO / "ui" / "app" / "jobs-table.js").read_text()
    dashboard_html = (REPO / "bin" / "dashboard.html").read_text()

    m = re.search(r'const pillCls = disabled \? "([^"]+)" : \(idle \? "([^"]+)" : "([^"]+)"\)',
                  overview_js)
    assert m, "the job card's pill-class ternary was not found where expected in overview.js"
    card_disabled, card_idle, card_on = m.groups()

    m = re.search(r'const pillCls = F\.disabled \? "([^"]+)" : \(F\.idle \? "([^"]+)" : "([^"]+)"\)',
                  jobs_table_js)
    assert m, "the Jobs table's pill-class ternary was not found where expected in jobs-table.js"
    table_disabled, table_idle, table_on = m.groups()

    m = re.search(r'pill \'\+\(DATA\.launchd_loaded\?"([^"]+)":"([^"]+)"\)', dashboard_html)
    assert m, "the launchd pill-class ternary was not found where expected in dashboard.html"
    launchd_on, launchd_off = m.groups()

    assert (card_disabled, card_idle, card_on) == (table_disabled, table_idle, table_on), (
        "the job card and the Jobs table disagree on what a disabled/idle/"
        f"enabled job's pill class is: {(card_disabled, card_idle, card_on)} "
        f"vs {(table_disabled, table_idle, table_on)}"
    )
    assert card_disabled != launchd_off, (
        "a disabled job's pill and the launchd fault pill resolve to the "
        f"same class ({card_disabled!r}) -- a switched-off job would read "
        "as a problem again"
    )
    assert card_idle != launchd_off and card_on != launchd_off, (
        "a job pill state collides with the launchd fault class "
        f"({launchd_off!r})"
    )
