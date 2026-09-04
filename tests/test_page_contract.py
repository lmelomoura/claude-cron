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


# ---- temporal-dead-zone guard for the two boot-time interface objects.
#
# bin/dashboard.html builds one object for CCApp.init(...) and one for
# CCSecurity.init(...), each naming dozens of functions the moved-out modules
# call back into. Three times now, a name in one of these objects turned out
# to be a `const NAME = (...) => {...}` declared BELOW the object that reads
# it (activeRunsOf, backoffMultiplier, runKey) -- `const`/`let` are hoisted by
# name but not by value, so reading one before its own declaration line
# throws a ReferenceError from the temporal dead zone, and that throw happens
# while the object literal is being built, which is during page boot, which
# crashes the whole page before a single row of JavaScript that a test could
# `require()` ever runs. All three were fixed the same way: turn the arrow
# back into a hoisted `function NAME(...){...}`, which this guard treats as
# always safe regardless of where it sits, because a `function` declaration
# IS fully usable from line 1 of its enclosing script.
#
# No test here loads the page in a browser, so nothing else notices this
# class of bug -- it was found twice by a human loading the page and
# watching it crash. This is a static stand-in for that: it never executes
# the script, only inspects the two object literals' source text and
# compares it against every top-level `const`/`let` in the same file.

_IDENT = r"[A-Za-z_$][\w$]*"


def _skip_ws_comments(s, i):
    """Advance i past whitespace and //.../* */ comments, stopping at the
    first character that is neither."""
    n = len(s)
    while i < n:
        c = s[i]
        if c in " \t\r\n":
            i += 1
        elif s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j == -1 else j
        elif s.startswith("/*", i):
            j = s.find("*/", i)
            i = n if j == -1 else j + 2
        else:
            break
    return i


def _scan_balanced(s, start):
    """From the index of an opening bracket (one of ``{[(``), return the
    index one past its matching closer. Tracks nesting depth and skips over
    string literals and comments so a stray bracket inside either cannot
    desync the count.

    Not a JS parser: it does not understand regex literals or template-
    string interpolation (`` `${x}` `` is scanned as one opaque string, not
    as code containing an `x`), and a bracket inside either would misparse.
    Neither of this file's two interface objects contains one today."""
    opens = {"{": "}", "[": "]", "(": ")"}
    closer = opens[s[start]]
    depth = 0
    i, n = start, len(s)
    while i < n:
        c = s[i]
        if s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if s.startswith("/*", i):
            j = s.find("*/", i)
            i = n if j == -1 else j + 2
            continue
        if c in "\"'`":
            q = c
            i += 1
            while i < n and s[i] != q:
                i += 2 if s[i] == "\\" else 1
            i += 1
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError(f"unbalanced {closer!r} scanning from index {start}")


def _strip_comments(s):
    """`s` with every //.../* */ comment removed, string/template literals
    left untouched (so a comma or `//` typed inside one is never mistaken
    for a real one)."""
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if s.startswith("/*", i):
            j = s.find("*/", i)
            i = n if j == -1 else j + 2
            continue
        if s[i] in "\"'`":
            q = s[i]
            start = i
            i += 1
            while i < n and s[i] != q:
                i += 2 if s[i] == "\\" else 1
            i += 1
            out.append(s[start:i])
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _top_level_entries(body):
    """Split the inside of an object literal (braces already stripped) into
    its top-level, comma-separated property entries -- a comma nested inside
    a bracket, a string, or a comment never splits an entry in half."""
    entries, depth, i, n, start = [], 0, 0, len(body), 0
    while i < n:
        c = body[i]
        if body.startswith("//", i):
            j = body.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if body.startswith("/*", i):
            j = body.find("*/", i)
            i = n if j == -1 else j + 2
            continue
        if c in "\"'`":
            q = c
            i += 1
            while i < n and body[i] != q:
                i += 2 if body[i] == "\\" else 1
            i += 1
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        elif c == "," and depth == 0:
            entries.append(body[start:i])
            start = i + 1
        i += 1
    if body[start:].strip():
        entries.append(body[start:])
    return [e.strip() for e in entries if e.strip()]


def _top_level_statements(body):
    """Split a function BODY (its own outer braces already stripped) into its
    top-level statements -- a `;`/bracket nested inside a string or a nested
    block never splits one in half. Mirrors _top_level_entries's own
    technique (commas -> object-literal entries) for semicolon-terminated
    statements instead.

    Unlike _top_level_entries, this does NOT skip `//`/`/* */` comments
    itself -- call `_strip_comments` on `body` FIRST. A comment's own prose
    can legitimately contain a name a caller goes on to regex-match at the
    start of the NEXT statement (test_calling_the_bridged_chrome_builders_...
    below found this the hard way: ui/security/index.js's own init() narrates
    `pageHeader()` by name in a comment sitting between two real statements;
    left unstripped, that comment's text glues onto the following statement
    and both a false "pageHeader(" match and a missed real call slip through
    in the same stroke)."""
    stmts, depth, i, n, start = [], 0, 0, len(body), 0
    while i < n:
        c = body[i]
        if c in "\"'`":
            q = c
            i += 1
            while i < n and body[i] != q:
                i += 2 if body[i] == "\\" else 1
            i += 1
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        elif c == ";" and depth == 0:
            stmts.append(body[start:i])
            start = i + 1
        i += 1
    if body[start:].strip():
        stmts.append(body[start:])
    return [s.strip() for s in stmts if s.strip()]


def _iface_value_names(entry):
    """From one object-literal entry, return the bare identifier(s) whose
    VALUE is read the instant the enclosing object literal is built -- the
    exact moment a `const`/`let` in its temporal dead zone would throw.

    Three shapes read nothing eagerly and yield no names: a method shorthand
    (`name(args){...}`) and a getter/setter (`get name(){...}`) both define a
    function that only runs later, on a call the object's own construction
    never makes; an inline `function`/arrow VALUE (`key: () => ...`) is the
    same. A spread entry (`...x`) or a computed key (`[expr]: v`) are not
    produced by either call site today, so they are explicitly out of scope
    here rather than silently accepted as "no name to check".

    Honest limit: a value that is a bare identifier or a dotted chain of them
    (`renderJobs: renderJobsArea`, `icon: CC.icon`) is resolved to its root
    name; a value built from a call, a ternary, or any other expression is
    left unchecked, because none of those read an outer binding the instant
    the object literal is built the way a bare identifier reference does."""
    e = _strip_comments(entry).strip()
    if not e or e.startswith("...") or e.startswith("["):
        return []
    if re.match(rf"^(get|set)\s+{_IDENT}\s*\(", e):
        return []
    if re.match(rf"^{_IDENT}\s*\(", e):
        return []
    m = re.match(rf"^({_IDENT})\s*:\s*(.*)$", e, re.S)
    if m:
        value = m.group(2).strip()
        if (value.startswith("function") or "=>" in value
                or value.startswith("{") or value.startswith("[")):
            return []
        vm = re.match(rf"^({_IDENT})(?:\.{_IDENT})*$", value, re.S)
        return [vm.group(1)] if vm else []
    m = re.match(rf"^({_IDENT})$", e)
    return [m.group(1)] if m else []


def _init_call_object(js, call_name):
    """Return the (start, end) span of the object literal passed to
    `call_name(...)` -- indices of its outer braces, inclusive.

    Handles the two shapes this file's own call sites use: the object
    written inline at the call site (`X.init({ ... })`), and a bare
    identifier (`X.init(NAME)`) resolved back to the nearest EARLIER
    top-level `const NAME = {` in the same script. The object literal's own
    position is what is returned -- not the call's -- because that is where
    its properties' values are actually read; for CCSecurity.init(CC) that
    position is earlier in the file than the call itself, which only makes
    this check stricter, never weaker.

    `call_name + "("` also matches this file's own prose (two comments say
    "CCApp.init()" to explain what calls where); those are skipped by
    requiring the parenthesised argument be non-empty, which every real call
    here has and every comment mention does not."""
    call_idx = None
    for m in re.finditer(re.escape(call_name) + r"\(", js):
        if js[_skip_ws_comments(js, m.end())] != ")":
            call_idx = m.start()
            break
    if call_idx is None:
        raise AssertionError(f"no non-empty call to {call_name}(...) found")
    i = _skip_ws_comments(js, call_idx + len(call_name) + 1)
    if js[i] == "{":
        return i, _scan_balanced(js, i)
    m = re.match(_IDENT, js[i:])
    assert m, f"{call_name}(...)'s argument is neither an object literal nor a bare name"
    name = m.group(0)
    decl = None
    for dm in re.finditer(rf"^(?:const|let)\s+{name}\s*=\s*", js[:call_idx], re.M):
        decl = dm  # last one wins: the nearest declaration before the call
    assert decl, f"no top-level const/let {name} found before {call_name}(...)"
    brace = decl.end()
    assert js[brace] == "{", f"{name} is not bound to an object literal"
    return brace, _scan_balanced(js, brace)


def test_every_name_ccapp_and_ccsecurity_init_pass_is_already_usable(srv):
    """Guards the temporal-dead-zone class described above the helpers: for
    every bare-name property CCApp.init(...) and CCSecurity.init(...) pass,
    if that name is declared with `const`/`let` AFTER the point where the
    interface object reads it, fail -- a `function` declaration anywhere in
    the file (hoisted, always callable) is not flagged, deliberately, since
    that is the fix all three past occurrences converged on.

    This only recognises a TOP-LEVEL `const`/`let` -- one declared at column
    0, the convention every existing declaration in this file already
    follows (checked below) -- so a same-named `const` inside some unrelated
    function body is never confused with it, but a top-level declaration
    written with leading indentation would go unseen."""
    js = _js(srv)
    # The column-0 convention this guard relies on, asserted rather than
    # assumed -- if it ever stops holding the guard would quietly stop
    # seeing real declarations instead of failing loudly.
    assert re.search(r"^(?:const|let)\s", js, re.M), \
        "no top-level const/let found at all -- the column-0 convention this guard reads may have changed"

    for call_name in ("CCApp.init", "CCSecurity.init"):
        eval_pos, end = _init_call_object(js, call_name)
        names = []
        for entry in _top_level_entries(js[eval_pos + 1:end - 1]):
            names.extend(_iface_value_names(entry))
        assert names, f"{call_name}(...) yielded no bare-name properties -- the extraction itself may be broken"
        for name in names:
            decl = re.search(rf"^(?:const|let)\s+{re.escape(name)}\b",
                              js[eval_pos:], re.M)
            assert decl is None, (
                f"{call_name}(...) reads `{name}` at the point its interface "
                f"object is built, but `{name}` is declared `const`/`let` "
                f"BELOW that point -- reading it there throws a "
                f"ReferenceError from the temporal dead zone and crashes the "
                f"page on load. Declare it as a hoisted `function` instead "
                f"(the fix all three past occurrences of this bug used), or "
                f"move the declaration above this call."
            )


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
    // saveProject reads the effort through effortGet -- the page's one
    // route to the canonical CCApp.EFFORTS. The stub mirrors that route
    // rather than declaring a copy of the list: a copy here was the THIRD
    // EFFORTS in the tree, and proof the production code read a bare
    // page-global instead of the canonical one.
    const CCApp = { EFFORTS: ["","low","medium","high","xhigh","max"],
                    effortFromIndex: (i) => CCApp.EFFORTS[+i||0] || "" };
    const effortGet = (id) => CCApp.effortFromIndex($(id).value);
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


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_min_severity_dropdown_offers_info_as_the_lowest_option(srv, tmp_path):
    """The info severity sits below the default display floor, recorded but hidden,
    until somebody lowers the floor to look at it. The combo must offer info as
    the lowest option to make it reachable through the UI.

    sec-min-severity used to be a bare <select> with its own literal <option>
    list; now it is the house combo and its options are built by mapping
    titleOpt over CCSecurity.SEV_ORDER -- so this pins the combo's fidelity to
    that source (structurally, and by actually running the map), not a
    hand-typed option list living a second time in the page. SEV_ORDER's own
    order -- info lowest -- is pinned separately by
    test_sev_order_ranks_info_as_the_lowest_severity against the real
    vocabulary source, which is what this test's own SEV_ORDER comes from."""
    js = _js(srv)
    # Structural: the combo's options must come from CCSecurity.SEV_ORDER
    # itself, not a second hardcoded list that could quietly drift from it.
    assert "CCSecurity.SEV_ORDER.map(titleOpt)" in js, \
        "sec-min-severity must build its options from CCSecurity.SEV_ORDER, not a copy of it"
    assert 'secMinSevCombo.set("medium", CCSecurity.SEV_ORDER.map(titleOpt))' in js, \
        "medium is no longer offered as the selected default"
    sev_order_src = _const(_security_js(srv), "SEV_ORDER")
    script = tmp_path / "sevopts.js"
    script.write_text(sev_order_src + _plainfn(js, "titleOpt") + """
    console.log(JSON.stringify(SEV_ORDER.map(titleOpt)));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out[0] == {"v": "info", "label": "Info"}, \
        f"info must be the first (lowest) option offered, not {out[0]}"


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
# above) -- see the `resumable` comment in runRow (ui/app/runs.js, moved
# there whole from renderRuns in Phase 2 Task 7) for why this is ONE const
# read from three places rather than three separate checks. Both tests below
# read the app bundle rather than the page's own inline script for the same
# reason: the row this guard is about moved into ui/app/runs.js.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_stopped_run_is_resumable_alongside_error_and_warning(srv, tmp_path):
    """A `stopped` run never declares an ending either, so the engine keeps
    its tree and its services exactly as it does for an error's or a
    warning's -- specifically so a resume can pick them back up (see
    "Sessions that are still open" in the README). Before this, `resumable`
    covered error and warning only: the button did not cover the one status
    whose whole run dir is sitting there, kept, for exactly this reason."""
    block = _app_js(srv)
    line = re.search(r"const resumable = .*?;", block).group(0)
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
    block = _app_js(srv)
    assert "Only a failed, warning or stopped run can be resumed" in block
    assert "Only a failed or warning run can be resumed" not in block


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
    # run, only to not throw. filterBar, tableCard and tableFooter all take
    # the same `opts`-destructured-in-the-body shape as kpiCard specifically
    # so this test (and its structural sibling below) CAN pull in the real
    # ones instead of stubbing a second load-bearing piece.
    consts = (_const(block, "STATE_RANK") + _const(block, "JOB_SORTERS")
              + _const(block, "JOB_COLS") + _const(block, "KPI_ICONS"))
    fns = ("el", "kpiCard", "filterBar", "tableCard", "tableFooter",
           "inWindow", "nextCheckAt", "jobFacts", "visibleJobs", "sortJobs",
           "bulkOn", "bulkLabel", "jobsEmptyNote",
           "jobsHeaderSubtitle", "jobsKpis", "mountJobsToolbar",
           "paintJobFilterBar", "jobRow", "renderJobsTable", "renderJobsPage")
    return consts + "\n".join(_plainfn(block, n) for n in fns)


# The page's own static mounts -- renderJobsPage() only ever reaches for ids
# bin/dashboard.html already defines, never builds them itself. Shared by
# both tests below since both drive renderJobsPage() whole: "jobstoolbar" is
# deliberately NOT among them (mountJobsToolbar()'s own `if(!host) ...`
# guard is what a page with no toolbar mount falls through on, and neither
# test is about the toolbar), which is also why neither ever needs to stub
# filterBar's own three inputs ($("jobsearchbox") etc.) -- the guard returns
# before filterBar is ever called.
_JOBS_PAGE_STATIC_IDS = ("jobs-head", "jobs-kpis", "jactive", "jf-clear",
                         "bulk-all", "jobs-table")


def _jobs_page_harness(deps):
    """The page.js bindings and page-owned state renderJobsPage()'s own
    extracted body reaches for by bare name -- the same stand-ins
    test_the_jobs_page_footer_says_how_many_it_is_showing used before this
    helper existed, pulled out so its structural sibling below does not
    have to retype them."""
    return _INDEX_DOM_HARNESS + _JOBS_DOMAIN_HARNESS + """
    CC.DATA.jobs = [
      {id: "a", project: "Alpha", enabled: true},
      {id: "b", project: "Alpha", enabled: false},
      {id: "c", project: "Beta",  enabled: true},
    ];
    const ELS = {};
    """ + json.dumps(list(_JOBS_PAGE_STATIC_IDS)) + """
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
    """ + deps


# FakeElement (_INDEX_DOM_HARNESS) has no querySelector -- this is collectAll's
# own recursion, aimed at an id instead of a class/title/text record, since
# the structural test below needs to know WHERE in the tree a node sits, not
# just that it exists somewhere in it.
_FIND_BY_ID_JS = """
function findById(n, id){
  if(!n) return null;
  if(n.id === id) return n;
  for(const c of (n.childNodes || [])){
    const found = findById(c, id);
    if(found) return found;
  }
  return null;
}
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_jobs_page_footer_says_how_many_it_is_showing(srv, tmp_path):
    """Runs already had a pager; Jobs had none at all -- renderJobTable drew
    every visible row with nothing below the table. CCApp.renderJobsPage()
    (ui/app/jobs-table.js) is driven whole here -- header, KPIs, filter bar
    and table -- against a small fixed set of jobs, checking the one thing
    Task 3 actually added: a footer reading "Showing X to Y of N", present
    even on a set that fits on one page.

    Originally written to fail before renderJobsPage existed at all (no such
    name to extract, so _plainfn would raise). The gap-closing task that
    moved the footer into tableCard()/tableFooter() (chrome.js) changed
    WHERE these three ids live -- inside the table card renderJobsTable()
    now mounts under $("jobs-table"), not separate static elements of their
    own -- so the harness looks them up by walking that mount instead of
    reaching for them directly; the assertions themselves (the sentence, the
    disabled state) are exactly what they were before."""
    block = _app_js(srv)
    deps = _jobs_table_deps(block)
    script = tmp_path / "jobs-footer.js"
    script.write_text(_jobs_page_harness(deps) + _FIND_BY_ID_JS + """
    renderJobsPage();
    const table = $("jobs-table");
    const info = findById(table, "jobs-pg-info");
    const prev = findById(table, "jobs-pg-prev");
    const next = findById(table, "jobs-pg-next");
    console.log(JSON.stringify({
      info: info && info.textContent,
      prevDisabled: prev && prev.disabled,
      nextDisabled: next && next.disabled,
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


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_jobs_table_footer_sits_inside_the_table_card(srv, tmp_path):
    """The gap an inspection found after Task 3 landed: the rendered
    structure was `jobs-head / kpi-grid / jobstoolbar / tablewrap / pager` --
    the pager a loose sibling below `.tablewrap`, with no background and no
    border-top, instead of living inside the card the rows are in. The
    approved design puts the footer INSIDE the table card, separated from
    the rows by a border-top (see components.css's own `.table-foot`).

    Pinned structurally rather than visually: this walks the actual DOM
    renderJobsPage() builds and asserts that the element carrying the
    pager's own id (`jobs-pg-prev`, chosen arbitrarily among the footer's
    three ids -- any would do) is a DESCENDANT of the element with class
    `table-card`, not a sibling of it. A regression that put the footer back
    outside the card -- appending it next to `tableCard(...)`'s return value
    instead of handing it to `tableCard` as `footer` -- fails this without
    touching the footer's own text or disabled state, which is exactly what
    test_the_jobs_page_footer_says_how_many_it_is_showing above already
    covers and this test deliberately does not repeat.

    Recorded failing against the code this gap-closing task started from:
    tableCard/tableFooter did not exist in chrome.js, renderJobsTable()
    built `.tablewrap` and the pager as two separate pieces with nothing
    wrapping them both, and `_plainfn(block, "tableCard")` raised
    (`ValueError: no such function`) before a single assertion ran."""
    block = _app_js(srv)
    deps = _jobs_table_deps(block)
    script = tmp_path / "jobs-footer-in-card.js"
    script.write_text(_jobs_page_harness(deps) + _FIND_BY_ID_JS + """
    // Walks UP from the footer's own element to see whether a table-card
    // ancestor is on the way, rather than back down from the card -- no
    // parentNode on FakeElement, so the tree is searched from the card's
    // side and the footer's id is looked for underneath it.
    function hasDescendantWithId(n, id){
      return !!findById(n, id);
    }
    renderJobsPage();
    const table = $("jobs-table");
    function findByClass(n, cls){
      if(!n) return null;
      if((n.className || "").split(" ").includes(cls)) return n;
      for(const c of (n.childNodes || [])){
        const found = findByClass(c, cls);
        if(found) return found;
      }
      return null;
    }
    const card = findByClass(table, "table-card");
    console.log(JSON.stringify({
      cardFound: !!card,
      footerInsideCard: card ? hasDescendantWithId(card, "jobs-pg-prev") : false,
      footerAtTopLevel: hasDescendantWithId(table, "jobs-pg-prev"),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["cardFound"], "no element with class \"table-card\" was rendered at all"
    assert out["footerAtTopLevel"], "the footer's own pager button never rendered anywhere"
    assert out["footerInsideCard"], (
        "the footer rendered, but not inside the table-card element -- it is a "
        "loose sibling again, the exact regression this test exists to catch")


# ---- Projects, pinned ahead of phase 2's redesign (Task 4). Same deal as the
# Jobs table above: characterisation tests, so they pass on their first run --
# the falsifiability of each one (break, red, revert) is recorded by hand in
# .superpowers/sdd/task-4-5-report.md rather than by a red-then-green cycle
# here. visibleProjects already existed (bin/dashboard.html's module-level
# function, reading a module-level prjQuery); it and the isolation ternary
# renderProjects() used to build inline both moved to ui/app/projects.js,
# unchanged in substance -- see that file's own banner comment. groupJobs is
# not new: it already exists in ui/app/overview.js (moved there in Phase 1)
# and is pinned again here for what the favourite star specifically does with
# it, not duplicating the Overview's own grouping tests.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_projects_job_count_is_the_jobs_that_actually_name_it(srv, tmp_path):
    """visibleProjects()'s own `_jobs` field is what the Projects table shows
    in its Jobs column -- the count of jobs whose `project` names THIS
    project, not the size of the whole fleet. A project with none of its own
    must read 0, even on an install where every other project has jobs."""
    block = _app_js(srv)
    fn = _plainfn(block, "visibleProjects")
    script = tmp_path / "proj-count.js"
    script.write_text("""
    const CC = { DATA: { projects: [
      {name: "Alpha"}, {name: "Beta"}, {name: "Empty"},
    ], jobs: [
      {id: "a1", project: "Alpha"}, {id: "a2", project: "Alpha"},
      {id: "b1", project: "Beta"},
    ] } };
    const projFilters = { query: "" };
    """ + fn + """
    console.log(JSON.stringify(Object.fromEntries(
      visibleProjects().map(p => [p.name, p._jobs]))));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out == {"Alpha": 2, "Beta": 1, "Empty": 0}, out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_favourited_project_sorts_first_and_only_the_starred_one_does(srv, tmp_path):
    """groupJobs (ui/app/overview.js) is what actually gives the favourite
    star its effect -- a favourited project's jobs float to the top of the
    Overview's own grouping, and by the same mechanism, of the Jobs page.
    Pinned here for what the STAR specifically drives: which of two projects
    comes first flips with which one the caller says is favourited, not a
    fixed position in the list that would pass even with the favourite term
    deleted from the comparator entirely."""
    block = _app_js(srv)
    fn = _plainfn(block, "groupJobs")
    script = tmp_path / "group-fav.js"
    script.write_text(fn + """
    const jobs = [
      {id: "a", project: "Alpha"}, {id: "b", project: "Bravo"},
      {id: "c", project: "Charlie"},
    ];
    // Neither favourited name is "Alpha" -- the alphabetically-first one --
    // on purpose: a comparator with the favourite term deleted would fall
    // back to plain A-Z and still open on "Alpha" by coincidence, passing a
    // test that favourited it either way.
    const favBravo = {has: (n) => n === "Bravo"};
    const favCharlie = {has: (n) => n === "Charlie"};
    console.log(JSON.stringify({
      bravoFirst: groupJobs(jobs, favBravo).map(g => g.name),
      charlieFirst: groupJobs(jobs, favCharlie).map(g => g.name),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["bravoFirst"][0] == "Bravo", out["bravoFirst"]
    assert out["charlieFirst"][0] == "Charlie", out["charlieFirst"]
    # Whichever one is favourited changes the order -- proving the sort reads
    # the star's own state rather than always opening on the same name.
    assert out["bravoFirst"] != out["charlieFirst"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_starring_a_project_repaints_the_projects_page_too(srv, tmp_path):
    """Structural, not behavioural -- the same shape as
    test_resume_target_defers_to_resume_in_flight above, for the same
    reason: toggleFav() is a page-owned click handler wired to no seam a
    harness can drive without also standing up CFG/api()/loadConfig, so
    what is falsifiable here is which repaints it calls, not what a full
    render produces.

    The star shows on a project's row on BOTH the Jobs table (its project
    tag) and the Projects page (the row itself), and toggleFav() used to
    call only renderJobsArea() -- clicking a star on Projects updated the
    favourite_projects preference and left that very button unfilled and
    aria-pressed="false" for up to 5 seconds, until the next poll's
    render() got around to it, long enough to invite a second click that
    silently undoes the first."""
    js = _js(srv)
    body = _plainfn(js, "toggleFav")
    assert "renderJobsArea()" in body, "toggleFav no longer repaints Jobs"
    assert "CCApp.renderProjectsPage()" in body, (
        "toggleFav does not repaint Projects -- a star clicked there stays "
        "stale until the next poll")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_isolation_reads_three_states_not_two(srv, tmp_path):
    """A project can run every job in its own worktree (`true`), never
    (`false`), or leave it to the engine to decide per job -- "automatic",
    which is also what a project with no `worktree` block at all gets, and
    what a hand-edited config's literal string "auto" gets too (see
    config/projects.json). Collapsing "automatic" into either of the other
    two is a real misdescription: an "auto" project is not permanently
    isolated OR permanently not, and painting it as either would tell an
    operator something the engine does not actually do with it."""
    block = _app_js(srv)
    fn = _plainfn(block, "projectIsolation")
    script = tmp_path / "isolation.js"
    script.write_text(fn + """
    console.log(JSON.stringify({
      always: projectIsolation({worktree: {enabled: true}}),
      never:  projectIsolation({worktree: {enabled: false}}),
      auto:   projectIsolation({worktree: {enabled: "auto"}}),
      none:   projectIsolation({}),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["always"] == ["on", "always"], out["always"]
    assert out["never"] == ["off", "never"], out["never"]
    assert out["auto"] == ["auto", "auto"], out["auto"]
    assert out["none"] == ["auto", "auto"], out["none"]
    assert len({tuple(out["always"]), tuple(out["never"]), tuple(out["auto"])}) == 3, (
        "fewer than three distinct isolation states came back")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_project_search_reaches_the_directory_too(srv, tmp_path):
    """The search box narrows Projects by more than the name typed at setup
    time -- a project remembered by its folder, or by a phrase in its own
    description, has to surface just as reliably as one matched by name."""
    block = _app_js(srv)
    fn = _plainfn(block, "visibleProjects")
    script = tmp_path / "proj-search.js"
    script.write_text("""
    const CC = { DATA: { jobs: [], projects: [
      {name: "Quality Gate", description: "the QG Jira board", cwd: "/repos/qg"},
      {name: "Minerva", description: "Revenue Platform", cwd: "/repos/rp-dev-knowledge"},
      {name: "Scratch", description: "throwaway", cwd: "/tmp/scratch"},
    ] } };
    const projFilters = { query: "" };
    """ + fn + """
    function names(q){
      projFilters.query = q;
      return visibleProjects().map(p => p.name);
    }
    console.log(JSON.stringify({
      byName: names("minerva"),
      byDescription: names("jira board"),
      byDirectory: names("rp-dev-knowledge"),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["byName"] == ["Minerva"], out["byName"]
    assert out["byDescription"] == ["Quality Gate"], out["byDescription"]
    assert out["byDirectory"] == ["Minerva"], out["byDirectory"]


# ---- the Security column (Task 5) -- the only new information Phase 2 adds
# to Projects. Written BEFORE projectSecurity exists, per the task's own
# gate: the risk here is not a typo, it is painting two different facts
# alike, so the test is what has to exist first, not the column.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_security_column_tells_three_states_apart(srv, tmp_path):
    """Read straight from what the page actually has, not from what would be
    nice to show: `/api/config` carries a project's security block (enabled
    or not, plus its configuration knobs) and nothing about what any
    analysis found -- that lives behind `GET /api/security/index`, a
    subprocess-backed endpoint this page's 5-second poll has no business
    calling. `DATA.runs`, already fetched every poll for every other page,
    DOES carry the derived "security-<slug>" job's own runs, correctly
    attributed to the real project name (`bin/claude-cron`'s
    `security_derived_jobs` sets `project` on the derived job element
    itself) -- so "never analysed" and "analysed" are told apart from data
    the page already has in hand, without inventing a severity this column
    has no way to know. A completed run's own status is deliberately not
    read as a stand-in for posture either: checked against the real ledger
    behind this branch, a project's most recent run said "success" while its
    analysis had recorded 6 high and 33 medium findings -- "the run
    succeeded" and "nothing was found" are not the same fact, and painting
    one as the other would be exactly the mistake this column exists to
    avoid making a second time."""
    block = _app_js(srv)
    fn = _plainfn(block, "projectSecurity")
    script = tmp_path / "prj-security.js"
    script.write_text("""
    const CC = { DATA: { runs: [
      {id: "security-beta", project: "Beta", start: 100, status: "success"},
      {id: "security-beta", project: "Beta", start: 200, status: "error"},
    ] } };
    """ + fn + """
    console.log(JSON.stringify({
      off:        projectSecurity({name: "Alpha", security: {enabled: false}}).state,
      absent:     projectSecurity({name: "Alpha"}).state,
      unanalysed: projectSecurity({name: "Alpha", security: {enabled: true}}).state,
      analysed:   projectSecurity({name: "Beta", security: {enabled: true}}).state,
      lastAt:     projectSecurity({name: "Beta", security: {enabled: true}}).lastAt,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["off"] == "disabled", out
    assert out["absent"] == "disabled", out
    assert out["unanalysed"] == "unanalysed", out
    assert out["analysed"] == "analysed", out
    # The most recent of Beta's two runs, not whichever one the array lists
    # first.
    assert out["lastAt"] == 200, out
    assert len({out["off"], out["unanalysed"], out["analysed"]}) == 3, (
        "two of the three security states painted alike")


# ---- the Security column overlapping the row actions (visual-inspection
# finding 1). PRJ_COLS gained a seventh entry (Security) above and
# #view-projects's own width rules in ui/css/pages.css were never updated to
# match: five nth-child rules plus th:last-child already summed to 100%
# without it, so the new th:nth-child(6) had no width rule at all. Under
# table-layout:fixed that is not "shares whatever is left" -- it computed to
# a hair over 0px (confirmed live: getBoundingClientRect() on the Security
# <th> read 0.03125px against a table 1218px wide) -- and the pill inside it
# (white-space:nowrap, nothing of its own to clip it) spilled rightward into
# the actions column, landing on top of the row's own edit/delete buttons.
#
# Geometry itself cannot be driven here: _INDEX_DOM_HARNESS's FakeElement
# (this file's own Node DOM stand-in) has no layout whatsoever -- a bare
# .style object, no getBoundingClientRect, no cascade, nothing table-layout
# could even be computed against -- so no test in this suite can lay out a
# row and measure whether two cells' boxes overlap. Nor would "is the actions
# cell a real final <td>, not an overlay" have caught this: it always was a
# real final <td> in normal table flow -- that was never the defect, so a
# test of only that shape would pass on the broken CSS just as it does on the
# fixed CSS, and prove nothing. What actually was wrong, and is testable
# without a layout engine, is the CSS's own bookkeeping: does every column
# tableCard() (ui/app/chrome.js) renders have a declared width, summing to a
# real 100% -- read from the same PRJ_COLS/JOB_COLS arrays the page itself
# renders from, not a hand-typed column count that could drift from them the
# same way the CSS already did once.

def test_the_page_has_no_effort_vocabulary_of_its_own(srv):
    """The effort levels live in ONE place: EFFORTS in ui/app/editor-domain.js,
    reached from the page only through CCApp. The page used to carry its own
    literal copy, read by exactly one call site -- the one that SAVES
    proj.security.effort -- while the slider's label read the canonical list.
    The day the two diverged, the user would confirm one effort level on
    screen and a different one would land in the config, silently.

    Three copies existed at the worst point (page, domain module, and a test
    stub feeding the extracted saveProject). This pins the count at one."""
    page = srv.render_page()
    assert "const EFFORTS" not in page, (
        "the page declares its own EFFORTS again -- the effort vocabulary "
        "must only be reached through CCApp (see ui/app/editor-domain.js)"
    )


def test_the_cells_icon_rule_cannot_repaint_the_favourite_star(srv):
    """The identity cell (.jobcell) holds two icons: its own, a direct child,
    and the favourite star's, nested inside the .favstar button. The star
    fills with currentColor so the BUTTON's colour can say off (--line) or
    on (--warn). A descendant selector -- `.jobcell .ic` with a space -- sets
    color on the nested icon directly, and currentColor reads the element's
    own color first: both stars painted accent, identical in either state,
    and clicking one changed the class but not a single pixel. Found on the
    live install, with the whole suite green, because the earlier check read
    the CLASS back and never the paint.

    Guards the mechanism: the cell's icon rule must use the direct-child
    combinator, so it can never reach into the button."""
    css, _ = srv.static_asset("app.css")
    offenders = [ln.strip() for ln in css.splitlines()
                 if ".jobcell .ic" in ln or ".jobcell  .ic" in ln]
    assert not offenders, (
        "a descendant .jobcell icon rule is back -- it repaints the "
        f"favourite star and makes its states indistinguishable: {offenders}"
    )


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("view,const_name,bundle", [
    ("#view-jobs", "JOB_COLS", "app"),
    ("#view-projects", "PRJ_COLS", "app"),
    ("#view-runs", "RUN_COLS", "app"),
    # SEC_PROJECT_COLS/SEC_RECENT_COLS live in ui/security/index-screen.js --
    # a separate bundle from ui/app/'s three (see ui/security/index.js's own
    # banner comment on why the two stay apart), so these rows read
    # `bundle="security"`. TWO security tables, each with its own selector
    # scope: one shared `#view-security th:nth-child` set once gave the
    # Recent-analyses table the fleet's widths -- its RUN column wore
    # Project's 22% and the card scrolled sideways for nothing. Scoping the
    # rules per table is the fix; parametrising per table is what keeps a
    # third table in this view from inheriting either set unnoticed.
    (".secidx-fleet", "SEC_PROJECT_COLS", "security"),
    (".secidx-recent", "SEC_RECENT_COLS", "security"),
    # Three more joined by Phase 4 Task 6's own footer work (project-screen.js,
    # findings-screen.js, activity-screen.js) -- same reasoning, same fix:
    # each table gets its OWN scoped class and width set rather than a
    # view-wide rule, and its own row here rather than trusting the other
    # security rows to somehow also cover it.
    (".secpj-runstable", "SEC_RUNS_COLS", "security"),
    (".secfind-table", "SEC_FIND_TABLE_COLS", "security"),
    (".secact-table", "SEC_ACT_TABLE_COLS", "security"),
    # The project Overview's Top-findings card (overview-tab.js) -- the
    # ninth table on this shape, same scoped-class-and-width-set rule.
    (".secov-findtable", "SEC_OVFIND_COLS", "security"),
    # The Branches tab's own table (branches-tab.js, ProjectBranches.png).
    (".secbr-table", "SEC_BRANCH_COLS", "security"),
    # The Reports tab's own table (reports-tab.js, ProjectReports.png).
    (".secrp-table", "SEC_REPORT_COLS", "security"),
], ids=["jobs", "projects", "runs", "security-fleet", "security-recent",
        "security-runs", "security-findings", "security-activity",
        "security-top-findings", "security-branches", "security-reports"])
def test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column(
        srv, tmp_path, view, const_name, bundle):
    """Must fail against the pre-fix CSS (Security's th:nth-child(6) has no
    width rule, so column 6 is 'missing') and pass once every column gets
    one. The sum-to-100% assertion below is a second, weaker guard -- it is
    NOT what pins this bug, since the broken CSS's five nth-child rules plus
    th:last-child already summed to exactly 100% without the Security column
    ever entering the sum at all. `missing` is the assertion that actually
    catches it.

    Jobs is included in the same parametrize list, not because it was ever
    broken (JOB_COLS' own eight columns already had eight matching width
    rules, summing to 100%, both before and after this fix), but so a future
    column added to Jobs is checked exactly the same way a future one added
    to Projects or Runs is -- the whole point being one guard that holds
    regardless of which of the three pages next grows a column, not a
    Projects-only patch good for exactly seven columns. Runs joined in Phase
    2 Task 7, once its own table moved onto tableCard() and gained its own
    #view-runs rules -- this parametrize entry is that promise kept, not a
    new guard. Security joined in Phase 4 Task 3 for the identical reason,
    the fourth table converted onto this same shape (secIndexProjectsTable,
    ui/security/index-screen.js) -- and the ORIGINAL five-column Security
    table is exactly the one this guard was written against in the first
    place (see this docstring's own opening sentence), so this row closes
    the loop: the table that motivated the guard now carries it too."""
    src_js = _app_js(srv) if bundle == "app" else _security_js(srv)
    consts = _const(src_js, const_name)
    script = tmp_path / f"{re.sub(r'[^a-z]', '_', view)}-cols.js"
    script.write_text(consts + f"console.log({const_name}.length);")
    n_cols = int(subprocess.run(["node", str(script)], capture_output=True,
                                 text=True, check=True).stdout.strip())

    css = (REPO / "ui" / "css" / "pages.css").read_text()
    rule = re.compile(
        re.escape(view) + r" th:nth-child\((\d+)\)\{width:([\d.]+)%\}|"
        + re.escape(view) + r" th:last-child\{width:([\d.]+)%\}")
    nth_widths = {}
    last_width = None
    for m in rule.finditer(css):
        if m.group(1):
            nth_widths[int(m.group(1))] = float(m.group(2))
        else:
            last_width = float(m.group(3))

    # A table whose last column is a real data column (the recent-analyses
    # table ends in Date, no actions cell) declares all n columns by
    # nth-child and has no last-child rule at all -- both shapes are valid,
    # and either way every rendered column must be declared and the set must
    # sum to 100.
    declared_last = 1 if last_width is not None else 0
    missing = [i for i in range(1, n_cols + 1 - declared_last)
               if i not in nth_widths]
    assert not missing, (
        f"{view} renders {n_cols} columns ({const_name}) but "
        f"th:nth-child({missing}) has no width rule -- an undeclared column "
        f"computes to ~0px under table-layout:fixed and spills its content "
        f"into whichever column comes after it")
    total = sum(nth_widths.values()) + (last_width or 0)
    assert abs(total - 100) < 0.01, (
        f"{view}'s declared column widths sum to {total}%, not 100%: "
        f"nth-child {nth_widths} + last-child {last_width}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_table_footer_takes_an_irregular_plural_and_a_numbered_pager(srv, tmp_path):
    """Found live (Phase 4 Task 5), verifying the Security index's Recent-
    analyses card against its mockup: the footer read "Showing 1 to 5 of 12
    analysiss" the moment its `noun` became "analysis" -- tableFooter's own
    pluraliser is a bare `noun + "s"`, right for every regular noun this app
    already hands it (project, job, run) but wrong for this one. `plural`,
    optional, fixes the sentence without teaching this function a general
    pluraliser it does not need for anything else it draws -- a caller that
    never passes it (every one before this task) keeps reading `noun + "s"`
    exactly as before, pinned here as the "regular" case.

    `numbered` is pinned alongside it: one `.pagebtn` per page, `.active` on
    the current one, `.iconbtn` (not `.btn.ghost`) for a text-less Prev/Next
    -- and, with only one page, no pager nav at all, the mockup's own
    Projects-table footer with nothing to page through."""
    block = _app_js(srv)
    deps = _plainfn(block, "el") + _plainfn(block, "tableFooter")
    script = tmp_path / "table-footer.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const irregular = collectAll(tableFooter({
      shown: {from: 1, to: 5}, total: 12, noun: "analysis", plural: "analyses",
      page: 1, pages: 3, numbered: true,
    }), []);
    const regular = collectAll(tableFooter({
      shown: {from: 1, to: 2}, total: 2, noun: "project", page: 1, pages: 1,
    }), []);
    const onePageNumbered = collectAll(tableFooter({
      shown: {from: 1, to: 2}, total: 2, noun: "project",
      page: 1, pages: 1, numbered: true,
    }), []);
    console.log(JSON.stringify({irregular, regular, onePageNumbered}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)

    def info_text(rows):
        return next(r["text"] for r in rows if r["cls"] == "table-foot-info")

    assert info_text(out["irregular"]) == "Showing 1 to 5 of 12 analyses", \
        info_text(out["irregular"])
    pagebtns = [r["text"] for r in out["irregular"] if r["cls"].startswith("pagebtn")]
    assert pagebtns == ["1", "2", "3"], pagebtns
    active = [r for r in out["irregular"] if r["cls"] == "pagebtn active"]
    assert active and active[0]["text"] == "1", \
        f"the current page must be marked .active: {active}"
    iconbtns = [r for r in out["irregular"] if r["cls"] == "iconbtn"]
    assert len(iconbtns) == 2 and all(r["text"] == "" for r in iconbtns), \
        f"numbered Prev/Next must be icon-only .iconbtn, no .btn.ghost text: {iconbtns}"

    assert info_text(out["regular"]) == "Showing 1 to 2 of 2 projects", \
        "a caller with no plural override must keep reading the bare noun + 's'"

    assert not [r for r in out["onePageNumbered"] if r["cls"].startswith("table-foot-pager")], \
        "a numbered footer with only one page must render no pager nav at all"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_collapsed_pager_keeps_the_edges_and_the_current_pages_neighbours(srv, tmp_path):
    """`collapse` (Phase 4, AllFindings.png): "‹ 1 2 3 4 5 … 19 ›", not one
    `.pagebtn` per page at a page count this tall -- existing `numbered`
    callers (none of which pass `collapse`) must render byte-for-byte as
    before (the plain-numbered test above already pins that on its own).
    Below 8 pages `collapse` is a no-op: 7 is the most `1, pages, page-1,
    page, page+1` can ever cover on its own with no gap left to close, so a
    caller at or under that count must see EVERY page number, never a "…"
    standing in for one it could have shown directly."""
    block = _app_js(srv)
    deps = _plainfn(block, "el") + _plainfn(block, "tableFooter")
    script = tmp_path / "table-footer-collapse.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const atStart = collectAll(tableFooter({
      shown: {from: 1, to: 10}, total: 189, noun: "finding",
      page: 1, pages: 19, numbered: true, collapse: true,
    }), []);
    const middle = collectAll(tableFooter({
      shown: {from: 91, to: 100}, total: 189, noun: "finding",
      page: 10, pages: 19, numbered: true, collapse: true,
    }), []);
    const atEnd = collectAll(tableFooter({
      shown: {from: 181, to: 189}, total: 189, noun: "finding",
      page: 19, pages: 19, numbered: true, collapse: true,
    }), []);
    const smallUncollapsed = collectAll(tableFooter({
      shown: {from: 1, to: 10}, total: 70, noun: "finding",
      page: 1, pages: 7, numbered: true, collapse: true,
    }), []);
    function pageEntries(rows){
      return rows.filter(r => r.cls.startsWith("pagebtn")).map(r => r.text);
    }
    console.log(JSON.stringify({
      atStart: pageEntries(atStart), middle: pageEntries(middle),
      atEnd: pageEntries(atEnd), smallUncollapsed: pageEntries(smallUncollapsed),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["atStart"] == ["1", "2", "…", "19"], \
        f"page 1 of 19 must keep 1, its neighbour 2, an ellipsis, then 19: {out['atStart']}"
    assert out["middle"] == ["1", "…", "9", "10", "11", "…", "19"], \
        f"a middle page must show both edges and its own neighbours either side: {out['middle']}"
    assert out["atEnd"] == ["1", "…", "18", "19"], \
        f"the last page must keep its own neighbour and the leading edge: {out['atEnd']}"
    assert out["smallUncollapsed"] == [str(n) for n in range(1, 8)], \
        f"7 pages must never collapse -- the window already covers all of them: {out['smallUncollapsed']}"


# ---- the Runs table, pinned ahead of phase 2's redesign (Task 6), then
# moved whole into ui/app/runs.js by the redesign itself (Task 7). Same gate
# as the Jobs and Projects tables above: characterisation tests, so they pass
# on their first run -- the falsifiability of each one (break, red, revert)
# is recorded by hand in .superpowers/sdd/f2-task-6-7-report.md rather than
# by a red-then-green cycle here. filteredRuns and SORTERS were extracted
# verbatim from bin/dashboard.html's own filteredRuns() in Task 6 and are
# pure and pinned directly below; renderRunsTable's own pagination clamp and
# footer count moved whole into the same module in Task 7 (they were
# renderRuns's, read out of the page's own inline script through Task 6 --
# now read out of the app bundle instead, the same "the test follows the
# code" update test_a_job_card_shows_every_kept_session_honestly's own
# comment describes) and are pinned by driving the REAL function -- not a
# hand-copied snippet -- over a scenario engineered so its row-building
# branch (built with el(), and already exercised by the Resume-button tests
# above) is never reached: an empty filtered set skips straight to the
# fallback row, so the only things that matter here -- the page clamp and
# the footer's own opts -- are exercised without needing runRow's own
# dependencies (icon names, resumeTarget, isStopping and the rest) at all.

def _runs_table_stub_harness():
    """Every free name renderRunsTable (ui/app/runs.js) reaches for, stood up
    just enough to run it to completion against an EMPTY filtered set: $,
    el, icon, document.createTextNode, tableCard and paintRunFilters are all
    stubs that build nothing real, and tableFooter is a stub that RECORDS
    the options it was called with instead -- `page`, `total` and `pages`
    are read back from that capture rather than from parsed footer text, so
    this harness does not also have to reimplement tableFooter's own "Showing
    X to Y of N" sentence (chrome.js, already exercised by the Jobs table's
    own test_the_jobs_page_footer_says_how_many_it_is_showing).

    An EMPTY filtered set is enough for both of Task 6's own tests below: it
    skips renderRunsTable's row-building branch entirely (`slice.map(r =>
    runRow(r))` never calls its callback over an empty slice), so runRow's
    own row-only dependencies (icon names, resumeTarget, isStopping and the
    rest) never need stubbing here at all -- they are what the Resume-button
    tests above already exercise, not what these two are about."""
    return """
    const ELS = {};
    function $(id){ if(!ELS[id]) ELS[id] = {textContent:"", disabled:false, appendChild(){}}; return ELS[id]; }
    function el(tag, cls, text){ return {tag, cls, text, childNodes: [], appendChild(c){ this.childNodes.push(c); }}; }
    function icon(_name){ return el("span"); }
    const document = { createTextNode(s){ return {text: s}; } };
    function mountRunsToolbar(){}
    function paintRunFilters(_shown){}
    function tableCard(_opts){ return el("div"); }
    let lastFooterOpts = null;
    function tableFooter(opts){ lastFooterOpts = opts; return el("div"); }
    const RF = {};
    function unjournaledLive(){ return []; }
    let searchKeys = null;
    let sortKey = "when", sortDir = -1;
    """


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_shrunk_filtered_set_pulls_the_current_page_back_from_beyond_it(srv, tmp_path):
    """A filter (or a search) that narrows the visible runs below the page
    the operator is already on must not leave them staring at a page that no
    longer exists -- renderRunsTable() pulls `page` back to the last real
    page the moment the filtered set no longer reaches it. Drives the real
    function out of the app bundle (ui/app/runs.js), which is where it moved
    in Phase 2 Task 7 -- not a hand-copied snippet."""
    block = _app_js(srv)
    deps = _const(block, "RUN_COLS") + _plainfn(block, "renderRunsTable")
    script = tmp_path / "runs-page-clamp.js"
    script.write_text(_runs_table_stub_harness() + """
    // The filter narrowed the set to nothing -- one page, and page 5 (where
    // the operator was looking at a larger, unfiltered set) is well past it.
    function filteredRuns(){ return []; }
    const CC = { DATA: { runs: [1, 2, 3, 4, 5] } };
    let page = 5, pageSize = 25;
    """ + deps + """
    renderRunsTable();
    console.log(JSON.stringify({page, pages: lastFooterOpts.pages}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["pages"] == 1, out
    assert out["page"] == 1, (
        f"the filtered set has one page, but page stayed at {out['page']} -- "
        "the operator is left looking at a page that no longer exists")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_footer_and_pager_count_the_filtered_set_not_the_total(srv, tmp_path):
    """"0 of 5 runs" and "5 of 5 runs" are two different sentences -- the
    footer (and the page count driving it) must read off the FILTERED set
    filteredRuns() returns, never CC.DATA.runs.length, or a filter that
    narrowed the table to nothing would still claim to be showing
    everything."""
    block = _app_js(srv)
    deps = _const(block, "RUN_COLS") + _plainfn(block, "renderRunsTable")
    script = tmp_path / "runs-footer-count.js"
    script.write_text(_runs_table_stub_harness() + """
    // Five runs on record; the active filter matches none of them -- the
    // footer has to say 0, not 5.
    function filteredRuns(){ return []; }
    const CC = { DATA: { runs: [1, 2, 3, 4, 5] } };
    let page = 1, pageSize = 25;
    """ + deps + """
    renderRunsTable();
    console.log(JSON.stringify({total: lastFooterOpts.total}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["total"] == 0, (
        f"the footer did not read the filtered count (0): got {out['total']}, "
        "which is CC.DATA.runs.length (the total, 5) if this regressed")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_run_matched_only_in_its_log_content_still_surfaces(srv, tmp_path):
    """/api/search's own index covers a run's log content as well as its id
    (see ui/app/runs.js's own comment on filteredRuns) -- the client has to
    trust that whole result set, so a run whose id shares nothing with the
    query text, matched purely by something its LOG said, must still show up
    here. Restricting the client's own filter to names as well -- redundant
    with the server, and exactly the regression this test exists to catch --
    would silently hide it again."""
    block = _app_js(srv)
    fn = _plainfn(block, "filteredRuns")
    script = tmp_path / "search-log-content.js"
    script.write_text("""
    const CC = { DATA: { runs: [
      {id: "nightly-backup", start: 1000, status: "success"},
      {id: "weekly-report",  start: 2000, status: "success"},
    ] } };
    function normStatus(s){ return s === "ok" ? "success" : (s || "\\u2014"); }
    const RF = {project: "", job: "", status: "", from: "", to: ""};
    // The server flagged "weekly-report" as a match -- nothing about that id
    // shares a word with the query; the hit came from something its log said.
    const searchKeys = new Set(["weekly-report|2000"]);
    """ + fn + """
    console.log(JSON.stringify(filteredRuns(RF, [], searchKeys, "when", -1).map(r => r.id)));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out == ["weekly-report"], (
        "a run the server matched by log content alone did not survive the "
        f"client's own filter: got {out}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_duration_and_cost_sort_independently(srv, tmp_path):
    """The slowest run of the day and the most expensive one are rarely the
    same run -- Duration and Cost are separate comparators (ui/app/runs.js's
    SORTERS) precisely so both stay reachable by their own header. They used
    to be merged into one column, which silently dropped the cost sort: the
    comparator still existed, but no header could reach it, so the priciest
    run of a 25-row page became unfindable -- the historical defect RUN_COLS'
    own comment (bin/dashboard.html) describes."""
    block = _app_js(srv)
    sorters = _const(block, "SORTERS")
    script = tmp_path / "sort-cost-duration.js"
    script.write_text(sorters + """
    const rows = [
      {id: "slow-cheap",  start: 1, duration: 500, cost: 1},
      {id: "fast-pricey", start: 2, duration: 10,  cost: 99},
      {id: "mid",         start: 3, duration: 100, cost: 20},
    ];
    console.log(JSON.stringify({
      byDuration: [...rows].sort(SORTERS.duration).map(r => r.id),
      byCost:     [...rows].sort(SORTERS.cost).map(r => r.id),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["byDuration"] == ["fast-pricey", "mid", "slow-cheap"], out["byDuration"]
    assert out["byCost"] == ["slow-cheap", "mid", "fast-pricey"], out["byCost"]
    assert out["byDuration"] != out["byCost"], (
        "sorting by cost produced the same order as duration -- the "
        "historical regression RUN_COLS' own comment describes")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_overview_and_runs_warning_cards_name_the_same_window(srv, tmp_path):
    """The Overview's Warnings/Errors cards are a door into Runs
    (initStatFilters, bin/dashboard.html): click one and CCApp.RF.status is
    set, landing on the Runs page's OWN Warnings/Errors cards -- same label,
    same icon, same box. This is the second time the two disagreed under
    that identical label: the Overview counts a 7-day window and says so
    (`sub: "in the last 7 days"`); the Runs page counted ALL of
    CC.DATA.runs -- which the server caps at 1000 rows, far more than 7
    days at any real job count -- and said "N% of finished runs" instead,
    with no window named anywhere on the card. A reader who follows the
    door lands on a page whose own card reports a different number under
    the label they just clicked.

    Reads both card builders' own source out of the built bundle and
    compares their `sub` text directly -- no fixture is shared between
    them, each computes its own numbers from its own inputs, the way the
    two pages genuinely do -- so the next page that grows a Warnings/Errors
    card either names the same window or turns this red."""
    block = _app_js(srv)
    overview_fn = _plainfn(block, "pulseKpis")
    runs_fn = _plainfn(block, "runsKpis")
    script = tmp_path / "window-agreement.js"
    script.write_text("""
    // normStatus is a page-owned binding (bin/dashboard.html), filled in at
    // runtime by bindPage() -- not a function this block can extract, so it
    // is stubbed the same trivial way
    // test_a_run_matched_only_in_its_log_content_still_surfaces above
    // already does. pct is ui/app/runs.js's own module-private helper --
    // stubbed the same way so this test does not care whether runsKpis
    // still calls it.
    function normStatus(s){ return s === "ok" ? "success" : (s || "\\u2014"); }
    function pct(num, den){ return den ? Math.round(num/den*100) + "%" : "\\u2014"; }
    """ + overview_fn + runs_fn + """
    const overview = pulseKpis({checks: 10, per: {woke: 1}, warn: 3, err: 2,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    const now = Math.floor(Date.now() / 1000);
    const runs = [
      {id: "r1", start: now - 3600,     status: "warning"},
      {id: "r2", start: now - 3600,     status: "error"},
      {id: "r3", start: now - 40*86400, status: "warning"},
    ];
    const runsPage = runsKpis(runs, 0);
    const by = (list) => Object.fromEntries(list.map(c => [c.label, c]));
    const ov = by(overview), rp = by(runsPage);
    console.log(JSON.stringify({
      overviewWarnSub: ov["Warnings"].sub, runsWarnSub: rp["Warnings"].sub,
      overviewErrSub: ov["Errors"].sub, runsErrSub: rp["Errors"].sub,
    }));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["overviewWarnSub"] == got["runsWarnSub"], (
        f"Overview's Warnings card says {got['overviewWarnSub']!r}, Runs' "
        f"own says {got['runsWarnSub']!r} -- the door and its destination "
        f"name different windows under the same label")
    assert got["overviewErrSub"] == got["runsErrSub"], (
        f"Overview's Errors card says {got['overviewErrSub']!r}, Runs' own "
        f"says {got['runsErrSub']!r} -- the door and its destination name "
        f"different windows under the same label")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_total_runs_says_1000_plus_at_the_servers_own_cap(srv, tmp_path):
    """bin/claude-cron-server's own load_data() caps the runs query at 1000
    rows (`ORDER BY start DESC, rowid DESC LIMIT 1000`) -- CC.DATA.runs can
    never carry more than that, no matter how much history actually exists.
    "Total runs" used to print that capped length as a plain number, which
    reads as a complete count at exactly the point it stops being one: the
    1001st-oldest run is sitting in the same database, uncounted.

    Keyed on `finished` (the journaled rows actually in hand), not `total`
    (finished + live) -- a run in flight is not yet in the capped list, so
    adding it on top must not turn an honest floor back into a
    precise-looking number a run or two later."""
    block = _app_js(srv)
    fn = _plainfn(block, "runsKpis")
    script = tmp_path / "total-runs-cap.js"
    script.write_text("""
    function normStatus(s){ return s === "ok" ? "success" : (s || "\\u2014"); }
    """ + fn + """
    const mk = (n) => Array.from({length: n}, (_, i) => ({id: "r"+i, start: i, status: "success"}));
    const totalRuns = (runs, live) =>
      runsKpis(runs, live).find(c => c.label === "Total runs").value;
    console.log(JSON.stringify({
      atCap:    totalRuns(mk(1000), 0),
      belowCap: totalRuns(mk(999),  0),
      overCap:  totalRuns(mk(1000), 3),
    }));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["atCap"] == "1000+", f"1000 journaled runs should read as a floor: {got['atCap']!r}"
    assert got["belowCap"] == "999", f"below the cap, the exact count should still show: {got['belowCap']!r}"
    assert got["overCap"] == "1000+", (
        f"live runs on top of a capped 1000 must not turn the floor back "
        f"into a precise-looking number: {got['overCap']!r}")


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


# ---- the native <select> ban. Two user reports on this branch, both about
# the same thing: a bare <select> renders as a grey OS menu right next to the
# house .picker (makePicker) or .combo (createCombo) every other dropdown in
# the product wears, and drags a SECOND chevron of its own in on top of
# whichever one the surrounding markup already drew -- the extra chevron is
# what made the Security index's own filter bar wrap under Refresh at the
# pane's own width, before Phase 4 Task 5 fixed it. The house has one
# dropdown vocabulary; this is the guard that keeps a native <select> from
# ever joining it again -- not just the six the plan named (the filter bar's
# three, the Analyse launcher's three) but the findings browser's own
# saved-filters dropdown this task found unnamed on its own, which is
# exactly the kind of instance a scan over every module beats a scan over a
# named list at catching.

def _select_findings(page, sources_text):
    """Every sign of a native <select> the guard below refuses: a literal
    <select> tag anywhere the rendered page sends to the browser, or a
    createElement("select") / createElement('select') call anywhere under
    ui/ -- both quote styles, since nothing here enforces which one a future
    edit reaches for.

    HTML comments are stripped from `page` first: this file's own prose (and
    bin/dashboard.html's, explaining what a field used to be) says "<select>"
    freely, same as the codebase already did before this guard existed --
    the rule is about what the browser renders or the script creates, not
    about the five characters "<select" appearing in a sentence. The
    JS-source check gets no such pass: createElement("select"/'select') is
    specific enough as a call shape that prose is never going to write it by
    accident (this file's own HTML_SINKS denylist above leans on the same
    idea -- innerHTML alone, in a sentence, matches none of its patterns
    either)."""
    rendered = re.sub(r"<!--.*?-->", "", page, flags=re.S)
    found = []
    if "<select" in rendered:
        found.append("<select> in the rendered page")
    if re.search(r"""createElement\(\s*["']select["']\s*\)""", sources_text):
        found.append('createElement("select") under ui/')
    return found


def test_the_page_and_every_ui_module_are_free_of_native_selects(srv):
    """_security_sources() (see its own comment) already walks the whole of
    `ui/` by default, ui/app/ included -- one scan, not two, covers both "the
    Security area" and "the app bundle" the same way _security_js's own
    HTML-sink guards above do."""
    found = _select_findings(_page(srv), _security_js(srv))
    assert not found, f"a native <select> survives: {found}"


def test_the_select_ban_would_catch_one(srv):
    """The guard above passes today because there is nothing left to find,
    which is also what a broken guard looks like. Mutate the real page and
    the real sources the way a regression actually would -- a hand-written
    <select> back in the markup, a createElement call in either quote style
    -- and check each shape is seen."""
    assert _select_findings(_page(srv) + '\n<select id="regression"></select>\n', _security_js(srv))
    assert _select_findings(_page(srv), _security_js(srv) + '\n  document.createElement("select");\n')
    assert _select_findings(_page(srv), _security_js(srv) + "\n  document.createElement('select');\n")


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


def test_the_coverage_is_summarised_by_phase_above_the_paragraph(srv):
    """`coverage_note` is one string assembled from 27 note constants across
    six server modules -- ~2,000 characters on a real analysis. Every sentence
    is true and the block of them is unreadable; the operator who built this
    read one and asked "what IS this alert?". The screen now draws the phase
    summary FIRST (bin/security/coverage.py's structure, in the row's own
    `coverage` column) and folds each phase's prose underneath.

    THE ORDER IS THE WHOLE POINT, so it is asserted and not merely described:
    a summary painted after the paragraph is a summary nobody reaches."""
    page = srv.render_page("boot-authed")
    assert 'id="sec-phases"' in page
    block = _security_js(srv)
    paint = _plainfn(block, "secPaint")
    assert "secRenderCoveragePhases(a)" in paint
    # Against the paragraph's own render, not against the first mention of the
    # id -- `secPaint`'s no-analysis branch hides both boxes near the top and
    # would satisfy any looser comparison.
    assert paint.index("secRenderCoveragePhases(a)") \
        < paint.index('const note = $("sec-coverage")'), \
        "the phase summary must be painted BEFORE the coverage paragraph"
    render = _plainfn(block, "secRenderCoveragePhases")
    # Same rule as every other line of this view: text, never markup -- and
    # every one of these values arrives from a database column.
    assert "innerHTML" not in render
    # The status is the server's word, not something read back out of the
    # prose, and the screen must not invent one either.
    assert "JSON.parse" in render


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_each_coverage_phase_renders_one_line_with_a_status_and_its_producer(
        srv, tmp_path):
    """Drives the real renderer under Node. One row per phase, the status as
    both a word and a class (so the row is scannable by colour), the producer
    that answered, and the phase's own prose folded beneath it rather than run
    together with the rest of the table's -- one row per entry of
    `coverage.PHASE_ORDER`, however many that tuple holds; the count is not
    this test's to know."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_PHASE_STATUS")
            + _index_screen_deps(block, "secEl", "secRenderCoveragePhases"))
    script = tmp_path / "coverage-phases.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    const HOSTS = {};
    function $(id){
      if(!HOSTS[id]) HOSTS[id] = document.createElement("div");
      return HOSTS[id];
    }
    """ + deps + """
    secRenderCoveragePhases({coverage: JSON.stringify({phases: [
      {name: "secrets", status: "ran", by: "gitleaks", note: ""},
      {name: "iac", status: "skipped", by: null,
       note: "trivy is not available to this analysis"},
      {name: "triage", status: "warning", by: "agent",
       note: "12 deterministic findings were never triaged"}]})});
    console.log(JSON.stringify({
      hidden: $("sec-phases").hidden,
      nodes: collectAll($("sec-phases"), []),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True,
                                    check=True).stdout)
    assert out["hidden"] is False
    rows = [n for n in out["nodes"] if n["cls"].startswith("secphase secphase-")]
    assert len(rows) == 3, f"one row per phase, got {len(rows)}: {out['nodes']}"
    assert [r["cls"] for r in rows] == ["secphase secphase-ran",
                                        "secphase secphase-skipped",
                                        "secphase secphase-warning"]
    joined = " ".join(r["text"] for r in rows)
    assert "secrets" in joined and "gitleaks" in joined
    assert "skipped" in joined
    # `warning` is not the word a reader needs -- "partly" is what it means
    # for the report: something looked, but not the whole of what the phase
    # covers.
    assert "partly" in joined, joined
    # The prose is THERE, under its own phase, not concatenated into one
    # paragraph with the other phases' (`coverage.PHASE_ORDER` says how many).
    notes = [n["text"] for n in out["nodes"] if n["cls"] == "secphase-note"]
    assert "trivy is not available to this analysis" in notes


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_analysis_with_no_structured_coverage_draws_no_phase_summary(
        srv, tmp_path):
    """Every analysis written before the `coverage` column carries '' in it,
    and this screen has always shown the paragraph alone. Nothing about that
    may change -- no empty box, no header over nothing. A column that somehow
    holds something unreadable takes the same path: a screen is not the place
    to discover a corrupt column, and the paragraph below is still true."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_PHASE_STATUS")
            + _index_screen_deps(block, "secEl", "secRenderCoveragePhases"))
    script = tmp_path / "coverage-none.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    const HOSTS = {};
    function $(id){
      if(!HOSTS[id]) HOSTS[id] = document.createElement("div");
      return HOSTS[id];
    }
    """ + deps + """
    const seen = [];
    for(const cov of [undefined, "", "not json", '{"phases": "secrets"}']){
      secRenderCoveragePhases({coverage: cov});
      seen.push({hidden: $("sec-phases").hidden,
                 text: $("sec-phases").textContent});
    }
    console.log(JSON.stringify(seen));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True,
                                    check=True).stdout)
    for state in out:
        assert state["hidden"] is True, out
        assert state["text"] == "", out


# ---- the index screen's own renderer. Everything above this point drives
# the JSON contract (tests/security/test_cli.py, tests/test_security_api.py)
# but never the DOM the JSON is painted into -- so a regression in, say, the
# dash-versus-percent ternary or a fallback-branch note would have passed
# every one of those tests. This stub stands in for the DOM the real browser
# gives ui/security/index-screen.js: plain objects, no jsdom dependency,
# just enough of Element/Text/Node for secEl/secIcon (dom.js) and the
# createElement/createElementNS calls the screen's own functions make.

_INDEX_DOM_HARNESS = """
// The builders ask this as they build a Run now / Resume button, so that a
// repaint which never reaches render() cannot hand a pending start back live
// (see test_every_run_and_resume_button_asks_about_the_pending_start_as_it_is_built).
// Nothing here is testing that guard, so the stand-in is the "nothing pending"
// answer: it hands the button straight back, exactly as the real one does when
// no start is in flight.
function markIfStarting(b){ return b; }
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
    deps = _index_screen_deps(block, "el", "secEl", "secIcon", "kpiCard",
                              "secCappedScopeNote", "secIndexCards")
    script = tmp_path / "kpi-dash.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 1, analyses: 0, critical: 0, high: 0,
                                  capped_projects: 0, success_rate: null});
    console.log(JSON.stringify(collectAll(cards, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    # secidx-num was the card's own number class before Phase 4 Task 1 moved
    # the five KPI cards onto the shared kpiCard() builder (ui/app/chrome.js)
    # -- kpi-card-num is its exact replacement, same one-number-per-card shape.
    nums = [r["text"] for r in out if r["cls"] == "kpi-card-num"]
    assert "—" in nums, f"no dash rendered for a null success rate: {nums}"
    assert "0%" not in nums, f"a zero-percent rendered where a dash belongs: {nums}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_fallen_back_branch_is_rendered_with_its_name_visible(srv, tmp_path):
    """Postures of different branches must never be confused in silence --
    the branch a posture actually belongs to has to stay on the page, not
    just a bare "(fell back)" note with nothing named (see the comment on
    secIndexProjectRow's own Last analysis cell -- the fallen-back note's
    home since Phase 4 Task 3 folded the table's old dedicated Branch column
    into that cell's "profile · branch" sub-line). Drives
    secIndexProjectsTable end to end rather than the JSON contract alone."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_PROJECT_COLS") + _const(block, "FIND_SEVS")
            + _index_screen_deps(block, "secEl", "secIcon", "secIndexProjectRow",
                                 "secIndexProjectsTable", "secIndexFindingsChips",
                                 "secIndexTrendSpark", "secLastRunDuration",
                                 "secIndexRunWhen", "secProfileLabel"))
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
    secIndexProjectRow) and pass after it. The cue itself moved to the
    Findings cell in Phase 4 Task 3 (secIndexFindingsChips) -- the counts it
    qualifies are the ones on that cell now, not a separate Posture column."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_PROJECT_COLS") + _const(block, "FIND_SEVS")
            + _index_screen_deps(block, "secEl", "secIcon", "secIndexProjectRow",
                                 "secIndexProjectsTable", "secIndexFindingsChips",
                                 "secIndexTrendSpark", "secLastRunDuration",
                                 "secIndexRunWhen", "secProfileLabel"))
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
    deps = (_const(block, "SEC_PROJECT_COLS") + _const(block, "FIND_SEVS")
            + _index_screen_deps(block, "secEl", "secIcon", "secIndexProjectRow",
                                 "secIndexProjectsTable", "secIndexFindingsChips",
                                 "secIndexTrendSpark", "secLastRunDuration",
                                 "secIndexRunWhen", "secProfileLabel"))
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


# ---- Phase 4 Task 3's own new substance: the filter bar's pure filtering
# function, the trend sparkline's honest-empty-cell rule, the Findings
# cell's fixed three-chip shape and the Status pill's enabled/disabled read.
# None of these four existed before this task; each is pinned here rather
# than left to only the mockup's own pixels to hold in place.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_secFilterProjects_matches_by_query_status_profile_and_branch(srv, tmp_path):
    """The filter bar's own client-side filtering ("they filter THIS table
    client-side from what the payload carries") -- a pure function, no DOM,
    so this drives it directly rather than through a picker's onchange no
    test here can click. Query matches name OR description, case-
    insensitively; status/profile/branch are exact matches against the
    row's own fields, empty meaning "All"."""
    block = _security_js(srv)
    deps = _plainfn(block, "secFilterProjects")
    script = tmp_path / "filter-projects.js"
    script.write_text(deps + """
    const rows = [
      {name: "Minerva", description: "Revenue platform", profile: "deep",
       branch: "develop", enabled: true},
      {name: "Quality Gate", description: "QG board", profile: "standard",
       branch: "main", enabled: false},
    ];
    console.log(JSON.stringify({
      byQuery: secFilterProjects(rows, {query: "revenue"}).map(p => p.name),
      byQueryOnName: secFilterProjects(rows, {query: "GATE"}).map(p => p.name),
      byStatusActive: secFilterProjects(rows, {status: "active"}).map(p => p.name),
      byStatusDisabled: secFilterProjects(rows, {status: "disabled"}).map(p => p.name),
      byProfile: secFilterProjects(rows, {profile: "standard"}).map(p => p.name),
      byBranch: secFilterProjects(rows, {branch: "develop"}).map(p => p.name),
      noFilters: secFilterProjects(rows, {}).map(p => p.name),
      noMatch: secFilterProjects(rows, {query: "nothing-matches-this"}).map(p => p.name),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["byQuery"] == ["Minerva"], out
    assert out["byQueryOnName"] == ["Quality Gate"], out
    assert out["byStatusActive"] == ["Minerva"], out
    assert out["byStatusDisabled"] == ["Quality Gate"], out
    assert out["byProfile"] == ["Quality Gate"], out
    assert out["byBranch"] == ["Minerva"], out
    assert out["noFilters"] == ["Minerva", "Quality Gate"], out
    assert out["noMatch"] == [], out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_empty_trend_renders_a_dash_not_a_fabricated_flat_line(srv, tmp_path):
    """trend_series (bin/security/queries.py) returns [] for a project with
    no declared base, or one never analysed on it -- deliberately never
    plotting a FALLBACK branch's history under a name it does not belong to
    (see that function's own docstring). The cell has to say so honestly --
    a flat zero-height line drawn over an empty list would look like a
    measured, unchanging history instead of "nothing to plot"."""
    block = _security_js(srv)
    deps = _plainfn(block, "secEl") + _plainfn(block, "secIndexTrendSpark")
    script = tmp_path / "trend-spark.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const empty = secIndexTrendSpark([]);
    const withPoints = secIndexTrendSpark([1, 5, 2, 0, 8]);
    console.log(JSON.stringify({
      emptyText: empty.textContent,
      emptyTag: empty.tagName,
      pointsTag: withPoints.tagName,
      barCount: (withPoints.childNodes || []).length,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["emptyText"] == "—", out
    assert out["emptyTag"] == "span", f"an empty trend must not render an <svg>: {out}"
    assert out["pointsTag"] == "svg", out
    assert out["barCount"] == 5, "one bar per point, five points in: " + str(out)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_findings_chips_show_three_severities_and_the_postures_own_total(srv, tmp_path):
    """Three FIXED chips (critical/high/medium), always in that order even
    at zero -- and "N total" is posture's OWN total, not a sum of the three
    shown chips: low/info both count toward it with no chip of their own,
    exactly like the mockup's own "89 total" over chips that only add to 82."""
    block = _security_js(srv)
    deps = _plainfn(block, "secEl") + _plainfn(block, "secIndexFindingsChips")
    script = tmp_path / "findings-chips.js"
    # FIND_SEVS is a module-level const the real file declares OUTSIDE the
    # function (same reason _JOBS_DOMAIN_HARNESS stands up small stand-ins
    # for names jobFacts reads from its own module's outer scope).
    script.write_text(_INDEX_DOM_HARNESS + """
    const FIND_SEVS = ["critical", "high", "medium"];
    """ + deps + """
    const cell = secIndexFindingsChips(
      {critical: 12, high: 27, medium: 43, low: 5, info: 2, total: 89}, false);
    console.log(JSON.stringify({
      chipCount: cell.childNodes[0].childNodes.length,
      chips: cell.childNodes[0].childNodes.map(c => c.textContent),
      total: cell.childNodes[1].textContent,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["chipCount"] == 3, out
    assert out["chips"] == ["12", "27", "43"], out
    assert out["total"] == "89 total", \
        f"total must be posture's OWN total, not 12+27+43: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_status_pill_reads_active_or_disabled_from_the_enabled_field(srv, tmp_path):
    """`.pill.off` stays reserved for the scheduler fault (its own comment,
    components.css) -- a project simply switched off gets `.pill.disabled`,
    the grey one, never the red one. `enabled` defaults to active when
    absent -- every real row today IS security-enabled by construction (see
    secIndexProjectRow's own comment on the PROJECT cell's badge), so the
    real payload never actually sends `enabled: false`; this proves the
    branch still works honestly for whenever a payload does."""
    block = _security_js(srv)
    deps = (_const(block, "FIND_SEVS")
            + _index_screen_deps(block, "secEl", "secIcon", "secIndexProjectRow",
                                 "secIndexProjectsTable", "secIndexFindingsChips",
                                 "secIndexTrendSpark", "secLastRunDuration",
                                 "secIndexRunWhen", "secProfileLabel"))
    script = tmp_path / "status-pill.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const base = {name: "web", description: "", branch: "main",
      branch_fell_back: false, posture: {critical:0,high:0,medium:0,low:0,info:0,total:0},
      profile: "quick", last_started: 0, last_duration: 0, last_state: "done", analyses: 1};
    const active = secIndexProjectRow(Object.assign({}, base));
    const disabled = secIndexProjectRow(Object.assign({}, base, {enabled: false}));
    // Exact match, not "starts with pill " -- the Profile cell's own pill
    // ("pill profile") would otherwise be the first match collectAll finds,
    // since it sits earlier in the row than Status does.
    function statusPill(tr){
      return collectAll(tr, []).find(r => r.cls === "pill on" || r.cls === "pill disabled");
    }
    console.log(JSON.stringify({active: statusPill(active), disabled: statusPill(disabled)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["active"]["cls"] == "pill on" and out["active"]["text"] == "Active", out
    assert out["disabled"]["cls"] == "pill disabled" and out["disabled"]["text"] == "Disabled", out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_critical_and_high_kpi_cards_flag_incomplete_contributors(srv, tmp_path):
    """The other half of finding 1: when any project's latest analysis is
    capped, the Critical/High KPI cards must say how many, instead of
    presenting a fleet-wide total that looks complete."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "el", "secEl", "secIcon", "kpiCard",
                              "secCappedScopeNote", "secIndexCards")
    script = tmp_path / "kpi-capped.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 2, analyses: 3, critical: 1, high: 2,
                                  capped_projects: 1, success_rate: 1.0});
    console.log(JSON.stringify(collectAll(cards, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    # The caveat used to be a visible .secidx-note line; Phase 4 Task 1's
    # kpiCard-based cards have no room left in the sub for a sentence this
    # long (the mockup's own sub is the fixed, short "needs immediate
    # attention"), so it now lives in the card's own `.title` tooltip instead
    # -- kpiCard's documented purpose for that attribute (see its own comment
    # in ui/app/chrome.js). Still the outer card element, still reachable by
    # `collectAll`, just a different field on the same record.
    notes = [r["title"] for r in out if r["cls"].startswith("kpi-card") and r["title"]]
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

# The chrome bridge's kpiCard, as a deliberately trivial stand-in for tests
# that drive a builder composing KPI cards (the findings strip, the Overview
# row) -- same child order as the real one: number, label, optional sub.
_KPI_CARD_STUB = """
function kpiCard(o){
  const c = new FakeElement("div");
  c.className = "kpi-card" + (o.tone ? " " + o.tone : "");
  if(o.title) c.title = o.title;
  const num = new FakeElement("span"); num.className = "kpi-card-num";
  num.textContent = o.value; c.appendChild(num);
  const lab = new FakeElement("div"); lab.className = "kpi-card-label";
  lab.textContent = o.label; c.appendChild(lab);
  if(o.sub){ const s = new FakeElement("div"); s.className = "kpi-card-sub";
    s.textContent = o.sub; c.appendChild(s); }
  return c;
}
"""

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
// pushNav (F4 history layer): a trivial stand-in for bin/dashboard.html's
// own history.pushState wrapper, bridged in the same way fmtWhen/
// openProjectEditor above are. secSwitchProjectTab, secBack and
// activity-screen.js's secOpenActivity/secBackFromActivity/secActSwitchTab
// all call it once they finish updating their own state (see each
// function's own comment) -- these tests are about which pane ends up
// visible or which tab ends up active, never about browser history, so this
// only has to exist and not throw.
function pushNav(_state){}
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


def _overview_tab_deps(block):
    """Everything the Overview tab's full render (overview-tab.js) reaches,
    extracted from the bundle, plus deliberately trivial stubs for the
    bridge and cross-module bindings the harness cannot extract (kpiCard is
    a CCApp bridge binding; secRuleMeta/secSevKey/the three navigation
    callees are other modules' own, not under test here)."""
    consts = "".join(_const(block, n) for n in
        ("SEV5", "SEV_LABEL", "SEV_KPI_ICON", "SEV_KPI_TONE", "SEC_OVFIND_COLS",
         "SEC_NEVER", "SEC_EVENT_META", "EVENT_KIND_LABEL"))
    fns = "\n".join(_plainfn(block, n) for n in
        ("secEl", "secIcon", "secOvDeltaText", "secOvShare", "secOvKpis",
         "secOvTrendCard", "secOvTrendSeg", "secOvDay", "secOvTrendValue",
         "secOvTrendSvg", "secOvSevToken", "secOvDrawChart", "secOvWireResize",
         "secOvCategoryCard", "secOvDonutSvg", "secDonutArc",
         "secOvViewAll", "secOvCap", "secOvSortedFindings", "secOvTopFindings",
         "secOvSortableHeader", "secOvFindingRow", "secProjectActivity",
         "secRenderProjectOverview"))
    stubs = """
    let secOvTrendSev = "total", secOvSort = null,
        secOvProject = null, secOvPayload = null,
        secOvChartMount = null, secOvChartState = null, secOvResizeWired = false;
    const window = {addEventListener(){}};
    function kpiCard(o){
      const c = new FakeElement("div");
      c.className = "kpi-card" + (o.tone ? " " + o.tone : "");
      if(o.title) c.title = o.title;
      const num = new FakeElement("span"); num.className = "kpi-card-num";
      num.textContent = o.value; c.appendChild(num);
      const lab = new FakeElement("div"); lab.className = "kpi-card-label";
      lab.textContent = o.label; c.appendChild(lab);
      if(o.sub){ const s = new FakeElement("div"); s.className = "kpi-card-sub";
        s.textContent = o.sub; c.appendChild(s); }
      return c;
    }
    function secRuleMeta(_cat, rule){ return {label: "L:" + (rule || ""), icon: "key"}; }
    function secSevKey(f){ return f.severity || "info"; }
    function secSwitchProjectTab(_t){}
    function secShowAnalysis(_id, _pin){}
    function secOpenActivity(_p){}
    """
    return consts + stubs + fns


# A payload every field of the full Overview render reads -- the same shape
# cmd_project_data serves, trimmed to one branch, two analyses' worth.
_OVERVIEW_PAYLOAD = """
    const PAYLOAD = {
      project: "web",
      header: {branch: "main", branch_fell_back: false},
      tabs: {overview: {state: "capped", attempted: true,
        posture: {critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1},
        previous: {critical: 2, high: 0, medium: 0, low: 0, info: 0, total: 2},
        trend: [{analysis_id: 1, started: 1700000000, state: "done", open: 2,
                 by_severity: {critical: 2, high: 0, medium: 0, low: 0, info: 0}},
                {analysis_id: 2, started: 1700086400, state: "capped", open: 1,
                 by_severity: {critical: 1, high: 0, medium: 0, low: 0, info: 0}}],
        categories: [{rule: "sql-injection", category: "sast", count: 1}],
        top_findings: [{fingerprint: "f", severity: "critical",
          title: "SQL injection", rule: "sql-injection", category: "sast",
          file: "app/db.py", line: 40, more: 1, analysis_id: 2,
          profile: "deep", first_seen: 1700000000}],
        checklist: {}}},
      sidebar: {activity: [{kind: "analysis_finished", detail: "done", at: 5}]},
    };
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_capped_latest_analysis_renders_the_incompleteness_notice(srv, tmp_path):
    """THE SAME notice secPaint gives on the old analysis screen and the
    index screen gives on a project row -- a capped analysis is a PARTIAL
    read, so the numbers underneath are what it had reached, not what is
    there. Driven through the FULL Overview render (overview-tab.js), so
    the notice's survival is checked in the pane that actually shows it."""
    block = _security_js(srv)
    script = tmp_path / "pj-capped.js"
    script.write_text(_PROJECT_DOM_HARNESS + _overview_tab_deps(block)
                      + _OVERVIEW_PAYLOAD + """
    secRenderProjectOverview(PAYLOAD);
    console.log(JSON.stringify(collectAll(_els["sec-pj-overview"], [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "INCOMPLETE" in joined, f"no incompleteness notice rendered: {joined}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_overview_kpis_count_severities_and_state_a_real_delta(srv, tmp_path):
    """ProjectOverview.png's six cards, rendered honestly: the Total card's
    small line is the real change against the previous finished analysis
    (green down / red up / "no previous analysis" when there is none --
    never a delta nothing was compared against), and each severity card's
    line is its share of the total, labelled as exactly that. The mockup's
    own sample prints shares under a "vs. previous analysis" sublabel its
    numbers contradict; the layout is kept, the lie is not."""
    block = _security_js(srv)
    script = tmp_path / "ov-kpis.js"
    script.write_text(_PROJECT_DOM_HARNESS + _overview_tab_deps(block) + """
    const withPrev = secOvKpis({
      posture: {critical: 1, high: 2, medium: 0, low: 0, info: 1, total: 4},
      previous: {critical: 2, high: 3, medium: 0, low: 0, info: 3, total: 8}});
    const noPrev = secOvKpis({
      posture: {critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0},
      previous: null});
    const cards = withPrev.childNodes.map(c => ({cls: c.className,
      text: collectAll(c, []).map(r => r.text).join(" ")}));
    console.log(JSON.stringify({cards,
      d_down: secOvDeltaText(4, 8), d_up: secOvDeltaText(8, 4),
      d_same: secOvDeltaText(3, 3), d_none: secOvDeltaText(3, null),
      d_fromzero: secOvDeltaText(3, 0),
      noPrevTotal: collectAll(noPrev.childNodes[0], []).map(r => r.text).join(" "),
      share: secOvShare(1, 4), shareNone: secOvShare(0, 0)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    cards = out["cards"]
    assert len(cards) == 6, f"six KPI cards, total + five severities: {len(cards)}"
    tones = [c["cls"] for c in cards]
    assert tones[1:] == ["kpi-card sev-crit", "kpi-card sev-high", "kpi-card sev-med",
                         "kpi-card sev-low", "kpi-card sev-info"], \
        f"severity cards wear the severity scale, never err/warn: {tones}"
    # 8 -> 4 open findings is a 50% improvement, said with the green arrow.
    assert out["d_down"] == {"text": "↓ 50%", "dir": "good", "sub": "vs. previous analysis"}
    assert out["d_up"]["dir"] == "bad" and out["d_up"]["text"].startswith("↑")
    assert out["d_same"]["text"] == "no change" and out["d_same"]["dir"] == ""
    assert out["d_none"] == {"text": "—", "dir": "", "sub": "no previous analysis"}
    # From zero there is no percentage to state -- the absolute count is.
    assert out["d_fromzero"]["text"] == "↑ +3" and out["d_fromzero"]["dir"] == "bad"
    assert "no previous analysis" in out["noPrevTotal"]
    assert "vs. previous analysis" in cards[0]["text"]
    assert "of total findings" in cards[1]["text"]
    assert out["share"] == "25%"
    assert out["shareNone"] == "—", "a share of a zero total is not 0%, it is nothing"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_trend_chart_draws_the_selected_severitys_own_series(srv, tmp_path):
    """The Total/Critical/.../Info control swaps WHICH series the one line
    draws -- each dot's tooltip carries that series' own value at that
    analysis, and a capped point keeps the area's one honesty cue: hollow,
    with "(incomplete)" spelled out, so a dip at a run that merely stopped
    early cannot pass for progress."""
    block = _security_js(srv)
    script = tmp_path / "ov-trend.js"
    script.write_text(_PROJECT_DOM_HARNESS + _overview_tab_deps(block)
                      + _OVERVIEW_PAYLOAD + """
    const dots = (svg) => {
      const out = [];
      (function walk(n){
        if((n._attrs || {}).class && n._attrs.class.startsWith("secov-dot")){
          out.push({cls: n._attrs.class, tip: n.textContent});
        }
        (n.childNodes || []).forEach(walk);
      })(svg);
      return out;
    };
    const points = PAYLOAD.tabs.overview.trend;
    const total = dots(secOvTrendSvg(points, "total"));
    const crit = dots(secOvTrendSvg(points, "critical"));
    console.log(JSON.stringify({total, crit,
      value: secOvTrendValue(points[0], "critical"),
      legacy: secOvTrendValue({open: 5}, "critical"),
      wide: secOvTrendSvg(points, "total", 1600)._attrs.viewBox,
      fallback: secOvTrendSvg(points, "total")._attrs.viewBox}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    # Drawn at the measured width, one unit per pixel -- a 1600px card gets
    # a 1600-unit viewBox, so the 11px axis text renders at 11px there too
    # instead of scaling up with the card. 720 is the no-layout fallback.
    assert out["wide"] == "0 0 1600 250", out["wide"]
    assert out["fallback"] == "0 0 720 250", out["fallback"]
    assert [d["tip"].split(" — ")[1].split(" open")[0] for d in out["total"]] == ["2", "1"]
    assert [d["tip"].split(" — ")[1].split(" open")[0] for d in out["crit"]] == ["2", "1"]
    assert out["value"] == 2
    assert out["legacy"] == 0, "a point without by_severity reads 0, never NaN"
    capped = [d for d in out["total"] if "capped" in d["cls"]]
    assert len(capped) == 1 and "(incomplete)" in capped[0]["tip"], \
        f"the capped analysis's dot must carry the incompleteness cue: {out['total']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_category_donut_legend_counts_shares_and_the_other_remainder(srv, tmp_path):
    """The donut's centre is the SAME total the KPI row counts (one branch,
    one checklist), each legend row states its count and share, and
    everything past the served buckets is one honest grey "Other" row -- the
    checklist's own remainder, absent entirely when the buckets cover the
    total."""
    block = _security_js(srv)
    script = tmp_path / "ov-donut.js"
    script.write_text(_PROJECT_DOM_HARNESS + _overview_tab_deps(block) + """
    const card = secOvCategoryCard({
      posture: {total: 10},
      categories: [{rule: "a", category: "secrets", count: 5},
                   {rule: "b", category: "sast", count: 2}]});
    const covered = secOvCategoryCard({
      posture: {total: 3},
      categories: [{rule: "a", category: "secrets", count: 3}]});
    const empty = secOvCategoryCard({posture: {total: 0}, categories: []});
    console.log(JSON.stringify({
      card: collectAll(card, []).map(r => r.text).join(" | "),
      covered: collectAll(covered, []).map(r => r.text).join(" | "),
      empty: collectAll(empty, []).map(r => r.text).join(" "),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "5 (50%)" in out["card"] and "2 (20%)" in out["card"], out["card"]
    assert "Other" in out["card"] and "3 (30%)" in out["card"], \
        f"the remainder past the buckets must be one Other row: {out['card']}"
    assert "Total findings" in out["card"] and "10" in out["card"]
    assert "Other" not in out["covered"], \
        "buckets covering the whole total must not render a zero Other row"
    assert "No open findings to categorise." in out["empty"]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_every_event_kind_has_recent_activity_furniture(srv, tmp_path):
    """SEC_EVENT_META (vocabulary.js) walks EVENT_KINDS: every kind the
    ledger can record gets its icon, its badge label and a house .pill tone
    on the Recent-activity card -- a kind added to EVENT_KINDS without a
    row here would fall back to a bare label, and this is what surfaces
    that before a reader does."""
    block = _security_js(srv)
    script = tmp_path / "ov-eventmeta.js"
    script.write_text(_const(block, "EVENT_KINDS") + _const(block, "SEC_EVENT_META")
                      + "console.log(JSON.stringify({kinds: EVENT_KINDS, meta: SEC_EVENT_META}));")
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    for kind in out["kinds"]:
        meta = out["meta"].get(kind)
        assert meta, f"EVENT_KINDS member {kind!r} has no SEC_EVENT_META row"
        assert meta.get("icon") and meta.get("badge") and meta.get("pill"), \
            f"{kind!r}'s furniture is incomplete: {meta}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_top_findings_rows_mirror_the_findings_browsers_cells(srv, tmp_path):
    """The five cells the card shares with the findings browser read the
    same way there and here: the severity pill wears the severity class,
    the location is first-occurrence path:line with a "(+N more)" cue, the
    run link says "#id (Profile)", and a finding first seen at 0 (the
    defensive default) renders a dash, not a 1970 date. The default order
    is the card's own point -- the served severity rank -- and survives
    with no sort selected."""
    block = _security_js(srv)
    script = tmp_path / "ov-findrow.js"
    script.write_text(_PROJECT_DOM_HARNESS + _overview_tab_deps(block) + """
    const row = secOvFindingRow({severity: "high", title: "A long title",
      rule: "private-key-committed", category: "secrets", file: "conf/id_rsa",
      line: 3, more: 2, analysis_id: 5, profile: "deep", first_seen: 0});
    const cells = row.childNodes.map(td => collectAll(td, []).map(r => r.text).join(" "));
    const pill = collectAll(row, []).find(r => r.cls.startsWith("sevpill"));
    const served = [{severity: "critical", file: "b.py", analysis_id: 2},
                    {severity: "high", file: "a.py", analysis_id: 1}];
    const kept = secOvSortedFindings({top_findings: served}).map(f => f.severity);
    secOvSort = {key: "location", dir: "asc"};
    const byLoc = secOvSortedFindings({top_findings: served}).map(f => f.file);
    console.log(JSON.stringify({cells, pill: pill && pill.cls, kept, byLoc}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["pill"] == "sevpill high"
    assert "conf/id_rsa:3 (+2 more)" in out["cells"][2], out["cells"]
    assert "#5 (Deep)" in out["cells"][3], out["cells"]
    assert "—" in out["cells"][4] and "w0" not in out["cells"][4], \
        "first_seen 0 must render a dash, not a 1970 date"
    assert out["kept"] == ["critical", "high"], "no sort selected keeps the served rank"
    assert out["byLoc"] == ["a.py", "b.py"], "the Location header sorts by path"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_switching_project_tabs_shows_one_pane_and_hides_the_other(srv, tmp_path):
    block = _security_js(srv)
    deps = _plainfn(block, "secRenderTabs") + "\n" + _plainfn(block, "secSwitchProjectTab")
    script = tmp_path / "pj-tabs.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secProjectTab = "overview";
    // The title row now follows the tab (SEC_TAB_TITLES, project-screen.js)
    // -- stubbed like renderFindings below: these tests are about pane and
    // rail visibility, never about what the title row paints.
    function secRenderProjectTitle(){}
    // secSwitchProjectTab now also repaints the sidebar through this cache
    // (secRenderProjectSidebar, not extracted here) -- null, exactly the
    // real module's own value before the first project-data fetch answers,
    // is what keeps that call a no-op so this test stays about pane
    // visibility alone.
    let secProjectCache = null;
    """ + deps + """
    secRenderTabs();
    const initial = {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden,
                     side: _els["sec-pj-side"].hidden, crumb: _els["sec-crumb-tab"].textContent};
    secSwitchProjectTab("runs");
    const onRuns = {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden,
                    side: _els["sec-pj-side"].hidden, crumb: _els["sec-crumb-tab"].textContent};
    secSwitchProjectTab("overview");
    const backToOverview = {ov: _els["sec-pj-overview"].hidden, rn: _els["sec-pj-runs"].hidden};
    console.log(JSON.stringify({initial, onRuns, backToOverview}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["initial"]["ov"] is False and out["initial"]["rn"] is True, \
        "Overview must be the default pane"
    assert out["onRuns"]["ov"] is True and out["onRuns"]["rn"] is False, \
        "switching to Runs must hide Overview"
    assert out["backToOverview"] == {"ov": False, "rn": True}, \
        "switching back must hide Runs again, not leave both visible"
    # ProjectOverview.png draws the Overview full-width with its OWN right
    # column (one-branch scope); the all-branch rail beside it would be two
    # donuts with two different, equally true totals an inch apart. The Runs
    # tab keeps the rail exactly as ProjectRuns.png draws it.
    assert out["initial"]["side"] is True, "the all-branch rail must hide on Overview"
    assert out["onRuns"]["side"] is False, "the Runs tab must keep its rail"
    # The breadcrumb's third segment follows the active tab.
    assert out["initial"]["crumb"] == "Overview" and out["onRuns"]["crumb"] == "Runs"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_two_scope_captions_name_the_branch_and_the_branch_count(srv, tmp_path):
    """Finding 1's fix, twice reshaped: the one-branch scope cue lives in
    the shared HEADER (the meta strip names the branch; a fallen-back one
    gets its warning chip there), and the rail's every-analysed-branch
    sentence became secSidebarScopeNote -- a TOOLTIP on the donut block
    that carries those numbers, after the visible caption was caught
    floating above the tab strip and, on the Runs tab, describing the
    all-branch scope over cards that are the selected run's own. The
    substance is unchanged: postures of different branches (and different
    counting rules) must never be confused in silence."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secHeaderBit", "secRenderProjectHeader",
                      "secSidebarScopeNote"))
    deps = _const(block, "SEC_NEVER") + _const(block, "SEC_FLOOR_SCOPE_NOTE") + deps
    script = tmp_path / "pj-captions.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectHeader({header: {profile: "deep", branch: "develop",
      branch_fell_back: true, lines_of_code: 1, last_analysis: 1}});
    const fellBack = collectAll(_els["sec-pj-head"], []).map(r => r.text).join(" ");
    _els["sec-pj-head"] = new FakeElement("div");
    secRenderProjectHeader({header: {profile: "deep", branch: "main",
      branch_fell_back: false, lines_of_code: 1, last_analysis: 1}});
    const plain = collectAll(_els["sec-pj-head"], []).map(r => r.text).join(" ");
    console.log(JSON.stringify({
      fellBack, plain,
      two: secSidebarScopeNote(2),
      one: secSidebarScopeNote(1),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "develop" in out["fellBack"] and "fell back" in out["fellBack"], out["fellBack"]
    assert "main" in out["plain"] and "fell back" not in out["plain"], out["plain"]
    assert "all 2 analysed branches" in out["two"], out["two"]
    assert "fingerprint" in out["two"], \
        f"the note must say what the rollup counts: {out['two']}"
    assert "only analysed branch" in out["one"], \
        f"a single analysed branch must say so plainly: {out['one']}"
    assert "branches" not in out["one"].split("fingerprint")[0], \
        f"a single-branch note must not read as spanning several: {out['one']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_overview_tells_never_analysed_apart_from_never_finished(srv, tmp_path):
    """Finding 4's fix: a project whose every analysis failed has `state:
    ""` (no finished baseline) exactly like a project that was never
    touched, but `attempted: true` -- the Overview pane must show a
    different sentence for the two, not the same "Never analysed" over a
    Runs tab that lists real attempts."""
    block = _security_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secRenderProjectOverview"))
    # The module-local selections the render resets per project -- the
    # never-analysed path returns before any card builder is reached, so
    # these four lets are the only non-extracted state it touches.
    deps = (_const(block, "SEC_NEVER")
            + "let secOvTrendSev = 'total', secOvSort = null,"
            + " secOvProject = null, secOvPayload = null;\n" + deps)
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
    # secRunsTable now builds its own footer with the bridged tableFooter()
    # (Phase 4 Task 6) -- its real implementation (ui/app/chrome.js), not a
    # stub, joins the dependency list the same way test_the_pager_math_and_
    # button_disabling_at_both_edges (findings-screen.js's own pager test)
    # already pulls it in for real.
    chrome_deps = _plainfn(_app_js(srv), "el") + "\n" + _plainfn(_app_js(srv), "tableFooter")
    # secRunRow now paints its own STATE cell with secIndexRunStatusPill
    # (M6a, Phase 4 final review, index-screen.js) instead of the bare
    # lowercase word it used to -- both that function and the label map it
    # reads join the dependency list for the same reason SEC_RUNS_COLS
    # already does: secRunRow is exercised for real below, not stubbed.
    # secIcon/SEV_LETTER/secRunSeverityLine (Phase: Runs tab rebuild) join it
    # for the identical reason: the sortable Date header and the FINDINGS
    # cell's own per-severity sub-line ("64C 4H 3M 0L") are both real code
    # paths this table now runs through, not stubs standing in for them.
    deps = (_const(block, "SEC_RUNS_COLS") + _const(block, "SEC_RUN_STATUS_LABEL")
            + _const(block, "SEV_LETTER") + chrome_deps + "\n"
            + "\n".join(_plainfn(block, n) for n in
                ("secEl", "secIcon", "secIndexRunStatusPill", "secRunSeverityLine",
                 "secRunRow", "secRunsTable")))
    script = tmp_path / "pj-runs-header.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secRunsFilter = "";
    // secRunsTable's own Date-column sort state -- module-level in the real
    // file, declared plainly here the same way secRunsFilter already is.
    let secRunsSortDir = "desc";
    """ + deps + """
    const wrap = secRunsTable([{id: 2, profile: "quick", repo: "web", branch: "main",
      commit_sha: "abc123def456", started: 100, ended: 110, findings: 1,
      findings_by_severity: {high: 1}, state: "done"}]);
    // table-card -> table-scroll -> table -> thead -> tr (Phase 4 Task 6 put
    // the table inside a table-card, one level deeper than the bare
    // .tablewrap this used to walk into directly).
    const table = wrap.childNodes[0].childNodes[0];
    const thead = table.childNodes[0];
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
def _branches_tab_deps(block):
    """Everything the Branches tab's full render (branches-tab.js) reaches,
    extracted from the bundle, plus trivial stubs for the bridge and
    cross-module bindings -- the identical shape _overview_tab_deps takes
    for its own tab."""
    consts = "".join(_const(block, n) for n in
        ("SEC_BRANCH_COLS", "SEC_BR_SEVS", "SEC_BR_WINDOWS",
         "SEC_BRANCH_ACTIVE_DAYS", "BRANCH_CAPPED_TITLE", "BRANCH_SCOPE_TITLE",
         "SEC_NEVER"))
    fns = "\n".join(_plainfn(block, n) for n in
        ("secEl", "secIcon", "secBranchIsActive", "secBrDefaultBranch",
         "secBrKpis", "secBrRepaint", "secBrPicker", "secBrFilterBar",
         "secBrFiltered", "secBrTable", "secBranchRow", "secBrSevChips",
         "secBrTrendBars", "secBrKebab", "secBranchTrendText",
         "secRenderProjectBranches"))
    stubs = """
    let secBrSearch = "", secBrStatus = "", secBrDays = 0,
        secBrProject = null, secBrPayload = null;
    const window = {addEventListener(){}, innerWidth: 1400};
    function kpiCard(o){
      const c = new FakeElement("div");
      c.className = "kpi-card" + (o.tone ? " " + o.tone : "");
      if(o.title) c.title = o.title;
      const num = new FakeElement("span"); num.textContent = o.value; c.appendChild(num);
      const lab = new FakeElement("div"); lab.textContent = o.label; c.appendChild(lab);
      if(o.sub){ const s = new FakeElement("div"); s.textContent = o.sub; c.appendChild(s); }
      return c;
    }
    function projById(_id){ return {base: "develop"}; }
    function tableFooter(o){
      const f = new FakeElement("footer");
      f.textContent = "Showing " + o.shown.from + " to " + o.shown.to
        + " of " + o.total + " " + o.noun;
      return f;
    }
    function secFindTriggerLabel(label, valueText){
      const trigger = new FakeElement("summary");
      trigger.textContent = (label ? label + ": " : "") + valueText;
      return {trigger};
    }
    function secFindPositionPop(details, _trigger, pop){ details.appendChild(pop); }
    function renderFindings(_host, _project, _filters){}
    function secSwitchProjectTab(_t){}
    function secShowAnalysis(_id, _pin){}
    function secDownloadReport(_id, _fmt, _el){}
    function secRefreshProject(){}
    function secGitBranchCount(){ return 0; }
    function closeMenus(){}
    """
    return consts + stubs + fns


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_branches_tab_renders_one_row_per_branch_with_its_own_posture(srv, tmp_path):
    """Three rows through the FULL rebuilt render (ProjectBranches.png): a
    fresh default branch (Active, Default badge, severity chips, trend bars
    whose cell title is secBranchTrendText's own honest sentence), a stale
    clean branch (Inactive by the 7-day rule), and a branch whose every
    attempt failed (a dash and "Analysis failed", not an absence). The
    per-branch-vs-fingerprint scope sentence -- the substance the old
    caption paragraph carried -- now rides the Total-findings column
    header's own title."""
    block = _security_js(srv)
    script = tmp_path / "pj-branches.js"
    script.write_text(_PROJECT_DOM_HARNESS + _branches_tab_deps(block) + """
    const now = Math.floor(Date.now() / 1000);
    secRenderProjectBranches({project: "web", sidebar: {donut: {total: 3}}, tabs: {
      overview: {attempted: true},
      branches: [
      {branch: "develop", last_analysis: now - 3600, last_finished: now - 3600,
       analyses: 2, state: "done", latest_state: "done", analysis_id: 9,
       sha: "dfab1b2c333",
       open: {critical: 1, high: 0, medium: 2, low: 0, info: 0, total: 3},
       trend: [{analysis_id: 1, started: 1, open: 2, state: "done"},
               {analysis_id: 9, started: 2, open: 3, state: "done"}]},
      {branch: "main", last_analysis: now - 40 * 86400, last_finished: now - 40 * 86400,
       analyses: 1, state: "done", latest_state: "done", analysis_id: 3, sha: "abc123999",
       open: {critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0},
       trend: []},
      {branch: "broken", last_analysis: now - 7200, last_finished: 0,
       analyses: 1, state: "", latest_state: "failed", analysis_id: null, sha: "beefbeef1",
       open: null, trend: []},
    ]}});
    const rows = collectAll(_els["sec-pj-branches"], []);
    console.log(JSON.stringify(rows));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    titles = " ".join(r["title"] for r in out)
    classes = " ".join(r["cls"] for r in out)
    assert "develop" in joined and "main" in joined and "broken" in joined
    default_badges = [r for r in out
                      if r["cls"] == "pill profile" and r["text"] == "Default"]
    assert len(default_badges) == 1, \
        f"exactly the declared base wears the Default badge: {len(default_badges)}"
    assert "Active" in joined and "Inactive" in joined, \
        f"the 7-day activity rule must split these rows: {joined}"
    assert "Analysis failed" in joined, \
        "a failed-only branch must say so, not render zeros"
    assert "secbr-sevcount sev-critical" in classes and "secbr-sevcount none" in classes
    assert "dfab1b2" in joined and "dfab1b2c333" not in joined, \
        "the sha renders shortened"
    assert "2 → 3 open" in titles and "rising" in titles, \
        f"secBranchTrendText's sentence must survive as the trend cell's title: {titles}"
    assert "once per branch" in titles, \
        f"the per-branch-vs-fingerprint scope note must ride a title: {titles}"
    assert "3 branch" in joined, f"the footer must count the rows: {joined}"


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
    # The empty-state path returns before any card builder is reached --
    # only the render, its module lets and SEC_NEVER are live on it.
    deps = (_const(block, "SEC_NEVER")
            + "let secBrSearch = '', secBrStatus = '', secBrDays = 0,"
            + " secBrProject = null, secBrPayload = null;\n"
            + _plainfn(block, "secEl") + "\n"
            + _plainfn(block, "secRenderProjectBranches"))
    script = tmp_path / "pj-branches-empty.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    secRenderProjectBranches({project: "web", tabs: {overview: {attempted: false}, branches: []}});
    const neverAttempted = _els["sec-pj-branches"].textContent;
    secRenderProjectBranches({project: "web", tabs: {overview: {attempted: true}, branches: []}});
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
def test_every_project_tab_wears_its_own_title_and_subtitle(srv, tmp_path):
    """Two tabs sharing one title and one subtitle read as the same screen
    twice -- the complaint that forced SEC_TAB_TITLES to cover all five.
    Overview keeps the project's identity (name, profile badge, the
    mockup's own sentence with the name inside it); the other four wear
    their tab's name and sentence. No two tabs may render the same
    title+subtitle pair."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_TAB_TITLES")
            + "let secProjectTab = 'overview';\n"
            + "function projById(_id){ return {name: 'Web', security: {default_profile: 'deep'}}; }\n"
            + "\n".join(_plainfn(block, n) for n in
                        ("secEl", "secIcon", "secRenderProjectTitle")))
    script = tmp_path / "pj-titles.js"
    script.write_text(_PROJECT_DOM_HARNESS + deps + """
    const seen = {};
    ["overview", "runs", "branches", "findings", "reports"].forEach(tab => {
      secProjectTab = tab;
      _els["sec-pj-titleid"] = new FakeElement("div");
      _els["sec-pj-desc"] = new FakeElement("p");
      secRenderProjectTitle();
      seen[tab] = {title: _els["sec-pj-titleid"].textContent,
                   sub: _els["sec-pj-desc"].textContent};
    });
    console.log(JSON.stringify(seen));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "Web" in out["overview"]["title"] and "deep" in out["overview"]["title"]
    assert "Security overview of the Web project" in out["overview"]["sub"]
    assert out["runs"]["title"] == "Runs" and out["runs"]["sub"], \
        f"the Runs tab must have its own title and subtitle: {out['runs']}"
    assert out["branches"]["title"] == "Branches"
    assert out["findings"]["title"] == "Findings"
    assert out["reports"]["title"] == "Reports"
    pairs = [(v["title"], v["sub"]) for v in out.values()]
    assert len(set(pairs)) == 5, \
        f"two tabs render the same title+subtitle pair: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_a_branch_is_active_by_its_last_finished_analysis_alone(srv, tmp_path):
    """The one rule the Status column, the Active-branches KPI and the
    Status filter all read (SEC_BRANCH_ACTIVE_DAYS): at most 7 days since
    the latest FINISHED analysis -- keyed to last_finished, never
    last_analysis, so a branch whose recent attempts all fail cannot count
    as fresher the more it fails."""
    block = _security_js(srv)
    deps = (_const(block, "SEC_BRANCH_ACTIVE_DAYS")
            + _plainfn(block, "secBranchIsActive"))
    script = tmp_path / "br-active.js"
    script.write_text(deps + """
    const now = 1000 * 86400;
    console.log(JSON.stringify({
      fresh: secBranchIsActive({last_finished: now - 7 * 86400 + 10}, now),
      stale: secBranchIsActive({last_finished: now - 7 * 86400 - 10}, now),
      neverFinished: secBranchIsActive(
        {last_finished: 0, last_analysis: now - 60}, now),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["fresh"] is True, "just inside the window must be active"
    assert out["stale"] is False, "just outside the window must not be"
    assert out["neverFinished"] is False, \
        "a fresh FAILED attempt must not make a never-finished branch active"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_reports_tab_renders_one_row_per_analysis_with_four_downloads(srv, tmp_path):
    """One row per analysis regardless of state -- but the downloads
    themselves only on a FINISHED one (ProjectReports.png's own rule,
    replacing the everything-gets-buttons this tab used to have: a report
    generated over a run that fell over, or has not finished, carries a
    partial checklist that READS as a complete one; the Runs tab's own
    single-analysis downloads still cover any state). A failed row says
    "No report generated", a running one "Not finished yet". The SBOM
    caveat -- the branch's CURRENT document, not a snapshot -- rides every
    SBOM control's own tooltip now, and the severity-floor note survives
    below the table."""
    block = _security_js(srv)
    consts = (_const(block, "SEC_REPORT_FORMATS") + _const(block, "SEC_REPORT_COLS")
              + _const(block, "SBOM_CAVEAT") + _const(block, "GENERATED_NOTE"))
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secRpCap", "secRpFinished",
                      "secReportRow",
                      "secReportsTable", "secRenderProjectReports"))
    script = tmp_path / "pj-reports.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secRpSortDir = "desc", secRpPayload = null;
    function secDownloadReport(){}
    function secShowAnalysis(_id, _pin){}
    function secSwitchProjectTab(_t){}
    function tableFooter(o){
      const f = new FakeElement("footer");
      f.textContent = "Showing " + o.shown.from + " to " + o.shown.to
        + " of " + o.total + " " + o.noun;
      return f;
    }
    """ + consts + deps + """
    secRenderProjectReports({tabs: {reports: [
      {analysis_id: 7, branch: "main", started: 1700000000, state: "done", profile: "deep"},
      {analysis_id: 8, branch: "develop", started: 1700000100, state: "running", profile: "deep"},
      {analysis_id: 9, branch: "develop", started: 1700000200, state: "failed", profile: "standard"},
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
    titles = " ".join(r["title"] for r in out["rows"])
    assert "#7" in joined and "#8" in joined and "#9" in joined, \
        f"an analysis id is missing: {joined}"
    assert "main" in joined and "develop" in joined
    assert "Deep (Running)" in joined and "Standard (Failed)" in joined, \
        f"the profile cell must fold the unfinished state in: {joined}"
    # The finished row alone carries downloads -- its four format chips are
    # the only download controls (no Actions column: the chips already ARE
    # the downloads); every row keeps its own run chip.
    assert out["buttons"] == 1 * 3 + 4, \
        f"only the finished row may offer downloads: {out['buttons']}"
    assert "No report generated" in joined, \
        f"a failed analysis must say why there is nothing to download: {joined}"
    assert "Not finished yet" in joined, \
        f"a running analysis must say why there is nothing to download: {joined}"
    assert "CURRENT document" in titles, \
        f"the SBOM caveat must ride the SBOM controls' own tooltips: {titles}"
    assert "every recorded finding" in joined, f"the severity-floor note is missing: {joined}"
    assert "3 report" in joined, f"the footer must count the rows: {joined}"


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
    // The title row now follows the tab (SEC_TAB_TITLES, project-screen.js)
    // -- stubbed like renderFindings below: these tests are about pane and
    // rail visibility, never about what the title row paints.
    function secRenderProjectTitle(){}
    // secSwitchProjectTab now also repaints the sidebar through this cache
    // (secRenderProjectSidebar, not extracted here) -- null, the real
    // module's own value before the first project-data fetch answers, is
    // what keeps that call a no-op so this test stays about pane
    // visibility alone.
    let secProjectCache = null;
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
    "Open the run" points at.

    Read from the app bundle rather than the page's own inline script since
    Phase 2 Task 7: the row this guard is about moved into ui/app/runs.js
    along with the rest of the Runs table."""
    block = _app_js(srv)
    assert 'String(r.id||"").startsWith("security-")' in block
    assert "A security analysis is never resumed" in block
    assert "the Security area owns its lifecycle" in block


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
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES")
             + _const(block, "ICON_HYGIENE")
             + _const(block, "SEC_CATEGORY_LABEL") + _const(block, "SEC_CATEGORY_ICON"))
    arrows = (re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secCategoryMeta", "secFindRow",
                      "secFindDecisionControls", "secFindActionsCell"))
    script = tmp_path / "find-row.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    const fs = {project: "web"};
    """ + consts + arrows + deps + """
    const row = secFindRow(fs, {title: "<img src=x onerror=alert(1)>", severity: "high",
      state: "new", category: "sast", branch: "feature/<b>bold</b>", first_seen: 1700000000,
      occurrences: [{file: "a.py", line: 1}, {file: "b.py", line: 2}], fingerprint: "a".repeat(64)});
    // Decision buttons alone (role=menuitem, inside the kebab's own
    // menu-pop) -- Phase 4 gave every row an unconditional eye/view button
    // too (AllFindings.png's own Actions column), so a bare COUNT of every
    // <button> anywhere in the row no longer isolates the decision actions
    // this test is actually about (see secFindDecisionControls's own
    // comment for why it returns exactly this menu-pop and nothing else).
    function countButtons(n, c){
      (n.childNodes || []).forEach(x => {
        if(x.tagName === "button" && x._attrs && x._attrs.role === "menuitem") c.n++;
        countButtons(x, c);
      });
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
             + _const(block, "SEV_ORDER") + _const(block, "SEC_STATES")
             + _const(block, "ICON_HYGIENE")
             + _const(block, "SEC_CATEGORY_LABEL") + _const(block, "SEC_CATEGORY_ICON"))
    arrows = (re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secCategoryMeta", "secFindRow",
                      "secFindDecisionControls", "secFindActionsCell"))
    script = tmp_path / "find-row-fixed.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    function fmtWhen(t){ return "w" + String(t); }
    const fs = {project: "web"};
    """ + consts + arrows + deps + """
    const row = secFindRow(fs, {title: "t", severity: "low", state: "fixed", category: "sast",
      branch: "main", first_seen: 1, occurrences: [], fingerprint: "a".repeat(64)});
    // See the sibling test above (non-fixed) for why this counts only
    // role=menuitem buttons -- the row's own unconditional eye/view button
    // is not a decision control and must not affect either count.
    function countButtons(n, c){
      (n.childNodes || []).forEach(x => {
        if(x.tagName === "button" && x._attrs && x._attrs.role === "menuitem") c.n++;
        countButtons(x, c);
      });
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
    consts = (_const(block, "SEV_ORDER") + _const(block, "ROW_PILL_TITLE")
              + _const(block, "SEV_KPI_ICON") + _const(block, "SEV_KPI_TONE"))
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "_secCap", "secFindHiddenByFloor", "secFindStrip"))
    script = tmp_path / "find-strip.js"
    script.write_text(_INDEX_DOM_HARNESS + _KPI_CARD_STUB + """
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
    # Total and Unique are two of the seven KPI CARDS now
    # (ProjectFindings.png), each still carrying its marker class -- found
    # by that marker rather than by a literal wording, each one's own
    # aggregated text still carrying both its label and its number
    # together, which is what "distinctly labelled" means.
    total_stat = next(r for r in out if "secfind-stat total" in r["cls"])
    unique_stat = next(r for r in out if "secfind-stat unique" in r["cls"])
    assert "Total findings" in total_stat["text"] and "10" in total_stat["text"], \
        f"the Total stat must carry both its label and its number: {total_stat}"
    assert "Unique issues" in unique_stat["text"] and "8" in unique_stat["text"], \
        f"the Unique stat must carry both its label and its number: {unique_stat}"
    assert total_stat["text"] != unique_stat["text"], \
        "total and unique must not collapse into the same number"
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
             + _const(block, "FIND_SORT_COLUMNS") + _const(block, "ICON_HYGIENE")
             + _const(block, "SEC_CATEGORY_LABEL") + _const(block, "SEC_CATEGORY_ICON"))
    arrows = (re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
             + re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secCategoryMeta", "secFindRow",
                      "secFindDecisionControls", "secFindActionsCell", "secFindTableSection", "secVisible"))
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
             + _const(block, "FIND_SORT_COLUMNS") + _const(block, "ICON_HYGIENE")
             + _const(block, "SEC_CATEGORY_LABEL") + _const(block, "SEC_CATEGORY_ICON"))
    arrows = (re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
             + re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    consts = (consts + _const(block, "ROW_PILL_TITLE")
              + _const(block, "SEV_KPI_ICON") + _const(block, "SEV_KPI_TONE"))
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "_secCap", "secCategoryMeta",
                      "secFindHiddenByFloor", "secFindStrip", "secFindRow", "secFindDecisionControls", "secFindActionsCell",
                      "secFindTableSection", "secVisible"))
    script = tmp_path / "find-fixed-floor.js"
    script.write_text(_INDEX_DOM_HARNESS + _KPI_CARD_STUB + """
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
             + _const(block, "FIND_SORT_COLUMNS") + _const(block, "ICON_HYGIENE")
             + _const(block, "SEC_CATEGORY_LABEL") + _const(block, "SEC_CATEGORY_ICON"))
    arrows = (re.search(r"const secSevRank = .*?\};", block, re.S).group(0) + "\n"
             + re.search(r"const secSevKey = .*?;", block).group(0) + "\n"
             + re.search(r"const secStateKey = .*?;", block).group(0) + "\n")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secCategoryMeta", "secFindRow",
                      "secFindDecisionControls", "secFindActionsCell", "secFindTableSection", "secVisible"))
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
    // table-card -> table-scroll -> table -> thead -> tr (Phase 4 Task 6 put
    // the table inside a table-card, one level deeper than the bare
    // .tablewrap this used to walk into directly).
    const headerRow = section.childNodes[0].childNodes[0].childNodes[0].childNodes[0];
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
    """secFindPager (Phase 4 Task 6) now builds the bridged tableFooter() --
    AllFindings.png's own "Showing X to Y of N findings" + pager, replacing
    the old bare "Page X / Y · N rows" line that sat outside the table's own
    box -- and wires its own Prev/Next by POSITION (tableFooter's own
    non-numbered output is always an info span, then a nav holding exactly
    Prev then Next), not by id: this module mounts into two hosts at once
    (see this file's own header comment), and a fixed id would collide the
    moment both mounts' footers rendered together. Driving the REAL
    tableFooter (ui/app/chrome.js) here, not a stub, so a regression in
    EITHER half -- secFindPager's own from/to and page/pages math, or
    tableFooter's own disabled-state and pluralisation rules -- fails this,
    the same `el`+`tableFooter` combination
    test_table_footer_takes_an_irregular_plural_and_a_numbered_pager already
    drives for real above."""
    block = _security_js(srv)
    chrome_deps = _plainfn(_app_js(srv), "el") + "\n" + _plainfn(_app_js(srv), "tableFooter")
    consts = _const(block, "FIND_PER_PAGE") + _const(block, "FIND_PER_PAGE_OPTIONS")
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "secFindTriggerLabel", "secFindPositionPop",
                      "secFindPerPageField", "secFindPager"))
    script = tmp_path / "find-pager.js"
    script.write_text(_INDEX_DOM_HARNESS + """
    let refreshedTo = null;
    function secFindRefresh(_fs){ refreshedTo = _fs.page; }
    const fs = {page: 1, perPage: 25};
    """ + chrome_deps + "\n" + consts + deps + """
    // wrap's own three children now (Phase 4: the per-page picker sits
    // between the info sentence and the pager nav) -- nav is `undefined`
    // at exactly one page, tableFooter's own numbered-mode rule (see its
    // comment, ui/app/chrome.js) that this pager inherits unchanged.
    function btns(p){
      const nav = p.childNodes[2];
      return {info: p.childNodes[0].textContent, nav,
              prevDisabled: nav ? nav.childNodes[0].disabled : null,
              nextDisabled: nav ? nav.childNodes[nav.childNodes.length - 1].disabled : null};
    }
    const first = btns(secFindPager(fs, {total: 47, per_page: 25, page: 1}));
    const last = btns(secFindPager(fs, {total: 47, per_page: 25, page: 2}));
    const empty = btns(secFindPager(fs, {total: 0, per_page: 25, page: 1}));

    fs.page = 1;
    first.nav.childNodes[first.nav.childNodes.length - 1].onclick();   // Next, from page 1 of 2
    const nextClickedTo = refreshedTo;
    fs.page = 2;
    last.nav.childNodes[0].onclick();       // Prev, from page 2 of 2
    const prevClickedTo = refreshedTo;
    // A numbered pager's own page-N button, not just Prev/Next -- clicking
    // "1" while on page 2 must jump straight there.
    fs.page = 2;
    const pageOneBtn = Array.from(last.nav.childNodes).find(c => c.dataset && c.dataset.page === "1");
    pageOneBtn.onclick();
    const pageBtnClickedTo = refreshedTo;

    console.log(JSON.stringify({
      first: {info: first.info, prevDisabled: first.prevDisabled, nextDisabled: first.nextDisabled},
      last: {info: last.info, prevDisabled: last.prevDisabled, nextDisabled: last.nextDisabled},
      empty: {info: empty.info, noNav: !empty.nav},
      nextClickedTo, prevClickedTo, pageBtnClickedTo,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["first"]["prevDisabled"] is True and out["first"]["nextDisabled"] is False
    assert out["first"]["info"] == "Showing 1 to 25 of 47 findings", out["first"]["info"]
    assert out["last"]["prevDisabled"] is False and out["last"]["nextDisabled"] is True
    assert out["last"]["info"] == "Showing 26 to 47 of 47 findings", out["last"]["info"]
    # At one page (0 total, per_page 25) the numbered pager renders no nav
    # at all -- tableFooter's own established rule for "nothing to page
    # through" (see test_table_footer_takes_an_irregular_plural_and_a_
    # numbered_pager's own "onePageNumbered" case), inherited here rather
    # than a disabled Prev/Next with no pages behind either button.
    assert out["empty"]["noNav"], "one page must render no pager nav at all"
    assert out["empty"]["info"] == "Showing 0 to 0 of 0 findings", out["empty"]["info"]
    assert out["nextClickedTo"] == 2, "Next must advance fs.page"
    assert out["prevClickedTo"] == 1, "Prev must step fs.page back"
    assert out["pageBtnClickedTo"] == 1, "clicking a numbered page button must jump straight to it"
    assert out["empty"]["info"] == "Showing 0 to 0 of 0 findings", out["empty"]["info"]
    assert out["nextClickedTo"] == 2, "Next must advance fs.page"
    assert out["prevClickedTo"] == 1, "Prev must step fs.page back"


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
    // The title row now follows the tab (SEC_TAB_TITLES, project-screen.js)
    // -- stubbed like renderFindings below: these tests are about pane and
    // rail visibility, never about what the title row paints.
    function secRenderProjectTitle(){}
    let secProjectCache = null;
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


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_project_sidebar_hides_for_findings_and_overview(srv, tmp_path):
    """AllFindings.png draws the findings browser full-width, with no
    donut/categories/recent-activity rail beside it -- that rail is a
    summary beside SOME tabs, and repeating "2 critical / 8 high / ..."
    beside a table that already lists every one of those rows individually
    would say the same numbers twice a few inches apart. ProjectOverview.png
    then drew the Overview full-width too, with its OWN right column inside
    the pane -- and that column's donut is one-branch scoped where the
    rail's spans every analysed branch, so showing both would be two donuts
    with two different, equally true totals an inch apart (this used to be
    "hides for Findings alone"; the Overview rebuild is what widened it).
    Runs/Branches/Reports keep the rail exactly as before."""
    block = _security_js(srv)
    deps = _plainfn(block, "secRenderTabs") + "\n" + _plainfn(block, "secSwitchProjectTab")
    script = tmp_path / "pj-side.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secProjectTab = "overview";
    // The title row now follows the tab (SEC_TAB_TITLES, project-screen.js)
    // -- stubbed like renderFindings below: these tests are about pane and
    // rail visibility, never about what the title row paints.
    function secRenderProjectTitle(){}
    let secProjectCache = null;
    function renderFindings(_host, _project){}
    """ + deps + """
    function sideHidden(){ return _els["sec-pj-side"].hidden; }
    secRenderTabs();
    const onOverview = sideHidden();
    secSwitchProjectTab("runs");
    const onRuns = sideHidden();
    secSwitchProjectTab("findings");
    const onFindings = sideHidden();
    secSwitchProjectTab("reports");
    const onReports = sideHidden();
    secSwitchProjectTab("overview");
    const backToOverview = sideHidden();
    console.log(JSON.stringify({onOverview, onRuns, onFindings, onReports, backToOverview}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out == {"onOverview": True, "onRuns": False, "onFindings": True,
                   "onReports": False, "backToOverview": True}, out


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
                    "secFindTriggerLabel", "secFindPositionPop", "secFindSavedFilters",
                    "secFindHeader", "secFindPaint")


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
    deps = _activity_deps(block, "secEl", "secActTimeCell", "secActWhen", "secActRow",
                          "secActRelatedCell")
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
    disabled the moment it does not, and "Prev" is disabled on page 1.
    secActPager (Phase 4 Task 6) now builds a `.table-foot`-shaped footer,
    the same LOOK chrome.js's own tableFooter gives every other table-card
    in this app, hand-built rather than calling that bridged function
    directly since its own "Showing X to Y of N" sentence needs a real
    total this endpoint deliberately does not carry -- the mechanism this
    test pins (Prev/Next disabled state, inferred from a full page) is
    unchanged; only the child it lives under one level deeper now."""
    block = _security_js(srv)
    deps = _activity_deps(block, "secEl", "secIcon", "secActPager")
    script = tmp_path / "act-pager.js"
    script.write_text(_PROJECT_DOM_HARNESS + """
    let secActState = {page: 1};
    """ + deps + """
    function pagerState(data){
      // secActPager's own, fixed shape: an info span, then a nav div
      // holding exactly Prev then Next -- indexed rather than filtered by
      // tagName, since FakeElement (unlike a real DOM) does not uppercase
      // what was passed to document.createElement.
      const p = secActPager(data);
      const nav = p.childNodes[1];
      return {prevDisabled: nav.childNodes[0].disabled, nextDisabled: nav.childNodes[1].disabled};
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
    deps = _index_screen_deps(block, "el", "secEl", "secIcon", "kpiCard",
                              "secCappedScopeNote", "secIndexCards")
    script = tmp_path / "kpi-fellback.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 3, analyses: 4, critical: 2, high: 1,
      capped_projects: 0, fell_back_projects: 1, success_rate: 1.0});
    const clean = secIndexCards({projects: 3, analyses: 4, critical: 2, high: 1,
      capped_projects: 0, fell_back_projects: 0, success_rate: 1.0});
    // secidx-note was a visible line before Phase 4 Task 1's kpiCard-based
    // cards moved this caveat into the card's own `.title` tooltip (see the
    // comment above secIndexCards) -- kpi-card is the outer card's class,
    // and `.title` is where the same sentence lives now.
    console.log(JSON.stringify({
      notes: collectAll(cards, []).filter(r => r.cls.indexOf("kpi-card") === 0 && r.title)
                                  .map(r => r.title),
      cleanNotes: collectAll(clean, []).filter(r => r.cls.indexOf("kpi-card") === 0 && r.title)
                                       .map(r => r.title),
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
    deps = _index_screen_deps(block, "el", "secEl", "secIcon", "kpiCard",
                              "secCappedScopeNote", "secIndexCards")
    script = tmp_path / "kpi-scope.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const cards = secIndexCards({projects: 2, analyses: 5, critical: 0, high: 0,
      capped_projects: 0, fell_back_projects: 0, success_rate: 0.8});
    // Phase 4 Task 1 moved this card's own scope sentence from its `sub`
    // (now the mockup's fixed, short "analyses completed") into its `.title`
    // tooltip -- collecting title alongside text keeps this reachable
    // wherever kpiCard put it, without caring which of the two it landed in.
    console.log(JSON.stringify(collectAll(cards, []).map(r => r.text + " " + r.title)));
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
                              "secDonutArc", "secIndexDonutSvg", "secIndexDonutLegend",
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
    deps = _index_screen_deps(block, "secDonutArc", "secIndexDonutSvg")
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
    script = tmp_path / "pj-branches-capped.js"
    script.write_text(_PROJECT_DOM_HARNESS + _branches_tab_deps(block) + """
    secRenderProjectBranches({project: "web", sidebar: {}, tabs: {
      overview: {attempted: true}, branches: [
      {branch: "main", last_analysis: 1700000000, last_finished: 1700000000,
       analyses: 2, state: "capped", latest_state: "capped", analysis_id: 2,
       sha: "aaaa1111", open: {critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0},
       trend: [{open: 0, state: "capped"}]},
      {branch: "develop", last_analysis: 1700000100, last_finished: 1700000100,
       analyses: 1, state: "done", latest_state: "done", analysis_id: 3,
       sha: "bbbb2222", open: {critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1},
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
              + _const(block, "ROW_PILL_TITLE")
              + _const(block, "SEV_KPI_ICON") + _const(block, "SEV_KPI_TONE"))
    # `secVisible` is deliberately absent: every payload below carries an
    # empty `rows`, and secFindTableSection answers that before it ever
    # reaches the floor -- which is the case under test.
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "_secCap", "secFindHiddenByFloor", "secFindStrip",
                      "secFindTableSection"))
    script = tmp_path / "find-never.js"
    script.write_text(_INDEX_DOM_HARNESS + _KPI_CARD_STUB + """
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
              + _const(block, "ROW_PILL_TITLE")
              + _const(block, "SEV_KPI_ICON") + _const(block, "SEV_KPI_TONE"))
    deps = "\n".join(_plainfn(block, n) for n in
                     ("secEl", "secIcon", "_secCap", "secFindHiddenByFloor", "secFindStrip"))
    script = tmp_path / "find-capped.js"
    script.write_text(_INDEX_DOM_HARNESS + _KPI_CARD_STUB + """
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
                    + _const(block, "ROW_PILL_TITLE")
                    + _const(block, "SEV_KPI_ICON") + _const(block, "SEV_KPI_TONE"))
    strip_deps = "\n".join(_plainfn(block, n) for n in
                           ("secEl", "secIcon", "_secCap", "secFindHiddenByFloor", "secFindStrip"))
    donut_consts = _const(block, "SEV_ORDER5") + _const(block, "DONUT_PILL_TITLE")
    donut_deps = _plainfn(block, "secIndexDonutLegend")
    script = tmp_path / "pill-scopes.js"
    script.write_text(_INDEX_DOM_HARNESS + _KPI_CARD_STUB + """
    function secMinSeverity(_p){ return "low"; }
    const fs = {project: "web", filters: {}};
    """ + strip_consts + strip_deps + donut_consts + donut_deps + """
    const sev = {critical: 2, high: 0, medium: 0, low: 0, info: 0};
    const strip = collectAll(secFindStrip(fs, {rows: [], total: 2, unique: 1,
      by_severity: sev, fixed_by_severity: {critical:0,high:0,medium:0,low:0,info:0},
      page: 1, per_page: 25, attempted: true, analysed: true}), []);
    const legend = collectAll(secIndexDonutLegend({critical: 1}), []);
    // The strip's own Critical stat (ProjectFindings.png: a KPI card
    // wearing the sev-crit tone class, not a ".sevpill" chip -- its NUMBER
    // and its TITLE are what this test is actually about, not the exact
    // element shape carrying them).
    const stripStat = strip.filter(r => r.cls.includes("sev-crit"))[0] || {};
    const legendPill = legend.filter(r => r.cls === "sevpill critical")[0] || {};
    console.log(JSON.stringify({strip: stripStat, legend: legendPill}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert "2" in out["strip"].get("text", ""), out["strip"]
    assert out["legend"].get("text") == "1 critical", out["legend"]
    assert "Rows" in out["strip"].get("title", ""), \
        f"the strip's severity pill does not say it counts rows: {out['strip']}"
    assert "counts twice" in out["strip"].get("title", ""), out["strip"]
    assert "fingerprint" in out["legend"].get("title", "").lower(), \
        f"the donut's severity pill does not say it counts problems: {out['legend']}"
    assert "counts once" in out["legend"].get("title", ""), out["legend"]
    assert out["strip"]["title"] != out["legend"]["title"], \
        "two numbers answering different questions still carry the same explanation"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_findings_overview_legend_states_each_severitys_share_of_the_total(srv, tmp_path):
    """Phase 4 Task 5. The mockup's own legend row -- a coloured dot, the
    severity's NAME alone ("Critical"), and a right-aligned "count (pct%)"
    ("45 (23.8%)") -- its own element, not a `.sevpill` wearing a
    percentage the way Task 4 first built it (see secIndexDonutLegend's own
    comment for why that shape was replaced). Opt-in (`{showPercent: true}`,
    the index screen's own call) so the project screen's sidebar donut --
    the SAME function's other caller, checked against no mockup of its own
    -- keeps rendering its plain `.sevpill` legend exactly as it always has;
    the pinned pill-scope test
    (test_the_two_kinds_of_severity_pill_each_say_what_they_count) already
    proves that one-argument call stays untouched. The percentage itself is
    the mockup's own arithmetic: each severity's share of the TOTAL (45 of
    189 is 23.8%), not a share that has to sum to 100 across the legend --
    45+90+54 do add to 189 here (a real, internally consistent payload
    always sums this way, since the total is computed FROM the severities),
    but the mockup's own three printed numbers (45+127+78=250 against a
    printed total of 189) do not, which is the mockup's own inconsistency,
    not a formula to reproduce with equally inconsistent test data."""
    block = _security_js(srv)
    consts = _const(block, "SEV_ORDER5") + _const(block, "DONUT_PILL_TITLE")
    deps = _index_screen_deps(block, "secEl", "secIndexDonutLegend")
    script = tmp_path / "findings-legend-pct.js"
    script.write_text(_INDEX_DOM_HARNESS + consts + deps + """
    const donut = {critical: 45, high: 90, medium: 54, low: 0, info: 0};
    const withPct = collectAll(secIndexDonutLegend(donut, {showPercent: true}), []);
    const without = collectAll(secIndexDonutLegend(donut), []);
    console.log(JSON.stringify({withPct, without}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)

    def by_class(rows, cls):
        return {r["text"] for r in rows if r["cls"] == cls}

    names = by_class(out["withPct"], "secidx-legendname")
    counts = by_class(out["withPct"], "secidx-legendcount")
    assert names == {"Critical", "High", "Medium"}, names
    assert counts == {"45 (23.8%)", "90 (47.6%)", "54 (28.6%)"}, \
        f"the legend's own count-and-percentage pairs are wrong: {counts}"
    # A legend row, not a sevpill: this branch must never produce the OLD
    # "45 critical" pill Task 4 built. `.startswith("sevpill ")`, with the
    # trailing space, so the WRAPPER's own plural "sevpills secidx-
    # findlegend" class (which also starts with the substring "sevpill")
    # does not false-positive this check.
    per_severity_pill = {"sevpill " + s for s in
                         ("critical", "high", "medium", "low", "info")}
    assert not (per_severity_pill & {r["cls"] for r in out["withPct"]}), \
        f"a sevpill rendered in the percentage-mode legend: {out['withPct']}"
    # Opt-out (no second argument, the project screen's own call shape)
    # renders the plain sevpill legend, no dot/name/count row at all -- the
    # identical DOM the function always produced, not a half-migrated shape.
    assert not by_class(out["without"], "secidx-legendcount"), \
        "a count-and-percentage row rendered without opting in"
    assert {r["cls"] for r in out["without"]} & {
        "sevpill critical", "sevpill high", "sevpill medium"}, \
        "the opt-out call must still render its own plain sevpills"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_findings_legend_percentage_never_divides_by_a_zero_denominator(srv, tmp_path):
    """The brief's own dash rule: a zero denominator renders no percentage,
    never "0.0%" and never a NaN/Infinity leaking onto the page. Already
    structurally true (a zero total never leaves the early "nothing open"
    branch to reach the division at all) -- this pins that guarantee so a
    later refactor moving the percentage above that branch fails loudly."""
    block = _security_js(srv)
    consts = _const(block, "SEV_ORDER5") + _const(block, "DONUT_PILL_TITLE")
    deps = _index_screen_deps(block, "secEl", "secIndexDonutLegend")
    script = tmp_path / "findings-legend-zero.js"
    script.write_text(_INDEX_DOM_HARNESS + consts + deps + """
    const empty = {critical: 0, high: 0, medium: 0, low: 0, info: 0};
    console.log(JSON.stringify(
      collectAll(secIndexDonutLegend(empty, {showPercent: true}), [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "nothing open" in joined, f"the clean pill did not render: {joined}"
    assert "%" not in joined, f"a percentage rendered over a zero denominator: {joined}"
    assert "NaN" not in joined and "Infinity" not in joined, joined
    # The clean pill keeps its ordinary green chip look -- .secidx-findlegend's
    # own CSS override excludes `.sevpill.clean` by name specifically so this
    # stays true (see ui/css/pages.css's own comment beside that rule).
    clean = [r for r in out if r["cls"] == "sevpill clean"]
    assert clean, f"no clean pill in the percentage-mode legend: {out}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_recent_analyses_findings_cell_shows_three_severity_chips_or_an_honest_dash(
        srv, tmp_path):
    """Phase 4 Task 5. `queries.recent_analyses` now tallies `severities`
    (critical/high/medium) per row from the SAME `checklist()` call its own
    `open` count already made -- so this cell draws the mockup's own three
    fixed chips, the identical shape (and "always three, even zero" rule)
    `secIndexFindingsChips` already draws on the fleet table above it --
    see test_findings_chips_show_three_severities_and_the_postures_own_total.
    `null` (a running/failed analysis has not finished recording findings
    yet) still reads as an honest dash, never a fabricated zero -- the one
    honesty case carried over from this cell's pre-Task-5 shape."""
    block = _security_js(srv)
    deps = (_const(block, "FIND_SEVS")
            + _index_screen_deps(block, "secEl", "secIndexRecentFindingsChips"))
    script = tmp_path / "recent-findings-chips.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify({
      notYet: collectAll(secIndexRecentFindingsChips(null), []),
      clean: collectAll(secIndexRecentFindingsChips(
        {critical: 0, high: 0, medium: 0}), []),
      some: collectAll(secIndexRecentFindingsChips(
        {critical: 1, high: 2, medium: 5}), []),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert any(r["text"] == "—" for r in out["notYet"]), \
        f"a not-yet-recorded analysis did not render an honest dash: {out['notYet']}"
    assert not any(r["cls"].startswith("sevpill") for r in out["notYet"]), \
        "the dash case must never also render a chip"

    clean_chips = [r["text"] for r in out["clean"] if r["cls"].startswith("sevpill ")]
    assert clean_chips == ["0", "0", "0"], \
        f"zero findings must still draw three fixed chips, same as the fleet table: {clean_chips}"

    some_chips = [r["text"] for r in out["some"] if r["cls"].startswith("sevpill ")]
    assert some_chips == ["1", "2", "5"], some_chips


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_recent_analyses_status_pill_uses_its_own_tone_family(srv, tmp_path):
    """Phase 4 Task 4. RUN_STATES' own four values (project-screen.js), each
    Title-Cased and given a NEW `.pill` modifier -- never `.pill.on`/
    `.pill.off`, which stay reserved for a project's own active/launchd-
    fault reading (see that class's own comment, ui/css/components.css).
    An unrecognised state reads as a loud fault, not a silent "Running"."""
    block = _security_js(srv)
    consts = _const(block, "SEC_RUN_STATUS_LABEL")
    deps = _index_screen_deps(block, "secEl", "secIndexRunStatusPill")
    script = tmp_path / "recent-status-pill.js"
    script.write_text(_INDEX_DOM_HARNESS + consts + deps + """
    console.log(JSON.stringify(["running", "done", "capped", "failed", "corrupted"]
      .map(s => collectAll(secIndexRunStatusPill(s), [])[0])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    by_state = dict(zip(["running", "done", "capped", "failed", "corrupted"], out))
    assert by_state["running"] == {"cls": "pill running", "title": "", "text": "Running"}
    assert by_state["done"] == {"cls": "pill done", "title": "", "text": "Completed"}
    assert by_state["capped"] == {"cls": "pill capped", "title": "", "text": "Capped"}
    assert by_state["failed"] == {"cls": "pill failed", "title": "", "text": "Failed"}
    # Corrupted data (a value RUN_STATES never actually emits) reads as a
    # fault -- the loud branch, not a quiet, misleading "Running".
    assert by_state["corrupted"]["cls"] == "pill failed", by_state["corrupted"]
    assert by_state["corrupted"]["text"] == "Unknown", by_state["corrupted"]
    for state, row in by_state.items():
        assert row["cls"] not in ("pill on", "pill off"), \
            f"{state} reused the project active/launchd-fault pill classes: {row}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_view_full_report_is_an_honest_door(srv, tmp_path):
    """Phase 4 Task 4. There is no report spanning every project (a report
    is generated from one analysis's own checklist), so "View full report"
    opens the most recent analysis's own project on its Reports tab -- and
    is disabled, honestly, when there is no analysis yet to pick one from,
    the same door-with-nothing-behind-it reasoning kpiCard's own `door` flag
    documents (ui/app/chrome.js)."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secIcon", "secViewFullReportButton")
    script = tmp_path / "view-full-report.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    function secOpenProject(){} function secSwitchProjectTab(){}
    const closedDoor = secViewFullReportButton([]);
    const openDoor = secViewFullReportButton([{project: "minerva", id: 12}]);
    console.log(JSON.stringify({
      closed: {disabled: !!closedDoor.disabled, title: closedDoor.title,
               text: closedDoor.textContent},
      open: {disabled: !!openDoor.disabled, title: openDoor.title,
             text: openDoor.textContent},
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["closed"]["disabled"], f"nothing to report but the door is open: {out['closed']}"
    assert "nothing to report" in out["closed"]["title"].lower(), out["closed"]
    assert not out["open"]["disabled"], f"an analysis exists but the door stayed shut: {out['open']}"
    assert "minerva" in out["open"]["title"], \
        f"the door does not say which project it opens: {out['open']}"
    assert out["closed"]["text"] == out["open"]["text"] == "View full report", \
        "the label itself changes between the open and closed door"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_recent_analyses_card_head_names_todays_navigation_and_the_empty_state(
        srv, tmp_path):
    """Phase 4 Task 4. The card's own head (title, sub, "View all analyses")
    and its honest empty state -- exercised through the empty branch only,
    which returns before ever touching the pagination state
    (secRecentPage/SEC_RECENT_PAGE_SIZE) a standalone script has not stood
    up, the same reason the pinned tests above never drive
    secIndexProjectsTable's OWN footer branch without building one first."""
    block = _security_js(srv)
    deps = _index_screen_deps(block, "secEl", "secIcon", "secIndexCardHead",
                              "secViewAllAnalysesButton", "secIndexRecentCard")
    script = tmp_path / "recent-card-empty.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    function secOpenActivity(){} function secActSwitchTab(){}
    console.log(JSON.stringify(collectAll(secIndexRecentCard({rows: [], total: 0}), [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    joined = " ".join(r["text"] for r in out)
    assert "Recent analyses" in joined
    assert "Latest security analyses across all projects" in joined
    assert "View all analyses" in joined
    assert "No analyses have run yet." in joined


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
    # Said on the index screen (its KPI cards, posture pills and donut are
    # all unfloored) and on the project screen's rail, whose one visible
    # caption became per-variant tooltips ON the cards that carry the
    # numbers: secSidebarScopeNote rides the leftover tabs' donut block,
    # secProjectRunSidebar's own donut title carries the Runs variant, and
    # secAllBranchDonutCard -- the card the Branches AND Reports rails
    # both mount -- carries theirs.
    for fn in ("secRenderIndex", "secSidebarScopeNote", "secProjectRunSidebar",
               "secAllBranchDonutCard"):
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
    "secidx-categories",
    # secFindStrip's Total/Unique KPI cards (findings-screen.js): pure
    # MARKER classes appended to two .kpi-card elements whose whole layout
    # and colour come from the shared component -- the hooks the pinned
    # total-vs-unique test finds them by, styled by nothing on purpose.
    "secfind-stat",
    "total",
    "unique",
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


# ---- Phase 3 Task 1: render()'s dialog contract. Two of the page's dialogs
# (editor, projmodal) are the obvious ones, but profmodal, confirm, secreason
# and fsmodal hold exactly the same kind of thing: a form a person may be
# mid-typing into. Every one of them is mounted once in the page's static
# markup, filled by its own "open" function, and never touched again until it
# closes -- but until this test existed, that was true only because nothing
# had ever wired render() into one of them, not because anything stopped it.
# Phase 3 is about to restyle these dialogs; this is what turns the accident
# into a rule that moving code cannot break silently.

FORM_DIALOGS = ("editor", "projmodal", "profmodal", "confirm", "secreason", "fsmodal",
                # seclaunch (Runs tab parity pass 2): the repo/branch/profile
                # launcher, moved from an always-open strip on the Runs tab
                # into its own dialog -- the free-text branch field is
                # exactly the mid-typing state this tuple exists to protect.
                "seclaunch")

# wtmodal and logmodal are deliberately NOT in the list above. Both are
# read-only surfaces that live-update BY DESIGN: logmodal tails a running
# agent's own output, and renderRetained() -- called from render() on every
# poll -- repaints wtmodal's worktrees table on purpose (see renderRetained's
# own comment on wthead/wt-blurb/wtrows). This contract protects state a
# person is mid-typing, not "a view that never changes without a click" --
# holding those two to the same rule this test enforces would make it red
# against exactly the behaviour they exist for. If you are looking at this
# list wondering whether to "fix" the omission: don't -- read the paragraph
# above first.

# The functions render() reaches, at DIRECT-CALL depth only -- not the
# transitive closure. renderJobsArea() also calls CCApp.renderJobsPage(),
# which this test does not descend into; renderProjectsPage() calls
# mountProjectsToolbar() and renderProjectsTable(), likewise unscanned. That
# is a stated limit, not an oversight: this test catches render() (or one of
# the names below) reaching directly into a form dialog. A violation two
# calls deeper -- say, renderProjectsTable() itself starting to read
# $("ed-id") -- would not be caught here. A full call-graph walk would catch
# that too, but the list below is short, hand-countable, and has been stable
# since the page was split into bin/dashboard.html + ui/app/ + ui/security/;
# widening the scan was judged not worth the complexity it would add for the
# violation shape it would additionally catch.
_DIALOG_POLL_PAGE_FNS = ("render", "renderRetained", "renderJobsArea", "paintNav", "paintUser")
_DIALOG_POLL_APP_FNS = ("renderProjectsPage", "renderRunsPage", "renderOverviewHead",
                        # render() calls this one directly too -- it builds the
                        # Overview's worktrees summary card every poll.
                        "worktreesCard")


_LIVE_DIALOGS = ("wtmodal", "logmodal")


def test_every_dialog_is_either_guarded_or_deliberately_live(srv):
    """FORM_DIALOGS is hand-maintained. Today it plus the two deliberate
    exclusions covers every <dialog> on the page -- but a ninth dialog with a
    text input would be silently unguarded while this file stayed green. This
    pins the accounting: a new dialog must be filed in one list or the other,
    on purpose, before the suite passes again."""
    page = srv.render_page()
    on_page = set(re.findall(r'<dialog id="(\w+)"', page))
    accounted = set(FORM_DIALOGS) | set(_LIVE_DIALOGS)
    assert on_page == accounted, (
        f"dialogs unaccounted for: {sorted(on_page - accounted)} -- add each "
        "to FORM_DIALOGS (holds user input; the poll must never repaint it) "
        f"or to _LIVE_DIALOGS (read-only, live-updates by design); "
        f"stale entries: {sorted(accounted - on_page)}"
    )


def _dialog_static_ids(page, dialog_id):
    """Every id="..." belonging to <dialog id="dialog_id">'s own static
    markup -- a plain regex over the segment from that opening tag through
    its matching </dialog>, the same brace-free, DOM-free approach the rest
    of this file uses for source-level scans.

    The segment starts AT the literal `<dialog id="dialog_id"`, so the
    dialog's own id is itself the first match: a poll-reached
    `$("editor").close()` would yank a dialog shut out from under whoever
    opened it exactly as much as a poll-reached `$("ed-id")` would clobber a
    field inside it, and this way both are one rule instead of the
    container id needing a special case."""
    start = page.index(f'<dialog id="{dialog_id}"')
    end = page.index("</dialog>", start)
    return re.findall(r'id="([^"]+)"', page[start:end])


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_pushnav_never_stacks_the_state_it_is_already_on(srv, tmp_path):
    """Two navigation paths can fire for one gesture (opening the Activity
    screen re-asserts the security view on its way), and each pushing the
    same state gave Back a stop that showed the screen it was already on --
    the duplicate-entry wart both the implementer's and the coordinator's
    live back-walks hit. pushNav dedups against the CURRENT entry only:
    A -> B -> A must still stack three."""
    js = _js(srv)
    fn = _plainfn(js, "pushNav")
    script = tmp_path / "pushnav-dedup.js"
    script.write_text("""
    const entries = [];
    const history = {state: null,
      pushState(s){ this.state = s; entries.push(s); }};
    const location = {href: "/"};
    """ + fn + """
    pushNav({view: "jobs"});
    pushNav({view: "jobs"});
    pushNav({view: "security"});
    pushNav({view: "jobs"});
    console.log(JSON.stringify(entries.map(e => e.view)));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out == ["jobs", "security", "jobs"], (
        f"expected the duplicate push dropped and the A-B-A kept: {out}"
    )


def test_the_poll_never_reaches_into_a_form_dialog(srv):
    """render() runs on every 5-second poll and rebuilds the page's views
    from scratch. If it, or anything it calls directly, ever reached into
    one of FORM_DIALOGS, it would overwrite a field mid-keystroke -- input
    lost to a timer no click ever asked for. Until now that has been true by
    accident of how the code happens to be laid out; this test is what makes
    moving code (Phase 3 restyles these dialogs next) unable to reintroduce
    it without a test going red first.

    Method: extract every id="..." from each form dialog's own static markup
    (_dialog_static_ids), extract the source of render() and everything it
    calls directly -- brace-matched for the page's own functions
    (_DIALOG_POLL_PAGE_FNS), and via _app_js()/_security_js() for the two
    bundles (_DIALOG_POLL_APP_FNS, plus CCSecurity.render, exported from
    renderSecurity in ui/security/index.js) -- and assert that none of those
    bodies contains `$("<id>")`, single- or double-quoted, for any id that
    belongs to a form dialog.

    See the comments above FORM_DIALOGS for what is deliberately excluded
    (wtmodal, logmodal) and why; see the comment above
    _DIALOG_POLL_PAGE_FNS for why the scan stops at direct calls instead of
    walking the full call graph."""
    page = _page(srv)
    js = _js(srv)
    app_js = _app_js(srv)
    sec_js = _security_js(srv)

    guarded = {d: _dialog_static_ids(page, d) for d in FORM_DIALOGS}
    for d, ids in guarded.items():
        assert ids, f'<dialog id="{d}"> has no ids in its static markup -- did the markup move?'

    scanned = {}
    for name in _DIALOG_POLL_PAGE_FNS:
        scanned[f"{name}() (bin/dashboard.html)"] = _plainfn(js, name)
    for name in _DIALOG_POLL_APP_FNS:
        scanned[f"CCApp.{name}() (ui/app/)"] = _plainfn(app_js, name)
    scanned["CCSecurity.render() (renderSecurity, ui/security/index.js)"] = (
        _plainfn(sec_js, "renderSecurity"))

    violations = []
    for label, body in scanned.items():
        for dialog, ids in guarded.items():
            for gid in ids:
                if re.search(r"""\$\(\s*(['"])""" + re.escape(gid) + r"""\1\s*\)""", body):
                    violations.append(
                        f'{label} reads $("{gid}") -- belongs to <dialog id="{dialog}">')

    assert not violations, (
        "the poll reaches directly into a form dialog's own markup, which "
        "would clobber whatever a person was doing in it:\n  "
        + "\n  ".join(violations)
    )


# ---- Phase 3 Task 2: the two editor dialogs' pure half, pinned ahead of
# their own restyle -- same deal as the Jobs table's own Task 2 section
# above: characterisation tests, so they pass on their first run. The
# falsifiability of each one (break the named thing, run this one test, see
# it fail, revert) is recorded by hand in .superpowers/sdd/f3-task-2-report.md
# rather than by a red-then-green cycle here. changedKeys, effortIndex,
# effortFromIndex, dayNumbers, shapeRepoRows and projectStepError are all new
# in ui/app/editor-domain.js, extracted verbatim from edWiz/pjWiz's shared
# makeWizard, effortSet/effortGet, getDays, collectRepos and
# validateProjectStep (bin/dashboard.html) -- the decision/mapping half of
# each, never the DOM read that feeds it. makeWizard itself did NOT move (it
# stays page-owned, shared by both dialogs) and is pinned here by pulling its
# own source out of the inline script rather than the app bundle.


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_dirty_tracking_compares_snapshots_by_value_not_by_reference(srv, tmp_path):
    """edIsDirty (bin/dashboard.html) is edWiz.dirty(), i.e. W.changed().length>0,
    and W.changed() is now CCApp.changedKeys(now, clean) -- makeWizard's own
    inline filter, extracted whole. Pinned against the three shapes the
    wizard actually asks it for: an untouched form, one changed field, and a
    freshly taken snapshot compared right back against an equal one (what
    markClean() leaves behind) -- the last of which is exactly what a
    reference comparison gets wrong, since snapshot() builds a brand new
    object on every call and two of those are never `===` even when every
    value inside agrees."""
    block = _app_js(srv)
    fn = _plainfn(block, "changedKeys")
    script = tmp_path / "changed-keys.js"
    script.write_text(fn + """
    const clean = {"ed-id": "job-1", "ed-desc": "", __days: "1,2,3"};
    console.log(JSON.stringify({
      untouched: changedKeys({...clean}, clean).length > 0,
      oneChanged: changedKeys({...clean, "ed-desc": "now filled in"}, clean).length > 0,
      freshSnapshot: changedKeys({...clean}, {...clean}).length > 0,
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["untouched"] is False, "an untouched form must not read as dirty"
    assert out["oneChanged"] is True, "a single changed field must read as dirty"
    assert out["freshSnapshot"] is False, "a snapshot compared to an equal one must read as clean"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_wizard_gates_advancing_on_validation_but_editing_reaches_any_tab(srv, tmp_path):
    """makeWizard (bin/dashboard.html) backs both editor dialogs' dual mode:
    CREATING walks a numbered stepper where Next (stepForward -> edWiz/
    pjWiz.forward()) refuses to advance past an invalid step and says why;
    EDITING shows flat tabs and any of them is one click away
    (onTabClick's own `!W.creating ||` short-circuit), because every step
    is already filled in and there is no "next" to reach. Drives the real
    makeWizard under Node with a synthetic 3-step config -- the shared
    mechanism itself, not either dialog's own field-specific rules
    (validateStep/validateProjectStep are pinned on their own, elsewhere)."""
    js = _js(srv)
    deps = "\n".join([_plainfn(js, "showFormTab"), _plainfn(js, "focusFirstControl"),
                       _plainfn(js, "makeWizard")])
    script = tmp_path / "wizard.js"
    script.write_text("""
    const I = {cleft:"<cleft>", cright:"<cright>", check2:"<check2>", alert:"<alert>"};
    const esc = (s) => String(s);
    function paintPromptHighlight(){}
    // makeWizard's own W.changed() (dirtySteps' path, taken once editing
    // paints its nav) now calls CCApp.changedKeys -- pinned on its own in
    // test_dirty_tracking_compares_snapshots_by_value_not_by_reference above,
    // so a small, honest stand-in here is enough; this test is about
    // forward()/onTabClick, not the comparison itself.
    const CCApp = {changedKeys: (now, clean) => Object.keys(now).filter(k => now[k] !== clean[k])};
    // A tab strip minimal enough to drive paintTabs/paintNav: innerHTML is
    // parsed only for the one attribute paintTabs ever writes (data-ttab="key"),
    // in the order the real DOM would give querySelectorAll.
    function makeTabsEl(attr){
      let btns = [];
      return {
        classList: {add(){}, toggle(){}},
        set innerHTML(html){
          const re = new RegExp(attr + '="([^"]+)"', "g");
          btns = [...html.matchAll(re)].map(m => ({
            getAttribute(a){ return a === attr ? m[1] : null; },
            classList: {toggle(){}},
            querySelector(sel){ return sel === ".stepn" ? {innerHTML: ""} : null; },
          }));
        },
        get innerHTML(){ return ""; },
        querySelectorAll(){ return btns; },
      };
    }
    const DLG = {querySelectorAll: () => [], querySelector: () => null, close(){}};
    const ELS = {
      "t-tabs": makeTabsEl("data-ttab"),
      "t-back": {hidden: false, innerHTML: ""},
      "t-save": {innerHTML: ""},
      "t-err": {hidden: true, innerHTML: ""},
    };
    function $(id){ return id === "dlg" ? DLG : ELS[id]; }
    """ + deps + """
    let nextErr = null;
    const wiz = makeWizard({
      id: "dlg", prefix: "t", tabAttr: "data-ttab", paneAttr: "data-tpane",
      steps: [{k:"a",label:"A",next:"B"}, {k:"b",label:"B",next:"C"}, {k:"c",label:"C",next:null}],
      validate: (k) => nextErr,
      saveLabel: "Save", createLabel: "Create",
    });

    // CREATING: numbered stepper, Next validates before advancing.
    wiz.open(true);
    wiz.goto(0);
    nextErr = "bad";
    const invalidAdvance = {ret: wiz.forward(), i: wiz.i, errShown: !ELS["t-err"].hidden};
    nextErr = null;
    const step1 = {ret: wiz.forward(), i: wiz.i};   // a -> b
    const step2 = {ret: wiz.forward(), i: wiz.i};   // b -> c (last)
    const step3 = {ret: wiz.forward(), i: wiz.i};   // c is last: signal save, do not move
    wiz.goto(0);
    wiz.onTabClick("c");                            // clicking ahead while creating: refused
    const creatingTabClickAhead = wiz.i;

    // EDITING: flat tabs, every one reachable regardless of order.
    wiz.open(false);
    wiz.goto(0);
    wiz.onTabClick("c");
    const editingTabClick = wiz.i;

    console.log(JSON.stringify({invalidAdvance, step1, step2, step3,
                                 creatingTabClickAhead, editingTabClick}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["invalidAdvance"] == {"ret": False, "i": 0, "errShown": True}, \
        "an invalid step must refuse to advance, and must show why"
    assert out["step1"] == {"ret": False, "i": 1}, "a valid, non-last step must advance"
    assert out["step2"] == {"ret": False, "i": 2}, "a valid, non-last step must advance"
    assert out["step3"] == {"ret": True, "i": 2}, "the last valid step signals save, not another advance"
    assert out["creatingTabClickAhead"] == 0, "creating must not let a tab click skip ahead"
    assert out["editingTabClick"] == 2, "editing must let a tab click reach any step directly"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_project_step_validation_refuses_an_empty_name_and_a_malformed_repo(srv, tmp_path):
    """validateProjectStep (bin/dashboard.html) gathers the step's own fields
    and hands them to CCApp.projectStepError for the decision -- extracted
    whole, same conditions, same messages, in the same order. Two ways a
    step can be incomplete, pinned against the two the brief calls out by
    name: an empty project name, and a repo row that never became one.
    shapeRepoRows -- collectRepos' own pure half -- drops a row missing its
    name or its path before validation ever sees it, so a "malformed" row on
    the DOM and an empty list handed to projectStepError are the same case."""
    block = _app_js(srv)
    deps = "\n".join(_plainfn(block, n) for n in ("shapeRepoRows", "projectStepError"))
    script = tmp_path / "project-step.js"
    script.write_text(deps + """
    const base = {name:"Web", cwd:"/x/web", editingProject:"Web", projects:[], multi:false, repos:[]};
    const emptyName = projectStepError("project", {...base, name:""});
    const dupeName = projectStepError("project", {...base, editingProject:null,
      projects:[{name:"Web"}]});
    const noCwd = projectStepError("project", {...base, cwd:""});
    const okProject = projectStepError("project", base);

    // A row with a path but no name never becomes a repo -- shapeRepoRows
    // drops it, exactly as it would coming straight off the DOM.
    const malformed = shapeRepoRows([{name:"", path:"/x/web", base:""}]);
    const reposEmpty = projectStepError("repos", {...base, multi:true, repos: malformed});
    const reposMismatch = projectStepError("repos", {...base, multi:true,
      repos: shapeRepoRows([{name:"other", path:"/elsewhere", base:""}])});
    const reposOk = projectStepError("repos", {...base, multi:true,
      repos: shapeRepoRows([{name:"web", path:"/x/web", base:""}])});
    const reposSkippedWhenSingle = projectStepError("repos", {...base, multi:false, repos:[]});

    console.log(JSON.stringify({emptyName, dupeName, noCwd, okProject,
      malformedDropped: malformed.length, reposEmpty, reposMismatch, reposOk,
      reposSkippedWhenSingle}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["emptyName"] == {"ok": False, "message": "A project name is required."}
    assert out["dupeName"] == {"ok": False, "message": "A project with that name already exists."}
    assert out["noCwd"]["ok"] is False and "working directory" in out["noCwd"]["message"]
    assert out["okProject"] == {"ok": True}
    assert out["malformedDropped"] == 0, "a repo row missing its name must not survive shaping"
    assert out["reposEmpty"]["ok"] is False and "Add a repository" in out["reposEmpty"]["message"]
    assert (out["reposMismatch"]["ok"] is False
            and "must be exactly the working directory" in out["reposMismatch"]["message"])
    assert out["reposOk"] == {"ok": True}
    assert out["reposSkippedWhenSingle"] == {"ok": True}, "the repos rule only applies in multi-repo mode"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_days_and_effort_map_form_and_job_without_loss(srv, tmp_path):
    """dayNumbers (getDays' own pure half) and effortIndex/effortFromIndex
    (effortSet/effortGet's) are the form<->job halves of every value a job's
    active_days and effort fields can hold. Pinned against literal slider
    positions, not just round-trip invertibility -- swapping two names in
    EFFORTS would still round-trip perfectly, because both directions would
    then agree on the very same shuffled table; only checking a known value
    against its known position catches a level quietly renamed."""
    block = _app_js(srv)
    deps = ("\n".join(_plainfn(block, n) for n in ("effortIndex", "effortFromIndex", "dayNumbers"))
            + "\n" + _const(block, "EFFORTS"))
    script = tmp_path / "days-effort.js"
    script.write_text(deps + """
    const levels = ["", "low", "medium", "high", "xhigh", "max"];
    console.log(JSON.stringify({
      indexOf: levels.map(v => effortIndex(v)),
      valueOf: [0,1,2,3,4,5].map(i => effortFromIndex(String(i))),
      roundTrip: levels.every(v => effortFromIndex(String(effortIndex(v))) === v),
      unknownSettlesOnUnset: effortIndex("not-a-real-level"),
      outOfRangeSettlesOnUnset: effortFromIndex("99"),
      days: {
        none: dayNumbers([]),
        some: dayNumbers(["1","4","7"]),
        allSeven: dayNumbers(["1","2","3","4","5","6","7"]),
      },
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["indexOf"] == [0, 1, 2, 3, 4, 5], f"effort level -> slider index drifted: {out['indexOf']}"
    assert out["valueOf"] == ["", "low", "medium", "high", "xhigh", "max"], \
        f"slider index -> effort level drifted: {out['valueOf']}"
    assert out["roundTrip"] is True
    assert out["unknownSettlesOnUnset"] == 0, "an effort value the slider does not have settles on 0 (unset)"
    assert out["outOfRangeSettlesOnUnset"] == "", "a slider position past the table settles on unset"
    assert out["days"]["none"] == []
    assert out["days"]["some"] == [1, 4, 7]
    assert out["days"]["allSeven"] == [1, 2, 3, 4, 5, 6, 7]


# ---- Artboard parity: closing four divergences between the shipped editor
# dialogs and their approved artboards (JobEditor.view.html/ProjectEditor.
# view.html, extracted from the design canvas) -- edit mode's flat tabs vs
# create mode's numbered stepper (paintTabs), a Delete button in the job
# editor's footer wired through the Jobs table row's own delete flow, the
# job pane's Project/Working directory pairing, and the Security pane's
# checkbox becoming a segmented control over the same hidden #sec-enabled
# saveProject/openProjectEditor already read and write.

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_paint_tabs_renders_flat_text_tabs_while_editing_and_the_numbered_stepper_while_creating(
        srv, tmp_path):
    """paintTabs (makeWizard, bin/dashboard.html) is the one place that
    builds the tab strip's own markup -- paintNav (pinned elsewhere) only
    toggles classes on buttons paintTabs already drew. The approved
    artboards show a numbered stepper only while CREATING; EDITING gets the
    same flat, underlined text tabs every other page's plain .tabs/.tab
    already draw -- no "wiz" class on the nav, no per-tab step number. Drives
    the real makeWizard (not a copy) and inspects exactly what it assigned
    to the nav element's classList/innerHTML on each mode."""
    js = _js(srv)
    deps = "\n".join([_plainfn(js, "showFormTab"), _plainfn(js, "focusFirstControl"),
                       _plainfn(js, "makeWizard")])
    script = tmp_path / "paint-tabs.js"
    script.write_text("""
    const I = {cleft:"<cleft>", cright:"<cright>", check2:"<check2>", alert:"<alert>"};
    const esc = (s) => String(s);
    function paintPromptHighlight(){}
    const CCApp = {changedKeys: () => []};
    function makeNav(){
      const rec = {wiz: [], html: []};
      return {
        rec,
        classList: {toggle(cls, val){ if(cls === "wiz") rec.wiz.push(!!val); }},
        set innerHTML(h){ rec.html.push(h); },
        get innerHTML(){ return rec.html[rec.html.length - 1] || ""; },
        querySelectorAll(){ return []; },
      };
    }
    const nav = makeNav();
    const DLG = {querySelectorAll: () => [], querySelector: () => null, close(){}};
    const ELS = {
      "t-tabs": nav, "t-back": {hidden:false, innerHTML:""},
      "t-save": {innerHTML:""}, "t-err": {hidden:true, innerHTML:""},
    };
    function $(id){ return id === "dlg" ? DLG : ELS[id]; }
    """ + deps + """
    const wiz = makeWizard({
      id: "dlg", prefix: "t", tabAttr: "data-ttab", paneAttr: "data-tpane",
      steps: [{k:"a",label:"Alpha",next:"B"}, {k:"b",label:"Beta",next:null}],
      validate: () => null, saveLabel: "Save", createLabel: "Create",
    });
    wiz.open(true);
    const creating = {wizFlag: nav.rec.wiz[nav.rec.wiz.length - 1],
                       html: nav.rec.html[nav.rec.html.length - 1]};
    wiz.open(false);
    const editing = {wizFlag: nav.rec.wiz[nav.rec.wiz.length - 1],
                      html: nav.rec.html[nav.rec.html.length - 1]};
    console.log(JSON.stringify({creating, editing}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["creating"]["wizFlag"] is True, "creating must still get the numbered stepper's wiz class"
    assert '<span class="stepn">1</span>' in out["creating"]["html"], "creating lost its step numbers"
    assert out["editing"]["wizFlag"] is False, "editing must not carry the numbered stepper's wiz class"
    assert "stepn" not in out["editing"]["html"], \
        "editing still renders a step-number span -- the artboard shows flat text tabs"
    assert "Alpha</button>" in out["editing"]["html"] and "Beta</button>" in out["editing"]["html"], \
        "editing must still render every tab's own label"


def test_flat_tabs_get_their_own_bad_and_edited_treatment(srv):
    """.tabs.wiz .tab.bad/.edited (ui/css/pages.css) only fire on a stepn
    circle to redden or badge -- which edit mode no longer renders (previous
    test). test_no_class_the_shipped_ui_uses_lacks_a_css_rule cannot catch a
    missing rule here, because paintTabs writes "bad"/"edited" from inside
    dashboard.html's own <script>, which that scan deliberately excludes (it
    is a static-markup/JS-bundle scan) -- so this checks the built
    stylesheet directly: a failed save can still gotoStep() into a tab you
    are not looking at while editing (saveEditor/saveProject validate every
    step, not only the current one), and a changed step still needs an
    "unsaved" signal without a circle to put a corner-dot on."""
    css, _ = srv.static_asset("app.css")
    assert re.search(r"\.tabs:not\(\.wiz\)\s+\.tab\.bad\s*\{[^}]*color:var\(--err\)", css), \
        "editing needs its own .tab.bad rule -- .tabs.wiz .tab.bad alone no longer reaches a flat tab"
    assert re.search(r"\.tabs:not\(\.wiz\)\s+\.tab\.edited::after\s*\{", css), \
        "editing needs its own dirty-step indicator -- the wiz one lives on a stepn circle that is gone"


def test_delete_job_from_the_editor_reuses_the_rows_own_confirm_and_api_call(srv):
    """B: the job editor's Delete button must not become a second way to
    delete a job with its own, possibly-drifting confirm copy or its own
    endpoint. deleteJobFromModal (bin/dashboard.html) has to ask the exact
    same question the Jobs table row's own data-op="delete" branch asks
    (same title, message and confirmLabel), and call the exact same
    api("delete", ...) -- never a new "job_delete" op."""
    js = _js(srv)
    row = re.search(
        r'if\(op==="delete"\)\{\s*'
        r'const yes=await showConfirm\(\{tone:"danger", icon:"trash", title:"Delete job "\+id\+"\?",\s*'
        r'message:"([^"]+)",\s*'
        r'confirmLabel:"([^"]+)"\}\);',
        js)
    assert row, "the Jobs table row's own delete confirmation was not found where expected"
    modal = _fn(js, "deleteJobFromModal")
    assert 'title:"Delete job "+id+"?"' in modal, "the modal's confirm title drifted from the row's"
    assert f'message:"{row.group(1)}"' in modal, "the modal's confirm message drifted from the row's"
    assert f'confirmLabel:"{row.group(2)}"' in modal, "the modal's confirm label drifted from the row's"
    assert 'api("delete",{id})' in modal, 'must call the row-shared api("delete", ...), not a new op'
    assert "job_delete" not in js, "a second, job_delete-named delete path must not exist"


def test_ed_delete_sits_first_in_the_footer_and_only_shows_up_while_editing(srv):
    """Mirrors pj-delete: present and visible only when there is a job to
    delete (openEditor), hidden while creating (openCreator) -- the wizard's
    footer there is Back/Next, and there is no job yet to delete."""
    page = _page(srv)
    js = _js(srv)
    footer_start = page.index('<div class="dlg-f">')
    footer = page[footer_start:footer_start + 400]
    first_button = re.search(r"<button[^>]*>", footer)
    assert first_button and 'id="ed-delete"' in first_button.group(0), (
        "Delete job must be the FIRST control in the job editor's own footer, "
        f"the same position pj-delete already holds in the project editor: {first_button}"
    )
    assert 'class="btn danger"' in first_button.group(0), "must read as a destructive action, like pj-delete"
    assert "Delete job</button>" in footer
    open_editor = _plainfn(js, "openEditor")
    open_creator = _plainfn(js, "openCreator")
    assert '$("ed-delete").style.display=""' in open_editor, "openEditor must show the Delete button"
    assert '$("ed-delete").style.display="none"' in open_creator, \
        "openCreator must hide the Delete button -- there is no job yet to delete"


def test_the_job_panes_project_and_working_directory_are_paired(srv):
    """C: the artboard pairs Project and Working directory side by side in
    one .row2; the shipped page used to stack them with Description sitting
    between the two. ids and help text are untouched -- only the grouping
    and the order moved, to match the artboard's own field order."""
    page = _page(srv)
    job_pane = page[page.index('data-edpane="job"'):page.index("<!-- /pane job -->")]
    assert job_pane.count('<div class="row2">') == 1, \
        "expected exactly one .row2 pairing in the job pane"
    i_row2 = job_pane.index('<div class="row2">')
    i_project = job_pane.index('id="ed-project-combo"')
    i_cwd = job_pane.index('id="ed-cwd"')
    i_browse = job_pane.index("Browse…")
    i_desc_label = job_pane.index("<label>Description</label>")
    assert i_row2 < i_project < i_cwd < i_browse < i_desc_label, (
        "Project and Working directory must sit together inside one .row2, "
        "ahead of Description -- the artboard's own field order"
    )
    # every id this pane owned before the reshuffle is still exactly there
    for field in ("ed-project-combo", "ed-project-trigger", "ed-project-val", "ed-project-pop",
                  "ed-project-search", "ed-project-opts", "ed-project", "ed-cwd", "ed-cwd-help",
                  "ed-cwd-note", "ed-desc"):
        assert f'id="{field}"' in job_pane, f"the job pane lost {field} in the reshuffle"


def test_security_enable_is_a_hidden_checkbox_behind_a_segmented_control(srv):
    """D: the artboard shows an Enabled/Disabled segmented control, not a
    checkbox. saveProject/openProjectEditor are untouched -- both still work
    through a real #sec-enabled checkbox, kept in the DOM (hidden, not
    removed) so W.snapshot()'s querySelectorAll("input[id]...") still finds
    it, and the two segments toggle that hidden checkbox rather than being a
    second, competing source of truth."""
    page = _page(srv)
    assert '<input type="checkbox" id="sec-enabled" hidden>' in page, \
        "sec-enabled must still be a real checkbox saveProject/openProjectEditor can read and set -- just hidden"
    assert "Enable security analysis" not in page, "the old checkbox label must not linger alongside the segments"
    seg = re.search(r'<div class="segctl" id="sec-enabled-seg">(.*?)</div>', page, re.S)
    assert seg, "the Enabled/Disabled segmented control is missing"
    opts = re.findall(r'<button[^>]*data-secenabled="(\d)"[^>]*>([^<]+)</button>', seg.group(1))
    assert opts == [("1", "Enabled"), ("0", "Disabled")], \
        f"expected the artboard's two segments, in order, got {opts}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_paint_sec_enabled_reflects_the_hidden_checkboxs_state(srv, tmp_path):
    """The segments are paint, not state -- see paintSecEnabled's own comment
    in bin/dashboard.html. Drives the real function over a stub DOM: checked
    lights Enabled and only Enabled; unchecked lights Disabled and only
    Disabled -- the stale segment must lose its "on" class rather than both
    staying lit or neither lighting up."""
    js = _js(srv)
    fn = _plainfn(js, "paintSecEnabled")
    script = tmp_path / "paint-sec-enabled.js"
    script.write_text("""
    let ELS = {};
    function $(id){ return ELS[id]; }
    """ + fn + """
    function button(v){
      const b = {dataset: {secenabled: v}, on: false, pressed: null};
      b.classList = {toggle(cls, val){ if(cls === "on") b.on = !!val; }};
      b.setAttribute = (k, val) => { if(k === "aria-pressed") b.pressed = val; };
      return b;
    }
    function run(checked){
      const enabledBtn = button("1"), disabledBtn = button("0");
      ELS = {"sec-enabled": {checked},
             "sec-enabled-seg": {querySelectorAll: () => [enabledBtn, disabledBtn]}};
      paintSecEnabled();
      return {enabled: {on: enabledBtn.on, pressed: enabledBtn.pressed},
              disabled: {on: disabledBtn.on, pressed: disabledBtn.pressed}};
    }
    console.log(JSON.stringify({whenOn: run(true), whenOff: run(false)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["whenOn"] == {"enabled": {"on": True, "pressed": "true"},
                              "disabled": {"on": False, "pressed": "false"}}
    assert out["whenOff"] == {"enabled": {"on": False, "pressed": "false"},
                               "disabled": {"on": True, "pressed": "true"}}


def test_clicking_a_segment_sets_the_hidden_checkbox_and_fires_change(srv):
    """#projmodal's own delegated change listener (paintNav) is what used to
    react to a person ticking #sec-enabled directly; a segment click must
    keep it reacting exactly as before, so this pins that the click handler
    flips the real checkbox and dispatches a bubbling "change" -- not a
    hand-rolled repaint that route would stop seeing."""
    js = _js(srv)
    handler = re.search(
        r'\$\("sec-enabled-seg"\)\.addEventListener\("click",\(e\)=>\{(.*?)\}\);',
        js, re.S)
    assert handler, "no click handler wired on the segmented control"
    body = handler.group(1)
    assert '$("sec-enabled").checked=on' in body, "a segment click must set the real, hidden checkbox"
    assert 'new Event("change",{bubbles:true})' in body, \
        'the click must dispatch a bubbling change event so #projmodal\'s own change listener still fires'


# ---- rule vocabulary (secRuleMeta / SEC_RULE_META, ui/security/vocabulary.js)
#
# secRuleMeta resolves the label and icon "Top issue categories" draws for one
# rule (secIndexCategories, ui/security/index-screen.js) -- see that map's own
# module comment for the four rule vocabularies it covers (secret, hygiene,
# dependency, sast) and why a curated map replaced the substring heuristic
# (secIndexCatIcon) this screen used to run over the raw rule string. These
# tests drive the real function under Node, and check every icon it can
# return against the page's OWN icon table (`const I={...}`, bin/
# dashboard.html) rather than a second, hand-typed list that could drift from
# it the next time an icon is renamed.

def _icon_names(js):
    """Every key the page's own icon table (`const I={...}`) defines, parsed
    from the live page rather than copied into a second list a new icon
    could be added without updating. Brace-matched with _scan_balanced the
    same way _const matches a `const NAME = {...}` value -- _const's own
    exact-substring lookup wants `"const NAME ="` with a space either side
    of the `=`, and this table is written `const I={` with none."""
    i = js.index("const I={")
    open_idx = js.index("{", i)
    end = _scan_balanced(js, open_idx)
    body = _strip_comments(js[open_idx:end])
    return set(re.findall(r"(?:^|[{,\s])([A-Za-z_$][\w$]*)\s*:\s*ic\(", body))


def _rule_meta_deps(block):
    """Everything secRuleMeta needs to run standalone: the consts it closes
    over (ICON_HYGIENE, SEC_RULE_META, SEC_CATEGORY_ICON -- its own per-
    category fallback icon, factored out for secCategoryMeta to share rather
    than a second hand-typed list, see that const's own comment), the
    pattern it tests an advisory id against (SEC_ADVISORY_RULE), and the one
    private helper it calls on its "sast" branch (secHumaniseRule). Pulled
    together once so every test below gets secRuleMeta's whole dependency
    set, not a per-test guess at which of its branches that test happens to
    reach."""
    return (_const(block, "ICON_HYGIENE") + _const(block, "SEC_RULE_META")
            + _const(block, "SEC_ADVISORY_RULE") + _const(block, "SEC_CATEGORY_ICON")
            + _plainfn(block, "secHumaniseRule") + _plainfn(block, "secRuleMeta"))


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_every_deterministic_rule_resolves_its_pinned_label_and_a_real_icon(srv, tmp_path):
    """SEC_RULE_META is the closed vocabulary for the secret and hygiene
    engines (bin/security/secrets.py's own `_RULES`, bin/security/
    hygiene.py's four findings) -- every rule either module can write must
    be in it, worded from that rule's own rationale (see the map's own
    comment -- missing_gitignore's label says "no .gitignore", not "build
    artifacts", because the rule's rationale is about a stray .env or key
    file slipping in, not about build output), and every one of them must
    name an icon the page's real table defines: a typo here is a blank
    glyph on a live dashboard, not a failure anywhere else in this suite."""
    block = _security_js(srv)
    deps = _rule_meta_deps(block)
    icon_names = _icon_names(_js(srv))
    script = tmp_path / "rule-meta-exact.js"
    script.write_text(deps + """
    console.log(JSON.stringify(Object.keys(SEC_RULE_META).map(rule => (
      Object.assign({rule}, secRuleMeta(null, rule))
    ))));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    expected = {
        "private_key":         "Private keys committed",
        "generic_secret":      "Hardcoded secrets",
        "aws_access_key":      "AWS access key committed",
        "github_token":        "GitHub token committed",
        "slack_token":         "Slack token committed",
        "stripe_key":          "Stripe live key committed",
        "openai_key":          "OpenAI API key committed",
        "google_api_key":      "Google API key committed",
        # The same credential types under gitleaks' OWN rule ids. The engine
        # writes its id into the finding (the fingerprint contains the rule,
        # so re-spelling it would orphan every recorded decision), and without
        # these keys every secret on an engine-scanned project drew the
        # generic humanised label instead of the curated one. One rule of ours
        # is several of theirs -- five GitHub token kinds, seven Slack ones.
        "aws-access-token":          "AWS access key committed",
        "github-pat":                "GitHub token committed",
        "github-fine-grained-pat":   "GitHub token committed",
        "github-oauth":              "GitHub OAuth token committed",
        "github-app-token":          "GitHub app token committed",
        "github-refresh-token":      "GitHub refresh token committed",
        "slack-bot-token":           "Slack token committed",
        "slack-user-token":          "Slack token committed",
        "slack-app-token":           "Slack token committed",
        "slack-config-access-token": "Slack token committed",
        "slack-legacy-bot-token":    "Slack token committed",
        "slack-legacy-token":        "Slack token committed",
        "slack-webhook-url":         "Slack webhook URL committed",
        "stripe-access-token":       "Stripe live key committed",
        "openai-api-key":            "OpenAI API key committed",
        "gcp-api-key":               "Google API key committed",
        "private-key":               "Private keys committed",
        "generic-api-key":           "Hardcoded secrets",
        "committed_env_file":  ".env file committed",
        "committed_key_file":  "Private key file committed",
        "missing_gitignore":   "No .gitignore in the repository",
        "world_writable_file": "World-writable file",
    }
    got = {row["rule"]: row["label"] for row in out}
    assert got == expected, f"a label drifted from the pinned map: {got}"
    for row in out:
        assert row["icon"] in icon_names, (
            f"{row['rule']} points at icon {row['icon']!r}, which bin/dashboard.html's "
            f"own table does not define: {sorted(icon_names)}")
    # private_key and committed_key_file name a key sitting in the repository
    # found two different ways -- both must draw the SAME icon (see
    # SEC_RULE_META's own comment), not two different ones that would make a
    # reader wonder why the same risk looks different depending on which
    # scanner found it.
    by_rule = {row["rule"]: row["icon"] for row in out}
    assert by_rule["private_key"] == by_rule["committed_key_file"] == "key"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_every_rule_the_engine_grades_has_a_curated_label(srv, tmp_path):
    """The two lists that name gitleaks' rules must not drift apart.

    bin/security/adapters.py's `SEVERITY_BY_RULE` is the set of engine rules
    this project has an OPINION about -- each one carried across from a
    `secrets._RULES` judgement so the scanner swap does not re-grade a
    repository's backlog. Every one of them therefore has a curated label
    waiting for it here; a rule graded in Python and humanised on screen is
    exactly the half-done state this test exists to catch, and it is invisible
    otherwise (the label still renders, just genericly).

    The other direction is deliberately NOT asserted: gitleaks ships ~180
    rules and gains more every release, and adapters.DEFAULT_SEVERITY exists
    precisely so an unmapped one is still graded. Those humanise on screen, as
    they should.
    """
    import sys
    sys.path.insert(0, str(REPO / "bin"))
    try:
        from security import adapters
    finally:
        sys.path.pop(0)

    block = _security_js(srv)
    deps = _rule_meta_deps(block)
    script = tmp_path / "rule-meta-engine.js"
    script.write_text(deps + """
    console.log(JSON.stringify(Object.keys(SEC_RULE_META)));
    """)
    known = set(json.loads(subprocess.run(["node", str(script)],
                                          capture_output=True, text=True,
                                          check=True).stdout))
    missing = sorted(set(adapters.SEVERITY_BY_RULE) - known)
    assert not missing, (
        f"adapters.SEVERITY_BY_RULE grades these gitleaks rules, but "
        f"SEC_RULE_META has no label for them, so they render as the generic "
        f"humanised slug: {missing}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_advisory_id_keeps_itself_as_the_label(srv, tmp_path):
    """bin/security/osv.py writes the OSV.dev advisory id itself as the
    `rule` -- GHSA-... or CVE-... -- and an id is already a name (the
    mockup keeps "GHSA-8xcm-r25x-g524" verbatim, never translates it). Both
    prefixes, both cases, so a lowercase id is not silently treated as an
    unrecognised rule."""
    block = _security_js(srv)
    deps = _rule_meta_deps(block)
    script = tmp_path / "rule-meta-advisory.js"
    script.write_text(deps + """
    console.log(JSON.stringify({
      ghsa: secRuleMeta("dependency", "GHSA-8xcm-r25x-g524"),
      cve: secRuleMeta("dependency", "CVE-2024-12345"),
      lower: secRuleMeta("dependency", "ghsa-lowercase-id"),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["ghsa"] == {"label": "GHSA-8xcm-r25x-g524", "icon": "shield"}
    assert out["cve"] == {"label": "CVE-2024-12345", "icon": "shield"}
    assert out["lower"] == {"label": "ghsa-lowercase-id", "icon": "shield"}


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_iac_check_id_keeps_itself_as_the_label(srv, tmp_path):
    """bin/security/adapters.py's `_iac_finding` writes Trivy's own check id
    as the `rule` -- `DS-0002`, `KSV-0001`, `AVD-AWS-0088` -- and a check id
    is the SAME kind of object an advisory id (above) is: an opaque vendor
    identifier, not a sentence. Before this fix secRuleMeta had no branch for
    it and fell through to secHumaniseRule, which splits on the hyphen:
    "DS-0002" rendered as "DS 0002" in every "Top issue categories" rollup
    (index-screen.js, overview-tab.js, project-screen.js) -- a string that
    matches neither the id an operator would grep the ledger for nor a real
    human label. The fix keeps the id verbatim in its own branch (not a join
    onto SEC_ADVISORY_RULE, which recognises only GHSA/CVE) and draws the
    iac category's own `cpu` icon rather than the advisory branch's
    `shield`.

    The containment probe is `sastControl`: the identical string under the
    "sast" category must still humanise. The new branch is keyed on
    `category === "iac"`, not on the shape of the rule, so a sast rule id
    that happens to look like a Trivy check id must not start keeping
    itself verbatim too."""
    block = _security_js(srv)
    deps = _rule_meta_deps(block)
    script = tmp_path / "rule-meta-iac.js"
    script.write_text(deps + """
    console.log(JSON.stringify({
      ds: secRuleMeta("iac", "DS-0002"),
      ksv: secRuleMeta("iac", "KSV-0001"),
      avd: secRuleMeta("iac", "AVD-AWS-0088"),
      sastControl: secRuleMeta("sast", "DS-0002"),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["ds"] == {"label": "DS-0002", "icon": "cpu"}
    assert out["ksv"] == {"label": "KSV-0001", "icon": "cpu"}
    assert out["avd"] == {"label": "AVD-AWS-0088", "icon": "cpu"}
    assert out["sastControl"] == {"label": "DS 0002", "icon": "code"}, (
        "the iac branch must be keyed on category, not on the rule's shape "
        f"-- a sast rule that happens to look like a check id must still "
        f"humanise: {out['sastControl']}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_unknown_sast_rule_is_humanised_not_shown_as_a_raw_slug(srv, tmp_path):
    """sast is the one OPEN vocabulary (SEC_RULE_META's own comment): the
    analysis agent writes its own kebab-case rule id per finding, so this is
    the one category secRuleMeta transforms rather than looks up.
    "auth-gate-fails-open" is a real rule id already sitting in the ledger
    (data/security.db), not a made-up example -- pinned as an exact in/out
    pair, not just "contains a capital letter somewhere". MINOR 2 (Phase 4
    final review): the agent is not promised to write kebab-case rather than
    snake_case, so the identical rule id spelled "auth_gate_fails_open" is
    pinned alongside it, same expected label -- secHumaniseRule's own comment
    already promised both separators; this is what holds it to that."""
    block = _security_js(srv)
    deps = _rule_meta_deps(block)
    script = tmp_path / "rule-meta-sast.js"
    script.write_text(deps + """
    console.log(JSON.stringify({
      kebab: secRuleMeta("sast", "auth-gate-fails-open"),
      snake: secRuleMeta("sast", "auth_gate_fails_open"),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["kebab"] == {"label": "Auth gate fails open", "icon": "code"}
    assert out["snake"] == {"label": "Auth gate fails open", "icon": "code"}, \
        f"snake_case did not humanise the same way kebab-case does: {out['snake']}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_an_unknown_category_falls_back_safely(srv, tmp_path):
    """`top_categories` serves each row's category now, but the resolver
    still has to survive whatever it is handed: an unknown category string,
    an unknown rule, or nothing at all. It must never throw and never point
    at an icon the page cannot draw -- and an unknown id HUMANISES (sentence
    case) rather than rendering raw, because the card's whole job is human
    labels and the raw id lives on the row's title. Advisory ids are the one
    exception, tested beside the GHSA case."""
    block = _security_js(srv)
    deps = _rule_meta_deps(block)
    icon_names = _icon_names(_js(srv))
    script = tmp_path / "rule-meta-unknown.js"
    script.write_text(deps + """
    console.log(JSON.stringify({
      noCategory: secRuleMeta(undefined, "totally-unrecognised-rule"),
      bogusCategory: secRuleMeta("not-a-real-category", "totally-unrecognised-rule"),
      noRuleEither: secRuleMeta(undefined, undefined),
    }));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    for key in ("noCategory", "bogusCategory"):
        row = out[key]
        assert row["label"] == "Totally unrecognised rule", f"{key}: {row}"
        assert row["icon"] in icon_names, f"{key} points at an unknown icon: {row}"
    assert out["noRuleEither"]["icon"] in icon_names
    assert out["noRuleEither"]["label"], "even with no rule at all, some label must render"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_iac_is_a_labelled_category_with_a_real_icon(srv, tmp_path):
    """The fifth category (bin/security/adapters.py's `trivy_misconfigs`,
    diff.DETERMINISTIC_CATEGORIES) has to earn its own word here too, or a
    checklist row using it falls through to the generic sentence-case
    fallback ("Iac") `secCategoryMeta`'s own comment describes for a category
    this map has not been told about."""
    block = _security_js(srv)
    consts = (_const(block, "ICON_HYGIENE") + _const(block, "SEC_CATEGORY_LABEL")
             + _const(block, "SEC_CATEGORY_ICON"))
    deps = _plainfn(block, "secCategoryMeta")
    icon_names = _icon_names(_js(srv))
    script = tmp_path / "cat-meta-iac.js"
    script.write_text(consts + deps + """
    console.log(JSON.stringify(secCategoryMeta("iac")));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert out["label"] == "IaC"
    assert out["icon"] in icon_names, (
        f"iac points at icon {out['icon']!r}, which bin/dashboard.html's own "
        f"table does not define: {sorted(icon_names)}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_all_findings_category_filter_matches_the_project_tabs_own_labels(
        srv, tmp_path):
    """findings-screen.js's Category filter (secFindFilterBar) used to label
    its options with `_secCap(c)` -- a bare capitalised category string
    ("Iac", "Sast") -- while analysis.js's secFindCatPicker, the identical
    filter on the per-project Findings tab, already reads `secCategoryMeta
    (cat).label` ("IaC", "SAST"). Same five values, two spellings depending
    on which screen a reader had open. This extracts the ACTUAL options
    expression out of the live secFindFilterBar source (whichever helper it
    currently calls) and evaluates it for real, so reverting the fix back to
    `_secCap` fails this test rather than only reading correctly in a diff."""
    block = _security_js(srv)
    filter_bar_src = _plainfn(block, "secFindFilterBar")
    m = re.search(r"FIND_CATEGORIES\.map\(c => \(\{v: c, label: [^}]*\}\)\)",
                  filter_bar_src)
    assert m, "could not find the Category picker's options expression in secFindFilterBar"
    deps = (_const(block, "FIND_CATEGORIES") + _const(block, "ICON_HYGIENE")
            + _const(block, "SEC_CATEGORY_LABEL") + _const(block, "SEC_CATEGORY_ICON")
            + _plainfn(block, "secCategoryMeta") + _plainfn(block, "_secCap"))
    script = tmp_path / "find-category-filter.js"
    script.write_text(deps + f"""
    console.log(JSON.stringify({m.group(0)}));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    labels = {row["v"]: row["label"] for row in out}
    assert labels == {"secret": "Secrets", "dependency": "Dependency",
                       "sast": "SAST", "hygiene": "Hygiene", "iac": "IaC"}, (
        "the All Findings Category filter must spell every category the way "
        f"the project Findings tab's own picker does: {labels}")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_rendered_category_row_keeps_the_raw_rule_id_one_hover_away(srv, tmp_path):
    """secIndexCategories now shows a human label instead of the raw rule id
    -- an operator who greps the ledger by rule id must still find it, so
    the id moves to the row's own title rather than disappearing from the
    page entirely."""
    block = _security_js(srv)
    deps = (_rule_meta_deps(block)
            + _index_screen_deps(block, "secEl", "secIcon", "secIndexCategories"))
    script = tmp_path / "cat-row-title.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const wrap = secIndexCategories([{rule: "private_key", count: 23}]);
    console.log(JSON.stringify(collectAll(wrap, [])));
    """)
    out = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    row = next(r for r in out if r["cls"] == "secidx-catrow")
    assert row["title"] == "private_key", f"the raw rule id is not on the row's title: {row}"
    assert "Private keys committed" in row["text"], \
        f"the resolved label did not render at all: {row['text']!r}"
    assert "private_key" not in row["text"], \
        "the raw rule id leaked into the visible text instead of staying in the title only"


def test_calling_the_bridged_chrome_builders_during_securitys_own_init_does_not_reach_a_dead_binding():
    """CRITICAL 2 (Phase 4 final review). ui/security/page.js's own comment
    explains the trap this guards: pageHeader/kpiCard/tableFooter are read
    off CCApp at CCSecurity.init(CC) time (bin/dashboard.html) -- a plain
    property READ, safe that early, since CCApp's own module script has
    already executed and defined them by then. But CALLING one of the three,
    synchronously, from inside ui/security/index.js's own init() (or a
    function it calls directly, at that same synchronous point) runs
    chrome.js's own function body immediately -- and that body calls
    `icon(...)`, which for THIS bridge resolves to ui/app/page.js's own
    binding. That binding is not assigned until CCApp.init() runs, which
    bin/dashboard.html calls AFTER CCSecurity.init(CC) (see that file's own
    banner comment above the CC object) -- so at the instant init() would
    call pageHeader(), `icon` there is still `undefined`, and `icon(...)`
    throws "icon is not a function". The whole page comes up blank, and
    every OTHER test in this suite still passes, because none of them boots
    the real script in the real order: the reviewer reproduced exactly this
    -- 775 green tests, one blank page -- by adding a bare `pageHeader({})`
    call to init(). Falsified against this exact guard: with that one line
    added, this test goes red (the assertion below fails, naming
    "init() calls pageHeader("); reverted, it is green again.

    Honest limit: SYNCHRONOUS, DIRECT callees only. A bare `name(...)`
    statement sitting at init()'s own top level counts; a callback handed to
    `addEventListener`/`onPick`/etc. does not, because it runs later, off an
    event, never while init() itself is on the stack -- and neither does
    anything TWO calls deep (what a direct callee's OWN callees call). Every
    import at the top of index.js is a "./..." one, so a direct callee's own
    definition -- when it has one at all; `iconLabel` and `$` are bridged
    bindings with no local function body to find -- can only live under
    ui/security/, never ui/app/: that other bundle defines its own,
    DIFFERENT `bindPage`, and checking it would silently guard nothing."""
    index_js = (UI_ROOT / "security" / "index.js").read_text()
    init_src = _plainfn(index_js, "init")
    init_body = _strip_comments(init_src[init_src.index("{") + 1:init_src.rindex("}")])

    forbidden = ("pageHeader(", "kpiCard(", "tableFooter(")

    def violations(label, text):
        return [f"{label} calls {name}" for name in forbidden if name in text]

    problems = violations("init()", init_body)

    security_dir = UI_ROOT / "security"
    security_files = {p.name: p.read_text() for p in security_dir.glob("*.js")}
    checked = set()
    for stmt in _top_level_statements(init_body):
        m = re.match(rf"^({_IDENT})\(", stmt)
        if not m or m.group(1) in checked or m.group(1) == "init":
            continue
        name = m.group(1)
        checked.add(name)
        for fname, text in security_files.items():
            if fname == "index.js" or not re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", text):
                continue
            callee_body = _strip_comments(_plainfn(text, name))
            problems.extend(violations(f"{name}() ({fname}), a direct callee of init()",
                                        callee_body))

    assert problems == [], (
        "init() (or a function it calls directly and synchronously) reaches a "
        "bridged chrome builder before CCApp.init() has bound ui/app/page.js's "
        "own `icon` -- this throws and blanks the whole page on load: "
        + "; ".join(problems)
    )


# ============================================================ F4: browser history
# bin/dashboard.html's own router comment (beside setView) is the contract; these
# tests drive the REAL extracted functions rather than re-describe it. Three
# behavioural layers: the page's own router (pushNav/setView/restoreNav/
# initViews, this file's _js), the Security bridge that composes/applies its own
# screen (secNavState/secNavigate, ui/security/index.js), and -- text-level,
# for the fetch-heavy screen functions a full behavioural drive would need a
# network mock disproportionate to what is being pinned -- the one property a
# render/fetch cannot hide: every navigation function pushes its OWN state,
# guarded by `fromHistory`, and a compound click suppresses every step but its
# last.

def _norm(s):
    """Collapses whitespace so a substring check does not care whether the
    real source wrapped an object literal onto a second line."""
    return re.sub(r"\s+", " ", s)


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_push_nav_writes_the_given_state_to_history(srv, tmp_path):
    """pushNav is the one function in the whole router that touches `history`
    directly -- everything else (setView, and every Security navigation
    point through the CC.pushNav bridge) goes through it. Pinned alone so the
    tests below can stub it as a plain recorder without re-proving this
    wiring every time."""
    js = _js(srv)
    script = tmp_path / "pushnav.js"
    script.write_text(_plainfn(js, "pushNav") + """
    const pushed = [];
    const location = { href: "http://127.0.0.1:8787/" };
    const history = { pushState(state, title, url){ pushed.push({state, title, url}); } };
    pushNav({view: "jobs"});
    console.log(JSON.stringify(pushed));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out == [{"state": {"view": "jobs"}, "title": "", "url": "http://127.0.0.1:8787/"}], out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_set_view_pushes_a_real_navigation_and_a_restore_skips_both_the_push_and_securitys_enter(srv, tmp_path):
    """The two things setView must get right for the router to work: a real
    navigation (no second argument) pushes the composed state, entering
    Security through CCSecurity.enter() first so the pushed `sec` reflects
    whatever it resolved to; a restore (`fromHistory=true`) does neither --
    CCSecurity.enter() is skipped too, not just the push, because a restore
    (restoreNav, tested below) already knows the exact screen and is about
    to call CCSecurity.navigate() with it right after setView returns --
    see setView's own comment for why calling enter() first would just be a
    second, wasted guess.

    Drives FOUR calls in one script rather than one assertion each: the
    counters below only mean anything as a sequence (entered stays 1 across
    TWO transitions into Security, because only the first was a real one)."""
    js = _js(srv)
    deps = "\n".join(_plainfn(js, n) for n in ("currentNavState", "setView"))
    script = tmp_path / "setview-push.js"
    script.write_text("""
    const VIEWS = ["overview","jobs","runs","projects","security"];
    let currentView = "overview";
    const localStorage = {};
    class FakeEl { constructor(){ this.hidden = false; this.dataset = {}; this.classList = { toggle(){} }; } }
    const _els = {};
    function $(id){ if(!_els[id]) _els[id] = new FakeEl(); return _els[id]; }
    const document = { querySelectorAll: () => [] };
    function closeDrawer(){}
    function render(){}
    let entered = 0, left = 0;
    const CCSecurity = {
      enter(){ entered++; },
      leave(){ left++; },
      navState(){ return {screen: "index"}; },
    };
    let pushed = [];
    function pushNav(state){ pushed.push(state); }
    """ + deps + """
    setView("jobs");             // real navigation, not Security: pushes {view:"jobs"}
    setView("security");         // real navigation, into Security: enter() once, pushes the composed sec
    setView("overview", true);   // restore, leaving Security: leave() but no push
    setView("security", true);   // restore, back into Security: enter() must NOT run again, no push
    console.log(JSON.stringify({pushed, entered, left, currentView}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["pushed"] == [{"view": "jobs"}, {"view": "security", "sec": {"screen": "index"}}], out["pushed"]
    assert out["entered"] == 1, (
        "CCSecurity.enter() must run for the ONE real navigation into Security "
        f"and be skipped for the restore back into it: {out}"
    )
    # leave() is unconditional on "the new view is not Security" -- it runs on
    # BOTH of the two calls that land somewhere else (#1 into "jobs", #3 the
    # restore into "overview"), fromHistory or not; only enter() is gated.
    assert out["left"] == 2, out
    assert out["currentView"] == "security"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_restore_nav_applies_state_without_pushing_and_a_dropped_flag_would_loop(srv, tmp_path):
    """The classic bug this router exists to avoid, spelled out in bin/
    dashboard.html's own comment: if a popstate handler ever pushed the state
    it is restoring, Back would land on a NEW entry identical to the one just
    left, and the next Back would re-land on THAT instead of moving further
    back -- a loop, one press deep, that never reaches the page a reader is
    actually trying to leave to.

    Falsifiability, concretely: the second call below is not a hypothetical
    mutant description, it is the literal call graph restoreNav's own
    `setView(state.view, true)` degenerates into if that `true` is ever
    dropped -- `setView(state.view)`. Driving both through the SAME real
    extracted functions proves the guard is load-bearing, not vacuous: remove
    the assertion on afterMutant and this test would still pass with the flag
    silently gone."""
    js = _js(srv)
    deps = "\n".join(_plainfn(js, n) for n in ("currentNavState", "setView", "restoreNav"))
    script = tmp_path / "restorenav.js"
    script.write_text("""
    const VIEWS = ["overview","jobs","runs","projects","security"];
    let currentView = "overview";
    const localStorage = {};
    class FakeEl { constructor(){ this.hidden = false; this.dataset = {}; this.classList = { toggle(){} }; } }
    const _els = {};
    function $(id){ if(!_els[id]) _els[id] = new FakeEl(); return _els[id]; }
    const document = { querySelectorAll: () => [] };
    function closeDrawer(){}
    function render(){}
    const CCSecurity = { enter(){}, leave(){}, navState(){ return {screen: "index"}; }, navigate(){} };
    let pushed = [];
    function pushNav(state){ pushed.push(state); }
    """ + deps + """
    // The real path: a popstate event handing the browser's own remembered
    // state back to restoreNav.
    restoreNav({view: "jobs"});
    const afterRealRestore = pushed.length;
    // The mutant restoreNav's own `true` exists to prevent.
    setView("overview");
    const afterMutant = pushed.length;
    console.log(JSON.stringify({afterRealRestore, afterMutant, currentView}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["afterRealRestore"] == 0, "restoreNav must not push the state it is restoring"
    assert out["currentView"] == "overview"
    assert out["afterMutant"] == 1, (
        "dropping restoreNav's own `true` is exactly what would make a restore "
        f"push -- if this is 0 too, the flag has stopped doing anything: {out}"
    )


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_boot_replaces_history_and_never_pushes_or_calls_securitys_enter(srv, tmp_path):
    """Boot (initViews) is a restore of its own kind -- the reader did not
    navigate to open the tab -- so it REPLACES the tab's very first entry and
    must never push. For a Security boot specifically it must also never call
    CCSecurity.enter(): cold boot is deterministically the index screen
    (ui/security/state.js's secState starts fresh on every load), and
    initViews calls CCSecurity.navigate({screen:"index"}) directly instead --
    enter()'s own guess is not just unnecessary here but wrong the instant a
    future change gives Security any cross-reload memory. CCSecurity.enter()
    is wired to THROW below specifically to make that regression loud rather
    than silently wrong."""
    js = _js(srv)
    deps = "\n".join(_plainfn(js, n) for n in ("currentNavState", "setView", "initViews"))
    script = tmp_path / "boot-router.js"
    script.write_text("""
    const VIEWS = ["overview","jobs","runs","projects","security"];
    let currentView;
    const localStorage = {};
    class FakeEl { constructor(){ this.hidden = false; this.dataset = {}; this.classList = { toggle(){} }; } }
    const _els = {};
    function $(id){ if(!_els[id]) _els[id] = new FakeEl(); return _els[id]; }
    const document = { querySelectorAll: () => [] };
    function closeDrawer(){}
    function render(){}
    let pushed = [], replaced = [], navigated = [];
    function pushNav(state){ pushed.push(state); }
    const location = { href: "http://127.0.0.1:8787/" };
    const history = { replaceState(state){ replaced.push(state); } };
    const CCSecurity = {
      enter(){ throw new Error("CCSecurity.enter() must never run during boot"); },
      leave(){},
      navState(){ return {screen: "index"}; },
      navigate(sec){ navigated.push(sec); },
    };
    """ + deps + """
    currentView = "jobs";
    initViews();
    const afterPlainBoot = {pushed: pushed.slice(), replaced: replaced.slice(),
                             navigated: navigated.slice(), currentView};
    pushed = []; replaced = []; navigated = [];
    currentView = "security";
    initViews();
    const afterSecurityBoot = {pushed: pushed.slice(), replaced: replaced.slice(),
                                navigated: navigated.slice(), currentView};
    console.log(JSON.stringify({afterPlainBoot, afterSecurityBoot}));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    plain, sec = out["afterPlainBoot"], out["afterSecurityBoot"]
    assert plain == {"pushed": [], "replaced": [{"view": "jobs"}], "navigated": [], "currentView": "jobs"}, plain
    assert sec == {"pushed": [], "replaced": [{"view": "security", "sec": {"screen": "index"}}],
                   "navigated": [{"screen": "index"}], "currentView": "security"}, sec


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_sec_navigate_composes_the_right_screen_and_avoids_reopening_what_is_already_on_screen(srv, tmp_path):
    """CCSecurity.navState()/navigate() (ui/security/index.js) are the bridge
    a restore actually calls. Real extracted logic, small honest stand-ins
    for every screen function it calls out to (secOpenProject and friends) --
    this is about the DECISION (open fresh vs. just switch tab, and the
    unknown-project fallback), not about their own fetches, which the rest of
    this suite already covers close to where they live."""
    block = _security_js(srv)
    deps = "\n".join(_anyfn(block, n) for n in ("secNavigate",)) + "\n" + _plainfn(block, "secNavState")
    script = tmp_path / "sec-navigate.js"
    script.write_text("""
    let secState = {project: ""};
    let secActOpenFlag = false, secActProject = "", secActTab = "", projTab = "overview";
    let calls = [];
    function secIsActivityOpen(){ return secActOpenFlag; }
    function secActNavState(){ return {project: secActProject, tab: secActTab}; }
    function secCurrentProjectTab(){ return projTab; }
    function projById(name){ return ["alpha", "beta"].includes(name) ? {name} : null; }
    async function secOpenProject(name, fromHistory){
      calls.push(["open", name, fromHistory]); secState.project = name; projTab = "overview";
    }
    function secSwitchProjectTab(tab, fromHistory){
      calls.push(["tab", tab, fromHistory]); projTab = tab;
    }
    async function secOpenActivity(project, fromHistory){
      calls.push(["actopen", project, fromHistory]);
      secActOpenFlag = true; secActProject = project; secActTab = "";
    }
    function secActSwitchTab(key, fromHistory){
      calls.push(["acttab", key, fromHistory]); secActTab = key;
    }
    function secBack(fromHistory){ calls.push(["back", fromHistory]); secState.project = ""; }
    function secBackFromActivity(fromHistory){ calls.push(["actback", fromHistory]); secActOpenFlag = false; }
    """ + deps + """
    (async () => {
      const results = {freshIndex: secNavState()};

      await secNavigate({screen: "project", project: "alpha", tab: "findings"});
      results.openAlpha = {calls: calls.slice(), state: secNavState()};
      calls = [];

      // Same project, different tab -- must switch, must NOT reopen.
      await secNavigate({screen: "project", project: "alpha", tab: "reports"});
      results.sameProjectDifferentTab = {calls: calls.slice(), state: secNavState()};
      calls = [];

      // A project the fleet no longer lists -- falls back to the index.
      await secNavigate({screen: "project", project: "ghost", tab: "overview"});
      results.unknownProject = {calls: calls.slice(), state: secNavState()};
      calls = [];

      await secNavigate({screen: "activity", project: "beta", tab: "findings"});
      results.openActivity = {calls: calls.slice(), state: secNavState()};
      calls = [];

      // Same activity scope, different tab -- must switch, must NOT reopen.
      await secNavigate({screen: "activity", project: "beta", tab: "settings"});
      results.sameActivityDifferentTab = {calls: calls.slice(), state: secNavState()};
      calls = [];

      console.log(JSON.stringify(results));
    })();
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["freshIndex"] == {"screen": "index"}, out["freshIndex"]

    assert out["openAlpha"]["calls"] == [["open", "alpha", True], ["tab", "findings", True]], out["openAlpha"]
    assert out["openAlpha"]["state"] == {"screen": "project", "project": "alpha", "tab": "findings"}

    assert out["sameProjectDifferentTab"]["calls"] == [["tab", "reports", True]], \
        f"already on this project -- must not reopen it: {out['sameProjectDifferentTab']}"
    assert out["sameProjectDifferentTab"]["state"] == {"screen": "project", "project": "alpha", "tab": "reports"}

    assert out["unknownProject"]["calls"] == [["back", True]], (
        f"a project the fleet no longer lists must fall back to the index, "
        f"not open it anyway: {out['unknownProject']}"
    )
    assert out["unknownProject"]["state"] == {"screen": "index"}

    assert out["openActivity"]["calls"] == [["actopen", "beta", True], ["acttab", "findings", True]]
    assert out["openActivity"]["state"] == {"screen": "activity", "project": "beta", "tab": "findings"}

    assert out["sameActivityDifferentTab"]["calls"] == [["acttab", "settings", True]], (
        f"already scoped to this project's activity -- must not reopen it: "
        f"{out['sameActivityDifferentTab']}"
    )
    assert out["sameActivityDifferentTab"]["state"] == {"screen": "activity", "project": "beta", "tab": "settings"}


def test_every_security_navigation_point_pushes_its_own_resulting_screen_unless_told_not_to(srv):
    """Text-level pin (these are fetch-heavy screen functions; a full
    behavioural drive of all six would need a network mock disproportionate
    to what is being pinned here): every one of the six navigation points
    bin/dashboard.html's router comment names calls pushNav with the state
    IT resulted in, guarded by `!fromHistory` -- never unconditionally,
    never with some other screen's shape."""
    block = _security_js(srv)
    checks = [
        (_plainfn(block, "secBack"), '{screen: "index"}'),
        (_anyfn(block, "secOpenProject"),
         '{screen: "project", project: name, tab: secProjectTab}'),
        (_plainfn(block, "secSwitchProjectTab"),
         '{screen: "project", project: secState.project, tab: secProjectTab}'),
        (_anyfn(block, "secOpenActivity"),
         '{screen: "activity", project: secActState.project, tab: secActState.tab}'),
        (_plainfn(block, "secBackFromActivity"), '{screen: "index"}'),
        (_plainfn(block, "secActSwitchTab"),
         '{screen: "activity", project: secActState.project, tab: secActState.tab}'),
    ]
    for body, needle in checks:
        norm = _norm(body)
        assert "if(!fromHistory) pushNav({view: \"security\", sec:" in norm, (
            f"not guarded by fromHistory, or not calling pushNav at all: {body}")
        assert needle in norm, f"pushed the wrong state shape -- expected {needle!r} in: {body}"


def test_compound_navigations_suppress_every_step_but_the_last(srv):
    """One click, one history entry: a navigation function reused purely for
    its teardown (secOpenActivity reusing secBack's own; the two chained
    "jump straight to a tab" buttons; the Activity table's own deep link into
    an analysis) must suppress every call but the one that pushes the screen
    the click actually ends up showing -- see bin/dashboard.html's router
    comment on why, and each call site's own comment for which one that is."""
    block = _security_js(srv)

    open_activity_body = _anyfn(block, "secOpenActivity")
    assert "secBack(true)" in open_activity_body, (
        "secOpenActivity must suppress its own teardown call into secBack -- "
        f"otherwise opening Activity pushes a phantom \"index\" entry first: {open_activity_body}"
    )

    open_analysis_body = _anyfn(block, "secActOpenAnalysis")
    assert "secBackFromActivity(true)" in open_analysis_body, open_analysis_body
    assert "secOpenProject(project, true)" in open_analysis_body, open_analysis_body
    # The chain's own last call, secSwitchProjectTab("runs"), is deliberately
    # NOT suppressed -- it is the one real destination this whole click has.
    assert "secSwitchProjectTab(\"runs\");" in open_analysis_body, open_analysis_body

    index_screen_js = (UI_ROOT / "security" / "index-screen.js").read_text()
    assert 'secOpenActivity("", true); secActSwitchTab("analyses"); ' in _norm(index_screen_js), (
        "secViewAllAnalysesButton must suppress secOpenActivity's own push -- "
        "\"All activity\" is not the tab this button's click ends up showing"
    )
    assert 'secOpenProject(latest.project, true); secSwitchProjectTab("reports"); ' in _norm(index_screen_js), (
        "secViewFullReportButton must suppress secOpenProject's own push -- "
        "\"overview\" is not the tab this button's click ends up showing"
    )


def test_the_activity_and_index_back_buttons_are_wrapped_not_passed_bare(srv):
    """secBack/secBackFromActivity now take a `fromHistory` parameter --
    addEventListener hands its listener the click's own Event object as the
    first argument, so a BARE function reference here would read that Event
    as `fromHistory` and read truthy, silently suppressing the button's own
    history push on every real click. Both must be wrapped in a
    zero-argument arrow instead."""
    index_js = (UI_ROOT / "security" / "index.js").read_text()
    assert '.addEventListener("click", secBack)' not in index_js, (
        "sec-back's listener is passed bare -- the click Event would leak "
        "into secBack's own fromHistory parameter"
    )
    assert '.addEventListener("click", secBackFromActivity)' not in index_js, (
        "sec-act-back's listener is passed bare -- the click Event would leak "
        "into secBackFromActivity's own fromHistory parameter"
    )
    assert '.addEventListener("click", () => secBack())' in index_js
    assert '.addEventListener("click", () => secBackFromActivity())' in index_js


def test_every_menu_popover_ships_hidden(srv):
    """A popover that is in the page from the first paint but carries no
    `hidden` attribute reads as OPEN to anything asking `:not([hidden])`.

    #sec-run-filterpop shipped exactly like that: it sits inside a closed
    <details>, so nobody could see it, and its `hidden` is only ever written
    by that element's own ontoggle -- which never fires until the filter is
    opened by hand. renderOverviewJobs() skips its repaint while a menu is
    open, so on every install where the Security page had been built the
    Overview's job cards were never drawn at all. Eight jobs, an empty
    column, and nothing in the console.

    Every sibling popover in that same bar already ships `hidden`; this pins
    the whole class rather than the one element, because the cost of
    forgetting is a screenful of jobs that silently stops rendering."""
    page = _page(srv)
    tags = re.findall(r'<div[^>]*class="menu-pop[^"]*"[^>]*>', page)
    assert tags, "no .menu-pop in the page — this test is watching nothing"
    naked = [t for t in tags if not re.search(r"(?<![-\w])hidden(?![-\w])", t)]
    assert not naked, (
        "these popovers ship without `hidden`, so they read as open menus and "
        "stall the Overview repaint: " + "; ".join(naked))


def test_the_overview_repaint_guard_asks_whether_a_menu_is_on_screen(srv, tmp_path):
    """The guard must skip the repaint for a menu that is really on screen and
    only for that one.

    Two failure modes, one on each side, and both have a real cost:
      * testing the ABSENCE of `hidden` (what shipped) counts a popover hidden
        by any other means -- a closed <details>, a `display:none` -- as open,
        and the job cards then never render at all;
      * testing `offsetParent` instead would miss a genuinely open menu, which
        positions itself `position:fixed`, and the repaint would snatch it away
        mid-reach -- the very thing the guard exists to prevent.

    getClientRects() is the test that separates them, so the four cases below
    are asserted together: no menus, a popover in a closed <details>, one
    carrying `hidden`, and one actually open."""
    src = _plainfn(_js(srv), "renderOverviewJobs")
    m = re.search(r"const menuOpen\s*=.*?;\n", src, re.S)
    assert m, ("renderOverviewJobs no longer computes `menuOpen` — if the guard went "
               "back to a bare `.menu-pop:not([hidden])` query, that is the bug this "
               "test exists for; if it was renamed, update this test with it")
    script = tmp_path / "overview-menu-guard.js"
    script.write_text("""
// One fake popover per case: `hidden` is the attribute, `rects` is whether the
// browser lays it out at all (false for display:none and for a closed <details>).
function fakeDoc(pops){
  return {querySelectorAll(sel){
    const onlyVisibleAttr = sel.includes(":not([hidden])");
    return pops.filter(p => !(onlyVisibleAttr && p.hidden))
               .map(p => ({getClientRects: () => (p.rects ? [{}] : [])}));
  }};
}
const CASES = {
  noMenus:       [],
  closedDetails: [{hidden: false, rects: false}],
  hiddenAttr:    [{hidden: true,  rects: false}],
  openMenu:      [{hidden: false, rects: true}],
};
const out = {};
for(const [name, pops] of Object.entries(CASES)){
  const document = fakeDoc(pops);
""" + m.group(0) + """
  out[name] = menuOpen;
}
console.log(JSON.stringify(out));
""")
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["openMenu"] is True, (
        "a menu that is on screen no longer stops the repaint — it will be snatched "
        "away mid-reach")
    assert got["closedDetails"] is False, (
        "a popover inside a closed <details> still counts as an open menu, so the "
        "Overview will render no job cards")
    assert got["hiddenAttr"] is False, "a `hidden` popover counts as an open menu"
    assert got["noMenus"] is False, "the guard fires with no menus in the page at all"


def test_the_cause_badge_explains_itself_on_hover(srv, tmp_path):
    """The badge is a 30px pill saying "API" or "limit" — useless without the
    sentence behind it, which is why the CSS gives it `cursor:help`.

    It carried that sentence in a `title`, and a native tooltip needs the
    pointer to dwell for about a second before the browser draws it. This is a
    table that repaints every 5 seconds, so on a badge that size the dwell
    rarely completes: the cursor turned into a question mark and nothing ever
    appeared — a promise the page could not keep. The page's own bubble
    (tipShow, wired to a delegated mouseover on `[data-tip]`) shows on hover
    with no dwell and cannot be clipped by an ancestor, so the badge uses that.
    """
    js = _app_js(srv)
    fn = _plainfn(js, "causeTag")
    assert "dataset.tip" in fn, (
        "causeTag no longer sets data-tip, so the badge's explanation is back to a "
        "native tooltip the pointer rarely dwells long enough to trigger")
    assert ".title" not in fn, (
        "causeTag sets a `title` as well — the browser then draws its own tooltip "
        "over the page's bubble a second later")

    labels = re.search(r"const CAUSE_LABEL=\{.*?\n\};", js, re.S)
    assert labels, "CAUSE_LABEL moved — update this test with it"
    script = tmp_path / "causetag.js"
    script.write_text("""
function el(tag, cls, text){ return {tag, className: cls, textContent: text, dataset: {}}; }
""" + labels.group(0) + "\n" + fn + """
const out = {};
for(const cause of Object.keys(CAUSE_LABEL)){
  const t = causeTag({cause});
  out[cause] = {label: t.textContent, tip: decodeURIComponent(t.dataset.tip || "")};
}
out.unknown = causeTag({cause: "something-new"});
out.none = causeTag({});
console.log(JSON.stringify(out));
""")
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["none"] is None, "a run with no cause still gets a badge"
    assert got["unknown"] is None, "an unrecognised cause invents a badge with no text"
    for cause, seen in got.items():
        if cause in ("none", "unknown"):
            continue
        assert seen["label"], f"{cause} has no badge text"
        assert len(seen["tip"]) > 20, (
            f"{cause}'s badge carries no explanation — the whole point of the pill "
            f"is that the sentence is one hover away")
    assert "the provider's fault" in got["api_error"]["tip"], (
        "the API badge no longer says whose fault it is, which is what tells the "
        "operator to wait rather than go and look")


def test_a_start_keeps_its_button_down_until_the_run_appears(srv, tmp_path):
    """A click has to stay committed until the run it started is visible.

    The server answers a start as soon as `cc(..., background=True)` has
    forked; the slot, and therefore the row, appear on a later poll. Handing
    the button back in between is how one reviewer job ended up with two
    sessions cut short on the SAME port block — two runs from two clicks, the
    first dying and releasing block 21000, the second taking it back, and
    neither resumable while the other was going.

    The four things that must all hold: down while in flight, back up when the
    run lands, back up after the grace period if nothing ever lands (or the
    only way to run the job again is a page reload), and — for a resume —
    keyed by session, so a job's other Resume buttons stay usable."""
    js = _js(srv)
    state = re.search(r"const starting=new Map\(\);.*?const START_GRACE_S=\d+;", js, re.S)
    assert state, "the pending-start state moved — update this test with it"
    script = tmp_path / "pending-starts.js"
    script.write_text("""
// Stubs for the two live-slot readers isStarting consults.
let SLOTS = {};
function activeRunsOf(id){ return SLOTS[id] || []; }
function resumeInFlight(id, sid){ return activeRunsOf(id).some(a => a.resume_of === sid); }
let NOW = 1000;
const _realNow = Date.now;
Date.now = () => NOW * 1000;
""" + state.group(0) + "\n"
   + _plainfn(js, "startKey") + "\n"
   + _plainfn(js, "markStarting") + "\n"
   + _plainfn(js, "isStarting") + """
const out = {};

// A job already running one thing; the click must not be cleared by that.
SLOTS = {rev: [{pid: 111}]};
markStarting("rev");
out.downWhileForking = isStarting("rev");
SLOTS = {rev: [{pid: 111}]};                 // still only the old slot
out.stillDownWithOnlyTheOldRun = isStarting("rev");
SLOTS = {rev: [{pid: 111}, {pid: 222}]};     // the started run appears
out.upWhenTheRunLands = isStarting("rev");

// Nothing ever lands: the button has to come back on its own.
SLOTS = {dev: []};
markStarting("dev");
out.downBeforeGrace = isStarting("dev");
NOW += START_GRACE_S + 1;
out.upAfterGrace = isStarting("dev");
NOW = 1000;

// Two Resume buttons on one card: only the clicked one goes down.
SLOTS = {rev: []};
markStarting("rev", "sid-A");
out.resumeAdown = isStarting("rev", "sid-A");
out.resumeBstillUp = isStarting("rev", "sid-B");
SLOTS = {rev: [{pid: 333, resume_of: "sid-A"}]};
out.resumeAupWhenItLands = isStarting("rev", "sid-A");

// A run and a resume of the same job are tracked apart.
SLOTS = {promo: []};
markStarting("promo");
markStarting("promo", "sid-C");
SLOTS = {promo: [{pid: 444, resume_of: "sid-C"}]};
out.resumeLandedButRunStillPending = [isStarting("promo", "sid-C"), isStarting("promo")];

Date.now = _realNow;
console.log(JSON.stringify(out));
""")
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["downWhileForking"] is True, "the button is live while the run is still forking"
    assert got["stillDownWithOnlyTheOldRun"] is True, (
        "a run the job already had before the click cleared the pending state — at "
        "max_parallel > 1 that clears it instantly and the guard buys nothing")
    assert got["upWhenTheRunLands"] is False, "the button never comes back once the run appears"
    assert got["downBeforeGrace"] is True
    assert got["upAfterGrace"] is False, (
        "a start that never landed strands its button — a page reload becomes the "
        "only way to run the job again")
    assert got["resumeAdown"] is True
    assert got["resumeBstillUp"] is False, (
        "resuming one session disabled another session's Resume button on the same card")
    assert got["resumeAupWhenItLands"] is False
    assert got["resumeLandedButRunStillPending"] == [False, True], (
        "a run and a resume of one job are not tracked apart")


def test_the_start_path_does_not_hand_the_button_straight_back(srv):
    """The success branch must not re-enable the button: that is the window a
    second click landed in. Pinned as source, because the failure is invisible
    in any single render — it is the two lines running in the wrong order."""
    js = _js(srv)
    i = js.index('toast("Started "+id, false, "play");')
    branch = js[i:i + 400]
    assert "markStarting(id)" in branch, (
        "a successful start no longer records itself as pending, so the next repaint "
        "hands the button back before the run exists")
    assert "b.disabled=false" not in branch, (
        "the success path re-enables the button while the run is still forking — "
        "this is exactly the double-click window")


def test_the_pending_start_is_committed_at_the_click_not_at_the_start(srv):
    """`b.disabled` holds one element; the repaint replaces it.

    "Run now" awaits a precheck fetch before it ever posts the run, and can sit
    on a showConfirm on top of that. Every 5-second poll during that rebuilds
    the card, and the replacement button is born enabled — so recording the
    pending state only after the run POST succeeded left the whole precheck
    window open. Measured against a 4-second precheck: the button came back
    live mid-probe and TWO run POSTs left the page.

    So markStarting has to be called on the click, before anything is awaited,
    and every path that then decides NOT to start must clear it — otherwise a
    declined precheck would leave the button dead for the full grace period."""
    js = _js(srv)
    i_handler = js.index('const b=e.target.closest("button[data-op]")')
    handler = js[i_handler:i_handler + 6000]

    i_mark = handler.index("markStarting(id, b.dataset.session")
    i_precheck = handler.index('op:"precheck"')
    assert i_mark < i_precheck, (
        "the start is recorded after the precheck fetch, so a repaint during the probe "
        "hands the button back and a second click starts a second run")

    # Every give-up path lets go again: the two precheck confirms, and the
    # refusal/failure exits of both run and resume.
    gives_up = [seg for seg in handler.split("\n")
                if "b.disabled=false" in seg and "clearStarting" not in seg]
    assert not gives_up, (
        "these paths re-enable the button without dropping the pending start, so it is "
        "re-disabled on the next repaint and stays dead for the grace period: "
        + " | ".join(s.strip()[:90] for s in gives_up))


def test_giving_up_hands_the_button_back_without_waiting_for_a_repaint(srv, tmp_path):
    """Dropping the map entry is not enough. A poll can land while the confirm
    dialog is open, and markIfStarting() disables the replacement button as it
    that very repaint — with nothing to re-enable it until the next one. The
    operator answers "no" and the button is dead for up to five seconds.

    So clearStarting re-enables what is in the page now, matched the same way
    markIfStarting() disables it: same job, same session."""
    fn = _plainfn(_js(srv), "clearStarting")
    assert "querySelectorAll" in fn, (
        "clearStarting only drops the map entry — the button already replaced by a "
        "repaint stays disabled until the next poll")
    script = tmp_path / "clear-starting.js"
    script.write_text("""
const BUTTONS = [
  {dataset: {op: "run",    id: "rev"},                    disabled: true, tag: "run:rev"},
  {dataset: {op: "run",    id: "dev"},                    disabled: true, tag: "run:dev"},
  {dataset: {op: "resume", id: "rev", session: "sid-A"},  disabled: true, tag: "res:rev:A"},
  {dataset: {op: "resume", id: "rev", session: "sid-B"},  disabled: true, tag: "res:rev:B"},
];
const starting = new Map();
function startKey(id, sid){ return sid ? id+"|"+sid : id; }
const document = { querySelectorAll: () => BUTTONS };
""" + fn + """
const out = {};
// A plain run: only that job's Run now comes back, and no Resume of the same job.
starting.set("rev", {});
clearStarting("rev");
out.afterRunClear = BUTTONS.filter(b => !b.disabled).map(b => b.tag);
BUTTONS.forEach(b => { b.disabled = true; });
// A resume: only the clicked session's button, not the job's other one.
starting.set("rev|sid-A", {});
clearStarting("rev", "sid-A");
out.afterResumeClear = BUTTONS.filter(b => !b.disabled).map(b => b.tag);
out.entryDropped = !starting.has("rev|sid-A");
console.log(JSON.stringify(out));
""")
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["afterRunClear"] == ["run:rev"], (
        "clearing a run re-enabled the wrong buttons: " + repr(got["afterRunClear"]))
    assert got["afterResumeClear"] == ["res:rev:A"], (
        "clearing one resume re-enabled another session's button: "
        + repr(got["afterResumeClear"]))
    assert got["entryDropped"] is True


def test_every_run_and_resume_button_asks_about_the_pending_start_as_it_is_built(srv):
    """render() is not the only thing that rebuilds these buttons.

    A keystroke in the jobs search box, a column sort, a page change, a project
    or status pick, a filter chip, a favourite toggle — fourteen paths in all —
    call renderJobsArea() or CCApp.renderRunsPage() directly and never reach
    render(). The first cut of the pending-start guard was re-applied from the
    last line of render(), so every one of those paths minted a fresh, enabled
    Run now / Resume and handed the second click straight through: typing one
    character while a start was in flight was enough to start a second run.

    `isStopping` and `resumeInFlight` never had that hole, because the row
    builder consults them as it builds. This pins that every builder of a
    `data-op="run"`/`"resume"` button does the same, so there is no repaint path
    left to forget — the guard cannot be defeated by a rebuild that does not
    know about it."""
    builders = {}
    for path in sorted(APP_ROOT.rglob("*.js")):
        src = path.read_text()
        for m in re.finditer(r'dataset\.op\s*=\s*"(run|resume)"', src):
            # The call has to be near the button it guards, not merely somewhere
            # in the file: a builder that sets data-op and never asks is the bug.
            window = src[m.start():m.start() + 700]
            builders.setdefault(f"{path.name}:{m.group(1)}@{src[:m.start()].count(chr(10)) + 1}",
                                "markIfStarting" in window)
    assert builders, "no run/resume button builders found — this test is watching nothing"
    missing = [k for k, ok in builders.items() if not ok]
    assert not missing, (
        "these buttons are built without asking whether a start is pending, so any "
        "repaint that does not go through render() hands them back live: "
        + ", ".join(missing))

    # And it has to actually reach them: declared on the interface, bound, imported.
    page = (APP_ROOT / "page.js").read_text()
    assert page.count("markIfStarting") >= 2, (
        "markIfStarting is not both declared and bound in page.js, so the builders "
        "would be calling an undefined import")
    for name in sorted({k.split(":")[0] for k in builders}):
        src = (APP_ROOT / name).read_text()
        assert re.search(r'import\s*\{[^}]*markIfStarting[^}]*\}\s*from\s*"\./page\.js"', src, re.S), (
            f"{name} calls markIfStarting without importing it")
