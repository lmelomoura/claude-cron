"""The one route that serves a file off disk.

Everything else this server answers is either JSON it built or the page it
rendered. This route hands back bytes named by the request, which is the shape
every directory-traversal bug has ever had -- so the refusals are tested before
the success is.
"""

import re


def test_the_bundle_is_served_as_javascript(srv):
    body, ctype = srv.static_asset("security.js")
    assert ctype.startswith("application/javascript")
    assert body


def test_a_traversing_path_is_refused(srv):
    """The one thing a static route must never do."""
    for bad in ("../agentloop-server", "..%2Fagentloop-server",
                "sub/dir.js", "/etc/passwd"):
        assert srv.static_asset(bad) == (None, None)


def test_an_unknown_asset_is_a_miss_not_a_crash(srv):
    assert srv.static_asset("nope.js") == (None, None)


def test_an_unknown_extension_is_refused_even_when_the_file_is_there(
        srv, tmp_path, monkeypatch):
    """The allowlist is the extension, not the name. `static_asset` reads a file
    and hands it to a browser with a Content-Type this table chose; a suffix the
    table does not know has no answer to what that type should be, and guessing
    one is how a static route starts serving things it was never meant to.

    Points STATIC_DIR at tmp_path rather than writing into the repo's own
    bin/static/: that directory is tracked, and an interrupted run used to
    leave an untracked file sitting in it."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    (tmp_path / "notes.txt").write_text("not for the browser")
    assert srv.static_asset("notes.txt") == (None, None)


def test_a_name_too_long_for_the_filesystem_is_a_miss_not_a_crash(
        srv, tmp_path, monkeypatch):
    """`path.is_file()` used to sit OUTSIDE the try around this route, and
    ENAMETOOLONG is not one of the errnos pathlib swallows on its own: a name
    past the filesystem's limit raised OSError straight out of `static_asset`.
    Confirmed live: `GET /static/<300 a's>.js` produced a server traceback and
    a dropped connection with no HTTP response at all -- not a 404. `.js`
    keeps the name inside the extension allowlist so the crash, not the
    allowlist, is what this proves."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    assert srv.static_asset("a" * 300 + ".js") == (None, None)


def test_a_non_utf8_asset_is_a_miss_not_a_crash(srv, tmp_path, monkeypatch):
    """`read_text()` raises UnicodeDecodeError -- a ValueError, not an OSError --
    on a file that is not valid UTF-8, and only OSError was ever caught around
    it. A stray binary asset, or one saved with the wrong encoding, crashed
    this route instead of simply not being served."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    (tmp_path / "bad.js").write_bytes(b"\xff\xfe not utf8 \x80\x81")
    assert srv.static_asset("bad.js") == (None, None)


def test_a_symlink_inside_static_dir_is_refused(srv, tmp_path, monkeypatch):
    """`x.js -> /etc/passwd` would otherwise be followed and handed back as
    application/javascript. It needs write access to a tracked directory, so
    it is not a practical vector today -- but the belt is cheap: the resolved
    path has to stay inside the resolved STATIC_DIR, not just satisfy the
    single-segment name check that a symlink's own name passes fine."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    outside = tmp_path.parent / "secret_outside.txt"
    outside.write_text("top secret")
    (tmp_path / "x.js").symlink_to(outside)
    assert srv.static_asset("x.js") == (None, None)


def test_the_bundle_is_reachable_without_signing_in(srv):
    """The login card is drawn by the same page the dashboard is, and the page
    cannot load its own code from behind the gate that the code is what asks to
    pass. Gating this route would leave a signed-out browser holding a page with
    half its JavaScript missing -- and the bundle is not a secret: it is the
    same file every install ships in git."""
    import inspect
    src = inspect.getsource(srv.Handler.do_GET)
    static_at = src.index('path.startswith("/static/")')
    gate_at = src.index('path.startswith("/api/")')
    assert static_at < gate_at, \
        "the /static/ route sits behind the session gate -- the login screen " \
        "cannot load the code that draws it"


def test_the_build_id_moves_when_a_served_stylesheet_changes(
        srv, tmp_path, monkeypatch):
    """`_build_id` used to glob "*.js" alone. The page asks for every asset
    with `?v=<build id>` on it, so an id that cannot see a stylesheet serves
    a changed one out of an open tab's cache indefinitely -- the exact
    failure the id was added to prevent for the JS bundle.

    Driven through the same table that decides what this directory is
    allowed to serve: anything servable has to be fingerprinted, or the two
    disagree and the gap is a cache that never clears."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    (tmp_path / "app.css").write_text(":root{--bg:#fff}")
    before = srv._build_id()
    (tmp_path / "app.css").write_text(":root{--bg:#000}")
    assert srv._build_id() != before, (
        "a changed stylesheet left the build id untouched -- "
        "browsers will keep serving the old one from cache"
    )


def _versioned_css_link(page):
    m = re.search(r'app\.css\?v=([0-9a-f]+)', page)
    assert m, "no versioned app.css link found in the rendered page"
    return m.group(1)


def test_the_build_id_follows_disk_state_per_request_without_restarting(
        srv, tmp_path, monkeypatch):
    """F4: `_build_id()` used to run exactly once, at import, into a
    module-level BUILD -- so a `git pull` (simulated here as any edit to a
    servable file) landing under a running server left every later page load
    stamping `?v=` with the OLD id. Browsers then kept the stale cached
    bundle against markup that had just changed underneath it, fixable only
    by finding and restarting the process.

    current_build_id() replaces that fixed value with a cache that is
    cheap to CHECK (a stat() per tracked file, every render_page() call) and
    expensive only to REFRESH (a real sha256 over full file contents, only
    when that stat says something moved). This pins both halves at once: an
    unchanged tree serves the identical id and the real hash runs exactly
    once across two renders; a changed file moves the id on the very next
    render -- and nothing here restarts anything. Same `srv` module, same
    process, same import throughout -- only the bytes on disk change between
    calls, exactly what a `git pull` under a live server looks like from
    this function's own point of view."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    # A fresh cache: other tests may have already primed the real one against
    # the real STATIC_DIR, and this test's own assertions must not depend on
    # whatever they left behind.
    monkeypatch.setattr(srv, "_build_cache", {"stat": None, "id": None})
    (tmp_path / "app.css").write_text(":root{--bg:#fff}")

    real_build_id = srv._build_id
    calls = []

    def counting_build_id():
        calls.append(1)
        return real_build_id()
    monkeypatch.setattr(srv, "_build_id", counting_build_id)

    first = _versioned_css_link(srv.render_page())
    second = _versioned_css_link(srv.render_page())
    assert first == second, "an unchanged tree must serve the identical build id"
    assert len(calls) == 1, (
        f"the real content hash ran {len(calls)} times across two renders "
        "with nothing on disk changed -- current_build_id() must be serving "
        "the cache, not re-hashing on every request"
    )

    (tmp_path / "app.css").write_text(":root{--bg:#000}")
    third = _versioned_css_link(srv.render_page())
    assert third != first, (
        "a changed stylesheet must move the build id on the very next "
        "render -- serving the old one is exactly the stale-cache-after-a-"
        "pull bug this feature exists to close"
    )
    assert len(calls) == 2, "the changed file must trigger exactly one more real hash"


def test_api_data_reports_the_same_live_build_id_render_page_does(srv, clean_data, tmp_path, monkeypatch):
    """render_page() and load_data() (the /api/data poll body) used to share
    one module-level BUILD; current_build_id() is the one function both now
    call, so an ALREADY-OPEN tab's poll notices a change exactly when a fresh
    page load would -- see bin/dashboard.html's own `d.build !== BUILD`
    self-reload check for what reads this field."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    monkeypatch.setattr(srv, "_build_cache", {"stat": None, "id": None})
    (tmp_path / "app.css").write_text(":root{--bg:#fff}")

    before = srv.load_data()["build"]
    assert before == _versioned_css_link(srv.render_page())

    (tmp_path / "app.css").write_text(":root{--bg:#000}")
    after = srv.load_data()["build"]
    assert after != before, "the /api/data poll kept the old build id after a static file changed"
    assert after == _versioned_css_link(srv.render_page())


def test_every_servable_extension_is_fingerprinted(srv, tmp_path, monkeypatch):
    """Not "js and css" spelled out a second time: the fingerprint walks the
    same STATIC_TYPES table the route reads, so a third type added there is
    covered without anybody remembering to come back here."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    ids = set()
    for i, suffix in enumerate(sorted(srv.STATIC_TYPES)):
        (tmp_path / f"a{suffix}").write_text(f"/* {i} */")
        ids.add(srv._build_id())
    assert len(ids) == len(srv.STATIC_TYPES), (
        "adding a servable file did not always move the build id"
    )


def test_the_stylesheet_is_served_as_css(srv):
    body, ctype = srv.static_asset("app.css")
    assert ctype.startswith("text/css")
    assert ":root" in body, "the stylesheet reached the route without its tokens"
