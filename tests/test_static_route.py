"""The one route that serves a file off disk.

Everything else this server answers is either JSON it built or the page it
rendered. This route hands back bytes named by the request, which is the shape
every directory-traversal bug has ever had -- so the refusals are tested before
the success is.
"""


def test_the_bundle_is_served_as_javascript(srv):
    body, ctype = srv.static_asset("security.js")
    assert ctype.startswith("application/javascript")
    assert body


def test_a_traversing_path_is_refused(srv):
    """The one thing a static route must never do."""
    for bad in ("../claude-cron-server", "..%2Fclaude-cron-server",
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
