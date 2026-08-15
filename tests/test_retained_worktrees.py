"""Run dirs the sweep decided to keep.

wt_teardown preserves a run dir whose session is marked `open`, or not marked
at all (a crash writes no marker either), and re-reaches that same conclusion
on every tick — so nothing ever releases it on its own. Until these were
listed they were invisible: disk filling up with no screen anywhere admitting
it.
"""

import os
import shutil


def _mk_run_dir(srv, job, stamp):
    d = srv.DATA_DIR / "worktrees" / job / stamp
    (d / "repo").mkdir(parents=True)
    return d


def _claim(srv, job, pid, run_dir):
    slot = srv.DATA_DIR / "locks" / job / str(pid)
    slot.mkdir(parents=True)
    (slot / "pid").write_text(str(pid))
    (slot / "worktree").write_text(str(run_dir))
    return slot


def test_no_worktrees_dir_is_not_an_error(clean_data):
    assert clean_data.retained_worktrees() == []


def test_an_unclaimed_run_dir_is_reported(clean_data):
    srv = clean_data
    d = _mk_run_dir(srv, "alpha", "20260726T120000Z-1")
    got = srv.retained_worktrees()
    assert len(got) == 1
    assert got[0]["job"] == "alpha"
    assert got[0]["stamp"] == "20260726T120000Z-1"
    assert got[0]["path"] == str(d)
    assert got[0]["age"] >= 0


def test_a_run_dir_a_live_run_is_using_is_not_listed(clean_data):
    """Those are not retained, they are in use — listing them would invite a
    drop that pulls the ground out from under a working agent."""
    srv = clean_data
    d = _mk_run_dir(srv, "beta", "stamp-live")
    _claim(srv, "beta", os.getpid(), d)
    assert srv.retained_worktrees() == []


def test_a_dir_claimed_by_a_dead_slot_is_retained(clean_data):
    """A crashed run leaves its slot behind; its dir is nobody's now."""
    srv = clean_data
    d = _mk_run_dir(srv, "gamma", "stamp-dead")
    dead = 99999
    while _alive(dead):
        dead -= 1
    _claim(srv, "gamma", dead, d)
    got = srv.retained_worktrees()
    assert [g["stamp"] for g in got] == ["stamp-dead"]


def test_the_repos_a_run_dir_holds_are_named(clean_data):
    srv = clean_data
    d = _mk_run_dir(srv, "delta", "s1")
    (d / "backend").mkdir()
    got = srv.retained_worktrees()[0]
    assert sorted(got["repos"]) == ["backend", "repo"]


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_an_open_session_reports_the_time_it_has_left(clean_data):
    """A kept directory that says nothing about when it goes is the old leak
    wearing a new label."""
    srv = clean_data
    d = _mk_run_dir(srv, "epsilon", "s-open")
    (d / ".ended").write_text("open\n")
    got = srv.retained_worktrees()[0]
    assert got["expires_in"] > 0


def test_a_closed_session_has_no_expiry_because_it_goes_next_sweep(clean_data):
    srv = clean_data
    d = _mk_run_dir(srv, "zeta", "s-done")
    (d / ".ended").write_text("done\n")
    got = srv.retained_worktrees()[0]
    assert got["expires_in"] is None


def test_a_dir_with_no_marker_at_all_is_also_on_the_clock(clean_data):
    """A kill -9 or a reboot writes no marker. The engine expires anything that
    is not `done`, so the dashboard has to agree — a directory it shows as
    permanent while the sweep is counting it down is a lie in the other
    direction."""
    srv = clean_data
    _mk_run_dir(srv, "eta", "s-unmarked")
    got = srv.retained_worktrees()[0]
    assert got["expires_in"] > 0


def test_the_countdown_uses_the_worktree_ttl_and_not_some_other_one(clean_data):
    """Pins the value, not just its sign. `SESSION_TTL` was already taken in
    this module by the HTTP sign-in idle timeout, and a second module-level
    assignment of that name loses silently — leaving the dashboard counting
    every kept directory down against an auth constant. Asserting `> 0` cannot
    see that; asserting the number can."""
    srv = clean_data
    d = _mk_run_dir(srv, "theta", "s-ttl")
    (d / ".ended").write_text("open\n")
    got = srv.retained_worktrees()[0]
    # Freshly created, so age is 0 or 1 second.
    assert srv.WORKTREE_SESSION_TTL - got["expires_in"] <= 2
    assert srv.WORKTREE_SESSION_TTL == 86400


# ---- .session: absent, empty and unreadable are three different things, and
# only the first of them means "no session" in the ordinary, nothing-went-
# wrong sense. See _session_bound_to's own docstring for why they must not
# collapse into one silently-swallowed "".

def test_a_run_dir_with_a_bound_session_reports_it(clean_data):
    srv = clean_data
    d = _mk_run_dir(srv, "iota", "s-sess")
    # bind_session's real write: a trailing newline, via mktemp + rename.
    (d / ".session").write_text("sess-abc123\n")
    got = srv.retained_worktrees()[0]
    assert got["session"] == "sess-abc123"


def test_a_run_dir_with_no_session_file_reports_no_session(clean_data):
    """The ordinary case: bind_session only ever creates `.session` once it
    already has a non-empty id, so its absence means the run's agent never
    got far enough to report one — not that something went wrong reading it."""
    srv = clean_data
    _mk_run_dir(srv, "kappa", "s-none")
    got = srv.retained_worktrees()[0]
    assert got["session"] == ""


def test_an_empty_session_file_reports_no_session_not_a_blank_id(clean_data):
    """bind_session's write path cannot produce this file empty (it checks the
    id is non-empty before ever calling mktemp), so an empty file on disk is a
    contract violation, not a legitimate zero-length session id. Either way
    there is nothing a resume could use."""
    srv = clean_data
    d = _mk_run_dir(srv, "lambda", "s-empty")
    (d / ".session").write_text("")
    got = srv.retained_worktrees()[0]
    assert got["session"] == ""


def test_a_session_file_that_cannot_be_read_does_not_crash_the_poll(clean_data):
    """`.session` existing as a directory (not a file) stands in for "exists
    but unreadable" — permission errors are hard to engineer portably in a
    test, but both raise OSError on read_text() and must be handled the same
    way. retained_worktrees backs every 5-second dashboard poll, so one bad
    run dir raising out of this call would blank the whole page, not just its
    own row."""
    srv = clean_data
    d = _mk_run_dir(srv, "mu", "s-unreadable")
    (d / ".session").mkdir()
    got = srv.retained_worktrees()[0]
    assert got["session"] == ""


def test_an_absent_session_file_is_the_quiet_case(clean_data, capsys):
    """The ordinary state must not spam the server log every 5-second poll
    just because a kept directory exists with no session yet — that would be
    true of most freshly-cut-short runs, all day."""
    srv = clean_data
    _mk_run_dir(srv, "xi", "s-quiet")
    srv.retained_worktrees()
    assert capsys.readouterr().err == ""


def test_an_empty_session_file_is_logged_as_empty(clean_data, capsys):
    """Distinct from silence (the absent case) AND from the unreadable case
    below — conflating either would hide which contract actually broke."""
    srv = clean_data
    d = _mk_run_dir(srv, "omicron", "s-loud-empty")
    (d / ".session").write_text("")
    srv.retained_worktrees()
    err = capsys.readouterr().err
    assert str(d / ".session") in err
    assert "empty" in err


def test_an_unreadable_session_file_is_logged_as_unreadable(clean_data, capsys):
    srv = clean_data
    d = _mk_run_dir(srv, "pi", "s-loud-bad")
    (d / ".session").mkdir()
    srv.retained_worktrees()
    err = capsys.readouterr().err
    assert str(d / ".session") in err
    assert "could not be read" in err
    assert "empty" not in err


def test_a_session_file_with_invalid_utf8_bytes_does_not_crash_the_poll(clean_data):
    """.session is written by a single `printf` and should always be plain
    ASCII, but a corrupted or hand-edited file is still readable AS BYTES --
    and Path.read_text() raises UnicodeDecodeError (a ValueError, not an
    OSError) on one that is not valid UTF-8. An `except OSError` alone does
    not catch that: it would propagate out of retained_worktrees() and take
    down the whole /api/data poll, for every job's card, not just this one
    row -- the exact failure this function's own docstring says the
    unreadable branch exists to prevent."""
    srv = clean_data
    d = _mk_run_dir(srv, "rho", "s-badbytes")
    (d / ".session").write_bytes(b"\xff\xfe\x00not-valid-utf8")
    got = srv.retained_worktrees()  # must not raise
    assert got[0]["session"] != ""  # decoded (lossily) rather than discarded
    assert isinstance(got[0]["session"], str)


# ---- retained_worktrees() backs the /api/data poll, every 5 seconds. An
# unthrottled log line for a standing bad-.session condition repeats for as
# long as the TTL takes to reclaim the directory -- up to 24h of identical
# lines for one already-diagnosed file. These pin the throttle: quiet on
# repeat, loud again the moment the condition actually changes.

def test_a_repeated_empty_session_is_logged_once_not_every_poll(clean_data, capsys):
    srv = clean_data
    d = _mk_run_dir(srv, "sigma", "s-repeat-empty")
    (d / ".session").write_text("")
    srv.retained_worktrees()
    assert "empty" in capsys.readouterr().err
    srv.retained_worktrees()
    srv.retained_worktrees()
    assert capsys.readouterr().err == ""


def test_a_repeated_unreadable_session_is_logged_once_not_every_poll(clean_data, capsys):
    srv = clean_data
    d = _mk_run_dir(srv, "tau", "s-repeat-bad")
    (d / ".session").mkdir()
    srv.retained_worktrees()
    assert "could not be read" in capsys.readouterr().err
    srv.retained_worktrees()
    assert capsys.readouterr().err == ""


def test_a_condition_that_changes_for_the_same_directory_is_logged_again(clean_data, capsys):
    """Throttling must not turn into permanent silence: a directory whose
    problem changes shape, or clears and then recurs, is still news."""
    srv = clean_data
    d = _mk_run_dir(srv, "upsilon", "s-changing")
    (d / ".session").write_text("")
    srv.retained_worktrees()
    assert "empty" in capsys.readouterr().err

    # Same condition again: silence.
    srv.retained_worktrees()
    assert capsys.readouterr().err == ""

    # Changes shape (empty -> unreadable): reported again, not swallowed by
    # what the first occurrence already logged.
    (d / ".session").unlink()
    (d / ".session").mkdir()
    srv.retained_worktrees()
    assert "could not be read" in capsys.readouterr().err

    # Resolves cleanly: no more log lines, and a real session reads through.
    (d / ".session").rmdir()
    (d / ".session").write_text("sess-recovered\n")
    got = srv.retained_worktrees()
    assert capsys.readouterr().err == ""
    assert got[0]["session"] == "sess-recovered"

    # The SAME bad condition recurs after having cleared: reported again, not
    # silenced by the very first occurrence's now-stale cache entry.
    (d / ".session").unlink()
    (d / ".session").write_text("")
    srv.retained_worktrees()
    assert "empty" in capsys.readouterr().err


def test_a_removed_run_dir_does_not_leak_its_condition_forever(clean_data):
    """Without pruning, a directory that once had a bad .session and was later
    torn down (the ordinary end of a retained run dir's life) would sit in the
    in-memory throttle cache for the rest of the server process's life -- a
    slow, unbounded leak across weeks of runs. retained_worktrees() sees the
    full set of directories still on disk on every call, so it is the one
    place that can know a cached path is now stale."""
    srv = clean_data
    d = _mk_run_dir(srv, "phi", "s-leak")
    (d / ".session").write_text("")
    srv.retained_worktrees()
    assert str(d) in srv._session_bound_logged
    shutil.rmtree(d.parent)
    srv.retained_worktrees()
    assert str(d) not in srv._session_bound_logged
