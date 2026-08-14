"""Run dirs the sweep decided to keep.

wt_teardown preserves a run dir whose session is marked `open`, or not marked
at all (a crash writes no marker either), and re-reaches that same conclusion
on every tick — so nothing ever releases it on its own. Until these were
listed they were invisible: disk filling up with no screen anywhere admitting
it.
"""

import os


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
