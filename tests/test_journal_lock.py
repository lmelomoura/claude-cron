"""The server's half of the journal lock.

Both sides take the same mkdir lock by name, so they have to agree on when a
lock may be broken. The engine now steals only from a dead owner; a server that
still broke on elapsed time would reintroduce the loss from the other side.
"""

import os
import time

import pytest


def test_a_free_lock_is_taken_and_released(srv):
    with srv.journal_lock() as lk:
        assert lk.path.is_dir()
    assert not lk.path.exists()


def test_the_holder_records_its_pid(srv):
    with srv.journal_lock() as lk:
        assert (lk.path / "pid").read_text().strip() == str(os.getpid())


def test_a_lock_whose_owner_is_gone_is_taken_at_once(srv):
    lock = srv.DATA_DIR / "locks" / ".journal.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    if lock.exists():
        for f in lock.iterdir():
            f.unlink()
        lock.rmdir()
    lock.mkdir()
    dead = 99999
    while _alive(dead):
        dead -= 1
    (lock / "pid").write_text(str(dead))

    t0 = time.time()
    with srv.journal_lock():
        pass
    assert time.time() - t0 < 2.0


def test_a_live_holder_is_never_robbed(srv):
    """The engine holds this lock across a whole-journal rewrite. Breaking it on
    a timer is exactly how an appended run record gets overwritten and lost."""
    lock = srv.DATA_DIR / "locks" / ".journal.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    if lock.exists():
        for f in lock.iterdir():
            f.unlink()
        lock.rmdir()
    lock.mkdir()
    (lock / "pid").write_text(str(os.getpid()))  # us: definitely alive
    try:
        with pytest.raises(TimeoutError):
            with srv.journal_lock(timeout=2.0):
                pass
    finally:
        for f in lock.iterdir():
            f.unlink()
        lock.rmdir()


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
