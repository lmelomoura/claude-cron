"""A lock slot is a lease, not a pid.

data/locks survives a reboot and the kernel reissues pids from 1 on the way up,
so a recycled pid used to make a dead slot answer os.kill(pid, 0). The server
believed it too: a phantom slot hid a retained run dir from the only screen that
lists them.
"""

import os


def _slot(srv, job, pid, boot=None, worktree=None):
    slot = srv.DATA_DIR / "locks" / job / str(pid)
    slot.mkdir(parents=True)
    (slot / "pid").write_text(str(pid))
    if boot is not None:
        (slot / "boot").write_text(boot)
    if worktree is not None:
        (slot / "worktree").write_text(str(worktree))
    return slot


def test_this_process_in_this_boot_is_alive(clean_data):
    srv = clean_data
    slot = _slot(srv, "alpha", os.getpid(), boot=srv.boot_id())
    assert srv.slot_alive(slot) is True


def test_the_same_live_pid_from_an_earlier_boot_is_dead(clean_data):
    srv = clean_data
    slot = _slot(srv, "beta", os.getpid(), boot="0")
    assert srv.slot_alive(slot) is False


def test_a_slot_with_no_boot_file_falls_back_to_the_pid(clean_data):
    """Slots that predate the boot id must not all be reaped by an upgrade."""
    srv = clean_data
    slot = _slot(srv, "gamma", os.getpid())
    assert srv.slot_alive(slot) is True


def test_a_pre_reboot_claim_does_not_hide_a_retained_run_dir(clean_data):
    srv = clean_data
    d = srv.DATA_DIR / "worktrees" / "delta" / "stamp-old"
    (d / "repo").mkdir(parents=True)
    _slot(srv, "delta", os.getpid(), boot="0", worktree=d)
    assert [g["stamp"] for g in srv.retained_worktrees()] == ["stamp-old"]
