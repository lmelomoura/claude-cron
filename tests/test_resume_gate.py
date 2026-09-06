"""The resume gate.

A resume must reclaim the EXACT port block its services were bound to, so the
engine refuses when a live run holds it (port_base_reclaim in bin/agentloop)
rather than substitute a fresh block and point the resumed agent at ports
nothing is listening on.

That refusal lands after the run has detached. The dashboard launches a resume
with `cc(..., background=True)`, so it used to answer 200 before the engine had
looked: the button went disabled, a "Resuming…" toast appeared, nothing
happened, and the reason existed only in tick.log. Two runs of one job cut
short in a row share a block, which is how one job came to show two Resume
buttons where resuming either made the other impossible.
"""

import json
import os
import shutil


JID = "resume-gate-job"
OTHER = "resume-gate-other"
SID = "1f78a14d-6bae-4d75-8427-17450e25a582"


def _retained(srv, session=SID, port_base="21000", stamp="20260903T132740Z-90689"):
    d = srv.DATA_DIR / "worktrees" / JID / stamp
    d.mkdir(parents=True, exist_ok=True)
    if session is not None:
        (d / ".session").write_text(session + "\n")
    payload = {"repos": []}
    if port_base is not None:
        payload["port_base"] = port_base
    (d / ".run.json").write_text(json.dumps(payload))
    return d


def _slot(srv, job, pid, port_base):
    """A live slot: no `boot` file on purpose — slot_alive falls back to the pid
    alone, and this test's own pid is the one process it can be sure about."""
    s = srv.DATA_DIR / "locks" / job / str(pid)
    s.mkdir(parents=True, exist_ok=True)
    (s / "pid").write_text(str(pid) + "\n")
    (s / "portbase").write_text(str(port_base) + "\n")
    return s


def _clean(srv):
    for p in (srv.DATA_DIR / "worktrees" / JID,
              srv.DATA_DIR / "locks" / JID,
              srv.DATA_DIR / "locks" / OTHER):
        shutil.rmtree(p, ignore_errors=True)


def test_a_live_run_holding_the_block_is_named_not_guessed_at(srv):
    """The block is held by a run of ANOTHER job here, deliberately: a block is
    machine-wide, so the holder is not necessarily a run of the job being
    resumed, and reporting "this job already has runs going" would have sent
    the operator looking in the wrong place."""
    _clean(srv)
    try:
        _retained(srv)
        _slot(srv, OTHER, os.getpid(), "21000")
        block, holder = srv.resume_port_block_held_by(JID, SID)
        assert block == "21000"
        assert holder is not None, "a live run on this block was not reported"
        assert holder["job"] == OTHER
        assert holder["pid"] == os.getpid()
    finally:
        _clean(srv)


def test_nothing_holding_the_block_leaves_the_resume_free_to_go(srv):
    _clean(srv)
    try:
        _retained(srv)
        block, holder = srv.resume_port_block_held_by(JID, SID)
        assert block == "21000"
        assert holder is None, "an unheld block was reported as taken"
    finally:
        _clean(srv)


def test_a_dead_slot_does_not_hold_a_block(srv):
    """A slot left behind by a run that died is exactly the state a resume is
    reached FROM — if its own stale slot counted, no cut-short session could
    ever be resumed at all."""
    _clean(srv)
    try:
        _retained(srv)
        # pid 1 is alive but is not ours; a pid that cannot exist is the honest
        # dead slot. os.kill(pid, 0) raises for it, which is what slot_alive reads.
        _slot(srv, OTHER, 2 ** 31 - 1, "21000")
        block, holder = srv.resume_port_block_held_by(JID, SID)
        assert block == "21000"
        assert holder is None, "a dead slot was counted as holding the block"
    finally:
        _clean(srv)


def test_a_run_dir_with_no_recorded_block_is_never_blocked(srv):
    """No `port_base` in the manifest means the engine allocates a fresh one,
    so there is nothing that can be in the way — answering otherwise would
    refuse a resume that would have worked."""
    _clean(srv)
    try:
        _retained(srv, port_base=None)
        _slot(srv, OTHER, os.getpid(), "21000")
        block, holder = srv.resume_port_block_held_by(JID, SID)
        assert block == ""
        assert holder is None
    finally:
        _clean(srv)


def test_another_session_of_the_same_job_is_not_mistaken_for_this_one(srv):
    """Two cut-short dirs of one job, and only one of them is being resumed."""
    _clean(srv)
    try:
        _retained(srv, session=SID, port_base="21000",
                  stamp="20260903T132740Z-90689")
        _retained(srv, session="eee53599-ca66-4481-8b07-72fc75cef6cb",
                  port_base="21500", stamp="20260903T132802Z-93377")
        _slot(srv, OTHER, os.getpid(), "21500")
        block, holder = srv.resume_port_block_held_by(JID, SID)
        assert block == "21000", "read the other retained dir's block"
        assert holder is None, "blocked on a block belonging to another session"
    finally:
        _clean(srv)


def test_the_handler_asks_before_it_launches(srv):
    """Order matters and nothing else can enforce it: asked after the launch,
    the answer is useless — `cc(..., background=True)` has already returned 200
    and the engine's refusal is in tick.log where nobody is looking."""
    src = (srv.__file__ if hasattr(srv, "__file__") else "")
    text = open(src, encoding="utf-8").read() if src else ""
    assert text, "could not read the server source to check the call order"
    i_ask = text.index("resume_port_block_held_by(jid, sid)")
    i_launch = text.index('cc(["resume", jid, sid]')
    assert i_ask < i_launch, (
        "the port-block check runs after the resume is launched, so its 409 can "
        "never reach the dashboard")
