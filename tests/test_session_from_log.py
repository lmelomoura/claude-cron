"""Reading a live run's session id out of its transcript.

The init event carries the run's whole tool roster. With a few MCP servers
attached it passes 8 KB on its own, and the byte window this used to read with
cut it mid-object — json.loads raised on the fragment and the id was never
found. The transcript is append-only, so those first bytes never change: the
miss was permanent, not something the next poll recovered from.

The bash side (`session_from_stream` in bin/agentloop) was fixed by reading
lines instead. These tests pin the same property here, so the two cannot drift.
"""

import json


def _write_stream(srv, job, stamp, lines):
    """Lay a transcript out where _session_from_log expects it, and return the
    .json path it is addressed by."""
    d = srv.DATA_DIR / "logs" / job
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{stamp}.stream.ndjson").write_text("".join(l + "\n" for l in lines))
    return str(d / f"{stamp}.json")


def _init_event(sid, tools=0):
    return json.dumps({
        "type": "system", "subtype": "init", "session_id": sid,
        "tools": [f"a-tool-with-a-long-name-{i}" for i in range(tools)],
    })


def test_the_init_events_session_is_found(clean_data):
    srv = clean_data
    logp = _write_stream(srv, "alpha", "s1", [
        _init_event("sess-abc123"),
        json.dumps({"type": "assistant", "message": {}}),
    ])
    assert srv._session_from_log(logp) == "sess-abc123"


def test_an_init_event_over_8kb_is_still_read(clean_data):
    """The regression. A byte-capped read truncates this one mid-object and
    finds nothing, for the life of the run."""
    srv = clean_data
    big = _init_event("sess-big", tools=900)
    assert len(big) > 8192, "the fixture is too small to prove anything"
    logp = _write_stream(srv, "beta", "s2", [
        big,
        json.dumps({"type": "assistant", "message": {}}),
    ])
    assert srv._session_from_log(logp) == "sess-big"


def test_a_transcript_with_no_session_yet_reports_nothing(clean_data):
    srv = clean_data
    logp = _write_stream(srv, "gamma", "s3", [
        json.dumps({"type": "assistant", "message": {}}),
    ])
    assert srv._session_from_log(logp) == ""


def test_an_empty_transcript_reports_nothing(clean_data):
    srv = clean_data
    logp = _write_stream(srv, "delta", "s4", [])
    assert srv._session_from_log(logp) == ""


def test_a_half_written_first_line_reports_nothing_rather_than_guessing(clean_data):
    """The poll can land while the agent is still writing the event. An
    unterminated object is not JSON, so it is skipped and the next poll — by
    which time the line is complete — finds it."""
    srv = clean_data
    d = srv.DATA_DIR / "logs" / "epsilon"
    d.mkdir(parents=True, exist_ok=True)
    (d / "s5.stream.ndjson").write_text('{"type":"system","session_id":"sess-par')
    assert srv._session_from_log(str(d / "s5.json")) == ""


def test_a_transcript_outside_the_logs_root_is_refused(clean_data):
    """The path arrives from a slot breadcrumb; it is not a reason to read
    anywhere on disk."""
    srv = clean_data
    outside = srv.DATA_DIR / "elsewhere"
    outside.mkdir(parents=True, exist_ok=True)
    (outside / "x.stream.ndjson").write_text(_init_event("sess-outside") + "\n")
    assert srv._session_from_log(str(outside / "x.json")) == ""
