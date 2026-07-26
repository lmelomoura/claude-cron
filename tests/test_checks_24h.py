"""The dashboard's "checks in the last 24h" counters, read from tick.log."""

import time


def _stamp(ago_seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - ago_seconds))


def _write_log(srv, lines):
    (srv.DATA_DIR / "tick.log").write_text("".join(l + "\n" for l in lines))


def test_counts_idle_checks_and_runs(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(60)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(50)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(40)} alpha: starting run (20260726T120000Z-1)",
        f"{_stamp(30)} beta: starting run (20260726T120000Z-2)",
    ])
    counts = srv.checks_24h()
    assert counts["alpha"] == {"checks": 3, "runs": 1}
    assert counts["beta"] == {"checks": 1, "runs": 1}


def test_entries_older_than_24h_are_excluded(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(90000)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(60)} alpha: precheck found nothing to do (exit 1)",
    ])
    assert srv.checks_24h()["alpha"] == {"checks": 1, "runs": 0}


def test_a_busy_day_is_not_truncated(clean_data):
    """The whole point of the counter is to prove the loop is alive.

    The old implementation kept only the last 6000 lines, which at 21 jobs on a
    5-minute interval is barely a day — so a busy install silently under-reported
    exactly when it had the most to report.
    """
    srv = clean_data
    lines = [f"{_stamp(3600)} alpha: precheck found nothing to do (exit 1)"
             for _ in range(8000)]
    _write_log(srv, lines)
    assert srv.checks_24h()["alpha"]["checks"] == 8000


def test_only_the_tail_of_a_huge_log_is_read(clean_data):
    """A log far past the rotation cap must not be read whole on every poll.

    Proven from the outside: a RECENT entry parked at the very top of a file
    much larger than the read window is invisible to the counter. If the reader
    ever went back to slurping the whole file, this count would be 2.
    """
    srv = clean_data
    buried = f"{_stamp(60)} alpha: starting run (buried-at-the-top)"
    filler = [f"{_stamp(90000)} old: precheck found nothing to do (exit 1)"] * 60000
    tail = [f"{_stamp(60)} alpha: starting run (in-the-window)"]
    _write_log(srv, [buried] + filler + tail)
    assert (srv.DATA_DIR / "tick.log").stat().st_size > 3_000_000

    assert srv.checks_24h()["alpha"] == {"checks": 1, "runs": 1}


def test_a_partial_first_line_is_discarded(clean_data):
    """Reading from a byte offset lands mid-line; that fragment is not an entry."""
    srv = clean_data
    srv.TICK_TAIL_BYTES  # the reader is offset-based, so this case is reachable
    _write_log(srv, [
        f"{_stamp(70)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(60)} alpha: starting run (x)",
    ])
    # Half a timestamp cannot parse, so it must be skipped rather than counted.
    log = srv.DATA_DIR / "tick.log"
    log.write_text("26T12:00:00Z garbage: half a line\n" + log.read_text())
    assert srv.checks_24h()["alpha"] == {"checks": 2, "runs": 1}
    assert "garbage" not in srv.checks_24h()
