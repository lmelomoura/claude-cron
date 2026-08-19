"""The dashboard's 24h view of tick.log: the per-job counters and the band.

`checks_24h()` returns both, from one pass: the counters the job cards read and
the bucketed series the band at the top of the page draws.
"""

import time


def _stamp(ago_seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - ago_seconds))


def _write_log(srv, lines):
    (srv.DATA_DIR / "tick.log").write_text("".join(l + "\n" for l in lines))


def _counts(srv):
    return srv.checks_24h()[0]


def _band(srv):
    return srv.checks_24h()[1]


def _totals(band):
    """The whole band collapsed to one {outcome: count}."""
    return {k: sum(b[i] for b in band["buckets"])
            for i, k in enumerate(band["outcomes"])}


def test_counts_idle_checks_and_runs(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(60)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(50)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(40)} alpha: starting run (20260726T120000Z-1)",
        f"{_stamp(30)} beta: starting run (20260726T120000Z-2)",
    ])
    counts = _counts(srv)
    assert (counts["alpha"]["checks"], counts["alpha"]["runs"]) == (3, 1)
    assert (counts["beta"]["checks"], counts["beta"]["runs"]) == (1, 1)


def test_entries_older_than_24h_are_excluded(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(90000)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(60)} alpha: precheck found nothing to do (exit 1)",
    ])
    counts = _counts(srv)
    assert (counts["alpha"]["checks"], counts["alpha"]["runs"]) == (1, 0)


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
    assert _counts(srv)["alpha"]["checks"] == 8000


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

    counts = _counts(srv)
    assert (counts["alpha"]["checks"], counts["alpha"]["runs"]) == (1, 1)


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
    counts = _counts(srv)
    assert (counts["alpha"]["checks"], counts["alpha"]["runs"]) == (2, 1)
    assert "garbage" not in counts


# ------------------------------------------------------------ classification

def test_every_decision_the_engine_logs_is_classified(clean_data):
    """The band is only honest if it recognises the lines the engine writes.

    These are verbatim shapes from bin/claude-cron; a reworded log line that
    stops matching would silently drop that outcome out of the band.
    """
    srv = clean_data
    cases = {
        "starting run (20260726T120000Z-1)": "woke",
        "precheck found nothing to do (exit 1)": "idle",
        "PRECHECK FAILED (exit 7) — the probe could not run, so no work was "
        "looked for": "failed",
        "daily cap reached ($9 / $5) — skipping": "capped",
        "GLOBAL daily cap reached ($9 / $5 across all jobs) — skipping": "capped",
        "already at max_parallel=3 run(s), not launching another": "blocked",
        "at max_parallel=3 run(s), not launching another": "blocked",
        "no prompt, skipped": "failed",
        "cwd missing (/nope), skipped": "failed",
        "claude_config_dir missing (/nope), skipped": "failed",
        "worktree isolation failed — run aborted (no shared-checkout fallback)": "failed",
        "provisioning failed for alpha — aborting the run": "failed",
    }
    for msg, want in cases.items():
        assert srv.classify_tick(msg) == want, msg


def test_bookkeeping_chatter_is_not_a_check(clean_data):
    """Lines the engine writes ABOUT a run, not as a decision to make one.

    Counting these would inflate the band with events the loop never chose —
    one run would look like four checks.
    """
    srv = clean_data
    for msg in ("finished status=success rc=0 denials=0 cost=$0.03 turns=2",
                "isolated in /tmp/wt (cwd /tmp/wt/alpha)",
                "run dir kept — unpushed or uncommitted work at /tmp/wt",
                "run dir 20260726T120000Z-1 dropped by the user",
                "refreshing family→id resolutions (cache older than 86400s)",
                "on-run-end hook failed or timed out — see exec.log"):
        assert srv.classify_tick(msg) is None, msg


# -------------------------------------------------------------------- band

def test_the_band_covers_a_full_day_oldest_first(clean_data):
    srv = clean_data
    _write_log(srv, [f"{_stamp(60)} alpha: starting run (x)"])
    band = _band(srv)
    assert len(band["buckets"]) == srv.TICK_BUCKETS
    assert band["bucket_seconds"] * len(band["buckets"]) == 86400
    # a tick a minute ago belongs at the RIGHT-HAND end of the band
    woke = band["outcomes"].index("woke")
    assert band["buckets"][-1][woke] == 1
    assert sum(b[woke] for b in band["buckets"][:-1]) == 0


def test_the_band_totals_every_outcome(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(600)} alpha: starting run (x)",
        f"{_stamp(500)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(400)} alpha: PRECHECK FAILED (exit 7) — the probe could not run",
        f"{_stamp(300)} beta: daily cap reached ($9 / $5) — skipping",
        # A spent usage window is its own outcome, not a `capped`: the operator
        # can raise a dollar cap they set, but a window they can only wait for.
        f"{_stamp(250)} beta: usage limit reached — the seven_day window is 98% "
        f"used and overage is off, so the ceiling is a dead stop — it resets in "
        f"42 min — skipping",
        f"{_stamp(200)} beta: already at max_parallel=3 run(s), not launching another",
    ])
    assert _totals(_band(srv)) == {"woke": 1, "idle": 1, "failed": 1,
                                  "capped": 1, "rate_limited": 1, "blocked": 1}


def test_a_job_gets_an_hourly_series_the_card_can_draw(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(30)} alpha: starting run (x)",
        f"{_stamp(60)} alpha: precheck found nothing to do (exit 1)",
        f"{_stamp(3600 * 5)} alpha: precheck found nothing to do (exit 1)",
    ])
    a = _counts(srv)["alpha"]
    assert len(a["series"]) == srv.JOB_BUCKETS == len(a["woke"])
    assert sum(a["series"]) == 3 and sum(a["woke"]) == 1
    # the two recent ones land in the newest hour, the old one further left
    assert a["series"][-1] == 2 and a["woke"][-1] == 1
    assert a["series"][-6] == 1


def test_a_failed_probe_is_counted_against_the_job(clean_data):
    srv = clean_data
    _write_log(srv, [
        f"{_stamp(60)} alpha: PRECHECK FAILED (exit 7) — the probe could not run",
        f"{_stamp(50)} alpha: precheck found nothing to do (exit 1)",
    ])
    a = _counts(srv)["alpha"]
    assert (a["checks"], a["runs"], a["failed"]) == (2, 0, 1)
