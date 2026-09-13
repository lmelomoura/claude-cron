"""The OpenCode -> stream-json normalizer, tested on the measured fixtures.

Every fixture under test/fixtures/opencode/ is a real `opencode run --format
json` run captured on 2026-09-12 (opencode-ai 1.18.30), except the one whose
name says `synthetic`. The normalizer is pure: feed() takes one OpenCode event
and returns the canonical events it becomes, so these tests drive it
in-process; two tests drive the CLI itself, because the FIFO launch in run_job
only ever sees that -- and because the watchdog's empty-stream rule now makes
"the first line is out at once" a matter of life and death for a run.
"""
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NORM = REPO / "bin" / "platforms" / "opencode_stream.py"
FIX = REPO / "test" / "fixtures" / "opencode"

_spec = importlib.util.spec_from_file_location("opencode_stream", NORM)
ocs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ocs)

PRICE = {"input": 1.0, "cached_input": 0.5, "output": 2.0, "cache_write": 0.25}
SESSION_03 = "ses_f69f73155ffeAHgrtVv1sVFbr7"


def events_of(name):
    out = []
    for line in (FIX / name).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:  # noqa: BLE001
            continue
    return out


def normalize(name=None, events=None, priced=False, price=None, model="opencode/big-pickle",
              permission="full-access"):
    n = ocs.Normalizer(model, permission, "/tmp/x", priced, price)
    out = []
    for ev in (events if events is not None else events_of(name)):
        out.extend(n.feed(ev))
    out.extend(n.finish())
    return out


def as_text(events):
    return "\n".join(json.dumps(e) for e in events) + "\n"


def blocks(out, kind, role):
    return [b for e in out if e["type"] == role for b in e["message"]["content"] if b["type"] == kind]


# ------------------------------------------------------------ the shape

def test_the_first_line_is_the_init_event_carrying_the_session_id():
    out = normalize("03-tool-use.jsonl")
    first = out[0]
    assert first["type"] == "system" and first["subtype"] == "init"
    assert first["session_id"] == SESSION_03
    assert first["model"] == "opencode/big-pickle"      # what was ASKED for
    assert first["platform"] == "opencode"
    assert first["permissionMode"] == "full-access"
    assert first["cwd"] == "/tmp/x" and first["tools"] == []


def test_a_lone_step_start_already_produces_the_init_line():
    # The watchdog kills a run whose stream is still EMPTY after the stall
    # window. step_start is the first thing the CLI writes, and it arrives
    # only when the model starts answering -- so it must reach the file at
    # once, not wait for a completed tool or a closed step.
    n = ocs.Normalizer("m", "full-access", "/", False, None)
    out = n.feed(events_of("03-tool-use.jsonl")[0])
    assert len(out) == 1 and out[0]["subtype"] == "init" and out[0]["session_id"] == SESSION_03


def test_a_finished_turn_ends_in_a_success_result_summing_every_step():
    out = normalize("03-tool-use.jsonl")
    last = out[-1]
    assert last["type"] == "result"
    assert last["subtype"] == "success" and last["is_error"] is False
    assert last["session_id"] == SESSION_03 and last["platform"] == "opencode"
    assert last["result"] == "done"                     # the last text part
    assert last["num_turns"] == sum(1 for e in out if e["type"] == "assistant")
    assert last["permission_denials"] == []
    # two steps: 11909+65 input, 43+6 output, 1792+13696 cached, 0 reasoning
    assert last["tokens"] == {"input": 11974, "cached": 15488, "cache_write": 0, "output": 49, "reasoning": 0}
    assert last["usage"] == {"input_tokens": 11974, "cache_read_input_tokens": 15488,
                             "cache_creation_input_tokens": 0, "output_tokens": 49}
    assert last["api_error_status"] is None


def test_a_tool_call_becomes_a_bash_tool_use_and_its_result_at_once():
    out = normalize("03-tool-use.jsonl")
    uses, results = blocks(out, "tool_use", "assistant"), blocks(out, "tool_result", "user")
    assert uses == [{"type": "tool_use", "id": "call_99041d057e2b48ccb4af895f", "name": "Bash",
                     "input": {"command": "ls"}}]
    assert results == [{"type": "tool_result", "tool_use_id": "call_99041d057e2b48ccb4af895f",
                        "content": "a.txt\nb.txt\n", "is_error": False}]
    # the two come out of ONE event, in order, tool_use first
    kinds = [(e["type"], e["message"]["content"][0]["type"]) for e in out[1:3]]
    assert kinds == [("assistant", "tool_use"), ("user", "tool_result")]


def test_tool_names_are_the_claude_ones_and_unknown_names_pass_through():
    out = normalize("02-tool-use-bash-and-read.jsonl")
    names = [b["name"] for b in blocks(out, "tool_use", "assistant")]
    assert names == ["Bash", "Read"]
    read = [b for b in blocks(out, "tool_use", "assistant") if b["name"] == "Read"][0]
    assert read["input"] == {"filePath": "/tmp/probe/p/a.txt"}
    assert ocs.canonical_name("task") == "Task" and ocs.canonical_name("webfetch") == "WebFetch"
    assert ocs.canonical_name("invalid") == "invalid" and ocs.canonical_name("mcp_thing") == "mcp_thing"


def test_the_server_timeline_draws_the_command(srv):
    turns = srv.parse_turns_text(as_text(normalize("03-tool-use.jsonl")))
    tools = [t for turn in turns for t in turn["tools"]]
    assert tools and tools[0]["tool"] == "Bash" and "ls" in tools[0]["hint"]


def test_a_truncated_copy_still_salvages_session_and_turns(srv):
    text = as_text(normalize("03-tool-use.jsonl"))
    last_text, turns, sess = srv._salvage_from_stream(text[: len(text) // 2])
    assert sess == SESSION_03 and turns >= 1


def test_reasoning_tokens_ride_beside_output_and_inside_usage():
    last = normalize("11-variant-high.jsonl", model="opencode/ling-3.0-flash-fin-free")[-1]
    assert last["tokens"]["output"] == 12 and last["tokens"]["reasoning"] == 15
    assert last["usage"]["output_tokens"] == 27          # output + reasoning: what the model generated
    assert last["tokens"]["input"] == 12225 and last["tokens"]["cached"] == 1920


def test_a_long_tool_output_is_cut_at_eight_kilobytes():
    ev = events_of("03-tool-use.jsonl")[1]
    ev["part"]["state"]["output"] = "x" * 20_000
    out = normalize(events=[events_of("03-tool-use.jsonl")[0], ev])
    content = blocks(out, "tool_result", "user")[0]["content"]
    assert len(content.encode()) < 9_000 and content.endswith("[truncated]")


def test_a_run_cut_off_before_its_final_step_emits_no_result():
    out = normalize("12-interrupted-turn.jsonl")      # step_start only: killed mid-tool
    assert out[-1]["type"] != "result"
    evs = [e for e in events_of("03-tool-use.jsonl") if not (e["type"] == "step_finish" and e["part"]["reason"] == "stop")]
    assert normalize(events=evs)[-1]["type"] != "result"


def test_only_one_result_is_ever_emitted_for_a_run():
    evs = events_of("01-trivial-turn.jsonl")
    out = normalize(events=evs + [evs[-1]])
    assert sum(1 for e in out if e["type"] == "result") == 1


def test_an_unknown_finish_reason_ends_the_run_as_an_error():
    evs = events_of("01-trivial-turn.jsonl")
    evs[-1]["part"]["reason"] = "length"
    last = normalize(events=evs)[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["subtype"] == "error_during_execution" and "length" in last["result"]


def test_a_missing_finish_reason_is_treated_like_tool_calls():
    # A malformed step_finish with no `reason` at all must not be read as
    # "the model stopped: unknown" -- it accumulates like "tool-calls" and
    # emits nothing, since more of the turn may still be coming.
    evs = events_of("01-trivial-turn.jsonl")
    del evs[-1]["part"]["reason"]
    out = normalize(events=evs)
    assert all(e["type"] != "result" for e in out)


# ------------------------------------------------------------ denials

def test_a_rule_denial_is_a_permission_denial_and_the_turn_goes_on():
    out = normalize("23-rule-denied-bash.jsonl")
    last = out[-1]
    assert last["type"] == "result" and last["subtype"] == "success"   # the model answered "attempted"
    assert last["result"] == "attempted"
    assert last["permission_denials"] == [{"tool_name": "Bash", "tool_use_id": "call_2dedd6815de446afb9cc493d",
                                           "tool_input": {"command": "echo hello-from-bash ; whatever"}}]
    res = blocks(out, "tool_result", "user")[0]
    assert res["is_error"] is True and res["content"].startswith("The user has specified a rule")


def test_a_rule_denial_does_not_end_the_turn_at_eof():
    # Fixture 23 in full recovers (the model answers "attempted" after the
    # denial). Cut right after the denial's step_finish (tool-calls) and hit
    # EOF there instead: a rule denial must NOT be read as ending the turn --
    # only an auto-rejected ask does that -- so this run is left to the
    # salvage path, same as any other kill mid-turn.
    evs = events_of("23-rule-denied-bash.jsonl")[:3]
    out = normalize(events=evs)
    assert all(e["type"] != "result" for e in out)


def test_a_rule_denial_then_a_killed_step_still_emits_no_result():
    # The run is killed one step later instead (the measured shape of 12: a
    # lone step_start, nothing after). The rule denial two events back must
    # still not make finish() fire.
    evs = events_of("23-rule-denied-bash.jsonl")[:3] + events_of("12-interrupted-turn.jsonl")
    out = normalize(events=evs)
    assert all(e["type"] != "result" for e in out)


def test_an_auto_rejected_ask_ends_the_run_as_tools_denied_at_eof():
    for name, tool in (("04-auto-rejected-ask.jsonl", "Bash"), ("18-auto-rejected-write.jsonl", "Write")):
        out = normalize(name)
        last = out[-1]
        assert last["type"] == "result" and last["is_error"] is True
        assert last["subtype"] == "error_during_execution"
        assert "rejected permission" in last["result"] and tool in last["result"]
        assert len(last["permission_denials"]) == 1 and last["permission_denials"][0]["tool_name"] == tool
        assert last["api_error_status"] is None


def test_a_rejection_then_a_new_step_is_not_read_as_how_the_run_ended():
    # Fixture 04 in full ends on the rejection (EOF right after the
    # step_finish that follows it). Here a new step_start (fixture 12's)
    # arrives instead of EOF: the run kept going past the rejection, so
    # last_rejected must not survive to color finish() -- this is left to
    # the salvage path, same as any other kill mid-turn.
    evs = events_of("04-auto-rejected-ask.jsonl") + events_of("12-interrupted-turn.jsonl")
    out = normalize(events=evs)
    assert all(e["type"] != "result" for e in out)


def test_a_tool_removed_from_the_roster_is_drawn_as_invalid_not_denied():
    out = normalize("06-tool-denied-invalid.jsonl")
    names = [b["name"] for b in blocks(out, "tool_use", "assistant")]
    assert names[0] == "invalid" and "Glob" in names
    assert out[-1]["permission_denials"] == []          # the model adapted; nothing was refused to it


def test_denial_of_reads_the_two_measured_phrases_and_nothing_else():
    assert ocs.denial_of({"status": "error", "error": "The user rejected permission to use this specific tool call."})
    assert ocs.denial_of({"status": "error", "error": "The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules []"})
    assert not ocs.denial_of({"status": "error", "error": "command not found"})
    assert not ocs.denial_of({"status": "completed", "output": "The user rejected permission"})


# ------------------------------------------------------------ failures

def test_an_unknown_model_is_an_error_result_with_no_status():
    out = normalize("09-unknown-model.jsonl")
    assert out[0]["subtype"] == "init"                  # the error event carries the session id
    last = out[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["subtype"] == "error_during_execution"
    assert last["api_error_status"] is None
    assert "Unexpected server error" in last["result"] and "err_001b5330" in last["result"]
    assert last["cost_basis"] == "none" and last["total_cost_usd"] is None
    assert last["usage"] == {"input_tokens": 0, "cache_read_input_tokens": 0,
                             "cache_creation_input_tokens": 0, "output_tokens": 0}


def test_an_api_error_carries_its_status_code():
    last = normalize("16-api-error-401.jsonl")[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["api_error_status"] == 401 and "Incorrect API key" in last["result"]


def test_a_rate_limit_carries_429():
    last = normalize("quota-429.synthetic.jsonl")[-1]
    assert last["api_error_status"] == 429 and last["is_error"] is True


# ------------------------------------------------------------ cost

def test_a_priced_catalog_model_reports_the_cli_cost():
    last = normalize("34-paid-provider-cost.jsonl", priced=True, model="pdm_ai/glm-5.3-flash")[-1]
    assert last["cost_basis"] == "reported"
    assert last["total_cost_usd"] == 0.000426176016
    assert last["tokens"] == {"input": 12800, "cached": 0, "cache_write": 0, "output": 3, "reasoning": 23}


def test_the_reported_cost_is_the_sum_of_every_step():
    evs = events_of("03-tool-use.jsonl")
    for e in evs:
        if e["type"] == "step_finish":
            e["part"]["cost"] = 0.0002
    last = normalize(events=evs, priced=True)[-1]
    assert last["cost_basis"] == "reported" and last["total_cost_usd"] == 0.0004


def test_the_reported_cost_rounds_the_sum_to_the_clis_own_twelve_decimals():
    # measured Task 12 acceptance run: four step_finish costs at the CLI's
    # own precision (12 decimals) sum in python to 0.0018640076180000001 --
    # noise past the eighteenth digit the CLI never reported. Rounding the
    # sum to 12 decimals loses nothing of the CLI's own numbers.
    costs = [0.000461385212, 0.000465814535, 0.000466379568, 0.000470428303]
    evs = []
    for i, cost in enumerate(costs):
        reason = "stop" if i == len(costs) - 1 else "tool-calls"
        evs.append({"type": "step_finish", "timestamp": 1789226678042 + i,
                    "sessionID": "ses_synthetic_cost_sum",
                    "part": {"id": "prt_synthetic_%d" % i, "reason": reason,
                             "messageID": "msg_synthetic", "sessionID": "ses_synthetic_cost_sum",
                             "type": "step-finish",
                             "tokens": {"total": 0, "input": 0, "output": 0, "reasoning": 0,
                                        "cache": {"write": 0, "read": 0}},
                             "cost": cost}})
    last = normalize(events=evs, priced=True)[-1]
    assert last["cost_basis"] == "reported"
    assert last["total_cost_usd"] == 0.001864007618


def test_an_error_result_after_priced_steps_carries_the_reported_cost():
    # An error result must not discard a cost the CLI already reported: it
    # carries the same total_cost_usd/cost_basis a success would, computed
    # from the same steps seen so far.
    evs = events_of("01-trivial-turn.jsonl")
    evs[-1]["part"]["reason"] = "length"
    evs[-1]["part"]["cost"] = 0.0003
    last = normalize(events=evs, priced=True)[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["cost_basis"] == "reported" and last["total_cost_usd"] == 0.0003


def test_a_priced_model_with_no_numeric_cost_falls_through_to_the_estimate():
    # A priced catalog model whose step_finish events never carried a
    # numeric `cost` at all (not even zero) must not report a silent zero:
    # it falls through to the estimate, then to none, exactly like an
    # unpriced model would.
    evs = events_of("03-tool-use.jsonl")
    for e in evs:
        if e["type"] == "step_finish":
            del e["part"]["cost"]
    last_none = normalize(events=evs, priced=True, price=None)[-1]
    assert last_none["cost_basis"] == "none" and last_none["total_cost_usd"] is None
    # 11974 in, 49 out at the output price, 15488 cached, 0 cache_write
    expected = round((11974 * 1.0 + 49 * 2.0 + 15488 * 0.5 + 0 * 0.25) / 1_000_000, 6)
    last_est = normalize(events=evs, priced=True, price=PRICE)[-1]
    assert last_est["cost_basis"] == "estimated" and last_est["total_cost_usd"] == expected


def test_an_unpriced_model_with_a_table_row_is_estimated_like_the_cli_does():
    last = normalize("24c-priced-reasoning.jsonl", priced=False, price=PRICE)[-1]
    # 11800 in, 32 out + 39 reasoning at the output price, 1856 cached
    expected = round((11800 * 1.0 + (32 + 39) * 2.0 + 1856 * 0.5 + 0 * 0.25) / 1_000_000, 6)
    assert last["cost_basis"] == "estimated" and last["total_cost_usd"] == expected


def test_the_catalog_price_wins_over_the_table():
    last = normalize("34-paid-provider-cost.jsonl", priced=True, price=PRICE, model="pdm_ai/glm-5.3-flash")[-1]
    assert last["cost_basis"] == "reported" and last["total_cost_usd"] == 0.000426176016


def test_zero_in_the_catalog_and_no_table_row_is_unknown_never_free():
    last = normalize("01-trivial-turn.jsonl", priced=False, price=None)[-1]
    assert last["cost_basis"] == "none" and last["total_cost_usd"] is None
    assert last["tokens"]["input"] == 14915             # the tokens are still reported


def test_a_manual_zero_row_is_an_estimated_free_run():
    zero = {"input": 0, "cached_input": 0, "output": 0, "cache_write": 0}
    last = normalize("01-trivial-turn.jsonl", priced=False, price=zero)[-1]
    assert last["cost_basis"] == "estimated" and last["total_cost_usd"] == 0.0


def test_load_price_and_catalog_priced_read_the_two_files(tmp_path):
    table = tmp_path / "pricing.json"
    table.write_text(json.dumps({"opencode": {
        "pdm_ai/x": {"input": 1, "cached_input": 0.1, "output": 2, "cache_write": 0},
        "pdm_ai/half": {"input": None, "cached_input": 0.1, "output": 2}}}))
    assert ocs.load_price(str(table), "pdm_ai/x") == {"input": 1.0, "cached_input": 0.1, "output": 2.0, "cache_write": 0.0}
    assert ocs.load_price(str(table), "pdm_ai/half") is None
    assert ocs.load_price(str(table), "absent") is None
    assert ocs.load_price(str(tmp_path / "nope.json"), "pdm_ai/x") is None
    catalog = tmp_path / "models.json"
    catalog.write_text(json.dumps({"opencode": {"models": [
        {"id": "pdm_ai/glm-5.3-flash", "priced": True}, {"id": "opencode/big-pickle", "priced": False}]}}))
    assert ocs.catalog_priced(str(catalog), "pdm_ai/glm-5.3-flash") is True
    assert ocs.catalog_priced(str(catalog), "opencode/big-pickle") is False
    assert ocs.catalog_priced(str(catalog), "nope/nope") is False
    assert ocs.catalog_priced(str(tmp_path / "missing.json"), "pdm_ai/glm-5.3-flash") is False


# ------------------------------------------------------------ the CLI

def test_the_cli_normalizes_stdin_and_copies_every_raw_line(tmp_path):
    raw_in = (FIX / "03-tool-use.jsonl").read_text() + "this line is not json\n"
    raw_out = tmp_path / "copy.raw"
    p = subprocess.run([sys.executable, "-u", str(NORM), "--model", "opencode/big-pickle",
                        "--permission", "full-access", "--cwd", "/tmp/x",
                        "--raw-out", str(raw_out)],
                       input=raw_in, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    lines = [json.loads(ln) for ln in p.stdout.splitlines()]
    assert lines[0]["subtype"] == "init" and lines[-1]["type"] == "result"
    assert lines[-1]["cost_basis"] == "none"
    assert raw_out.read_text() == raw_in            # copied verbatim, bad line included
    assert p.stderr == ""


def test_the_cli_flushes_the_init_line_before_the_stream_ends(tmp_path):
    # Feed step_start alone, keep stdin OPEN, and read the first line back:
    # a normalizer that buffered would leave the file empty for the whole
    # run, and the watchdog would kill a live run at the stall window. Read
    # it on a background thread with a hard join timeout, so a regression
    # fails this test in 10s instead of hanging the suite forever.
    # No -u: this test's whole point is that the normalizer's own out.flush()
    # delivers the line, so it must not pass just because -u already makes
    # stdout unbuffered on its own. -u lives in the engine's launch line, not
    # here -- if a regression ever dropped the flush call, this Popen must be
    # the one that notices.
    first = events_of("03-tool-use.jsonl")[0]
    p = subprocess.Popen([sys.executable, str(NORM), "--model", "m", "--permission", "full-access",
                          "--cwd", "/"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    read = {}

    def read_first_line():
        read["line"] = p.stdout.readline()          # blocks for ever if nothing was flushed

    thread = threading.Thread(target=read_first_line, daemon=True)
    try:
        p.stdin.write(json.dumps(first) + "\n")
        p.stdin.flush()
        thread.start()
        thread.join(timeout=10)
        if thread.is_alive():
            p.kill()
            assert False, "the init line was not flushed within 10 s"
        assert json.loads(read["line"])["subtype"] == "init"
    finally:
        p.stdin.close()
        p.wait(timeout=10)
