"""test/fake-opencode stands in for the OpenCode CLI in the e2e suite and the
selftest. A stand-in that emits a shape the real CLI never emitted would make
those suites green over nothing, so this pins its output to the measured
shapes (test/fixtures/opencode/) in every mode."""
import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "test" / "fake-opencode"
FIX = REPO / "test" / "fixtures" / "opencode"


def run(args, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([str(FAKE)] + args, env=e, cwd=cwd, capture_output=True,
                          text=True, timeout=30, stdin=subprocess.DEVNULL)


def events(text):
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def test_version_models_and_auth_answer_like_the_cli():
    assert run(["--version"]).stdout.strip() == "1.18.30"
    ids = run(["models"]).stdout.split()
    assert "opencode/big-pickle" in ids and "pdm_ai/glm-5.3-flash" in ids
    assert "pdm_ai/openai/gpt-oss-120b" in ids          # a slash inside the model id
    verbose = run(["models", "--verbose"]).stdout
    assert verbose == (FIX / "models-verbose.txt").read_text()
    assert run(["models"], env={"FAKE_OPENCODE_NO_MODELS": "1"}).stdout.strip() == ""
    auth = run(["auth", "list"]).stdout
    assert "0 credentials" in auth


def test_a_complete_run_has_the_measured_shape(tmp_path):
    p = run(["run", "--format", "json", "--pure", "--auto", "-m", "opencode/big-pickle",
             "--dir", str(tmp_path), "--", "do the thing"],
            env={"FAKE_SESSION": "ses_test0001", "FAKE_ARGV_OUT": str(tmp_path / "argv"),
                 "FAKE_DIR_OUT": str(tmp_path / "dir"), "FAKE_CONFIG_OUT": str(tmp_path / "cfg"),
                 "OPENCODE_CONFIG_CONTENT": '{"share":"disabled"}'})
    assert p.returncode == 0 and p.stderr == ""
    evs = events(p.stdout)
    assert [e["type"] for e in evs] == ["step_start", "tool_use", "step_finish", "step_start", "text", "step_finish"]
    assert all(e["sessionID"] == "ses_test0001" for e in evs)
    assert evs[1]["part"]["tool"] == "bash" and evs[1]["part"]["state"]["status"] == "completed"
    assert evs[2]["part"]["reason"] == "tool-calls" and evs[-1]["part"]["reason"] == "stop"
    assert evs[-1]["part"]["tokens"] == {"total": 13767, "input": 65, "output": 6, "reasoning": 0,
                                         "cache": {"write": 0, "read": 13696}}
    assert evs[-1]["part"]["cost"] == 0
    assert evs[4]["part"]["text"] == "RUN COMPLETE: nothing needed doing."
    assert (tmp_path / "argv").read_text().splitlines()[0] == "ARGC\t11"
    assert (tmp_path / "dir").read_text().strip() == str(tmp_path)
    assert (tmp_path / "cfg").read_text().strip() == '{"share":"disabled"}'


def test_a_cost_per_step_is_reported_when_asked(tmp_path):
    p = run(["run", "--format", "json", "-m", "pdm_ai/glm-5.3-flash", "--dir", str(tmp_path), "--", "x"],
            env={"FAKE_COST": "0.0002"})
    finishes = [e for e in events(p.stdout) if e["type"] == "step_finish"]
    assert [e["part"]["cost"] for e in finishes] == [0.0002, 0.0002]


def test_the_failure_modes_match_the_measured_events(tmp_path):
    base = ["run", "--format", "json", "-m", "opencode/big-pickle", "--dir", str(tmp_path), "--", "x"]
    err = run(base, env={"FAKE_MODE": "error"})
    assert err.returncode == 1
    ev = events(err.stdout)
    assert len(ev) == 1 and ev[0]["type"] == "error" and ev[0]["error"]["name"] == "UnknownError"
    quota = run(base, env={"FAKE_MODE": "quota"})
    assert quota.returncode == 1
    ev = events(quota.stdout)
    assert ev[0]["error"]["name"] == "APIError" and ev[0]["error"]["data"]["statusCode"] == 429
    rej = run(base, env={"FAKE_MODE": "reject"})
    assert rej.returncode == 0
    ev = events(rej.stdout)
    assert [e["type"] for e in ev] == ["step_start", "tool_use", "step_finish"]
    assert ev[1]["part"]["state"]["status"] == "error"
    assert ev[1]["part"]["state"]["error"].startswith("The user rejected permission")
    assert ev[2]["part"]["reason"] == "tool-calls"          # the turn died there
    assert "auto-rejecting" in rej.stderr
    den = run(base, env={"FAKE_MODE": "deny"})
    assert den.returncode == 0
    ev = events(den.stdout)
    assert ev[1]["part"]["state"]["error"].startswith("The user has specified a rule which prevents")
    assert ev[-1]["part"]["reason"] == "stop"               # the turn went on


def test_export_names_the_model_that_ran(tmp_path):
    p = run(["export", "ses_test0002"], env={"FAKE_RAN_MODEL": "pdm_ai/glm-5.3-flash-real"})
    assert p.returncode == 0
    doc = json.loads(p.stdout)
    assert doc["info"]["id"] == "ses_test0002"
    assert doc["info"]["model"] == {"id": "glm-5.3-flash-real", "providerID": "pdm_ai", "variant": "default"}
    assert p.stderr.strip() == "Exporting session: ses_test0002"


def test_the_undeclared_and_dirty_endings(tmp_path):
    base = ["run", "--format", "json", "-m", "opencode/big-pickle", "--dir", str(tmp_path), "--", "x"]
    und = events(run(base, env={"FAKE_MODE": "undeclared"}).stdout)
    assert und[4]["part"]["text"] == "I did some work."
    run(base, env={"FAKE_MODE": "dirty"}, cwd=tmp_path)
    assert (tmp_path / "agent-left-this.txt").exists()
