"""The security package reads two things straight from the environment: the
engines switch and the marker that says "this process is the agent under
review". Both had another prefix until 2026-09-06 and both are still read
under it for one release. Delete the fallbacks, and this file, after."""
import os
import subprocess
import sys
from pathlib import Path

from security import adapters
from test_cli import open_analysis   # the same fixture test_cli's own refusal test opens

REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"


def test_the_engines_switch_reads_its_pre_rename_name_for_one_release(monkeypatch):
    monkeypatch.delenv(adapters.ENGINES_ENV, raising=False)
    monkeypatch.setenv(adapters.LEGACY_ENGINES_ENV, "off")
    assert adapters._engines_setting() == "off"
    monkeypatch.setenv(adapters.ENGINES_ENV, "on")
    assert adapters._engines_setting() == "on", "the new name wins when both are set"
    monkeypatch.delenv(adapters.ENGINES_ENV)
    monkeypatch.delenv(adapters.LEGACY_ENGINES_ENV)
    assert adapters._engines_setting() == ""


def test_the_door_refuses_the_agent_under_its_pre_rename_marker(tmp_path):
    """`decide` is refused inside an analysis run. The marker arrives as
    AL_SECURITY_AGENT now; a precheck or hook written before the rename may
    still spell it the old way, and the refusal must hold either way."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("AL_SECURITY_AGENT", "CC_SECURITY_AGENT")}
    env["CC_SECURITY_AGENT"] = "1"   # the spelling before AL_SECURITY_AGENT
    open_analysis(tmp_path / "security.db")
    out = subprocess.run(
        [sys.executable, str(CLI), "decide", "--project", "web", "--fingerprint", "a" * 64,
         "--state", "false_positive", "--reason", "r", "--by", "me",
         "--db", str(tmp_path / "security.db")],
        capture_output=True, text=True, check=False, env=env)
    assert out.returncode != 0
    assert "AL_SECURITY_AGENT" in out.stderr
