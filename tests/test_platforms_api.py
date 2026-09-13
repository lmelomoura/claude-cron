"""/api/models per platform, and the one vocabulary the server mirrors from
the engine.

The page will read platforms, models, efforts and permission modes from this
endpoint (plan B2); until then the old top-level keys (`models`, `efforts`)
stay exactly as they were, so the page that exists today keeps working. The
permission vocabulary lives in the engine (platform_permissions) and the
server repeats it with labels: `test_the_permission_vocabulary_matches_the_engine`
is what keeps the two from drifting, the way the backoff curve test does.
"""
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ENGINE = REPO / "bin" / "agentloop"
FAKE_CODEX = REPO / "test" / "fake-codex"
FAKE_OPENCODE = REPO / "test" / "fake-opencode"
FIX = REPO / "test" / "fixtures" / "codex"


def _catalog_block():
    cat = json.loads((FIX / "models-catalog.stripped.json").read_text())["models"]
    return {"at": 1788616000, "source": "fixture", "models": [
        {"slug": m["slug"], "display_name": m["display_name"], "description": m["description"],
         "default_effort": m["default_reasoning_level"],
         "efforts": [l["effort"] for l in m["supported_reasoning_levels"]],
         "visibility": m["visibility"], "priority": m["priority"],
         "deprecated_by": (m.get("upgrade") or {}).get("model") or "",
         "retires_at": (m.get("upgrade") or {}).get("retirement_at") or ""}
        for m in cat]}


def _write_models(srv, openai=None, resolved=None):
    data = {"resolved": resolved or {"opus": {"id": "claude-opus-5", "at": 1788585387}}}
    if openai is not None:
        data["openai"] = openai
    (srv.CONFIG_DIR / "models.json").write_text(json.dumps(data))


def _run_platforms(tmp_path, seed_catalog=False):
    """Run `agentloop platforms` the way a real install would -- except the
    CLI is the fake and every path is a scratch dir under tmp_path, so this
    NEVER reaches the real ~/.codex or runs the real codex (platform_ready
    openai shells out to `codex login status`, which the fixture answers)."""
    config_dir, data_dir, codex_home = (tmp_path / "config"), (tmp_path / "data"), (tmp_path / "codex-home")
    for d in (config_dir, data_dir, codex_home):
        d.mkdir(parents=True, exist_ok=True)
    if seed_catalog:
        (config_dir / "models.json").write_text(json.dumps({"resolved": {}, "openai": _catalog_block()}))
    env = dict(os.environ, AGENTLOOP_CODEX_BIN=str(FAKE_CODEX), CODEX_HOME=str(codex_home),
               AGENTLOOP_CONFIG=str(config_dir), AGENTLOOP_DATA=str(data_dir))
    out = subprocess.run(["/bin/bash", str(ENGINE), "platforms"],
                         capture_output=True, text=True, env=env, check=True).stdout
    return json.loads(out)


def _write_platforms(srv, platforms):
    srv.PLATFORMS_FILE.write_text(json.dumps({"platforms": platforms}))


@pytest.fixture(autouse=True)
def _isolated_registry(srv, tmp_path, monkeypatch):
    """Every test in this file reads a platforms file of its own -- {"platforms":
    {}} (empty until the test writes one: list_models then reads nothing
    enabled) written straight to disk, so list_models() never launches the
    engine for a seed it then throws away -- and the engine behind al() -- the
    seed, `platform check` -- only ever sees the stand-in CLIs, never the
    operator's."""
    platforms_file = tmp_path / "platforms.json"
    platforms_file.write_text(json.dumps({"platforms": {}}))
    monkeypatch.setattr(srv, "PLATFORMS_FILE", platforms_file)
    monkeypatch.setenv("AGENTLOOP_CLAUDE_BIN", str(REPO / "test" / "fake-claude"))
    monkeypatch.setenv("AGENTLOOP_CODEX_BIN", str(FAKE_CODEX))
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("AGENTLOOP_CLAUDE_CONFIG_DIR", "")


def test_the_registry_rides_on_api_models(srv, tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "JOBS_FILE", tmp_path / "jobs.json")
    monkeypatch.setattr(srv, "PROJECTS_FILE", tmp_path / "projects.json")
    _write_models(srv, openai=_catalog_block())
    srv.JOBS_FILE.write_text(json.dumps({"jobs": [
        {"id": "a", "model": "claude-opus-5"},
        {"id": "b", "model": "claude-opus-5"},
        {"id": "off", "enabled": False, "model": "claude-sonnet-5"},
        {"id": "o", "platform": "openai", "model": "gpt-5.6-luna"},
        {"id": "nomodel"},
        {"id": "bad", "platform": "openai", "model": "opus"}]}))
    srv.PROJECTS_FILE.write_text(json.dumps({"projects": [
        {"name": "P", "security": {"enabled": True, "model": "claude-fable-5-1"}},
        {"name": "Q", "security": {"enabled": True}}]}))
    _write_platforms(srv, {
        "anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5", "claude-fable-5-1"]},
        "openai": {"enabled": True, "bin": "", "models": ["gpt-5.6-luna"]},
        "opencode": {"enabled": False, "bin": "", "models": []}})
    out = srv.list_models()
    p = out["platforms"]
    assert set(p) == {"anthropic", "openai", "opencode"}
    a, o, c = p["anthropic"], p["openai"], p["opencode"]
    assert a["supported"] is True and a["enabled"] is True and a["usable"] is True
    assert a["models_enabled"] == ["claude-opus-5", "claude-fable-5-1"]
    # "nomodel" (no model) and Q's security block (no model) both fall back to
    # the platform's default -- the first enabled model, claude-opus-5 -- and
    # still count on the platform even though neither adds a new model key.
    # "off" is switched off and still counts: the page presents these numbers
    # as "who is configured to use this model", and a parked job is
    # configuration the operator means to switch back on.
    assert a["jobs_using"] == {"claude-opus-5": 4, "claude-fable-5-1": 1, "claude-sonnet-5": 1}
    assert a["jobs_on_platform"] == 6 and a["jobs_on_platform_enabled"] == 5
    # the same map with "off" taken back out -- this is what the model rows'
    # tooltips count, so a filter that drifts here mislabels every row
    assert a["jobs_using_enabled"] == {"claude-opus-5": 4, "claude-fable-5-1": 1}
    assert o["enabled"] is True and o["usable"] is True
    # "bad"'s model ("opus") is not a valid openai slug, so it falls back to
    # openai's default too and lands under the same key as "o".
    assert o["jobs_using"] == {"gpt-5.6-luna": 2}
    assert o["jobs_on_platform"] == 2 and o["jobs_on_platform_enabled"] == 2
    assert o["jobs_using_enabled"] == {"gpt-5.6-luna": 2}     # nothing parked on openai here
    # The server's registry runs opencode (bin/agentloop, this delivery), so
    # `supported` follows the same PLATFORMS_PLANNED mirror as the other two
    # and reads True. The entry itself is unavailable: the autouse fixture
    # above points AGENTLOOP_OPENCODE_BIN nowhere, so _opencode_platform()'s
    # own probe finds no binary to resolve a catalog from, and the entry
    # reads its own "opencode not installed" reason rather than a value
    # list_models() invents.
    assert c["supported"] is True and c["usable"] is False
    assert c["available"] is False and "opencode not installed" in c["reason"]
    assert out["configured"] is True and out["error"] == ""
    assert a["bin_source"] == "env" and a["bin"].endswith("test/fake-claude")
    # the keys the page reads today are still there, unchanged in shape
    assert out["models"] == a["models"] and isinstance(a["models"][0], str)
    assert a["catalog_at"] == 1788585387
    # What a family resolves to right now -- the id the engine gates a family
    # job on at launch; the families the cache has not resolved are left out.
    assert a["families"] == {"opus": "claude-opus-5"}


def test_the_opencode_entry_reads_the_catalog_and_prices_from_it(srv, monkeypatch, tmp_path):
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}, "opencode": {
        "at": 1789226000, "source": "opencode models --verbose", "version": "1.18.30", "models": [
            {"id": "opencode/big-pickle", "provider": "opencode", "name": "Big Pickle",
             "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}, "priced": False,
             "context": 200000, "output_limit": 32000, "variants": [], "tools": True, "reasoning": True, "status": "active"},
            {"id": "pdm_ai/glm-5.3-flash", "provider": "pdm_ai", "name": "glm-5.3-flash",
             "cost": {"input": 0.033011, "output": 0.139816, "cache_read": 0, "cache_write": 0}, "priced": True,
             "context": 197144, "output_limit": 65000, "variants": ["max", "high", "non-think"], "tools": True,
             "reasoning": True, "status": "active"},
            {"id": "pdm_ai/old", "provider": "pdm_ai", "name": "old", "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
             "priced": False, "context": 1, "output_limit": 1, "variants": [], "tools": False, "reasoning": False, "status": "retired"}]}}))
    (cfg / "pricing.json").write_text(json.dumps({"opencode": {
        "opencode/big-pickle": {"input": 0, "cached_input": 0, "output": 0, "cache_write": 0, "source": "manual"}}}))
    # Through srv.PLATFORMS_FILE, not a literal path under CONFIG_DIR: the
    # autouse _isolated_registry fixture above points PLATFORMS_FILE at a
    # tmp_path of its own so list_models() never seeds/discards the real
    # engine's file, and platforms_config() reads that current reference.
    _write_platforms(srv, {
        "anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5"]},
        "openai": {"enabled": False, "bin": "", "models": []},
        "opencode": {"enabled": True, "bin": "", "models": ["pdm_ai/glm-5.3-flash"]}})
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    c = srv.list_models()["platforms"]["opencode"]
    assert c["supported"] is True and c["available"] is True and c["reason"] == ""
    assert c["catalog_at"] == 1789226000
    assert [m["v"] for m in c["models"]] == ["opencode/big-pickle", "pdm_ai/glm-5.3-flash"]   # retired: out
    glm = c["models"][1]
    assert glm["label"] == "glm-5.3-flash" and glm["provider"] == "pdm_ai"
    assert glm["efforts"] == ["max", "high", "non-think"] and glm["default_effort"] == ""
    assert glm["priced"] is True and glm["price"] == {"input": 0.033011, "cached_input": 0, "output": 0.139816, "cache_write": 0}
    assert glm["tools"] is True and glm["context"] == 197144
    pickle = c["models"][0]
    assert pickle["priced"] is True and pickle["price"]["input"] == 0          # the operator's manual zero row IS a price
    assert pickle["efforts"] == []
    assert c["efforts"] == ["max", "high", "non-think"]
    assert [p["v"] for p in c["permissions"]] == ["full-access", "read-only"]
    assert c["default_model"] == "pdm_ai/glm-5.3-flash" and c["usable"] is True
    assert c["unpriced"] == []


def test_an_unpriced_opencode_model_is_named(srv, monkeypatch):
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}, "opencode": {"at": 1, "source": "x", "version": "1.18.30", "models": [
        {"id": "opencode/big-pickle", "provider": "opencode", "name": "Big Pickle", "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
         "priced": False, "context": 1, "output_limit": 1, "variants": [], "tools": True, "reasoning": True, "status": "active"}]}}))
    (cfg / "pricing.json").write_text(json.dumps({"opencode": {}}))
    c = srv.list_models()["platforms"]["opencode"]
    assert c["models"][0]["priced"] is False and c["models"][0]["price"] is None
    assert c["unpriced"] == ["opencode/big-pickle"]


def test_without_a_catalog_and_without_the_binary_the_entry_says_so(srv, monkeypatch):
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}}))
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    c = srv.list_models()["platforms"]["opencode"]
    assert c["supported"] is True and c["available"] is False
    assert "opencode not installed" in c["reason"]
    assert c["models"] == [] and c["permissions"] and c["permissions"][0]["v"] == "full-access"


def test_a_two_key_platforms_file_still_lists_the_opencode_card_disabled(srv, monkeypatch):
    # The file every install has today has no opencode key; the card comes
    # from the registry and reads disabled, never as an error.
    _write_platforms(srv, {
        "anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5"]},
        "openai": {"enabled": False, "bin": "", "models": []}})
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}}))
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    out = srv.list_models()
    c = out["platforms"]["opencode"]
    assert c["supported"] is True and c["enabled"] is False and c["usable"] is False
    assert c["models_enabled"] == [] and out["error"] in ("", None)
    assert out["platforms"]["anthropic"]["enabled"] is True


def test_the_server_permission_lists_match_the_engine_for_opencode(srv):
    # The engine is the authority on the vocabulary; the server mirrors it.
    # tests/test_platforms_api.py already pins anthropic and openai this way
    # (read that test and call the engine exactly as it does; the shape below
    # is the plain `agentloop platforms` call).
    env = {**os.environ, "AGENTLOOP_CONFIG": str(srv.CONFIG_DIR), "AGENTLOOP_DATA": str(srv.DATA_DIR),
           "AGENTLOOP_OPENCODE_BIN": "/nonexistent/opencode"}
    out = subprocess.run([str(REPO / "bin" / "agentloop"), "platforms"], capture_output=True, text=True, env=env, timeout=60)
    engine = json.loads(out.stdout)
    assert [p["v"] for p in srv.PLATFORM_PERMISSIONS["opencode"]] == engine["opencode"]["permissions"]


def test_the_engines_opencode_prices_match_the_servers_over_the_same_catalog(srv):
    # Two readers of the same two files -- config/models.json's opencode
    # block and config/pricing.json's opencode rows: the engine's `platform
    # models opencode` (platform_models_json, what `agentloop platforms` and
    # `status` print) and the server's /api/models entry (_opencode_platform,
    # what the Settings page shows). Resolved once through the stand-in into
    # the fixture's own config dir, so both read the same catalog: every id
    # the server lists is on the engine's list, and the price per million
    # agrees on each -- the catalog's own for a priced model, the operator's
    # row for an unpriced one, none when neither prices it.
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "pricing.json").write_text(json.dumps({"opencode": {
        "opencode/big-pickle": {"input": 0.5, "cached_input": 0.05, "output": 1.5, "cache_write": 0, "source": "manual"}}}))
    env = {**os.environ, "AGENTLOOP_CONFIG": str(srv.CONFIG_DIR), "AGENTLOOP_DATA": str(srv.DATA_DIR),
           "AGENTLOOP_OPENCODE_BIN": str(FAKE_OPENCODE)}
    out = subprocess.run([str(REPO / "bin" / "agentloop"), "platform", "models", "opencode"],
                         capture_output=True, text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    engine = json.loads(out.stdout)
    assert engine["stale"] is False and len(engine["models"]) == 13
    server = srv.list_models()["platforms"]["opencode"]
    assert server["available"] is True and len(server["models"]) == 13
    engine_by_id = {m["v"]: m for m in engine["models"]}
    assert {m["v"] for m in server["models"]} <= set(engine_by_id)
    for m in server["models"]:
        e = engine_by_id[m["v"]]
        if m["price"] is None:
            assert e["price"] is None, m["v"]
        else:
            assert e["price"] == {"input": m["price"]["input"], "output": m["price"]["output"]}, m["v"]
    # both sources were exercised: the catalog's own price, and the operator's row
    assert engine_by_id["pdm_ai/glm-5.3-flash"]["price"] == {"input": 0.033011, "output": 0.139816}
    assert engine_by_id["opencode/big-pickle"]["price"] == {"input": 0.5, "output": 1.5}
    assert any(m["price"] is None for m in server["models"])            # and a model neither prices


def test_a_parked_jobs_model_still_counts_as_using_the_platform(srv, tmp_path, monkeypatch):
    """The reported defect: an operator whose jobs are all switched off saw
    "no jobs" on every model those jobs name, so switching the model off read
    as free. The count the page shows is "who is configured to use this",
    which includes a parked job; `jobs_on_platform_enabled` is the separate
    number for "who would run right now"."""
    monkeypatch.setattr(srv, "JOBS_FILE", tmp_path / "jobs.json")
    monkeypatch.setattr(srv, "PROJECTS_FILE", tmp_path / "projects.json")
    _write_models(srv, openai=_catalog_block())
    srv.JOBS_FILE.write_text(json.dumps({"jobs": [
        {"id": "parked", "enabled": False, "model": "claude-sonnet-5"},
        {"id": "parked-o", "enabled": False, "platform": "openai", "model": "gpt-5.6-luna"}]}))
    srv.PROJECTS_FILE.write_text(json.dumps({"projects": [
        {"name": "P", "security": {"enabled": False, "model": "claude-fable-5-1"}}]}))
    _write_platforms(srv, {
        "anthropic": {"enabled": False, "bin": "", "models": []},
        "openai": {"enabled": False, "bin": "", "models": []}})
    p = srv.list_models()["platforms"]
    a, o = p["anthropic"], p["openai"]
    # the disabled job AND the disabled security block are both counted
    assert a["jobs_using"] == {"claude-sonnet-5": 1, "claude-fable-5-1": 1}
    assert a["jobs_on_platform"] == 2 and a["jobs_on_platform_enabled"] == 0
    assert o["jobs_using"] == {"gpt-5.6-luna": 1}
    assert o["jobs_on_platform"] == 1 and o["jobs_on_platform_enabled"] == 0
    # the discriminating half: a parked job is in jobs_using and in NEITHER
    # of the enabled twins, so the model rows read "(0 switched on)"
    assert a["jobs_using_enabled"] == {} and o["jobs_using_enabled"] == {}


def test_a_seed_that_leaves_no_file_reports_a_sentence_not_the_registry(srv, tmp_path, monkeypatch):
    """`agentloop platforms` prints the registry JSON on success; a run that
    exits 0 and still leaves no file behind must not hand that JSON to the
    page as `error` -- only a failing engine's own output is a reason."""
    monkeypatch.setattr(srv, "PLATFORMS_FILE", tmp_path / "never" / "platforms.json")
    monkeypatch.setattr(srv, "al", lambda *a, **k: (True, '{"anthropic": {"enabled": true}}'))
    cfg, err = srv.platforms_config()
    assert cfg == {} and err.endswith("could not be seeded")
    monkeypatch.setattr(srv, "al", lambda *a, **k: (False, "platforms: could not write the seed"))
    assert srv.platforms_config() == ({}, "platforms: could not write the seed")


def test_bin_found_requires_a_file_like_the_engine(srv, tmp_path, monkeypatch):
    """The engine's check is `-f && -x`; os.access alone says a directory is
    executable, and a path pointed at a folder would read as found."""
    _write_models(srv, openai=_catalog_block())   # a block on disk: nothing to resolve through the engine
    monkeypatch.setenv("AGENTLOOP_CODEX_BIN", str(tmp_path))
    assert srv.list_models()["platforms"]["openai"]["bin_found"] is False
    monkeypatch.setenv("AGENTLOOP_CODEX_BIN", str(FAKE_CODEX))
    assert srv.list_models()["platforms"]["openai"]["bin_found"] is True


def test_a_hand_edited_non_dict_platform_entry_does_not_crash(srv):
    """A hand edit can leave .platforms.anthropic as a bare string. platform_entry
    already falls back to {} for a non-dict entry; default_model must be read
    from that same fallback's models_enabled, not re-derived from cfg[p] a
    second time (which used to crash on a string: ("x" or {}).get(...))."""
    _write_platforms(srv, {"anthropic": "x"})
    a = srv.list_models()["platforms"]["anthropic"]
    assert a["default_model"] == "" and a["models_enabled"] == []


def test_a_null_jobs_list_does_not_crash_list_models(srv, tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "JOBS_FILE", tmp_path / "jobs.json")
    srv.JOBS_FILE.write_text(json.dumps({"jobs": None}))
    srv.list_models()          # must not raise


def test_nothing_usable_reads_as_not_configured_and_an_unreadable_file_says_why(srv):
    _write_platforms(srv, {"anthropic": {"enabled": False, "bin": "", "models": []}})
    assert srv.list_models()["configured"] is False
    srv.PLATFORMS_FILE.write_text("{oops")
    out = srv.list_models()
    assert out["configured"] is False
    assert out["error"].endswith("is not a valid platforms file (not JSON, or no .platforms object) — no platform is enabled until it is fixed")
    srv.PLATFORMS_FILE.write_text(json.dumps({"platform": {"anthropic": {"enabled": True}}}))   # a typo by hand: no .platforms object
    assert srv.list_models()["error"].endswith("no platform is enabled until it is fixed")
    assert out["platforms"]["anthropic"]["enabled"] is False


def test_a_missing_platforms_file_is_seeded_by_the_engine(srv, tmp_path, monkeypatch):
    """The server never invents the seed: it asks the engine once (`agentloop
    platforms` runs platforms_ensure) and reads what it wrote."""
    cfg = tmp_path / "config"; cfg.mkdir()
    monkeypatch.setattr(srv, "PLATFORMS_FILE", cfg / "platforms.json")
    monkeypatch.setenv("AGENTLOOP_CONFIG", str(cfg))
    (cfg / "jobs.json").write_text(json.dumps({"jobs": [{"id": "a", "model": "claude-opus-5"}]}))
    cfg_, err = srv.platforms_config()
    assert err == "" and (cfg / "platforms.json").exists()
    assert cfg_["anthropic"]["enabled"] is True and cfg_["anthropic"]["models"] == ["claude-opus-5"]


def test_the_bin_precedence_matches_the_engine(srv, tmp_path, monkeypatch):
    """env override, then the file's bin, then detection -- pinned to
    `agentloop platform check`, which is what a launch actually obeys."""
    cfg = tmp_path / "config"; cfg.mkdir()
    fake = tmp_path / "mycodex"; fake.write_text("#!/bin/sh\necho codex-cli 1.0\n"); fake.chmod(0o755)
    env = dict(os.environ, AGENTLOOP_CONFIG=str(cfg), AGENTLOOP_DATA=str(tmp_path / "data"),
               AGENTLOOP_CLAUDE_BIN=str(REPO / "test" / "fake-claude"), AGENTLOOP_CLAUDE_CONFIG_DIR="",
               CODEX_HOME=str(tmp_path / "codex-home"))
    env.pop("AGENTLOOP_CODEX_BIN", None)

    def engine_bin():
        out = subprocess.run(["/bin/bash", str(ENGINE), "platform", "check", "openai"],
                             capture_output=True, text=True, env=env, check=True).stdout
        j = json.loads(out)
        return j["bin"], j["bin_source"]

    monkeypatch.setattr(srv, "PLATFORMS_FILE", cfg / "platforms.json")
    monkeypatch.delenv("AGENTLOOP_CODEX_BIN", raising=False)
    (cfg / "platforms.json").write_text(json.dumps({"platforms": {"openai": {"enabled": True, "bin": str(fake), "models": []}}}))
    assert srv.platform_bin("openai", {"bin": str(fake)}) == (str(fake), "file") == engine_bin()
    (cfg / "platforms.json").write_text(json.dumps({"platforms": {"openai": {"enabled": True, "bin": "", "models": []}}}))
    assert srv.platform_bin("openai", {"bin": ""}) == engine_bin()
    assert srv.platform_bin("openai", {"bin": ""})[1] == "auto"
    env["AGENTLOOP_CODEX_BIN"] = str(fake)
    monkeypatch.setenv("AGENTLOOP_CODEX_BIN", str(fake))
    assert srv.platform_bin("openai", {"bin": "/elsewhere"}) == (str(fake), "env") == engine_bin()


def test_platform_actions_call_the_engine_and_relay_what_it_says(srv, monkeypatch):
    seen = []

    def fake(args, stdin=None):
        seen.append((args, stdin))
        if args[1] == "check":
            return True, '{"platform":"openai","ready":true}'
        if args[1] == "models":
            return True, '{"platform":"openai","stale":false,"models":[]}'
        if args[1] == "enable":
            return False, "cannot enable openai: codex is not signed in (run: codex login)"
        return True, "openai disabled\n1 enabled job (o) runs on openai and will be skipped until it is enabled again"
    monkeypatch.setattr(srv, "al", fake)
    assert srv.platform_action("platform_check", {"platform": "openai"}) == (200, {"ok": True, "check": {"platform": "openai", "ready": True}})
    assert srv.platform_action("platform_models", {"platform": "openai"})[1]["catalog"]["models"] == []
    code, payload = srv.platform_action("platform_enable", {"platform": "openai"})
    assert code == 500 and payload["ok"] is False and "codex is not signed in" in payload["output"]
    code, payload = srv.platform_action("platform_disable", {"platform": "openai"})
    assert code == 200 and "will be skipped" in payload["output"]
    srv.platform_action("platform_set_bin", {"platform": "openai", "bin": "/opt/x/codex"})
    srv.platform_action("platform_set_models", {"platform": "openai", "models": ["gpt-5.6-luna"]})
    assert [a for a, _ in seen] == [["platform", "check", "openai"], ["platform", "models", "openai"],
                                    ["platform", "enable", "openai"], ["platform", "disable", "openai"],
                                    ["platform", "set-bin", "openai", "/opt/x/codex"],
                                    ["platform", "set-models", "openai"]]
    assert json.loads(seen[-1][1]) == ["gpt-5.6-luna"]
    assert srv.platform_action("platform_check", {"platform": "martian"})[0] == 400
    assert srv.platform_action("platform_set_models", {"platform": "openai", "models": "gpt"})[0] == 400


def test_config_sig_moves_when_platforms_json_does(srv, tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "PLATFORMS_FILE", tmp_path / "platforms.json")
    before = srv.config_sig()
    _write_platforms(srv, {"anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5"]}})
    assert srv.config_sig() != before


def test_config_sig_moves_when_models_json_does(srv, tmp_path, monkeypatch):
    """The `families` map /api/models carries comes from models.json, not from
    platforms.json -- so the day the daily pass moves a family to a new id, an
    open tab has to notice too, and it only ever notices through this sig."""
    monkeypatch.setattr(srv, "CONFIG_DIR", tmp_path)
    before = srv.config_sig()
    _write_models(srv)
    assert srv.config_sig() != before


def test_the_old_keys_are_still_there_for_the_current_page(srv):
    _write_models(srv, openai=_catalog_block())
    out = srv.list_models()
    assert "claude-opus-5" in out["models"]
    assert out["efforts"] == ["low", "medium", "high", "xhigh", "max"]


def test_the_old_models_key_lists_anthropic_models_only(srv, tmp_path, monkeypatch):
    """The dashboard that exists today drives its model selector off the old
    `models` key, and every job it edits is an Anthropic one. A Codex slug
    reaching that list -- from the example OpenAI job a fresh install seeds
    into jobs.json, or from a single OpenAI run already in the history -- is a
    value the page will happily offer and `set-field model` then refuses (500).
    So `models` carries what `platform_model_ok anthropic` accepts, nothing
    else, and `platforms.anthropic.models` stays the same list.
    """
    monkeypatch.setattr(srv, "JOBS_FILE", tmp_path / "jobs.json")
    monkeypatch.setattr(srv, "DB_FILE", tmp_path / "index.db")
    # No CLI to scan, so every id below has one traceable source.
    monkeypatch.setenv("AGENTLOOP_CLAUDE_BIN", str(tmp_path / "no-claude"))
    _write_models(srv, openai=_catalog_block(),
                  resolved={"sonnet": {"id": "claude-sonnet-9", "at": 1788585387}})
    srv.JOBS_FILE.write_text(json.dumps({"jobs": [
        {"id": "a", "model": "claude-opus-5"},
        {"id": "o", "platform": "openai", "model": "gpt-5.6-luna"}]}))
    conn = srv.db_conn()
    srv.db_init(conn)
    conn.execute("INSERT INTO runs (key, job, model_id, platform)"
                 " VALUES ('o|1|x.json', 'o', 'gpt-5.6-sol', 'openai')")
    conn.commit()
    conn.close()

    out = srv.list_models()
    assert "claude-opus-5" in out["models"]          # the anthropic job's own model
    assert "claude-sonnet-9" in out["models"]        # what the family resolved to
    assert [m for m in out["models"] if m.startswith("gpt-")] == []
    assert out["platforms"]["anthropic"]["models"] == out["models"]
    # and the slugs are still offered where they belong
    assert "gpt-5.6-luna" in [m["v"] for m in out["platforms"]["openai"]["models"]]


def test_platforms_carry_the_catalog_visible_models_in_priority_order(srv):
    _write_models(srv, openai=_catalog_block())
    (srv.CONFIG_DIR / "pricing.json").write_text(
        json.dumps({"openai": {"gpt-5.6-sol": {"input": 4, "cached_input": 0.4, "output": 20}}}))
    _write_platforms(srv, {"anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5"]},
                           "openai": {"enabled": True, "bin": "", "models": ["gpt-5.6-sol"]}})
    p = srv.list_models()["platforms"]
    assert set(p) == {"anthropic", "openai", "opencode"}
    a, o = p["anthropic"], p["openai"]
    assert a["available"] is True and a["default_model"] == "claude-opus-5"
    assert a["models"] == srv.list_models()["models"]
    assert [m["v"] for m in a["permissions"]] == \
        ["acceptEdits", "auto", "bypassPermissions", "manual", "dontAsk", "plan"]
    assert o["available"] is True and o["catalog_at"] == 1788616000
    slugs = [m["v"] for m in o["models"]]
    assert slugs == ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5", "gpt-5.4-mini"]
    assert "gpt-reserve" not in slugs                        # hidden stays hidden
    sol = o["models"][0]
    assert sol["label"] == "GPT-5.6-Sol" and sol["efforts"][-1] == "ultra"
    assert sol["default_effort"] == "low" and sol["priced"] is True
    mini = o["models"][-1]
    assert mini["deprecated_by"] == "gpt-5.6-luna" and mini["retires_at"].startswith("2026-08-31")
    assert mini["priced"] is False                          # no pricing.json row
    assert o["efforts"] == ["low", "medium", "high", "xhigh", "max", "ultra"]
    assert [m["v"] for m in o["permissions"]] == ["read-only", "workspace-write", "full-access"]
    assert o["default_model"] == "gpt-5.6-sol"


def test_an_unavailable_catalog_says_why(srv):
    _write_models(srv, openai={"at": 1, "available": False, "reason": "codex not installed"})
    o = srv.list_models()["platforms"]["openai"]
    assert o["available"] is False and o["reason"] == "codex not installed"
    assert o["models"] == [] and o["default_model"] == ""


def test_a_missing_block_is_resolved_once_when_codex_exists(srv, monkeypatch):
    _write_models(srv, openai=None)
    calls = []

    def fake_al(args, stdin=None, background=False):
        calls.append(args)
        _write_models(srv, openai=_catalog_block())
        return True, "ok"
    monkeypatch.setattr(srv, "al", fake_al)
    # name-aware: a blanket truthy path would also make _opencode_platform's
    # own shutil.which("opencode") probe fire, adding a second, unwanted call.
    monkeypatch.setattr(srv.shutil, "which", lambda name: "/opt/homebrew/bin/codex" if name == "codex" else None)
    monkeypatch.setattr(srv.os.path, "exists", lambda p: False)
    # _opencode_platform's probe now goes through _bin_detect, whose last
    # resort is os.access on ~/.opencode/bin/opencode and then a hard-coded
    # Homebrew path -- neither mock above touches os.access, and a machine
    # with a real opencode install at either path would otherwise fire a
    # second, unwanted al() here (and fake_al above does not even take that
    # call's new env= kwarg).
    monkeypatch.setattr(srv.os, "access", lambda p, mode: False)
    monkeypatch.delenv("AGENTLOOP_OPENCODE_BIN", raising=False)
    o = srv.list_models()["platforms"]["openai"]
    assert calls == [["resolve-models", "openai"]]
    assert o["available"] is True


def test_a_missing_block_without_codex_is_reported_not_resolved(srv, monkeypatch):
    _write_models(srv, openai=None)
    monkeypatch.setattr(srv, "al", lambda *a, **k: (_ for _ in ()).throw(AssertionError("al called")))
    monkeypatch.setattr(srv.shutil, "which", lambda name: None)
    # _openai_platform's last-resort discovery checks this exact path too
    # (launchd gives a job a minimal PATH, so shutil.which("codex") alone
    # misses a real install); a dev machine that actually has Codex there
    # must not make "no codex" a host-dependent result.
    monkeypatch.setattr(srv.os.path, "exists", lambda p: False)
    monkeypatch.delenv("AGENTLOOP_CODEX_BIN", raising=False)
    # Same story for opencode: the autouse fixture's AGENTLOOP_OPENCODE_BIN
    # is a non-empty (if bogus) path, which alone would make
    # _opencode_platform think the CLI exists and call the forbidden al().
    monkeypatch.delenv("AGENTLOOP_OPENCODE_BIN", raising=False)
    # _bin_detect's own last resort (~/.opencode/bin, then a hard-coded
    # Homebrew path) is checked with os.access, not os.path.exists -- a
    # machine with a real opencode install at either path must not make
    # this test host-dependent either.
    monkeypatch.setattr(srv.os, "access", lambda p, mode: False)
    o = srv.list_models()["platforms"]["openai"]
    assert o["available"] is False and "codex" in o["reason"]


def test_a_missing_opencode_block_is_resolved_through_the_detected_binary(srv, monkeypatch):
    """T8 fix wave 1, finding 1: the probe used to know only PATH and the
    hard-coded Homebrew path, so a CLI the official installer puts under
    ~/.opencode/bin read as "not installed" until the next daily pass. It now
    goes through _bin_detect -- platform_entry's own detection -- plus an
    os.access check, so AGENTLOOP_OPENCODE_BIN (standing in here for that
    installer path, which the old probe never consulted at all) resolves the
    catalog on the very first /api/models, proving the sync resolve ran
    through the detected binary rather than sitting unresolved."""
    _write_models(srv)   # {"resolved": {...}}, no "opencode" key: nothing to read back yet
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", str(FAKE_OPENCODE))
    c = srv.list_models()["platforms"]["opencode"]
    assert c["available"] is True and c["reason"] == ""
    # test/fixtures/opencode/models-verbose.txt: 13 models, every one "active"
    assert len(c["models"]) == 13


def test_a_hung_opencode_cli_gets_the_engines_short_deadline_not_als(srv, monkeypatch, tmp_path):
    """T8 fix wave 1, finding 2: al()'s own 30s subprocess timeout used to race
    the engine's 60s `models --verbose` deadline, so a hung CLI got killed by
    al() first -- before run_bounded's own deadline could fire and write a
    stub -- leaving config/models.json's opencode block untouched and making
    every following /api/models repeat the same 30s wait. The in-request
    resolve passes AGENTLOOP_OPENCODE_DEADLINE from the server's own
    OPENCODE_RESOLVE_DEADLINE constant (8s in production: spent once on
    `--version`, now bounded too, and twice on `models --verbose`, 24s in
    all), which always finishes inside al()'s window and lets the engine
    write its own timeout stub instead. This test shrinks that constant to
    2s (2 + 4 = 6s at most) so the stub -- and the test -- land in seconds
    rather than paying the production deadline in full."""
    _write_models(srv)   # no "opencode" key: the probe below must run resolve-models
    stub = tmp_path / "opencode-hang"
    stub.write_text(
        "#!/bin/bash\n"
        "case \"$1\" in\n"
        "  --version) echo 1.0.0 ;;\n"
        "  *) exec sleep 601 ;;\n"   # 601, not 600: unique against every other stand-in's hang mode
        "esac\n"
    )
    stub.chmod(0o755)
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", str(stub))
    monkeypatch.setattr(srv, "OPENCODE_RESOLVE_DEADLINE", "2")
    start = time.monotonic()
    c = srv.list_models()["platforms"]["opencode"]
    elapsed = time.monotonic() - start
    assert elapsed < 12, f"took {elapsed:.1f}s -- al()'s 30s timeout, not the engine's short stub, must have fired"
    assert c["available"] is False
    assert "timed out" in c["reason"]
    # run_bounded ends the WHOLE process group on its own deadline -- the
    # stand-in's sleep (601, picked to be unique) must not outlive the request.
    left = subprocess.run("ps -ax -o command= | grep -c '^sleep 601$'",
                           shell=True, capture_output=True, text=True).stdout.strip()
    assert left == "0", "sleep 601 is still running: run_bounded did not kill the process group"


def test_the_permission_vocabulary_matches_the_engine(srv, tmp_path):
    engine = _run_platforms(tmp_path)
    for platform, modes in srv.PLATFORM_PERMISSIONS.items():
        assert [m["v"] for m in modes] == engine[platform]["permissions"], platform
    assert engine["anthropic"]["efforts"] == ["low", "medium", "high", "xhigh", "max"]
    assert engine["openai"]["efforts"] == []                  # no catalog resolved in this scratch config


def test_the_engines_openai_efforts_are_the_visible_catalogs_union(tmp_path):
    # Same rule cmd_platforms and the server's _openai_platform both apply:
    # the union of the VISIBLE models' efforts, not the fixed six levels a
    # bare `openai_catalog_efforts ""` used to fall back to regardless of
    # whether a catalog was even resolved.
    engine = _run_platforms(tmp_path, seed_catalog=True)
    assert engine["openai"]["efforts"] == ["low", "medium", "high", "xhigh", "max", "ultra"]


def test_the_server_lets_platform_through_set_field():
    src = (REPO / "bin" / "agentloop-server").read_text()
    allow = src[src.index('elif op == "set_field"'):][:900]
    assert '"platform"' in allow


def test_the_openai_platform_carries_its_prices_and_their_freshness(srv):
    _write_models(srv, openai=_catalog_block())
    (srv.CONFIG_DIR / "pricing.json").write_text(json.dumps({
        "_source_url": "file:///fixture", "_refreshed_at": 1788800000,
        "openai": {
            "gpt-5.6-sol": {"input": 4, "cached_input": 0.4, "output": 20, "cache_write": 5,
                            "source": "litellm", "at": 1788800000},
            "gpt-5.5": {"input": 9, "cached_input": 9, "output": 9, "cache_write": 0, "source": "manual"}}}))
    o = srv.list_models()["platforms"]["openai"]
    assert o["pricing_at"] == 1788800000 and o["pricing_source"] == "file:///fixture"
    by = {m["v"]: m for m in o["models"]}
    assert by["gpt-5.6-sol"]["priced"] is True
    assert by["gpt-5.6-sol"]["price"] == {"input": 4, "cached_input": 0.4, "output": 20,
                                          "cache_write": 5, "source": "litellm", "at": 1788800000}
    assert by["gpt-5.5"]["price"]["source"] == "manual" and by["gpt-5.5"]["price"]["at"] is None
    assert by["gpt-5.6-luna"]["priced"] is False and by["gpt-5.6-luna"]["price"] is None
    assert o["unpriced"] == ["gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.4-mini"]


def test_without_a_price_table_the_platform_says_so(srv):
    _write_models(srv, openai=_catalog_block())
    p = srv.CONFIG_DIR / "pricing.json"
    if p.exists():
        p.unlink()
    o = srv.list_models()["platforms"]["openai"]
    assert o["pricing_at"] == 0 and o["pricing_source"] == ""
    assert o["unpriced"] == [m["v"] for m in o["models"]]
    assert all(m["price"] is None for m in o["models"])


def test_a_malformed_price_table_never_breaks_the_platform(srv):
    """pricing.json can be valid JSON and still not be {"openai": {slug:
    row}} -- a list at the top, or an "openai" block that is a list. Either
    used to raise AttributeError out of list_models() (table.get("openai")
    on a list, then priced.get(slug) on a list), taking /api/models down
    with it. The platform must instead answer exactly as if there were no
    price table at all."""
    _write_models(srv, openai=_catalog_block())
    pricing = srv.CONFIG_DIR / "pricing.json"
    for content in (json.dumps([1, 2, 3]), json.dumps({"openai": [1, 2, 3]}),
                    json.dumps("just a string"), "not json at all"):
        pricing.write_text(content)
        o = srv.list_models()["platforms"]["openai"]
        assert o["pricing_at"] == 0 and o["pricing_source"] == "", content
        assert all(m["price"] is None and m["priced"] is False for m in o["models"]), content
        assert o["unpriced"] == [m["v"] for m in o["models"]], content


def test_a_non_string_source_url_is_never_the_pricing_source(srv):
    _write_models(srv, openai=_catalog_block())
    (srv.CONFIG_DIR / "pricing.json").write_text(json.dumps({"_source_url": 7, "openai": {}}))
    assert srv.list_models()["platforms"]["openai"]["pricing_source"] == ""


def test_price_of_falls_back_to_defaults_row_by_row(srv):
    """Each field price_of trusts only when it has the right type; anything
    else gets the same default a missing field would, or -- for `input`, or
    a row that is not even a dict -- drops the whole row. Pinned per field so
    a future edit to price_of cannot silently loosen one of these checks."""
    _write_models(srv, openai=_catalog_block())
    pricing = srv.CONFIG_DIR / "pricing.json"
    pricing.write_text(json.dumps({"openai": {
        "gpt-5.6-sol": {"input": 1, "cached_input": 1, "output": 1},                        # no cache_write
        "gpt-5.6-terra": {"input": 1, "cached_input": 1, "output": 1, "cache_write": "5"},   # cache_write: string
        "gpt-5.6-luna": 7,                                                                   # row is not a dict
        "gpt-5.5": {"input": 1, "cached_input": 1, "output": 1, "cache_write": 2},           # no at
        "gpt-5.4-mini": {"input": True, "cached_input": 1, "output": 1}}}))                  # input: bool
    by = {m["v"]: m for m in srv.list_models()["platforms"]["openai"]["models"]}
    assert by["gpt-5.6-sol"]["price"]["cache_write"] == 0
    assert by["gpt-5.6-terra"]["price"]["cache_write"] == 0
    assert by["gpt-5.6-luna"]["price"] is None and by["gpt-5.6-luna"]["priced"] is False
    assert by["gpt-5.5"]["price"]["at"] is None
    assert by["gpt-5.4-mini"]["price"] is None

    pricing.write_text(json.dumps({"openai": {
        "gpt-5.6-sol": {"input": 1, "cached_input": 1, "output": 1, "cache_write": True},   # cache_write: bool
        "gpt-5.6-terra": {"input": 1, "cached_input": 1, "output": 1, "at": "yesterday"},   # at: string
        "gpt-5.4-mini": {"input": "4", "cached_input": 1, "output": 1}}}))                  # input: string
    by = {m["v"]: m for m in srv.list_models()["platforms"]["openai"]["models"]}
    assert by["gpt-5.6-sol"]["price"]["cache_write"] == 0
    assert by["gpt-5.6-terra"]["price"]["at"] is None
    assert by["gpt-5.4-mini"]["price"] is None
