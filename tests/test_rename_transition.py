"""The rename kept the old spellings alive for one release. These pin the two
the server itself honours: its environment names, and the dashboard's token
header. Both fallbacks are deleted in the release after the rename, and so
are these tests."""


def test_the_server_reads_the_pre_rename_environment_names_for_one_release(srv, monkeypatch):
    legacy = srv.LEGACY_ENV_PREFIX + "SESSION_TTL"
    monkeypatch.delenv("AGENTLOOP_SESSION_TTL", raising=False)
    monkeypatch.setenv(legacy, "42")
    assert srv._env("SESSION_TTL") == "42"
    monkeypatch.setenv("AGENTLOOP_SESSION_TTL", "7")
    assert srv._env("SESSION_TTL") == "7", "the new name wins when both are set"
    monkeypatch.delenv("AGENTLOOP_SESSION_TTL")
    monkeypatch.delenv(legacy)
    assert srv._env("SESSION_TTL", "fallback") == "fallback"
    assert srv._env("SESSION_TTL") is None
