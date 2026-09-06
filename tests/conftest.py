"""Test harness for the control server.

The server binds CONFIG_DIR/DATA_DIR at IMPORT time from the environment, and
its import has side effects (it creates the dirs and mints a control token). So
the environment has to point at a scratch tree before the module is ever
imported — hence the session-scoped fixture below and the import inside it,
rather than at the top of a test file.

The server ships as `bin/agentloop-server` with no .py extension (it is an
executable, not a package), so it is loaded by path.
"""

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "bin" / "agentloop-server"


@pytest.fixture(scope="session")
def srv(tmp_path_factory):
    """The server module, bound to a throwaway config/data tree."""
    root = tmp_path_factory.mktemp("al")
    (root / "config").mkdir()
    (root / "data").mkdir()
    os.environ["CLAUDE_CRON_CONFIG"] = str(root / "config")
    os.environ["CLAUDE_CRON_DATA"] = str(root / "data")
    spec = importlib.util.spec_from_loader(
        "cc_server", importlib.machinery.SourceFileLoader("cc_server", str(SERVER)))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cc_server"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def clean_data(srv):
    """An empty data dir for one test.

    Everything a test can leave behind, not just the journal: run dirs and lock
    slots leak between tests otherwise, and a test that asserts on "what is on
    disk right now" then reads the previous test's fixtures as its own.
    """
    for p in (srv.RUNS_FILE, srv.DB_FILE,
              Path(str(srv.DB_FILE) + "-wal"), Path(str(srv.DB_FILE) + "-shm"),
              srv.DATA_DIR / "tick.log"):
        if p.exists():
            p.unlink()
    for name in ("logs", "worktrees", "locks"):
        d = srv.DATA_DIR / name
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    return srv
