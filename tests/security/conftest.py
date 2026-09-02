"""Loads bin/security as a package. bin/ has no __init__ chain of its own."""
import os
import sys
from pathlib import Path

# Modify sys.path at module load time, BEFORE conftest is fully initialized
REPO = Path(__file__).resolve().parent.parent.parent
bin_path = str(REPO / "bin")
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

# WHICH SECRET SCANNER THESE TESTS EXERCISE, DECIDED HERE AND NOT BY THE
# MACHINE. `prepare` prefers gitleaks whenever it is installed, so without
# this line the same test suite tests two different products depending on
# whether somebody has run `brew install gitleaks` -- and the tests that plant
# a credential and assert what came back would pass on one laptop and fail on
# the next. They are tests OF the built-in scanner reached through the CLI, so
# they are pinned to it.
#
# `setdefault`, not an assignment: `CC_SECURITY_ENGINES=on pytest` runs the
# same suite against the engines, which is how the difference between the two
# is inspected rather than guessed at. The engine path has its own tests in
# test_adapters.py, which switch it on explicitly.
os.environ.setdefault("CC_SECURITY_ENGINES", "off")
