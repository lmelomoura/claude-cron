"""The suite has to be green in the configuration that ships.

`conftest.py` pins `CC_SECURITY_ENGINES=off` so that a test which plants a
credential exercises ONE scanner rather than whichever one a laptop happens to
have installed. That pin is right. What it also did, silently, was buy the
whole suite a configuration nobody checks: a real analysis runs with the
engines ON, and for the entire life of the engine path
`CC_SECURITY_ENGINES=on pytest tests/security/` was red -- seven tests
asserting the built-in scanner's vocabulary, or planting material only the
built-in scanner reports, while inheriting a default they never declared.
Nothing ever ran the second configuration, so nothing ever said so. The
failures were found by hand, months later, in a review.

This test runs it. One subprocess, the security package only -- nothing
outside it reads the switch -- on a machine that actually has gitleaks,
because where the binary is missing `on` and `off` are the same run and there
is nothing to prove.

WHAT IT COSTS, stated rather than discovered: the engines-on run is the suite
again, plus the engine invocations, so `pytest tests/security/` roughly
triples on a machine with gitleaks installed. That is the price of the
guarantee and it is the honest one. The cheaper candidate was a static check
-- every test naming a scanner rule must also name `CC_SECURITY_ENGINES` --
and it was rejected because it would have caught six of the seven: the
seventh, `test_migrate_rules_is_refused_without_gitleaks`, named no rule at
all and asserted a refusal that only the ambient default produced. A guard
that catches most of a class is how the next one gets through.

There is no CI in this repository (`.github/` holds a PR template and nothing
else), so "the suite" is the only gate there is, and a gate that runs one of
the two configurations is a gate on half the product.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from security import engines

SUITE = Path(__file__).resolve().parent
REPO = SUITE.parent.parent


@pytest.mark.skipif(
    engines.find("gitleaks") is None,
    reason="no gitleaks here: engines on and off are the same run")
@pytest.mark.skipif(
    os.environ.get("CC_SECURITY_ENGINES") == "on",
    reason="this run IS the engines-on run -- it would only spawn itself")
def test_the_security_suite_is_green_with_the_engines_on():
    """Run the whole security suite again with the engines switched on.

    The two skips are also the recursion guard: the child run has
    `CC_SECURITY_ENGINES=on` in its environment, so its own copy of this test
    skips instead of forking a third.
    """
    out = subprocess.run(
        [sys.executable, "-m", "pytest", str(SUITE), "-q", "--tb=line", "-rf",
         "-p", "no:cacheprovider"],
        cwd=str(REPO), capture_output=True, text=True, check=False,
        env={**os.environ, "CC_SECURITY_ENGINES": "on"})

    lines = out.stdout.splitlines()
    failed = [ln for ln in lines if ln.startswith("FAILED") or ln.startswith("ERROR")]
    report = "\n".join(failed or lines[-25:])

    # A COLLECTION failure is not a pass. pytest exits 5 having run nothing
    # when it collects nothing, and it aborts the entire run with "no tests
    # ran" when one node id is missing -- output with zero FAILED lines in it,
    # which reads exactly like success to anything that only greps for those.
    # So the count is asserted before the exit code, not after.
    ran = re.search(r"(\d+) passed", out.stdout)
    assert ran and int(ran.group(1)) > 0, (
        "the engines-on run reported no passing tests at all, which is a "
        f"collection failure and not a green run (rc={out.returncode}):\n"
        f"{report}\n{out.stderr[-2000:]}")

    assert out.returncode == 0, (
        "tests/security/ is RED with CC_SECURITY_ENGINES=on -- the "
        "configuration every real analysis runs in. A test that depends on "
        "which scanner ran has to say so in its own env, the way "
        "test_the_default_noise_filter_reaches_every_deterministic_phase "
        f"does; the ambient default is not a fact a test may inherit:\n{report}")
