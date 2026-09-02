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
outside it reads the switch -- on a machine that actually has one of the
engines, because where none of them is installed `on` and `off` really are the
same run and there is nothing to prove.

ONE OF THE FOUR, NOT GITLEAKS. The first version of this guard skipped unless
gitleaks was present, reasoning that without it "engines on and off are the
same run". That is false, and falsifiably so: `adapters.engine_path` is the
one switch, and it gates the DEPENDENCY phase (`cli._scan_dependencies`, via
trivy), the SAST pre-pass (`cli._scan_sast`, via semgrep), the IaC phase
(`cli._scan_iac`, via trivy) and the SBOM producer (`cli._scan_sbom`, via
syft) exactly as it gates the secret phase. On a trivy/semgrep-only machine
the guard skipped while the two configurations genuinely differed -- silently
proving nothing, which is the precise failure it exists to end.

WHAT IT COSTS, stated rather than discovered: the engines-on run is the suite
again, plus the engine invocations, so `pytest tests/security/` roughly
triples on a machine with the engines installed. That is the price of the
guarantee and it is the honest one. The cheaper candidate was a static check
-- every test naming a scanner rule must also name `CC_SECURITY_ENGINES` --
and it was rejected because it would have caught six of the seven: the
seventh, `test_migrate_rules_is_refused_without_gitleaks`, named no rule at
all and asserted a refusal that only the ambient default produced. A guard
that catches most of a class is how the next one gets through.

AND THERE IS NO OPT-OUT ENVIRONMENT VARIABLE, which was weighed rather than
forgotten. An opt-out would buy back ~170 seconds for whoever set it, and it
is the kind of variable that gets exported once into a shell profile and never
unset -- converting a cost that is loud into a gap that is silent, in the one
file written to end exactly that. The fast path costs nothing and needs no
switch: while iterating, deselect this node id (the README says how). Then the
gate is intact for anyone who runs the suite plainly, which is what a gate is
for.

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

from security import adapters, engines

SUITE = Path(__file__).resolve().parent
REPO = SUITE.parent.parent

# Every binary `adapters.engine_path` gates. If NONE of them is installed, the
# child run really would be the parent run again.
ENGINES = ("gitleaks", "trivy", "semgrep", "syft")


def _engines_are_on() -> bool:
    """Whether THIS process is already the engines-on run.

    Asks the question the product asks, rather than `== "on"`. `engine_path`
    treats anything not in `adapters._OFF` as on, so `CC_SECURITY_ENGINES=ON`
    -- or `1`, or `yes` -- was an engines-on run that did not recognise itself
    and spawned a second one, paying 166 seconds to run the configuration it
    was already running.
    """
    return (os.environ.get(adapters.ENGINES_ENV, "").strip().lower()
            not in adapters._OFF)


@pytest.mark.skipif(
    all(engines.find(name) is None for name in ENGINES),
    reason=f"none of {', '.join(ENGINES)} is installed here: with no engine to "
           "reach, engines on and off are the same run")
@pytest.mark.skipif(
    _engines_are_on(),
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


# ------------------------------- the two predicates, pinned so they stay true

def _would_skip(installed, monkeypatch) -> bool:
    """The guard's own first skip predicate, over a pretended machine."""
    monkeypatch.setattr(engines, "find",
                        lambda name: f"/usr/bin/{name}" if name in installed else None)
    return all(engines.find(name) is None for name in ENGINES)


def test_the_guard_does_not_skip_on_a_machine_with_only_trivy_and_semgrep(monkeypatch):
    """THE SKIP THAT PROVED NOTHING. It used to read `engines.find("gitleaks")
    is None`, reasoning "engines on and off are the same run" -- and
    `adapters.engine_path` is one switch over four binaries, gating the
    dependency phase (`cli._scan_dependencies`), the SAST pre-pass
    (`cli._scan_sast`), the IaC phase (`cli._scan_iac`) and the SBOM producer
    (`cli._scan_sbom`) as well as the secret phase. On a trivy/semgrep-only
    machine the guard skipped while the two configurations genuinely
    differed, which is the precise failure it exists to end.
    """
    assert not _would_skip({"trivy", "semgrep"}, monkeypatch)
    assert not _would_skip({"gitleaks"}, monkeypatch)
    assert not _would_skip({"syft"}, monkeypatch)


def test_the_guard_skips_only_when_NO_engine_is_installed(monkeypatch):
    """The one machine where `on` and `off` really are the same run, and the
    only one where skipping proves as much as running."""
    assert _would_skip(set(), monkeypatch)


def test_the_guard_reads_the_switch_the_way_the_PRODUCT_reads_it(monkeypatch):
    """`== "on"` was not the product's own test. `engine_path` treats anything
    not in `adapters._OFF` as on, so `CC_SECURITY_ENGINES=ON` was an
    engines-on run that did not recognise itself and spawned a second one --
    166 seconds to run the configuration it was already running."""
    for spelling in ("on", "ON", "1", "yes", "true"):
        monkeypatch.setenv(adapters.ENGINES_ENV, spelling)
        assert _engines_are_on(), spelling
        assert ((adapters.engine_path("gitleaks") is not None)
                == (engines.find("gitleaks") is not None)), spelling
    for spelling in ("off", "OFF", "0", "no", "false", "none", " off "):
        monkeypatch.setenv(adapters.ENGINES_ENV, spelling)
        assert not _engines_are_on(), spelling
        assert adapters.engine_path("gitleaks") is None, spelling
