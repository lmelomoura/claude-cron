"""The suite has to be green in the configuration that ships.

`conftest.py` pins `AL_SECURITY_ENGINES=off` so that a test which plants a
credential exercises ONE scanner rather than whichever one a laptop happens to
have installed. That pin is right. What it also did, silently, was buy the
whole suite a configuration nobody checks: a real analysis runs with the
engines ON, and for the entire life of the engine path
`AL_SECURITY_ENGINES=on pytest tests/security/` was red -- seven tests
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
-- every test naming a scanner rule must also name `AL_SECURITY_ENGINES` --
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

THE OTHER HALF OF THIS GUARANTEE IS NOW `.github/workflows/ci.yml`, which runs
both configurations as two named jobs over engines it installs at pinned
versions. This test is not made redundant by that, and it is not the same
check: CI proves the two configurations pass on a machine that HAS the engines,
while this proves that a developer who has them cannot get a green local run
having exercised only one configuration -- the failure that actually happened
here, months before anyone looked. CI deliberately deselects THIS test in its
engines-off job (and only there): the second configuration is a separate job
there, and spawning it from inside the first would be a third execution of a
~250s suite. Locally, nothing deselects it.
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

# Every outcome that means a test was RUN, so that `passed + skipped + ...`
# can be held against what collection found. `deselected` is deliberately
# absent: a deselected test is one nobody ran, which is the whole failure
# below.
_OUTCOMES = ("passed", "failed", "error", "errors", "skipped", "xfailed",
             "xpassed")


def _ran(stdout: str) -> int:
    """How many tests the child actually ran, off its own summary line."""
    return sum(int(n) for n, word in re.findall(
        r"(\d+) (%s)\b" % "|".join(_OUTCOMES), stdout))


def _collected() -> int:
    """How many tests `tests/security/` HOLDS -- asked, not assumed.

    A separate collection pass rather than this run's own `testscollected`,
    because the parent may itself be a subset (`pytest tests/security/
    test_diff.py`, or a `-k` while iterating) while the child always runs the
    whole directory. Comparing the child against the parent's selection would
    make the gate weaker exactly when someone is narrowing it.

    Collection is ~0.2s and executes no test. `skipif` markers do not change
    it: a skipped test is still a collected one, and it is still counted in
    the child's `N skipped`.
    """
    out = subprocess.run(
        [sys.executable, "-m", "pytest", str(SUITE), "-q", "--collect-only",
         "-p", "no:cacheprovider"],
        cwd=str(REPO), capture_output=True, text=True, check=False)
    found = re.search(r"(\d+) tests? collected", out.stdout)
    assert found, ("could not count the tests in tests/security/ -- without "
                   "that number the engines-on run below cannot be told from "
                   f"a partial collection of it:\n{out.stdout[-2000:]}")
    return int(found.group(1))


def _engines_are_on() -> bool:
    """Whether THIS process is already the engines-on run.

    Goes through `adapters._engines_setting()` rather than reading the
    environment itself, so this can never disagree with `engine_path` about
    what the switch says -- under either its current spelling or its
    pre-rename one. `engine_path` treats anything not in `adapters._OFF` as
    on, so `AL_SECURITY_ENGINES=ON` -- or `1`, or `yes` -- was an engines-on
    run that did not recognise itself and spawned a second one, paying 166
    seconds to run the configuration it was already running.
    """
    return adapters._engines_setting() not in adapters._OFF


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
    `AL_SECURITY_ENGINES=on` in its environment, so its own copy of this test
    skips instead of forking a third.
    """
    out = subprocess.run(
        [sys.executable, "-m", "pytest", str(SUITE), "-q", "--tb=line", "-rf",
         "-p", "no:cacheprovider"],
        cwd=str(REPO), capture_output=True, text=True, check=False,
        env={**os.environ, "AL_SECURITY_ENGINES": "on"})

    lines = out.stdout.splitlines()
    failed = [ln for ln in lines if ln.startswith("FAILED") or ln.startswith("ERROR")]
    report = "\n".join(failed or lines[-25:])

    # A COLLECTION failure is not a pass. pytest exits 5 having run nothing
    # when it collects nothing, and it aborts the entire run with "no tests
    # ran" when one node id is missing -- output with zero FAILED lines in it,
    # which reads exactly like success to anything that only greps for those.
    # So the count is asserted before the exit code, not after.
    #
    # AGAINST THE SUITE'S OWN COUNT, not against zero. `N passed with N > 0`
    # plus `returncode == 0` is satisfied by a run that collected 40 of 808
    # and passed all forty -- a green gate over 5% of the suite. Anything that
    # narrows the child's collection (a plugin erroring while collecting one
    # module, an `--ignore` leaking in from a config file, a conftest raising
    # `Skipped` at module scope) now fails here instead of passing quietly.
    # CI needs no equivalent of this: it invokes each configuration directly
    # and reads pytest's own exit code, which is already non-zero when a
    # module errors during collection. This test has only a child's stdout.
    expected = _collected()
    ran = _ran(out.stdout)
    assert ran >= expected, (
        f"the engines-on run accounted for {ran} of the {expected} tests "
        "tests/security/ holds, so it is a PARTIAL run being reported as a "
        f"green one (rc={out.returncode}):\n"
        f"{report}\n{out.stderr[-2000:]}")

    assert out.returncode == 0, (
        "tests/security/ is RED with AL_SECURITY_ENGINES=on -- the "
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
    not in `adapters._OFF` as on, so `AL_SECURITY_ENGINES=ON` was an
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

    # The pre-rename spelling too -- otherwise the guard can read the switch
    # on while the product it is guarding has already read it off.
    monkeypatch.delenv(adapters.ENGINES_ENV, raising=False)
    monkeypatch.setenv(adapters.LEGACY_ENGINES_ENV, "off")
    assert not _engines_are_on()
