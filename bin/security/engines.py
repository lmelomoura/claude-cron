"""The one door to an external scanner binary.

Everything about running someone else's program lives here: finding it,
checking it answers, running it, and -- the part that matters -- throwing
away the fields it returns that carry the thing we promised never to
record.

WHY THE PURGE HAPPENS HERE AND NOT AT THE CALL SITE. Three of the four
engines return the content they matched: Gitleaks puts the credential in
`Match` and `Secret`, Semgrep returns the source line in `extra.lines`,
and Trivy's secret scanner has its own `Match`. If the purge lived in the
adapter, every future adapter would have to remember it, and a debug
`print` between the parse and the purge would be enough to put a
credential into the run's `.stream.ndjson`. That is not hypothetical:
this repository's own logs carry a 1,546-character PEM block, printed by
a masking command the agent built and then never piped through. A
promise that depends on somebody remembering a step is not a promise.

OUTPUT GOES TO A FILE, NEVER TO A PIPE WE PRINT. Each engine is asked to
write JSON to a temporary file. Nothing this module returns has passed
through a stream the run's transcript captures.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

# Engine -> the field NAMES whose values carry matched content. NAMES, not
# paths: `_strip` drops them from every dict it walks, at every depth, and
# that is the design rather than a shortcut. Gitleaks returns a flat list
# today and Semgrep nests `lines` two levels down, but a version bump moves
# fields around, and a table written as paths would keep matching the old
# shape and silently stop purging -- a leak that looks exactly like a clean
# report. Depth-agnostic costs a little over-stripping (an unrelated key
# that happens to share the name goes too) and buys the guarantee that a
# field cannot escape by moving. Do not add a path-shaped entry here: it
# would never match anything.
#
# An engine that is NOT a key here is REFUSED, not passed through -- see
# `purge`. An engine that genuinely returns nothing it matched is registered
# with an empty tuple, so "nothing to strip" is always a decision somebody
# recorded and never the accident of a name nobody added.
PURGE = {
    # `Match` is the line, `Secret` is the credential itself.
    "gitleaks": ("Match", "Secret"),
    # `lines` is the matched source. `abstract_content` (and its propagated
    # twin) is what a metavariable bound to -- for a rule that fires ON a
    # hardcoded credential, that IS the credential. `fix` / `rendered_fix`
    # quote the source back in order to rewrite it, and `dataflow_trace`
    # carries a snippet for every step of the path.
    "semgrep": ("lines", "abstract_content", "svalue_abstract_content",
                "fix", "rendered_fix", "dataflow_trace"),
    # `Match` is the secret scanner's. `Content` and `Highlighted` are the
    # raw source lines Trivy attaches to a secret AND to a misconfiguration,
    # under `Code.Lines[]` in both.
    "trivy": ("Match", "Content", "Highlighted"),
    # Syft produces a Software Bill of Materials, not a match report: package
    # names, versions, licences, purls and cpes, assembled from a lockfile's
    # own declarations rather than from a scan for a credential's or a
    # secret's value. There is nothing here that ever carries matched
    # content, so the empty tuple is a decision this table records, not a
    # gap in it -- see the module docstring above for why an engine absent
    # from `PURGE` is refused rather than assumed safe.
    "syft": (),
}

_TIMEOUT = 600


class UnknownEngine(LookupError):
    """`purge` was asked about an engine `PURGE` does not name.

    Raised rather than answered, because the useful answer does not exist:
    "I do not know what this engine puts its matched content in" and "this
    engine has no matched content" are different facts, and only the second
    one is safe to act on. `PURGE` records the second explicitly.
    """


def find(name: str):
    """The binary's path, or None. Never raises: absence is a normal state."""
    return shutil.which(name)


def version_of(name: str):
    """The engine's own version string, or None if it will not answer.

    An engine that is installed but will not report a version is treated
    as absent by the callers: a parser written against a format that has
    since changed is worse than a phase that declared it did not run.
    """
    path = find(name)
    if not path:
        return None
    for flag in ("--version", "version"):
        try:
            # errors="replace": an engine is free to put raw bytes in its
            # banner or on stderr, and strict decoding would raise
            # UnicodeDecodeError -- a ValueError, which slips past the
            # handler below and out of a function documented to return None.
            out = subprocess.run([path, flag], capture_output=True, text=True,
                                 errors="replace", timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip().splitlines()[0]
    return None


def _strip(obj, fields):
    """Recursively drop `fields` from every dict in `obj`."""
    if isinstance(obj, dict):
        return {k: _strip(v, fields) for k, v in obj.items() if k not in fields}
    if isinstance(obj, list):
        return [_strip(v, fields) for v in obj]
    return obj


def fields_for(name: str):
    """`PURGE`'s entry for `name`, or raise. Never returns "I don't know"."""
    try:
        return PURGE[name]
    except KeyError:
        raise UnknownEngine(
            f"{name!r} is not in engines.PURGE, so which of its fields carry "
            f"matched content is unknown. Add it to the table -- with an "
            f"empty tuple if it carries none.") from None


def purge(name: str, data):
    """`data` with the engine's forbidden fields removed, at any depth.

    Recursive on purpose. Gitleaks returns a flat list today and Semgrep
    nests `lines` two levels down, but a version bump can move a field --
    and a purge that only looks where the field is today would silently
    stop purging.

    FAILS CLOSED on a name it does not know. This used to return `data`
    untouched, which made every kind of typo silent: `purge("gitleaks-git",
    raw)` and `purge("Gitleaks", raw)` both handed the credential straight
    back. It is not a theoretical slip -- the Gitleaks adapter calls this
    module twice, once for the tree and once for the history, and only one
    of the two has to be spelled wrong. In a module whose whole argument is
    that forgetting must be impossible, "I have never heard of this engine"
    cannot mean "then everything it found is fine to keep".
    """
    return _strip(data, frozenset(fields_for(name)))


def run_json(name: str, args, cwd, timeout: int = _TIMEOUT):
    """Run the engine and return (purged JSON, note).

    `note` is empty when everything worked and is a sentence for the
    coverage note otherwise. The engine writes its JSON to a temporary
    file that this function names, so no result ever crosses a stream the
    run's log captures.

    Returns (None, note) for every failure: not installed, not in the purge
    table, will not report a version, timed out, exited badly, wrote
    nothing, or wrote something that is not JSON. An analysis never dies
    because a scanner did; it says what it could not check. That includes
    the failures `purge` raises on: this function is the one door, and a
    door that throws is a dead analysis.
    """
    path = find(name)
    if not path:
        return None, (f"{name} is not installed, so its phase did not run.")
    try:
        # Before the engine is executed, not after: an engine whose output
        # this module cannot strip must not even run. Checked after `find`
        # only so that a missing binary keeps reporting as a missing binary
        # -- both paths return (None, note), so an unregistered engine
        # cannot produce data down either one.
        fields_for(name)
    except UnknownEngine:
        return None, (f"{name} is not in this module's purge table, so it "
                      f"was not run: an engine whose matched content cannot "
                      f"be stripped does not get to produce findings.")
    version = version_of(name)
    if not version:
        return None, (f"{name} is installed but did not report a version, "
                      f"so its phase was skipped rather than parsed blind.")
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "out.json"
        try:
            # errors="replace" for the same reason as in `version_of`, and
            # here the anticipated case is the one that used to crash: an
            # engine that fails while reading a file puts that file's BYTES
            # in its error message, and a repository holding a binary blob
            # or a filename that is not valid UTF-8 turned a scanner hiccup
            # into a dead analysis. Nothing is lost by decoding loosely --
            # stderr is never quoted back.
            proc = subprocess.run([path, *[a.replace("{out}", str(out_file)) for a in args]],
                                  cwd=str(cwd), capture_output=True, text=True,
                                  errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f"{name} did not finish within {timeout}s and was stopped."
        except OSError as exc:
            return None, f"{name} could not be run: {exc.__class__.__name__}."
        if not out_file.exists():
            # stderr is NOT quoted back: an engine that fails while reading a
            # file can put that file's bytes in its error message.
            return None, (f"{name} exited {proc.returncode} without writing a "
                          f"report, so its phase did not run.")
        try:
            data = json.loads(out_file.read_text())
        except (ValueError, OSError, RecursionError):
            # RecursionError is a RuntimeError, not a ValueError: a report
            # nested deeper than the interpreter will descend is exactly the
            # "wrote something that is not JSON" case above, and without it
            # named here it escaped as an exception instead. `_strip` walks
            # far deeper than `json.loads` does, so the limit reached here is
            # always the parser's.
            return None, f"{name} wrote a report this version cannot read."
    try:
        clean = purge(name, data)
    except RecursionError:
        # The same escape as above, one step later and easy to miss:
        # `json.loads` descends in C and tolerates thousands of levels,
        # while `_strip` is a Python walk that stops around 995 -- so a
        # report can parse cleanly and still be too deep to strip. Handing
        # back what came out of the parser is not an option; the report is
        # dropped, like every other report this module cannot handle.
        # `UnknownEngine` cannot arrive here: the table was consulted
        # before the engine ran.
        return None, (f"{name} wrote a report too deeply nested to purge, "
                      f"so it was dropped rather than reported unstripped.")
    return clean, ""
