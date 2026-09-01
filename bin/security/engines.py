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

# Engine -> the fields that carry matched content, by the path they sit at.
# "*" means "every element of the top-level list".
PURGE = {
    "gitleaks": ("Match", "Secret"),
    "semgrep": ("lines",),
    "trivy": ("Match",),
}

_TIMEOUT = 600


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
            out = subprocess.run([path, flag], capture_output=True, text=True,
                                 timeout=30)
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


def purge(name: str, data):
    """`data` with the engine's forbidden fields removed, at any depth.

    Recursive on purpose. Gitleaks returns a flat list today and Semgrep
    nests `lines` two levels down, but a version bump can move a field --
    and a purge that only looks where the field is today would silently
    stop purging.
    """
    fields = PURGE.get(name)
    if not fields:
        return data
    return _strip(data, frozenset(fields))


def run_json(name: str, args, cwd, timeout: int = _TIMEOUT):
    """Run the engine and return (purged JSON, note).

    `note` is empty when everything worked and is a sentence for the
    coverage note otherwise. The engine writes its JSON to a temporary
    file that this function names, so no result ever crosses a stream the
    run's log captures.

    Returns (None, note) for every failure: not installed, will not report
    a version, timed out, exited badly, wrote nothing, or wrote something
    that is not JSON. An analysis never dies because a scanner did; it
    says what it could not check.
    """
    path = find(name)
    if not path:
        return None, (f"{name} is not installed, so its phase did not run.")
    version = version_of(name)
    if not version:
        return None, (f"{name} is installed but did not report a version, "
                      f"so its phase was skipped rather than parsed blind.")
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "out.json"
        try:
            proc = subprocess.run([path, *[a.replace("{out}", str(out_file)) for a in args]],
                                  cwd=str(cwd), capture_output=True, text=True,
                                  timeout=timeout)
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
        except (ValueError, OSError):
            return None, f"{name} wrote a report this version cannot read."
    return purge(name, data), ""
