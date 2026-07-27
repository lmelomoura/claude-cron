"""Checks on the dashboard page that do not need a browser.

The page is ~100 KB of JS inside the server, so a typo in it is invisible to
every other test here and only shows up as a blank dashboard. These are the
cheap guards: it parses, the elements the new code reaches for exist, and the
arithmetic it duplicates from the engine still agrees with the engine.
"""

import re
import shutil
import subprocess

import pytest

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
ENGINE = REPO / "bin" / "claude-cron"


def _page(srv):
    return srv.render_page()


def _js(srv):
    return re.search(r"<script>(.*)</script>", _page(srv), re.S).group(1)


def test_the_page_renders_with_the_token_and_favicon_substituted(srv):
    page = _page(srv)
    assert "__TOKEN__" not in page and "__BUILD__" not in page and "__FAVICON__" not in page
    assert srv.TOKEN in page


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_page_javascript_parses(srv, tmp_path):
    f = tmp_path / "page.js"
    f.write_text(_js(srv))
    p = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


def test_every_element_the_script_reaches_for_exists(srv):
    """$("foo") against an id the markup does not define is a silent no-op that
    turns into a TypeError the first time the code touches .value."""
    page = _page(srv)
    html = page.split("<script>")[0]
    ids = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', html))
    # ids created at runtime by innerHTML rather than present in the skeleton
    dynamic = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', page.split("<script>", 1)[1]))
    referenced = set(re.findall(r'\$\("([a-zA-Z0-9_-]+)"\)', _js(srv)))
    missing = referenced - ids - dynamic
    assert not missing, f"script reaches for ids that no markup defines: {sorted(missing)}"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_backoff_curve_matches_the_engine(srv, tmp_path):
    """The page recomputes the engine's backoff so it can say when the next
    check really is. Two implementations of one rule drift; this is what stops
    the card promising a check the tick will not make."""
    js = _js(srv)
    fn = re.search(r"const BACKOFF_AFTER=.*?\n};", js, re.S).group(0)
    script = tmp_path / "b.js"
    script.write_text(fn + "\nconsole.log([0,1,2,3,4,5,6,7,20]"
                           ".map(backoffMultiplier).join(' '));")
    from_js = subprocess.run(["node", str(script)],
                             capture_output=True, text=True, check=True).stdout.split()

    from_bash = []
    for s in (0, 1, 2, 3, 4, 5, 6, 7, 20):
        out = subprocess.run(
            ["/bin/bash", "-c",
             f'source "{ENGINE}" >/dev/null 2>&1; backoff_multiplier {s}'],
            capture_output=True, text=True)
        from_bash.append(out.stdout.strip())

    assert from_js == from_bash, f"js={from_js} bash={from_bash}"
