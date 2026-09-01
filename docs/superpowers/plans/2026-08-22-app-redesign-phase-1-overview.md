# App Redesign — Phase 1 (Foundation and Overview) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the dashboard's CSS and its Overview page out of `bin/dashboard.html` into built modules under `ui/`, restyle the Overview into the visual language of the Security mockups, and close two latent bugs this move would otherwise activate.

**Architecture:** Three new build artifacts (`bin/static/app.css`, `bin/static/app.js`, alongside the existing `security.js`) are produced by `build/build-ui.sh` from sources under `ui/css/` and `ui/app/`, committed to git, and proven fresh by the selftest. `ui/app/page.js` states the interface the page hands the bundle, exactly as `ui/security/page.js` already does. The Overview's renderers build DOM nodes rather than HTML strings, which the existing sink-scan test enforces the moment the files exist.

**Tech Stack:** Bash, Python 3 stdlib, vanilla ES modules bundled by a pinned `esbuild@0.25.0`, pytest, Node (test harness only).

## Global Constraints

- **Runtime dependencies never grow.** Installing claude-cron needs `jq`, `python3`, `curl`, `git`, `bash` — never Node. Build outputs are committed.
- **Prose the user reads is pt-PT; everything shipped is English.** Code, identifiers, docstrings, code comments, commit messages, branch names: English.
- **Behaviour does not change in this phase.** Only where information is read, and where the code that draws it lives. No number changes.
- **esbuild is pinned at `0.25.0`** and invoked through `npx --yes`.
- **Every task ends green:** `pytest`, `bash bin/claude-cron selftest`, clean tree.
- **Every task that touches `bin/`, `skills/` or `test/` writes its own CHANGELOG.md entry, in the same commit.** The selftest compares the last commit touching those paths against the last touching `CHANGELOG.md`; a task that defers the entry leaves the tree red for every task after it. Write the entry the way the file's own header asks: say what behaviour changed and what it cost not to have it.
- **Run the selftest AFTER committing, not before.** The changelog guard reads `git log`, not the working tree, so a gate run before the commit is reading the previous task's state and will pass on a tree that is about to be red.
- **Build artifacts are committed in the same commit as the sources they were built from.** A task that edits anything under `ui/` runs `bash build/build-ui.sh` before committing.
- **Branch:** `feat/security-analysis`. No new branches.
- **`ui/app/` must never build DOM from HTML strings.** `_security_sources()` in `tests/test_page_contract.py` already walks all of `ui/`, so the sink-scan applies from the moment the directory exists.

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `ui/css/tokens.css` | The `:root` custom properties, light and dark. Nothing else. |
| `ui/css/components.css` | Page header, KPI card, filter bar, table card, table footer and pager, pills, buttons, tabs, right rail. The shared vocabulary. |
| `ui/css/pages.css` | Everything that belongs to one page and is not a component. |
| `ui/app/page.js` | The stated interface the dashboard hands the bundle. Mirrors `ui/security/page.js`. |
| `ui/app/jobs-domain.js` | `jobFacts`, `visibleJobs`, the job filters, bulk state. Pure — no DOM. |
| `ui/app/overview.js` | The greeting, the 24h band, the KPI cards, the job cards, the worktrees card. |
| `ui/app/index.js` | `bindPage` plus the surface the dashboard calls. |
| `bin/static/app.css` | Built artifact, committed. |
| `bin/static/app.js` | Built artifact, committed. |

**Modified:**

| Path | Change |
|---|---|
| `bin/claude-cron-server` | `_build_id()` stops globbing `*.js` only. |
| `bin/claude-cron` | The selftest's freshness block becomes a function run over three artifacts. |
| `build/build-ui.sh` | Builds three artifacts; stamps all three with the block-comment form. |
| `build/ui-bundle-digest.sh` | Reads and strips the block-comment stamp form. |
| `bin/dashboard.html` | Loses the `<style>` block and the Overview's renderers; gains the theme script, the stylesheet link, and the `app.js` tag. |
| `tests/test_page_contract.py` | New Overview characterisation tests; the sink-scan test is renamed. |
| `tests/test_static_route.py` | `app.css` is served as CSS. |

---

## Task 1: The build id sees CSS

`_build_id()` hashes `STATIC_DIR.glob("*.js")`. Once a stylesheet lives in that directory, a change to it would not move the build id, and `?v=` would serve the old CSS from an open tab's cache forever. This runs first because every later task depends on a served asset actually reaching the browser.

**Files:**
- Modify: `bin/claude-cron-server` (`_build_id`, around line 3290)
- Test: `tests/test_static_route.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `_build_id()` reacts to any file in `bin/static/` whose suffix is a key of `STATIC_TYPES`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_static_route.py`:

```python
def test_the_build_id_moves_when_a_served_stylesheet_changes(
        srv, tmp_path, monkeypatch):
    """`_build_id` used to glob "*.js" alone. The page asks for every asset
    with `?v=<build id>` on it, so an id that cannot see a stylesheet serves
    a changed one out of an open tab's cache indefinitely -- the exact
    failure the id was added to prevent for the JS bundle.

    Driven through the same table that decides what this directory is
    allowed to serve: anything servable has to be fingerprinted, or the two
    disagree and the gap is a cache that never clears."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    (tmp_path / "app.css").write_text(":root{--bg:#fff}")
    before = srv._build_id()
    (tmp_path / "app.css").write_text(":root{--bg:#000}")
    assert srv._build_id() != before, (
        "a changed stylesheet left the build id untouched -- "
        "browsers will keep serving the old one from cache"
    )


def test_every_servable_extension_is_fingerprinted(srv, tmp_path, monkeypatch):
    """Not "js and css" spelled out a second time: the fingerprint walks the
    same STATIC_TYPES table the route reads, so a third type added there is
    covered without anybody remembering to come back here."""
    monkeypatch.setattr(srv, "STATIC_DIR", tmp_path)
    ids = set()
    for i, suffix in enumerate(sorted(srv.STATIC_TYPES)):
        (tmp_path / f"a{suffix}").write_text(f"/* {i} */")
        ids.add(srv._build_id())
    assert len(ids) == len(srv.STATIC_TYPES), (
        "adding a servable file did not always move the build id"
    )
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_static_route.py -k build_id -v`
Expected: FAIL — `a changed stylesheet left the build id untouched`.

- [ ] **Step 3: Make the fingerprint read the same table the route reads**

In `bin/claude-cron-server`, replace the loop inside `_build_id()`:

```python
    # Everything this directory is ALLOWED to serve, not a second list of
    # extensions kept in step by hand. The page asks for each asset with
    # `?v=<this id>`, so a servable file the id cannot see is a file an open
    # tab keeps out of cache forever. This globbed "*.js" while the Security
    # bundle was the only asset; the stylesheet that joined it in the same
    # directory would have been invisible.
    served = sorted(p for p in STATIC_DIR.iterdir()
                    if p.suffix in STATIC_TYPES) if STATIC_DIR.is_dir() else []
    for f in (PAGE_FILE, Path(__file__), *served):
```

Leave the body of the loop and the `except OSError` fallback exactly as they are.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_static_route.py -v`
Expected: PASS, all of them.

- [ ] **Step 5: Full gates and commit**

```bash
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add bin/claude-cron-server tests/test_static_route.py
git commit -m "fix(server): the build id sees every asset the route serves

_build_id() globbed *.js, from when the Security bundle was the only
thing in bin/static/. The page requests each asset with ?v=<build id>,
so an id blind to a stylesheet would serve a changed one out of an open
tab's cache with nothing to clear it.

Reads STATIC_TYPES -- the table that already decides what this route may
serve -- rather than a second list of extensions to keep in step by
hand.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: One stamp format, valid in both languages

Two artifacts will be JavaScript and one will be CSS. CSS has no `//` comments. Rather than teach every reader two forms, both move to the block form `/* ui-sources: … */`, which is a valid comment in JS and CSS alike.

**Files:**
- Modify: `build/ui-bundle-digest.sh`
- Modify: `build/build-ui.sh`
- Modify: `bin/claude-cron` (selftest freshness block, around line 5996)
- Test: `tests/test_page_contract.py`

**Interfaces:**
- Consumes: nothing.
- Produces: stamps are written and read as `/* ui-sources: <hex> */` and `/* ui-bundle: <hex> */`, exactly one of each per artifact. `build/ui-bundle-digest.sh <path>` strips both forms before hashing.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_page_contract.py`, after the existing freshness tests (near `test_a_second_stamp_line_is_refused_rather_than_silently_preferred`):

```python
def test_the_stamp_form_is_a_block_comment_so_css_can_carry_it(tmp_path):
    """One stamp form across every built artifact. CSS has no `//` comment,
    and the alternative -- a line form for JS and a block form for CSS -- is
    two spellings for every reader to accept and one of them to forget. The
    block form is valid in both languages, so there is only ever one."""
    art = tmp_path / "app.css"
    art.write_text(":root{--bg:#fff}\n")
    body = subprocess.run(["bash", str(REPO / "build" / "ui-bundle-digest.sh"),
                           str(art)], capture_output=True, text=True,
                          check=True).stdout.strip()
    art.write_text(":root{--bg:#fff}\n"
                   f"/* ui-bundle: {body} */\n"
                   "/* ui-sources: deadbeef */\n")
    again = subprocess.run(["bash", str(REPO / "build" / "ui-bundle-digest.sh"),
                            str(art)], capture_output=True, text=True,
                           check=True).stdout.strip()
    assert again == body, (
        "the stamps were not stripped before hashing -- a stamped artifact "
        "no longer hashes to what the build recorded for it"
    )


def test_a_second_block_stamp_is_refused_in_either_language(tmp_path):
    """The exactly-one rule is what stops a freshly computed stamp being
    appended below the real one and read instead of it. It has to hold for
    the block form too, or the hole simply moved."""
    for name in ("app.css", "app.js"):
        art = tmp_path / name
        art.write_text("body{}\n"
                       "/* ui-sources: aaaa */\n"
                       "/* ui-sources: bbbb */\n")
        r = subprocess.run(["bash", str(REPO / "build" / "ui-bundle-digest.sh"),
                            str(art)], capture_output=True, text=True)
        assert r.returncode == 1, f"{name}: a doubled stamp was accepted"
        assert "stamps" in r.stderr, f"{name}: refused without saying why"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `pytest tests/test_page_contract.py -k block_stamp -v` and
`pytest tests/test_page_contract.py -k "stamp_form" -v`
Expected: FAIL — the digest script only knows the `//` form, so the stamps are hashed as content.

- [ ] **Step 3: Teach the digest script the block form**

In `build/ui-bundle-digest.sh`, replace the counting loop and the body extraction:

```bash
# ONE stamp form for every built artifact. bin/static/ holds JavaScript and
# CSS, and CSS has no `//` comment -- a line form for one and a block form for
# the other is two spellings for every reader here, in build-ui.sh and in the
# selftest, and one of them to forget. `/* ... */` is valid in both languages,
# so there is exactly one form to write and one to strip.
for kind in ui-sources ui-bundle; do
  n="$(grep -c "^/\* $kind: .* \*/\$" "$bundle" || true)"
  if [ "${n:-0}" -gt 1 ]; then
    echo "ui-bundle-digest: $bundle carries $n '$kind' stamps — exactly" \
         "one is expected, and a second one hides whatever the first says" >&2
    exit 1
  fi
done

{ grep -v -e '^/\* ui-sources: .* \*/$' -e '^/\* ui-bundle: .* \*/$' \
    "$bundle" || true; } | shasum -a 256 | awk '{print $1}'
```

- [ ] **Step 4: Write the stamps in the new form**

In `build/build-ui.sh`, replace the two `printf` lines:

```bash
printf '/* ui-bundle: %s */\n' "$(bash build/ui-bundle-digest.sh bin/static/security.js)" \
  >> bin/static/security.js
printf '/* ui-sources: %s */\n' "$(bash build/ui-digest.sh)" >> bin/static/security.js
```

- [ ] **Step 5: Teach the selftest to read it**

In `bin/claude-cron`, inside the freshness block, replace the four reads:

```bash
    _ns="$(grep -c '^/\* ui-sources: .* \*/$' "$_bundle" || true)"
    _nb="$(grep -c '^/\* ui-bundle: .* \*/$' "$_bundle" || true)"
    _stamp="$(sed -n 's|^/\* ui-sources: \(.*\) \*/$|\1|p' "$_bundle")"
    _bstamp="$(sed -n 's|^/\* ui-bundle: \(.*\) \*/$|\1|p' "$_bundle")"
```

- [ ] **Step 6: Rebuild, verify, commit**

```bash
bash build/build-ui.sh
tail -2 bin/static/security.js   # both stamps in /* ... */ form
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add build/ bin/claude-cron bin/static/security.js tests/test_page_contract.py
git commit -m "build: one stamp form, valid in JavaScript and CSS alike

bin/static/ is about to hold a stylesheet as well as bundles, and CSS
has no // comment. A line form for JS and a block form for CSS would be
two spellings for the digest script, the build and the selftest to
accept, and one of them to forget on the next artifact.

/* ... */ is valid in both languages, so there is one form to write and
one to strip. The exactly-one rule -- what stops a freshly computed
stamp being appended below the real one and read instead of it --
carries over unchanged.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: The theme stops flashing

`applyTheme(themePref())` runs in the script at the end of the body and reads `localStorage`; until then the CSS is in its light default. With 6725 lines of page and 93 KB of bundle ahead of it, a dark-mode user gets a white flash today. Fixing it is also what lets the CSS leave the file in Task 4 without the tokens having to live in two places.

**Files:**
- Modify: `bin/dashboard.html` (`<head>`, around line 4; and `themePref`/`applyTheme`, around line 2528)
- Test: `tests/test_page_contract.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `document.documentElement.dataset.theme` is set before the first stylesheet is parsed. `themePref()` keeps its exact current signature and semantics.

- [ ] **Step 1: Write the failing test**

```python
def test_the_theme_is_resolved_before_the_first_stylesheet(srv):
    """A dark-mode user must never see a white frame. The theme is stored in
    localStorage, which only script can read, so the read has to happen in
    the head ahead of any stylesheet -- once styles are parsed the page can
    paint, and a data-theme applied after that is applied to a frame the user
    has already seen.

    Asserted by position rather than by presence: a theme script that exists
    somewhere on the page is exactly what the page had while it flashed."""
    page = srv.render_page()
    head = page[:page.index("</head>")]
    theme_at = head.index("dataset.theme")
    first_style = min(
        (head.index(m) for m in ("<style", "<link rel=\"stylesheet\"")
         if m in head), default=None)
    assert first_style is not None, "no stylesheet in the head at all"
    assert theme_at < first_style, (
        "the theme is resolved after the first stylesheet -- dark mode will "
        "paint one white frame before it corrects itself"
    )


def test_the_theme_preference_has_exactly_one_definition(srv):
    """The inline head script and themePref() must not each carry their own
    copy of "localStorage, else the media query" -- two spellings of one
    rule, and the day they disagree the page corrects its own first frame to
    the wrong theme."""
    page = srv.render_page()
    assert page.count("prefers-color-scheme: dark") == 1, (
        "the theme preference rule is written in more than one place"
    )
```

- [ ] **Step 2: Run them to verify they fail**

Run: `pytest tests/test_page_contract.py -k theme -v`
Expected: FAIL — `dataset.theme` appears only in the body script, so `head.index` raises `ValueError`.

- [ ] **Step 3: Resolve the theme in the head**

In `bin/dashboard.html`, immediately after the `<meta name="theme-color">` line and **before** `<style>`:

```html
<!-- The theme, resolved before anything can paint. It lives in localStorage,
     which only script can read, and the script that used to read it sat at
     the end of the body behind 6,700 lines of page and a 93 KB bundle -- so
     a dark-mode user got one white frame on every load. The stylesheet below
     is render-blocking, so setting the attribute here means the first frame
     is already right. themePref() further down reads this back rather than
     spelling the rule a second time. -->
<script>
document.documentElement.dataset.theme =
  localStorage.ccTheme ||
  (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
</script>
```

- [ ] **Step 4: Make `themePref()` read it back rather than restate it**

Replace the existing `themePref`:

```javascript
/* The rule itself is in the head script, which had to run before any
   stylesheet (see its comment). Restating it here would be two spellings of
   one preference, and the day they disagreed the page would correct its own
   correct first frame to the wrong theme. */
function themePref(){ return document.documentElement.dataset.theme || "light"; }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_page_contract.py -k theme -v`
Expected: PASS.

- [ ] **Step 6: Full gates and commit**

```bash
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add bin/dashboard.html tests/test_page_contract.py
git commit -m "fix(ui): resolve the theme before the first paint

applyTheme(themePref()) ran in the script at the end of the body and
read localStorage; until then the CSS sat in its light default. With
6725 lines of page and a 93 KB bundle ahead of it, a dark-mode user got
a white frame on every load.

Three lines in the head, ahead of the render-blocking stylesheet, so the
first frame is already right. themePref() reads the attribute back
instead of spelling the rule a second time -- two copies of one
preference would eventually disagree, and the page would then correct a
correct first frame to the wrong theme.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: The CSS moves to `ui/css/` and is served

The mechanical half. 1415 lines and 789 rules leave `bin/dashboard.html` for three files under `ui/css/`, are concatenated into `bin/static/app.css`, and are linked from the head. No rule's text changes in this task — the proof is that the selector set is identical before and after.

**Files:**
- Create: `ui/css/tokens.css`, `ui/css/components.css`, `ui/css/pages.css`
- Modify: `build/build-ui.sh`, `bin/dashboard.html`, `bin/claude-cron` (selftest), `tests/test_static_route.py`
- Test: `tests/test_page_contract.py`

**Interfaces:**
- Consumes: Task 1's fingerprint, Task 2's stamp form, Task 3's head script.
- Produces: `bin/static/app.css`, served at `/static/app.css?v=<build id>`. `build/build-ui.sh` produces three artifacts. The selftest checks all three through one function.

- [ ] **Step 1: Capture the current selector set as the contract**

```python
def _selectors(css_text):
    """Every selector in a stylesheet, as a set. Comments and declaration
    bodies are dropped; whitespace inside a selector is collapsed so
    `a , b` and `a, b` compare equal."""
    body = re.sub(r"/\*.*?\*/", "", css_text, flags=re.S)
    out = set()
    for chunk in re.findall(r"([^{}]+)\{[^{}]*\}", body):
        sel = " ".join(chunk.split())
        if sel and not sel.startswith("@"):
            out.add(sel)
    return out


def test_no_css_rule_was_lost_when_the_stylesheet_moved_out(srv):
    """The move out of dashboard.html is mechanical, and mechanical moves of
    1400 lines lose things quietly. This is the contract: whatever the page
    styled before, it styles now.

    Compares SELECTORS rather than bytes -- the three files are allowed to
    reorder and regroup rules, which is the whole point of splitting them --
    and it is checked against the built artifact, not the sources, so a rule
    that lands in a file the build forgets to concatenate still fails."""
    served, ctype = srv.static_asset("app.css")
    assert ctype.startswith("text/css")
    baseline = (REPO / "tests" / "data" / "css-selectors-before.txt").read_text()
    want = {ln for ln in baseline.splitlines() if ln}
    have = _selectors(served)
    assert not (want - have), f"rules lost in the move: {sorted(want - have)[:20]}"
```

Generate the baseline from the tree as it stands **before** the move:

```bash
mkdir -p tests/data
python3 - <<'EOF' > tests/data/css-selectors-before.txt
import re, pathlib
src = pathlib.Path("bin/dashboard.html").read_text()
css = re.search(r"<style>(.*?)</style>", src, re.S).group(1)
body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
seen = set()
for chunk in re.findall(r"([^{}]+)\{[^{}]*\}", body):
    sel = " ".join(chunk.split())
    if sel and not sel.startswith("@"):
        seen.add(sel)
for s in sorted(seen):
    print(s)
EOF
wc -l tests/data/css-selectors-before.txt   # expect ~700-790
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/test_page_contract.py -k css_rule_was_lost -v`
Expected: FAIL — `static_asset("app.css")` returns `(None, None)`, so the `ctype` assertion raises `AttributeError`.

- [ ] **Step 3: Split the stylesheet into three files**

Cut the contents of the `<style>` block from `bin/dashboard.html` into:

- `ui/css/tokens.css` — the `:root{…}` block and the `:root[data-theme="dark"]{…}` block, and nothing else.
- `ui/css/components.css` — the rules for the shared vocabulary: page header, KPI card, filter bar, table card, table footer and pager, pills, buttons, tabs, right rail, plus the generic element rules (`*`, `body`, `a`, `table`, `th`, `td`).
- `ui/css/pages.css` — everything else: what belongs to one page, the dialogs, the sidebar, the job cards, the pulse panel, the media queries.

Each file opens with a comment saying what belongs in it and what does not. Do not rewrite a single declaration in this task — move text.

- [ ] **Step 4: Build the stylesheet**

In `build/build-ui.sh`, after the esbuild call for `security.js`:

```bash
# The stylesheet is CONCATENATED, not bundled: it has no imports and no
# module graph, so running it through esbuild would buy nothing and add a
# minifier's opinions to a diff that should stay readable. Order matters --
# tokens first, because everything below reads them; components before pages,
# so a page rule wins a tie against the component it specialises.
cat ui/css/tokens.css ui/css/components.css ui/css/pages.css > bin/static/app.css
```

Then generalise the stamping, replacing the two `printf` lines from Task 2:

```bash
# Every built artifact carries the same two stamps: what it was built FROM,
# and what it IS. Written in one loop rather than three pairs of printfs, so
# a fourth artifact is one word in this list.
for art in bin/static/security.js bin/static/app.css; do
  printf '/* ui-bundle: %s */\n' "$(bash build/ui-bundle-digest.sh "$art")" >> "$art"
  printf '/* ui-sources: %s */\n' "$(bash build/ui-digest.sh)" >> "$art"
done
echo "built bin/static/security.js, bin/static/app.css"
```

- [ ] **Step 5: Link it from the page**

In `bin/dashboard.html`, replace the whole `<style>…</style>` block with:

```html
<!-- Built from ui/css/ by build/build-ui.sh. Render-blocking by design: the
     head script above has already set data-theme, so the first painted frame
     is both styled and in the right theme. `?v=` is the build id, which is
     derived from this file's own bytes (see _build_id) so a changed
     stylesheet is never served from an open tab's cache. -->
<link rel="stylesheet" href="/static/app.css?v=__BUILD__">
```

- [ ] **Step 6: Make the selftest check all three artifacts**

In `bin/claude-cron`, lift the freshness block into a function above `cmd_selftest`:

```bash
# One artifact's two freshness questions, asked the same way for each. This
# was written out once, inline, for bin/static/security.js; a second and third
# artifact copied three times over is three places for the next fix to reach
# two of.
check_ui_artifact() { # <path relative to BASE_DIR>
  local _rel="$1" _bundle="$BASE_DIR/$1" _stamp _want _bstamp _bwant _ns _nb
  if [ ! -f "$_bundle" ]; then
    bad "$_rel is missing — run build/build-ui.sh"; return
  fi
  _ns="$(grep -c '^/\* ui-sources: .* \*/$' "$_bundle" || true)"
  _nb="$(grep -c '^/\* ui-bundle: .* \*/$' "$_bundle" || true)"
  _stamp="$(sed -n 's|^/\* ui-sources: \(.*\) \*/$|\1|p' "$_bundle")"
  _bstamp="$(sed -n 's|^/\* ui-bundle: \(.*\) \*/$|\1|p' "$_bundle")"
  _want="$(bash "$BASE_DIR/build/ui-digest.sh" 2>/dev/null)"
  _bwant="$(bash "$BASE_DIR/build/ui-bundle-digest.sh" "$_bundle" 2>/dev/null)"
  if [ "${_ns:-0}" != "1" ] || [ "${_nb:-0}" != "1" ]; then
    bad "$_rel carries ${_ns:-0} ui-sources and ${_nb:-0} ui-bundle stamps — exactly one of each is expected; run build/build-ui.sh"
  elif [ -z "$_want" ] || [ -z "$_bwant" ]; then
    bad "could not fingerprint ui/ or $_rel — is shasum on PATH?"
  elif [ "$_stamp" != "$_want" ]; then
    bad "$_rel is stale — run build/build-ui.sh"
  elif [ "$_bstamp" != "$_bwant" ]; then
    bad "$_rel has been MODIFIED since it was built — its body no longer hashes to its own stamp; rebuild with build/build-ui.sh and check what changed"
  else
    ok "$_rel matches the sources it was built from, and has not been touched since"
  fi
}
```

Replace the inline block in `cmd_selftest` with:

```bash
  echo "the committed UI artifacts — built from the sources sitting next to them"
  check_ui_artifact "bin/static/security.js"
  check_ui_artifact "bin/static/app.css"
```

- [ ] **Step 7: Add the static-route test**

```python
def test_the_stylesheet_is_served_as_css(srv):
    body, ctype = srv.static_asset("app.css")
    assert ctype.startswith("text/css")
    assert ":root" in body, "the stylesheet reached the route without its tokens"
```

- [ ] **Step 8: Build, verify, commit**

```bash
bash build/build-ui.sh
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/css bin/static/app.css build/build-ui.sh bin/dashboard.html \
        bin/claude-cron tests/
git commit -m "refactor(ui): the stylesheet moves to ui/css/ and is served

1415 lines and 789 rules leave dashboard.html for tokens/components/
pages under ui/css/, concatenated into bin/static/app.css and linked
from the head. Not bundled: the stylesheet has no imports, so esbuild
would buy nothing and add a minifier's opinions to a diff that should
stay readable.

No declaration is rewritten here. The contract is a selector-set
comparison against a baseline taken before the move, checked against the
BUILT artifact rather than the sources -- so a rule that lands in a file
the build forgets to concatenate fails too.

The selftest's freshness block becomes a function run per artifact.
Written out once inline it was fine for one bundle; copied for a second
and third it would be three places for the next fix to reach two of.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: `ui/app/` is born — the interface and the jobs domain

The Overview cannot move until the domain it shares with the Jobs table has somewhere to live. `renderJobs()` is one function serving both; splitting it across two phases would duplicate `jobFacts`/`visibleJobs` until Phase 2, which is the drifting-vocabulary defect this branch has already paid for twice.

**Files:**
- Create: `ui/app/page.js`, `ui/app/jobs-domain.js`, `ui/app/index.js`
- Modify: `build/build-ui.sh`, `bin/dashboard.html`, `bin/claude-cron`, `tests/test_page_contract.py`
- Test: `tests/test_page_contract.py`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `ui/app/page.js` exports `bindPage(cc)`, `CC`, and the destructured bindings `$, TOKEN, api, toast, esc, fmtAgo, fmtWhen, fmtDur, fmtIn, money, icon, iconLabel, openLog, openEditor, projById, isFav, eff, setView`.
  - `ui/app/jobs-domain.js` exports `jobFacts(job) -> {st, chk, disabled, idle, running, nLive, spentToday, cap, capped, streak, backoff, dueAt, nextAt, state}`, `visibleJobs() -> Job[]`, `jobFilters` (an object with `project`, `status`, `query`), and `bulkOn(jobs) -> boolean`.
  - `ui/app/index.js` exports a global `CCApp` with `{init(cc)}`.
  - The page tag `<script src="/static/app.js?v=__BUILD__"></script>` sits beside the Security one, before the page's own script.

- [ ] **Step 1: Write the characterisation test for the domain**

```python
_JOBS_DOMAIN_HARNESS = """
// jobFacts reads the clock; pinned so "in 4 minutes" is a number, not a race.
const NOW = 1_800_000_000;
Date.now = () => NOW * 1000;
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_job_facts_survive_the_move_unchanged(srv, tmp_path):
    """jobFacts is the arithmetic both the Overview's cards and the Jobs
    table read -- the state, the next run, the cap, the backoff. Moving it
    out of the page must not shift a single one of those, so this pins the
    answers for a job of each shape before the move and holds them after."""
    block = _app_js(srv)
    deps = _plainfn(block, "jobFacts")
    script = tmp_path / "facts.js"
    script.write_text(_JOBS_DOMAIN_HARNESS + deps + """
    const cases = {
      plain:    {id: "a", enabled: true,  interval_minutes: 15},
      disabled: {id: "b", enabled: false, interval_minutes: 15},
      backoff:  {id: "c", enabled: true,  interval_minutes: 15},
    };
    const out = {};
    for(const [k, j] of Object.entries(cases)){
      const f = jobFacts(j);
      out[k] = {state: f.state, disabled: !!f.disabled, capped: !!f.capped};
    }
    console.log(JSON.stringify(out));
    """)
    out = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True,
                                    check=True).stdout)
    assert out["plain"]["state"] == "enabled"
    assert out["disabled"]["disabled"] is True
    assert out["plain"]["capped"] is False
```

Add the source reader beside `_security_js`:

```python
APP_ROOT = REPO / "ui" / "app"


def _app_js(srv):
    """The app bundle's own sources, concatenated. Mirrors _security_js: the
    tests have to read exactly the code that draws the view, not a block of
    dashboard.html that may no longer be where the code lives."""
    return "\n".join(p.read_text() for p in sorted(APP_ROOT.rglob("*.js")))
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/test_page_contract.py -k job_facts_survive -v`
Expected: FAIL — `ui/app/` does not exist, so `_app_js` returns `""` and `_plainfn` raises `ValueError: substring not found`.

- [ ] **Step 3: Write `ui/app/page.js`**

```javascript
/* Everything the app's own screens are given by the page they live in.

   The same contract ui/security/page.js states, for the same reason: out here
   the page's scope is gone, and a stated interface beats a handful of reads
   off `window`. A name that is not in this list does not exist, and a missing
   one fails at bind time rather than as `undefined is not a function` three
   screens in.

   Two files rather than one shared page.js: the Security area's interface is
   settled and this one will grow through phases 2 and 3, and a single file
   would make every addition here a reason to re-read that one. They may be
   merged once both stop moving. */
export let $, TOKEN, api, toast, esc, fmtAgo, fmtWhen, fmtDur, fmtIn, money,
           icon, iconLabel, openLog, openEditor, projById, isFav, eff, setView;

/* DATA and currentView are REASSIGNED by the page -- DATA on every five-second
   poll, currentView on every navigation. Destructured they would freeze at
   whatever they held when init() ran. Read through the object, live, and the
   different spelling is the reminder that they move under you. */
export let CC = null;

export function bindPage(cc){
  CC = cc;
  ({ $, TOKEN, api, toast, esc, fmtAgo, fmtWhen, fmtDur, fmtIn, money,
     icon, iconLabel, openLog, openEditor, projById, isFav, eff,
     setView } = cc);
}
```

- [ ] **Step 4: Move the jobs domain verbatim**

Create `ui/app/jobs-domain.js` and move `jobFacts`, `visibleJobs`, `bulkOn`, `bulkLabel`, `clearJobFilters`, `jobProjectNames`, `nextCheckAt` and `inWindow` out of `bin/dashboard.html` into it, unchanged except for:
- `export` on each declaration that another module needs
- an `import { CC, eff, ... } from "./page.js";` header for the page bindings they read
- the module-level filter state (`jobProjectFilter`, `jobStatusFilter`, `jobQuery`) becomes one exported object:

```javascript
/* One object rather than three module-level `let`s. Three bindings can only
   be read across a module boundary by exporting three getters and three
   setters; an object is read and written through the same reference from
   either side, which is what the page's toolbar and this module both need. */
export const jobFilters = { project: "", status: "", query: "" };
```

Every read of `jobProjectFilter` becomes `jobFilters.project`, and likewise for the other two, at every call site in `bin/dashboard.html` and in the new module.

- [ ] **Step 5: Write `ui/app/index.js`**

```javascript
/* What the page calls into. Mirrors ui/security/index.js: this file is
   evaluated BEFORE the page's own script (see the tag's comment in
   dashboard.html), so it only DEFINES -- no DOM is touched and nothing is
   read off the page until init() runs. */
import { bindPage } from "./page.js";
import { jobFacts, visibleJobs, jobFilters, bulkOn } from "./jobs-domain.js";

function init(cc){
  bindPage(cc);
}

window.CCApp = { init, jobFacts, visibleJobs, jobFilters, bulkOn };
```

- [ ] **Step 6: Build it and load it**

In `build/build-ui.sh`, beside the Security esbuild call:

```bash
npx --yes esbuild@0.25.0 ui/app/index.js \
  --bundle --format=iife --target=safari15 \
  --outfile=bin/static/app.js
```

and add `bin/static/app.js` to the stamping loop's list and to the `echo`.

In `bin/dashboard.html`, beside the Security script tag:

```html
<script src="/static/app.js?v=__BUILD__"></script>
```

In the page's own script, where the moved functions used to be, build the interface object and hand it over:

```javascript
/* The app bundle's interface, built here and handed over once. Everything in
   ui/app/page.js's export list has to appear in this object -- a name missing
   from it is a bind-time failure with that name in the message, which is the
   whole reason the list is stated rather than read off window. */
CCApp.init({ $, TOKEN, api, toast, esc, fmtAgo, fmtWhen, fmtDur, fmtIn, money,
             icon, iconLabel, openLog, openEditor, projById, isFav, eff,
             setView,
             get DATA(){ return DATA; },
             get currentView(){ return currentView; } });
```

- [ ] **Step 7: Rename the sink-scan test to say what it now covers**

`_security_sources()` already walks all of `ui/`, so `ui/app/` is scanned the moment it exists — no logic changes. Only the name lies. Rename:

```python
def test_the_built_ui_never_builds_dom_from_html_strings():
```

and update its docstring's first line to say "every module under ui/", not "the Security area".

- [ ] **Step 8: Run everything**

Run: `pytest tests/test_page_contract.py -v`
Expected: PASS, including `test_job_facts_survive_the_move_unchanged` and the renamed sink-scan.

- [ ] **Step 9: Build, verify, commit**

```bash
bash build/build-ui.sh
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/app bin/static/app.js bin/static/app.css bin/static/security.js \
        build/build-ui.sh bin/dashboard.html tests/
git commit -m "refactor(ui): ui/app/ takes the jobs domain

renderJobs() is one function serving both the Overview's cards and the
Jobs table, and jobFacts/visibleJobs are shared between them. Moving
only the Overview would duplicate that domain until phase 2 -- the
drifting-vocabulary defect this branch has already paid for twice -- so
the domain moves whole and phase 2 adds the second consumer.

ui/app/page.js states the interface the page hands over, the same
contract ui/security/page.js states: a name not in the list does not
exist, and a missing one fails at bind time with its own name in the
message.

The three module-level filter bindings become one exported object.
Three `let`s can only cross a module boundary as three getters and
three setters; an object is read and written through one reference from
either side.

The sink-scan test is renamed, not changed: _security_sources() already
walked all of ui/, so ui/app/ is covered the moment it exists. Only the
name said otherwise.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: Pin the Overview's behaviour before touching it

Ten characterisation tests, written against the code **as it is today**. They pass on the first run — that is what a characterisation test does — so the usual "run it and watch it fail" does not apply. Something else has to, or these are tests that cannot fail, which is the exact defect that ran through this branch.

**The rule for this task: every test is proven falsifiable before it is committed.** For each one, break the behaviour it claims to pin, watch the test go red, then revert the break. A test whose assertion survives a deliberate break is not pinning anything and must be rewritten.

**Files:**
- Modify: `tests/test_page_contract.py`
- Test: itself

**Interfaces:**
- Consumes: `_app_js`, `_plainfn`, `_INDEX_DOM_HARNESS` from earlier tasks.
- Produces: ten tests that any later task must keep green.

- [ ] **Step 1: The five KPI numbers**

```python
@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_kpis_come_from_the_numbers_the_loop_recorded(srv, tmp_path):
    """Checks, woke, warnings, errors and today's spend, from a known
    tick.log and a known journal. Pinned before the panel is redrawn: the
    redesign moves these five out of three loose tiles and a footer strip
    into five cards, and the one thing that must not change on the way is
    what any of them says."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "kpis.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(pulseKpis({
      checks: 96, per: {woke: 23, idle: 68, blocked: 4, capped: 1},
      warn: 3, err: 1, spentToday: 9.34, spentWeek: 41.02,
      runsToday: 12, runsWeek: 58,
    })));
    """)
    got = json.loads(subprocess.run(["node", str(script)],
                                    capture_output=True, text=True,
                                    check=True).stdout)
    by = {c["label"]: c for c in got}
    assert by["Checks"]["value"] == "96"
    assert by["Woke a run"]["value"] == "23"
    assert by["Woke a run"]["sub"] == "24% of checks"
    assert by["Warnings"]["value"] == "3"
    assert by["Errors"]["value"] == "1"
    assert by["Spent today"]["value"] == "$9.34"
```

**Falsifiability check:** change `pct()` to round up rather than to nearest and confirm `24% of checks` fails. Revert.

`pulseKpis` does not exist yet — extract it in this step from `pulseHtml`'s existing arithmetic as a pure function returning `[{label, value, sub, tone, filter}]`, leaving `pulseHtml` to render whatever it returns. That extraction is the smallest change that makes the numbers testable without pinning the markup.

- [ ] **Step 2: A percentage with no denominator**

```python
def test_a_percentage_of_nothing_is_a_dash_not_zero_percent(srv, tmp_path):
    """"0% error rate" over an empty denominator is a confident claim about
    a day on which the loop never ran. The rule is already in pct(); nothing
    held it."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "pct.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify(pulseKpis({
      checks: 0, per: {woke: 0}, warn: 0, err: 0,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0,
    })));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    subs = [c["sub"] for c in got]
    assert not any("0%" in s for s in subs), f"a zero percent was printed: {subs}"
    assert any("—" in s for s in subs), f"no dash where a percentage cannot exist: {subs}"
```

**Falsifiability check:** change `pct` to `Math.round(n/checks*100)+"%"` unguarded and confirm `0%` appears. Revert.

- [ ] **Step 3: Warnings and errors are doors, and inert at zero**

```python
def test_the_warning_and_error_cards_lead_to_the_runs_they_count(srv, tmp_path):
    """These two are the way IN to the runs behind them -- today as chips
    carrying data-statfilter, after the redesign as cards. The navigation is
    the point of them, and a card with nothing to show must be inert rather
    than navigating to an empty filtered table."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "pulseKpis")
    script = tmp_path / "doors.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const some = pulseKpis({checks: 10, per: {woke: 1}, warn: 3, err: 2,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    const none = pulseKpis({checks: 10, per: {woke: 1}, warn: 0, err: 0,
      spentToday: 0, spentWeek: 0, runsToday: 0, runsWeek: 0});
    console.log(JSON.stringify({some, none}));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    some = {c["label"]: c for c in got["some"]}
    none = {c["label"]: c for c in got["none"]}
    assert some["Warnings"]["filter"] == "warning"
    assert some["Errors"]["filter"] == "error"
    assert not none["Warnings"]["filter"], "a card with nothing to show still navigates"
    assert not none["Errors"]["filter"], "a card with nothing to show still navigates"
```

**Falsifiability check:** drop the `n ?` guard on the filter and confirm the `none` assertions fail. Revert.

- [ ] **Step 4: The band's four empty states**

```python
@pytest.mark.parametrize("jobs,expected", [
    ([], "There are no jobs yet."),
    ([{"enabled": False}], "All 1 jobs are disabled."),
    ([{"enabled": False}, {"enabled": True}], "1 of 2 jobs are disabled."),
    ([{"enabled": True}], "Every job is enabled — the next tick will show up here."),
])
def test_a_band_with_no_checks_says_which_empty_it_is(srv, tmp_path, jobs, expected):
    """A fresh install, an evening with everything switched off, and a loop
    that is about to tick are three different facts. One blank chart for all
    three is the state this sentence exists to prevent."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "bandEmptyReason")
    script = tmp_path / "band.js"
    script.write_text(deps + f"""
    console.log(bandEmptyReason({json.dumps(jobs)}));
    """)
    got = subprocess.run(["node", str(script)], capture_output=True, text=True,
                         check=True).stdout.strip()
    assert got == expected
```

Extract `bandEmptyReason(jobs)` from the existing `if(!checks)` branch of `pulseHtml`, verbatim in its wording.

**Falsifiability check:** swap the `off === jobs.length` and `off` branches and confirm two cases fail. Revert.

- [ ] **Step 5: The probe has three verdicts, not two**

```python
@pytest.mark.parametrize("exit_code,expect", [
    (0, "work found"), (1, "nothing to do"), (2, "probe FAILED"),
    (127, "probe FAILED"),
])
def test_a_probe_that_could_not_run_says_so(srv, tmp_path, exit_code, expect):
    """Any exit other than 0 or 1 once rendered as the calm "nothing to do",
    so a job whose credentials had gone missing looked healthy while it
    silently never ran again. Fixed in the code, never held by a test --
    and the card is about to be rewritten."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "probeVerdict")
    script = tmp_path / "probe.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + f"""
    const n = probeVerdict({{exit: {exit_code}, output: ""}});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert any(expect in r["text"] for r in got), \
        f"exit {exit_code} did not read as {expect!r}: {[r['text'] for r in got]}"
```

Extract `probeVerdict(pc)` from `jobCard`, returning a DOM node.

**Falsifiability check:** change the guard to `pc.exit === 0 ? … : "nothing to do"` and confirm both failure cases go red. Revert.

- [ ] **Step 6: The spend bar's two thresholds**

```python
@pytest.mark.parametrize("spent,cap,expect", [
    (1.00, 5.00, ""), (3.99, 5.00, ""), (4.00, 5.00, "near"),
    (4.90, 5.00, "near"), (5.00, 5.00, "over"), (7.00, 5.00, "over"),
])
def test_the_spend_bar_warns_before_the_cap_and_says_when_it_is_reached(
        srv, tmp_path, spent, cap, expect):
    """80% is a warning and 100% is a stop, and the boundary between them is
    exactly where an off-by-one lives. Pinned at both edges."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "spendTone")
    script = tmp_path / "spend.js"
    script.write_text(deps + f"console.log(spendTone({spent}, {cap}) || '');")
    got = subprocess.run(["node", str(script)], capture_output=True, text=True,
                         check=True).stdout.strip()
    assert got == expect
```

Extract `spendTone(spent, cap)` from `jobCard`'s `barCls` expression.

**Falsifiability check:** change `>= 80` to `> 80` and confirm the `4.00` case fails. Revert.

- [ ] **Step 7: Grouping, favourites, and the flat grid**

```python
def test_favourite_projects_come_first_and_no_projects_means_a_flat_grid(
        srv, tmp_path):
    """The star's whole purpose: on an install with a dozen projects, the two
    you are working in stop being a scroll away. And a install with no
    projects at all gets no group chrome to scroll past."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "groupJobs")
    script = tmp_path / "group.js"
    script.write_text(deps + """
    const jobs = [{id:"a",project:"Zeta"},{id:"b",project:"Alpha"},
                  {id:"c",project:"Minerva"}];
    console.log(JSON.stringify({
      starred:   groupJobs(jobs, new Set(["Zeta"])).map(g => g.name),
      unstarred: groupJobs(jobs, new Set()).map(g => g.name),
      flat:      groupJobs([{id:"x"},{id:"y"}], new Set()).map(g => g.name),
    }));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["starred"][0] == "Zeta", "a favourite did not sort to the top"
    assert got["unstarred"] == ["Alpha", "Minerva", "Zeta"]
    assert got["flat"] == [], "jobs with no project were given group chrome"
```

Extract `groupJobs(jobs, favSet) -> [{name, jobs}]` from `renderJobCards`.

**Falsifiability check:** drop the `isFav(b) - isFav(a)` term and confirm `starred` fails. Revert.

- [ ] **Step 8: The empty states tell the two emptinesses apart**

```python
@pytest.mark.parametrize("filtering,expect", [
    (False, "No jobs yet"), (True, "No jobs match"),
])
def test_an_empty_list_says_whether_a_filter_emptied_it(srv, tmp_path,
                                                         filtering, expect):
    """"Nothing here" and "nothing here MATCHING WHAT YOU TYPED" send a
    reader to two different places. Getting it wrong sends them to create a
    job they already have."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "jobsEmptyNote")
    script = tmp_path / "empty.js"
    script.write_text(deps
                      + f"console.log(jobsEmptyNote({str(filtering).lower()}));")
    got = subprocess.run(["node", str(script)], capture_output=True, text=True,
                         check=True).stdout
    assert expect in got
```

- [ ] **Step 9: Backoff and the window are each said in full**

```python
def test_backoff_names_the_multiplier_and_the_failures_behind_it(srv, tmp_path):
    """"backing off" alone does not say for how long or why. The number of
    failed runs is what tells an operator whether to wait or to look."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "nextRunNote")
    script = tmp_path / "backoff.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const n = nextRunNote({enabled: true}, {nextAt: 1, dueAt: 1,
                                            backoff: 4, streak: 3});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    txt = " ".join(r["text"] for r in json.loads(
        subprocess.run(["node", str(script)], capture_output=True, text=True,
                       check=True).stdout))
    assert "4×" in txt and "3 failed" in txt, txt


@pytest.mark.parametrize("job,facts,expect", [
    ({"enabled": False}, {"nextAt": None}, "disabled"),
    ({"enabled": True}, {"nextAt": None}, "no matching window"),
])
def test_no_window_and_switched_off_are_different_answers(srv, tmp_path, job,
                                                           facts, expect):
    """A job nobody enabled and a job whose window will not reopen today are
    two different things to do something about."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "nextRunNote")
    script = tmp_path / "window.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + f"""
    const n = nextRunNote({json.dumps(job)}, {json.dumps(facts)});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    txt = " ".join(r["text"] for r in json.loads(
        subprocess.run(["node", str(script)], capture_output=True, text=True,
                       check=True).stdout))
    assert expect in txt, txt
```

Extract `nextRunNote(job, facts)` from `jobCard`'s `next` expression, returning a DOM node.

**Falsifiability check for both:** collapse the disabled and no-window branches into one and confirm the second test fails. Revert.

- [ ] **Step 10: Run the whole set, then prove each one can fail**

```bash
pytest tests/test_page_contract.py -v -k "kpi or percentage or door or band or probe or spend or favourite or empty or backoff or window"
```

Expected: PASS, all of them.

Then walk the falsifiability checks noted in steps 1–9, one at a time: apply the break, run that one test, confirm RED, `git checkout -- bin/dashboard.html ui/app`. **A test that stays green under its break is rewritten before this task is committed.**

- [ ] **Step 11: Build, verify, commit**

```bash
bash build/build-ui.sh
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/app bin/static bin/dashboard.html tests/test_page_contract.py
git commit -m "test(ui): pin the Overview's behaviour before it is redrawn

Ten characterisation tests over what the Overview says: the five KPI
numbers, a percentage with no denominator, the two cards that are doors
into Runs, the band's four empty states, the probe's three verdicts, the
spend bar's two thresholds, favourite-first grouping, the two
emptinesses, and backoff versus no-window.

They pass on the first run, which is what a characterisation test does,
so each one was instead proven falsifiable: break the behaviour, watch
it go red, revert. A test that survives its own break pins nothing --
the defect that ran through this branch -- so that check is the gate
here rather than a first red run.

The arithmetic they read is extracted into pure functions (pulseKpis,
bandEmptyReason, probeVerdict, spendTone, groupJobs, jobsEmptyNote,
nextRunNote). That is the smallest change that makes the numbers
testable without pinning markup the redesign exists to change.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: The pure half moves — ABSORBED INTO TASK 6 AND TASK 8

**Do not execute this task.** Task 6 needed these functions extracted in order to test them, so it moved seven of the nine: `pulseKpis`, `bandEmptyReason`, `probeVerdict`, `spendTone`, `groupJobs`, `jobsEmptyNote` and `nextRunNote` are already in `ui/app/overview.js`.

What remained was `tickTotals` and `pickLine`, and both are consumed only by the renderers Task 8 rewrites. Moving them alone would be a commit with no deliverable of its own and two functions with no call site in the bundle, so Task 8 takes them.

The reasoning below is kept because it is why this phase has no "moved unchanged, tests prove it" step at all — that constraint still governs Tasks 8, 9 and 10.

### Original text


**Read this before starting — it corrects an assumption the earlier tasks were written under.** This task originally said "move the Overview's renderers, pixel-identical, and let Task 6's tests prove it". That is not possible, and the pre-flight review of this plan caught it.

`test_the_built_ui_never_builds_dom_from_html_strings` forbids `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `createContextualFragment`, `DOMParser` and `setAttribute("on` in **every** `.js` file under `ui/`, with no exceptions. `pulseHtml`, `helloHtml`, `jobCard`, `renderJobCards` and `renderRetained` are all HTML-string builders. Moving any of them into `ui/app/` turns that scan red the moment it arrives.

So no renderer is moved. This task takes only what is already sink-free — the pure functions Task 6 extracted — and Tasks 8, 9 and 10 **write** their DOM replacements in `ui/app/`, deleting the string versions from the page as each one is replaced.

The consequence is worth stating plainly: there is no "moved unchanged, tests prove it" step in this phase. Task 6's ten tests are the only net across the rewrite, which is exactly why they were written first and proven falsifiable.

**Files:**
- Create: `ui/app/overview.js`
- Modify: `bin/dashboard.html`, `ui/app/index.js`

**Interfaces:**
- Consumes: everything from Tasks 5 and 6.
- Produces: `ui/app/overview.js` exports the pure helpers `pulseKpis`, `bandEmptyReason`, `spendTone`, `groupJobs`, `jobsEmptyNote`, `tickTotals`, `pickLine`, and the DOM builders `probeVerdict` and `nextRunNote`. `CCApp` gains all of them.

- [ ] **Step 1: Move only what has no sink**

Move into `ui/app/overview.js`: `pulseKpis`, `bandEmptyReason`, `spendTone`, `groupJobs`, `jobsEmptyNote`, `tickTotals`, `pickLine`, `probeVerdict` and `nextRunNote`.

The last two already return DOM nodes — Task 6 extracted them that way. Everything else is arithmetic or a plain string.

**Leave in `bin/dashboard.html` for now:** `pulseHtml`, `helloHtml`, `jobCard`, `renderJobCards`, `checkList`, `renderRetained`, `setDashTab`, `sessionLines` and `renderJobs`. They call into the moved helpers via `CCApp`.

- [ ] **Step 2: Verify the moved set is sink-free before wiring anything**

```bash
grep -nE 'innerHTML|insertAdjacentHTML|outerHTML|createContextualFragment|DOMParser|setAttribute\("on' ui/app/*.js
```

Expected: no output. If anything matches, that function does not belong in this task — put it back and let Task 8 or 9 write its replacement.

- [ ] **Step 3: Wire it**

In `ui/app/index.js`, import from `./overview.js` and add each name to the `window.CCApp` object.

In `bin/dashboard.html`, the remaining string renderers call `CCApp.pulseKpis(...)`, `CCApp.spendTone(...)` and so on. `probeVerdict` and `nextRunNote` return nodes, so their call sites use `.outerHTML`— **no.** Those two call sites move into Task 9 with `jobCard` itself; until then `jobCard` keeps its own inline string versions of those two fragments, and the moved DOM builders are exercised only by Task 6's tests.

That duplication is deliberate, temporary and lasts exactly one task. Note it in the commit message so it is not mistaken for drift.

- [ ] **Step 4: Run everything**

Run: `pytest tests/test_page_contract.py -v`
Expected: PASS, including the sink-scan — nothing with a sink moved.

- [ ] **Step 5: Build, verify, commit**

```bash
bash build/build-ui.sh
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/app bin/static bin/dashboard.html
git commit -m "refactor(ui): the Overview's pure half moves to ui/app/

The arithmetic and the two DOM fragments extracted while pinning the
Overview's behaviour move out; every HTML-string renderer stays in the
page.

Not a staging choice -- a constraint. The sink scan forbids innerHTML in
every file under ui/, so pulseHtml, jobCard and their neighbours cannot
be moved at all, only rewritten. Tasks 8 and 9 write their DOM
replacements and delete the string versions as they go.

probeVerdict and nextRunNote have no call site until jobCard is
rewritten, so jobCard keeps inline copies of those two fragments for one
task. Deliberate and temporary; task 9 deletes them.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: The Overview's header, KPI cards and band

Now the visual work. The page header replaces the loose greeting line; five KPI cards replace three tiles and a footer strip; the band goes full width.

**Files:**
- Modify: `ui/app/overview.js`, `ui/css/components.css`, `ui/css/pages.css`, `bin/dashboard.html`

**Interfaces:**
- Consumes: Task 7.
- Produces: `pageHeader({icon, title, subtitle, actions})` and `kpiCard({icon, tone, value, label, sub, filter})` in `ui/app/overview.js`, both returning DOM nodes. Later phases reuse both.

- [ ] **Step 1: Write the component CSS**

In `ui/css/components.css`, add the page-header, KPI-card, filter-bar, table-card, table-footer and pager rules from the approved canvas. Use only tokens from `ui/css/tokens.css` — no literal colours.

- [ ] **Step 2: Write the header, the cards and the band as DOM**

In `ui/app/overview.js`, add `pageHeader`, `kpiCard` and `renderPulse` as DOM builders, using a local `el(tag, cls, text)` helper matching `ui/security/dom.js`'s. The band's bars and the axis are `createElement`; nothing here goes through the HTML parser.

`kpiCard` renders `filter` as a click target only when it is truthy, and sets `disabled` when it is not — that is what Task 6's door test pins.

The header's sentence is `helloHtml`'s existing wording, as text. The five cards come from `pulseKpis`.

- [ ] **Step 3: Delete the string versions**

Remove `pulseHtml` and `helloHtml` from `bin/dashboard.html` entirely, along with the three `tile()` calls, the `pulse-f` footer strip and the two `chip()` calls inside them. The call site becomes `CCApp.renderOverviewHead()`.

Confirm nothing was left behind:

```bash
grep -n 'pulseHtml\|helloHtml\|pulse-f\|function tile\|function chip' bin/dashboard.html
```

Expected: no output.

- [ ] **Step 4: Run the pinned tests**

Run: `pytest tests/test_page_contract.py -v`
Expected: PASS. The Task 6 tests read `pulseKpis`, not markup, so they hold across this change. If one fails, it was pinning appearance and must be fixed, not the code.

- [ ] **Step 5: Look at it**

```bash
bash build/build-ui.sh
```

Open the dashboard, in both themes. Compare against the `Main.dc.html` artboard on the approved canvas.

- [ ] **Step 6: Commit**

```bash
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/ bin/static bin/dashboard.html
git commit -m "feat(ui): the Overview gets a page header and KPI cards

Three loose tiles and a footer strip carrying Today / 7 days / warnings
/ errors become five KPI cards, and the greeting line becomes the page
header's sentence. The 24-hour band keeps its place and takes the full
width -- it is a time series with nothing competing for the room.

Warnings and Errors stay doors into Runs: clickable when they have
somewhere to go, inert when the count is zero. Pinned two commits ago.

pageHeader() and kpiCard() are written as reusable builders here because
phases 2 and 3 need both on every remaining page.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 9: The job cards, rebuilt as DOM

164 lines of HTML-string concatenation become DOM builders. This is the restyle and the sink-scan compliance in one pass, because they are the same rewrite.

**Files:**
- Modify: `ui/app/overview.js`, `ui/css/pages.css`

**Interfaces:**
- Consumes: Tasks 6–8.
- Produces: `jobCard(job) -> Element`.

- [ ] **Step 1: Write the failing test**

`jobCard` still lives in `bin/dashboard.html`, so the sink-scan is green and cannot be this task's failing test. Write one that fails because the card is not in the bundle yet:

```python
@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_job_card_is_built_from_nodes_and_shows_what_it_always_showed(
        srv, tmp_path):
    """The card is the densest thing on the page and the last HTML-string
    builder in the Overview. Rewritten as nodes it keeps every fact: the
    state, what the probe saw, the counts it reported, the spend against the
    cap, and when the next run is.

    checkList renders the first line of an arbitrary probe script's output,
    so a card built from nodes is also the end of that exposure -- the
    sink scan holds the rule, this holds the content."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "el", "probeVerdict", "nextRunNote",
                              "spendTone", "checkList", "jobCard")
    script = tmp_path / "card.js"
    script.write_text(_INDEX_DOM_HARNESS + _JOBS_DOMAIN_HARNESS + deps + """
    const n = jobCard({id: "qg-dev-agent", project: "Quality Gate",
                       enabled: true, interval_minutes: 15});
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    txt = " ".join(r["text"] for r in got)
    assert "qg-dev-agent" in txt, "the card did not name its own job"


def test_a_probe_line_containing_markup_stays_text(srv, tmp_path):
    """The first line of a probe script's stdout, rendered. `esc()` held
    this before by discipline; nodes hold it by construction."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "el", "checkList")
    script = tmp_path / "probe-markup.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    const n = checkList('ready=<img src=x onerror=alert(1)> blocked=0');
    console.log(JSON.stringify(collectAll(n, [])));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    txt = " ".join(r["text"] for r in got)
    assert "<img" in txt, "the markup was not preserved as literal text"
    tags = [r for r in got if r.get("cls") == "" and "img" in str(r)]
    assert all("onerror" not in str(r.get("cls", "")) for r in got)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `pytest tests/test_page_contract.py -k "job_card_is_built_from_nodes or probe_line_containing_markup" -v`
Expected: FAIL — `_plainfn` raises `ValueError: substring not found`; `jobCard` and `checkList` are still in the page, not in the bundle.

- [ ] **Step 3: Write `jobCard` and `checkList` as DOM in `ui/app/overview.js`**

Build and return an `Element`. Keep every fact the string version showed: the state pill, the probe verdict (from `probeVerdict`, now getting its first call site), the check list, the sparkline, the spend bar, the next-run note (from `nextRunNote`, likewise), the kept-session notice and the buttons.

Use the same local `el(tag, cls, text)` Task 8 introduced. Do not import across the two bundles; a shared module can wait until both stop moving.

The sparkline and the icons are the only SVG: build them with `createElementNS`, as the Security screens do.

- [ ] **Step 4: Delete the string versions and their temporary duplicates**

Remove `jobCard`, `renderJobCards` and `checkList` from `bin/dashboard.html`, including the inline copies of the probe-verdict and next-run fragments that Task 7 left there for exactly one task.

```bash
grep -n 'function jobCard\|function checkList\|function renderJobCards' bin/dashboard.html
```

Expected: no output.

- [ ] **Step 5: Restyle in `ui/css/pages.css`**

Card radius and shadow to match the table cards, the state as a pill using the `.pill` classes from `components.css`, the six type roles, and the spend bar sharing the progress-bar rule.

- [ ] **Step 6: Run everything**

Run: `pytest tests/test_page_contract.py -v`
Expected: PASS — the two new tests, the sink-scan, and all ten pinned tests.

- [ ] **Step 7: Look at it, then commit**

```bash
bash build/build-ui.sh
```

Check both themes, a job in each state: running, enabled, idle, disabled, backing off, capped, with a kept session.

```bash
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/ bin/static
git commit -m "feat(ui): job cards rebuilt as DOM, in the new language

164 lines of HTML-string concatenation become DOM builders. The restyle
and the sink-scan compliance are one rewrite, not two: the card had to
be rewritten to be restyled, and rewriting it as nodes costs nothing
extra while removing the class of bug entirely.

The exposure was real -- checkList renders the output of an arbitrary
probe script, and ticket names come from Jira. esc() handled it
correctly, by discipline; discipline is the part that fails.

Every fact the card showed it still shows: state, probe verdict, check
counts, sparkline, spend against the cap, next run, kept session.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 10: The dashboard tabs go, worktrees becomes a card

The last structural change. Jobs and Runs are sidebar pages; the Overview's tabs duplicated them. Worktrees stops being a tab that is always present saying there is nothing.

**Files:**
- Modify: `bin/dashboard.html`, `ui/app/overview.js`, `ui/css/pages.css`
- Test: `tests/test_page_contract.py`

**Interfaces:**
- Consumes: Tasks 7–9.
- Produces: `worktreesCard(items) -> Element | null`.

- [ ] **Step 1: Write the failing test**

```python
def test_the_worktrees_card_appears_only_when_there_is_something_on_disk(
        srv, tmp_path):
    """A directory holding the only copy of some work is a thing to deal
    with; the absence of one is not news. As a tab it was always present,
    saying there was nothing -- a permanent fixture reporting the ordinary
    case."""
    block = _app_js(srv)
    deps = _index_screen_deps(block, "worktreesCard")
    script = tmp_path / "wt.js"
    script.write_text(_INDEX_DOM_HARNESS + deps + """
    console.log(JSON.stringify({
      empty: worktreesCard([]) === null,
      some:  collectAll(worktreesCard([
        {job: "qg-dev-agent", size: "184 MB"}]), []).some(
          r => r.text.includes("qg-dev-agent")),
    }));
    """)
    got = json.loads(subprocess.run(["node", str(script)], capture_output=True,
                                    text=True, check=True).stdout)
    assert got["empty"], "an empty worktrees card was rendered anyway"
    assert got["some"], "a retained worktree was not named on the card"


def test_the_overview_has_no_tabs_of_its_own(srv):
    """Jobs and Runs are pages in the sidebar. A second set of tabs
    reaching the same two lists is one navigation too many, and the one that
    silently disagreed with the sidebar about which was selected."""
    page = srv.render_page()
    assert 'id="viewtabs"' not in page
    for gone in ('id="vt-jobs"', 'id="vt-runs"', 'id="vt-wt"'):
        assert gone not in page, f"{gone} outlived the tab strip"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `pytest tests/test_page_contract.py -k "worktrees_card or no_tabs" -v`
Expected: FAIL — `worktreesCard` does not exist; `viewtabs` is still in the page.

- [ ] **Step 3: Remove the tabs**

Delete `<nav class="viewtabs" id="viewtabs">` and its three buttons from `bin/dashboard.html`, the `#pane-jobs` / `#pane-runs` / `#pane-worktrees` wrappers, both `paneblurb` paragraphs, and `setDashTab`, `paintDashPanes` and the `dashTab` state from `ui/app/overview.js`.

The Overview's job cards render straight into `#jobs`.

- [ ] **Step 4: Write `worktreesCard`**

Returns `null` for an empty list. Otherwise a rail card: title, one grey line, up to four rows with right-aligned sizes, and a full-width footer button to the retained-worktrees view.

- [ ] **Step 5: Run everything**

Run: `pytest tests/test_page_contract.py -v`
Expected: PASS. `test_every_element_the_script_reaches_for_exists` is the one to watch: a leftover `$("vt-jobs")` fails here.

- [ ] **Step 6: Build, verify, commit**

```bash
bash build/build-ui.sh
pytest -q && bash bin/claude-cron selftest >/dev/null && echo GREEN
git add ui/ bin/static bin/dashboard.html tests/test_page_contract.py
git commit -m "feat(ui): the Overview's tabs go; worktrees becomes a card

Jobs and Runs are pages in the sidebar. A second tab strip reaching the
same two lists was one navigation too many -- and the one that could
silently disagree with the sidebar about which was selected.

Worktrees stops being a permanent tab reporting the ordinary case. A
directory holding the only copy of some work is a thing to deal with;
the absence of one is not news, so the card appears only when there is
something on disk.

The two paneblurb paragraphs go with them: what they said is the page
header's sentence now.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 11: Close the phase

**Files:**
- Modify: `docs/superpowers/specs/2026-08-22-app-redesign-phase-1-overview-design.md`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: Run every gate**

```bash
pytest -q
bash bin/claude-cron selftest
bash test/e2e.test.sh
git status --porcelain    # must be empty
```

All green, tree clean.

- [ ] **Step 2: Confirm the artifacts are fresh in the commit, not just on disk**

```bash
git stash list            # nothing hiding a rebuild
bash build/build-ui.sh
git diff --stat bin/static/    # must be EMPTY: a diff here means a commit
                               # shipped sources without their build
```

- [ ] **Step 3: Check the drawing against what shipped**

Open the dashboard in both themes beside the `Main.dc.html` artboard. Note every deliberate divergence in the spec's own words — the spec records what landed, not what was hoped for. Do not describe a missing piece as a design decision.

- [ ] **Step 4: Update the docs**

`README.md`: the build step now produces three artifacts, and `ui/` holds CSS as well as JS.

`CHANGELOG.md` is already written — each task wrote its own entry as it landed, which is what the selftest's changelog guard forces. Read the entries this phase added, end to end, and check they describe one coherent change rather than eleven disconnected ones. Merge or reword where two entries say the same thing twice; do not add a summary entry on top of them.

- [ ] **Step 5: Commit**

```bash
git add docs README.md CHANGELOG.md
git commit -m "docs: phase 1 of the redesign, as it landed

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage.** Every section of the design maps to a task: the file layout to Tasks 4 and 5; the `renderJobs` coupling to Task 5; the Overview's four parts to Tasks 8, 9 and 10; the three removals to Tasks 8 and 10; the DOM rule to Task 9; the ten tests to Task 6; the shared source digest and the stamps to Tasks 2 and 4; the two latent bugs to Tasks 1 and 3; the verification gates to Task 11.

**A conflict found in the pre-flight review of this plan, and how it was resolved.** Task 7 originally moved the Overview's renderers into `ui/app/` "pixel-identical", with Task 6's tests as the proof, and Task 9 then rewrote `jobCard` as DOM. That sequence cannot run: the sink scan forbids `innerHTML` in *every* file under `ui/`, so `pulseHtml`, `helloHtml`, `jobCard`, `renderJobCards` and `renderRetained` turn it red the moment they arrive — they cannot be moved at all, only rewritten in place of.

Task 7 now takes only the sink-free pure functions, and Tasks 8, 9 and 10 write DOM replacements and delete the string versions as they go. The cost is real and is stated in Task 7: this phase has no "moved unchanged, tests prove it" step, so Task 6's ten tests are the only net across the rewrite. That is why they are written first and proven falsifiable.

**One deviation from the spec, recorded here rather than silently.** The spec says the DOM rule needs "one line" in the sink-scan test. It needs none: `_security_sources()` already walks all of `ui/`, so `ui/app/` is covered from the moment it exists. Only the test's name was wrong, and Task 5 renames it.

**One simplification.** The spec describes teaching `ui-bundle-digest.sh` a second, block-comment stamp form beside the existing `//` one. Task 2 instead moves *both* stamps to the block form, which is valid in JavaScript and CSS alike — one form to write and one to strip, rather than two spellings for three readers to accept.

**Type consistency.** `jobFilters` is one object with `.project` / `.status` / `.query` in Task 5 and is read that way everywhere after. `jobFacts` returns the same named fields in Tasks 5, 6 and 9. `pulseKpis` returns `[{label, value, sub, tone, filter}]` in Task 6 and is consumed with those exact keys in Task 8. `kpiCard` takes `{icon, tone, value, label, sub, filter}` — the same `filter` key `pulseKpis` produces. `worktreesCard(items)` returns `Element | null` in Task 10, and the null is what the caller branches on.
