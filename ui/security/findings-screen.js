/* ------------------------------------------------------- findings browser
   Every finding of one project, in one filterable, paginated table --
   `GET /api/security/findings` (bin/claude-cron-server's `security_findings`,
   bin/security/cli.py's `findings-page`), which is `queries.finding_rows`
   (Task 6) itself: a checklist per branch -- the latest finished analysis of
   each -- unioned, so the state a row shows is the state that branch's own
   newest analysis gives the finding, never a recomputed one. Sorting,
   filtering and paging all happen on the server; this module never re-derives
   any of it client-side.

   ONE MODULE, TWO HOMES. `renderFindings(host, project, initialFilters)` is
   the whole surface: `project-screen.js` mounts it into its Findings tab pane
   (`#sec-pj-findings`), and it is written to make no assumption about WHERE
   `host` lives or who else is on screen beside it -- no read of `secState`,
   no reach into `secProjectCache`. Task 12's Activity screen is the second
   caller anticipated when this module was rebuilt host-keyed (Task 11): it
   mounts the identical function into its own fingerprint dialog, `initialFilters`
   set to `{fingerprint: "<prefix>"}`, without a second copy of a filterable
   table to drift the way a duplicated download function, and a duplicated
   state machine before it, already have (see reports-tab.js's own comment on
   secDownloadReport, and queries.py's on checklist()). Two mounts open AT
   ONCE -- the Findings tab and that dialog, on screen together -- are not
   hypothetical: every piece of state below (filters, sort, page, the fetch
   generation) is keyed by `host` in `secFindStates`, so two hosts showing the
   SAME project never share a filter, and whichever of two overlapping
   fetches answers last still paints its OWN pane rather than losing a
   staleness race to the other one's (see `secFindStates`'s own comment).

   `initialFilters` (optional, a partial filters object) is applied ON TOP OF
   `_defaultFilters()` -- never merged with whatever the host's own state
   already held -- every time it is passed, even on a re-mount of the SAME
   host/project: a caller that hands one in is making a deliberate "show me
   THIS, filtered to THIS" request (the Activity screen mounting a fresh
   fingerprint each time a different decision's row is clicked), not asking
   to resume wherever a previous visit left off. Omitting the argument keeps
   the existing behaviour byte-for-byte: `project-screen.js`'s two call sites
   never pass it, so a tab switch away from and back to Findings still keeps
   its filters/sort/page exactly as before this task.

   `total` vs `unique`: the strip shows both, labelled, because they answer
   different questions -- the same finding open on two branches is one row
   each time it is open (`total`) but one problem (`unique`, distinct
   fingerprints). 189 findings can be 93 problems; collapsing the two into one
   number would silently answer whichever question the reader was not asking.

   The severity floor (`min_severity`) is DISPLAY-ONLY and lives entirely in
   this file -- the server's `by_severity`/`total`/`unique` describe every row
   the current FILTERS match, never narrowed by the floor, so the count of
   what the floor hides is exact across every page, not just the one on
   screen. A FIXED finding is exempted from the floor entirely (`secVisible`,
   the same rule vocabulary.js's checklist already applies): the floor's job
   is to declutter what still needs attention, and a fix that closed is not
   that, so it stays visible and out of the "hidden" count regardless of its
   severity (`fixed_by_severity` is what lets that count still add up exactly
   -- see its own comment on `secFindHiddenByFloor`). Two things this screen
   says out loud, per the brief: how many rows the floor is hiding and why (a
   missing number is otherwise indistinguishable from one that was never
   found), and that downloads always carry every recorded finding regardless
   of what the floor shows here -- the identical sentence index.js's
   `#sec-dl-note` and reports-tab.js's own caption already give, so a reader
   moving between screens learns it once.

   Per-host state, not module-level. `secFindStates` is a WeakMap from host to
   {project, filters, sort, dir, page, gen, data, error, savedName, newName}
   -- a Map would work for lookups too, but would also hold every host this
   ever mounted into, and everything it fetched, alive forever; a WeakMap
   entry is exactly as long-lived as its host, so a discarded host (and its
   payload) stops being kept alive here without anything having to notice or
   clean it up. `secFindLoad`'s own staleness guard checks
   `secFindStates.get(host) !== state` -- object identity against whatever is
   CURRENTLY registered for that host -- rather than a single shared "current
   host" variable, so a second mount into a DIFFERENT host can never
   invalidate this one's in-flight fetch, and a re-mount of THIS host (a
   project switch, or a fresh caller) always installs a brand new state
   object the old fetch's own closure no longer matches. Switching to a
   DIFFERENT project resets every transient control (filters, sort, page, the
   saved-filter picker); switching away and back to the SAME project's
   Findings tab -- on the SAME host -- keeps them, the same as every other
   tab on this screen. */
import { api, toast, fmtWhen, tableFooter } from "./page.js";
import { secEl, secIcon, secFetch } from "./dom.js";
import { SEC_STATES, SEC_STATE_LABEL, SEC_STATE_HELP, SEV_ORDER, SEC_NEVER,
         secMinSeverity, secSevKey, secStateKey, secVisible } from "./vocabulary.js";
import { secAskReason } from "./reason.js";
import { secInvalidateProject } from "./project-screen.js";

// Mirrors bin/security/queries.py's SORTABLE, and bin/claude-cron-server's
// FINDING_CATEGORIES -- duplicated here, not fetched, because the filter bar
// has to draw its own options before any request has ever answered. Kept in
// step by hand, the same duplication every edge in this area already carries
// (see claude-cron-server's own comment on FINDING_SEVERITIES/FINDING_STATES/
// FINDING_CATEGORIES for why a value the server already validates is still
// named again here).
// Phase 4 Task 6: State and First seen swapped from their original order --
// a pre-existing mismatch found while giving this table its own width class
// (below), where the HEADER this array draws read "...Branch | First seen |
// State | Actions" while secFindRow's own cells rendered "...Branch | State
// | First seen | Actions": the header and the body disagreed about which
// column was which. This order matches both secFindRow's own cell order and
// AllFindings.png's own column order; only the sort buttons' own visual
// position moves -- which key each one sorts by (`fs.sort`) is unchanged.
const FIND_SORT_COLUMNS = [
  ["severity", "Severity"], ["title", "Title"], ["category", "Category"],
  ["branch", "Branch"], ["state", "State"], ["first_seen", "First seen"],
];
// Mirrors FIND_SORT_COLUMNS plus the Actions column rendered after it --
// kept in step by hand (the same duplication FIND_CATEGORIES below already
// carries against the server's own FINDING_CATEGORIES) because
// test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column's
// own harness extracts ONE const in total isolation: a
// `FIND_SORT_COLUMNS.concat(...)` expression here would throw
// ReferenceError under that harness, which never also stands up
// FIND_SORT_COLUMNS alongside it.
const SEC_FIND_TABLE_COLS = [
  ["severity", "Severity"], ["title", "Title"], ["category", "Category"],
  ["branch", "Branch"], ["state", "State"], ["first_seen", "First seen"],
  [null, "Actions"],
];
const FIND_CATEGORIES = ["secret", "dependency", "sast", "hygiene"];
const FIND_PER_PAGE = 25;

function _defaultFilters(){
  return {severity: [], state: [], category: [], branch: "", path: "", q: "",
          analysis: "", show_resolved: false, fingerprint: ""};
}

function _newFindState(host, project){
  return {
    host, project, gen: 0, data: null, error: "",
    filters: _defaultFilters(), sort: "severity", dir: "desc", page: 1,
    savedName: "", newName: "",
  };
}

// One entry per host this has ever been mounted into -- see this file's own
// comment for why a WeakMap and not a Map.
const secFindStates = new WeakMap();

/* The one exported entry point -- see this file's own comment. An existing
   mount into the SAME host for the SAME project keeps its state (a tab
   switch away and back); anything else -- a brand new host, or the same host
   handed a different project -- starts from a fresh one, the same reset a
   project change has always done. `initialFilters`, when given, always
   overrides whatever filters the host's state currently holds (see this
   file's own header comment on why that is deliberate, not a bug). */
export async function renderFindings(host, project, initialFilters){
  let fs = secFindStates.get(host);
  if(!fs || fs.project !== project){
    fs = _newFindState(host, project);
    secFindStates.set(host, fs);
  }
  if(initialFilters){
    fs.filters = Object.assign(_defaultFilters(), initialFilters);
    fs.page = 1;
  }
  await secFindLoad(fs);
}

function secFindQuery(fs){
  const p = new URLSearchParams();
  p.set("project", fs.project);
  p.set("sort", fs.sort);
  p.set("dir", fs.dir);
  p.set("page", String(fs.page));
  p.set("per_page", String(FIND_PER_PAGE));
  const f = fs.filters;
  if(f.severity.length) p.set("severity", f.severity.join(","));
  if(f.state.length) p.set("state", f.state.join(","));
  if(f.category.length) p.set("category", f.category.join(","));
  if(f.branch.trim()) p.set("branch", f.branch.trim());
  if(f.path.trim()) p.set("path", f.path.trim());
  if(f.q.trim()) p.set("q", f.q.trim());
  if(f.analysis.trim()) p.set("analysis", f.analysis.trim());
  if(f.show_resolved) p.set("show_resolved", "1");
  if(f.fingerprint.trim()) p.set("fingerprint", f.fingerprint.trim());
  return p.toString();
}

async function secFindLoad(fs){
  const host = fs.host, project = fs.project;
  if(!host || !project) return;
  const gen = ++fs.gen;
  // No "Loading…" flash on a filter/sort/page change or a poll-driven
  // refresh -- only on the very first fetch for this project, the same
  // no-flicker rule secLoadIndex already follows for its own cache.
  if(!fs.data){
    host.textContent = "";
    host.appendChild(secEl("div", "tblempty", "Loading…"));
  }
  let data;
  try{
    data = await secFetch("/api/security/findings?" + secFindQuery(fs));
  }catch(e){
    // `secFindStates.get(host) !== fs`, not a host/project comparison: a
    // second mount into a DIFFERENT host can never invalidate this one (its
    // own entry is untouched), and a re-mount of THIS host (a project
    // switch, or a fresh caller) always installs a NEW state object, so
    // object identity catches every way this fetch could now be stale in
    // one guard -- see this file's own header comment.
    if(gen !== fs.gen || secFindStates.get(host) !== fs) return;
    fs.error = e.message; fs.data = null;
    secFindPaint(fs);
    return;
  }
  if(gen !== fs.gen || secFindStates.get(host) !== fs) return;
  fs.error = "";
  fs.data = data;
  // A filter change can move the requested page past the end; follow what
  // the server actually served (finding_rows clamps, never invents rows)
  // rather than keep the control pointed at a page whose rows never answer.
  fs.page = data.page || 1;
  secFindPaint(fs);
}

async function secFindRefresh(fs){ await secFindLoad(fs); }

function secFindPaint(fs){
  const host = fs.host;
  if(!host) return;
  host.textContent = "";
  if(fs.error){
    const box = secEl("div", "tblempty");
    box.appendChild(secIcon("alert"));
    box.appendChild(document.createTextNode("Could not read findings — " + fs.error));
    host.appendChild(box);
    return;
  }
  const data = fs.data;
  if(!data) return;
  host.appendChild(secFindStrip(fs, data));
  host.appendChild(secFindFilterBar(fs, data));
  const section = secFindTableSection(fs, data);
  // The footer lives INSIDE the same table-card the rows are in, never as a
  // loose sibling below it (see tableFooter's own comment in chrome.js on
  // test_the_jobs_table_footer_sits_inside_the_table_card for the regression
  // that shape used to be) -- so it is appended only when secFindTableSection
  // actually built one; its two "nothing to show" branches return a bare
  // .tblempty with no box for a footer to sit inside.
  if((section.className || "").includes("table-card")) section.appendChild(secFindPager(fs, data));
  host.appendChild(section);
}

/* ------------------------------------------------------------------ strip
   total, unique issues, and the five severities -- see this file's own
   comment for why total and unique are both shown, labelled, rather than
   collapsed into one number. */
function secFindHiddenByFloor(data, minSeverity){
  const floor = SEV_ORDER.indexOf(minSeverity);
  const bySev = data.by_severity || {}, fixedBySev = data.fixed_by_severity || {};
  let n = 0;
  SEV_ORDER.forEach((sev, i) => {
    // A fixed finding below the floor is exempted the same way `secVisible`
    // exempts it from the checklist's own floor (see this file's header
    // comment) -- shown regardless of severity, so it must not be counted
    // as hidden either, or this number and the table beneath it would openly
    // disagree about the very same row.
    if(i < floor) n += (bySev[sev] || 0) - (fixedBySev[sev] || 0);
  });
  return n;
}

// What the strip's per-severity pills COUNT. The strip labels its own
// `total`/`unique` pair, and then drew five per-severity pills that are ROWS
// with no label at all -- in markup identical to the sidebar donut's legend,
// which on the project screen is a flex sibling of the tab panes and so is on
// screen AT THE SAME TIME, four inches away, showing per-severity pills that
// are distinct FINGERPRINTS. Two numbers answering different questions, side
// by side, in the same shape, with only one of the two pairs labelled. Both
// sides now say which question they answer (see DONUT_PILL_TITLE in
// index-screen.js for the other half).
const ROW_PILL_TITLE = "Rows matching the current filters — the same finding "
  + "open on two branches counts twice here.";

function secFindStrip(fs, data){
  // `secfind-sev3` (Phase 4 Task 6): AllFindings.png paints these five per-
  // severity pills crit-red/high-orange/medium-amber/low-blue/info-grey --
  // this design's tokens (ui/css/tokens.css) have no blue defined for any
  // severity (the donut legend's own Low dot is the same neutral grey
  // `--sev-low` already is), so this dialect matches the three tones the
  // tokens DO give distinctly (critical/high/medium) and leaves low/info in
  // their existing muted look, exactly the choice the index screen's own
  // `.secidx-sev3` already made for the identical reason -- see that class's
  // own comment (ui/css/pages.css) and this class's own, beside it.
  const wrap = secEl("div", "sevpills secfind-sev3");
  const totalPill = secEl("span", "sevpill", data.total + " total");
  totalPill.title = ROW_PILL_TITLE;
  wrap.appendChild(totalPill);
  const uniquePill = secEl("span", "sevpill", data.unique + " unique issues");
  uniquePill.title = "Distinct problems (fingerprints) — the same finding open "
    + "on two branches counts once here.";
  wrap.appendChild(uniquePill);
  const bySev = data.by_severity || {};
  let any = false;
  ["critical", "high", "medium", "low", "info"].forEach(sev => {
    if(!bySev[sev]) return;
    any = true;
    const pill = secEl("span", "sevpill " + sev, bySev[sev] + " " + sev);
    pill.title = ROW_PILL_TITLE;
    wrap.appendChild(pill);
  });
  // The ok-green `clean` pill is a VERDICT -- "we looked and there is nothing
  // matching" -- so it may only be drawn over a project something has
  // actually read. `analysed` false means nothing ever finished here, and
  // painting that green (beside "0 total", with the table below blaming
  // filters the reader never set) is the one wrong answer this strip can
  // give. See queries.finding_rows's own docstring for the two flags.
  if(!any && data.analysed !== false){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing matches"));
  }

  const minSeverity = secMinSeverity(fs.project);
  const hidden = secFindHiddenByFloor(data, minSeverity);
  const note = secEl("div", "secpj-caption");
  if(hidden > 0){
    note.appendChild(document.createTextNode(
      hidden + " finding" + (hidden === 1 ? "" : "s") + " below " + minSeverity
      + " " + (hidden === 1 ? "is" : "are")
      + " hidden by this project's severity floor — recorded, not shown. "));
  }
  note.appendChild(secEl("b", null,
    "Downloads always contain every recorded finding, whatever the severity floor shows."));

  const box = secEl("div", "secfind-strip");
  // FIRST, above everything else the strip says: this project has never been
  // read, or has been attempted and never finished. In the SAME two sentences
  // the Overview and Branches tabs already use for the identical fact (see
  // SEC_NEVER in vocabulary.js) rather than a third phrasing invented here.
  if(data.analysed === false){
    const line = secEl("div", "warnline bad");
    line.appendChild(secIcon("alert"));
    line.appendChild(secEl("span", "grow",
      data.attempted ? SEC_NEVER.attempted : SEC_NEVER.next));
    box.appendChild(line);
  }else if(data.capped_branches){
    // A partial read, the same caveat the index table's `incomplete` badge
    // and the sidebar donut's own note already give: these rows are what was
    // found before at least one branch's analysis stopped, not what is there.
    const line = secEl("div", "warnline bad");
    line.appendChild(secIcon("alert"));
    line.appendChild(secEl("span", "grow",
      data.capped_branches + " of these branches had a latest analysis that "
      + "stopped before covering its whole scope — what is below is what it "
      + "had reached, not what is there."));
    box.appendChild(line);
  }
  // The Activity screen's own deep link (Task 12): the table below is
  // narrowed to one fingerprint prefix, not this project's whole list --
  // said out loud, since a filtered table with no visible filter chip set
  // (this one travels through `initialFilters`, not a chip a reader
  // clicked) would otherwise read as the WHOLE list for this severity/
  // state/category selection.
  const fingerprintFilter = ((fs.filters || {}).fingerprint || "").trim();
  if(fingerprintFilter){
    box.appendChild(secEl("div", "secpj-caption",
      "Filtered to fingerprint " + fingerprintFilter + "… — "
      + "“Clear filters” below shows this project's whole list."));
  }
  box.appendChild(wrap);
  box.appendChild(note);
  return box;
}

/* -------------------------------------------------------------- filter bar
   Severity, state and category as toggle chips (secchip/secchips, the same
   pattern secRunsFilters/secRenderChecklist already use elsewhere on this
   screen); branch, path, analysis and free text as plain fields (secfield/
   secbar, the same furniture the repo/branch/profile picker above already
   uses) -- reusing both rather than inventing a third look for a fourth
   filter row. */
function secFindChips(options, selected, onToggle, labelFor){
  const row = secEl("div", "secchips");
  options.forEach(opt => {
    const chip = secEl("button", "secchip" + (selected.includes(opt) ? " on" : ""));
    chip.type = "button";
    chip.appendChild(secEl("span", null, labelFor ? labelFor(opt) : opt));
    chip.onclick = () => onToggle(opt);
    row.appendChild(chip);
  });
  return row;
}

function secFindChipField(label, chipsRow){
  const field = secEl("div", "secfield");
  field.appendChild(secEl("span", null, label));
  field.appendChild(chipsRow);
  return field;
}

function secFindToggleIn(list, value){
  const i = list.indexOf(value);
  if(i >= 0) list.splice(i, 1); else list.push(value);
}

function secFindSeverityField(fs){
  return secFindChipField("Severity", secFindChips(
    ["critical", "high", "medium", "low", "info"], fs.filters.severity,
    (sev) => { secFindToggleIn(fs.filters.severity, sev); fs.page = 1; secFindRefresh(fs); }));
}

function secFindCategoryField(fs){
  return secFindChipField("Category", secFindChips(
    FIND_CATEGORIES, fs.filters.category,
    (cat) => { secFindToggleIn(fs.filters.category, cat); fs.page = 1; secFindRefresh(fs); }));
}

function secFindStateField(fs){
  const row = secFindChips(SEC_STATES, fs.filters.state,
    (st) => { secFindToggleIn(fs.filters.state, st); fs.page = 1; secFindRefresh(fs); },
    (st) => SEC_STATE_LABEL[st] || st);
  // secFindChips has no notion of a per-option title -- threaded on
  // afterwards, same as every chip helper on this screen sets .title once
  // the element already exists (see secRenderChecklist's identical pattern).
  Array.from(row.childNodes).forEach((chip, i) => { chip.title = SEC_STATE_HELP[SEC_STATES[i]] || ""; });
  return secFindChipField("State", row);
}

function secFindTextField(label, value, onChange){
  const field = secEl("div", "secfield");
  field.appendChild(secEl("span", null, label));
  const inp = document.createElement("input");
  inp.type = "text";
  inp.value = value;
  inp.spellcheck = false;
  inp.autocomplete = "off";
  // change, not input: a fetch per keystroke would be a subprocess per
  // keystroke on the server (see index.js's identical reasoning for
  // #sec-branch-other).
  inp.addEventListener("change", () => onChange(inp.value));
  field.appendChild(inp);
  return field;
}

function secFindShowResolvedField(fs){
  const field = secEl("div", "secfield");
  field.appendChild(secEl("span", null, "Resolved"));
  const label = document.createElement("label");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = fs.filters.show_resolved;
  cb.addEventListener("change", () => {
    fs.filters.show_resolved = cb.checked;
    fs.page = 1;
    secFindRefresh(fs);
  });
  label.appendChild(cb);
  label.appendChild(document.createTextNode(" Show resolved"));
  field.appendChild(label);
  return field;
}

function secFindClearButton(fs){
  const btn = secEl("button", "btn ghost", "Clear filters");
  btn.type = "button";
  btn.onclick = () => { fs.filters = _defaultFilters(); fs.page = 1; secFindRefresh(fs); };
  return btn;
}

function secFindCurrentQuery(fs){
  const f = fs.filters;
  return {severity: f.severity, state: f.state, category: f.category,
          branch: f.branch, path: f.path, q: f.q, analysis: f.analysis,
          show_resolved: f.show_resolved, fingerprint: f.fingerprint,
          sort: fs.sort, dir: fs.dir};
}

function secFindApplyQuery(fs, q){
  const query = q || {};
  fs.filters = {
    severity: Array.isArray(query.severity) ? query.severity.slice() : [],
    state: Array.isArray(query.state) ? query.state.slice() : [],
    category: Array.isArray(query.category) ? query.category.slice() : [],
    branch: typeof query.branch === "string" ? query.branch : "",
    path: typeof query.path === "string" ? query.path : "",
    q: typeof query.q === "string" ? query.q : "",
    analysis: typeof query.analysis === "string" ? query.analysis : "",
    show_resolved: !!query.show_resolved,
    fingerprint: typeof query.fingerprint === "string" ? query.fingerprint : "",
  };
  fs.sort = FIND_SORT_COLUMNS.some(([key]) => key === query.sort) ? query.sort : "severity";
  fs.dir = query.dir === "asc" ? "asc" : "desc";
  fs.page = 1;
  secFindRefresh(fs);
}

async function secFindSaveCurrent(fs, name){
  const trimmed = (name || "").trim();
  if(!trimmed){ toast("Name this filter set before saving", true); return; }
  const ok = await api("security_filter_save",
    {project: fs.project, name: trimmed, query: secFindCurrentQuery(fs)});
  if(!ok) return;           // api() has already shown the server's own message
  toast("Filter saved", false, "check");
  fs.savedName = trimmed;
  fs.newName = "";
  await secFindRefresh(fs);
}

async function secFindDeleteSaved(fs, name){
  if(!name) return;
  const ok = await api("security_filter_delete", {project: fs.project, name});
  if(!ok) return;
  toast("Filter deleted", false, "check");
  fs.savedName = "";
  await secFindRefresh(fs);
}

// The house <details>/<summary>/.menu-pop popover (Phase 4 Task 5) --
// secIndexProjectRow's own kebab and secFindingsPeriodPicker (both
// index-screen.js) already draw this exact shape for the identical reason:
// a short, dynamically-populated list with no paging, mounted and torn down
// far too often for makePicker's own module-level PICKERS registry (built
// for STATIC, boot-once markup -- Jobs/Runs' pickers, and this screen's own
// three filter pickers, all live exactly once for the page's whole life).
// This one is neither: renderFindings rebuilds its whole host, savedName
// included, on every filter change and every poll tick, AND -- see this
// file's own "ONE MODULE, TWO HOMES" comment -- can be mounted twice at
// once (the Findings tab and the Activity screen's fingerprint dialog). A
// <details>-based popover closes over its OWN nodes, not a shared id
// registry, so neither repeated rebuilds nor two live instances collide the
// way a second makePicker("secfind-saved", ...) call on a duplicate id
// would.
function secFindSavedFilters(fs, data){
  const bar = secEl("div", "secbar");
  const pickField = secEl("div", "secfield");
  pickField.appendChild(secEl("span", null, "Saved filters"));

  const filters = data.filters || [];
  // Mirrors the old <select>'s own reset: a name that no longer matches any
  // saved filter (renamed or deleted from elsewhere) must not keep pinning
  // the field to it.
  if(!filters.some(f => f.name === fs.savedName)) fs.savedName = "";

  const delBtn = secEl("button", "btn ghost", "Delete");
  delBtn.type = "button";
  delBtn.disabled = !fs.savedName;
  delBtn.onclick = () => secFindDeleteSaved(fs, fs.savedName);

  const wrap = document.createElement("details");
  wrap.className = "secfind-savedpick";
  const trigger = document.createElement("summary");
  trigger.className = "filterpick";
  // Found live by secFindingsPeriodPicker first (see that function's own
  // comment): bin/dashboard.html's global "click outside a menu-pop closes
  // every open one" listener has no idea this menu is a <details> rather
  // than the older hidden-attribute-toggled pattern, and hides this very
  // popover a beat before the browser's own default action opens it, unless
  // the opening click is stopped here from ever reaching that listener.
  trigger.onclick = (e) => e.stopPropagation();
  const valueEl = secEl("span", null, fs.savedName || "— choose —");
  trigger.appendChild(valueEl);
  trigger.appendChild(secIcon("cdown"));
  wrap.appendChild(trigger);

  const pop = secEl("div", "menu-pop");
  pop.setAttribute("role", "menu");

  // A custom widget has no browser-native "picking an option repaints the
  // control" behaviour the way the old <select> did -- the trigger label and
  // the Delete button's own enabled state are repainted here, by hand, on
  // every pick (the list itself is rebuilt fresh from scratch the next time
  // it opens, so it never needs a matching manual repaint).
  function pick(name, query){
    fs.savedName = name;
    valueEl.textContent = name || "— choose —";
    delBtn.disabled = !name;
    wrap.open = false;
    // Only a REAL saved filter re-fetches -- picking "— choose —" just
    // clears the field, the same no-op the old <select>'s blank option was
    // (sel.value === "" never matched a saved filter's own name, so
    // secFindApplyQuery was never reached for it either).
    if(query) secFindApplyQuery(fs, query);
  }

  const blank = document.createElement("button");
  blank.type = "button";
  blank.setAttribute("role", "menuitem");
  blank.appendChild(document.createTextNode("— choose —"));
  if(!fs.savedName) blank.appendChild(secIcon("check2"));
  blank.onclick = (e) => { e.stopPropagation(); pick(""); };
  pop.appendChild(blank);

  filters.forEach(f => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    // .textContent, never markup: a saved filter's name is a string a human
    // typed on this page, but still text a reader did not write, the same
    // rule every other value in this area follows.
    item.appendChild(document.createTextNode(f.name));
    if(f.name === fs.savedName) item.appendChild(secIcon("check2"));
    item.onclick = (e) => { e.stopPropagation(); pick(f.name, f.query); };
    pop.appendChild(item);
  });
  wrap.appendChild(pop);

  // Found live, the hard way: bin/dashboard.html's global closeMenus() (bound
  // on document, fired by any click that is not inside an open .menu-pop --
  // navigating to this very tab is exactly such a click) sets `hidden` on
  // EVERY `.menu-pop` in the document that does not already carry it,
  // including one this function only just built and never opened yet.
  // secIndexProjectRow's own kebab and secFindingsPeriodPicker (both
  // index-screen.js) share this exact shape and are not immune to the same
  // race in principle, but in practice self-heal within one 5-second poll
  // tick, which rebuilds their markup hidden-attribute-free again; this
  // table has no such tick (it fetches on demand, not on a timer), so a
  // find-filters bar built once could stay silently un-openable until the
  // next filter change or tab switch rebuilt it. Setting `hidden` here, from
  // the trigger's OWN open/close state rather than trusting whatever a
  // stray earlier click left behind, is what makes ontoggle the one place
  // that can never disagree with `wrap.open`.
  //
  // Positioning is recomputed on every open from the trigger's own screen
  // position, the identical fix secIndexProjectRow's own kebab and
  // secFindingsPeriodPicker both already need: this table sits inside an
  // overflow-clipped card the same way theirs do, which cuts off a popup
  // positioned any other way.
  wrap.ontoggle = () => {
    pop.hidden = !wrap.open;
    if(!wrap.open) return;
    const r = trigger.getBoundingClientRect();
    pop.style.position = "fixed";
    pop.style.top = (r.bottom + 6) + "px";
    pop.style.left = r.left + "px";
    pop.style.right = "auto";
    pop.style.bottom = "auto";
  };

  pickField.appendChild(wrap);
  bar.appendChild(pickField);

  const nameField = secEl("div", "secfield");
  nameField.appendChild(secEl("span", null, "Save current as"));
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.placeholder = "name this view";
  nameInput.value = fs.newName;
  nameInput.addEventListener("change", () => { fs.newName = nameInput.value; });
  nameField.appendChild(nameInput);
  bar.appendChild(nameField);

  const saveBtn = secEl("button", "btn ghost", "Save");
  saveBtn.type = "button";
  saveBtn.onclick = () => secFindSaveCurrent(fs, nameInput.value);
  bar.appendChild(saveBtn);

  bar.appendChild(delBtn);

  return bar;
}

function secFindFilterBar(fs, data){
  const wrap = document.createElement("div");
  wrap.appendChild(secFindSeverityField(fs));
  wrap.appendChild(secFindStateField(fs));
  wrap.appendChild(secEl("div", "secpj-caption",
    "Fixed, accepted and false-positive rows are excluded unless “Show resolved” is checked."));
  wrap.appendChild(secFindCategoryField(fs));

  const bar = secEl("div", "secbar");
  bar.appendChild(secFindTextField("Branch", fs.filters.branch, (v) => {
    fs.filters.branch = v; fs.page = 1; secFindRefresh(fs);
  }));
  bar.appendChild(secFindTextField("Path contains", fs.filters.path, (v) => {
    fs.filters.path = v; fs.page = 1; secFindRefresh(fs);
  }));
  bar.appendChild(secFindTextField("Analysis #", fs.filters.analysis, (v) => {
    fs.filters.analysis = v; fs.page = 1; secFindRefresh(fs);
  }));
  // Matches what queries.finding_rows's own `q` filter actually searches --
  // title, rule, rationale and every occurrence's file path. "CVE" is not a
  // field of its own: for a dependency finding it is folded into `rule`, so
  // naming `rule` here is what makes that searchable text discoverable at
  // all, rather than implying a fifth, nonexistent column.
  bar.appendChild(secFindTextField("Search title / rule / rationale / file", fs.filters.q, (v) => {
    fs.filters.q = v; fs.page = 1; secFindRefresh(fs);
  }));
  bar.appendChild(secFindShowResolvedField(fs));
  bar.appendChild(secFindClearButton(fs));
  wrap.appendChild(bar);

  wrap.appendChild(secFindSavedFilters(fs, data));
  return wrap;
}

/* ------------------------------------------------------------------ table
   The state a row shows is the state its OWN branch's latest finished
   analysis gives it -- a list that crosses branches (and so crosses
   analyses) has to say which one it is speaking about, hence the Branch and
   First seen columns beside State rather than a bare severity/title pair. */
function secFindRow(fs, f){
  const tr = document.createElement("tr");
  tr.className = "sev-" + secSevKey(f) + " state-" + secStateKey(f);
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };

  tr.appendChild(cell(f.severity || ""));

  const tdTitle = document.createElement("td");
  // Titles and paths come out of analysed code, and a branch name may
  // legally contain '<', '>' and '&' -- textContent, always, the one rule
  // this whole area exists to keep (see vocabulary.js's own file comment).
  tdTitle.appendChild(secEl("div", "sectitle", f.title || ""));
  const occ = f.occurrences || [];
  if(occ.length){
    const first = occ[0];
    const where = first.line ? first.file + ":" + first.line : first.file;
    const more = occ.length > 1 ? " (+" + (occ.length - 1) + " more)" : "";
    tdTitle.appendChild(secEl("div", "secmeta", where + more));
  }
  tr.appendChild(tdTitle);

  tr.appendChild(cell(f.category || ""));
  tr.appendChild(cell(f.branch || ""));

  const tdState = document.createElement("td");
  const stBadge = secEl("span", "secstate " + secStateKey(f), SEC_STATE_LABEL[f.state] || f.state);
  stBadge.title = SEC_STATE_HELP[f.state] || "";
  tdState.appendChild(stBadge);
  tr.appendChild(tdState);

  tr.appendChild(cell(f.first_seen ? fmtWhen(f.first_seen) : "—"));

  const tdAct = document.createElement("td");
  // A fixed finding is gone: there is nothing left to accept or dismiss --
  // the same rule secFindingRow in analysis.js already follows.
  if(f.state !== "fixed") tdAct.appendChild(secFindDecisionControls(fs, f));
  tr.appendChild(tdAct);
  return tr;
}

function secFindDecisionControls(fs, f){
  const wrap = secEl("div", "secactions");
  [["accepted", "Accept risk"], ["false_positive", "False positive"]].forEach(([state, label]) => {
    const b = secEl("button", "btn", label);
    b.type = "button";
    b.onclick = () => secFindDecide(fs, f, state, label);
    wrap.appendChild(b);
  });
  return wrap;
}

async function secFindDecide(fs, f, state, label){
  // Required, not optional: the API refuses a blank reason with a 400 of its
  // own -- asked here so that refusal is never how somebody discovers the
  // rule (see analysis.js's identical secDecide).
  const reason = await secAskReason(label, f.title);
  if(reason === null) return;
  const ok = await api("security_decide",
    {project: fs.project, fingerprint: f.fingerprint, state, reason});
  // api() has already put the server's own sentence on screen when this is
  // false -- including the one this page must never swallow: a decision
  // refused because an analysis of this project is still running.
  if(!ok) return;
  toast(label + " recorded", false, "check");
  // Overview's checklist counts and the sidebar donut both read this
  // decision the next time either is fetched -- invalidated here, the same
  // way secDecide in analysis.js does for the old single-analysis view, so
  // neither shows a stale count without a real reload.
  secInvalidateProject();
  await secFindRefresh(fs);
}

function secFindTableSection(fs, data){
  const rows = data.rows || [];
  if(!rows.length){
    // "No findings match these filters" blames the reader's own controls, and
    // over a project nothing has ever read that is simply false -- there are
    // no findings because nobody looked, not because a chip is set. Same two
    // sentences as the strip above and as Overview/Branches.
    if(data.analysed === false){
      return secEl("div", "tblempty",
        data.attempted ? SEC_NEVER.attempted : SEC_NEVER.next);
    }
    return secEl("div", "tblempty", "No findings match these filters.");
  }

  const minSeverity = secMinSeverity(fs.project);
  // `secVisible`, not a bare rank comparison: the exact exemption
  // vocabulary.js's checklist already gives a FIXED finding (shown
  // regardless of severity) -- see this file's own header comment for why
  // the two floors have to agree with each other.
  const visible = secVisible(rows, minSeverity);
  if(!visible.length){
    return secEl("div", "tblempty",
      "Every finding on this page is below the " + minSeverity
      + " severity floor — recorded, not shown.");
  }

  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secfind-table";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  FIND_SORT_COLUMNS.forEach(([key, label]) => {
    const th = document.createElement("th");
    const btn = secEl("button", "btn ghost");
    btn.type = "button";
    const active = fs.sort === key;
    btn.appendChild(secEl("span", null, label + (active ? (fs.dir === "asc" ? " ▲" : " ▼") : "")));
    btn.onclick = () => {
      if(fs.sort === key) fs.dir = fs.dir === "asc" ? "desc" : "asc";
      else { fs.sort = key; fs.dir = key === "severity" ? "desc" : "asc"; }
      fs.page = 1;
      secFindRefresh(fs);
    };
    th.appendChild(btn);
    htr.appendChild(th);
  });
  const thAct = document.createElement("th");
  thAct.textContent = "Actions";
  htr.appendChild(thAct);
  thead.appendChild(htr);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  visible.forEach(f => tbody.appendChild(secFindRow(fs, f)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  return wrap;
}

/* ------------------------------------------------------------------ pager
   The bridged tableFooter() (Phase 4 Task 6) -- AllFindings.png's own
   "Showing X to Y of N findings" + pager, replacing the bare "Page X / Y ·
   N rows" line that used to sit outside the table's own box (`.pager`, the
   shape Jobs/Runs/Projects already moved off of onto this same builder).
   The MECHANISM is untouched -- still Prev/Next stepping `fs.page` through a
   server-paginated fetch -- only the LOOK converges on what every other
   table card in this app already uses. `numbered` is left unset (plain
   Prev/Next), not the numbered-dots variant the mockup itself shows:
   chrome.js's own tableFooter draws one button per page with no "…"
   collapsing, fine at Jobs/Runs/Projects' own page counts but untested at
   however many pages a heavily-findings project can reach here.
   secFindPaint appends this INSIDE the same table-card secFindTableSection
   returns (see that call site's own comment) -- this function only builds
   the footer and wires its own two buttons, and is not responsible for
   where it ends up mounted. The buttons are found by their fixed position
   in tableFooter's own non-numbered output (info span, then a nav holding
   exactly Prev then Next) rather than by id: this module mounts into two
   hosts at once (see this file's own header comment), and a fixed id would
   collide the moment both mounts' footers rendered together. */
function secFindPager(fs, data){
  const total = data.total || 0;
  const perPage = data.per_page || FIND_PER_PAGE;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const page = data.page || 1;
  const from = total ? (page - 1) * perPage + 1 : 0;
  const to = Math.min(page * perPage, total);

  const foot = tableFooter({shown: {from, to}, total, noun: "finding", page, pages});
  const nav = foot.childNodes[1];
  if(nav){
    const prev = nav.childNodes[0], next = nav.childNodes[1];
    prev.onclick = () => { fs.page = Math.max(1, page - 1); secFindRefresh(fs); };
    next.onclick = () => { fs.page = Math.min(pages, page + 1); secFindRefresh(fs); };
  }
  return foot;
}
