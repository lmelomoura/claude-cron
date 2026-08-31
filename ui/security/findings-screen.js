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
   {project, filters, sort, dir, page, perPage, gen, data, error, savedName,
   newName} -- a Map would work for lookups too, but would also hold every
   host this ever mounted into, and everything it fetched, alive forever; a
   WeakMap entry is exactly as long-lived as its host, so a discarded host
   (and its payload) stops being kept alive here without anything having to
   notice or clean it up. `secFindLoad`'s own staleness guard checks
   `secFindStates.get(host) !== state` -- object identity against whatever is
   CURRENTLY registered for that host -- rather than a single shared "current
   host" variable, so a second mount into a DIFFERENT host can never
   invalidate this one's in-flight fetch, and a re-mount of THIS host (a
   project switch, or a fresh caller) always installs a brand new state
   object the old fetch's own closure no longer matches. Switching to a
   DIFFERENT project resets every transient control (filters, sort, page, the
   saved-filter picker); switching away and back to the SAME project's
   Findings tab -- on the SAME host -- keeps them, the same as every other
   tab on this screen.

   PHASE 4 (AllFindings.png): this file used to draw its own furniture over
   the mockup's shape -- chip rows instead of pickers, two bare text buttons
   instead of an eye+kebab, a "Page X / Y" line instead of the numbered
   footer every other table-card in this app now shares. Every FUNCTION named
   below survives this pass unchanged in what it computes; only how each
   result reaches the screen changes. See secFindHeader, secFindStrip and
   secFindFilterBar's own comments for the specific shape each one now
   draws, and this file's own header list above for which names are pinned
   by tests/test_page_contract.py and must keep both their name and their
   contract. */
import { api, toast, fmtWhen, tableFooter, closeMenus, kpiCard } from "./page.js";
import { secEl, secIcon, secFetch } from "./dom.js";
import { SEC_STATES, SEC_STATE_LABEL, SEC_STATE_HELP, SEV_ORDER, SEC_NEVER,
         secMinSeverity, secSevKey, secStateKey, secVisible, secCategoryMeta } from "./vocabulary.js";
import { SEV_KPI_ICON, SEV_KPI_TONE } from "./overview-tab.js";
import { secAskReason } from "./reason.js";
import { secInvalidateProject, secSwitchProjectTab } from "./project-screen.js";
import { secShowAnalysis, secBack } from "./analysis.js";

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
// "Status", not "State" (Phase 4, AllFindings.png's own column header) --
// the sort KEY (queries.finding_rows's own SORTABLE entry) is unchanged,
// only the human-facing label moves; the pills this sorts among still read
// SEC_STATE_LABEL exactly as before.
const FIND_SORT_COLUMNS = [
  ["severity", "Severity"], ["title", "Title"], ["category", "Category"],
  ["branch", "Branch"], ["state", "Status"], ["first_seen", "First seen"],
];
// The full nine-column order AllFindings.png draws (Location and Analysis
// run are new; see secFindTableSection's own header-building code for why
// this const is NOT what that code walks to build them). Kept only for
// test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column's
// own harness, which extracts ONE const in total isolation:
// `FIND_SORT_COLUMNS.concat(...)` (or any other expression reading a name
// this file declares elsewhere) would throw ReferenceError under that
// harness, which never also stands up anything but the ONE const it asked
// for. Kept in step by hand against secFindTableSection's real header loop
// -- the same duplication FIND_CATEGORIES below already carries against the
// server's own FINDING_CATEGORIES.
const SEC_FIND_TABLE_COLS = [
  ["severity", "Severity"], ["title", "Title"], [null, "Location"],
  ["category", "Category"], [null, "Analysis run"], ["branch", "Branch"],
  ["state", "Status"], ["first_seen", "First seen"], [null, "Actions"],
];
const FIND_CATEGORIES = ["secret", "dependency", "sast", "hygiene"];
// AllFindings.png's own default per-page selection and picker options.
// 25 by default -- ProjectFindings.png's own footer reads "25 per page";
// 10 stays pickable for a tighter read.
const FIND_PER_PAGE = 25;
const FIND_PER_PAGE_OPTIONS = [10, 25, 50];

function _defaultFilters(){
  return {severity: [], state: [], category: [], branch: "", path: "", q: "",
          analysis: "", show_resolved: false, fingerprint: ""};
}

function _newFindState(host, project){
  return {
    host, project, gen: 0, data: null, error: "",
    filters: _defaultFilters(), sort: "severity", dir: "desc", page: 1,
    perPage: FIND_PER_PAGE,
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
  p.set("per_page", String(fs.perPage || FIND_PER_PAGE));
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
  host.appendChild(secFindHeader(fs, fs.data));
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

/* ---------------------------------------------------------------- header
   Breadcrumb, shield title and the two right-aligned buttons (Phase 4,
   AllFindings.png) -- self-contained inside #sec-pj-findings the same way
   every other element on this pane already is (see this file's own "ONE
   MODULE, TWO HOMES" comment): it does not reach into or replace
   project-screen.js's own shared #sec-back/#sec-title/tab strip, which
   still renders above this pane exactly as it does for the other four tabs
   -- reshaping THAT shared, boot-once chrome into a tab-aware breadcrumb of
   its own is a bigger change than this task's own file list asks for, and
   is named as a scope boundary in this task's own report rather than done
   here silently.

   Skipped entirely (returns an empty, harmless wrapper) when this mount is
   the Activity screen's fingerprint dialog: that dialog already carries its
   own title ("Findings in <project>", secActOpenFinding) and its own close
   button, so a second, page-level header stacked inside an already-titled
   modal would say the same thing twice in two registers. `fingerprint`
   being set is the one signal that tells the two mounts apart -- only that
   dialog's own caller ever passes it, through `initialFilters` (see
   secFindStrip's own identical read of it, a few lines below). */
function secFindHeader(fs, data){
  const wrap = secEl("div");
  if(((fs.filters || {}).fingerprint || "").trim()) return wrap;

  // The breadcrumb this pane used to draw for itself moved up, and now its
  // TITLE has too: the page's own title row says "Findings" with this
  // pane's exact sentence beneath it (SEC_TAB_TITLES, project-screen.js)
  // the moment the tab is active, so the "All findings" heading this
  // header used to draw underneath said the same thing twice a few lines
  // apart. What is left here is the pane's own ACTIONS row -- Export and
  // Saved filters are this pane's function, not its name.
  const head = secEl("div", "secfind-head");
  head.appendChild(secEl("span", "spacer"));

  const actions = secEl("div", "secfind-head-actions");
  // "+ Save filter" out in the open (ProjectFindings.png draws it as its
  // own button, not only a field tucked inside the Saved-filters popover):
  // it opens that same popover -- where the name input and the save flow
  // already live -- rather than duplicating the flow behind a second door.
  const savedWrap = secFindSavedFilters(fs, data || {});
  const saveBtn = secEl("button", "btn ghost");
  saveBtn.type = "button";
  saveBtn.appendChild(secIcon("plus"));
  saveBtn.appendChild(document.createTextNode("Save filter"));
  saveBtn.title = "Save the current filters under a name";
  saveBtn.onclick = (e) => {
    e.stopPropagation();
    savedWrap.open = true;
    if(savedWrap.ontoggle) savedWrap.ontoggle();
  };
  actions.appendChild(saveBtn);
  const exportBtn = secEl("button", "btn ghost");
  exportBtn.type = "button";
  exportBtn.appendChild(secIcon("download"));
  exportBtn.appendChild(document.createTextNode("Export"));
  // Reuses the project's own Reports tab -- the report/download surface
  // this project already offers (secRenderProjectReports,
  // reports-tab.js: Markdown/JSON/HTML/SBOM per analysis) -- rather than
  // inventing a second export path with no downloads of its own behind it.
  exportBtn.title = "Open this project's Reports tab";
  exportBtn.onclick = () => secSwitchProjectTab("reports");
  actions.appendChild(exportBtn);
  actions.appendChild(savedWrap);
  head.appendChild(actions);
  wrap.appendChild(head);
  return wrap;
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

// What the strip's per-severity stats COUNT. Threaded onto every stat's own
// `.title` -- both this strip and the sidebar donut legend (index-screen.js,
// see DONUT_PILL_TITLE there) draw the same kind of row/fingerprint split,
// and both now say which one they answer rather than leave two adjacent
// numbers to be told apart by guessing.
const ROW_PILL_TITLE = "Rows matching the current filters — the same finding "
  + "open on two branches counts twice here.";

function _secCap(s){
  s = String(s || "");
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

/* AllFindings.png's own stat strip: Total findings (a doc icon), the five
   severities (a coloured dot, the count, the share of `total` beneath), a
   divider, then Unique issues. Its own shape now, not `.sevpills`/`.sevpill`
   (the pill this file draws everywhere else, including the table's own
   Severity column below) -- the mockup draws a plain dot beside each label
   here, a large number under it and a percentage under THAT, closer to a
   KPI card's own anatomy than to a pill. `secfind-stat total`/`secfind-stat
   unique` carry their own distinguishing class for exactly the same reason
   every severity stat carries its own (`.critical`/`.high`/… below) -- so
   each of the two honesty-critical numbers (this file's own header comment
   on why total and unique are both shown) stays independently findable,
   never just "the Nth number in the row". */
function secFindStrip(fs, data){
  const box = secEl("div");
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

  // Seven KPI CARDS (ProjectFindings.png), the house kpi-grid replacing the
  // one-container stat strip this used to be: Total findings, the five
  // severities (each with its share of the total on the same delta line the
  // Overview's cards use), and Unique issues. Same numbers, same titles --
  // ROW_PILL_TITLE on everything row-counted, the fingerprint sentence on
  // Unique -- and the same marker classes on Total/Unique the pinned tests
  // find them by. The severity cards wear the shared severity icon/tone
  // maps (SEV_KPI_ICON/SEV_KPI_TONE, overview-tab.js), so the two tabs'
  // cards can never drift apart.
  const strip = secEl("div", "kpi-grid");

  const totalCard = kpiCard({icon: "layers", value: String(data.total || 0),
    label: "Total findings", title: ROW_PILL_TITLE});
  totalCard.className += " secfind-stat total";
  strip.appendChild(totalCard);

  const bySev = data.by_severity || {};
  const total = data.total || 0;
  let any = false;
  ["critical", "high", "medium", "low", "info"].forEach(sev => {
    any = any || !!bySev[sev];
    const n = bySev[sev] || 0;
    const card = kpiCard({icon: SEV_KPI_ICON[sev], tone: SEV_KPI_TONE[sev],
      value: String(n), label: _secCap(sev), title: ROW_PILL_TITLE});
    // A dash, not "0.0%" -- a percentage of nothing is not a measured zero
    // share, the same distinction this app's own KPI cards already draw for
    // a rate with no denominator yet.
    card.appendChild(secEl("div", "secov-delta",
      total ? ((n / total) * 100).toFixed(1) + "%" : "—"));
    strip.appendChild(card);
  });

  const uniqueCard = kpiCard({icon: "diamond", value: String(data.unique || 0),
    label: "Unique issues",
    title: "Distinct problems (fingerprints) — the same finding open "
      + "on two branches counts once here."});
  uniqueCard.className += " secfind-stat unique";
  strip.appendChild(uniqueCard);

  box.appendChild(strip);
  // The ok-green "nothing matches" signal (Phase 4: no longer a `.sevpill`
  // chip inside the strip's own row of pills, which this shape does not
  // have any more, but the identical fact still needs the identical cue) --
  // may only be drawn over a project something has actually READ. `analysed`
  // false means nothing ever finished here, and painting this green (beside
  // an all-zero strip, with the table below blaming filters the reader
  // never set) is the one wrong answer this strip can give. See
  // queries.finding_rows's own docstring for the two flags.
  if(!any && data.analysed !== false){
    box.appendChild(secEl("span", "sevpill clean", "Nothing matches"));
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
  box.appendChild(note);
  return box;
}

/* -------------------------------------------------------------- filter bar
   Two rows -- a wide search, five "Label: value" pickers, then Category, the
   Show-resolved switch and, right-aligned, Clear filters + the Filters(N)
   badge (AllFindings.png). Every picker below is the SAME hand-rolled
   <details>/<summary>/.menu-pop shape secFindSavedFilters already used one
   task ago, for the identical reason that comment gives: `makePicker`
   (bin/dashboard.html) needs STATIC, boot-once markup registered exactly
   once into its own module-level PICKERS array, and this whole bar is
   rebuilt from scratch on every filter/sort/page change -- a second
   `makePicker(id, ...)` call on the same id every repaint would either find
   stale markup or grow that registry forever.

   Every filter's SEMANTICS are exactly `queries.finding_rows`'s own, byte
   for byte: severity/state/category stay arrays (multi-select), branch/
   analysis/path/q stay the same plain strings the server has always
   accepted -- Branch and Analysis run merely gain real OPTIONS to pick from
   (`data.branches`/`data.analyses`, both already exact-match fields
   server-side; see queries.finding_rows's own docstring) instead of a bare
   text box asking the reader to already know a branch name or an analysis
   id by heart. File path stays genuinely free text (a substring search),
   its trigger just wearing the same "Label: value ▾" look as its five
   siblings -- opening it reveals the text input, not an enumerated list.

   secFindTriggerLabel/secFindPositionPop are exported (F4 Activity polish):
   the Activity screen's own period picker (activity-screen.js) is the same
   hand-rolled <details>/<summary>/.menu-pop shape for the identical reason
   this file's pickers are -- a short list rebuilt whole on every pick, no
   fit for makePicker's own boot-once registry -- so it reuses these two
   rather than a third copy of either. */
export function secFindTriggerLabel(label, valueText){
  const trigger = document.createElement("summary");
  trigger.className = "filterpick";
  // Found live by secFindingsPeriodPicker first (see index-screen.js's own
  // comment): bin/dashboard.html's global "click outside a menu-pop closes
  // every open one" listener has no idea this menu is a <details> rather
  // than the older hidden-attribute-toggled pattern, and hides this very
  // popover a beat before the browser's own default action opens it, unless
  // the opening click is stopped here from ever reaching that listener.
  trigger.onclick = (e) => e.stopPropagation();
  if(label) trigger.appendChild(secEl("span", "pk-k", label + ":"));
  const valueEl = secEl("span", "pk-v", valueText);
  trigger.appendChild(valueEl);
  trigger.appendChild(secIcon("cdown"));
  return {trigger, valueEl};
}

// Positions `pop` below `trigger`'s own current screen position every time
// it opens -- escaping `.table-card{overflow:hidden}` the same way
// secFindSavedFilters's own popover already has to (see that function's own
// comment, kept below, for the full reasoning: closeMenus() and this bar's
// own repaint-from-scratch cadence both apply here identically). Also what
// keeps `pop.hidden` resynced from `details.open` on EVERY toggle rather
// than trusting whatever an earlier stray click outside left behind (the
// exact race this file's own CHANGELOG entry describes finding first) --
// the Activity screen's own period picker imports this rather than the
// OLDER, unfixed pattern secFindingsPeriodPicker (index-screen.js) still
// uses: that widget's own card is torn down and rebuilt whole every
// 5-second poll tick, so the same race there self-heals within one tick:
// the Activity screen never polls while open (secIsActivityOpen() is what
// stops it), so nothing would ever rebuild a stuck instance for it.
export function secFindPositionPop(details, trigger, pop){
  pop.setAttribute("role", "menu");
  pop.hidden = true;
  details.appendChild(pop);
  details.ontoggle = () => {
    pop.hidden = !details.open;
    if(!details.open) return;
    const r = trigger.getBoundingClientRect();
    pop.style.position = "fixed";
    pop.style.top = (r.bottom + 6) + "px";
    pop.style.left = r.left + "px";
    pop.style.right = "auto";
    pop.style.bottom = "auto";
  };
}

function secFindMultiPicker(label, options, selected, onToggle){
  const field = secEl("div", "secfind-fpick");
  const valueText = !selected.length ? "All"
    : selected.length === 1 ? ((options.find(o => o.v === selected[0]) || {}).label || selected[0])
    : selected.length + " selected";
  const {trigger} = secFindTriggerLabel(label, valueText);
  const details = document.createElement("details");
  details.appendChild(trigger);
  const pop = secEl("div", "menu-pop");
  options.forEach(opt => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitemcheckbox");
    item.setAttribute("aria-checked", selected.includes(opt.v) ? "true" : "false");
    item.appendChild(document.createTextNode(opt.label));
    if(selected.includes(opt.v)) item.appendChild(secIcon("check2"));
    // Stays open: a multi-select is usually more than one pick in a row.
    item.onclick = (e) => { e.stopPropagation(); onToggle(opt.v); };
    pop.appendChild(item);
  });
  secFindPositionPop(details, trigger, pop);
  field.appendChild(details);
  return field;
}

function secFindSinglePicker(label, options, selected, onPick){
  const field = secEl("div", "secfind-fpick");
  const current = options.find(o => o.v === selected);
  const {trigger} = secFindTriggerLabel(label, selected && current ? current.label : "All");
  const details = document.createElement("details");
  details.appendChild(trigger);
  const pop = secEl("div", "menu-pop");
  const allItem = document.createElement("button");
  allItem.type = "button";
  allItem.setAttribute("role", "menuitem");
  allItem.appendChild(document.createTextNode("All"));
  if(!selected) allItem.appendChild(secIcon("check2"));
  allItem.onclick = (e) => { e.stopPropagation(); details.open = false; onPick(""); };
  pop.appendChild(allItem);
  options.forEach(opt => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    item.appendChild(document.createTextNode(opt.label));
    if(selected === opt.v) item.appendChild(secIcon("check2"));
    item.onclick = (e) => { e.stopPropagation(); details.open = false; onPick(opt.v); };
    pop.appendChild(item);
  });
  secFindPositionPop(details, trigger, pop);
  field.appendChild(details);
  return field;
}

function secFindTextPicker(label, value, onChange){
  const field = secEl("div", "secfind-fpick");
  const {trigger} = secFindTriggerLabel(label, value.trim() ? value : "All");
  const details = document.createElement("details");
  details.appendChild(trigger);
  const pop = secEl("div", "menu-pop");
  const inp = document.createElement("input");
  inp.type = "text";
  inp.spellcheck = false;
  inp.autocomplete = "off";
  inp.placeholder = "contains…";
  inp.value = value;
  inp.onclick = (e) => e.stopPropagation();
  // change, not input: a fetch per keystroke would be a subprocess per
  // keystroke on the server (see index.js's identical reasoning for
  // #sec-branch-other).
  inp.onchange = () => onChange(inp.value);
  pop.appendChild(inp);
  secFindPositionPop(details, trigger, pop);
  field.appendChild(details);
  return field;
}

function secFindToggleIn(list, value){
  const i = list.indexOf(value);
  if(i >= 0) list.splice(i, 1); else list.push(value);
}

// Filters(N): a read-only count of how many DIMENSIONS are currently
// narrowing the request, one per distinct filter -- not per value inside a
// multi-select, so picking "Critical" and "High" together still reads as
// ONE active narrow (Severity), the same granularity a reader thinks in
// ("I have a severity filter on") rather than an internal implementation
// detail (how many values happen to be inside it). `show_resolved` being
// OFF counts as an active narrow too, deliberately: it is the one filter
// this bar applies before a reader ever touches a control (the caption
// beside Category says so), and it genuinely removes rows from what
// `finding_rows` returns -- the same reason AllFindings.png's own default,
// fully-"All" screenshot still reads "Filters (1)" rather than (0).
function secFindActiveFilterCount(fs){
  const f = fs.filters;
  let n = 0;
  if(f.severity.length) n++;
  if(f.state.length) n++;
  if(f.category.length) n++;
  if(f.branch.trim()) n++;
  if(f.path.trim()) n++;
  if(f.analysis.trim()) n++;
  if(f.q.trim()) n++;
  if(!f.show_resolved) n++;
  return n;
}

function secFindClearButton(fs){
  const btn = secEl("button", "btn ghost");
  btn.type = "button";
  btn.appendChild(secIcon("x"));
  btn.appendChild(document.createTextNode("Clear filters"));
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

/* The Saved-filters control: a "Saved filters ▾" trigger (moved into
   secFindHeader, restyled as AllFindings.png's own button+chevron) whose
   popover lists every saved filter, a trash icon per row to delete it, and
   a "Save current view as…" mini-form at the bottom -- the same three
   operations the old bottom-bar layout offered (pick/save/delete), now
   inside the one control that opens them rather than three separate always-
   visible fields. Still the house <details>/<summary>/.menu-pop popover
   (Phase 4 Task 5) -- secIndexProjectRow's own kebab and
   secFindingsPeriodPicker (both index-screen.js) already draw this exact
   shape for the identical reason: a short, dynamically-populated list with
   no paging, mounted and torn down far too often for makePicker's own
   module-level PICKERS registry (built for STATIC, boot-once markup --
   Jobs/Runs' pickers, and this screen's own picker fields above, all live
   exactly once for the page's whole life). This one is neither: secFindPaint
   rebuilds its whole host, savedName included, on every filter change and
   every poll tick, AND -- see this file's own "ONE MODULE, TWO HOMES"
   comment -- can be mounted twice at once (the Findings tab and the
   Activity screen's fingerprint dialog, though that mount never actually
   renders this control -- see secFindHeader's own early return). A
   <details>-based popover closes over its OWN nodes, not a shared id
   registry, so neither repeated rebuilds nor two live instances collide the
   way a second makePicker("secfind-saved", ...) call on a duplicate id
   would. */
function secFindSavedFilters(fs, data){
  const filters = data.filters || [];
  // Mirrors the old <select>'s own reset: a name that no longer matches any
  // saved filter (renamed or deleted from elsewhere) must not keep pinning
  // the field to it.
  if(!filters.some(f => f.name === fs.savedName)) fs.savedName = "";

  const details = document.createElement("details");
  details.className = "secfind-savedpick";
  const {trigger, valueEl} = secFindTriggerLabel(null, fs.savedName || "Saved filters");
  details.appendChild(trigger);
  const pop = secEl("div", "menu-pop");

  // A custom widget has no browser-native "picking an option repaints the
  // control" behaviour the way the old <select> did -- the trigger label is
  // repainted here, by hand, on every pick (the list itself is rebuilt
  // fresh from scratch the next time it opens, so it never needs a matching
  // manual repaint).
  function pick(name, query){
    fs.savedName = name;
    valueEl.textContent = name || "Saved filters";
    details.open = false;
    // Only a REAL saved filter re-fetches -- picking "— none —" just clears
    // the field, the same no-op the old <select>'s blank option was.
    if(query) secFindApplyQuery(fs, query);
  }

  const blank = document.createElement("button");
  blank.type = "button";
  blank.setAttribute("role", "menuitem");
  blank.appendChild(document.createTextNode("— none —"));
  if(!fs.savedName) blank.appendChild(secIcon("check2"));
  blank.onclick = (e) => { e.stopPropagation(); pick(""); };
  pop.appendChild(blank);

  filters.forEach(f => {
    const row = secEl("div", "secfind-savedrow");
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    // .textContent (via createTextNode below), never markup: a saved
    // filter's name is a string a human typed on this page, but still text
    // a reader did not write, the same rule every other value in this area
    // follows.
    item.appendChild(document.createTextNode(f.name));
    if(f.name === fs.savedName) item.appendChild(secIcon("check2"));
    item.onclick = (e) => { e.stopPropagation(); pick(f.name, f.query); };
    row.appendChild(item);
    const del = document.createElement("button");
    del.type = "button";
    del.className = "iconbtn";
    del.title = "Delete this saved filter";
    del.appendChild(secIcon("trash"));
    del.onclick = (e) => { e.stopPropagation(); details.open = false; secFindDeleteSaved(fs, f.name); };
    row.appendChild(del);
    pop.appendChild(row);
  });

  pop.appendChild(secEl("div", "sep"));
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.placeholder = "Save current view as…";
  nameInput.value = fs.newName;
  nameInput.onclick = (e) => e.stopPropagation();
  nameInput.onchange = () => { fs.newName = nameInput.value; };
  pop.appendChild(nameInput);
  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.setAttribute("role", "menuitem");
  saveBtn.appendChild(secIcon("check2"));
  saveBtn.appendChild(document.createTextNode("Save"));
  saveBtn.onclick = (e) => { e.stopPropagation(); secFindSaveCurrent(fs, nameInput.value); };
  pop.appendChild(saveBtn);

  secFindPositionPop(details, trigger, pop);
  return details;
}

function secFindFilterBar(fs, data){
  const wrap = secEl("div", "secfind-filters");

  const row1 = secEl("div", "secfind-filters-row");
  const search = secEl("div", "secfind-search");
  search.appendChild(secIcon("search"));
  const searchInput = document.createElement("input");
  searchInput.type = "text";
  searchInput.placeholder = "Search by message, file, or CVE…";
  searchInput.spellcheck = false;
  searchInput.autocomplete = "off";
  searchInput.value = fs.filters.q;
  // Matches what queries.finding_rows's own `q` filter actually searches --
  // title, rule, rationale and every occurrence's file path. "CVE" is not a
  // field of its own: for a dependency finding it is folded into `rule`, so
  // naming `rule` here (in the tooltip -- the mockup's own placeholder
  // above is the friendly gloss) is what makes that searchable text
  // discoverable at all, rather than implying a fifth, nonexistent column.
  searchInput.title = "Search title / rule / rationale / file";
  searchInput.onchange = () => { fs.filters.q = searchInput.value; fs.page = 1; secFindRefresh(fs); };
  search.appendChild(searchInput);
  row1.appendChild(search);

  row1.appendChild(secFindMultiPicker("Severity",
    [...SEV_ORDER].reverse().map(s => ({v: s, label: _secCap(s)})),
    fs.filters.severity,
    (v) => { secFindToggleIn(fs.filters.severity, v); fs.page = 1; secFindRefresh(fs); }));

  row1.appendChild(secFindMultiPicker("Status",
    SEC_STATES.map(s => ({v: s, label: SEC_STATE_LABEL[s] || s})),
    fs.filters.state,
    (v) => { secFindToggleIn(fs.filters.state, v); fs.page = 1; secFindRefresh(fs); }));

  row1.appendChild(secFindSinglePicker("Analysis run",
    (data.analyses || []).map(a => ({v: String(a.id),
      label: "#" + a.id + " (" + _secCap(a.profile) + ") — " + a.branch})),
    fs.filters.analysis,
    (v) => { fs.filters.analysis = v || ""; fs.page = 1; secFindRefresh(fs); }));

  row1.appendChild(secFindSinglePicker("Branch",
    (data.branches || []).map(b => ({v: b, label: b})),
    fs.filters.branch,
    (v) => { fs.filters.branch = v || ""; fs.page = 1; secFindRefresh(fs); }));

  row1.appendChild(secFindTextPicker("File path", fs.filters.path,
    (v) => { fs.filters.path = v; fs.page = 1; secFindRefresh(fs); }));

  wrap.appendChild(row1);

  const row2 = secEl("div", "secfind-filters-row row2");
  row2.appendChild(secFindMultiPicker("Category",
    FIND_CATEGORIES.map(c => ({v: c, label: _secCap(c)})),
    fs.filters.category,
    (v) => { secFindToggleIn(fs.filters.category, v); fs.page = 1; secFindRefresh(fs); }));

  const toggleField = secEl("label", "secfind-toggle-field");
  // Fixed, accepted and false-positive rows are excluded unless this is on
  // -- said out loud on the control itself (a hover, not a permanent line
  // of text the mockup's own row 2 does not draw): the old layout carried
  // this as a standing caption between the chip rows; AllFindings.png has
  // no such line, so the explanation moves to where a reader who wants it
  // will find it without it costing space for the reader who does not.
  toggleField.title = "Fixed, accepted and false-positive rows are excluded unless this is on.";
  const sw = secEl("span", "switch");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = fs.filters.show_resolved;
  cb.onchange = () => { fs.filters.show_resolved = cb.checked; fs.page = 1; secFindRefresh(fs); };
  sw.appendChild(cb);
  sw.appendChild(secEl("span", "track"));
  sw.appendChild(secEl("span", "knob"));
  toggleField.appendChild(sw);
  toggleField.appendChild(secEl("span", null, "Show resolved findings"));
  row2.appendChild(toggleField);

  const right = secEl("div", "secfind-filters-right");
  right.appendChild(secFindClearButton(fs));
  const filtBadge = secEl("button", "btn ghost");
  filtBadge.type = "button";
  // A read-only count, not a second control -- see
  // secFindActiveFilterCount's own comment for what it counts.
  filtBadge.disabled = true;
  filtBadge.appendChild(secIcon("filter"));
  filtBadge.appendChild(document.createTextNode("Filters"));
  filtBadge.appendChild(secEl("span", "secfind-filters-badge", String(secFindActiveFilterCount(fs))));
  right.appendChild(filtBadge);
  row2.appendChild(right);

  wrap.appendChild(row2);
  return wrap;
}

/* ------------------------------------------------------------------ table
   The state a row shows is the state its OWN branch's latest finished
   analysis gives it -- a list that crosses branches (and so crosses
   analyses) has to say which one it is speaking about, hence the Branch and
   Analysis run columns beside Status rather than a bare severity/title
   pair. */
function secFindRow(fs, f){
  const tr = document.createElement("tr");
  tr.className = "sev-" + secSevKey(f) + " state-" + secStateKey(f);

  // SEVERITY: a coloured pill (AllFindings.png) -- the row's own left edge
  // (.secfind-table tr.sev-*>td:first-child, ui/css/pages.css) reads the
  // SAME class this <tr> already carries; the pill is the second half of
  // the identical cue, not a separate severity-to-colour map of its own.
  const tdSev = document.createElement("td");
  tdSev.appendChild(secEl("span", "sevpill " + secSevKey(f), f.severity || ""));
  tr.appendChild(tdSev);

  // TITLE: bold title, one-line muted rationale beneath. The occurrence
  // path used to live in THIS cell's own second line -- it is Location's
  // own column now (below), split out to match AllFindings.png.
  const tdTitle = document.createElement("td");
  // Titles and rationale come out of analysed code, and a branch name may
  // legally contain '<', '>' and '&' -- textContent, always, the one rule
  // this whole area exists to keep (see vocabulary.js's own file comment).
  // Clamped to two lines by CSS (real titles run to whole sentences where
  // the mockup's sample says "SQL Injection"), the full text one hover
  // away -- the same treatment the Overview's Top-findings card gives the
  // same field.
  const titleEl = secEl("div", "sectitle", f.title || "");
  titleEl.title = f.title || "";
  tdTitle.appendChild(titleEl);
  if((f.rationale || "").trim()){
    tdTitle.appendChild(secEl("div", "secmeta clamp1", f.rationale));
  }
  tr.appendChild(tdTitle);

  // LOCATION: the first occurrence's own path:line, a "(+N more)" cue when
  // there is more than one -- the cue's own title lists the rest, so
  // nothing is lost, only deferred to a hover.
  const tdLoc = document.createElement("td");
  const occ = f.occurrences || [];
  if(occ.length){
    const first = occ[0];
    const where = first.line ? first.file + ":" + first.line : first.file;
    const more = occ.length > 1 ? " (+" + (occ.length - 1) + " more)" : "";
    const locEl = secEl("div", "secfind-loc", where + more);
    if(occ.length > 1){
      locEl.title = occ.slice(1)
        .map(o => o.line ? o.file + ":" + o.line : o.file).join(", ");
    }
    tdLoc.appendChild(locEl);
  }
  tr.appendChild(tdLoc);

  // CATEGORY: the ledger's own category (Secrets/Dependency/Hygiene/SAST),
  // not a rule's per-rule label -- secRuleMeta's "Private keys committed"
  // used to render here, duplicating TITLE one column to its left (a
  // finding's own title says exactly that already). secCategoryMeta
  // (vocabulary.js) is the coarser, category-level reading of the SAME
  // vocabulary: same four icons secRuleMeta's own fallback assigns per
  // category (one shared table, see that function's own comment), a fixed
  // label instead of a humanised rule id. secRuleMeta stays untouched for
  // its other caller ("Top issue categories", index-screen.js), which is
  // ranking RULES, not categories. The raw rule id stays one hover away.
  const tdCat = document.createElement("td");
  const meta = secCategoryMeta(f.category);
  const catWrap = secEl("div", "secfind-cat");
  catWrap.appendChild(secIcon(meta.icon));
  catWrap.appendChild(secEl("span", null, meta.label));
  if(f.rule) catWrap.title = f.rule;
  tdCat.appendChild(catWrap);
  tr.appendChild(tdCat);

  // ANALYSIS RUN: "#<id> (<Profile>)", the date beneath -- links to that
  // analysis exactly where the Runs tab's own "#N" button already does
  // (secShowAnalysis), switching this project screen onto its Runs tab
  // first since that is where the single-analysis drill-down actually
  // renders (project-screen.js's own comment: "below the Runs table").
  // Profile/date are read off `fs.data.analyses` (queries.finding_rows's
  // own per-branch list) by this row's own `branch`/`analysis_id` rather
  // than carried a second time on every one of hundreds of finding rows
  // that can share the same handful of analyses.
  const tdRun = document.createElement("td");
  const runWrap = secEl("div", "secfind-run");
  const runInfo = ((fs.data || {}).analyses || []).find(a => a.id === f.analysis_id);
  if(f.analysis_id != null){
    const runBtn = document.createElement("button");
    runBtn.type = "button";
    runBtn.title = "Show this analysis";
    const profileWord = runInfo && runInfo.profile ? " (" + _secCap(runInfo.profile) + ")" : "";
    runBtn.appendChild(document.createTextNode("#" + f.analysis_id + profileWord));
    runBtn.onclick = (e) => {
      e.stopPropagation();
      secSwitchProjectTab("runs");
      secShowAnalysis(f.analysis_id, true);
    };
    runWrap.appendChild(runBtn);
  }
  if(runInfo && runInfo.started){
    runWrap.appendChild(secEl("div", "secmeta", fmtWhen(runInfo.started)));
  }
  tdRun.appendChild(runWrap);
  tr.appendChild(tdRun);

  // BRANCH
  const tdBranch = document.createElement("td");
  tdBranch.textContent = f.branch || "";
  tr.appendChild(tdBranch);

  // STATUS: the SAME .secstate pill this table has always drawn -- only the
  // COLUMN header renamed, from "State" to AllFindings.png's own "Status"
  // (FIND_SORT_COLUMNS, this file's own top); the pill and the ledger
  // states it draws are unchanged.
  const tdState = document.createElement("td");
  const stBadge = secEl("span", "secstate " + secStateKey(f), SEC_STATE_LABEL[f.state] || f.state);
  stBadge.title = SEC_STATE_HELP[f.state] || "";
  tdState.appendChild(stBadge);
  tr.appendChild(tdState);

  // FIRST SEEN
  const tdFirst = document.createElement("td");
  tdFirst.textContent = f.first_seen ? fmtWhen(f.first_seen) : "—";
  tr.appendChild(tdFirst);

  // ACTIONS: an eye (view -- the same analysis drill-down Analysis run
  // links to) plus a kebab holding the decision actions, reusing this app's
  // own established eye-for-view (runs.js's own "View log") and
  // kebab-for-more (.secidx-kebab, index-screen.js) vocabulary rather than
  // the row's own two always-visible text buttons this table used to draw.
  tr.appendChild(secFindActionsCell(fs, f));

  return tr;
}

/* The decision menu's own two items -- returns the <div class="menu-pop">
   itself so a caller (secFindActionsCell) can mount it inside its own
   kebab. `onPicked`, when given, runs before the API call fires (closing
   the kebab immediately, rather than leaving it open through the confirm
   dialog secAskReason shows next). */
function secFindDecisionControls(fs, f, onPicked){
  const pop = secEl("div", "menu-pop");
  [["accepted", "Accept risk"], ["false_positive", "False positive"]].forEach(([state, label]) => {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.appendChild(document.createTextNode(label));
    b.onclick = (e) => {
      e.stopPropagation();
      if(onPicked) onPicked();
      secFindDecide(fs, f, state, label);
    };
    pop.appendChild(b);
  });
  return pop;
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

/* AllFindings.png's own Actions column: an eye, always present, plus a
   kebab for a non-fixed finding's decision actions. `.rowacts` is this
   app's own established actions-cell layout (ui/app/jobs-table.js,
   projects.js, runs.js all already use it) -- text-align/inline spacing on
   the CELL itself, never `display:flex` on the `<td>` (this area's own
   rule), which is exactly why a bare `.iconbtn`/`<details>` pair laid out
   through it needs no flex container of its own. */
function secFindActionsCell(fs, f){
  const td = document.createElement("td");
  td.className = "rowacts";

  const view = document.createElement("button");
  view.type = "button";
  view.className = "iconbtn";
  view.title = f.analysis_id != null ? "View this analysis" : "No analysis to view";
  view.disabled = f.analysis_id == null;
  view.appendChild(secIcon("eye"));
  view.onclick = (e) => {
    e.stopPropagation();
    if(f.analysis_id == null) return;
    secSwitchProjectTab("runs");
    secShowAnalysis(f.analysis_id, true);
  };
  td.appendChild(view);

  // A fixed finding is gone: there is nothing left to accept or dismiss --
  // the same rule secFindingRow in analysis.js already follows. No kebab at
  // all here, not one with an empty menu: a menu button opening onto
  // nothing is a worse affordance than no button.
  if(f.state !== "fixed"){
    const kebab = document.createElement("details");
    kebab.className = "secidx-kebab";
    const summary = document.createElement("summary");
    summary.className = "iconbtn";
    summary.title = "More actions";
    summary.appendChild(secIcon("dots"));
    // Closes any OTHER open row's kebab the instant this one is clicked --
    // see secIndexProjectRow's own identical comment (index-screen.js) for
    // why `closeMenus()` here can never also close THIS one on its own
    // opening click (the browser's default action, which flips `.open`,
    // runs only after every bubble-phase listener including this one).
    summary.onclick = (e) => { e.stopPropagation(); closeMenus(); };
    kebab.appendChild(summary);
    const pop = secFindDecisionControls(fs, f, () => { kebab.open = false; });
    kebab.appendChild(pop);
    // Same `position:fixed` escape from `.table-card{overflow:hidden}`
    // every other popover on this screen already needs (see
    // secFindPositionPop's own comment) -- right-aligned, since this is the
    // table's own last column and a left-aligned popover would routinely
    // open past the viewport's own right edge.
    kebab.ontoggle = () => {
      pop.hidden = !kebab.open;
      if(!kebab.open) return;
      const r = summary.getBoundingClientRect();
      pop.style.position = "fixed";
      pop.style.top = (r.bottom + 6) + "px";
      pop.style.left = "auto";
      pop.style.right = (window.innerWidth - r.right) + "px";
      pop.style.bottom = "auto";
    };
    td.appendChild(kebab);
  }
  return td;
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

  // Nine header cells, AllFindings.png's own order. Six are sortable
  // (FIND_SORT_COLUMNS, this file's own top); Location, Analysis run and
  // Actions are not -- every one of the nine still gets the SAME inert
  // `<button class="btn ghost">` shape (no `onclick` on the three that are
  // not sortable) rather than a bare `<th>`, for the identical reason
  // MINOR 5's own comment (kept below, unchanged) already gives the Actions
  // header: a plain `<th>` reads this page's generic uppercase small-caps
  // rule, and every sortable sibling beside it does not, because each
  // one's label sits inside a `<button>`, whose own UA stylesheet resets
  // `text-transform` before this file ever touches it.
  //
  // Walks FIND_SORT_COLUMNS itself (not SEC_FIND_TABLE_COLS -- see that
  // const's own comment for why the render path never reads it) and
  // splices the three non-sortable headers in after the sortable column
  // each one follows in the mockup, rather than a second nine-entry array
  // naming the same nine columns FIND_SORT_COLUMNS plus SEC_FIND_TABLE_COLS
  // already do between them.
  const INSERT_AFTER = {title: "Location", category: "Analysis run"};
  function sortableHeader(key, label){
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
    return th;
  }
  function inertHeader(label){
    const th = document.createElement("th");
    const btn = secEl("button", "btn ghost");
    btn.type = "button";
    btn.appendChild(secEl("span", null, label));
    th.appendChild(btn);
    return th;
  }
  FIND_SORT_COLUMNS.forEach(([key, label]) => {
    htr.appendChild(sortableHeader(key, label));
    if(INSERT_AFTER[key]) htr.appendChild(inertHeader(INSERT_AFTER[key]));
  });
  htr.appendChild(inertHeader("Actions"));
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
   The bridged tableFooter() (Phase 4 Task 6, extended Phase 4 for
   AllFindings.png's own numbered/ellipsis pager and per-page picker) --
   "Showing X to Y of N findings", the per-page picker, then "‹ 1 2 3 4 5 …
   19 ›". `numbered: true, collapse: true` is tableFooter's own opt-in
   variant (ui/app/chrome.js, see its comment) -- this table is the first
   caller tall enough in real use to need the collapsed form; the index's
   own two tables (a handful of pages at most today) may adopt either
   variant later if their own page counts ever grow into it, per that
   const's own comment, but neither is this task's to change.

   Every button below is wired through `.onclick` assignment, never
   `addEventListener` -- the Node-driven pinned test that drives this
   function for real (test_the_pager_math_and_button_disabling_at_both_edges)
   runs it against a FakeElement with no `addEventListener` of its own, the
   same constraint this whole file's hand-rolled popovers already write
   around. secFindPager appends this INSIDE the same table-card
   secFindTableSection returns (see that call site's own comment in
   secFindPaint) -- this function only builds the footer and wires its own
   buttons, and is not responsible for where it ends up mounted. */
function secFindPerPageField(fs){
  const field = secEl("div", "secfind-fpick secfind-perpage");
  const current = fs.perPage || FIND_PER_PAGE;
  const {trigger} = secFindTriggerLabel(null, current + " per page");
  const details = document.createElement("details");
  details.appendChild(trigger);
  const pop = secEl("div", "menu-pop");
  FIND_PER_PAGE_OPTIONS.forEach(n => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    item.appendChild(document.createTextNode(n + " per page"));
    if(current === n) item.appendChild(secIcon("check2"));
    item.onclick = (e) => {
      e.stopPropagation();
      details.open = false;
      fs.perPage = n;
      fs.page = 1;
      secFindRefresh(fs);
    };
    pop.appendChild(item);
  });
  secFindPositionPop(details, trigger, pop);
  field.appendChild(details);
  return field;
}

function secFindPager(fs, data){
  const total = data.total || 0;
  const perPage = data.per_page || fs.perPage || FIND_PER_PAGE;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const page = data.page || 1;
  const from = total ? (page - 1) * perPage + 1 : 0;
  const to = Math.min(page * perPage, total);

  const foot = tableFooter({shown: {from, to}, total, noun: "finding",
    page, pages, numbered: true, collapse: true});
  // tableFooter's own numbered mode drops the pager nav entirely at one
  // page (see its own comment) -- `nav` is `undefined` then, and every
  // button-wiring step below is skipped along with it.
  const nav = foot.childNodes[1];
  if(nav){
    const kids = nav.childNodes || [];
    const prev = kids[0], next = kids[kids.length - 1];
    if(prev) prev.onclick = () => { fs.page = Math.max(1, page - 1); secFindRefresh(fs); };
    if(next && next !== prev){
      next.onclick = () => { fs.page = Math.min(pages, page + 1); secFindRefresh(fs); };
    }
    kids.forEach(child => {
      if(child.dataset && child.dataset.page){
        child.onclick = () => { fs.page = Number(child.dataset.page); secFindRefresh(fs); };
      }
    });
  }
  const wrap = secEl("div", "table-foot");
  wrap.appendChild(foot.childNodes[0]);
  wrap.appendChild(secFindPerPageField(fs));
  if(nav) wrap.appendChild(nav);
  return wrap;
}
