/* -------------------------------------------------------- the Activity screen
   What happened and when, filterable by kind, every project unless scoped to
   one -- `GET /api/security/activity` (bin/security/cli.py's `activity-data`,
   bin/claude-cron-server's `security_activity`), which bundles the events
   (`ledger.events_for`, Task 3), their per-kind counts for the period
   (`queries.activity_summary`, Task 5) and the busiest projects in one
   round trip, the same "one call answers the whole screen" rule every
   sibling screen in this area already follows.

   The last of this area's four screens. Two entry points: the toolbar
   button on the Security index (unscoped -- every project), and the "View
   all" link on a project's own "Recent activity" card (scoped to that one
   project) -- see ui/security/project-screen.js's `secProjectActivity`.
   `secOpenActivity`/`secBackFromActivity` toggle `#sec-activity` against
   `#sec-projects` the same way `secOpen`/`secBack` (analysis.js) already
   toggle `#sec-detail` against it; `secIsActivityOpen()` is what index.js's
   `renderSecurity()` checks to stay off this screen's own painting, the
   identical guard it already gives the project screen.

   `kind` narrows the TABLE only; `project` narrows the table, the summary
   AND the projects list -- a real change of scope, unlike a tab (see
   `cmd_activity_data`'s own docstring for why). No user column and no IP:
   this install has one operator (app.db's own `CHECK (id = 1)`), and the
   sidebar has no "top active users" either -- with one operator that is a
   list of one, which is not an insight (the identical reasoning the brief
   gives for dropping the mockup's Users tab). "Most active projects" earns
   its place instead: with several projects sharing one ledger, WHICH one
   is busiest is a real question with more than one possible answer.

   Detail, project and Time's own absolute sub-line are `textContent`/text
   nodes, always: an event's `detail` carries human-written text (a
   decision's own reason), the same rule vocabulary.js's opening comment
   states for this whole area. TIME itself is structured now (F4 Activity
   polish: relative time above, the exact moment beneath, the house two-line
   pattern this screen's siblings already use) rather than one bare
   textContent string, but every piece of it is still a text node built by
   secEl/createTextNode -- never a template string handed to the parser.

   The table's "Related" column is the one interesting design decision here:
   an analysis id (`analysis_started`/`analysis_finished`/`report_exported`)
   NAVIGATES to that analysis -- opens its project, switches to Runs,
   focuses the row -- reusing the existing, fixed-id single-analysis view
   verbatim (analysis.js's own `secShowAnalysis`, unchanged). A fingerprint
   prefix (`decision_made`) instead opens a SECOND, independent mount of
   `renderFindings()` in its own dialog, filtered to that one fingerprint,
   without leaving this screen -- see findings-screen.js's own file comment
   on being host-keyed for exactly this. The two links behave differently
   because the two underlying views are shaped differently: the analysis
   view is a fixed-id pane wired into the project screen with no portable
   host of its own, while the findings browser was already rebuilt
   (Task 11) to be mountable anywhere, twice over. */
import { $, fmtAgo, pageHeader, makePicker } from "./page.js";
import { secEl, secIcon, secIconHTML, secFetch } from "./dom.js";
import { EVENT_KINDS, EVENT_KIND_LABEL } from "./vocabulary.js";
import { secBack, secShowAnalysis } from "./analysis.js";
import { secOpenProject, secSwitchProjectTab } from "./project-screen.js";
import { renderFindings, secFindTriggerLabel, secFindPositionPop } from "./findings-screen.js";

// The mockup's own tab order, minus Users -- see this file's header comment.
// Each tab is the SAME table, scoped to a subset of EVENT_KINDS; "All
// activity"'s empty `kinds` means "every kind", not "no kind".
const ACT_TABS = [
  {key: "", label: "All activity", kinds: []},
  {key: "analyses", label: "Analyses", kinds: ["analysis_started", "analysis_finished"]},
  {key: "findings", label: "Findings", kinds: ["decision_made"]},
  {key: "settings", label: "Settings", kinds: ["settings_changed", "report_exported"]},
];
const ACT_TAB_BUTTON_ID = {"": "secactt-all", analyses: "secactt-analyses",
                           findings: "secactt-findings", settings: "secactt-settings"};
// Day windows, translated into `since` client-side before the fetch --
// `security_activity`'s own `since` is a raw timestamp, matching
// `ledger.events_for`'s contract, so the "last N days" framing lives here,
// not on the wire. 0 means "no lower bound" (every event ever recorded).
// Exported (Phase 4 Task 4): the index screen's own Findings-overview period
// picker reuses this SAME four-bucket vocabulary rather than typing a second
// copy — see secFindingsPeriodPicker (index-screen.js). Its own totals stay
// unwindowed regardless of which bucket is showing (queries.severity_totals/
// top_categories deliberately took a `days` parameter and dropped it again,
// see this repository's own CHANGELOG entry on why), so the picker there is
// this vocabulary's labels only, not a second fetch.
export const ACT_PERIODS = [[7, "7 days"], [30, "30 days"], [90, "90 days"], [0, "All time"]];
const ACT_PER_PAGE = 25;

let secActOpen = false;
let secActGen = 0;
// One instance at a time -- there is exactly one #sec-activity in the page,
// the same simplification the Index and Project screens already make for
// their own module-level state. Unlike findings-screen.js's per-host
// WeakMap, nothing here ever needs two mounts of ITSELF; the one thing that
// does (the fingerprint dialog's own findings browser) already gets that
// from renderFindings()'s own per-host state -- see this file's header.
let secActState = null;
// The house PROJECT picker (makePicker), wired once by secActInitProjectPicker
// -- see that function's own comment for why once, not per screen-open.
let secActProjPicker = null;

function _freshState(project){
  return {project: project || "", tab: "", days: 30, page: 1, data: null, error: ""};
}

export function secIsActivityOpen(){ return secActOpen; }

/* The entry point both links above call. `secBack()` (analysis.js) does the
   full project-screen teardown (stops the poll, invalidates both caches,
   clears secState, shows #sec-projects) whether or not a project was even
   open -- reused here rather than half-duplicated, then immediately
   overridden to show #sec-activity instead of the index it just painted. */
export async function secOpenActivity(project){
  secBack();
  secActOpen = true;
  secActState = _freshState(project);
  $("sec-projects").hidden = true;
  $("sec-activity").hidden = false;
  secActRenderShell();
  await secActLoad();
}

export function secBackFromActivity(){
  secActOpen = false;
  $("sec-activity").hidden = true;
  $("sec-projects").hidden = false;
}

export async function secActReload(){
  if(!secActOpen) return;
  await secActLoad();
}

export function secActSwitchTab(key){
  if(!secActState) return;
  secActState.tab = ACT_TABS.some(t => t.key === key) ? key : "";
  secActState.page = 1;
  secActRenderTabs();
  secActLoad();
}

// Private now (F4 Activity polish): the free-text <input>'s own `change`
// listener (ui/security/index.js) used to call this directly. The house
// picker's `onPick` is the only caller left -- see secActInitProjectPicker.
function secActProjectChanged(value){
  if(!secActState) return;
  secActState.project = (value || "").trim();
  secActState.page = 1;
  if(secActProjPicker) secActProjPicker.paint();
  secActLoad();
}

function _scopeToProject(project){
  secActState.project = project;
  secActState.page = 1;
  // Repaints the picker's own trigger label ("Project: web") -- the old
  // free-text project input this function used to sync by setting its own
  // `.value` is gone; a custom widget has no browser-native "the underlying
  // value changed, repaint yourself" behaviour the way that input had.
  if(secActProjPicker) secActProjPicker.paint();
  secActLoad();
}

/* --------------------------------------------------------------- fetching */
function secActSince(){
  if(secActState.days <= 0) return 0;
  return Math.floor(Date.now() / 1000) - secActState.days * 86400;
}

function secActQuery(){
  const p = new URLSearchParams();
  const tab = ACT_TABS.find(t => t.key === secActState.tab) || ACT_TABS[0];
  tab.kinds.forEach(k => p.append("kind", k));
  if(secActState.project) p.set("project", secActState.project);
  p.set("since", String(secActSince()));
  p.set("page", String(secActState.page));
  p.set("per_page", String(ACT_PER_PAGE));
  return p.toString();
}

async function secActLoad(){
  if(!secActState || !secActOpen) return;
  const gen = ++secActGen;
  // No "Loading…" flash on a tab/period/project change -- only on the very
  // first fetch, the same no-flicker rule secFindLoad (findings-screen.js)
  // and secLoadIndex (index-screen.js) already follow.
  if(!secActState.data){
    const host = $("sec-act-table");
    if(host){ host.textContent = ""; host.appendChild(secEl("div", "tblempty", "Loading…")); }
  }
  let data;
  try{
    data = await secFetch("/api/security/activity?" + secActQuery());
  }catch(e){
    if(gen !== secActGen || !secActOpen) return;
    secActState.error = e.message;
    secActState.data = null;
    secActPaint();
    return;
  }
  if(gen !== secActGen || !secActOpen) return;
  secActState.error = "";
  secActState.data = data;
  secActState.page = data.page || 1;
  secActPaint();
}

/* ----------------------------------------------------------------- shell */
function secActRenderShell(){
  const titleText = secActState.project ? "Activity — " + secActState.project : "Activity";
  // The page header (Phase 4 Task 6) -- FullActivity.png's own icon, title
  // and grey sentence, replacing the loose `<p class="paneblurb">` that used
  // to sit here (bin/dashboard.html), the same conversion the index screen's
  // own secRenderHead already made in an earlier task. Built once per open,
  // the same cadence the small-caps eyebrow this used to sit beside had --
  // I2 (Phase 4 final review) removed that eyebrow (`#sec-act-title`) for
  // painting the SAME computed title text a second time right above this
  // one: the mockup draws exactly one heading here, and a reader had no way
  // to tell the two apart as anything but a duplicate. Back navigation
  // (`#sec-act-back`, wired in index.js's own init()) is untouched -- it
  // never lived in the eyebrow's own element, only beside it.
  const head = $("sec-act-head");
  if(head){
    head.textContent = "";
    head.appendChild(pageHeader({
      icon: "activity", title: titleText,
      subtitle: "What happened and when. An analysis links to that analysis; "
        + "a decision links into the findings browser filtered to the one "
        + "fingerprint it decided about.",
    }));
  }
  // The house PROJECT picker's own trigger ("Project: web") -- repainted
  // here so opening the screen already scoped (the index table's own kebab,
  // "View activity" for one project) shows the right value from the first
  // paint, not just "Project: All" until the reader touches the picker.
  if(secActProjPicker) secActProjPicker.paint();
  secActRenderTabs();
  secActRenderPeriod();
}

function secActRenderTabs(){
  ACT_TABS.forEach(t => {
    const btn = $(ACT_TAB_BUTTON_ID[t.key]);
    if(btn) btn.classList.toggle("active", secActState.tab === t.key);
  });
}

// "Last 30 days"/"All time" -- the exact wording secFindPeriodLabel
// (index-screen.js) already uses for the index's own Findings-overview
// period picker, duplicated here rather than imported: this file EXPORTS
// ACT_PERIODS for index-screen.js already (see that const's own comment
// above) -- importing anything back would be this file's first import FROM
// index-screen.js, a cycle neither module has needed yet, for one string
// formatter small enough that a second copy costs nothing to keep in step.
function secActPeriodLabel(days){
  return days > 0 ? "Last " + days + " days" : "All time";
}

/* The house control (F4 Activity polish): the SAME <details>/<summary>/
   .menu-pop popover the index screen's own Findings-overview card already
   draws for its period picker (secFindingsPeriodPicker, index-screen.js) --
   one period vocabulary (ACT_PERIODS), one widget, replacing the row of
   .secchip buttons this used to be. Built with secFindTriggerLabel/
   secFindPositionPop (findings-screen.js) rather than a third hand-rolled
   copy of either -- see their own comments for why those two, not
   secFindingsPeriodPicker's older pattern: THAT widget's own card is torn
   down and rebuilt whole every 5-second poll tick, which papers over a
   `closeMenus()` race (a stray click outside hides the popover without
   resetting the <details>'s own `open`); this screen never polls while it
   is open (secIsActivityOpen() is what stops it, see this file's header),
   so nothing would ever rebuild a stuck instance here.

   Rebuilt whole on every pick (the item's own onclick, below) rather than
   updated in place: secActPaint() never touches this host (#sec-act-period
   sits in the SHELL, painted once per open by secActRenderShell(), not by
   every fetch the way the index screen's own donut card is), so nothing
   else would ever repaint this trigger's own checkmark/label after a pick
   if this function did not rebuild itself -- the identical "rebuild, don't
   patch" the old chip row's own onclick already relied on. */
function secActPeriodPicker(){
  const {trigger} = secFindTriggerLabel(null, secActPeriodLabel(secActState.days));
  trigger.title = "Change the period this screen's table and sidebar cover.";
  const wrap = document.createElement("details");
  wrap.className = "secidx-periodpick";
  wrap.appendChild(trigger);

  const pop = secEl("div", "menu-pop");
  ACT_PERIODS.forEach(([days]) => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    item.appendChild(document.createTextNode(secActPeriodLabel(days)));
    if(days === secActState.days) item.appendChild(secIcon("check2"));
    item.onclick = (e) => {
      e.stopPropagation();
      secActState.days = days;
      secActState.page = 1;
      secActRenderPeriod();
      secActLoad();
    };
    pop.appendChild(item);
  });
  secFindPositionPop(wrap, trigger, pop);
  return wrap;
}

function secActRenderPeriod(){
  const host = $("sec-act-period");
  if(!host) return;
  host.textContent = "";
  host.appendChild(secActPeriodPicker());
}

/* Wired ONCE, from ui/security/index.js's own init() -- the identical split
   secInitLaunchCombos (analysis.js) already uses for sec-repo/sec-branch/
   sec-profile: `#sec-act-projpick` is STATIC markup (bin/dashboard.html)
   that lives for the page's whole life, so there is exactly one call to
   make, not one per screen-open the way the index screen's own three filter
   pickers (built fresh into throwaway markup, secProjectsFilterBar) need --
   a second makePicker() call on the same id would either find stale markup
   or grow that widget's own module-level PICKERS registry forever.

   The house picker in place of the free-text <input> this used to be --
   "Project: All" reads the same "Label: value" trigger the index screen's
   own Status/Profile/Branch pickers already use, and a reader picks a real
   name instead of typing one that may or may not exist. */
export function secActInitProjectPicker(){
  secActProjPicker = makePicker("sec-act-projpick", {
    icon: secIconHTML("folder"), label: "Project",
    valueLabel: () => secActState.project || "All",
    rows: () => {
      const data = secActState.data;
      const list = (data && data.projects) || [];
      const rows = [{v: "", label: "All", n: null,
        sel: !secActState.project, icon: secIconHTML("layers")}];
      const seen = new Set();
      list.forEach(p => {
        seen.add(p.project);
        rows.push({v: p.project, label: p.project, n: p.count,
          sel: secActState.project === p.project, icon: secIconHTML("folder")});
      });
      // The active scope can legitimately be missing from `list`: the
      // payload's own `projects` is grouped from events in the CURRENT
      // window AND scope (cmd_activity_data's own docstring), so a project
      // already scoped with zero events this period would otherwise vanish
      // from its own picker the moment it is selected.
      if(secActState.project && !seen.has(secActState.project)){
        rows.push({v: secActState.project, label: secActState.project, n: 0,
          sel: true, icon: secIconHTML("folder")});
      }
      return rows;
    },
    onPick: (v) => secActProjectChanged(v),
  });
}

/* ----------------------------------------------------------------- paint */
function secActPaint(){
  if(!secActOpen) return;
  // No separate `sec-act-pager` slot any more (Phase 4 Task 6): the footer
  // now renders INSIDE secActTable's own table-card -- see that function's
  // own comment.
  const host = $("sec-act-table"), side = $("sec-act-side");
  if(host) host.textContent = "";
  if(side) side.textContent = "";
  if(!host) return;
  if(secActState.error){
    const box = secEl("div", "tblempty");
    box.appendChild(secIcon("alert"));
    box.appendChild(document.createTextNode("Could not read activity — " + secActState.error));
    host.appendChild(box);
    return;
  }
  const data = secActState.data;
  if(!data) return;
  host.appendChild(secActTable(data));
  if(side) side.appendChild(secActSidebar(data));
}

/* ------------------------------------------------------------------ table
   Time, event, detail, project, and what it relates to -- exactly the
   columns the brief names. `detail`/`project` are `textContent`: an
   event's detail carries a human-written decision reason, the one string
   in this whole payload that must never be parsed as markup. */
function secActPeriodPhrase(){
  return secActState.days <= 0 ? "at any time" : "in the last " + secActState.days + " days";
}

function secActEmptyMessage(){
  const scope = secActState.project ? "for " + secActState.project + " " : "";
  // Names the range searched, so an empty screen reads as legibly empty
  // rather than possibly broken -- the same rule every empty state in this
  // area already follows (see index-screen.js's recent-analyses feed and
  // findings-screen.js's own floor/filter messages).
  return "No activity recorded " + scope + secActPeriodPhrase() + ".";
}

// [key, label] tuples, SEC_PROJECT_COLS-shaped (index-screen.js) even
// though nothing here sorts by one yet -- test_the_jobs_projects_and_runs_
// tables_declare_a_width_for_every_column (tests/test_page_contract.py)
// reads only `.length` off this, so a sixth column added here later is
// caught by the same guard with no change to the test itself. No `null`/
// "Actions" entry: Related is a real data column, not an actions column --
// the same shape the index screen's own Recent-analyses table (SEC_RECENT_
// COLS) already uses for its own Date column, and the width guard handles
// both shapes (see its own docstring).
const SEC_ACT_TABLE_COLS = [
  ["time", "Time"], ["event", "Event"], ["detail", "Detail"],
  ["project", "Project"], ["related", "Related"],
];

function secActTable(data){
  const events = data.events || [];
  if(!events.length) return secEl("div", "tblempty", secActEmptyMessage());

  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secact-table";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_ACT_TABLE_COLS.forEach(([, label]) => {
    const th = document.createElement("th");
    th.textContent = label;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  events.forEach(e => tbody.appendChild(secActRow(e)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  // The footer lives INSIDE this same table-card, never as a loose sibling
  // below it (see tableFooter's own comment in chrome.js on
  // test_the_jobs_table_footer_sits_inside_the_table_card for the regression
  // that shape used to be) -- folded in here rather than by the caller
  // (contrast findings-screen.js's secFindPaint) since this table has no
  // "nothing to show" branch that would leave it without a box to sit in
  // once the empty-events return above has already run.
  wrap.appendChild(secActPager(data));
  return wrap;
}

// "Aug 27, 7:23 AM" -- TIME's own absolute sub-line, the same reading
// secIndexRunWhen (index-screen.js) gives its own LAST RUN cell, duplicated
// here rather than imported: this file exports ACT_PERIODS/secActSwitchTab/
// secOpenActivity FOR index-screen.js already -- importing anything back
// would be this file's first import FROM it, a cycle neither module has
// needed yet, for a formatter small enough a second copy costs nothing to
// keep in step. The shared fmtWhen (page.js) spells out the full numeric
// date AND the seconds ("8/27/2026, 7:23:19 AM"), the right call for an
// exact-timestamp tooltip elsewhere but more than this column's own house
// two-line pattern wants beneath the relative reading above it.
function secActWhen(ts){
  if(!ts) return "";
  return new Date(ts * 1000).toLocaleString(undefined,
    {month: "short", day: "numeric", hour: "numeric", minute: "2-digit"});
}

// TIME: the house two-line pattern -- long-form relative on top ("2 hours
// ago", the same fmtAgo(_, true) reading this screen's own siblings use, not
// the terse "2h"), the exact moment beneath in the same muted sub-line class
// (.secidx-sub) the index screen's own Recent-analyses DATE column and LAST
// RUN cell already use. Replaces the bare fmtWhen() locale string
// ("8/27/2026, 7:23:23 AM") this cell used to print raw.
function secActTimeCell(at){
  const td = document.createElement("td");
  td.appendChild(document.createTextNode(fmtAgo(at, true)));
  td.appendChild(secEl("div", "secidx-sub", secActWhen(at)));
  return td;
}

function secActRow(e){
  const tr = document.createElement("tr");
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };
  tr.appendChild(secActTimeCell(e.at));
  tr.appendChild(cell(EVENT_KIND_LABEL[e.kind] || e.kind));
  tr.appendChild(cell(e.detail || ""));
  tr.appendChild(cell(e.project || ""));
  tr.appendChild(secActRelatedCell(e));
  return tr;
}

// Kinds whose `related` is an analysis id -- see ledger.record_event's own
// call sites (cmd_open_analysis, cmd_finish, and the report download route)
// for why these three, and only these three, carry one.
const ACT_ANALYSIS_KINDS = ["analysis_started", "analysis_finished", "report_exported"];

function secActRelatedCell(e){
  const td = document.createElement("td");
  const related = (e.related || "").trim();
  if(!related){ td.textContent = "—"; return td; }

  if(e.kind === "decision_made"){
    const b = secEl("button", "btn ghost", "Finding " + related + "…");
    b.type = "button";
    b.title = "Open the findings browser filtered to this fingerprint";
    b.onclick = () => secActOpenFinding(e.project, related);
    td.appendChild(b);
    return td;
  }
  if(ACT_ANALYSIS_KINDS.includes(e.kind)){
    const b = secEl("button", "btn ghost", "Analysis #" + related);
    b.type = "button";
    b.title = "Open this analysis";
    b.onclick = () => secActOpenAnalysis(e.project, related);
    td.appendChild(b);
    return td;
  }
  // An unrecognised kind's `related` (there is none today -- settings_changed
  // never carries one) is still shown, as plain text, rather than silently
  // dropped: a value that is not a link is still a fact about what happened.
  td.textContent = related;
  return td;
}

/* An analysis id navigates to the project screen's Runs tab and focuses
   that exact row -- the existing single-analysis view (analysis.js), fixed
   to a handful of DOM ids and not portable, so reused by NAVIGATING to it
   rather than mounted a second time (contrast with the fingerprint link
   below). Leaves the Activity screen entirely, the same way clicking a
   project on the Security index does. */
async function secActOpenAnalysis(project, relatedId){
  const id = Number(relatedId);
  if(!project || !Number.isFinite(id)) return;
  secBackFromActivity();
  await secOpenProject(project);
  secSwitchProjectTab("runs");
  // `pinned`: this link names ONE analysis, and it is routinely on a branch
  // the project screen's picker did not resolve to. Without it the poll
  // replaced it with that picker's newest analysis within four seconds, so a
  // deep link into a `develop` run landed on `main`'s latest instead.
  await secShowAnalysis(id, true);
}

/* A fingerprint prefix opens a SECOND, independent mount of
   renderFindings() in its own dialog -- "beside" whatever the project
   screen's own Findings tab may be showing, per findings-screen.js's own
   file comment anticipating exactly this caller. Filtered to the one
   fingerprint the decision was about; "Clear filters" inside it still
   escapes to the project's whole findings list without leaving the dialog. */
function secActOpenFinding(project, fingerprintPrefix){
  const titleEl = $("sec-act-finding-title");
  // The PROJECT, not the fingerprint. The dialog's title is set once, here,
  // and never hears about what happens inside it -- so a title naming the
  // fingerprint went on naming it after "Clear filters" had dropped that
  // filter, and read "Finding a3f9c2… in minerva" over that project's whole
  // list. The fingerprint scope belongs where it can disappear with the
  // filter it describes, and it already lives there: secFindStrip renders
  // "Filtered to fingerprint …" from `fs.filters` on every paint.
  if(titleEl) titleEl.textContent = "Findings in " + project;
  const halo = $("sec-act-finding-halo");
  if(halo){ halo.textContent = ""; halo.appendChild(secIcon("search")); }
  const dlg = $("sec-act-finding");
  if(dlg && dlg.showModal) dlg.showModal();
  renderFindings($("sec-act-finding-body"), project, {fingerprint: fingerprintPrefix});
}

export function wireActivityFindingDialog(){
  const dlg = $("sec-act-finding");
  const close = $("sec-act-finding-close");
  if(close && dlg) close.addEventListener("click", () => dlg.close());
}

/* ------------------------------------------------------------------ pager
   The same LOOK every other table-card footer in this app now uses
   (.table-foot/.table-foot-info/.table-foot-pager, chrome.js's own
   tableFooter) -- hand-built here rather than calling that bridged function
   directly, because its own "Showing X to Y of N" sentence needs a real
   total, and this endpoint deliberately has none: a plain COUNT(*) alongside
   a paginated events query would be a second query for a number this screen
   has no strict need of (see this file's own header comment on
   cmd_activity_data's docstring). "Page N" is what stays sayable without
   one. The MECHANISM is exactly what it was: "is there a next page" is still
   inferred from whether this page came back full, the same heuristic every
   "Next" button here can offer without a total -- on the rare exact
   multiple, one extra click lands on a legitimately empty next page rather
   than a wrong answer about one that still has rows. */
function secActPager(data){
  const foot = secEl("div", "table-foot");
  foot.appendChild(secEl("span", "table-foot-info", "Page " + (data.page || 1)));

  const page = data.page || 1;
  const perPage = data.per_page || ACT_PER_PAGE;
  const hasMore = (data.events || []).length >= perPage;

  const nav = secEl("div", "table-foot-pager");
  const prev = secEl("button", "btn ghost");
  prev.type = "button";
  prev.appendChild(secIcon("cleft"));
  prev.appendChild(document.createTextNode("Prev"));
  prev.disabled = page <= 1;
  prev.onclick = () => { secActState.page = Math.max(1, page - 1); secActLoad(); };
  nav.appendChild(prev);

  const next = secEl("button", "btn ghost");
  next.type = "button";
  next.appendChild(document.createTextNode("Next"));
  next.appendChild(secIcon("cright"));
  next.disabled = !hasMore;
  next.onclick = () => { secActState.page = page + 1; secActLoad(); };
  nav.appendChild(next);

  foot.appendChild(nav);
  return foot;
}

/* ---------------------------------------------------------------- sidebar
   The period's counts per kind (ALWAYS every kind, regardless of which tab
   is selected -- see this file's header comment), and the most active
   projects. No "top active users": with one operator that is a list of
   one, which is not an insight -- the brief's own reasoning for cutting the
   mockup's Users tab, carried down to the sidebar too. */
function secActSidebar(data){
  const wrap = document.createElement("div");
  wrap.appendChild(secActSummaryCard(data.summary || {}));
  wrap.appendChild(secActProjectsCard(data.projects || []));
  return wrap;
}

function secActSummaryCard(summary){
  // "card secact-sidecard", not bare "card": .card's own accent-tinted
  // border and 3px left rail (ui/css/pages.css) are a Jobs-board state cue
  // -- "the thing you act on" -- and painted this sidebar's two cards with a
  // purple outline no other card in Security wears. secact-sidecard resets
  // just the two border declarations back to the plain --line every other
  // card here uses, keeping .card's own padding/radius/shadow (already the
  // house look) untouched -- see that class's own comment, ui/css/pages.css.
  const box = secEl("div", "card secact-sidecard");
  const head = secEl("div", "secpj-cardhead");
  // M6b (Phase 4 final review): the mockup's own wording (FullActivity.png)
  // -- ui/css/pages.css's own `.secpj-cardhead h3` comment already cites
  // this exact phrase as what the artboard draws here; this card's own
  // title never actually caught up to it.
  head.appendChild(secEl("h3", null, "Activity summary"));
  box.appendChild(head);
  box.appendChild(secEl("div", "secpj-caption",
    "Every kind, regardless of which tab is selected above."));
  const chips = secEl("div", "secchips");
  EVENT_KINDS.forEach(kind => {
    const n = summary[kind] || 0;
    const chip = secEl("span", "secpj-statchip" + (n ? "" : " zero"));
    chip.appendChild(secEl("span", null, EVENT_KIND_LABEL[kind] || kind));
    chip.appendChild(secEl("span", "n", String(n)));
    chips.appendChild(chip);
  });
  box.appendChild(chips);
  return box;
}

function secActProjectsCard(projects){
  // See secActSummaryCard's own comment just above: the identical border fix.
  const box = secEl("div", "card secact-sidecard");
  // Wrapped in the SAME .secpj-cardhead the summary card above already uses
  // (Phase 4 Task 6), rather than a bare h3, so this title picks up the
  // identical card-title style (bold, sentence-case) the index screen's own
  // two bottom cards use -- see that class's own comment in ui/css/pages.css.
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Most active projects"));
  box.appendChild(head);
  if(secActState.project){
    // The one operator's reasoning, applied here too: a list already
    // filtered down to a single project is a list of one, which the
    // project field above already says plainly -- a redundant one-row
    // table teaches nothing a second time.
    box.appendChild(secEl("div", "tblempty", "Scoped to one project."));
    return box;
  }
  if(!projects.length){
    box.appendChild(secEl("div", "tblempty", secActEmptyMessage()));
    return box;
  }
  const list = secEl("div", "seclist");
  projects.forEach(p => {
    const row = secEl("button", "secrow secidx-recentrow");
    row.type = "button";
    row.title = "Filter this screen to " + p.project;
    row.onclick = () => _scopeToProject(p.project);
    row.appendChild(secIcon("activity"));
    const grow = secEl("div", "grow");
    grow.appendChild(secEl("div", "secname", p.project));
    grow.appendChild(secEl("div", "secmeta", p.count + " event" + (p.count === 1 ? "" : "s")));
    row.appendChild(grow);
    list.appendChild(row);
  });
  box.appendChild(list);
  return box;
}
