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

   Time and detail cells are `textContent`, always: an event's `detail`
   carries human-written text (a decision's own reason), the same rule
   vocabulary.js's opening comment states for this whole area.

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
import { $, fmtWhen } from "./page.js";
import { secEl, secIcon, secFetch } from "./dom.js";
import { EVENT_KINDS, EVENT_KIND_LABEL } from "./vocabulary.js";
import { secBack, secShowAnalysis } from "./analysis.js";
import { secOpenProject, secSwitchProjectTab } from "./project-screen.js";
import { renderFindings } from "./findings-screen.js";

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

export function secActProjectChanged(value){
  if(!secActState) return;
  secActState.project = (value || "").trim();
  secActState.page = 1;
  secActLoad();
}

function _scopeToProject(project){
  secActState.project = project;
  secActState.page = 1;
  const input = $("sec-act-project");
  if(input) input.value = project;
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
  const title = $("sec-act-title");
  if(title){
    title.textContent = "";
    title.appendChild(secIcon("activity"));
    title.appendChild(document.createTextNode(
      secActState.project ? "Activity — " + secActState.project : "Activity"));
  }
  const input = $("sec-act-project");
  if(input) input.value = secActState.project;
  secActRenderTabs();
  secActRenderPeriod();
}

function secActRenderTabs(){
  ACT_TABS.forEach(t => {
    const btn = $(ACT_TAB_BUTTON_ID[t.key]);
    if(btn) btn.classList.toggle("active", secActState.tab === t.key);
  });
}

function secActPeriodChips(){
  const wrap = secEl("div", "secchips");
  ACT_PERIODS.forEach(([days, label]) => {
    const chip = secEl("button", "secchip" + (secActState.days === days ? " on" : ""));
    chip.type = "button";
    chip.appendChild(secEl("span", null, label));
    chip.onclick = () => {
      secActState.days = days;
      secActState.page = 1;
      secActRenderPeriod();
      secActLoad();
    };
    wrap.appendChild(chip);
  });
  return wrap;
}

function secActRenderPeriod(){
  const host = $("sec-act-period");
  if(!host) return;
  host.textContent = "";
  host.appendChild(secActPeriodChips());
}

/* ----------------------------------------------------------------- paint */
function secActPaint(){
  if(!secActOpen) return;
  const host = $("sec-act-table"), pager = $("sec-act-pager"), side = $("sec-act-side");
  if(host) host.textContent = "";
  if(pager) pager.textContent = "";
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
  if(pager) pager.appendChild(secActPager(data));
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

function secActTable(data){
  const events = data.events || [];
  if(!events.length) return secEl("div", "tblempty", secActEmptyMessage());

  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Time", "Event", "Detail", "Project", "Related"].forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  events.forEach(e => tbody.appendChild(secActRow(e)));
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function secActRow(e){
  const tr = document.createElement("tr");
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };
  tr.appendChild(cell(fmtWhen(e.at)));
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
   No `total` in the payload (see cmd_activity_data's own docstring: a plain
   COUNT(*) alongside a paginated events query would be a second query for a
   number this screen has no strict need of) -- so "is there a next page" is
   inferred from whether this page came back full, the same heuristic every
   "Next" button here can offer without it: on the rare exact multiple, one
   extra click lands on a legitimately empty next page rather than a wrong
   answer about one that still has rows. */
function secActPager(data){
  const wrap = secEl("div", "pager");
  const page = data.page || 1;
  const perPage = data.per_page || ACT_PER_PAGE;
  const hasMore = (data.events || []).length >= perPage;

  const prev = secEl("button", "btn ghost", "Prev");
  prev.type = "button";
  prev.disabled = page <= 1;
  prev.onclick = () => { secActState.page = Math.max(1, page - 1); secActLoad(); };
  wrap.appendChild(prev);

  wrap.appendChild(secEl("span", null, "Page " + page));

  const next = secEl("button", "btn ghost", "Next");
  next.type = "button";
  next.disabled = !hasMore;
  next.onclick = () => { secActState.page = page + 1; secActLoad(); };
  wrap.appendChild(next);

  return wrap;
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
  const box = secEl("div", "card");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "This period"));
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
  const box = secEl("div", "card");
  box.appendChild(secEl("h3", null, "Most active projects"));
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
