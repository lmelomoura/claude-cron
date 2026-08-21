/* -------------------------------------------------------- the project screen
   What "open a project" leads to: a header saying what this project analyses
   and how big it is, and the run history behind tabs (Overview, Runs)
   instead of one long column. One request, `GET /api/security/project`,
   answers with everything the header, both tabs and the sidebar draw -- see
   bin/security/cli.py's `project-data` and bin/claude-cron-server's
   `security_project`.

   This module owns the header, the tabs and the sidebar. It deliberately
   does NOT own the repo/branch/profile picker, the Analyse button, or the
   single-analysis detail below the Runs table (status, the incomplete/
   coverage notices, the severity pills, the checklist chips, the downloads,
   the findings list with its decision controls) -- that whole flow already
   works, is exercised by tests/test_page_contract.py, and stays exactly as
   it is in ui/security/analysis.js, ui/security/actions.js,
   ui/security/history.js and ui/security/reason.js. It is simply nested
   under the Runs tab now instead of sitting directly under the repo bar --
   clicking a row in the new analyses table below calls the same
   secShowAnalysis() the old "#7" buttons in "Earlier analyses of this
   branch" always did. Findings-with-decisions gets its own screen later
   (the findings browser); this task is the header and the tabs around it. */
import { $, fmtAgo, fmtDur, fmtWhen, openProjectEditor } from "./page.js";
import { secIcon, secEl, secFetch } from "./dom.js";
import { SEC_STATES, SEC_STATE_LABEL, SEC_STATE_HELP } from "./vocabulary.js";
import { secState } from "./state.js";
import { secIndexPosturePills, secIndexDonut } from "./index-screen.js";
import { secOpen, secShowAnalysis } from "./analysis.js";

// Every state `analysis.state` can hold (see bin/security/ledger.py's
// `start_analysis`/`ANALYSIS_END_STATES`) -- the Runs tab's own filter row,
// a different vocabulary from SEC_STATES above (that one is a FINDING's
// state; this one is an ANALYSIS's).
const RUN_STATES = ["running", "done", "capped", "failed"];

const EVENT_KIND_LABEL = {
  analysis_started: "Analysis started", analysis_finished: "Analysis finished",
  decision_made: "Decision made", settings_changed: "Settings changed",
  report_exported: "Report exported",
};

let secProjectCache = null;
let secProjectGen = 0;
let secProjectTab = "overview";
let secRunsFilter = "";

/* Called after anything that could have changed this project's numbers (a
   run just started or finished, a decision was just made) so the next load
   asks again rather than repainting a stale answer -- the same reasoning
   secInvalidateIndex already applies to the index screen's own cache. */
export function secInvalidateProject(){ secProjectCache = null; }

/* The entry point every "open this project" click now calls, instead of
   analysis.js's secOpen directly. secOpen still does everything it always
   did -- shows #sec-detail, resolves the repo/branch/profile pickers, loads
   the default analysis for drilling into below the Runs table -- this only
   adds the header/tabs/sidebar fetch on top of it. */
export async function secOpenProject(name){
  secProjectTab = "overview";
  secRunsFilter = "";
  secOpen(name);
  await secLoadProject(name, true);
}

/* Re-read this project's data after anything that might have changed it.
   Called from analysis.js's secReload() -- the same poll tick and the same
   post-Analyse reload that already refresh the old detail pane -- so one
   timer drives both, rather than a second interval hitting the server on
   its own. A no-op once the view has moved on, the same guard secLoadIndex
   already uses for the identical race. */
export async function secRefreshProject(){
  if(!secState.project) return;
  await secLoadProject(secState.project, true);
}

async function secLoadProject(name, force){
  if(secProjectCache && secProjectCache.project === name && !force){
    secRenderProject();
    return;
  }
  secProjectGen++;
  const gen = secProjectGen;
  let data;
  try{
    data = await secFetch("/api/security/project?project=" + encodeURIComponent(name));
  }catch(e){
    if(gen !== secProjectGen || secState.project !== name) return;
    secProjectCache = null;
    secRenderProjectError(e.message);
    return;
  }
  if(gen !== secProjectGen || secState.project !== name) return;   // a newer request already answered, or the view moved on
  secProjectCache = data;
  secRenderProject();
}

function secRenderProjectError(msg){
  const host = $("sec-pj-head");
  if(!host) return;
  host.textContent = "";
  host.appendChild(secIcon("alert"));
  host.appendChild(secEl("span", "grow", "Could not read this project — " + msg));
}

export function secSwitchProjectTab(tab){
  secProjectTab = (tab === "runs") ? "runs" : "overview";
  secRenderTabs();
}

function secRenderProject(){
  if(!secProjectCache) return;
  secRenderProjectHeader(secProjectCache);
  secRenderTabs();
  secRenderProjectOverview(secProjectCache);
  secRenderProjectRuns(secProjectCache);
  secRenderProjectSidebar(secProjectCache);
}

function secRenderTabs(){
  const ov = $("secpjt-overview"), rn = $("secpjt-runs");
  if(ov) ov.classList.toggle("active", secProjectTab === "overview");
  if(rn) rn.classList.toggle("active", secProjectTab === "runs");
  const ovPane = $("sec-pj-overview"), rnPane = $("sec-pj-runs");
  if(ovPane) ovPane.hidden = secProjectTab !== "overview";
  if(rnPane) rnPane.hidden = secProjectTab !== "runs";
}

/* --------------------------------------------------------------- header */
function secRenderProjectHeader(payload){
  const host = $("sec-pj-head");
  if(!host) return;
  host.textContent = "";
  const h = payload.header || {};

  const meta = secEl("div", "secpjmeta grow");
  meta.appendChild(secHeaderBit("Profile", h.profile || "standard"));
  const branch = secHeaderBit("Branch", h.branch || "—");
  if(h.branch_fell_back){
    // Postures of different branches must never be confused in silence --
    // the SAME cue the index screen's own project table gives a branch it
    // fell back to (see secIndexProjectRow's tdBranch).
    branch.appendChild(secEl("span", "secidx-fellback",
      " (fell back — the declared base was never analysed)"));
  }
  meta.appendChild(branch);
  // 0 is "not counted" -- every analysis before the lines_of_code column
  // existed, or a project never analysed at all -- and a dash keeps that
  // from reading as an empty repository.
  meta.appendChild(secHeaderBit("Lines of code",
    h.lines_of_code ? h.lines_of_code.toLocaleString() : "—"));
  meta.appendChild(secHeaderBit("Last analysis",
    h.last_analysis ? fmtAgo(h.last_analysis) : "Never analysed"));
  host.appendChild(meta);

  const settings = secEl("button", "btn ghost");
  settings.type = "button";
  settings.title = "Open this project's editor";
  settings.onclick = () => openProjectEditor(secState.project);
  settings.appendChild(secIcon("gear"));
  settings.appendChild(document.createTextNode("Project settings"));
  host.appendChild(settings);
}

function secHeaderBit(label, value){
  const span = secEl("span", null, label + ": ");
  span.appendChild(secEl("b", null, value));
  return span;
}

/* -------------------------------------------------------------- overview */
function secRenderProjectOverview(payload){
  const host = $("sec-pj-overview");
  if(!host) return;
  host.textContent = "";
  const ov = (payload.tabs || {}).overview || {};

  if(!ov.state){
    host.appendChild(secEl("div", "empty",
      "Never analysed. Switch to Runs to pick a branch and start."));
    return;
  }
  if(ov.state === "capped"){
    // THE SAME NOTICE the index screen and the old analysis screen already
    // give: a capped analysis is a PARTIAL read of the repository, so the
    // posture below is what it had reached, not what is there.
    const warn = secEl("div", "warnline bad");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", "grow",
      "This analysis is INCOMPLETE: it stopped before covering the whole "
      + "scope. The posture below is what it had reached, not what is there."));
    host.appendChild(warn);
  }
  host.appendChild(secIndexPosturePills(ov.posture || {}));

  const chips = secEl("div", "secchips");
  const checklist = ov.checklist || {};
  SEC_STATES.forEach(state => {
    const n = checklist[state] || 0;
    const chip = secEl("span", "secpj-statchip" + (n ? "" : " zero"));
    chip.title = SEC_STATE_HELP[state] || "";
    chip.appendChild(secEl("span", null, SEC_STATE_LABEL[state] || state));
    chip.appendChild(secEl("span", "n", String(n)));
    chips.appendChild(chip);
  });
  host.appendChild(chips);
}

/* ------------------------------------------------------------------ runs */
function secRenderProjectRuns(payload){
  const host = $("sec-pj-runstable");
  if(!host) return;
  host.textContent = "";
  const runs = (payload.tabs || {}).runs || [];
  host.appendChild(secRunsFilters(runs));
  host.appendChild(secRunsTable(runs));
}

function secRunsFilters(runs){
  const wrap = secEl("div", "secchips");
  const counts = {};
  runs.forEach(r => { counts[r.state] = (counts[r.state] || 0) + 1; });

  const all = secEl("button", "secchip" + (secRunsFilter ? "" : " on"));
  all.type = "button";
  all.appendChild(secEl("span", null, "All"));
  all.appendChild(secEl("span", "n", String(runs.length)));
  all.onclick = () => { secRunsFilter = ""; secRenderProjectRuns(secProjectCache); };
  wrap.appendChild(all);

  RUN_STATES.forEach(state => {
    const n = counts[state] || 0;
    const chip = secEl("button", "secchip" + (n ? "" : " zero")
      + (secRunsFilter === state ? " on" : ""));
    chip.type = "button";
    chip.appendChild(secEl("span", null, state));
    chip.appendChild(secEl("span", "n", String(n)));
    chip.onclick = () => { secRunsFilter = state; secRenderProjectRuns(secProjectCache); };
    wrap.appendChild(chip);
  });
  return wrap;
}

function secRunsTable(runs){
  const filtered = secRunsFilter ? runs.filter(r => r.state === secRunsFilter) : runs;
  if(!filtered.length){
    return secEl("div", "tblempty", runs.length
      ? "Nothing in that state." : "No analyses of this project yet.");
  }
  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Run", "Profile", "Branch", "Commit", "Duration", "Findings", "State", "Date"].forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  filtered.forEach(r => tbody.appendChild(secRunRow(r)));
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function secRunRow(r){
  const tr = document.createElement("tr");
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };

  const tdId = document.createElement("td");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn ghost";
  btn.textContent = "#" + r.id;
  btn.title = "Show this analysis below";
  // The existing single-analysis drill-down, unchanged: the same function
  // "Earlier analyses of this branch" already calls for its own "#N" rows.
  btn.onclick = () => secShowAnalysis(r.id);
  tdId.appendChild(btn);
  tr.appendChild(tdId);

  tr.appendChild(cell(r.profile || ""));
  tr.appendChild(cell((r.repo || "") + " @ " + (r.branch || "")));
  tr.appendChild(cell(String(r.commit_sha || "").slice(0, 12)));
  tr.appendChild(cell(r.started && r.ended ? fmtDur(Math.max(0, r.ended - r.started))
                                            : (r.state === "running" ? "running…" : "—")));
  tr.appendChild(cell(r.open == null ? "—" : String(r.open)));
  tr.appendChild(cell(r.state));
  tr.appendChild(cell(fmtWhen(r.started)));
  return tr;
}

/* --------------------------------------------------------------- sidebar */
function secRenderProjectSidebar(payload){
  const host = $("sec-pj-side");
  if(!host) return;
  host.textContent = "";
  const sb = payload.sidebar || {};
  host.appendChild(secIndexDonut(sb.donut || {}, sb.categories || []));
  host.appendChild(secProjectActivity(sb.activity || []));
}

function secProjectActivity(events){
  const box = secEl("div", "card");
  box.appendChild(secEl("h3", null, "Recent activity"));
  if(!events.length){
    box.appendChild(secEl("div", "tblempty", "No activity recorded yet."));
    return box;
  }
  const list = secEl("div", "seclist");
  events.forEach(e => {
    const row = secEl("div", "secrow");
    row.appendChild(secIcon("activity"));
    const grow = secEl("div", "grow");
    grow.appendChild(secEl("div", "secname", EVENT_KIND_LABEL[e.kind] || e.kind));
    grow.appendChild(secEl("div", "secmeta",
      [e.detail, fmtAgo(e.at)].filter(Boolean).join(" · ")));
    row.appendChild(grow);
    list.appendChild(row);
  });
  box.appendChild(list);
  // No link to the Activity screen yet — it does not exist until a later
  // task, and a link to nowhere is worse than no link at all. This feed
  // becomes that screen's entry point once it lands.
  return box;
}
