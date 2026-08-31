/* --------------------------------------------------------- the Branches tab
   ProjectBranches.png, element by element: five KPI cards, a filter bar
   (search + Status + Last-analysis pickers + Refresh), the branches table
   (Branch with the Default badge, Status, Last analysis, Total findings,
   the five-chip Severity breakdown, a 30-day bar sparkline, Last commit,
   View + kebab) with a numbered footer, and -- through secBranchesSidebar,
   mounted by project-screen.js's own rail -- the tab's own three rail
   cards: the all-branch severity donut, Top issue categories, and Branch
   coverage.

   One row per branch that has EVER been analysed -- any state, now
   including a branch whose every attempt failed (a dash and "Analysis
   failed", per the mockup, instead of the absence this tab used to show).
   Fed by `tabs.branches` (bin/security/cli.py's `project-data`), which is
   exactly `queries.branch_rows`'s own rows.

   The one scope fact this tab still says, now where the numbers are
   instead of a paragraph above them: a branch's own `open` counts once PER
   BRANCH, while the rail donut and the Total-findings KPI count a
   fingerprint once for the whole project -- so the rows can legitimately
   add up to more than either. The KPI, the column header and the rail
   card's own "(all branches)" each carry their half of it. */
import { $, fmtAgo, fmtWhen, kpiCard, projById, tableFooter } from "./page.js";
import { secEl, secIcon } from "./dom.js";
import { SEC_NEVER, SEC_FLOOR_SCOPE_NOTE } from "./vocabulary.js";
import { secIndexDonutSvg, secIndexDonutLegend, secIndexCategories,
         secCappedScopeNote } from "./index-screen.js";
import { secFindTriggerLabel, secFindPositionPop, renderFindings } from "./findings-screen.js";
import { secShowAnalysis, secGitBranchCount } from "./analysis.js";
import { secDownloadReport } from "./actions.js";
import { secSwitchProjectTab, secRefreshProject } from "./project-screen.js";
import { closeMenus } from "./page.js";
import { secState } from "./state.js";

/* The cue for a PARTIAL read, in the same class and the same words the
   index screen's own project row uses (secIndexProjectRow's `secidx-capped`
   badge) and the Overview panel's banner repeats: a `capped` analysis
   stopped before covering the whole scope, so "critical: 0" beside it
   means "none found before it stopped," not "none." */
const BRANCH_CAPPED_TITLE = "This analysis is INCOMPLETE: it stopped before "
  + "covering the whole scope. The posture beside this badge is what it had "
  + "reached, not what is there.";

const BRANCH_SCOPE_TITLE = "Counted once per branch — the same finding open "
  + "on several branches counts once in each row here, while the rail's "
  + "donut and the Total-findings card count it once for the whole project, "
  + "so these rows can add up to more than either.";

// A branch is ACTIVE while its latest FINISHED analysis is at most this old
// -- keyed to last_finished, never last_analysis, so a branch whose recent
// attempts all fail cannot count as fresher the more it fails. One constant,
// read by the Status column, the Active-branches KPI and the Status filter
// alike, so the three can never disagree about the same branch.
const SEC_BRANCH_ACTIVE_DAYS = 7;

// [key, label] tuples, SEC_PROJECT_COLS-shaped --
// test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column
// covers this table like every other (`.secbr-table` widths, pages.css).
const SEC_BRANCH_COLS = [
  ["branch", "Branch"], ["status", "Status"], ["last", "Last analysis"],
  ["total", "Total findings"], ["sev", "Severity breakdown"],
  ["trend", "Trend (30d)"], ["commit", "Last commit"], ["actions", "Actions"],
];

// Unique name on purpose (not the SEV5 overview-tab.js also declares): the
// two modules land in ONE bundle, esbuild renames the second declaration,
// and the test harness extracts functions from the bundle by their source
// names -- a renamed reference inside an extracted body dangles.
const SEC_BR_SEVS = ["critical", "high", "medium", "low", "info"];

// The filter bar's own selections -- surface-local, surviving poll repaints,
// reset when a different project is opened (the same lifecycle
// secRunsFilter/secOvSort already follow on their own tabs).
let secBrSearch = "";
let secBrStatus = "";          // "" = all, "active", "inactive"
let secBrDays = 0;             // 0 = all time; else last-analysis window in days
let secBrProject = null;
let secBrPayload = null;

const SEC_BR_WINDOWS = [[0, "All time"], [7, "Last 7 days"],
                        [30, "Last 30 days"], [90, "Last 90 days"]];

function secBranchIsActive(r, now){
  return !!r.last_finished
    && (now - r.last_finished) <= SEC_BRANCH_ACTIVE_DAYS * 86400;
}

/* The project's DECLARED base -- projects.json's own `base`, read from the
   client-side project object like the title row does, NOT payload.header
   .branch: that one is default_branch_posture's resolved pick and may be a
   branch it fell back to, and the Default badge must never migrate onto a
   fallback. */
function secBrDefaultBranch(){
  return (projById(secState.project) || {}).base || "";
}

export function secRenderProjectBranches(payload){
  const host = $("sec-pj-branches");
  if(!host) return;
  secBrPayload = payload;
  if(secBrProject !== payload.project){
    secBrProject = payload.project;
    secBrSearch = ""; secBrStatus = ""; secBrDays = 0;
  }
  host.textContent = "";
  const tabs = (payload || {}).tabs || {};
  const rows = tabs.branches || [];
  if(!rows.length){
    // The same never-vs-attempted distinction secRenderProjectOverview
    // draws from the identical flag in the SAME payload -- a project whose
    // every analysis failed must not read exactly like one never touched.
    // With failed-only branches now getting rows of their own, this empty
    // state is genuinely "nothing was ever attempted" in practice.
    const attempted = !!(tabs.overview || {}).attempted;
    host.appendChild(secEl("div", "empty",
      attempted ? SEC_NEVER.attempted : SEC_NEVER.next));
    return;
  }
  host.appendChild(secBrKpis(rows, payload));
  host.appendChild(secBrFilterBar(rows));
  host.appendChild(secBrTable(rows));
}

/* -------------------------------------------------------------- KPI cards */
function secBrKpis(rows, payload){
  const wrap = secEl("div", "kpi-grid");
  const now = Math.floor(Date.now() / 1000);
  const analyzed30 = rows.filter(r =>
    r.last_finished && (now - r.last_finished) <= 30 * 86400).length;
  wrap.appendChild(kpiCard({icon: "gitbranch", value: String(analyzed30),
    label: "Branches analyzed", sub: "in the last 30 days"}));

  const active = rows.filter(r => secBranchIsActive(r, now)).length;
  wrap.appendChild(kpiCard({icon: "activity", tone: "ok", value: String(active),
    label: "Active branches", sub: "with recent analyses",
    title: "A branch is active while its latest finished analysis is at "
      + "most " + SEC_BRANCH_ACTIVE_DAYS + " days old — the same rule the "
      + "Status column and filter read."}));

  // The DECLARED base's own posture, straight off its row -- a dash when it
  // was never successfully read, which is not the same claim as zero.
  const base = secBrDefaultBranch();
  const baseRow = rows.find(r => r.branch === base);
  const crit = baseRow && baseRow.open ? String(baseRow.open.critical || 0) : "—";
  wrap.appendChild(kpiCard({icon: "shield", tone: "sev-crit", value: crit,
    label: "Critical findings", sub: "in default branch",
    title: crit === "—"
      ? "The declared base (" + (base || "none declared") + ") has no "
        + "finished analysis to read a posture from."
      : "Open critical findings in " + base + "'s latest finished analysis."}));

  const donut = (payload.sidebar || {}).donut || {};
  wrap.appendChild(kpiCard({icon: "alertcircle", value: String(donut.total || 0),
    label: "Total findings", sub: "across all branches",
    title: "Distinct problems (fingerprints) — the same finding open on "
      + "two branches counts once here, while each branch's own row counts "
      + "it again for itself."}));

  // "Covered" reads the base's latest finished analysis state: a clean
  // `done` read the whole scope (100%), a `capped` one stopped early
  // (Partial), and no finished analysis at all is a dash -- there is no
  // finer-grained coverage number recorded than that, so none is invented.
  const covered = !baseRow || !baseRow.state ? "—"
    : baseRow.state === "done" ? "100%" : "Partial";
  wrap.appendChild(kpiCard({icon: "covers", value: covered,
    label: "Default branch covered",
    sub: baseRow && baseRow.last_finished
      ? "last analysis " + fmtAgo(baseRow.last_finished) : SEC_NEVER.short,
    title: "100% means the default branch's latest finished analysis "
      + "completed clean; Partial means it stopped before covering the "
      + "whole scope (capped)."}));
  return wrap;
}

/* -------------------------------------------------------------- filter bar */
function secBrRepaint(){
  if(secBrPayload) secRenderProjectBranches(secBrPayload);
}

/* The house <details>/<summary>/.menu-pop picker, the exact widget the
   Activity screen's period control and the findings browser's own pickers
   already are (secFindTriggerLabel/secFindPositionPop, findings-screen.js)
   -- rebuilt whole on every pick like secActPeriodPicker, since this tab
   re-renders itself on every change anyway. */
function secBrPicker(labelText, valueText, options, isCurrent, onPick){
  const {trigger} = secFindTriggerLabel(labelText, valueText);
  const wrap = document.createElement("details");
  wrap.className = "secidx-periodpick";
  wrap.appendChild(trigger);
  const pop = secEl("div", "menu-pop");
  options.forEach(([value, label]) => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    item.appendChild(document.createTextNode(label));
    if(isCurrent(value)) item.appendChild(secIcon("check2"));
    item.onclick = (e) => { e.stopPropagation(); onPick(value); };
    pop.appendChild(item);
  });
  secFindPositionPop(wrap, trigger, pop);
  return wrap;
}

function secBrFilterBar(rows){
  const bar = secEl("div", "toolbar secbr-bar");
  const box = secEl("div", "searchbox");
  const input = document.createElement("input");
  input.type = "search";
  input.placeholder = "Search branches…";
  input.autocomplete = "off";
  input.value = secBrSearch;
  input.oninput = () => {
    // Repainting the TABLE alone (not this bar) keeps the caret alive in
    // this very input while the rows underneath follow each keystroke.
    secBrSearch = input.value;
    const host = $("sec-pj-branches");
    const old = host && host.querySelector ? host.querySelector(".secbr-tablehost") : null;
    if(old && secBrPayload){
      const fresh = secBrTable(((secBrPayload.tabs || {}).branches) || []);
      old.replaceWith(fresh);
    }
  };
  box.appendChild(input);
  bar.appendChild(box);

  bar.appendChild(secBrPicker("Status",
    secBrStatus === "" ? "All" : secBrStatus === "active" ? "Active" : "Inactive",
    [["", "All"], ["active", "Active"], ["inactive", "Inactive"]],
    v => v === secBrStatus,
    v => { secBrStatus = v; secBrRepaint(); }));

  bar.appendChild(secBrPicker("Last analysis",
    (SEC_BR_WINDOWS.find(([d]) => d === secBrDays) || [0, "All time"])[1],
    SEC_BR_WINDOWS,
    v => v === secBrDays,
    v => { secBrDays = v; secBrRepaint(); }));

  bar.appendChild(secEl("span", "spacer"));

  // Refresh re-asks the server for the whole project payload -- the same
  // door the poll uses (secRefreshProject forces a fresh fetch and
  // re-renders every tab off the answer) -- rather than repainting stale
  // rows.
  const refresh = secEl("button", "btn ghost", "Refresh");
  refresh.type = "button";
  refresh.title = "Re-read this project's data";
  refresh.onclick = () => secRefreshProject();
  bar.appendChild(refresh);
  return bar;
}

/* ------------------------------------------------------------------ table */
function secBrFiltered(rows){
  const now = Math.floor(Date.now() / 1000);
  const needle = secBrSearch.trim().toLowerCase();
  return rows.filter(r => {
    if(needle && !(r.branch || "").toLowerCase().includes(needle)) return false;
    if(secBrStatus === "active" && !secBranchIsActive(r, now)) return false;
    if(secBrStatus === "inactive" && secBranchIsActive(r, now)) return false;
    if(secBrDays && (!r.last_analysis
        || (now - r.last_analysis) > secBrDays * 86400)) return false;
    return true;
  });
}

function secBrTable(rows){
  const filtered = secBrFiltered(rows);
  const hostWrap = secEl("div", "secbr-tablehost");
  if(!filtered.length){
    hostWrap.appendChild(secEl("div", "tblempty",
      "No branch matches these filters."));
    return hostWrap;
  }
  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secbr-table";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_BRANCH_COLS.forEach(([key, label]) => {
    const th = document.createElement("th");
    th.textContent = label;
    if(key === "total") th.title = BRANCH_SCOPE_TITLE;
    if(key === "commit"){
      th.title = "The commit the branch's newest analysis read — recorded "
        + "when the analysis started, not read from git now.";
    }
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  filtered.forEach(r => tbody.appendChild(secBranchRow(r)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  // Everything this payload holds, one real page, said honestly -- the
  // identical shape the Runs tab's own table already uses.
  wrap.appendChild(tableFooter({
    shown: {from: 1, to: filtered.length}, total: filtered.length,
    noun: "branch", page: 1, pages: 1, numbered: true,
  }));
  hostWrap.appendChild(wrap);
  return hostWrap;
}

function secBranchRow(r){
  const tr = document.createElement("tr");
  const now = Math.floor(Date.now() / 1000);

  const tdName = document.createElement("td");
  const name = secEl("div", "secbr-name");
  name.appendChild(secIcon("gitbranch"));
  name.appendChild(secEl("span", "secbr-branch", r.branch || ""));
  if(r.branch && r.branch === secBrDefaultBranch()){
    const badge = secEl("span", "pill profile", "Default");
    badge.title = "This project's declared base branch";
    name.appendChild(badge);
  }
  tdName.appendChild(name);
  tr.appendChild(tdName);

  const active = secBranchIsActive(r, now);
  const tdStatus = document.createElement("td");
  const status = secEl("span", "secbr-status " + (active ? "active" : "inactive"));
  status.appendChild(secEl("span", "secbr-statusdot"));
  status.appendChild(document.createTextNode(active ? "Active" : "Inactive"));
  status.title = "Active while the latest finished analysis is at most "
    + SEC_BRANCH_ACTIVE_DAYS + " days old.";
  tdStatus.appendChild(status);
  tr.appendChild(tdStatus);

  const tdLast = document.createElement("td");
  if(r.last_analysis){
    tdLast.appendChild(secEl("div", "secbr-ago", fmtAgo(r.last_analysis)));
    tdLast.appendChild(secEl("div", "secmeta", fmtWhen(r.last_analysis)));
  }else{
    tdLast.textContent = "—";
  }
  tr.appendChild(tdLast);

  // `open` is None for a branch never successfully read -- a dash plus WHY
  // (the newest attempt's own state), the mockup's own "— / Analysis
  // failed" row. A finished posture with a NEWER failed attempt keeps its
  // numbers and says the failure happened, instead of hiding it behind the
  // older success.
  const tdTotal = document.createElement("td");
  tdTotal.appendChild(secEl("div", "secbr-total",
    r.open ? String(r.open.total || 0) : "—"));
  if(r.latest_state === "failed"){
    tdTotal.appendChild(secEl("div", "secmeta secbr-failed",
      r.open ? "Latest attempt failed" : "Analysis failed"));
  }else if(r.latest_state === "running"){
    tdTotal.appendChild(secEl("div", "secmeta", "Analysis running…"));
  }
  if(r.state === "capped"){
    const badge = secEl("span", "secidx-capped", "incomplete");
    badge.title = BRANCH_CAPPED_TITLE;
    tdTotal.appendChild(badge);
  }
  tr.appendChild(tdTotal);

  const tdSev = document.createElement("td");
  tdSev.appendChild(secBrSevChips(r.open));
  tr.appendChild(tdSev);

  // The 30-day bars, with secBranchTrendText -- the sentence that refuses a
  // direction the whole series does not support -- as the cell's title, so
  // the honest reading survives the move from text to pixels.
  const tdTrend = document.createElement("td");
  tdTrend.appendChild(secBrTrendBars(r.trend));
  tdTrend.title = secBranchTrendText(r.trend);
  tr.appendChild(tdTrend);

  const tdCommit = document.createElement("td");
  if(r.sha){
    tdCommit.appendChild(secEl("div", "secbr-sha", r.sha.slice(0, 7)));
    tdCommit.appendChild(secEl("div", "secmeta", fmtWhen(r.last_analysis)));
  }else{
    tdCommit.textContent = "—";
  }
  tr.appendChild(tdCommit);

  const tdActs = document.createElement("td");
  tdActs.className = "rowacts";
  const view = document.createElement("button");
  view.type = "button";
  view.className = "btn ghost";
  view.textContent = "View";
  view.disabled = r.analysis_id == null;
  view.title = r.analysis_id == null
    ? "No finished analysis of this branch to open yet"
    : "Open this branch's latest finished analysis on the Runs tab";
  if(r.analysis_id != null){
    view.onclick = () => {
      secSwitchProjectTab("runs");
      secShowAnalysis(r.analysis_id, true);
    };
  }
  tdActs.appendChild(view);
  tdActs.appendChild(secBrKebab(r));
  tr.appendChild(tdActs);
  return tr;
}

function secBrSevChips(open){
  const wrap = secEl("div", "secbr-sev");
  SEC_BR_SEVS.forEach(sev => {
    const chip = secEl("div", "secbr-sevchip");
    if(!open){
      chip.appendChild(secEl("span", "secbr-sevcount none", "—"));
    }else{
      const n = open[sev] || 0;
      chip.appendChild(secEl("span",
        "secbr-sevcount sev-" + sev + (n ? "" : " zero"), String(n)));
    }
    chip.appendChild(secEl("span", "secbr-sevname",
      sev.charAt(0).toUpperCase() + sev.slice(1)));
    wrap.appendChild(chip);
  });
  return wrap;
}

/* One bar per analysis in the 30-day window, oldest first, height
   proportional to that point's own open count -- a capped point draws
   hollow, the same incomplete cue the Overview's trend dots and the
   `incomplete` badge already wear. Fixed-size viewBox scaled by CSS to a
   small cell; at this size the bars are a shape, and the numbers live in
   the cell's own title (secBranchTrendText). */
function secBrTrendBars(trend){
  // The newest analyses that FIT -- at the 2px-minimum bar width the cell
  // seats 24; a busier month keeps its newest 24 bars rather than clipping
  // the left edge, and the title's own sentence still covers every point.
  const pts = (trend || []).slice(-24);
  if(!pts.length) return secEl("span", "secbr-notrend", "—");
  const ns = "http://www.w3.org/2000/svg";
  const W = 96, H = 28, gap = 2;
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);
  svg.setAttribute("class", "secbr-bars");
  svg.setAttribute("role", "img");
  const max = Math.max(1, ...pts.map(p => p.open || 0));
  const bw = Math.max(2, Math.min(8, (W - gap * (pts.length - 1)) / pts.length));
  const span = pts.length * bw + (pts.length - 1) * gap;
  const x0 = W - span;   // right-aligned: the newest bar hugs the cell's end
  pts.forEach((p, i) => {
    const h = Math.max(2, Math.round(((p.open || 0) / max) * (H - 2)));
    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("x", String(x0 + i * (bw + gap)));
    rect.setAttribute("y", String(H - h));
    rect.setAttribute("width", String(bw));
    rect.setAttribute("height", String(h));
    rect.setAttribute("rx", "1");
    rect.setAttribute("class", "secbr-bar" + (p.state === "capped" ? " capped" : ""));
    svg.appendChild(rect);
  });
  return svg;
}

function secBrKebab(r){
  const kebab = document.createElement("details");
  kebab.className = "secidx-kebab";
  const summary = document.createElement("summary");
  summary.className = "iconbtn";
  summary.title = "More";
  summary.appendChild(secIcon("dots"));
  // closeMenus() called directly and synchronously (Phase 4's own
  // post-review decision): the stopPropagation that keeps this click off
  // the row also keeps it from ever reaching the document listener that
  // would otherwise close the OTHER open menus.
  summary.onclick = (e) => { e.stopPropagation(); closeMenus(); };
  kebab.appendChild(summary);
  const pop = secEl("div", "menu-pop");
  pop.setAttribute("role", "menu");

  const findings = document.createElement("button");
  findings.setAttribute("role", "menuitem");
  findings.appendChild(secIcon("filter"));
  findings.appendChild(document.createTextNode("View findings"));
  findings.title = "Open the findings browser filtered to this branch";
  findings.onclick = (e) => {
    e.stopPropagation();
    kebab.open = false;
    secSwitchProjectTab("findings");
    // The SECOND render wins by generation (secFindLoad's own fs.gen guard):
    // the tab switch's own unfiltered load is already stale by the time
    // this one starts, so the browser lands filtered, never racing back.
    // `branch` is a STRING here -- the browser's own client-side filter
    // shape (_defaultFilters, findings-screen.js), not finding_rows's
    // server-side list form.
    renderFindings($("sec-pj-findings"), secState.project, {branch: r.branch});
  };
  pop.appendChild(findings);

  const report = document.createElement("button");
  report.setAttribute("role", "menuitem");
  report.appendChild(secIcon("download"));
  report.appendChild(document.createTextNode("Download report"));
  report.title = r.analysis_id == null
    ? "No finished analysis of this branch yet"
    : "Download the latest finished analysis's report (Markdown)";
  report.disabled = r.analysis_id == null;
  report.onclick = (e) => {
    e.stopPropagation();
    kebab.open = false;
    if(r.analysis_id != null) secDownloadReport(r.analysis_id, "md", report);
  };
  pop.appendChild(report);

  kebab.appendChild(pop);
  kebab.ontoggle = () => {
    pop.hidden = !kebab.open;
    if(!kebab.open) return;
    const rect = summary.getBoundingClientRect();
    pop.style.position = "fixed";
    pop.style.top = (rect.bottom + 6) + "px";
    pop.style.right = (window.innerWidth - rect.right) + "px";
    pop.style.left = "auto";
    pop.style.bottom = "auto";
  };
  return kebab;
}

/* Pure and DOM-free on purpose, so a Node script can drive it with a plain
   array literal. `trend` is queries.trend()'s own shape: analyses of this
   branch within the last 30 days, oldest first, each carrying how many
   findings were open at that point. Since the Branches rebuild it is the
   trend CELL's title rather than its text -- the honest sentence survives
   the move to bars, it just moved one hover away.

   Only the FIRST and LAST point used to reach this text, with "rising"/
   "falling" read off the two of them alone -- so a branch that spiked to
   forty open findings and got mostly fixed (5, 40, 6) rendered as
   "5 → 6 ... (rising)", the opposite of what happened, and nothing in the
   diff that shipped this ever drove it with three points to notice (see
   tests/test_page_contract.py's
   test_branch_trend_text_refuses_a_direction_the_whole_series_does_not_support).
   A direction word is kept only when it holds for the WHOLE series, not
   just its ends: every step between consecutive points has to agree (a tie
   does not break it). When the points disagree about direction, this names
   the peak or trough the endpoints alone would hide instead of forcing a
   false "rising"/"falling" on data that went both ways -- a spike that was
   fixed, or a dip that crept back up, is the single most useful thing this
   line can say. */
function secBranchTrendText(trend){
  const pts = trend || [];
  if(!pts.length) return "No analyses of this branch in the last 30 days.";
  // A `capped` point is a PARTIAL read: its `open` count is what that run had
  // found before it stopped, not what was there. A direction word read across
  // one is a claim about the CODE made from a fact about the RUN -- "falling"
  // off an analysis that simply ran out of room before finding anything. So
  // the numbers still get shown (they are what was recorded, and hiding them
  // would be its own lie) and the direction is withheld, the same way this
  // function already withholds one from a series that went both ways.
  const partial = pts.some(p => p.state === "capped");
  if(pts.length === 1){
    return pts[0].open + " open — only one analysis in the last 30 days, "
      + "nothing yet to compare it against."
      + (partial ? " It stopped early, so that count is what it reached." : "");
  }
  const opens = pts.map(p => p.open);
  const first = opens[0], last = opens[opens.length - 1];
  const base = first + " → " + last + " open across " + pts.length
    + " analyses in the last 30 days";
  if(partial){
    return base + ", but at least one of them stopped before covering the "
      + "whole scope — no direction is claimed across a partial read";
  }

  let direction = "flat";
  for(let i = 1; i < opens.length; i++){
    const step = opens[i] < opens[i - 1] ? "falling"
               : opens[i] > opens[i - 1] ? "rising" : "flat";
    if(step === "flat") continue;
    if(direction === "flat") direction = step;
    else if(direction !== step){ direction = null; break; }
  }
  if(direction) return base + " (" + direction + ")";

  // Not monotonic: the endpoints alone would misdescribe what happened in
  // between. Name whichever of the peak/trough goes further than BOTH
  // endpoints -- the fact the direction word cannot say.
  const peak = Math.max(...opens), trough = Math.min(...opens);
  if(peak > first && peak > last) return base + ", peaked at " + peak;
  if(trough < first && trough < last) return base + ", dipped to " + trough;
  return base;
}

/* ------------------------------------------------------------- the rail
   The Branches tab's own three cards (ProjectBranches.png), mounted by
   project-screen.js's secRenderProjectSidebar when this tab is up: the
   all-branch severity donut (title carrying its scope where the other
   tabs' rail says it in a caption), Top issue categories with the
   "View all findings" door, and Branch coverage. */
export function secBranchesSidebar(payload){
  const frag = document.createDocumentFragment();
  const sb = (payload || {}).sidebar || {};
  const rows = ((payload || {}).tabs || {}).branches || [];

  const donutCard = secEl("div", "card secpj-plaincard");
  const donutHead = secEl("div", "secpj-cardhead");
  const donutTitle = secEl("h3", null, "Findings by severity ");
  donutTitle.appendChild(secEl("span", "secbr-scope", "(all branches)"));
  donutTitle.title = "Distinct problems (fingerprints) across every "
    + "analysed branch — the same finding open on two branches counts once "
    + "here, once per branch in the table. " + SEC_FLOOR_SCOPE_NOTE;
  donutHead.appendChild(donutTitle);
  donutCard.appendChild(donutHead);
  const row = secEl("div", "secrun-donutrow");
  row.appendChild(secIndexDonutSvg(sb.donut || {}));
  row.appendChild(secIndexDonutLegend(sb.donut || {},
    {showPercent: true, showZero: true}));
  donutCard.appendChild(row);
  // The one honesty cue the donut cannot carry per-row: how many of the
  // branches it rolls up were only read partially.
  const capped = secCappedScopeNote(sb.capped_branches || 0,
    sb.branch_count || 0, "branch");
  if(capped) donutCard.appendChild(capped);
  frag.appendChild(donutCard);

  const catCard = secEl("div", "card secpj-plaincard");
  const catHead = secEl("div", "secpj-cardhead");
  catHead.appendChild(secEl("h3", null, "Top issue categories"));
  catCard.appendChild(catHead);
  catCard.appendChild(secIndexCategories(sb.categories || []));
  const viewAll = secEl("button", "btn ghost secpj-viewallcats");
  viewAll.type = "button";
  viewAll.appendChild(document.createTextNode("View all findings"));
  viewAll.appendChild(secIcon("cright"));
  viewAll.title = "Open this project's findings browser";
  viewAll.onclick = () => secSwitchProjectTab("findings");
  catCard.appendChild(viewAll);
  frag.appendChild(catCard);

  frag.appendChild(secBrCoverageCard(rows));
  return frag;
}

/* "X / Y analyzed" in the last 30 days. Y is git's own branch count for the
   picked repo when the launcher's list has answered (secGitBranchCount,
   analysis.js -- the same fetch, no second git call), and never less than
   the branches the ledger itself knows; before that list answers it is the
   ledger's count alone, and the caption says which of the two it was. */
function secBrCoverageCard(rows){
  const card = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Branch coverage"));
  card.appendChild(head);
  const now = Math.floor(Date.now() / 1000);
  const analyzed = rows.filter(r =>
    r.last_finished && (now - r.last_finished) <= 30 * 86400).length;
  const gitCount = secGitBranchCount();
  const total = Math.max(gitCount, rows.length);
  const pct = total ? Math.round((analyzed / total) * 100) : 0;

  const line = secEl("div", "secbr-covline");
  line.appendChild(secEl("span", "secbr-covcount", analyzed + " / " + total + " analyzed"));
  line.appendChild(secEl("span", "secbr-covpct", pct + "%"));
  card.appendChild(line);
  const barTrack = secEl("div", "secbr-covtrack");
  const bar = secEl("div", "secbr-covbar");
  bar.style.width = pct + "%";
  barTrack.appendChild(bar);
  card.appendChild(barTrack);
  const scope = gitCount ? "of the branches the repository lists"
                         : "of the branches ever analysed";
  card.appendChild(secEl("div", "secpj-caption",
    !total ? "Nothing has been analysed yet."
    : analyzed >= total
      ? "All branches have been analyzed in the last 30 days."
      : (total - analyzed) + " " + scope
        + (total - analyzed === 1 ? " has" : " have")
        + " not been analyzed in the last 30 days."));
  return card;
}
