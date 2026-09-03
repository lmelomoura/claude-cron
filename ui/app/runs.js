/* ----------------------------------------------------------------- runs

   The Runs page, rebuilt in the Overview's own visual language: a page
   header, four KPI cards, the existing filter bar repainted rather than
   rebuilt, a table card and a footer with real pagination -- the same shape
   jobs-table.js and projects.js already gave their own pages. `RUN_COLS`,
   the sort state, `RF` and everything that used to read them directly
   (`renderRunHead`, `renderRuns`, `paintRunFilters`, `runSearch`,
   `clearRunFilters`) move here from bin/dashboard.html, unchanged in
   substance -- Task 6 already moved the pure filter+sort arithmetic
   (`filteredRuns`, `SORTERS`) ahead of this move, for exactly this day.

   What does NOT move: the log modal (`renderLog`/`paintLog`/`openLog` and
   everything that keeps a live one tailing) stays in bin/dashboard.html.
   It is not a table -- it is a terminal with live-tail scrolling, syntax
   highlighting and an input box -- and converting its 191 lines of raw
   HTML-string markup into DOM builders is a reimplementation of exactly
   the kind of component where behaviour goes missing quietly. It also
   renders agent output, which is untrusted input, so the HTML-parsing sink
   it uses to do that is worth removing on its own terms -- with its own
   tests and its own falsifiability pass -- not as a rushed sub-step of the
   last, largest task of this phase. This module reaches `openLog` through
   the page.js interface instead, the same way it reaches every other
   page-owned function below.

   Four pieces of Runs-only bookkeeping stay in bin/dashboard.html and are
   reached through page.js for the same "one implementation, not a second
   copy" reason eff/backoffMultiplier/activeRunsOf already are for jobFacts:
   `unjournaledLive` (also read by the page's own sidebar count),
   `isStopping` (reads the page's own `stopping` Set, kept in step by
   `markStopping`, which the page's central click dispatcher still calls
   directly), and the resume-tooltip machinery (`resumeTarget`, `resumeTip`,
   `continuedRun`, `resumedBadgeTip`, `runKey`) -- all five keep returning
   the exact values/strings they always did; only where the row that reads
   them is built has changed. See page.js's own comment for the full list
   and why each one stays where it is. */
import { $, CC, icon, money, fmtAgo, fmtDur, fmtWhen, normStatus,
         openLog, resumeTarget, resumeTip, continuedRun, resumedBadgeTip,
         runKey, isStopping, unjournaledLive, paintRunPickers, runDateLabel,
         toast, TOKEN } from "./page.js";
import { el, pageHeader, kpiCard, filterBar, tableCard, tableFooter } from "./chrome.js";

// One object rather than five `let`s, the same reason jobFilters/projFilters
// take this shape (see jobs-domain.js's own comment): an ES module cannot
// let an importer reassign a plain binding, only read and write through the
// same reference from either side, which is what the four pickers'
// `onPick` callbacks (bin/dashboard.html) and this module both need.
export const RF = { project:"", job:"", status:"", from:"", to:"" };

// Column sort. `when` descending is the default and the only order in which
// a live run belongs at the top, so live rows keep their place there and are
// sorted with everything else under any other key. Duration and cost are
// SEPARATE comparators because they answer different questions -- "what is
// slow" and "what is expensive" are rarely the same run. They used to be
// merged into one column, which silently dropped the cost sort: the
// comparator still existed, but no header could reach it, so the most
// expensive run of a day became unfindable in a 25-row page --
// test_duration_and_cost_sort_independently (tests/test_page_contract.py)
// pins the two staying apart.
export const SORTERS = {
  when:(a,b)=>a.start-b.start,
  job:(a,b)=>String(a.id).localeCompare(String(b.id)) || a.start-b.start,
  status:(a,b)=>String(a.live?"running":normStatus(a.status))
                  .localeCompare(String(b.live?"running":normStatus(b.status))) || a.start-b.start,
  cost:(a,b)=>((a.cost||0)-(b.cost||0)) || a.start-b.start,
  duration:(a,b)=>((a.duration||0)-(b.duration||0)) || a.start-b.start,
};

// The set the Runs table is showing right now: live rows and journaled runs
// merged, both filtered by `rf`, re-sorted only when the caller asked for
// something other than the default "newest first" -- the default order is
// already what the query produced. `rf`, `liveRows`, `searchKeys`,
// `sortKey` and `sortDir` are explicit parameters rather than closures over
// this module's own RF/sortKey/sortDir/searchKeys below, unchanged since
// Task 6 pinned it: the four characterisation tests that read this function
// out of the built bundle construct their own fixtures for every one of
// these, and changing the signature out from under them is not this task's
// to do.
export function filteredRuns(rf, liveRows, searchKeys, sortKey, sortDir){
  const fromT=rf.from?Date.parse(rf.from):null, toT=rf.to?Date.parse(rf.to):null;
  // live rows first -- a search narrows to indexed runs, so they drop out here
  const live=searchKeys?[]:liveRows;
  const rows=live.concat(CC.DATA.runs).filter(r=>{
    if(r.live){
      if(rf.project){ const rp=r.project||""; if(rf.project==="__none__" ? rp!=="" : rp!==rf.project) return false; }
      if(rf.job && r.id!==rf.job) return false;
      if(rf.status && rf.status!=="running") return false;
      return true;
    }
    // Trusts the server's own search results as-is: /api/search's index
    // covers a run's log content as well as its id, so a run matched purely
    // by something said IN its log has to surface here just as reliably as
    // one matched by name -- re-checking the id against the query text would
    // undo exactly that on the client, the regression
    // test_a_run_matched_only_in_its_log_content_still_surfaces
    // (tests/test_page_contract.py) pins against.
    if(searchKeys && !searchKeys.has(r.id+"|"+r.start)) return false;
    if(rf.project){ const rp=r.project||""; if(rf.project==="__none__" ? rp!=="" : rp!==rf.project) return false; }
    if(rf.job && r.id!==rf.job) return false;
    if(rf.status && normStatus(r.status)!==rf.status) return false;
    const t=r.start*1000;
    if(fromT && t<fromT) return false;
    if(toT && t>toT) return false;
    return true;
  });
  // The default order is already what the query produced, so only re-sort when
  // the user has actually asked for something else.
  if(sortKey!=="when" || sortDir!==-1){
    const cmp=SORTERS[sortKey]||SORTERS.when;
    rows.sort((a,b)=>cmp(a,b)*sortDir);
  }
  return rows;
}

/* -------------------------------------------------------------- the header */
function runsHeaderSubtitle(runs, liveCount){
  const total = runs.length + liveCount;
  if(!total) return "Nothing recorded yet — a run appears here the moment a job wakes.";
  const t0 = Math.floor(new Date().setHours(0,0,0,0)/1000);
  const today = runs.filter(r => r.start >= t0).length + liveCount;
  return total + " run" + (total===1?"":"s") + " on record, " + today + " today.";
}

/* --------------------------------------------------------------- the KPIs
   Total, running now, warnings, errors -- the four numbers this page
   already knows without asking the server for anything new. None of these
   is a door: unlike the Overview's own Warning/Error cards (which lead HERE
   from a different page), a door back into the page you are already on
   leads nowhere, the same reasoning that keeps all four of Jobs' own cards
   `door: false`.

   Warnings/Errors used to count ALL of `runs` (the server's own 1000-row
   cap on CC.DATA.runs -- see bin/claude-cron-server's `LIMIT 1000`, far
   more than 7 days at any real job count) and said "N% of finished runs".
   The Overview's own cards of the same name count only the last 7 days and
   say so in their `sub` -- and one of them is a DOOR that lands a click
   straight on this page's own card, so the two disagreeing under an
   identical label was not a coincidence anyone could see, only a bug
   waiting for someone to click through. `wk` is the Overview's own cutoff,
   copied rather than imported: render() (bin/dashboard.html) computes the
   identical `Math.floor(Date.now()/1000)-7*86400` against this exact same
   CC.DATA.runs to feed CCApp.renderOverviewHead, so the two windows can
   only ever agree if this is the same formula, not a second one that
   happens to produce the same answer today. See
   test_the_overview_and_runs_warning_cards_name_the_same_window
   (tests/test_page_contract.py) for the guard. */
function runsKpis(runs, liveCount){
  const t0 = Math.floor(new Date().setHours(0,0,0,0)/1000);
  const wk = Math.floor(Date.now()/1000) - 7*86400;
  const total = runs.length + liveCount;
  const finished = runs.length;
  const recent = runs.filter(r => r.start >= wk);
  const warnCount = recent.filter(r => normStatus(r.status)==="warning").length;
  const errCount = recent.filter(r => normStatus(r.status)==="error").length;
  const todayCount = runs.filter(r => r.start >= t0).length + liveCount;

  return [
    // The server's own cap (see above) makes `total` a FLOOR at that cap,
    // not a true total -- "1000 runs on record" reads as a complete count
    // when the 1001st-oldest run is sitting right there, uncounted, in the
    // same database. `finished` rather than `total`: the live count on top
    // does not change what the journaled cap has already thrown away.
    {label: "Total runs", value: finished >= 1000 ? "1000+" : String(total),
     sub: todayCount + " today", tone: "", filter: "", door: false},
    {label: "Running now", value: String(liveCount),
     sub: liveCount ? "following live" : "none in flight", tone: "", filter: "", door: false},
    {label: "Warnings", value: String(warnCount), sub: "in the last 7 days",
     title: "Runs that finished without failing but did not do the work",
     tone: "", filter: "", door: false},
    {label: "Errors", value: String(errCount), sub: "in the last 7 days",
     title: "Runs that failed",
     tone: "", filter: "", door: false},
  ];
}

const KPI_ICONS = {"Total runs": "layers", "Running now": "play",
                    "Warnings": "alert", "Errors": "xcircle"};

/* ------------------------------------------------------------- the toolbar
   Assembled ONCE, not on every poll -- the same "move the live search input,
   never rebuild it" reasoning mountJobsToolbar (jobs-table.js) states in
   full. `#rsizepick` (the per-page picker) and `#f-clear` both land in `actions`, right of
   the spacer filterBar itself inserts -- the static markup's own `.spacer`
   div, which used to sit between the pickers and `#f-clear`, goes with it;
   the two never disagreed about WHAT the toolbar's rightmost group is, only
   about which side of it `#f-clear` used to sit. */
function mountRunsToolbar(){
  const host = $("runstoolbar");
  if(!host || host.dataset.mounted) return;
  const bar = filterBar({
    search: $("searchbox"),
    selects: [$("rprojpick"), $("rjobpick"), $("rstatpick"), $("rdatepick")],
    actions: [$("f-clear"), $("rsizepick")],
  });
  host.insertBefore(bar, $("ractive"));
  host.dataset.mounted = "1";
}

/* ------------------------------------------------------------ the filters
   Repaints the four pickers, the active-filter chip row and the search
   box's own clear button -- the same three things `paintRunFilters`
   (bin/dashboard.html) used to, against the SAME `#ractive`/`#f-clear`
   static markup: the pickers are not rebuilt here, only their state, through
   `paintRunPickers()` (page.js) the same way `paintJobFilterBar`
   (jobs-table.js) reaches `paintJobPickers()`. The date range is one chip
   however it was set, because "From 2026-07-01T00:00" and "Last 7 days" are
   the same filter and two chips for it would imply two. */
function paintRunFilters(shown){
  paintRunPickers();
  const box = $("ractive");
  box.textContent = "";
  const chips = [];
  if(RF.project) chips.push(["project", "Project: "
    + (RF.project==="__none__" ? "No project" : RF.project)]);
  if(RF.job) chips.push(["job", "Job: " + RF.job]);
  if(RF.status) chips.push(["status", "Status: " + RF.status]);
  if(RF.from || RF.to) chips.push(["date", "Date: " + runDateLabel()]);
  const q = $("q").value.trim();
  if(q) chips.push(["q", 'Search: "' + q + '"']);
  box.hidden = !chips.length;
  if(chips.length){
    box.appendChild(el("span", "aflabel", "Active filters:"));
    chips.forEach(([key, label]) => {
      const chip = el("span", "afchip");
      chip.appendChild(document.createTextNode(label));
      const drop = el("button");
      drop.dataset.droprf = key;
      drop.title = "Remove this filter";
      drop.appendChild(icon("x"));
      chip.appendChild(drop);
      box.appendChild(chip);
    });
    box.appendChild(el("span", "aflabel", shown + " of " + (CC.DATA.runs||[]).length + " runs"));
  }
  $("f-clear").hidden = !chips.length;
}

/* --------------------------------------------------------------- the table
   Sort state, page number, page size and the search's own bookkeeping are
   this module's own, the same split jobs-table.js/projects.js keep for the
   identical reason: nothing outside this file ever needs to know which
   column is sorted, which page is showing, or what the last search
   returned. */
let sortKey="when", sortDir=-1, page=1;
let pageSize=parseInt(localStorage.ccPageSize||"25",10)||25;
let searchKeys=null, snippets={}, searchSeq=0;

export function runsSort(key){
  if(sortKey===key) sortDir=-sortDir;
  // Names and status open A→Z; the clock and money columns open on the
  // largest, which is the end of each you actually came to look at -- same
  // rule bin/dashboard.html's own click handler used to apply.
  else { sortKey=key; sortDir=(key==="job"||key==="status")?1:-1; }
  page=1; renderRunsPage();
}

export function runsSetPage(delta){
  page+=delta; renderRunsPage();
}

// Every picker's own onPick, the date range's two exact fields and the
// dropped-chip handler (bin/dashboard.html) all used to inline `page=1;
// renderRuns();` after touching RF -- this is that one line, named, so a
// future filter has one place to call rather than one more inlined copy.
export function runsFilterChanged(){
  page=1; renderRunsPage();
}

// The Overview's own Warning/Error KPI cards jump here with RF.status
// already set and switch the view themselves right after -- the view switch
// (bin/dashboard.html's setView) renders every page unconditionally on its
// own, so resetting the page number is all this needs to do; rendering here
// too would just be a second, wasted render of a view not on screen yet.
export function runsGotoFirstPage(){
  page=1;
}

export function runsSetPageSize(n){
  pageSize=n; localStorage.ccPageSize=n; page=1; renderRunsPage();
}

// Read by the per-page picker's own valueLabel/rows on every paint, so the
// trigger always shows whatever was persisted last session.
export function runsPageSize(){ return pageSize; }

export function clearRunFilters(){
  RF.project=RF.job=RF.status=RF.from=RF.to="";
  $("f-from").value=""; $("f-to").value="";
  $("q").value=""; $("q-clear").hidden=true;
  page=1; runSearch("");
}

export async function runSearch(q){
  const seq=++searchSeq;
  if(!q || q.trim().length<2){ searchKeys=null; snippets={}; renderRunsPage(); return; }
  try{
    const r=await fetch("/api/search?q="+encodeURIComponent(q.trim()), {headers:{"X-CC-Token":TOKEN}});
    if(!r.ok) throw new Error("HTTP "+r.status);
    const j=await r.json();
    if(seq!==searchSeq) return;            // a newer query superseded this one
    searchKeys=new Set(); snippets={};
    (j.results||[]).forEach(x=>{ const k=x.id+"|"+x.start; searchKeys.add(k); if(x.snippet) snippets[k]=x.snippet; });
    page=1; renderRunsPage();
  }catch(e){ if(seq===searchSeq) toast("Search failed — "+e.message, true); }
}

// The Runs picker's own project list -- the run count for each name, mirrors
// jobProjectNames (jobs-domain.js) for the identical reason: known() has to
// agree with what the picker itself is about to count rows out of.
export function runProjectNames(){
  return [...new Set((CC.DATA.runs||[]).map(r=>r.project||"").filter(Boolean))].sort();
}

// "Succeeded, but nothing actually ran" — the engine puts the agent's own
// `NOTHING TO DO: <reason>` in the run's note. Returns the reason, or "".
function nothingNote(r){
  const n=(r&&r.note)||"";
  const i=n.indexOf("NOTHING TO DO:");
  return i<0 ? "" : n.slice(i+"NOTHING TO DO:".length).trim();
}

// Which live slot to stop from a runs-table row. With one live run it is
// that run; with several, the row cannot tell them apart, so fall back to
// the first and let the engine's per-pid stop do the precise work.
function livePidFor(id){
  const a=(CC.DATA.active_runs||{})[id]||[];
  return a.length ? a[0].pid : "";
}

// The icon each status reads with -- STATUS_ICON's own keys, mapped to the
// names icon() (page.js) knows rather than to bin/dashboard.html's raw SVG
// strings: this module builds real DOM, and icon() is the one route to it
// that hands the HTML parser nothing (see chrome.js's own comment on why
// this is the icon table's ONLY route out of the page).
const STATUS_ICON_NAME = {success:"check", warning:"alert", error:"xcircle",
                           idle:"clock", running:"timer", stopped:"power"};

// `error` covered a 529 the API returned and an agent that got its tools
// taken away, and those want opposite responses from the person reading the
// table -- wait, versus go and look. The cause says which without opening
// the run. Moved out of bin/dashboard.html's own CAUSE_LABEL/causeTag, which
// returned an HTML string; this returns a real element instead, since the
// row it sits in is built the same way.
const CAUSE_LABEL={
  api_error:    ["API",      "the API refused a turn — the provider's fault, not this job's, and it does not count towards the failure backoff"],
  rate_limited: ["limit",    "the account is over its rate or usage limit — it does not count towards the failure backoff"],
  tools_denied: ["blocked",  "the agent asked for a tool it is not allowed, so it could not do the work"],
  killed:       ["killed",   "the run was cut off — a watchdog, a crash, or a kill — and never reported a result"],
  agent_error:  ["agent",    "the agent itself ended in error"],
};
// `data-tip`, not `title`: the page's own bubble (tipShow in bin/dashboard.html,
// reached by the delegated mouseover on `[data-tip]`) appears on hover instead
// of after the browser's own ~1s dwell, and cannot be clipped by an ancestor.
// The dwell is what made this label unreachable in practice -- the tag is a
// 30px pill in a table that repaints every 5 seconds, so the pointer rarely
// sits still on it long enough for a native tooltip to ever appear, and the
// `cursor:help` the CSS gives it promised an explanation that never came.
// Encoded because tipShow decodeURIComponent()s what it reads back.
function causeTag(rec){
  const c=CAUSE_LABEL[(rec&&rec.cause)||""];
  if(!c) return null;
  const tag=el("span", "causetag", c[0]);
  tag.dataset.tip=encodeURIComponent(c[1]);
  return tag;
}

// Duration and cost are SEPARATE columns because they answer different
// questions and you sort by them for different reasons — "what is slow" and
// "what is expensive" are rarely the same run. Merging them dropped the cost
// sort entirely: the comparator above still existed, but no header could
// reach it, so the most expensive run of a day became unfindable in a
// 25-row page -- test_duration_and_cost_sort_independently pins the two
// staying apart (see SORTERS' own comment).
export const RUN_COLS = [
  ["when","When"],["job","Job"],[null,"Project"],["status","Status"],
  ["duration","Duration"],["cost","Cost"],[null,"Session"],[null,""],
];

// One row. Session, When and Status carry more than their own column's
// number -- a search snippet, a "resumed" badge, a "?" tooltip -- because a
// table row is the one place an operator reads all of a run's story at
// once; splitting these into their own columns would cost four more of them
// for facts that matter only sometimes.
function runRow(r){
  const tr = el("tr");
  const s = normStatus(r.status);
  const snip = searchKeys ? (snippets[r.id+"|"+r.start]||"") : "";
  // A single source of truth for "can this row's Resume button ever be
  // live", read at three places below (the followUp lookup, the "?" badge,
  // and the button itself) -- three separate checks is three places to keep
  // in sync the day this set changes again, which is exactly what happened
  // going from `error`-only to `error`-or-`warning`, and again when
  // `stopped` was folded in here too.
  const resumable = s==="error"||s==="warning"||s==="stopped";
  // A derived security run is OBSERVED here, never managed here: resume
  // cannot work (the analysis request it ran on was consumed, and its
  // ledger row is closed), and deleting it erases the transcript the
  // Security page's "Open the run" points at.
  const isSec = String(r.id||"").startsWith("security-");
  const followUp = resumable ? resumeTarget(r.id, r.start) : null;
  const parent = continuedRun(r);

  // "3 days ago" is what you are actually reading for; the stamp to the
  // second is one hover away, where it belongs.
  const tdWhen = el("td", "num");
  const when = el("span", "when-rel", fmtAgo(r.start));
  when.title = fmtWhen(r.start);
  tdWhen.appendChild(when);
  if(r.forced) tdWhen.appendChild(el("span", "trigger-badge", "forced"));
  if(parent){
    const badge = el("span", "trigger-badge resumed", "resumed");
    badge.dataset.tip = encodeURIComponent(resumedBadgeTip(parent));
    tdWhen.appendChild(badge);
  }
  if(snip){
    const snipEl = el("div", "snip", snip);
    snipEl.title = snip;
    tdWhen.appendChild(snipEl);
  }
  tr.appendChild(tdWhen);

  const tdJob = el("td");
  tdJob.appendChild(el("code", null, r.id));
  tr.appendChild(tdJob);

  const tdProject = el("td");
  if(r.project){
    const tag = el("span", "projtag");
    tag.appendChild(icon("folder"));
    // .projtag-name, not a bare text node -- see jobs-table.js's own comment
    // beside its identical tag.appendChild(el("span", "projtag-name", ...)):
    // ellipsis needs an element's box to apply to, and .projtag's own box
    // (display:inline-flex, for the icon/name alignment) is not eligible
    // for it at all.
    tag.appendChild(el("span", "projtag-name", r.project));
    tdProject.appendChild(tag);
  }else{
    tdProject.appendChild(el("span", "muted", "—"));
  }
  tr.appendChild(tdProject);

  const tdStatus = el("td");
  if(r.live){
    const badge = el("span", "runningbadge" + (isStopping(r) ? " stopping" : ""));
    badge.appendChild(el("span", "pulse"));
    badge.appendChild(document.createTextNode(isStopping(r) ? "stopping…" : "running…"));
    tdStatus.appendChild(badge);
  }else{
    const cell = el("span", "stat-cell s-" + s);
    cell.appendChild(icon(STATUS_ICON_NAME[s] || "clock"));
    cell.appendChild(document.createTextNode(s));
    tdStatus.appendChild(cell);
    const cause = causeTag(r);
    if(cause) tdStatus.appendChild(cause);
    if(resumable && followUp){
      const badge = el("span", "tipbadge", "?");
      badge.dataset.tip = encodeURIComponent(resumeTip(r.id, r.start));
      tdStatus.appendChild(badge);
    }else{
      // A run can end fine having done nothing at all — a resumed task
      // already finished, or its ticket is gone. That is recorded as a
      // WARNING, and the reason is shown here, so a clean-looking run is
      // never mistaken for work that happened.
      const note = nothingNote(r);
      if(note){
        const badge = el("span", "tipbadge", "?");
        badge.dataset.tip = encodeURIComponent("Nothing was done in this run — " + note);
        tdStatus.appendChild(badge);
      }
    }
  }
  tr.appendChild(tdStatus);

  // How long and how much are read together — two columns half the table
  // apart just made you scan across the empty middle.
  const tdDuration = el("td", "num");
  tdDuration.appendChild(document.createTextNode(fmtDur(r.duration)));
  if(r.live){
    tdDuration.appendChild(document.createTextNode(" "));
    tdDuration.appendChild(el("span", "muted", "so far"));
  }
  tr.appendChild(tdDuration);

  const tdCost = el("td", "num");
  if(r.live) tdCost.appendChild(el("span", "muted", "—"));
  else tdCost.appendChild(document.createTextNode(money(r.cost)));
  tr.appendChild(tdCost);

  const tdSession = el("td");
  tdSession.appendChild(el("code", null, (r.session||"").slice(0,8) || "—"));
  tr.appendChild(tdSession);

  const tdActs = el("td", "rowacts");

  // View the log. Reaches openLog directly (through the page.js interface)
  // rather than through a `data-log-id` attribute a central listener used
  // to read -- see page.js's own comment on why this one action moved with
  // the row instead of staying declarative.
  const view = el("button", "iconbtn" + (r.live ? " live" : ""));
  view.title = r.live ? "Follow this run live" : "View log";
  view.appendChild(icon("eye"));
  view.addEventListener("click", () => openLog(r.id, r.start));
  tdActs.appendChild(view);

  // Stop and Resume are rendered on EVERY row, greyed where they do not
  // apply, because a toolbar whose icons move between rows is one you have
  // to re-read each time. The reason a button is dead is on its tooltip,
  // and a dead button still teaches that the action exists — an empty slot
  // teaches nothing. Both stay declarative (`data-op`, read by the page's
  // one central click dispatcher, unchanged) since neither needs more than
  // that dispatcher already does for every other action on this page.
  const stop = el("button", "iconbtn" + (r.live ? " danger" : ""));
  stop.appendChild(icon("power"));
  if(r.live){
    if(isStopping(r)){
      stop.disabled = true;
      stop.title = "Already stopping — waiting for it to wind down";
    }else{
      stop.title = "Stop this run";
      stop.dataset.op = "stop";
      stop.dataset.id = r.id;
      stop.dataset.runPid = r.pid || livePidFor(r.id);
    }
  }else{
    stop.disabled = true;
    stop.title = "This run has already finished — only a running run can be stopped";
  }
  tdActs.appendChild(stop);

  // A failed OR warning run is worth retrying — offer it right where the
  // problem shows. Reuses the Run-now op, so it inherits the precheck guard
  // and toasts. Gone once the job has picked the task back up (resumed here
  // or anywhere): a second resume would just duplicate the work, and the
  // "?" beside the status says where it went.
  const retry = el("button", "iconbtn retry");
  retry.appendChild(icon("play"));
  if(r.live){
    retry.disabled = true;
    retry.title = "This run is still going";
  }else if(isSec){
    retry.disabled = true;
    retry.title = "A security analysis is never resumed — its request was consumed when it ran. Launch a fresh one from the Security area";
  }else if(resumable){
    if(!r.session){
      retry.disabled = true;
      retry.title = "This run recorded no session id, so it cannot be resumed";
    }else if(followUp){
      retry.disabled = true;
      retry.title = (followUp.running ? "A newer run is in progress" : "This task was already resumed")
        + " — see the ? beside the status";
    }else{
      retry.title = "Resume this task — continue session " + (r.session||"").slice(0,8) + " where it stopped";
      retry.dataset.op = "resume";
      retry.dataset.id = r.id;
      retry.dataset.session = r.session || "";
      retry.dataset.resumeKey = runKey(r.id, r.start);
    }
  }else{
    retry.disabled = true;
    retry.title = "Only a failed, warning or stopped run can be resumed";
  }
  tdActs.appendChild(retry);

  // Erase this run for good: its log files, its journal line and its rows
  // in the search database. Never offered while it is still running.
  const del = el("button", "iconbtn" + (r.live || isSec ? "" : " danger"));
  del.appendChild(icon("trash"));
  if(r.live){
    del.disabled = true;
    del.title = "A running run cannot be deleted — stop it first";
  }else if(isSec){
    del.disabled = true;
    del.title = "This run is a security analysis's evidence — the Security area owns its lifecycle";
  }else{
    del.title = "Delete this run and everything it left behind";
    del.dataset.delId = r.id;
    del.dataset.delStart = r.start;
  }
  tdActs.appendChild(del);

  tr.appendChild(tdActs);
  return tr;
}

function renderRunsTable(){
  const all = filteredRuns(RF, unjournaledLive(), searchKeys, sortKey, sortDir);
  const total = all.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  // A filter (or a search) that shrinks the set must not leave `page`
  // pointing past its last real one --
  // test_a_shrunk_filtered_set_pulls_the_current_page_back_from_beyond_it
  // (tests/test_page_contract.py) pins this.
  if(page > pages) page = pages;
  if(page < 1) page = 1;
  const from = total ? (page - 1) * pageSize + 1 : 0;
  const to = Math.min(page * pageSize, total);
  const slice = all.slice((page - 1) * pageSize, page * pageSize);

  let rows;
  if(!total){
    const tr = el("tr");
    const td = el("td", "tblempty");
    td.colSpan = RUN_COLS.length;
    td.appendChild(icon("inbox"));
    td.appendChild(document.createTextNode(
      (CC.DATA.runs||[]).length
        ? (searchKeys ? "No runs match this search." : "No runs match the filters.")
        : "No runs recorded yet."));
    tr.appendChild(td);
    rows = [tr];
  }else{
    rows = slice.map(r => runRow(r));
  }

  const footer = tableFooter({
    // The footer and the pager count the FILTERED set, never the total --
    // test_the_footer_and_pager_count_the_filtered_set_not_the_total pins
    // this the same way.
    shown: {from, to}, total, noun: "run", page, pages,
    prevId: "runs-pg-prev", nextId: "runs-pg-next", infoId: "runs-pg-info",
  });
  const card = tableCard({
    columns: RUN_COLS, sortKey, sortDir, sortAttr: "sort", rows, footer,
  });

  const host = $("runs-table");
  host.textContent = "";
  host.appendChild(card);

  paintRunFilters(total);
}

/* -------------------------------------------------------------- the mount
   Called once per poll from bin/dashboard.html's render(), the same way it
   already calls CCApp.renderJobsPage()/CCApp.renderProjectsPage(). */
export function renderRunsPage(){
  mountRunsToolbar();
  const runs = CC.DATA.runs || [];
  const liveCount = unjournaledLive().length;

  const headHost = $("runs-head");
  if(headHost){
    headHost.textContent = "";
    headHost.appendChild(pageHeader({
      icon: "activity", title: "Runs", subtitle: runsHeaderSubtitle(runs, liveCount),
      actions: [{id: "runs-refresh", icon: "radar", label: "Refresh"}],
    }));
  }

  const kpiHost = $("runs-kpis");
  if(kpiHost){
    kpiHost.textContent = "";
    runsKpis(runs, liveCount).forEach(c => kpiHost.appendChild(kpiCard({
      icon: KPI_ICONS[c.label], tone: c.tone, value: c.value,
      label: c.label, sub: c.sub, title: c.title, filter: c.filter, door: c.door,
    })));
  }

  renderRunsTable();
}
