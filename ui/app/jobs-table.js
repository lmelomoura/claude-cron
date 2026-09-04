/* -------------------------------------------------------------- jobs table

   The Jobs page, rebuilt in the Overview's own visual language: a page
   header written from the real numbers, four KPI cards, the existing filter
   bar repainted rather than rebuilt, a table card and a footer with real
   pagination -- the one piece of this page that did not exist before.
   `renderJobTable`, `renderJobHead`, `paintJobFilters` and the branch inside
   `renderJobs()` that used to fork between cards and table all moved here
   from bin/dashboard.html, verbatim in substance. `initJobDrag` moved too --
   it still drags job CARDS on the Overview (the table's rows do not drag),
   but it is job-domain code, not page furniture, so it lives with the rest
   of what this module owns rather than behind alone in the page.

   jobs-domain.js's own banner comment named this module by name: `jobFacts`
   and `visibleJobs` moved out of bin/dashboard.html specifically so this
   table would not have to duplicate them. This is that second consumer.

   Two findings from the task that pinned this table's behaviour (Task 2)
   are closed here, not reopened:

   1. The table's own empty row used to duplicate `jobsEmptyNote`'s two
      sentences character for character in an inline ternary. It now calls
      the function -- see the empty branch in renderJobsTable() below.
   2. The `state` column's id tiebreak reverses with the sort direction
      while `project`'s deliberately does not -- a real inconsistency in
      `JOB_SORTERS` (ui/app/jobs-domain.js), pinned as-is by Task 2's tests
      and NOT changed here: a restyle is exactly the kind of change that
      hides a sort regression, and the pinned tests would not catch this
      particular one going the other way. `project`'s comparator is the one
      that matches its own stated intent ("stay A→Z whichever way the arrow
      points") -- `state` should eventually match it, by moving its id
      fallback out of `cmp` and into its own `tie`, but that is a
      deliberate follow-up, not this task.

   Two more findings, from inspection of what THIS task's own first pass
   landed, are closed here instead of being left for Projects and Runs to
   repeat: the footer used to be a loose `<div class="pager">` sibling below
   `.tablewrap` -- no border, no background, floating under the card rather
   than belonging to it -- and the card's own radius was 12px where every
   other card in this language is 13px. `renderJobsTableHead` and the
   `<table>`/footer markup it and `renderJobsTable` used to build directly
   are gone; both now come from chrome.js's `tableCard`/`tableFooter`, the
   second consumer promised when those two (and `filterBar`, for the
   toolbar below) were added there alongside `pageHeader`/`kpiCard`. See
   chrome.js's own comments on `tableCard` and `tableFooter` for why the
   sort click and the pager click are still answered by
   bin/dashboard.html's one delegated listener rather than a listener built
   here. */
import { jobFacts, visibleJobs, jobFilters, sortJobs, JOB_COLS,
         bulkOn, bulkLabel } from "./jobs-domain.js";
import { jobsEmptyNote } from "./overview.js";
import { el, pageHeader, kpiCard, filterBar, tableCard, tableFooter } from "./chrome.js";
import { $, CC, icon, money, fmtAgo, fmtDur, fmtWhen, fmtIn, isFav,
         TOKEN, toast, refresh, paintJobPickers, markIfPending } from "./page.js";

/* ------------------------------------------------------------ the header
   One sentence, built from what is actually configured -- not a static
   caption. Kept a plain function rather than folded into renderJobsPage()
   so its wording can change without touching anything that builds DOM. */
function jobsHeaderSubtitle(jobs){
  if(!jobs.length) return "Nothing configured yet — add a job to put the scheduler to work.";
  const enabled = jobs.filter(j => j.enabled !== false).length;
  const disabled = jobs.length - enabled;
  const projects = new Set(jobs.map(j => j.project).filter(Boolean)).size;
  const n = jobs.length;
  const projPart = projects ? " across " + projects + " project" + (projects === 1 ? "" : "s") : "";
  const offPart = disabled ? ", " + disabled + " disabled" : ", all enabled";
  return n + " job" + (n === 1 ? "" : "s") + projPart + offPart + ".";
}

/* --------------------------------------------------------------- the KPIs
   Total, enabled, running now, spent today -- the four numbers this page
   already knows without asking the server for anything new. None of these
   is a door: `door:false` on all four renders them as plain, always-
   full-contrast elements (see kpiCard's own comment in chrome.js on why a
   card that never navigates must not be a disabled button pretending to be
   one -- Phase 1 shipped exactly that bug on this page's siblings once).

   Each sublabel pairs its card's own number with a second one from the same
   set of jobs, the way pulseKpis' Spent-today card pairs today's total with
   the week's -- never restating the number already on the card. */
export function jobsKpis(jobs){
  const total = jobs.length;
  const enabled = jobs.filter(j => j.enabled !== false);
  const disabled = total - enabled.length;
  const facts = jobs.map(j => jobFacts(j));
  const idle = facts.filter(F => F.idle).length;
  const runningJobs = facts.filter(F => F.running).length;
  const spentToday = facts.reduce((a, F) => a + F.spentToday, 0);
  const cappedCount = facts.filter(F => F.capped).length;
  // Percentage of nothing is not 0% -- pulseKpis' own rule (overview.js),
  // reached for again here rather than duplicated as a bare ternary.
  const pct = (num, den) => den ? Math.round(num / den * 100) + "%" : "—";

  return [
    {label: "Total jobs", value: String(total),
     sub: disabled ? disabled + " disabled" : "all enabled",
     tone: "", filter: "", door: false},
    {label: "Enabled", value: String(enabled.length),
     sub: !enabled.length ? "nothing enabled yet"
        : idle ? idle + " idle right now" : "all within their window",
     tone: "", filter: "", door: false},
    {label: "Running now", value: String(runningJobs),
     sub: pct(runningJobs, enabled.length) + " of enabled jobs",
     tone: "", filter: "", door: false},
    {label: "Spent today", value: money(spentToday),
     sub: cappedCount ? cappedCount + " at their cap" : "no jobs at cap",
     tone: "", filter: "", door: false},
  ];
}

const KPI_ICONS = {"Total jobs": "layers", "Enabled": "power",
                   "Running now": "play", "Spent today": "dollar"};

/* ------------------------------------------------------------- the toolbar
   Assembled ONCE, not on every poll: `#jobstoolbar`'s static markup used to
   hand-lay-out the search box, the two pickers and the two trailing buttons
   itself (a `.toolbar` div with a `.spacer` in it, hand-copied into Runs'
   own markup as well); chrome.js's `filterBar` is now that layout,
   reachable by every page rather than re-typed by each. Guarded by
   `#jobstoolbar`'s own `data-mounted` rather than rebuilt every
   renderJobsPage() call the way the header and KPI row are: the search box
   filterBar re-parents is a LIVE `<input>` an operator may be mid-typing
   into, and rebuilding it from scratch every five seconds would drop
   whatever they had just typed. The pickers and buttons filterBar also
   re-parents are moved, not rebuilt -- see filterBar's own comment
   (chrome.js) on why moving an already-wired element costs it nothing. */
function mountJobsToolbar(){
  const host = $("jobstoolbar");
  if(!host || host.dataset.mounted) return;
  const bar = filterBar({
    search: $("jobsearchbox"),
    selects: [$("projpick"), $("statpick")],
    actions: [$("jf-clear"), $("bulk-all")],
  });
  host.insertBefore(bar, $("jactive"));
  host.dataset.mounted = "1";
}

/* ------------------------------------------------------------ the filters
   Repaints the pickers, the active-filter chip row and the top bulk button
   -- the same three things `paintJobFilters` (bin/dashboard.html) used to,
   against the SAME elements: `#jactive`, `#jf-clear` and `#bulk-all` are
   static markup that already exists in the page (the pickers are not
   rebuilt here, only their state; the toolbar that lays them out is built
   once by mountJobsToolbar() above, not repainted here). */
function paintJobFilterBar(vis, allJobs){
  paintJobPickers();

  const box = $("jactive");
  box.textContent = "";
  const chips = [];
  if(jobFilters.project) chips.push(["project", "Project: "
    + (jobFilters.project === "__none__" ? "Standalone" : jobFilters.project)]);
  if(jobFilters.status) chips.push(["status", "Status: " + jobFilters.status]);
  if(jobFilters.query.trim()) chips.push(["q", 'Search: "' + jobFilters.query.trim() + '"']);
  box.hidden = !chips.length;
  if(chips.length){
    box.appendChild(el("span", "aflabel", "Active filters:"));
    chips.forEach(([key, label]) => {
      const chip = el("span", "afchip");
      chip.appendChild(document.createTextNode(label));
      const drop = el("button");
      drop.dataset.dropjf = key;
      drop.title = "Remove this filter";
      drop.appendChild(icon("x"));
      chip.appendChild(drop);
      box.appendChild(chip);
    });
    box.appendChild(el("span", "aflabel", vis.length + " of " + allJobs.length + " jobs"));
  }
  $("jf-clear").hidden = !chips.length;

  // The top button acts on exactly what is on screen right now, so it can
  // never reach a job a filter has taken off-screen -- see bulkScope's own
  // "visible" case (bin/dashboard.html) for the click side of this.
  const ball = $("bulk-all");
  ball.hidden = !vis.length;
  if(vis.length){
    const on = bulkOn(vis);
    ball.dataset.bulkKind = "visible";
    ball.dataset.bulk = "__visible__";
    ball.dataset.bulkTo = on ? "0" : "1";
    // The toolbar is repainted on every poll like everything else, and this
    // switch fires toggle_many over every visible job -- see the page's own
    // `pending` for why the guard cannot live on the element.
    markIfPending(ball);
    ball.textContent = "";
    ball.appendChild(icon("power"));
    ball.appendChild(document.createTextNode(bulkLabel(on, vis.length)));
  }
}

/* --------------------------------------------------------------- the table
   Sort state and page number are this module's own -- nothing outside it
   ever needs to know which column is sorted or which page is showing, so
   neither is exposed beyond the two actions below that change them. */
let sortKey = "job", sortDir = 1, page = 1;
// Small on purpose: every install this shipped against had well under this
// many jobs, so the common case is the one the brief asked for by name --
// "Showing X to Y of N" and a pager even when there is exactly one page.
const PAGE_SIZE = 20;

export function jobsSort(key){
  if(sortKey === key) sortDir = -sortDir;
  // Names and status open A→Z / worst-first; the clock and money columns
  // open on the largest, which is the end of each you actually came to
  // look at -- same rule bin/dashboard.html's click handler used to apply.
  else { sortKey = key; sortDir = (key === "job" || key === "project" || key === "state") ? 1 : -1; }
  page = 1;
  renderJobsPage();
}

export function jobsSetPage(delta){
  page += delta;
  renderJobsPage();
}

// One row, four flat action icons and no overflow menu -- in a table the
// row already IS the list, the same reasoning renderJobTable's own comment
// gave for never hiding two of the four actions behind a kebab.
function jobRow(j, F){
  const tr = el("tr", F.disabled ? "rowoff" : null);

  const tdJob = el("td");
  const jobcell = el("span", "jobcell");
  jobcell.appendChild(icon("bot"));
  jobcell.appendChild(el("code", null, j.id));
  tdJob.appendChild(jobcell);
  if(j.description){
    const snip = el("div", "snip", j.description);
    snip.title = j.description;
    tdJob.appendChild(snip);
  }
  tr.appendChild(tdJob);

  const tdProj = el("td");
  if(j.project){
    const tag = el("span", "projtag");
    tag.appendChild(icon("folder"));
    // A bare text node cannot take its own overflow/text-overflow -- ellipsis
    // only ever applies to an ELEMENT's box, never to a text node directly,
    // and (per the CSS spec) not even to a FLEX container's own box either
    // -- .projtag is `display:inline-flex` for the icon/name alignment, so
    // the ellipsis has to live on this inner span instead (see .projtag-name,
    // ui/css/pages.css), the one flex ITEM here that is actually allowed to
    // shrink: .projtag .ic carries `flex:none` (ui/css/components.css) so a
    // long name shrinks only the name, never distorts the folder icon
    // beside it.
    tag.appendChild(el("span", "projtag-name", j.project));
    if(isFav(j.project)){
      const fav = el("span", "favdot");
      fav.title = "Favourite";
      fav.appendChild(icon("star"));
      tag.appendChild(fav);
    }
    tdProj.appendChild(tag);
  }else{
    tdProj.appendChild(el("span", "muted", "—"));
  }
  tr.appendChild(tdProj);

  const tdState = el("td");
  if(F.running){
    const badge = el("span", "runningbadge");
    badge.appendChild(el("span", "pulse"));
    badge.appendChild(document.createTextNode(F.nLive + " running…"));
    tdState.appendChild(badge);
  }else{
    // .pill.disabled for a job nobody enabled -- .pill.off is reserved for
    // the launchd service itself being down, and is red on purpose (see its
    // own comment in components.css and
    // test_the_job_disabled_pill_and_the_launchd_off_pill_use_different_classes).
    const pillCls = F.disabled ? "disabled" : (F.idle ? "idle" : "on");
    const pill = el("span", "pill " + pillCls, F.state);
    if(F.idle) pill.title = "Outside its active window — no runs until the window reopens";
    tdState.appendChild(pill);
  }
  tr.appendChild(tdState);

  const tdSched = el("td", "nowrap");
  tdSched.appendChild(el("span", "muted", "every"));
  tdSched.appendChild(document.createTextNode(" " + fmtDur(j.interval_seconds || 300)));
  if(F.backoff > 1){
    const back = el("span", "s-warning", " ×" + F.backoff);
    back.title = "Backing off after " + F.streak + " failed runs";
    tdSched.appendChild(back);
  }
  tr.appendChild(tdSched);

  const tdLast = el("td", "nowrap");
  if(F.st.last_run_start){
    const span = el("span", null, fmtAgo(F.st.last_run_start));
    span.title = fmtWhen(F.st.last_run_start);
    tdLast.appendChild(span);
  }else{
    tdLast.appendChild(el("span", "muted", "never"));
  }
  tr.appendChild(tdLast);

  const tdNext = el("td", "nowrap");
  if(F.disabled){
    tdNext.appendChild(el("span", "muted", "disabled"));
  }else if(F.nextAt == null){
    tdNext.appendChild(el("span", "muted", "no window"));
  }else{
    const span = el("span", null, fmtIn(F.nextAt));
    span.title = fmtWhen(F.nextAt);
    tdNext.appendChild(span);
  }
  tr.appendChild(tdNext);

  const tdToday = el("td", "num nowrap");
  tdToday.appendChild(document.createTextNode(money(F.spentToday)));
  if(F.cap != null){
    tdToday.appendChild(document.createTextNode(" "));
    tdToday.appendChild(el("span", "cap", "of " + money(F.cap)));
  }
  if(F.capped){
    tdToday.appendChild(document.createTextNode(" "));
    tdToday.appendChild(el("span", "s-error", "capped"));
  }
  tr.appendChild(tdToday);

  const tdActs = el("td", "rowacts");
  const run = el("button", "iconbtn");
  run.dataset.op = "run"; run.dataset.id = j.id; run.title = "Run now";
  // A sort, a page change or a keystroke rebuilds this row without going
  // through render() -- see overview.js's jobCard for the whole story.
  markIfPending(run);
  run.appendChild(icon("play"));
  tdActs.appendChild(run);

  const toggle = el("button", "iconbtn");
  toggle.dataset.op = F.disabled ? "enable" : "disable"; toggle.dataset.id = j.id;
  markIfPending(toggle);
  toggle.title = F.disabled ? "Enable" : "Disable";
  toggle.appendChild(icon("power"));
  tdActs.appendChild(toggle);

  const editBtn = el("button", "iconbtn");
  editBtn.dataset.op = "edit"; editBtn.dataset.id = j.id; editBtn.title = "Edit";
  editBtn.appendChild(icon("pencil"));
  tdActs.appendChild(editBtn);

  const del = el("button", "iconbtn danger");
  del.dataset.op = "delete"; del.dataset.id = j.id; del.title = "Delete job";
  markIfPending(del);
  del.appendChild(icon("trash"));
  tdActs.appendChild(del);

  tr.appendChild(tdActs);
  return tr;
}

function renderJobsTable(vis){
  const sorted = sortJobs(vis.map(j => ({j, F: jobFacts(j)})), sortKey, sortDir);
  const total = sorted.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  // Both ends: `.disabled` on the pager buttons is what stops an ordinary
  // click from ever pushing `page` out of range, but that is a UI gate, not
  // a floor on the number itself -- jobsSetPage(-1) called twice in a row
  // (a double-click racing the disabled state, or straight from the
  // console) must not leave `page` at 0 or below, which read as "Showing
  // -19 to 0 of 8 jobs" here before this clamp existed.
  if(page > pages) page = pages;
  if(page < 1) page = 1;
  const from = total ? (page - 1) * PAGE_SIZE + 1 : 0;
  const to = Math.min(page * PAGE_SIZE, total);
  const slice = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  let rows;
  if(!total){
    // Calls jobsEmptyNote rather than restating its two sentences -- see this
    // module's own banner comment, finding 1.
    const filtering = !!(jobFilters.project || jobFilters.status || jobFilters.query.trim());
    const tr = el("tr");
    const td = el("td", "tblempty");
    td.colSpan = JOB_COLS.length;
    td.appendChild(icon("inbox"));
    td.appendChild(document.createTextNode(jobsEmptyNote(filtering)));
    tr.appendChild(td);
    rows = [tr];
  }else{
    rows = slice.map(({j, F}) => jobRow(j, F));
  }

  const footer = tableFooter({
    shown: {from, to}, total, noun: "job", page, pages,
    prevId: "jobs-pg-prev", nextId: "jobs-pg-next", infoId: "jobs-pg-info",
  });
  const card = tableCard({
    columns: JOB_COLS, sortKey, sortDir, sortAttr: "jobsort", rows, footer,
  });

  const host = $("jobs-table");
  host.textContent = "";
  host.appendChild(card);
}

/* -------------------------------------------------------------- the mount
   bin/dashboard.html's own renderJobsArea() calls this once per poll, the
   same way render() already calls CCApp.renderOverviewHead() -- rebuilding
   the header, the KPI row and the table card whole rather than patching
   them, since none of the three is more than a handful of elements and
   none holds anything an operator could be mid-typing into. The toolbar is
   the one exception -- mountJobsToolbar() above is guarded to run once,
   not every poll, for exactly that reason. */
export function renderJobsPage(){
  mountJobsToolbar();
  const jobs = (CC.DATA.jobs || []);
  // A stale project filter (the project was renamed or deleted out from
  // under it) must not silently hide every job -- mirrors the same guard
  // bin/dashboard.html's own renderJobCards() runs for the card view, so
  // the two cannot disagree about what "Standalone" or a stale name means.
  const allProjects = [...new Set(jobs.map(j => j.project || "").filter(Boolean))].sort();
  if(jobFilters.project && jobFilters.project !== "__none__"
     && !allProjects.includes(jobFilters.project)) jobFilters.project = "";

  const vis = visibleJobs();

  const headHost = $("jobs-head");
  if(headHost){
    headHost.textContent = "";
    headHost.appendChild(pageHeader({
      icon: "zap", title: "Jobs", subtitle: jobsHeaderSubtitle(jobs),
      actions: [
        {id: "jobs-refresh", icon: "radar", label: "Refresh"},
        {id: "new-job", icon: "plus", label: "New job", primary: true},
      ],
    }));
  }

  const kpiHost = $("jobs-kpis");
  if(kpiHost){
    kpiHost.textContent = "";
    jobsKpis(jobs).forEach(c => kpiHost.appendChild(kpiCard({
      icon: KPI_ICONS[c.label], tone: c.tone, value: c.value,
      label: c.label, sub: c.sub, filter: c.filter, door: c.door,
    })));
  }

  paintJobFilterBar(vis, jobs);
  renderJobsTable(vis);
}

/* ---- drag to reorder job cards within their group ----
   Moved verbatim from bin/dashboard.html: it still drags CARDS on the
   Overview (`$("jobs")`, not this table's rows) -- see this module's own
   banner comment on why the code lives here anyway. Order lives in
   jobs.json (the engine rewrites only the dragged group's slots), so it
   survives reloads and is the order the tick walks the jobs in. */
let _dragId = null;
export function initJobDrag(){
  const host = $("jobs"); if(!host) return;
  host.addEventListener("dragstart", (e) => {
    const c = e.target.closest(".card[data-job-id]"); if(!c) return;
    _dragId = c.dataset.jobId; c.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    try{ e.dataTransfer.setData("text/plain", _dragId); }catch(_){}
  });
  host.addEventListener("dragend", () => {
    _dragId = null;
    host.querySelectorAll(".dragging,.dragover").forEach(x => x.classList.remove("dragging", "dragover"));
  });
  host.addEventListener("dragover", (e) => {
    if(!_dragId) return;
    const over = e.target.closest(".card[data-job-id]");
    const from = host.querySelector('.card[data-job-id="' + CSS.escape(_dragId) + '"]');
    // Only within the same group: reordering is per project, never across.
    if(!over || !from || over === from || over.closest(".grid") !== from.closest(".grid")) return;
    e.preventDefault(); e.dataTransfer.dropEffect = "move";
    host.querySelectorAll(".dragover").forEach(x => x.classList.remove("dragover"));
    over.classList.add("dragover");
  });
  host.addEventListener("drop", async (e) => {
    const over = e.target.closest(".card[data-job-id]");
    const from = _dragId && host.querySelector('.card[data-job-id="' + CSS.escape(_dragId) + '"]');
    if(!over || !from || over === from || over.closest(".grid") !== from.closest(".grid")) return;
    e.preventDefault();
    const grid = over.closest(".grid");
    // Insert before or after, depending on which way the card was dragged.
    const cards = [...grid.querySelectorAll(".card[data-job-id]")];
    grid.insertBefore(from, cards.indexOf(from) < cards.indexOf(over) ? over.nextSibling : over);
    over.classList.remove("dragover");
    const order = [...grid.querySelectorAll(".card[data-job-id]")].map(c => c.dataset.jobId);
    _dragId = null;
    const r = await fetch("/api/action", {method: "POST",
      headers: {"Content-Type": "text/plain", "X-CC-Token": TOKEN},
      body: JSON.stringify({op: "reorder", order})});
    if(!r.ok){ const j = await r.json().catch(() => ({})); toast("Could not save the order — " + (j.error || ("HTTP " + r.status)), true); }
    else toast("Order saved", false, "check");
    refresh();
  });
}
