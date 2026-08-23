/* ---------------------------------------------------------------- projects

   visibleProjects() and the isolation read are the two pieces Phase 2 Task 4's
   characterisation tests need without a DOM -- moved here verbatim from
   bin/dashboard.html's module-level visibleProjects() and the isolation
   ternary renderProjects() used to build inline, the same "extract the pure
   arithmetic first, move the table around it later" split Task 2 already
   used for the Jobs table (see jobs-domain.js's own banner comment).

   Task 5 builds the restyled page around them: a page header, four KPI
   cards, the same search box repainted rather than rebuilt, and a table
   card with a real pager -- the same shape jobs-table.js already gave the
   Jobs page, reached through the same chrome.js builders. */
import { CC, $, icon, isFav, fmtWhen } from "./page.js";
import { el, pageHeader, kpiCard, filterBar, tableCard, tableFooter } from "./chrome.js";

export const projFilters = { query: "" };

// The set Projects is showing right now -- every project, annotated with the
// job count and repo count its own row needs, filtered by the search box.
// `_jobs` counts only jobs that name THIS project: counting every job
// regardless of project is Task 4's own named break -- a project with none
// of its own would otherwise inherit a count that belongs to the whole
// fleet. The search reaches the name, the description AND the working
// directory -- a project remembered by its folder, or by a phrase in its
// own description, has to surface just as reliably as one matched by name.
export function visibleProjects(){
  const jobs = CC.DATA.jobs || [];
  const q = projFilters.query.trim().toLowerCase();
  return (CC.DATA.projects || [])
    .map(p => Object.assign({}, p, {_jobs: jobs.filter(j => j.project === p.name).length,
                                     _repos: (p.repos || []).length}))
    .filter(p => !q || (p.name + " " + (p.description || "") + " " + (p.cwd || ""))
      .toLowerCase().includes(q));
}

// Three states, not two: a project can run every job in its own worktree
// (`true`), never (`false`), or leave it to the engine to decide per job --
// "automatic", which is also what a project with no `worktree` block at all
// gets, and what a hand-edited config's literal string "auto" gets too (see
// config/projects.json). Collapsing "automatic" into either of the other two
// is Task 4's own named break: an "auto" project is not permanently isolated
// OR permanently not, and painting it as either would tell an operator
// something the engine does not actually do with it.
export function projectIsolation(p){
  const wt = p.worktree && p.worktree.enabled;
  return (wt === true || wt === "true") ? ["on", "always"]
       : (wt === false || wt === "false") ? ["off", "never"]
       : ["auto", "auto"];
}

/* ------------------------------------------------------- the Security column

   The only new information this whole phase adds, and the one place the
   plan itself warns "if something goes wrong, it is here" -- so this reads
   only what the page can actually stand behind, in two steps:

   1. `p.security` -- the raw block `/api/config` already carries for every
      project (`CFG.projects[].security`, read straight off
      config/projects.json). It says whether analysis is turned ON and
      names its knobs (model, effort, budgets, permission mode) -- nothing
      about what any analysis found. That verdict lives in `data/security.db`,
      reachable only through `GET /api/security/index`, which shells out to
      the CLI's `index-data` command on every call -- exactly the per-call
      subprocess cost the Security index screen itself was rewritten to stop
      paying (see its own banner comment). Projects' 5-second poll has no
      business calling it, so this column does not.

   2. `DATA.runs` -- already fetched every poll for every other page, and it
      DOES carry the derived "security-<slug>" job's own run history: an
      analysis is `run_job` under the hood (bin/claude-cron), and the
      derived job element `security_derived_jobs` builds sets `project` to
      the real project name explicitly, so a run's own `project` field
      names this row correctly without reimplementing the engine's slugging
      here (`String(r.id).startsWith("security-")` mirrors the one existing
      client-side check of the same shape, in bin/dashboard.html's own Runs
      table). This is enough to tell "never analysed" apart from "analysed
      at least once" honestly, with data the page already has in hand.

   What this deliberately does NOT do: read a completed run's own `status`
   as a stand-in for posture. Checked against the real ledger behind this
   branch, a project's most recent analysis run said "success" while the
   analysis itself had recorded 6 high and 33 medium findings -- "the run
   finished cleanly" and "nothing was found" are not the same fact, and
   showing one as the other would be this page's own version of the error
   the Security area already paid for once: absence (of a crash) read as
   proof (of a clean bill of health). So the "analysed" state says exactly
   that -- analysed, and when -- and nothing about what it found. Seeing the
   actual posture still means opening the Security area, which already
   knows how to ask for it. */
export function projectSecurity(p){
  const sec = p.security;
  const enabled = !!(sec && typeof sec === "object" && (sec.enabled === true || sec.enabled === "true"));
  if(!enabled) return {state: "disabled", cls: "disabled", label: "Disabled"};
  const runs = (CC.DATA.runs || []).filter(r =>
    r.project === p.name && String(r.id || "").startsWith("security-"));
  if(!runs.length) return {state: "unanalysed", cls: "idle", label: "Never analysed"};
  const last = runs.reduce((a, b) => (a.start > b.start ? a : b));
  return {state: "analysed", cls: "on", label: "Analysed", lastAt: last.start};
}

/* ------------------------------------------------------------------ the KPIs
   Four numbers this page already knows without a new fetch, each paired
   with a second one from the same set rather than restating the first --
   the same rule jobsKpis (ui/app/jobs-table.js) follows. None is a door:
   there is no project-scoped filter elsewhere on this page for one of these
   cards to lead into, the same reasoning that keeps all four of Jobs' own
   cards `door: false`. */
function projectsKpis(rows){
  const total = rows.length;
  const withJobs = rows.filter(p => p._jobs > 0).length;
  const jobsTotal = rows.reduce((a, p) => a + p._jobs, 0);
  const secStates = rows.map(p => projectSecurity(p).state);
  const secEnabled = secStates.filter(s => s !== "disabled").length;
  const secAnalysed = secStates.filter(s => s === "analysed").length;
  const isoStates = rows.map(p => projectIsolation(p)[0]);
  const isolated = isoStates.filter(s => s === "on").length;
  const neverIsolated = isoStates.filter(s => s === "off").length;

  return [
    {label: "Projects", value: String(total),
     sub: !total ? "none configured yet"
        : (total - withJobs) ? (total - withJobs) + " with no jobs of their own"
        : "every one has a job",
     tone: "", filter: "", door: false},
    {label: "Jobs organised", value: String(jobsTotal),
     sub: total ? (jobsTotal / total).toFixed(1) + " per project" : "no projects yet",
     tone: "", filter: "", door: false},
    {label: "Security enabled", value: String(secEnabled),
     sub: !secEnabled ? "none turned on yet" : secAnalysed + " analysed at least once",
     tone: "", filter: "", door: false},
    {label: "Isolated", value: String(isolated),
     sub: neverIsolated ? neverIsolated + " never isolate" : "none set to never",
     tone: "", filter: "", door: false},
  ];
}

const KPI_ICONS = {"Projects": "folder", "Jobs organised": "layers",
                   "Security enabled": "shield", "Isolated": "cpu"};

// One sentence, written from the real numbers -- the same rule
// jobsHeaderSubtitle (ui/app/jobs-table.js) follows for its own page.
function projectsHeaderSubtitle(rows){
  if(!rows.length) return "Nothing configured yet — a project gives a group of jobs somewhere to inherit from.";
  const n = rows.length;
  const withJobs = rows.filter(p => p._jobs > 0).length;
  const secOn = rows.filter(p => projectSecurity(p).state !== "disabled").length;
  const jobsPart = withJobs === n ? ", every one with jobs of its own"
                 : withJobs ? ", " + withJobs + " with jobs of their own"
                 : ", none with jobs of their own yet";
  const secPart = secOn ? ", " + secOn + " with security enabled" : "";
  return n + " project" + (n === 1 ? "" : "s") + jobsPart + secPart + ".";
}

/* ------------------------------------------------------------- the toolbar
   Assembled once, not on every poll -- the same "move the live search input,
   never rebuild it" reasoning mountJobsToolbar (jobs-table.js) states in
   full. Projects has one filter today (the search box) and no dropdowns, so
   there is nothing else for filterBar to lay out; `new-project` moved into
   the page header's own actions instead of staying a toolbar button, the
   same move `new-job` already made when the Jobs page grew a header. */
function mountProjectsToolbar(){
  const host = $("prjtoolbar");
  if(!host || host.dataset.mounted) return;
  const bar = filterBar({search: $("projsearchbox")});
  host.appendChild(bar);
  host.dataset.mounted = "1";
}

// "No projects yet" and "no projects match this search" are two different
// facts -- the same distinction jobsEmptyNote (ui/app/overview.js) already
// draws for Jobs, restated here rather than shared: this predicate is the
// query alone, unlike jobsEmptyNote's `project || status || query`.
function projectsEmptyNote(filtering){
  return filtering ? "No projects match that search."
                    : "No projects yet — a job does not need one, but jobs that share a repo do.";
}

/* --------------------------------------------------------------- the table
   Sort state and page number are this module's own, the same split
   jobs-table.js keeps for the identical reason: nothing outside this file
   ever needs to know which column is sorted or which page is showing. */
export const PRJ_COLS = [
  ["name", "Project"], ["jobs", "Jobs"], [null, "Working directory"],
  ["repos", "Repos"], [null, "Isolation"], [null, "Security"], [null, ""],
];
const PRJ_SORTERS = {
  name: {cmp: (a, b) => String(a.name).localeCompare(String(b.name))},
  jobs: {cmp: (a, b) => a._jobs - b._jobs,
         tie: (a, b) => String(a.name).localeCompare(String(b.name))},
  repos: {cmp: (a, b) => a._repos - b._repos,
          tie: (a, b) => String(a.name).localeCompare(String(b.name))},
};
let sortKey = "name", sortDir = 1, page = 1;
const PAGE_SIZE = 20;

export function projectsSort(key){
  if(sortKey === key) sortDir = -sortDir;
  // Same rule the old click handler applied: the name column opens A→Z, the
  // two numeric columns open on the largest value first.
  else { sortKey = key; sortDir = (key === "name") ? 1 : -1; }
  page = 1;
  renderProjectsPage();
}

export function projectsSetPage(delta){
  page += delta;
  renderProjectsPage();
}

function projectRow(p){
  const tr = el("tr");

  const tdName = el("td");
  const cell = el("span", "jobcell");
  cell.appendChild(icon("folder"));
  cell.appendChild(el("b", null, p.name));
  const fav = isFav(p.name);
  const favBtn = el("button", "favstar" + (fav ? " on" : ""));
  favBtn.dataset.fav = p.name;
  favBtn.setAttribute("aria-pressed", fav ? "true" : "false");
  favBtn.title = fav ? "Remove from favourites" : "Favourite — keeps this project at the top of Jobs";
  favBtn.appendChild(icon("star"));
  cell.appendChild(favBtn);
  tdName.appendChild(cell);
  if(p.description){
    const snip = el("div", "snip", p.description);
    snip.title = p.description;
    tdName.appendChild(snip);
  }
  tr.appendChild(tdName);

  tr.appendChild(el("td", "num nowrap", String(p._jobs)));

  const tdCwd = el("td");
  if(p.cwd){
    const code = el("code", "pathcell", p.cwd);
    code.title = p.cwd;
    tdCwd.appendChild(code);
  }else{
    tdCwd.appendChild(el("span", "muted", "—"));
  }
  tr.appendChild(tdCwd);

  const tdRepos = el("td", "nowrap");
  if(p._repos) tdRepos.appendChild(document.createTextNode(p._repos + " repo" + (p._repos === 1 ? "" : "s")));
  else tdRepos.appendChild(el("span", "muted", "single"));
  tr.appendChild(tdRepos);

  const tdIso = el("td", "nowrap");
  const iso = projectIsolation(p);
  tdIso.appendChild(el("span", "isopill " + iso[0], iso[1]));
  tr.appendChild(tdIso);

  const tdSec = el("td", "nowrap");
  const sec = projectSecurity(p);
  const pill = el("span", "pill " + sec.cls, sec.label);
  // Only the analysed state has a timestamp to show -- "disabled" and
  // "never analysed" both have nothing further to say, on purpose (see this
  // file's own comment above projectSecurity on why no severity is here).
  if(sec.state === "analysed") pill.title = "Last analysed " + fmtWhen(sec.lastAt);
  tdSec.appendChild(pill);
  tr.appendChild(tdSec);

  const tdActs = el("td", "rowacts");
  const editBtn = el("button", "iconbtn");
  editBtn.dataset.editproj = p.name;
  editBtn.title = "Edit project";
  editBtn.appendChild(icon("pencil"));
  tdActs.appendChild(editBtn);
  const delBtn = el("button", "iconbtn danger");
  delBtn.dataset.delproj = p.name;
  delBtn.title = "Delete project";
  delBtn.appendChild(icon("trash"));
  tdActs.appendChild(delBtn);
  tr.appendChild(tdActs);

  return tr;
}

function renderProjectsTable(vis){
  const S = PRJ_SORTERS[sortKey] || PRJ_SORTERS.name;
  const sorted = [...vis].sort((a, b) => (S.cmp(a, b) * sortDir) || (S.tie ? S.tie(a, b) : 0));
  const total = sorted.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  // Both ends, same clamp jobs-table.js's own renderJobsTable applies: a
  // filter that shrinks the set must not leave `page` pointing past the end.
  if(page > pages) page = pages;
  if(page < 1) page = 1;
  const from = total ? (page - 1) * PAGE_SIZE + 1 : 0;
  const to = Math.min(page * PAGE_SIZE, total);
  const slice = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  let rows;
  if(!total){
    const filtering = !!projFilters.query.trim();
    const tr = el("tr");
    const td = el("td", "tblempty");
    td.colSpan = PRJ_COLS.length;
    td.appendChild(icon("inbox"));
    td.appendChild(document.createTextNode(projectsEmptyNote(filtering)));
    tr.appendChild(td);
    rows = [tr];
  }else{
    rows = slice.map(p => projectRow(p));
  }

  const footer = tableFooter({
    shown: {from, to}, total, noun: "project", page, pages,
    prevId: "prj-pg-prev", nextId: "prj-pg-next", infoId: "prj-pg-info",
  });
  const card = tableCard({
    columns: PRJ_COLS, sortKey, sortDir, sortAttr: "prjsort", rows, footer,
  });

  const host = $("prj-table");
  host.textContent = "";
  host.appendChild(card);
}

/* -------------------------------------------------------------- the mount
   Called once per poll from bin/dashboard.html's render(), the same way it
   already calls CCApp.renderJobsPage(). Unlike the old renderProjects(),
   this carries no ".menu-pop" redraw guard: that guard belongs to the job
   CARD's own kebab menu (renderOverviewJobs), and the Jobs table's own
   restyle (Task 3) already dropped it for the identical reason -- a table
   row's actions here are two flat icon buttons, never a popover this redraw
   could yank out from under an open menu. */
export function renderProjectsPage(){
  mountProjectsToolbar();
  const rows = visibleProjects();

  const headHost = $("prj-head");
  if(headHost){
    headHost.textContent = "";
    headHost.appendChild(pageHeader({
      icon: "folder", title: "Projects", subtitle: projectsHeaderSubtitle(rows),
      actions: [{id: "new-project", icon: "plus", label: "New project", primary: true}],
    }));
  }

  const kpiHost = $("prj-kpis");
  if(kpiHost){
    kpiHost.textContent = "";
    projectsKpis(rows).forEach(c => kpiHost.appendChild(kpiCard({
      icon: KPI_ICONS[c.label], tone: c.tone, value: c.value,
      label: c.label, sub: c.sub, filter: c.filter, door: c.door,
    })));
  }

  $("pq-clear").hidden = !projFilters.query;
  renderProjectsTable(rows);
}
