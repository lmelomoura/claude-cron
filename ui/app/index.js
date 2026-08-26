/* What the page calls into. Mirrors ui/security/index.js: this file is
   evaluated BEFORE the page's own script (see the tag's comment in
   dashboard.html), so it only DEFINES -- no DOM is touched and nothing is
   read off the page until init() runs.

   Beyond init(), the surface is every export of jobs-domain.js the PAGE's own
   surviving code still calls: renderJobTable, bulkBtn, bulkScope, renderJobs,
   paintJobFilters and initPickers all read this domain today and stayed
   behind because they draw the Jobs table -- the second consumer a later
   phase adds, not this one. A page that could no longer reach visibleJobs,
   bulkOn, bulkLabel, clearJobFilters, jobProjectNames, sortJobs or JOB_COLS
   would not fail loudly; it would throw the first time a 5-second poll
   tried to redraw. jobFacts is jobs-domain.js's own export too, but reached
   only by ES import inside this bundle (overview.js, jobs-table.js) -- the
   page itself never calls CCApp.jobFacts(), so it does not belong on this
   list or on window.CCApp below.

   overview.js's exports are the same deal for what pulseHtml, helloHtml and
   renderJobCards used to build: the arithmetic, the wording and the markup
   itself all moved here (pulseHtml as pulseKpis/renderPulse, helloHtml as
   greetingParts/pageHeader, both mounted together by renderOverviewHead;
   renderJobCards's per-card markup as jobCard), and the page calls back in
   by name instead of building any of it inline. jobCard (Task 9) was the
   last to move -- checkList and the kept-session notice moved with it as
   jobCard's own internal helpers, and renderJobCards's own grouping chrome
   (project headers, the star, the bulk button) stayed in the page as
   renderJobs, since it builds markup from strings the page chooses itself
   rather than from a job's own fields. */
import { bindPage } from "./page.js";
import { visibleJobs, jobFilters, bulkOn, bulkLabel,
         clearJobFilters, jobProjectNames, sortJobs, JOB_COLS } from "./jobs-domain.js";
import { groupJobs, jobsEmptyNote, worktreesCard,
         renderOverviewHead, jobCard } from "./overview.js";
import { renderJobsPage, jobsSort, jobsSetPage, initJobDrag } from "./jobs-table.js";
import { visibleProjects, projFilters, projectIsolation,
         renderProjectsPage, projectsSort, projectsSetPage } from "./projects.js";
import { RF, renderRunsPage, runsSort, runsSetPage,
         runsFilterChanged, runsGotoFirstPage, runsSetPageSize, runsPageSize,
         clearRunFilters, runSearch, runProjectNames } from "./runs.js";

function init(cc){
  bindPage(cc);
}

// pulseKpis, bandEmptyReason, probeVerdict, spendTone and nextRunNote are
// NOT re-exported here, even though overview.js exports all five: Tasks 8
// and 9 made every one of them internal the moment renderOverviewHead and
// jobCard moved into the same module and started calling them by their bare
// name. Nothing outside overview.js -- not bin/dashboard.html, not a test --
// has ever called CCApp.pulseKpis() or any of the other four; the
// characterisation tests that pin their behaviour read the function's own
// source text out of the built bundle (`_app_js` + `_plainfn` in
// tests/test_page_contract.py), never this global. Putting them on
// window.CCApp would be a second, unused way to reach code the page never
// asks for that way -- see this file's own history for the four that WERE
// carried here for a stated future and then never trimmed once that future
// landed inside the module instead.
window.CCApp = { init, visibleJobs, jobFilters, bulkOn,
                 bulkLabel, clearJobFilters, jobProjectNames,
                 // sortJobs and JOB_COLS are Task 2 (phase 2)'s: renderJobTable
                 // and renderJobHead in bin/dashboard.html call CCApp.sortJobs
                 // and read CCApp.JOB_COLS instead of keeping their own copies,
                 // the same "table is the second consumer" reach visibleJobs
                 // already has above.
                 sortJobs, JOB_COLS,
                 groupJobs, jobsEmptyNote, worktreesCard,
                 // pageHeader, kpiCard and renderPulse (all three from
                 // ./chrome.js and ./overview.js) used to sit here for a
                 // stated future -- Jobs and Runs had a header of their own
                 // but no KPI row and no 24h band, and CCApp.
                 // renderOverviewHead's own two DOM builders were what the
                 // day either grew one would reach for. That future landed
                 // differently: Jobs, Runs and Projects all grew their own
                 // KPI row this phase (jobsKpis/runsKpis/projectsKpis, each
                 // calling kpiCard() by a direct ES import inside its own
                 // module, never through this global), and
                 // bin/dashboard.html's initPageHeaders() -- pageHeader's
                 // one and only caller -- is gone: boot order meant its
                 // static Runs header was always overwritten by
                 // CCApp.renderRunsPage() before a frame painted, and the
                 // two disagreed besides. Grepped for CCApp.pageHeader,
                 // CCApp.kpiCard and CCApp.renderPulse across bin/ and
                 // tests/ before removing them -- zero readers of any of
                 // the three. renderOverviewHead remains the only one of
                 // the four this phase's own call site (bin/dashboard.html's
                 // render()) actually calls itself.
                 renderOverviewHead,
                 // jobCard is Task 9's: renderJobCards() in bin/dashboard.html
                 // (the Overview's own cards, what used to be inside
                 // renderJobs() before the Jobs table forked off it) calls
                 // CCApp.jobCard(j) per job instead of building the card as
                 // an HTML string. checkList and the kept-session notice are
                 // internal to jobCard and have no other caller, so they
                 // stay unexported, the same shape as el() above.
                 jobCard,
                 // renderJobsPage, jobsSort, jobsSetPage and initJobDrag are
                 // Phase 2 Task 3's: the Jobs table itself, moved whole out
                 // of bin/dashboard.html (renderJobTable/renderJobHead/
                 // paintJobFilters and the table branch that used to live
                 // inside renderJobs()) into ui/app/jobs-table.js.
                 // renderJobsArea() (bin/dashboard.html) calls
                 // CCApp.renderJobsPage() once per poll, the same way it
                 // calls renderJobCards() for the Overview's own cards; the
                 // page's delegated click listener calls CCApp.jobsSort(key)
                 // for a sortable header and CCApp.jobsSetPage(delta) for
                 // the footer's pager instead of keeping jobSortKey/
                 // jobSortDir/page as its own module state.
                 renderJobsPage, jobsSort, jobsSetPage, initJobDrag,
                 // visibleProjects, projFilters and projectIsolation are
                 // Phase 2 Task 4's: the search box's input/clear handlers
                 // read and write CCApp.projFilters.query instead of a
                 // module-level prjQuery -- the same "table is the second
                 // consumer" reach sortJobs/JOB_COLS already have above.
                 visibleProjects, projFilters, projectIsolation,
                 // renderProjectsPage, projectsSort and projectsSetPage are
                 // Phase 2 Task 5's: the Projects table itself, moved whole
                 // out of bin/dashboard.html's renderProjects() into
                 // ui/app/projects.js, the same move jobs-table.js already
                 // made for Jobs. render() (bin/dashboard.html) calls
                 // CCApp.renderProjectsPage() once per poll; the page's
                 // delegated click listener calls CCApp.projectsSort(key)
                 // for a sortable header and CCApp.projectsSetPage(delta)
                 // for the footer's pager, instead of keeping
                 // prjSortKey/prjSortDir/page as its own module state.
                 renderProjectsPage, projectsSort, projectsSetPage,
                 // filteredRuns (Phase 2 Task 6) and SORTERS both stay
                 // internal to ui/app/runs.js's own exports now that Task 7
                 // gave the rest of the table a home beside it: nothing in
                 // bin/dashboard.html or a test has ever called
                 // CCApp.filteredRuns() -- the characterisation tests that
                 // pin its behaviour read the function's own source text
                 // out of the built bundle (`_app_js` + `_plainfn` in
                 // tests/test_page_contract.py), the same as pulseKpis and
                 // its neighbours above, so it does not belong on
                 // window.CCApp either.
                 // RF, renderRunsPage, runsSort, runsSetPage,
                 // runsFilterChanged, runsGotoFirstPage, runsSetPageSize,
                 // runsPageSize, clearRunFilters, runSearch and
                 // runProjectNames are Phase 2 Task 7's: the Runs table
                 // itself, moved whole out of bin/dashboard.html
                 // (renderRunHead/renderRuns/paintRunFilters/runSearch/
                 // clearRunFilters and the four pickers' own onPick bodies)
                 // into ui/app/runs.js, the same move jobs-table.js and
                 // projects.js already made for their own tables. RF is a
                 // single exported object rather than five module-level
                 // `let`s for the same reason jobFilters/projFilters are:
                 // the four Runs pickers' own onPick callbacks (still in
                 // bin/dashboard.html, since they are page-owned stateful
                 // widgets) read and write CCApp.RF.project/job/status/
                 // from/to directly. render() (bin/dashboard.html) calls
                 // CCApp.renderRunsPage() once per poll; the page's
                 // delegated click listener calls CCApp.runsSort(key) for a
                 // sortable header and CCApp.runsSetPage(delta) for the
                 // footer's pager; runsFilterChanged/runsGotoFirstPage are
                 // the two shapes every filter change needs (one that also
                 // redraws, one that does not because a view switch is about
                 // to); runsSetPageSize/runsPageSize back the per-page
                 // `<select>`; clearRunFilters and runSearch are `#f-clear`'s
                 // and the search box's own click/input handlers.
                 RF, renderRunsPage, runsSort, runsSetPage, runsFilterChanged,
                 runsGotoFirstPage, runsSetPageSize, runsPageSize,
                 clearRunFilters, runSearch, runProjectNames };
