/* What the page calls into. Mirrors ui/security/index.js: this file is
   evaluated BEFORE the page's own script (see the tag's comment in
   dashboard.html), so it only DEFINES -- no DOM is touched and nothing is
   read off the page until init() runs.

   Beyond init(), the surface is every export of jobs-domain.js the PAGE's own
   surviving code still calls: renderJobTable, bulkBtn, bulkScope, renderJobs,
   paintJobFilters and initPickers all read this domain today and stayed
   behind because they draw the Jobs table -- the second consumer a later
   phase adds, not this one. A page that could no longer reach jobFacts,
   visibleJobs, bulkOn, bulkLabel, clearJobFilters or jobProjectNames would
   not fail loudly; it would throw the first time a 5-second poll tried to
   redraw.

   overview.js's exports are the same deal for pulseHtml, helloHtml, jobCard
   and renderJobCards: the arithmetic, the wording and the markup itself all
   moved here, and the page calls back in by name instead of building any of
   it inline. jobCard (Task 9) is the last of the four -- checkList and the
   kept-session notice moved with it as jobCard's own internal helpers, and
   renderJobCards's grouping chrome (project headers, the star, the bulk
   button) stayed in the page, since it builds markup from strings the page
   chooses itself rather than from a job's own fields. */
import { bindPage } from "./page.js";
import { jobFacts, visibleJobs, jobFilters, bulkOn, bulkLabel,
         clearJobFilters, jobProjectNames } from "./jobs-domain.js";
import { pulseKpis, bandEmptyReason, probeVerdict, spendTone, groupJobs,
         jobsEmptyNote, nextRunNote, pageHeader, kpiCard, renderPulse,
         renderOverviewHead, jobCard } from "./overview.js";

function init(cc){
  bindPage(cc);
}

window.CCApp = { init, jobFacts, visibleJobs, jobFilters, bulkOn,
                 bulkLabel, clearJobFilters, jobProjectNames,
                 pulseKpis, bandEmptyReason, probeVerdict, spendTone,
                 groupJobs, jobsEmptyNote, nextRunNote,
                 // pageHeader/kpiCard/renderPulse are exported for Phases 2
                 // and 3, which put a page header and KPI cards on every
                 // remaining page -- renderOverviewHead is the only one of
                 // the four this phase's own call site (bin/dashboard.html's
                 // render()) actually calls.
                 pageHeader, kpiCard, renderPulse, renderOverviewHead,
                 // jobCard is Task 9's: renderJobs() in bin/dashboard.html
                 // calls CCApp.jobCard(j) per job instead of building the
                 // card as an HTML string. checkList and the kept-session
                 // notice are internal to jobCard and have no other caller,
                 // so they stay unexported, the same shape as el() above.
                 jobCard };
