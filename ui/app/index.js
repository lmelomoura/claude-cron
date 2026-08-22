/* What the page calls into. Mirrors ui/security/index.js: this file is
   evaluated BEFORE the page's own script (see the tag's comment in
   dashboard.html), so it only DEFINES -- no DOM is touched and nothing is
   read off the page until init() runs.

   Beyond init(), the surface is every export of jobs-domain.js the PAGE's own
   surviving code still calls: jobCard, renderJobTable, bulkBtn, bulkScope,
   renderJobs, paintJobFilters and initPickers all read this domain today and
   stayed behind because they draw the Overview's cards or the Jobs table --
   the second consumer a later phase adds, not this one. A page that could no
   longer reach jobFacts, visibleJobs, bulkOn, bulkLabel, clearJobFilters or
   jobProjectNames would not fail loudly; it would throw the first time a
   5-second poll tried to redraw.

   overview.js's exports are the same deal for pulseHtml, helloHtml, jobCard
   and renderJobCards: the arithmetic, the wording and (as of the page header
   and the five KPI cards) the markup itself all moved here, and the page
   calls back in by name instead of building any of it inline. jobCard and
   renderJobCards are still to come -- Task 9 rewrites those the same way. */
import { bindPage } from "./page.js";
import { jobFacts, visibleJobs, jobFilters, bulkOn, bulkLabel,
         clearJobFilters, jobProjectNames } from "./jobs-domain.js";
import { pulseKpis, bandEmptyReason, probeVerdict, spendTone, groupJobs,
         jobsEmptyNote, nextRunNote, pageHeader, kpiCard, renderPulse,
         renderOverviewHead } from "./overview.js";

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
                 pageHeader, kpiCard, renderPulse, renderOverviewHead };
