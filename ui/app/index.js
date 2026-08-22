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
   5-second poll tried to redraw. */
import { bindPage } from "./page.js";
import { jobFacts, visibleJobs, jobFilters, bulkOn, bulkLabel,
         clearJobFilters, jobProjectNames } from "./jobs-domain.js";

function init(cc){
  bindPage(cc);
}

window.CCApp = { init, jobFacts, visibleJobs, jobFilters, bulkOn,
                 bulkLabel, clearJobFilters, jobProjectNames };
