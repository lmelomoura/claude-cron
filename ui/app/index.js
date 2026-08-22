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
import { jobFacts, visibleJobs, jobFilters, bulkOn, bulkLabel,
         clearJobFilters, jobProjectNames } from "./jobs-domain.js";
import { groupJobs, jobsEmptyNote, worktreesCard, pageHeader, kpiCard,
         renderPulse, renderOverviewHead, jobCard } from "./overview.js";

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
window.CCApp = { init, jobFacts, visibleJobs, jobFilters, bulkOn,
                 bulkLabel, clearJobFilters, jobProjectNames,
                 groupJobs, jobsEmptyNote, worktreesCard,
                 // pageHeader already has a second caller today, not a
                 // future one: bin/dashboard.html's initPageHeaders() calls
                 // CCApp.pageHeader() for the Jobs and Runs pages' own
                 // headers, in this same phase. kpiCard and renderPulse are
                 // the two still genuinely waiting -- Jobs and Runs have a
                 // header now but no KPI row and no 24h band of their own,
                 // and CCApp.renderOverviewHead's own two DOM builders are
                 // exactly what the day one of them grows either will reach
                 // for, the same way initPageHeaders reached for pageHeader.
                 // renderOverviewHead remains the only one of the four this
                 // phase's own call site (bin/dashboard.html's render())
                 // actually calls itself.
                 pageHeader, kpiCard, renderPulse, renderOverviewHead,
                 // jobCard is Task 9's: renderJobs() in bin/dashboard.html
                 // calls CCApp.jobCard(j) per job instead of building the
                 // card as an HTML string. checkList and the kept-session
                 // notice are internal to jobCard and have no other caller,
                 // so they stay unexported, the same shape as el() above.
                 jobCard };
