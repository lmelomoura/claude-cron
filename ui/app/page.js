/* Everything the app's own screens are given by the page they live in.

   The same contract ui/security/page.js states, for the same reason: out here
   the page's scope is gone, and a stated interface beats a handful of reads
   off `window`. A name that is not in this list does not exist, and a missing
   one fails at bind time rather than as `undefined is not a function` three
   screens in.

   Two files rather than one shared page.js: the Security area's interface is
   settled and this one will grow through phases 2 and 3, and a single file
   would make every addition here a reason to re-read that one. They may be
   merged once both stop moving.

   backoffMultiplier, activeRunsOf and renderJobs are here alongside the names
   the plan for this phase named explicitly: jobFacts reads the first two, and
   clearJobFilters calls the third, exactly as they did inside the page's own
   script. Leaving them off this list would not remove the dependency, only
   hide it until the first `ReferenceError` -- and duplicating either helper
   into this module instead is the drifting-vocabulary defect this branch has
   already paid for twice.

   effortLabel, fmtExpiresIn and resumeInFlight join the list for the same
   reason, added when the job card moved into this module (Task 9): the
   card's config line reads the first, its kept-session notice the other two,
   and each already has exactly one implementation in the page's own script
   -- fmtExpiresIn also feeds the Sessions dialog, resumeInFlight also guards
   resumeTarget's live-slot branch, so a second copy here would be the same
   drift the paragraph above already paid for.

   fmtWhen, fmtIn, isFav, TOKEN, toast, refresh and paintJobPickers joined
   when the Jobs table moved into this module (Phase 2 Task 3): the table's
   own cells read the first two for their tooltips and their "next" column,
   isFav for the same favourite-project star the job card already shows,
   and initJobDrag -- job-domain code that moved into the same module even
   though it still drags CARDS on the Overview, not this table's rows --
   reads TOKEN, toast and refresh for its own save-then-refresh round trip.
   paintJobPickers is not a page global at all: it is a small wrapper
   bin/dashboard.html defines purely to hand over `projPicker.paint()` and
   `jobStatusPicker.paint()` without handing over the picker objects
   themselves, which also paint the four Runs pickers this same
   `initPickers()` builds and are not this module's to own.

   normStatus joins the list for the Runs table's own sake (Phase 2 Task 6):
   the page's one implementation (`s==="ok"?"success":(s||"—")`) normalises a
   run's stored status for the log modal, the resume tooltip AND the Runs
   table's own sort -- ui/app/runs.js's SORTERS.status reads it rather than
   keeping a second copy, the same "one implementation, reached from every
   caller" rule eff/backoffMultiplier/activeRunsOf already followed above.

   esc, iconLabel, openLog, openEditor and setView still are not exported:
   nothing under ui/app/ calls any of them. api is not either -- the module's
   own network calls (initJobDrag's reorder) go through a plain `fetch` the
   same way the page's own `api()` wraps one, since bulkToggle/showConfirm's
   confirmation dialog stays behind in the page for the one caller
   (bulkToggle) that still needs it. */
export let $, fmtAgo, fmtDur, money,
           icon, projById, eff,
           backoffMultiplier, activeRunsOf, renderJobs,
           effortLabel, fmtExpiresIn, resumeInFlight,
           fmtWhen, fmtIn, isFav, TOKEN, toast, refresh, paintJobPickers,
           normStatus;

/* DATA and currentView are REASSIGNED by the page -- DATA on every five-second
   poll, currentView on every navigation. Destructured they would freeze at
   whatever they held when init() ran. Read through the object, live, and the
   different spelling is the reminder that they move under you. */
export let CC = null;

export function bindPage(cc){
  CC = cc;
  ({ $, fmtAgo, fmtDur, money,
     icon, projById, eff,
     backoffMultiplier, activeRunsOf, renderJobs,
     effortLabel, fmtExpiresIn, resumeInFlight,
     fmtWhen, fmtIn, isFav, TOKEN, toast, refresh, paintJobPickers,
     normStatus } = cc);
}
