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
   -- fmtExpiresIn also feeds the Sessions tab, resumeInFlight also guards
   resumeTarget's live-slot branch, so a second copy here would be the same
   drift the paragraph above already paid for. */
export let $, TOKEN, api, toast, esc, fmtAgo, fmtWhen, fmtDur, fmtIn, money,
           icon, iconLabel, openLog, openEditor, projById, isFav, eff, setView,
           backoffMultiplier, activeRunsOf, renderJobs,
           effortLabel, fmtExpiresIn, resumeInFlight;

/* DATA and currentView are REASSIGNED by the page -- DATA on every five-second
   poll, currentView on every navigation. Destructured they would freeze at
   whatever they held when init() ran. Read through the object, live, and the
   different spelling is the reminder that they move under you. */
export let CC = null;

export function bindPage(cc){
  CC = cc;
  ({ $, TOKEN, api, toast, esc, fmtAgo, fmtWhen, fmtDur, fmtIn, money,
     icon, iconLabel, openLog, openEditor, projById, isFav, eff,
     setView, backoffMultiplier, activeRunsOf, renderJobs,
     effortLabel, fmtExpiresIn, resumeInFlight } = cc);
}
