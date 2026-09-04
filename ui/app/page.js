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

   openLog, resumeTarget, resumeTip, continuedRun, resumedBadgeTip, runKey,
   isStopping, unjournaledLive, paintRunPickers and runDateLabel join the
   list for the Runs table's own move (Phase 2 Task 7). Every one of them
   keeps its single implementation in the page:

   - openLog opens the log modal, which stays in bin/dashboard.html --
     see that file's own banner comment on why the modal did not move with
     the rest of this table. The row's own "view" button reaches it
     directly (an `addEventListener`, the same way initJobDrag reaches
     TOKEN/toast/refresh below for its own reorder round trip) rather than
     through a `data-log-id` attribute a central listener used to read, since
     nothing else needs that attribute once the row that carried it moved.
   - resumeTarget, resumeTip and continuedRun are the resume-tooltip
     machinery: which failed/warning/stopped run already has a follow-up,
     and the rich tooltip describing it. Both keep returning a plain HTML
     string, exactly as before -- it is assigned to a real element's
     `.dataset.tip` now instead of spliced into a template, and read back by
     the page's own unmoved tipShow(), so nothing about what the tooltip
     says or how it renders changed.
   - resumedBadgeTip is new: the "resumed" badge's own tooltip content used
     to be built inline inside the row template renderRuns() no longer has;
     naming it here is the only change, not a rewrite of what it says.
   - runKey names the `id|start` composite key the resumed-run bookkeeping
     (resumedRuns, localStorage-backed) is keyed by; the table's own row
     needs it for the same `data-resume-key` attribute it always carried.
   - isStopping reads the page's own `stopping` Set (kept in step by
     markStopping, which the page's central click dispatcher still calls
     directly, and by forgetDeadStops, folded into unjournaledLive below).
   - unjournaledLive is live runs not yet in the journal -- already reached
     by the page's own sidebar count (paintNav), so it stays defined there
     rather than gaining a second home; forgetDeadStops now runs inside it
     rather than being a second call every caller had to remember to make.
   - paintRunPickers/runDateLabel mirror paintJobPickers exactly: the four
     Runs pickers stay page-owned stateful widgets (initPickers() builds
     them alongside the two Jobs ones), and this module only ever reaches
     their `.paint()`/`.label()` through these two small bridges.

   esc, iconLabel, openEditor and setView still are not exported: nothing
   under ui/app/ calls any of them. api is not either -- the module's own
   network calls (initJobDrag's reorder) go through a plain `fetch` the
   same way the page's own `api()` wraps one, since bulkToggle/showConfirm's
   confirmation dialog stays behind in the page for the one caller
   (bulkToggle) that still needs it. */
export let $, fmtAgo, fmtDur, money,
           icon, projById, eff,
           backoffMultiplier, activeRunsOf, renderJobs,
           effortLabel, fmtExpiresIn, resumeInFlight, markIfPending,
           fmtWhen, fmtIn, isFav, TOKEN, toast, refresh, paintJobPickers,
           normStatus,
           openLog, resumeTarget, resumeTip, continuedRun, resumedBadgeTip,
           runKey, isStopping, unjournaledLive, paintRunPickers, runDateLabel;

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
     effortLabel, fmtExpiresIn, resumeInFlight, markIfPending,
     fmtWhen, fmtIn, isFav, TOKEN, toast, refresh, paintJobPickers,
     normStatus,
     openLog, resumeTarget, resumeTip, continuedRun, resumedBadgeTip,
     runKey, isStopping, unjournaledLive, paintRunPickers, runDateLabel } = cc);
}
