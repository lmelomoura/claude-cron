/* Everything the Security area is given by the page it lives in.

   The area used to BE the page — one 7,300-line dashboard.html with a single
   <script> in it — so it read `DATA`, `$`, `toast` and a dozen others straight
   out of the surrounding scope. Out here that scope is gone, and the honest
   replacement is a stated interface rather than a handful of reads off
   `window`: dashboard.html builds one object, hands it to init(), and this
   file is the list of what is in it. Anything the area needs that is not here
   does not exist, which is the point — a missing name fails at bind time
   instead of as `undefined is not a function` three screens in.

   The bindings are `let` and filled by bindPage() because the bundle is loaded
   BEFORE the page's own script runs (it has to be: setView() calls into this
   area during boot, so the area must already be defined when the page's script
   executes). Nothing here is readable until init() has been called, and
   nothing in this area runs before that. */
export let $, TOKEN, api, toast, openLog, projById, sessionLost,
           unjournaledLive, fmtAgo, fmtWhen, fmtDur, money, icon, iconLabel,
           openProjectEditor,
           // The chrome bridge (Phase 4 Task 1): pageHeader, kpiCard and
           // tableFooter are ui/app/chrome.js's own builders, read off
           // CCApp -- not imported -- because ui/security/ and ui/app/ are
           // two separate esbuild bundles, and importing chrome.js here
           // would pull in a SECOND, never-bound copy of ui/app/page.js
           // (its `icon` stays undefined forever, since only CCApp.init()
           // binds it). bin/dashboard.html's CC object reads
           // CCApp.pageHeader/CCApp.kpiCard/CCApp.tableFooter -- the ONE
           // compiled copy chrome.js ever gets, already bound to the app
           // bundle's own `icon` by the time anything here calls one of
           // these -- and hands them into CCSecurity.init(CC) alongside
           // every other name. One executing copy, zero drift.
           //
           // tableFooter has no caller under ui/security/ yet: it joins the
           // other two now so a later task's own project/recent-analyses
           // pager does not have to touch this bridge again to reach it.
           pageHeader, kpiCard, tableFooter;

/* DATA and currentView are the two the page REASSIGNS as it runs — DATA on
   every five-second poll, currentView on every navigation. Destructured into a
   local like the rest, they would freeze at whatever they held when init() ran:
   an empty DATA (the poll has not answered yet) and the startup view. So they
   are the two things read through the object, live, at the moment they are
   needed — `CC.DATA`, `CC.currentView` — and the difference in spelling is the
   reminder that they change under you. */
export let CC = null;

export function bindPage(cc) {
  CC = cc;
  ({ $, TOKEN, api, toast, openLog, projById, sessionLost, unjournaledLive,
     fmtAgo, fmtWhen, fmtDur, money, icon, iconLabel, openProjectEditor,
     pageHeader, kpiCard, tableFooter } = cc);
}
