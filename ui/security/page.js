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
           unjournaledLive, fmtAgo, fmtWhen, fmtDur, money, icon, iconLabel, iconHTML,
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
           // tableFooter joined the other two so a later task's own project/
           // recent-analyses pager would not have to touch this bridge again
           // to reach it -- it now has four callers: the fleet table and the
           // recent-analyses table (both index-screen.js), the project
           // screen's own Runs tab (project-screen.js) and the findings
           // browser (findings-screen.js).
           pageHeader, kpiCard, tableFooter,
           // makePicker/createCombo (Phase 4 Task 5) are the opposite
           // direction of bridge from the three above: pageHeader/kpiCard/
           // tableFooter are ui/app/chrome.js's own builders, read off CCApp
           // because THEY live outside the page; makePicker and createCombo
           // are hoisted `function`s bin/dashboard.html defines directly in
           // its own inline script (there is no ui/-side source for either
           // one to import), read off CC just like every other page-native
           // name above. Both build and wire a widget whose markup can live
           // anywhere, but whose BEHAVIOUR -- what a row means, what picking
           // one does -- belongs to whichever screen is asking, so unlike
           // Jobs/Runs' own pickers and the project editor's own combos
           // (built once, in the page, by the page), the Security area calls
           // these itself: secProjectsFilterBar (index-screen.js) builds
           // three `.picker` DOM nodes at runtime and wires them with
           // makePicker, and secInitLaunchCombos (analysis.js) does the same
           // for the three `.combo` nodes replacing sec-repo/sec-branch/
           // sec-profile's old <select>s. Safe to read this early (this
           // object is built before CCSecurity.init(CC) even runs): both are
           // `function` declarations, hoisted whole, not `const`/`let` --
           // test_every_name_ccapp_and_ccsecurity_init_pass_is_already_usable
           // exists to catch exactly the alternative.
           //
           // iconHTML (grouped with icon/iconLabel above, not here) is what
           // feeds makePicker's own cfg.icon/row.icon: bin/dashboard.html's
           // paintTrigger/paintList concatenate it into a trigger/row's own
           // markup STRING, the same shape every other picker's cfg already
           // passes -- not an element the way icon() wraps one. dom.js's
           // secIconHTML reads this rather than pulling the string back out
           // of icon()'s own returned element, which would spell, bare, the
           // one DOM property name this area's own sink guard
           // (tests/test_page_contract.py) bans from every module under ui/
           // -- a read is as invisible to that guard's plain substring check
           // as a write, and rightly so, since nothing there can tell code
           // from prose either.
           makePicker, createCombo,
           // closeMenus (I4, Phase 4 final review) joins makePicker/
           // createCombo's own direction of bridge -- a hoisted `function`
           // bin/dashboard.html defines directly, native to the page, not
           // ui/app/chrome.js's. The row kebab's own summary needs to call it
           // DIRECTLY, synchronously, the instant a reader opens one kebab
           // while another is already open: that click's own
           // `e.stopPropagation()` (see secIndexProjectRow's own comment on
           // why it is there at all -- protecting the row's own click-to-
           // open from firing underneath the kebab) also keeps it from ever
           // bubbling to `document`, which is where bin/dashboard.html's own
           // closeMenus() is normally reached from. Safe to read this early
           // for the identical reason makePicker/createCombo already are: a
           // hoisted `function` declaration, not `const`/`let`.
           closeMenus;

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
     fmtAgo, fmtWhen, fmtDur, money, icon, iconLabel, iconHTML, openProjectEditor,
     pageHeader, kpiCard, tableFooter, makePicker, createCombo, closeMenus } = cc);
}
