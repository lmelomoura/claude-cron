/* The generic chrome every remaining page reaches for: a plain element
   builder, a page header and a KPI card. All three started life in
   overview.js because the Overview was the first page rebuilt, but nothing
   about them is the Overview's -- Phase 1's final review flagged that six
   pages importing generic pieces from a file called overview.js is a
   filename lying six times over, and Phase 2, which puts a header and a KPI
   row on Jobs and Runs, is the first of those six pages to land. Moved here
   verbatim: no function body below changed in the move. */
import { icon } from "./page.js";

/* ----------------------------------------------------------------- the DOM
   Everything below builds elements rather than arithmetic. secEl's shape,
   copied rather than imported -- ui/security/dom.js's own secEl reaches for
   the Security area's icon table indirectly through page.js, and importing
   across the two bundles for four lines is the coupling both bundles were
   split to avoid (see ui/security/index.js's own banner comment on why
   ui/app/ and ui/security/ stay two builds). */
export function el(tag, cls, text){
  const n = document.createElement(tag);
  if(cls) n.className = cls;
  if(text != null) n.textContent = text;
  return n;
}

/* -------------------------------------------------------------- the header
   Icon, title, one sentence, actions trailing on the right. Generic on
   purpose -- Phases 2 and 3 put one of these on every remaining page, so
   nothing here may assume it is the Overview's. `actions` is a list of
   {id, icon, label, primary}: this builder only draws the button and gives
   it the id the caller asked for, the same "markup carries the hook, a
   central listener does the click" split kpiCard uses below for
   data-statfilter -- see bin/dashboard.html's delegated click listener for
   where #ov-refresh and #ov-new-job are answered. */
export function pageHeader({icon: iconName, title, subtitle, actions}){
  const head = el("div", "page-header");
  const icWrap = el("div", "page-header-ic");
  if(iconName) icWrap.appendChild(icon(iconName));
  head.appendChild(icWrap);
  const body = el("div", "page-header-body");
  body.appendChild(el("h1", null, title));
  if(subtitle) body.appendChild(el("p", null, subtitle));
  head.appendChild(body);
  if(actions && actions.length){
    const bar = el("div", "page-header-actions");
    actions.forEach(a => bar.appendChild(pageHeaderAction(a)));
    head.appendChild(bar);
  }
  return head;
}

function pageHeaderAction(a){
  const btn = el("button", "btn " + (a.primary ? "primary" : "ghost"));
  if(a.id) btn.id = a.id;
  if(a.icon) btn.appendChild(icon(a.icon));
  btn.appendChild(document.createTextNode(a.label));
  return btn;
}

/* ----------------------------------------------------------------- the KPI
   One card per number pulseKpis hands back. The tinted icon square and the
   NUMBER share the first line -- the number is what the eye should land on
   beside the icon, not the caption -- then the label, then the muted
   sublabel.

   `door` says whether this card is a way IN to Runs at all, and decides the
   element itself: false renders a plain, non-interactive element -- never a
   <button>, never `disabled` -- for Checks/Woke a run/Spent today, which
   have nowhere to navigate and never will; true renders a real <button>,
   `data-statfilter` set when `filter` is truthy, `disabled` when it is not.
   A door with nothing behind it (its own count at zero) is the one case
   `disabled` is for -- it is then telling the truth ("nothing to open
   here"), not making the page look broken. `filter` alone cannot carry this
   -- it is empty both for a card that never navigates and for a door at a
   zero count -- which is why `door` is a separate flag pulseKpis sets.
   test_the_warning_and_error_cards_lead_to_the_runs_they_count pins what
   `filter` means; the door-vs-plain-element test beside it pins this.

   `title`, when pulseKpis hands one over, becomes the card's own DOM
   `.title` -- a native tooltip, not markup, so a full explanatory sentence
   costs nothing here the way it would in `sub`. It exists because `sub` is
   held to three to five words (see pulseKpis's own comment beside
   Warnings/Errors): the definition of what the card is counting lives in
   the tooltip instead of being spliced into the sublabel. */
export function kpiCard(opts){
  // `opts` rather than destructuring in the parameter list itself: _plainfn
  // (tests/test_page_contract.py) extracts a function by name by matching
  // braces starting from the first opening brace after its name, and a
  // destructured parameter's own opening brace would be mistaken for the
  // body's. Destructuring on the next line instead keeps every call site
  // (`kpiCard({icon, tone, ...})`) exactly as it was.
  const {icon: iconName, tone, value, label, sub, title, filter, door} = opts;
  const card = el(door ? "button" : "div", "kpi-card" + (tone ? " " + tone : ""));
  if(title) card.title = title;
  const head = el("div", "kpi-card-h");
  const icWrap = el("div", "kpi-card-ic");
  if(iconName) icWrap.appendChild(icon(iconName));
  head.appendChild(icWrap);
  head.appendChild(el("span", "kpi-card-num", value));
  card.appendChild(head);
  card.appendChild(el("div", "kpi-card-label", label));
  if(sub) card.appendChild(el("div", "kpi-card-sub", sub));
  if(door){
    if(filter) card.dataset.statfilter = filter;
    else card.disabled = true;
  }
  return card;
}

/* ------------------------------------------------------------ the filter bar
   Search box, pill dropdowns, right-aligned actions -- in that order, with a
   `.spacer` between the dropdowns and the actions so the actions land flush
   right. Jobs, Runs and Projects all have this exact shape already, but as
   STATIC markup in bin/dashboard.html rather than a shared builder: the
   search box, the pickers (Jobs has two, Runs has four, Projects has none)
   and the trailing buttons are stateful widgets this file has no business
   rebuilding (the pickers in particular are `makePicker()`'s own DOM,
   wired to open/close/scroll-page by id before this ever runs) -- so
   `search`, `selects` and `actions` are the ALREADY-BUILT elements the page
   found by id, and filterBar's only job is to lay them out in the one
   correct order and hand back the `.toolbar` div they belong in. Moving an
   already-wired element does not touch its listeners; only its position in
   the tree changes, which is why this is safe to call once a page's static
   pickers already exist and are already wired (see jobs-table.js's own
   call, guarded to run exactly once per page load rather than every poll --
   rebuilding the search input from scratch every five seconds would drop
   whatever the operator was mid-typing). */
export function filterBar(opts){
  const {search, selects, actions} = opts;
  const bar = el("div", "toolbar");
  if(search) bar.appendChild(search);
  (selects || []).forEach(s => { if(s) bar.appendChild(s); });
  bar.appendChild(el("div", "spacer"));
  (actions || []).forEach(a => { if(a) bar.appendChild(a); });
  return bar;
}

/* ------------------------------------------------------------- the table card
   Header, rows and (optionally) a footer, all inside the one bordered,
   13px-radius box -- `.table-card` wraps a `.table-scroll` (JUST
   overflow-x:auto, nothing else) around the `<table>` and, as a SIBLING of
   the scroller rather than something inside it, the footer, so a table wide
   enough to scroll never drags its own footer sideways with it.

   `.table-card` is deliberately its OWN class, not `.tablewrap` with a new
   trick: `.tablewrap` is used bare -- no footer, no card wrapper -- by Runs,
   Projects, the Sessions dialog and six ui/security/*.js screens, and
   changing what that class means would restyle every one of them. The 13px
   radius this design language uses everywhere else (.card, .kpi-card) is
   applied to `.tablewrap` too (see components.css) since that fix is a
   plain one-property change every existing user of the class wants; the
   footer-inside-a-card shape is not, so it gets a new name instead of a
   second meaning for the old one.

   `columns` is JOB_COLS-shaped: `[key, label]` tuples, a falsy key for a
   column with nothing to sort by (Schedule, the trailing actions column
   with no label at all). `sortAttr` names the `data-` attribute a sortable
   `<th>` carries (`"jobsort"` for Jobs today) -- kept a caller-supplied
   string rather than a fixed name because the click itself is still
   answered by bin/dashboard.html's one delegated listener, the same
   "markup carries the hook, a central listener does the click" split
   pageHeader's own comment describes: this file has no `addEventListener`
   anywhere (the Node harness the characterisation tests run under stubs a
   DOM with no event system at all -- see tests/test_page_contract.py's
   `_INDEX_DOM_HARNESS` -- so a click has to be answered by the page reading
   an attribute, never by a listener built here). Three different attribute
   names for the identical click (`data-jobsort`, `data-prjsort`, Runs' own
   `data-sort`) is exactly the divergence this file exists to end, so
   tableCard takes the ONE mechanism as a parameter rather than deciding a
   fourth name of its own -- Projects and Runs can each keep their own
   attribute (their own central-listener case already reads it) or unify to
   one later; nothing here forces either.

   `rows` is an array of already-built `<tr>` elements, the empty-state row
   included: Jobs' status pill and backoff badge, Projects' star and
   isolation pill, Runs' live/resumed badges share nothing beyond being a
   `<tr>`, so tableCard stays ignorant of what is inside one and tells rows
   apart from the header only.

   `footer` is a pre-built element from tableFooter() below, or left out
   entirely for a table that never paginates -- kept a separate function so
   a future caller can use one without the other. */
export function tableCard(opts){
  const {columns, sortKey, sortDir, sortAttr, rows, footer} = opts;
  const headRow = el("tr");
  columns.forEach(([key, label]) => {
    if(!key){ headRow.appendChild(el("th", null, label)); return; }
    const on = sortKey === key;
    const th = el("th", "sortable" + (on ? " sorted" : ""));
    th.dataset[sortAttr] = key;
    th.setAttribute("aria-sort", on ? (sortDir < 0 ? "descending" : "ascending") : "none");
    th.title = "Sort by " + label.toLowerCase();
    th.appendChild(document.createTextNode(label));
    th.appendChild(icon(on && sortDir > 0 ? "sortasc" : "sortdesc"));
    headRow.appendChild(th);
  });
  const thead = el("thead");
  thead.appendChild(headRow);
  const tbody = el("tbody");
  rows.forEach(tr => tbody.appendChild(tr));
  const table = el("table");
  table.appendChild(thead);
  table.appendChild(tbody);
  const scroll = el("div", "table-scroll");
  scroll.appendChild(table);
  const card = el("div", "table-card");
  card.appendChild(scroll);
  if(footer) card.appendChild(footer);
  return card;
}

/* --------------------------------------------------------------- the footer
   "Showing X to Y of N <noun>" on the left, Prev/Next on the right, INSIDE
   the table card tableCard() builds -- the gap this pair of functions
   exists to close: the Jobs table's first version (Phase 2 Task 3) built
   this footer as a loose sibling below `.tablewrap`, with no border and no
   background of its own, floating under the card instead of belonging to
   it. See test_the_jobs_table_footer_sits_inside_the_table_card
   (tests/test_page_contract.py) for what pins the fix.

   `shown` is `{from, to}` -- the caller has already computed and clamped
   these (see jobs-table.js's own PAGE_SIZE arithmetic; a page number can
   run past the end when a filter shrinks the set, and clamping THAT is the
   caller's job, not this one's, exactly the split kpiCard draws between
   "what the number is" and "how it is drawn"). `total`/`noun` build the
   sentence; `page`/`pages` only disable the two buttons at either end.

   `plural` (Phase 4 Task 5) is the noun's own irregular plural, used
   instead of the bare `noun + "s"` below when the count is not 1 --
   optional, so every caller before this one (project/job/run, all regular)
   is untouched. Found live: the Recent-analyses card's own footer read
   "Showing 1 to 5 of 12 analysiss" the moment its `noun` became "analysis"
   -- a previous task's own report names this exact trap and had sidestepped
   it by keeping `noun: "run"` there instead, which this task's mockup does
   not allow ("...of 12 analyses" is the literal text asked for). Passing
   `plural: "analyses"` fixes the sentence without teaching this function a
   general pluraliser it does not need for anything else it draws.

   `prevId`/`nextId`/`infoId` exist for the same reason `sortAttr` does on
   tableCard: the actual click is answered by bin/dashboard.html's existing
   delegated listener (`#jobs-pg-prev`/`#jobs-pg-next` today), and this file
   builds no listener of its own. All three are optional -- a page with only
   ever one instance of its own table on screen at a time could skip them,
   but Jobs, Projects and Runs coexist in the DOM at once (hidden by their
   view, not removed), so an id every page must supply its OWN name for is
   the only way three footers do not collide.

   `numbered` (Phase 4 Task 5) is the mockup's own "‹ 1 2 3 ›" pager for the
   Security index's two tables -- optional, defaulting to the Prev/Next-with-
   text shape above, so Jobs/Runs/Projects (none of which pass it) are byte-
   for-byte untouched. Numbered mode drops the two buttons' own text (icon
   only, `.iconbtn`-sized) and inserts one `.pagebtn` per page between them,
   `.active` marking the current one -- and, when there is only one page,
   drops the whole nav rather than showing a pager with nothing to page
   through: the fleet table's own footer in the mockup ("Showing 1 to 2 of 2
   projects") carries no buttons at all, unlike Jobs/Projects/Runs, which
   keep showing a disabled Prev/Next even at one page and are not this
   task's to change. Clicking a page number is answered by the CALLER's own
   `footer.onclick` (the same "built fresh every repaint, wired directly on
   the element just built" idiom secIndexRecentCard's own Prev/Next already
   use) reading `closest("[data-page]")`, not a central dashboard.html
   listener -- neither of this variant's two callers is page-static markup. */
export function tableFooter(opts){
  const {shown, total, noun, plural, page, pages, prevId, nextId, infoId, numbered} = opts;
  const foot = el("div", "table-foot");
  const info = el("span", "table-foot-info",
    "Showing " + shown.from + " to " + shown.to + " of " + total + " "
    + (total === 1 ? noun : (plural || noun + "s")));
  if(infoId) info.id = infoId;
  foot.appendChild(info);
  if(numbered && pages <= 1) return foot;
  const nav = el("div", "table-foot-pager" + (numbered ? " numbered" : ""));
  // `.iconbtn` alone in numbered mode, not `.btn.ghost` too -- both are
  // complete, self-sufficient button styles (fixed 30px square vs.
  // padded-to-content), and combining them would fight over box sizing.
  // `.iconbtn` is this app's own established icon-only button (the row
  // kebab, `.rowacts`), exactly what a numbered pager's bare Prev/Next
  // chevrons are.
  const prev = el("button", numbered ? "iconbtn" : "btn ghost");
  if(prevId) prev.id = prevId;
  prev.appendChild(icon("cleft"));
  if(!numbered) prev.appendChild(document.createTextNode("Prev"));
  prev.disabled = page <= 1;
  nav.appendChild(prev);
  if(numbered){
    for(let p = 1; p <= pages; p++){
      const btn = el("button", "pagebtn" + (p === page ? " active" : ""), String(p));
      btn.type = "button";
      btn.dataset.page = String(p);
      if(p === page) btn.disabled = true;
      nav.appendChild(btn);
    }
  }
  const next = el("button", numbered ? "iconbtn" : "btn ghost");
  if(nextId) next.id = nextId;
  if(!numbered) next.appendChild(document.createTextNode("Next"));
  next.appendChild(icon("cright"));
  next.disabled = page >= pages;
  nav.appendChild(next);
  foot.appendChild(nav);
  return foot;
}
