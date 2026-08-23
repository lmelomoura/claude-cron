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
