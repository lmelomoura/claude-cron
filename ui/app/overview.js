/* --------------------------------------------------------------- overview

   The Overview's own arithmetic, pulled out of pulseHtml, jobCard and
   renderJobCards ahead of the redesign that turns three loose tiles and a
   footer strip into five KPI cards, and job cards built from HTML strings
   into DOM nodes. Extracted, not rewritten: every threshold, every branch
   and every word below is what the page already says today, moved rather
   than reworded so a characterisation test can hold it still while the
   markup around it changes.

   Every function here is deliberately self-contained -- no import, no
   module-level helper shared between two of them -- because
   tests/test_page_contract.py pulls each one out of this file BY NAME
   (`_plainfn`) and runs it alone under Node. A function that reached for a
   sibling defined elsewhere in this module would work on the real page and
   throw a ReferenceError the moment its own test tried to run it standing
   alone, which is exactly the gap a characterisation test exists to not
   have. Where that means a formula also lives in ui/app/page.js's bindings
   (money's currency format, fmtWhen's date format), it is duplicated here
   on purpose, the same trade `backoffMultiplier`'s BACKOFF_AFTER/BACKOFF_MAX
   pair already makes against the engine's own bash copy: kept in step by
   hand, called out here so the next person knows there are two to update.

   pageHeader, kpiCard, renderPulse and renderOverviewHead, added below the
   pinned functions, are a different kind of thing: they build the DOM the
   page mounts, so they need $, CC and icon from ./page.js the way every
   other screen's renderer does (see ui/security/index-screen.js). None of
   them is pulled out and run standing alone by a test, so the isolation
   rule above does not bind them -- but tickTotals, pickLine and
   greetingParts, which they call, still are self-contained on purpose:
   nothing stops a future test from extracting one of those three the same
   way pulseKpis already is. */
import { $, CC, icon } from "./page.js";

// A percentage of nothing is not 0%, it is nothing -- pulseHtml's own pct()
// said so first; this is that rule, nested rather than a module-level
// sibling so pulseKpis can be extracted whole.
//
// The five numbers the loop's last 24 hours and 7 days produced, as plain
// card descriptors: {label, value, sub, tone, filter}. `filter` is the
// data-statfilter a card still carries into Runs, empty when there is
// nothing behind it to navigate to -- see pulseHtml's own chip() closure,
// which this is extracted from. `value` and the currency in "Spent today"
// are already display-ready strings, not raw numbers, so a caller can drop
// them straight into a card with no formatting of its own to get wrong.
export function pulseKpis(k){
  const checks = k.checks || 0;
  const per = k.per || {};
  const warn = k.warn || 0;
  const err = k.err || 0;
  const spentToday = k.spentToday || 0;
  const pct = (n) => checks ? Math.round(n / checks * 100) + "%" : "—";
  // Mirrors page.js's money() exactly: same style, same 2-vs-4 decimal
  // switch for a sub-10-cent run. Duplicated rather than imported -- see
  // this file's own banner comment.
  const dollars = new Intl.NumberFormat("en-US", {
    style: "currency", currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: (Math.abs(spentToday) < 0.1 ? 4 : 2),
  }).format(spentToday);
  return [
    {label: "Checks", value: String(checks),
     sub: checks ? "in the last 24h" : "nothing yet", tone: "", filter: ""},
    {label: "Woke a run", value: String(per.woke || 0),
     sub: pct(per.woke || 0) + " of checks", tone: "", filter: ""},
    // Warnings and errors are a way IN to the runs they count, and inert
    // when there is nothing to go to -- see pulseHtml's own comment beside
    // chip() on why a card with nothing to show must not navigate.
    {label: "Warnings", value: String(warn),
     sub: warn ? "Runs that finished without failing but did not do the work — open them in Runs"
               : "No warnings in the last 7 days",
     tone: "warn", filter: warn ? "warning" : ""},
    {label: "Errors", value: String(err),
     sub: err ? "Runs that failed — open them in Runs" : "No errors in the last 7 days",
     tone: "err", filter: err ? "error" : ""},
    {label: "Spent today", value: dollars, sub: "", tone: "", filter: ""},
  ];
}

// The band's own empty state: a fresh install, an evening with everything
// switched off, and a loop about to tick are three different facts, and one
// blank chart for all three is the state this sentence exists to prevent.
// Extracted verbatim from pulseHtml's `if(!checks)` branch.
export function bandEmptyReason(jobs){
  const js = jobs || [];
  const off = js.filter(j => j.enabled === false).length;
  return !js.length ? "There are no jobs yet."
    : off === js.length ? "All " + js.length + " jobs are disabled."
    : off ? off + " of " + js.length + " jobs are disabled."
    : "Every job is enabled — the next tick will show up here.";
}

// Three outcomes, not two. A probe that could not run (any exit other than 0
// or 1) once rendered as the calm "nothing to do", so a job whose
// credentials had gone missing looked healthy while it silently never ran
// again -- see jobCard's own comment on the branch this replaces.
export function probeVerdict(pc){
  const span = document.createElement("span");
  if(pc.exit === 0){
    span.style.color = "var(--ok)";
    span.textContent = "work found";
  }else if(pc.exit === 1){
    span.textContent = "nothing to do";
  }else{
    span.style.color = "var(--err)";
    span.style.fontWeight = "600";
    span.textContent = "probe FAILED (exit " + pc.exit + ")";
  }
  return span;
}

// The spend bar's two thresholds: 80% is a warning, 100% is a stop.
// Extracted from jobCard's `barCls` expression -- `spent`/`cap` rather than
// the whole facts object, since the tone depends on nothing else.
export function spendTone(spent, cap){
  const capped = (cap != null && spent >= cap);
  const pct = (cap != null && cap > 0) ? Math.min(100, spent / cap * 100) : 0;
  return capped ? "over" : (pct >= 80 ? "near" : "");
}

// Favourite projects first, then the rest alphabetically -- the star's whole
// purpose: on an install with a dozen projects, the two you are working in
// stop being a scroll away. `favSet` only ever needs `.has(name)`, so the
// page can hand this the existing isFav() wrapped in an object rather than
// building a real Set of every favourited name.
//
// No group at all when none of the given jobs carry a project AND the
// caller has nothing to say about projects elsewhere: a jobs list with no
// project data anywhere gets no group chrome to scroll past, the same
// "flat grid" pulseHtml's caller already special-cases for an install with
// no projects at all. `allProjects` is the third, optional argument that
// tells the two cases apart -- the install's own unfiltered project names,
// not the jobs this call was actually handed. Omitted (or empty), this
// behaves exactly as it always has: `jobs` is all there is to go on, and no
// project anywhere in it means no groups. Given a non-empty list, though, a
// `jobs` with nothing but standalone jobs is read correctly as "the
// Standalone filter is on", not "this install has no projects", and the
// loose group below still gets built -- the filtered set the Standalone
// project filter produces is exactly this: every visible job project-less,
// on an install that has projects elsewhere.
export function groupJobs(jobs, favSet, allProjects){
  const names = [...new Set(jobs.map(j => j.project || "").filter(Boolean))]
    .sort((a, b) => (favSet.has(b) - favSet.has(a)) || a.localeCompare(b));
  if(!names.length && !(allProjects && allProjects.length)) return [];
  const groups = [];
  for(const name of names){
    const js = jobs.filter(j => j.project === name);
    if(js.length) groups.push({name, jobs: js});
  }
  const loose = jobs.filter(j => !j.project);
  if(loose.length) groups.push({name: "__standalone__", jobs: loose});
  return groups;
}

// "Nothing here" and "nothing here matching what you typed" send a reader to
// two different places -- getting it wrong sends them to create a job they
// already have. Extracted verbatim from renderJobCards's empty-grid branch.
export function jobsEmptyNote(filtering){
  return filtering ? "No jobs match these filters." : "No jobs yet — create one.";
}

// What the "next" line says: disabled, no matching window, or a time --
// optionally qualified by "when the window reopens" and/or how far backoff
// has stretched the interval. Extracted from jobCard's `next` expression.
export function nextRunNote(job, facts){
  const wrap = document.createElement("span");
  if(job.enabled === false){
    const muted = document.createElement("span");
    muted.className = "muted";
    muted.textContent = "disabled";
    wrap.appendChild(muted);
    return wrap;
  }
  const {nextAt, dueAt, backoff, streak} = facts;
  if(nextAt == null){
    const muted = document.createElement("span");
    muted.className = "muted";
    muted.textContent = "no matching window";
    wrap.appendChild(muted);
    return wrap;
  }
  // Mirrors page.js's fmtWhen() exactly: explicit parts rather than
  // dateStyle:"short", which renders a 2-digit year. Duplicated rather than
  // imported -- see this file's own banner comment.
  wrap.appendChild(document.createTextNode(new Date(nextAt * 1000).toLocaleString(undefined,
    {year: "numeric", month: "numeric", day: "numeric",
     hour: "numeric", minute: "2-digit", second: "2-digit"})));
  if(nextAt > dueAt + 30){
    const reopen = document.createElement("span");
    reopen.className = "muted";
    reopen.textContent = " · when the window reopens";
    wrap.appendChild(reopen);
  }
  if(backoff > 1){
    // "backing off" alone does not say for how long or why -- the number of
    // failed runs is what tells an operator whether to wait or to look.
    const back = document.createElement("span");
    back.style.color = "var(--warn)";
    back.textContent = " · backing off " + backoff + "× after " + streak + " failed runs";
    wrap.appendChild(back);
  }
  return wrap;
}

/* ----------------------------------------------------------------- the DOM
   Everything below builds elements rather than arithmetic. secEl's shape,
   copied rather than imported -- ui/security/dom.js's own secEl reaches for
   the Security area's icon table indirectly through page.js, and importing
   across the two bundles for four lines is the coupling both bundles were
   split to avoid (see ui/security/index.js's own banner comment on why
   ui/app/ and ui/security/ stay two builds). */
function el(tag, cls, text){
  const n = document.createElement(tag);
  if(cls) n.className = cls;
  if(text != null) n.textContent = text;
  return n;
}

// What each outcome means, in the order the server stacks them, and the
// clock format the band's tooltips and axis marks share. Moved here
// verbatim from pulseHtml's own top -- see this file's own banner comment
// on why the DOM builders below need them and the pinned functions above
// do not.
const TICK_KINDS = [
  ["woke",   "started a run"],
  ["idle",   "nothing to do"],
  ["capped", "daily cap reached"],
  // Money and usage are different ceilings with different next moves: a daily
  // cap is a number the operator chose and can raise, a spent window is a wait
  // for the clock. Folding them together hid which one was holding the fleet.
  ["rate_limited", "usage window spent"],
  // Not "at its parallel limit": with max_parallel=1 — the common case — that
  // reads as a ceiling the operator should consider raising, when all it means
  // is that the previous run had not finished. "Already running" is true at
  // every limit and says the thing the operator actually needs to know.
  ["blocked", "already running"],
  ["failed", "could not run"],
];
const clockAt = (sec) => new Date(sec * 1000)
  .toLocaleTimeString(undefined, {hour: "2-digit", minute: "2-digit"});

/* What the ticks add up to, split out because the header's own sentence reads
   the same numbers the band draws — and two independent tallies of one thing
   is how a page ends up contradicting itself. Takes `ticks` (DATA.ticks) as a
   plain argument rather than reading DATA itself, the same reason pulseKpis
   above takes a plain object instead of reaching for the page's globals. */
export function tickTotals(ticks){
  const T = ticks || {}, buckets = Array.isArray(T.buckets) ? T.buckets : [];
  const kinds = Array.isArray(T.outcomes) ? T.outcomes : TICK_KINDS.map(x => x[0]);
  const per = {};
  TICK_KINDS.forEach(([name]) => { per[name] = 0; });   // every kind counts, even at zero
  kinds.forEach((name, i) => { per[name] = buckets.reduce((a, b) => a + (b[i] || 0), 0); });
  return {per, checks: Object.values(per).reduce((a, n) => a + n, 0), buckets, kinds, T};
}

/* ------------------------------------------------------------- the greeting
   Written from what the loop actually did, so it is worth reading twice rather
   than being a fortune cookie stapled to a dashboard. Pinned to the hour on
   purpose: the header repaints every five seconds, and a line that rerolled
   each time would be unreadable — and would look like the page was glitching. */
export function pickLine(lines){
  return lines[Math.floor(Date.now() / 3600000) % lines.length];
}

/* helloHtml's own wording, unchanged, as {title, subtitle} for pageHeader's
   slots instead of an <h2>/<p> pair: `m` is the same merged kpis object
   pulseKpis reads (checks, per, warn, err, spentToday, runsToday), `jobs` is
   DATA.jobs and `firstName` is the signed-in user's full name (CFG.user.name
   — CFG has no other reason to reach ui/app/, so the page passes just this
   one field through renderOverviewHead's own argument rather than growing
   page.js's bind list for it). Duplicates the currency format rather than
   importing money() — see this file's own banner comment. */
export function greetingParts(m, jobs, firstName){
  const per = m.per || {};
  const checks = m.checks || 0;
  const h = new Date().getHours();
  const when = h < 5 ? "Still up" : h < 12 ? "Good morning"
             : h < 19 ? "Good afternoon" : "Good evening";
  const js = jobs || [];
  const off = js.filter(j => j.enabled === false).length;
  const runs = m.runsToday || 0;
  const money = (n) => new Intl.NumberFormat("en-US", {
    style: "currency", currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: (Math.abs(n) < 0.1 ? 4 : 2),
  }).format(n);
  const spent = money(m.spentToday || 0);
  // "All 1 jobs disabled" is the kind of seam that makes a friendly line read
  // as generated. Every count in a sentence goes through here.
  const nOf = (n, word) => n + " " + word + (n === 1 ? "" : "s");
  let line;
  if(!js.length){
    line = pickLine([
      "No jobs yet, so nothing has gone wrong. Enjoy the perfect record while it lasts.",
      "An empty scheduler has never once exceeded its budget.",
      "Nothing to run. This is the safest this dashboard will ever be."]);
  }else if(off === js.length){
    line = pickLine([
      "Every job is switched off — the quietest kind of correct.",
      (js.length === 1 ? "Your one job is disabled" : "All " + js.length + " jobs are disabled")
        + ". Nothing is spending your money, which is one way to stay under budget.",
      "The loop is awake and has absolutely nothing to do about it."]);
  }else if(m.err){
    line = pickLine([
      nOf(m.err, "error") + " in the last 7 days. They are not going to read themselves.",
      nOf(m.err, "run") + " failed this week — the logs know why, and they are one click away.",
      "Something broke " + nOf(m.err, "time") + " this week. Better here than in review."]);
  }else if(per.failed){
    line = pickLine([
      nOf(per.failed, "check") + " could not even start today. That is usually a path or a lock.",
      "The prober failed " + nOf(per.failed, "time") + " — worth a look before it becomes a habit."]);
  }else if(runs && m.spentToday >= 50){
    line = pickLine([
      nOf(runs, "run") + " and " + spent + " today. The agents have been enthusiastic.",
      spent + " spent today across " + nOf(runs, "run") + ". Money well spent, presumably.",
      nOf(runs, "run") + " today. Your credit card has been paying attention."]);
  }else if(runs){
    line = pickLine([
      nOf(runs, "run") + " today, nothing on fire.",
      nOf(runs, "run") + " today for " + spent + ", none of which asked permission.",
      nOf(runs, "run") + " today and zero errors. Suspicious, but I will take it."]);
  }else if(checks){
    line = pickLine([
      "Nothing has run today. The loop is awake, just unimpressed by the queue.",
      nOf(checks, "check") + " today and nothing worth waking a run for. That is the system working.",
      "Quiet so far — every precheck looked and found nothing to do."]);
  }else{
    line = pickLine([
      "The loop has not checked anything in the last 24 hours.",
      "No ticks today. If that is a surprise, check that launchd is still loaded."]);
  }
  const first = String(firstName || "").trim().split(/\s+/)[0] || "";
  return {title: when + (first ? ", " + first : "") + ".", subtitle: line};
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
   One card per number pulseKpis hands back. `filter` is rendered as a click
   target — a real <button>, `data-statfilter` set — only when it is truthy;
   otherwise the button is `disabled`, same as an empty pulseKpis card always
   was as a chip. That is the whole contract
   test_the_warning_and_error_cards_lead_to_the_runs_they_count is written
   against: it drives pulseKpis, not this function, but the two have to agree
   on what `filter` means or the door pulseKpis says is open would not be. */
export function kpiCard({icon: iconName, tone, value, label, sub, filter}){
  const btn = el("button", "kpi-card" + (tone ? " " + tone : ""));
  const head = el("div", "kpi-card-h");
  const icWrap = el("div", "kpi-card-ic");
  if(iconName) icWrap.appendChild(icon(iconName));
  head.appendChild(icWrap);
  head.appendChild(el("span", null, label));
  btn.appendChild(head);
  btn.appendChild(el("div", "kpi-card-num", value));
  if(sub) btn.appendChild(el("div", "kpi-card-sub", sub));
  if(filter) btn.dataset.statfilter = filter;
  else btn.disabled = true;
  return btn;
}

/* ------------------------------------------------------------------ the band
   Bars, axis and legend, unchanged in substance from pulseHtml's own -- only
   the width they are drawn at changes, now that no KPI column sits beside
   them. Returns a DocumentFragment rather than one wrapping element: the
   three pieces are siblings inside #stats, and #stats's own padding already
   does the job a wrapper div would only repeat. */
export function renderPulse(ticks, jobs){
  const {per, checks, buckets, kinds, T} = tickTotals(ticks);
  const span = T.bucket_seconds || 900;
  const start = T.start || (Math.floor(Date.now() / 1000) - 86400);
  const totalOf = (b) => b.reduce((a, n) => a + n, 0);
  const max = buckets.reduce((m, b) => Math.max(m, totalOf(b)), 0);
  const frag = document.createDocumentFragment();
  frag.appendChild(el("div", "pulse-t", "Last 24 hours"));

  if(!checks){
    // The honest empty state. A fresh install, or an evening after everything
    // was switched off, is not a broken chart — say which it is.
    const asleep = el("div", "band asleep");
    asleep.appendChild(el("span", null,
      "The loop has not checked anything in the last 24 hours. " + bandEmptyReason(jobs)));
    frag.appendChild(asleep);
  }else{
    const band = el("div", "band");
    buckets.forEach((b, bi) => {
      const at = start + bi * span, tot = totalOf(b);
      const bk = el("div", "bk");
      // A real DOM property, not an HTML attribute string: the newlines below
      // render in the tooltip exactly the same way, with no esc() needed —
      // nothing here goes through the HTML parser to begin with.
      bk.title = tot
        ? clockAt(at) + "–" + clockAt(at + span) + "\n"
          + kinds.map((name, i) => b[i] ? b[i] + " " + (TICK_KINDS.find(x => x[0] === name) || [, name])[1] : "")
              .filter(Boolean).join("\n")
        : clockAt(at) + "–" + clockAt(at + span) + "\nno checks";
      kinds.forEach((name, i) => {
        if(!b[i]) return;
        const bar = el("i", "k-" + name);
        bar.style.height = (b[i] / max * 100).toFixed(2) + "%";
        bk.appendChild(bar);
      });
      band.appendChild(bk);
    });
    frag.appendChild(band);
  }

  const axis = el("div", "axis");
  [0, .25, .5, .75].forEach(f => axis.appendChild(el("span", null, clockAt(start + 86400 * f))));
  axis.appendChild(el("span", null, "now"));
  frag.appendChild(axis);

  const shown = TICK_KINDS.filter(([name]) => per[name]);
  if(shown.length){
    const legend = el("div", "legend");
    shown.forEach(([name, what]) => {
      const item = el("span");
      item.appendChild(el("i", "k-" + name));
      item.appendChild(document.createTextNode(per[name] + " " + what));
      legend.appendChild(item);
    });
    frag.appendChild(legend);
  }
  return frag;
}

/* ------------------------------------------------------------- the mount
   The Overview's own call site: `render()` in bin/dashboard.html now calls
   this once instead of assigning two HTML-string builders' output. `kpis` is the same
   {runsToday, spentToday, runsWeek, spentWeek, warn, err} object render()
   already built from DATA.runs; `firstName` is CFG.user.name (see
   greetingParts's own comment on why that one field is passed rather than
   bound). checks/per come from DATA.ticks, read here rather than passed in,
   since tickTotals needs them anyway for the band immediately below. */
export function renderOverviewHead(kpis, firstName){
  const jobs = CC.DATA.jobs || [];
  const ticks = CC.DATA.ticks || {};
  const tt = tickTotals(ticks);
  const merged = Object.assign({}, kpis, {checks: tt.checks, per: tt.per});
  const cards = pulseKpis(merged);
  const {title, subtitle} = greetingParts(merged, jobs, firstName);

  const headHost = $("ov-head");
  if(headHost){
    headHost.textContent = "";
    headHost.appendChild(pageHeader({
      icon: "grid", title, subtitle,
      actions: [
        {id: "ov-refresh", icon: "radar", label: "Refresh"},
        {id: "ov-new-job", icon: "plus", label: "New job", primary: true},
      ],
    }));
  }

  const kpiHost = $("ov-kpis");
  if(kpiHost){
    kpiHost.textContent = "";
    // Icons are a rendering choice, not part of what pulseKpis computes --
    // its own five objects carry no icon field, and none is added here.
    // Warnings/errors reuse the exact glyphs the old chip() called with.
    const ICONS = {"Checks": "radar", "Woke a run": "zap", "Warnings": "alert",
                   "Errors": "xcircle", "Spent today": "dollar"};
    cards.forEach(c => kpiHost.appendChild(kpiCard({
      icon: ICONS[c.label], tone: c.tone, value: c.value,
      label: c.label, sub: c.sub, filter: c.filter,
    })));
  }

  const bandHost = $("stats");
  if(bandHost){
    bandHost.textContent = "";
    bandHost.appendChild(renderPulse(ticks, jobs));
  }
}
