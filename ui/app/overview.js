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
   hand, called out here so the next person knows there are two to update. */

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
// No group at all when none of the given jobs carry a project: a jobs list
// with no project data (or filtered down to none) gets no group chrome to
// scroll past, the same "flat grid" pulseHtml's caller already special-cases
// for an install with no projects anywhere.
export function groupJobs(jobs, favSet){
  const names = [...new Set(jobs.map(j => j.project || "").filter(Boolean))]
    .sort((a, b) => (favSet.has(b) - favSet.has(a)) || a.localeCompare(b));
  if(!names.length) return [];
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
