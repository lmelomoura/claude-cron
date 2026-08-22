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
   other screen's renderer does (see ui/security/index-screen.js). Most of
   them are never pulled out and run standing alone by a test, so the
   isolation rule above does not bind them -- but tickTotals, pickLine and
   greetingParts, which they call, still are self-contained on purpose:
   nothing stops a future test from extracting one of those three the same
   way pulseKpis already is. kpiCard is the one exception: the door-vs-
   plain-element characterisation test extracts it (and its own `el`
   helper) by name, which is why its parameter is a plain `opts` rather
   than a destructured object -- see its own comment. */
import { $, CC, icon, eff, fmtAgo, fmtDur, money, effortLabel, fmtExpiresIn,
         resumeInFlight, projById } from "./page.js";
import { jobFacts } from "./jobs-domain.js";

// A percentage of nothing is not 0%, it is nothing -- pulseHtml's own pct()
// said so first; this is that rule, nested rather than a module-level
// sibling so pulseKpis can be extracted whole.
//
// The five numbers the loop's last 24 hours and 7 days produced, as plain
// card descriptors: {label, value, sub, tone, filter, door}. `filter` is the
// data-statfilter a card still carries into Runs, empty when there is
// nothing behind it to navigate to -- see pulseHtml's own chip() closure,
// which this is extracted from. `door` says whether the card is a way IN to
// Runs AT ALL, regardless of the current count: true for Warnings/Errors,
// false for the other three, always -- see kpiCard's own comment on why
// `filter` alone (empty both for a card that never navigates and for a door
// at a zero count) cannot carry that distinction by itself. `value` and the
// currency in "Spent today" are already display-ready strings, not raw
// numbers, so a caller can drop them straight into a card with no
// formatting of its own to get wrong.
export function pulseKpis(k){
  const checks = k.checks || 0;
  const per = k.per || {};
  const warn = k.warn || 0;
  const err = k.err || 0;
  const spentToday = k.spentToday || 0;
  const spentWeek = k.spentWeek || 0;
  const pct = (n) => checks ? Math.round(n / checks * 100) + "%" : "—";
  // Mirrors page.js's money() exactly: same style, same 2-vs-4 decimal
  // switch for a sub-10-cent run. Duplicated rather than imported -- see
  // this file's own banner comment.
  const money = (n) => new Intl.NumberFormat("en-US", {
    style: "currency", currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: (Math.abs(n) < 0.1 ? 4 : 2),
  }).format(n);
  return [
    {label: "Checks", value: String(checks),
     sub: checks ? "in the last 24h" : "nothing yet", tone: "", filter: "", door: false},
    {label: "Woke a run", value: String(per.woke || 0),
     sub: pct(per.woke || 0) + " of checks", tone: "", filter: "", door: false},
    // Warnings and errors are a way IN to the runs they count, and inert
    // when there is nothing to go to -- see pulseHtml's own comment beside
    // chip() on why a card with nothing to show must not navigate. `door`
    // stays true even then: it is what tells kpiCard this is a button that
    // happens to have nothing behind it right now, not a card that was
    // never a button to begin with.
    {label: "Warnings", value: String(warn),
     sub: warn ? "Runs that finished without failing but did not do the work — open them in Runs"
               : "No warnings in the last 7 days",
     tone: "warn", filter: warn ? "warning" : "", door: true},
    {label: "Errors", value: String(err),
     sub: err ? "Runs that failed — open them in Runs" : "No errors in the last 7 days",
     tone: "err", filter: err ? "error" : "", door: true},
    // The pulse-f strip this redesign removed paired "today" with "7 days"
    // for both runs and spend. The week's spend is that pair's other half --
    // one card, the total in its own sublabel, not a separate strip ("one
    // number per label" applied to the pair it was always part of). The
    // two run counts (runsToday/runsWeek) are deliberately NOT added here or
    // to any other card -- see task-8-report.md for why.
    {label: "Spent today", value: money(spentToday),
     sub: money(spentWeek) + " over 7 days", tone: "", filter: "", door: false},
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
    // .s-success/.s-error are the same six type-role classes the Runs table
    // colours its own status cells with (components.css) -- an inline
    // `style.color` here said the same thing in a second, unshared spelling.
    span.className = "s-success";
    span.textContent = "work found";
  }else if(pc.exit === 1){
    span.textContent = "nothing to do";
  }else{
    span.className = "s-error";
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
    // .s-warning is the same type-role class the Runs table's own status
    // cells use, in place of the inline `style.color` this carried before.
    const back = document.createElement("span");
    back.className = "s-warning";
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

/* -------------------------------------------------------------- the job card
   164 lines of HTML-string concatenation (`jobCard`, `renderJobCards`,
   `checkList`) in the pre-Task-9 `bin/dashboard.html`, rebuilt here as node
   builders. `renderJobCards`'s own grouping chrome (the collapsible project
   headers, the star, the bulk button) stayed in the page -- that markup is
   built from strings the page CHOOSES itself (project names, counts), never
   from a probe's stdout or a job's own fields, so it carries none of the
   exposure this move exists to close. `jobCard` is the one that does, and so
   is `checkList`, the panel inside it: `checkList` renders the FIRST LINE OF
   AN ARBITRARY PROBE SCRIPT'S STDOUT, and a job's own id/description and its
   project's name all come from files an operator edits and Jira ticket
   titles that flow through them -- `esc()` held that safely before, by
   discipline. A `<li>` built with `createElement`/`createTextNode` holds it
   by construction: there is no HTML parser between a probe's output and the
   screen for a crafted string to reach.

   Both call sibling functions in this module by their bare names --
   `probeVerdict`, `nextRunNote`, `spendTone`, `checkList`, `el` -- getting
   their first real caller here; jobCard is the reason they were extracted
   ahead of this task. `jobFacts` (state, next run, cap, backoff) comes from
   `./jobs-domain.js` -- a normal import, not the isolation the PINNED
   functions above need, since nothing extracts jobCard on its own and runs
   it standing alone the way `_plainfn` does for those. */

// Active days as a short label, mirroring the toolbar/engine's own reading of
// active_days. A small pure formatter kept local rather than folded into
// jobs-domain.js: nothing else needs it, and TICK_KINDS/clockAt below sit
// beside the DOM code that reads them for the same reason.
const DOW = ["", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
function fmtDays(arr){
  const a = [...new Set((arr || []).map(Number))].filter(n => n >= 1 && n <= 7).sort((x, y) => x - y);
  if(!a.length) return "—";
  const s = a.join(",");
  if(s === "1,2,3,4,5,6,7") return "Every day";
  if(s === "1,2,3,4,5") return "Mon–Fri";
  if(s === "6,7") return "Sat–Sun";
  return a.map(n => DOW[n]).join(", ");
}

// The precheck's first output line as a bulleted key:value list, one row per
// "key=value" pair plus whatever text was not part of one -- exactly
// checkList's old string shape, built from nodes instead: `m[2]`, the value
// after "=", is an arbitrary probe script's own stdout, appended as a TEXT
// NODE and never parsed. Returns null rather than an empty string when there
// is nothing to show -- jobCard tests the return value itself to decide
// whether to draw the checks panel at all.
function checkList(output){
  const raw = String(output || "").split("\n")[0];
  if(!raw) return null;
  const pairs = [...raw.matchAll(/([A-Za-z_]+)=(\S+)/g)];
  const rest = raw.replace(/[A-Za-z_]+=\S+/g, "").replace(/->/g, "→").replace(/\s+/g, " ").trim();
  const items = pairs.map(m => {
    const li = document.createElement("li");
    li.appendChild(document.createTextNode(m[1].replace(/_/g, " ") + ": "));
    li.appendChild(el("span", "ck-v", m[2]));
    return li;
  });
  if(rest) items.push(el("li", null, rest));
  if(!items.length) return null;
  const ul = el("ul", "checklist");
  items.forEach(li => ul.appendChild(li));
  return ul;
}

// Every retained run directory this job still owns, each as its own notice --
// almost always zero or one, but nothing stops a job from cutting two runs
// short before either is resumed or expires. Same source as the Sessions tab
// (CC.DATA.retained_worktrees) -- no second fetch, no second shape for one
// server-side list to drift against. fmtExpiresIn and resumeInFlight are the
// page's own single implementations (see page.js's own comment on why they
// are bound rather than duplicated here).
function sessionNotices(jobId){
  const kept = (CC.DATA.retained_worktrees || []).filter(w => w.job === jobId);
  return kept.map(w => {
    const left = fmtExpiresIn(w.expires_in);
    const until = left ? " — expires " + left : "";
    const line = el("div", "warnline");
    line.appendChild(icon("folder"));
    const grow = el("span", "grow");
    if(!w.session){
      grow.textContent = "Holding a run directory with no session recorded" + until
        + " — it never got far enough to report one, so it cannot be resumed.";
      line.appendChild(grow);
      return line;
    }
    grow.textContent = "Holding a session that was cut short" + until + ".";
    line.appendChild(grow);
    // Reuses the SAME guard resumeTarget uses for the Runs table -- see
    // resumeInFlight's own comment for why this must not be a second,
    // independently-drifting `activeRunsOf(...).some(...)` of its own.
    if(resumeInFlight(jobId, w.session)){
      const badge = el("span", "runningbadge");
      badge.appendChild(el("span", "pulse"));
      badge.appendChild(document.createTextNode("resuming…"));
      line.appendChild(badge);
    }else{
      const btn = el("button", "btn");
      btn.dataset.op = "resume";
      btn.dataset.id = jobId;
      btn.dataset.session = w.session;
      btn.title = "Resume this task — continue session " + w.session.slice(0, 8) + " where it stopped";
      btn.appendChild(icon("play"));
      btn.appendChild(document.createTextNode("Resume"));
      line.appendChild(btn);
    }
    return line;
  });
}

/* One job, in full: the state pill, what the probe last saw and counted, the
   24h pulse, the spend against its cap, when it next runs, its own settings
   where they differ from the project's, and the buttons that act on it.
   Every `data-op`/`data-menu`/`data-jobruns`/`data-fav` attribute below is
   read by bin/dashboard.html's ONE delegated click listener -- unchanged by
   this move, since a real DOM attribute set by `.dataset` is exactly what
   `e.target.closest("[data-op]")` already looked for. `renderJobs()`'s own
   guard against redrawing while an overflow `.menu-pop` is open lives in the
   page, one call above this function, and does not need to move: it decides
   whether to call this at all, not how this builds one card. */
export function jobCard(j){
  const F = jobFacts(j);
  const {st, chk, disabled, spentToday, cap, capped, nLive, idle} = F;
  const pc = st.last_precheck || null;
  const hasProbe = pc && typeof pc === "object";

  // The card's left edge no longer carries state -- .st-run/.st-on/.st-idle
  // lost their ::before rule when the pill took over saying the word
  // instead of asking the reader to learn four colours (see pages.css's own
  // comment on .card.st-off). Only .st-off still does anything (it dims a
  // disabled card's background and text), so it is the only one still worth
  // computing.
  const card = el("div", "card" + (disabled ? " st-off" : ""));
  // Cards are draggable so a group can be put in the order the work runs in.
  // The drag handle is the whole card; buttons and inputs still work normally.
  card.draggable = true;
  card.dataset.jobId = j.id;

  const h2 = el("h2");
  const nameSpan = el("span", "jobname");
  nameSpan.title = "Drag to reorder within the project";
  nameSpan.appendChild(icon("bot"));
  nameSpan.appendChild(document.createTextNode(j.id));
  h2.appendChild(nameSpan);
  // Badge has three states: disabled (grey -- nobody switched it on, not a
  // fault), idle (amber -- enabled but outside its active window and not
  // currently running), enabled (green). The pill alone carries this now --
  // see `card`'s own comment above on why the left edge does not. `.pill.off`
  // is reserved for a real fault (see its own comment in components.css), so
  // "disabled" gets its own class rather than reusing it.
  const pillCls = disabled ? "disabled" : (idle ? "idle" : "on");
  const pill = el("span", "pill " + pillCls, disabled ? "disabled" : (idle ? "idle" : "enabled"));
  if(idle) pill.title = "Outside its active window — no runs until the window reopens";
  h2.appendChild(pill);
  card.appendChild(h2);

  // Disabling stops FUTURE runs; one already in flight keeps going. Say so,
  // instead of letting "disabled" sit beside a spinning "running now…".
  if(disabled && nLive){
    const w = el("div", "warnline");
    w.appendChild(icon("alert"));
    w.appendChild(document.createTextNode(
      "Disabled — " + nLive + " run" + (nLive === 1 ? "" : "s") + " started earlier "
      + (nLive === 1 ? "is" : "are") + " still going. Stop " + (nLive === 1 ? "it" : "them")
      + " from the Runs table."));
    card.appendChild(w);
  }
  // A kept run dir used to be visible only as a count on the Sessions tab --
  // findable only by an operator who already suspected one was there. See it
  // here instead, on the job it belongs to.
  sessionNotices(j.id).forEach(n => card.appendChild(n));

  card.appendChild(el("div", "desc", j.description || ""));

  // ---- the pulse: this job's own 24h, at one bar an hour. Plain div/i bars
  // (.spark/.spark i in pages.css), the same mechanism renderPulse's own
  // band draws with above -- there is no SVG sparkline in this stylesheet.
  const series = Array.isArray(chk.series) ? chk.series : [];
  const woke = Array.isArray(chk.woke) ? chk.woke : [];
  const peak = series.reduce((m, n) => Math.max(m, n), 0);
  let spark;
  if(peak){
    // No bars at all when there is nothing to plot -- an empty 110px
    // sparkline just pushed the sentence explaining the emptiness into the
    // middle of the card.
    spark = el("span", "spark");
    spark.title = chk.checks + " checks in the last 24h, one bar an hour";
    series.forEach((n, i) => {
      const bar = el("i", woke[i] ? "w" : null);
      bar.style.height = (n ? Math.max(8, n / peak * 100).toFixed(0) : 0) + "%";
      spark.appendChild(bar);
    });
  }else{
    spark = icon("activity");
  }
  const sparkLine = el("div", "cardline");
  sparkLine.appendChild(spark);
  const sparkn = el("span", "sparkn grow");
  if(chk.checks){
    sparkn.appendChild(el("b", null, String(chk.checks)));
    sparkn.appendChild(document.createTextNode(" check" + (chk.checks === 1 ? "" : "s") + " · "));
    sparkn.appendChild(el("b", null, String(chk.runs)));
    sparkn.appendChild(document.createTextNode(" woke a run"));
    if(chk.failed){
      sparkn.appendChild(document.createTextNode(" · "));
      sparkn.appendChild(el("b", "s-error", chk.failed + " failed"));
    }
  }else{
    sparkn.textContent = disabled ? "no automatic checks — disabled" : "no automatic checks in 24h";
  }
  sparkLine.appendChild(sparkn);

  // A job may have SEVERAL runs going at once, so say how many rather than
  // one "running now". The per-run outcome is not summarised on the card:
  // each run is individual and carries its own status in the Runs table.
  const runLine = el("div", "cardline");
  runLine.appendChild(icon("play"));
  const runGrow = el("span", "grow");
  if(nLive){
    const badge = el("span", "runningbadge");
    badge.appendChild(el("span", "pulse"));
    badge.appendChild(document.createTextNode(nLive + " running now…"));
    runGrow.appendChild(badge);
  }
  if(st.last_run_start){
    runGrow.appendChild(el("span", "muted",
      (nLive ? " · last ran " : "last ran ") + fmtAgo(st.last_run_start)));
  }else if(!nLive){
    runGrow.appendChild(el("span", "muted", "never ran"));
  }
  runLine.appendChild(runGrow);

  // ---- what the probe last saw. Its own line only when there is something
  // to say: on a job that has never been checked, three rows of "never" said
  // nothing three times over.
  let probeLine = null;
  let checkItems = null;
  if(st.last_start || hasProbe){
    const line = el("div", "cardline top");
    line.appendChild(icon("radar"));
    const grow = el("span", "grow");
    if(st.last_start) grow.appendChild(document.createTextNode("probed " + fmtAgo(st.last_start)));
    if(hasProbe){
      // Three outcomes, not two. A probe that could not run (any exit other
      // than 0 or 1) once rendered as the calm "nothing to do", so a job
      // whose credentials had gone missing looked healthy while it silently
      // never ran again. See probeVerdict's own comment.
      grow.appendChild(document.createTextNode(st.last_start ? " — " : "last probe: "));
      grow.appendChild(probeVerdict(pc));
      // The counts the probe reported get their own panel beside the status
      // lines, instead of trailing off the end of one of them. They are the
      // densest thing on the card and the reason you look at it.
      checkItems = checkList(pc.output);
    }
    line.appendChild(grow);
    probeLine = line;
  }

  const cardstat = el("div", "cardstat");
  cardstat.appendChild(sparkLine);
  cardstat.appendChild(runLine);
  if(probeLine) cardstat.appendChild(probeLine);
  // Two columns when there is a probe result to show: the job's own state on
  // the left, what its precheck counted on the right.
  const cardbody = el("div", "cardbody" + (checkItems ? " has-checks" : ""));
  cardbody.appendChild(cardstat);
  if(checkItems){
    const panel = el("div", "checkpanel");
    panel.appendChild(el("div", "cp-h", "Pre-checks"));
    panel.appendChild(checkItems);
    cardbody.appendChild(panel);
  }
  card.appendChild(cardbody);

  // `next` sits under both columns -- it is the conclusion the two of them
  // lead to.
  const nextLine = el("div", "cardline");
  nextLine.appendChild(icon("cright"));
  nextLine.appendChild(el("span", "lbl", "next"));
  const nextGrow = el("span", "grow");
  nextGrow.appendChild(nextRunNote(j, F));
  nextLine.appendChild(nextGrow);
  card.appendChild(nextLine);

  // ---- the money. A cap you are close to is worth seeing before you hit it.
  const model = eff(j, "model", "opus"), perm = eff(j, "permission_mode", "dontAsk"),
        budg = eff(j, "max_budget_usd", 2);
  const pct = (cap != null && cap > 0) ? Math.min(100, spentToday / cap * 100) : 0;
  const tone = spendTone(spentToday, cap);
  const spend = el("div", "spend");
  if(cap != null){
    const bar = el("div", "spendbar" + (tone ? " " + tone : ""));
    const fill = el("i");
    fill.style.width = pct.toFixed(1) + "%";
    bar.appendChild(fill);
    spend.appendChild(bar);
  }
  const spendtxt = el("div", "spendtxt");
  const left = el("span");
  left.appendChild(document.createTextNode(money(spentToday) + " today "));
  left.appendChild(cap != null
    ? el("span", "cap", "of " + money(cap))
    : el("span", "muted", "· no daily cap"));
  spendtxt.appendChild(left);
  if(capped) spendtxt.appendChild(el("span", "s-error", "capped until midnight"));
  spend.appendChild(spendtxt);
  card.appendChild(spend);

  // ---- settings, one line. Only what this job overrides on top of its
  // project is inked; the rest is inherited and stays quiet. Listing all
  // nine on every card is what made twenty-one cards look identical.
  const p = j.project ? projById(j.project) : null;
  const own = (field) => j[field] != null && j[field] !== "" && p != null
    && String(j[field]) !== String(p[field] == null ? "" : p[field]);
  const bit = (txt, mine, cls) => el("span", mine ? (cls || "o") : null, txt);
  // An icon on the three that answer a different question -- how often,
  // when, how much. Five bare phrases in a row read as one long string; the
  // marks are what let the eye jump to the one it wants.
  const marked = (iconName, inner) => {
    const s = el("span", "cfgi");
    s.appendChild(icon(iconName));
    s.appendChild(inner);
    return s;
  };
  const cfg = el("div", "cfgline");
  cfg.appendChild(marked("timer", bit("every " + fmtDur(j.interval_seconds || 300), own("interval_seconds"))));
  cfg.appendChild(marked("clock", bit((j.active_hours || "24h") + " "
    + fmtDays(j.active_days || [1, 2, 3, 4, 5, 6, 7]), own("active_hours") || own("active_days"))));
  cfg.appendChild(bit(model, own("model")));
  if(effortLabel(eff(j, "effort", "")) !== "default"){
    cfg.appendChild(bit(effortLabel(eff(j, "effort", "")), own("effort")));
  }
  cfg.appendChild(marked("dollar", bit(money(budg) + "/run", own("max_budget_usd"))));
  // a permission mode is the one setting worth flagging rather than folding away
  cfg.appendChild(bit(perm, perm !== "dontAsk", "warn"));
  card.appendChild(cfg);

  // Run now always available: several runs of a job may go at once (up to
  // max_parallel), so a live run no longer replaces this with a stop.
  // Stopping is per-run, from the Runs table -- a job-wide stop would kill
  // them all. It carries the accent whether or not the job is enabled,
  // because it WORKS whether or not the job is enabled -- it is a
  // deliberate manual override, and the primary action on the card.
  const actions = el("div", "actions");
  const runBtn = el("button", "btn primary");
  runBtn.dataset.op = "run"; runBtn.dataset.id = j.id;
  runBtn.appendChild(icon("play"));
  runBtn.appendChild(document.createTextNode("Run now"));
  actions.appendChild(runBtn);

  const toggleBtn = el("button", "btn");
  toggleBtn.dataset.op = disabled ? "enable" : "disable";
  toggleBtn.dataset.id = j.id;
  toggleBtn.appendChild(icon("power"));
  toggleBtn.appendChild(document.createTextNode(disabled ? "Enable" : "Disable"));
  actions.appendChild(toggleBtn);

  const editBtn = el("button", "btn");
  editBtn.dataset.op = "edit"; editBtn.dataset.id = j.id;
  editBtn.appendChild(icon("pencil"));
  editBtn.appendChild(document.createTextNode("Edit"));
  actions.appendChild(editBtn);

  // Delete sits behind the overflow: it is irreversible, and as a fourth
  // equal button it was one slip away from Edit on every card.
  const menu = el("div", "menu");
  const menuBtn = el("button", "iconbtn");
  menuBtn.dataset.menu = j.id;
  menuBtn.setAttribute("aria-haspopup", "menu");
  menuBtn.setAttribute("aria-expanded", "false");
  menuBtn.title = "More actions";
  menuBtn.appendChild(icon("dots"));
  menu.appendChild(menuBtn);

  const pop = el("div", "menu-pop");
  pop.setAttribute("role", "menu");
  pop.hidden = true;
  const jobRunsBtn = el("button");
  jobRunsBtn.setAttribute("role", "menuitem");
  jobRunsBtn.dataset.jobruns = j.id;
  jobRunsBtn.appendChild(icon("activity"));
  jobRunsBtn.appendChild(document.createTextNode("Show this job's runs"));
  pop.appendChild(jobRunsBtn);
  pop.appendChild(el("div", "sep"));
  const delBtn = el("button", "danger");
  delBtn.setAttribute("role", "menuitem");
  delBtn.dataset.op = "delete"; delBtn.dataset.id = j.id;
  delBtn.appendChild(icon("trash"));
  delBtn.appendChild(document.createTextNode("Delete job"));
  pop.appendChild(delBtn);
  menu.appendChild(pop);
  actions.appendChild(menu);
  card.appendChild(actions);

  return card;
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
   `filter` means; the door-vs-plain-element test beside it pins this. */
export function kpiCard(opts){
  // `opts` rather than destructuring in the parameter list itself: _plainfn
  // (tests/test_page_contract.py) extracts a function by name by matching
  // braces starting from the first opening brace after its name, and a
  // destructured parameter's own opening brace would be mistaken for the
  // body's. Destructuring on the next line instead keeps every call site
  // (`kpiCard({icon, tone, ...})`) exactly as it was.
  const {icon: iconName, tone, value, label, sub, filter, door} = opts;
  const card = el(door ? "button" : "div", "kpi-card" + (tone ? " " + tone : ""));
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
      label: c.label, sub: c.sub, filter: c.filter, door: c.door,
    })));
  }

  const bandHost = $("stats");
  if(bandHost){
    bandHost.textContent = "";
    bandHost.appendChild(renderPulse(ticks, jobs));
  }
}
