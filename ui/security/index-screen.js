/* ------------------------------------------------------------ the index
   The Security area's front page: one request, `GET /api/security/index`,
   answers with everything this screen draws -- the five KPI cards, the
   project table (one row per project, its default branch's current
   posture), the recent-analyses feed and the severity donut with the rules
   that produced it. See bin/security/cli.py's `index-data` and
   bin/claude-cron-server's `security_index`/`_security_projects`.

   The old per-project list (projects.js) cost one subprocess PER PROJECT on
   every load and every Refresh -- `security list`, and for whichever
   project had a finished analysis, `security checklist` on top. This is the
   whole screen in one call, however many projects are configured.

   Cached the same way projects.js cached postures: fetched once, painted
   from the cache on every repaint the poll drives (renderSecurity() in
   index.js calls secRenderIndex() unconditionally, the same as it always
   called secRenderList()), and refetched only on an explicit Refresh or
   when something that changed the numbers just happened (secBack(), after
   leaving a project screen where an analysis may have just finished). */
import { $, fmtAgo, money, pageHeader, kpiCard, tableFooter, openProjectEditor } from "./page.js";
import { secIcon, secEl, secFetch } from "./dom.js";
import { SEC_NEVER, SEC_FLOOR_SCOPE_NOTE } from "./vocabulary.js";
import { secOpenProject } from "./project-screen.js";
// secOpenActivity: the kebab's own "View activity" item (Phase 4 Task 3)
// opens the SAME Activity screen the header button always has, scoped to
// this one row's project -- secOpenActivity(project) already takes that
// filter (index.js's own openActivity binding passes "" for "every
// project"). No cycle risk this file did not already have: project-screen.js
// already imports back from here (secIndexPosturePills/secIndexDonut, below),
// and activity-screen.js imports nothing from this module.
import { secOpenActivity } from "./activity-screen.js";

let secIndexCache = null;
let secIndexGen = 0;

/* Called after anything that could have changed the fleet's posture (a run
   just finished, a decision was just made) so the next paint asks again
   rather than repeating stale numbers. */
export function secInvalidateIndex(){ secIndexCache = null; }

export async function secLoadIndex(force){
  if(secIndexCache && !force) return;   // nothing to do -- already have an answer to paint
  if(force) secIndexGen++;
  const gen = secIndexGen;
  if(!secIndexCache){
    const host = $("sec-list");
    if(host){ host.textContent = ""; host.appendChild(secEl("div", "tblempty", "Loading…")); }
  }
  let data;
  try{
    data = await secFetch("/api/security/index");
  }catch(e){
    if(gen !== secIndexGen) return;      // a newer request (Refresh) already answered
    const host = $("sec-list");
    if(host){
      host.textContent = "";
      const box = secEl("div", "tblempty");
      box.appendChild(secIcon("alert"));
      box.appendChild(document.createTextNode(
        "Could not read the security index — " + e.message));
      host.appendChild(box);
    }
    return;
  }
  if(gen !== secIndexGen) return;
  secIndexCache = data;
  secRenderIndex();
}

/* The index's own page header (Phase 4 Task 1) -- shield, "Security", one
   sentence, no trailing actions (Phase 4 Task 3 moved Activity/Refresh down
   into the projects filter bar -- see this function's own inline comment
   below for why, and secProjectsFilterBar for where they landed). Before
   Task 1 this was a loose <p class="paneblurb"> plus a bare .toolbar
   holding those same two buttons. #sec-head is static markup
   (bin/dashboard.html), always in the DOM whether or not the security view
   is the one showing, the same as #jobs-head/#prj-head/#runs-head already
   are for their own pages.

   Rebuilt whole on every call, exactly like every other page's own
   pageHeader() call (renderJobsPage(), renderProjectsPage(), ...) -- cheap,
   nothing here carries a listener of its own to lose by doing so.

   Called from secRenderIndex() rather than ui/security/index.js's own
   init(), and this is not a style choice: init() runs inside
   CCSecurity.init(CC), which bin/dashboard.html calls BEFORE CCApp.init() --
   see that file's own banner comment above the CC object. pageHeader (like
   kpiCard) calls straight into `icon()`, which for this bridge resolves to
   ui/app/page.js's own binding, and that binding is not set until
   CCApp.init() runs. Calling pageHeader() from inside init() would read it
   in its temporal dead zone and throw on every load. secRenderIndex() only
   ever runs off a poll tick or a resolved fetch, both strictly after the
   page's own script has finished running top to bottom -- CCApp.init()
   included -- so this is the earliest point that is actually safe. */
function secRenderHead(){
  const host = $("sec-head");
  if(!host) return;
  host.textContent = "";
  // No trailing actions here any more (Phase 4 Task 3): the mockup's own
  // header carries none -- just the shield, the title and the one sentence.
  // Activity and Refresh both moved down into the projects filter bar's own
  // right side instead (secProjectsFilterBar, below the table), the mockup's
  // named place for Refresh; the mockup has no Activity button at all, so
  // this is a deliberate divergence-resolution, not something it shows.
  // Both ids (#sec-view-activity/#sec-reload) are UNCHANGED, so
  // bin/dashboard.html's existing delegated click listener answers them
  // from their new home exactly as it did in the header.
  host.appendChild(pageHeader({
    icon: "shield", title: "Security",
    subtitle: "Vulnerability analysis across your projects.",
  }));
}

/* Cheap and synchronous: paints whatever is already cached, or leaves the
   host exactly as secLoadIndex last left it (its own "Loading…" placeholder,
   or an error) when nothing has answered yet. Safe to call on every poll
   tick -- it touches no network -- so the relative "3m ago" stamps in the
   recent-analyses feed and the project table stay current between fetches. */
export function secRenderIndex(){
  secRenderHead();
  const host = $("sec-list");
  if(!host) return;
  if(!secIndexCache) return;
  const data = secIndexCache;

  // Five stable slots, mounted ONCE and never torn down again after that --
  // unlike every other repaint on this screen, the Projects slot below holds
  // the filter bar's own live search box, and an operator mid-keystroke in
  // it must not lose focus every five seconds the way unconditionally
  // rebuilding this whole host (as this function used to) would risk: a real
  // DOM node loses focus the instant it is DETACHED, even if the very same
  // node is reattached one line later with its value untouched -- see
  // mountJobsToolbar's own comment (ui/app/jobs-table.js) for the identical
  // reasoning Jobs' own search box already relies on. Everything else below
  // still repaints whole on every call, exactly as before -- cheap, and none
  // of it holds anything an operator could be mid-typing into.
  //
  // `host.contains(...)`, not a `dataset.mounted` flag: secLoadIndex's own
  // "Loading…" placeholder (above) clears this SAME host whenever the cache
  // is invalidated (an explicit Refresh, or secBack() after leaving a
  // project screen) -- found live, the hard way, clicking "View activity"
  // and then "All projects" back to a Security screen stuck on "Loading…"
  // forever. A `dataset` flag survives that clear (it lives on the host
  // element itself, not its children) and would have skipped remounting
  // right when there was nothing left in the DOM TO update -- checking
  // whether the slot is ACTUALLY still attached catches that wipe and
  // remounts for real, at the one-time cost of a fresh (empty) search box
  // on an explicit reload, never on the five-second poll this guard exists
  // for in the first place.
  if(!host.contains(host._secProjects)){
    host.textContent = "";
    host._secCards = secEl("div");
    host._secProjects = secEl("div", "secidx-section");
    host._secRecent = secEl("div");
    host._secDonut = secEl("div");
    host.appendChild(host._secCards);
    // ONCE per screen, under the cards and above every other number on it --
    // the KPI cards, the table's findings chips and the donut are all
    // UNFLOORED, and until this line existed nothing anywhere said so while
    // the drill-down one click away openly held rows back. A fixed constant,
    // painted once at mount and never touched again -- see
    // SEC_FLOOR_SCOPE_NOTE's own comment in vocabulary.js for the decision.
    host.appendChild(secEl("div", "secpj-caption", SEC_FLOOR_SCOPE_NOTE));
    host.appendChild(host._secProjects);
    host.appendChild(host._secRecent);
    host.appendChild(host._secDonut);
    secMountProjectsSection(host._secProjects);
  }

  host._secCards.textContent = "";
  host._secCards.appendChild(secIndexCards(data.summary || {}));

  // The table's own filter bar reads this on every keystroke/picker change,
  // never fetching again -- "filters THIS table client-side from what the
  // payload carries" (Phase 4 Task 3), not a new round trip per filter.
  secLatestProjects = data.projects || [];
  secRefreshFilterOptions(secLatestProjects);
  secRepaintProjectsTable();

  host._secRecent.textContent = "";
  host._secRecent.appendChild(secIndexSection("Recent analyses",
    secIndexRecent(data.recent || [])));

  host._secDonut.textContent = "";
  host._secDonut.appendChild(secIndexSection("Findings by severity",
    // The donut is the fleet's whole posture rolled into one figure, so it
    // cannot carry the per-row `incomplete` badge the table beside it uses --
    // it gets the same caveat the Critical/High cards get, from the same
    // count, or it is the one number on this screen that still presents a
    // partial read as a complete one.
    secIndexDonut(data.donut || {}, data.categories || [],
                  secCappedNote(data.summary || {}))));
}

/* The one sentence the cards, the donut and (via project-data's own
   `capped_branches`) the project sidebar all use for a PARTIAL read, so the
   caveat reads identically wherever a rollup cannot show a per-row badge.
   `n` of `of` had their latest analysis stop before covering the whole
   scope: what is counted is what was found before it stopped, not what is
   there. */
export function secCappedScopeNote(n, of, noun){
  if(!n) return "";
  return n + " of " + of + " " + noun + (of === 1 ? "" : "s")
    + " had a latest analysis that stopped before covering its whole scope "
    + "— this total may be an undercount";
}

function secCappedNote(summary){
  return secCappedScopeNote(summary.capped_projects || 0,
                            summary.projects || 0, "project");
}

function secIndexSection(title, body){
  const sec = secEl("div", "secidx-section");
  sec.appendChild(secEl("h3", null, title));
  sec.appendChild(body);
  return sec;
}

/* ------------------------------------------------------------------ cards
   Five cards for the five COUNTS `index_summary` computes -- `projects`,
   `analyses`, `critical`, `high`, `success_rate` -- no sixth number invented
   here, and none of these five dropped. `capped_projects` is not a card of
   its own: it qualifies the Critical/High cards' own note when the fleet
   total they show might be an undercount (see the comment below).

   Built with the bridged kpiCard() (Phase 4 Task 1) instead of a local
   secIndexCard() helper -- the mockup draws these five exactly like every
   other page's KPI row (number beside a tinted icon, then a bold label, then
   a muted one-line sub), so this area reaches for the SAME builder Jobs/
   Runs/Projects already do rather than keeping its own inverted variant
   (number below the icon, no tone) in step by hand. See ui/security/page.js
   for how kpiCard reaches this file without ui/security/ importing
   ui/app/chrome.js directly.

   The label and sub are now FIXED, mockup-drawn strings -- "Critical
   findings"/"needs immediate attention", not a number-qualified sentence --
   which leaves nowhere left in the card's own layout for a caveat as long as
   the capped/fell-back note above. `title` is that home: kpiCard's own
   comment in chrome.js already uses it for exactly this, "the definition of
   what the card is counting" as a native tooltip instead of squeezed into
   `sub`. Critical and High both carry the caveat there when one applies, and
   the plain "Open now, in every project's latest analysis" sentence
   otherwise -- so the card that never has a caveat still explains its own
   count on hover, the same as it did before this task touched it. */
function secIndexCards(summary){
  const wrap = secEl("div", "kpi-grid");
  const s = summary || {};
  wrap.appendChild(kpiCard({icon: "folder", value: String(s.projects || 0),
    label: "Projects", sub: "with security enabled"}));
  wrap.appendChild(kpiCard({icon: "activity", value: String(s.analyses || 0),
    label: "Total analyses", sub: "across all projects",
    title: "All time — a historical total, not current posture"}));
  // A capped analysis is a PARTIAL read of the repository (see secPaint's own
  // notice on the analysis screen): its "critical: 0"/"high: 0" means "none
  // found before it stopped," not "none." Folding one into these totals with
  // no cue would present a total that looks complete when it might not be --
  // so when index_summary says any project's LATEST analysis stopped short,
  // the cards say how many, instead of just the number.
  //
  // A FALLEN-BACK project is the other way these two totals can mislead, and
  // it used to be silent here: the project's declared base has never been
  // analysed, so its contribution was read off a branch nobody named. The
  // table below says so per row (secIndexProjectRow's own Last analysis
  // cell, its "profile · branch" sub-line); the cards summing those same
  // postures said nothing, and a fallback branch is never silent in this
  // area. Both caveats are qualifications of the SAME number, so they share
  // one note rather than competing for the same line.
  const capped = s.capped_projects || 0;
  const fellBack = s.fell_back_projects || 0;
  const total = s.projects || 0;
  const caveats = [];
  if(capped) caveats.push(secCappedScopeNote(capped, total, "project"));
  if(fellBack){
    caveats.push(fellBack + " of " + total + " project" + (total === 1 ? "" : "s")
      + " is counted from a branch other than its declared base, because that "
      + "base has never been analysed");
  }
  const cappedNote = caveats.length ? caveats.join(" · ")
                                    : "Open now, in every project's latest analysis";
  wrap.appendChild(kpiCard({icon: "shield", tone: "err", value: String(s.critical || 0),
    label: "Critical findings", sub: "needs immediate attention", title: cappedNote}));
  wrap.appendChild(kpiCard({icon: "alertcircle", tone: "warn", value: String(s.high || 0),
    label: "High severity", sub: "requires review", title: cappedNote}));
  const rate = s.success_rate;
  // A dash, not 0%: no finished analysis is not a zero-percent success rate --
  // those are different facts, and the number below has to say which one it is.
  //
  // "All time" still said, just moved: this card sits between two cards that
  // say "open now" and is itself a historical ratio over every analysis ever
  // run, which is exactly the unlabelled scope clash this area has had to
  // fix five times over -- the sentence saying so is now the card's `title`
  // rather than its `sub`, since the mockup's own sub for this card is the
  // fixed "analyses completed", the same three-to-five-word budget every
  // other card's sub keeps to.
  wrap.appendChild(kpiCard({icon: "check", tone: "ok",
    value: rate == null ? "—" : Math.round(rate * 100) + "%",
    label: "Success rate",
    sub: rate == null ? "No finished analysis yet" : "analyses completed",
    title: rate == null ? "" : "All time — a historical total, not current posture: "
      + "finished analyses that completed clean, not capped or failed"}));
  return wrap;
}

/* ------------------------------------------------------------- the table
   secIndexPosturePills and secIndexDonut (below) are exported too: the
   project screen's Overview tab needs the identical severity pills, and its
   sidebar needs the identical donut+categories block -- the same shapes,
   the same colours, the same "nothing open" wording, so a reader moving
   between the two screens never has to learn a second rendering of the
   same numbers. See ui/security/project-screen.js. */
export function secIndexPosturePills(posture){
  const wrap = secEl("span", "sevpills");
  const p = posture || {};
  if(!p.total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  ["critical", "high", "medium", "low", "info"].forEach(sev => {
    if(p[sev]) wrap.appendChild(secEl("span", "sevpill " + sev, p[sev] + " " + sev));
  });
  return wrap;
}

/* ------------------------------------------------- the 8-column redesign
   Phase 4 Task 3: the mockup's own table, column for column -- Project,
   Last analysis, Profile, Last run, Findings, Trend (30d), Status, Actions
   -- replacing the flat five (Project/Branch/Posture/Last analysis/
   Analyses) the JSON contract tests alone used to drive. Every cue the
   pinned tests above already hold this screen to survives the reshape:
   a capped analysis still marks its row (now on the Findings cell, where
   the counts it qualifies actually are); a fallen-back branch still names
   itself, now inside the Last analysis cell's own "profile · branch" sub-
   line instead of a dedicated Branch column; never-analysed still reads
   SEC_NEVER, not a bare dash. `secEl`/text nodes only, same as every other
   line this area draws -- a finding's own strings never had to pass through
   here, but the discipline is the same one test_findings_row_renders_
   analysed_strings_as_text_never_markup holds the findings screen to. */
const FIND_SEVS = ["critical", "high", "medium"];

/* The three fixed severities, ALWAYS three chips (even a 0), unlike
   secIndexPosturePills' own "only show what's open" -- that shape suits a
   pill row of unpredictable length elsewhere, but three numbers this small
   are read as one fixed row (crit/high/med, always in that order); letting
   the count of chips itself vary would move the numbers the cell exists to
   let a reader find at a glance. `total` (posture's OWN total, not a sum of
   the three chips) can be larger than what they show -- low/info both count
   toward it without a chip of their own, exactly as the mockup's own "89
   total" undershoots 12+27+43. `capped`, when true, appends the SAME
   incomplete cue the row used to carry on its Posture cell -- the counts
   above it are what a partial read had reached, not what is there. */
function secIndexFindingsChips(posture, capped){
  const p = posture || {};
  const wrap = secEl("div", "secidx-findcell");
  const chips = secEl("div", "sevpills");
  FIND_SEVS.forEach(sev => chips.appendChild(
    secEl("span", "sevpill " + sev, String(p[sev] || 0))));
  wrap.appendChild(chips);
  wrap.appendChild(secEl("div", "secidx-findtotal", (p.total || 0) + " total"));
  if(capped){
    // THE SAME NOTICE secPaint gives on the analysis screen itself: a capped
    // analysis is a PARTIAL read of the repository, and the counts above
    // this badge are the counts of a partial read -- "critical: 0" means
    // "none found before it stopped," not "none."
    const badge = secEl("span", "secidx-capped", "incomplete");
    badge.title = "This analysis is INCOMPLETE: it stopped before covering "
      + "the whole scope. The counts above are what it had reached, not "
      + "what is there.";
    wrap.appendChild(badge);
  }
  return wrap;
}

/* A bar sparkline over `trend` (bin/security/queries.py's trend_series --
   the open-findings count at each finished analysis of the project's own
   declared branch, oldest first), baseline-aligned, accent-coloured, built
   with createElementNS like the donut beside it. `.style.fill`, not a CSS
   class on the bar itself -- an SVG element's own `className` has no plain
   setter in a real browser (unlike an HTMLElement's), so this mirrors
   secIndexDonutSvg's own `.style.stroke` exactly rather than reaching for a
   mechanism that silently no-ops there. An EMPTY list (no declared base, or
   a declared base never analysed -- trend_series returns [] for both,
   deliberately never plotting a fallback branch's history under a name it
   does not belong to) renders an honest muted dash, not a fabricated flat
   line pretending to be a real zero-history reading. */
function secIndexTrendSpark(trend){
  const points = (trend || []).map(n => Math.max(0, n || 0));
  if(!points.length) return secEl("span", "muted", "—");
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 100 32");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "secidx-spark-svg");
  svg.setAttribute("role", "img");
  const max = Math.max(1, ...points);
  const n = points.length;
  const slot = 100 / n;
  const barW = Math.max(0.6, slot * 0.6);
  points.forEach((v, i) => {
    // A floor of 1 unit tall: a true zero still draws a hairline at the
    // baseline, which reads as "measured, and it was zero" -- an invisible
    // 0-height bar would read as a gap in the series instead.
    const h = Math.max(1, (v / max) * 30);
    const bar = document.createElementNS(ns, "rect");
    bar.setAttribute("x", String(i * slot + (slot - barW) / 2));
    bar.setAttribute("y", String(32 - h));
    bar.setAttribute("width", String(barW));
    bar.setAttribute("height", String(h));
    bar.style.fill = "var(--accent)";
    svg.appendChild(bar);
  });
  return svg;
}

// "deep" -> "Deep": PROFILE's own pill text and the LAST ANALYSIS sub-line
// both want the mockup's Title Case, not the lowercase the CLI/ledger store.
function secProfileLabel(profile){
  return profile ? profile[0].toUpperCase() + profile.slice(1) : "";
}

// "2h 15m"/"45m": LAST RUN's own duration, coarser than the shared fmtDur
// (ui/app's own "135m 0s") on purpose -- an hours-and-minutes reading is
// what the mockup shows for a run long enough to have an hours digit at
// all, and fmtDur's seconds digit would just be noise at this scale.
function secLastRunDuration(seconds){
  const s = Math.max(0, Math.floor(seconds || 0));
  if(s < 60) return s + "s";
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return (h ? h + "h " : "") + m + "m";
}

// "Aug 21, 7:23 AM": LAST RUN's own sub-date -- the shared fmtWhen (page.js)
// spells out the full numeric date AND the seconds (e.g. "8/21/2026,
// 7:23:19 AM"), which is the right call for an exact-timestamp tooltip
// elsewhere but far more than this sub-line's own small type has room for;
// this is a purpose-built reading for this one cell, not a second fmtWhen.
function secIndexRunWhen(ts){
  if(!ts) return "";
  return new Date(ts * 1000).toLocaleString(undefined,
    {month: "short", day: "numeric", hour: "numeric", minute: "2-digit"});
}

function secIndexProjectRow(p){
  const tr = document.createElement("tr");
  tr.className = "secidx-rowlink";
  // The row already answers this click -- View (the Actions cell, below)
  // and a click anywhere else in the row do the same one thing, so a mouse
  // user never has to land on the one small button to open a project.
  tr.onclick = () => secOpenProject(p.name);

  // PROJECT: folder icon, bold name, a small green enabled badge, a
  // two-line grey description. The badge is UNCONDITIONAL, not a second
  // read of the Status cell's own `p.enabled` below -- every row on this
  // screen is, by construction, a security-ENABLED project
  // (_security_projects(), bin/claude-cron-server, never hands this screen
  // one that is not), so this badge and Status answer two independent
  // questions (security on; the PROJECT itself active) that happen to both
  // be true for most rows, not the same fact painted twice.
  const tdProject = document.createElement("td");
  const nameLine = secEl("div", "secidx-pname");
  nameLine.appendChild(secIcon("folder"));
  nameLine.appendChild(secEl("span", "secidx-pname-text", p.name));
  const badge = secEl("span", "secidx-enabled");
  badge.appendChild(secIcon("shieldcheck"));
  badge.title = "Security analysis is enabled for this project";
  nameLine.appendChild(badge);
  tdProject.appendChild(nameLine);
  if((p.description || "").trim()){
    tdProject.appendChild(secEl("div", "secidx-desc", p.description));
  }
  tr.appendChild(tdProject);

  // LAST ANALYSIS: relative time, then "profile · branch" beneath -- the
  // fallen-back note moves here from the old dedicated Branch column, the
  // branch's own name still visible right beside it (postures of different
  // branches must never be confused in silence -- see the note this used to
  // carry on tdBranch).
  const tdAnalysis = document.createElement("td");
  if(!p.analyses){
    // The compact density of the one wording (see SEC_NEVER in
    // vocabulary.js): the cell has room for the label, the title carries the
    // same "and here is what to do" sentence the full-width empty states
    // render, so no occurrence of this fact is a dead end.
    tdAnalysis.textContent = SEC_NEVER.short;
    tdAnalysis.title = SEC_NEVER.next;
  }else{
    tdAnalysis.appendChild(document.createTextNode(fmtAgo(p.last_started)));
    const sub = secEl("div", "secidx-sub");
    // Lowercase, unlike the Profile column's own pill (secProfileLabel) --
    // the mockup's own sub-line reads "deep · develop", the raw profile
    // string the payload already carries, not Title Case repeated twice on
    // the same row.
    sub.appendChild(document.createTextNode(
      [p.profile, p.branch || "—"].filter(Boolean).join(" · ")));
    if(p.branch_fell_back){
      sub.appendChild(secEl("span", "secidx-fellback",
        " (fell back — the default branch was never analysed)"));
    }
    tdAnalysis.appendChild(sub);
  }
  tr.appendChild(tdAnalysis);

  // PROFILE: a pill (Deep/Standard/Quick).
  const tdProfile = document.createElement("td");
  if(p.profile){
    tdProfile.appendChild(secEl("span", "pill profile", secProfileLabel(p.profile)));
  }else{
    tdProfile.appendChild(secEl("span", "muted", "—"));
  }
  tr.appendChild(tdProfile);

  // LAST RUN: the last analysis's own duration, its date beneath -- from
  // the row data this screen already has (project_rows' own `last_duration`/
  // `last_started`), no new fetch.
  const tdRun = document.createElement("td");
  if(p.last_duration){
    tdRun.appendChild(document.createTextNode(secLastRunDuration(p.last_duration)));
    tdRun.appendChild(secEl("div", "secidx-sub", secIndexRunWhen(p.last_started)));
  }else{
    tdRun.appendChild(secEl("span", "muted", "—"));
  }
  tr.appendChild(tdRun);

  // FINDINGS: three severity chips plus "N total", the capped cue attached
  // here now -- the counts it qualifies are the ones on this cell.
  const tdFindings = document.createElement("td");
  tdFindings.appendChild(secIndexFindingsChips(p.posture, p.last_state === "capped"));
  tr.appendChild(tdFindings);

  // TREND (30D): the bar sparkline, or an honest dash.
  const tdTrend = document.createElement("td");
  tdTrend.appendChild(secIndexTrendSpark(p.trend));
  tr.appendChild(tdTrend);

  // STATUS: Active (green) or the grey disabled pill -- `.pill.off` stays
  // reserved for the scheduler fault (components.css), never for a project
  // simply switched off. `enabled` is read `!== false`, the same convention
  // jobFacts (ui/app/jobs-domain.js) already uses for a job: not because
  // the real payload sends it false today (every row here is already
  // security-enabled by construction -- see the PROJECT cell's own comment
  // above), but so a fabricated or future payload can drive this branch
  // honestly instead of it being dead code with no producer.
  const tdStatus = document.createElement("td");
  const active = p.enabled !== false;
  tdStatus.appendChild(secEl("span", "pill " + (active ? "on" : "disabled"),
    active ? "Active" : "Disabled"));
  tr.appendChild(tdStatus);

  // ACTIONS: a solid View (the click the row already answers) plus a kebab
  // for the row's existing extra actions -- View activity for exactly this
  // project (secOpenActivity, already project-scoped) and Edit project
  // (openProjectEditor, the same dialog every other "Edit" in this app
  // opens). Both stop the click from also reaching the row's own handler.
  const tdActions = document.createElement("td");
  tdActions.className = "rowacts";
  const view = document.createElement("button");
  view.type = "button";
  view.className = "btn primary";
  view.appendChild(document.createTextNode("View"));
  view.onclick = (e) => { e.stopPropagation(); secOpenProject(p.name); };
  tdActions.appendChild(view);

  const kebab = document.createElement("details");
  kebab.className = "secidx-kebab";
  const summary = document.createElement("summary");
  summary.className = "iconbtn";
  summary.title = "More actions";
  summary.appendChild(secIcon("dots"));
  summary.onclick = (e) => e.stopPropagation();
  kebab.appendChild(summary);
  const pop = secEl("div", "menu-pop");
  pop.setAttribute("role", "menu");
  const actBtn = document.createElement("button");
  actBtn.setAttribute("role", "menuitem");
  actBtn.appendChild(secIcon("activity"));
  actBtn.appendChild(document.createTextNode("View activity"));
  actBtn.onclick = (e) => { e.stopPropagation(); kebab.open = false; secOpenActivity(p.name); };
  pop.appendChild(actBtn);
  const editBtn = document.createElement("button");
  editBtn.setAttribute("role", "menuitem");
  editBtn.appendChild(secIcon("pencil"));
  editBtn.appendChild(document.createTextNode("Edit project"));
  editBtn.onclick = (e) => { e.stopPropagation(); kebab.open = false; openProjectEditor(p.name); };
  pop.appendChild(editBtn);
  kebab.appendChild(pop);
  // `.table-card{overflow:hidden}` clips to its own rounded corners (see
  // that class's own comment, ui/css/components.css) and `.table-card td,
  // .table-card th{overflow:hidden}` clips a cell whose content spills past
  // its own column -- both real, load-bearing rules the table already
  // depends on, and both clip a plain `position:absolute` popup right along
  // with everything else escaping this row's own box: found live (the
  // popup's own layout rect was correct, `.open` was true, and nothing
  // painted). `ontoggle` -- a standard property, same "no addEventListener"
  // idiom as every other handler in this file -- recomputes `position:fixed`
  // coordinates from the button's own screen position each time the kebab
  // opens, which escapes every ancestor's overflow the way `position:
  // absolute` never can. A table scrolled sideways WHILE the popup is open
  // is the one thing this does not track (no scroll listener here for a
  // popup this short-lived) -- accepted rather than a second mechanism for
  // a case nobody scrolls into mid-click.
  kebab.ontoggle = () => {
    if(!kebab.open) return;
    const r = summary.getBoundingClientRect();
    pop.style.position = "fixed";
    pop.style.top = (r.bottom + 6) + "px";
    pop.style.right = (window.innerWidth - r.right) + "px";
    pop.style.left = "auto";
    pop.style.bottom = "auto";
  };
  tdActions.appendChild(kebab);
  tr.appendChild(tdActions);

  return tr;
}

// [key, label] tuples, JOB_COLS-shaped (ui/app/jobs-domain.js) even though
// nothing here sorts by one yet -- test_the_jobs_projects_and_runs_tables_
// declare_a_width_for_every_column (tests/test_page_contract.py) reads only
// `.length` off this, the same way it already does for JOB_COLS/PRJ_COLS/
// RUN_COLS, so a ninth column added here later is caught by the same guard
// with no change to the test itself.
const SEC_PROJECT_COLS = [
  ["project", "Project"], ["analysis", "Last analysis"], ["profile", "Profile"],
  ["run", "Last run"], ["findings", "Findings"], ["trend", "Trend (30d)"],
  ["status", "Status"], [null, ""],
];

/* `footer`, when given, is a pre-built tableFooter() (ui/app/chrome.js)
   element -- appended INSIDE the same .table-card the table itself sits in,
   never as a loose sibling below it (see tableFooter's own comment on
   test_the_jobs_table_footer_sits_inside_the_table_card for exactly the
   regression that shape used to be). Optional and ignored on the empty-state
   branch: secRepaintProjectsTable (below) is the only caller that ever
   passes one, and the pinned tests above call this with one argument, the
   same as before this task -- a filtered-to-nothing result is a DIFFERENT
   message, built by that caller instead of by this function (see its own
   comment), never this one's "nothing configured at all" empty state. */
function secIndexProjectsTable(projects, footer){
  if(!projects.length){
    const e = secEl("div", "tblempty");
    e.appendChild(secIcon("inbox"));
    e.appendChild(document.createTextNode(
      "No projects have security analysis enabled yet — turn it on in a "
      + "project's editor, on the Security tab."));
    return e;
  }
  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_PROJECT_COLS.forEach(([, label]) => htr.appendChild(secEl("th", null, label)));
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  projects.slice()
    .sort((a, b) => String(a.name).localeCompare(String(b.name)))
    .forEach(p => tbody.appendChild(secIndexProjectRow(p)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  if(footer) wrap.appendChild(footer);
  return wrap;
}

/* ------------------------------------------------------- the filter bar
   Search projects + Status + Profile + Branch + Refresh, per the mockup --
   filtering the SAME table client-side, from whatever `secLatestProjects`
   (the last payload's own `projects` array) already carries. No new fetch:
   Refresh (moved here from the header, see secRenderHead's own comment) is
   still the only thing that asks the server again.

   Plain <select>s, not chrome.js's own custom `.picker`/`makePicker()`
   widget (ui/app/chrome.js's own filterBar comment, and bin/dashboard.html's
   makePicker itself): that widget's pickers are static markup already
   wired, per id, inside dashboard.html at boot -- Jobs/Runs/Projects all
   reach for ALREADY-BUILT elements filterBar only lays out, never ones it
   builds itself. Four brand-new pickers for a screen in a SEPARATE bundle
   (ui/security/, built apart from ui/app/ -- see ui/security/index.js's own
   banner comment on why) would mean porting that widget's JS across the
   bundle split for this one filter bar, a bigger migration than this
   table's own redesign asked for -- `.filterpick` (ui/css/pages.css) copies
   `.picker-trigger`'s look by hand instead, so restyling the real widget
   later cannot silently restyle a plain select it was never meant to reach. */
let secProjectFilters = {query: "", status: "", profile: "", branch: ""};
let secLatestProjects = [];
let secProjectsTableHost = null;
let secProfileFilterSelect = null;
let secBranchFilterSelect = null;

/* Pure and exported: filters `projects` against `filters` with no DOM and
   no module state of its own, so a test can drive it directly with a
   fabricated array and fabricated filters and check exactly what survives. */
export function secFilterProjects(projects, filters){
  const f = filters || {};
  const q = (f.query || "").trim().toLowerCase();
  return (projects || []).filter(p => {
    if(q){
      const hay = ((p.name || "") + " " + (p.description || "")).toLowerCase();
      if(!hay.includes(q)) return false;
    }
    if(f.status){
      const active = p.enabled !== false;
      if(f.status === "active" && !active) return false;
      if(f.status === "disabled" && active) return false;
    }
    if(f.profile && (p.profile || "") !== f.profile) return false;
    if(f.branch && (p.branch || "") !== f.branch) return false;
    return true;
  });
}

function secOption(value, label){
  const o = document.createElement("option");
  o.value = value;
  o.textContent = label;
  return o;
}

// Repopulates an already-built <select> in place (never recreated -- see
// secMountProjectsSection's own comment on why the bar itself is built
// once) with "All" plus one option per value, restoring `selected` when it
// is still among them -- a stale profile/branch (the one project that had
// it is gone after a Refresh) must not silently pin the picker to a value
// nothing can ever match again.
function secFillFilterOptions(select, values, selected){
  select.textContent = "";
  select.appendChild(secOption("", "All"));
  values.forEach(v => select.appendChild(secOption(v, v)));
  select.value = (selected && values.includes(selected)) ? selected : "";
}

function secUniqueValues(projects, key){
  return [...new Set((projects || []).map(p => p[key]).filter(Boolean))].sort();
}

// One picker: an icon, a muted "Label:", the live <select> and a trailing
// chevron -- `.filterpick`'s own shape (ui/css/pages.css).
function secFilterPick(iconName, label, id){
  const wrap = secEl("label", "filterpick");
  wrap.appendChild(secIcon(iconName));
  wrap.appendChild(secEl("span", "fp-k", label));
  const select = document.createElement("select");
  select.id = id;
  wrap.appendChild(select);
  wrap.appendChild(secIcon("cdown"));
  return {wrap, select};
}

function secProjectsFilterBar(){
  const bar = secEl("div", "toolbar");

  const search = secEl("div", "searchbox");
  search.appendChild(secIcon("search"));
  const input = document.createElement("input");
  input.type = "search";
  input.placeholder = "Search projects…";
  input.setAttribute("aria-label", "Search projects by name or description");
  input.oninput = () => { secProjectFilters.query = input.value; secRepaintProjectsTable(); };
  search.appendChild(input);
  bar.appendChild(search);

  const status = secFilterPick("filter", "Status:", "secpj-filter-status");
  status.select.appendChild(secOption("", "All"));
  status.select.appendChild(secOption("active", "Active"));
  status.select.appendChild(secOption("disabled", "Disabled"));
  status.select.onchange = () => { secProjectFilters.status = status.select.value; secRepaintProjectsTable(); };
  bar.appendChild(status.wrap);

  const profile = secFilterPick("shield", "Profile:", "secpj-filter-profile");
  profile.select.onchange = () => { secProjectFilters.profile = profile.select.value; secRepaintProjectsTable(); };
  bar.appendChild(profile.wrap);
  secProfileFilterSelect = profile.select;

  const branch = secFilterPick("gitbranch", "Branch:", "secpj-filter-branch");
  branch.select.onchange = () => { secProjectFilters.branch = branch.select.value; secRepaintProjectsTable(); };
  bar.appendChild(branch.wrap);
  secBranchFilterSelect = branch.select;

  bar.appendChild(secEl("div", "spacer"));

  // Both ids unchanged from the header they moved out of -- see
  // secRenderHead's own comment on why that is enough for
  // bin/dashboard.html's existing delegated listener to keep answering them.
  const activity = document.createElement("button");
  activity.type = "button";
  activity.id = "sec-view-activity";
  activity.className = "btn ghost";
  activity.appendChild(secIcon("activity"));
  activity.appendChild(document.createTextNode("Activity"));
  bar.appendChild(activity);

  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.id = "sec-reload";
  refresh.className = "btn ghost";
  refresh.appendChild(secIcon("radar"));
  refresh.appendChild(document.createTextNode("Refresh"));
  bar.appendChild(refresh);

  return bar;
}

function secRefreshFilterOptions(projects){
  if(secProfileFilterSelect) secFillFilterOptions(secProfileFilterSelect,
    secUniqueValues(projects, "profile"), secProjectFilters.profile);
  if(secBranchFilterSelect) secFillFilterOptions(secBranchFilterSelect,
    secUniqueValues(projects, "branch"), secProjectFilters.branch);
}

// Repaints ONLY the table + footer -- never the filter bar mounted above it
// (secMountProjectsSection), so the live search box and the two picker
// selects are never rebuilt, on a poll tick or on a filter change alike.
function secRepaintProjectsTable(){
  if(!secProjectsTableHost) return;
  secProjectsTableHost.textContent = "";
  if(!secLatestProjects.length){
    secProjectsTableHost.appendChild(secIndexProjectsTable([]));
    return;
  }
  const filtered = secFilterProjects(secLatestProjects, secProjectFilters);
  if(!filtered.length){
    // A DIFFERENT empty state from secIndexProjectsTable's own "nothing
    // configured" one -- projects exist, the filters just matched none of
    // them, and the fix is to loosen a filter, not to turn security on
    // somewhere.
    const e = secEl("div", "tblempty");
    e.appendChild(secIcon("inbox"));
    e.appendChild(document.createTextNode(
      "No projects match these filters — try a different search or picker."));
    secProjectsTableHost.appendChild(e);
    return;
  }
  const footer = tableFooter({
    shown: {from: 1, to: filtered.length}, total: filtered.length, noun: "project",
    page: 1, pages: 1,
    prevId: "secpj-pg-prev", nextId: "secpj-pg-next", infoId: "secpj-pg-info",
  });
  secProjectsTableHost.appendChild(secIndexProjectsTable(filtered, footer));
}

// Runs exactly once (secRenderIndex's own mount guard): the filter bar built
// here holds the live search box and the two picker <select>s, none of
// which this screen may ever rebuild from scratch again after this.
function secMountProjectsSection(sectionHost){
  sectionHost.appendChild(secProjectsFilterBar());
  secProjectsTableHost = secEl("div");
  sectionHost.appendChild(secProjectsTableHost);
}

/* ---------------------------------------------------------- recent feed */
function secIndexRecentRow(a){
  const row = document.createElement("button");
  row.type = "button";
  row.className = "secrow secidx-recentrow";
  // Opens the project, not this exact historical analysis -- there is no
  // per-analysis screen yet outside the project's own history list.
  row.onclick = () => secOpenProject(a.project);
  row.appendChild(secIcon(a.state === "running" ? "timer"
    : a.state === "failed" ? "xcircle" : "check"));
  const grow = secEl("div", "grow");
  grow.appendChild(secEl("div", "secname",
    a.project + " · " + a.repo + " @ " + a.branch));
  const bits = [a.profile, a.state,
    a.state === "running" ? "started " + fmtAgo(a.started)
                          : "ended " + fmtAgo(a.ended || a.started)];
  if(a.open != null) bits.push(a.open + " open");
  bits.push(money(a.spend_usd || 0));
  grow.appendChild(secEl("div", "secmeta", bits.filter(Boolean).join(" · ")));
  row.appendChild(grow);
  return row;
}

function secIndexRecent(recent){
  if(!recent.length){
    return secEl("div", "tblempty", "No analyses have run yet.");
  }
  const host = secEl("div", "seclist");
  recent.forEach(a => host.appendChild(secIndexRecentRow(a)));
  return host;
}

/* --------------------------------------------------------- donut + rules */
const SEV_ORDER5 = ["critical", "high", "medium", "low", "info"];
// The exact colour grouping .sevpill already uses (critical and high share
// one colour there too, and so do low and info) -- a donut that invented a
// finer palette than the pills the rest of the area draws with would teach
// the reader a distinction the pills never made.
//
// `info` was `var(--line)` -- the SAME token the empty track below is painted
// with, so an info-only segment was invisible against the ring it was drawn
// on while the legend beside it went on listing the count. `.sevpill.info`
// and `.sevpill.low` are both `var(--muted)` in the stylesheet, which is the
// grouping this table is supposed to be mirroring in the first place.
const SEV_STROKE = {critical: "var(--err)", high: "var(--err)",
                    medium: "var(--warn)", low: "var(--muted)", info: "var(--muted)"};

function secIndexDonutSvg(donut){
  const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 120 120");
  svg.setAttribute("class", "secidx-donut-svg");
  svg.setAttribute("role", "img");
  const r = 50, c = 60, circumference = 2 * Math.PI * r;

  const track = document.createElementNS(ns, "circle");
  track.setAttribute("cx", String(c));
  track.setAttribute("cy", String(c));
  track.setAttribute("r", String(r));
  track.setAttribute("fill", "none");
  track.setAttribute("stroke-width", "14");
  track.style.stroke = "var(--line)";
  svg.appendChild(track);

  let offset = 0;
  SEV_ORDER5.forEach(sev => {
    const n = donut[sev] || 0;
    if(!n || !total) return;
    const len = (n / total) * circumference;
    const seg = document.createElementNS(ns, "circle");
    seg.setAttribute("cx", String(c));
    seg.setAttribute("cy", String(c));
    seg.setAttribute("r", String(r));
    seg.setAttribute("fill", "none");
    seg.setAttribute("stroke-width", "14");
    seg.setAttribute("stroke-dasharray", len + " " + (circumference - len));
    seg.setAttribute("stroke-dashoffset", String(-offset));
    // Segments start at 12 o'clock rather than a bare circle's 3 o'clock.
    seg.setAttribute("transform", "rotate(-90 " + c + " " + c + ")");
    seg.style.stroke = SEV_STROKE[sev] || "var(--muted)";
    svg.appendChild(seg);
    offset += len;
  });

  const label = document.createElementNS(ns, "text");
  label.setAttribute("x", String(c));
  label.setAttribute("y", String(c));
  label.setAttribute("text-anchor", "middle");
  label.setAttribute("dominant-baseline", "central");
  label.setAttribute("class", "secidx-donut-total");
  label.textContent = String(total);
  svg.appendChild(label);
  return svg;
}

/* What a donut segment COUNTS, on every pill in its legend.

   These are distinct fingerprints -- `severity_totals`, which collapses the
   same finding open on two branches into the one problem it is. The findings
   browser's strip, in identical markup and (on the project screen) four
   inches away on the same page, shows per-severity pills that are ROWS. The
   strip labels its own `total`/`unique` pair and the donut names its scope in
   a caption, but the per-severity pills on both sides said only "3 critical"
   and left the reader to assume the two agreed. They can legitimately
   differ, so each side now says which question it is answering. */
const DONUT_PILL_TITLE = "Distinct problems (fingerprints) — the same finding "
  + "open on two branches counts once here.";

function secIndexDonutLegend(donut){
  const wrap = secEl("div", "sevpills");
  const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
  if(!total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  SEV_ORDER5.forEach(sev => {
    if(!donut[sev]) return;
    const pill = secEl("span", "sevpill " + sev, donut[sev] + " " + sev);
    pill.title = DONUT_PILL_TITLE;
    wrap.appendChild(pill);
  });
  return wrap;
}

function secIndexCategories(categories){
  if(!categories.length){
    return secEl("div", "tblempty", "No open findings to categorise.");
  }
  const wrap = secEl("div", "secidx-categories");
  const max = categories.reduce((n, c) => Math.max(n, c.count || 0), 1);
  categories.forEach(c => {
    const row = secEl("div", "secidx-catrow");
    row.appendChild(secEl("span", "secidx-catname", c.rule));
    const bar = secEl("span", "secidx-catbar");
    const fill = secEl("span", "secidx-catfill");
    fill.style.width = Math.max(6, Math.round(((c.count || 0) / max) * 100)) + "%";
    bar.appendChild(fill);
    row.appendChild(bar);
    row.appendChild(secEl("span", "secidx-catcount", String(c.count || 0)));
    wrap.appendChild(row);
  });
  return wrap;
}

/* `cappedNote`, when given, is the same PARTIAL-read caveat the Critical/High
   cards and the index table's own `incomplete` badge already carry -- said
   here because a donut is every branch (or every project) rolled into one
   figure, and a rollup has no row to hang a badge off. Both callers pass one:
   the index screen from `summary.capped_projects`, the project sidebar from
   `sidebar.capped_branches`. Omitting it keeps the plain donut. */
export function secIndexDonut(donut, categories, cappedNote){
  const wrap = secEl("div", "secidx-donutwrap");
  const left = secEl("div", "secidx-donutcol");
  left.appendChild(secIndexDonutSvg(donut));
  left.appendChild(secIndexDonutLegend(donut));
  if((cappedNote || "").trim()){
    const warn = secEl("div", "warnline bad");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", "grow", cappedNote));
    left.appendChild(warn);
  }
  wrap.appendChild(left);
  const right = secEl("div", "secidx-catcol");
  right.appendChild(secEl("div", "secidx-cathead",
    "Rules producing the most open findings"));
  right.appendChild(secIndexCategories(categories));
  wrap.appendChild(right);
  return wrap;
}
