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
import { $, fmtAgo, pageHeader, kpiCard, tableFooter, openProjectEditor, makePicker } from "./page.js";
import { secIcon, secIconHTML, secEl, secFetch } from "./dom.js";
import { SEC_NEVER, SEC_FLOOR_SCOPE_NOTE, secRuleMeta } from "./vocabulary.js";
// secSwitchProjectTab: "View full report" (Phase 4 Task 4) opens a project
// straight onto its own Reports tab -- see secViewFullReportButton, below.
import { secOpenProject, secSwitchProjectTab } from "./project-screen.js";
// secOpenActivity: the kebab's own "View activity" item (Phase 4 Task 3)
// opens the SAME Activity screen the header button always has, scoped to
// this one row's project -- secOpenActivity(project) already takes that
// filter (index.js's own openActivity binding passes "" for "every
// project"). No cycle risk this file did not already have: project-screen.js
// already imports back from here (secIndexPosturePills/secIndexDonut, below),
// and activity-screen.js imports nothing from this module.
//
// secActSwitchTab/ACT_PERIODS (Phase 4 Task 4): "View all analyses" jumps
// straight to the Activity screen's own "Analyses" tab instead of leaving a
// reader to find it themselves (secViewAllAnalysesButton, below); ACT_PERIODS
// is the exact vocabulary the Findings-overview card's period picker borrows
// rather than re-typing (secFindingsPeriodPicker, below).
import { secOpenActivity, secActSwitchTab, ACT_PERIODS } from "./activity-screen.js";

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
    // `days`/`recent_page` are the Findings-overview period and the Recent-
    // analyses page -- both module state below (secFindPeriodDays,
    // secRecentPage), read live at fetch time so a period change or a page
    // click (both now force a real refetch, see secFindingsPeriodPicker's
    // and secIndexRecentCard's own onclick handlers) asks the server for
    // exactly what the reader just chose, and the routine 5-second poll
    // keeps asking for whatever they chose last rather than resetting it.
    data = await secFetch("/api/security/index?days=" + secFindPeriodDays
      + "&recent_page=" + secRecentPage);
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
  // The id (#sec-reload) is UNCHANGED, so
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
    // Recent analyses and Findings overview sit SIDE BY SIDE now (Phase 4
    // Task 4), the mockup's own bottom row -- reusing the project screen's
    // own main+sidebar split (.secpjbody/.secpjmain, ui/css/components.css)
    // for the row and its left card rather than inventing a second grid:
    // same gap, same flex-wrap, same "stacks under 900px" behaviour, already
    // proven on that screen. The right card gets its own fixed-basis class
    // (.secidx-findcard, ui/css/pages.css) instead of that same file's
    // .secpjside -- 300px is too narrow for a donut sitting beside its own
    // legend, and this card alone needs the room, not the project sidebar's
    // every other user.
    host._secBottomRow = secEl("div", "secpjbody secidx-bottom");
    host._secRecent = secEl("div", "secpjmain");
    host._secDonut = secEl("div", "secidx-findcard");
    host._secBottomRow.appendChild(host._secRecent);
    host._secBottomRow.appendChild(host._secDonut);
    host.appendChild(host._secCards);
    // ONCE per screen, as the KPI strip's own tooltip -- the cards, the
    // table's findings chips and the donut are all UNFLOORED, and the
    // drill-down one click away openly holds rows back, so the scope has to
    // be said where the unfloored numbers are. It used to be a paragraph
    // between the cards and the filter bar; the approved mockup has no such
    // line, so the sentence moved into `title` on the strip that carries the
    // numbers it explains -- same words, reachable from the numbers, off the
    // page's face. See SEC_FLOOR_SCOPE_NOTE's own comment in vocabulary.js.
    host._secCards.title = SEC_FLOOR_SCOPE_NOTE;
    host.appendChild(host._secProjects);
    host.appendChild(host._secBottomRow);
    secMountProjectsSection(host._secProjects);
  }

  host._secCards.textContent = "";
  host._secCards.appendChild(secIndexCards(data.summary || {}));

  // The table's own filter bar reads this on every keystroke/picker change,
  // never fetching again -- "filters THIS table client-side from what the
  // payload carries" (Phase 4 Task 3), not a new round trip per filter.
  secLatestProjects = data.projects || [];
  secClearStaleFilterValues(secLatestProjects);
  secRepaintProjectsTable();

  // `{rows, total}` now (Phase 4 Task 5) -- `queries.recent_analyses` pages
  // server-side, see its own docstring. `rows` alone is what
  // secIndexFindingsCard's own "View full report" button needs (the most
  // recent analysis's own project); the card itself reads `total` too, for
  // its footer's honest "of N analyses".
  const recent = data.recent || {rows: [], total: 0};
  host._secRecent.textContent = "";
  host._secRecent.appendChild(secIndexRecentCard(recent));

  host._secDonut.textContent = "";
  host._secDonut.appendChild(secIndexFindingsCard(data.donut || {}, data.categories || [],
    // The donut is the fleet's whole posture rolled into one figure, so it
    // cannot carry the per-row `incomplete` badge the table beside it uses --
    // it gets the same caveat the Critical/High cards get, from the same
    // count, or it is the one number on this screen that still presents a
    // partial read as a complete one.
    secCappedNote(data.summary || {}), recent.rows));
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
  // "trend", not "activity" (Phase 4 Task 5): the mockup's own upward
  // trend-line for this card, distinct from the ECG-pulse `activity` icon
  // still means everywhere else it appears on this screen (the kebab's own
  // "View activity" item, the header's Activity button).
  wrap.appendChild(kpiCard({icon: "trend", value: String(s.analyses || 0),
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
  // `secidx-sev3`: this screen's own three-tone chip colours (item 4) --
  // critical/high/medium each a distinct hue, reusing the donut's own
  // SEV_STROKE vocabulary (below) rather than the two-tone grouping
  // `.sevpill.critical,.sevpill.high` share everywhere else findings are
  // chipped (the findings browser, the branches tab, a project's own
  // Overview) -- screens this task does not touch. Scoped to this class
  // rather than changed at `.sevpill`'s own source for exactly that reason.
  const chips = secEl("div", "sevpills secidx-sev3");
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
    // `true`: long-form ("2 hours ago"), the mockup's own wording for this
    // screen -- see fmtAgo's own comment (bin/dashboard.html) for why this
    // is the shared formatter itself, not a second one.
    tdAnalysis.appendChild(document.createTextNode(fmtAgo(p.last_started, true)));
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
  ["status", "Status"], [null, "Actions"],
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
  table.className = "secidx-fleet";
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

   The house `.picker` widget now (Phase 4 Task 5), not a hand-copied
   `.filterpick` wearing a plain <select>: three native selects here, plus
   three more on the Analyse launcher (analysis.js), were the product's last
   ones, flagged twice by the same reader, and each one wore TWO chevrons --
   the native indicator plus this screen's own decorative one -- which is
   what made the bar wrap under Refresh at the pane's own width in the first
   place. bin/dashboard.html's makePicker() is bridged in through
   CCSecurity.init(CC) rather than ported a second time into this bundle
   (see ui/security/page.js's own comment on why that bridge runs in THIS
   direction, the opposite of pageHeader/kpiCard/tableFooter's) -- this
   screen still builds the markup, at runtime, the way it always has (unlike
   Jobs/Runs' own pickers, this screen's DOM is never static); it just wires
   that markup with the real widget instead of copying its look by hand.
   secPickerShell builds the `.picker`/`-trigger`/`-pop`/`-list` nodes
   makePicker expects to already find by id; secInitProjectFilterPickers
   wires each one, called only AFTER secMountProjectsSection has actually
   attached that markup to the live document -- makePicker's own constructor
   looks its ids up with $(), document.getElementById underneath, which
   finds nothing on a still-detached fragment and would silently wire
   nothing. */
let secProjectFilters = {query: "", status: "", profile: "", branch: ""};
let secLatestProjects = [];
let secProjectsTableHost = null;
let secStatusPicker = null, secProfileFilterPicker = null, secBranchFilterPicker = null;

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

function secUniqueValues(projects, key){
  return [...new Set((projects || []).map(p => p[key]).filter(Boolean))].sort();
}

// The bare `.picker`/`-trigger`/`-pop`/`-list` shell makePicker's own
// constructor wires by id -- no search box, no paged footer: all three
// filters below are short, in-memory lists with nothing to page through,
// the same shape jobStatusPicker/runStatusPicker/runSizePicker already use
// for the identical reason (bin/dashboard.html, see makePicker's own
// comment on cfg.pageSize).
function secPickerShell(id){
  const wrap = secEl("div", "picker");
  wrap.id = id;
  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "picker-trigger";
  trigger.id = id + "-trigger";
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");
  wrap.appendChild(trigger);
  const pop = secEl("div", "picker-pop");
  pop.id = id + "-pop";
  pop.hidden = true;
  const list = secEl("div", "picker-list");
  list.id = id + "-list";
  list.setAttribute("role", "listbox");
  pop.appendChild(list);
  wrap.appendChild(pop);
  return wrap;
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

  bar.appendChild(secPickerShell("secpj-filter-status"));
  bar.appendChild(secPickerShell("secpj-filter-profile"));
  bar.appendChild(secPickerShell("secpj-filter-branch"));

  bar.appendChild(secEl("div", "spacer"));

  // Both ids unchanged from the header they moved out of -- see
  // secRenderHead's own comment on why that is enough for
  // bin/dashboard.html's existing delegated listener to keep answering them.

  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.id = "sec-reload";
  refresh.className = "btn ghost";
  refresh.appendChild(secIcon("radar"));
  refresh.appendChild(document.createTextNode("Refresh"));
  bar.appendChild(refresh);

  return bar;
}

// Wired onto secProjectsFilterBar's own markup by secMountProjectsSection,
// once, right after that markup is attached to the live document. Each cfg
// mirrors exactly what the three <select>s' own onchange handlers did
// before this task: valueLabel reads secProjectFilters, rows counts
// secLatestProjects by the SAME predicate secFilterProjects itself checks
// (above), onPick writes the filter and repaints the table. "All" always
// carries the `layers` icon, the same "this row means every one of them"
// convention every other picker's own "All ..." row already uses
// (bin/dashboard.html's projPicker/jobStatusPicker/runProjPicker/
// runJobPicker/runStatusPicker); a real profile/branch value has no
// individual icon of its own to reach for, so it wears the picker's own
// trigger icon instead, the same way runSizePicker's page-size rows all
// wear `layers`, its own trigger icon, rather than nothing.
function secInitProjectFilterPickers(){
  secStatusPicker = makePicker("secpj-filter-status", {
    icon: secIconHTML("filter"), label: "Status",
    valueLabel: () => secProjectFilters.status === "active" ? "Active"
      : secProjectFilters.status === "disabled" ? "Disabled" : "All",
    rows: () => {
      const projects = secLatestProjects;
      const activeN = projects.filter(p => p.enabled !== false).length;
      return [
        {v: "", label: "All", n: projects.length,
         sel: secProjectFilters.status === "", icon: secIconHTML("layers")},
        {v: "active", label: "Active", n: activeN,
         sel: secProjectFilters.status === "active", icon: secIconHTML("play")},
        {v: "disabled", label: "Disabled", n: projects.length - activeN,
         sel: secProjectFilters.status === "disabled", icon: secIconHTML("power")},
      ];
    },
    onPick: (v) => { secProjectFilters.status = v; secRepaintProjectsTable(); },
  });
  secProfileFilterPicker = makePicker("secpj-filter-profile", {
    icon: secIconHTML("shield"), label: "Profile",
    valueLabel: () => secProjectFilters.profile ? secProfileLabel(secProjectFilters.profile) : "All",
    rows: () => {
      const projects = secLatestProjects, values = secUniqueValues(projects, "profile");
      const rows = [{v: "", label: "All", n: projects.length,
        sel: secProjectFilters.profile === "", icon: secIconHTML("layers")}];
      values.forEach(v => rows.push({v, label: secProfileLabel(v),
        n: projects.filter(p => p.profile === v).length,
        sel: secProjectFilters.profile === v, icon: secIconHTML("shield")}));
      return rows;
    },
    onPick: (v) => { secProjectFilters.profile = v; secRepaintProjectsTable(); },
  });
  secBranchFilterPicker = makePicker("secpj-filter-branch", {
    icon: secIconHTML("gitbranch"), label: "Branch",
    valueLabel: () => secProjectFilters.branch || "All",
    rows: () => {
      const projects = secLatestProjects, values = secUniqueValues(projects, "branch");
      const rows = [{v: "", label: "All", n: projects.length,
        sel: secProjectFilters.branch === "", icon: secIconHTML("layers")}];
      values.forEach(v => rows.push({v, label: v,
        n: projects.filter(p => p.branch === v).length,
        sel: secProjectFilters.branch === v, icon: secIconHTML("gitbranch")}));
      return rows;
    },
    onPick: (v) => { secProjectFilters.branch = v; secRepaintProjectsTable(); },
  });
}

// A stale filter value -- the one project that had it just vanished after a
// Refresh -- must not silently pin a picker to a value nothing can ever
// match again. Used to reset a bare <select>'s own .value, which repainted
// the trigger for free (a browser-native behaviour); now resets the plain
// filter state instead, and secRepaintProjectsTable's own picker.paint()
// calls below are what make the reset visible, since a custom widget has no
// such free repaint.
function secClearStaleFilterValues(projects){
  const profiles = secUniqueValues(projects, "profile");
  if(secProjectFilters.profile && !profiles.includes(secProjectFilters.profile)) secProjectFilters.profile = "";
  const branches = secUniqueValues(projects, "branch");
  if(secProjectFilters.branch && !branches.includes(secProjectFilters.branch)) secProjectFilters.branch = "";
}

// Repaints ONLY the table + footer -- never the filter bar mounted above it
// (secMountProjectsSection), so the live search box is never rebuilt, on a
// poll tick or on a filter change alike. The three pickers' own trigger
// labels DO repaint here every time, though -- the identical "repaint on
// every render, not just after a pick" idiom ui/app/jobs-table.js's own
// paintJobFilterBar() already follows for paintJobPickers(), since a poll
// tick can silently invalidate a stale profile/branch (secClearStaleFilterValues,
// called from secRenderIndex below) with no onPick anywhere in the loop.
function secRepaintProjectsTable(){
  if(secStatusPicker) secStatusPicker.paint();
  if(secProfileFilterPicker) secProfileFilterPicker.paint();
  if(secBranchFilterPicker) secBranchFilterPicker.paint();
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
  // `numbered: true` (Phase 4 Task 5): this table has exactly one page
  // today (client-side filtering only, and the mockup itself shows two
  // projects), so tableFooter's own numbered branch shows the "Showing 1 to
  // 2 of 2 projects" sentence with NO pager at all -- the mockup's own
  // footer for this table, byte for byte, rather than a disabled Prev/Next
  // with nothing behind either button.
  const footer = tableFooter({
    shown: {from: 1, to: filtered.length}, total: filtered.length, noun: "project",
    page: 1, pages: 1, numbered: true,
    prevId: "secpj-pg-prev", nextId: "secpj-pg-next", infoId: "secpj-pg-info",
  });
  secProjectsTableHost.appendChild(secIndexProjectsTable(filtered, footer));
}

// Runs exactly once (secRenderIndex's own mount guard): the filter bar built
// here holds the live search box and the three pickers, none of which this
// screen may ever rebuild from scratch again after this. secInitProjectFilterPickers
// runs AFTER the appendChild, deliberately -- see this file's own banner
// comment on the filter bar for why makePicker must find its ids already in
// the live document.
function secMountProjectsSection(sectionHost){
  sectionHost.appendChild(secProjectsFilterBar());
  secInitProjectFilterPickers();
  secProjectsTableHost = secEl("div");
  sectionHost.appendChild(secProjectsTableHost);
}

/* ------------------------------------------------------------- card heads
   Phase 4 Task 4: the mockup's own header for BOTH bottom-row cards -- a
   title, an optional grey one-line sub, and one trailing action -- replacing
   the small-caps `h3` secIndexSection used to draw (an eyebrow style meant
   for a label ABOVE a busier panel, not the mockup's own bold, sentence-case
   card titles). `.secidx-cardhead h3` (ui/css/pages.css) opts back out of
   the page's generic uppercase `h3` rather than that rule changing for
   every OTHER eyebrow on this screen (the table headers, `.secidx-cathead`
   beside it) that still wants it. */
function secIndexCardHead(title, sub, action){
  const head = secEl("div", "secidx-cardhead");
  const text = secEl("div", "secidx-cardhead-text");
  text.appendChild(secEl("h3", null, title));
  if(sub) text.appendChild(secEl("p", "secidx-cardhead-sub", sub));
  head.appendChild(text);
  if(action) head.appendChild(action);
  return head;
}

/* "View all analyses" -- today's own equivalent navigation, kept rather than
   invented: the "View all analyses" button on the Recent-analyses card already opens
   this exact screen, unscoped, for "every analysis across every project";
   this button is the same door, just opened straight onto its "Analyses"
   tab instead of leaving a reader to find that tab themselves. Two calls,
   not one new `secOpenActivity(project, tab)` parameter: `secOpenActivity`
   starts an ALL-activity fetch (`tab: ""`) before this can run one line
   later, but `secActSwitchTab`'s own generation counter (`secActGen`) makes
   the second, "analyses"-scoped fetch it starts the newest request in
   flight -- so the first response loses the race in `secActLoad` and is
   dropped silently, the identical guard a reader double-clicking two tabs
   in a row already relies on. The reader never sees "All activity" flash
   before "Analyses" paints. */
function secViewAllAnalysesButton(){
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn ghost";
  btn.appendChild(secIcon("activity"));
  btn.appendChild(document.createTextNode("View all analyses"));
  btn.onclick = () => { secOpenActivity(""); secActSwitchTab("analyses"); };
  return btn;
}

/* "View full report" -- there is no report spanning every project (a report
   is generated from ONE analysis's own checklist, see reports-tab.js's own
   file comment), so this opens the most recent analysis's OWN project,
   straight onto its Reports tab -- the nearest existing surface, not an
   invented cross-project one. Disabled, honestly, when there is nothing to
   open: an install with no analyses yet has no "most recent" project to
   jump to, the same door-with-nothing-behind-it reasoning kpiCard's own
   `door` flag documents (ui/app/chrome.js). */
function secViewFullReportButton(recent){
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn ghost secidx-reportbtn";
  btn.appendChild(secIcon("file"));
  btn.appendChild(document.createTextNode("View full report"));
  const latest = (recent || [])[0];
  if(!latest){
    btn.disabled = true;
    btn.title = "No analyses yet — there is nothing to report.";
    return btn;
  }
  btn.title = "Open " + latest.project + "’s own Reports tab — the nearest "
    + "report to this card's totals; there is no single report spanning "
    + "every project.";
  btn.onclick = () => { secOpenProject(latest.project); secSwitchProjectTab("reports"); };
  return btn;
}

/* ---------------------------------------------------------- recent table
   Phase 4 Task 4: the mockup's own table -- Run (#N), Project, Profile,
   Branch, Findings, Status, Date -- replacing the old plain list
   (secIndexRecentRow/secIndexRecent) the same way Phase 4 Task 3 replaced
   the five-column project list with the fleet table beside it. Reuses this
   file's own established cell-builders (secProfileLabel, secIndexRunWhen)
   rather than inventing a second set for a table that is, in every way that
   matters, shaped like the one above it. */
const SEC_RECENT_COLS = [
  ["run", "Run"], ["project", "Project"], ["profile", "Profile"],
  ["branch", "Branch"], ["findings", "Findings"], ["status", "Status"],
  ["date", "Date"],
];

// STATUS pill vocabulary for an ANALYSIS -- RUN_STATES's own four values
// (project-screen.js), Title-Cased for the mockup's own "Completed" -- new
// `.pill` modifiers (ui/css/components.css, beside `.pill.profile`) rather
// than reusing `.pill.on`/`.pill.off`: those two are reserved for the
// launchd fault pill and the disabled-project pill respectively (see
// `.pill.off`'s own comment there), and an analysis's own running/done/
// capped/failed is a third, unrelated fact that happens to want the same
// four tone families, not the same two classes.
const SEC_RUN_STATUS_LABEL = {running: "Running", done: "Completed",
                              capped: "Capped", failed: "Failed"};

function secIndexRunStatusPill(state){
  // An unrecognised state (corrupted data; every value the pipeline can
  // legitimately produce is listed above) reads as a fault rather than
  // silently as "Running" or vanishing from the cell entirely -- the same
  // "loud branch, not a quiet one" rule secSevRank's own comment states for
  // a severity nothing in the pipeline actually emits.
  const known = Object.prototype.hasOwnProperty.call(SEC_RUN_STATUS_LABEL, state);
  return secEl("span", "pill " + (known ? state : "failed"),
    known ? SEC_RUN_STATUS_LABEL[state] : "Unknown");
}

/* FINDINGS: three fixed severity chips -- `queries.recent_analyses` now
   tallies `severities` (critical/high/medium) per row from the SAME
   `checklist()` call its own `open` count already made (Phase 4 Task 5;
   before this, it had only the combined count, and this cell said so with
   plain text rather than guess a split it had no severity to colour). The
   SAME fixed three, SAME order and SAME "always three, even zero" rule the
   fleet table's own `secIndexFindingsChips` draws a few pixels above this
   one -- this table's own mockup shows the identical chip shape, just with
   no "N total" line beneath (there is nothing beyond the three shown here
   to total: low/info are not tracked per historical row the way the fleet
   table's own current posture tracks them). `null` (a `running`/`failed`
   analysis has not finished recording findings yet) still reads as an
   honest dash, never a fabricated zero -- the same distinction
   `secIndexProjectRow`'s own Last analysis cell already draws for "not
   counted" vs "counted as zero". */
function secIndexRecentFindingsChips(severities){
  if(!severities) return secEl("span", "muted", "—");
  const wrap = secEl("div", "sevpills secidx-sev3");
  FIND_SEVS.forEach(sev => wrap.appendChild(
    secEl("span", "sevpill " + sev, String(severities[sev] || 0))));
  return wrap;
}

function secIndexRecentRow(a){
  const tr = document.createElement("tr");
  tr.className = "secidx-rowlink";
  // Same destination as a click on the fleet table's own row above it:
  // there is no per-analysis screen yet outside the project's own history
  // list (secIndexProjectRow's own comment says the identical thing).
  tr.onclick = () => secOpenProject(a.project);

  const tdRun = document.createElement("td");
  tdRun.textContent = "#" + a.id;
  tr.appendChild(tdRun);

  const tdProject = document.createElement("td");
  const nameLine = secEl("div", "secidx-pname");
  nameLine.appendChild(secIcon("folder"));
  nameLine.appendChild(secEl("span", "secidx-pname-text", a.project));
  tdProject.appendChild(nameLine);
  tr.appendChild(tdProject);

  const tdProfile = document.createElement("td");
  tdProfile.appendChild(a.profile
    ? secEl("span", "pill profile", secProfileLabel(a.profile))
    : secEl("span", "muted", "—"));
  tr.appendChild(tdProfile);

  // textContent, never markup: a branch name may legally contain '<', '>'
  // and '&' (vocabulary.js's own opening comment) and a repository chooses
  // it, not this page.
  const tdBranch = document.createElement("td");
  tdBranch.textContent = a.branch || "—";
  tr.appendChild(tdBranch);

  const tdFindings = document.createElement("td");
  tdFindings.appendChild(secIndexRecentFindingsChips(a.severities));
  tr.appendChild(tdFindings);

  const tdStatus = document.createElement("td");
  tdStatus.appendChild(secIndexRunStatusPill(a.state));
  tr.appendChild(tdStatus);

  const tdDate = document.createElement("td");
  // `true`: long-form, the mockup's own wording -- see the Last-analysis
  // cell's identical call above for why this is the shared fmtAgo itself.
  tdDate.appendChild(document.createTextNode(fmtAgo(a.started, true)));
  tdDate.appendChild(secEl("div", "secidx-sub", secIndexRunWhen(a.started)));
  tr.appendChild(tdDate);

  return tr;
}

/* The whole card: head (title, sub, "View all analyses"), the table (or the
   honest empty state), and `tableFooter`'s own numbered footer.

   Paged SERVER-SIDE now (Phase 4 Task 5): `recent` is `{rows, total}`,
   `rows` already exactly the page `secRecentPage` asked for (`queries.
   recent_analyses`'s own `limit=5`/`offset`, threaded through `index-data`'s
   `--recent-page` and this screen's own fetch, secLoadIndex) and `total`
   the TRUE count across every analysis the scope matches -- so the footer
   can read "Showing 6 to 8 of 12 analyses" against a real server, not the
   "of 5" a previous task named as a divergence forced by the payload never
   carrying more than its own page. Clicking a page number or Prev/Next asks
   the server again (below) rather than re-slicing an array already fetched
   whole, which is what let this table page at all before this task even
   though the server itself never served more than 5 rows to slice. */
const SEC_RECENT_PAGE_SIZE = 5;
let secRecentPage = 1;

function secIndexRecentCard(recent){
  const card = secEl("div", "table-card");
  card.appendChild(secIndexCardHead("Recent analyses",
    "Latest security analyses across all projects", secViewAllAnalysesButton()));

  const rows = recent.rows || [];
  const total = recent.total || 0;
  if(!total){
    const e = secEl("div", "tblempty");
    e.appendChild(secIcon("inbox"));
    e.appendChild(document.createTextNode("No analyses have run yet."));
    card.appendChild(e);
    return card;
  }

  const pages = Math.max(1, Math.ceil(total / SEC_RECENT_PAGE_SIZE));
  // A display safeguard, not the pagination mechanism itself any more: the
  // server already served the page `secRecentPage` asked for. This only
  // matters if the set shrinks out from under a reader sitting on its last
  // page between two polls -- clamped here so the sentence below never
  // claims a page number past the end; the NUMBER itself stays stale until
  // the next poll re-asks with the corrected one.
  secRecentPage = Math.min(Math.max(1, secRecentPage), pages);
  const from = total ? (secRecentPage - 1) * SEC_RECENT_PAGE_SIZE + 1 : 0;
  const to = from + rows.length - 1;

  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secidx-recent";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_RECENT_COLS.forEach(([, label]) => htr.appendChild(secEl("th", null, label)));
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  rows.forEach(a => tbody.appendChild(secIndexRecentRow(a)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  card.appendChild(scroll);

  // Numbered (Phase 4 Task 5): tableFooter's own "‹ 1 2 3 ›" variant
  // (ui/app/chrome.js) -- Prev/Next-with-text was a divergence a previous
  // task named rather than fork a second footer component for one card;
  // this task closes it, over the SAME footer both this table and the
  // fleet table above it now share.
  const footer = tableFooter({
    // `plural: "analyses"` -- tableFooter's own bare `noun + "s"` reads
    // "analysiss" otherwise (see its own comment, ui/app/chrome.js); found
    // live, in this exact card, verifying against the mockup.
    shown: {from, to}, total, noun: "analysis", plural: "analyses",
    page: secRecentPage, pages, numbered: true,
    prevId: "secrecent-pg-prev", nextId: "secrecent-pg-next",
  });
  // Wired directly on the footer THIS call just built, the same "rebuilt
  // fresh every repaint" idiom as before -- `closest`, not a bare id check,
  // because a click can land on a button's own icon glyph rather than the
  // button itself. `secLoadIndex(true)`, not a local re-render: a page
  // change now genuinely asks the server for different rows.
  footer.onclick = (e) => {
    const pageBtn = e.target.closest(".pagebtn");
    if(pageBtn){
      secRecentPage = Number(pageBtn.dataset.page);
    }else if(e.target.closest("#secrecent-pg-prev")){
      secRecentPage = Math.max(1, secRecentPage - 1);
    }else if(e.target.closest("#secrecent-pg-next")){
      secRecentPage = Math.min(pages, secRecentPage + 1);
    }else{
      return;
    }
    secLoadIndex(true);
  };
  card.appendChild(footer);
  return card;
}

/* --------------------------------------------------------- donut + rules */
const SEV_ORDER5 = ["critical", "high", "medium", "low", "info"];
// Three DISTINCT tones for critical/high/medium (Phase 4 Task 5) -- the
// mockup's own donut draws three visibly different wedges (red, orange,
// yellow-amber), which critical/high sharing one colour (this table's own
// choice before this task) never reproduced regardless of intent. `high` is
// `color-mix()`, not a new hex literal: this design's token set has only
// `--err` (red) and `--warn` (amber) as hue tokens (ui/css/tokens.css), no
// third "orange" of its own, so high sits exactly between the two existing
// ones it is severity-between -- the same `color-mix()` idiom
// `.sevpill.critical`'s own border-color already uses (ui/css/pages.css).
// This IS now the one vocabulary: `.secidx-sev3` (the findings chips, both
// tables) and `.secidx-legendrow` (the legend dots) below both read the
// identical two expressions, not a second palette of their own.
//
// `info` stays `var(--muted)`, distinct from `var(--line)` -- the SAME
// token the empty track below is painted with, so an info-only segment
// remains visible against the ring it is drawn on while the legend beside
// it lists its count. `.sevpill.info`/`.sevpill.low` keep the same grouping
// in the stylesheet, unaffected by this task (out of scope: chips elsewhere
// on the app stay as they are, only this screen's own vocabulary changes).
// The severity hue tokens (ui/css/tokens.css) -- sampled from the mockup's
// own pixels, one scale for donut, legend and chips alike.
const SEV_STROKE = {critical: "var(--sev-crit)", high: "var(--sev-high)",
                    medium: "var(--sev-med)", low: "var(--sev-low)",
                    info: "var(--sev-info)"};

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

/* `showPercent` (Phase 4 Task 4, reshaped by Task 5): the index screen's own
   Findings-overview card draws the mockup's own legend row -- a coloured
   dot, the severity's name, and a right-aligned "45 (23.8%)" -- which is
   its own element, NOT a `.sevpill` wearing a percentage. Opt-in, defaulting
   OFF, so the project screen's own sidebar donut (secIndexDonut's other
   caller, project-screen.js) keeps rendering the plain `.sevpill` legend it
   always has -- this task's mockup is the index page's alone.
   `test_the_two_kinds_of_severity_pill_each_say_what_they_count` calls this
   with ONE argument, so `showPercent` is `undefined` there and the whole
   `if(!showPercent)` branch below behaves exactly as it did before this
   option existed -- byte for byte the same `.sevpill` shape, same title.

   The `showPercent:true` branch dropped its OWN pinned shape (Task 4's
   `.sevpill critical` reading "45 critical", a `.secidx-legendpct` sibling
   reading "(23.8%)") for the mockup's literal one: "the sevpill tests pin
   sevpills where sevpills appear" is true of the OTHER branch above, which
   still is one -- this branch draws a legend row instead, on purpose, and
   the test that pinned its old sevpill-shaped reading moved with it (see
   test_the_findings_overview_legend_states_each_severitys_share_of_the_
   total). Colour lives on the ROW (`.secidx-legendrow.<severity>`), which
   both the dot and (via CSS) nothing else read -- one selector, matching
   `.secidx-sev3`'s own chips and SEV_STROKE's own donut wedges, the "one
   vocabulary" this screen now keeps everywhere severity has a colour. */
function secIndexDonutLegend(donut, opts){
  const showPercent = !!(opts && opts.showPercent);
  const wrap = secEl("div", "sevpills" + (showPercent ? " secidx-findlegend" : ""));
  const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
  if(!total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  if(!showPercent){
    SEV_ORDER5.forEach(sev => {
      if(!donut[sev]) return;
      const pill = secEl("span", "sevpill " + sev, donut[sev] + " " + sev);
      pill.title = DONUT_PILL_TITLE;
      wrap.appendChild(pill);
    });
    return wrap;
  }
  SEV_ORDER5.forEach(sev => {
    if(!donut[sev]) return;
    const row = secEl("div", "secidx-legendrow " + sev);
    row.title = DONUT_PILL_TITLE;
    row.appendChild(secEl("span", "secidx-legenddot"));
    row.appendChild(secEl("span", "secidx-legendname",
      sev[0].toUpperCase() + sev.slice(1)));
    // `total` is never 0 here (the guard above already returned "nothing
    // open" for that case), and neither is `donut[sev]` (the `if(!donut[sev])
    // return` just above it) -- so this division never sees a zero
    // denominator and never needs the dash rule the brief names for one.
    row.appendChild(secEl("span", "secidx-legendcount",
      donut[sev] + " (" + ((donut[sev] / total) * 100).toFixed(1) + "%)"));
    wrap.appendChild(row);
  });
  return wrap;
}

/* Icon, human label, right-aligned count -- the mockup's own row, replacing
   the width-scaled bar Phase 4 Task 3 drew here (no bar in the mockup at
   all). The label and icon both come from secRuleMeta (ui/security/
   vocabulary.js) now, in place of the guesswork this used to run over the
   raw rule string (a substring heuristic, and before that `c.rule` shown
   verbatim -- see that function's own comment for why a curated map
   replaced both: the mockup's "Private keys committed" is a real label the
   engine's own rationale earns, not a coincidence of the rule's name).
   `c.category` is not in `top_categories`'s own payload today
   (bin/security/queries.py groups by rule alone) -- secRuleMeta is written
   to resolve correctly without it regardless, and picks it up for free the
   day that payload carries one.

   The raw rule id is never dropped, only demoted to `.title`: an operator
   who greps the ledger by rule id still finds it one hover away, even on a
   row whose visible name is now a human label rather than that id. */
function secIndexCategories(categories){
  if(!categories.length){
    return secEl("div", "tblempty", "No open findings to categorise.");
  }
  const wrap = secEl("div", "secidx-categories");
  categories.forEach(c => {
    const meta = secRuleMeta(c.category, c.rule);
    const row = secEl("div", "secidx-catrow");
    row.title = c.rule;
    row.appendChild(secIcon(meta.icon));
    row.appendChild(secEl("span", "secidx-catname", meta.label));
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
export function secIndexDonut(donut, categories, cappedNote, opts){
  const wrap = secEl("div", "secidx-donutwrap");
  const left = secEl("div", "secidx-donutcol");
  left.appendChild(secIndexDonutSvg(donut));
  left.appendChild(secIndexDonutLegend(donut, opts));
  if((cappedNote || "").trim()){
    const warn = secEl("div", "warnline bad");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", "grow", cappedNote));
    left.appendChild(warn);
  }
  wrap.appendChild(left);
  const right = secEl("div", "secidx-catcol");
  // "Top issue categories" (Phase 4 Task 4): the mockup's own title for
  // this same data -- `top_categories` (queries.py) really does rank RULES,
  // not the small `category` enum a finding also carries, so the OLD
  // caption was the more literally accurate one; the new one is shorter and
  // reads as a section title instead of an explanation, which is what the
  // mockup draws here. Shared by both callers of secIndexDonut (this index
  // screen and the project screen's sidebar) rather than gated behind
  // `opts`, unlike the percentage above -- a caption rename changes no
  // shape and nothing on the project screen has to look any different for
  // this one word choice to be consistently true there too.
  right.appendChild(secEl("div", "secidx-cathead", "Top issue categories"));
  right.appendChild(secIndexCategories(categories));
  wrap.appendChild(right);
  return wrap;
}

/* ------------------------------------------------------- findings overview
   Phase 4 Task 4: the mockup's own right-hand card -- a title, a period
   picker that does NOT filter the totals beneath it (see
   secFindingsPeriodPicker's own comment for why that is a deliberate, tested
   decision and not a missing feature), the donut+legend+categories block
   above, and "View full report" beneath. */

// The house combo, not a native <select> -- this card's own period picker
// has to say so out loud the moment it opens (see below), which a <select>
// has nowhere to put; the SAME <details>/<summary>/.menu-pop popover this
// file already draws for the row kebab (secIndexProjectRow), including its
// `position:fixed` recompute on open -- `.table-card{overflow:hidden}`
// clips a `position:absolute` popup here exactly as it does there, and this
// card is a `.table-card` too (see secIndexFindingsCard).
let secFindPeriodDays = 30;

function secFindPeriodLabel(days){
  return days > 0 ? "Last " + days + " days" : "All time";
}

// "(30 days)"/"(7 days)"/"(All time)" -- the card head's own title suffix
// (secIndexFindingsCard, below), bound to the same secFindPeriodDays this
// picker sets. Deliberately NOT secFindPeriodLabel's own "Last 30 days":
// the mockup's card title reads "Findings overview (30 days)", the trigger
// itself reads "Last 30 days" a few pixels below it -- two different
// readings of the same number, both the mockup's own.
function secFindPeriodTitleSuffix(days){
  return days > 0 ? "(" + days + " day" + (days === 1 ? "" : "s") + ")" : "(All time)";
}

/* Real now (Phase 4 Task 5): `queries.severity_totals`/`top_categories` both
   USED to accept a `days` parameter, ignore it completely, and were never
   passed one by either caller -- that history (and the fuller reasoning
   this supersedes) is in CHANGELOG.md. Picking a bucket here now asks the
   server again (see this picker's own `onclick`, below) with THAT `days`
   value, and `cmd_index_data` forwards it straight through -- the donut,
   legend and categories all re-render from whatever the server sends back
   for the selected period, a real window over "findings whose analyses
   fall in the period", not the fleet's as-of-now posture this same card
   showed before this task. */
const SEC_FIND_PERIOD_TITLE = "Findings recorded by analyses that ran in this "
  + "period. Changing it asks the server again — the donut, legend and "
  + "categories below all re-render for the period chosen.";

function secFindingsPeriodPicker(){
  const wrap = document.createElement("details");
  wrap.className = "secidx-periodpick";
  const trigger = document.createElement("summary");
  trigger.className = "filterpick";
  trigger.title = SEC_FIND_PERIOD_TITLE;
  // Found live: bin/dashboard.html's global "click outside a menu-pop closes
  // every open one" listener (closeMenus(), bound on `document`) has no idea
  // this menu is a <details> rather than the older hidden-attribute-toggled
  // .mtrig pattern -- a click on THIS trigger bubbles past it exactly like a
  // click anywhere else, and closeMenus() sets `hidden` on every visible
  // `.menu-pop` it finds, this one included, a beat before the browser's own
  // default action opens the <details>. The popover opened and was
  // immediately re-hidden by a listener that never meant to touch it.
  // secIndexProjectRow's own kebab already carries this exact line for the
  // identical reason -- missing it here was this task's own bug, not a
  // second occurrence of a pre-existing one.
  trigger.onclick = (e) => e.stopPropagation();
  const value = secEl("span", null, secFindPeriodLabel(secFindPeriodDays));
  trigger.appendChild(value);
  trigger.appendChild(secIcon("cdown"));
  wrap.appendChild(trigger);

  const pop = secEl("div", "menu-pop");
  pop.setAttribute("role", "menu");
  ACT_PERIODS.forEach(([days]) => {
    const item = document.createElement("button");
    item.type = "button";
    item.setAttribute("role", "menuitem");
    item.appendChild(document.createTextNode(secFindPeriodLabel(days)));
    if(days === secFindPeriodDays) item.appendChild(secIcon("check2"));
    item.onclick = (e) => {
      e.stopPropagation();
      secFindPeriodDays = days;
      wrap.open = false;
      // A real refetch (Phase 4 Task 5), not a local re-render from cache:
      // the period now genuinely changes what the server sends back (see
      // SEC_FIND_PERIOD_TITLE's own comment) -- secLoadIndex(true) reads
      // secFindPeriodDays live and asks again, the same "force" path an
      // explicit Refresh already uses.
      secLoadIndex(true);
    };
    pop.appendChild(item);
  });
  wrap.appendChild(pop);

  // Recomputed on every open from the trigger's own screen position, the
  // identical fix secIndexProjectRow's own kebab already needed for the
  // same `.table-card{overflow:hidden}` clip -- see that popup's own
  // `ontoggle` comment.
  wrap.ontoggle = () => {
    if(!wrap.open) return;
    const r = trigger.getBoundingClientRect();
    pop.style.position = "fixed";
    pop.style.top = (r.bottom + 6) + "px";
    pop.style.right = (window.innerWidth - r.right) + "px";
    pop.style.left = "auto";
    pop.style.bottom = "auto";
  };
  return wrap;
}

/* The whole card: head (title, the period picker above), the donut block
   (percentages on, "Top issue categories" beneath it, no small-caps eyebrow
   -- see ui/css/pages.css's own `.secidx-cardhead h3`), and "View full
   report". `.secidx-findbody` (ui/css/pages.css) is where the donut block's
   OWN box chrome (background/border/shadow/padding, needed when
   project-screen.js plants it bare in its sidebar) is stripped back out
   again -- this card already draws that chrome once, itself, and nesting
   the shared block's own copy inside it would double it. Scoped to this one
   wrapper class rather than changing `.secidx-donutwrap` itself, the same
   reasoning `showPercent` above already follows: nothing here has been
   checked against the project screen's own pixels. */
function secIndexFindingsCard(donut, categories, cappedNote, recent){
  const card = secEl("div", "table-card");
  // "(30 days)" back in the title (Phase 4 Task 5), bound to the picker's
  // own selection -- see secFindPeriodTitleSuffix's own comment for why
  // this reads "(30 days)" while the trigger beside it reads "Last 30
  // days": both are the mockup's own wording, in two different spots.
  card.appendChild(secIndexCardHead(
    "Findings overview " + secFindPeriodTitleSuffix(secFindPeriodDays),
    null, secFindingsPeriodPicker()));
  const body = secEl("div", "secidx-findbody");
  body.appendChild(secIndexDonut(donut, categories, cappedNote, {showPercent: true}));
  card.appendChild(body);
  card.appendChild(secViewFullReportButton(recent));
  return card;
}
