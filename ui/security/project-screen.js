/* -------------------------------------------------------- the project screen
   What "open a project" leads to: a header saying what this project analyses
   and how big it is, and the run history behind tabs (Overview, Runs)
   instead of one long column. One request, `GET /api/security/project`,
   answers with everything the header, both tabs and the sidebar draw -- see
   bin/security/cli.py's `project-data` and bin/claude-cron-server's
   `security_project`.

   This module owns the header (now including the name/badge/description row
   and the breadcrumb's current segment's surrounding chrome), the tabs, the
   Runs tab's own "Analysis runs" table and its selected run's shell (the
   Run #N head and the "Findings recorded" strip -- see secRenderRunHead/
   secRenderRunRecorded's own comments for why those two specifically live
   here rather than in analysis.js), the sidebar, and (Runs tab parity pass
   2) the compact "Analyse" button that OPENS <dialog id="seclaunch">, in the
   "Analysis runs" card's own title row. It deliberately does NOT own the
   repo/branch/profile picker INSIDE that dialog, or the single-analysis
   detail proper (the meta grid, the incomplete/coverage/live-run notices,
   the search/category/state Filters bar, the findings list with its
   decision controls) -- that whole flow already works, is exercised by
   tests/test_page_contract.py, and stays exactly as it is in
   ui/security/analysis.js, ui/security/actions.js, ui/security/history.js
   and ui/security/reason.js, just moved from an always-open strip into a
   dialog (secLaunchButton below calls analysis.js's own secOpenLaunch,
   nothing more than `$("seclaunch").showModal()`).
   Clicking a row in the analyses table below calls the same
   secShowAnalysis() the old "#7" buttons in "Earlier analyses of this
   branch" always did -- see that call's own comment for why it does not
   push browser history. Findings-with-decisions has its own screen too (the
   findings browser, ui/security/findings-screen.js) mounted under the
   Findings tab -- unrelated to the Runs tab's own, run-scoped findings list,
   which stays analysis.js's. */
import { $, closeMenus, fmtAgo, fmtWhen, openLog, openProjectEditor, projById,
         tableFooter, pushNav } from "./page.js";
import { secIcon, secEl, secFetch } from "./dom.js";
import { SEC_STATES, SEC_STATE_LABEL, SEC_STATE_HELP, SEC_NEVER,
         SEC_FLOOR_SCOPE_NOTE, EVENT_KIND_LABEL, secMinSeverity,
         secPosture, secRuleMeta, secVisible } from "./vocabulary.js";
import { secState } from "./state.js";
import { secIndexPosturePills, secIndexDonut, secIndexDonutSvg, secIndexDonutLegend,
         secIndexCategories, secCappedScopeNote, secIndexRunStatusPill } from "./index-screen.js";
import { secOpen, secShowAnalysis, secOpenLaunch } from "./analysis.js";
import { secDownloadReport } from "./actions.js";
import { secRunFor } from "./history.js";
import { secRenderProjectBranches } from "./branches-tab.js";
import { secRenderProjectReports } from "./reports-tab.js";
import { renderFindings } from "./findings-screen.js";
import { secOpenActivity } from "./activity-screen.js";

// Every state `analysis.state` can hold (see bin/security/ledger.py's
// `start_analysis`/`ANALYSIS_END_STATES`) -- the Runs tab's own filter row,
// a different vocabulary from SEC_STATES above (that one is a FINDING's
// state; this one is an ANALYSIS's).
const RUN_STATES = ["running", "done", "capped", "failed"];

let secProjectCache = null;
let secProjectGen = 0;
let secProjectTab = "overview";
let secRunsFilter = "";

/* Called after anything that could have changed this project's numbers (a
   run just started or finished, a decision was just made) so the next load
   asks again rather than repainting a stale answer -- the same reasoning
   secInvalidateIndex already applies to the index screen's own cache. */
export function secInvalidateProject(){ secProjectCache = null; }

/* The entry point every "open this project" click now calls, instead of
   analysis.js's secOpen directly. secOpen still does everything it always
   did -- shows #sec-detail, resolves the repo/branch/profile pickers, loads
   the default analysis for drilling into below the Runs table -- this only
   adds the header/tabs/sidebar fetch on top of it.

   `fromHistory` (F4 history layer): set by CCSecurity.navigate (a popstate
   restore) and by the two index-screen.js buttons that immediately follow
   this call with their own secSwitchProjectTab -- that second call is the
   one real navigation ("open this project's Reports tab") and is the one
   that pushes; this one would otherwise push the "overview" tab a click
   never actually showed. See bin/dashboard.html's own router comment. */
export async function secOpenProject(name, fromHistory){
  secProjectTab = "overview";
  secRunsFilter = "";
  secOpen(name);
  // Painted from projById() alone, before the project-data fetch even
  // starts: the icon, the name, the badge and the description are already
  // in hand client-side (the same object secOpen() just read for its own
  // repo picker), and a reader should not wait on a round trip for a name
  // this screen already knew the instant it opened.
  secRenderProjectTitle();
  // Pushed here, before the project-data fetch, not after: the reader is
  // looking at the project screen (loading state and all) from the instant
  // this returns, and a fast Back before the fetch settles must already have
  // this entry to land on.
  if(!fromHistory) pushNav({view: "security", sec: {screen: "project", project: name, tab: secProjectTab}});
  await secLoadProject(name, true);
}

/* Re-read this project's data after anything that might have changed it.
   Called from analysis.js's secReload() -- the same poll tick and the same
   post-Analyse reload that already refresh the old detail pane -- so one
   timer drives both, rather than a second interval hitting the server on
   its own. A no-op once the view has moved on, the same guard secLoadIndex
   already uses for the identical race. */
export async function secRefreshProject(){
  if(!secState.project) return;
  await secLoadProject(secState.project, true);
}

async function secLoadProject(name, force){
  if(secProjectCache && secProjectCache.project === name && !force){
    secRenderProject();
    return;
  }
  secProjectGen++;
  const gen = secProjectGen;
  let data;
  try{
    data = await secFetch("/api/security/project?project=" + encodeURIComponent(name));
  }catch(e){
    if(gen !== secProjectGen || secState.project !== name) return;
    secProjectCache = null;
    secRenderProjectError(e.message);
    return;
  }
  if(gen !== secProjectGen || secState.project !== name) return;   // a newer request already answered, or the view moved on
  secProjectCache = data;
  secRenderProject();
}

function secRenderProjectError(msg){
  const host = $("sec-pj-head");
  if(!host) return;
  host.textContent = "";
  host.appendChild(secIcon("alert"));
  host.appendChild(secEl("span", "grow", "Could not read this project — " + msg));
}

/* `fromHistory` (F4 history layer): true only for CCSecurity.navigate's own
   restore -- every tab button in the page wires this with a bare tab name,
   so `fromHistory` there stays undefined/false and every real click still
   pushes. See bin/dashboard.html's own router comment, beside setView. */
export function secSwitchProjectTab(tab, fromHistory){
  secProjectTab = ["overview", "runs", "branches", "findings", "reports"].includes(tab)
    ? tab : "overview";
  secRenderTabs();
  // The right rail's own content depends on WHICH tab is active now (the
  // Runs tab reads secState.findings; every other tab reads this cache's
  // own sidebar payload -- see secRenderProjectSidebar's own comment) --
  // repainted here, on every tab switch, since neither secRenderTabs above
  // nor the pane-visibility toggle it just did touches #sec-pj-side, and
  // the next poll tick that otherwise would could be up to 4 seconds away.
  // A no-op before the first project-data fetch ever answers.
  if(secProjectCache) secRenderProjectSidebar(secProjectCache);
  // Findings is fetched on its own (GET /api/security/findings, sorted/
  // filtered/paged server-side) rather than riding the single project-data
  // payload every other tab shares -- so switching TO it is what triggers its
  // first fetch, and secRenderProject below re-fetches it on every later poll
  // tick ONLY while it stays the active tab, never while some other tab is
  // on screen.
  if(secProjectTab === "findings") renderFindings($("sec-pj-findings"), secState.project);
  if(!fromHistory) pushNav({view: "security", sec: {screen: "project", project: secState.project, tab: secProjectTab}});
}

/* The project screen's own active tab -- read by CCSecurity.navState()
   (ui/security/index.js) to compose the history state a real navigation
   elsewhere (entering Security from the sidebar, resuming a project) pushes.
   secProjectTab itself stays module-private; this is the one door in. */
export function secCurrentProjectTab(){ return secProjectTab; }

function secRenderProject(){
  if(!secProjectCache) return;
  secRenderProjectHeader(secProjectCache);
  secRenderTabs();
  secRenderProjectOverview(secProjectCache);
  secRenderProjectRuns(secProjectCache);
  secRenderProjectBranches(secProjectCache);
  secRenderProjectReports(secProjectCache);
  secRenderProjectSidebar(secProjectCache);
  if(secProjectTab === "findings") renderFindings($("sec-pj-findings"), secState.project);
}

function secRenderTabs(){
  const ov = $("secpjt-overview"), rn = $("secpjt-runs"),
        br = $("secpjt-branches"), fd = $("secpjt-findings"), rp = $("secpjt-reports");
  if(ov) ov.classList.toggle("active", secProjectTab === "overview");
  if(rn) rn.classList.toggle("active", secProjectTab === "runs");
  if(br) br.classList.toggle("active", secProjectTab === "branches");
  if(fd) fd.classList.toggle("active", secProjectTab === "findings");
  if(rp) rp.classList.toggle("active", secProjectTab === "reports");
  const ovPane = $("sec-pj-overview"), rnPane = $("sec-pj-runs"),
        brPane = $("sec-pj-branches"), fdPane = $("sec-pj-findings"),
        rpPane = $("sec-pj-reports");
  if(ovPane) ovPane.hidden = secProjectTab !== "overview";
  if(rnPane) rnPane.hidden = secProjectTab !== "runs";
  if(brPane) brPane.hidden = secProjectTab !== "branches";
  if(fdPane) fdPane.hidden = secProjectTab !== "findings";
  if(rpPane) rpPane.hidden = secProjectTab !== "reports";
  // The donut/categories/recent-activity rail (#sec-pj-side) is a summary
  // of the OTHER four tabs' own posture -- AllFindings.png draws the
  // findings browser full-width, with no such rail beside it, and a rail
  // repeating "2 critical / 8 high / ..." beside a table that already lists
  // every one of those rows individually would be the same numbers said
  // twice a few inches apart. Hidden for Findings alone; the other four
  // tabs keep it exactly as before.
  const side = $("sec-pj-side");
  if(side) side.hidden = secProjectTab === "findings";
}

/* --------------------------------------------------------------- header */
/* The name row above the meta strip -- project icon, bold name, the green
   "Security enabled" badge, then the project's own description -- all read
   from projById(), the SAME client-side project object secOpen() already
   reads for its repo picker (`secRepos(p)`) a few lines into opening this
   very screen. Not part of `payload` (cmd_project_data's own JSON never
   carries a project's name or description -- it is not a security-ledger
   fact, it is projects.json's), and not worth a new field there either: the
   page already holds this, in hand, before the fetch this function's other
   half depends on even starts.

   `folder`, not the mockup's own bespoke glyph: this area's one existing
   icon table (bin/dashboard.html's `I`) has no shape for it, and every
   OTHER "this is a project" icon on this bundle already reads `folder`
   (secIndexProjectRow's own name cell) -- one icon for the one fact, not a
   new one drawn to chase a mockup pixel nothing else on the page repeats. */
function secRenderProjectTitle(){
  const idHost = $("sec-pj-titleid");
  if(idHost){
    idHost.textContent = "";
    const p = projById(secState.project) || {};
    idHost.appendChild(secIcon("folder"));
    idHost.appendChild(secEl("span", "secpjtitle-name", p.name || secState.project));
    // `.pill.on` (components.css), not secIndexProjectRow's own bare-icon
    // .secidx-enabled badge: the mockup draws a filled green PILL reading
    // "Security enabled", text and all, a different shape from that row's
    // small inline checkmark -- the identical tone (.pill.on already means
    // "this is active/enabled" everywhere else it appears), a new label on
    // it rather than a bespoke class replicating a colour this one already
    // carries. Unconditional: every project screen open here is, by
    // construction, security-enabled (the Security index never opens one
    // that is not -- see secIndexProjectRow's own identical comment).
    const badge = secEl("span", "pill on", "Security enabled");
    badge.title = "Security analysis is enabled for this project";
    idHost.appendChild(badge);
  }
  const desc = $("sec-pj-desc");
  if(desc) desc.textContent = (projById(secState.project) || {}).description || "";
}

function secRenderProjectHeader(payload){
  const host = $("sec-pj-head");
  if(!host) return;
  host.textContent = "";
  const h = payload.header || {};

  const meta = secEl("div", "secpjmeta grow");
  const profile = secEl("span", null, "Profile: ");
  profile.appendChild(secEl("span", "pill profile", h.profile || "standard"));
  meta.appendChild(profile);
  meta.appendChild(secHeaderBit("Branch", h.branch || "—"));
  if(h.branch_fell_back){
    // Postures of different branches must never be confused in silence --
    // the SAME sentence the index screen's own project table gives a branch
    // it fell back to (see secIndexProjectRow's tdBranch), now its OWN meta
    // strip item with the warning's own icon (the mockup's own amber chip)
    // instead of trailing text appended to the Branch bit above -- a reader
    // scanning the strip for a warning glyph could otherwise miss a plain
    // sentence tacked onto a value they had already read.
    const warn = secEl("span", "secpj-fellback");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", null,
      "fell back — the declared base was never analysed"));
    meta.appendChild(warn);
  }
  // 0 is "not counted" -- every analysis before the lines_of_code column
  // existed, or a project never analysed at all -- and a dash keeps that
  // from reading as an empty repository. The dash alone still does not SAY
  // that, though: a reader has no way to tell "not counted" from a repository
  // this screen is claiming is empty, so the title spells it out, the same
  // compact-density device the "Never analysed" cell beside it uses.
  meta.appendChild(secHeaderBit("Lines of code",
    h.lines_of_code ? h.lines_of_code.toLocaleString() : "—",
    h.lines_of_code ? "" : "Not counted — this analysis predates the line "
      + "count, or nothing has been analysed yet. It is not a claim that the "
      + "repository is empty."));
  meta.appendChild(secHeaderBit("Last analysis",
    h.last_analysis ? fmtAgo(h.last_analysis) : SEC_NEVER.short,
    h.last_analysis ? "" : SEC_NEVER.next));
  host.appendChild(meta);

  const settings = secEl("button", "btn ghost");
  settings.type = "button";
  settings.title = "Open this project's editor";
  settings.onclick = () => openProjectEditor(secState.project);
  settings.appendChild(secIcon("gear"));
  settings.appendChild(document.createTextNode("Project settings"));
  host.appendChild(settings);
}

function secHeaderBit(label, value, title){
  const span = secEl("span", null, label + ": ");
  span.appendChild(secEl("b", null, value));
  // Only when there is something to explain -- a bare `title=""` on every
  // header bit would be noise in the markup and a no-op on screen.
  if((title || "").trim()) span.title = title;
  return span;
}

/* The Overview tab's own caption: which ONE branch its posture describes.
   `default_branch_posture` already knows both halves of this (the branch it
   picked, and whether it had to fall back) -- this is just the Overview
   pane saying so out loud, in the same wording the header's own branch bit
   and secIndexProjectRow's tdBranch already use for a fell-back branch, so a
   reader moving between the header, this caption and the index screen never
   has to learn a second phrasing of the same fact. */
function secOverviewCaption(header){
  const cap = secEl("div", "secpj-caption", "Posture of " + (header.branch || "—"));
  if(header.branch_fell_back){
    cap.appendChild(secEl("span", "secidx-fellback",
      " (fell back — the declared base was never analysed)"));
  }
  return cap;
}

/* The sidebar's own caption: how many branches the donut/categories below
   actually span. They are severity_totals/top_categories, rolled up across
   EVERY analysed branch (see queries.py's _open_findings_by_fingerprint) --
   a different scope from the Overview panel right above, which is one
   branch only. A project with exactly one analysed branch says so plainly
   rather than a phrase that could be read as implying more than one. */
function secSidebarCaption(branchCount, attempted){
  if(!branchCount){
    // The SAME two sentences every other empty state in this area uses (see
    // SEC_NEVER in vocabulary.js) -- this one used to be a seventh variant,
    // "No finished analysis yet.", which told the reader nothing about which
    // of the two situations they were in or what to do about either.
    return secEl("div", "secpj-caption",
      attempted ? SEC_NEVER.attempted : SEC_NEVER.next);
  }
  const scope = branchCount === 1 ? "this project's only analysed branch"
                                  : "all " + branchCount + " analysed branches";
  const cap = secEl("div", "secpj-caption",
    "Posture and categories below span " + scope + ".");
  // The sidebar is a flex SIBLING of the tab panes -- it is on screen during
  // Overview, Runs, Branches, Findings and Reports alike -- so this is the
  // one place on the project screen that can say what the floor does and be
  // read from every tab. The Overview chips, the Branches tab's "Open" and
  // the donut right below are all unfloored; the findings table one tab over
  // is floored and says so itself. See SEC_FLOOR_SCOPE_NOTE.
  //
  // A `title`, not a second visible sentence (Phase 4 Task 6): none of the
  // three mockups print this caveat as prose anywhere on the page -- the
  // index screen's own identical note already lives in a bare tooltip on the
  // element that carries the unfloored numbers (secRenderIndex's own
  // `host._secCards.title`), and this is that same treatment applied here.
  // The branch-count sentence above stays visible text: it disambiguates
  // which of two genuinely different totals a reader is looking at, which a
  // hover-only aside would hide rather than explain.
  cap.title = SEC_FLOOR_SCOPE_NOTE;
  return cap;
}

/* -------------------------------------------------------------- overview */
function secRenderProjectOverview(payload){
  const host = $("sec-pj-overview");
  if(!host) return;
  host.textContent = "";
  const ov = (payload.tabs || {}).overview || {};

  if(!ov.state){
    // `attempted` tells "never analysed" apart from "analysed, nothing has
    // finished yet" -- a project whose every analysis failed used to read
    // exactly like one that had never been touched, even though its own
    // Runs tab plainly lists the attempts.
    host.appendChild(secEl("div", "empty",
      ov.attempted ? SEC_NEVER.attempted : SEC_NEVER.next));
    return;
  }
  // Which branch this posture is FOR -- default_branch_posture's own choice
  // (the project's declared base, or the branch it fell back to). The
  // sidebar's own donut/categories describe every analysed branch instead
  // (see secSidebarCaption); without naming the branch here, a multi-branch
  // project's two different, equally true totals read as a disagreement
  // rather than two different questions answered.
  host.appendChild(secOverviewCaption(payload.header || {}));
  if(ov.state === "capped"){
    // THE SAME NOTICE the index screen and the old analysis screen already
    // give: a capped analysis is a PARTIAL read of the repository, so the
    // posture below is what it had reached, not what is there.
    const warn = secEl("div", "warnline bad");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", "grow",
      "This analysis is INCOMPLETE: it stopped before covering the whole "
      + "scope. The posture below is what it had reached, not what is there."));
    host.appendChild(warn);
  }
  host.appendChild(secIndexPosturePills(ov.posture || {}));

  const chips = secEl("div", "secchips");
  const checklist = ov.checklist || {};
  SEC_STATES.forEach(state => {
    const n = checklist[state] || 0;
    const chip = secEl("span", "secpj-statchip" + (n ? "" : " zero"));
    chip.title = SEC_STATE_HELP[state] || "";
    chip.appendChild(secEl("span", null, SEC_STATE_LABEL[state] || state));
    chip.appendChild(secEl("span", "n", String(n)));
    chips.appendChild(chip);
  });
  host.appendChild(chips);
}

/* ------------------------------------------------------------------ runs */
function secRenderProjectRuns(payload){
  const host = $("sec-pj-runstable");
  if(!host) return;
  host.textContent = "";
  const card = secEl("div", "card secpj-plaincard secpj-runslistcard");
  const cardHead = secEl("div", "secpj-cardhead");
  cardHead.appendChild(secEl("h3", null, "Analysis runs"));
  // The launcher, moved here from the always-open strip the Runs tab used to
  // draw above its two columns (Runs tab parity pass 2 -- ProjectRuns.png
  // never pictured that strip): the house card-header-action slot, the same
  // one secProjectActivity's "View all" and secViewAllAnalysesButton's "View
  // all analyses" already occupy elsewhere on this bundle. `.btn.primary`,
  // not `.btn.ghost` like those two -- this button starts a run rather than
  // navigating to a read-only list, the same weight `#sec-run` itself always
  // carried as the strip's own one primary action.
  cardHead.appendChild(secLaunchButton());
  card.appendChild(cardHead);
  const runs = (payload.tabs || {}).runs || [];
  card.appendChild(secRunsFilters(runs));
  card.appendChild(secRunsTable(runs));
  host.appendChild(card);
}

/* Opens <dialog id="seclaunch"> (bin/dashboard.html), which now holds the
   exact repo/branch/profile/Analyse controls the old strip did -- same
   elements, same ids, so secOpenLaunch (analysis.js) is nothing more than
   `$("seclaunch").showModal()`: every combo already stays in sync with the
   project on screen regardless of the dialog's own open/closed state
   (secOpen/secLoadBranches/secSyncScope all run whether or not anybody has
   ever opened this dialog), so there is nothing to re-populate on open. */
function secLaunchButton(){
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn primary";
  btn.title = "Start a new analysis of this project";
  btn.appendChild(document.createTextNode("Analyse"));
  btn.onclick = () => secOpenLaunch();
  return btn;
}

function secRunsFilters(runs){
  const wrap = secEl("div", "secchips");
  const counts = {};
  runs.forEach(r => { counts[r.state] = (counts[r.state] || 0) + 1; });

  const all = secEl("button", "secchip" + (secRunsFilter ? "" : " on"));
  all.type = "button";
  all.appendChild(secEl("span", null, "All"));
  all.appendChild(secEl("span", "n", String(runs.length)));
  all.onclick = () => { secRunsFilter = ""; secRenderProjectRuns(secProjectCache); };
  wrap.appendChild(all);

  RUN_STATES.forEach(state => {
    const n = counts[state] || 0;
    const chip = secEl("button", "secchip" + (n ? "" : " zero")
      + (secRunsFilter === state ? " on" : ""));
    chip.type = "button";
    // Title Case ("Running"/"Done"/"Capped"/"Failed"), matching the mockup's
    // own chip row -- ANALYSIS_END_STATES itself is lowercase (it is also a
    // URL-safe filter value, read back by this same chip's onclick), and a
    // bare `state` used to print that raw lowercase word here. Not
    // SEC_RUN_STATUS_LABEL (index-screen.js): that map spells "done" as
    // "Completed" for the STATUS pill a few pixels to the right, a
    // deliberately friendlier word for a cell whose whole job is naming one
    // run's state; this chip is a COUNT bucket, and the mockup's own pixels
    // spell that same bucket "Done", not "Completed" -- a second, shorter
    // label for the identical value, not a second copy of the pill's map.
    chip.appendChild(secEl("span", null, state.charAt(0).toUpperCase() + state.slice(1)));
    chip.appendChild(secEl("span", "n", String(n)));
    chip.onclick = () => { secRunsFilter = state; secRenderProjectRuns(secProjectCache); };
    wrap.appendChild(chip);
  });
  return wrap;
}

/* This column and the checklist chips one click below it (secRenderChecklist,
   fed by the same finding's-worth of data through queries.checklist()) can
   legitimately total different numbers for the SAME row. This column is
   finding_counts_by_analysis's plain per-analysis COUNT(*) -- how many
   findings THAT RUN recorded, a fact a later run or decision can never
   change (see that function's own docstring). checklist() answers a
   different question, "what is open right now": it also carries forward
   findings that disappeared since the branch's previous analysis, marked
   fixed or pending, so its own total can run higher. Same resolution as
   secOverviewCaption/secSidebarCaption above -- name what each number
   counts rather than force one to match the other. */
// [key, label] tuples, SEC_PROJECT_COLS-shaped (index-screen.js) --
// test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column
// (tests/test_page_contract.py) reads only `.length` off this, so a fifth
// column added here later is caught by the same guard with no change to
// the test itself. Down from eight columns to the mockup's own four
// (Phase: Runs tab rebuild) -- Profile/Branch/Commit/Duration move into the
// selected run's own meta grid in the middle column instead (they describe
// ONE run, which is exactly what that card is for), and this table keeps
// only what tells rows apart from EACH OTHER at a glance: which run, its
// state, how much it found, and when.
const SEC_RUNS_COLS = [
  ["run", "Run"], ["state", "Status"], ["findings", "Findings recorded"], ["date", "Date"],
];

// The Date column's own sort, client-side over the rows this payload
// already holds (at most 100, cmd_project_data's own LIMIT) -- the mockup's
// own sort-arrow header, the identical `th.sortable`/`.sorted` look
// components.css already gives every other sortable header on this page.
// Not the app bundle's own tableCard() (ui/app/chrome.js): that mechanism
// answers its click through bin/dashboard.html's ONE delegated
// data-attribute listener, which this bundle's own tables never use --
// every interactive element in ui/security/ is wired with a direct
// `.onclick`, this one included, the same idiom secIndexProjectRow's own
// kebab and every chip on this screen already follow.
let secRunsSortDir = "desc";

// "64C 4H 3M 0L" -- the compact per-severity sub-line the mockup draws
// under each row's own total, from `findings_by_severity`
// (queries.finding_severity_by_analysis, cmd_project_data) -- a `null` row
// (a running or failed analysis; see that field's own comment) renders
// nothing, the same "not counted yet" the total beside it already shows as
// a dash. Critical/High/Medium/Low only, in that order, never Info: the
// mockup's own sample never shows a fifth letter, and four single-letter
// counts is the density this sub-line's own small type has room for -- the
// full five-severity breakdown, Info included, is what the right rail's own
// "Findings by severity" donut is for.
const SEV_LETTER = [["critical", "C"], ["high", "H"], ["medium", "M"], ["low", "L"]];

function secRunSeverityLine(bySeverity){
  if(!bySeverity) return null;
  const line = secEl("div", "secrun-sevline");
  SEV_LETTER.forEach(([sev, letter]) => {
    line.appendChild(secEl("span", "secrun-sevbit sev-" + sev,
      (bySeverity[sev] || 0) + letter));
  });
  return line;
}

function secRunsTable(runs){
  const filtered = secRunsFilter ? runs.filter(r => r.state === secRunsFilter) : runs;
  if(!filtered.length){
    return secEl("div", "tblempty", runs.length
      ? "Nothing in that state." : "No analyses of this project yet.");
  }
  const sorted = filtered.slice().sort((a, b) =>
    secRunsSortDir === "asc" ? (a.started || 0) - (b.started || 0)
                              : (b.started || 0) - (a.started || 0));
  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secpj-runstable";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_RUNS_COLS.forEach(([key, label]) => {
    const th = document.createElement("th");
    th.appendChild(document.createTextNode(label));
    if(key === "findings"){
      // The one-sentence version of the comment above secRunSeverityLine,
      // for whoever is looking at the rendered table rather than this
      // source.
      th.title = "How many findings this run recorded — the checklist chips "
        + "below can total more, since they also carry forward findings "
        + "that disappeared since the previous analysis of this branch, "
        + "marked fixed or pending.";
    }
    if(key === "date"){
      th.className = "sortable sorted";
      th.title = "Sort by date";
      th.setAttribute("aria-sort", secRunsSortDir === "asc" ? "ascending" : "descending");
      th.appendChild(secIcon(secRunsSortDir === "asc" ? "sortasc" : "sortdesc"));
      th.onclick = () => {
        secRunsSortDir = secRunsSortDir === "asc" ? "desc" : "asc";
        secRenderProjectRuns(secProjectCache);
      };
    }
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  sorted.forEach(r => tbody.appendChild(secRunRow(r)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  // `numbered: true`, page/pages fixed at 1/1 (Phase 4 Task 6, matching the
  // mockup's own footer where the PNG shows one): this table holds
  // everything secRenderProjectRuns was handed (at most 100 rows,
  // cmd_project_data's own LIMIT) with no slicing of its own -- the identical
  // "one real page, said honestly" shape secRepaintProjectsTable
  // (index-screen.js) already established for the fleet table against the
  // same mockup-vs-data gap (a numbered pager with nothing behind a second
  // page), rather than a disabled Prev/Next or an invented page size.
  wrap.appendChild(tableFooter({
    shown: {from: 1, to: sorted.length}, total: sorted.length, noun: "run",
    page: 1, pages: 1, numbered: true,
  }));
  return wrap;
}

function secRunRow(r){
  const tr = document.createElement("tr");
  // The mockup's own accent border on the SELECTED run's row -- whichever
  // analysis is actually on screen in the middle column below, pinned or
  // followed alike (both set secState.analysis the same way; see
  // secShowAnalysis's own comment in analysis.js for the one difference
  // between them, which is about what the NEXT poll tick may replace, not
  // about which row this reads right now).
  if(secState.analysis && secState.analysis.id === r.id) tr.className = "secrun-selected";
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };

  const tdId = document.createElement("td");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn ghost";
  btn.textContent = "#" + r.id;
  btn.title = "Show this analysis below";
  // The existing single-analysis drill-down, unchanged: the same function
  // "Earlier analyses of this branch" already calls for its own "#N" rows.
  // `pinned`, for the same reason it does: this row is a deliberate choice of
  // ONE analysis, and the 4-second poll must not replace it with the picker's
  // branch's newest four seconds later. It does NOT push browser history --
  // a row pick is a selection within this surface (like a filter chip or
  // this table's own column sort), not a navigation to a new screen.
  btn.onclick = () => secShowAnalysis(r.id, true);
  tdId.appendChild(btn);
  tr.appendChild(tdId);

  // M6a (Phase 4 final review): the index screen's own Recent-analyses table
  // reads this exact fact (an analysis's `state`) as a Title-Cased colour
  // pill (secIndexRunStatusPill, index-screen.js) -- this table used to
  // print the raw lowercase word instead (`cell(r.state)`), the same state
  // in a second, plainer register a reader crossing between the two tables
  // had no reason to expect. Imported rather than re-typed: both modules
  // are ui/security/'s own bundle, so this is not a new cross-bundle bridge.
  const tdState = document.createElement("td");
  tdState.appendChild(secIndexRunStatusPill(r.state));
  tr.appendChild(tdState);

  const tdFindings = document.createElement("td");
  tdFindings.appendChild(secEl("div", "secrun-findtotal",
    r.findings == null ? "—" : String(r.findings)));
  const sevLine = secRunSeverityLine(r.findings_by_severity);
  if(sevLine) tdFindings.appendChild(sevLine);
  tr.appendChild(tdFindings);

  tr.appendChild(cell(fmtWhen(r.started)));
  return tr;
}

/* -------------------------------------------------------- the selected run
   Two pieces of the mockup's middle column that live here rather than in
   analysis.js, which owns everything else in that card (the meta grid, the
   incomplete/coverage/live-run notices, the search/category/Filters bar,
   the finding cards): secRenderRunHead's own actions need secDownloadReport
   (actions.js) and secRunFor (history.js), and importing either into
   analysis.js would open a NEW import cycle -- actions.js already imports
   FROM analysis.js (secScope/secReload/secSyncPoll/secPaintRunButton), and
   history.js imports secShowAnalysis from it too, so analysis.js importing
   either back would close a loop that does not exist today. project-
   screen.js already has ONE cycle with analysis.js (secInvalidateProject/
   secRefreshProject go one way, secOpen/secShowAnalysis the other) --
   extending that existing edge costs nothing new, where opening a second,
   different cycle would. secRenderRunRecorded lives here for an unrelated
   reason: it reads THIS module's own project-data cache (secProjectCache),
   never secState.findings, so it was never analysis.js's fact to begin
   with. Both are called from analysis.js's own secPaint(), every time it
   repaints, exactly where the old secPaint built the equivalent content
   into #sec-status inline. */

function secProjectRunRow(id){
  const runs = ((secProjectCache || {}).tabs || {}).runs || [];
  return runs.find(r => r.id === id) || null;
}

function secRenderRunHead(){
  const host = $("sec-run-head");
  if(!host) return;
  host.textContent = "";
  const a = secState.analysis;
  if(!a) return;
  const head = secEl("div", "secrun-head");
  const title = secEl("div", "secrun-headtitle");
  title.appendChild(secEl("h3", "secrun-headid", "Run #" + a.id));
  title.appendChild(secIndexRunStatusPill(a.state));
  head.appendChild(title);

  const actions = secEl("div", "secrun-headactions");

  // The one-click download: the run's report, Markdown -- the format every
  // other single-click download on this page defaults to (reports-tab.js's
  // own row lists all four; this icon is the fast path to the one most
  // reached for, the rest live one click further, in the kebab below).
  // Reuses secDownloadReport, the exact fetch+Blob+token mechanism
  // reports-tab.js's own per-row buttons and actions.js's own secDownload
  // already share -- see that function's own comment for why it is not two
  // near-identical copies.
  const dl = document.createElement("button");
  dl.type = "button";
  dl.className = "iconbtn";
  dl.title = "Download this run's report (Markdown)";
  dl.appendChild(secIcon("download"));
  dl.onclick = () => secDownloadReport(a.id, "md", dl);
  actions.appendChild(dl);

  // The run's own live/journaled session -- secRunFor is the SAME lookup
  // secPaint's old "Open the run" button already used (history.js), and
  // openLog the same page-native opener; disabled rather than hidden when
  // none is found, so the row of three icons never reflows depending on the
  // state of the run behind it.
  const run = secRunFor(a);
  const eye = document.createElement("button");
  eye.type = "button";
  eye.className = "iconbtn";
  eye.title = run ? "Open this run's live session"
                  : "No live or journalled session found for this run";
  eye.disabled = !run;
  eye.appendChild(secIcon("eye"));
  if(run) eye.onclick = () => openLog(run.id, run.start);
  actions.appendChild(eye);

  // The rest: JSON/HTML/SBOM, the three download formats the one-click icon
  // above does not cover -- same secDownloadReport call, same house
  // <details>/<summary>/.menu-pop kebab secIndexProjectRow's own row already
  // draws (see that function's own comment for the position:fixed/
  // closeMenus() reasoning, identical here).
  const kebab = document.createElement("details");
  kebab.className = "secidx-kebab";
  const summary = document.createElement("summary");
  summary.className = "iconbtn";
  summary.title = "More downloads";
  summary.appendChild(secIcon("dots"));
  summary.onclick = (e) => { e.stopPropagation(); closeMenus(); };
  kebab.appendChild(summary);
  const pop = secEl("div", "menu-pop");
  pop.setAttribute("role", "menu");
  [["json", "JSON"], ["html", "HTML"], ["sbom", "SBOM"]].forEach(([fmt, label]) => {
    const item = document.createElement("button");
    item.setAttribute("role", "menuitem");
    item.appendChild(secIcon("file"));
    item.appendChild(document.createTextNode(label));
    item.onclick = (e) => { e.stopPropagation(); kebab.open = false; secDownloadReport(a.id, fmt, item); };
    pop.appendChild(item);
  });
  kebab.appendChild(pop);
  kebab.ontoggle = () => {
    pop.hidden = !kebab.open;
    if(!kebab.open) return;
    const r = summary.getBoundingClientRect();
    pop.style.position = "fixed";
    pop.style.top = (r.bottom + 6) + "px";
    pop.style.right = (window.innerWidth - r.right) + "px";
    pop.style.left = "auto";
    pop.style.bottom = "auto";
  };
  actions.appendChild(kebab);

  head.appendChild(actions);
  host.appendChild(head);
}

/* "N total" + a dot-and-count per severity, zeros muted -- the mockup's own
   "Findings recorded" strip. Reads the SAME row the Runs table's own
   FINDINGS column and its per-severity sub-line already read
   (secProjectRunRow, this module's own project-data cache) -- how many
   findings THIS RUN recorded, never secState.findings/secPosture (the
   checklist, which also carries forward fixed/pending findings from this
   branch's history -- see SEC_RUNS_COLS's own comment for why the two are
   allowed to disagree for the very same run). The right rail's "Findings by
   severity" donut a few inches away is deliberately the OTHER number --
   what is open right now, from the checklist -- so this strip and that
   donut can legitimately show different totals for the identical run, the
   same resolution this screen already applies everywhere else two counts
   answer two different questions. */
function secRenderRunRecorded(){
  const host = $("sec-run-recorded");
  if(!host) return;
  host.textContent = "";
  const a = secState.analysis;
  if(!a) return;
  const row = secProjectRunRow(a.id);
  const total = row && row.findings != null ? row.findings : null;
  const bySeverity = (row && row.findings_by_severity) || null;
  const strip = secEl("div", "secrun-recorded");
  strip.appendChild(secEl("span", "secrun-recorded-label", "Findings recorded"));
  strip.appendChild(secEl("span", "secrun-recorded-total",
    total == null ? "—" : total + " total"));
  ["critical", "high", "medium", "low", "info"].forEach(sev => {
    const n = bySeverity ? (bySeverity[sev] || 0) : 0;
    const pill = secEl("span", "secrun-recpill sev-" + sev + (n ? "" : " zero"));
    pill.appendChild(secEl("span", "secrun-recdot"));
    pill.appendChild(document.createTextNode(n + " " + (sev[0].toUpperCase() + sev.slice(1))));
    strip.appendChild(pill);
  });
  host.appendChild(strip);
}

/* --------------------------------------------------------------- sidebar */
/* What is "open" from a single run's own checklist -- the SAME question
   secRenderSummary's old severity pills used to ask of secState.findings
   (secPosture already excludes fixed/accepted/false_positive and applies
   the project's own severity floor; see SEC_FLOOR_SCOPE_NOTE for why THIS
   surface, "the checklist of a single analysis", is one of the two allowed
   to floor at all). Read here, in project-screen.js, rather than left where
   the pills used to live: the right rail is this module's own furniture,
   and secState is already imported here for the sidebar caption above. */
function secProjectRunPosture(){
  return secPosture(secState.findings, secMinSeverity(secState.project));
}

/* The same run's findings, grouped by RULE (secRuleMeta's own resolution --
   the identical label/icon a rule earns everywhere else on this bundle),
   top 5 -- the run-scoped twin of queries.top_categories, computed
   client-side from data already in hand (secState.findings, the same
   checklist fetch the findings list and the donut above both already read)
   rather than a new request for a number this small: at most a few hundred
   findings, one pass to bucket and sort, well under what fetching them
   already cost. Decided and fixed findings are excluded, the same
   "what is still standing" reading top_categories itself applies via
   `_open_findings_by_fingerprint`. */
function secProjectRunCategories(){
  const open = secVisible(secState.findings, secMinSeverity(secState.project))
    .filter(f => !["fixed", "accepted", "false_positive"].includes(f.state));
  const byRule = {};
  open.forEach(f => {
    const key = f.rule || "";
    if(!byRule[key]) byRule[key] = {rule: f.rule, category: f.category, count: 0};
    byRule[key].count++;
  });
  return Object.values(byRule)
    .sort((a, b) => b.count - a.count || String(a.rule).localeCompare(String(b.rule)))
    .slice(0, 5);
}

/* The Runs tab's own right rail: TWO separate cards (ProjectRuns.png draws
   "Findings by severity" and "Top issue categories" as distinct boxes, a
   gap between them, unlike the one merged block secIndexDonut returns for
   every OTHER tab's sidebar a few lines below in secRenderProjectSidebar)
   built from the pieces secIndexDonut is itself built from
   (secIndexDonutSvg/secIndexDonutLegend/secIndexCategories, all exported
   from index-screen.js for exactly this reuse) rather than a second,
   hand-rolled donut. `showZero` (secIndexDonutLegend's own new opt-in) is
   what makes this legend list Low/Info even at 0, the mockup's own reading
   -- every OTHER caller of that function keeps hiding a zero severity
   exactly as it always has. */
function secProjectRunSidebar(){
  const frag = document.createDocumentFragment();
  const donut = secProjectRunPosture();

  const donutCard = secEl("div", "card secpj-plaincard");
  const donutHead = secEl("div", "secpj-cardhead");
  donutHead.appendChild(secEl("h3", null, "Findings by severity"));
  donutCard.appendChild(donutHead);
  const row = secEl("div", "secrun-donutrow");
  row.appendChild(secIndexDonutSvg(donut));
  row.appendChild(secIndexDonutLegend(donut, {showPercent: true, showZero: true}));
  donutCard.appendChild(row);
  frag.appendChild(donutCard);

  const catCard = secEl("div", "card secpj-plaincard");
  const catHead = secEl("div", "secpj-cardhead");
  catHead.appendChild(secEl("h3", null, "Top issue categories"));
  catCard.appendChild(catHead);
  catCard.appendChild(secIndexCategories(secProjectRunCategories()));
  const viewAll = secEl("button", "btn ghost secpj-viewallcats", "View all categories");
  viewAll.type = "button";
  viewAll.title = "Open this project's Findings tab";
  viewAll.onclick = () => secSwitchProjectTab("findings");
  catCard.appendChild(viewAll);
  frag.appendChild(catCard);

  return frag;
}

/* Called from analysis.js's own secPaint(), on every one of its repaints --
   every one of the THREE things below depends on secState.analysis/
   secState.findings, which change on every analysis switch and every poll
   tick, neither of which otherwise reaches this module's own panels at all
   (secRenderProject, this file's own per-fetch orchestrator, and
   secSwitchProjectTab's own repaint are the only other two callers of any
   of them, and neither runs on a plain row click or a poll's own
   secShowAnalysis). A no-op before the first project-data fetch answers,
   the same guard secRefreshProject already uses.

   secRenderProjectRuns is in this list for a reason easy to miss: it is
   what paints the LEFT table's own `.secrun-selected` row highlight
   (secRunRow reads secState.analysis.id fresh on every call), and that
   table has no OTHER reason to repaint just because a different row was
   clicked or a pinned analysis's poll tick came back -- without this, the
   highlight only ever moved on the next full project-data refresh (up to
   4 seconds later during a live run, or never for a done project nothing
   is polling). secRenderRunHead/secRenderRunRecorded are this module's own
   pieces of the mockup's middle column (see each one's own comment for why
   they live here and not in analysis.js); secRenderProjectSidebar is the
   right rail, tab-aware (secProjectRunSidebar's own comment). */
export function secRefreshRunPanels(){
  if(!secProjectCache) return;
  secRenderProjectRuns(secProjectCache);
  secRenderRunHead();
  secRenderRunRecorded();
  secRenderProjectSidebar(secProjectCache);
}

function secRenderProjectSidebar(payload){
  const host = $("sec-pj-side");
  if(!host) return;
  host.textContent = "";
  const sb = payload.sidebar || {};
  const attempted = !!(((payload.tabs || {}).overview) || {}).attempted;
  host.appendChild(secSidebarCaption(sb.branch_count || 0, attempted));
  if(secProjectTab === "runs"){
    host.appendChild(secProjectRunSidebar());
  }else{
    // The donut collapses every analysed branch into one figure, so it has no
    // row to hang the `incomplete` badge off the way the Overview panel and the
    // index table do -- it gets the same caveat as a sentence instead.
    host.appendChild(secIndexDonut(sb.donut || {}, sb.categories || [],
      secCappedScopeNote(sb.capped_branches || 0, sb.branch_count || 0, "branch")));
  }
  host.appendChild(secProjectActivity(sb.activity || []));
}

function secProjectActivity(events){
  const box = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Recent activity"));
  // The Activity screen's own entry point from here: this feed is the last
  // five events (see cmd_project_data's own `ledger.events_for(..., limit=5)`),
  // the full screen is every event, filterable by kind, for this project.
  const viewAll = secEl("button", "btn ghost", "View all");
  viewAll.type = "button";
  viewAll.onclick = () => secOpenActivity(secState.project);
  head.appendChild(viewAll);
  box.appendChild(head);
  if(!events.length){
    box.appendChild(secEl("div", "tblempty", "No activity recorded yet."));
    return box;
  }
  const list = secEl("div", "seclist");
  events.forEach(e => {
    const row = secEl("div", "secrow");
    row.appendChild(secIcon("activity"));
    const grow = secEl("div", "grow");
    grow.appendChild(secEl("div", "secname", EVENT_KIND_LABEL[e.kind] || e.kind));
    grow.appendChild(secEl("div", "secmeta",
      [e.detail, fmtAgo(e.at)].filter(Boolean).join(" · ")));
    row.appendChild(grow);
    list.appendChild(row);
  });
  box.appendChild(list);
  return box;
}
