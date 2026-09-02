/* --------------------------------------------------------- one project */
import { $, CC, api, toast, projById, fmtDur, fmtWhen, money, createCombo,
         makePicker, pushNav } from "./page.js";
import { secIcon, secIconHTML, secEl, secFetch } from "./dom.js";
import { SEC_POLL_MS, SEC_PROFILES, SEC_STATES, SEC_STATE_HELP, SEC_STATE_LABEL,
         SEC_NEVER, secCategoryMeta, secDefaultProfile, secMinSeverity,
         secRepos, secSevKey, secSevRank, secStateKey, secVisible } from "./vocabulary.js";
import { secState } from "./state.js";
import { secInvalidateIndex, secRenderIndex, secLoadIndex } from "./index-screen.js";
import { secRunFor, secRenderHistory } from "./history.js";
import { secAskReason } from "./reason.js";
import { secInvalidateProject, secRefreshProject, secRefreshRunPanels } from "./project-screen.js";

// "quick" -> "Quick": the launcher's own profile combo, mapped off the same
// SEC_PROFILES list the project editor's default-profile combo already maps
// with its own titleOpt (bin/dashboard.html) -- not a second hand-typed
// "Quick"/"Standard"/"Deep" list, which is exactly what the old <option>
// markup this replaces would have become the moment a fourth profile shipped.
function secProfileOpt(v){ return {v, label: v.charAt(0).toUpperCase() + v.slice(1)}; }

// The three combos that replaced sec-repo/sec-branch/sec-profile's native
// <select>s (Phase 4 Task 5). Populated by secOpen/secLoadBranches below,
// exactly where secFill() used to feed the bare <select>s; read by
// secScope/secAnalyse through the hidden input each keeps, at the same id,
// so neither of those changed at all.
let secRepoCombo = null, secBranchCombo = null, secProfileCombo = null;

// Wires the three above onto the static markup bin/dashboard.html now draws
// for them -- called once from index.js's own init(), the identical
// "constructed once at boot" moment bin/dashboard.html's own initCombos()
// wires every other combo on the page. createCombo itself stays defined
// there (see page.js's own comment on the chrome bridge, and makePicker's
// twin one in secProjectsFilterBar below) -- bridged in through
// CCSecurity.init(CC) because the WIDGET is the page's, but what populates
// it and what a pick does is this area's own.
export function secInitLaunchCombos(){
  // onPick mirrors exactly what index.js's own sec-repo/sec-branch `change`
  // listeners did before this task -- a hidden input's `.value` is never
  // touched by a person, so those listeners would otherwise just stop firing.
  secRepoCombo = createCombo({id: "sec-repo", allowNone: false,
    onPick: async () => { await secLoadBranches(""); $("sec-branch-other").value = ""; secSyncScope(); }});
  secBranchCombo = createCombo({id: "sec-branch", allowNone: false,
    onPick: () => { $("sec-branch-other").value = ""; secSyncScope(); }});
  secProfileCombo = createCombo({id: "sec-profile", allowNone: false, def: "standard"});
  secProfileCombo.set("standard", SEC_PROFILES.map(secProfileOpt));
}

/* Runs tab parity pass 2: the three combos above (and sec-branch-other, and
   sec-run) used to sit in an always-open strip above the Runs tab's own two
   columns; ProjectRuns.png never pictured that strip, so it moved whole into
   <dialog id="seclaunch"> (bin/dashboard.html), opened by a compact "Analyse"
   button in the "Analysis runs" card's own title row (secLaunchButton,
   project-screen.js). Nothing to populate here on open: every combo above is
   already kept in sync with the project on screen (secOpen/secLoadBranches/
   secSyncScope all run regardless of whether this dialog has ever been
   opened), so showing it is the whole function. */
export function secOpenLaunch(){ $("seclaunch").showModal(); }

/* Cancel closes with no side effect -- there is nothing to discard: this
   dialog commits nothing on its own (Analyse does, through secAnalyse,
   actions.js, wired directly to #sec-run by index.js exactly as before this
   task), so unlike editor/projmodal's own Cancel there is no dirty state to
   warn about. Escape needs no listener of its own for the same reason --
   native <dialog> Escape-to-close is exactly right here, the same minimal
   wiring wireActivityFindingDialog's own Close button already uses
   (activity-screen.js). */
export function wireLaunchDialog(){
  $("seclaunch-cancel").addEventListener("click", () => $("seclaunch").close());
}

let secTimer = null;
export function secStopPoll(){ if(secTimer){ clearInterval(secTimer); secTimer = null; } }
export function secSyncPoll(){
  // Polling exists for one reason — an analysis in flight — but WHERE the
  // operator is looking is part of that reason, and leaving the view has to end
  // it. It used to decide on project+running alone, so a secReload() already in
  // the air when the view was left re-armed the interval a moment after
  // secLeave() had cleared it: two subprocess-backed GETs every four seconds,
  // from the Overview or the Jobs page, for as long as the analysis ran.
  const running = CC.currentView === "security" && secState.project
                  && secState.analyses.some(a => a.state === "running");
  // The poll tick itself must not force a full header/tabs/sidebar refetch
  // (see secReload's own comment) -- every OTHER caller of secReload still
  // does, by leaving its argument at the default.
  if(running && !secTimer) secTimer = setInterval(() => secReload(false), SEC_POLL_MS);
  if(!running) secStopPoll();
}

/* Coming back to a project screen re-reads it and picks the poll back up: what
   is on it may be minutes old, and leaving the page stopped the watching. */
export function secEnter(){ if(secState.project) secReload(); else secLoadIndex(false); }
export function secLeave(){ secStopPoll(); }

/* `fromHistory` (F4 history layer): true for exactly two kinds of caller,
   neither of which is a reader pressing "All projects" -- CCSecurity.navigate
   (bin/dashboard.html's popstate handler, restoring a state that already IS
   this one) and secOpenActivity (activity-screen.js), which reuses this
   function for its own teardown and pushes ITS OWN, later, resulting state.
   Either way the entry for "back to the index" must not be pushed a second
   time -- see bin/dashboard.html's own router comment, beside setView, for
   the full contract and for what happens when this flag is dropped. */
export function secBack(fromHistory){
  secStopPoll();
  // Whatever just happened in there (a new analysis, a decision) may have
  // changed the fleet's posture, so the index's cached answer is thrown away
  // and re-read rather than repainting numbers from before. The project
  // screen's own cache gets the identical treatment, for the identical
  // reason.
  secInvalidateIndex();
  secInvalidateProject();
  secState.project = ""; secState.analysis = null; secState.findings = [];
  secState.analyses = []; secState.stateFilter = ""; secState.pinned = false;
  $("sec-detail").hidden = true;
  $("sec-projects").hidden = false;
  secRenderIndex();
  secLoadIndex(false);
  if(!fromHistory) pushNav({view: "security", sec: {screen: "index"}});
}

export async function secOpen(project){
  secStopPoll();
  // This screen's generation, in the same counter secShowAnalysis uses. Opening
  // a project is three round trips (its analyses, its branches, its checklist)
  // and the list is one click away behind Back: without this, a slow answer for
  // the project somebody left lands on the project they are now looking at and
  // fills its pickers with another repository's branches.
  const seq = ++secState.seq;
  secState.project = project;
  secState.analysis = null; secState.findings = []; secState.analyses = [];
  secState.stateFilter = ""; secState.pinned = false;
  // A fresh project starts the running/not-running comparison over: the
  // value from whatever project was open before (or none) must never make
  // this project's own first poll tick look unchanged by coincidence.
  secProjectPollWasRunning = null;
  $("sec-projects").hidden = true;
  $("sec-detail").hidden = false;
  // The breadcrumb's own CURRENT segment (see bin/dashboard.html's own
  // comment on #sec-crumbs) -- plain text, no icon: a small crumb has no
  // room for one, and the project already gets its own icon on the name
  // row right below (secRenderProjectTitle, project-screen.js).
  $("sec-title").textContent = project;
  $("sec-findings").textContent = "";
  $("sec-history").textContent = "";
  $("sec-summary").textContent = "";
  $("sec-checklist").textContent = "";
  $("sec-dl").hidden = true;
  secResetFindBar();
  secStatus("Loading…");

  const p = projById(project) || {};
  const repos = secRepos(p);
  secRepoCombo.set("", repos.map(r => ({v: r, label: r})));
  // With one checkout there is nothing to choose between, and the row is filed
  // under the project's own name either way.
  $("sec-repo-field").hidden = repos.length < 2;
  secProfileCombo.set(secDefaultProfile(project));
  $("sec-branch-other").value = "";

  try{
    const list = await secFetch("/api/security?project=" + encodeURIComponent(project));
    if(seq !== secState.seq) return;      // a newer screen is up
    secState.analyses = list;
  }catch(e){
    if(seq !== secState.seq) return;
    secState.analyses = []; secStatus("Could not read its analyses — " + e.message);
  }
  // Open on what was last analysed: that is the screen somebody came back for.
  const last = secState.analyses[0];
  if(last && repos.includes(last.repo)) secRepoCombo.set(last.repo);
  await secLoadBranches(last ? last.branch : "");
  if(seq !== secState.seq) return;
  if(last && SEC_PROFILES.includes(last.profile)) secProfileCombo.set(last.profile);
  // secSyncScope() takes the next generation for itself, so nothing after this
  // may test `seq` again.
  await secSyncScope();
}

// How many branches git itself lists for the repo currently picked -- kept
// from the SAME fetch that fills the launcher's branch combo below, so the
// Branches tab's coverage card (secBranchesSidebar, branches-tab.js) can put
// a real denominator under "X / Y analyzed" without a second git call. 0
// until the list has ever answered for this project (the card falls back to
// counting only the branches ever analysed, and says so).
let secGitBranches = 0;
export function secGitBranchCount(){ return secGitBranches; }

export async function secLoadBranches(want){
  // Same generation guard as secOpen and secShowAnalysis, for the same reason:
  // this is a `git for-each-ref` on the server, and the answer for the repo
  // somebody has already navigated away from must not fill the picker of the
  // one now on screen.
  const seq = secState.seq;
  // Zeroed before the fetch, not only on failure: between opening a project
  // and this answer landing, the previous project's count must not pose as
  // the new one's.
  secGitBranches = 0;
  secBranchCombo.set("…", [{v: "…", label: "…"}]);
  let branches = [];
  try{
    const j = await secFetch("/api/security/branches?project="
      + encodeURIComponent(secState.project) + "&repo=" + encodeURIComponent($("sec-repo").value));
    if(seq !== secState.seq) return;
    branches = j.branches || [];
    secGitBranches = branches.length;
  }catch(e){
    if(seq !== secState.seq) return;
    secGitBranches = 0;
    secBranchCombo.set("", []);
    toast("Could not list branches — " + e.message, true);
    return;
  }
  // The branch of the last analysis may be gone from the checkout by now; it is
  // still the one this screen is about, so it stays in the list.
  if(want && !branches.includes(want)) branches = [want].concat(branches);
  secBranchCombo.set(want, branches.map(b => ({v: b, label: b})));
}

/* What the three controls currently say. The free-text field wins when it has
   anything in it: it is the one somebody typed. */
export function secScope(){
  const typed = $("sec-branch-other").value.trim();
  return {repo: $("sec-repo").value, branch: typed || $("sec-branch").value || ""};
}

export async function secSyncScope(){
  const s = secScope();
  secState.repo = s.repo; secState.branch = s.branch;
  const mine = secState.analyses.filter(a => a.repo === s.repo && a.branch === s.branch);
  await secShowAnalysis(mine.length ? mine[0].id : null);
}

/* `pinned` marks a DELIBERATE open -- a row clicked in the Runs table, an
   "#N" in the history list, the Activity screen's deep link into one exact
   analysis. Without it the 4-second poll took the branch's newest analysis
   every tick and painted that instead, so a historical run opened on purpose
   was swapped out from under the reader within four seconds of arriving. The
   poll still REFRESHES a pinned analysis (same id, re-fetched, so a live one
   keeps moving) -- it just stops choosing a different one.

   Cleared by everything that is not a deliberate open: `secSyncScope` (the
   picker changed, so following the newest is exactly right again), `secOpen`
   and `secBack`. It is a property of the SCREEN, not of the id, which is why
   it lives in secState beside the analysis it applies to rather than in a
   variable this module alone can see. */
export async function secShowAnalysis(id, pinned){
  const seq = ++secState.seq;
  secState.pinned = !!pinned;
  if(id == null){
    secState.analysis = null; secState.findings = [];
    secPaint();
    return;
  }
  try{
    const j = await secFetch("/api/security/checklist?analysis=" + encodeURIComponent(id));
    if(seq !== secState.seq) return;    // a newer request already answered
    secState.analysis = j.analysis || null;
    secState.findings = j.findings || [];
  }catch(e){
    if(seq !== secState.seq) return;
    secState.analysis = null; secState.findings = [];
    secStatus("Could not read that analysis — " + e.message);
    return;
  }
  secPaint();
}

// Whether ANY analysis of the project was `running` as of the last
// secReload() call -- so a poll tick can tell "still watching the same run"
// apart from "a run just finished", see secReload's own comment. `null`
// (not a boolean) until the first reload, so that first call always counts
// as a change and forces the one-time refresh it would have forced anyway.
let secProjectPollWasRunning = null;

/* Re-read the list and, with it, whatever is on screen. Called by the poll
   while an analysis is running, once after every action, and by secEnter()
   when the view is opened -- `forceProject` is true for all of those by
   default; only secSyncPoll's own recurring tick passes `false`. */
export async function secReload(forceProject = true){
  if(!secState.project || CC.currentView !== "security") return;
  try{
    secState.analyses = await secFetch("/api/security?project="
      + encodeURIComponent(secState.project));
  }catch(e){ secStopPoll(); return; }
  // Left the project screen, or the view entirely, while the fetch was out. The
  // interval is cleared here as well as in secLeave(), because THIS is the call
  // that would otherwise re-arm it on the way out.
  if(!secState.project || CC.currentView !== "security"){ secStopPoll(); return; }
  const mine = secState.analyses.filter(a => a.repo === secState.repo
                                          && a.branch === secState.branch);
  // Follow the newest analysis of the branch on screen: one just started is the
  // one worth watching, not the one that was being read a moment ago.
  //
  // UNLESS somebody deliberately opened a particular one (a Runs row, an "#N"
  // in the history, the Activity screen's deep link). That analysis is what
  // the reader asked for, and replacing it with the branch's newest -- which
  // this did unconditionally, on every 4-second tick -- meant a deep-linked
  // run vanished within four seconds of being opened. It is still re-fetched
  // here, by its own id, so a pinned RUNNING analysis keeps updating.
  const pinnedId = (secState.pinned && secState.analysis) ? secState.analysis.id : null;
  const want = pinnedId != null ? pinnedId
             : (mine.length ? mine[0].id : (secState.analysis && secState.analysis.id));
  await secShowAnalysis(want == null ? null : want, secState.pinned);
  secSyncPoll();
  // The same poll tick (and the same post-Analyse reload) that refreshes the
  // old detail pane above also keeps the header/tabs/sidebar in step --
  // one timer driving both, rather than a second interval hitting the
  // server on its own for numbers this same reload already has fresh.
  //
  // BUT the root fix for the cost this used to have (see cmd_project_data's
  // own docstring) does not, by itself, stop a live run's poll tick from
  // re-fetching the whole payload every four seconds for nothing: while
  // every analysis of this project stays `running`, the header/tabs/sidebar
  // cannot have changed -- Overview and the sidebar both describe the
  // latest FINISHED analysis, which is not the one still in flight, and the
  // Runs tab's own findings counts are frozen for any row that already
  // closed. The only thing a poll tick can ever learn that the LAST poll
  // tick did not is that a run finished -- so a tick that sees the same
  // running/not-running shape as last time skips this fetch, and only a
  // forced caller (opening the project, or right after an action that
  // really did just change something -- a new analysis started, a decision
  // recorded) still gets it unconditionally.
  const runningNow = secState.analyses.some(a => a.state === "running");
  const changed = runningNow !== secProjectPollWasRunning;
  secProjectPollWasRunning = runningNow;
  if(forceProject || changed) secRefreshProject();
}

export function secStatus(text){
  const box = $("sec-status");
  box.textContent = "";
  box.appendChild(secEl("span", null, text));
  // `.secstat`'s own background/border/radius/padding (pages.css) render
  // regardless of content -- an author `display:flex` on that class
  // outranks the UA's own `[hidden]{display:none}`, the exact trap
  // `.secfield`/`.secdl`/`.warnline` are already told to ignore -- so this
  // box must be explicitly UNhidden every time it has something to say, not
  // just cleared. secPaint (below) is the one place that hides it again,
  // the moment an analysis is on screen and this message is not needed.
  box.hidden = false;
}

/* The mockup's own meta grid under the Run #N head -- Profile (a pill),
   Branch, Commit (short sha, mono), Duration, Date, and (Runs tab parity
   pass 2) Cost as a sixth labelled cell alongside them. The mockup's own
   sample run has no spend recorded, so its five-cell grid never had to draw
   a sixth -- that is the mockup's data being incomplete, not an instruction
   to drop a figure this screen has always shown (nothing in this task's own
   file list asked for it to disappear); it used to ride along instead as an
   unlabelled trailing line below the whole grid, which on screen read as
   dangling text under whichever cell happened to sit at the same left edge
   (Profile, the grid's first cell). Housed here, in the grid proper, with
   the same "—" a run before this field existed already shows for Commit/
   Duration, rather than a trailing line at all. */
function secRenderRunMeta(a){
  const host = $("sec-run-meta");
  host.textContent = "";
  const grid = secEl("div", "secrun-metagrid");
  const cell = (label, valueNode, extraCls) => {
    const c = secEl("div", "secrun-metacell");
    c.appendChild(secEl("div", "secrun-metalabel", label));
    const v = secEl("div", "secrun-metaval" + (extraCls ? " " + extraCls : ""));
    v.appendChild(valueNode);
    c.appendChild(v);
    return c;
  };
  const running = a.state === "running";
  grid.appendChild(cell("Profile", secEl("span", "pill profile", a.profile || "—")));
  grid.appendChild(cell("Branch", document.createTextNode(a.branch || "—")));
  grid.appendChild(cell("Commit",
    document.createTextNode(String(a.commit_sha || "").slice(0, 12) || "—"), "mono"));
  grid.appendChild(cell("Duration", document.createTextNode(
    a.ended && a.started ? fmtDur(Math.max(0, a.ended - a.started))
                          : (running ? "running…" : "—"))));
  grid.appendChild(cell("Date", document.createTextNode(fmtWhen(a.started))));
  grid.appendChild(cell("Cost", document.createTextNode(
    a.spend_usd ? money(a.spend_usd) : "—")));
  host.appendChild(grid);
}

/* The three transient messages secPaint's old #sec-status line used to
   append inline, unchanged in wording and in the facts that decide which
   (if any) shows: the running-analysis reassurance, and the "running in the
   ledger but no live slot" disagreement's own two readings (dead without a
   journal past the 180s launch window, or still in the pre-agent worktree-
   cutting window before that). The "Open the run" button that used to sit
   beside them is now the Run head's own eye icon (secRenderRunHead,
   project-screen.js) -- the same secRunFor/openLog call, not a second one. */
function secRenderRunNotice(a){
  const host = $("sec-run-notice");
  host.textContent = "";
  const running = a.state === "running";
  if(running){
    host.appendChild(secEl("div", "secrun-notice",
      "Secrets, dependencies and CVEs are written moments after the agent starts — "
      + "they are its first command — so what is below is already real while the "
      + "code review keeps going."));
  }
  const run = secRunFor(a);
  // `running` in the ledger is a claim; a live slot is the fact. When the two
  // disagree for longer than a launch could take, say so — a run killed
  // without a journal (a reboot, a group-kill) leaves exactly this state, and
  // the page used to show "Analysing…" over it indefinitely.
  if(running && !run){
    if((Date.now()/1000 - (a.started||0)) > 180){
      host.appendChild(secEl("div", "secrun-notice warn",
        "No live run is behind this analysis — it likely died without closing. "
        + "The next Analyse sweeps it; until then downloads carry what it recorded."));
    }else{
      // The pre-agent window: the engine is cutting a worktree from a fresh
      // fetch of the branch, which on a big repository is most of the wait.
      // The run trace exists once the agent starts; until then, name the
      // phase instead of showing a button-less void.
      host.appendChild(secEl("div", "secrun-notice",
        "Preparing the run — fetching the branch and cutting a clean worktree. "
        + "The live trace appears here the moment the agent starts."));
    }
  }
}

/* THE COVERAGE, COMPACT -- one line per phase, above the paragraph.

   `coverage_note` is one string built by concatenating 27 `*_NOTE` constants
   across six server modules (bin/security/cli.py, cmd_prepare). On a real
   analysis it is around two thousand characters. Every sentence in it was
   written because its absence had cost something, and every one of them is
   true; read as one block, in the alert box below this one, they were
   unreadable -- the operator who built this system read a real one and asked
   "what IS this alert?".

   So the same sentences arrive here attributed to the phase that produced
   them (bin/security/coverage.py), and this draws the summary FIRST: name,
   status, and the producer that answered. The prose is folded underneath each
   phase, one <details> at a time, for the reader who then asks why.

   NOTHING IS INVENTED HERE. The status came off the server's own control
   flow, not off a sentence, and a phase with no note renders as a plain row
   rather than an empty disclosure that opens onto nothing. An analysis
   written before the `coverage` column existed carries no phases at all, and
   this hides itself: that screen is exactly what it was. */
const SEC_PHASE_STATUS = {
  ran: "ran",
  // "partly" and not "warning": the row is already coloured, and the word a
  // reader needs is what it means for the report -- something looked, but not
  // the whole of what this phase covers.
  warning: "partly",
  skipped: "skipped",
};

export function secRenderCoveragePhases(a){
  const host = $("sec-phases");
  host.textContent = "";
  let phases = [];
  try{
    // The column is a JSON string on the analysis row. Parsed HERE and never
    // trusted to be anything: a screen is not the place to discover that a
    // column got corrupted, and the paragraph below is still true either way
    // -- the same rule the server's own `coverage.decode` follows.
    const doc = JSON.parse(a.coverage || "");
    if(doc && Array.isArray(doc.phases)) phases = doc.phases;
  }catch(e){ phases = []; }
  phases = phases.filter(p => p && p.name);
  if(!phases.length){ host.hidden = true; return; }
  host.hidden = false;
  const list = secEl("div", "secphases");
  for(const p of phases){
    const status = String(p.status || "");
    const label = SEC_PHASE_STATUS[status] || status;
    const by = p.by ? String(p.by) : "";
    const note = String(p.note || "").trim();
    // A row with something to say is a <details>; one without is a plain
    // <div> carrying the identical inner markup. Both paths build the same
    // pieces, so the two never drift into looking like different things --
    // and a phase with no note never renders a disclosure that opens onto
    // nothing.
    const row = document.createElement(note ? "details" : "div");
    // The status is also the class, so the dot and the row's own tint come
    // off one value. A status this screen has not been taught still renders
    // -- as its own raw word, under `unknown` -- rather than vanishing.
    row.className = "secphase secphase-"
      + (SEC_PHASE_STATUS[status] ? status : "unknown");
    const head = document.createElement(note ? "summary" : "div");
    head.className = "secphase-head";
    head.appendChild(secEl("span", "secphase-dot"));
    head.appendChild(secEl("span", "secphase-name", String(p.name)));
    head.appendChild(secEl("span", "secphase-status", label));
    // The producer, or nothing at all. An em dash on every skipped phase
    // would be a column of dashes a reader learns to skip -- the same call
    // the downloaded report's own `scope` line makes.
    if(by) head.appendChild(secEl("span", "secphase-by", by));
    row.appendChild(head);
    if(note) row.appendChild(secEl("div", "secphase-note", note));
    list.appendChild(row);
  }
  host.appendChild(list);
}

export function secPaint(){
  const a = secState.analysis;
  secPaintRunButton();
  // Here rather than only after pressing Analyse: arriving on a project whose
  // analysis somebody else started has to start watching it too, or the screen
  // sits on a running row that never moves.
  secSyncPoll();
  // #sec-status is now ONLY the "nothing selected yet" message (loading, no
  // branch picked, never analysed on this branch) -- the structured Run #N
  // head/meta grid/notices below all get their OWN hosts, built only when
  // an analysis actually exists, so this box takes no visual space once one
  // does. `hidden`, not just cleared: `.secstat`'s own border/radius/padding
  // (pages.css) paint regardless of content, so an empty-but-visible box
  // rendered above Run #N on every one of the mockup's own states (an
  // analysis is always on screen there) until this box started hiding
  // itself the moment it has nothing to say, same as `.secfield`/`.secdl`/
  // `.warnline` already do.
  const box = $("sec-status");
  box.hidden = true;
  box.textContent = "";
  // secRefreshRunPanels (project-screen.js: the Runs table's own selection
  // highlight, the Run head, the "Findings recorded" strip and the right
  // rail) and secRenderRunMeta/secRenderRunNotice (below) all clear their
  // own host first and return early on `!a` -- called unconditionally here
  // so a branch switched away from a loaded analysis back to an empty one
  // clears every one of them, not just the two this function still owns
  // directly.
  secRefreshRunPanels();
  if(!a){
    box.hidden = false;
    box.appendChild(secEl("span", null,
      secState.branch ? SEC_NEVER.branch : SEC_NEVER.pickBranch));
    $("sec-run-meta").textContent = "";
    $("sec-run-notice").textContent = "";
    $("sec-incomplete").hidden = true;
    $("sec-phases").textContent = "";
    $("sec-phases").hidden = true;
    $("sec-coverage").hidden = true;
    $("sec-summary").textContent = "";
    $("sec-checklist").textContent = "";
    $("sec-dl").hidden = true;
    $("sec-findings").textContent = "";
    secRenderHistory();
    return;
  }
  secRenderRunMeta(a);
  secRenderRunNotice(a);

  // THE SAME NOTICE THE DOWNLOADED REPORT OPENS WITH (bin/security/report.py,
  // _coverage). A capped or failed analysis is a PARTIAL read of the
  // repository, and the numbers under it are the numbers of a partial read:
  // "critical: 0" there means "none found before it stopped", not "none". The
  // file said so and the page did not, so the screen everybody actually looks
  // at was the one place that presented a truncated analysis as a finished
  // one.
  const inc = $("sec-incomplete");
  inc.textContent = "";
  const incomplete = a.state === "capped" ? "This analysis is INCOMPLETE: it stopped before covering the whole scope."
                   : a.state === "failed" ? "This analysis is INCOMPLETE: it did not finish."
                   : "";
  if(incomplete){
    inc.appendChild(secIcon("alert"));
    inc.appendChild(secEl("span", "grow", incomplete
      + " What is below is what it had reached, not what is there."));
    inc.hidden = false;
  }else inc.hidden = true;

  // ABOVE the paragraph, and the reason is the paragraph. See
  // secRenderCoveragePhases.
  secRenderCoveragePhases(a);

  const note = $("sec-coverage");
  note.textContent = "";
  if((a.coverage_note || "").trim()){
    note.appendChild(secIcon("alert"));
    note.appendChild(secEl("span", "grow", a.coverage_note));
    note.hidden = false;
  }else note.hidden = true;

  secRenderSummary();
  secRenderChecklist();
  $("sec-dl").hidden = false;
  secRenderFindings();
  secRenderHistory();
}

export function secPaintRunButton(){
  const btn = $("sec-run");
  // A project analyses one branch at a time: the derived job carries
  // max_parallel 1, and `security analyze` refuses a second one outright. The
  // button says so before it is pressed rather than after — and if one starts
  // between the repaint and the click, the refusal the server sends back is
  // what gets shown, because that message is the one that is actually true.
  const running = secState.analyses.some(a => a.state === "running");
  btn.disabled = running;
  btn.title = running
    ? "An analysis of this project is already running — one at a time."
    : "Analyse the selected branch";
  btn.textContent = running ? "Analysing…" : "Analyse";
}

// The five category values a finding can carry -- duplicated from the
// server's own closed set (secrets.py/hygiene.py/osv.py/adapters.py's
// `trivy_misconfigs`, plus the open "sast" vocabulary -- see vocabulary.js's
// own SEC_RULE_META comment for why those five and no more), the same
// duplication findings-screen.js's own FIND_CATEGORIES already carries
// against the server: the Category picker has to draw its options before any
// request (there is no request here at all -- this list floors what
// secState.findings already holds) has ever answered.
const SEC_FIND_CATEGORIES = ["secret", "dependency", "sast", "hygiene", "iac"];

// This run's own search text and category pick -- module state beside
// secState.stateFilter for the identical reason: secOpen() resets all
// three on a fresh project (or a different one), and nothing else may --
// least of all secPaint's own 4-second poll repaint, which must find a
// reader's half-typed search exactly where they left it.
let secFindSearch = "";
let secFindCategory = "";
let secFindCatPicker = null;
let secFindBadge = null;

/* What the search box, the Category picker AND the checklist chips all
   narrow further -- the SAME severity-floored list secRenderSummary's own
   footnote counts against secState.findings, never the raw checklist: a
   search or category pick tightens the list the floor already produced, it
   does not open a second, wider one that could surface a row the floor is
   hiding. */
function secFindVisible(){
  return secVisible(secState.findings, secMinSeverity(secState.project));
}

/* Search + Category + Filters -- STATIC markup (bin/dashboard.html's own
   #sec-find-bar, the identical "static markup, dynamic behaviour" shape
   sec-repo-combo/sec-branch-combo above it and the Activity screen's own
   sec-act-projpick already use), wired ONCE here, at boot, like
   secInitLaunchCombos below -- never rebuilt by secPaint's own 4-second
   poll repaint or by a project switch, the way the checklist chips and the
   finding cards both already ARE on every one of secPaint's calls.
   Rebuilding the search <input> on a timer or a fresh secOpen would drop
   whatever a reader had half-typed, and the caret with it -- the exact bug
   class secSyncPoll's own view guard and secShowAnalysis's own pin exist to
   keep out of this screen's OTHER moving parts. secResetFindBar (below) is
   the per-project-open half: it only ever RESETS the value/selection, never
   touches the DOM.

   "Filters" is the old always-visible checklist chip row (SEC_STATES,
   secRenderChecklist below, untouched) collapsed behind a button: the
   mockup draws Search/Category/Filters as one bar with nothing else beside
   it, so the eight-chip row that used to sit in the open here now sits
   inside this popover instead -- same id, same function, same counts, only
   its container and default visibility changed. */
export function secInitFindBar(){
  // The magnifying-glass icon every other .searchbox on this bundle already
  // carries (secProjectsFilterBar's own, index-screen.js) -- markup cannot
  // call secIcon() itself, so it is inserted here, once, ahead of the
  // static <input> rather than left out for this one search box alone.
  $("sec-find-search-box").insertBefore(secIcon("search"), $("sec-find-search"));
  const input = $("sec-find-search");
  input.setAttribute("aria-label", "Search findings in this run");
  input.oninput = () => { secFindSearch = input.value; secRenderFindings(); };

  const fTrigger = $("sec-run-filterpick-trigger");
  fTrigger.appendChild(secIcon("filter"));
  fTrigger.appendChild(document.createTextNode("Filters"));
  secFindBadge = secEl("span", "secfind-filters-badge", "1");
  secFindBadge.hidden = true;
  fTrigger.appendChild(secFindBadge);
  fTrigger.appendChild(secIcon("cdown"));
  // Found live by secIndexProjectRow's own kebab first (see its comment):
  // without this, closeMenus() (reached from document's own click listener)
  // re-hides this popover the instant the browser's default action opens
  // it, on the very click that was supposed to open it.
  fTrigger.onclick = (e) => e.stopPropagation();
  const filters = $("sec-run-filterpick");
  const fPop = $("sec-run-filterpop");
  // Resynced from `filters.open` on every toggle, and recomputed to
  // `position:fixed` off the trigger's own screen position -- the identical
  // fix secIndexProjectRow's own kebab and secFindingsPeriodPicker's own
  // popover both already need against a `.table-card{overflow:hidden}`
  // ancestor; `.card` (this popover's own ancestor here) is not that class,
  // but the fix is cheap and the alternative -- a popover that silently
  // clips or mispositions the one time a caller nests this bar somewhere
  // narrower -- is not something to find out live a second time.
  filters.ontoggle = () => {
    fPop.hidden = !filters.open;
    if(!filters.open) return;
    const r = fTrigger.getBoundingClientRect();
    fPop.style.position = "fixed";
    fPop.style.top = (r.bottom + 6) + "px";
    fPop.style.right = (window.innerWidth - r.right) + "px";
    fPop.style.left = "auto";
    fPop.style.bottom = "auto";
  };

  secFindCatPicker = makePicker("sec-find-catpick", {
    icon: secIconHTML("filter"), label: "Category",
    valueLabel: () => secFindCategory ? secCategoryMeta(secFindCategory).label : "All",
    rows: () => {
      const visible = secFindVisible();
      const counts = {};
      visible.forEach(f => { counts[f.category] = (counts[f.category] || 0) + 1; });
      const rows = [{v: "", label: "All", n: visible.length,
        sel: secFindCategory === "", icon: secIconHTML("layers")}];
      SEC_FIND_CATEGORIES.forEach(cat => {
        const meta = secCategoryMeta(cat);
        rows.push({v: cat, label: meta.label, n: counts[cat] || 0,
          sel: secFindCategory === cat, icon: secIconHTML(meta.icon)});
      });
      return rows;
    },
    onPick: (v) => { secFindCategory = v; secRenderFindings(); },
  });
}

// Called from secOpen(), every time a project opens (a fresh one, or a
// reader coming back to one already open): resets the search text and the
// category pick the same way secOpen already resets secState.stateFilter,
// without touching the DOM the way a full rebuild would have.
function secResetFindBar(){
  secFindSearch = ""; secFindCategory = "";
  const input = $("sec-find-search");
  if(input) input.value = "";
  if(secFindCatPicker) secFindCatPicker.paint();
}

/* The open-posture pills this used to draw ("3 critical, 1 high...") moved
   to the right rail's own donut (secProjectRunPosture, project-screen.js) --
   the mockup's "Findings by severity" card is that exact same computation
   (secPosture over this same secState.findings), read once by the module
   that already owns the rail rather than duplicated here to feed a second
   pill row the mockup does not draw. What is left here, and the one thing
   secPosture's own donut cannot say for itself, is the severity floor's own
   footnote: how many recorded findings the floor is keeping OFF the list
   below (SEC_FLOOR_SCOPE_NOTE) -- a fact about the LIST, not the posture,
   and the donut is explicitly the unfloored reading (see that function's
   own comment). */
function secRenderSummary(){
  const host = $("sec-summary");
  host.textContent = "";
  const shown = secVisible(secState.findings, secMinSeverity(secState.project));
  const hidden = secState.findings.length - shown.length;
  if(hidden > 0){
    host.appendChild(document.createTextNode(hidden + " finding" + (hidden === 1 ? "" : "s")
      + " below " + secMinSeverity(secState.project) + " — recorded, not shown"));
  }
}

function secRenderChecklist(){
  const host = $("sec-checklist");
  host.textContent = "";
  const shown = secVisible(secState.findings, secMinSeverity(secState.project));
  SEC_STATES.forEach(state => {
    const n = shown.filter(f => f.state === state).length;
    const chip = secEl("button", "secchip" + (n ? "" : " zero")
      + (secState.stateFilter === state ? " on" : ""));
    chip.type = "button";
    chip.title = SEC_STATE_HELP[state] || "";
    chip.appendChild(secEl("span", null, SEC_STATE_LABEL[state]));
    chip.appendChild(secEl("span", "n", String(n)));
    chip.onclick = () => {
      secState.stateFilter = (secState.stateFilter === state) ? "" : state;
      secRenderChecklist(); secRenderFindings();
    };
    host.appendChild(chip);
  });
  // The Filters button's own count badge -- one active state filter is the
  // only thing this popover can hold today, so it is always 0 or 1, never a
  // real count to add up.
  if(secFindBadge) secFindBadge.hidden = !secState.stateFilter;
}

/* Search text against a finding's own title and its occurrences' file
   paths -- a rationale search would also match half the OTHER findings on
   the same run, since remediation prose reuses the same handful of nouns
   (auth, token, query) across unrelated rows; title and location are what a
   reader scanning "does this run already know about X" is actually typing.
   Plain substring, case-insensitive, against text/attribute strings only --
   never markup, the same discipline every other read of a finding's own
   fields keeps in this area (see this file's own vocabulary.js banner). */
function secFindMatchesSearch(f, q){
  if(!q) return true;
  const needle = q.trim().toLowerCase();
  if(!needle) return true;
  if(String(f.title || "").toLowerCase().includes(needle)) return true;
  return (f.occurrences || []).some(o => String(o.file || "").toLowerCase().includes(needle));
}

function secRenderFindings(){
  const host = $("sec-findings");
  host.textContent = "";
  let list = secVisible(secState.findings, secMinSeverity(secState.project));
  if(secState.stateFilter) list = list.filter(f => f.state === secState.stateFilter);
  if(secFindCategory) list = list.filter(f => f.category === secFindCategory);
  if(secFindSearch.trim()) list = list.filter(f => secFindMatchesSearch(f, secFindSearch));
  // Worst first, and inside a severity the ones nobody has judged yet.
  const stateRank = (f) => SEC_STATES.indexOf(f.state);
  list = list.slice().sort((x, y) => (secSevRank(y.severity) - secSevRank(x.severity))
                                  || (stateRank(x) - stateRank(y))
                                  || String(x.title).localeCompare(String(y.title)));
  if(!list.length){
    const e = secEl("div", "empty", (secState.stateFilter || secFindCategory || secFindSearch.trim())
      ? "Nothing matches these filters." : "This analysis reported nothing to show.");
    host.appendChild(e);
  }else{
    list.forEach(f => host.appendChild(secFindingRow(f)));
  }
  // The Category picker's own counts are a function of secState.findings,
  // which just changed (a new analysis, a decision, a poll tick) -- painted
  // here rather than a second call at every one of secRenderFindings' own
  // callers, the same "repaint on every render" rule secRepaintProjectsTable
  // already follows for its own three pickers.
  if(secFindCatPicker) secFindCatPicker.paint();
}

function secFindingRow(f){
  // Titles and paths come out of analysed code. textContent, always: handing
  // any of it to the HTML parser here would let a repository script this
  // dashboard.
  const row = document.createElement("div");
  row.className = "secfinding sev-" + secSevKey(f) + " state-" + secStateKey(f);
  const h = document.createElement("h4");
  const title = document.createElement("span");
  title.className = "sectitle";
  title.textContent = "[" + f.severity + "] " + f.title;
  h.appendChild(title);
  const st = document.createElement("span");
  st.className = "secstate " + secStateKey(f);
  st.title = SEC_STATE_HELP[f.state] || "";
  st.textContent = SEC_STATE_LABEL[f.state] || f.state;
  h.appendChild(st);
  row.appendChild(h);
  const where = document.createElement("ul");
  where.className = "secwhere";
  (f.occurrences || []).forEach(o => {
    const li = document.createElement("li");
    li.textContent = o.line ? o.file + ":" + o.line : o.file;
    where.appendChild(li);
  });
  if(where.childNodes.length) row.appendChild(where);
  if((f.rationale || "").trim()) row.appendChild(secEl("p", "secwhy", f.rationale));
  if((f.remediation || "").trim()) row.appendChild(secEl("p", "secfix", "Remediation: " + f.remediation));
  if((f.partial_note || "").trim()) row.appendChild(secEl("p", "secwhy", "Partial: " + f.partial_note));
  if((f.decision_reason || "").trim()){
    row.appendChild(secEl("p", "secwhy", SEC_STATE_LABEL[f.state] + " — " + f.decision_reason));
  }
  // A mono code-snippet block, when the finding carries one -- the mockup's
  // own "sql: $sql->where(...)" line under a SAST finding's rationale.
  // Nothing in today's pipeline ever populates `f.snippet`: `occurrence`
  // stores only a `snippet_hash` (see bin/security/ledger.py's own schema
  // comment, and cmd_report_finding's -- storing the raw line back out
  // would be the exact secret-in-the-open this area's own report-finding
  // op was written to avoid for a secrets finding, and there is no
  // per-category exception for a SAST one today). This still renders
  // whatever the field holds, guarded exactly like remediation/partial_note
  // above, so a future finding that DOES carry one displays correctly on
  // day one rather than needing a second change here -- it is simply dark
  // with every finding this build has ever seen. textContent only, as
  // always: a snippet is analysed code, not markup.
  if((f.snippet || "").trim()){
    const box = secEl("div", "secsnippet");
    if((f.snippet_lang || "").trim()) box.appendChild(secEl("span", "secsnippet-lang", f.snippet_lang + ":"));
    box.appendChild(secEl("code", null, f.snippet));
    row.appendChild(box);
  }
  row.appendChild(secEl("div", "secfp", (f.category || "") + " · " + (f.rule || "")
    + " · " + (f.fingerprint || "")));
  // A fixed finding is gone: there is nothing left to accept or dismiss.
  if(f.state !== "fixed") row.appendChild(secDecisionControls(f));
  return row;
}

function secDecisionControls(f){
  const wrap = document.createElement("div");
  wrap.className = "secactions";
  [["accepted","Accept risk"],["false_positive","False positive"]].forEach(
    ([state, label]) => {
      const b = document.createElement("button");
      b.className = "btn";
      b.type = "button";
      b.textContent = label;
      b.onclick = () => secDecide(f, state, label);
      wrap.appendChild(b);
    });
  return wrap;
}

async function secDecide(f, state, label){
  // Required, not optional: this decision outlives every future analysis, and
  // without a reason it is unreadable in three months. The API refuses a blank
  // one with a 400 of its own — asked here so that refusal is never the way
  // somebody discovers the rule.
  const reason = await secAskReason(label, f.title);
  if(reason === null) return;
  const ok = await api("security_decide", {project: secState.project,
              fingerprint: f.fingerprint, state, reason});
  if(!ok) return;          // api() has already shown the server's own message
  toast(label + " recorded", false, "check");
  await secReload();
}
