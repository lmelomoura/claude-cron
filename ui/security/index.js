/* ================================================================ security

   The Security area. It used to be ~870 lines in the middle of dashboard.html's
   single <script>; it is now these modules, bundled by build/build-ui.sh into
   bin/static/security.js and served by the page as /static/security.js.

   HOW IT IS LOADED, and why that order is not negotiable: the tag sits BEFORE
   the page's own <script>, so this bundle is evaluated first and only DEFINES
   things — no DOM is touched, nothing is read off the page. The page's script
   then runs exactly as it always did, and at the point where this area's code
   used to begin it builds one interface object and calls CCSecurity.init(it).
   Every statement therefore still executes in the same order it did when this
   was one file.

   Loading it AFTER the page's script — the obvious arrangement — does not work
   and fails loudly: initViews() calls setView() while the page's script is
   still running, and setView() calls both render() and enter()/leave(). Those
   are this area's, so they must already exist by then.

   What the page hands in is listed in page.js. What it gets back is the object
   below: this is the whole surface between the two. */
import { bindPage, $, iconLabel, CC, projById } from "./page.js";
import { SEC_PROFILES, SEV_ORDER } from "./vocabulary.js";
import { secState } from "./state.js";
import { secRenderIndex, secLoadIndex } from "./index-screen.js";
import { secBack, secEnter, secLeave, secSyncScope, secInitLaunchCombos, secInitFindBar,
         wireLaunchDialog } from "./analysis.js";
import { secAnalyse, secDownload } from "./actions.js";
import { wireReasonDialog } from "./reason.js";
import { secSwitchProjectTab, secOpenProject, secCurrentProjectTab } from "./project-screen.js";
import { secOpenActivity, secBackFromActivity, secActReload, secActSwitchTab,
         secActInitProjectPicker, secIsActivityOpen, secActNavState,
         wireActivityFindingDialog } from "./activity-screen.js";

function renderSecurity(){
  if(CC.currentView !== "security") return;
  if(secIsActivityOpen()) return;   // the Activity screen paints from its own fetch
  if(secState.project) return;   // the project screen paints from its own fetches
  secRenderIndex();
  secLoadIndex(false);           // a no-op once the index has already answered once
}

/* ---------------------------------------------------------------- wiring */
function init(cc){
  bindPage(cc);
  wireReasonDialog();
  iconLabel($("sr-halo"), "shield");
  // <dialog id="seclaunch">'s own halo -- static, unlike sec-act-finding's
  // (activity-screen.js), which is re-set on every open because ITS icon
  // depends on what it is showing; this dialog always means the same thing.
  iconLabel($("seclaunch-halo"), "activity");
  // The breadcrumb's own static first crumb (bin/dashboard.html's own
  // #sec-crumbs) -- plain text and its own click, wired once like every
  // other fixed label/listener in this function; #sec-title beside it is
  // the CURRENT segment, which stays analysis.js's own to set (secOpen),
  // since it already knows which project is open the moment it opens one.
  // Wrapped, not passed bare, for the identical reason #sec-back is a few
  // lines below: secBack takes its own `fromHistory` parameter.
  $("sec-crumb-security").textContent = "Security";
  $("sec-crumb-security").addEventListener("click", () => secBack());
  iconLabel($("sec-back"), "cleft", "All projects");
  iconLabel($("sec-dl-md"), "file", "Markdown");
  iconLabel($("sec-dl-json"), "file", "JSON");
  iconLabel($("sec-dl-html"), "file", "HTML");
  iconLabel($("sec-dl-sbom"), "file", "SBOM");
  iconLabel($("secpjt-overview"), "grid", "Overview");
  iconLabel($("secpjt-runs"), "activity", "Runs");
  iconLabel($("secpjt-branches"), "layers", "Branches");
  iconLabel($("secpjt-findings"), "search", "Findings");
  iconLabel($("secpjt-reports"), "file", "Reports");
  $("secpjt-overview").addEventListener("click", () => secSwitchProjectTab("overview"));
  $("secpjt-runs").addEventListener("click", () => secSwitchProjectTab("runs"));
  $("secpjt-branches").addEventListener("click", () => secSwitchProjectTab("branches"));
  $("secpjt-findings").addEventListener("click", () => secSwitchProjectTab("findings"));
  $("secpjt-reports").addEventListener("click", () => secSwitchProjectTab("reports"));

  // The Activity screen: its own back/reload, its four kind tabs, its
  // PROJECT picker, and the fingerprint dialog a decision's own row opens.
  // See ui/security/activity-screen.js. The entry point used to be here too
  // (#sec-reload, iconLabel'd and wired the same direct way as every id
  // below) -- it is now one of the index header's own actions, built fresh
  // on every repaint by ui/security/index-screen.js's own secRenderHead()
  // (pageHeader() draws its icon and label from the actions array, so a
  // separate iconLabel() call here would fight it), and answered by
  // bin/dashboard.html's central delegated click listener through
  // CCSecurity.openActivity() below, the same "rebuilt every poll, answered
  // by id centrally" split every other page's pageHeader() action already
  // uses. #sec-reload moved the same way, into CCSecurity.reload().
  iconLabel($("sec-act-back"), "cleft", "All projects");
  iconLabel($("sec-act-reload"), "radar", "Refresh");
  iconLabel($("secactt-all"), "activity", "All activity");
  iconLabel($("secactt-analyses"), "shield", "Analyses");
  iconLabel($("secactt-findings"), "search", "Findings");
  iconLabel($("secactt-settings"), "gear", "Settings");
  // Wrapped, not passed bare: secBackFromActivity/secBack (just below) now
  // take a `fromHistory` parameter (F4 history layer), and addEventListener
  // hands its listener the click's own Event object as the first argument --
  // passed bare, that Event would land IN `fromHistory` and read as truthy,
  // silently suppressing this button's own history push on every real click.
  $("sec-act-back").addEventListener("click", () => secBackFromActivity());
  $("sec-act-reload").addEventListener("click", secActReload);
  $("secactt-all").addEventListener("click", () => secActSwitchTab(""));
  $("secactt-analyses").addEventListener("click", () => secActSwitchTab("analyses"));
  $("secactt-findings").addEventListener("click", () => secActSwitchTab("findings"));
  $("secactt-settings").addEventListener("click", () => secActSwitchTab("settings"));
  // The house picker (F4 Activity polish), replacing the free-text
  // #sec-act-project <input> and its own `change` listener -- see
  // secActInitProjectPicker's own comment (activity-screen.js) for why this
  // is wired here, once, exactly like secInitLaunchCombos below.
  secActInitProjectPicker();
  wireActivityFindingDialog();
  // The list above this row is filtered by the project's min_severity; these
  // files are not. Said here, next to the buttons, because the gap between what
  // is on screen and what is in the file you hand to somebody else is exactly
  // where a reader assumes they match.
  $("sec-dl-note").textContent = "Downloads always contain every recorded finding, whatever the severity floor shows.";
  // Wrapped for the identical reason as sec-act-back above: secBack now
  // takes its own `fromHistory` parameter, and a bare reference here would
  // read the click's Event object as it.
  $("sec-back").addEventListener("click", () => secBack());
  $("sec-run").addEventListener("click", secAnalyse);
  $("sec-dl-md").addEventListener("click", () => secDownload("md"));
  $("sec-dl-json").addEventListener("click", () => secDownload("json"));
  $("sec-dl-html").addEventListener("click", () => secDownload("html"));
  $("sec-dl-sbom").addEventListener("click", () => secDownload("sbom"));
  // sec-repo/sec-branch are the house combo now (Phase 4 Task 5): a hidden
  // input's `.value` is never touched by a person, so a `change` listener
  // here would simply stop firing. secInitLaunchCombos (analysis.js) wires
  // the equivalent behaviour -- "pick a repo, reload its branches", "choosing
  // from the list overrules the typed field" -- as each combo's own onPick.
  secInitLaunchCombos();
  // <dialog id="seclaunch">'s own Cancel button (Runs tab parity pass 2) --
  // wired once, at boot, exactly like the launch combos just above it now
  // lives inside. Escape needs no listener of its own; see wireLaunchDialog's
  // own comment (analysis.js).
  wireLaunchDialog();
  // The Runs tab's own Search/Category/Filters bar (#sec-find-bar) -- wired
  // once, at boot, exactly like the launch combos just above; secOpen()
  // only ever resets it per project (secResetFindBar, analysis.js).
  secInitFindBar();
  // `change`, not `input`: a fetch per keystroke would be a subprocess per
  // keystroke on the server.
  $("sec-branch-other").addEventListener("change", () => secSyncScope());
}

/* ---------------------------------------------------------- history bridge
   bin/dashboard.html's router (see its own comment, beside setView) asks
   this area exactly two questions and never more: "where are you right now"
   (navState, read once a navigation elsewhere -- entering Security from the
   sidebar -- has settled, so the page can push it) and "go here" (navigate,
   called from a popstate handler restoring a previously-pushed entry, and
   once at boot for the deterministic "cold boot is always the index" case --
   see initViews's own comment in bin/dashboard.html).

   navigate() passes `true` (its own `fromHistory`) to everything it calls:
   none of this is a reader clicking, so none of it should push a second
   copy of the very entry it is restoring. It is idempotent by construction,
   never a second visible screen even if called twice running or right after
   a stale secEnter() guess: secOpenProject/secOpenActivity are skipped
   outright when already scoped to the right project (the fetch a fresh open
   would start is exactly the one already in flight or just answered), and
   secSwitchProjectTab/secActSwitchTab safely repaint the tab they are
   already on. */
function secNavState(){
  if(secIsActivityOpen()){
    const a = secActNavState();
    return {screen: "activity", project: a.project, tab: a.tab};
  }
  if(secState.project) return {screen: "project", project: secState.project, tab: secCurrentProjectTab()};
  return {screen: "index"};
}

async function secNavigate(sec){
  sec = sec || {};
  if(sec.screen === "project" && sec.project && projById(sec.project)){
    if(secIsActivityOpen()) secBackFromActivity(true);
    if(secState.project !== sec.project) await secOpenProject(sec.project, true);
    secSwitchProjectTab(sec.tab || "overview", true);
    return;
  }
  if(sec.screen === "activity"){
    const already = secIsActivityOpen() && secActNavState().project === (sec.project || "");
    if(!already) await secOpenActivity(sec.project || "", true);
    secActSwitchTab(sec.tab || "", true);
    return;
  }
  // Falls through here for screen:"index", an unrecognised screen, and a
  // project the fleet no longer lists (renamed, deleted since the entry was
  // pushed) -- all three have nowhere else to land.
  if(secIsActivityOpen()) secBackFromActivity(true); else secBack(true);
}

/* The page calls init() once and then only these. SEV_ORDER and SEC_PROFILES
   are read by the PROJECT EDITOR, which stayed in the page: it validates its
   two dropdowns against the same vocabulary the area works in, and the
   vocabulary belongs with the area that defines what the words mean.

   openActivity/reload (Phase 4 Task 1) are the index header's own two
   actions, answered by bin/dashboard.html's central delegated click
   listener (`#sec-reload`) rather than a listener
   ui/security/index-screen.js attaches itself -- see secRenderHead's own
   comment on why: pageHeader() rebuilds both buttons on every repaint, the
   same as every other page's own header actions, so a listener attached
   directly to either one would be torn away the moment the next repaint
   replaces it with a new element. Thin, zero-argument wrappers rather than
   exporting secOpenActivity/secLoadIndex themselves: the delegated call
   site wants "open the all-projects activity feed" and "refresh the index",
   not a project-scoped open or a soft (cache-permitting) refresh -- the two
   things secOpenActivity("") and secLoadIndex(true) actually mean here. */
window.CCSecurity = {
  init,
  render: renderSecurity,
  enter: secEnter,
  leave: secLeave,
  openActivity: () => secOpenActivity(""),
  reload: () => secLoadIndex(true),
  // navState/navigate (F4 history layer): the bridge bin/dashboard.html's
  // router uses the OTHER direction from every name above -- those answer a
  // click the page already routed here; these let the page ask this area
  // what to push, and tell it what to restore. See this file's own comment
  // above secNavState/secNavigate, and bin/dashboard.html's, beside setView.
  navState: secNavState,
  navigate: secNavigate,
  SEV_ORDER,
  SEC_PROFILES,
};
