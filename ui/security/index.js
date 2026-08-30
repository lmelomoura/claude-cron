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
import { bindPage, $, iconLabel, CC } from "./page.js";
import { SEC_PROFILES, SEV_ORDER } from "./vocabulary.js";
import { secState } from "./state.js";
import { secRenderIndex, secLoadIndex } from "./index-screen.js";
import { secBack, secEnter, secLeave, secSyncScope, secInitLaunchCombos } from "./analysis.js";
import { secAnalyse, secDownload } from "./actions.js";
import { wireReasonDialog } from "./reason.js";
import { secSwitchProjectTab } from "./project-screen.js";
import { secOpenActivity, secBackFromActivity, secActReload, secActSwitchTab,
         secActInitProjectPicker, secIsActivityOpen, wireActivityFindingDialog } from "./activity-screen.js";

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
  $("sec-act-back").addEventListener("click", secBackFromActivity);
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
  $("sec-back").addEventListener("click", secBack);
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
  // `change`, not `input`: a fetch per keystroke would be a subprocess per
  // keystroke on the server.
  $("sec-branch-other").addEventListener("change", () => secSyncScope());
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
  SEV_ORDER,
  SEC_PROFILES,
};
