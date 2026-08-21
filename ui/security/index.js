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
import { secBack, secEnter, secLeave, secLoadBranches, secSyncScope } from "./analysis.js";
import { secAnalyse, secDownload } from "./actions.js";
import { wireReasonDialog } from "./reason.js";
import { secSwitchProjectTab } from "./project-screen.js";
import { secOpenActivity, secBackFromActivity, secActReload, secActSwitchTab,
         secActProjectChanged, secIsActivityOpen, wireActivityFindingDialog } from "./activity-screen.js";

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
  iconLabel($("sec-reload"), "radar", "Refresh");
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

  // The Activity screen: entry point from the index, its own back/reload,
  // its four kind tabs, its free-text project scope, and the fingerprint
  // dialog a decision's own row opens. See ui/security/activity-screen.js.
  iconLabel($("sec-view-activity"), "activity", "Activity");
  iconLabel($("sec-act-back"), "cleft", "All projects");
  iconLabel($("sec-act-reload"), "radar", "Refresh");
  iconLabel($("secactt-all"), "activity", "All activity");
  iconLabel($("secactt-analyses"), "shield", "Analyses");
  iconLabel($("secactt-findings"), "search", "Findings");
  iconLabel($("secactt-settings"), "gear", "Settings");
  $("sec-view-activity").addEventListener("click", () => secOpenActivity(""));
  $("sec-act-back").addEventListener("click", secBackFromActivity);
  $("sec-act-reload").addEventListener("click", secActReload);
  $("secactt-all").addEventListener("click", () => secActSwitchTab(""));
  $("secactt-analyses").addEventListener("click", () => secActSwitchTab("analyses"));
  $("secactt-findings").addEventListener("click", () => secActSwitchTab("findings"));
  $("secactt-settings").addEventListener("click", () => secActSwitchTab("settings"));
  // `change`, not `input`: a fetch per keystroke would be a subprocess per
  // keystroke on the server, the same reasoning `#sec-branch-other` below
  // already follows.
  $("sec-act-project").addEventListener("change", () =>
    secActProjectChanged($("sec-act-project").value));
  wireActivityFindingDialog();
  // The list above this row is filtered by the project's min_severity; these
  // files are not. Said here, next to the buttons, because the gap between what
  // is on screen and what is in the file you hand to somebody else is exactly
  // where a reader assumes they match.
  $("sec-dl-note").textContent = "Downloads always contain every recorded finding, whatever the severity floor shows.";
  $("sec-back").addEventListener("click", secBack);
  $("sec-reload").addEventListener("click", () => { secLoadIndex(true); });
  $("sec-run").addEventListener("click", secAnalyse);
  $("sec-dl-md").addEventListener("click", () => secDownload("md"));
  $("sec-dl-json").addEventListener("click", () => secDownload("json"));
  $("sec-dl-html").addEventListener("click", () => secDownload("html"));
  $("sec-dl-sbom").addEventListener("click", () => secDownload("sbom"));
  $("sec-repo").addEventListener("change", async () => {
    await secLoadBranches("");
    $("sec-branch-other").value = "";
    secSyncScope();
  });
  // Choosing from the list is a decision; the typed field would otherwise keep
  // overruling it from off screen.
  $("sec-branch").addEventListener("change", () => {
    $("sec-branch-other").value = "";
    secSyncScope();
  });
  // `change`, not `input`: a fetch per keystroke would be a subprocess per
  // keystroke on the server.
  $("sec-branch-other").addEventListener("change", () => secSyncScope());
}

/* The page calls init() once and then only these. SEV_ORDER and SEC_PROFILES
   are read by the PROJECT EDITOR, which stayed in the page: it validates its
   two dropdowns against the same vocabulary the area works in, and the
   vocabulary belongs with the area that defines what the words mean. */
window.CCSecurity = {
  init,
  render: renderSecurity,
  enter: secEnter,
  leave: secLeave,
  SEV_ORDER,
  SEC_PROFILES,
};
