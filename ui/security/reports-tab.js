/* ---------------------------------------------------------- the Reports tab
   ProjectReports.png, element by element: one "Reports" card holding the
   table -- Analysis (the run chip, a door to the Runs tab's drill-down),
   Profile with the run number beneath, Branch, Generated at (sortable),
   and the four FORMAT chips as the downloads themselves -- plus, through
   secReportsSidebar (mounted by project-screen.js's rail), the tab's own
   three rail cards: the all-branch severity donut and Top issue
   categories (shared with the Branches tab's rail, imported from
   branches-tab.js rather than copied) and the Reports summary card. The
   mockup's trailing ACTIONS column (a quick-download icon and a kebab of
   the same formats) is deliberately not drawn -- user call: the chips
   already ARE the downloads, and that column was the same four files
   behind a second door.

   One row per analysis, whatever its state -- but the downloads themselves
   only on a FINISHED one (done or capped). The mockup draws a failed row
   as "— / No report generated", and it is the better rule than the
   everything-gets-buttons this tab used to have: a report generated over a
   run that fell over (or has not finished) carries a partial checklist
   that READS as a complete one. The single-analysis pane on the Runs tab
   still offers its own downloads for whatever state is on screen, so
   nothing becomes unreachable -- this table just stops presenting a
   partial read as a finished document.

   Deliberately NOT drawn from the mockup, because the reports are
   GENERATED ON DEMAND from each analysis's own ledger records at the
   moment a download is clicked: a SIZE column and a "Total size" line
   (there is no file to weigh until the click), an "Export all" button
   (no aggregate artifact exists server-side), and "kept for 90 days"
   (nothing is kept or expires -- the ledger is the source and it stays).
   The summary card says the true version of that last one.

   Downloads go through fetch + Blob for the identical reason actions.js's
   secDownload already does: every GET on this API carries the X-AL-Token
   header, which a bare `<a href>` cannot attach. Both call actions.js's
   secDownloadReport, the shared fetch+Blob mechanism parameterised by an
   explicit analysis id, format and button element.

   The one fact this tab still says where the reader acts, in the README's
   own words: SBOM is not a report over any one analysis's checklist. It is
   the stored CycloneDX inventory itself, kept per (project, repo, branch)
   with only the LATEST document (ledger.py's `sbom` table) -- so the SBOM
   chip on an OLDER analysis's row still downloads that branch's CURRENT
   document. That caveat rides every SBOM control's own tooltip now, no
   longer a paragraph above the table. */
import { $, fmtAgo, fmtWhen, tableFooter } from "./page.js";
import { secEl, secIcon } from "./dom.js";
import { secDownloadReport } from "./actions.js";
import { secAllBranchDonutCard, secTopCategoriesCard } from "./branches-tab.js";
import { secShowAnalysis } from "./analysis.js";
import { secSwitchProjectTab } from "./project-screen.js";

const SEC_REPORT_FORMATS = [["md", "Markdown"], ["html", "HTML"],
                            ["json", "JSON"], ["sbom", "SBOM"]];

const SBOM_CAVEAT = "SBOM is not a report over this analysis's checklist: "
  + "it is the branch's stored CycloneDX inventory, kept with only the most "
  + "recent document — so this row downloads the branch's CURRENT document, "
  + "not a snapshot of what this analysis saw.";

const GENERATED_NOTE = "Reports are generated from each analysis's own "
  + "ledger records at the moment you download one — this is when the "
  + "analysis ran, which is what a report of it describes.";

// [key, label] tuples, SEC_PROJECT_COLS-shaped -- the width test's own
// parametrize covers this table like every other (`.secrp-table`,
// ui/css/pages.css). No Actions column, deliberately against the mockup
// (user call): the FORMAT chips ARE the downloads, and a quick-download +
// kebab beside them was the same four files behind a second door.
const SEC_REPORT_COLS = [
  ["analysis", "Analysis"], ["profile", "Profile"], ["branch", "Branch"],
  ["generated", "Generated at"], ["formats", "Format"],
];

// The Generated-at column's own sort -- client-side over the rows already
// in hand, the same shape the Runs table's Date sort keeps.
let secRpSortDir = "desc";

function secRpCap(s){
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
}

function secRpFinished(r){
  return r.state === "done" || r.state === "capped";
}

function secReportRow(r){
  const tr = document.createElement("tr");

  // The run chip is a door to the same drill-down every other "#N" on this
  // screen already opens: the Runs tab, with this analysis pinned.
  const tdId = document.createElement("td");
  const idBtn = document.createElement("button");
  idBtn.type = "button";
  idBtn.className = "btn ghost secrp-id";
  idBtn.textContent = "#" + r.analysis_id;
  idBtn.title = "Open this analysis on the Runs tab";
  idBtn.onclick = () => {
    secSwitchProjectTab("runs");
    secShowAnalysis(r.analysis_id, true);
  };
  tdId.appendChild(idBtn);
  tr.appendChild(tdId);

  // "Deep (Capped)" -- the profile with the state folded in the way the
  // mockup spells it, the run number beneath. A done run keeps the bare
  // profile; the pill vocabulary for the same states lives one tab over,
  // and repeating a coloured pill here would crowd a cell whose job is the
  // profile.
  const tdProfile = document.createElement("td");
  const suffix = r.state === "capped" ? " (Capped)"
    : r.state === "failed" ? " (Failed)"
    : r.state === "running" ? " (Running)" : "";
  tdProfile.appendChild(secEl("div", "secrp-profile",
    secRpCap(r.profile || "") + suffix));
  tdProfile.appendChild(secEl("div", "secmeta", "Run #" + r.analysis_id));
  tr.appendChild(tdProfile);

  const tdBranch = document.createElement("td");
  tdBranch.textContent = r.branch || "";
  tr.appendChild(tdBranch);

  const tdWhen = document.createElement("td");
  if(r.started){
    tdWhen.appendChild(secEl("div", "secrp-when", fmtWhen(r.started)));
    tdWhen.appendChild(secEl("div", "secmeta", fmtAgo(r.started)));
  }else{
    tdWhen.textContent = "—";
  }
  tr.appendChild(tdWhen);

  // The four formats ARE the downloads (the mockup's own chips). Only on a
  // finished analysis -- see this file's header for why a failed or
  // still-running one shows the reason instead of buttons.
  const tdFmt = document.createElement("td");
  if(secRpFinished(r)){
    const rowEl = secEl("div", "secrp-fmts");
    SEC_REPORT_FORMATS.forEach(([fmt, label]) => {
      const btn = secEl("button", "secrp-fmt");
      btn.type = "button";
      btn.appendChild(document.createTextNode(label));
      btn.title = fmt === "sbom" ? SBOM_CAVEAT
        : "Download this analysis's report as " + label;
      btn.onclick = () => secDownloadReport(r.analysis_id, fmt, btn);
      rowEl.appendChild(btn);
    });
    tdFmt.appendChild(rowEl);
  }else{
    tdFmt.appendChild(secEl("div", "secrp-none", "—"));
    tdFmt.appendChild(secEl("div", "secmeta",
      r.state === "failed" ? "No report generated" : "Not finished yet"));
  }
  tr.appendChild(tdFmt);
  return tr;
}

function secReportsTable(rows){
  const sorted = rows.slice().sort((a, b) =>
    secRpSortDir === "asc" ? (a.started || 0) - (b.started || 0)
                            : (b.started || 0) - (a.started || 0));
  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secrp-table";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_REPORT_COLS.forEach(([key, label]) => {
    const th = document.createElement("th");
    th.appendChild(document.createTextNode(label));
    if(key === "generated"){
      th.className = "sortable sorted";
      th.title = GENERATED_NOTE + " Click to sort.";
      th.setAttribute("aria-sort", secRpSortDir === "asc" ? "ascending" : "descending");
      th.appendChild(secIcon(secRpSortDir === "asc" ? "sortasc" : "sortdesc"));
      th.onclick = () => {
        secRpSortDir = secRpSortDir === "asc" ? "desc" : "asc";
        if(secRpPayload) secRenderProjectReports(secRpPayload);
      };
    }
    if(key === "formats"){
      th.title = "Each chip downloads that format, generated on the spot "
        + "from the analysis's own records.";
    }
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  sorted.forEach(r => tbody.appendChild(secReportRow(r)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  wrap.appendChild(tableFooter({
    shown: {from: 1, to: sorted.length}, total: sorted.length, noun: "report",
    page: 1, pages: 1, numbered: true,
  }));
  return wrap;
}

let secRpPayload = null;

export function secRenderProjectReports(payload){
  const host = $("sec-pj-reports");
  if(!host) return;
  secRpPayload = payload;
  host.textContent = "";
  const rows = ((payload || {}).tabs || {}).reports || [];

  const card = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  const titles = secEl("div", "grow");
  titles.appendChild(secEl("h3", null, "Reports"));
  titles.appendChild(secEl("div", "secpj-caption",
    "Export detailed results for audits, compliance and sharing with your team."));
  head.appendChild(titles);
  card.appendChild(head);

  if(!rows.length){
    card.appendChild(secEl("div", "tblempty", "No analyses of this project yet."));
  }else{
    card.appendChild(secReportsTable(rows));
  }
  // The same sentence the single-analysis Downloads row carries (see
  // ui/security/index.js's #sec-dl-note): the severity floor is a display
  // filter over the findings LIST, and every download here still contains
  // everything that analysis recorded regardless of it.
  card.appendChild(secEl("div", "secdlnote",
    "Downloads always contain every recorded finding, whatever the severity floor shows."));
  host.appendChild(card);
}

/* --------------------------------------------------------------- the rail
   ProjectReports.png's own right column: the same all-branch donut and
   Top-issue-categories cards the Branches rail draws (imported, one copy),
   plus the Reports summary. Mounted by project-screen.js's
   secRenderProjectSidebar when this tab is up. */
export function secReportsSidebar(payload){
  const frag = document.createDocumentFragment();
  const sb = (payload || {}).sidebar || {};
  frag.appendChild(secAllBranchDonutCard(sb));
  frag.appendChild(secTopCategoriesCard(sb));
  frag.appendChild(secReportsSummaryCard(((payload || {}).tabs || {}).reports || []));
  return frag;
}

/* "Reports available", not the mockup's "Total reports generated": nothing
   is generated until a chip is clicked, so the honest count is how many
   analyses have a report TO generate (finished ones). No "Total size"
   line for the same reason -- there is no file to weigh -- and the
   retention sentence says what is actually true of an on-demand system. */
function secReportsSummaryCard(rows){
  const card = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Reports summary"));
  card.appendChild(head);
  const available = rows.filter(secRpFinished).length;
  const failed = rows.filter(r => r.state === "failed").length;
  const line = (label, value) => {
    const el = secEl("div", "secrp-sumline");
    el.appendChild(secEl("span", "secrp-sumlabel", label));
    el.appendChild(secEl("b", null, String(value)));
    return el;
  };
  card.appendChild(line("Reports available", available));
  card.appendChild(line("Failed analyses", failed));
  card.appendChild(secEl("div", "secpj-caption",
    "Reports are generated on demand from each analysis's own ledger "
    + "records — nothing is stored or expires."));
  return card;
}
