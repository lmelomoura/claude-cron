/* --------------------------------------------------------- the Branches tab
   One row per branch that has EVER been analysed -- not only the single
   branch the header and the Overview tab show (default_branch_posture's own
   pick: the project's declared base, or the branch it fell back to). Fed by
   `tabs.branches` (bin/security/cli.py's `project-data`), which is exactly
   `queries.branch_rows`'s own rows -- last analysis, open findings by
   severity, how many analyses, and the 30-day trend -- built from the same
   `checklist()`/`posture()` every other number on this screen uses. See
   queries.py's own docstring for why a read-only connection never pays for
   the same analysis id's checklist twice within one request.

   The one fact this tab has to say out loud, in the same voice
   secOverviewCaption/secSidebarCaption already use in project-screen.js for
   the identical kind of fact: a branch's own `open` count here is NOT the
   sidebar donut's question. The donut collapses every analysed branch's
   open findings into one count per FINGERPRINT, project-wide -- a finding
   open on both `main` and `develop` counts once there. Here it counts once
   PER BRANCH, because that is what "this branch's own posture" means -- so
   these rows can legitimately add up to more than the sidebar's own total.
   secBranchesCaption says so; nothing here recomputes or reconciles the two
   numbers. */
import { $, fmtAgo } from "./page.js";
import { secEl } from "./dom.js";
import { secIndexPosturePills } from "./index-screen.js";

function secBranchesCaption(){
  return secEl("div", "secpj-caption",
    "Each row is that branch's own posture — the same computation the "
    + "Overview panel above uses for its one branch. The sidebar's donut "
    + "counts a finding once for the whole project even when it is open on "
    + "several branches; here it counts once per branch, so these rows can "
    + "add up to more than the sidebar's own total.");
}

/* Pure and DOM-free on purpose, so a Node script can drive it with a plain
   array literal -- no fake document required, unlike the row/table builders
   below. `trend` is queries.trend()'s own shape: analyses of this branch
   within the last 30 days, oldest first, each carrying how many findings
   were open at that point. */
function secBranchTrendText(trend){
  const pts = trend || [];
  if(!pts.length) return "No analyses of this branch in the last 30 days.";
  if(pts.length === 1){
    return pts[0].open + " open — only one analysis in the last 30 days, "
      + "nothing yet to compare it against.";
  }
  const first = pts[0].open, last = pts[pts.length - 1].open;
  const word = last < first ? "falling" : last > first ? "rising" : "flat";
  return first + " → " + last + " open over the last 30 days (" + word + ")";
}

function secBranchRow(r){
  const tr = document.createElement("tr");
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };

  tr.appendChild(cell(r.branch || ""));
  tr.appendChild(cell(r.last_analysis ? fmtAgo(r.last_analysis) : "—"));

  const tdCount = cell(String(r.analyses || 0));
  tdCount.className = "num";
  tr.appendChild(tdCount);

  const tdOpen = document.createElement("td");
  tdOpen.appendChild(secIndexPosturePills(r.open || {}));
  tr.appendChild(tdOpen);

  tr.appendChild(cell(secBranchTrendText(r.trend)));
  return tr;
}

function secBranchesTable(rows){
  if(!rows.length){
    return secEl("div", "tblempty", "No branch of this project has been analysed yet.");
  }
  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Branch", "Last analysis", "Analyses", "Open", "Trend (30d)"].forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  rows.forEach(r => tbody.appendChild(secBranchRow(r)));
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

export function secRenderProjectBranches(payload){
  const host = $("sec-pj-branches");
  if(!host) return;
  host.textContent = "";
  const rows = ((payload || {}).tabs || {}).branches || [];
  host.appendChild(secBranchesCaption());
  host.appendChild(secBranchesTable(rows));
}
