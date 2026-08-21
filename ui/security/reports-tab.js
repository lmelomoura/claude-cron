/* ---------------------------------------------------------- the Reports tab
   One row per analysis, whatever its state, with the four downloads
   (Markdown, JSON, HTML, SBOM) that used to be reachable only from
   whichever single analysis happened to be open under the Runs tab. Fed by
   `tabs.reports` (bin/security/cli.py's `project-data`) -- a thin
   projection of the exact same `runs` rows the Runs tab already has, not a
   second query; see that function's own docstring.

   Downloads go through fetch + Blob for the identical reason actions.js's
   secDownload already does: every GET on this API carries the X-CC-Token
   header, which a bare `<a href>` cannot attach, so the response is fetched,
   held as a Blob and handed to a link the page clicks itself. This tab
   cannot just CALL secDownload, though: that one is wired to the currently
   loaded secState.analysis and to four fixed button ids (sec-dl-md, ...),
   neither of which fits a table with one button per (row, format) pair.
   secDownloadAnalysisReport below is the same fetch+Blob mechanism,
   parameterised by an explicit analysis id and its own button element
   instead of a global and a lookup by fixed id.

   The one fact this tab has to say out loud, in the README's own words: SBOM
   is not a report over any one analysis's checklist. It is the stored
   CycloneDX inventory itself, kept per (project, repo, branch) with only the
   LATEST document (ledger.py's `sbom` table, `store_sbom`'s upsert) -- so
   the SBOM button on an OLDER analysis's row still downloads that branch's
   CURRENT document, not a reconstruction of what the tree held that day.
   secReportsCaption says so; a reader who has not opened the README must not
   be left to assume otherwise. */
import { $, TOKEN, fmtWhen, toast } from "./page.js";
import { secEl, secIcon } from "./dom.js";

const SEC_REPORT_FORMATS = [["md", "Markdown"], ["json", "JSON"],
                            ["html", "HTML"], ["sbom", "SBOM"]];

export async function secDownloadAnalysisReport(id, fmt, btn){
  btn.disabled = true;
  try{
    const r = await fetch("/api/security/report?analysis=" + encodeURIComponent(id)
                          + "&format=" + encodeURIComponent(fmt), {headers:{"X-CC-Token":TOKEN}});
    if(!r.ok){
      const j = await r.json().catch(() => null);
      throw new Error((j && j.error) || ("HTTP " + r.status));
    }
    const url = URL.createObjectURL(await r.blob());
    const link = document.createElement("a");
    link.href = url;
    // Mirrors REPORT_EXTENSIONS in bin/claude-cron-server, exactly like
    // actions.js's secDownload: a fetch never turns Content-Disposition into
    // a download name on its own, so the two have to agree by hand.
    link.download = "security-analysis-" + id + "." + (fmt === "sbom" ? "cdx.json" : fmt);
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }catch(e){ toast("Download failed — " + e.message, true); }
  finally{ btn.disabled = false; }
}

function secReportsCaption(){
  const cap = secEl("div", "secpj-caption");
  cap.appendChild(document.createTextNode(
    "Markdown, JSON and HTML are generated from each analysis's own checklist "
    + "at the moment you download one. "));
  cap.appendChild(secEl("b", null, "SBOM is different: "));
  cap.appendChild(document.createTextNode(
    "it is not a report over any analysis's checklist but the stored CycloneDX "
    + "inventory itself, kept per branch with only the most recent document — "
    + "so the SBOM button on an older row still downloads that branch's CURRENT "
    + "document, not a snapshot of what that analysis saw."));
  return cap;
}

function secReportRow(r){
  const tr = document.createElement("tr");
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };

  tr.appendChild(cell("#" + r.analysis_id));
  tr.appendChild(cell(r.branch || ""));
  tr.appendChild(cell(r.started ? fmtWhen(r.started) : "—"));
  tr.appendChild(cell(r.state || ""));

  const tdDl = document.createElement("td");
  const row = secEl("div", "secdl");
  SEC_REPORT_FORMATS.forEach(([fmt, label]) => {
    const btn = secEl("button", "btn ghost");
    btn.type = "button";
    btn.appendChild(secIcon("file"));
    btn.appendChild(document.createTextNode(label));
    btn.onclick = () => secDownloadAnalysisReport(r.analysis_id, fmt, btn);
    row.appendChild(btn);
  });
  tdDl.appendChild(row);
  tr.appendChild(tdDl);
  return tr;
}

function secReportsTable(rows){
  if(!rows.length){
    return secEl("div", "tblempty", "No analyses of this project yet.");
  }
  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Analysis", "Branch", "Started", "State", "Downloads"].forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  rows.forEach(r => tbody.appendChild(secReportRow(r)));
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

export function secRenderProjectReports(payload){
  const host = $("sec-pj-reports");
  if(!host) return;
  host.textContent = "";
  const rows = ((payload || {}).tabs || {}).reports || [];
  host.appendChild(secReportsCaption());
  host.appendChild(secReportsTable(rows));
  // The same sentence the single-analysis Downloads row carries (see
  // ui/security/index.js's #sec-dl-note): the severity floor is a display
  // filter over the findings LIST, and every download here still contains
  // everything that analysis recorded regardless of it.
  host.appendChild(secEl("div", "secdlnote",
    "Downloads always contain every recorded finding, whatever the severity floor shows."));
}
