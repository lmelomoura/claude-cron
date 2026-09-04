/* --------------------------------------------------------------- actions */
import { $, TOKEN, api, toast, markPending, clearPending } from "./page.js";
import { secState } from "./state.js";
import { secScope, secReload, secSyncPoll, secPaintRunButton } from "./analysis.js";

export async function secAnalyse(){
  const s = secScope();
  if(!s.branch){ toast("Pick a branch, or type one", true); return; }
  const btn = $("sec-run");
  btn.disabled = true;
  btn.textContent = "Analysing…";
  // secPaint() rebuilds this button on its own 4-second cycle, so `disabled`
  // alone is gone before the detached `security analyze` has reached
  // acquire_slot -- and the engine's "one at a time" gate is that slot, which
  // takes a second or two to exist. A second click in the gap really starts a
  // second analysis.
  const ak = ["security_analyze", secState.project, ""];
  markPending(...ak);
  try{
    // ALWAYS this op, never a bare run of the derived job: the request file the
    // job reads is written here, and running the job on its own would make it
    // re-read a spent one and analyse the wrong branch. A refusal — a branch
    // name the engine will not take, an analysis already running — comes back
    // as the server's own sentence, which api() puts on screen.
    const ok = await api("security_analyze", {project: secState.project,
                repo: s.repo, branch: s.branch, profile: $("sec-profile").value});
    if(!ok) return;
    toast("Analysis started", false, "shield");
    // Closed on SUCCESS only, never on a refusal above -- the same rule
    // bin/dashboard.html's own saveProject/deleteProjectFromModal already
    // follow for #projmodal: a validation refusal (an empty branch, a
    // second analysis already running) leaves the dialog open with its own
    // fields exactly as typed, so fixing them is the very next thing a
    // reader does, not a fresh re-open. #sec-run lives inside
    // <dialog id="seclaunch"> as of Runs tab parity pass 2; this is the one
    // new line that dialog needed, since nothing closed it before.
    $("seclaunch").close();
    secState.branch = s.branch; secState.repo = s.repo;
    // The deterministic phase writes in the agent's first seconds, so polling shows
    // secrets and CVEs within seconds while the SAST is still running.
    await secReload();
    secSyncPoll();
  } finally {
    clearPending(...ak);
    btn.disabled = false;
    btn.textContent = "Analyse";
    secPaintRunButton();
  }
}

// Shared by secDownload below and reports-tab.js's per-row download
// buttons -- the identical fetch + Blob + anchor + revoke mechanics,
// parameterised by an explicit analysis id, format and button element
// instead of a global and a lookup by fixed DOM id. This used to be two
// near-verbatim copies, kept apart only because two tests in
// tests/test_page_contract.py (test_a_report_download_carries_the_token,
// test_the_sbom_download_is_named_the_way_its_tooling_expects) extracted
// secDownload's own literal source and asserted substrings inside it.
// Neither property they guard -- "downloads carry the token", "the SBOM
// filename matches REPORT_EXTENSIONS" -- is about a function's NAME, so
// both tests now extract THIS function instead, and secDownload/
// reports-tab.js's per-row buttons both call it rather than each keeping
// their own copy that would drift the first time one of them was fixed.
export async function secDownloadReport(id, fmt, btn){
  btn.disabled = true;
  // /api/security/report is not read-only: it spawns `security render`, then
  // `security analysis`, and writes a report_exported event into the ledger.
  // The `finally` below lands on a node secPaint may already have replaced.
  const dk = ["security_report", id, fmt];
  markPending(...dk);
  try{
    // Every GET on this API carries the token header, which a plain
    // `<a href="/api/security/report?…">` cannot attach — so the report is
    // fetched, held as a Blob and handed to a link the page clicks itself. The
    // filename is built here from the same id and format that were asked for:
    // the server names the file in Content-Disposition, and a fetch never turns
    // that header into a download name on its own.
    const r = await fetch("/api/security/report?analysis=" + encodeURIComponent(id)
                          + "&format=" + encodeURIComponent(fmt), {headers:{"X-CC-Token":TOKEN}});
    if(!r.ok){
      const j = await r.json().catch(() => null);
      throw new Error((j && j.error) || ("HTTP " + r.status));
    }
    const url = URL.createObjectURL(await r.blob());
    const link = document.createElement("a");
    link.href = url;
    // Mirrors REPORT_EXTENSIONS in bin/claude-cron-server: a fetch never turns
    // the server's Content-Disposition into a download name on its own, so the
    // two have to agree by hand. `.cdx.json` is what SBOM tooling recognises.
    link.download = "security-analysis-" + id + "." + (fmt === "sbom" ? "cdx.json" : fmt);
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Revoked late rather than immediately: the click is handed to the browser
    // asynchronously and a URL revoked in the same tick can lose the race.
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }catch(e){ toast("Download failed — " + e.message, true); }
  finally{ clearPending(...dk); btn.disabled = false; }
}

export async function secDownload(fmt){
  const a = secState.analysis;
  if(!a) return;
  await secDownloadReport(a.id, fmt, $("sec-dl-" + fmt));
}
