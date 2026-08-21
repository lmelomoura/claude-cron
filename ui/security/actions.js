/* --------------------------------------------------------------- actions */
import { $, TOKEN, api, toast } from "./page.js";
import { secState } from "./state.js";
import { secScope, secReload, secSyncPoll, secPaintRunButton } from "./analysis.js";

export async function secAnalyse(){
  const s = secScope();
  if(!s.branch){ toast("Pick a branch, or type one", true); return; }
  const btn = $("sec-run");
  btn.disabled = true;
  btn.textContent = "Analysing…";
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
    secState.branch = s.branch; secState.repo = s.repo;
    // The deterministic phase writes in the agent's first seconds, so polling shows
    // secrets and CVEs within seconds while the SAST is still running.
    await secReload();
    secSyncPoll();
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyse";
    secPaintRunButton();
  }
}

export async function secDownload(fmt){
  const a = secState.analysis;
  if(!a) return;
  const btn = $("sec-dl-" + fmt);
  btn.disabled = true;
  try{
    // Every GET on this API carries the token header, which a plain
    // `<a href="/api/security/report?…">` cannot attach — so the report is
    // fetched, held as a Blob and handed to a link the page clicks itself. The
    // filename is built here from the same id and format that were asked for:
    // the server names the file in Content-Disposition, and a fetch never turns
    // that header into a download name on its own.
    const r = await fetch("/api/security/report?analysis=" + encodeURIComponent(a.id)
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
    link.download = "security-analysis-" + a.id + "." + (fmt === "sbom" ? "cdx.json" : fmt);
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Revoked late rather than immediately: the click is handed to the browser
    // asynchronously and a URL revoked in the same tick can lose the race.
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }catch(e){ toast("Download failed — " + e.message, true); }
  finally{ btn.disabled = false; }
}
