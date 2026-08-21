/* ------------------------------------------------------- the project list
   One /api/security per enabled project and one checklist for its last
   finished analysis — each of those is a subprocess on the server, so it
   happens when the page is opened and when Refresh is pressed, never on the
   five-second poll. A project already in this cache is skipped, which is what
   keeps renderSecurity() calling this on every repaint from costing anything.

   The list is projects rather than jobs on purpose: a project can be
   registered for security analysis and never have a job at all. */
import { $, CC, fmtAgo } from "./page.js";
import { secIcon, secEl, secFetch } from "./dom.js";
import { SEV_ORDER, secEnabled, secMinSeverity, secPosture } from "./vocabulary.js";
import { secOpen } from "./analysis.js";

export const secPost = {};
let secPostGen = 0;
export async function secLoadPostures(force){
  const names = (CC.DATA.projects || []).filter(secEnabled).map(p => p.name);
  if(force){ secPostGen++; names.forEach(n => { delete secPost[n]; }); }
  // Read once: a Refresh pressed mid-flight empties the cache, and a reply that
  // was already in the air would otherwise land on top of the fresh answer.
  const gen = secPostGen;
  for(const name of names){
    if(secPost[name]) continue;
    secPost[name] = {state:"loading"};
    try{
      const list = await secFetch("/api/security?project=" + encodeURIComponent(name));
      if(gen !== secPostGen) return;
      const done = (list || []).find(a => a.state !== "running") || null;
      // The FINDINGS are cached, never the counts derived from them: the counts
      // depend on the project's min_severity, this cache outlives an edit to it,
      // and a posture computed once would keep painting yesterday's threshold
      // until something happened to evict the project. Deriving at paint costs
      // one pass over an array the page already holds.
      const rec = {state:"ok", analyses:list || [], latest:(list || [])[0] || null,
                   done, findings:null};
      secPost[name] = rec;
      secRenderList();
      if(done){
        const ck = await secFetch("/api/security/checklist?analysis=" + encodeURIComponent(done.id));
        if(gen !== secPostGen) return;
        rec.findings = ck.findings || [];
      }
    }catch(e){
      if(gen !== secPostGen) return;
      secPost[name] = {state:"error", error:e.message};
    }
    secRenderList();
  }
}

export function secRenderList(){
  const host = $("sec-list");
  if(!host) return;
  host.textContent = "";
  const projects = (CC.DATA.projects || []).slice()
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
  if(!projects.length){
    const e = secEl("div", "tblempty");
    e.appendChild(secIcon("inbox"));
    e.appendChild(document.createTextNode(
      "No projects yet. Security analysis is configured on a project, so there "
      + "has to be one first."));
    host.appendChild(e);
    return;
  }
  projects.forEach(p => host.appendChild(secProjectRow(p)));
}

function secProjectRow(p){
  const on = secEnabled(p);
  // A button when there is somewhere to go, a plain div when there is not: a
  // clickable row that opens a screen with nothing on it is a worse answer
  // than a sentence saying where to switch it on.
  const row = document.createElement(on ? "button" : "div");
  row.className = "secrow" + (on ? "" : " off");
  if(on){ row.type = "button"; row.onclick = () => secOpen(p.name); }
  row.appendChild(secIcon("shield"));
  const grow = secEl("div", "grow");
  grow.appendChild(secEl("div", "secname", p.name));
  const meta = secEl("div", "secmeta");
  if(!on){
    meta.textContent = "Security analysis is off for this project — turn it on in the "
      + "project editor, on the Security tab.";
  }else{
    const rec = secPost[p.name];
    if(!rec || rec.state === "loading") meta.textContent = "Loading…";
    else if(rec.state === "error") meta.textContent = "Could not read its analyses — " + rec.error;
    else if(!rec.latest) meta.textContent = "Never analysed. Open it to pick a branch and start.";
    else{
      const a = rec.latest;
      meta.textContent = (a.state === "running" ? "Analysing " : "Last analysed ")
        + a.repo + " @ " + a.branch + " · " + a.profile
        + " · " + (a.state === "running" ? "started " + fmtAgo(a.started)
                                         : a.state + " " + fmtAgo(a.ended || a.started));
    }
  }
  grow.appendChild(meta);
  row.appendChild(grow);
  if(on) row.appendChild(secPosturePills(secPost[p.name], p.name));
  return row;
}

/* The project's name, not just its record: the severity floor is a project
   setting and the posture is computed here, at paint, from the cached findings
   — so changing min_severity in the editor repaints correctly instead of
   showing a count taken against the old threshold. */
function secPosturePills(rec, name){
  const wrap = secEl("div", "sevpills");
  if(!rec || rec.state !== "ok" || !rec.findings) return wrap;
  const counts = secPosture(rec.findings, secMinSeverity(name));
  const total = SEV_ORDER.reduce((n, s) => n + (counts[s] || 0), 0) + (counts.other || 0);
  if(!total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  ["critical","high","medium","low","info"].forEach(sev => {
    if(!counts[sev]) return;
    wrap.appendChild(secEl("span", "sevpill " + sev, counts[sev] + " " + sev));
  });
  if(counts.other) wrap.appendChild(secEl("span", "sevpill low", counts.other + " other"));
  return wrap;
}
