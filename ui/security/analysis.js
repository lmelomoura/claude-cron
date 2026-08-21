/* --------------------------------------------------------- one project */
import { $, CC, api, toast, openLog, projById, fmtAgo, fmtDur, money } from "./page.js";
import { secIcon, secEl, secFill, secFetch } from "./dom.js";
import { SEC_POLL_MS, SEC_PROFILES, SEC_STATES, SEC_STATE_HELP, SEC_STATE_LABEL,
         SEV_ORDER, secDefaultProfile, secMinSeverity, secPosture, secRepos,
         secSevKey, secSevRank, secStateKey, secVisible } from "./vocabulary.js";
import { secState } from "./state.js";
import { secInvalidateIndex, secRenderIndex, secLoadIndex } from "./index-screen.js";
import { secRunFor, secRenderHistory } from "./history.js";
import { secAskReason } from "./reason.js";
import { secInvalidateProject, secRefreshProject } from "./project-screen.js";

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

export function secBack(){
  secStopPoll();
  // Whatever just happened in there (a new analysis, a decision) may have
  // changed the fleet's posture, so the index's cached answer is thrown away
  // and re-read rather than repainting numbers from before. The project
  // screen's own cache gets the identical treatment, for the identical
  // reason.
  secInvalidateIndex();
  secInvalidateProject();
  secState.project = ""; secState.analysis = null; secState.findings = [];
  secState.analyses = []; secState.stateFilter = "";
  $("sec-detail").hidden = true;
  $("sec-projects").hidden = false;
  secRenderIndex();
  secLoadIndex(false);
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
  secState.stateFilter = "";
  // A fresh project starts the running/not-running comparison over: the
  // value from whatever project was open before (or none) must never make
  // this project's own first poll tick look unchanged by coincidence.
  secProjectPollWasRunning = null;
  $("sec-projects").hidden = true;
  $("sec-detail").hidden = false;
  const title = $("sec-title");
  title.textContent = "";
  title.appendChild(secIcon("shield"));
  title.appendChild(document.createTextNode(project));
  $("sec-findings").textContent = "";
  $("sec-history").textContent = "";
  $("sec-summary").textContent = "";
  $("sec-checklist").textContent = "";
  $("sec-dl").hidden = true;
  secStatus("Loading…");

  const p = projById(project) || {};
  const repos = secRepos(p);
  secFill($("sec-repo"), repos);
  // With one checkout there is nothing to choose between, and the row is filed
  // under the project's own name either way.
  $("sec-repo-field").hidden = repos.length < 2;
  $("sec-profile").value = secDefaultProfile(project);
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
  if(last && repos.includes(last.repo)) $("sec-repo").value = last.repo;
  await secLoadBranches(last ? last.branch : "");
  if(seq !== secState.seq) return;
  if(last && SEC_PROFILES.includes(last.profile)) $("sec-profile").value = last.profile;
  // secSyncScope() takes the next generation for itself, so nothing after this
  // may test `seq` again.
  await secSyncScope();
}

export async function secLoadBranches(want){
  // Same generation guard as secOpen and secShowAnalysis, for the same reason:
  // this is a `git for-each-ref` on the server, and the answer for the repo
  // somebody has already navigated away from must not fill the picker of the
  // one now on screen.
  const seq = secState.seq;
  const sel = $("sec-branch");
  secFill(sel, ["…"], "…");
  let branches = [];
  try{
    const j = await secFetch("/api/security/branches?project="
      + encodeURIComponent(secState.project) + "&repo=" + encodeURIComponent($("sec-repo").value));
    if(seq !== secState.seq) return;
    branches = j.branches || [];
  }catch(e){
    if(seq !== secState.seq) return;
    secFill(sel, []);
    toast("Could not list branches — " + e.message, true);
    return;
  }
  // The branch of the last analysis may be gone from the checkout by now; it is
  // still the one this screen is about, so it stays in the list.
  if(want && !branches.includes(want)) branches = [want].concat(branches);
  secFill(sel, branches, want);
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

export async function secShowAnalysis(id){
  const seq = ++secState.seq;
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
  const want = mine.length ? mine[0].id : (secState.analysis && secState.analysis.id);
  await secShowAnalysis(want == null ? null : want);
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
}

export function secPaint(){
  const a = secState.analysis;
  const running = !!a && a.state === "running";
  secPaintRunButton();
  // Here rather than only after pressing Analyse: arriving on a project whose
  // analysis somebody else started has to start watching it too, or the screen
  // sits on a running row that never moves.
  secSyncPoll();
  const box = $("sec-status");
  box.textContent = "";
  if(!a){
    box.appendChild(secEl("span", null,
      secState.branch ? "No analysis of this branch yet — press Analyse to make the first one."
                      : "Pick a branch, or type one, and press Analyse."));
    $("sec-incomplete").hidden = true;
    $("sec-coverage").hidden = true;
    $("sec-summary").textContent = "";
    $("sec-checklist").textContent = "";
    $("sec-dl").hidden = true;
    $("sec-findings").textContent = "";
    secRenderHistory();
    return;
  }
  box.appendChild(secIcon(running ? "timer" : (a.state === "failed" ? "xcircle" : "check")));
  box.appendChild(secEl("b", null, "Analysis " + a.id));
  const bits = [a.repo + " @ " + a.branch, String(a.commit_sha || "").slice(0, 12),
                a.profile, a.state,
                running ? "started " + fmtAgo(a.started)
                        : (a.ended ? "ended " + fmtAgo(a.ended) : "started " + fmtAgo(a.started))];
  if(a.ended && a.started) bits.push(fmtDur(Math.max(0, a.ended - a.started)));
  bits.push(money(a.spend_usd || 0));
  box.appendChild(secEl("span", null, bits.filter(Boolean).join(" · ")));
  if(running){
    box.appendChild(secEl("span", null,
      "Secrets, dependencies and CVEs are written moments after the agent starts — "
      + "they are its first command — so what is below is already real while the "
      + "code review keeps going."));
  }
  const run = secRunFor(a);
  if(run){
    const b = secEl("button", "btn", "Open the run");
    b.type = "button";
    b.onclick = () => openLog(run.id, run.start);
    box.appendChild(b);
  }
  // `running` in the ledger is a claim; a live slot is the fact. When the two
  // disagree for longer than a launch could take, say so — a run killed
  // without a journal (a reboot, a group-kill) leaves exactly this state, and
  // the page used to show "Analysing…" over it indefinitely.
  if(running && !run){
    if((Date.now()/1000 - (a.started||0)) > 180){
      box.appendChild(secEl("span", "note",
        "No live run is behind this analysis — it likely died without closing. "
        + "The next Analyse sweeps it; until then downloads carry what it recorded."));
    }else{
      // The pre-agent window: the engine is cutting a worktree from a fresh
      // fetch of the branch, which on a big repository is most of the wait.
      // The run trace exists once the agent starts; until then, name the
      // phase instead of showing a button-less void.
      box.appendChild(secEl("span", null,
        "Preparing the run — fetching the branch and cutting a clean worktree. "
        + "The live trace appears here the moment the agent starts."));
    }
  }

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

function secRenderSummary(){
  const host = $("sec-summary");
  host.textContent = "";
  const shown = secVisible(secState.findings, secMinSeverity(secState.project));
  const counts = secPosture(secState.findings, secMinSeverity(secState.project));
  const open = SEV_ORDER.reduce((n, s) => n + counts[s], 0) + counts.other;
  if(!shown.length){
    host.appendChild(secEl("span", "sevpill clean", "nothing found"));
  }else if(!open){
    host.appendChild(secEl("span", "sevpill clean", "nothing open"));
  }else{
    ["critical","high","medium","low","info"].forEach(sev => {
      if(counts[sev]) host.appendChild(secEl("span", "sevpill " + sev, counts[sev] + " " + sev));
    });
    if(counts.other) host.appendChild(secEl("span", "sevpill low", counts.other + " other"));
  }
  // What the project's own threshold is keeping off this page. Said out loud,
  // because the number that is missing is otherwise indistinguishable from a
  // number that was never found.
  const hidden = secState.findings.length - shown.length;
  if(hidden > 0){
    host.appendChild(secEl("span", "sevpill low", hidden + " below "
      + secMinSeverity(secState.project) + " — recorded, not shown"));
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
}

function secRenderFindings(){
  const host = $("sec-findings");
  host.textContent = "";
  let list = secVisible(secState.findings, secMinSeverity(secState.project));
  if(secState.stateFilter) list = list.filter(f => f.state === secState.stateFilter);
  // Worst first, and inside a severity the ones nobody has judged yet.
  const stateRank = (f) => SEC_STATES.indexOf(f.state);
  list = list.slice().sort((x, y) => (secSevRank(y.severity) - secSevRank(x.severity))
                                  || (stateRank(x) - stateRank(y))
                                  || String(x.title).localeCompare(String(y.title)));
  if(!list.length){
    const e = secEl("div", "empty", secState.stateFilter
      ? "Nothing in that state." : "This analysis reported nothing to show.");
    host.appendChild(e);
    return;
  }
  list.forEach(f => host.appendChild(secFindingRow(f)));
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
