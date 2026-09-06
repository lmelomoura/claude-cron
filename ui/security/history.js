/* -------------------------------------------------------------- history */
import { $, AL, openLog, unjournaledLive, fmtWhen, money } from "./page.js";
import { secEl } from "./dom.js";
import { SEC_RUN_WINDOW } from "./vocabulary.js";
import { secState } from "./state.js";
import { secShowAnalysis } from "./analysis.js";

export function secRunFor(a){
  if(!a || !a.run_id) return null;
  // A RUNNING analysis only ever links a LIVE run: matching it against the
  // journal is how a dead previous attempt got its transcript shown over a
  // live analysis. A finished analysis searches both pools — its run is
  // usually journaled, but the journal lags the end of the run by a poll.
  const running = a.state === "running";
  const pool = running ? unjournaledLive()
                       : unjournaledLive().concat(AL.DATA.runs || []);
  let best = null, bestd = Infinity;
  pool.forEach(r => {
    if(r.id !== a.run_id) return;
    const d = Math.abs((r.start || 0) - (a.started || 0));
    if(d < bestd){ best = r; bestd = d; }
  });
  return bestd <= SEC_RUN_WINDOW ? best : null;
}

/* "Earlier analyses of THIS branch" -- this branch being the one belonging to
   the analysis ON SCREEN, not the one the picker at the top happens to be
   pointing at.

   Those are usually the same and are not always: open a `develop` run from
   the Runs table (or follow the Activity screen's deep link into one) while
   the picker still reads `main`, and the status line above says `develop`
   while the list below it is `main`'s history. Nothing on screen said which
   branch the list was for, so it read as this analysis's history and was
   another branch's. The analysis is the subject of this whole pane; the
   picker is a control for STARTING one, and it is not the subject of
   anything below it. */
export function secRenderHistory(){
  const host = $("sec-history");
  host.textContent = "";
  const shown = secState.analysis;
  // No analysis on screen yet (a branch nothing has ever analysed) is the one
  // case with no subject to follow -- the picker is then the only statement
  // of scope there is, and it is the right one.
  const repo = shown ? shown.repo : secState.repo;
  const branch = shown ? shown.branch : secState.branch;
  const mine = secState.analyses.filter(x => x.repo === repo && x.branch === branch);
  if(!mine.length){
    // Names the branch: with the list no longer following the picker, a
    // reader has to be able to tell WHICH branch has nothing behind it.
    host.appendChild(secEl("div", "empty", branch
      ? "Nothing else analysed on " + branch + " yet."
      : "Nothing analysed on this branch yet."));
    return;
  }
  const current = shown && shown.id;
  mine.forEach(a => {
    const row = secEl("div", "sechrow" + (a.id === current ? " on" : ""));
    const open = secEl("button", "btn ghost", "#" + a.id);
    open.type = "button";
    open.title = "Show this analysis";
    // `pinned`: a deliberate open. The 4-second poll must not swap this out
    // from under the reader for the branch's newest analysis -- see
    // secShowAnalysis's own comment in analysis.js.
    open.onclick = () => secShowAnalysis(a.id, true);
    row.appendChild(open);
    row.appendChild(secEl("span", "grow", [a.state, a.profile,
      String(a.commit_sha || "").slice(0, 12),
      fmtWhen(a.started), money(a.spend_usd || 0)].filter(Boolean).join(" · ")));
    const run = secRunFor(a);
    if(run){
      const b = secEl("button", "btn ghost", "Run");
      b.type = "button";
      b.title = "Open this analysis's run";
      b.onclick = () => openLog(run.id, run.start);
      row.appendChild(b);
    }
    host.appendChild(row);
  });
}
