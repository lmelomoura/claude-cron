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
import { SEC_NEVER } from "./vocabulary.js";
import { secIndexPosturePills } from "./index-screen.js";

/* The cue Task 8 established for a PARTIAL read, in the same class and the
   same words the index screen's own project row uses (secIndexProjectRow's
   `secidx-capped` badge) and the Overview panel's banner repeats: a `capped`
   analysis stopped before covering the whole scope, so "critical: 0" beside
   it means "none found before it stopped," not "none."

   This tab could not say it at all. `branch_rows` admitted `done` and
   `capped` alike and returned no state, and the table had no column for one
   -- so the single screen whose entire purpose is per-branch posture was the
   only posture surface in the area that presented a truncated read as a
   finished one. */
const BRANCH_CAPPED_TITLE = "This analysis is INCOMPLETE: it stopped before "
  + "covering the whole scope. The posture beside this badge is what it had "
  + "reached, not what is there.";

function secBranchesCaption(){
  return secEl("div", "secpj-caption",
    "Each row is that branch's own posture — the same computation the "
    + "Overview panel above uses for its one branch. A branch appears here "
    + "only once one of its analyses has reached done or capped; a branch "
    + "whose only analyses so far are still running or have failed already "
    + "shows up in Runs and Reports but will not have a row here yet. The "
    + "sidebar's donut counts a finding once for the whole project even "
    + "when it is open on several branches; here it counts once per branch, "
    + "so these rows can add up to more than the sidebar's own total.");
}

/* Pure and DOM-free on purpose, so a Node script can drive it with a plain
   array literal -- no fake document required, unlike the row/table builders
   below. `trend` is queries.trend()'s own shape: analyses of this branch
   within the last 30 days, oldest first, each carrying how many findings
   were open at that point.

   Only the FIRST and LAST point used to reach this text, with "rising"/
   "falling" read off the two of them alone -- so a branch that spiked to
   forty open findings and got mostly fixed (5, 40, 6) rendered as
   "5 → 6 ... (rising)", the opposite of what happened, and nothing in the
   diff that shipped this ever drove it with three points to notice (see
   tests/test_page_contract.py's
   test_branch_trend_text_refuses_a_direction_the_whole_series_does_not_support).
   A direction word is kept only when it holds for the WHOLE series, not
   just its ends: every step between consecutive points has to agree (a tie
   does not break it). When the points disagree about direction, this names
   the peak or trough the endpoints alone would hide instead of forcing a
   false "rising"/"falling" on data that went both ways -- a spike that was
   fixed, or a dip that crept back up, is the single most useful thing this
   line can say. */
function secBranchTrendText(trend){
  const pts = trend || [];
  if(!pts.length) return "No analyses of this branch in the last 30 days.";
  // A `capped` point is a PARTIAL read: its `open` count is what that run had
  // found before it stopped, not what was there. A direction word read across
  // one is a claim about the CODE made from a fact about the RUN -- "falling"
  // off an analysis that simply ran out of room before finding anything. So
  // the numbers still get shown (they are what was recorded, and hiding them
  // would be its own lie) and the direction is withheld, the same way this
  // function already withholds one from a series that went both ways.
  const partial = pts.some(p => p.state === "capped");
  if(pts.length === 1){
    return pts[0].open + " open — only one analysis in the last 30 days, "
      + "nothing yet to compare it against."
      + (partial ? " It stopped early, so that count is what it reached." : "");
  }
  const opens = pts.map(p => p.open);
  const first = opens[0], last = opens[opens.length - 1];
  const base = first + " → " + last + " open across " + pts.length
    + " analyses in the last 30 days";
  if(partial){
    return base + ", but at least one of them stopped before covering the "
      + "whole scope — no direction is claimed across a partial read";
  }

  let direction = "flat";
  for(let i = 1; i < opens.length; i++){
    const step = opens[i] < opens[i - 1] ? "falling"
               : opens[i] > opens[i - 1] ? "rising" : "flat";
    if(step === "flat") continue;
    if(direction === "flat") direction = step;
    else if(direction !== step){ direction = null; break; }
  }
  if(direction) return base + " (" + direction + ")";

  // Not monotonic: the endpoints alone would misdescribe what happened in
  // between. Name whichever of the peak/trough goes further than BOTH
  // endpoints -- the fact the direction word cannot say.
  const peak = Math.max(...opens), trough = Math.min(...opens);
  if(peak > first && peak > last) return base + ", peaked at " + peak;
  if(trough < first && trough < last) return base + ", dipped to " + trough;
  return base;
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
  if(r.state === "capped"){
    const badge = secEl("span", "secidx-capped", "incomplete");
    badge.title = BRANCH_CAPPED_TITLE;
    tdOpen.appendChild(badge);
  }
  tr.appendChild(tdOpen);

  // The state the row's posture was actually read from, in its own column --
  // not only as a badge, so a reader scanning the table can see at a glance
  // which branches were read whole and which were not.
  tr.appendChild(cell(r.state || "—"));

  tr.appendChild(cell(secBranchTrendText(r.trend)));
  return tr;
}

function secBranchesTable(rows, attempted){
  if(!rows.length){
    // The same distinction secRenderProjectOverview already draws for this
    // project's one default branch (see its own `ov.attempted` comment in
    // project-screen.js), applied here instead of collapsing back into one
    // sentence: a project whose every analysis failed must not read exactly
    // like one that has never been touched, or this tab contradicts the
    // Overview tab one click away over the identical project.
    return secEl("div", "tblempty",
      attempted ? SEC_NEVER.attempted : SEC_NEVER.next);
  }
  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Branch", "Last analysis", "Analyses", "Open", "Last state", "Trend (30d)"].forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    if(h === "Last state"){
      th.title = "The state of the analysis this row's Open posture was read "
        + "from. `capped` means it stopped before covering the whole scope, "
        + "so those counts are what it reached, not what is there.";
    }
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
  const tabs = (payload || {}).tabs || {};
  const rows = tabs.branches || [];
  // `tabs.overview.attempted` is the identical flag secRenderProjectOverview
  // already receives in the SAME payload -- true the moment any analysis of
  // this project exists, in any state. Threaded through here so the empty
  // state below can draw the same never-vs-attempted distinction instead of
  // inventing a third, weaker sentence of its own.
  const attempted = !!(tabs.overview || {}).attempted;
  host.appendChild(secBranchesCaption());
  host.appendChild(secBranchesTable(rows, attempted));
}
