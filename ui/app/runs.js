/* ----------------------------------------------------------------- runs

   The pure filter/sort arithmetic behind the Runs table, extracted ahead of
   the table's own move into this module (Phase 2 Task 7) so Task 6's
   characterisation tests can read it without a DOM -- the same "extract the
   pure arithmetic first, move the table around it later" split Task 2
   (ui/app/jobs-domain.js) and Task 4 (ui/app/projects.js) already used.

   Unlike jobFilters/projFilters, the filter state itself (`RF` in
   bin/dashboard.html) does NOT move here yet. jobFilters and projFilters
   each had one or three call sites reading them outside their own table;
   RF has five fields read from FOUR picker call sites apiece -- around forty
   references in bin/dashboard.html today. Relocating its ownership now would
   be a page-wide rename with no testing benefit, since none of Task 6's four
   tests are about who OWNS the filter values, only about what the algorithm
   does with them. filteredRuns() below therefore takes the filter object as
   its own first argument (`rf`) instead of closing over a module-owned
   singleton. Task 7, which rebuilds the whole page, is the natural point to
   finish that move -- the same way PRJ_COLS and prjSortKey/prjSortDir stayed
   in bin/dashboard.html through Task 4 and only moved in Task 5 (see that
   commit's own CHANGELOG entry).

   RUN_COLS and the sort-state (`sortKey`/`sortDir`) stay in bin/dashboard.html
   for the same reason -- test_the_jobs_and_projects_tables_declare_a_width_
   for_every_column (tests/test_page_contract.py) only needs RUN_COLS here
   once Runs gains its own tableCard() call in Task 7, and neither is read by
   any of Task 6's own four tests.

   normStatus is not here either: bin/dashboard.html's one copy is used by
   the log modal and the resume tooltip as well as this table, so it is not
   this task's to relocate -- it now travels through page.js's shared
   interface instead (see that file's own comment), the same as
   backoffMultiplier/activeRunsOf do for jobFacts. */
import { CC, normStatus } from "./page.js";

// Column sort. `when` descending is the default and the only order in which
// a live run belongs at the top, so live rows keep their place there and are
// sorted with everything else under any other key. Duration and cost are
// SEPARATE comparators because they answer different questions -- "what is
// slow" and "what is expensive" are rarely the same run. They used to be
// merged into one column, which silently dropped the cost sort: the
// comparator still existed, but no header could reach it, so the most
// expensive run of a day became unfindable in a 25-row page --
// test_duration_and_cost_sort_independently (tests/test_page_contract.py)
// pins the two staying apart.
export const SORTERS = {
  when:(a,b)=>a.start-b.start,
  job:(a,b)=>String(a.id).localeCompare(String(b.id)) || a.start-b.start,
  status:(a,b)=>String(a.live?"running":normStatus(a.status))
                  .localeCompare(String(b.live?"running":normStatus(b.status))) || a.start-b.start,
  cost:(a,b)=>((a.cost||0)-(b.cost||0)) || a.start-b.start,
  duration:(a,b)=>((a.duration||0)-(b.duration||0)) || a.start-b.start,
};

// The set the Runs table is showing right now: live rows and journaled runs
// merged, both filtered by `rf`, re-sorted only when the caller asked for
// something other than the default "newest first" -- the default order is
// already what the query produced. Moved out of bin/dashboard.html's own
// filteredRuns(), unchanged in substance: `rf`, `liveRows`, `searchKeys`,
// `sortKey` and `sortDir` were module-level reads there and are explicit
// parameters here instead, for the reason this file's own banner comment
// gives for RF not moving yet.
export function filteredRuns(rf, liveRows, searchKeys, sortKey, sortDir){
  const fromT=rf.from?Date.parse(rf.from):null, toT=rf.to?Date.parse(rf.to):null;
  // live rows first -- a search narrows to indexed runs, so they drop out here
  const live=searchKeys?[]:liveRows;
  const rows=live.concat(CC.DATA.runs).filter(r=>{
    if(r.live){
      if(rf.project){ const rp=r.project||""; if(rf.project==="__none__" ? rp!=="" : rp!==rf.project) return false; }
      if(rf.job && r.id!==rf.job) return false;
      if(rf.status && rf.status!=="running") return false;
      return true;
    }
    // Trusts the server's own search results as-is: /api/search's index
    // covers a run's log content as well as its id, so a run matched purely
    // by something said IN its log has to surface here just as reliably as
    // one matched by name -- re-checking the id against the query text would
    // undo exactly that on the client, the regression
    // test_a_run_matched_only_in_its_log_content_still_surfaces
    // (tests/test_page_contract.py) pins against.
    if(searchKeys && !searchKeys.has(r.id+"|"+r.start)) return false;
    if(rf.project){ const rp=r.project||""; if(rf.project==="__none__" ? rp!=="" : rp!==rf.project) return false; }
    if(rf.job && r.id!==rf.job) return false;
    if(rf.status && normStatus(r.status)!==rf.status) return false;
    const t=r.start*1000;
    if(fromT && t<fromT) return false;
    if(toT && t>toT) return false;
    return true;
  });
  // The default order is already what the query produced, so only re-sort when
  // the user has actually asked for something else.
  if(sortKey!=="when" || sortDir!==-1){
    const cmp=SORTERS[sortKey]||SORTERS.when;
    rows.sort((a,b)=>cmp(a,b)*sortDir);
  }
  return rows;
}
