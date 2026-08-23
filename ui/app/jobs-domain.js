/* -------------------------------------------------------------- jobs domain

   jobFacts and visibleJobs are the arithmetic the Overview's cards and the
   Jobs table both read: what state a job is in, when it next runs, whether
   its budget is capped, how far backoff has stretched its interval. Moving
   only the Overview's screens would leave this domain duplicated until the
   table followed in a later phase -- so it moves whole, here, and the table
   becomes its second consumer later. */
import { CC, $, eff, backoffMultiplier, activeRunsOf, renderJobs } from "./page.js";

/* One object rather than three module-level `let`s. Three bindings can only
   be read across a module boundary by exporting three getters and three
   setters; an object is read and written through the same reference from
   either side, which is what the page's toolbar and this module both need. */
export const jobFilters = { project: "", status: "", query: "" };

// Mirrors in_window() in the bash engine: is NOW inside the job's active window?
// Same rules — active_days is 1=Mon..7=Sun, active_hours is "HH:MM-HH:MM" and
// may cross midnight; an empty/absent value means "no restriction".
export function inWindow(j, when){
  const now=when||new Date();
  const days=j.active_days;
  if(Array.isArray(days) && days.length){
    const dow=now.getDay()===0?7:now.getDay();   // JS 0=Sun → 7
    if(!days.map(Number).includes(dow)) return false;
  }
  const hours=j.active_hours;
  if(hours && /^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/.test(hours)){
    const [a,b]=hours.split("-");
    const toMin=(s)=>{ const [h,m]=s.split(":").map(Number); return h*60+m; };
    const s=toMin(a), e=toMin(b), nowMin=now.getHours()*60+now.getMinutes();
    if(s<=e){ if(!(nowMin>=s && nowMin<e)) return false; }
    else { if(!(nowMin>=s || nowMin<e)) return false; }   // window crosses midnight
  }
  return true;
}

// When the next precheck will actually happen. The tick skips any job outside
// its window (in_window is checked BEFORE the precheck), so "last + interval" is
// wrong once that lands outside the schedule — the real answer is when the
// window next opens. Returns epoch seconds, or null if nothing fits in 8 days.
export function nextCheckAt(j, fromEpoch){
  const from=new Date(fromEpoch*1000);
  if(inWindow(j, from)) return fromEpoch;
  const days=(Array.isArray(j.active_days)&&j.active_days.length)?j.active_days.map(Number):null;
  const hours=(j.active_hours && /^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/.test(j.active_hours))?j.active_hours:null;
  const [oh,om]=(hours?hours.split("-")[0]:"00:00").split(":").map(Number);
  for(let i=0;i<=8;i++){
    const c=new Date(from); c.setDate(c.getDate()+i); c.setHours(oh,om,0,0);
    if(c.getTime()<from.getTime()) continue;      // that day's opening already passed
    const dow=c.getDay()===0?7:c.getDay();
    if(days && !days.includes(dow)) continue;
    return Math.floor(c.getTime()/1000);
  }
  return null;
}

/* Everything about one job that is read rather than configured. Extracted so the
   card and the table cannot drift: they are two renderings of one set of facts,
   and a "next check" that differed between them would be a bug nobody could see
   without opening both at once. */
export function jobFacts(j){
  const t0=Math.floor(new Date().setHours(0,0,0,0)/1000);
  const st=CC.DATA.state[j.id]||{}, disabled=j.enabled===false;
  const chk=(CC.DATA.checks||{})[j.id]||{checks:0,runs:0};
  const spentToday=CC.DATA.runs.filter(r=>r.id===j.id && r.start>=t0).reduce((a,r)=>a+(r.cost||0),0);
  // Inherited from the project when the job does not set it, exactly as
  // daily_cap_for() does in the engine — reading it from the job alone made a
  // project-level cap invisible here as well as inert there.
  const capRaw=eff(j,"daily_budget_usd",null);
  const cap=(capRaw!=null && capRaw!==""?+capRaw:null);
  const capped=(cap!=null && spentToday>=cap);
  // Due time by interval, then pushed to the next window opening if that falls
  // outside the schedule — so nothing here ever promises a check that cannot
  // run. Repeated failures stretch the interval (see backoff_multiplier in the
  // engine); using anything else would promise a check minutes before the tick
  // will actually take one.
  const streak=+(st.fail_streak||0);
  const backoff=backoffMultiplier(streak);
  const ivEff=(j.interval_seconds||300)*backoff;
  const dueAt=st.last_start?(st.last_start+ivEff):Math.floor(Date.now()/1000);
  const nextAt=nextCheckAt(j, dueAt);
  const nLive=activeRunsOf(j.id).length;
  const running=nLive>0;
  const idle=!disabled && !running && !inWindow(j);
  return {st, chk, disabled, spentToday, cap, capped, streak, backoff, dueAt, nextAt,
          nLive, running, idle,
          state: disabled?"disabled":(running?"running":(idle?"idle":"enabled"))};
}

// The set the Jobs page is showing right now — every filter applied, exactly as
// renderJobs (bin/dashboard.html) applies them, so the top button can never
// reach a job that the current filter has taken off-screen.
export function visibleJobs(){
  let jobs=CC.DATA.jobs||[];
  if(jobFilters.project==="__none__") jobs=jobs.filter(j=>!j.project);
  else if(jobFilters.project) jobs=jobs.filter(j=>j.project===jobFilters.project);
  if(jobFilters.status==="enabled") jobs=jobs.filter(j=>j.enabled!==false);
  else if(jobFilters.status==="disabled") jobs=jobs.filter(j=>j.enabled===false);
  const q=jobFilters.query.trim().toLowerCase();
  if(q) jobs=jobs.filter(j=>
    (j.id+" "+(j.description||"")+" "+(j.project||"")).toLowerCase().includes(q));
  return jobs;
}

// Direction of the switch: while ANY job in the set is still on, the button
// turns them off; it only offers to turn them on once every one is off. Same
// defaulting as the engine — a job with no `enabled` key is enabled.
export function bulkOn(js){ return js.some(j=>j.enabled!==false); }

// Single source for the button phrasing, with or without a trailing count —
// used by bulkBtn's group buttons (no count; the pgh-count badge already
// shows one) and by the #bulk-all block in bin/dashboard.html's renderJobs
// (count, since "all" is ambiguous while a chip filter is on).
export function bulkLabel(on, n){ return (on?"Disable all":"Enable all")+(n===undefined?"":" "+n); }

export function clearJobFilters(){
  jobFilters.project=jobFilters.status=jobFilters.query="";
  $("jq").value=""; $("jq-clear").hidden=true;
  renderJobs();
}

export function jobProjectNames(){
  return [...new Set((CC.DATA.jobs||[]).map(j=>j.project||"").filter(Boolean))].sort();
}

/* ------------------------------------------------------------- jobs as a table
   The same set the cards show, for when jobs are what you came for rather than
   something you are glancing at. Deliberately narrow: a card can afford a
   sparkline, a probe verdict and nine settings; a table row that tried would be
   unreadable at twenty rows, which is the only size where a table wins. What is
   here is what you sort or scan by — everything else is one click into Edit.
   Moved out of bin/dashboard.html's renderJobTable, unchanged: the table is
   this module's second consumer, not yet a rewrite of what it sorts by. */
export const JOB_COLS = [
  ["job","Job"],["project","Project"],["state","Status"],[null,"Schedule"],
  ["last","Last run"],["next","Next"],["today","Today"],[null,""],
];
// Worst-first when sorting by status: disabled and idle are the two you are
// looking for, and "enabled" is the state of everything you are not.
const STATE_RANK = {running:0, enabled:1, idle:2, disabled:3};
// `missing` is the rows the column has no answer for — a job that has never run
// has no "last run", a disabled one has no "next". They sort to the BOTTOM
// whichever way the arrow points, because "never" is neither early nor late:
// treating it as a very large number is what put seventeen disabled jobs above
// the ones actually due the moment you reversed the column.
const JOB_SORTERS = {
  job:{cmp:(a,b)=>String(a.j.id).localeCompare(String(b.j.id))},
  // Within a project the jobs stay A→Z whichever way the column points: you sort
  // by project to read one project's jobs together, not to scramble them.
  project:{cmp:(a,b)=>String(a.j.project).localeCompare(String(b.j.project)),
           tie:(a,b)=>String(a.j.id).localeCompare(String(b.j.id)),
           missing:(x)=>!x.j.project},
  state:{cmp:(a,b)=>(STATE_RANK[a.F.state]-STATE_RANK[b.F.state])
                    || String(a.j.id).localeCompare(String(b.j.id))},
  last:{cmp:(a,b)=>(a.F.st.last_run_start-b.F.st.last_run_start),
        missing:(x)=>!x.F.st.last_run_start},
  next:{cmp:(a,b)=>(a.F.nextAt-b.F.nextAt),
        missing:(x)=>x.F.disabled || x.F.nextAt==null},
  today:{cmp:(a,b)=>(a.F.spentToday-b.F.spentToday)},
};

// Orders one column's worth of `{j, F}` rows exactly as renderJobTable
// (bin/dashboard.html) built the sort inline: rows the column has an answer
// for, sorted by that column and tie-broken by id -- the tiebreak deliberately
// NOT reversed with `dir`, see JOB_SORTERS' own `project` comment -- then rows
// it has none for, appended in id order regardless of `dir` (see the `missing`
// comment above JOB_SORTERS).
export function sortJobs(rows, key, dir){
  const S=JOB_SORTERS[key]||JOB_SORTERS.job;
  const have=[], none=[];
  rows.forEach(x => ((S.missing && S.missing(x)) ? none : have).push(x));
  have.sort((a,b)=>(S.cmp(a,b)*dir) || (S.tie ? S.tie(a,b) : 0));
  none.sort((a,b)=>String(a.j.id).localeCompare(String(b.j.id)));
  return have.concat(none);
}
