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
// renderJobs applies them below, so the top button can never reach a job that
// the current filter has taken off-screen.
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
// shows one) and by the #bulk-all block below (count, since "all" is
// ambiguous while a chip filter is on).
export function bulkLabel(on, n){ return (on?"Disable all":"Enable all")+(n===undefined?"":" "+n); }

export function clearJobFilters(){
  jobFilters.project=jobFilters.status=jobFilters.query="";
  $("jq").value=""; $("jq-clear").hidden=true;
  renderJobs();
}

export function jobProjectNames(){
  return [...new Set((CC.DATA.jobs||[]).map(j=>j.project||"").filter(Boolean))].sort();
}
