/* ------------------------------------------------------------ editor domain

   The job editor and the project editor share one wizard (makeWizard,
   bin/dashboard.html) for their dual-mode navigation and dirty tracking, and
   each owns a handful of small form<->job mappings and a per-step validation
   rule. Every one of those reads $("...") or `document` directly today,
   which is exactly what a characterisation test cannot drive without a
   browser -- so only the DOM-free half of each moved here: the comparison,
   the mapping, the rule. The DOM read that feeds it (the snapshot itself,
   the day buttons, the repo rows, the slider's raw value, the fields
   validation reads) stays exactly where it was, in bin/dashboard.html, which
   now calls back in by name.

   Nothing here touches $, document or AL.DATA -- every export takes plain
   values and returns plain values, so this module needs nothing from
   ./page.js and nothing bindPage() sets up. */

// Two snapshots of one wizard (makeWizard's own W.snapshot()) -- which keys
// disagree between them. Compared key by key, never the two container
// objects themselves: snapshot() builds a fresh object on every call, so two
// snapshots holding identical values are never `===`, and a reference
// comparison here would report the form dirty the instant a second one was
// taken, even an untouched one. edWiz/pjWiz's own W.changed() (dirtySteps'
// own source) and W.dirty() (edIsDirty) both read this -- one true
// implementation of "what changed" for both.
export function changedKeys(now, clean){
  return Object.keys(now).filter(k => now[k] !== clean[k]);
}

// Effort: slider position <-> CLI value. 0 leaves it unset (the CLI
// decides). Slider stops, in order -- the job editor's "ed-effort" and the
// project editor's Security pane's "sec-effort" are one control (effortSet/
// effortGet, bin/dashboard.html), so a level moved to the wrong index here
// is a level silently renamed everywhere the slider is shown.
export const EFFORTS = ["", "low", "medium", "high", "xhigh", "max"];

// A job's effort string -> the slider index that represents it. An
// empty/unrecognised value settles on 0 (unset), never -1.
export function effortIndex(v){
  return Math.max(0, EFFORTS.indexOf(v || ""));
}

// The slider's own raw (string) value -> the job's effort string. An
// out-of-range index settles on "" (unset), the same as 0 does.
export function effortFromIndex(raw){
  return EFFORTS[+raw || 0] || "";
}

// The "on" day buttons' own dataset.day strings (already read off the DOM by
// getDays, bin/dashboard.html) -> the numbers a job's active_days is stored
// as.
export function dayNumbers(rawValues){
  return rawValues.map(v => +v);
}

// One raw repo row (untrimmed .value strings straight off the DOM) -> the
// {name,path,base} shape the rest of the project editor works with, dropping
// a row missing its name or its path. Such a row is not "malformed" so much
// as not filled in yet -- collectRepos (bin/dashboard.html) has always
// dropped it before anything downstream, including validateProjectStep's own
// "repos" rule below, ever saw it.
export function shapeRepoRows(rawRows){
  return rawRows
    .map(r => ({ name: r.name.trim(), path: r.path.trim(), base: r.base.trim() }))
    .filter(r => r.name && r.path);
}

// validateProjectStep's (bin/dashboard.html) own rules -- given what a step's
// fields hold, is it complete enough to move past? Extracted whole: same
// conditions, same messages, in the same order, only turned from
// "return the reason, or null" into a verdict, since a pure decision
// answering a question is what this is. The DOM reads that gather `values`
// (pj-name, pj-cwd, editingProject, DATA.projects, pjMulti, collectRepos())
// stay in validateProjectStep itself.
export function projectStepError(k, values){
  if(k === "project"){
    const n = values.name;
    if(!n) return { ok: false, message: "A project name is required." };
    // Creating only: renaming onto an existing name is the engine's to
    // refuse, and it knows about jobs pointing at both.
    if(!values.editingProject && values.projects.some(p => p.name === n))
      return { ok: false, message: "A project with that name already exists." };
    if(!values.cwd)
      return { ok: false, message: "Pick a working directory — the folder its runs work in." };
  }
  // The engine picks the repo the agent starts in by matching a row's path
  // against the cwd, and aborts the run when none does. That used to
  // surface hours later as a run that failed for no stated reason; catch it
  // here, where the two paths are both on screen.
  if(k === "repos" && values.multi){
    const rows = values.repos;
    if(!rows.length)
      return { ok: false, message: "Add a repository, or go back to a single repository." };
    if(!rows.some(r => r.path === values.cwd))
      return { ok: false, message: "One repo's path must be exactly the working directory from step 1 — "
             + "that is the repo the agent starts in. None of these match it." };
  }
  return { ok: true };
}
