/* ---------------------------------------------------------------- projects

   visibleProjects() and the isolation read are the two pieces Phase 2 Task 4's
   characterisation tests need without a DOM -- moved here verbatim from
   bin/dashboard.html's module-level visibleProjects() and the isolation
   ternary renderProjects() used to build inline, the same "extract the pure
   arithmetic first, move the table around it later" split Task 2 already
   used for the Jobs table (see jobs-domain.js's own banner comment). Task 5
   builds the restyled table -- and its own Security column -- around these;
   this task only relocates what renderProjects() already computed, so a
   characterisation test can read it without pulling the whole page in.

   projFilters mirrors jobFilters (ui/app/jobs-domain.js): a single exported
   object rather than a bare `let`, because an ES module cannot let an
   importer reassign a plain binding -- see jobs-domain.js's own comment on
   why jobFilters takes this shape. Projects has one filter today (free-text
   search), so the object holds one key instead of three; it grows the same
   way jobFilters would if a project-page dropdown were ever added. */
import { CC } from "./page.js";

export const projFilters = { query: "" };

// The set Projects is showing right now -- every project, annotated with the
// job count and repo count its own row needs, filtered by the search box.
// `_jobs` counts only jobs that name THIS project: counting every job
// regardless of project is Task 4's own named break -- a project with none
// of its own would otherwise inherit a count that belongs to the whole
// fleet. The search reaches the name, the description AND the working
// directory -- a project remembered by its folder, or by a phrase in its
// own description, has to surface just as reliably as one matched by name.
export function visibleProjects(){
  const jobs = CC.DATA.jobs || [];
  const q = projFilters.query.trim().toLowerCase();
  return (CC.DATA.projects || [])
    .map(p => Object.assign({}, p, {_jobs: jobs.filter(j => j.project === p.name).length,
                                     _repos: (p.repos || []).length}))
    .filter(p => !q || (p.name + " " + (p.description || "") + " " + (p.cwd || ""))
      .toLowerCase().includes(q));
}

// Three states, not two: a project can run every job in its own worktree
// (`true`), never (`false`), or leave it to the engine to decide per job --
// "automatic", which is also what a project with no `worktree` block at all
// gets, and what a hand-edited config's literal string "auto" gets too (see
// config/projects.json). Collapsing "automatic" into either of the other two
// is Task 4's own named break: an "auto" project is not permanently isolated
// OR permanently not, and painting it as either would tell an operator
// something the engine does not actually do with it.
export function projectIsolation(p){
  const wt = p.worktree && p.worktree.enabled;
  return (wt === true || wt === "true") ? ["on", "always"]
       : (wt === false || wt === "false") ? ["off", "never"]
       : ["auto", "auto"];
}
