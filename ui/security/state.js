/* The one project screen's state, in a file that imports nothing.

   Three modules read and write it — the screen itself, its history list and its
   actions — and they refer to each other in a cycle, which is fine for function
   declarations and not fine for a `const` somebody might touch while the
   bundle's modules are still being evaluated. With no imports of its own this
   file is always evaluated first, so the object exists before anything can look
   for it. */
/* `pinned` is whether the analysis on screen was opened DELIBERATELY (a Runs
   row, an "#N" in the history list, the Activity screen's deep link) rather
   than resolved from the picker. It lives here, beside `analysis`, because it
   is a fact about the screen that both analysis.js (which decides what the
   poll may replace) and its own opener have to agree on -- see
   secShowAnalysis's comment for what it costs to not have it. */
export const secState = {project:"", repo:"", branch:"", analyses:[], analysis:null,
                  findings:[], stateFilter:"", seq:0, pinned:false};
