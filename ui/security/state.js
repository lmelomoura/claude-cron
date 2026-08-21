/* The one project screen's state, in a file that imports nothing.

   Three modules read and write it — the screen itself, its history list and its
   actions — and they refer to each other in a cycle, which is fine for function
   declarations and not fine for a `const` somebody might touch while the
   bundle's modules are still being evaluated. With no imports of its own this
   file is always evaluated first, so the object exists before anything can look
   for it. */
export const secState = {project:"", repo:"", branch:"", analyses:[], analysis:null,
                  findings:[], stateFilter:"", seq:0};
