/* The things every screen in this area builds with.

   secIcon is a thin pass to the page's own icon helper. The icon TABLE lives in
   dashboard.html, and so does the one line that injects its markup — see the
   comment on the rule in vocabulary.js. Keeping the name here means every call
   site reads exactly as it did inside the page.

   secIconHTML (Phase 4 Task 5) is the same table read a different way: the
   raw markup STRING for one entry, not an element wrapping it, for
   makePicker's own cfg.icon/row.icon (bin/dashboard.html's paintTrigger/
   paintList concatenate it into a trigger/row's own markup string, the same
   shape every other picker's cfg already passes). Reading the string back
   out of secIcon(name)'s own returned element would spell, bare, the one DOM
   property name this file's own sink guard (tests/test_page_contract.py)
   bans from every module under ui/ -- a READ is exactly as invisible to that
   guard's plain substring check as a write, and correctly so, since nothing
   there can tell code from prose. page.js's own comment on the bridge has
   the rest.

   secFill used to be a third thing here: it populated a bare <select> with
   .value/.textContent options, never markup, because a branch name is
   allowed to contain '<', '>' and '&' and a repository chooses it. Phase 4
   Task 5 converted its last three callers (sec-repo/sec-branch, both in
   analysis.js) to the house combo -- createCombo's own .set(value, options)
   takes an array of {v, label} instead, so this file no longer has a
   <select> left to feed. The text-not-markup rule it existed to keep still
   holds: every {v, label} this area builds now (see analysis.js and
   index-screen.js's own picker rows) is still .value/.textContent under
   createCombo/makePicker's own escaping, never a template string handed to
   the HTML parser. */
import { icon, iconHTML, sessionLost, TOKEN } from "./page.js";

export function secIcon(name){
  return icon(name);
}
export function secIconHTML(name){
  return iconHTML(name);
}
export function secEl(tag, cls, text){
  const n = document.createElement(tag);
  if(cls) n.className = cls;
  if(text != null) n.textContent = text;
  return n;
}

export async function secFetch(path){
  const r = await fetch(path, {headers:{"X-AL-Token":TOKEN}});
  // Same two codes /api/data treats as "go back to the login card", for the
  // same reason: a session that ended is a state, not an error to report.
  if(r.status === 401 || r.status === 428){ sessionLost(); throw new Error("signed out"); }
  const j = await r.json().catch(() => null);
  if(!r.ok) throw new Error((j && (j.error || j.output)) || ("HTTP " + r.status));
  return j;
}
