/* The four things every screen in this area builds with.

   secIcon is a thin pass to the page's own icon helper. The icon TABLE lives in
   dashboard.html, and so does the one line that injects its markup — see the
   comment on the rule in vocabulary.js. Keeping the name here means every call
   site reads exactly as it did inside the page. */
import { icon, sessionLost, TOKEN } from "./page.js";

export function secIcon(name){
  return icon(name);
}
export function secEl(tag, cls, text){
  const n = document.createElement(tag);
  if(cls) n.className = cls;
  if(text != null) n.textContent = text;
  return n;
}

export function secFill(select, values, selected){
  select.textContent = "";
  values.forEach(v => {
    const o = document.createElement("option");
    // .value and .textContent, never markup: a branch name is allowed to
    // contain '<', '>' and '&', and a repository chooses it.
    o.value = v; o.textContent = v;
    select.appendChild(o);
  });
  if(selected != null && values.includes(selected)) select.value = selected;
}

export async function secFetch(path){
  const r = await fetch(path, {headers:{"X-CC-Token":TOKEN}});
  // Same two codes /api/data treats as "go back to the login card", for the
  // same reason: a session that ended is a state, not an error to report.
  if(r.status === 401 || r.status === 428){ sessionLost(); throw new Error("signed out"); }
  const j = await r.json().catch(() => null);
  if(!r.ok) throw new Error((j && (j.error || j.output)) || ("HTTP " + r.status));
  return j;
}
