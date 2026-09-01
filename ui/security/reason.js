/* --------------------------------------------------- the reason dialog */
import { $ } from "./page.js";
import { secIcon, secEl } from "./dom.js";

let _srResolve = null;
export function secAskReason(label, title){
  $("sr-title").textContent = label;
  $("sr-sub").textContent = title || "";
  $("sr-why").value = "";
  $("sr-err").hidden = true;
  $("secreason").showModal();
  return new Promise(res => { _srResolve = res; });
}
function secReasonDone(value){
  $("secreason").close();
  if(_srResolve){ _srResolve(value); _srResolve = null; }
}

/* The listeners ran at the point this code was reached inside dashboard.html's
   one <script>. Out here the module body is evaluated before the page's script
   has run at all — there is no `$` yet, let alone a #secreason — so they are
   wired from init() instead, at the same point in the same order. */
export function wireReasonDialog(){
  $("sr-cancel").addEventListener("click", () => secReasonDone(null));
  $("secreason").addEventListener("cancel", (e) => { e.preventDefault(); secReasonDone(null); });
  $("sr-ok").addEventListener("click", () => {
    const v = $("sr-why").value.trim();
    if(!v){
      // Beside the field that is empty, not in a toast on the other side of the
      // screen and not as a 400 after the dialog has already closed.
      const err = $("sr-err");
      err.textContent = "";
      err.appendChild(secIcon("alert"));
      err.appendChild(secEl("span", null, "A decision needs a reason."));
      err.hidden = false;
      $("sr-why").focus();
      return;
    }
    secReasonDone(v);
  });
  $("sr-why").addEventListener("input", () => { $("sr-err").hidden = true; });
}
