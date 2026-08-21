/* ------------------------------------------------------- findings browser
   Every finding of one project, in one filterable, paginated table --
   `GET /api/security/findings` (bin/claude-cron-server's `security_findings`,
   bin/security/cli.py's `findings-page`), which is `queries.finding_rows`
   (Task 6) itself: a checklist per branch -- the latest finished analysis of
   each -- unioned, so the state a row shows is the state that branch's own
   newest analysis gives the finding, never a recomputed one. Sorting,
   filtering and paging all happen on the server; this module never re-derives
   any of it client-side.

   ONE MODULE, TWO HOMES. `renderFindings(host, project)` is the whole surface:
   `project-screen.js` mounts it into its Findings tab pane
   (`#sec-pj-findings`), and it is written to make no assumption about WHERE
   `host` lives or who else is on screen beside it -- no read of `secState`,
   no reach into `secProjectCache`. A future caller (the Activity screen's own
   plan is to link a fingerprint prefix straight into "the findings browser
   filtered to it") mounts the identical function into whatever container it
   owns, without a second copy of a filterable table to drift the way a
   duplicated download function, and a duplicated state machine before it,
   already have (see reports-tab.js's own comment on secDownloadReport, and
   queries.py's on checklist()).

   `total` vs `unique`: the strip shows both, labelled, because they answer
   different questions -- the same finding open on two branches is one row
   each time it is open (`total`) but one problem (`unique`, distinct
   fingerprints). 189 findings can be 93 problems; collapsing the two into one
   number would silently answer whichever question the reader was not asking.

   The severity floor (`min_severity`) is DISPLAY-ONLY and lives entirely in
   this file -- the server's `by_severity`/`total`/`unique` describe every row
   the current FILTERS match, never narrowed by the floor, so the count of
   what the floor hides is exact across every page, not just the one on
   screen. Two things this screen says out loud, per the brief: how many rows
   the floor is hiding and why (a missing number is otherwise indistinguishable
   from one that was never found), and that downloads always carry every
   recorded finding regardless of what the floor shows here -- the identical
   sentence index.js's `#sec-dl-note` and reports-tab.js's own caption already
   give, so a reader moving between screens learns it once.

   Module-level state, like project-screen.js's own secProjectCache/
   secProjectTab -- a deliberate simplification, not an oversight: nothing in
   this codebase mounts two instances of one screen at once, so a single set
   of module-level variables (rather than state keyed by `host`) is the same
   choice every sibling screen in this area already makes. Switching to a
   DIFFERENT project resets every transient control (filters, sort, page, the
   saved-filter picker); switching away and back to the SAME project's
   Findings tab keeps them, the same as every other tab on this screen. */
import { api, toast, fmtWhen } from "./page.js";
import { secEl, secIcon, secFetch } from "./dom.js";
import { SEC_STATES, SEC_STATE_LABEL, SEC_STATE_HELP, SEV_ORDER,
         secMinSeverity, secSevRank, secSevKey, secStateKey } from "./vocabulary.js";
import { secAskReason } from "./reason.js";
import { secInvalidateProject } from "./project-screen.js";

// Mirrors bin/security/queries.py's SORTABLE, and bin/claude-cron-server's
// FINDING_CATEGORIES -- duplicated here, not fetched, because the filter bar
// has to draw its own options before any request has ever answered. Kept in
// step by hand, the same duplication every edge in this area already carries
// (see claude-cron-server's own comment on FINDING_SEVERITIES/FINDING_STATES/
// FINDING_CATEGORIES for why a value the server already validates is still
// named again here).
const FIND_SORT_COLUMNS = [
  ["severity", "Severity"], ["title", "Title"], ["category", "Category"],
  ["branch", "Branch"], ["first_seen", "First seen"], ["state", "State"],
];
const FIND_CATEGORIES = ["secret", "dependency", "sast", "hygiene"];
const FIND_PER_PAGE = 25;

function _defaultFilters(){
  return {severity: [], state: [], category: [], branch: "", path: "", q: "",
          analysis: "", show_resolved: false};
}

let secFindHost = null;
let secFindProject = "";
let secFindGen = 0;
let secFindData = null;
let secFindError = "";
let secFindFilters = _defaultFilters();
let secFindSort = "severity";
let secFindDir = "desc";
let secFindPage = 1;
let secFindSavedName = "";
let secFindNewName = "";

/* The one exported entry point -- see this file's own comment. */
export async function renderFindings(host, project){
  if(secFindProject !== project){
    secFindProject = project;
    secFindFilters = _defaultFilters();
    secFindSort = "severity"; secFindDir = "desc"; secFindPage = 1;
    secFindSavedName = ""; secFindNewName = "";
    secFindData = null; secFindError = "";
  }
  secFindHost = host;
  await secFindLoad();
}

function secFindQuery(){
  const p = new URLSearchParams();
  p.set("project", secFindProject);
  p.set("sort", secFindSort);
  p.set("dir", secFindDir);
  p.set("page", String(secFindPage));
  p.set("per_page", String(FIND_PER_PAGE));
  const f = secFindFilters;
  if(f.severity.length) p.set("severity", f.severity.join(","));
  if(f.state.length) p.set("state", f.state.join(","));
  if(f.category.length) p.set("category", f.category.join(","));
  if(f.branch.trim()) p.set("branch", f.branch.trim());
  if(f.path.trim()) p.set("path", f.path.trim());
  if(f.q.trim()) p.set("q", f.q.trim());
  if(f.analysis.trim()) p.set("analysis", f.analysis.trim());
  if(f.show_resolved) p.set("show_resolved", "1");
  return p.toString();
}

async function secFindLoad(){
  const host = secFindHost, project = secFindProject;
  if(!host || !project) return;
  const gen = ++secFindGen;
  // No "Loading…" flash on a filter/sort/page change or a poll-driven
  // refresh -- only on the very first fetch for this project, the same
  // no-flicker rule secLoadIndex already follows for its own cache.
  if(!secFindData){
    host.textContent = "";
    host.appendChild(secEl("div", "tblempty", "Loading…"));
  }
  let data;
  try{
    data = await secFetch("/api/security/findings?" + secFindQuery());
  }catch(e){
    if(gen !== secFindGen || secFindHost !== host || secFindProject !== project) return;
    secFindError = e.message; secFindData = null;
    secFindPaint();
    return;
  }
  if(gen !== secFindGen || secFindHost !== host || secFindProject !== project) return;
  secFindError = "";
  secFindData = data;
  // A filter change can move the requested page past the end; follow what
  // the server actually served (finding_rows clamps, never invents rows)
  // rather than keep the control pointed at a page whose rows never answer.
  secFindPage = data.page || 1;
  secFindPaint();
}

async function secFindRefresh(){ await secFindLoad(); }

function secFindPaint(){
  const host = secFindHost;
  if(!host) return;
  host.textContent = "";
  if(secFindError){
    const box = secEl("div", "tblempty");
    box.appendChild(secIcon("alert"));
    box.appendChild(document.createTextNode("Could not read findings — " + secFindError));
    host.appendChild(box);
    return;
  }
  const data = secFindData;
  if(!data) return;
  host.appendChild(secFindStrip(data));
  host.appendChild(secFindFilterBar(data));
  host.appendChild(secFindTableSection(data));
  host.appendChild(secFindPager(data));
}

/* ------------------------------------------------------------------ strip
   total, unique issues, and the five severities -- see this file's own
   comment for why total and unique are both shown, labelled, rather than
   collapsed into one number. */
function secFindHiddenByFloor(data, minSeverity){
  const floor = SEV_ORDER.indexOf(minSeverity);
  let n = 0;
  SEV_ORDER.forEach((sev, i) => { if(i < floor) n += (data.by_severity || {})[sev] || 0; });
  return n;
}

function secFindStrip(data){
  const wrap = secEl("div", "sevpills");
  const totalPill = secEl("span", "sevpill", data.total + " total");
  totalPill.title = "Every row matching the current filters — the same finding "
    + "open on two branches counts twice here.";
  wrap.appendChild(totalPill);
  const uniquePill = secEl("span", "sevpill", data.unique + " unique issues");
  uniquePill.title = "Distinct problems (fingerprints) — the same finding open "
    + "on two branches counts once here.";
  wrap.appendChild(uniquePill);
  const bySev = data.by_severity || {};
  let any = false;
  ["critical", "high", "medium", "low", "info"].forEach(sev => {
    if(bySev[sev]){ any = true; wrap.appendChild(secEl("span", "sevpill " + sev, bySev[sev] + " " + sev)); }
  });
  if(!any) wrap.appendChild(secEl("span", "sevpill clean", "nothing matches"));

  const minSeverity = secMinSeverity(secFindProject);
  const hidden = secFindHiddenByFloor(data, minSeverity);
  const note = secEl("div", "secpj-caption");
  if(hidden > 0){
    note.appendChild(document.createTextNode(
      hidden + " finding" + (hidden === 1 ? "" : "s") + " below " + minSeverity
      + " " + (hidden === 1 ? "is" : "are")
      + " hidden by this project's severity floor — recorded, not shown. "));
  }
  note.appendChild(secEl("b", null,
    "Downloads always contain every recorded finding, whatever the severity floor shows."));

  const box = secEl("div", "secfind-strip");
  box.appendChild(wrap);
  box.appendChild(note);
  return box;
}

/* -------------------------------------------------------------- filter bar
   Severity, state and category as toggle chips (secchip/secchips, the same
   pattern secRunsFilters/secRenderChecklist already use elsewhere on this
   screen); branch, path, analysis and free text as plain fields (secfield/
   secbar, the same furniture the repo/branch/profile picker above already
   uses) -- reusing both rather than inventing a third look for a fourth
   filter row. */
function secFindChips(options, selected, onToggle, labelFor){
  const row = secEl("div", "secchips");
  options.forEach(opt => {
    const chip = secEl("button", "secchip" + (selected.includes(opt) ? " on" : ""));
    chip.type = "button";
    chip.appendChild(secEl("span", null, labelFor ? labelFor(opt) : opt));
    chip.onclick = () => onToggle(opt);
    row.appendChild(chip);
  });
  return row;
}

function secFindChipField(label, chipsRow){
  const field = secEl("div", "secfield");
  field.appendChild(secEl("span", null, label));
  field.appendChild(chipsRow);
  return field;
}

function secFindToggleIn(list, value){
  const i = list.indexOf(value);
  if(i >= 0) list.splice(i, 1); else list.push(value);
}

function secFindSeverityField(){
  return secFindChipField("Severity", secFindChips(
    ["critical", "high", "medium", "low", "info"], secFindFilters.severity,
    (sev) => { secFindToggleIn(secFindFilters.severity, sev); secFindPage = 1; secFindRefresh(); }));
}

function secFindCategoryField(){
  return secFindChipField("Category", secFindChips(
    FIND_CATEGORIES, secFindFilters.category,
    (cat) => { secFindToggleIn(secFindFilters.category, cat); secFindPage = 1; secFindRefresh(); }));
}

function secFindStateField(){
  const row = secFindChips(SEC_STATES, secFindFilters.state,
    (state) => { secFindToggleIn(secFindFilters.state, state); secFindPage = 1; secFindRefresh(); },
    (state) => SEC_STATE_LABEL[state] || state);
  // secFindChips has no notion of a per-option title -- threaded on
  // afterwards, same as every chip helper on this screen sets .title once
  // the element already exists (see secRenderChecklist's identical pattern).
  Array.from(row.childNodes).forEach((chip, i) => { chip.title = SEC_STATE_HELP[SEC_STATES[i]] || ""; });
  return secFindChipField("State", row);
}

function secFindTextField(label, value, onChange){
  const field = secEl("div", "secfield");
  field.appendChild(secEl("span", null, label));
  const inp = document.createElement("input");
  inp.type = "text";
  inp.value = value;
  inp.spellcheck = false;
  inp.autocomplete = "off";
  // change, not input: a fetch per keystroke would be a subprocess per
  // keystroke on the server (see index.js's identical reasoning for
  // #sec-branch-other).
  inp.addEventListener("change", () => onChange(inp.value));
  field.appendChild(inp);
  return field;
}

function secFindShowResolvedField(){
  const field = secEl("div", "secfield");
  field.appendChild(secEl("span", null, "Resolved"));
  const label = document.createElement("label");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = secFindFilters.show_resolved;
  cb.addEventListener("change", () => {
    secFindFilters.show_resolved = cb.checked;
    secFindPage = 1;
    secFindRefresh();
  });
  label.appendChild(cb);
  label.appendChild(document.createTextNode(" Show resolved"));
  field.appendChild(label);
  return field;
}

function secFindClearButton(){
  const btn = secEl("button", "btn ghost", "Clear filters");
  btn.type = "button";
  btn.onclick = () => { secFindFilters = _defaultFilters(); secFindPage = 1; secFindRefresh(); };
  return btn;
}

function secFindCurrentQuery(){
  const f = secFindFilters;
  return {severity: f.severity, state: f.state, category: f.category,
          branch: f.branch, path: f.path, q: f.q, analysis: f.analysis,
          show_resolved: f.show_resolved, sort: secFindSort, dir: secFindDir};
}

function secFindApplyQuery(q){
  const query = q || {};
  secFindFilters = {
    severity: Array.isArray(query.severity) ? query.severity.slice() : [],
    state: Array.isArray(query.state) ? query.state.slice() : [],
    category: Array.isArray(query.category) ? query.category.slice() : [],
    branch: typeof query.branch === "string" ? query.branch : "",
    path: typeof query.path === "string" ? query.path : "",
    q: typeof query.q === "string" ? query.q : "",
    analysis: typeof query.analysis === "string" ? query.analysis : "",
    show_resolved: !!query.show_resolved,
  };
  secFindSort = FIND_SORT_COLUMNS.some(([key]) => key === query.sort) ? query.sort : "severity";
  secFindDir = query.dir === "asc" ? "asc" : "desc";
  secFindPage = 1;
  secFindRefresh();
}

async function secFindSaveCurrent(name){
  const trimmed = (name || "").trim();
  if(!trimmed){ toast("Name this filter set before saving", true); return; }
  const ok = await api("security_filter_save",
    {project: secFindProject, name: trimmed, query: secFindCurrentQuery()});
  if(!ok) return;           // api() has already shown the server's own message
  toast("Filter saved", false, "check");
  secFindSavedName = trimmed;
  secFindNewName = "";
  await secFindRefresh();
}

async function secFindDeleteSaved(name){
  if(!name) return;
  const ok = await api("security_filter_delete", {project: secFindProject, name});
  if(!ok) return;
  toast("Filter deleted", false, "check");
  secFindSavedName = "";
  await secFindRefresh();
}

function secFindSavedFilters(data){
  const bar = secEl("div", "secbar");
  const pickField = secEl("div", "secfield");
  pickField.appendChild(secEl("span", null, "Saved filters"));
  const sel = document.createElement("select");
  const blank = document.createElement("option");
  blank.value = ""; blank.textContent = "— choose —";
  sel.appendChild(blank);
  (data.filters || []).forEach(f => {
    const o = document.createElement("option");
    // .value/.textContent, never markup: a saved filter's name is a string a
    // human typed on this page, but still text a reader did not write, the
    // same rule every other value in this area follows.
    o.value = f.name; o.textContent = f.name;
    sel.appendChild(o);
  });
  if((data.filters || []).some(f => f.name === secFindSavedName)) sel.value = secFindSavedName;
  else secFindSavedName = "";
  sel.addEventListener("change", () => {
    secFindSavedName = sel.value;
    const found = (data.filters || []).find(f => f.name === sel.value);
    if(found) secFindApplyQuery(found.query);
  });
  pickField.appendChild(sel);
  bar.appendChild(pickField);

  const nameField = secEl("div", "secfield");
  nameField.appendChild(secEl("span", null, "Save current as"));
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.placeholder = "name this view";
  nameInput.value = secFindNewName;
  nameInput.addEventListener("change", () => { secFindNewName = nameInput.value; });
  nameField.appendChild(nameInput);
  bar.appendChild(nameField);

  const saveBtn = secEl("button", "btn ghost", "Save");
  saveBtn.type = "button";
  saveBtn.onclick = () => secFindSaveCurrent(nameInput.value);
  bar.appendChild(saveBtn);

  const delBtn = secEl("button", "btn ghost", "Delete");
  delBtn.type = "button";
  delBtn.disabled = !secFindSavedName;
  delBtn.onclick = () => secFindDeleteSaved(secFindSavedName);
  bar.appendChild(delBtn);

  return bar;
}

function secFindFilterBar(data){
  const wrap = document.createElement("div");
  wrap.appendChild(secFindSeverityField());
  wrap.appendChild(secFindStateField());
  wrap.appendChild(secEl("div", "secpj-caption",
    "Fixed, accepted and false-positive rows are excluded unless “Show resolved” is checked."));
  wrap.appendChild(secFindCategoryField());

  const bar = secEl("div", "secbar");
  bar.appendChild(secFindTextField("Branch", secFindFilters.branch, (v) => {
    secFindFilters.branch = v; secFindPage = 1; secFindRefresh();
  }));
  bar.appendChild(secFindTextField("Path contains", secFindFilters.path, (v) => {
    secFindFilters.path = v; secFindPage = 1; secFindRefresh();
  }));
  bar.appendChild(secFindTextField("Analysis #", secFindFilters.analysis, (v) => {
    secFindFilters.analysis = v; secFindPage = 1; secFindRefresh();
  }));
  bar.appendChild(secFindTextField("Search title / rule / CVE / file", secFindFilters.q, (v) => {
    secFindFilters.q = v; secFindPage = 1; secFindRefresh();
  }));
  bar.appendChild(secFindShowResolvedField());
  bar.appendChild(secFindClearButton());
  wrap.appendChild(bar);

  wrap.appendChild(secFindSavedFilters(data));
  return wrap;
}

/* ------------------------------------------------------------------ table
   The state a row shows is the state its OWN branch's latest finished
   analysis gives it -- a list that crosses branches (and so crosses
   analyses) has to say which one it is speaking about, hence the Branch and
   First seen columns beside State rather than a bare severity/title pair. */
function secFindRow(f){
  const tr = document.createElement("tr");
  tr.className = "sev-" + secSevKey(f) + " state-" + secStateKey(f);
  const cell = (text) => { const td = document.createElement("td"); td.textContent = text; return td; };

  tr.appendChild(cell(f.severity || ""));

  const tdTitle = document.createElement("td");
  // Titles and paths come out of analysed code, and a branch name may
  // legally contain '<', '>' and '&' -- textContent, always, the one rule
  // this whole area exists to keep (see vocabulary.js's own file comment).
  tdTitle.appendChild(secEl("div", "sectitle", f.title || ""));
  const occ = f.occurrences || [];
  if(occ.length){
    const first = occ[0];
    const where = first.line ? first.file + ":" + first.line : first.file;
    const more = occ.length > 1 ? " (+" + (occ.length - 1) + " more)" : "";
    tdTitle.appendChild(secEl("div", "secmeta", where + more));
  }
  tr.appendChild(tdTitle);

  tr.appendChild(cell(f.category || ""));
  tr.appendChild(cell(f.branch || ""));

  const tdState = document.createElement("td");
  const stBadge = secEl("span", "secstate " + secStateKey(f), SEC_STATE_LABEL[f.state] || f.state);
  stBadge.title = SEC_STATE_HELP[f.state] || "";
  tdState.appendChild(stBadge);
  tr.appendChild(tdState);

  tr.appendChild(cell(f.first_seen ? fmtWhen(f.first_seen) : "—"));

  const tdAct = document.createElement("td");
  // A fixed finding is gone: there is nothing left to accept or dismiss --
  // the same rule secFindingRow in analysis.js already follows.
  if(f.state !== "fixed") tdAct.appendChild(secFindDecisionControls(f));
  tr.appendChild(tdAct);
  return tr;
}

function secFindDecisionControls(f){
  const wrap = secEl("div", "secactions");
  [["accepted", "Accept risk"], ["false_positive", "False positive"]].forEach(([state, label]) => {
    const b = secEl("button", "btn", label);
    b.type = "button";
    b.onclick = () => secFindDecide(f, state, label);
    wrap.appendChild(b);
  });
  return wrap;
}

async function secFindDecide(f, state, label){
  // Required, not optional: the API refuses a blank reason with a 400 of its
  // own -- asked here so that refusal is never how somebody discovers the
  // rule (see analysis.js's identical secDecide).
  const reason = await secAskReason(label, f.title);
  if(reason === null) return;
  const ok = await api("security_decide",
    {project: secFindProject, fingerprint: f.fingerprint, state, reason});
  // api() has already put the server's own sentence on screen when this is
  // false -- including the one this page must never swallow: a decision
  // refused because an analysis of this project is still running.
  if(!ok) return;
  toast(label + " recorded", false, "check");
  // Overview's checklist counts and the sidebar donut both read this
  // decision the next time either is fetched -- invalidated here, the same
  // way secDecide in analysis.js does for the old single-analysis view, so
  // neither shows a stale count without a real reload.
  secInvalidateProject();
  await secFindRefresh();
}

function secFindTableSection(data){
  const rows = data.rows || [];
  if(!rows.length) return secEl("div", "tblempty", "No findings match these filters.");

  const minSeverity = secMinSeverity(secFindProject);
  const floor = SEV_ORDER.indexOf(minSeverity);
  const visible = rows.filter(f => secSevRank(f.severity) >= floor);
  if(!visible.length){
    return secEl("div", "tblempty",
      "Every finding on this page is below the " + minSeverity
      + " severity floor — recorded, not shown.");
  }

  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  FIND_SORT_COLUMNS.forEach(([key, label]) => {
    const th = document.createElement("th");
    const btn = secEl("button", "btn ghost");
    btn.type = "button";
    const active = secFindSort === key;
    btn.appendChild(secEl("span", null, label + (active ? (secFindDir === "asc" ? " ▲" : " ▼") : "")));
    btn.onclick = () => {
      if(secFindSort === key) secFindDir = secFindDir === "asc" ? "desc" : "asc";
      else { secFindSort = key; secFindDir = key === "severity" ? "desc" : "asc"; }
      secFindPage = 1;
      secFindRefresh();
    };
    th.appendChild(btn);
    htr.appendChild(th);
  });
  const thAct = document.createElement("th");
  thAct.textContent = "Actions";
  htr.appendChild(thAct);
  thead.appendChild(htr);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  visible.forEach(f => tbody.appendChild(secFindRow(f)));
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

/* ------------------------------------------------------------------ pager */
function secFindPager(data){
  const wrap = secEl("div", "pager");
  const total = data.total || 0;
  const perPage = data.per_page || FIND_PER_PAGE;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const page = data.page || 1;

  const prev = secEl("button", "btn ghost", "Prev");
  prev.type = "button";
  prev.disabled = page <= 1;
  prev.onclick = () => { secFindPage = Math.max(1, page - 1); secFindRefresh(); };
  wrap.appendChild(prev);

  wrap.appendChild(secEl("span", null,
    "Page " + page + " / " + pages + " · " + total + " row" + (total === 1 ? "" : "s")));

  const next = secEl("button", "btn ghost", "Next");
  next.type = "button";
  next.disabled = page >= pages;
  next.onclick = () => { secFindPage = Math.min(pages, page + 1); secFindRefresh(); };
  wrap.appendChild(next);

  return wrap;
}
