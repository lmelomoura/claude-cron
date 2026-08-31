/* ------------------------------------------------- the project Overview tab
   ProjectOverview.png, element by element: six severity KPI cards (total +
   the five severities, each with a share/delta line), then a 2/3-1/3 grid --
   "Findings trend" (an SVG line chart of the last 7 days, one line per
   severity behind a Total/Critical/.../Info segmented control) and "Top
   findings" (the five most severe open findings, three of the findings
   browser's own columns) on the left; "Findings by category" (a donut over
   rule buckets with a counted, percented legend) and "Recent activity" (the
   project's last events, icon + kind badge + absolute date) on the right.

   Every number on this pane reads ONE scope: the latest finished analysis of
   the branch the header names (default_branch_posture's own choice, fallen
   back or not) -- `posture`, `categories`, `top_findings` and `previous` are
   all projections of that same checklist, computed server-side in
   cmd_project_data precisely so the KPI total, the donut's centre and the
   Top findings rows can never disagree. The old always-on right rail
   (#sec-pj-side) is hidden while this tab is on screen -- its donut spans
   EVERY analysed branch, a different scope, and the mockup draws this tab
   full-width with its own right column instead.

   Lives in its own module, branches-tab.js/reports-tab.js's own pattern,
   imported by project-screen.js; the one import back
   (secSwitchProjectTab, for the two "View all" doors and the row chevrons)
   is the same established cycle findings-screen.js already has with the
   same module. */
import { $, fmtWhen, kpiCard } from "./page.js";
import { secEl, secIcon } from "./dom.js";
import { SEC_NEVER, EVENT_KIND_LABEL, SEC_EVENT_META, secRuleMeta,
         secSevKey } from "./vocabulary.js";
import { secState } from "./state.js";
import { secSwitchProjectTab } from "./project-screen.js";
import { secShowAnalysis } from "./analysis.js";
import { secOpenActivity } from "./activity-screen.js";

const SEV5 = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = {critical: "Critical", high: "High", medium: "Medium",
                   low: "Low", info: "Info"};
// Icon per KPI card, ProjectOverview.png's own shapes: a shield for the
// countable severities, the circled-i (this table's `alertcircle`) for the
// two the mockup draws as an information glyph. All six exist in the page's
// one icon table -- no bespoke glyphs drawn to chase a pixel.
const SEV_KPI_ICON = {critical: "shield", high: "shield", medium: "alertcircle",
                      low: "shield", info: "alertcircle"};
// .kpi-card tone class per severity -- sev-crit/sev-high already exist
// (Phase 4's own I3 decision: severity cards wear the severity scale, never
// err/warn); sev-med/sev-low/sev-info join them in components.css for this
// tab's other three cards.
const SEV_KPI_TONE = {critical: "sev-crit", high: "sev-high", medium: "sev-med",
                      low: "sev-low", info: "sev-info"};

// [key, label] pairs, SEC_PROJECT_COLS-shaped, so
// test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column
// covers this table like every other. The last column is the row chevron --
// headerless in the mockup, a column all the same.
const SEC_OVFIND_COLS = [
  ["severity", "Severity"], ["title", "Title"], ["location", "Location"],
  ["run", "Analysis run"], ["first_seen", "First seen"], ["go", ""],
];

// Which line the trend chart draws, and the Top-findings sort override --
// surface-local selections (a segmented control, a column header), the same
// kind of state as secRunsFilter/secRunsSortDir one tab over: they survive
// poll repaints and reset when a different project is opened.
let secOvTrendSev = "total";
let secOvSort = null;   // null = the served order (severity rank); {key, dir}
let secOvProject = null;
let secOvPayload = null;

export function secRenderProjectOverview(payload){
  const host = $("sec-pj-overview");
  if(!host) return;
  secOvPayload = payload;
  if(secOvProject !== payload.project){
    secOvProject = payload.project;
    secOvTrendSev = "total";
    secOvSort = null;
  }
  host.textContent = "";
  const ov = (payload.tabs || {}).overview || {};

  if(!ov.state){
    // `attempted` tells "never analysed" apart from "analysed, nothing has
    // finished yet" -- a project whose every analysis failed used to read
    // exactly like one that had never been touched, even though its own
    // Runs tab plainly lists the attempts.
    host.appendChild(secEl("div", "empty",
      ov.attempted ? SEC_NEVER.attempted : SEC_NEVER.next));
    return;
  }
  if(ov.state === "capped"){
    // THE SAME NOTICE the index screen and the analysis screen already
    // give: a capped analysis is a PARTIAL read of the repository, so the
    // numbers below are what it had reached, not what is there.
    const warn = secEl("div", "warnline bad");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", "grow",
      "This analysis is INCOMPLETE: it stopped before covering the whole "
      + "scope. The posture below is what it had reached, not what is there."));
    host.appendChild(warn);
  }

  host.appendChild(secOvKpis(ov));

  const grid = secEl("div", "secov-grid");
  const main = secEl("div", "secov-main");
  main.appendChild(secOvTrendCard(ov));
  main.appendChild(secOvTopFindings(ov));
  grid.appendChild(main);
  const side = secEl("div", "secov-side");
  side.appendChild(secOvCategoryCard(ov));
  side.appendChild(secProjectActivity((payload.sidebar || {}).activity || []));
  grid.appendChild(side);
  host.appendChild(grid);
}

/* ------------------------------------------------------------- KPI cards */
/* What the small line under a KPI label says. The mockup's own sample
   prints the severity SHARE of the total on five cards with "vs. previous
   analysis" under all six -- its five numbers are exactly shares of its own
   71 (2/71 = 2.8%, 8/71 = 11.3%, ...), a sublabel its own numbers
   contradict. Rendered honestly instead: the Total card carries the real
   delta against the previous finished analysis (that is what an arrow and
   a green/red tone can truthfully say), and each severity card carries its
   share of the total, labelled as exactly that. */
function secOvDeltaText(now, before){
  if(before == null) return {text: "—", dir: "", sub: "no previous analysis"};
  if(now === before) return {text: "no change", dir: "", sub: "vs. previous analysis"};
  if(!before) return {text: "↑ +" + now, dir: "bad", sub: "vs. previous analysis"};
  const pct = Math.round(Math.abs(now - before) / before * 100);
  return now < before
    ? {text: "↓ " + pct + "%", dir: "good", sub: "vs. previous analysis"}
    : {text: "↑ " + pct + "%", dir: "bad", sub: "vs. previous analysis"};
}

function secOvShare(n, total){
  if(!total) return "—";
  return (Math.round(n / total * 1000) / 10) + "%";
}

function secOvKpis(ov){
  const wrap = secEl("div", "kpi-grid");
  const p = ov.posture || {};
  const total = p.total || 0;

  // kpiCard builds head/label/sub; the delta line the mockup draws between
  // label and sub is this tab's own, appended after -- the builder itself
  // stays untouched for its five other pages.
  const totalCard = kpiCard({icon: "shield", value: String(total),
    label: "Total findings",
    title: "Open findings in the latest finished analysis of the branch "
      + "the header names."});
  const d = secOvDeltaText(total, ov.previous ? (ov.previous.total || 0) : null);
  totalCard.appendChild(secEl("div", "secov-delta " + d.dir, d.text));
  totalCard.appendChild(secEl("div", "kpi-card-sub", d.sub));
  wrap.appendChild(totalCard);

  SEV5.forEach(sev => {
    const n = p[sev] || 0;
    const card = kpiCard({icon: SEV_KPI_ICON[sev], tone: SEV_KPI_TONE[sev],
      value: String(n), label: SEV_LABEL[sev]});
    card.appendChild(secEl("div", "secov-delta", secOvShare(n, total)));
    card.appendChild(secEl("div", "kpi-card-sub", "of total findings"));
    wrap.appendChild(card);
  });
  return wrap;
}

/* ------------------------------------------------------------ trend card */
function secOvTrendCard(ov){
  const card = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  const titles = secEl("div", "grow");
  titles.appendChild(secEl("h3", null, "Findings trend"));
  const subLabel = secOvTrendSev === "total"
    ? "Total findings" : SEV_LABEL[secOvTrendSev] + " findings";
  const sub = secEl("div", "secpj-caption", subLabel + " over the last 7 days");
  sub.title = "Open findings at each finished analysis of the branch the "
    + "header names, over the last 7 days.";
  titles.appendChild(sub);
  head.appendChild(titles);
  head.appendChild(secOvTrendSeg());
  card.appendChild(head);

  const points = ov.trend || [];
  if(!points.length){
    card.appendChild(secEl("div", "tblempty",
      "No finished analyses in the last 7 days."));
    return card;
  }
  card.appendChild(secOvTrendSvg(points, secOvTrendSev));
  return card;
}

function secOvTrendSeg(){
  const seg = secEl("div", "secseg");
  ["total"].concat(SEV5).forEach(key => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secseg-btn" + (secOvTrendSev === key ? " on" : "");
    btn.textContent = key === "total" ? "Total" : SEV_LABEL[key];
    btn.onclick = () => {
      secOvTrendSev = key;
      if(secOvPayload) secRenderProjectOverview(secOvPayload);
    };
    seg.appendChild(btn);
  });
  return seg;
}

function secOvDay(ts){
  return new Date(ts * 1000).toLocaleDateString(undefined,
    {month: "short", day: "numeric"});
}

/* The value one trend point contributes to the line currently selected --
   total, or one severity's own count. A point from before by_severity
   existed reads 0 for a severity, never undefined into NaN geometry. */
function secOvTrendValue(point, key){
  if(key === "total") return point.open || 0;
  return (point.by_severity || {})[key] || 0;
}

function secOvTrendSvg(points, key){
  const ns = "http://www.w3.org/2000/svg";
  const W = 720, H = 250, L = 38, R = 30, T = 12, B = 30;
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);
  svg.setAttribute("class", "secov-trendsvg");
  svg.setAttribute("role", "img");

  // X is TIME across the 7-day window ending now, not an even per-point
  // spacing: two analyses an hour apart sit an hour apart, and a quiet
  // day stays visibly quiet -- the mockup's own evenly spaced dots are a
  // sample that happened to run daily, not a rule about spacing.
  const now = Math.floor(Date.now() / 1000);
  const x0 = now - 7 * 86400;
  const spanX = now - x0;
  const values = points.map(p => secOvTrendValue(p, key));
  const maxV = Math.max(1, ...values);
  // A nice ceiling: 1/2/5 times a power of ten, at least 4 so tiny counts
  // do not stretch a 1-finding line across the whole card height.
  let step = 1;
  while(step * 4 < maxV) step *= (String(step)[0] === "2") ? 2.5 : 2;
  const top = Math.max(4, Math.ceil(maxV / step) * step);
  const xFor = ts => L + ((Math.min(Math.max(ts, x0), now) - x0) / spanX) * (W - L - R);
  const yFor = v => H - B - (v / top) * (H - T - B);

  // Horizontal gridlines with their values, 0 to `top` in four steps.
  for(let i = 0; i <= 4; i++){
    const v = (top / 4) * i;
    const y = yFor(v);
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", String(L)); line.setAttribute("x2", String(W - R));
    line.setAttribute("y1", String(y)); line.setAttribute("y2", String(y));
    line.setAttribute("class", "secov-gridline");
    svg.appendChild(line);
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", String(L - 8)); t.setAttribute("y", String(y + 3));
    t.setAttribute("text-anchor", "end");
    t.setAttribute("class", "secov-axis");
    t.textContent = String(Math.round(v));
    svg.appendChild(t);
  }
  // One date label per day boundary.
  for(let d = 0; d <= 7; d++){
    const ts = x0 + d * 86400;
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", String(xFor(ts))); t.setAttribute("y", String(H - 10));
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("class", "secov-axis");
    t.textContent = secOvDay(ts);
    svg.appendChild(t);
  }

  const stroke = key === "total" ? "var(--accent)" : "var(--sev-" + secOvSevToken(key) + ")";
  const coords = points.map((p, i) => [xFor(p.started), yFor(values[i])]);
  if(coords.length > 1){
    const area = document.createElementNS(ns, "path");
    area.setAttribute("d", "M" + coords.map(c => c[0] + "," + c[1]).join(" L")
      + " L" + coords[coords.length - 1][0] + "," + yFor(0)
      + " L" + coords[0][0] + "," + yFor(0) + " Z");
    area.setAttribute("class", "secov-area");
    area.style.fill = stroke;
    svg.appendChild(area);
    const line = document.createElementNS(ns, "path");
    line.setAttribute("d", "M" + coords.map(c => c[0] + "," + c[1]).join(" L"));
    line.setAttribute("class", "secov-line");
    line.style.stroke = stroke;
    svg.appendChild(line);
  }
  points.forEach((p, i) => {
    const dot = document.createElementNS(ns, "circle");
    dot.setAttribute("cx", String(coords[i][0]));
    dot.setAttribute("cy", String(coords[i][1]));
    dot.setAttribute("r", "3.5");
    // A capped point is a PARTIAL read -- hollow, the same "incomplete" cue
    // this area gives everywhere, so a dip at a capped point cannot pass
    // for progress. The <title> spells it out.
    dot.setAttribute("class", "secov-dot" + (p.state === "capped" ? " capped" : ""));
    dot.style.stroke = stroke;
    if(p.state !== "capped") dot.style.fill = stroke;
    const tip = document.createElementNS(ns, "title");
    tip.textContent = "#" + p.analysis_id + " — " + values[i] + " open · "
      + fmtWhen(p.started) + (p.state === "capped" ? " (incomplete)" : "");
    dot.appendChild(tip);
    svg.appendChild(dot);
  });
  return svg;
}

// tokens.css spells the severity tokens --sev-crit/--sev-high/--sev-med/
// --sev-low/--sev-info; the data spells severities in full. One place maps.
function secOvSevToken(sev){
  return {critical: "crit", high: "high", medium: "med", low: "low",
          info: "info"}[sev] || "info";
}

/* --------------------------------------------------------- category donut */
function secOvCategoryCard(ov){
  const card = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Findings by category"));
  head.appendChild(secOvViewAll("Open this project's findings browser"));
  card.appendChild(head);

  const total = (ov.posture || {}).total || 0;
  const cats = ov.categories || [];
  if(!total || !cats.length){
    card.appendChild(secEl("div", "tblempty", "No open findings to categorise."));
    return card;
  }
  const listed = cats.reduce((n, c) => n + (c.count || 0), 0);
  const slices = cats.map((c, i) => {
    const meta = secRuleMeta(c.category, c.rule);
    return {label: meta.label, rule: c.rule, count: c.count || 0,
            color: "var(--cat-" + (i + 1) + ")"};
  });
  // Everything past the top five, one grey slice -- the checklist's own
  // remainder, never a padding value: listed can equal total, and then
  // there is no Other row at all.
  if(total - listed > 0){
    slices.push({label: "Other", rule: "", count: total - listed,
                 color: "var(--cat-other)"});
  }

  const row = secEl("div", "secov-donutrow");
  row.appendChild(secOvDonutSvg(slices, total));
  const legend = secEl("div", "secov-legend");
  slices.forEach(s => {
    const item = secEl("div", "secov-legendrow");
    if(s.rule) item.title = s.rule;
    const dot = secEl("span", "secov-legdot");
    dot.style.background = s.color;
    item.appendChild(dot);
    item.appendChild(secEl("span", "secov-legname", s.label));
    // "19 (26.8%)" -- the count dark, its share muted, the mockup's own
    // two-tone reading of one value.
    const count = secEl("span", "secov-legcount");
    count.appendChild(secEl("b", null, String(s.count)));
    count.appendChild(document.createTextNode(" (" + secOvShare(s.count, total) + ")"));
    item.appendChild(count);
    legend.appendChild(item);
  });
  row.appendChild(legend);
  card.appendChild(row);
  return card;
}

/* The same 120-viewBox, r-50, 14-stroke geometry as secIndexDonutSvg
   (index-screen.js) so the two donuts on this screen family read as one
   shape -- not that function itself, because that one is keyed to the five
   severities and their tokens, and this one paints arbitrary category
   slices with the categorical palette. Centre carries the total AND its
   label, the mockup's own "71 / Total findings". */
function secOvDonutSvg(slices, total){
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 120 120");
  svg.setAttribute("class", "secov-donutsvg");
  svg.setAttribute("role", "img");
  const r = 50, c = 60, circumference = 2 * Math.PI * r;
  const track = document.createElementNS(ns, "circle");
  track.setAttribute("cx", String(c)); track.setAttribute("cy", String(c));
  track.setAttribute("r", String(r));
  track.setAttribute("fill", "none");
  track.setAttribute("stroke-width", "14");
  track.style.stroke = "var(--line)";
  svg.appendChild(track);
  let offset = 0;
  slices.forEach(s => {
    if(!s.count || !total) return;
    const len = (s.count / total) * circumference;
    const seg = document.createElementNS(ns, "circle");
    seg.setAttribute("cx", String(c)); seg.setAttribute("cy", String(c));
    seg.setAttribute("r", String(r));
    seg.setAttribute("fill", "none");
    seg.setAttribute("stroke-width", "14");
    seg.setAttribute("stroke-dasharray", len + " " + (circumference - len));
    seg.setAttribute("stroke-dashoffset", String(-offset));
    seg.setAttribute("transform", "rotate(-90 " + c + " " + c + ")");
    seg.style.stroke = s.color;
    svg.appendChild(seg);
    offset += len;
  });
  const num = document.createElementNS(ns, "text");
  num.setAttribute("x", String(c)); num.setAttribute("y", "56");
  num.setAttribute("text-anchor", "middle");
  num.setAttribute("class", "secov-donut-total");
  num.textContent = String(total);
  svg.appendChild(num);
  const sub = document.createElementNS(ns, "text");
  sub.setAttribute("x", String(c)); sub.setAttribute("y", "73");
  sub.setAttribute("text-anchor", "middle");
  sub.setAttribute("class", "secov-donut-sub");
  sub.textContent = "Total findings";
  svg.appendChild(sub);
  return svg;
}

/* ----------------------------------------------------------- top findings */
function secOvViewAll(title){
  const btn = secEl("button", "btn ghost", "View all");
  btn.type = "button";
  btn.title = title;
  btn.onclick = () => secSwitchProjectTab("findings");
  return btn;
}

function secOvCap(s){
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
}

function secOvSortedFindings(ov){
  const rows = (ov.top_findings || []).slice();
  if(!secOvSort) return rows;   // the served order: severity rank, then newest
  const {key, dir} = secOvSort;
  const mul = dir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    if(key === "location"){
      const la = (a.file || "") + ":" + (a.line || 0);
      const lb = (b.file || "") + ":" + (b.line || 0);
      return mul * la.localeCompare(lb);
    }
    return mul * ((a.analysis_id || 0) - (b.analysis_id || 0));
  });
  return rows;
}

function secOvTopFindings(ov){
  const card = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Top findings"));
  head.appendChild(secOvViewAll("Open this project's findings browser"));
  card.appendChild(head);

  const rows = secOvSortedFindings(ov);
  if(!rows.length){
    card.appendChild(secEl("div", "tblempty", "No open findings."));
    return card;
  }
  const wrap = secEl("div", "table-card");
  const scroll = secEl("div", "table-scroll");
  const table = document.createElement("table");
  table.className = "secov-findtable";
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  SEC_OVFIND_COLS.forEach(([key, label]) => {
    if(key === "location" || key === "run"){
      htr.appendChild(secOvSortableHeader(key, label));
      return;
    }
    const th = document.createElement("th");
    th.textContent = label;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  rows.forEach(f => tbody.appendChild(secOvFindingRow(f)));
  table.appendChild(tbody);
  scroll.appendChild(table);
  wrap.appendChild(scroll);
  card.appendChild(wrap);
  return card;
}

/* The findings browser's own sortable-header idiom (findings-screen.js's
   sortableHeader): a ghost button, the arrow only while active. The two
   mockup-arrowed columns only -- the card's default order IS its point
   ("top" = most severe, then newest), so Severity/Title/First seen stay
   plain and the full nine-column, six-way-sortable table is one View-all
   click away. */
function secOvSortableHeader(key, label){
  const th = document.createElement("th");
  const btn = secEl("button", "btn ghost");
  btn.type = "button";
  const active = secOvSort && secOvSort.key === key;
  btn.appendChild(secEl("span", null,
    label + (active ? (secOvSort.dir === "asc" ? " ▲" : " ▼") : "")));
  btn.title = "Sort by " + label.toLowerCase();
  btn.onclick = () => {
    secOvSort = active
      ? {key, dir: secOvSort.dir === "asc" ? "desc" : "asc"}
      : {key, dir: "asc"};
    if(secOvPayload) secRenderProjectOverview(secOvPayload);
  };
  th.appendChild(btn);
  return th;
}

function secOvFindingRow(f){
  const tr = document.createElement("tr");
  // The same row/pill classes the findings browser wears (secFindRow) --
  // one severity-to-colour vocabulary, not a second map.
  tr.className = "sev-" + secSevKey(f);

  const tdSev = document.createElement("td");
  tdSev.appendChild(secEl("span", "sevpill " + secSevKey(f), f.severity || ""));
  tr.appendChild(tdSev);

  const tdTitle = document.createElement("td");
  const meta = secRuleMeta(f.category, f.rule);
  // A finding's own title when the agent wrote one; the rule's own label
  // otherwise. Real titles run to whole sentences where the mockup's sample
  // says "SQL Injection" -- the cell clamps to two lines (CSS) and the
  // full title plus the raw rule id stay one hover away.
  const titleEl = secEl("div", "sectitle", f.title || meta.label);
  titleEl.title = [f.title, f.rule].filter(Boolean).join("\n");
  tdTitle.appendChild(titleEl);
  tr.appendChild(tdTitle);

  const tdLoc = document.createElement("td");
  if(f.file){
    const where = f.line ? f.file + ":" + f.line : f.file;
    tdLoc.appendChild(secEl("div", "secfind-loc",
      where + (f.more ? " (+" + f.more + " more)" : "")));
  }else{
    tdLoc.textContent = "—";
  }
  tr.appendChild(tdLoc);

  // "#7 (Deep)" -- the analysis that attests this finding now, the same
  // drill-down the findings browser's own Analysis run column links to.
  const tdRun = document.createElement("td");
  const runBtn = document.createElement("button");
  runBtn.type = "button";
  runBtn.className = "btn ghost";
  runBtn.title = "Show this analysis";
  runBtn.appendChild(document.createTextNode("#" + f.analysis_id
    + (f.profile ? " (" + secOvCap(f.profile) + ")" : "")));
  runBtn.onclick = () => {
    secSwitchProjectTab("runs");
    secShowAnalysis(f.analysis_id, true);
  };
  tdRun.appendChild(runBtn);
  tr.appendChild(tdRun);

  const tdFirst = document.createElement("td");
  tdFirst.textContent = f.first_seen ? fmtWhen(f.first_seen) : "—";
  tr.appendChild(tdFirst);

  const tdGo = document.createElement("td");
  const go = document.createElement("button");
  go.type = "button";
  go.className = "iconbtn";
  go.title = "Open this project's findings browser";
  go.appendChild(secIcon("cright"));
  go.onclick = () => secSwitchProjectTab("findings");
  tdGo.appendChild(go);
  tr.appendChild(tdGo);
  return tr;
}

/* -------------------------------------------------------- recent activity */
/* ProjectOverview.png's own row anatomy -- icon in a tinted box, the kind
   as a bold title with the event's detail beneath, a kind badge and the
   absolute date on the right -- for BOTH mounts of this card: this tab's
   own right column, and the rail every other tab still shows
   (secRenderProjectSidebar, project-screen.js, which imports it from here
   now that the Overview owns the card's shape). */
export function secProjectActivity(events){
  const box = secEl("div", "card secpj-plaincard");
  const head = secEl("div", "secpj-cardhead");
  head.appendChild(secEl("h3", null, "Recent activity"));
  // The Activity screen's own entry point from here: this feed is the last
  // five events (cmd_project_data's own `ledger.events_for(..., limit=5)`),
  // the full screen is every event, filterable by kind, for this project.
  const viewAll = secEl("button", "btn ghost", "View all");
  viewAll.type = "button";
  viewAll.onclick = () => secOpenActivity(secState.project);
  head.appendChild(viewAll);
  box.appendChild(head);
  if(!events.length){
    box.appendChild(secEl("div", "tblempty", "No activity recorded yet."));
    return box;
  }
  const list = secEl("div", "secov-actlist");
  events.forEach(e => {
    const meta = SEC_EVENT_META[e.kind];
    const row = secEl("div", "secov-actrow");
    const ic = secEl("span", "secov-actic");
    ic.appendChild(secIcon(meta ? meta.icon : "activity"));
    row.appendChild(ic);
    const grow = secEl("div", "grow");
    grow.appendChild(secEl("div", "secname", EVENT_KIND_LABEL[e.kind] || e.kind));
    if((e.detail || "").trim()) grow.appendChild(secEl("div", "secmeta", e.detail));
    row.appendChild(grow);
    const right = secEl("div", "secov-actright");
    if(meta) right.appendChild(secEl("span", "pill " + meta.pill, meta.badge));
    right.appendChild(secEl("span", "secmeta", fmtWhen(e.at)));
    row.appendChild(right);
    list.appendChild(row);
  });
  box.appendChild(list);
  return box;
}
