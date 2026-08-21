/* ------------------------------------------------------------ the index
   The Security area's front page: one request, `GET /api/security/index`,
   answers with everything this screen draws -- the five KPI cards, the
   project table (one row per project, its default branch's current
   posture), the recent-analyses feed and the severity donut with the rules
   that produced it. See bin/security/cli.py's `index-data` and
   bin/claude-cron-server's `security_index`/`_security_projects`.

   The old per-project list (projects.js) cost one subprocess PER PROJECT on
   every load and every Refresh -- `security list`, and for whichever
   project had a finished analysis, `security checklist` on top. This is the
   whole screen in one call, however many projects are configured.

   Cached the same way projects.js cached postures: fetched once, painted
   from the cache on every repaint the poll drives (renderSecurity() in
   index.js calls secRenderIndex() unconditionally, the same as it always
   called secRenderList()), and refetched only on an explicit Refresh or
   when something that changed the numbers just happened (secBack(), after
   leaving a project screen where an analysis may have just finished). */
import { $, fmtAgo, fmtDur, money } from "./page.js";
import { secIcon, secEl, secFetch } from "./dom.js";
import { secOpenProject } from "./project-screen.js";

let secIndexCache = null;
let secIndexGen = 0;

/* Called after anything that could have changed the fleet's posture (a run
   just finished, a decision was just made) so the next paint asks again
   rather than repeating stale numbers. */
export function secInvalidateIndex(){ secIndexCache = null; }

export async function secLoadIndex(force){
  if(secIndexCache && !force) return;   // nothing to do -- already have an answer to paint
  if(force) secIndexGen++;
  const gen = secIndexGen;
  if(!secIndexCache){
    const host = $("sec-list");
    if(host){ host.textContent = ""; host.appendChild(secEl("div", "tblempty", "Loading…")); }
  }
  let data;
  try{
    data = await secFetch("/api/security/index");
  }catch(e){
    if(gen !== secIndexGen) return;      // a newer request (Refresh) already answered
    const host = $("sec-list");
    if(host){
      host.textContent = "";
      const box = secEl("div", "tblempty");
      box.appendChild(secIcon("alert"));
      box.appendChild(document.createTextNode(
        "Could not read the security index — " + e.message));
      host.appendChild(box);
    }
    return;
  }
  if(gen !== secIndexGen) return;
  secIndexCache = data;
  secRenderIndex();
}

/* Cheap and synchronous: paints whatever is already cached, or leaves the
   host exactly as secLoadIndex last left it (its own "Loading…" placeholder,
   or an error) when nothing has answered yet. Safe to call on every poll
   tick -- it touches no network -- so the relative "3m ago" stamps in the
   recent-analyses feed and the project table stay current between fetches. */
export function secRenderIndex(){
  const host = $("sec-list");
  if(!host) return;
  if(!secIndexCache) return;
  host.textContent = "";
  const data = secIndexCache;
  host.appendChild(secIndexCards(data.summary || {}));
  host.appendChild(secIndexSection("Projects",
    secIndexProjectsTable(data.projects || [])));
  host.appendChild(secIndexSection("Recent analyses",
    secIndexRecent(data.recent || [])));
  host.appendChild(secIndexSection("Findings by severity",
    secIndexDonut(data.donut || {}, data.categories || [])));
}

function secIndexSection(title, body){
  const sec = secEl("div", "secidx-section");
  sec.appendChild(secEl("h3", null, title));
  sec.appendChild(body);
  return sec;
}

/* ------------------------------------------------------------------ cards
   Five cards for the five COUNTS `index_summary` computes -- `projects`,
   `analyses`, `critical`, `high`, `success_rate` -- no sixth number invented
   here, and none of these five dropped. `capped_projects` is not a card of
   its own: it qualifies the Critical/High cards' own note when the fleet
   total they show might be an undercount (see the comment below). */
function secIndexCard(iconName, label, valueText, note, warn){
  const card = secEl("div", "card secidx-card");
  const head = secEl("div", "secidx-card-h");
  head.appendChild(secIcon(iconName));
  head.appendChild(secEl("span", null, label));
  card.appendChild(head);
  card.appendChild(secEl("div", "secidx-num", valueText));
  if(note) card.appendChild(secEl("div", "secidx-note" + (warn ? " warn" : ""), note));
  return card;
}

function secIndexCards(summary){
  const wrap = secEl("div", "secidx-kpis");
  const s = summary || {};
  wrap.appendChild(secIndexCard("shield", "Projects", String(s.projects || 0),
    "Security analysis is on"));
  wrap.appendChild(secIndexCard("activity", "Analyses", String(s.analyses || 0),
    "All time — a historical total, not current posture"));
  // A capped analysis is a PARTIAL read of the repository (see secPaint's own
  // notice on the analysis screen): its "critical: 0"/"high: 0" means "none
  // found before it stopped," not "none." Folding one into these totals with
  // no cue would present a total that looks complete when it might not be --
  // so when index_summary says any project's LATEST analysis stopped short,
  // the cards say how many, instead of just the number.
  const capped = s.capped_projects || 0;
  const cappedNote = capped
    ? capped + " of " + (s.projects || 0) + " project" + ((s.projects || 0) === 1 ? "" : "s")
      + " had a latest analysis that stopped before covering its whole scope "
      + "— this total may be an undercount"
    : "Open now, in every project's latest analysis";
  wrap.appendChild(secIndexCard("alert", "Critical", String(s.critical || 0),
    cappedNote, !!capped));
  wrap.appendChild(secIndexCard("zap", "High", String(s.high || 0),
    cappedNote, !!capped));
  const rate = s.success_rate;
  // A dash, not 0%: no finished analysis is not a zero-percent success rate --
  // those are different facts, and the number below has to say which one it is.
  wrap.appendChild(secIndexCard("check", "Success rate",
    rate == null ? "—" : Math.round(rate * 100) + "%",
    rate == null ? "No finished analysis yet"
                 : "Finished analyses that completed clean, not capped or failed"));
  return wrap;
}

/* ------------------------------------------------------------- the table
   secIndexPosturePills and secIndexDonut (below) are exported too: the
   project screen's Overview tab needs the identical severity pills, and its
   sidebar needs the identical donut+categories block -- the same shapes,
   the same colours, the same "nothing open" wording, so a reader moving
   between the two screens never has to learn a second rendering of the
   same numbers. See ui/security/project-screen.js. */
export function secIndexPosturePills(posture){
  const wrap = secEl("span", "sevpills");
  const p = posture || {};
  if(!p.total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  ["critical", "high", "medium", "low", "info"].forEach(sev => {
    if(p[sev]) wrap.appendChild(secEl("span", "sevpill " + sev, p[sev] + " " + sev));
  });
  return wrap;
}

function secIndexProjectRow(p){
  const tr = document.createElement("tr");

  const tdName = document.createElement("td");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn ghost";
  btn.textContent = p.name;
  btn.onclick = () => secOpenProject(p.name);
  tdName.appendChild(btn);
  if((p.description || "").trim()){
    tdName.appendChild(secEl("div", "secidx-desc", p.description));
  }
  tr.appendChild(tdName);

  const tdBranch = document.createElement("td");
  tdBranch.appendChild(document.createTextNode(p.branch || "—"));
  if(p.branch_fell_back){
    // The name stays visible next to the note: postures of different
    // branches must never be confused in silence, and a note alone (with no
    // branch named) would still leave that ambiguous.
    tdBranch.appendChild(secEl("span", "secidx-fellback",
      " (fell back — the default branch was never analysed)"));
  }
  tr.appendChild(tdBranch);

  const tdPosture = document.createElement("td");
  tdPosture.appendChild(secIndexPosturePills(p.posture));
  if(p.last_state === "capped"){
    // THE SAME NOTICE secPaint gives on the analysis screen itself: a capped
    // analysis is a PARTIAL read of the repository, and the counts beside
    // this badge are the counts of a partial read -- "critical: 0" means
    // "none found before it stopped," not "none." Without this, the index
    // was the one place a truncated analysis still read as a finished one.
    const badge = secEl("span", "secidx-capped", "incomplete");
    badge.title = "This analysis is INCOMPLETE: it stopped before covering "
      + "the whole scope. The posture above is what it had reached, not "
      + "what is there.";
    tdPosture.appendChild(badge);
  }
  tr.appendChild(tdPosture);

  const tdLast = document.createElement("td");
  if(!p.analyses){
    tdLast.textContent = "Never analysed";
  }else{
    const bits = [p.profile, fmtAgo(p.last_started)];
    if(p.last_duration) bits.push(fmtDur(p.last_duration));
    tdLast.textContent = bits.filter(Boolean).join(" · ");
  }
  tr.appendChild(tdLast);

  const tdCount = document.createElement("td");
  tdCount.className = "num";
  tdCount.textContent = String(p.analyses || 0);
  tr.appendChild(tdCount);

  return tr;
}

function secIndexProjectsTable(projects){
  if(!projects.length){
    const e = secEl("div", "tblempty");
    e.appendChild(secIcon("inbox"));
    e.appendChild(document.createTextNode(
      "No projects have security analysis enabled yet — turn it on in a "
      + "project's editor, on the Security tab."));
    return e;
  }
  const wrap = secEl("div", "tablewrap");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  ["Project", "Branch", "Posture", "Last analysis", "Analyses"].forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  projects.slice()
    .sort((a, b) => String(a.name).localeCompare(String(b.name)))
    .forEach(p => tbody.appendChild(secIndexProjectRow(p)));
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

/* ---------------------------------------------------------- recent feed */
function secIndexRecentRow(a){
  const row = document.createElement("button");
  row.type = "button";
  row.className = "secrow secidx-recentrow";
  // Opens the project, not this exact historical analysis -- there is no
  // per-analysis screen yet outside the project's own history list.
  row.onclick = () => secOpenProject(a.project);
  row.appendChild(secIcon(a.state === "running" ? "timer"
    : a.state === "failed" ? "xcircle" : "check"));
  const grow = secEl("div", "grow");
  grow.appendChild(secEl("div", "secname",
    a.project + " · " + a.repo + " @ " + a.branch));
  const bits = [a.profile, a.state,
    a.state === "running" ? "started " + fmtAgo(a.started)
                          : "ended " + fmtAgo(a.ended || a.started)];
  if(a.open != null) bits.push(a.open + " open");
  bits.push(money(a.spend_usd || 0));
  grow.appendChild(secEl("div", "secmeta", bits.filter(Boolean).join(" · ")));
  row.appendChild(grow);
  return row;
}

function secIndexRecent(recent){
  if(!recent.length){
    return secEl("div", "tblempty", "No analyses have run yet.");
  }
  const host = secEl("div", "seclist");
  recent.forEach(a => host.appendChild(secIndexRecentRow(a)));
  return host;
}

/* --------------------------------------------------------- donut + rules */
const SEV_ORDER5 = ["critical", "high", "medium", "low", "info"];
// The exact colour grouping .sevpill already uses (critical and high share
// one colour there too, and so do low and info) -- a donut that invented a
// finer palette than the pills the rest of the area draws with would teach
// the reader a distinction the pills never made.
const SEV_STROKE = {critical: "var(--err)", high: "var(--err)",
                    medium: "var(--warn)", low: "var(--muted)", info: "var(--line)"};

function secIndexDonutSvg(donut){
  const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 120 120");
  svg.setAttribute("class", "secidx-donut-svg");
  svg.setAttribute("role", "img");
  const r = 50, c = 60, circumference = 2 * Math.PI * r;

  const track = document.createElementNS(ns, "circle");
  track.setAttribute("cx", String(c));
  track.setAttribute("cy", String(c));
  track.setAttribute("r", String(r));
  track.setAttribute("fill", "none");
  track.setAttribute("stroke-width", "14");
  track.style.stroke = "var(--line)";
  svg.appendChild(track);

  let offset = 0;
  SEV_ORDER5.forEach(sev => {
    const n = donut[sev] || 0;
    if(!n || !total) return;
    const len = (n / total) * circumference;
    const seg = document.createElementNS(ns, "circle");
    seg.setAttribute("cx", String(c));
    seg.setAttribute("cy", String(c));
    seg.setAttribute("r", String(r));
    seg.setAttribute("fill", "none");
    seg.setAttribute("stroke-width", "14");
    seg.setAttribute("stroke-dasharray", len + " " + (circumference - len));
    seg.setAttribute("stroke-dashoffset", String(-offset));
    // Segments start at 12 o'clock rather than a bare circle's 3 o'clock.
    seg.setAttribute("transform", "rotate(-90 " + c + " " + c + ")");
    seg.style.stroke = SEV_STROKE[sev] || "var(--muted)";
    svg.appendChild(seg);
    offset += len;
  });

  const label = document.createElementNS(ns, "text");
  label.setAttribute("x", String(c));
  label.setAttribute("y", String(c));
  label.setAttribute("text-anchor", "middle");
  label.setAttribute("dominant-baseline", "central");
  label.setAttribute("class", "secidx-donut-total");
  label.textContent = String(total);
  svg.appendChild(label);
  return svg;
}

function secIndexDonutLegend(donut){
  const wrap = secEl("div", "sevpills");
  const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
  if(!total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  SEV_ORDER5.forEach(sev => {
    if(donut[sev]) wrap.appendChild(secEl("span", "sevpill " + sev, donut[sev] + " " + sev));
  });
  return wrap;
}

function secIndexCategories(categories){
  if(!categories.length){
    return secEl("div", "tblempty", "No open findings to categorise.");
  }
  const wrap = secEl("div", "secidx-categories");
  const max = categories.reduce((n, c) => Math.max(n, c.count || 0), 1);
  categories.forEach(c => {
    const row = secEl("div", "secidx-catrow");
    row.appendChild(secEl("span", "secidx-catname", c.rule));
    const bar = secEl("span", "secidx-catbar");
    const fill = secEl("span", "secidx-catfill");
    fill.style.width = Math.max(6, Math.round(((c.count || 0) / max) * 100)) + "%";
    bar.appendChild(fill);
    row.appendChild(bar);
    row.appendChild(secEl("span", "secidx-catcount", String(c.count || 0)));
    wrap.appendChild(row);
  });
  return wrap;
}

export function secIndexDonut(donut, categories){
  const wrap = secEl("div", "secidx-donutwrap");
  const left = secEl("div", "secidx-donutcol");
  left.appendChild(secIndexDonutSvg(donut));
  left.appendChild(secIndexDonutLegend(donut));
  wrap.appendChild(left);
  const right = secEl("div", "secidx-catcol");
  right.appendChild(secEl("div", "secidx-cathead",
    "Rules producing the most open findings"));
  right.appendChild(secIndexCategories(categories));
  wrap.appendChild(right);
  return wrap;
}
