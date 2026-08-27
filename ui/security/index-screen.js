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
import { $, fmtAgo, fmtDur, money, pageHeader, kpiCard } from "./page.js";
import { secIcon, secEl, secFetch } from "./dom.js";
import { SEC_NEVER, SEC_FLOOR_SCOPE_NOTE } from "./vocabulary.js";
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

/* The index's own page header (Phase 4 Task 1) -- shield, "Security", one
   sentence, Activity and Refresh trailing right -- replacing what used to be
   a loose <p class="paneblurb"> plus a bare .toolbar holding those same two
   buttons. #sec-head is static markup (bin/dashboard.html), always in the
   DOM whether or not the security view is the one showing, the same as
   #jobs-head/#prj-head/#runs-head already are for their own pages.

   Rebuilt whole on every call, exactly like every other page's own
   pageHeader() call (renderJobsPage(), renderProjectsPage(), ...): neither
   action button carries a listener of its own, so throwing both away and
   drawing fresh ones costs nothing. Activity and Refresh are answered by
   bin/dashboard.html's central delegated click listener
   (`#sec-view-activity`/`#sec-reload`, routed to CCSecurity.openActivity()/
   reload()) instead, the same "markup carries the hook, a central listener
   does the click" split chrome.js's own pageHeader comment describes for
   every other page's actions -- pageHeader only ever draws the button and
   stamps the id the caller asked for, never a click handler.

   Called from secRenderIndex() rather than ui/security/index.js's own
   init(), and this is not a style choice: init() runs inside
   CCSecurity.init(CC), which bin/dashboard.html calls BEFORE CCApp.init() --
   see that file's own banner comment above the CC object. pageHeader (like
   kpiCard) calls straight into `icon()`, which for this bridge resolves to
   ui/app/page.js's own binding, and that binding is not set until
   CCApp.init() runs. Calling pageHeader() from inside init() would read it
   in its temporal dead zone and throw on every load. secRenderIndex() only
   ever runs off a poll tick or a resolved fetch, both strictly after the
   page's own script has finished running top to bottom -- CCApp.init()
   included -- so this is the earliest point that is actually safe. */
function secRenderHead(){
  const host = $("sec-head");
  if(!host) return;
  host.textContent = "";
  host.appendChild(pageHeader({
    icon: "shield", title: "Security",
    subtitle: "Vulnerability analysis across your projects.",
    actions: [
      {id: "sec-view-activity", icon: "activity", label: "Activity"},
      {id: "sec-reload", icon: "radar", label: "Refresh"},
    ],
  }));
}

/* Cheap and synchronous: paints whatever is already cached, or leaves the
   host exactly as secLoadIndex last left it (its own "Loading…" placeholder,
   or an error) when nothing has answered yet. Safe to call on every poll
   tick -- it touches no network -- so the relative "3m ago" stamps in the
   recent-analyses feed and the project table stay current between fetches. */
export function secRenderIndex(){
  secRenderHead();
  const host = $("sec-list");
  if(!host) return;
  if(!secIndexCache) return;
  host.textContent = "";
  const data = secIndexCache;
  host.appendChild(secIndexCards(data.summary || {}));
  // ONCE per screen, under the cards and above every other number on it --
  // the KPI cards, the table's posture pills and the donut are all UNFLOORED,
  // and until this line existed nothing anywhere said so while the drill-down
  // one click away openly held rows back. See SEC_FLOOR_SCOPE_NOTE's own
  // comment in vocabulary.js for the decision and why it went this way.
  host.appendChild(secEl("div", "secpj-caption", SEC_FLOOR_SCOPE_NOTE));
  host.appendChild(secIndexSection("Projects",
    secIndexProjectsTable(data.projects || [])));
  host.appendChild(secIndexSection("Recent analyses",
    secIndexRecent(data.recent || [])));
  host.appendChild(secIndexSection("Findings by severity",
    // The donut is the fleet's whole posture rolled into one figure, so it
    // cannot carry the per-row `incomplete` badge the table beside it uses --
    // it gets the same caveat the Critical/High cards get, from the same
    // count, or it is the one number on this screen that still presents a
    // partial read as a complete one.
    secIndexDonut(data.donut || {}, data.categories || [],
                  secCappedNote(data.summary || {}))));
}

/* The one sentence the cards, the donut and (via project-data's own
   `capped_branches`) the project sidebar all use for a PARTIAL read, so the
   caveat reads identically wherever a rollup cannot show a per-row badge.
   `n` of `of` had their latest analysis stop before covering the whole
   scope: what is counted is what was found before it stopped, not what is
   there. */
export function secCappedScopeNote(n, of, noun){
  if(!n) return "";
  return n + " of " + of + " " + noun + (of === 1 ? "" : "s")
    + " had a latest analysis that stopped before covering its whole scope "
    + "— this total may be an undercount";
}

function secCappedNote(summary){
  return secCappedScopeNote(summary.capped_projects || 0,
                            summary.projects || 0, "project");
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
   total they show might be an undercount (see the comment below).

   Built with the bridged kpiCard() (Phase 4 Task 1) instead of a local
   secIndexCard() helper -- the mockup draws these five exactly like every
   other page's KPI row (number beside a tinted icon, then a bold label, then
   a muted one-line sub), so this area reaches for the SAME builder Jobs/
   Runs/Projects already do rather than keeping its own inverted variant
   (number below the icon, no tone) in step by hand. See ui/security/page.js
   for how kpiCard reaches this file without ui/security/ importing
   ui/app/chrome.js directly.

   The label and sub are now FIXED, mockup-drawn strings -- "Critical
   findings"/"needs immediate attention", not a number-qualified sentence --
   which leaves nowhere left in the card's own layout for a caveat as long as
   the capped/fell-back note above. `title` is that home: kpiCard's own
   comment in chrome.js already uses it for exactly this, "the definition of
   what the card is counting" as a native tooltip instead of squeezed into
   `sub`. Critical and High both carry the caveat there when one applies, and
   the plain "Open now, in every project's latest analysis" sentence
   otherwise -- so the card that never has a caveat still explains its own
   count on hover, the same as it did before this task touched it. */
function secIndexCards(summary){
  const wrap = secEl("div", "kpi-grid");
  const s = summary || {};
  wrap.appendChild(kpiCard({icon: "folder", value: String(s.projects || 0),
    label: "Projects", sub: "with security enabled"}));
  wrap.appendChild(kpiCard({icon: "activity", value: String(s.analyses || 0),
    label: "Total analyses", sub: "across all projects",
    title: "All time — a historical total, not current posture"}));
  // A capped analysis is a PARTIAL read of the repository (see secPaint's own
  // notice on the analysis screen): its "critical: 0"/"high: 0" means "none
  // found before it stopped," not "none." Folding one into these totals with
  // no cue would present a total that looks complete when it might not be --
  // so when index_summary says any project's LATEST analysis stopped short,
  // the cards say how many, instead of just the number.
  //
  // A FALLEN-BACK project is the other way these two totals can mislead, and
  // it used to be silent here: the project's declared base has never been
  // analysed, so its contribution was read off a branch nobody named. The
  // table below says so per row (secIndexProjectRow's tdBranch); the cards
  // summing those same postures said nothing, and a fallback branch is never
  // silent in this area. Both caveats are qualifications of the SAME number,
  // so they share one note rather than competing for the same line.
  const capped = s.capped_projects || 0;
  const fellBack = s.fell_back_projects || 0;
  const total = s.projects || 0;
  const caveats = [];
  if(capped) caveats.push(secCappedScopeNote(capped, total, "project"));
  if(fellBack){
    caveats.push(fellBack + " of " + total + " project" + (total === 1 ? "" : "s")
      + " is counted from a branch other than its declared base, because that "
      + "base has never been analysed");
  }
  const cappedNote = caveats.length ? caveats.join(" · ")
                                    : "Open now, in every project's latest analysis";
  wrap.appendChild(kpiCard({icon: "shield", tone: "err", value: String(s.critical || 0),
    label: "Critical findings", sub: "needs immediate attention", title: cappedNote}));
  wrap.appendChild(kpiCard({icon: "alertcircle", tone: "warn", value: String(s.high || 0),
    label: "High severity", sub: "requires review", title: cappedNote}));
  const rate = s.success_rate;
  // A dash, not 0%: no finished analysis is not a zero-percent success rate --
  // those are different facts, and the number below has to say which one it is.
  //
  // "All time" still said, just moved: this card sits between two cards that
  // say "open now" and is itself a historical ratio over every analysis ever
  // run, which is exactly the unlabelled scope clash this area has had to
  // fix five times over -- the sentence saying so is now the card's `title`
  // rather than its `sub`, since the mockup's own sub for this card is the
  // fixed "analyses completed", the same three-to-five-word budget every
  // other card's sub keeps to.
  wrap.appendChild(kpiCard({icon: "check", tone: "ok",
    value: rate == null ? "—" : Math.round(rate * 100) + "%",
    label: "Success rate",
    sub: rate == null ? "No finished analysis yet" : "analyses completed",
    title: rate == null ? "" : "All time — a historical total, not current posture: "
      + "finished analyses that completed clean, not capped or failed"}));
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
    // The compact density of the one wording (see SEC_NEVER in
    // vocabulary.js): the cell has room for the label, the title carries the
    // same "and here is what to do" sentence the full-width empty states
    // render, so no occurrence of this fact is a dead end.
    tdLast.textContent = SEC_NEVER.short;
    tdLast.title = SEC_NEVER.next;
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
//
// `info` was `var(--line)` -- the SAME token the empty track below is painted
// with, so an info-only segment was invisible against the ring it was drawn
// on while the legend beside it went on listing the count. `.sevpill.info`
// and `.sevpill.low` are both `var(--muted)` in the stylesheet, which is the
// grouping this table is supposed to be mirroring in the first place.
const SEV_STROKE = {critical: "var(--err)", high: "var(--err)",
                    medium: "var(--warn)", low: "var(--muted)", info: "var(--muted)"};

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

/* What a donut segment COUNTS, on every pill in its legend.

   These are distinct fingerprints -- `severity_totals`, which collapses the
   same finding open on two branches into the one problem it is. The findings
   browser's strip, in identical markup and (on the project screen) four
   inches away on the same page, shows per-severity pills that are ROWS. The
   strip labels its own `total`/`unique` pair and the donut names its scope in
   a caption, but the per-severity pills on both sides said only "3 critical"
   and left the reader to assume the two agreed. They can legitimately
   differ, so each side now says which question it is answering. */
const DONUT_PILL_TITLE = "Distinct problems (fingerprints) — the same finding "
  + "open on two branches counts once here.";

function secIndexDonutLegend(donut){
  const wrap = secEl("div", "sevpills");
  const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
  if(!total){
    wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
    return wrap;
  }
  SEV_ORDER5.forEach(sev => {
    if(!donut[sev]) return;
    const pill = secEl("span", "sevpill " + sev, donut[sev] + " " + sev);
    pill.title = DONUT_PILL_TITLE;
    wrap.appendChild(pill);
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

/* `cappedNote`, when given, is the same PARTIAL-read caveat the Critical/High
   cards and the index table's own `incomplete` badge already carry -- said
   here because a donut is every branch (or every project) rolled into one
   figure, and a rollup has no row to hang a badge off. Both callers pass one:
   the index screen from `summary.capped_projects`, the project sidebar from
   `sidebar.capped_branches`. Omitting it keeps the plain donut. */
export function secIndexDonut(donut, categories, cappedNote){
  const wrap = secEl("div", "secidx-donutwrap");
  const left = secEl("div", "secidx-donutcol");
  left.appendChild(secIndexDonutSvg(donut));
  left.appendChild(secIndexDonutLegend(donut));
  if((cappedNote || "").trim()){
    const warn = secEl("div", "warnline bad");
    warn.appendChild(secIcon("alert"));
    warn.appendChild(secEl("span", "grow", cappedNote));
    left.appendChild(warn);
  }
  wrap.appendChild(left);
  const right = secEl("div", "secidx-catcol");
  right.appendChild(secEl("div", "secidx-cathead",
    "Rules producing the most open findings"));
  right.appendChild(secIndexCategories(categories));
  wrap.appendChild(right);
  return wrap;
}
