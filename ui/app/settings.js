/* Settings › Platforms: one card per listed platform -- found, checked,
   enabled -- and the models switched on for it, in the four steps the
   operator described: the binary, the session, the models, the switch.

   Everything drawn here is read off /api/models (the registry -- no probe
   runs there) plus two calls this page makes on demand: platform_check (the
   live session probe, run for every card when the page opens and on Test)
   and platform_models (the catalog, loaded once a check passes and on
   Refresh). Every change saves at once through a platform_* action; the
   page then re-reads /api/models (ctx.onChange, the page's own loadModels)
   and repaints this page from the fresh payload, so a change made by the
   CLI in the meantime shows up too. Live results stay at module level
   across repaints -- they are this page's, not the payload's. */
import { el, pageHeader } from "./chrome.js";
import { $, icon, sessionLost, toast, TOKEN } from "./page.js";

export const REGISTRY = [
  {id: "anthropic", name: "Anthropic", cli: "claude", sub: "Claude Code — claude -p", mark: "A"},
  {id: "openai", name: "OpenAI", cli: "codex", sub: "Codex CLI — codex exec --json", mark: "O"},
  {id: "opencode", name: "OpenCode", cli: "opencode", sub: "OpenCode — opencode run --format json", mark: "OC"},
];

const live = {checks: {}, checkedAt: {}, catalogs: {}, busy: {}, notes: {}, typedBin: {}};
let ctx = null;   // {platforms, configured, error, onChange}
let probed = false;   // the three live checks have been fired once, on the first paint with a real payload
// True while paint() tears #st-platforms down and rebuilds it. The Binary
// field's blur/keydown handlers (binaryBlock) no-op while this is set -- see
// the comment there for why.
let repainting = false;

async function post(op, extra){
  const r = await fetch("/api/action", {method: "POST",
    headers: {"Content-Type": "text/plain", "X-AL-Token": TOKEN},
    body: JSON.stringify(Object.assign({op}, extra))});
  // The session ran out, or was signed out from another tab: the page's
  // refresh() answers this by putting the login screen back, and so does
  // this -- no "HTTP 401" toast over a page about to be replaced, and no
  // sentence for the card (change() keeps none for an empty output).
  if(r.status === 401 || r.status === 428){ sessionLost(); return {ok: false, output: ""}; }
  const j = await r.json().catch(() => ({}));
  if(!r.ok || j.ok === false){
    const output = j.output || j.error || ("HTTP " + r.status);
    toast(output, true);
    // {ok:false, output}, not null: change() reads the engine's own refusal
    // sentence back out of this for the card note. The other two callers
    // (runCheck, loadCatalog) only ever act on j.check/j.catalog off a
    // successful call, so a falsy `ok` still reads as failure for them.
    return {ok: false, output};
  }
  return j;
}

// The `platform_affected_note` sentences (the enabled jobs a disable or a
// model switch-off leaves skipped) arrive as extra lines after the op's own
// first line -- pulled out on its own so change() and a node test both
// reach the same extraction.
export function noteFromOutput(output){
  return (output || "").split("\n").slice(1).join(" ");
}

export function settingsSummary(platforms){
  const entries = REGISTRY.map(r => (platforms || {})[r.id] || {});
  const enabled = entries.filter(p => p.enabled === true).length;
  // platform_disable does not clear models_enabled, so a disabled platform's
  // leftover list must not count -- those models are not available to a job.
  const models = entries.reduce((n, p) => n + (p.enabled === true ? (p.models_enabled || []).length : 0), 0);
  return enabled + " of " + REGISTRY.length + " platforms enabled · " + models + " model" + (models === 1 ? "" : "s") + " available to jobs";
}

// The chip's word, from the registry entry and the last live check.
export function platformStatus(entry, check){
  if(entry && entry.supported === false) return {cls: "disabled", label: "Coming soon"};
  if(check && check.bin_found === false) return {cls: "off", label: "Not installed"};
  if(check && check.ready === false) return {cls: "idle", label: "Not signed in"};
  return (entry && entry.enabled) ? {cls: "on", label: "Enabled"} : {cls: "disabled", label: "Disabled"};
}

// The strip Overview and Jobs show while nothing is configured (Task 9 mounts it).
export function setupBanner(configured, error, withButton = true){
  if(configured !== false && !error) return null;
  const b = el("div", "setup-banner");
  const bic = el("div", "bic"); bic.appendChild(icon("alert")); b.appendChild(bic);
  const t = el("div", "btxt");
  t.appendChild(el("b", null, error ? "The platform settings cannot be read." : "No platform is enabled yet."));
  t.appendChild(el("span", null, error ? error
    : "Enable one in Settings › Platforms and switch on at least one model; until then no job can be created. New job takes you there."));
  b.appendChild(t);
  if(withButton){
    // No id here: this banner is about to be mounted on two views at once
    // (Task 9), so the click is delegated by class instead of a duplicated id.
    const btn = el("button", "btn primary open-settings"); btn.type = "button";
    btn.appendChild(icon("gear")); btn.appendChild(document.createTextNode("Open Settings"));
    b.appendChild(btn);
  }
  return b;
}

function ago(ms){
  if(!ms) return "";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  return s < 60 ? "checked " + s + " s ago" : "checked " + Math.round(s / 60) + " min ago";
}

function switchEl(on, disabled, title, ariaLabel, onToggle){
  const lab = el("label", "switch"); if(title) lab.title = title;
  const inp = el("input"); inp.type = "checkbox"; inp.checked = !!on; inp.disabled = !!disabled;
  inp.setAttribute("aria-label", ariaLabel);
  inp.addEventListener("change", () => onToggle(inp.checked));
  lab.appendChild(inp); lab.appendChild(el("span", "track")); lab.appendChild(el("span", "knob"));
  return lab;
}

function button(label, iconName, onClick, disabled){
  const b = el("button", "btn"); b.type = "button"; b.disabled = !!disabled;
  if(iconName) b.appendChild(icon(iconName));
  b.appendChild(document.createTextNode(label));
  b.addEventListener("click", onClick);
  return b;
}

async function runCheck(id){
  live.busy[id] = true; paint();
  const j = await post("platform_check", {platform: id});
  if(j && j.check){ live.checks[id] = j.check; live.checkedAt[id] = Date.now(); }
  live.busy[id] = false; paint();
  if(j && j.check && j.check.ready && !live.catalogs[id]) await loadCatalog(id);
}

async function loadCatalog(id){
  live.busy[id] = true; paint();
  const j = await post("platform_models", {platform: id});
  if(j && j.catalog) live.catalogs[id] = j.catalog;
  live.busy[id] = false; paint();
}

async function change(op, extra){
  // Lock the card for the round trip -- paint() already disables its
  // switches and buttons while live.busy[platform] is set, so a second
  // toggle clicked before this one lands can no longer read the same stale
  // `entry` and clobber the first save.
  live.busy[extra.platform] = true; paint();
  try{
    const j = await post(op, extra);
    if(j && j.ok){
      toast(j.output.split("\n")[0], false, "check");
      // The spec's promise: switching a platform or a model off shows what
      // the command answers. Any lines after the first are
      // platform_affected_note's sentences -- cleared by a later successful
      // change that carries none of its own.
      const note = noteFromOutput(j.output);
      if(note) live.notes[extra.platform] = {text: note, err: false};
      else delete live.notes[extra.platform];
    } else if(j && j.output){
      // Refused -- post() already toasted j.output. The card keeps that same
      // sentence, in the engine's own words, until the next successful change.
      // (A lost session answers with no output at all: nothing to keep.)
      live.notes[extra.platform] = {text: j.output, err: true};
    }
    if(ctx && ctx.onChange) await ctx.onChange();   // the page re-reads /api/models and repaints this page
    return (j && j.ok) ? j : null;   // truthy on success, null on a refused or failed call
  } finally {
    live.busy[extra.platform] = false;
    paint();
  }
}

function binaryBlock(r, entry, check){
  const box = el("div");
  box.appendChild(el("h3", null, "Binary"));
  const val = el("div", "val" + (check ? (check.bin_found ? "" : " err") : " mute"));
  if(check && !check.bin_found){ val.appendChild(icon("xcircle")); val.appendChild(document.createTextNode("Not found on the launchd PATH")); }
  else { const c = el("code", null, (check && check.bin) || entry.bin || "…"); val.appendChild(c); }
  box.appendChild(val);
  const src = {env: "from AGENTLOOP_" + r.cli.toUpperCase() + "_BIN", file: "set here", auto: "found on PATH"}[(check || entry).bin_source] || "";
  const sub = el("div", "sub");
  sub.textContent = check
    ? (check.bin_found ? [src, check.version].filter(Boolean).join(" · ") + " · this is the path launchd sees, the one scheduled runs use"
                       : "looked at " + check.bin + " — type the path if it lives elsewhere, or install it: " + (check.reason.split("install: ")[1] || check.reason))
    : (live.busy[r.id] ? "checking…" : "— not checked");
  box.appendChild(sub);
  const ctrl = el("div", "ctrl");
  const inp = el("input"); inp.type = "text";
  // A refused save keeps what was typed on screen (live.typedBin) instead of
  // snapping back to the last saved entry.bin -- a bad path should not have
  // to be retyped from scratch.
  inp.value = live.typedBin[r.id] !== undefined ? live.typedBin[r.id] : (entry.bin || "");
  inp.placeholder = "Use another binary… (leave empty to detect)";
  inp.disabled = !!live.busy[r.id] || entry.supported === false;
  // Save on blur (and Enter, which just blurs) instead of "change": a
  // repaint can land while the operator is mid-typing (the three open-page
  // checks, any Test/Refresh/toggle on any card, the 5 s config_sig
  // re-read), and Chrome fires "change" -- and "blur" -- on an <input>
  // being removed from the DOM, with whatever partial path is typed so
  // far. `repainting` (set around the host rebuild in paint()) and
  // `inp.isConnected` both catch that and skip the save; paint()'s focus
  // preservation restores the typed text onto the new input, so the next
  // real blur/Enter still saves what the operator actually finished
  // typing. The value check also keeps a no-op blur (tab through without
  // editing) from re-posting the same path.
  const saveBin = async () => {
    if(repainting || !inp.isConnected) return;
    const v = inp.value.trim();
    if(v === (entry.bin || "")){
      // The operator retyped the stored path by hand, undoing an earlier
      // refused edit -- drop the stale typed value and its note so the
      // field and the card both go back to describing the saved state
      // right away, rather than on the next unrelated repaint.
      delete live.typedBin[r.id]; delete live.notes[r.id];
      paint();
      return;
    }
    live.typedBin[r.id] = v;   // shown back on a refusal -- see the input's value above
    const ok = await change("platform_set_bin", {platform: r.id, bin: v});
    if(!ok) return;
    delete live.typedBin[r.id];
    delete live.checks[r.id]; delete live.catalogs[r.id];   // the old check named the old binary
    await runCheck(r.id);
  };
  inp.addEventListener("blur", saveBin);
  inp.addEventListener("keydown", (e) => {
    if(e.key !== "Enter") return;
    if(repainting || !inp.isConnected) return;
    inp.blur();   // triggers saveBin above
  });
  ctrl.appendChild(inp);
  ctrl.appendChild(button("Detect", "radar", async () => {
    const ok = await change("platform_set_bin", {platform: r.id, bin: ""});
    if(!ok) return;
    delete live.typedBin[r.id];
    delete live.checks[r.id]; delete live.catalogs[r.id];
    await runCheck(r.id);
  }, live.busy[r.id] || entry.supported === false));
  box.appendChild(ctrl);
  return box;
}

function sessionBlock(r, entry, check){
  const box = el("div");
  box.appendChild(el("h3", null, "Session"));
  const val = el("div", "val" + (check ? (check.ready ? " ok" : (check.bin_found ? " err" : " mute")) : " mute"));
  if(!check){ val.textContent = live.busy[r.id] ? "checking…" : "— not checked"; }
  else if(check.ready){
    val.appendChild(icon("check"));
    const account = check.account || "unknown";
    // The engine already phrases codex's own answer as "Logged in ..." --
    // prefixing "Signed in as " on top of that reads twice.
    val.appendChild(document.createTextNode(account.startsWith("Logged in") ? account : "Signed in as " + account));
  }
  else if(!check.bin_found){ val.textContent = "— waiting for a binary"; }
  else { val.appendChild(icon("xcircle")); val.appendChild(document.createTextNode(check.reason)); }
  box.appendChild(val);
  const sub = el("div", "sub");
  sub.textContent = entry.supported === false
    ? "the session test and the model list arrive when the platform is supported"
    : (check ? ago(live.checkedAt[r.id]) + " with " + ({anthropic: "claude auth status", openai: "codex login status", opencode: "opencode models"})[r.id] : "");
  box.appendChild(sub);
  const ctrl = el("div", "ctrl");
  ctrl.appendChild(button("Test", "refresh", () => runCheck(r.id), live.busy[r.id] || entry.supported === false || (check && !check.bin_found)));
  ctrl.appendChild(el("span", "muted", "re-runs the sign-in check and the version probe"));
  box.appendChild(ctrl);
  return box;
}

// The two numbers behind these sentences answer two different questions, and
// the page used to print one of them under the other's name. jobs_on_platform
// is who is CONFIGURED to run here -- a job the operator parked still is;
// jobs_on_platform_enabled is who would run right now. Calling the first
// "enabled jobs" told an operator whose jobs were all parked that nothing used
// the platform, so switching it (or one of its models) off looked free.
function platformJobsLine(entry, r){
  if(entry.supported === false) return "runs on " + r.name + " are not supported yet";
  const n = entry.jobs_on_platform || 0;
  if(!n) return entry.enabled ? "jobs may pick this platform" : "unlocks when the session test passes";
  const on = entry.jobs_on_platform_enabled;
  return n + " job" + (n === 1 ? "" : "s") + " run" + (n === 1 ? "s" : "") + " here"
    + (typeof on === "number" && on !== n ? " (" + on + " enabled)" : "");
}

// A model row's badge counts everything; the tooltip is where the switched-on
// half is spelled out, so the badge stays a short read. `on` is undefined when
// the payload predates jobs_using_enabled -- the same rule platformJobsLine
// follows: an absent number is not zero, so the clause is left off entirely
// rather than telling every row that nothing uses it.
function modelJobsTitle(n, on){
  if(!n) return "";
  return n + " job" + (n === 1 ? "" : "s") + " use" + (n === 1 ? "s" : "") + " this model"
    + (typeof on === "number" ? " (" + on + " switched on)" : "");
}

function modelRow(r, entry, m, using, gone){
  const enabledNow = (entry.models_enabled || []).includes(m.v);
  const row = el("div", "mrow" + (enabledNow ? "" : " offrow"));
  // The long reason lives in the row's tooltip, not the line itself -- the
  // span stays a short read, the hover is for whoever wants the why.
  if(gone) row.title = "the engine refuses a list with an id it cannot find";
  const name = el("div", "mname");
  name.appendChild(el("b", null, m.label || m.v));
  name.appendChild(el("span", null, m.v + (m.desc ? " — " + m.desc : "")
    + (gone ? " — no longer in the catalog — switch it off before changing the others" : "")
    + (m.deprecated_by ? " — deprecated, → " + m.deprecated_by : "")));
  row.appendChild(name);
  const meta = el("div", "mmeta");
  if(m.provider) meta.appendChild(el("span", null, m.provider));
  if(m.price) meta.appendChild(el("span", "price", "$" + m.price.input + " / $" + m.price.output));
  else if(r.id !== "anthropic" && !gone) meta.appendChild(el("span", null, "no price"));
  if(m.tools === false) meta.appendChild(el("span", null, "no tools"));
  if(m.efforts && m.efforts.length) meta.appendChild(el("span", null, m.efforts[0] + " → " + m.efforts[m.efforts.length - 1]));
  const n = using[m.v] || 0;
  if(n) meta.appendChild(el("span", "jobs", n + " job" + (n === 1 ? "" : "s")));
  row.appendChild(meta);
  const onHere = entry.jobs_using_enabled ? (entry.jobs_using_enabled[m.v] || 0) : undefined;
  row.appendChild(switchEl(enabledNow, live.busy[r.id], modelJobsTitle(n, onHere), "Switch on " + m.v, async (on) => {
    const cur = (entry.models_enabled || []).slice();
    const next = on ? (cur.includes(m.v) ? cur : cur.concat([m.v])) : cur.filter(v => v !== m.v);
    await change("platform_set_models", {platform: r.id, models: next});
  }));
  return row;
}

function modelsSection(r, entry, check, catalog){
  const frag = document.createDocumentFragment();
  const head = el("div", "models-h");
  head.appendChild(el("h3", null, "Models"));
  const age = el("span", "age");
  if(catalog){
    const from = ({anthropic: "from the installed CLI", openai: "from codex debug models", opencode: "from opencode models --verbose"})[r.id];
    age.textContent = from + (catalog.stale ? " — " + catalog.reason : "") + (r.id === "anthropic" ? " · every Claude model takes effort low → max" : "");
  }else if(entry.supported === false){
    age.textContent = "the providers you sign in to, listed by " + r.cli + " models";
  }
  head.appendChild(age);
  head.appendChild(el("span", "sp"));
  const ready = !!(check && check.ready);
  head.appendChild(button(catalog ? "Refresh" : "Load models", "refresh", () => loadCatalog(r.id), !ready || live.busy[r.id]));
  frag.appendChild(head);
  if(entry.supported === false){
    frag.appendChild(el("div", "mempty", "Nothing to switch on yet — " + r.name + " jobs, and this list, come with the next release. The card is here so the binary is found and named before that day."));
    return frag;
  }
  if(!catalog){
    frag.appendChild(el("div", "mempty", live.busy[r.id] ? "Loading the models…"
      : (ready ? "The catalog could not be loaded — Load models to try again." : "Test the session first, then load the models.")));
    return frag;
  }
  const using = entry.jobs_using || {};
  const seen = new Set();
  catalog.models.forEach(m => { seen.add(m.v); frag.appendChild(modelRow(r, entry, m, using, false)); });
  (entry.models_enabled || []).filter(v => !seen.has(v)).forEach(v => frag.appendChild(modelRow(r, entry, {v, label: v}, using, true)));
  if(!catalog.models.length && !(entry.models_enabled || []).length) frag.appendChild(el("div", "mempty", "The catalog came back empty" + (catalog.reason ? " — " + catalog.reason : "") + "."));
  return frag;
}

function platformCard(r, entry, check, catalog){
  const card = el("section", "platcard"); card.id = "platcard-" + r.id;
  const h = el("div", "platcard-h");
  h.appendChild(el("div", "platcard-ic" + (entry.supported === false ? " off" : ""), r.mark));
  const t = el("div", "platcard-t"); t.appendChild(el("b", null, r.name)); t.appendChild(el("span", null, r.sub)); h.appendChild(t);
  const right = el("div", "platcard-r");
  const st = platformStatus(entry, check);
  const pill = el("span", "pill " + st.cls, st.label); right.appendChild(pill);
  const sw = el("div", "swlabel");
  const row = el("div", "swrow"); row.appendChild(document.createTextNode(entry.enabled ? "Enabled " : "Disabled "));
  const canToggle = entry.supported !== false && !live.busy[r.id] && (entry.enabled || (check && check.ready));
  row.appendChild(switchEl(!!entry.enabled, !canToggle,
    entry.supported === false ? "runs on " + r.name + " arrive with the next release" : (canToggle ? "" : "unlocks when the session test passes"),
    "Enable " + r.name,
    async (on) => { await change(on ? "platform_enable" : "platform_disable", {platform: r.id}); }));
  sw.appendChild(row);
  sw.appendChild(el("span", null, platformJobsLine(entry, r)));
  right.appendChild(sw); h.appendChild(right); card.appendChild(h);
  // The engine's own answer, in its own words: a refusal (red, alert icon)
  // or -- a switch-off's sentence about the enabled jobs it leaves skipped --
  // a plain note (check icon). See change() for how live.notes is kept.
  const note = live.notes[r.id];
  if(note){
    const nd = el("div", "platnote" + (note.err ? " err" : ""));
    nd.appendChild(icon(note.err ? "alert" : "check"));
    nd.appendChild(document.createTextNode(note.text));
    card.appendChild(nd);
  }
  const g = el("div", "platcard-g"); g.appendChild(binaryBlock(r, entry, check)); g.appendChild(sessionBlock(r, entry, check)); card.appendChild(g);
  card.appendChild(modelsSection(r, entry, check, catalog));
  return card;
}

function paint(){
  if(!ctx) return;
  const head = $("st-head"), host = $("st-platforms");
  if(!head || !host) return;
  head.textContent = "";
  head.appendChild(pageHeader({icon: "gear", title: "Settings",
    subtitle: "Which agent CLIs this scheduler may run, and which of their models a job may pick."}));
  // The three checks and two catalogs this page fires on open land within
  // the first seconds, each one repainting -- so save the focused Binary
  // field's card, value and selection before tearing the DOM down, and
  // restore them after, or a still-typing operator loses keystrokes to a
  // completion that has nothing to do with what they are editing. Every
  // switch is an <input> too (components.css covers the whole label with an
  // invisible checkbox, which is the real click target and keeps focus
  // after a toggle) -- type === "text" is what tells the Binary field apart
  // from one of those, or a toggle would overwrite it with the checkbox's
  // own value ("on").
  const active = document.activeElement;
  let savedFocus = null;
  if(active && active.tagName === "INPUT" && active.type === "text" && host.contains(active)){
    const card = active.closest("section.platcard");
    if(card) savedFocus = {cardId: card.id, value: active.value, selectionStart: active.selectionStart, selectionEnd: active.selectionEnd};
  }
  repainting = true;   // see binaryBlock: an input torn out below must not save on the blur this causes
  try{
    host.textContent = "";
    if(ctx.error){
      const b = setupBanner(false, ctx.error, false); if(b) host.appendChild(b);
    }
    host.appendChild(el("div", "summary", settingsSummary(ctx.platforms)));
    REGISTRY.forEach(r => host.appendChild(platformCard(r, (ctx.platforms || {})[r.id] || {}, live.checks[r.id] || null, live.catalogs[r.id] || null)));
  } finally {
    // A throw mid-rebuild (a bad payload, a bug in one card) must not leave
    // this stuck true -- that would silently disable the Binary field's
    // save for every card, not just the one that failed to draw.
    repainting = false;
  }
  if(savedFocus){
    const card = $(savedFocus.cardId);
    const inp = card && card.querySelector(".ctrl input");
    if(inp){
      inp.value = savedFocus.value;
      inp.setSelectionRange(savedFocus.selectionStart, savedFocus.selectionEnd);
      inp.focus({preventScroll: true});
    }
  }
}

// The page calls this on entering the view and after every /api/models
// re-read. The first paint that carries a real payload also fires the three
// live checks, in parallel. `configured` is undefined until /api/models has
// answered, and the page only reads it once signed in -- so a paint before
// that (the tab restored onto Settings with its session gone: the page draws
// the views before it asks the server for the session) shows the shells and
// probes nothing. A check sent then only comes back 401, and were it the one
// that spent the flag, the cards would sit at "checking" until Test.
export function renderSettingsPage(c){
  ctx = c;
  paint();
  if(probed || c.configured === undefined) return;
  probed = true;
  REGISTRY.forEach(r => { if(!live.checks[r.id] && !live.busy[r.id]) runCheck(r.id); });
}
