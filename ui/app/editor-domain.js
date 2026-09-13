/* ------------------------------------------------------------ editor domain

   The job editor and the project editor share one wizard (makeWizard,
   bin/dashboard.html) for their dual-mode navigation and dirty tracking, and
   each owns a handful of small form<->job mappings and a per-step validation
   rule. Every one of those reads $("...") or `document` directly today,
   which is exactly what a characterisation test cannot drive without a
   browser -- so only the DOM-free half of each moved here: the comparison,
   the mapping, the rule. The DOM read that feeds it (the snapshot itself,
   the day buttons, the repo rows, the slider's raw value, the fields
   validation reads) stays exactly where it was, in bin/dashboard.html, which
   now calls back in by name.

   Nothing here touches $, document or AL.DATA -- every export takes plain
   values and returns plain values, so this module needs nothing from
   ./page.js and nothing bindPage() sets up. */

// Two snapshots of one wizard (makeWizard's own W.snapshot()) -- which keys
// disagree between them. Compared key by key, never the two container
// objects themselves: snapshot() builds a fresh object on every call, so two
// snapshots holding identical values are never `===`, and a reference
// comparison here would report the form dirty the instant a second one was
// taken, even an untouched one. edWiz/pjWiz's own W.changed() (dirtySteps'
// own source) and W.dirty() (edIsDirty) both read this -- one true
// implementation of "what changed" for both.
export function changedKeys(now, clean){
  return Object.keys(now).filter(k => now[k] !== clean[k]);
}

// The three platforms this page knows how to run a job on, and the label
// their combos and chips show for each. platformKey is the key a platform
// value reads /api/models under: the value itself when the page knows it,
// anthropic for anything else (a hand-edited unknown) -- the one rule every
// per-platform lookup below reads instead of its own "openai ? openai :
// anthropic" guess.
export const KNOWN_PLATFORMS = ["anthropic", "openai", "opencode"];
export const PLATFORM_LABELS = {anthropic: "Anthropic", openai: "OpenAI", opencode: "OpenCode"};
export function platformKey(p){ return KNOWN_PLATFORMS.includes(p) ? p : "anthropic"; }

// Effort: slider position <-> CLI value. Index 0 is always "" (unset: the
// CLI decides), so a slider's stops are [""] + the platform's levels. The
// levels are the PLATFORM's -- and on OpenAI the chosen MODEL's -- read off
// /api/models (its `platforms` object); FALLBACK_EFFORTS is what the page
// opens with before that fetch answers, and what a platform the payload does
// not carry gets. A platform the payload DOES carry but with no levels (the
// server's "codex unavailable" shape: available false, empty lists) offers
// only the unset stop -- the built-in ladder is Anthropic's, and the engine
// would refuse its stops on OpenAI.
// The job editor's "ed-effort" and the Security pane's "sec-effort" are one
// control (effortSet/effortGet, bin/dashboard.html); each keeps the ladder
// it was last built with and passes it back in here.
export const FALLBACK_EFFORTS = ["", "low", "medium", "high", "xhigh", "max"];
export const EFFORTS = FALLBACK_EFFORTS;   // the pre-platforms name, still read at boot and by tests

export function effortsFor(platform, model, platforms){
  const key = platformKey(platform);
  const p = (platforms || {})[key];
  if(!p) return FALLBACK_EFFORTS.slice();
  let levels = null;
  if(key !== "anthropic" && model){
    const m = (p.models || []).find(x => x && x.v === model);
    // A model FOUND with an empty `efforts` array is a model without variants
    // -- but that is only true on OpenCode, where opencode_catalog_efforts
    // gives that same explicit, falsy answer for a model with no variants.
    // OpenAI's openai_catalog_efforts treats an empty `supported_reasoning_levels`
    // like the model was never found, so it falls through to the platform's
    // broader union below the same way a model NOT found at all does (which
    // leaves `levels` untouched at null).
    if(m && Array.isArray(m.efforts) && (key === "opencode" || m.efforts.length)) levels = m.efforts;
  }
  if(!levels && Array.isArray(p.efforts) && p.efforts.length) levels = p.efforts;
  if(!levels || !levels.length) return [""];   // listed, but with no levels: nothing to offer beyond unset
  return [""].concat(levels.filter(l => typeof l === "string" && l));
}

// A job's effort string -> the slider index that represents it on `list`
// (the built-in ladder when none is given). An empty/unrecognised value
// settles on 0 (unset), never -1.
export function effortIndex(v, list){
  return Math.max(0, (list || FALLBACK_EFFORTS).indexOf(v || ""));
}

// The slider's own raw (string) value -> the job's effort string on `list`.
// An out-of-range index settles on "" (unset), the same as 0 does.
export function effortFromIndex(raw, list){
  return (list || FALLBACK_EFFORTS)[+raw || 0] || "";
}

// The permission modes and defaults, per platform. The engine owns both
// vocabularies (platform_permissions, platform_default_permission) and the
// server mirrors them on /api/models; this is the page's read of that
// payload, with a built-in fallback for before the fetch answers. The
// fallback is the server's PLATFORM_PERMISSIONS (bin/agentloop-server)
// verbatim -- labels AND order -- so nothing flips on screen when the
// payload arrives; tests/test_page_contract.py pins the two together. The
// labels say what a mode DOES on that CLI.
export const FALLBACK_PERMISSIONS = {
  anthropic: [
    {v: "acceptEdits", label: "acceptEdits — edits allowed, commands ask"},
    {v: "auto", label: "auto — the CLI decides per tool"},
    {v: "bypassPermissions", label: "bypassPermissions — nothing asks"},
    {v: "manual", label: "manual — everything asks (headless: everything denied)"},
    {v: "dontAsk", label: "dontAsk — allowlisted tools only, no prompts"},
    {v: "plan", label: "plan — read-only planning"},
  ],
  openai: [
    {v: "read-only", label: "read-only — sandbox: no writes, no network"},
    {v: "workspace-write", label: "workspace-write — sandbox: writes inside the workspace"},
    {v: "full-access", label: "full-access — no sandbox, no approvals"},
  ],
  opencode: [
    {v: "full-access", label: "full-access — every tool, no approvals (the worktree is the isolation)"},
    {v: "read-only", label: "read-only — no edit, write, bash or subagents"},
  ],
};

export function permissionsFor(platform, platforms){
  const key = platformKey(platform);
  const p = (platforms || {})[key];
  const list = (p && Array.isArray(p.permissions) && p.permissions.length) ? p.permissions : FALLBACK_PERMISSIONS[key];
  return list.map(o => ({v: o.v, label: o.label || o.v}));
}

// platform_default_permission's two answers, mirrored: what a job and what a
// security analysis run as when nothing is set.
export function defaultPermissionFor(platform, kind){
  if(platform === "opencode") return "full-access";
  if(platform === "openai") return kind === "security" ? "full-access" : "workspace-write";
  // Both kinds, for the reason the engine's platform_default_permission gives:
  // every run here is headless, and dontAsk denies every tool it has no
  // allowlist for -- a job left on it can do nothing and spends a session
  // finding out.
  return "bypassPermissions";
}

export function defaultModelFor(platform, platforms){
  const key = platformKey(platform);
  const p = (platforms || {})[key];
  if(p && p.default_model) return p.default_model;
  return key === "anthropic" ? "opus" : "";
}

// The suffix a flagged value's label ends with -- one spelling shared by
// modelOptionsFor and platformOptions, so a value Settings switched off
// never reads two different ways depending on which combo it showed up in.
export const DISABLED_SUFFIX = " (disabled in Settings)";

// Whether Settings lets a job keep this model: no verdict until the registry
// arrives (models_enabled absent → true), the id itself on the list, or a
// family value (opus…) that the engine would launch. The engine resolves a
// family to the id its cache holds NOW (effective_model) and gates on THAT
// id -- /api/models carries the same resolutions as `families` -- so a
// family is on when the list names the family itself or the id it resolves
// to today; any other id of the family on the list does not count, since on
// the day the daily pass moves the family to a new id the launch is refused
// (a payload without `families` falls back to the by-prefix guess). The
// reverse also holds: an explicit id counts as on when its bare family name
// -- what the seed writes before the cache ever resolved anything -- sits on
// the enabled list and `families` maps that family to this same id; any
// OTHER id of that family still stays off. The one rule modelOptionsFor,
// platformState and the editor's Agent step all read.
export function modelEnabled(platform, model, platforms){
  const key = platformKey(platform);
  const p = (platforms || {})[key];
  if(!p || !Array.isArray(p.models_enabled)) return true;
  if(!model) return true;
  if(p.models_enabled.includes(model)) return true;
  if(!/^(opus|sonnet|haiku|fable)$/.test(model)){
    // Not a bare family value either -- the only other way in is a family
    // whose name sits unresolved on the list and resolves to THIS id.
    return Object.entries(p.families || {}).some(([f, id]) => id === model && p.models_enabled.includes(f));
  }
  if(p.families && typeof p.families === "object"){
    const id = p.families[model];
    return typeof id === "string" && id !== "" && p.models_enabled.includes(id);
  }
  return p.models_enabled.some(id => id.startsWith("claude-" + model + "-"));
}

// The model combo's option list for one platform, filtered by what Settings
// switched on (`models_enabled`; a payload without it filters nothing).
// Anthropic keeps the family/generation grouping the page already draws
// (groupFn is the page's groupModels); OpenAI is flat, in the catalog's own
// order, each slug with its description, a deprecated slug at the end
// pointing at its successor, and " · no price" on a slug config/pricing.json
// does not price. `current` -- the job's own value -- joins the end, flagged,
// when modelEnabled says Settings really switched it off (never while the
// registry is still unknown, and never for a family value some concrete id
// of it keeps enabled): the editor shows the truth, never rewrites.
export function modelOptionsFor(platform, platforms, groupFn, current){
  const key = platformKey(platform);
  const p = (platforms || {})[key];
  const enabledList = (p && Array.isArray(p.models_enabled)) ? p.models_enabled : null;
  const keep = (v) => !enabledList || enabledList.includes(v);
  let opts;
  if(key === "anthropic"){
    const ids = ((p && Array.isArray(p.models)) ? p.models : []).filter(keep);
    opts = groupFn ? groupFn(ids) : ids.map(v => ({v, label: v}));
  }else if(key === "opencode"){
    // Flat, like OpenAI's own list just below -- but named by provider
    // instead of described, since the catalog gives OpenCode a provider per
    // model and no free-text description at all. The same two flags OpenAI
    // already carries (no price, an id Settings switched off) plus a third
    // this platform alone has: a model the catalog says makes no tool calls.
    const list = ((p && Array.isArray(p.models)) ? p.models : []).filter(m => keep(m.v));
    opts = list.map(m => ({v: m.v, label: (m.label || m.v)
      + (m.provider ? " (" + m.provider + ")" : "")
      + (m.priced === false ? " · no price" : "")
      + (m.tools === false ? " · no tools" : "")}));
  }else{
    const list = ((p && Array.isArray(p.models)) ? p.models : []).filter(m => keep(m.v));
    const noPrice = (m) => m.priced === false ? " · no price" : "";
    const live = list.filter(m => !m.deprecated_by).map(m => ({
      v: m.v, label: (m.label || m.v) + (m.desc ? " — " + m.desc : "") + noPrice(m)}));
    const old = list.filter(m => m.deprecated_by).map(m => ({
      v: m.v, label: (m.label || m.v) + " — → " + m.deprecated_by
        + (m.retires_at ? ", retires " + String(m.retires_at).slice(0, 10) : "") + noPrice(m)}));
    opts = live.concat(old);
  }
  if(current && !modelEnabled(platform, current, platforms)){
    opts.push({v: current, label: current + DISABLED_SUFFIX, flagged: true});
  }
  return opts;
}

// A job's effective platform, the engine's way: resolve() hands back the
// job's OWN platform whenever it is non-empty -- the project's only fills an
// EMPTY one -- and job_platform() then reads any word the engine does not
// know as anthropic. So an unknown own value is anthropic here too, never the
// project's platform; an unknown project value is anthropic as well.
export function platformOf(job, project){
  const own = job && job.platform;
  if(own) return platformKey(own);
  const pp = project && project.platform;
  if(KNOWN_PLATFORMS.includes(pp)) return pp;
  return "anthropic";
}

export function platformLabel(p){ return PLATFORM_LABELS[p] || "Anthropic"; }

// Whether /api/models has told this page what Settings switched on: the
// registry rides on every platform entry as `enabled`. A payload without it
// (or none yet) leaves every editor as it was before Settings existed.
export function registryKnown(platforms){
  const a = platforms && platforms.anthropic;
  return !!(a && a.enabled !== undefined);
}

// The Platform combo's options: the platforms switched on in Settings (both,
// until the registry arrives), plus the job's current one flagged when it is
// not among them -- the editor never rewrites a job on its own.
export function platformOptions(platforms, current){
  const known = KNOWN_PLATFORMS;
  const have = registryKnown(platforms);
  const out = known.filter(p => !have || ((platforms[p] || {}).usable === true))
                   .map(p => ({v: p, label: PLATFORM_LABELS[p]}));
  if(current && !out.some(o => o.v === current)){
    const label = (PLATFORM_LABELS[current] || current) + DISABLED_SUFFIX;
    out.push({v: current, label, flagged: true});
  }
  return out;
}

// How many models the catalog carries that Settings keeps off the list.
export function hiddenModelCount(platform, platforms){
  const key = platformKey(platform);
  const p = (platforms || {})[key];
  if(!p || !Array.isArray(p.models_enabled) || !Array.isArray(p.models)) return 0;
  const ids = p.models.map(m => typeof m === "string" ? m : m.v);
  return ids.filter(v => !p.models_enabled.includes(v)).length;
}

// The "on" day buttons' own dataset.day strings (already read off the DOM by
// getDays, bin/dashboard.html) -> the numbers a job's active_days is stored
// as.
export function dayNumbers(rawValues){
  return rawValues.map(v => +v);
}

// One raw repo row (untrimmed .value strings straight off the DOM) -> the
// {name,path,base} shape the rest of the project editor works with, dropping
// a row missing its name or its path. Such a row is not "malformed" so much
// as not filled in yet -- collectRepos (bin/dashboard.html) has always
// dropped it before anything downstream, including validateProjectStep's own
// "repos" rule below, ever saw it.
export function shapeRepoRows(rawRows){
  return rawRows
    .map(r => ({ name: r.name.trim(), path: r.path.trim(), base: r.base.trim() }))
    .filter(r => r.name && r.path);
}

// validateProjectStep's (bin/dashboard.html) own rules -- given what a step's
// fields hold, is it complete enough to move past? Extracted whole: same
// conditions, same messages, in the same order, only turned from
// "return the reason, or null" into a verdict, since a pure decision
// answering a question is what this is. The DOM reads that gather `values`
// (pj-name, pj-cwd, editingProject, DATA.projects, pjMulti, collectRepos())
// stay in validateProjectStep itself.
export function projectStepError(k, values){
  if(k === "project"){
    const n = values.name;
    if(!n) return { ok: false, message: "A project name is required." };
    // Creating only: renaming onto an existing name is the engine's to
    // refuse, and it knows about jobs pointing at both.
    if(!values.editingProject && values.projects.some(p => p.name === n))
      return { ok: false, message: "A project with that name already exists." };
    if(!values.cwd)
      return { ok: false, message: "Pick a working directory — the folder its runs work in." };
  }
  // The engine picks the repo the agent starts in by matching a row's path
  // against the cwd, and aborts the run when none does. That used to
  // surface hours later as a run that failed for no stated reason; catch it
  // here, where the two paths are both on screen.
  if(k === "repos" && values.multi){
    const rows = values.repos;
    if(!rows.length)
      return { ok: false, message: "Add a repository, or go back to a single repository." };
    if(!rows.some(r => r.path === values.cwd))
      return { ok: false, message: "One repo's path must be exactly the working directory from step 1 — "
             + "that is the repo the agent starts in. None of these match it." };
  }
  return { ok: true };
}

// What a run's cost cell says, by cost_basis. `fmt` is the caller's money()
// (page.js, or overview.js's own copy) so this stays free of the DOM and of
// Intl. `reported` is the CLI's own figure; `estimated` is ours, from tokens
// and config/pricing.json, and says so with a ~ and a tooltip; `none` is a
// dash -- never $0.00, which would read as "free". A record from before the
// field existed is a reported one.
export function costParts(r, fmt){
  const basis = (r && r.cost_basis) || "reported";
  if(basis === "none") return {text: "—", cls: "cost-none",
    tip: "No cost recorded: the model has no price in config/pricing.json, or the run ended without a final event"};
  if(basis === "estimated") return {text: "~" + fmt((r && r.cost) || 0), cls: "cost-est",
    tip: "Estimated from the run's tokens with config/pricing.json — the Codex CLI reports tokens, not dollars"};
  return {text: fmt((r && r.cost) || 0), cls: "", tip: ""};
}

// A run's token counts in one line: "32,675 in (28,160 cached) · 123 out".
// Reasoning tokens are INSIDE output_tokens on Codex, so they are named in
// brackets and never added. null (a run with no usage) -> "—".
export function tokensText(t){
  if(!t || typeof t !== "object") return "—";
  const n = (v) => Number(v || 0).toLocaleString("en-US");
  const extra = [];
  if(t.cached) extra.push(n(t.cached) + " cached");
  if(t.cache_write) extra.push(n(t.cache_write) + " cache write");
  let s = n(t.input) + " in" + (extra.length ? " (" + extra.join(", ") + ")" : "") + " · " + n(t.output) + " out";
  if(t.reasoning) s += " (" + n(t.reasoning) + " reasoning)";
  return s;
}
