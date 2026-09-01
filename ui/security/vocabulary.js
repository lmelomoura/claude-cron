/* The words this area works in, and the pure functions over them.

   THE ONE RULE FOR THIS WHOLE AREA: nothing that came out of an analysis is
   ever handed to the HTML parser. A finding's title, its file paths, its rationale
   and the branch it was found on are all strings from analysed code — and a
   branch name may legally contain '<', '>' and '&', so
   `feature/<img src=x onerror=…>` is a branch a repository can create and this
   page will list. Every one of them goes in through textContent or an
   attribute property. The area reaches no HTML sink at all: the only markup it
   draws is an icon, and injecting THAT stayed in the page beside the icon
   table it comes from (CC.icon / CC.iconLabel). A test in
   tests/test_page_contract.py pins both halves so the pattern cannot come
   back.

   That test is a plain substring scan of these files, comments included, which
   is why no comment in this area spells the sinks out either: a guard that has
   to parse JavaScript to decide what is code is a guard with a way around it.
   Name the HTML parser, not the property. */
import { projById } from "./page.js";

export const SEC_STATES = ["new","regressed","open","partial","pending","fixed",
                    "accepted","false_positive"];
export const SEC_STATE_LABEL = {new:"New", regressed:"Regressed", open:"Open", partial:"Partial",
                         pending:"Not re-checked", fixed:"Fixed",
                         accepted:"Accepted", false_positive:"False positive"};
/* Every state earns its own word, and the word alone does not explain it. */
export const SEC_STATE_HELP = {
  new:        "Not in the previous analysis of this branch.",
  regressed:  "Was fixed once and is back — usually a fix that closed the symptom, not the route.",
  open:       "Was here last time too, unchanged.",
  partial:    "Some of its places are gone, or the agent recorded it as mitigated but not eliminated.",
  pending:    "In the previous analysis and not re-checked by this one yet — a statement "
            + "about this analysis, not about the code. Becomes fixed only when its absence "
            + "is proven: deterministic findings once prepare completes, code-review findings "
            + "only when the analysis closes with full coverage.",
  fixed:      "Gone since the previous analysis of this branch — and the phase that would "
            + "have re-found it DID finish, so the absence is proven, not assumed.",
  accepted:   "You accepted the risk. The reason is recorded and outlives every analysis after it.",
  false_positive: "You said it is not real. If the code around it changes the fingerprint changes "
                + "and it comes back as new — different code, so a fresh judgement.",
};
// Every KNOWN severity must appear here, lowest first, or it inherits
// secSevRank's above-critical fallback below -- meant for corrupted data,
// not for a legitimate value the vocabulary simply forgot.
export const SEV_ORDER = ["info","low","medium","high","critical"];
export const SEC_PROFILES = ["quick","standard","deep"];
/* Mirrors bin/security/ledger.py's own EVENT_KINDS -- a closed set, not
   fetched: the sidebar's per-kind counts (project-screen.js's recent-activity
   card, and the Activity screen's own summary card) have to draw their own
   labels before any request has ever answered, the same reasoning
   FIND_CATEGORIES in findings-screen.js is duplicated rather than read off a
   response. Kept in ONE place (here) rather than two, after the Activity
   screen needed the identical label table project-screen.js already had --
   a duplicate the moment a second reader showed up is exactly the drift this
   file's own opening paragraph warns every OTHER vocabulary in this area
   against. */
export const EVENT_KINDS = ["analysis_started", "analysis_finished", "decision_made",
                    "settings_changed", "report_exported"];
export const EVENT_KIND_LABEL = {
  analysis_started: "Analysis started", analysis_finished: "Analysis finished",
  decision_made: "Decision made", settings_changed: "Settings changed",
  report_exported: "Report exported",
};
/* The Recent-activity card's row furniture per kind (ProjectOverview.png):
   the icon in its tinted box, and the kind badge on the row's right --
   label plus which house .pill tone it wears. Tones reuse the pill
   vocabulary components.css already defines rather than the mockup's own
   sampled tints: `running`/`done` are the analysis-state pair (an
   analysis_started event mirrors the state a run entered, a finished one
   the state it closed in), `profile` is the accent tone every neutral
   this-area badge already wears, `disabled` the grey for configuration
   noise. One entry per EVENT_KINDS member -- a kind added there without a
   row here falls back to the plain label with no badge, and the contract
   test that walks EVENT_KINDS against this table is what keeps the two
   from drifting apart in silence. */
export const SEC_EVENT_META = {
  analysis_started:  {icon: "play",        badge: "Started",   pill: "running"},
  analysis_finished: {icon: "shieldcheck", badge: "Completed", pill: "done"},
  decision_made:     {icon: "hammer",      badge: "Decision",  pill: "profile"},
  settings_changed:  {icon: "gear",        badge: "Settings",  pill: "disabled"},
  report_exported:   {icon: "file",        badge: "Exported",  pill: "profile"},
};
/* ONE wording for "nothing has ever been read here", used by every screen in
   the area that has to say it. There were six near-variants of this sentence
   across four modules -- three of them told the reader what to do next and
   three did not, twice on the same screen -- so the same fact read as
   different facts depending on which panel you happened to be looking at.

   The two DENSITIES are deliberate and are not two wordings: a table cell or
   a header bit has room for the label alone, so it renders `.short` and
   carries `.next` as its title, and every occurrence still tells the reader
   where to go. `.attempted` is the other half of the distinction the area
   already draws everywhere it draws this one at all -- a project whose every
   analysis failed is not a project nobody ever touched, and collapsing the
   two is what made the Overview tab contradict the Branches tab one click
   away over the identical project. `.branch`/`.pickBranch` are the
   single-analysis pane's own scope: one BRANCH, not the project, which is a
   genuinely different fact and keeps its own sentence rather than being
   forced into the project one. */
export const SEC_NEVER = {
  short: "Never analysed",
  next: "Never analysed — switch to Runs to pick a branch and start.",
  attempted: "No analysis of this project has finished yet — see Runs for what was attempted.",
  branch: "Never analysed on this branch — press Analyse to make the first one.",
  pickBranch: "Pick a branch, or type one, and press Analyse.",
};

/* WHAT THE SEVERITY FLOOR IS, said once on every screen that shows a number
   it does not apply to.

   `min_severity` (a project's own setting) is a DRILL-DOWN READING AID and
   nothing else. It narrows two surfaces -- the single-analysis checklist
   (analysis.js) and the findings browser's table (findings-screen.js) -- and
   both of those say out loud how many rows they are holding back. It narrows
   NOTHING else: not the Overview chips, not the index KPIs or posture pills,
   not the Branches tab's "Open", not either donut. Those are POSTURE numbers,
   and a posture number is a statement about exposure: a recorded finding
   below somebody's triage threshold is still exposure, and a fleet total that
   quietly dropped it would be under-reporting, which is the wrong way for a
   security screen to be wrong. The floor's job is to declutter a working
   list; it is not a claim that anything went away.

   That is the decision, and this constant is it being said rather than
   assumed. It was previously neither: the floor was applied on two surfaces
   and ignored on six, only the two that applied it mentioned it, and a reader
   comparing "3 open" on the Overview with two rows in the drill-down of the
   same analysis had nothing on screen to explain the difference. */
export const SEC_FLOOR_SCOPE_NOTE =
  "Every recorded finding is counted here. A project's severity floor only "
  + "narrows its findings list and the checklist of a single analysis, and "
  + "each of those says how many rows it is holding back — it never narrows "
  + "a posture total.";

/* The deterministic phase (secrets, dependencies, CVEs, hygiene) writes its
   findings before the agent is even launched, so a poll this quick shows real
   results within seconds of pressing Analyse while the SAST is still running. */
export const SEC_POLL_MS = 4000;
/* An analysis row is opened moments BEFORE the run that carries it starts, so
   the two stamps are seconds apart and never equal. A project analyses one
   branch at a time (the derived job is max_parallel 1), so "the run nearest
   this analysis's start" is unambiguous — but only inside a window, or an
   analysis whose run never made it to the journal would adopt a stranger. */
// analyze opens the ledger row and detaches the run within seconds of each
// other, so the right run starts within moments of the analysis. 900s once
// linked a RUNNING analysis to the previous attempt's failed run -- 8 minutes
// apart, same job id, nearest by start -- and "Open the run" showed a dead
// run's BLOCKED transcript over a live analysis.
export const SEC_RUN_WINDOW = 120;

export const secCfg = (name) => (projById(name) || {}).security || {};
/* EXACTLY what security_enabled does in the engine, and no wider. It reads the
   field through `jq -r`, which prints the boolean true and the string "true"
   identically, and compares the result to "true" — so those two values are on
   and every other one, `1` included, is off. /api/config serves projects.json
   through untouched, so the page sees the same raw JSON jq does: a project
   accepted here but refused there would offer an Analyse button whose only
   possible outcome is the engine's refusal. */
export const secEnabled = (p) => { const s = (p || {}).security;
  return !!(s && (s.enabled === true || s.enabled === "true")); };
export const secMinSeverity = (name) => { const v = secCfg(name).min_severity;
  return SEV_ORDER.includes(v) ? v : "low"; };
export const secDefaultProfile = (name) => { const v = secCfg(name).default_profile;
  return SEC_PROFILES.includes(v) ? v : "standard"; };
/* A severity the vocabulary does not know is ranked ABOVE critical rather
   than below low: an unrecognised value is not a reason to hide a finding,
   and the display filter is the one place that could silently do it. This
   fallback is for CORRUPTED data only -- a value nothing in the pipeline
   ever produces -- and it is a trap, not a feature: every severity the
   pipeline can legitimately emit (info included) MUST be listed in
   SEV_ORDER, or it silently falls into this branch and sorts and filters as
   if it were worse than critical. */
export const secSevRank = (s) => { const i = SEV_ORDER.indexOf(s);
  return i < 0 ? SEV_ORDER.length : i; };
/* Class names, not labels: the label shows whatever the record actually says,
   the class has to be one of the values the stylesheet knows about. */
export const secSevKey = (f) => SEV_ORDER.includes(f.severity) ? f.severity : "unknown";
export const secStateKey = (f) => SEC_STATES.includes(f.state) ? f.state : "unknown";
/* A project with one checkout has no repo rows, and `repo` is still the column
   every analysis is filed under — so its own name is what it is filed as. Read
   from here by everything, so the history of a single-repo project cannot end
   up split across two spellings. */
export function secRepos(p){
  const rows = ((p || {}).repos || []).map(r => r && r.name).filter(Boolean);
  return rows.length ? rows : [(p || {}).name].filter(Boolean);
}

export function secVisible(findings, minSeverity){
  const floor = SEV_ORDER.indexOf(minSeverity || "low");
  // A fixed finding is always shown regardless of severity: the checklist's
  // whole job is to tell you what closed, and hiding that would make a good
  // outcome look like nothing happened.
  return findings.filter(f => f.state === "fixed" ||
                              secSevRank(f.severity) >= floor);
}
/* What is still standing, by severity. Decided and fixed findings are out of
   it by definition — the posture is what is left for somebody to do. */
export function secPosture(findings, minSeverity){
  const counts = {critical:0, high:0, medium:0, low:0, info:0, other:0};
  secVisible(findings, minSeverity).forEach(f => {
    if(["fixed","accepted","false_positive"].includes(f.state)) return;
    if(counts[f.severity] == null) counts.other++; else counts[f.severity]++;
  });
  return counts;
}

/* ---------------------------------------------------------- rule vocabulary
   The label and icon a RULE earns on screen -- today the Security index's
   "Top issue categories" card (secIndexCategories, ui/security/index-
   screen.js) -- kept here for the reason every other word in this file is:
   one home, so a second screen that wants the same word never grows a copy
   that can drift from this one.

   SEC_RULE_META covers exactly the CLOSED rule vocabularies: category
   "secret" and category "hygiene" (bin/security/hygiene.py's own findings)
   -- fixed lists, because the engine that writes them ships a fixed list of
   its own. "secret" has TWO such lists, because two scanners can write it:
   bin/security/secrets.py's own `_RULES` (snake_case) when the built-in
   pattern scanner runs, and gitleaks' rule ids (kebab-case) when the engine
   does -- see the second block below. Only ever one of the two per analysis,
   but both across a fleet, and a ledger keeps findings from both. Two more
   categories are closed too and still need no entry here: "dependency"
   (bin/security/osv.py) writes the OSV.dev advisory id itself as the rule --
   GHSA-... or CVE-... -- and an advisory id is already a name (the mockup
   keeps "GHSA-8xcm-r25x-g524" verbatim, never translates it, see
   SEC_ADVISORY_RULE below); "sast" is the one OPEN vocabulary -- the
   analysis agent writes its own kebab-case rule id per finding, so no fixed
   list could ever cover it, and secRuleMeta humanises it instead of looking
   it up.

   Every label below was written FROM the rule's own rationale in secrets.py
   or hygiene.py, not guessed from the rule's name -- both files are short;
   read them before changing a word here. `committed_key_file` earns the
   SAME icon as `private_key` rather than the other three hygiene rules'
   icon: both name a key sitting in the repository, found two different ways
   (by content, by filename), and the icon is about the risk, not which
   scanner tripped over it. */
const ICON_HYGIENE = "hammer";
export const SEC_RULE_META = {
  // secret -- bin/security/secrets.py's `_RULES`, in that file's own order.
  private_key:         {label: "Private keys committed",         icon: "key"},
  generic_secret:      {label: "Hardcoded secrets",               icon: "lock"},
  aws_access_key:      {label: "AWS access key committed",        icon: "lock"},
  github_token:        {label: "GitHub token committed",          icon: "lock"},
  slack_token:         {label: "Slack token committed",           icon: "lock"},
  stripe_key:          {label: "Stripe live key committed",       icon: "lock"},
  openai_key:          {label: "OpenAI API key committed",        icon: "lock"},
  google_api_key:      {label: "Google API key committed",        icon: "lock"},
  /* secret, again -- gitleaks' OWN rule ids, for the same credential types.
     bin/security/adapters.py runs gitleaks instead of secrets.py whenever the
     binary is installed, and it writes the ENGINE's rule id into the finding
     (`aws-access-token`, not `aws_access_key`) because the fingerprint
     contains the rule and re-spelling it would orphan every decision recorded
     against the old identity. Without these keys every secret on an
     engine-scanned project fell through to secHumaniseRule -- "Aws access
     token" with the generic category icon, instead of the curated label above.
     The snake_case keys STAY: the built-in scanner still emits them wherever
     gitleaks is absent or switched off, and both vocabularies are live at once
     across a fleet of projects.

     Paired with adapters.SEVERITY_BY_RULE, which maps the same ids -- one
     rule of ours is routinely several of theirs (five GitHub token kinds,
     seven Slack ones), and each gets the label its own credential type earns
     rather than a shared one that would flatten them back together. Anything
     outside this list is one of gitleaks' ~180 other rules and humanises, as
     it did before. */
  "aws-access-token":          {label: "AWS access key committed",    icon: "lock"},
  "github-pat":                {label: "GitHub token committed",      icon: "lock"},
  "github-fine-grained-pat":   {label: "GitHub token committed",      icon: "lock"},
  "github-oauth":              {label: "GitHub OAuth token committed", icon: "lock"},
  "github-app-token":          {label: "GitHub app token committed",  icon: "lock"},
  "github-refresh-token":      {label: "GitHub refresh token committed", icon: "lock"},
  "slack-bot-token":           {label: "Slack token committed",       icon: "lock"},
  "slack-user-token":          {label: "Slack token committed",       icon: "lock"},
  "slack-app-token":           {label: "Slack token committed",       icon: "lock"},
  "slack-config-access-token": {label: "Slack token committed",       icon: "lock"},
  "slack-legacy-bot-token":    {label: "Slack token committed",       icon: "lock"},
  "slack-legacy-token":        {label: "Slack token committed",       icon: "lock"},
  "slack-webhook-url":         {label: "Slack webhook URL committed", icon: "lock"},
  "stripe-access-token":       {label: "Stripe live key committed",   icon: "lock"},
  "openai-api-key":            {label: "OpenAI API key committed",    icon: "lock"},
  "gcp-api-key":               {label: "Google API key committed",    icon: "lock"},
  "private-key":               {label: "Private keys committed",      icon: "key"},
  "generic-api-key":           {label: "Hardcoded secrets",           icon: "lock"},
  // hygiene -- bin/security/hygiene.py's four findings. Labels say what each
  // rule's own rationale says it detects, not what its name suggests:
  // missing_gitignore's rationale is "the first .env, key or credential file
  // someone adds is committed by default" -- about secrets slipping in, not
  // about build output -- so the label says that, not "build artifacts".
  committed_env_file:  {label: ".env file committed",             icon: ICON_HYGIENE},
  committed_key_file:  {label: "Private key file committed",      icon: "key"},
  missing_gitignore:   {label: "No .gitignore in the repository", icon: ICON_HYGIENE},
  world_writable_file: {label: "World-writable file",             icon: ICON_HYGIENE},
};

// Every advisory id OSV.dev can hand back for a dependency (bin/security/
// osv.py's own `rule` field) matches one of these two prefixes -- an id IS
// the finding's name, so a rule shaped like one is echoed back exactly as it
// arrived, never looked up or reworded.
const SEC_ADVISORY_RULE = /^(?:GHSA|CVE)-/i;

/* kebab-case OR snake_case -> sentence case, and nothing else:
   "auth-gate-fails-open" and "auth_gate_fails_open" both become "Auth gate
   fails open" -- the agent that writes the open "sast" vocabulary's own rule
   ids (see SEC_RULE_META's own comment for why a fixed list cannot cover it)
   is not promised to pick one separator over the other, so this splits on
   either rather than only ever recognising the one it happened to be
   written against. A plain, reversible transform rather than a dictionary
   someone has to keep in sync with an agent that can invent a new rule id on
   every run. */
function secHumaniseRule(rule){
  const words = String(rule || "").split(/[-_]/).filter(Boolean);
  if(!words.length) return String(rule || "");
  const sentence = words.join(" ");
  return sentence.charAt(0).toUpperCase() + sentence.slice(1);
}

/* (category, rule) -> {label, icon} for one row of "Top issue categories" --
   never throws, and never names an icon bin/dashboard.html's own table (`I`)
   does not define (tests/test_page_contract.py parses that table directly
   and checks every icon this function can return against it, rather than
   trusting a second list here).

   In order:
     1. SEC_RULE_META, regardless of what `category` says -- queries.
        top_categories (bin/security/queries.py) now serves each row's own
        category alongside its rule, but this step still checks the map
        FIRST and ignores `category` when it matches: every rule a CLOSED
        engine (secrets.py, hygiene.py) can produce is in that map, labelled
        from the engine's own rationale, which a generic per-category label
        (step 4, below) would only flatten.
     2. An advisory id (SEC_ADVISORY_RULE) keeps itself as the label.
     3. `category === "sast"` -- the one OPEN vocabulary -- humanised.
     4. Whatever `category` says, sensibly, for a rule from a closed engine
        this map has not been told about yet (a future secret/dependency/
        hygiene rule).
     5. `shield`, unconditionally -- the same fallback an unrecognised
        severity or state already gets elsewhere in this file (secSevRank,
        secStateKey). */
export function secRuleMeta(category, rule){
  const known = SEC_RULE_META[rule];
  if(known) return known;
  const safe = (rule == null || rule === "") ? "Unknown rule" : String(rule);
  // Advisory ids ARE names -- never humanised, whatever the category says.
  if(SEC_ADVISORY_RULE.test(safe)) return {label: safe, icon: "shield"};
  // Every other unknown id humanises. A raw kebab/snake id is never a better
  // display string than its sentence-case form, and the raw id stays one
  // hover away in the row's title -- this is what keeps the card legible
  // when a category outside the four known ones shows up (an agent is free
  // to invent one tomorrow). The icon is SEC_CATEGORY_ICON's own (below) --
  // shared with secCategoryMeta rather than a second per-category branch
  // here that could drift from it.
  return {label: secHumaniseRule(safe), icon: SEC_CATEGORY_ICON[category] || "shield"};
}

// The icon each of the four categories earns when nothing more specific
// applies -- secRuleMeta's own fallback, above, factored out so
// secCategoryMeta (below) draws the IDENTICAL icon a rule from that same
// category would otherwise fall back to, rather than a second, hand-typed
// list that could drift from it the next time either one changes.
const SEC_CATEGORY_ICON = {secret: "lock", dependency: "package",
                           hygiene: ICON_HYGIENE, sast: "code"};

// The category's own fixed label -- "Secrets"/"Dependency"/"Hygiene"/"SAST",
// the mockup's own CATEGORY column (findings-screen.js's own secFindRow),
// coarser than secRuleMeta's per-RULE label ("Private keys committed") a
// column to its left already shows -- the same fact at two resolutions, not
// one duplicating the other.
const SEC_CATEGORY_LABEL = {secret: "Secrets", dependency: "Dependency",
                            hygiene: "Hygiene", sast: "SAST"};

/* (category) -> {label, icon}, for a column that draws the ledger's own
   CATEGORY rather than a rule's label -- secRuleMeta (above) stays the one
   RULE resolver, untouched, for its other caller ("Top issue categories",
   index-screen.js, which ranks rules, not categories). A category outside
   the four the ledger writes today (ledger.py's own schema promises one
   always arrives: `category TEXT NOT NULL`) still reads as something
   legible -- sentence case of whatever string it actually is, `shield` for
   its icon, the identical "never throw, never point at an unlisted icon"
   discipline secRuleMeta's own fallback already follows. */
export function secCategoryMeta(category){
  const label = SEC_CATEGORY_LABEL[category];
  if(label) return {label, icon: SEC_CATEGORY_ICON[category]};
  const safe = String(category || "");
  return {label: safe ? safe.charAt(0).toUpperCase() + safe.slice(1) : "Unknown",
          icon: "shield"};
}
