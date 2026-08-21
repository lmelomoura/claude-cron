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
