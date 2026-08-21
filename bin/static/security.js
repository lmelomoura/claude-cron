(() => {
  // ui/security/page.js
  var $;
  var TOKEN;
  var api;
  var toast;
  var openLog;
  var projById;
  var sessionLost;
  var unjournaledLive;
  var fmtAgo;
  var fmtWhen;
  var fmtDur;
  var money;
  var icon;
  var iconLabel;
  var openProjectEditor;
  var CC = null;
  function bindPage(cc) {
    CC = cc;
    ({
      $,
      TOKEN,
      api,
      toast,
      openLog,
      projById,
      sessionLost,
      unjournaledLive,
      fmtAgo,
      fmtWhen,
      fmtDur,
      money,
      icon,
      iconLabel,
      openProjectEditor
    } = cc);
  }

  // ui/security/vocabulary.js
  var SEC_STATES = [
    "new",
    "regressed",
    "open",
    "partial",
    "pending",
    "fixed",
    "accepted",
    "false_positive"
  ];
  var SEC_STATE_LABEL = {
    new: "New",
    regressed: "Regressed",
    open: "Open",
    partial: "Partial",
    pending: "Not re-checked",
    fixed: "Fixed",
    accepted: "Accepted",
    false_positive: "False positive"
  };
  var SEC_STATE_HELP = {
    new: "Not in the previous analysis of this branch.",
    regressed: "Was fixed once and is back \u2014 usually a fix that closed the symptom, not the route.",
    open: "Was here last time too, unchanged.",
    partial: "Some of its places are gone, or the agent recorded it as mitigated but not eliminated.",
    pending: "In the previous analysis and not re-checked by this one yet \u2014 a statement about this analysis, not about the code. Becomes fixed only when its absence is proven: deterministic findings once prepare completes, code-review findings only when the analysis closes with full coverage.",
    fixed: "Gone since the previous analysis of this branch \u2014 and the phase that would have re-found it DID finish, so the absence is proven, not assumed.",
    accepted: "You accepted the risk. The reason is recorded and outlives every analysis after it.",
    false_positive: "You said it is not real. If the code around it changes the fingerprint changes and it comes back as new \u2014 different code, so a fresh judgement."
  };
  var SEV_ORDER = ["info", "low", "medium", "high", "critical"];
  var SEC_PROFILES = ["quick", "standard", "deep"];
  var SEC_POLL_MS = 4e3;
  var SEC_RUN_WINDOW = 120;
  var secCfg = (name) => (projById(name) || {}).security || {};
  var secMinSeverity = (name) => {
    const v = secCfg(name).min_severity;
    return SEV_ORDER.includes(v) ? v : "low";
  };
  var secDefaultProfile = (name) => {
    const v = secCfg(name).default_profile;
    return SEC_PROFILES.includes(v) ? v : "standard";
  };
  var secSevRank = (s) => {
    const i = SEV_ORDER.indexOf(s);
    return i < 0 ? SEV_ORDER.length : i;
  };
  var secSevKey = (f) => SEV_ORDER.includes(f.severity) ? f.severity : "unknown";
  var secStateKey = (f) => SEC_STATES.includes(f.state) ? f.state : "unknown";
  function secRepos(p) {
    const rows = ((p || {}).repos || []).map((r) => r && r.name).filter(Boolean);
    return rows.length ? rows : [(p || {}).name].filter(Boolean);
  }
  function secVisible(findings, minSeverity) {
    const floor = SEV_ORDER.indexOf(minSeverity || "low");
    return findings.filter((f) => f.state === "fixed" || secSevRank(f.severity) >= floor);
  }
  function secPosture(findings, minSeverity) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, other: 0 };
    secVisible(findings, minSeverity).forEach((f) => {
      if (["fixed", "accepted", "false_positive"].includes(f.state)) return;
      if (counts[f.severity] == null) counts.other++;
      else counts[f.severity]++;
    });
    return counts;
  }

  // ui/security/state.js
  var secState = {
    project: "",
    repo: "",
    branch: "",
    analyses: [],
    analysis: null,
    findings: [],
    stateFilter: "",
    seq: 0
  };

  // ui/security/dom.js
  function secIcon(name) {
    return icon(name);
  }
  function secEl(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function secFill(select, values, selected) {
    select.textContent = "";
    values.forEach((v) => {
      const o = document.createElement("option");
      o.value = v;
      o.textContent = v;
      select.appendChild(o);
    });
    if (selected != null && values.includes(selected)) select.value = selected;
  }
  async function secFetch(path) {
    const r = await fetch(path, { headers: { "X-CC-Token": TOKEN } });
    if (r.status === 401 || r.status === 428) {
      sessionLost();
      throw new Error("signed out");
    }
    const j = await r.json().catch(() => null);
    if (!r.ok) throw new Error(j && (j.error || j.output) || "HTTP " + r.status);
    return j;
  }

  // ui/security/history.js
  function secRunFor(a) {
    if (!a || !a.run_id) return null;
    const running = a.state === "running";
    const pool = running ? unjournaledLive() : unjournaledLive().concat(CC.DATA.runs || []);
    let best = null, bestd = Infinity;
    pool.forEach((r) => {
      if (r.id !== a.run_id) return;
      const d = Math.abs((r.start || 0) - (a.started || 0));
      if (d < bestd) {
        best = r;
        bestd = d;
      }
    });
    return bestd <= SEC_RUN_WINDOW ? best : null;
  }
  function secRenderHistory() {
    const host = $("sec-history");
    host.textContent = "";
    const mine = secState.analyses.filter((a) => a.repo === secState.repo && a.branch === secState.branch);
    if (!mine.length) {
      host.appendChild(secEl("div", "empty", "Nothing analysed on this branch yet."));
      return;
    }
    const current = secState.analysis && secState.analysis.id;
    mine.forEach((a) => {
      const row = secEl("div", "sechrow" + (a.id === current ? " on" : ""));
      const open = secEl("button", "btn ghost", "#" + a.id);
      open.type = "button";
      open.title = "Show this analysis";
      open.onclick = () => secShowAnalysis(a.id);
      row.appendChild(open);
      row.appendChild(secEl("span", "grow", [
        a.state,
        a.profile,
        String(a.commit_sha || "").slice(0, 12),
        fmtWhen(a.started),
        money(a.spend_usd || 0)
      ].filter(Boolean).join(" \xB7 ")));
      const run = secRunFor(a);
      if (run) {
        const b = secEl("button", "btn ghost", "Run");
        b.type = "button";
        b.title = "Open this analysis's run";
        b.onclick = () => openLog(run.id, run.start);
        row.appendChild(b);
      }
      host.appendChild(row);
    });
  }

  // ui/security/reason.js
  var _srResolve = null;
  function secAskReason(label, title) {
    $("sr-title").textContent = label;
    $("sr-sub").textContent = title || "";
    $("sr-why").value = "";
    $("sr-err").hidden = true;
    $("secreason").showModal();
    return new Promise((res) => {
      _srResolve = res;
    });
  }
  function secReasonDone(value) {
    $("secreason").close();
    if (_srResolve) {
      _srResolve(value);
      _srResolve = null;
    }
  }
  function wireReasonDialog() {
    $("sr-cancel").addEventListener("click", () => secReasonDone(null));
    $("secreason").addEventListener("cancel", (e) => {
      e.preventDefault();
      secReasonDone(null);
    });
    $("sr-ok").addEventListener("click", () => {
      const v = $("sr-why").value.trim();
      if (!v) {
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
    $("sr-why").addEventListener("input", () => {
      $("sr-err").hidden = true;
    });
  }

  // ui/security/analysis.js
  var secTimer = null;
  function secStopPoll() {
    if (secTimer) {
      clearInterval(secTimer);
      secTimer = null;
    }
  }
  function secSyncPoll() {
    const running = CC.currentView === "security" && secState.project && secState.analyses.some((a) => a.state === "running");
    if (running && !secTimer) secTimer = setInterval(() => secReload(false), SEC_POLL_MS);
    if (!running) secStopPoll();
  }
  function secEnter() {
    if (secState.project) secReload();
    else secLoadIndex(false);
  }
  function secLeave() {
    secStopPoll();
  }
  function secBack() {
    secStopPoll();
    secInvalidateIndex();
    secInvalidateProject();
    secState.project = "";
    secState.analysis = null;
    secState.findings = [];
    secState.analyses = [];
    secState.stateFilter = "";
    $("sec-detail").hidden = true;
    $("sec-projects").hidden = false;
    secRenderIndex();
    secLoadIndex(false);
  }
  async function secOpen(project) {
    secStopPoll();
    const seq = ++secState.seq;
    secState.project = project;
    secState.analysis = null;
    secState.findings = [];
    secState.analyses = [];
    secState.stateFilter = "";
    secProjectPollWasRunning = null;
    $("sec-projects").hidden = true;
    $("sec-detail").hidden = false;
    const title = $("sec-title");
    title.textContent = "";
    title.appendChild(secIcon("shield"));
    title.appendChild(document.createTextNode(project));
    $("sec-findings").textContent = "";
    $("sec-history").textContent = "";
    $("sec-summary").textContent = "";
    $("sec-checklist").textContent = "";
    $("sec-dl").hidden = true;
    secStatus("Loading\u2026");
    const p = projById(project) || {};
    const repos = secRepos(p);
    secFill($("sec-repo"), repos);
    $("sec-repo-field").hidden = repos.length < 2;
    $("sec-profile").value = secDefaultProfile(project);
    $("sec-branch-other").value = "";
    try {
      const list = await secFetch("/api/security?project=" + encodeURIComponent(project));
      if (seq !== secState.seq) return;
      secState.analyses = list;
    } catch (e) {
      if (seq !== secState.seq) return;
      secState.analyses = [];
      secStatus("Could not read its analyses \u2014 " + e.message);
    }
    const last = secState.analyses[0];
    if (last && repos.includes(last.repo)) $("sec-repo").value = last.repo;
    await secLoadBranches(last ? last.branch : "");
    if (seq !== secState.seq) return;
    if (last && SEC_PROFILES.includes(last.profile)) $("sec-profile").value = last.profile;
    await secSyncScope();
  }
  async function secLoadBranches(want) {
    const seq = secState.seq;
    const sel = $("sec-branch");
    secFill(sel, ["\u2026"], "\u2026");
    let branches = [];
    try {
      const j = await secFetch("/api/security/branches?project=" + encodeURIComponent(secState.project) + "&repo=" + encodeURIComponent($("sec-repo").value));
      if (seq !== secState.seq) return;
      branches = j.branches || [];
    } catch (e) {
      if (seq !== secState.seq) return;
      secFill(sel, []);
      toast("Could not list branches \u2014 " + e.message, true);
      return;
    }
    if (want && !branches.includes(want)) branches = [want].concat(branches);
    secFill(sel, branches, want);
  }
  function secScope() {
    const typed = $("sec-branch-other").value.trim();
    return { repo: $("sec-repo").value, branch: typed || $("sec-branch").value || "" };
  }
  async function secSyncScope() {
    const s = secScope();
    secState.repo = s.repo;
    secState.branch = s.branch;
    const mine = secState.analyses.filter((a) => a.repo === s.repo && a.branch === s.branch);
    await secShowAnalysis(mine.length ? mine[0].id : null);
  }
  async function secShowAnalysis(id) {
    const seq = ++secState.seq;
    if (id == null) {
      secState.analysis = null;
      secState.findings = [];
      secPaint();
      return;
    }
    try {
      const j = await secFetch("/api/security/checklist?analysis=" + encodeURIComponent(id));
      if (seq !== secState.seq) return;
      secState.analysis = j.analysis || null;
      secState.findings = j.findings || [];
    } catch (e) {
      if (seq !== secState.seq) return;
      secState.analysis = null;
      secState.findings = [];
      secStatus("Could not read that analysis \u2014 " + e.message);
      return;
    }
    secPaint();
  }
  var secProjectPollWasRunning = null;
  async function secReload(forceProject = true) {
    if (!secState.project || CC.currentView !== "security") return;
    try {
      secState.analyses = await secFetch("/api/security?project=" + encodeURIComponent(secState.project));
    } catch (e) {
      secStopPoll();
      return;
    }
    if (!secState.project || CC.currentView !== "security") {
      secStopPoll();
      return;
    }
    const mine = secState.analyses.filter((a) => a.repo === secState.repo && a.branch === secState.branch);
    const want = mine.length ? mine[0].id : secState.analysis && secState.analysis.id;
    await secShowAnalysis(want == null ? null : want);
    secSyncPoll();
    const runningNow = secState.analyses.some((a) => a.state === "running");
    const changed = runningNow !== secProjectPollWasRunning;
    secProjectPollWasRunning = runningNow;
    if (forceProject || changed) secRefreshProject();
  }
  function secStatus(text) {
    const box = $("sec-status");
    box.textContent = "";
    box.appendChild(secEl("span", null, text));
  }
  function secPaint() {
    const a = secState.analysis;
    const running = !!a && a.state === "running";
    secPaintRunButton();
    secSyncPoll();
    const box = $("sec-status");
    box.textContent = "";
    if (!a) {
      box.appendChild(secEl(
        "span",
        null,
        secState.branch ? "No analysis of this branch yet \u2014 press Analyse to make the first one." : "Pick a branch, or type one, and press Analyse."
      ));
      $("sec-incomplete").hidden = true;
      $("sec-coverage").hidden = true;
      $("sec-summary").textContent = "";
      $("sec-checklist").textContent = "";
      $("sec-dl").hidden = true;
      $("sec-findings").textContent = "";
      secRenderHistory();
      return;
    }
    box.appendChild(secIcon(running ? "timer" : a.state === "failed" ? "xcircle" : "check"));
    box.appendChild(secEl("b", null, "Analysis " + a.id));
    const bits = [
      a.repo + " @ " + a.branch,
      String(a.commit_sha || "").slice(0, 12),
      a.profile,
      a.state,
      running ? "started " + fmtAgo(a.started) : a.ended ? "ended " + fmtAgo(a.ended) : "started " + fmtAgo(a.started)
    ];
    if (a.ended && a.started) bits.push(fmtDur(Math.max(0, a.ended - a.started)));
    bits.push(money(a.spend_usd || 0));
    box.appendChild(secEl("span", null, bits.filter(Boolean).join(" \xB7 ")));
    if (running) {
      box.appendChild(secEl(
        "span",
        null,
        "Secrets, dependencies and CVEs are written moments after the agent starts \u2014 they are its first command \u2014 so what is below is already real while the code review keeps going."
      ));
    }
    const run = secRunFor(a);
    if (run) {
      const b = secEl("button", "btn", "Open the run");
      b.type = "button";
      b.onclick = () => openLog(run.id, run.start);
      box.appendChild(b);
    }
    if (running && !run) {
      if (Date.now() / 1e3 - (a.started || 0) > 180) {
        box.appendChild(secEl(
          "span",
          "note",
          "No live run is behind this analysis \u2014 it likely died without closing. The next Analyse sweeps it; until then downloads carry what it recorded."
        ));
      } else {
        box.appendChild(secEl(
          "span",
          null,
          "Preparing the run \u2014 fetching the branch and cutting a clean worktree. The live trace appears here the moment the agent starts."
        ));
      }
    }
    const inc = $("sec-incomplete");
    inc.textContent = "";
    const incomplete = a.state === "capped" ? "This analysis is INCOMPLETE: it stopped before covering the whole scope." : a.state === "failed" ? "This analysis is INCOMPLETE: it did not finish." : "";
    if (incomplete) {
      inc.appendChild(secIcon("alert"));
      inc.appendChild(secEl("span", "grow", incomplete + " What is below is what it had reached, not what is there."));
      inc.hidden = false;
    } else inc.hidden = true;
    const note = $("sec-coverage");
    note.textContent = "";
    if ((a.coverage_note || "").trim()) {
      note.appendChild(secIcon("alert"));
      note.appendChild(secEl("span", "grow", a.coverage_note));
      note.hidden = false;
    } else note.hidden = true;
    secRenderSummary();
    secRenderChecklist();
    $("sec-dl").hidden = false;
    secRenderFindings();
    secRenderHistory();
  }
  function secPaintRunButton() {
    const btn = $("sec-run");
    const running = secState.analyses.some((a) => a.state === "running");
    btn.disabled = running;
    btn.title = running ? "An analysis of this project is already running \u2014 one at a time." : "Analyse the selected branch";
    btn.textContent = running ? "Analysing\u2026" : "Analyse";
  }
  function secRenderSummary() {
    const host = $("sec-summary");
    host.textContent = "";
    const shown = secVisible(secState.findings, secMinSeverity(secState.project));
    const counts = secPosture(secState.findings, secMinSeverity(secState.project));
    const open = SEV_ORDER.reduce((n, s) => n + counts[s], 0) + counts.other;
    if (!shown.length) {
      host.appendChild(secEl("span", "sevpill clean", "nothing found"));
    } else if (!open) {
      host.appendChild(secEl("span", "sevpill clean", "nothing open"));
    } else {
      ["critical", "high", "medium", "low", "info"].forEach((sev) => {
        if (counts[sev]) host.appendChild(secEl("span", "sevpill " + sev, counts[sev] + " " + sev));
      });
      if (counts.other) host.appendChild(secEl("span", "sevpill low", counts.other + " other"));
    }
    const hidden = secState.findings.length - shown.length;
    if (hidden > 0) {
      host.appendChild(secEl("span", "sevpill low", hidden + " below " + secMinSeverity(secState.project) + " \u2014 recorded, not shown"));
    }
  }
  function secRenderChecklist() {
    const host = $("sec-checklist");
    host.textContent = "";
    const shown = secVisible(secState.findings, secMinSeverity(secState.project));
    SEC_STATES.forEach((state) => {
      const n = shown.filter((f) => f.state === state).length;
      const chip = secEl("button", "secchip" + (n ? "" : " zero") + (secState.stateFilter === state ? " on" : ""));
      chip.type = "button";
      chip.title = SEC_STATE_HELP[state] || "";
      chip.appendChild(secEl("span", null, SEC_STATE_LABEL[state]));
      chip.appendChild(secEl("span", "n", String(n)));
      chip.onclick = () => {
        secState.stateFilter = secState.stateFilter === state ? "" : state;
        secRenderChecklist();
        secRenderFindings();
      };
      host.appendChild(chip);
    });
  }
  function secRenderFindings() {
    const host = $("sec-findings");
    host.textContent = "";
    let list = secVisible(secState.findings, secMinSeverity(secState.project));
    if (secState.stateFilter) list = list.filter((f) => f.state === secState.stateFilter);
    const stateRank = (f) => SEC_STATES.indexOf(f.state);
    list = list.slice().sort((x, y) => secSevRank(y.severity) - secSevRank(x.severity) || stateRank(x) - stateRank(y) || String(x.title).localeCompare(String(y.title)));
    if (!list.length) {
      const e = secEl("div", "empty", secState.stateFilter ? "Nothing in that state." : "This analysis reported nothing to show.");
      host.appendChild(e);
      return;
    }
    list.forEach((f) => host.appendChild(secFindingRow(f)));
  }
  function secFindingRow(f) {
    const row = document.createElement("div");
    row.className = "secfinding sev-" + secSevKey(f) + " state-" + secStateKey(f);
    const h = document.createElement("h4");
    const title = document.createElement("span");
    title.className = "sectitle";
    title.textContent = "[" + f.severity + "] " + f.title;
    h.appendChild(title);
    const st = document.createElement("span");
    st.className = "secstate " + secStateKey(f);
    st.title = SEC_STATE_HELP[f.state] || "";
    st.textContent = SEC_STATE_LABEL[f.state] || f.state;
    h.appendChild(st);
    row.appendChild(h);
    const where = document.createElement("ul");
    where.className = "secwhere";
    (f.occurrences || []).forEach((o) => {
      const li = document.createElement("li");
      li.textContent = o.line ? o.file + ":" + o.line : o.file;
      where.appendChild(li);
    });
    if (where.childNodes.length) row.appendChild(where);
    if ((f.rationale || "").trim()) row.appendChild(secEl("p", "secwhy", f.rationale));
    if ((f.remediation || "").trim()) row.appendChild(secEl("p", "secfix", "Remediation: " + f.remediation));
    if ((f.partial_note || "").trim()) row.appendChild(secEl("p", "secwhy", "Partial: " + f.partial_note));
    if ((f.decision_reason || "").trim()) {
      row.appendChild(secEl("p", "secwhy", SEC_STATE_LABEL[f.state] + " \u2014 " + f.decision_reason));
    }
    row.appendChild(secEl("div", "secfp", (f.category || "") + " \xB7 " + (f.rule || "") + " \xB7 " + (f.fingerprint || "")));
    if (f.state !== "fixed") row.appendChild(secDecisionControls(f));
    return row;
  }
  function secDecisionControls(f) {
    const wrap = document.createElement("div");
    wrap.className = "secactions";
    [["accepted", "Accept risk"], ["false_positive", "False positive"]].forEach(
      ([state, label]) => {
        const b = document.createElement("button");
        b.className = "btn";
        b.type = "button";
        b.textContent = label;
        b.onclick = () => secDecide(f, state, label);
        wrap.appendChild(b);
      }
    );
    return wrap;
  }
  async function secDecide(f, state, label) {
    const reason = await secAskReason(label, f.title);
    if (reason === null) return;
    const ok = await api("security_decide", {
      project: secState.project,
      fingerprint: f.fingerprint,
      state,
      reason
    });
    if (!ok) return;
    toast(label + " recorded", false, "check");
    await secReload();
  }

  // ui/security/project-screen.js
  var RUN_STATES = ["running", "done", "capped", "failed"];
  var EVENT_KIND_LABEL = {
    analysis_started: "Analysis started",
    analysis_finished: "Analysis finished",
    decision_made: "Decision made",
    settings_changed: "Settings changed",
    report_exported: "Report exported"
  };
  var secProjectCache = null;
  var secProjectGen = 0;
  var secProjectTab = "overview";
  var secRunsFilter = "";
  function secInvalidateProject() {
    secProjectCache = null;
  }
  async function secOpenProject(name) {
    secProjectTab = "overview";
    secRunsFilter = "";
    secOpen(name);
    await secLoadProject(name, true);
  }
  async function secRefreshProject() {
    if (!secState.project) return;
    await secLoadProject(secState.project, true);
  }
  async function secLoadProject(name, force) {
    if (secProjectCache && secProjectCache.project === name && !force) {
      secRenderProject();
      return;
    }
    secProjectGen++;
    const gen = secProjectGen;
    let data;
    try {
      data = await secFetch("/api/security/project?project=" + encodeURIComponent(name));
    } catch (e) {
      if (gen !== secProjectGen || secState.project !== name) return;
      secProjectCache = null;
      secRenderProjectError(e.message);
      return;
    }
    if (gen !== secProjectGen || secState.project !== name) return;
    secProjectCache = data;
    secRenderProject();
  }
  function secRenderProjectError(msg) {
    const host = $("sec-pj-head");
    if (!host) return;
    host.textContent = "";
    host.appendChild(secIcon("alert"));
    host.appendChild(secEl("span", "grow", "Could not read this project \u2014 " + msg));
  }
  function secSwitchProjectTab(tab) {
    secProjectTab = tab === "runs" ? "runs" : "overview";
    secRenderTabs();
  }
  function secRenderProject() {
    if (!secProjectCache) return;
    secRenderProjectHeader(secProjectCache);
    secRenderTabs();
    secRenderProjectOverview(secProjectCache);
    secRenderProjectRuns(secProjectCache);
    secRenderProjectSidebar(secProjectCache);
  }
  function secRenderTabs() {
    const ov = $("secpjt-overview"), rn = $("secpjt-runs");
    if (ov) ov.classList.toggle("active", secProjectTab === "overview");
    if (rn) rn.classList.toggle("active", secProjectTab === "runs");
    const ovPane = $("sec-pj-overview"), rnPane = $("sec-pj-runs");
    if (ovPane) ovPane.hidden = secProjectTab !== "overview";
    if (rnPane) rnPane.hidden = secProjectTab !== "runs";
  }
  function secRenderProjectHeader(payload) {
    const host = $("sec-pj-head");
    if (!host) return;
    host.textContent = "";
    const h = payload.header || {};
    const meta = secEl("div", "secpjmeta grow");
    meta.appendChild(secHeaderBit("Profile", h.profile || "standard"));
    const branch = secHeaderBit("Branch", h.branch || "\u2014");
    if (h.branch_fell_back) {
      branch.appendChild(secEl(
        "span",
        "secidx-fellback",
        " (fell back \u2014 the declared base was never analysed)"
      ));
    }
    meta.appendChild(branch);
    meta.appendChild(secHeaderBit(
      "Lines of code",
      h.lines_of_code ? h.lines_of_code.toLocaleString() : "\u2014"
    ));
    meta.appendChild(secHeaderBit(
      "Last analysis",
      h.last_analysis ? fmtAgo(h.last_analysis) : "Never analysed"
    ));
    host.appendChild(meta);
    const settings = secEl("button", "btn ghost");
    settings.type = "button";
    settings.title = "Open this project's editor";
    settings.onclick = () => openProjectEditor(secState.project);
    settings.appendChild(secIcon("gear"));
    settings.appendChild(document.createTextNode("Project settings"));
    host.appendChild(settings);
  }
  function secHeaderBit(label, value) {
    const span = secEl("span", null, label + ": ");
    span.appendChild(secEl("b", null, value));
    return span;
  }
  function secOverviewCaption(header) {
    const cap = secEl("div", "secpj-caption", "Posture of " + (header.branch || "\u2014"));
    if (header.branch_fell_back) {
      cap.appendChild(secEl(
        "span",
        "secidx-fellback",
        " (fell back \u2014 the declared base was never analysed)"
      ));
    }
    return cap;
  }
  function secSidebarCaption(branchCount) {
    if (!branchCount) return secEl("div", "secpj-caption", "No finished analysis yet.");
    const scope = branchCount === 1 ? "this project's only analysed branch" : "all " + branchCount + " analysed branches";
    return secEl("div", "secpj-caption", "Posture and categories below span " + scope + ".");
  }
  function secRenderProjectOverview(payload) {
    const host = $("sec-pj-overview");
    if (!host) return;
    host.textContent = "";
    const ov = (payload.tabs || {}).overview || {};
    if (!ov.state) {
      host.appendChild(secEl("div", "empty", ov.attempted ? "No analysis of this project has finished yet \u2014 see Runs for what was attempted." : "Never analysed. Switch to Runs to pick a branch and start."));
      return;
    }
    host.appendChild(secOverviewCaption(payload.header || {}));
    if (ov.state === "capped") {
      const warn = secEl("div", "warnline bad");
      warn.appendChild(secIcon("alert"));
      warn.appendChild(secEl(
        "span",
        "grow",
        "This analysis is INCOMPLETE: it stopped before covering the whole scope. The posture below is what it had reached, not what is there."
      ));
      host.appendChild(warn);
    }
    host.appendChild(secIndexPosturePills(ov.posture || {}));
    const chips = secEl("div", "secchips");
    const checklist = ov.checklist || {};
    SEC_STATES.forEach((state) => {
      const n = checklist[state] || 0;
      const chip = secEl("span", "secpj-statchip" + (n ? "" : " zero"));
      chip.title = SEC_STATE_HELP[state] || "";
      chip.appendChild(secEl("span", null, SEC_STATE_LABEL[state] || state));
      chip.appendChild(secEl("span", "n", String(n)));
      chips.appendChild(chip);
    });
    host.appendChild(chips);
  }
  function secRenderProjectRuns(payload) {
    const host = $("sec-pj-runstable");
    if (!host) return;
    host.textContent = "";
    const runs = (payload.tabs || {}).runs || [];
    host.appendChild(secRunsFilters(runs));
    host.appendChild(secRunsTable(runs));
  }
  function secRunsFilters(runs) {
    const wrap = secEl("div", "secchips");
    const counts = {};
    runs.forEach((r) => {
      counts[r.state] = (counts[r.state] || 0) + 1;
    });
    const all = secEl("button", "secchip" + (secRunsFilter ? "" : " on"));
    all.type = "button";
    all.appendChild(secEl("span", null, "All"));
    all.appendChild(secEl("span", "n", String(runs.length)));
    all.onclick = () => {
      secRunsFilter = "";
      secRenderProjectRuns(secProjectCache);
    };
    wrap.appendChild(all);
    RUN_STATES.forEach((state) => {
      const n = counts[state] || 0;
      const chip = secEl("button", "secchip" + (n ? "" : " zero") + (secRunsFilter === state ? " on" : ""));
      chip.type = "button";
      chip.appendChild(secEl("span", null, state));
      chip.appendChild(secEl("span", "n", String(n)));
      chip.onclick = () => {
        secRunsFilter = state;
        secRenderProjectRuns(secProjectCache);
      };
      wrap.appendChild(chip);
    });
    return wrap;
  }
  function secRunsTable(runs) {
    const filtered = secRunsFilter ? runs.filter((r) => r.state === secRunsFilter) : runs;
    if (!filtered.length) {
      return secEl("div", "tblempty", runs.length ? "Nothing in that state." : "No analyses of this project yet.");
    }
    const wrap = secEl("div", "tablewrap");
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    ["Run", "Profile", "Branch", "Commit", "Duration", "Findings", "State", "Date"].forEach((h) => {
      const th = document.createElement("th");
      th.textContent = h;
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    filtered.forEach((r) => tbody.appendChild(secRunRow(r)));
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }
  function secRunRow(r) {
    const tr = document.createElement("tr");
    const cell = (text) => {
      const td = document.createElement("td");
      td.textContent = text;
      return td;
    };
    const tdId = document.createElement("td");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn ghost";
    btn.textContent = "#" + r.id;
    btn.title = "Show this analysis below";
    btn.onclick = () => secShowAnalysis(r.id);
    tdId.appendChild(btn);
    tr.appendChild(tdId);
    tr.appendChild(cell(r.profile || ""));
    tr.appendChild(cell((r.repo || "") + " @ " + (r.branch || "")));
    tr.appendChild(cell(String(r.commit_sha || "").slice(0, 12)));
    tr.appendChild(cell(r.started && r.ended ? fmtDur(Math.max(0, r.ended - r.started)) : r.state === "running" ? "running\u2026" : "\u2014"));
    tr.appendChild(cell(r.findings == null ? "\u2014" : String(r.findings)));
    tr.appendChild(cell(r.state));
    tr.appendChild(cell(fmtWhen(r.started)));
    return tr;
  }
  function secRenderProjectSidebar(payload) {
    const host = $("sec-pj-side");
    if (!host) return;
    host.textContent = "";
    const sb = payload.sidebar || {};
    host.appendChild(secSidebarCaption(sb.branch_count || 0));
    host.appendChild(secIndexDonut(sb.donut || {}, sb.categories || []));
    host.appendChild(secProjectActivity(sb.activity || []));
  }
  function secProjectActivity(events) {
    const box = secEl("div", "card");
    box.appendChild(secEl("h3", null, "Recent activity"));
    if (!events.length) {
      box.appendChild(secEl("div", "tblempty", "No activity recorded yet."));
      return box;
    }
    const list = secEl("div", "seclist");
    events.forEach((e) => {
      const row = secEl("div", "secrow");
      row.appendChild(secIcon("activity"));
      const grow = secEl("div", "grow");
      grow.appendChild(secEl("div", "secname", EVENT_KIND_LABEL[e.kind] || e.kind));
      grow.appendChild(secEl(
        "div",
        "secmeta",
        [e.detail, fmtAgo(e.at)].filter(Boolean).join(" \xB7 ")
      ));
      row.appendChild(grow);
      list.appendChild(row);
    });
    box.appendChild(list);
    return box;
  }

  // ui/security/index-screen.js
  var secIndexCache = null;
  var secIndexGen = 0;
  function secInvalidateIndex() {
    secIndexCache = null;
  }
  async function secLoadIndex(force) {
    if (secIndexCache && !force) return;
    if (force) secIndexGen++;
    const gen = secIndexGen;
    if (!secIndexCache) {
      const host = $("sec-list");
      if (host) {
        host.textContent = "";
        host.appendChild(secEl("div", "tblempty", "Loading\u2026"));
      }
    }
    let data;
    try {
      data = await secFetch("/api/security/index");
    } catch (e) {
      if (gen !== secIndexGen) return;
      const host = $("sec-list");
      if (host) {
        host.textContent = "";
        const box = secEl("div", "tblempty");
        box.appendChild(secIcon("alert"));
        box.appendChild(document.createTextNode(
          "Could not read the security index \u2014 " + e.message
        ));
        host.appendChild(box);
      }
      return;
    }
    if (gen !== secIndexGen) return;
    secIndexCache = data;
    secRenderIndex();
  }
  function secRenderIndex() {
    const host = $("sec-list");
    if (!host) return;
    if (!secIndexCache) return;
    host.textContent = "";
    const data = secIndexCache;
    host.appendChild(secIndexCards(data.summary || {}));
    host.appendChild(secIndexSection(
      "Projects",
      secIndexProjectsTable(data.projects || [])
    ));
    host.appendChild(secIndexSection(
      "Recent analyses",
      secIndexRecent(data.recent || [])
    ));
    host.appendChild(secIndexSection(
      "Findings by severity",
      secIndexDonut(data.donut || {}, data.categories || [])
    ));
  }
  function secIndexSection(title, body) {
    const sec = secEl("div", "secidx-section");
    sec.appendChild(secEl("h3", null, title));
    sec.appendChild(body);
    return sec;
  }
  function secIndexCard(iconName, label, valueText, note, warn) {
    const card = secEl("div", "card secidx-card");
    const head = secEl("div", "secidx-card-h");
    head.appendChild(secIcon(iconName));
    head.appendChild(secEl("span", null, label));
    card.appendChild(head);
    card.appendChild(secEl("div", "secidx-num", valueText));
    if (note) card.appendChild(secEl("div", "secidx-note" + (warn ? " warn" : ""), note));
    return card;
  }
  function secIndexCards(summary) {
    const wrap = secEl("div", "secidx-kpis");
    const s = summary || {};
    wrap.appendChild(secIndexCard(
      "shield",
      "Projects",
      String(s.projects || 0),
      "Security analysis is on"
    ));
    wrap.appendChild(secIndexCard(
      "activity",
      "Analyses",
      String(s.analyses || 0),
      "All time \u2014 a historical total, not current posture"
    ));
    const capped = s.capped_projects || 0;
    const cappedNote = capped ? capped + " of " + (s.projects || 0) + " project" + ((s.projects || 0) === 1 ? "" : "s") + " had a latest analysis that stopped before covering its whole scope \u2014 this total may be an undercount" : "Open now, in every project's latest analysis";
    wrap.appendChild(secIndexCard(
      "alert",
      "Critical",
      String(s.critical || 0),
      cappedNote,
      !!capped
    ));
    wrap.appendChild(secIndexCard(
      "zap",
      "High",
      String(s.high || 0),
      cappedNote,
      !!capped
    ));
    const rate = s.success_rate;
    wrap.appendChild(secIndexCard(
      "check",
      "Success rate",
      rate == null ? "\u2014" : Math.round(rate * 100) + "%",
      rate == null ? "No finished analysis yet" : "Finished analyses that completed clean, not capped or failed"
    ));
    return wrap;
  }
  function secIndexPosturePills(posture) {
    const wrap = secEl("span", "sevpills");
    const p = posture || {};
    if (!p.total) {
      wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
      return wrap;
    }
    ["critical", "high", "medium", "low", "info"].forEach((sev) => {
      if (p[sev]) wrap.appendChild(secEl("span", "sevpill " + sev, p[sev] + " " + sev));
    });
    return wrap;
  }
  function secIndexProjectRow(p) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn ghost";
    btn.textContent = p.name;
    btn.onclick = () => secOpenProject(p.name);
    tdName.appendChild(btn);
    if ((p.description || "").trim()) {
      tdName.appendChild(secEl("div", "secidx-desc", p.description));
    }
    tr.appendChild(tdName);
    const tdBranch = document.createElement("td");
    tdBranch.appendChild(document.createTextNode(p.branch || "\u2014"));
    if (p.branch_fell_back) {
      tdBranch.appendChild(secEl(
        "span",
        "secidx-fellback",
        " (fell back \u2014 the default branch was never analysed)"
      ));
    }
    tr.appendChild(tdBranch);
    const tdPosture = document.createElement("td");
    tdPosture.appendChild(secIndexPosturePills(p.posture));
    if (p.last_state === "capped") {
      const badge = secEl("span", "secidx-capped", "incomplete");
      badge.title = "This analysis is INCOMPLETE: it stopped before covering the whole scope. The posture above is what it had reached, not what is there.";
      tdPosture.appendChild(badge);
    }
    tr.appendChild(tdPosture);
    const tdLast = document.createElement("td");
    if (!p.analyses) {
      tdLast.textContent = "Never analysed";
    } else {
      const bits = [p.profile, fmtAgo(p.last_started)];
      if (p.last_duration) bits.push(fmtDur(p.last_duration));
      tdLast.textContent = bits.filter(Boolean).join(" \xB7 ");
    }
    tr.appendChild(tdLast);
    const tdCount = document.createElement("td");
    tdCount.className = "num";
    tdCount.textContent = String(p.analyses || 0);
    tr.appendChild(tdCount);
    return tr;
  }
  function secIndexProjectsTable(projects) {
    if (!projects.length) {
      const e = secEl("div", "tblempty");
      e.appendChild(secIcon("inbox"));
      e.appendChild(document.createTextNode(
        "No projects have security analysis enabled yet \u2014 turn it on in a project's editor, on the Security tab."
      ));
      return e;
    }
    const wrap = secEl("div", "tablewrap");
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    ["Project", "Branch", "Posture", "Last analysis", "Analyses"].forEach((h) => {
      const th = document.createElement("th");
      th.textContent = h;
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    projects.slice().sort((a, b) => String(a.name).localeCompare(String(b.name))).forEach((p) => tbody.appendChild(secIndexProjectRow(p)));
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }
  function secIndexRecentRow(a) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "secrow secidx-recentrow";
    row.onclick = () => secOpenProject(a.project);
    row.appendChild(secIcon(a.state === "running" ? "timer" : a.state === "failed" ? "xcircle" : "check"));
    const grow = secEl("div", "grow");
    grow.appendChild(secEl(
      "div",
      "secname",
      a.project + " \xB7 " + a.repo + " @ " + a.branch
    ));
    const bits = [
      a.profile,
      a.state,
      a.state === "running" ? "started " + fmtAgo(a.started) : "ended " + fmtAgo(a.ended || a.started)
    ];
    if (a.open != null) bits.push(a.open + " open");
    bits.push(money(a.spend_usd || 0));
    grow.appendChild(secEl("div", "secmeta", bits.filter(Boolean).join(" \xB7 ")));
    row.appendChild(grow);
    return row;
  }
  function secIndexRecent(recent) {
    if (!recent.length) {
      return secEl("div", "tblempty", "No analyses have run yet.");
    }
    const host = secEl("div", "seclist");
    recent.forEach((a) => host.appendChild(secIndexRecentRow(a)));
    return host;
  }
  var SEV_ORDER5 = ["critical", "high", "medium", "low", "info"];
  var SEV_STROKE = {
    critical: "var(--err)",
    high: "var(--err)",
    medium: "var(--warn)",
    low: "var(--muted)",
    info: "var(--line)"
  };
  function secIndexDonutSvg(donut) {
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
    SEV_ORDER5.forEach((sev) => {
      const n = donut[sev] || 0;
      if (!n || !total) return;
      const len = n / total * circumference;
      const seg = document.createElementNS(ns, "circle");
      seg.setAttribute("cx", String(c));
      seg.setAttribute("cy", String(c));
      seg.setAttribute("r", String(r));
      seg.setAttribute("fill", "none");
      seg.setAttribute("stroke-width", "14");
      seg.setAttribute("stroke-dasharray", len + " " + (circumference - len));
      seg.setAttribute("stroke-dashoffset", String(-offset));
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
  function secIndexDonutLegend(donut) {
    const wrap = secEl("div", "sevpills");
    const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
    if (!total) {
      wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
      return wrap;
    }
    SEV_ORDER5.forEach((sev) => {
      if (donut[sev]) wrap.appendChild(secEl("span", "sevpill " + sev, donut[sev] + " " + sev));
    });
    return wrap;
  }
  function secIndexCategories(categories) {
    if (!categories.length) {
      return secEl("div", "tblempty", "No open findings to categorise.");
    }
    const wrap = secEl("div", "secidx-categories");
    const max = categories.reduce((n, c) => Math.max(n, c.count || 0), 1);
    categories.forEach((c) => {
      const row = secEl("div", "secidx-catrow");
      row.appendChild(secEl("span", "secidx-catname", c.rule));
      const bar = secEl("span", "secidx-catbar");
      const fill = secEl("span", "secidx-catfill");
      fill.style.width = Math.max(6, Math.round((c.count || 0) / max * 100)) + "%";
      bar.appendChild(fill);
      row.appendChild(bar);
      row.appendChild(secEl("span", "secidx-catcount", String(c.count || 0)));
      wrap.appendChild(row);
    });
    return wrap;
  }
  function secIndexDonut(donut, categories) {
    const wrap = secEl("div", "secidx-donutwrap");
    const left = secEl("div", "secidx-donutcol");
    left.appendChild(secIndexDonutSvg(donut));
    left.appendChild(secIndexDonutLegend(donut));
    wrap.appendChild(left);
    const right = secEl("div", "secidx-catcol");
    right.appendChild(secEl(
      "div",
      "secidx-cathead",
      "Rules producing the most open findings"
    ));
    right.appendChild(secIndexCategories(categories));
    wrap.appendChild(right);
    return wrap;
  }

  // ui/security/actions.js
  async function secAnalyse() {
    const s = secScope();
    if (!s.branch) {
      toast("Pick a branch, or type one", true);
      return;
    }
    const btn = $("sec-run");
    btn.disabled = true;
    btn.textContent = "Analysing\u2026";
    try {
      const ok = await api("security_analyze", {
        project: secState.project,
        repo: s.repo,
        branch: s.branch,
        profile: $("sec-profile").value
      });
      if (!ok) return;
      toast("Analysis started", false, "shield");
      secState.branch = s.branch;
      secState.repo = s.repo;
      await secReload();
      secSyncPoll();
    } finally {
      btn.disabled = false;
      btn.textContent = "Analyse";
      secPaintRunButton();
    }
  }
  async function secDownload(fmt) {
    const a = secState.analysis;
    if (!a) return;
    const btn = $("sec-dl-" + fmt);
    btn.disabled = true;
    try {
      const r = await fetch("/api/security/report?analysis=" + encodeURIComponent(a.id) + "&format=" + encodeURIComponent(fmt), { headers: { "X-CC-Token": TOKEN } });
      if (!r.ok) {
        const j = await r.json().catch(() => null);
        throw new Error(j && j.error || "HTTP " + r.status);
      }
      const url = URL.createObjectURL(await r.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "security-analysis-" + a.id + "." + (fmt === "sbom" ? "cdx.json" : fmt);
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 3e4);
    } catch (e) {
      toast("Download failed \u2014 " + e.message, true);
    } finally {
      btn.disabled = false;
    }
  }

  // ui/security/index.js
  function renderSecurity() {
    if (CC.currentView !== "security") return;
    if (secState.project) return;
    secRenderIndex();
    secLoadIndex(false);
  }
  function init(cc) {
    bindPage(cc);
    wireReasonDialog();
    iconLabel($("sr-halo"), "shield");
    iconLabel($("sec-back"), "cleft", "All projects");
    iconLabel($("sec-reload"), "radar", "Refresh");
    iconLabel($("sec-dl-md"), "file", "Markdown");
    iconLabel($("sec-dl-json"), "file", "JSON");
    iconLabel($("sec-dl-html"), "file", "HTML");
    iconLabel($("sec-dl-sbom"), "file", "SBOM");
    iconLabel($("secpjt-overview"), "grid", "Overview");
    iconLabel($("secpjt-runs"), "activity", "Runs");
    $("secpjt-overview").addEventListener("click", () => secSwitchProjectTab("overview"));
    $("secpjt-runs").addEventListener("click", () => secSwitchProjectTab("runs"));
    $("sec-dl-note").textContent = "Downloads always contain every recorded finding, whatever the severity floor shows.";
    $("sec-back").addEventListener("click", secBack);
    $("sec-reload").addEventListener("click", () => {
      secLoadIndex(true);
    });
    $("sec-run").addEventListener("click", secAnalyse);
    $("sec-dl-md").addEventListener("click", () => secDownload("md"));
    $("sec-dl-json").addEventListener("click", () => secDownload("json"));
    $("sec-dl-html").addEventListener("click", () => secDownload("html"));
    $("sec-dl-sbom").addEventListener("click", () => secDownload("sbom"));
    $("sec-repo").addEventListener("change", async () => {
      await secLoadBranches("");
      $("sec-branch-other").value = "";
      secSyncScope();
    });
    $("sec-branch").addEventListener("change", () => {
      $("sec-branch-other").value = "";
      secSyncScope();
    });
    $("sec-branch-other").addEventListener("change", () => secSyncScope());
  }
  window.CCSecurity = {
    init,
    render: renderSecurity,
    enter: secEnter,
    leave: secLeave,
    SEV_ORDER,
    SEC_PROFILES
  };
})();
// ui-sources: 5aafe7cf5bc8ad28ddf9acf5413eb483fcf752d4281b069517a2d7b0b2214690
