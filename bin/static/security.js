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
      iconLabel
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
  var secEnabled = (p) => {
    const s = (p || {}).security;
    return !!(s && (s.enabled === true || s.enabled === "true"));
  };
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
    if (running && !secTimer) secTimer = setInterval(secReload, SEC_POLL_MS);
    if (!running) secStopPoll();
  }
  function secEnter() {
    if (secState.project) secReload();
    else secLoadPostures(false);
  }
  function secLeave() {
    secStopPoll();
  }
  function secBack() {
    secStopPoll();
    delete secPost[secState.project];
    secState.project = "";
    secState.analysis = null;
    secState.findings = [];
    secState.analyses = [];
    secState.stateFilter = "";
    $("sec-detail").hidden = true;
    $("sec-projects").hidden = false;
    secRenderList();
    secLoadPostures(false);
  }
  async function secOpen(project) {
    secStopPoll();
    const seq = ++secState.seq;
    secState.project = project;
    secState.analysis = null;
    secState.findings = [];
    secState.analyses = [];
    secState.stateFilter = "";
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
  async function secReload() {
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

  // ui/security/projects.js
  var secPost = {};
  var secPostGen = 0;
  async function secLoadPostures(force) {
    const names = (CC.DATA.projects || []).filter(secEnabled).map((p) => p.name);
    if (force) {
      secPostGen++;
      names.forEach((n) => {
        delete secPost[n];
      });
    }
    const gen = secPostGen;
    for (const name of names) {
      if (secPost[name]) continue;
      secPost[name] = { state: "loading" };
      try {
        const list = await secFetch("/api/security?project=" + encodeURIComponent(name));
        if (gen !== secPostGen) return;
        const done = (list || []).find((a) => a.state !== "running") || null;
        const rec = {
          state: "ok",
          analyses: list || [],
          latest: (list || [])[0] || null,
          done,
          findings: null
        };
        secPost[name] = rec;
        secRenderList();
        if (done) {
          const ck = await secFetch("/api/security/checklist?analysis=" + encodeURIComponent(done.id));
          if (gen !== secPostGen) return;
          rec.findings = ck.findings || [];
        }
      } catch (e) {
        if (gen !== secPostGen) return;
        secPost[name] = { state: "error", error: e.message };
      }
      secRenderList();
    }
  }
  function secRenderList() {
    const host = $("sec-list");
    if (!host) return;
    host.textContent = "";
    const projects = (CC.DATA.projects || []).slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
    if (!projects.length) {
      const e = secEl("div", "tblempty");
      e.appendChild(secIcon("inbox"));
      e.appendChild(document.createTextNode(
        "No projects yet. Security analysis is configured on a project, so there has to be one first."
      ));
      host.appendChild(e);
      return;
    }
    projects.forEach((p) => host.appendChild(secProjectRow(p)));
  }
  function secProjectRow(p) {
    const on = secEnabled(p);
    const row = document.createElement(on ? "button" : "div");
    row.className = "secrow" + (on ? "" : " off");
    if (on) {
      row.type = "button";
      row.onclick = () => secOpen(p.name);
    }
    row.appendChild(secIcon("shield"));
    const grow = secEl("div", "grow");
    grow.appendChild(secEl("div", "secname", p.name));
    const meta = secEl("div", "secmeta");
    if (!on) {
      meta.textContent = "Security analysis is off for this project \u2014 turn it on in the project editor, on the Security tab.";
    } else {
      const rec = secPost[p.name];
      if (!rec || rec.state === "loading") meta.textContent = "Loading\u2026";
      else if (rec.state === "error") meta.textContent = "Could not read its analyses \u2014 " + rec.error;
      else if (!rec.latest) meta.textContent = "Never analysed. Open it to pick a branch and start.";
      else {
        const a = rec.latest;
        meta.textContent = (a.state === "running" ? "Analysing " : "Last analysed ") + a.repo + " @ " + a.branch + " \xB7 " + a.profile + " \xB7 " + (a.state === "running" ? "started " + fmtAgo(a.started) : a.state + " " + fmtAgo(a.ended || a.started));
      }
    }
    grow.appendChild(meta);
    row.appendChild(grow);
    if (on) row.appendChild(secPosturePills(secPost[p.name], p.name));
    return row;
  }
  function secPosturePills(rec, name) {
    const wrap = secEl("div", "sevpills");
    if (!rec || rec.state !== "ok" || !rec.findings) return wrap;
    const counts = secPosture(rec.findings, secMinSeverity(name));
    const total = SEV_ORDER.reduce((n, s) => n + (counts[s] || 0), 0) + (counts.other || 0);
    if (!total) {
      wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
      return wrap;
    }
    ["critical", "high", "medium", "low", "info"].forEach((sev) => {
      if (!counts[sev]) return;
      wrap.appendChild(secEl("span", "sevpill " + sev, counts[sev] + " " + sev));
    });
    if (counts.other) wrap.appendChild(secEl("span", "sevpill low", counts.other + " other"));
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
    secRenderList();
    secLoadPostures(false);
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
    $("sec-dl-note").textContent = "Downloads always contain every recorded finding, whatever the severity floor shows.";
    $("sec-back").addEventListener("click", secBack);
    $("sec-reload").addEventListener("click", () => {
      secLoadPostures(true);
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
// ui-sources: 2404d93019db8f5bf8f364e2bde39d4b4b5ff05f3ccc35e5d39319d7aa00ecc3
