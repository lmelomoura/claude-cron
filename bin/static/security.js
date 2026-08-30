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
  var iconHTML;
  var openProjectEditor;
  var pageHeader;
  var kpiCard;
  var tableFooter;
  var makePicker;
  var createCombo;
  var closeMenus;
  var pushNav;
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
      iconHTML,
      openProjectEditor,
      pageHeader,
      kpiCard,
      tableFooter,
      makePicker,
      createCombo,
      closeMenus,
      pushNav
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
  var EVENT_KINDS = [
    "analysis_started",
    "analysis_finished",
    "decision_made",
    "settings_changed",
    "report_exported"
  ];
  var EVENT_KIND_LABEL = {
    analysis_started: "Analysis started",
    analysis_finished: "Analysis finished",
    decision_made: "Decision made",
    settings_changed: "Settings changed",
    report_exported: "Report exported"
  };
  var SEC_NEVER = {
    short: "Never analysed",
    next: "Never analysed \u2014 switch to Runs to pick a branch and start.",
    attempted: "No analysis of this project has finished yet \u2014 see Runs for what was attempted.",
    branch: "Never analysed on this branch \u2014 press Analyse to make the first one.",
    pickBranch: "Pick a branch, or type one, and press Analyse."
  };
  var SEC_FLOOR_SCOPE_NOTE = "Every recorded finding is counted here. A project's severity floor only narrows its findings list and the checklist of a single analysis, and each of those says how many rows it is holding back \u2014 it never narrows a posture total.";
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
  var ICON_HYGIENE = "hammer";
  var SEC_RULE_META = {
    // secret -- bin/security/secrets.py's `_RULES`, in that file's own order.
    private_key: { label: "Private keys committed", icon: "key" },
    generic_secret: { label: "Hardcoded secrets", icon: "lock" },
    aws_access_key: { label: "AWS access key committed", icon: "lock" },
    github_token: { label: "GitHub token committed", icon: "lock" },
    slack_token: { label: "Slack token committed", icon: "lock" },
    stripe_key: { label: "Stripe live key committed", icon: "lock" },
    openai_key: { label: "OpenAI API key committed", icon: "lock" },
    google_api_key: { label: "Google API key committed", icon: "lock" },
    // hygiene -- bin/security/hygiene.py's four findings. Labels say what each
    // rule's own rationale says it detects, not what its name suggests:
    // missing_gitignore's rationale is "the first .env, key or credential file
    // someone adds is committed by default" -- about secrets slipping in, not
    // about build output -- so the label says that, not "build artifacts".
    committed_env_file: { label: ".env file committed", icon: ICON_HYGIENE },
    committed_key_file: { label: "Private key file committed", icon: "key" },
    missing_gitignore: { label: "No .gitignore in the repository", icon: ICON_HYGIENE },
    world_writable_file: { label: "World-writable file", icon: ICON_HYGIENE }
  };
  var SEC_ADVISORY_RULE = /^(?:GHSA|CVE)-/i;
  function secHumaniseRule(rule) {
    const words = String(rule || "").split(/[-_]/).filter(Boolean);
    if (!words.length) return String(rule || "");
    const sentence = words.join(" ");
    return sentence.charAt(0).toUpperCase() + sentence.slice(1);
  }
  function secRuleMeta(category, rule) {
    const known = SEC_RULE_META[rule];
    if (known) return known;
    const safe = rule == null || rule === "" ? "Unknown rule" : String(rule);
    if (SEC_ADVISORY_RULE.test(safe)) return { label: safe, icon: "shield" };
    return { label: secHumaniseRule(safe), icon: SEC_CATEGORY_ICON[category] || "shield" };
  }
  var SEC_CATEGORY_ICON = {
    secret: "lock",
    dependency: "package",
    hygiene: ICON_HYGIENE,
    sast: "code"
  };
  var SEC_CATEGORY_LABEL = {
    secret: "Secrets",
    dependency: "Dependency",
    hygiene: "Hygiene",
    sast: "SAST"
  };
  function secCategoryMeta(category) {
    const label = SEC_CATEGORY_LABEL[category];
    if (label) return { label, icon: SEC_CATEGORY_ICON[category] };
    const safe = String(category || "");
    return {
      label: safe ? safe.charAt(0).toUpperCase() + safe.slice(1) : "Unknown",
      icon: "shield"
    };
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
    seq: 0,
    pinned: false
  };

  // ui/security/dom.js
  function secIcon(name) {
    return icon(name);
  }
  function secIconHTML(name) {
    return iconHTML(name);
  }
  function secEl(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
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
    const shown = secState.analysis;
    const repo = shown ? shown.repo : secState.repo;
    const branch = shown ? shown.branch : secState.branch;
    const mine = secState.analyses.filter((x) => x.repo === repo && x.branch === branch);
    if (!mine.length) {
      host.appendChild(secEl("div", "empty", branch ? "Nothing else analysed on " + branch + " yet." : "Nothing analysed on this branch yet."));
      return;
    }
    const current = shown && shown.id;
    mine.forEach((a) => {
      const row = secEl("div", "sechrow" + (a.id === current ? " on" : ""));
      const open = secEl("button", "btn ghost", "#" + a.id);
      open.type = "button";
      open.title = "Show this analysis";
      open.onclick = () => secShowAnalysis(a.id, true);
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
  function secProfileOpt(v) {
    return { v, label: v.charAt(0).toUpperCase() + v.slice(1) };
  }
  var secRepoCombo = null;
  var secBranchCombo = null;
  var secProfileCombo = null;
  function secInitLaunchCombos() {
    secRepoCombo = createCombo({
      id: "sec-repo",
      allowNone: false,
      onPick: async () => {
        await secLoadBranches("");
        $("sec-branch-other").value = "";
        secSyncScope();
      }
    });
    secBranchCombo = createCombo({
      id: "sec-branch",
      allowNone: false,
      onPick: () => {
        $("sec-branch-other").value = "";
        secSyncScope();
      }
    });
    secProfileCombo = createCombo({ id: "sec-profile", allowNone: false, def: "standard" });
    secProfileCombo.set("standard", SEC_PROFILES.map(secProfileOpt));
  }
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
  function secBack(fromHistory) {
    secStopPoll();
    secInvalidateIndex();
    secInvalidateProject();
    secState.project = "";
    secState.analysis = null;
    secState.findings = [];
    secState.analyses = [];
    secState.stateFilter = "";
    secState.pinned = false;
    $("sec-detail").hidden = true;
    $("sec-projects").hidden = false;
    secRenderIndex();
    secLoadIndex(false);
    if (!fromHistory) pushNav({ view: "security", sec: { screen: "index" } });
  }
  async function secOpen(project) {
    secStopPoll();
    const seq = ++secState.seq;
    secState.project = project;
    secState.analysis = null;
    secState.findings = [];
    secState.analyses = [];
    secState.stateFilter = "";
    secState.pinned = false;
    secProjectPollWasRunning = null;
    $("sec-projects").hidden = true;
    $("sec-detail").hidden = false;
    $("sec-title").textContent = project;
    $("sec-findings").textContent = "";
    $("sec-history").textContent = "";
    $("sec-summary").textContent = "";
    $("sec-checklist").textContent = "";
    $("sec-dl").hidden = true;
    secResetFindBar();
    secStatus("Loading\u2026");
    const p = projById(project) || {};
    const repos = secRepos(p);
    secRepoCombo.set("", repos.map((r) => ({ v: r, label: r })));
    $("sec-repo-field").hidden = repos.length < 2;
    secProfileCombo.set(secDefaultProfile(project));
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
    if (last && repos.includes(last.repo)) secRepoCombo.set(last.repo);
    await secLoadBranches(last ? last.branch : "");
    if (seq !== secState.seq) return;
    if (last && SEC_PROFILES.includes(last.profile)) secProfileCombo.set(last.profile);
    await secSyncScope();
  }
  async function secLoadBranches(want) {
    const seq = secState.seq;
    secBranchCombo.set("\u2026", [{ v: "\u2026", label: "\u2026" }]);
    let branches = [];
    try {
      const j = await secFetch("/api/security/branches?project=" + encodeURIComponent(secState.project) + "&repo=" + encodeURIComponent($("sec-repo").value));
      if (seq !== secState.seq) return;
      branches = j.branches || [];
    } catch (e) {
      if (seq !== secState.seq) return;
      secBranchCombo.set("", []);
      toast("Could not list branches \u2014 " + e.message, true);
      return;
    }
    if (want && !branches.includes(want)) branches = [want].concat(branches);
    secBranchCombo.set(want, branches.map((b) => ({ v: b, label: b })));
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
  async function secShowAnalysis(id, pinned) {
    const seq = ++secState.seq;
    secState.pinned = !!pinned;
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
    const pinnedId = secState.pinned && secState.analysis ? secState.analysis.id : null;
    const want = pinnedId != null ? pinnedId : mine.length ? mine[0].id : secState.analysis && secState.analysis.id;
    await secShowAnalysis(want == null ? null : want, secState.pinned);
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
  function secRenderRunMeta(a) {
    const host = $("sec-run-meta");
    host.textContent = "";
    const grid = secEl("div", "secrun-metagrid");
    const cell = (label, valueNode, extraCls) => {
      const c = secEl("div", "secrun-metacell");
      c.appendChild(secEl("div", "secrun-metalabel", label));
      const v = secEl("div", "secrun-metaval" + (extraCls ? " " + extraCls : ""));
      v.appendChild(valueNode);
      c.appendChild(v);
      return c;
    };
    const running = a.state === "running";
    grid.appendChild(cell("Profile", secEl("span", "pill profile", a.profile || "\u2014")));
    grid.appendChild(cell("Branch", document.createTextNode(a.branch || "\u2014")));
    grid.appendChild(cell(
      "Commit",
      document.createTextNode(String(a.commit_sha || "").slice(0, 12) || "\u2014"),
      "mono"
    ));
    grid.appendChild(cell("Duration", document.createTextNode(
      a.ended && a.started ? fmtDur(Math.max(0, a.ended - a.started)) : running ? "running\u2026" : "\u2014"
    )));
    grid.appendChild(cell("Date", document.createTextNode(fmtWhen(a.started))));
    host.appendChild(grid);
    if (a.spend_usd) host.appendChild(secEl("div", "secrun-spend", money(a.spend_usd)));
  }
  function secRenderRunNotice(a) {
    const host = $("sec-run-notice");
    host.textContent = "";
    const running = a.state === "running";
    if (running) {
      host.appendChild(secEl(
        "div",
        "secrun-notice",
        "Secrets, dependencies and CVEs are written moments after the agent starts \u2014 they are its first command \u2014 so what is below is already real while the code review keeps going."
      ));
    }
    const run = secRunFor(a);
    if (running && !run) {
      if (Date.now() / 1e3 - (a.started || 0) > 180) {
        host.appendChild(secEl(
          "div",
          "secrun-notice warn",
          "No live run is behind this analysis \u2014 it likely died without closing. The next Analyse sweeps it; until then downloads carry what it recorded."
        ));
      } else {
        host.appendChild(secEl(
          "div",
          "secrun-notice",
          "Preparing the run \u2014 fetching the branch and cutting a clean worktree. The live trace appears here the moment the agent starts."
        ));
      }
    }
  }
  function secPaint() {
    const a = secState.analysis;
    secPaintRunButton();
    secSyncPoll();
    const box = $("sec-status");
    box.textContent = "";
    secRefreshRunPanels();
    if (!a) {
      box.appendChild(secEl(
        "span",
        null,
        secState.branch ? SEC_NEVER.branch : SEC_NEVER.pickBranch
      ));
      $("sec-run-meta").textContent = "";
      $("sec-run-notice").textContent = "";
      $("sec-incomplete").hidden = true;
      $("sec-coverage").hidden = true;
      $("sec-summary").textContent = "";
      $("sec-checklist").textContent = "";
      $("sec-dl").hidden = true;
      $("sec-findings").textContent = "";
      secRenderHistory();
      return;
    }
    secRenderRunMeta(a);
    secRenderRunNotice(a);
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
  var SEC_FIND_CATEGORIES = ["secret", "dependency", "sast", "hygiene"];
  var secFindSearch = "";
  var secFindCategory = "";
  var secFindCatPicker = null;
  var secFindBadge = null;
  function secFindVisible() {
    return secVisible(secState.findings, secMinSeverity(secState.project));
  }
  function secInitFindBar() {
    $("sec-find-search-box").insertBefore(secIcon("search"), $("sec-find-search"));
    const input = $("sec-find-search");
    input.setAttribute("aria-label", "Search findings in this run");
    input.oninput = () => {
      secFindSearch = input.value;
      secRenderFindings();
    };
    const fTrigger = $("sec-run-filterpick-trigger");
    fTrigger.appendChild(secIcon("filter"));
    fTrigger.appendChild(document.createTextNode("Filters"));
    secFindBadge = secEl("span", "secfind-filters-badge", "1");
    secFindBadge.hidden = true;
    fTrigger.appendChild(secFindBadge);
    fTrigger.appendChild(secIcon("cdown"));
    fTrigger.onclick = (e) => e.stopPropagation();
    const filters = $("sec-run-filterpick");
    const fPop = $("sec-run-filterpop");
    filters.ontoggle = () => {
      fPop.hidden = !filters.open;
      if (!filters.open) return;
      const r = fTrigger.getBoundingClientRect();
      fPop.style.position = "fixed";
      fPop.style.top = r.bottom + 6 + "px";
      fPop.style.right = window.innerWidth - r.right + "px";
      fPop.style.left = "auto";
      fPop.style.bottom = "auto";
    };
    secFindCatPicker = makePicker("sec-find-catpick", {
      icon: secIconHTML("filter"),
      label: "Category",
      valueLabel: () => secFindCategory ? secCategoryMeta(secFindCategory).label : "All",
      rows: () => {
        const visible = secFindVisible();
        const counts = {};
        visible.forEach((f) => {
          counts[f.category] = (counts[f.category] || 0) + 1;
        });
        const rows = [{
          v: "",
          label: "All",
          n: visible.length,
          sel: secFindCategory === "",
          icon: secIconHTML("layers")
        }];
        SEC_FIND_CATEGORIES.forEach((cat) => {
          const meta = secCategoryMeta(cat);
          rows.push({
            v: cat,
            label: meta.label,
            n: counts[cat] || 0,
            sel: secFindCategory === cat,
            icon: secIconHTML(meta.icon)
          });
        });
        return rows;
      },
      onPick: (v) => {
        secFindCategory = v;
        secRenderFindings();
      }
    });
  }
  function secResetFindBar() {
    secFindSearch = "";
    secFindCategory = "";
    const input = $("sec-find-search");
    if (input) input.value = "";
    if (secFindCatPicker) secFindCatPicker.paint();
  }
  function secRenderSummary() {
    const host = $("sec-summary");
    host.textContent = "";
    const shown = secVisible(secState.findings, secMinSeverity(secState.project));
    const hidden = secState.findings.length - shown.length;
    if (hidden > 0) {
      host.appendChild(document.createTextNode(hidden + " finding" + (hidden === 1 ? "" : "s") + " below " + secMinSeverity(secState.project) + " \u2014 recorded, not shown"));
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
    if (secFindBadge) secFindBadge.hidden = !secState.stateFilter;
  }
  function secFindMatchesSearch(f, q) {
    if (!q) return true;
    const needle = q.trim().toLowerCase();
    if (!needle) return true;
    if (String(f.title || "").toLowerCase().includes(needle)) return true;
    return (f.occurrences || []).some((o) => String(o.file || "").toLowerCase().includes(needle));
  }
  function secRenderFindings() {
    const host = $("sec-findings");
    host.textContent = "";
    let list = secVisible(secState.findings, secMinSeverity(secState.project));
    if (secState.stateFilter) list = list.filter((f) => f.state === secState.stateFilter);
    if (secFindCategory) list = list.filter((f) => f.category === secFindCategory);
    if (secFindSearch.trim()) list = list.filter((f) => secFindMatchesSearch(f, secFindSearch));
    const stateRank = (f) => SEC_STATES.indexOf(f.state);
    list = list.slice().sort((x, y) => secSevRank(y.severity) - secSevRank(x.severity) || stateRank(x) - stateRank(y) || String(x.title).localeCompare(String(y.title)));
    if (!list.length) {
      const e = secEl("div", "empty", secState.stateFilter || secFindCategory || secFindSearch.trim() ? "Nothing matches these filters." : "This analysis reported nothing to show.");
      host.appendChild(e);
    } else {
      list.forEach((f) => host.appendChild(secFindingRow(f)));
    }
    if (secFindCatPicker) secFindCatPicker.paint();
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
    if ((f.snippet || "").trim()) {
      const box = secEl("div", "secsnippet");
      if ((f.snippet_lang || "").trim()) box.appendChild(secEl("span", "secsnippet-lang", f.snippet_lang + ":"));
      box.appendChild(secEl("code", null, f.snippet));
      row.appendChild(box);
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
  async function secDownloadReport(id, fmt, btn) {
    btn.disabled = true;
    try {
      const r = await fetch("/api/security/report?analysis=" + encodeURIComponent(id) + "&format=" + encodeURIComponent(fmt), { headers: { "X-CC-Token": TOKEN } });
      if (!r.ok) {
        const j = await r.json().catch(() => null);
        throw new Error(j && j.error || "HTTP " + r.status);
      }
      const url = URL.createObjectURL(await r.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "security-analysis-" + id + "." + (fmt === "sbom" ? "cdx.json" : fmt);
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
  async function secDownload(fmt) {
    const a = secState.analysis;
    if (!a) return;
    await secDownloadReport(a.id, fmt, $("sec-dl-" + fmt));
  }

  // ui/security/branches-tab.js
  var BRANCH_CAPPED_TITLE = "This analysis is INCOMPLETE: it stopped before covering the whole scope. The posture beside this badge is what it had reached, not what is there.";
  function secBranchesCaption() {
    return secEl(
      "div",
      "secpj-caption",
      "Each row is that branch's own posture \u2014 the same computation the Overview panel above uses for its one branch. A branch appears here only once one of its analyses has reached done or capped; a branch whose only analyses so far are still running or have failed already shows up in Runs and Reports but will not have a row here yet. The sidebar's donut counts a finding once for the whole project even when it is open on several branches; here it counts once per branch, so these rows can add up to more than the sidebar's own total."
    );
  }
  function secBranchTrendText(trend) {
    const pts = trend || [];
    if (!pts.length) return "No analyses of this branch in the last 30 days.";
    const partial = pts.some((p) => p.state === "capped");
    if (pts.length === 1) {
      return pts[0].open + " open \u2014 only one analysis in the last 30 days, nothing yet to compare it against." + (partial ? " It stopped early, so that count is what it reached." : "");
    }
    const opens = pts.map((p) => p.open);
    const first = opens[0], last = opens[opens.length - 1];
    const base = first + " \u2192 " + last + " open across " + pts.length + " analyses in the last 30 days";
    if (partial) {
      return base + ", but at least one of them stopped before covering the whole scope \u2014 no direction is claimed across a partial read";
    }
    let direction = "flat";
    for (let i = 1; i < opens.length; i++) {
      const step = opens[i] < opens[i - 1] ? "falling" : opens[i] > opens[i - 1] ? "rising" : "flat";
      if (step === "flat") continue;
      if (direction === "flat") direction = step;
      else if (direction !== step) {
        direction = null;
        break;
      }
    }
    if (direction) return base + " (" + direction + ")";
    const peak = Math.max(...opens), trough = Math.min(...opens);
    if (peak > first && peak > last) return base + ", peaked at " + peak;
    if (trough < first && trough < last) return base + ", dipped to " + trough;
    return base;
  }
  function secBranchRow(r) {
    const tr = document.createElement("tr");
    const cell = (text) => {
      const td = document.createElement("td");
      td.textContent = text;
      return td;
    };
    tr.appendChild(cell(r.branch || ""));
    tr.appendChild(cell(r.last_analysis ? fmtAgo(r.last_analysis) : "\u2014"));
    const tdCount = cell(String(r.analyses || 0));
    tdCount.className = "num";
    tr.appendChild(tdCount);
    const tdOpen = document.createElement("td");
    tdOpen.appendChild(secIndexPosturePills(r.open || {}));
    if (r.state === "capped") {
      const badge = secEl("span", "secidx-capped", "incomplete");
      badge.title = BRANCH_CAPPED_TITLE;
      tdOpen.appendChild(badge);
    }
    tr.appendChild(tdOpen);
    tr.appendChild(cell(r.state || "\u2014"));
    tr.appendChild(cell(secBranchTrendText(r.trend)));
    return tr;
  }
  function secBranchesTable(rows, attempted) {
    if (!rows.length) {
      return secEl(
        "div",
        "tblempty",
        attempted ? SEC_NEVER.attempted : SEC_NEVER.next
      );
    }
    const wrap = secEl("div", "tablewrap");
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    ["Branch", "Last analysis", "Analyses", "Open", "Last state", "Trend (30d)"].forEach((h) => {
      const th = document.createElement("th");
      th.textContent = h;
      if (h === "Last state") {
        th.title = "The state of the analysis this row's Open posture was read from. `capped` means it stopped before covering the whole scope, so those counts are what it reached, not what is there.";
      }
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    rows.forEach((r) => tbody.appendChild(secBranchRow(r)));
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }
  function secRenderProjectBranches(payload) {
    const host = $("sec-pj-branches");
    if (!host) return;
    host.textContent = "";
    const tabs = (payload || {}).tabs || {};
    const rows = tabs.branches || [];
    const attempted = !!(tabs.overview || {}).attempted;
    host.appendChild(secBranchesCaption());
    host.appendChild(secBranchesTable(rows, attempted));
  }

  // ui/security/reports-tab.js
  var SEC_REPORT_FORMATS = [
    ["md", "Markdown"],
    ["json", "JSON"],
    ["html", "HTML"],
    ["sbom", "SBOM"]
  ];
  function secReportsCaption() {
    const cap = secEl("div", "secpj-caption");
    cap.appendChild(document.createTextNode(
      "Markdown, JSON and HTML are generated from each analysis's own checklist at the moment you download one. "
    ));
    cap.appendChild(secEl("b", null, "SBOM is different: "));
    cap.appendChild(document.createTextNode(
      "it is not a report over any analysis's checklist but the stored CycloneDX inventory itself, kept per branch with only the most recent document \u2014 so the SBOM button on an older row still downloads that branch's CURRENT document, not a snapshot of what that analysis saw."
    ));
    return cap;
  }
  function secReportRow(r) {
    const tr = document.createElement("tr");
    const cell = (text) => {
      const td = document.createElement("td");
      td.textContent = text;
      return td;
    };
    tr.appendChild(cell("#" + r.analysis_id));
    tr.appendChild(cell(r.branch || ""));
    tr.appendChild(cell(r.started ? fmtWhen(r.started) : "\u2014"));
    tr.appendChild(cell(r.state || ""));
    const tdDl = document.createElement("td");
    const row = secEl("div", "secdl");
    SEC_REPORT_FORMATS.forEach(([fmt, label]) => {
      const btn = secEl("button", "btn ghost");
      btn.type = "button";
      btn.appendChild(secIcon("file"));
      btn.appendChild(document.createTextNode(label));
      btn.onclick = () => secDownloadReport(r.analysis_id, fmt, btn);
      row.appendChild(btn);
    });
    tdDl.appendChild(row);
    tr.appendChild(tdDl);
    return tr;
  }
  function secReportsTable(rows) {
    if (!rows.length) {
      return secEl("div", "tblempty", "No analyses of this project yet.");
    }
    const wrap = secEl("div", "tablewrap");
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    ["Analysis", "Branch", "Started", "State", "Downloads"].forEach((h) => {
      const th = document.createElement("th");
      th.textContent = h;
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    rows.forEach((r) => tbody.appendChild(secReportRow(r)));
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }
  function secRenderProjectReports(payload) {
    const host = $("sec-pj-reports");
    if (!host) return;
    host.textContent = "";
    const rows = ((payload || {}).tabs || {}).reports || [];
    host.appendChild(secReportsCaption());
    host.appendChild(secReportsTable(rows));
    host.appendChild(secEl(
      "div",
      "secdlnote",
      "Downloads always contain every recorded finding, whatever the severity floor shows."
    ));
  }

  // ui/security/findings-screen.js
  var FIND_SORT_COLUMNS = [
    ["severity", "Severity"],
    ["title", "Title"],
    ["category", "Category"],
    ["branch", "Branch"],
    ["state", "Status"],
    ["first_seen", "First seen"]
  ];
  var FIND_CATEGORIES = ["secret", "dependency", "sast", "hygiene"];
  var FIND_PER_PAGE = 10;
  var FIND_PER_PAGE_OPTIONS = [10, 25, 50];
  function _defaultFilters() {
    return {
      severity: [],
      state: [],
      category: [],
      branch: "",
      path: "",
      q: "",
      analysis: "",
      show_resolved: false,
      fingerprint: ""
    };
  }
  function _newFindState(host, project) {
    return {
      host,
      project,
      gen: 0,
      data: null,
      error: "",
      filters: _defaultFilters(),
      sort: "severity",
      dir: "desc",
      page: 1,
      perPage: FIND_PER_PAGE,
      savedName: "",
      newName: ""
    };
  }
  var secFindStates = /* @__PURE__ */ new WeakMap();
  async function renderFindings(host, project, initialFilters) {
    let fs = secFindStates.get(host);
    if (!fs || fs.project !== project) {
      fs = _newFindState(host, project);
      secFindStates.set(host, fs);
    }
    if (initialFilters) {
      fs.filters = Object.assign(_defaultFilters(), initialFilters);
      fs.page = 1;
    }
    await secFindLoad(fs);
  }
  function secFindQuery(fs) {
    const p = new URLSearchParams();
    p.set("project", fs.project);
    p.set("sort", fs.sort);
    p.set("dir", fs.dir);
    p.set("page", String(fs.page));
    p.set("per_page", String(fs.perPage || FIND_PER_PAGE));
    const f = fs.filters;
    if (f.severity.length) p.set("severity", f.severity.join(","));
    if (f.state.length) p.set("state", f.state.join(","));
    if (f.category.length) p.set("category", f.category.join(","));
    if (f.branch.trim()) p.set("branch", f.branch.trim());
    if (f.path.trim()) p.set("path", f.path.trim());
    if (f.q.trim()) p.set("q", f.q.trim());
    if (f.analysis.trim()) p.set("analysis", f.analysis.trim());
    if (f.show_resolved) p.set("show_resolved", "1");
    if (f.fingerprint.trim()) p.set("fingerprint", f.fingerprint.trim());
    return p.toString();
  }
  async function secFindLoad(fs) {
    const host = fs.host, project = fs.project;
    if (!host || !project) return;
    const gen = ++fs.gen;
    if (!fs.data) {
      host.textContent = "";
      host.appendChild(secEl("div", "tblempty", "Loading\u2026"));
    }
    let data;
    try {
      data = await secFetch("/api/security/findings?" + secFindQuery(fs));
    } catch (e) {
      if (gen !== fs.gen || secFindStates.get(host) !== fs) return;
      fs.error = e.message;
      fs.data = null;
      secFindPaint(fs);
      return;
    }
    if (gen !== fs.gen || secFindStates.get(host) !== fs) return;
    fs.error = "";
    fs.data = data;
    fs.page = data.page || 1;
    secFindPaint(fs);
  }
  async function secFindRefresh(fs) {
    await secFindLoad(fs);
  }
  function secFindPaint(fs) {
    const host = fs.host;
    if (!host) return;
    host.textContent = "";
    host.appendChild(secFindHeader(fs, fs.data));
    if (fs.error) {
      const box = secEl("div", "tblempty");
      box.appendChild(secIcon("alert"));
      box.appendChild(document.createTextNode("Could not read findings \u2014 " + fs.error));
      host.appendChild(box);
      return;
    }
    const data = fs.data;
    if (!data) return;
    host.appendChild(secFindStrip(fs, data));
    host.appendChild(secFindFilterBar(fs, data));
    const section = secFindTableSection(fs, data);
    if ((section.className || "").includes("table-card")) section.appendChild(secFindPager(fs, data));
    host.appendChild(section);
  }
  function secFindHeader(fs, data) {
    const wrap = secEl("div");
    if (((fs.filters || {}).fingerprint || "").trim()) return wrap;
    const head = secEl("div", "secfind-head");
    const titleWrap = secEl("div");
    const titleLine = secEl("div", "secfind-head-title");
    titleLine.appendChild(secIcon("shield"));
    titleLine.appendChild(secEl("span", null, "All findings"));
    titleWrap.appendChild(titleLine);
    titleWrap.appendChild(secEl(
      "p",
      "secfind-head-sub",
      "Complete list of security findings for all analyses in this project."
    ));
    head.appendChild(titleWrap);
    const actions = secEl("div", "secfind-head-actions");
    const exportBtn = secEl("button", "btn ghost");
    exportBtn.type = "button";
    exportBtn.appendChild(secIcon("download"));
    exportBtn.appendChild(document.createTextNode("Export"));
    exportBtn.title = "Open this project's Reports tab";
    exportBtn.onclick = () => secSwitchProjectTab("reports");
    actions.appendChild(exportBtn);
    actions.appendChild(secFindSavedFilters(fs, data || {}));
    head.appendChild(actions);
    wrap.appendChild(head);
    return wrap;
  }
  function secFindHiddenByFloor(data, minSeverity) {
    const floor = SEV_ORDER.indexOf(minSeverity);
    const bySev = data.by_severity || {}, fixedBySev = data.fixed_by_severity || {};
    let n = 0;
    SEV_ORDER.forEach((sev, i) => {
      if (i < floor) n += (bySev[sev] || 0) - (fixedBySev[sev] || 0);
    });
    return n;
  }
  var ROW_PILL_TITLE = "Rows matching the current filters \u2014 the same finding open on two branches counts twice here.";
  function _secCap(s) {
    s = String(s || "");
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }
  function secFindStrip(fs, data) {
    const box = secEl("div");
    if (data.analysed === false) {
      const line = secEl("div", "warnline bad");
      line.appendChild(secIcon("alert"));
      line.appendChild(secEl(
        "span",
        "grow",
        data.attempted ? SEC_NEVER.attempted : SEC_NEVER.next
      ));
      box.appendChild(line);
    } else if (data.capped_branches) {
      const line = secEl("div", "warnline bad");
      line.appendChild(secIcon("alert"));
      line.appendChild(secEl(
        "span",
        "grow",
        data.capped_branches + " of these branches had a latest analysis that stopped before covering its whole scope \u2014 what is below is what it had reached, not what is there."
      ));
      box.appendChild(line);
    }
    const fingerprintFilter = ((fs.filters || {}).fingerprint || "").trim();
    if (fingerprintFilter) {
      box.appendChild(secEl(
        "div",
        "secpj-caption",
        "Filtered to fingerprint " + fingerprintFilter + "\u2026 \u2014 \u201CClear filters\u201D below shows this project's whole list."
      ));
    }
    const strip = secEl("div", "secfind-strip");
    const totalStat = secEl("div", "secfind-stat total");
    totalStat.title = ROW_PILL_TITLE;
    totalStat.appendChild(secEl("div", "secfind-stat-label", "Total findings"));
    const totalLine = secEl("div", "secfind-stat-numline");
    totalLine.appendChild(secEl("span", "secfind-stat-num", String(data.total || 0)));
    const totalIc = secEl("span", "secfind-stat-ic");
    totalIc.appendChild(secIcon("file"));
    totalLine.appendChild(totalIc);
    totalStat.appendChild(totalLine);
    strip.appendChild(totalStat);
    const bySev = data.by_severity || {};
    const total = data.total || 0;
    let any = false;
    ["critical", "high", "medium", "low", "info"].forEach((sev) => {
      any = any || !!bySev[sev];
      const n = bySev[sev] || 0;
      const stat = secEl("div", "secfind-stat " + sev);
      stat.title = ROW_PILL_TITLE;
      const label = secEl("div", "secfind-stat-label");
      label.appendChild(secEl("span", "secfind-stat-dot"));
      label.appendChild(secEl("span", null, _secCap(sev)));
      stat.appendChild(label);
      stat.appendChild(secEl("div", "secfind-stat-num", String(n)));
      stat.appendChild(secEl("div", "secfind-stat-pct", total ? (n / total * 100).toFixed(1) + "%" : "\u2014"));
      strip.appendChild(stat);
    });
    strip.appendChild(secEl("div", "secfind-strip-div"));
    const uniqueStat = secEl("div", "secfind-stat unique");
    uniqueStat.title = "Distinct problems (fingerprints) \u2014 the same finding open on two branches counts once here.";
    const uLabel = secEl("div", "secfind-stat-label");
    const uIcon = secEl("span", "secfind-stat-diamond");
    uIcon.appendChild(secIcon("diamond"));
    uLabel.appendChild(uIcon);
    uLabel.appendChild(secEl("span", null, "Unique issues"));
    uniqueStat.appendChild(uLabel);
    uniqueStat.appendChild(secEl("div", "secfind-stat-num", String(data.unique || 0)));
    strip.appendChild(uniqueStat);
    box.appendChild(strip);
    if (!any && data.analysed !== false) {
      box.appendChild(secEl("span", "sevpill clean", "Nothing matches"));
    }
    const minSeverity = secMinSeverity(fs.project);
    const hidden = secFindHiddenByFloor(data, minSeverity);
    const note = secEl("div", "secpj-caption");
    if (hidden > 0) {
      note.appendChild(document.createTextNode(
        hidden + " finding" + (hidden === 1 ? "" : "s") + " below " + minSeverity + " " + (hidden === 1 ? "is" : "are") + " hidden by this project's severity floor \u2014 recorded, not shown. "
      ));
    }
    note.appendChild(secEl(
      "b",
      null,
      "Downloads always contain every recorded finding, whatever the severity floor shows."
    ));
    box.appendChild(note);
    return box;
  }
  function secFindTriggerLabel(label, valueText) {
    const trigger = document.createElement("summary");
    trigger.className = "filterpick";
    trigger.onclick = (e) => e.stopPropagation();
    if (label) trigger.appendChild(secEl("span", "pk-k", label + ":"));
    const valueEl = secEl("span", "pk-v", valueText);
    trigger.appendChild(valueEl);
    trigger.appendChild(secIcon("cdown"));
    return { trigger, valueEl };
  }
  function secFindPositionPop(details, trigger, pop) {
    pop.setAttribute("role", "menu");
    pop.hidden = true;
    details.appendChild(pop);
    details.ontoggle = () => {
      pop.hidden = !details.open;
      if (!details.open) return;
      const r = trigger.getBoundingClientRect();
      pop.style.position = "fixed";
      pop.style.top = r.bottom + 6 + "px";
      pop.style.left = r.left + "px";
      pop.style.right = "auto";
      pop.style.bottom = "auto";
    };
  }
  function secFindMultiPicker(label, options, selected, onToggle) {
    const field = secEl("div", "secfind-fpick");
    const valueText = !selected.length ? "All" : selected.length === 1 ? (options.find((o) => o.v === selected[0]) || {}).label || selected[0] : selected.length + " selected";
    const { trigger } = secFindTriggerLabel(label, valueText);
    const details = document.createElement("details");
    details.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    options.forEach((opt) => {
      const item = document.createElement("button");
      item.type = "button";
      item.setAttribute("role", "menuitemcheckbox");
      item.setAttribute("aria-checked", selected.includes(opt.v) ? "true" : "false");
      item.appendChild(document.createTextNode(opt.label));
      if (selected.includes(opt.v)) item.appendChild(secIcon("check2"));
      item.onclick = (e) => {
        e.stopPropagation();
        onToggle(opt.v);
      };
      pop.appendChild(item);
    });
    secFindPositionPop(details, trigger, pop);
    field.appendChild(details);
    return field;
  }
  function secFindSinglePicker(label, options, selected, onPick) {
    const field = secEl("div", "secfind-fpick");
    const current = options.find((o) => o.v === selected);
    const { trigger } = secFindTriggerLabel(label, selected && current ? current.label : "All");
    const details = document.createElement("details");
    details.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    const allItem = document.createElement("button");
    allItem.type = "button";
    allItem.setAttribute("role", "menuitem");
    allItem.appendChild(document.createTextNode("All"));
    if (!selected) allItem.appendChild(secIcon("check2"));
    allItem.onclick = (e) => {
      e.stopPropagation();
      details.open = false;
      onPick("");
    };
    pop.appendChild(allItem);
    options.forEach((opt) => {
      const item = document.createElement("button");
      item.type = "button";
      item.setAttribute("role", "menuitem");
      item.appendChild(document.createTextNode(opt.label));
      if (selected === opt.v) item.appendChild(secIcon("check2"));
      item.onclick = (e) => {
        e.stopPropagation();
        details.open = false;
        onPick(opt.v);
      };
      pop.appendChild(item);
    });
    secFindPositionPop(details, trigger, pop);
    field.appendChild(details);
    return field;
  }
  function secFindTextPicker(label, value, onChange) {
    const field = secEl("div", "secfind-fpick");
    const { trigger } = secFindTriggerLabel(label, value.trim() ? value : "All");
    const details = document.createElement("details");
    details.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    const inp = document.createElement("input");
    inp.type = "text";
    inp.spellcheck = false;
    inp.autocomplete = "off";
    inp.placeholder = "contains\u2026";
    inp.value = value;
    inp.onclick = (e) => e.stopPropagation();
    inp.onchange = () => onChange(inp.value);
    pop.appendChild(inp);
    secFindPositionPop(details, trigger, pop);
    field.appendChild(details);
    return field;
  }
  function secFindToggleIn(list, value) {
    const i = list.indexOf(value);
    if (i >= 0) list.splice(i, 1);
    else list.push(value);
  }
  function secFindActiveFilterCount(fs) {
    const f = fs.filters;
    let n = 0;
    if (f.severity.length) n++;
    if (f.state.length) n++;
    if (f.category.length) n++;
    if (f.branch.trim()) n++;
    if (f.path.trim()) n++;
    if (f.analysis.trim()) n++;
    if (f.q.trim()) n++;
    if (!f.show_resolved) n++;
    return n;
  }
  function secFindClearButton(fs) {
    const btn = secEl("button", "btn ghost");
    btn.type = "button";
    btn.appendChild(secIcon("x"));
    btn.appendChild(document.createTextNode("Clear filters"));
    btn.onclick = () => {
      fs.filters = _defaultFilters();
      fs.page = 1;
      secFindRefresh(fs);
    };
    return btn;
  }
  function secFindCurrentQuery(fs) {
    const f = fs.filters;
    return {
      severity: f.severity,
      state: f.state,
      category: f.category,
      branch: f.branch,
      path: f.path,
      q: f.q,
      analysis: f.analysis,
      show_resolved: f.show_resolved,
      fingerprint: f.fingerprint,
      sort: fs.sort,
      dir: fs.dir
    };
  }
  function secFindApplyQuery(fs, q) {
    const query = q || {};
    fs.filters = {
      severity: Array.isArray(query.severity) ? query.severity.slice() : [],
      state: Array.isArray(query.state) ? query.state.slice() : [],
      category: Array.isArray(query.category) ? query.category.slice() : [],
      branch: typeof query.branch === "string" ? query.branch : "",
      path: typeof query.path === "string" ? query.path : "",
      q: typeof query.q === "string" ? query.q : "",
      analysis: typeof query.analysis === "string" ? query.analysis : "",
      show_resolved: !!query.show_resolved,
      fingerprint: typeof query.fingerprint === "string" ? query.fingerprint : ""
    };
    fs.sort = FIND_SORT_COLUMNS.some(([key]) => key === query.sort) ? query.sort : "severity";
    fs.dir = query.dir === "asc" ? "asc" : "desc";
    fs.page = 1;
    secFindRefresh(fs);
  }
  async function secFindSaveCurrent(fs, name) {
    const trimmed = (name || "").trim();
    if (!trimmed) {
      toast("Name this filter set before saving", true);
      return;
    }
    const ok = await api(
      "security_filter_save",
      { project: fs.project, name: trimmed, query: secFindCurrentQuery(fs) }
    );
    if (!ok) return;
    toast("Filter saved", false, "check");
    fs.savedName = trimmed;
    fs.newName = "";
    await secFindRefresh(fs);
  }
  async function secFindDeleteSaved(fs, name) {
    if (!name) return;
    const ok = await api("security_filter_delete", { project: fs.project, name });
    if (!ok) return;
    toast("Filter deleted", false, "check");
    fs.savedName = "";
    await secFindRefresh(fs);
  }
  function secFindSavedFilters(fs, data) {
    const filters = data.filters || [];
    if (!filters.some((f) => f.name === fs.savedName)) fs.savedName = "";
    const details = document.createElement("details");
    details.className = "secfind-savedpick";
    const { trigger, valueEl } = secFindTriggerLabel(null, fs.savedName || "Saved filters");
    details.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    function pick(name, query) {
      fs.savedName = name;
      valueEl.textContent = name || "Saved filters";
      details.open = false;
      if (query) secFindApplyQuery(fs, query);
    }
    const blank = document.createElement("button");
    blank.type = "button";
    blank.setAttribute("role", "menuitem");
    blank.appendChild(document.createTextNode("\u2014 none \u2014"));
    if (!fs.savedName) blank.appendChild(secIcon("check2"));
    blank.onclick = (e) => {
      e.stopPropagation();
      pick("");
    };
    pop.appendChild(blank);
    filters.forEach((f) => {
      const row = secEl("div", "secfind-savedrow");
      const item = document.createElement("button");
      item.type = "button";
      item.setAttribute("role", "menuitem");
      item.appendChild(document.createTextNode(f.name));
      if (f.name === fs.savedName) item.appendChild(secIcon("check2"));
      item.onclick = (e) => {
        e.stopPropagation();
        pick(f.name, f.query);
      };
      row.appendChild(item);
      const del = document.createElement("button");
      del.type = "button";
      del.className = "iconbtn";
      del.title = "Delete this saved filter";
      del.appendChild(secIcon("trash"));
      del.onclick = (e) => {
        e.stopPropagation();
        details.open = false;
        secFindDeleteSaved(fs, f.name);
      };
      row.appendChild(del);
      pop.appendChild(row);
    });
    pop.appendChild(secEl("div", "sep"));
    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "Save current view as\u2026";
    nameInput.value = fs.newName;
    nameInput.onclick = (e) => e.stopPropagation();
    nameInput.onchange = () => {
      fs.newName = nameInput.value;
    };
    pop.appendChild(nameInput);
    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.setAttribute("role", "menuitem");
    saveBtn.appendChild(secIcon("check2"));
    saveBtn.appendChild(document.createTextNode("Save"));
    saveBtn.onclick = (e) => {
      e.stopPropagation();
      secFindSaveCurrent(fs, nameInput.value);
    };
    pop.appendChild(saveBtn);
    secFindPositionPop(details, trigger, pop);
    return details;
  }
  function secFindFilterBar(fs, data) {
    const wrap = secEl("div", "secfind-filters");
    const row1 = secEl("div", "secfind-filters-row");
    const search = secEl("div", "secfind-search");
    search.appendChild(secIcon("search"));
    const searchInput = document.createElement("input");
    searchInput.type = "text";
    searchInput.placeholder = "Search by message, file, or CVE\u2026";
    searchInput.spellcheck = false;
    searchInput.autocomplete = "off";
    searchInput.value = fs.filters.q;
    searchInput.title = "Search title / rule / rationale / file";
    searchInput.onchange = () => {
      fs.filters.q = searchInput.value;
      fs.page = 1;
      secFindRefresh(fs);
    };
    search.appendChild(searchInput);
    row1.appendChild(search);
    row1.appendChild(secFindMultiPicker(
      "Severity",
      [...SEV_ORDER].reverse().map((s) => ({ v: s, label: _secCap(s) })),
      fs.filters.severity,
      (v) => {
        secFindToggleIn(fs.filters.severity, v);
        fs.page = 1;
        secFindRefresh(fs);
      }
    ));
    row1.appendChild(secFindMultiPicker(
      "Status",
      SEC_STATES.map((s) => ({ v: s, label: SEC_STATE_LABEL[s] || s })),
      fs.filters.state,
      (v) => {
        secFindToggleIn(fs.filters.state, v);
        fs.page = 1;
        secFindRefresh(fs);
      }
    ));
    row1.appendChild(secFindSinglePicker(
      "Analysis run",
      (data.analyses || []).map((a) => ({
        v: String(a.id),
        label: "#" + a.id + " (" + _secCap(a.profile) + ") \u2014 " + a.branch
      })),
      fs.filters.analysis,
      (v) => {
        fs.filters.analysis = v || "";
        fs.page = 1;
        secFindRefresh(fs);
      }
    ));
    row1.appendChild(secFindSinglePicker(
      "Branch",
      (data.branches || []).map((b) => ({ v: b, label: b })),
      fs.filters.branch,
      (v) => {
        fs.filters.branch = v || "";
        fs.page = 1;
        secFindRefresh(fs);
      }
    ));
    row1.appendChild(secFindTextPicker(
      "File path",
      fs.filters.path,
      (v) => {
        fs.filters.path = v;
        fs.page = 1;
        secFindRefresh(fs);
      }
    ));
    wrap.appendChild(row1);
    const row2 = secEl("div", "secfind-filters-row row2");
    row2.appendChild(secFindMultiPicker(
      "Category",
      FIND_CATEGORIES.map((c) => ({ v: c, label: _secCap(c) })),
      fs.filters.category,
      (v) => {
        secFindToggleIn(fs.filters.category, v);
        fs.page = 1;
        secFindRefresh(fs);
      }
    ));
    const toggleField = secEl("label", "secfind-toggle-field");
    toggleField.title = "Fixed, accepted and false-positive rows are excluded unless this is on.";
    const sw = secEl("span", "switch");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = fs.filters.show_resolved;
    cb.onchange = () => {
      fs.filters.show_resolved = cb.checked;
      fs.page = 1;
      secFindRefresh(fs);
    };
    sw.appendChild(cb);
    sw.appendChild(secEl("span", "track"));
    sw.appendChild(secEl("span", "knob"));
    toggleField.appendChild(sw);
    toggleField.appendChild(secEl("span", null, "Show resolved findings"));
    row2.appendChild(toggleField);
    const right = secEl("div", "secfind-filters-right");
    right.appendChild(secFindClearButton(fs));
    const filtBadge = secEl("button", "btn ghost");
    filtBadge.type = "button";
    filtBadge.disabled = true;
    filtBadge.appendChild(secIcon("filter"));
    filtBadge.appendChild(document.createTextNode("Filters"));
    filtBadge.appendChild(secEl("span", "secfind-filters-badge", String(secFindActiveFilterCount(fs))));
    right.appendChild(filtBadge);
    row2.appendChild(right);
    wrap.appendChild(row2);
    return wrap;
  }
  function secFindRow(fs, f) {
    const tr = document.createElement("tr");
    tr.className = "sev-" + secSevKey(f) + " state-" + secStateKey(f);
    const tdSev = document.createElement("td");
    tdSev.appendChild(secEl("span", "sevpill " + secSevKey(f), f.severity || ""));
    tr.appendChild(tdSev);
    const tdTitle = document.createElement("td");
    tdTitle.appendChild(secEl("div", "sectitle", f.title || ""));
    if ((f.rationale || "").trim()) {
      tdTitle.appendChild(secEl("div", "secmeta clamp1", f.rationale));
    }
    tr.appendChild(tdTitle);
    const tdLoc = document.createElement("td");
    const occ = f.occurrences || [];
    if (occ.length) {
      const first = occ[0];
      const where = first.line ? first.file + ":" + first.line : first.file;
      const more = occ.length > 1 ? " (+" + (occ.length - 1) + " more)" : "";
      const locEl = secEl("div", "secfind-loc", where + more);
      if (occ.length > 1) {
        locEl.title = occ.slice(1).map((o) => o.line ? o.file + ":" + o.line : o.file).join(", ");
      }
      tdLoc.appendChild(locEl);
    }
    tr.appendChild(tdLoc);
    const tdCat = document.createElement("td");
    const meta = secCategoryMeta(f.category);
    const catWrap = secEl("div", "secfind-cat");
    catWrap.appendChild(secIcon(meta.icon));
    catWrap.appendChild(secEl("span", null, meta.label));
    if (f.rule) catWrap.title = f.rule;
    tdCat.appendChild(catWrap);
    tr.appendChild(tdCat);
    const tdRun = document.createElement("td");
    const runWrap = secEl("div", "secfind-run");
    const runInfo = ((fs.data || {}).analyses || []).find((a) => a.id === f.analysis_id);
    if (f.analysis_id != null) {
      const runBtn = document.createElement("button");
      runBtn.type = "button";
      runBtn.title = "Show this analysis";
      const profileWord = runInfo && runInfo.profile ? " (" + _secCap(runInfo.profile) + ")" : "";
      runBtn.appendChild(document.createTextNode("#" + f.analysis_id + profileWord));
      runBtn.onclick = (e) => {
        e.stopPropagation();
        secSwitchProjectTab("runs");
        secShowAnalysis(f.analysis_id, true);
      };
      runWrap.appendChild(runBtn);
    }
    if (runInfo && runInfo.started) {
      runWrap.appendChild(secEl("div", "secmeta", fmtWhen(runInfo.started)));
    }
    tdRun.appendChild(runWrap);
    tr.appendChild(tdRun);
    const tdBranch = document.createElement("td");
    tdBranch.textContent = f.branch || "";
    tr.appendChild(tdBranch);
    const tdState = document.createElement("td");
    const stBadge = secEl("span", "secstate " + secStateKey(f), SEC_STATE_LABEL[f.state] || f.state);
    stBadge.title = SEC_STATE_HELP[f.state] || "";
    tdState.appendChild(stBadge);
    tr.appendChild(tdState);
    const tdFirst = document.createElement("td");
    tdFirst.textContent = f.first_seen ? fmtWhen(f.first_seen) : "\u2014";
    tr.appendChild(tdFirst);
    tr.appendChild(secFindActionsCell(fs, f));
    return tr;
  }
  function secFindDecisionControls(fs, f, onPicked) {
    const pop = secEl("div", "menu-pop");
    [["accepted", "Accept risk"], ["false_positive", "False positive"]].forEach(([state, label]) => {
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("role", "menuitem");
      b.appendChild(document.createTextNode(label));
      b.onclick = (e) => {
        e.stopPropagation();
        if (onPicked) onPicked();
        secFindDecide(fs, f, state, label);
      };
      pop.appendChild(b);
    });
    return pop;
  }
  async function secFindDecide(fs, f, state, label) {
    const reason = await secAskReason(label, f.title);
    if (reason === null) return;
    const ok = await api(
      "security_decide",
      { project: fs.project, fingerprint: f.fingerprint, state, reason }
    );
    if (!ok) return;
    toast(label + " recorded", false, "check");
    secInvalidateProject();
    await secFindRefresh(fs);
  }
  function secFindActionsCell(fs, f) {
    const td = document.createElement("td");
    td.className = "rowacts";
    const view = document.createElement("button");
    view.type = "button";
    view.className = "iconbtn";
    view.title = f.analysis_id != null ? "View this analysis" : "No analysis to view";
    view.disabled = f.analysis_id == null;
    view.appendChild(secIcon("eye"));
    view.onclick = (e) => {
      e.stopPropagation();
      if (f.analysis_id == null) return;
      secSwitchProjectTab("runs");
      secShowAnalysis(f.analysis_id, true);
    };
    td.appendChild(view);
    if (f.state !== "fixed") {
      const kebab = document.createElement("details");
      kebab.className = "secidx-kebab";
      const summary = document.createElement("summary");
      summary.className = "iconbtn";
      summary.title = "More actions";
      summary.appendChild(secIcon("dots"));
      summary.onclick = (e) => {
        e.stopPropagation();
        closeMenus();
      };
      kebab.appendChild(summary);
      const pop = secFindDecisionControls(fs, f, () => {
        kebab.open = false;
      });
      kebab.appendChild(pop);
      kebab.ontoggle = () => {
        pop.hidden = !kebab.open;
        if (!kebab.open) return;
        const r = summary.getBoundingClientRect();
        pop.style.position = "fixed";
        pop.style.top = r.bottom + 6 + "px";
        pop.style.left = "auto";
        pop.style.right = window.innerWidth - r.right + "px";
        pop.style.bottom = "auto";
      };
      td.appendChild(kebab);
    }
    return td;
  }
  function secFindTableSection(fs, data) {
    const rows = data.rows || [];
    if (!rows.length) {
      if (data.analysed === false) {
        return secEl(
          "div",
          "tblempty",
          data.attempted ? SEC_NEVER.attempted : SEC_NEVER.next
        );
      }
      return secEl("div", "tblempty", "No findings match these filters.");
    }
    const minSeverity = secMinSeverity(fs.project);
    const visible = secVisible(rows, minSeverity);
    if (!visible.length) {
      return secEl(
        "div",
        "tblempty",
        "Every finding on this page is below the " + minSeverity + " severity floor \u2014 recorded, not shown."
      );
    }
    const wrap = secEl("div", "table-card");
    const scroll = secEl("div", "table-scroll");
    const table = document.createElement("table");
    table.className = "secfind-table";
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    const INSERT_AFTER = { title: "Location", category: "Analysis run" };
    function sortableHeader(key, label) {
      const th = document.createElement("th");
      const btn = secEl("button", "btn ghost");
      btn.type = "button";
      const active = fs.sort === key;
      btn.appendChild(secEl("span", null, label + (active ? fs.dir === "asc" ? " \u25B2" : " \u25BC" : "")));
      btn.onclick = () => {
        if (fs.sort === key) fs.dir = fs.dir === "asc" ? "desc" : "asc";
        else {
          fs.sort = key;
          fs.dir = key === "severity" ? "desc" : "asc";
        }
        fs.page = 1;
        secFindRefresh(fs);
      };
      th.appendChild(btn);
      return th;
    }
    function inertHeader(label) {
      const th = document.createElement("th");
      const btn = secEl("button", "btn ghost");
      btn.type = "button";
      btn.appendChild(secEl("span", null, label));
      th.appendChild(btn);
      return th;
    }
    FIND_SORT_COLUMNS.forEach(([key, label]) => {
      htr.appendChild(sortableHeader(key, label));
      if (INSERT_AFTER[key]) htr.appendChild(inertHeader(INSERT_AFTER[key]));
    });
    htr.appendChild(inertHeader("Actions"));
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    visible.forEach((f) => tbody.appendChild(secFindRow(fs, f)));
    table.appendChild(tbody);
    scroll.appendChild(table);
    wrap.appendChild(scroll);
    return wrap;
  }
  function secFindPerPageField(fs) {
    const field = secEl("div", "secfind-fpick secfind-perpage");
    const current = fs.perPage || FIND_PER_PAGE;
    const { trigger } = secFindTriggerLabel(null, current + " per page");
    const details = document.createElement("details");
    details.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    FIND_PER_PAGE_OPTIONS.forEach((n) => {
      const item = document.createElement("button");
      item.type = "button";
      item.setAttribute("role", "menuitem");
      item.appendChild(document.createTextNode(n + " per page"));
      if (current === n) item.appendChild(secIcon("check2"));
      item.onclick = (e) => {
        e.stopPropagation();
        details.open = false;
        fs.perPage = n;
        fs.page = 1;
        secFindRefresh(fs);
      };
      pop.appendChild(item);
    });
    secFindPositionPop(details, trigger, pop);
    field.appendChild(details);
    return field;
  }
  function secFindPager(fs, data) {
    const total = data.total || 0;
    const perPage = data.per_page || fs.perPage || FIND_PER_PAGE;
    const pages = Math.max(1, Math.ceil(total / perPage));
    const page = data.page || 1;
    const from = total ? (page - 1) * perPage + 1 : 0;
    const to = Math.min(page * perPage, total);
    const foot = tableFooter({
      shown: { from, to },
      total,
      noun: "finding",
      page,
      pages,
      numbered: true,
      collapse: true
    });
    const nav = foot.childNodes[1];
    if (nav) {
      const kids = nav.childNodes || [];
      const prev = kids[0], next = kids[kids.length - 1];
      if (prev) prev.onclick = () => {
        fs.page = Math.max(1, page - 1);
        secFindRefresh(fs);
      };
      if (next && next !== prev) {
        next.onclick = () => {
          fs.page = Math.min(pages, page + 1);
          secFindRefresh(fs);
        };
      }
      kids.forEach((child) => {
        if (child.dataset && child.dataset.page) {
          child.onclick = () => {
            fs.page = Number(child.dataset.page);
            secFindRefresh(fs);
          };
        }
      });
    }
    const wrap = secEl("div", "table-foot");
    wrap.appendChild(foot.childNodes[0]);
    wrap.appendChild(secFindPerPageField(fs));
    if (nav) wrap.appendChild(nav);
    return wrap;
  }

  // ui/security/activity-screen.js
  var ACT_TABS = [
    { key: "", label: "All activity", kinds: [] },
    { key: "analyses", label: "Analyses", kinds: ["analysis_started", "analysis_finished"] },
    { key: "findings", label: "Findings", kinds: ["decision_made"] },
    { key: "settings", label: "Settings", kinds: ["settings_changed", "report_exported"] }
  ];
  var ACT_TAB_BUTTON_ID = {
    "": "secactt-all",
    analyses: "secactt-analyses",
    findings: "secactt-findings",
    settings: "secactt-settings"
  };
  var ACT_PERIODS = [[7, "7 days"], [30, "30 days"], [90, "90 days"], [0, "All time"]];
  var ACT_PER_PAGE = 25;
  var secActOpen = false;
  var secActGen = 0;
  var secActState = null;
  var secActProjPicker = null;
  function _freshState(project) {
    return { project: project || "", tab: "", days: 30, page: 1, data: null, error: "" };
  }
  function secIsActivityOpen() {
    return secActOpen;
  }
  function secActNavState() {
    return secActState ? { project: secActState.project, tab: secActState.tab } : { project: "", tab: "" };
  }
  async function secOpenActivity(project, fromHistory) {
    secBack(true);
    secActOpen = true;
    secActState = _freshState(project);
    $("sec-projects").hidden = true;
    $("sec-activity").hidden = false;
    secActRenderShell();
    if (!fromHistory) pushNav({ view: "security", sec: {
      screen: "activity",
      project: secActState.project,
      tab: secActState.tab
    } });
    await secActLoad();
  }
  function secBackFromActivity(fromHistory) {
    secActOpen = false;
    $("sec-activity").hidden = true;
    $("sec-projects").hidden = false;
    if (!fromHistory) pushNav({ view: "security", sec: { screen: "index" } });
  }
  async function secActReload() {
    if (!secActOpen) return;
    await secActLoad();
  }
  function secActSwitchTab(key, fromHistory) {
    if (!secActState) return;
    secActState.tab = ACT_TABS.some((t) => t.key === key) ? key : "";
    secActState.page = 1;
    secActRenderTabs();
    secActLoad();
    if (!fromHistory) pushNav({ view: "security", sec: {
      screen: "activity",
      project: secActState.project,
      tab: secActState.tab
    } });
  }
  function secActProjectChanged(value) {
    if (!secActState) return;
    secActState.project = (value || "").trim();
    secActState.page = 1;
    if (secActProjPicker) secActProjPicker.paint();
    secActLoad();
  }
  function _scopeToProject(project) {
    secActState.project = project;
    secActState.page = 1;
    if (secActProjPicker) secActProjPicker.paint();
    secActLoad();
  }
  function secActSince() {
    if (secActState.days <= 0) return 0;
    return Math.floor(Date.now() / 1e3) - secActState.days * 86400;
  }
  function secActQuery() {
    const p = new URLSearchParams();
    const tab = ACT_TABS.find((t) => t.key === secActState.tab) || ACT_TABS[0];
    tab.kinds.forEach((k) => p.append("kind", k));
    if (secActState.project) p.set("project", secActState.project);
    p.set("since", String(secActSince()));
    p.set("page", String(secActState.page));
    p.set("per_page", String(ACT_PER_PAGE));
    return p.toString();
  }
  async function secActLoad() {
    if (!secActState || !secActOpen) return;
    const gen = ++secActGen;
    if (!secActState.data) {
      const host = $("sec-act-table");
      if (host) {
        host.textContent = "";
        host.appendChild(secEl("div", "tblempty", "Loading\u2026"));
      }
    }
    let data;
    try {
      data = await secFetch("/api/security/activity?" + secActQuery());
    } catch (e) {
      if (gen !== secActGen || !secActOpen) return;
      secActState.error = e.message;
      secActState.data = null;
      secActPaint();
      return;
    }
    if (gen !== secActGen || !secActOpen) return;
    secActState.error = "";
    secActState.data = data;
    secActState.page = data.page || 1;
    secActPaint();
  }
  function secActRenderShell() {
    const titleText = secActState.project ? "Activity \u2014 " + secActState.project : "Activity";
    const head = $("sec-act-head");
    if (head) {
      head.textContent = "";
      head.appendChild(pageHeader({
        icon: "activity",
        title: titleText,
        subtitle: "What happened and when. An analysis links to that analysis; a decision links into the findings browser filtered to the one fingerprint it decided about."
      }));
    }
    if (secActProjPicker) secActProjPicker.paint();
    secActRenderTabs();
    secActRenderPeriod();
  }
  function secActRenderTabs() {
    ACT_TABS.forEach((t) => {
      const btn = $(ACT_TAB_BUTTON_ID[t.key]);
      if (btn) btn.classList.toggle("active", secActState.tab === t.key);
    });
  }
  function secActPeriodLabel(days) {
    return days > 0 ? "Last " + days + " days" : "All time";
  }
  function secActPeriodPicker() {
    const { trigger } = secFindTriggerLabel(null, secActPeriodLabel(secActState.days));
    trigger.title = "Change the period this screen's table and sidebar cover.";
    const wrap = document.createElement("details");
    wrap.className = "secidx-periodpick";
    wrap.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    ACT_PERIODS.forEach(([days]) => {
      const item = document.createElement("button");
      item.type = "button";
      item.setAttribute("role", "menuitem");
      item.appendChild(document.createTextNode(secActPeriodLabel(days)));
      if (days === secActState.days) item.appendChild(secIcon("check2"));
      item.onclick = (e) => {
        e.stopPropagation();
        secActState.days = days;
        secActState.page = 1;
        secActRenderPeriod();
        secActLoad();
      };
      pop.appendChild(item);
    });
    secFindPositionPop(wrap, trigger, pop);
    return wrap;
  }
  function secActRenderPeriod() {
    const host = $("sec-act-period");
    if (!host) return;
    host.textContent = "";
    host.appendChild(secActPeriodPicker());
  }
  function secActInitProjectPicker() {
    secActProjPicker = makePicker("sec-act-projpick", {
      icon: secIconHTML("folder"),
      label: "Project",
      valueLabel: () => secActState.project || "All",
      rows: () => {
        const data = secActState.data;
        const list = data && data.projects || [];
        const rows = [{
          v: "",
          label: "All",
          n: null,
          sel: !secActState.project,
          icon: secIconHTML("layers")
        }];
        const seen = /* @__PURE__ */ new Set();
        list.forEach((p) => {
          seen.add(p.project);
          rows.push({
            v: p.project,
            label: p.project,
            n: p.count,
            sel: secActState.project === p.project,
            icon: secIconHTML("folder")
          });
        });
        if (secActState.project && !seen.has(secActState.project)) {
          rows.push({
            v: secActState.project,
            label: secActState.project,
            n: 0,
            sel: true,
            icon: secIconHTML("folder")
          });
        }
        return rows;
      },
      onPick: (v) => secActProjectChanged(v)
    });
  }
  function secActPaint() {
    if (!secActOpen) return;
    const host = $("sec-act-table"), side = $("sec-act-side");
    if (host) host.textContent = "";
    if (side) side.textContent = "";
    if (!host) return;
    if (secActState.error) {
      const box = secEl("div", "tblempty");
      box.appendChild(secIcon("alert"));
      box.appendChild(document.createTextNode("Could not read activity \u2014 " + secActState.error));
      host.appendChild(box);
      return;
    }
    const data = secActState.data;
    if (!data) return;
    host.appendChild(secActTable(data));
    if (side) side.appendChild(secActSidebar(data));
  }
  function secActPeriodPhrase() {
    return secActState.days <= 0 ? "at any time" : "in the last " + secActState.days + " days";
  }
  function secActEmptyMessage() {
    const scope = secActState.project ? "for " + secActState.project + " " : "";
    return "No activity recorded " + scope + secActPeriodPhrase() + ".";
  }
  var SEC_ACT_TABLE_COLS = [
    ["time", "Time"],
    ["event", "Event"],
    ["detail", "Detail"],
    ["project", "Project"],
    ["related", "Related"]
  ];
  function secActTable(data) {
    const events = data.events || [];
    if (!events.length) return secEl("div", "tblempty", secActEmptyMessage());
    const wrap = secEl("div", "table-card");
    const scroll = secEl("div", "table-scroll");
    const table = document.createElement("table");
    table.className = "secact-table";
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    SEC_ACT_TABLE_COLS.forEach(([, label]) => {
      const th = document.createElement("th");
      th.textContent = label;
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    events.forEach((e) => tbody.appendChild(secActRow(e)));
    table.appendChild(tbody);
    scroll.appendChild(table);
    wrap.appendChild(scroll);
    wrap.appendChild(secActPager(data));
    return wrap;
  }
  function secActWhen(ts) {
    if (!ts) return "";
    return new Date(ts * 1e3).toLocaleString(
      void 0,
      { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }
    );
  }
  function secActTimeCell(at) {
    const td = document.createElement("td");
    td.appendChild(document.createTextNode(fmtAgo(at, true)));
    td.appendChild(secEl("div", "secidx-sub", secActWhen(at)));
    return td;
  }
  function secActRow(e) {
    const tr = document.createElement("tr");
    const cell = (text) => {
      const td = document.createElement("td");
      td.textContent = text;
      return td;
    };
    tr.appendChild(secActTimeCell(e.at));
    tr.appendChild(cell(EVENT_KIND_LABEL[e.kind] || e.kind));
    tr.appendChild(cell(e.detail || ""));
    tr.appendChild(cell(e.project || ""));
    tr.appendChild(secActRelatedCell(e));
    return tr;
  }
  var ACT_ANALYSIS_KINDS = ["analysis_started", "analysis_finished", "report_exported"];
  function secActRelatedCell(e) {
    const td = document.createElement("td");
    const related = (e.related || "").trim();
    if (!related) {
      td.textContent = "\u2014";
      return td;
    }
    if (e.kind === "decision_made") {
      const b = secEl("button", "btn ghost", "Finding " + related + "\u2026");
      b.type = "button";
      b.title = "Open the findings browser filtered to this fingerprint";
      b.onclick = () => secActOpenFinding(e.project, related);
      td.appendChild(b);
      return td;
    }
    if (ACT_ANALYSIS_KINDS.includes(e.kind)) {
      const b = secEl("button", "btn ghost", "Analysis #" + related);
      b.type = "button";
      b.title = "Open this analysis";
      b.onclick = () => secActOpenAnalysis(e.project, related);
      td.appendChild(b);
      return td;
    }
    td.textContent = related;
    return td;
  }
  async function secActOpenAnalysis(project, relatedId) {
    const id = Number(relatedId);
    if (!project || !Number.isFinite(id)) return;
    secBackFromActivity(true);
    await secOpenProject(project, true);
    secSwitchProjectTab("runs");
    await secShowAnalysis(id, true);
  }
  function secActOpenFinding(project, fingerprintPrefix) {
    const titleEl = $("sec-act-finding-title");
    if (titleEl) titleEl.textContent = "Findings in " + project;
    const halo = $("sec-act-finding-halo");
    if (halo) {
      halo.textContent = "";
      halo.appendChild(secIcon("search"));
    }
    const dlg = $("sec-act-finding");
    if (dlg && dlg.showModal) dlg.showModal();
    renderFindings($("sec-act-finding-body"), project, { fingerprint: fingerprintPrefix });
  }
  function wireActivityFindingDialog() {
    const dlg = $("sec-act-finding");
    const close = $("sec-act-finding-close");
    if (close && dlg) close.addEventListener("click", () => dlg.close());
  }
  function secActPager(data) {
    const foot = secEl("div", "table-foot");
    foot.appendChild(secEl("span", "table-foot-info", "Page " + (data.page || 1)));
    const page = data.page || 1;
    const perPage = data.per_page || ACT_PER_PAGE;
    const hasMore = (data.events || []).length >= perPage;
    const nav = secEl("div", "table-foot-pager");
    const prev = secEl("button", "btn ghost");
    prev.type = "button";
    prev.appendChild(secIcon("cleft"));
    prev.appendChild(document.createTextNode("Prev"));
    prev.disabled = page <= 1;
    prev.onclick = () => {
      secActState.page = Math.max(1, page - 1);
      secActLoad();
    };
    nav.appendChild(prev);
    const next = secEl("button", "btn ghost");
    next.type = "button";
    next.appendChild(document.createTextNode("Next"));
    next.appendChild(secIcon("cright"));
    next.disabled = !hasMore;
    next.onclick = () => {
      secActState.page = page + 1;
      secActLoad();
    };
    nav.appendChild(next);
    foot.appendChild(nav);
    return foot;
  }
  function secActSidebar(data) {
    const wrap = document.createElement("div");
    wrap.appendChild(secActSummaryCard(data.summary || {}));
    wrap.appendChild(secActProjectsCard(data.projects || []));
    return wrap;
  }
  function secActSummaryCard(summary) {
    const box = secEl("div", "card secact-sidecard");
    const head = secEl("div", "secpj-cardhead");
    head.appendChild(secEl("h3", null, "Activity summary"));
    box.appendChild(head);
    box.appendChild(secEl(
      "div",
      "secpj-caption",
      "Every kind, regardless of which tab is selected above."
    ));
    const chips = secEl("div", "secchips");
    EVENT_KINDS.forEach((kind) => {
      const n = summary[kind] || 0;
      const chip = secEl("span", "secpj-statchip" + (n ? "" : " zero"));
      chip.appendChild(secEl("span", null, EVENT_KIND_LABEL[kind] || kind));
      chip.appendChild(secEl("span", "n", String(n)));
      chips.appendChild(chip);
    });
    box.appendChild(chips);
    return box;
  }
  function secActProjectsCard(projects) {
    const box = secEl("div", "card secact-sidecard");
    const head = secEl("div", "secpj-cardhead");
    head.appendChild(secEl("h3", null, "Most active projects"));
    box.appendChild(head);
    if (secActState.project) {
      box.appendChild(secEl("div", "tblempty", "Scoped to one project."));
      return box;
    }
    if (!projects.length) {
      box.appendChild(secEl("div", "tblempty", secActEmptyMessage()));
      return box;
    }
    const list = secEl("div", "seclist");
    projects.forEach((p) => {
      const row = secEl("button", "secrow secidx-recentrow");
      row.type = "button";
      row.title = "Filter this screen to " + p.project;
      row.onclick = () => _scopeToProject(p.project);
      row.appendChild(secIcon("activity"));
      const grow = secEl("div", "grow");
      grow.appendChild(secEl("div", "secname", p.project));
      grow.appendChild(secEl("div", "secmeta", p.count + " event" + (p.count === 1 ? "" : "s")));
      row.appendChild(grow);
      list.appendChild(row);
    });
    box.appendChild(list);
    return box;
  }

  // ui/security/project-screen.js
  var RUN_STATES = ["running", "done", "capped", "failed"];
  var secProjectCache = null;
  var secProjectGen = 0;
  var secProjectTab = "overview";
  var secRunsFilter = "";
  function secInvalidateProject() {
    secProjectCache = null;
  }
  async function secOpenProject(name, fromHistory) {
    secProjectTab = "overview";
    secRunsFilter = "";
    secOpen(name);
    secRenderProjectTitle();
    if (!fromHistory) pushNav({ view: "security", sec: { screen: "project", project: name, tab: secProjectTab } });
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
  function secSwitchProjectTab(tab, fromHistory) {
    secProjectTab = ["overview", "runs", "branches", "findings", "reports"].includes(tab) ? tab : "overview";
    secRenderTabs();
    if (secProjectCache) secRenderProjectSidebar(secProjectCache);
    if (secProjectTab === "findings") renderFindings($("sec-pj-findings"), secState.project);
    if (!fromHistory) pushNav({ view: "security", sec: { screen: "project", project: secState.project, tab: secProjectTab } });
  }
  function secCurrentProjectTab() {
    return secProjectTab;
  }
  function secRenderProject() {
    if (!secProjectCache) return;
    secRenderProjectHeader(secProjectCache);
    secRenderTabs();
    secRenderProjectOverview(secProjectCache);
    secRenderProjectRuns(secProjectCache);
    secRenderProjectBranches(secProjectCache);
    secRenderProjectReports(secProjectCache);
    secRenderProjectSidebar(secProjectCache);
    if (secProjectTab === "findings") renderFindings($("sec-pj-findings"), secState.project);
  }
  function secRenderTabs() {
    const ov = $("secpjt-overview"), rn = $("secpjt-runs"), br = $("secpjt-branches"), fd = $("secpjt-findings"), rp = $("secpjt-reports");
    if (ov) ov.classList.toggle("active", secProjectTab === "overview");
    if (rn) rn.classList.toggle("active", secProjectTab === "runs");
    if (br) br.classList.toggle("active", secProjectTab === "branches");
    if (fd) fd.classList.toggle("active", secProjectTab === "findings");
    if (rp) rp.classList.toggle("active", secProjectTab === "reports");
    const ovPane = $("sec-pj-overview"), rnPane = $("sec-pj-runs"), brPane = $("sec-pj-branches"), fdPane = $("sec-pj-findings"), rpPane = $("sec-pj-reports");
    if (ovPane) ovPane.hidden = secProjectTab !== "overview";
    if (rnPane) rnPane.hidden = secProjectTab !== "runs";
    if (brPane) brPane.hidden = secProjectTab !== "branches";
    if (fdPane) fdPane.hidden = secProjectTab !== "findings";
    if (rpPane) rpPane.hidden = secProjectTab !== "reports";
    const side = $("sec-pj-side");
    if (side) side.hidden = secProjectTab === "findings";
  }
  function secRenderProjectTitle() {
    const idHost = $("sec-pj-titleid");
    if (idHost) {
      idHost.textContent = "";
      const p = projById(secState.project) || {};
      idHost.appendChild(secIcon("folder"));
      idHost.appendChild(secEl("span", "secpjtitle-name", p.name || secState.project));
      const badge = secEl("span", "pill on", "Security enabled");
      badge.title = "Security analysis is enabled for this project";
      idHost.appendChild(badge);
    }
    const desc = $("sec-pj-desc");
    if (desc) desc.textContent = (projById(secState.project) || {}).description || "";
  }
  function secRenderProjectHeader(payload) {
    const host = $("sec-pj-head");
    if (!host) return;
    host.textContent = "";
    const h = payload.header || {};
    const meta = secEl("div", "secpjmeta grow");
    const profile = secEl("span", null, "Profile: ");
    profile.appendChild(secEl("span", "pill profile", h.profile || "standard"));
    meta.appendChild(profile);
    meta.appendChild(secHeaderBit("Branch", h.branch || "\u2014"));
    if (h.branch_fell_back) {
      const warn = secEl("span", "secpj-fellback");
      warn.appendChild(secIcon("alert"));
      warn.appendChild(secEl(
        "span",
        null,
        "fell back \u2014 the declared base was never analysed"
      ));
      meta.appendChild(warn);
    }
    meta.appendChild(secHeaderBit(
      "Lines of code",
      h.lines_of_code ? h.lines_of_code.toLocaleString() : "\u2014",
      h.lines_of_code ? "" : "Not counted \u2014 this analysis predates the line count, or nothing has been analysed yet. It is not a claim that the repository is empty."
    ));
    meta.appendChild(secHeaderBit(
      "Last analysis",
      h.last_analysis ? fmtAgo(h.last_analysis) : SEC_NEVER.short,
      h.last_analysis ? "" : SEC_NEVER.next
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
  function secHeaderBit(label, value, title) {
    const span = secEl("span", null, label + ": ");
    span.appendChild(secEl("b", null, value));
    if ((title || "").trim()) span.title = title;
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
  function secSidebarCaption(branchCount, attempted) {
    if (!branchCount) {
      return secEl(
        "div",
        "secpj-caption",
        attempted ? SEC_NEVER.attempted : SEC_NEVER.next
      );
    }
    const scope = branchCount === 1 ? "this project's only analysed branch" : "all " + branchCount + " analysed branches";
    const cap = secEl(
      "div",
      "secpj-caption",
      "Posture and categories below span " + scope + "."
    );
    cap.title = SEC_FLOOR_SCOPE_NOTE;
    return cap;
  }
  function secRenderProjectOverview(payload) {
    const host = $("sec-pj-overview");
    if (!host) return;
    host.textContent = "";
    const ov = (payload.tabs || {}).overview || {};
    if (!ov.state) {
      host.appendChild(secEl(
        "div",
        "empty",
        ov.attempted ? SEC_NEVER.attempted : SEC_NEVER.next
      ));
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
    const card = secEl("div", "card secpj-plaincard secpj-runslistcard");
    const cardHead = secEl("div", "secpj-cardhead");
    cardHead.appendChild(secEl("h3", null, "Analysis runs"));
    card.appendChild(cardHead);
    const runs = (payload.tabs || {}).runs || [];
    card.appendChild(secRunsFilters(runs));
    card.appendChild(secRunsTable(runs));
    host.appendChild(card);
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
  var SEC_RUNS_COLS = [
    ["run", "Run"],
    ["state", "Status"],
    ["findings", "Findings recorded"],
    ["date", "Date"]
  ];
  var secRunsSortDir = "desc";
  var SEV_LETTER = [["critical", "C"], ["high", "H"], ["medium", "M"], ["low", "L"]];
  function secRunSeverityLine(bySeverity) {
    if (!bySeverity) return null;
    const line = secEl("div", "secrun-sevline");
    SEV_LETTER.forEach(([sev, letter]) => {
      line.appendChild(secEl(
        "span",
        "secrun-sevbit sev-" + sev,
        (bySeverity[sev] || 0) + letter
      ));
    });
    return line;
  }
  function secRunsTable(runs) {
    const filtered = secRunsFilter ? runs.filter((r) => r.state === secRunsFilter) : runs;
    if (!filtered.length) {
      return secEl("div", "tblempty", runs.length ? "Nothing in that state." : "No analyses of this project yet.");
    }
    const sorted = filtered.slice().sort((a, b) => secRunsSortDir === "asc" ? (a.started || 0) - (b.started || 0) : (b.started || 0) - (a.started || 0));
    const wrap = secEl("div", "table-card");
    const scroll = secEl("div", "table-scroll");
    const table = document.createElement("table");
    table.className = "secpj-runstable";
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    SEC_RUNS_COLS.forEach(([key, label]) => {
      const th = document.createElement("th");
      th.appendChild(document.createTextNode(label));
      if (key === "findings") {
        th.title = "How many findings this run recorded \u2014 the checklist chips below can total more, since they also carry forward findings that disappeared since the previous analysis of this branch, marked fixed or pending.";
      }
      if (key === "date") {
        th.className = "sortable sorted";
        th.title = "Sort by date";
        th.setAttribute("aria-sort", secRunsSortDir === "asc" ? "ascending" : "descending");
        th.appendChild(secIcon(secRunsSortDir === "asc" ? "sortasc" : "sortdesc"));
        th.onclick = () => {
          secRunsSortDir = secRunsSortDir === "asc" ? "desc" : "asc";
          secRenderProjectRuns(secProjectCache);
        };
      }
      htr.appendChild(th);
    });
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    sorted.forEach((r) => tbody.appendChild(secRunRow(r)));
    table.appendChild(tbody);
    scroll.appendChild(table);
    wrap.appendChild(scroll);
    wrap.appendChild(tableFooter({
      shown: { from: 1, to: sorted.length },
      total: sorted.length,
      noun: "run",
      page: 1,
      pages: 1,
      numbered: true
    }));
    return wrap;
  }
  function secRunRow(r) {
    const tr = document.createElement("tr");
    if (secState.analysis && secState.analysis.id === r.id) tr.className = "secrun-selected";
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
    btn.onclick = () => secShowAnalysis(r.id, true);
    tdId.appendChild(btn);
    tr.appendChild(tdId);
    const tdState = document.createElement("td");
    tdState.appendChild(secIndexRunStatusPill(r.state));
    tr.appendChild(tdState);
    const tdFindings = document.createElement("td");
    tdFindings.appendChild(secEl(
      "div",
      "secrun-findtotal",
      r.findings == null ? "\u2014" : String(r.findings)
    ));
    const sevLine = secRunSeverityLine(r.findings_by_severity);
    if (sevLine) tdFindings.appendChild(sevLine);
    tr.appendChild(tdFindings);
    tr.appendChild(cell(fmtWhen(r.started)));
    return tr;
  }
  function secProjectRunRow(id) {
    const runs = ((secProjectCache || {}).tabs || {}).runs || [];
    return runs.find((r) => r.id === id) || null;
  }
  function secRenderRunHead() {
    const host = $("sec-run-head");
    if (!host) return;
    host.textContent = "";
    const a = secState.analysis;
    if (!a) return;
    const head = secEl("div", "secrun-head");
    const title = secEl("div", "secrun-headtitle");
    title.appendChild(secEl("h3", "secrun-headid", "Run #" + a.id));
    title.appendChild(secIndexRunStatusPill(a.state));
    head.appendChild(title);
    const actions = secEl("div", "secrun-headactions");
    const dl = document.createElement("button");
    dl.type = "button";
    dl.className = "iconbtn";
    dl.title = "Download this run's report (Markdown)";
    dl.appendChild(secIcon("download"));
    dl.onclick = () => secDownloadReport(a.id, "md", dl);
    actions.appendChild(dl);
    const run = secRunFor(a);
    const eye = document.createElement("button");
    eye.type = "button";
    eye.className = "iconbtn";
    eye.title = run ? "Open this run's live session" : "No live or journalled session found for this run";
    eye.disabled = !run;
    eye.appendChild(secIcon("eye"));
    if (run) eye.onclick = () => openLog(run.id, run.start);
    actions.appendChild(eye);
    const kebab = document.createElement("details");
    kebab.className = "secidx-kebab";
    const summary = document.createElement("summary");
    summary.className = "iconbtn";
    summary.title = "More downloads";
    summary.appendChild(secIcon("dots"));
    summary.onclick = (e) => {
      e.stopPropagation();
      closeMenus();
    };
    kebab.appendChild(summary);
    const pop = secEl("div", "menu-pop");
    pop.setAttribute("role", "menu");
    [["json", "JSON"], ["html", "HTML"], ["sbom", "SBOM"]].forEach(([fmt, label]) => {
      const item = document.createElement("button");
      item.setAttribute("role", "menuitem");
      item.appendChild(secIcon("file"));
      item.appendChild(document.createTextNode(label));
      item.onclick = (e) => {
        e.stopPropagation();
        kebab.open = false;
        secDownloadReport(a.id, fmt, item);
      };
      pop.appendChild(item);
    });
    kebab.appendChild(pop);
    kebab.ontoggle = () => {
      pop.hidden = !kebab.open;
      if (!kebab.open) return;
      const r = summary.getBoundingClientRect();
      pop.style.position = "fixed";
      pop.style.top = r.bottom + 6 + "px";
      pop.style.right = window.innerWidth - r.right + "px";
      pop.style.left = "auto";
      pop.style.bottom = "auto";
    };
    actions.appendChild(kebab);
    head.appendChild(actions);
    host.appendChild(head);
  }
  function secRenderRunRecorded() {
    const host = $("sec-run-recorded");
    if (!host) return;
    host.textContent = "";
    const a = secState.analysis;
    if (!a) return;
    const row = secProjectRunRow(a.id);
    const total = row && row.findings != null ? row.findings : null;
    const bySeverity = row && row.findings_by_severity || null;
    const strip = secEl("div", "secrun-recorded");
    strip.appendChild(secEl("span", "secrun-recorded-label", "Findings recorded"));
    strip.appendChild(secEl(
      "span",
      "secrun-recorded-total",
      total == null ? "\u2014" : total + " total"
    ));
    ["critical", "high", "medium", "low", "info"].forEach((sev) => {
      const n = bySeverity ? bySeverity[sev] || 0 : 0;
      const pill = secEl("span", "secrun-recpill sev-" + sev + (n ? "" : " zero"));
      pill.appendChild(secEl("span", "secrun-recdot"));
      pill.appendChild(document.createTextNode(n + " " + (sev[0].toUpperCase() + sev.slice(1))));
      strip.appendChild(pill);
    });
    host.appendChild(strip);
  }
  function secProjectRunPosture() {
    return secPosture(secState.findings, secMinSeverity(secState.project));
  }
  function secProjectRunCategories() {
    const open = secVisible(secState.findings, secMinSeverity(secState.project)).filter((f) => !["fixed", "accepted", "false_positive"].includes(f.state));
    const byRule = {};
    open.forEach((f) => {
      const key = f.rule || "";
      if (!byRule[key]) byRule[key] = { rule: f.rule, category: f.category, count: 0 };
      byRule[key].count++;
    });
    return Object.values(byRule).sort((a, b) => b.count - a.count || String(a.rule).localeCompare(String(b.rule))).slice(0, 5);
  }
  function secProjectRunSidebar() {
    const frag = document.createDocumentFragment();
    const donut = secProjectRunPosture();
    const donutCard = secEl("div", "card secpj-plaincard");
    const donutHead = secEl("div", "secpj-cardhead");
    donutHead.appendChild(secEl("h3", null, "Findings by severity"));
    donutCard.appendChild(donutHead);
    const row = secEl("div", "secrun-donutrow");
    row.appendChild(secIndexDonutSvg(donut));
    row.appendChild(secIndexDonutLegend(donut, { showPercent: true, showZero: true }));
    donutCard.appendChild(row);
    frag.appendChild(donutCard);
    const catCard = secEl("div", "card secpj-plaincard");
    const catHead = secEl("div", "secpj-cardhead");
    catHead.appendChild(secEl("h3", null, "Top issue categories"));
    catCard.appendChild(catHead);
    catCard.appendChild(secIndexCategories(secProjectRunCategories()));
    const viewAll = secEl("button", "btn ghost secpj-viewallcats", "View all categories");
    viewAll.type = "button";
    viewAll.title = "Open this project's Findings tab";
    viewAll.onclick = () => secSwitchProjectTab("findings");
    catCard.appendChild(viewAll);
    frag.appendChild(catCard);
    return frag;
  }
  function secRefreshRunPanels() {
    if (!secProjectCache) return;
    secRenderProjectRuns(secProjectCache);
    secRenderRunHead();
    secRenderRunRecorded();
    secRenderProjectSidebar(secProjectCache);
  }
  function secRenderProjectSidebar(payload) {
    const host = $("sec-pj-side");
    if (!host) return;
    host.textContent = "";
    const sb = payload.sidebar || {};
    const attempted = !!((payload.tabs || {}).overview || {}).attempted;
    host.appendChild(secSidebarCaption(sb.branch_count || 0, attempted));
    if (secProjectTab === "runs") {
      host.appendChild(secProjectRunSidebar());
    } else {
      host.appendChild(secIndexDonut(
        sb.donut || {},
        sb.categories || [],
        secCappedScopeNote(sb.capped_branches || 0, sb.branch_count || 0, "branch")
      ));
    }
    host.appendChild(secProjectActivity(sb.activity || []));
  }
  function secProjectActivity(events) {
    const box = secEl("div", "card secpj-plaincard");
    const head = secEl("div", "secpj-cardhead");
    head.appendChild(secEl("h3", null, "Recent activity"));
    const viewAll = secEl("button", "btn ghost", "View all");
    viewAll.type = "button";
    viewAll.onclick = () => secOpenActivity(secState.project);
    head.appendChild(viewAll);
    box.appendChild(head);
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
      data = await secFetch("/api/security/index?days=" + secFindPeriodDays + "&recent_page=" + secRecentPage);
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
  function secRenderHead() {
    const host = $("sec-head");
    if (!host) return;
    host.textContent = "";
    host.appendChild(pageHeader({
      icon: "shield",
      title: "Security",
      subtitle: "Vulnerability analysis across your projects."
    }));
  }
  function secRenderIndex() {
    secRenderHead();
    const host = $("sec-list");
    if (!host) return;
    if (!secIndexCache) return;
    const data = secIndexCache;
    if (!host.contains(host._secProjects)) {
      host.textContent = "";
      host._secCards = secEl("div");
      host._secProjects = secEl("div", "secidx-section");
      host._secBottomRow = secEl("div", "secpjbody secidx-bottom");
      host._secRecent = secEl("div", "secpjmain");
      host._secDonut = secEl("div", "secidx-findcard");
      host._secBottomRow.appendChild(host._secRecent);
      host._secBottomRow.appendChild(host._secDonut);
      host.appendChild(host._secCards);
      host._secCards.title = SEC_FLOOR_SCOPE_NOTE;
      host.appendChild(host._secProjects);
      host.appendChild(host._secBottomRow);
      secMountProjectsSection(host._secProjects);
    }
    host._secCards.textContent = "";
    host._secCards.appendChild(secIndexCards(data.summary || {}));
    secLatestProjects = data.projects || [];
    secClearStaleFilterValues(secLatestProjects);
    secRepaintProjectsTable();
    const recent = data.recent || { rows: [], total: 0 };
    host._secRecent.textContent = "";
    host._secRecent.appendChild(secIndexRecentCard(recent));
    host._secDonut.textContent = "";
    host._secDonut.appendChild(secIndexFindingsCard(
      data.donut || {},
      data.categories || [],
      // The donut is the fleet's whole posture rolled into one figure, so it
      // cannot carry the per-row `incomplete` badge the table beside it uses --
      // it gets the same caveat the Critical/High cards get, from the same
      // count, or it is the one number on this screen that still presents a
      // partial read as a complete one.
      secCappedNote(data.summary || {}),
      recent.rows
    ));
  }
  function secCappedScopeNote(n, of, noun) {
    if (!n) return "";
    return n + " of " + of + " " + (of === 1 ? noun : noun + (/(ch|sh|s|x|z)$/.test(noun) ? "es" : "s")) + " had a latest analysis that stopped before covering its whole scope \u2014 this total may be an undercount";
  }
  function secCappedNote(summary) {
    return secCappedScopeNote(
      summary.capped_projects || 0,
      summary.projects || 0,
      "project"
    );
  }
  function secIndexCards(summary) {
    const wrap = secEl("div", "kpi-grid");
    const s = summary || {};
    wrap.appendChild(kpiCard({
      icon: "folder",
      value: String(s.projects || 0),
      label: "Projects",
      sub: "with security enabled"
    }));
    wrap.appendChild(kpiCard({
      icon: "trend",
      value: String(s.analyses || 0),
      label: "Total analyses",
      sub: "across all projects",
      title: "All time \u2014 a historical total, not current posture"
    }));
    const capped = s.capped_projects || 0;
    const fellBack = s.fell_back_projects || 0;
    const total = s.projects || 0;
    const caveats = [];
    if (capped) caveats.push(secCappedScopeNote(capped, total, "project"));
    if (fellBack) {
      caveats.push(fellBack + " of " + total + " project" + (total === 1 ? "" : "s") + " is counted from a branch other than its declared base, because that base has never been analysed");
    }
    const cappedNote = caveats.length ? caveats.join(" \xB7 ") : "Open now, in every project's latest analysis";
    wrap.appendChild(kpiCard({
      icon: "shield",
      tone: "sev-crit",
      value: String(s.critical || 0),
      label: "Critical findings",
      sub: "needs immediate attention",
      title: cappedNote
    }));
    wrap.appendChild(kpiCard({
      icon: "alertcircle",
      tone: "sev-high",
      value: String(s.high || 0),
      label: "High severity",
      sub: "requires review",
      title: cappedNote
    }));
    const rate = s.success_rate;
    wrap.appendChild(kpiCard({
      icon: "check",
      tone: "ok",
      value: rate == null ? "\u2014" : Math.round(rate * 100) + "%",
      label: "Success rate",
      sub: rate == null ? "No finished analysis yet" : "analyses completed",
      title: rate == null ? "" : "All time \u2014 a historical total, not current posture: finished analyses that completed clean, not capped or failed"
    }));
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
  var FIND_SEVS = ["critical", "high", "medium"];
  function secIndexFindingsChips(posture, capped) {
    const p = posture || {};
    const wrap = secEl("div", "secidx-findcell");
    const chips = secEl("div", "sevpills secidx-sev3");
    FIND_SEVS.forEach((sev) => chips.appendChild(
      secEl("span", "sevpill " + sev, String(p[sev] || 0))
    ));
    wrap.appendChild(chips);
    wrap.appendChild(secEl("div", "secidx-findtotal", (p.total || 0) + " total"));
    if (capped) {
      const badge = secEl("span", "secidx-capped", "incomplete");
      badge.title = "This analysis is INCOMPLETE: it stopped before covering the whole scope. The counts above are what it had reached, not what is there.";
      wrap.appendChild(badge);
    }
    return wrap;
  }
  function secIndexTrendSpark(trend) {
    const points = (trend || []).map((n2) => Math.max(0, n2 || 0));
    if (!points.length) {
      const dash = secEl("span", "muted", "\u2014");
      dash.title = "No finished analysis of the declared base branch within the last 30 days";
      return dash;
    }
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 100 32");
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("class", "secidx-spark-svg");
    svg.setAttribute("role", "img");
    const max = Math.max(1, ...points);
    const n = points.length;
    const slot = 100 / n;
    const barW = Math.max(0.6, slot * 0.6);
    points.forEach((v, i) => {
      const h = Math.max(1, v / max * 30);
      const bar = document.createElementNS(ns, "rect");
      bar.setAttribute("x", String(i * slot + (slot - barW) / 2));
      bar.setAttribute("y", String(32 - h));
      bar.setAttribute("width", String(barW));
      bar.setAttribute("height", String(h));
      bar.style.fill = "var(--accent)";
      svg.appendChild(bar);
    });
    return svg;
  }
  function secProfileLabel(profile) {
    return profile ? profile[0].toUpperCase() + profile.slice(1) : "";
  }
  function secLastRunDuration(seconds) {
    const s = Math.max(0, Math.floor(seconds || 0));
    if (s < 60) return s + "s";
    const h = Math.floor(s / 3600);
    const m = Math.floor(s % 3600 / 60);
    return (h ? h + "h " : "") + m + "m";
  }
  function secIndexRunWhen(ts) {
    if (!ts) return "";
    return new Date(ts * 1e3).toLocaleString(
      void 0,
      { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }
    );
  }
  function secIndexProjectRow(p) {
    const tr = document.createElement("tr");
    tr.className = "secidx-rowlink";
    tr.onclick = () => secOpenProject(p.name);
    const tdProject = document.createElement("td");
    const nameLine = secEl("div", "secidx-pname");
    nameLine.appendChild(secIcon("folder"));
    nameLine.appendChild(secEl("span", "secidx-pname-text", p.name));
    const badge = secEl("span", "secidx-enabled");
    badge.appendChild(secIcon("shieldcheck"));
    badge.title = "Security analysis is enabled for this project";
    nameLine.appendChild(badge);
    tdProject.appendChild(nameLine);
    if ((p.description || "").trim()) {
      tdProject.appendChild(secEl("div", "secidx-desc", p.description));
    }
    tr.appendChild(tdProject);
    const tdAnalysis = document.createElement("td");
    if (!p.analyses) {
      tdAnalysis.textContent = SEC_NEVER.short;
      tdAnalysis.title = SEC_NEVER.next;
    } else {
      tdAnalysis.appendChild(document.createTextNode(fmtAgo(p.last_started, true)));
      const sub = secEl("div", "secidx-sub");
      sub.appendChild(document.createTextNode(
        [p.profile, p.branch || "\u2014"].filter(Boolean).join(" \xB7 ")
      ));
      if (p.branch_fell_back) {
        sub.appendChild(secEl(
          "span",
          "secidx-fellback",
          " (fell back \u2014 the default branch was never analysed)"
        ));
      }
      tdAnalysis.appendChild(sub);
    }
    tr.appendChild(tdAnalysis);
    const tdProfile = document.createElement("td");
    if (p.profile) {
      tdProfile.appendChild(secEl("span", "pill profile", secProfileLabel(p.profile)));
    } else {
      tdProfile.appendChild(secEl("span", "muted", "\u2014"));
    }
    tr.appendChild(tdProfile);
    const tdRun = document.createElement("td");
    if (p.last_duration) {
      tdRun.appendChild(document.createTextNode(secLastRunDuration(p.last_duration)));
      tdRun.appendChild(secEl("div", "secidx-sub", secIndexRunWhen(p.last_started)));
    } else {
      tdRun.appendChild(secEl("span", "muted", "\u2014"));
    }
    tr.appendChild(tdRun);
    const tdFindings = document.createElement("td");
    tdFindings.appendChild(secIndexFindingsChips(p.posture, p.last_state === "capped"));
    tr.appendChild(tdFindings);
    const tdTrend = document.createElement("td");
    tdTrend.appendChild(secIndexTrendSpark(p.trend));
    tr.appendChild(tdTrend);
    const tdStatus = document.createElement("td");
    const active = p.enabled !== false;
    tdStatus.appendChild(secEl(
      "span",
      "pill " + (active ? "on" : "disabled"),
      active ? "Active" : "Disabled"
    ));
    tr.appendChild(tdStatus);
    const tdActions = document.createElement("td");
    tdActions.className = "rowacts";
    const view = document.createElement("button");
    view.type = "button";
    view.className = "btn primary";
    view.appendChild(document.createTextNode("View"));
    view.onclick = (e) => {
      e.stopPropagation();
      secOpenProject(p.name);
    };
    tdActions.appendChild(view);
    const kebab = document.createElement("details");
    kebab.className = "secidx-kebab";
    const summary = document.createElement("summary");
    summary.className = "iconbtn";
    summary.title = "More actions";
    summary.appendChild(secIcon("dots"));
    summary.onclick = (e) => {
      e.stopPropagation();
      closeMenus();
    };
    kebab.appendChild(summary);
    const pop = secEl("div", "menu-pop");
    pop.setAttribute("role", "menu");
    const actBtn = document.createElement("button");
    actBtn.setAttribute("role", "menuitem");
    actBtn.appendChild(secIcon("activity"));
    actBtn.appendChild(document.createTextNode("View activity"));
    actBtn.onclick = (e) => {
      e.stopPropagation();
      kebab.open = false;
      secOpenActivity(p.name);
    };
    pop.appendChild(actBtn);
    const editBtn = document.createElement("button");
    editBtn.setAttribute("role", "menuitem");
    editBtn.appendChild(secIcon("pencil"));
    editBtn.appendChild(document.createTextNode("Edit project"));
    editBtn.onclick = (e) => {
      e.stopPropagation();
      kebab.open = false;
      openProjectEditor(p.name);
    };
    pop.appendChild(editBtn);
    kebab.appendChild(pop);
    kebab.ontoggle = () => {
      pop.hidden = !kebab.open;
      if (!kebab.open) return;
      const r = summary.getBoundingClientRect();
      pop.style.position = "fixed";
      pop.style.top = r.bottom + 6 + "px";
      pop.style.right = window.innerWidth - r.right + "px";
      pop.style.left = "auto";
      pop.style.bottom = "auto";
    };
    tdActions.appendChild(kebab);
    tr.appendChild(tdActions);
    return tr;
  }
  var SEC_PROJECT_COLS = [
    ["project", "Project"],
    ["analysis", "Last analysis"],
    ["profile", "Profile"],
    ["run", "Last run"],
    ["findings", "Findings"],
    ["trend", "Trend (30d)"],
    ["status", "Status"],
    [null, "Actions"]
  ];
  function secIndexProjectsTable(projects, footer) {
    if (!projects.length) {
      const e = secEl("div", "tblempty");
      e.appendChild(secIcon("inbox"));
      e.appendChild(document.createTextNode(
        "No projects have security analysis enabled yet \u2014 turn it on in a project's editor, on the Security tab."
      ));
      return e;
    }
    const wrap = secEl("div", "table-card");
    const scroll = secEl("div", "table-scroll");
    const table = document.createElement("table");
    table.className = "secidx-fleet";
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    SEC_PROJECT_COLS.forEach(([, label]) => htr.appendChild(secEl("th", null, label)));
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    projects.slice().sort((a, b) => String(a.name).localeCompare(String(b.name))).forEach((p) => tbody.appendChild(secIndexProjectRow(p)));
    table.appendChild(tbody);
    scroll.appendChild(table);
    wrap.appendChild(scroll);
    if (footer) wrap.appendChild(footer);
    return wrap;
  }
  var secProjectFilters = { query: "", status: "", profile: "", branch: "" };
  var secLatestProjects = [];
  var secProjectsTableHost = null;
  var secStatusPicker = null;
  var secProfileFilterPicker = null;
  var secBranchFilterPicker = null;
  function secFilterProjects(projects, filters) {
    const f = filters || {};
    const q = (f.query || "").trim().toLowerCase();
    return (projects || []).filter((p) => {
      if (q) {
        const hay = ((p.name || "") + " " + (p.description || "")).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (f.status) {
        const active = p.enabled !== false;
        if (f.status === "active" && !active) return false;
        if (f.status === "disabled" && active) return false;
      }
      if (f.profile && (p.profile || "") !== f.profile) return false;
      if (f.branch && (p.branch || "") !== f.branch) return false;
      return true;
    });
  }
  function secUniqueValues(projects, key) {
    return [...new Set((projects || []).map((p) => p[key]).filter(Boolean))].sort();
  }
  function secPickerShell(id) {
    const wrap = secEl("div", "picker");
    wrap.id = id;
    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "picker-trigger";
    trigger.id = id + "-trigger";
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    wrap.appendChild(trigger);
    const pop = secEl("div", "picker-pop");
    pop.id = id + "-pop";
    pop.hidden = true;
    const list = secEl("div", "picker-list");
    list.id = id + "-list";
    list.setAttribute("role", "listbox");
    pop.appendChild(list);
    wrap.appendChild(pop);
    return wrap;
  }
  function secProjectsFilterBar() {
    const bar = secEl("div", "toolbar");
    const search = secEl("div", "searchbox");
    search.appendChild(secIcon("search"));
    const input = document.createElement("input");
    input.type = "search";
    input.placeholder = "Search projects\u2026";
    input.setAttribute("aria-label", "Search projects by name or description");
    input.oninput = () => {
      secProjectFilters.query = input.value;
      secRepaintProjectsTable();
    };
    search.appendChild(input);
    bar.appendChild(search);
    bar.appendChild(secPickerShell("secpj-filter-status"));
    bar.appendChild(secPickerShell("secpj-filter-profile"));
    bar.appendChild(secPickerShell("secpj-filter-branch"));
    bar.appendChild(secEl("div", "spacer"));
    const refresh = document.createElement("button");
    refresh.type = "button";
    refresh.id = "sec-reload";
    refresh.className = "btn ghost";
    refresh.appendChild(secIcon("radar"));
    refresh.appendChild(document.createTextNode("Refresh"));
    bar.appendChild(refresh);
    return bar;
  }
  function secInitProjectFilterPickers() {
    secStatusPicker = makePicker("secpj-filter-status", {
      icon: secIconHTML("filter"),
      label: "Status",
      valueLabel: () => secProjectFilters.status === "active" ? "Active" : secProjectFilters.status === "disabled" ? "Disabled" : "All",
      rows: () => {
        const projects = secLatestProjects;
        const activeN = projects.filter((p) => p.enabled !== false).length;
        return [
          {
            v: "",
            label: "All",
            n: projects.length,
            sel: secProjectFilters.status === "",
            icon: secIconHTML("layers")
          },
          {
            v: "active",
            label: "Active",
            n: activeN,
            sel: secProjectFilters.status === "active",
            icon: secIconHTML("play")
          },
          {
            v: "disabled",
            label: "Disabled",
            n: projects.length - activeN,
            sel: secProjectFilters.status === "disabled",
            icon: secIconHTML("power")
          }
        ];
      },
      onPick: (v) => {
        secProjectFilters.status = v;
        secRepaintProjectsTable();
      }
    });
    secProfileFilterPicker = makePicker("secpj-filter-profile", {
      icon: secIconHTML("shield"),
      label: "Profile",
      valueLabel: () => secProjectFilters.profile ? secProfileLabel(secProjectFilters.profile) : "All",
      rows: () => {
        const projects = secLatestProjects, values = secUniqueValues(projects, "profile");
        const rows = [{
          v: "",
          label: "All",
          n: projects.length,
          sel: secProjectFilters.profile === "",
          icon: secIconHTML("layers")
        }];
        values.forEach((v) => rows.push({
          v,
          label: secProfileLabel(v),
          n: projects.filter((p) => p.profile === v).length,
          sel: secProjectFilters.profile === v,
          icon: secIconHTML("shield")
        }));
        return rows;
      },
      onPick: (v) => {
        secProjectFilters.profile = v;
        secRepaintProjectsTable();
      }
    });
    secBranchFilterPicker = makePicker("secpj-filter-branch", {
      icon: secIconHTML("gitbranch"),
      label: "Branch",
      valueLabel: () => secProjectFilters.branch || "All",
      rows: () => {
        const projects = secLatestProjects, values = secUniqueValues(projects, "branch");
        const rows = [{
          v: "",
          label: "All",
          n: projects.length,
          sel: secProjectFilters.branch === "",
          icon: secIconHTML("layers")
        }];
        values.forEach((v) => rows.push({
          v,
          label: v,
          n: projects.filter((p) => p.branch === v).length,
          sel: secProjectFilters.branch === v,
          icon: secIconHTML("gitbranch")
        }));
        return rows;
      },
      onPick: (v) => {
        secProjectFilters.branch = v;
        secRepaintProjectsTable();
      }
    });
  }
  function secClearStaleFilterValues(projects) {
    const profiles = secUniqueValues(projects, "profile");
    if (secProjectFilters.profile && !profiles.includes(secProjectFilters.profile)) secProjectFilters.profile = "";
    const branches = secUniqueValues(projects, "branch");
    if (secProjectFilters.branch && !branches.includes(secProjectFilters.branch)) secProjectFilters.branch = "";
  }
  function secRepaintProjectsTable() {
    if (secStatusPicker) secStatusPicker.paint();
    if (secProfileFilterPicker) secProfileFilterPicker.paint();
    if (secBranchFilterPicker) secBranchFilterPicker.paint();
    if (!secProjectsTableHost) return;
    secProjectsTableHost.textContent = "";
    if (!secLatestProjects.length) {
      secProjectsTableHost.appendChild(secIndexProjectsTable([]));
      return;
    }
    const filtered = secFilterProjects(secLatestProjects, secProjectFilters);
    if (!filtered.length) {
      const e = secEl("div", "tblempty");
      e.appendChild(secIcon("inbox"));
      e.appendChild(document.createTextNode(
        "No projects match these filters \u2014 try a different search or picker."
      ));
      secProjectsTableHost.appendChild(e);
      return;
    }
    const footer = tableFooter({
      shown: { from: 1, to: filtered.length },
      total: filtered.length,
      noun: "project",
      page: 1,
      pages: 1,
      numbered: true,
      prevId: "secpj-pg-prev",
      nextId: "secpj-pg-next",
      infoId: "secpj-pg-info"
    });
    secProjectsTableHost.appendChild(secIndexProjectsTable(filtered, footer));
  }
  function secMountProjectsSection(sectionHost) {
    sectionHost.appendChild(secProjectsFilterBar());
    secInitProjectFilterPickers();
    secProjectsTableHost = secEl("div");
    sectionHost.appendChild(secProjectsTableHost);
  }
  function secIndexCardHead(title, sub, action) {
    const head = secEl("div", "secidx-cardhead");
    const text = secEl("div", "secidx-cardhead-text");
    text.appendChild(secEl("h3", null, title));
    if (sub) text.appendChild(secEl("p", "secidx-cardhead-sub", sub));
    head.appendChild(text);
    if (action) head.appendChild(action);
    return head;
  }
  function secViewAllAnalysesButton() {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn ghost";
    btn.appendChild(secIcon("activity"));
    btn.appendChild(document.createTextNode("View all analyses"));
    btn.onclick = () => {
      secOpenActivity("", true);
      secActSwitchTab("analyses");
    };
    return btn;
  }
  function secViewFullReportButton(recent) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn ghost secidx-reportbtn";
    btn.appendChild(secIcon("file"));
    btn.appendChild(document.createTextNode("View full report"));
    const latest = (recent || [])[0];
    if (!latest) {
      btn.disabled = true;
      btn.title = "No analyses yet \u2014 there is nothing to report.";
      return btn;
    }
    btn.title = "Open " + latest.project + "\u2019s own Reports tab \u2014 the nearest report to this card's totals; there is no single report spanning every project.";
    btn.onclick = () => {
      secOpenProject(latest.project, true);
      secSwitchProjectTab("reports");
    };
    return btn;
  }
  var SEC_RECENT_COLS = [
    ["run", "Run"],
    ["project", "Project"],
    ["profile", "Profile"],
    ["branch", "Branch"],
    ["findings", "Findings"],
    ["status", "Status"],
    ["date", "Date"]
  ];
  var SEC_RUN_STATUS_LABEL = {
    running: "Running",
    done: "Completed",
    capped: "Capped",
    failed: "Failed"
  };
  function secIndexRunStatusPill(state) {
    const known = Object.prototype.hasOwnProperty.call(SEC_RUN_STATUS_LABEL, state);
    return secEl(
      "span",
      "pill " + (known ? state : "failed"),
      known ? SEC_RUN_STATUS_LABEL[state] : "Unknown"
    );
  }
  function secIndexRecentFindingsChips(severities) {
    if (!severities) return secEl("span", "muted", "\u2014");
    const wrap = secEl("div", "sevpills secidx-sev3");
    FIND_SEVS.forEach((sev) => wrap.appendChild(
      secEl("span", "sevpill " + sev, String(severities[sev] || 0))
    ));
    return wrap;
  }
  function secIndexRecentRow(a) {
    const tr = document.createElement("tr");
    tr.className = "secidx-rowlink";
    tr.onclick = () => secOpenProject(a.project);
    const tdRun = document.createElement("td");
    tdRun.textContent = "#" + a.id;
    tr.appendChild(tdRun);
    const tdProject = document.createElement("td");
    const nameLine = secEl("div", "secidx-pname");
    nameLine.appendChild(secIcon("folder"));
    nameLine.appendChild(secEl("span", "secidx-pname-text", a.project));
    tdProject.appendChild(nameLine);
    tr.appendChild(tdProject);
    const tdProfile = document.createElement("td");
    tdProfile.appendChild(a.profile ? secEl("span", "pill profile", secProfileLabel(a.profile)) : secEl("span", "muted", "\u2014"));
    tr.appendChild(tdProfile);
    const tdBranch = document.createElement("td");
    tdBranch.textContent = a.branch || "\u2014";
    tr.appendChild(tdBranch);
    const tdFindings = document.createElement("td");
    tdFindings.appendChild(secIndexRecentFindingsChips(a.severities));
    tr.appendChild(tdFindings);
    const tdStatus = document.createElement("td");
    tdStatus.appendChild(secIndexRunStatusPill(a.state));
    tr.appendChild(tdStatus);
    const tdDate = document.createElement("td");
    tdDate.appendChild(document.createTextNode(fmtAgo(a.started, true)));
    tdDate.appendChild(secEl("div", "secidx-sub", secIndexRunWhen(a.started)));
    tr.appendChild(tdDate);
    return tr;
  }
  var SEC_RECENT_PAGE_SIZE = 5;
  var secRecentPage = 1;
  function secIndexRecentCard(recent) {
    const card = secEl("div", "table-card");
    card.appendChild(secIndexCardHead(
      "Recent analyses",
      "Latest security analyses across all projects",
      secViewAllAnalysesButton()
    ));
    const rows = recent.rows || [];
    const total = recent.total || 0;
    if (!total) {
      const e = secEl("div", "tblempty");
      e.appendChild(secIcon("inbox"));
      e.appendChild(document.createTextNode("No analyses have run yet."));
      card.appendChild(e);
      return card;
    }
    const pages = Math.max(1, Math.ceil(total / SEC_RECENT_PAGE_SIZE));
    secRecentPage = Math.min(Math.max(1, secRecentPage), pages);
    const from = total ? (secRecentPage - 1) * SEC_RECENT_PAGE_SIZE + 1 : 0;
    const to = from + rows.length - 1;
    const scroll = secEl("div", "table-scroll");
    const table = document.createElement("table");
    table.className = "secidx-recent";
    const thead = document.createElement("thead");
    const htr = document.createElement("tr");
    SEC_RECENT_COLS.forEach(([, label]) => htr.appendChild(secEl("th", null, label)));
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    rows.forEach((a) => tbody.appendChild(secIndexRecentRow(a)));
    table.appendChild(tbody);
    scroll.appendChild(table);
    card.appendChild(scroll);
    const footer = tableFooter({
      // `plural: "analyses"` -- tableFooter's own bare `noun + "s"` reads
      // "analysiss" otherwise (see its own comment, ui/app/chrome.js); found
      // live, in this exact card, verifying against the mockup.
      shown: { from, to },
      total,
      noun: "analysis",
      plural: "analyses",
      page: secRecentPage,
      pages,
      numbered: true,
      prevId: "secrecent-pg-prev",
      nextId: "secrecent-pg-next"
    });
    footer.onclick = (e) => {
      const pageBtn = e.target.closest(".pagebtn");
      if (pageBtn) {
        secRecentPage = Number(pageBtn.dataset.page);
      } else if (e.target.closest("#secrecent-pg-prev")) {
        secRecentPage = Math.max(1, secRecentPage - 1);
      } else if (e.target.closest("#secrecent-pg-next")) {
        secRecentPage = Math.min(pages, secRecentPage + 1);
      } else {
        return;
      }
      secLoadIndex(true);
    };
    card.appendChild(footer);
    return card;
  }
  var SEV_ORDER5 = ["critical", "high", "medium", "low", "info"];
  var SEV_STROKE = {
    critical: "var(--sev-crit)",
    high: "var(--sev-high)",
    medium: "var(--sev-med)",
    low: "var(--sev-low)",
    info: "var(--sev-info)"
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
  var DONUT_PILL_TITLE = "Distinct problems (fingerprints) \u2014 the same finding open on two branches counts once here.";
  function secIndexDonutLegend(donut, opts) {
    const showPercent = !!(opts && opts.showPercent);
    const showZero = !!(opts && opts.showZero);
    const wrap = secEl("div", "sevpills" + (showPercent ? " secidx-findlegend" : ""));
    const total = SEV_ORDER5.reduce((n, s) => n + (donut[s] || 0), 0);
    if (!total && !showZero) {
      wrap.appendChild(secEl("span", "sevpill clean", "nothing open"));
      return wrap;
    }
    if (!showPercent) {
      SEV_ORDER5.forEach((sev) => {
        if (!donut[sev]) return;
        const pill = secEl("span", "sevpill " + sev, donut[sev] + " " + sev);
        pill.title = DONUT_PILL_TITLE;
        wrap.appendChild(pill);
      });
      return wrap;
    }
    SEV_ORDER5.forEach((sev) => {
      const n = donut[sev] || 0;
      if (!n && !showZero) return;
      const row = secEl("div", "secidx-legendrow " + sev + (n ? "" : " zero"));
      row.title = DONUT_PILL_TITLE;
      row.appendChild(secEl("span", "secidx-legenddot"));
      row.appendChild(secEl(
        "span",
        "secidx-legendname",
        sev[0].toUpperCase() + sev.slice(1)
      ));
      row.appendChild(secEl(
        "span",
        "secidx-legendcount",
        n + " (" + (n ? (n / total * 100).toFixed(1) : "0") + "%)"
      ));
      wrap.appendChild(row);
    });
    return wrap;
  }
  function secIndexCategories(categories) {
    if (!categories.length) {
      return secEl("div", "tblempty", "No open findings to categorise.");
    }
    const wrap = secEl("div", "secidx-categories");
    categories.forEach((c) => {
      const meta = secRuleMeta(c.category, c.rule);
      const row = secEl("div", "secidx-catrow");
      row.title = c.rule;
      row.appendChild(secIcon(meta.icon));
      row.appendChild(secEl("span", "secidx-catname", meta.label));
      row.appendChild(secEl("span", "secidx-catcount", String(c.count || 0)));
      wrap.appendChild(row);
    });
    return wrap;
  }
  function secIndexDonut(donut, categories, cappedNote, opts) {
    const wrap = secEl("div", "secidx-donutwrap");
    const left = secEl("div", "secidx-donutcol");
    left.appendChild(secIndexDonutSvg(donut));
    left.appendChild(secIndexDonutLegend(donut, opts));
    wrap.appendChild(left);
    const right = secEl("div", "secidx-catcol");
    right.appendChild(secEl("div", "secidx-cathead", "Top issue categories"));
    right.appendChild(secIndexCategories(categories));
    wrap.appendChild(right);
    if ((cappedNote || "").trim()) {
      const warn = secEl("div", "warnline bad secidx-donutwarn");
      warn.appendChild(secIcon("alert"));
      warn.appendChild(secEl("span", "grow", cappedNote));
      wrap.appendChild(warn);
    }
    return wrap;
  }
  var secFindPeriodDays = 30;
  function secFindPeriodLabel(days) {
    return days > 0 ? "Last " + days + " days" : "All time";
  }
  function secFindPeriodTitleSuffix(days) {
    return days > 0 ? "(" + days + " day" + (days === 1 ? "" : "s") + ")" : "(All time)";
  }
  var SEC_FIND_PERIOD_TITLE = "Findings recorded by analyses that ran in this period. Changing it asks the server again \u2014 the donut, legend and categories below all re-render for the period chosen.";
  function secFindingsPeriodPicker() {
    const wrap = document.createElement("details");
    wrap.className = "secidx-periodpick";
    const trigger = document.createElement("summary");
    trigger.className = "filterpick";
    trigger.title = SEC_FIND_PERIOD_TITLE;
    trigger.onclick = (e) => e.stopPropagation();
    const value = secEl("span", null, secFindPeriodLabel(secFindPeriodDays));
    trigger.appendChild(value);
    trigger.appendChild(secIcon("cdown"));
    wrap.appendChild(trigger);
    const pop = secEl("div", "menu-pop");
    pop.setAttribute("role", "menu");
    ACT_PERIODS.forEach(([days]) => {
      const item = document.createElement("button");
      item.type = "button";
      item.setAttribute("role", "menuitem");
      item.appendChild(document.createTextNode(secFindPeriodLabel(days)));
      if (days === secFindPeriodDays) item.appendChild(secIcon("check2"));
      item.onclick = (e) => {
        e.stopPropagation();
        secFindPeriodDays = days;
        wrap.open = false;
        secLoadIndex(true);
      };
      pop.appendChild(item);
    });
    wrap.appendChild(pop);
    wrap.ontoggle = () => {
      if (!wrap.open) return;
      const r = trigger.getBoundingClientRect();
      pop.style.position = "fixed";
      pop.style.top = r.bottom + 6 + "px";
      pop.style.right = window.innerWidth - r.right + "px";
      pop.style.left = "auto";
      pop.style.bottom = "auto";
    };
    return wrap;
  }
  function secIndexFindingsCard(donut, categories, cappedNote, recent) {
    const card = secEl("div", "table-card");
    card.appendChild(secIndexCardHead(
      "Findings overview " + secFindPeriodTitleSuffix(secFindPeriodDays),
      null,
      secFindingsPeriodPicker()
    ));
    const body = secEl("div", "secidx-findbody");
    body.appendChild(secIndexDonut(donut, categories, cappedNote, { showPercent: true }));
    card.appendChild(body);
    card.appendChild(secViewFullReportButton(recent));
    return card;
  }

  // ui/security/index.js
  function renderSecurity() {
    if (CC.currentView !== "security") return;
    if (secIsActivityOpen()) return;
    if (secState.project) return;
    secRenderIndex();
    secLoadIndex(false);
  }
  function init(cc) {
    bindPage(cc);
    wireReasonDialog();
    iconLabel($("sr-halo"), "shield");
    $("sec-crumb-security").textContent = "Security";
    $("sec-crumb-security").addEventListener("click", () => secBack());
    iconLabel($("sec-back"), "cleft", "All projects");
    iconLabel($("sec-dl-md"), "file", "Markdown");
    iconLabel($("sec-dl-json"), "file", "JSON");
    iconLabel($("sec-dl-html"), "file", "HTML");
    iconLabel($("sec-dl-sbom"), "file", "SBOM");
    iconLabel($("secpjt-overview"), "grid", "Overview");
    iconLabel($("secpjt-runs"), "activity", "Runs");
    iconLabel($("secpjt-branches"), "layers", "Branches");
    iconLabel($("secpjt-findings"), "search", "Findings");
    iconLabel($("secpjt-reports"), "file", "Reports");
    $("secpjt-overview").addEventListener("click", () => secSwitchProjectTab("overview"));
    $("secpjt-runs").addEventListener("click", () => secSwitchProjectTab("runs"));
    $("secpjt-branches").addEventListener("click", () => secSwitchProjectTab("branches"));
    $("secpjt-findings").addEventListener("click", () => secSwitchProjectTab("findings"));
    $("secpjt-reports").addEventListener("click", () => secSwitchProjectTab("reports"));
    iconLabel($("sec-act-back"), "cleft", "All projects");
    iconLabel($("sec-act-reload"), "radar", "Refresh");
    iconLabel($("secactt-all"), "activity", "All activity");
    iconLabel($("secactt-analyses"), "shield", "Analyses");
    iconLabel($("secactt-findings"), "search", "Findings");
    iconLabel($("secactt-settings"), "gear", "Settings");
    $("sec-act-back").addEventListener("click", () => secBackFromActivity());
    $("sec-act-reload").addEventListener("click", secActReload);
    $("secactt-all").addEventListener("click", () => secActSwitchTab(""));
    $("secactt-analyses").addEventListener("click", () => secActSwitchTab("analyses"));
    $("secactt-findings").addEventListener("click", () => secActSwitchTab("findings"));
    $("secactt-settings").addEventListener("click", () => secActSwitchTab("settings"));
    secActInitProjectPicker();
    wireActivityFindingDialog();
    $("sec-dl-note").textContent = "Downloads always contain every recorded finding, whatever the severity floor shows.";
    $("sec-back").addEventListener("click", () => secBack());
    $("sec-run").addEventListener("click", secAnalyse);
    $("sec-dl-md").addEventListener("click", () => secDownload("md"));
    $("sec-dl-json").addEventListener("click", () => secDownload("json"));
    $("sec-dl-html").addEventListener("click", () => secDownload("html"));
    $("sec-dl-sbom").addEventListener("click", () => secDownload("sbom"));
    secInitLaunchCombos();
    secInitFindBar();
    $("sec-branch-other").addEventListener("change", () => secSyncScope());
  }
  function secNavState() {
    if (secIsActivityOpen()) {
      const a = secActNavState();
      return { screen: "activity", project: a.project, tab: a.tab };
    }
    if (secState.project) return { screen: "project", project: secState.project, tab: secCurrentProjectTab() };
    return { screen: "index" };
  }
  async function secNavigate(sec) {
    sec = sec || {};
    if (sec.screen === "project" && sec.project && projById(sec.project)) {
      if (secIsActivityOpen()) secBackFromActivity(true);
      if (secState.project !== sec.project) await secOpenProject(sec.project, true);
      secSwitchProjectTab(sec.tab || "overview", true);
      return;
    }
    if (sec.screen === "activity") {
      const already = secIsActivityOpen() && secActNavState().project === (sec.project || "");
      if (!already) await secOpenActivity(sec.project || "", true);
      secActSwitchTab(sec.tab || "", true);
      return;
    }
    if (secIsActivityOpen()) secBackFromActivity(true);
    else secBack(true);
  }
  window.CCSecurity = {
    init,
    render: renderSecurity,
    enter: secEnter,
    leave: secLeave,
    openActivity: () => secOpenActivity(""),
    reload: () => secLoadIndex(true),
    // navState/navigate (F4 history layer): the bridge bin/dashboard.html's
    // router uses the OTHER direction from every name above -- those answer a
    // click the page already routed here; these let the page ask this area
    // what to push, and tell it what to restore. See this file's own comment
    // above secNavState/secNavigate, and bin/dashboard.html's, beside setView.
    navState: secNavState,
    navigate: secNavigate,
    SEV_ORDER,
    SEC_PROFILES
  };
})();
/* ui-bundle: 4f0d7426490c938d675ea3db732991fcc89d18bd0a0d2f980150cc31023b4bba */
/* ui-sources: db4d393b9fa63afaac76b9c97d555a961ca919a06c70790a4496e869247c93e8 */
