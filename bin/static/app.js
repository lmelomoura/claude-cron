(() => {
  // ui/app/page.js
  var $;
  var TOKEN;
  var api;
  var toast;
  var esc;
  var fmtAgo;
  var fmtWhen;
  var fmtDur;
  var fmtIn;
  var money;
  var icon;
  var iconLabel;
  var openLog;
  var openEditor;
  var projById;
  var isFav;
  var eff;
  var setView;
  var backoffMultiplier;
  var activeRunsOf;
  var renderJobs;
  var CC = null;
  function bindPage(cc) {
    CC = cc;
    ({
      $,
      TOKEN,
      api,
      toast,
      esc,
      fmtAgo,
      fmtWhen,
      fmtDur,
      fmtIn,
      money,
      icon,
      iconLabel,
      openLog,
      openEditor,
      projById,
      isFav,
      eff,
      setView,
      backoffMultiplier,
      activeRunsOf,
      renderJobs
    } = cc);
  }

  // ui/app/jobs-domain.js
  var jobFilters = { project: "", status: "", query: "" };
  function inWindow(j, when) {
    const now = when || /* @__PURE__ */ new Date();
    const days = j.active_days;
    if (Array.isArray(days) && days.length) {
      const dow = now.getDay() === 0 ? 7 : now.getDay();
      if (!days.map(Number).includes(dow)) return false;
    }
    const hours = j.active_hours;
    if (hours && /^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/.test(hours)) {
      const [a, b] = hours.split("-");
      const toMin = (s2) => {
        const [h, m] = s2.split(":").map(Number);
        return h * 60 + m;
      };
      const s = toMin(a), e = toMin(b), nowMin = now.getHours() * 60 + now.getMinutes();
      if (s <= e) {
        if (!(nowMin >= s && nowMin < e)) return false;
      } else {
        if (!(nowMin >= s || nowMin < e)) return false;
      }
    }
    return true;
  }
  function nextCheckAt(j, fromEpoch) {
    const from = new Date(fromEpoch * 1e3);
    if (inWindow(j, from)) return fromEpoch;
    const days = Array.isArray(j.active_days) && j.active_days.length ? j.active_days.map(Number) : null;
    const hours = j.active_hours && /^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/.test(j.active_hours) ? j.active_hours : null;
    const [oh, om] = (hours ? hours.split("-")[0] : "00:00").split(":").map(Number);
    for (let i = 0; i <= 8; i++) {
      const c = new Date(from);
      c.setDate(c.getDate() + i);
      c.setHours(oh, om, 0, 0);
      if (c.getTime() < from.getTime()) continue;
      const dow = c.getDay() === 0 ? 7 : c.getDay();
      if (days && !days.includes(dow)) continue;
      return Math.floor(c.getTime() / 1e3);
    }
    return null;
  }
  function jobFacts(j) {
    const t0 = Math.floor((/* @__PURE__ */ new Date()).setHours(0, 0, 0, 0) / 1e3);
    const st = CC.DATA.state[j.id] || {}, disabled = j.enabled === false;
    const chk = (CC.DATA.checks || {})[j.id] || { checks: 0, runs: 0 };
    const spentToday = CC.DATA.runs.filter((r) => r.id === j.id && r.start >= t0).reduce((a, r) => a + (r.cost || 0), 0);
    const capRaw = eff(j, "daily_budget_usd", null);
    const cap = capRaw != null && capRaw !== "" ? +capRaw : null;
    const capped = cap != null && spentToday >= cap;
    const streak = +(st.fail_streak || 0);
    const backoff = backoffMultiplier(streak);
    const ivEff = (j.interval_seconds || 300) * backoff;
    const dueAt = st.last_start ? st.last_start + ivEff : Math.floor(Date.now() / 1e3);
    const nextAt = nextCheckAt(j, dueAt);
    const nLive = activeRunsOf(j.id).length;
    const running = nLive > 0;
    const idle = !disabled && !running && !inWindow(j);
    return {
      st,
      chk,
      disabled,
      spentToday,
      cap,
      capped,
      streak,
      backoff,
      dueAt,
      nextAt,
      nLive,
      running,
      idle,
      state: disabled ? "disabled" : running ? "running" : idle ? "idle" : "enabled"
    };
  }
  function visibleJobs() {
    let jobs = CC.DATA.jobs || [];
    if (jobFilters.project === "__none__") jobs = jobs.filter((j) => !j.project);
    else if (jobFilters.project) jobs = jobs.filter((j) => j.project === jobFilters.project);
    if (jobFilters.status === "enabled") jobs = jobs.filter((j) => j.enabled !== false);
    else if (jobFilters.status === "disabled") jobs = jobs.filter((j) => j.enabled === false);
    const q = jobFilters.query.trim().toLowerCase();
    if (q) jobs = jobs.filter((j) => (j.id + " " + (j.description || "") + " " + (j.project || "")).toLowerCase().includes(q));
    return jobs;
  }
  function bulkOn(js) {
    return js.some((j) => j.enabled !== false);
  }
  function bulkLabel(on, n) {
    return (on ? "Disable all" : "Enable all") + (n === void 0 ? "" : " " + n);
  }
  function clearJobFilters() {
    jobFilters.project = jobFilters.status = jobFilters.query = "";
    $("jq").value = "";
    $("jq-clear").hidden = true;
    renderJobs();
  }
  function jobProjectNames() {
    return [...new Set((CC.DATA.jobs || []).map((j) => j.project || "").filter(Boolean))].sort();
  }

  // ui/app/overview.js
  function pulseKpis(k) {
    const checks = k.checks || 0;
    const per = k.per || {};
    const warn = k.warn || 0;
    const err = k.err || 0;
    const spentToday = k.spentToday || 0;
    const pct = (n) => checks ? Math.round(n / checks * 100) + "%" : "\u2014";
    const dollars = new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
      minimumFractionDigits: 2,
      maximumFractionDigits: Math.abs(spentToday) < 0.1 ? 4 : 2
    }).format(spentToday);
    return [
      {
        label: "Checks",
        value: String(checks),
        sub: checks ? "in the last 24h" : "nothing yet",
        tone: "",
        filter: ""
      },
      {
        label: "Woke a run",
        value: String(per.woke || 0),
        sub: pct(per.woke || 0) + " of checks",
        tone: "",
        filter: ""
      },
      // Warnings and errors are a way IN to the runs they count, and inert
      // when there is nothing to go to -- see pulseHtml's own comment beside
      // chip() on why a card with nothing to show must not navigate.
      {
        label: "Warnings",
        value: String(warn),
        sub: warn ? "Runs that finished without failing but did not do the work \u2014 open them in Runs" : "No warnings in the last 7 days",
        tone: "warn",
        filter: warn ? "warning" : ""
      },
      {
        label: "Errors",
        value: String(err),
        sub: err ? "Runs that failed \u2014 open them in Runs" : "No errors in the last 7 days",
        tone: "err",
        filter: err ? "error" : ""
      },
      { label: "Spent today", value: dollars, sub: "", tone: "", filter: "" }
    ];
  }
  function bandEmptyReason(jobs) {
    const js = jobs || [];
    const off = js.filter((j) => j.enabled === false).length;
    return !js.length ? "There are no jobs yet." : off === js.length ? "All " + js.length + " jobs are disabled." : off ? off + " of " + js.length + " jobs are disabled." : "Every job is enabled \u2014 the next tick will show up here.";
  }
  function probeVerdict(pc) {
    const span = document.createElement("span");
    if (pc.exit === 0) {
      span.style.color = "var(--ok)";
      span.textContent = "work found";
    } else if (pc.exit === 1) {
      span.textContent = "nothing to do";
    } else {
      span.style.color = "var(--err)";
      span.style.fontWeight = "600";
      span.textContent = "probe FAILED (exit " + pc.exit + ")";
    }
    return span;
  }
  function spendTone(spent, cap) {
    const capped = cap != null && spent >= cap;
    const pct = cap != null && cap > 0 ? Math.min(100, spent / cap * 100) : 0;
    return capped ? "over" : pct >= 80 ? "near" : "";
  }
  function groupJobs(jobs, favSet, allProjects) {
    const names = [...new Set(jobs.map((j) => j.project || "").filter(Boolean))].sort((a, b) => favSet.has(b) - favSet.has(a) || a.localeCompare(b));
    if (!names.length && !(allProjects && allProjects.length)) return [];
    const groups = [];
    for (const name of names) {
      const js = jobs.filter((j) => j.project === name);
      if (js.length) groups.push({ name, jobs: js });
    }
    const loose = jobs.filter((j) => !j.project);
    if (loose.length) groups.push({ name: "__standalone__", jobs: loose });
    return groups;
  }
  function jobsEmptyNote(filtering) {
    return filtering ? "No jobs match these filters." : "No jobs yet \u2014 create one.";
  }
  function nextRunNote(job, facts) {
    const wrap = document.createElement("span");
    if (job.enabled === false) {
      const muted = document.createElement("span");
      muted.className = "muted";
      muted.textContent = "disabled";
      wrap.appendChild(muted);
      return wrap;
    }
    const { nextAt, dueAt, backoff, streak } = facts;
    if (nextAt == null) {
      const muted = document.createElement("span");
      muted.className = "muted";
      muted.textContent = "no matching window";
      wrap.appendChild(muted);
      return wrap;
    }
    wrap.appendChild(document.createTextNode(new Date(nextAt * 1e3).toLocaleString(
      void 0,
      {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
        second: "2-digit"
      }
    )));
    if (nextAt > dueAt + 30) {
      const reopen = document.createElement("span");
      reopen.className = "muted";
      reopen.textContent = " \xB7 when the window reopens";
      wrap.appendChild(reopen);
    }
    if (backoff > 1) {
      const back = document.createElement("span");
      back.style.color = "var(--warn)";
      back.textContent = " \xB7 backing off " + backoff + "\xD7 after " + streak + " failed runs";
      wrap.appendChild(back);
    }
    return wrap;
  }

  // ui/app/index.js
  function init(cc) {
    bindPage(cc);
  }
  window.CCApp = {
    init,
    jobFacts,
    visibleJobs,
    jobFilters,
    bulkOn,
    bulkLabel,
    clearJobFilters,
    jobProjectNames,
    pulseKpis,
    bandEmptyReason,
    probeVerdict,
    spendTone,
    groupJobs,
    jobsEmptyNote,
    nextRunNote
  };
})();
/* ui-bundle: 007c4c1caeaa1177d3451f52a450f3fad4d141b5bb321e900d10254997c586fd */
/* ui-sources: 12dfe0c96e338f51bdec9882985c0555e4560c68d2ab217b4a9ba1e9b6371e6d */
