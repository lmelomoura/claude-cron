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
    jobProjectNames
  };
})();
/* ui-bundle: 382e8b3d69a86c59431e9d00322b87fad6328811b52f92b00f0c16aaa24ab44a */
/* ui-sources: 21552f6fd69190700fd5401d0f6b1b7881ba21e301af748f5294aca600481653 */
