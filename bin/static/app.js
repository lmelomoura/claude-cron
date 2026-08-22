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
    const spentWeek = k.spentWeek || 0;
    const pct = (n) => checks ? Math.round(n / checks * 100) + "%" : "\u2014";
    const money2 = (n) => new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
      minimumFractionDigits: 2,
      maximumFractionDigits: Math.abs(n) < 0.1 ? 4 : 2
    }).format(n);
    return [
      {
        label: "Checks",
        value: String(checks),
        sub: checks ? "in the last 24h" : "nothing yet",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Woke a run",
        value: String(per.woke || 0),
        sub: pct(per.woke || 0) + " of checks",
        tone: "",
        filter: "",
        door: false
      },
      // Warnings and errors are a way IN to the runs they count, and inert
      // when there is nothing to go to -- see pulseHtml's own comment beside
      // chip() on why a card with nothing to show must not navigate. `door`
      // stays true even then: it is what tells kpiCard this is a button that
      // happens to have nothing behind it right now, not a card that was
      // never a button to begin with.
      {
        label: "Warnings",
        value: String(warn),
        sub: warn ? "Runs that finished without failing but did not do the work \u2014 open them in Runs" : "No warnings in the last 7 days",
        tone: "warn",
        filter: warn ? "warning" : "",
        door: true
      },
      {
        label: "Errors",
        value: String(err),
        sub: err ? "Runs that failed \u2014 open them in Runs" : "No errors in the last 7 days",
        tone: "err",
        filter: err ? "error" : "",
        door: true
      },
      // The pulse-f strip this redesign removed paired "today" with "7 days"
      // for both runs and spend. The week's spend is that pair's other half --
      // one card, the total in its own sublabel, not a separate strip ("one
      // number per label" applied to the pair it was always part of). The
      // two run counts (runsToday/runsWeek) are deliberately NOT added here or
      // to any other card -- see task-8-report.md for why.
      {
        label: "Spent today",
        value: money2(spentToday),
        sub: money2(spentWeek) + " over 7 days",
        tone: "",
        filter: "",
        door: false
      }
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
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  var TICK_KINDS = [
    ["woke", "started a run"],
    ["idle", "nothing to do"],
    ["capped", "daily cap reached"],
    // Money and usage are different ceilings with different next moves: a daily
    // cap is a number the operator chose and can raise, a spent window is a wait
    // for the clock. Folding them together hid which one was holding the fleet.
    ["rate_limited", "usage window spent"],
    // Not "at its parallel limit": with max_parallel=1 — the common case — that
    // reads as a ceiling the operator should consider raising, when all it means
    // is that the previous run had not finished. "Already running" is true at
    // every limit and says the thing the operator actually needs to know.
    ["blocked", "already running"],
    ["failed", "could not run"]
  ];
  var clockAt = (sec) => new Date(sec * 1e3).toLocaleTimeString(void 0, { hour: "2-digit", minute: "2-digit" });
  function tickTotals(ticks) {
    const T = ticks || {}, buckets = Array.isArray(T.buckets) ? T.buckets : [];
    const kinds = Array.isArray(T.outcomes) ? T.outcomes : TICK_KINDS.map((x) => x[0]);
    const per = {};
    TICK_KINDS.forEach(([name]) => {
      per[name] = 0;
    });
    kinds.forEach((name, i) => {
      per[name] = buckets.reduce((a, b) => a + (b[i] || 0), 0);
    });
    return { per, checks: Object.values(per).reduce((a, n) => a + n, 0), buckets, kinds, T };
  }
  function pickLine(lines) {
    return lines[Math.floor(Date.now() / 36e5) % lines.length];
  }
  function greetingParts(m, jobs, firstName) {
    const per = m.per || {};
    const checks = m.checks || 0;
    const h = (/* @__PURE__ */ new Date()).getHours();
    const when = h < 5 ? "Still up" : h < 12 ? "Good morning" : h < 19 ? "Good afternoon" : "Good evening";
    const js = jobs || [];
    const off = js.filter((j) => j.enabled === false).length;
    const runs = m.runsToday || 0;
    const money2 = (n) => new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
      minimumFractionDigits: 2,
      maximumFractionDigits: Math.abs(n) < 0.1 ? 4 : 2
    }).format(n);
    const spent = money2(m.spentToday || 0);
    const nOf = (n, word) => n + " " + word + (n === 1 ? "" : "s");
    let line;
    if (!js.length) {
      line = pickLine([
        "No jobs yet, so nothing has gone wrong. Enjoy the perfect record while it lasts.",
        "An empty scheduler has never once exceeded its budget.",
        "Nothing to run. This is the safest this dashboard will ever be."
      ]);
    } else if (off === js.length) {
      line = pickLine([
        "Every job is switched off \u2014 the quietest kind of correct.",
        (js.length === 1 ? "Your one job is disabled" : "All " + js.length + " jobs are disabled") + ". Nothing is spending your money, which is one way to stay under budget.",
        "The loop is awake and has absolutely nothing to do about it."
      ]);
    } else if (m.err) {
      line = pickLine([
        nOf(m.err, "error") + " in the last 7 days. They are not going to read themselves.",
        nOf(m.err, "run") + " failed this week \u2014 the logs know why, and they are one click away.",
        "Something broke " + nOf(m.err, "time") + " this week. Better here than in review."
      ]);
    } else if (per.failed) {
      line = pickLine([
        nOf(per.failed, "check") + " could not even start today. That is usually a path or a lock.",
        "The prober failed " + nOf(per.failed, "time") + " \u2014 worth a look before it becomes a habit."
      ]);
    } else if (runs && m.spentToday >= 50) {
      line = pickLine([
        nOf(runs, "run") + " and " + spent + " today. The agents have been enthusiastic.",
        spent + " spent today across " + nOf(runs, "run") + ". Money well spent, presumably.",
        nOf(runs, "run") + " today. Your credit card has been paying attention."
      ]);
    } else if (runs) {
      line = pickLine([
        nOf(runs, "run") + " today, nothing on fire.",
        nOf(runs, "run") + " today for " + spent + ", none of which asked permission.",
        nOf(runs, "run") + " today and zero errors. Suspicious, but I will take it."
      ]);
    } else if (checks) {
      line = pickLine([
        "Nothing has run today. The loop is awake, just unimpressed by the queue.",
        nOf(checks, "check") + " today and nothing worth waking a run for. That is the system working.",
        "Quiet so far \u2014 every precheck looked and found nothing to do."
      ]);
    } else {
      line = pickLine([
        "The loop has not checked anything in the last 24 hours.",
        "No ticks today. If that is a surprise, check that launchd is still loaded."
      ]);
    }
    const first = String(firstName || "").trim().split(/\s+/)[0] || "";
    return { title: when + (first ? ", " + first : "") + ".", subtitle: line };
  }
  function pageHeader({ icon: iconName, title, subtitle, actions }) {
    const head = el("div", "page-header");
    const icWrap = el("div", "page-header-ic");
    if (iconName) icWrap.appendChild(icon(iconName));
    head.appendChild(icWrap);
    const body = el("div", "page-header-body");
    body.appendChild(el("h1", null, title));
    if (subtitle) body.appendChild(el("p", null, subtitle));
    head.appendChild(body);
    if (actions && actions.length) {
      const bar = el("div", "page-header-actions");
      actions.forEach((a) => bar.appendChild(pageHeaderAction(a)));
      head.appendChild(bar);
    }
    return head;
  }
  function pageHeaderAction(a) {
    const btn = el("button", "btn " + (a.primary ? "primary" : "ghost"));
    if (a.id) btn.id = a.id;
    if (a.icon) btn.appendChild(icon(a.icon));
    btn.appendChild(document.createTextNode(a.label));
    return btn;
  }
  function kpiCard(opts) {
    const { icon: iconName, tone, value, label, sub, filter, door } = opts;
    const card = el(door ? "button" : "div", "kpi-card" + (tone ? " " + tone : ""));
    const head = el("div", "kpi-card-h");
    const icWrap = el("div", "kpi-card-ic");
    if (iconName) icWrap.appendChild(icon(iconName));
    head.appendChild(icWrap);
    head.appendChild(el("span", "kpi-card-num", value));
    card.appendChild(head);
    card.appendChild(el("div", "kpi-card-label", label));
    if (sub) card.appendChild(el("div", "kpi-card-sub", sub));
    if (door) {
      if (filter) card.dataset.statfilter = filter;
      else card.disabled = true;
    }
    return card;
  }
  function renderPulse(ticks, jobs) {
    const { per, checks, buckets, kinds, T } = tickTotals(ticks);
    const span = T.bucket_seconds || 900;
    const start = T.start || Math.floor(Date.now() / 1e3) - 86400;
    const totalOf = (b) => b.reduce((a, n) => a + n, 0);
    const max = buckets.reduce((m, b) => Math.max(m, totalOf(b)), 0);
    const frag = document.createDocumentFragment();
    frag.appendChild(el("div", "pulse-t", "Last 24 hours"));
    if (!checks) {
      const asleep = el("div", "band asleep");
      asleep.appendChild(el(
        "span",
        null,
        "The loop has not checked anything in the last 24 hours. " + bandEmptyReason(jobs)
      ));
      frag.appendChild(asleep);
    } else {
      const band = el("div", "band");
      buckets.forEach((b, bi) => {
        const at = start + bi * span, tot = totalOf(b);
        const bk = el("div", "bk");
        bk.title = tot ? clockAt(at) + "\u2013" + clockAt(at + span) + "\n" + kinds.map((name, i) => b[i] ? b[i] + " " + (TICK_KINDS.find((x) => x[0] === name) || [, name])[1] : "").filter(Boolean).join("\n") : clockAt(at) + "\u2013" + clockAt(at + span) + "\nno checks";
        kinds.forEach((name, i) => {
          if (!b[i]) return;
          const bar = el("i", "k-" + name);
          bar.style.height = (b[i] / max * 100).toFixed(2) + "%";
          bk.appendChild(bar);
        });
        band.appendChild(bk);
      });
      frag.appendChild(band);
    }
    const axis = el("div", "axis");
    [0, 0.25, 0.5, 0.75].forEach((f) => axis.appendChild(el("span", null, clockAt(start + 86400 * f))));
    axis.appendChild(el("span", null, "now"));
    frag.appendChild(axis);
    const shown = TICK_KINDS.filter(([name]) => per[name]);
    if (shown.length) {
      const legend = el("div", "legend");
      shown.forEach(([name, what]) => {
        const item = el("span");
        item.appendChild(el("i", "k-" + name));
        item.appendChild(document.createTextNode(per[name] + " " + what));
        legend.appendChild(item);
      });
      frag.appendChild(legend);
    }
    return frag;
  }
  function renderOverviewHead(kpis, firstName) {
    const jobs = CC.DATA.jobs || [];
    const ticks = CC.DATA.ticks || {};
    const tt = tickTotals(ticks);
    const merged = Object.assign({}, kpis, { checks: tt.checks, per: tt.per });
    const cards = pulseKpis(merged);
    const { title, subtitle } = greetingParts(merged, jobs, firstName);
    const headHost = $("ov-head");
    if (headHost) {
      headHost.textContent = "";
      headHost.appendChild(pageHeader({
        icon: "grid",
        title,
        subtitle,
        actions: [
          { id: "ov-refresh", icon: "radar", label: "Refresh" },
          { id: "ov-new-job", icon: "plus", label: "New job", primary: true }
        ]
      }));
    }
    const kpiHost = $("ov-kpis");
    if (kpiHost) {
      kpiHost.textContent = "";
      const ICONS = {
        "Checks": "radar",
        "Woke a run": "zap",
        "Warnings": "alert",
        "Errors": "xcircle",
        "Spent today": "dollar"
      };
      cards.forEach((c) => kpiHost.appendChild(kpiCard({
        icon: ICONS[c.label],
        tone: c.tone,
        value: c.value,
        label: c.label,
        sub: c.sub,
        filter: c.filter,
        door: c.door
      })));
    }
    const bandHost = $("stats");
    if (bandHost) {
      bandHost.textContent = "";
      bandHost.appendChild(renderPulse(ticks, jobs));
    }
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
    nextRunNote,
    // pageHeader/kpiCard/renderPulse are exported for Phases 2
    // and 3, which put a page header and KPI cards on every
    // remaining page -- renderOverviewHead is the only one of
    // the four this phase's own call site (bin/dashboard.html's
    // render()) actually calls.
    pageHeader,
    kpiCard,
    renderPulse,
    renderOverviewHead
  };
})();
/* ui-bundle: 82609d70a4de3e6987fad0a5d45d8eab9759566eccf23a4833e409bcf3200e05 */
/* ui-sources: 7bdfa6f824949aca99ec038ec8e374b5aa46795131a4a9d5f3e8ee87e5dae7ab */
