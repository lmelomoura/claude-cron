(() => {
  // ui/app/page.js
  var $;
  var fmtAgo;
  var fmtDur;
  var money;
  var icon;
  var projById;
  var eff;
  var backoffMultiplier;
  var activeRunsOf;
  var renderJobs;
  var effortLabel;
  var fmtExpiresIn;
  var resumeInFlight;
  var CC = null;
  function bindPage(cc) {
    CC = cc;
    ({
      $,
      fmtAgo,
      fmtDur,
      money,
      icon,
      projById,
      eff,
      backoffMultiplier,
      activeRunsOf,
      renderJobs,
      effortLabel,
      fmtExpiresIn,
      resumeInFlight
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
  var JOB_COLS = [
    ["job", "Job"],
    ["project", "Project"],
    ["state", "Status"],
    [null, "Schedule"],
    ["last", "Last run"],
    ["next", "Next"],
    ["today", "Today"],
    [null, ""]
  ];
  var STATE_RANK = { running: 0, enabled: 1, idle: 2, disabled: 3 };
  var JOB_SORTERS = {
    job: { cmp: (a, b) => String(a.j.id).localeCompare(String(b.j.id)) },
    // Within a project the jobs stay A→Z whichever way the column points: you sort
    // by project to read one project's jobs together, not to scramble them.
    project: {
      cmp: (a, b) => String(a.j.project).localeCompare(String(b.j.project)),
      tie: (a, b) => String(a.j.id).localeCompare(String(b.j.id)),
      missing: (x) => !x.j.project
    },
    state: { cmp: (a, b) => STATE_RANK[a.F.state] - STATE_RANK[b.F.state] || String(a.j.id).localeCompare(String(b.j.id)) },
    last: {
      cmp: (a, b) => a.F.st.last_run_start - b.F.st.last_run_start,
      missing: (x) => !x.F.st.last_run_start
    },
    next: {
      cmp: (a, b) => a.F.nextAt - b.F.nextAt,
      missing: (x) => x.F.disabled || x.F.nextAt == null
    },
    today: { cmp: (a, b) => a.F.spentToday - b.F.spentToday }
  };
  function sortJobs(rows, key, dir) {
    const S = JOB_SORTERS[key] || JOB_SORTERS.job;
    const have = [], none = [];
    rows.forEach((x) => (S.missing && S.missing(x) ? none : have).push(x));
    have.sort((a, b) => S.cmp(a, b) * dir || (S.tie ? S.tie(a, b) : 0));
    none.sort((a, b) => String(a.j.id).localeCompare(String(b.j.id)));
    return have.concat(none);
  }

  // ui/app/chrome.js
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
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
    const { icon: iconName, tone, value, label, sub, title, filter, door } = opts;
    const card = el(door ? "button" : "div", "kpi-card" + (tone ? " " + tone : ""));
    if (title) card.title = title;
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
      // A percentage of nothing is not 0%, it is nothing -- checks-gated rather
      // than n-gated, or a fresh install with checks:0 but a stray per.woke would
      // print "0% of checks" instead of a dash. pct() already refuses to divide
      // by zero, but the old code appended " of checks" to its "—" regardless,
      // which reads as a dash with a dangling preposition rather than the plain
      // "nothing to report" pulseHtml's own original gave this card.
      {
        label: "Woke a run",
        value: String(per.woke || 0),
        sub: checks ? pct(per.woke || 0) + " of checks" : "\u2014",
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
      //
      // The sublabel carries the window and nothing else -- "in the last 7
      // days", the same string whether the count is zero or not. Checks and
      // Woke a run are 24h figures and the band right below them is titled
      // "Last 24 hours" -- a neighbour this close means Warnings/Errors have
      // to say "7 days" for themselves, every time, or a Monday failure reads
      // as if it happened today. What a warning or an error actually IS goes
      // in `title` instead, where a full sentence is free rather than
      // fighting the three-to-five-word bar every other sublabel holds to --
      // see kpiCard's own comment in chrome.js on how `title` reaches the card. "open them
      // in Runs" is dropped rather than moved: the card is already a button,
      // and a disabled one already says there is nothing behind it. Do not
      // restate the count in the sublabel ("2 in the last 7 days") -- the
      // number is already the largest thing on the card.
      {
        label: "Warnings",
        value: String(warn),
        sub: "in the last 7 days",
        title: "Runs that finished without failing but did not do the work",
        tone: "warn",
        filter: warn ? "warning" : "",
        door: true
      },
      {
        label: "Errors",
        value: String(err),
        sub: "in the last 7 days",
        title: "Runs that failed",
        tone: "err",
        filter: err ? "error" : "",
        door: true
      },
      // The pulse-f strip this redesign removed paired "today" with "7 days"
      // for both runs and spend. The week's spend is that pair's other half --
      // one card, the total in its own sublabel, not a separate strip ("one
      // number per label" applied to the pair it was always part of). The two
      // run counts (runsToday/runsWeek) are deliberately NOT added here or to
      // any other card: "Woke a run"'s sub is pinned character-for-character by
      // test_the_kpis_come_from_the_numbers_the_loop_recorded, so nothing can be
      // appended there without breaking a pinned test; "Checks" counts probe
      // cycles, a different thing from a run, so a run count there would
      // misattribute it; and inventing a sixth card was ruled out by the
      // original brief. runsToday already surfaces, unreliably, through the
      // greeting sentence above this row; both counts stay one click away on
      // the Runs page regardless.
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
      span.className = "s-success";
      span.textContent = "work found";
    } else if (pc.exit === 1) {
      span.textContent = "nothing to do";
    } else {
      span.className = "s-error";
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
      back.className = "s-warning";
      back.textContent = " \xB7 backing off " + backoff + "\xD7 after " + streak + " failed runs";
      wrap.appendChild(back);
    }
    return wrap;
  }
  function worktreesCard(items) {
    const kept = items || [];
    if (!kept.length) return null;
    const mk = (tag, cls, text) => {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    };
    const card = mk("div", "card");
    card.appendChild(mk("h2", null, "Sessions"));
    card.appendChild(mk(
      "div",
      "desc",
      "Run directories still on disk, kept because a session was cut short."
    ));
    kept.slice(0, 4).forEach((w) => {
      const row = mk("div", "cardline");
      row.appendChild(icon("folder"));
      row.appendChild(mk("span", "grow wtrow-name", w.job));
      row.appendChild(mk("span", "muted wtrow-size", w.size));
      card.appendChild(row);
    });
    const actions = mk("div", "actions");
    const btn = mk("button", "btn");
    btn.id = "ov-wt-view";
    btn.appendChild(icon("folder"));
    btn.appendChild(document.createTextNode(
      kept.length === 1 ? "View kept session" : "View " + kept.length + " kept sessions"
    ));
    actions.appendChild(btn);
    card.appendChild(actions);
    return card;
  }
  var DOW = ["", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function fmtDays(arr) {
    const a = [...new Set((arr || []).map(Number))].filter((n) => n >= 1 && n <= 7).sort((x, y) => x - y);
    if (!a.length) return "\u2014";
    const s = a.join(",");
    if (s === "1,2,3,4,5,6,7") return "Every day";
    if (s === "1,2,3,4,5") return "Mon\u2013Fri";
    if (s === "6,7") return "Sat\u2013Sun";
    return a.map((n) => DOW[n]).join(", ");
  }
  function checkList(output) {
    const raw = String(output || "").split("\n")[0];
    if (!raw) return null;
    const pairs = [...raw.matchAll(/([A-Za-z_]+)=(\S+)/g)];
    const rest = raw.replace(/[A-Za-z_]+=\S+/g, "").replace(/->/g, "\u2192").replace(/\s+/g, " ").trim();
    const items = pairs.map((m) => {
      const li = document.createElement("li");
      li.appendChild(document.createTextNode(m[1].replace(/_/g, " ") + ": "));
      li.appendChild(el("span", "ck-v", m[2]));
      return li;
    });
    if (rest) items.push(el("li", null, rest));
    if (!items.length) return null;
    const ul = el("ul", "checklist");
    items.forEach((li) => ul.appendChild(li));
    return ul;
  }
  function sessionNotices(jobId) {
    const kept = (CC.DATA.retained_worktrees || []).filter((w) => w.job === jobId);
    return kept.map((w) => {
      const left = fmtExpiresIn(w.expires_in);
      const until = left ? " \u2014 expires " + left : "";
      const line = el("div", "warnline");
      line.appendChild(icon("folder"));
      const grow = el("span", "grow");
      if (!w.session) {
        grow.textContent = "Holding a run directory with no session recorded" + until + " \u2014 it never got far enough to report one, so it cannot be resumed.";
        line.appendChild(grow);
        return line;
      }
      grow.textContent = "Holding a session that was cut short" + until + ".";
      line.appendChild(grow);
      if (resumeInFlight(jobId, w.session)) {
        const badge = el("span", "runningbadge");
        badge.appendChild(el("span", "pulse"));
        badge.appendChild(document.createTextNode("resuming\u2026"));
        line.appendChild(badge);
      } else {
        const btn = el("button", "btn");
        btn.dataset.op = "resume";
        btn.dataset.id = jobId;
        btn.dataset.session = w.session;
        btn.title = "Resume this task \u2014 continue session " + w.session.slice(0, 8) + " where it stopped";
        btn.appendChild(icon("play"));
        btn.appendChild(document.createTextNode("Resume"));
        line.appendChild(btn);
      }
      return line;
    });
  }
  function jobCard(j) {
    const F = jobFacts(j);
    const { st, chk, disabled, spentToday, cap, capped, nLive, idle } = F;
    const pc = st.last_precheck || null;
    const hasProbe = pc && typeof pc === "object";
    const card = el("div", "card" + (disabled ? " st-off" : ""));
    card.draggable = true;
    card.dataset.jobId = j.id;
    const h2 = el("h2");
    const nameSpan = el("span", "jobname");
    nameSpan.title = "Drag to reorder within the project";
    nameSpan.appendChild(icon("bot"));
    nameSpan.appendChild(document.createTextNode(j.id));
    h2.appendChild(nameSpan);
    const pillCls = disabled ? "disabled" : idle ? "idle" : "on";
    const pill = el("span", "pill " + pillCls, disabled ? "disabled" : idle ? "idle" : "enabled");
    if (idle) pill.title = "Outside its active window \u2014 no runs until the window reopens";
    h2.appendChild(pill);
    card.appendChild(h2);
    if (disabled && nLive) {
      const w = el("div", "warnline");
      w.appendChild(icon("alert"));
      w.appendChild(document.createTextNode(
        "Disabled \u2014 " + nLive + " run" + (nLive === 1 ? "" : "s") + " started earlier " + (nLive === 1 ? "is" : "are") + " still going. Stop " + (nLive === 1 ? "it" : "them") + " from the Runs table."
      ));
      card.appendChild(w);
    }
    sessionNotices(j.id).forEach((n) => card.appendChild(n));
    card.appendChild(el("div", "desc", j.description || ""));
    const series = Array.isArray(chk.series) ? chk.series : [];
    const woke = Array.isArray(chk.woke) ? chk.woke : [];
    const peak = series.reduce((m, n) => Math.max(m, n), 0);
    let spark;
    if (peak) {
      spark = el("span", "spark");
      spark.title = chk.checks + " checks in the last 24h, one bar an hour";
      series.forEach((n, i) => {
        const bar = el("i", woke[i] ? "w" : null);
        bar.style.height = (n ? Math.max(8, n / peak * 100).toFixed(0) : 0) + "%";
        spark.appendChild(bar);
      });
    } else {
      spark = icon("activity");
    }
    const sparkLine = el("div", "cardline");
    sparkLine.appendChild(spark);
    const sparkn = el("span", "sparkn grow");
    if (chk.checks) {
      sparkn.appendChild(el("b", null, String(chk.checks)));
      sparkn.appendChild(document.createTextNode(" check" + (chk.checks === 1 ? "" : "s") + " \xB7 "));
      sparkn.appendChild(el("b", null, String(chk.runs)));
      sparkn.appendChild(document.createTextNode(" woke a run"));
      if (chk.failed) {
        sparkn.appendChild(document.createTextNode(" \xB7 "));
        sparkn.appendChild(el("b", "s-error", chk.failed + " failed"));
      }
    } else {
      sparkn.textContent = disabled ? "no automatic checks \u2014 disabled" : "no automatic checks in 24h";
    }
    sparkLine.appendChild(sparkn);
    const runLine = el("div", "cardline");
    runLine.appendChild(icon("play"));
    const runGrow = el("span", "grow");
    if (nLive) {
      const badge = el("span", "runningbadge");
      badge.appendChild(el("span", "pulse"));
      badge.appendChild(document.createTextNode(nLive + " running now\u2026"));
      runGrow.appendChild(badge);
    }
    if (st.last_run_start) {
      runGrow.appendChild(el(
        "span",
        "muted",
        (nLive ? " \xB7 last ran " : "last ran ") + fmtAgo(st.last_run_start)
      ));
    } else if (!nLive) {
      runGrow.appendChild(el("span", "muted", "never ran"));
    }
    runLine.appendChild(runGrow);
    let probeLine = null;
    let checkItems = null;
    if (st.last_start || hasProbe) {
      const line = el("div", "cardline top");
      line.appendChild(icon("radar"));
      const grow = el("span", "grow");
      if (st.last_start) grow.appendChild(document.createTextNode("probed " + fmtAgo(st.last_start)));
      if (hasProbe) {
        grow.appendChild(document.createTextNode(st.last_start ? " \u2014 " : "last probe: "));
        grow.appendChild(probeVerdict(pc));
        checkItems = checkList(pc.output);
      }
      line.appendChild(grow);
      probeLine = line;
    }
    const cardstat = el("div", "cardstat");
    cardstat.appendChild(sparkLine);
    cardstat.appendChild(runLine);
    if (probeLine) cardstat.appendChild(probeLine);
    const cardbody = el("div", "cardbody" + (checkItems ? " has-checks" : ""));
    cardbody.appendChild(cardstat);
    if (checkItems) {
      const panel = el("div", "checkpanel");
      panel.appendChild(el("div", "cp-h", "Pre-checks"));
      panel.appendChild(checkItems);
      cardbody.appendChild(panel);
    }
    card.appendChild(cardbody);
    const nextLine = el("div", "cardline");
    nextLine.appendChild(icon("cright"));
    nextLine.appendChild(el("span", "lbl", "next"));
    const nextGrow = el("span", "grow");
    nextGrow.appendChild(nextRunNote(j, F));
    nextLine.appendChild(nextGrow);
    card.appendChild(nextLine);
    const model = eff(j, "model", "opus"), perm = eff(j, "permission_mode", "dontAsk"), budg = eff(j, "max_budget_usd", 2);
    const pct = cap != null && cap > 0 ? Math.min(100, spentToday / cap * 100) : 0;
    const tone = spendTone(spentToday, cap);
    const spend = el("div", "spend");
    if (cap != null) {
      const bar = el("div", "spendbar" + (tone ? " " + tone : ""));
      const fill = el("i");
      fill.style.width = pct.toFixed(1) + "%";
      bar.appendChild(fill);
      spend.appendChild(bar);
    }
    const spendtxt = el("div", "spendtxt");
    const left = el("span");
    left.appendChild(document.createTextNode(money(spentToday) + " today "));
    left.appendChild(cap != null ? el("span", "cap", "of " + money(cap)) : el("span", "muted", "\xB7 no daily cap"));
    spendtxt.appendChild(left);
    if (capped) spendtxt.appendChild(el("span", "s-error", "capped until midnight"));
    spend.appendChild(spendtxt);
    card.appendChild(spend);
    const p = j.project ? projById(j.project) : null;
    const own = (field) => j[field] != null && j[field] !== "" && p != null && String(j[field]) !== String(p[field] == null ? "" : p[field]);
    const bit = (txt, mine, cls) => el("span", mine ? cls || "o" : null, txt);
    const marked = (iconName, inner) => {
      const s = el("span", "cfgi");
      s.appendChild(icon(iconName));
      s.appendChild(inner);
      return s;
    };
    const cfg = el("div", "cfgline");
    cfg.appendChild(marked("timer", bit("every " + fmtDur(j.interval_seconds || 300), own("interval_seconds"))));
    cfg.appendChild(marked("clock", bit((j.active_hours || "24h") + " " + fmtDays(j.active_days || [1, 2, 3, 4, 5, 6, 7]), own("active_hours") || own("active_days"))));
    cfg.appendChild(bit(model, own("model")));
    if (effortLabel(eff(j, "effort", "")) !== "default") {
      cfg.appendChild(bit(effortLabel(eff(j, "effort", "")), own("effort")));
    }
    cfg.appendChild(marked("dollar", bit(money(budg) + "/run", own("max_budget_usd"))));
    cfg.appendChild(bit(perm, perm !== "dontAsk", "warn"));
    card.appendChild(cfg);
    const actions = el("div", "actions");
    const runBtn = el("button", "btn primary");
    runBtn.dataset.op = "run";
    runBtn.dataset.id = j.id;
    runBtn.appendChild(icon("play"));
    runBtn.appendChild(document.createTextNode("Run now"));
    actions.appendChild(runBtn);
    const toggleBtn = el("button", "btn");
    toggleBtn.dataset.op = disabled ? "enable" : "disable";
    toggleBtn.dataset.id = j.id;
    toggleBtn.appendChild(icon("power"));
    toggleBtn.appendChild(document.createTextNode(disabled ? "Enable" : "Disable"));
    actions.appendChild(toggleBtn);
    const editBtn = el("button", "btn");
    editBtn.dataset.op = "edit";
    editBtn.dataset.id = j.id;
    editBtn.appendChild(icon("pencil"));
    editBtn.appendChild(document.createTextNode("Edit"));
    actions.appendChild(editBtn);
    const menu = el("div", "menu");
    const menuBtn = el("button", "iconbtn");
    menuBtn.dataset.menu = j.id;
    menuBtn.setAttribute("aria-haspopup", "menu");
    menuBtn.setAttribute("aria-expanded", "false");
    menuBtn.title = "More actions";
    menuBtn.appendChild(icon("dots"));
    menu.appendChild(menuBtn);
    const pop = el("div", "menu-pop");
    pop.setAttribute("role", "menu");
    pop.hidden = true;
    const jobRunsBtn = el("button");
    jobRunsBtn.setAttribute("role", "menuitem");
    jobRunsBtn.dataset.jobruns = j.id;
    jobRunsBtn.appendChild(icon("activity"));
    jobRunsBtn.appendChild(document.createTextNode("Show this job's runs"));
    pop.appendChild(jobRunsBtn);
    pop.appendChild(el("div", "sep"));
    const delBtn = el("button", "danger");
    delBtn.setAttribute("role", "menuitem");
    delBtn.dataset.op = "delete";
    delBtn.dataset.id = j.id;
    delBtn.appendChild(icon("trash"));
    delBtn.appendChild(document.createTextNode("Delete job"));
    pop.appendChild(delBtn);
    menu.appendChild(pop);
    actions.appendChild(menu);
    card.appendChild(actions);
    return card;
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
        title: c.title,
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
    // sortJobs and JOB_COLS are Task 2 (phase 2)'s: renderJobTable
    // and renderJobHead in bin/dashboard.html call CCApp.sortJobs
    // and read CCApp.JOB_COLS instead of keeping their own copies,
    // the same "table is the second consumer" reach jobFacts and
    // visibleJobs already have above.
    sortJobs,
    JOB_COLS,
    groupJobs,
    jobsEmptyNote,
    worktreesCard,
    // pageHeader already has a second caller today, not a
    // future one: bin/dashboard.html's initPageHeaders() calls
    // CCApp.pageHeader() for the Jobs and Runs pages' own
    // headers, in this same phase. kpiCard and renderPulse are
    // the two still genuinely waiting -- Jobs and Runs have a
    // header now but no KPI row and no 24h band of their own,
    // and CCApp.renderOverviewHead's own two DOM builders are
    // exactly what the day one of them grows either will reach
    // for, the same way initPageHeaders reached for pageHeader.
    // renderOverviewHead remains the only one of the four this
    // phase's own call site (bin/dashboard.html's render())
    // actually calls itself.
    pageHeader,
    kpiCard,
    renderPulse,
    renderOverviewHead,
    // jobCard is Task 9's: renderJobs() in bin/dashboard.html
    // calls CCApp.jobCard(j) per job instead of building the
    // card as an HTML string. checkList and the kept-session
    // notice are internal to jobCard and have no other caller,
    // so they stay unexported, the same shape as el() above.
    jobCard
  };
})();
/* ui-bundle: 95ef56b6b934a82bb4a9d0811a155870be1b2dba667212a9649981ab46f9a08f */
/* ui-sources: 98e77745b1b3ff544083ff283fdae8c6fbcf041d54b7e3b45695157a70486a27 */
