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
  var fmtWhen;
  var fmtIn;
  var isFav;
  var TOKEN;
  var toast;
  var refresh;
  var paintJobPickers;
  var normStatus;
  var openLog;
  var resumeTarget;
  var resumeTip;
  var continuedRun;
  var resumedBadgeTip;
  var runKey;
  var isStopping;
  var unjournaledLive;
  var paintRunPickers;
  var runDateLabel;
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
      resumeInFlight,
      fmtWhen,
      fmtIn,
      isFav,
      TOKEN,
      toast,
      refresh,
      paintJobPickers,
      normStatus,
      openLog,
      resumeTarget,
      resumeTip,
      continuedRun,
      resumedBadgeTip,
      runKey,
      isStopping,
      unjournaledLive,
      paintRunPickers,
      runDateLabel
    } = cc);
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
  function filterBar(opts) {
    const { search, selects, actions } = opts;
    const bar = el("div", "toolbar");
    if (search) bar.appendChild(search);
    (selects || []).forEach((s) => {
      if (s) bar.appendChild(s);
    });
    bar.appendChild(el("div", "spacer"));
    (actions || []).forEach((a) => {
      if (a) bar.appendChild(a);
    });
    return bar;
  }
  function tableCard(opts) {
    const { columns, sortKey: sortKey4, sortDir: sortDir4, sortAttr, rows, footer } = opts;
    const headRow = el("tr");
    columns.forEach(([key, label]) => {
      if (!key) {
        headRow.appendChild(el("th", null, label));
        return;
      }
      const on = sortKey4 === key;
      const th = el("th", "sortable" + (on ? " sorted" : ""));
      th.dataset[sortAttr] = key;
      th.setAttribute("aria-sort", on ? sortDir4 < 0 ? "descending" : "ascending" : "none");
      th.title = "Sort by " + label.toLowerCase();
      th.appendChild(document.createTextNode(label));
      th.appendChild(icon(on && sortDir4 > 0 ? "sortasc" : "sortdesc"));
      headRow.appendChild(th);
    });
    const thead = el("thead");
    thead.appendChild(headRow);
    const tbody = el("tbody");
    rows.forEach((tr) => tbody.appendChild(tr));
    const table = el("table");
    table.appendChild(thead);
    table.appendChild(tbody);
    const scroll = el("div", "table-scroll");
    scroll.appendChild(table);
    const card = el("div", "table-card");
    card.appendChild(scroll);
    if (footer) card.appendChild(footer);
    return card;
  }
  function tableFooter(opts) {
    const {
      shown,
      total,
      noun,
      plural,
      page: page4,
      pages,
      prevId,
      nextId,
      infoId,
      numbered,
      collapse
    } = opts;
    const foot = el("div", "table-foot");
    const info = el(
      "span",
      "table-foot-info",
      "Showing " + shown.from + " to " + shown.to + " of " + total + " " + (total === 1 ? noun : plural || noun + "s")
    );
    if (infoId) info.id = infoId;
    foot.appendChild(info);
    if (numbered && pages <= 1) return foot;
    const nav = el("div", "table-foot-pager" + (numbered ? " numbered" : ""));
    const prev = el("button", numbered ? "iconbtn" : "btn ghost");
    if (prevId) prev.id = prevId;
    prev.appendChild(icon("cleft"));
    if (!numbered) prev.appendChild(document.createTextNode("Prev"));
    prev.disabled = page4 <= 1;
    nav.appendChild(prev);
    if (numbered) {
      let numberList;
      if (collapse && pages > 7) {
        const keep = /* @__PURE__ */ new Set([1, pages, page4 - 1, page4, page4 + 1]);
        const sorted = [...keep].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
        numberList = [];
        sorted.forEach((n, i) => {
          if (i > 0) {
            const gap = n - sorted[i - 1];
            if (gap === 2) numberList.push(sorted[i - 1] + 1);
            else if (gap > 2) numberList.push("\u2026");
          }
          numberList.push(n);
        });
      } else {
        numberList = [];
        for (let p = 1; p <= pages; p++) numberList.push(p);
      }
      numberList.forEach((n) => {
        if (n === "\u2026") {
          nav.appendChild(el("span", "pagebtn-ellipsis", "\u2026"));
          return;
        }
        const btn = el("button", "pagebtn" + (n === page4 ? " active" : ""), String(n));
        btn.type = "button";
        btn.dataset.page = String(n);
        if (n === page4) btn.disabled = true;
        nav.appendChild(btn);
      });
    }
    const next = el("button", numbered ? "iconbtn" : "btn ghost");
    if (nextId) next.id = nextId;
    if (!numbered) next.appendChild(document.createTextNode("Next"));
    next.appendChild(icon("cright"));
    next.disabled = page4 >= pages;
    nav.appendChild(next);
    foot.appendChild(nav);
    return foot;
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

  // ui/app/jobs-table.js
  function jobsHeaderSubtitle(jobs) {
    if (!jobs.length) return "Nothing configured yet \u2014 add a job to put the scheduler to work.";
    const enabled = jobs.filter((j) => j.enabled !== false).length;
    const disabled = jobs.length - enabled;
    const projects = new Set(jobs.map((j) => j.project).filter(Boolean)).size;
    const n = jobs.length;
    const projPart = projects ? " across " + projects + " project" + (projects === 1 ? "" : "s") : "";
    const offPart = disabled ? ", " + disabled + " disabled" : ", all enabled";
    return n + " job" + (n === 1 ? "" : "s") + projPart + offPart + ".";
  }
  function jobsKpis(jobs) {
    const total = jobs.length;
    const enabled = jobs.filter((j) => j.enabled !== false);
    const disabled = total - enabled.length;
    const facts = jobs.map((j) => jobFacts(j));
    const idle = facts.filter((F) => F.idle).length;
    const runningJobs = facts.filter((F) => F.running).length;
    const spentToday = facts.reduce((a, F) => a + F.spentToday, 0);
    const cappedCount = facts.filter((F) => F.capped).length;
    const pct = (num, den) => den ? Math.round(num / den * 100) + "%" : "\u2014";
    return [
      {
        label: "Total jobs",
        value: String(total),
        sub: disabled ? disabled + " disabled" : "all enabled",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Enabled",
        value: String(enabled.length),
        sub: !enabled.length ? "nothing enabled yet" : idle ? idle + " idle right now" : "all within their window",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Running now",
        value: String(runningJobs),
        sub: pct(runningJobs, enabled.length) + " of enabled jobs",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Spent today",
        value: money(spentToday),
        sub: cappedCount ? cappedCount + " at their cap" : "no jobs at cap",
        tone: "",
        filter: "",
        door: false
      }
    ];
  }
  var KPI_ICONS = {
    "Total jobs": "layers",
    "Enabled": "power",
    "Running now": "play",
    "Spent today": "dollar"
  };
  function mountJobsToolbar() {
    const host = $("jobstoolbar");
    if (!host || host.dataset.mounted) return;
    const bar = filterBar({
      search: $("jobsearchbox"),
      selects: [$("projpick"), $("statpick")],
      actions: [$("jf-clear"), $("bulk-all")]
    });
    host.insertBefore(bar, $("jactive"));
    host.dataset.mounted = "1";
  }
  function paintJobFilterBar(vis, allJobs) {
    paintJobPickers();
    const box = $("jactive");
    box.textContent = "";
    const chips = [];
    if (jobFilters.project) chips.push(["project", "Project: " + (jobFilters.project === "__none__" ? "Standalone" : jobFilters.project)]);
    if (jobFilters.status) chips.push(["status", "Status: " + jobFilters.status]);
    if (jobFilters.query.trim()) chips.push(["q", 'Search: "' + jobFilters.query.trim() + '"']);
    box.hidden = !chips.length;
    if (chips.length) {
      box.appendChild(el("span", "aflabel", "Active filters:"));
      chips.forEach(([key, label]) => {
        const chip = el("span", "afchip");
        chip.appendChild(document.createTextNode(label));
        const drop = el("button");
        drop.dataset.dropjf = key;
        drop.title = "Remove this filter";
        drop.appendChild(icon("x"));
        chip.appendChild(drop);
        box.appendChild(chip);
      });
      box.appendChild(el("span", "aflabel", vis.length + " of " + allJobs.length + " jobs"));
    }
    $("jf-clear").hidden = !chips.length;
    const ball = $("bulk-all");
    ball.hidden = !vis.length;
    if (vis.length) {
      const on = bulkOn(vis);
      ball.dataset.bulkKind = "visible";
      ball.dataset.bulk = "__visible__";
      ball.dataset.bulkTo = on ? "0" : "1";
      ball.textContent = "";
      ball.appendChild(icon("power"));
      ball.appendChild(document.createTextNode(bulkLabel(on, vis.length)));
    }
  }
  var sortKey = "job";
  var sortDir = 1;
  var page = 1;
  var PAGE_SIZE = 20;
  function jobsSort(key) {
    if (sortKey === key) sortDir = -sortDir;
    else {
      sortKey = key;
      sortDir = key === "job" || key === "project" || key === "state" ? 1 : -1;
    }
    page = 1;
    renderJobsPage();
  }
  function jobsSetPage(delta) {
    page += delta;
    renderJobsPage();
  }
  function jobRow(j, F) {
    const tr = el("tr", F.disabled ? "rowoff" : null);
    const tdJob = el("td");
    const jobcell = el("span", "jobcell");
    jobcell.appendChild(icon("bot"));
    jobcell.appendChild(el("code", null, j.id));
    tdJob.appendChild(jobcell);
    if (j.description) {
      const snip = el("div", "snip", j.description);
      snip.title = j.description;
      tdJob.appendChild(snip);
    }
    tr.appendChild(tdJob);
    const tdProj = el("td");
    if (j.project) {
      const tag = el("span", "projtag");
      tag.appendChild(icon("folder"));
      tag.appendChild(el("span", "projtag-name", j.project));
      if (isFav(j.project)) {
        const fav = el("span", "favdot");
        fav.title = "Favourite";
        fav.appendChild(icon("star"));
        tag.appendChild(fav);
      }
      tdProj.appendChild(tag);
    } else {
      tdProj.appendChild(el("span", "muted", "\u2014"));
    }
    tr.appendChild(tdProj);
    const tdState = el("td");
    if (F.running) {
      const badge = el("span", "runningbadge");
      badge.appendChild(el("span", "pulse"));
      badge.appendChild(document.createTextNode(F.nLive + " running\u2026"));
      tdState.appendChild(badge);
    } else {
      const pillCls = F.disabled ? "disabled" : F.idle ? "idle" : "on";
      const pill = el("span", "pill " + pillCls, F.state);
      if (F.idle) pill.title = "Outside its active window \u2014 no runs until the window reopens";
      tdState.appendChild(pill);
    }
    tr.appendChild(tdState);
    const tdSched = el("td", "nowrap");
    tdSched.appendChild(el("span", "muted", "every"));
    tdSched.appendChild(document.createTextNode(" " + fmtDur(j.interval_seconds || 300)));
    if (F.backoff > 1) {
      const back = el("span", "s-warning", " \xD7" + F.backoff);
      back.title = "Backing off after " + F.streak + " failed runs";
      tdSched.appendChild(back);
    }
    tr.appendChild(tdSched);
    const tdLast = el("td", "nowrap");
    if (F.st.last_run_start) {
      const span = el("span", null, fmtAgo(F.st.last_run_start));
      span.title = fmtWhen(F.st.last_run_start);
      tdLast.appendChild(span);
    } else {
      tdLast.appendChild(el("span", "muted", "never"));
    }
    tr.appendChild(tdLast);
    const tdNext = el("td", "nowrap");
    if (F.disabled) {
      tdNext.appendChild(el("span", "muted", "disabled"));
    } else if (F.nextAt == null) {
      tdNext.appendChild(el("span", "muted", "no window"));
    } else {
      const span = el("span", null, fmtIn(F.nextAt));
      span.title = fmtWhen(F.nextAt);
      tdNext.appendChild(span);
    }
    tr.appendChild(tdNext);
    const tdToday = el("td", "num nowrap");
    tdToday.appendChild(document.createTextNode(money(F.spentToday)));
    if (F.cap != null) {
      tdToday.appendChild(document.createTextNode(" "));
      tdToday.appendChild(el("span", "cap", "of " + money(F.cap)));
    }
    if (F.capped) {
      tdToday.appendChild(document.createTextNode(" "));
      tdToday.appendChild(el("span", "s-error", "capped"));
    }
    tr.appendChild(tdToday);
    const tdActs = el("td", "rowacts");
    const run = el("button", "iconbtn");
    run.dataset.op = "run";
    run.dataset.id = j.id;
    run.title = "Run now";
    run.appendChild(icon("play"));
    tdActs.appendChild(run);
    const toggle = el("button", "iconbtn");
    toggle.dataset.op = F.disabled ? "enable" : "disable";
    toggle.dataset.id = j.id;
    toggle.title = F.disabled ? "Enable" : "Disable";
    toggle.appendChild(icon("power"));
    tdActs.appendChild(toggle);
    const editBtn = el("button", "iconbtn");
    editBtn.dataset.op = "edit";
    editBtn.dataset.id = j.id;
    editBtn.title = "Edit";
    editBtn.appendChild(icon("pencil"));
    tdActs.appendChild(editBtn);
    const del = el("button", "iconbtn danger");
    del.dataset.op = "delete";
    del.dataset.id = j.id;
    del.title = "Delete job";
    del.appendChild(icon("trash"));
    tdActs.appendChild(del);
    tr.appendChild(tdActs);
    return tr;
  }
  function renderJobsTable(vis) {
    const sorted = sortJobs(vis.map((j) => ({ j, F: jobFacts(j) })), sortKey, sortDir);
    const total = sorted.length;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    if (page > pages) page = pages;
    if (page < 1) page = 1;
    const from = total ? (page - 1) * PAGE_SIZE + 1 : 0;
    const to = Math.min(page * PAGE_SIZE, total);
    const slice = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
    let rows;
    if (!total) {
      const filtering = !!(jobFilters.project || jobFilters.status || jobFilters.query.trim());
      const tr = el("tr");
      const td = el("td", "tblempty");
      td.colSpan = JOB_COLS.length;
      td.appendChild(icon("inbox"));
      td.appendChild(document.createTextNode(jobsEmptyNote(filtering)));
      tr.appendChild(td);
      rows = [tr];
    } else {
      rows = slice.map(({ j, F }) => jobRow(j, F));
    }
    const footer = tableFooter({
      shown: { from, to },
      total,
      noun: "job",
      page,
      pages,
      prevId: "jobs-pg-prev",
      nextId: "jobs-pg-next",
      infoId: "jobs-pg-info"
    });
    const card = tableCard({
      columns: JOB_COLS,
      sortKey,
      sortDir,
      sortAttr: "jobsort",
      rows,
      footer
    });
    const host = $("jobs-table");
    host.textContent = "";
    host.appendChild(card);
  }
  function renderJobsPage() {
    mountJobsToolbar();
    const jobs = CC.DATA.jobs || [];
    const allProjects = [...new Set(jobs.map((j) => j.project || "").filter(Boolean))].sort();
    if (jobFilters.project && jobFilters.project !== "__none__" && !allProjects.includes(jobFilters.project)) jobFilters.project = "";
    const vis = visibleJobs();
    const headHost = $("jobs-head");
    if (headHost) {
      headHost.textContent = "";
      headHost.appendChild(pageHeader({
        icon: "zap",
        title: "Jobs",
        subtitle: jobsHeaderSubtitle(jobs),
        actions: [
          { id: "jobs-refresh", icon: "radar", label: "Refresh" },
          { id: "new-job", icon: "plus", label: "New job", primary: true }
        ]
      }));
    }
    const kpiHost = $("jobs-kpis");
    if (kpiHost) {
      kpiHost.textContent = "";
      jobsKpis(jobs).forEach((c) => kpiHost.appendChild(kpiCard({
        icon: KPI_ICONS[c.label],
        tone: c.tone,
        value: c.value,
        label: c.label,
        sub: c.sub,
        filter: c.filter,
        door: c.door
      })));
    }
    paintJobFilterBar(vis, jobs);
    renderJobsTable(vis);
  }
  var _dragId = null;
  function initJobDrag() {
    const host = $("jobs");
    if (!host) return;
    host.addEventListener("dragstart", (e) => {
      const c = e.target.closest(".card[data-job-id]");
      if (!c) return;
      _dragId = c.dataset.jobId;
      c.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      try {
        e.dataTransfer.setData("text/plain", _dragId);
      } catch (_) {
      }
    });
    host.addEventListener("dragend", () => {
      _dragId = null;
      host.querySelectorAll(".dragging,.dragover").forEach((x) => x.classList.remove("dragging", "dragover"));
    });
    host.addEventListener("dragover", (e) => {
      if (!_dragId) return;
      const over = e.target.closest(".card[data-job-id]");
      const from = host.querySelector('.card[data-job-id="' + CSS.escape(_dragId) + '"]');
      if (!over || !from || over === from || over.closest(".grid") !== from.closest(".grid")) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      host.querySelectorAll(".dragover").forEach((x) => x.classList.remove("dragover"));
      over.classList.add("dragover");
    });
    host.addEventListener("drop", async (e) => {
      const over = e.target.closest(".card[data-job-id]");
      const from = _dragId && host.querySelector('.card[data-job-id="' + CSS.escape(_dragId) + '"]');
      if (!over || !from || over === from || over.closest(".grid") !== from.closest(".grid")) return;
      e.preventDefault();
      const grid = over.closest(".grid");
      const cards = [...grid.querySelectorAll(".card[data-job-id]")];
      grid.insertBefore(from, cards.indexOf(from) < cards.indexOf(over) ? over.nextSibling : over);
      over.classList.remove("dragover");
      const order = [...grid.querySelectorAll(".card[data-job-id]")].map((c) => c.dataset.jobId);
      _dragId = null;
      const r = await fetch("/api/action", {
        method: "POST",
        headers: { "Content-Type": "text/plain", "X-CC-Token": TOKEN },
        body: JSON.stringify({ op: "reorder", order })
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        toast("Could not save the order \u2014 " + (j.error || "HTTP " + r.status), true);
      } else toast("Order saved", false, "check");
      refresh();
    });
  }

  // ui/app/projects.js
  var projFilters = { query: "" };
  function visibleProjects() {
    const jobs = CC.DATA.jobs || [];
    const q = projFilters.query.trim().toLowerCase();
    return (CC.DATA.projects || []).map((p) => Object.assign({}, p, {
      _jobs: jobs.filter((j) => j.project === p.name).length,
      _repos: (p.repos || []).length
    })).filter((p) => !q || (p.name + " " + (p.description || "") + " " + (p.cwd || "")).toLowerCase().includes(q));
  }
  function projectIsolation(p) {
    const wt = p.worktree && p.worktree.enabled;
    return wt === true || wt === "true" ? ["on", "always"] : wt === false || wt === "false" ? ["off", "never"] : ["auto", "auto"];
  }
  function projectSecurity(p) {
    const sec = p.security;
    const enabled = !!(sec && typeof sec === "object" && (sec.enabled === true || sec.enabled === "true"));
    if (!enabled) return { state: "disabled", cls: "disabled", label: "Disabled" };
    const runs = (CC.DATA.runs || []).filter((r) => r.project === p.name && String(r.id || "").startsWith("security-"));
    if (!runs.length) return { state: "unanalysed", cls: "idle", label: "Never analysed" };
    const last = runs.reduce((a, b) => a.start > b.start ? a : b);
    return { state: "analysed", cls: "on", label: "Analysed", lastAt: last.start };
  }
  function projectsKpis(rows) {
    const total = rows.length;
    const withJobs = rows.filter((p) => p._jobs > 0).length;
    const jobsTotal = rows.reduce((a, p) => a + p._jobs, 0);
    const secStates = rows.map((p) => projectSecurity(p).state);
    const secEnabled = secStates.filter((s) => s !== "disabled").length;
    const secAnalysed = secStates.filter((s) => s === "analysed").length;
    const isoStates = rows.map((p) => projectIsolation(p)[0]);
    const isolated = isoStates.filter((s) => s === "on").length;
    const neverIsolated = isoStates.filter((s) => s === "off").length;
    const autoIsolated = isoStates.filter((s) => s === "auto").length;
    return [
      {
        label: "Projects",
        value: String(total),
        sub: !total ? "none configured yet" : total - withJobs ? total - withJobs + " with no jobs of their own" : "every one has a job",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Jobs organised",
        value: String(jobsTotal),
        // Rounded to one decimal, THEN handed to a Number rather than kept as a
        // fixed string -- two projects with four jobs each is a count ("4 per
        // project"), not a float wearing a trailing zero ("4.0"); two with four
        // and five is genuinely fractional ("4.5") and keeps its one digit.
        // `.toFixed(1)` always printed the zero; `Math.round(...)/10` produces
        // a Number, and Number#toString() drops it on its own.
        sub: total ? Math.round(jobsTotal / total * 10) / 10 + " per project" : "no projects yet",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Security enabled",
        value: String(secEnabled),
        sub: !secEnabled ? "none turned on yet" : secAnalysed + " analysed at least once",
        tone: "",
        filter: "",
        door: false
      },
      // Isolation is three states, not two (see projectIsolation's own
      // comment) -- `isolated` counts only "always" (`on`). Pairing it with
      // `neverIsolated` (`off`) alone used to fall back to "none set to never"
      // whenever off was zero, a sublabel that names a state nobody asked
      // about and never mentions the one the headline number actually counts
      // (checked against config/projects.json: Minerva is "always", Quality
      // Gate is "auto", so `off` is 0 and the reader saw "Isolated 1 / none
      // set to never" -- two facts about two different things, not one).
      // `off`, when it is the more informative of the remaining two states,
      // still leads; `auto` -- the state a real fleet is more likely to have
      // nonzero, since it is also what an unconfigured project defaults to --
      // is the fallback that keeps the pair naming an actual state instead of
      // the absence of one.
      {
        label: "Isolated",
        value: String(isolated),
        sub: neverIsolated ? neverIsolated + " never isolate" : autoIsolated ? autoIsolated + " left automatic" : total ? "every project isolates" : "no projects yet",
        tone: "",
        filter: "",
        door: false
      }
    ];
  }
  var KPI_ICONS2 = {
    "Projects": "folder",
    "Jobs organised": "layers",
    "Security enabled": "shield",
    "Isolated": "cpu"
  };
  function projectsHeaderSubtitle(rows) {
    if (!rows.length) return "Nothing configured yet \u2014 a project gives a group of jobs somewhere to inherit from.";
    const n = rows.length;
    const withJobs = rows.filter((p) => p._jobs > 0).length;
    const secOn = rows.filter((p) => projectSecurity(p).state !== "disabled").length;
    const jobsPart = withJobs === n ? ", every one with jobs of its own" : withJobs ? ", " + withJobs + " with jobs of their own" : ", none with jobs of their own yet";
    const secPart = secOn ? ", " + secOn + " with security enabled" : "";
    return n + " project" + (n === 1 ? "" : "s") + jobsPart + secPart + ".";
  }
  function mountProjectsToolbar() {
    const host = $("prjtoolbar");
    if (!host || host.dataset.mounted) return;
    const bar = filterBar({ search: $("projsearchbox") });
    host.appendChild(bar);
    host.dataset.mounted = "1";
  }
  function projectsEmptyNote(filtering) {
    return filtering ? "No projects match that search." : "No projects yet \u2014 a job does not need one, but jobs that share a repo do.";
  }
  var PRJ_COLS = [
    ["name", "Project"],
    ["jobs", "Jobs"],
    [null, "Working directory"],
    ["repos", "Repos"],
    [null, "Isolation"],
    [null, "Security"],
    [null, ""]
  ];
  var PRJ_SORTERS = {
    name: { cmp: (a, b) => String(a.name).localeCompare(String(b.name)) },
    jobs: {
      cmp: (a, b) => a._jobs - b._jobs,
      tie: (a, b) => String(a.name).localeCompare(String(b.name))
    },
    repos: {
      cmp: (a, b) => a._repos - b._repos,
      tie: (a, b) => String(a.name).localeCompare(String(b.name))
    }
  };
  var sortKey2 = "name";
  var sortDir2 = 1;
  var page2 = 1;
  var PAGE_SIZE2 = 20;
  function projectsSort(key) {
    if (sortKey2 === key) sortDir2 = -sortDir2;
    else {
      sortKey2 = key;
      sortDir2 = key === "name" ? 1 : -1;
    }
    page2 = 1;
    renderProjectsPage();
  }
  function projectsSetPage(delta) {
    page2 += delta;
    renderProjectsPage();
  }
  function projectRow(p) {
    const tr = el("tr");
    const tdName = el("td");
    const cell = el("span", "jobcell");
    cell.appendChild(icon("folder"));
    cell.appendChild(el("b", null, p.name));
    const fav = isFav(p.name);
    const favBtn = el("button", "favstar" + (fav ? " on" : ""));
    favBtn.dataset.fav = p.name;
    favBtn.setAttribute("aria-pressed", fav ? "true" : "false");
    favBtn.title = fav ? "Remove from favourites" : "Favourite \u2014 keeps this project at the top of Jobs";
    favBtn.appendChild(icon("star"));
    cell.appendChild(favBtn);
    tdName.appendChild(cell);
    if (p.description) {
      const snip = el("div", "snip", p.description);
      snip.title = p.description;
      tdName.appendChild(snip);
    }
    tr.appendChild(tdName);
    tr.appendChild(el("td", "num nowrap", String(p._jobs)));
    const tdCwd = el("td");
    if (p.cwd) {
      const code = el("code", "pathcell", p.cwd);
      code.title = p.cwd;
      tdCwd.appendChild(code);
    } else {
      tdCwd.appendChild(el("span", "muted", "\u2014"));
    }
    tr.appendChild(tdCwd);
    const tdRepos = el("td", "nowrap");
    if (p._repos) tdRepos.appendChild(document.createTextNode(p._repos + " repo" + (p._repos === 1 ? "" : "s")));
    else tdRepos.appendChild(el("span", "muted", "single"));
    tr.appendChild(tdRepos);
    const tdIso = el("td", "nowrap");
    const iso = projectIsolation(p);
    tdIso.appendChild(el("span", "isopill " + iso[0], iso[1]));
    tr.appendChild(tdIso);
    const tdSec = el("td", "nowrap");
    const sec = projectSecurity(p);
    const pill = el("span", "pill " + sec.cls, sec.label);
    if (sec.state === "analysed") pill.title = "Last analysed " + fmtWhen(sec.lastAt);
    tdSec.appendChild(pill);
    tr.appendChild(tdSec);
    const tdActs = el("td", "rowacts");
    const editBtn = el("button", "iconbtn");
    editBtn.dataset.editproj = p.name;
    editBtn.title = "Edit project";
    editBtn.appendChild(icon("pencil"));
    tdActs.appendChild(editBtn);
    const delBtn = el("button", "iconbtn danger");
    delBtn.dataset.delproj = p.name;
    delBtn.title = "Delete project";
    delBtn.appendChild(icon("trash"));
    tdActs.appendChild(delBtn);
    tr.appendChild(tdActs);
    return tr;
  }
  function renderProjectsTable(vis) {
    const S = PRJ_SORTERS[sortKey2] || PRJ_SORTERS.name;
    const sorted = [...vis].sort((a, b) => S.cmp(a, b) * sortDir2 || (S.tie ? S.tie(a, b) : 0));
    const total = sorted.length;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE2));
    if (page2 > pages) page2 = pages;
    if (page2 < 1) page2 = 1;
    const from = total ? (page2 - 1) * PAGE_SIZE2 + 1 : 0;
    const to = Math.min(page2 * PAGE_SIZE2, total);
    const slice = sorted.slice((page2 - 1) * PAGE_SIZE2, page2 * PAGE_SIZE2);
    let rows;
    if (!total) {
      const filtering = !!projFilters.query.trim();
      const tr = el("tr");
      const td = el("td", "tblempty");
      td.colSpan = PRJ_COLS.length;
      td.appendChild(icon("inbox"));
      td.appendChild(document.createTextNode(projectsEmptyNote(filtering)));
      tr.appendChild(td);
      rows = [tr];
    } else {
      rows = slice.map((p) => projectRow(p));
    }
    const footer = tableFooter({
      shown: { from, to },
      total,
      noun: "project",
      page: page2,
      pages,
      prevId: "prj-pg-prev",
      nextId: "prj-pg-next",
      infoId: "prj-pg-info"
    });
    const card = tableCard({
      columns: PRJ_COLS,
      sortKey: sortKey2,
      sortDir: sortDir2,
      sortAttr: "prjsort",
      rows,
      footer
    });
    const host = $("prj-table");
    host.textContent = "";
    host.appendChild(card);
  }
  function renderProjectsPage() {
    mountProjectsToolbar();
    const rows = visibleProjects();
    const headHost = $("prj-head");
    if (headHost) {
      headHost.textContent = "";
      headHost.appendChild(pageHeader({
        icon: "folder",
        title: "Projects",
        subtitle: projectsHeaderSubtitle(rows),
        actions: [{ id: "new-project", icon: "plus", label: "New project", primary: true }]
      }));
    }
    const kpiHost = $("prj-kpis");
    if (kpiHost) {
      kpiHost.textContent = "";
      projectsKpis(rows).forEach((c) => kpiHost.appendChild(kpiCard({
        icon: KPI_ICONS2[c.label],
        tone: c.tone,
        value: c.value,
        label: c.label,
        sub: c.sub,
        filter: c.filter,
        door: c.door
      })));
    }
    $("pq-clear").hidden = !projFilters.query;
    renderProjectsTable(rows);
  }

  // ui/app/runs.js
  var RF = { project: "", job: "", status: "", from: "", to: "" };
  var SORTERS = {
    when: (a, b) => a.start - b.start,
    job: (a, b) => String(a.id).localeCompare(String(b.id)) || a.start - b.start,
    status: (a, b) => String(a.live ? "running" : normStatus(a.status)).localeCompare(String(b.live ? "running" : normStatus(b.status))) || a.start - b.start,
    cost: (a, b) => (a.cost || 0) - (b.cost || 0) || a.start - b.start,
    duration: (a, b) => (a.duration || 0) - (b.duration || 0) || a.start - b.start
  };
  function filteredRuns(rf, liveRows, searchKeys2, sortKey4, sortDir4) {
    const fromT = rf.from ? Date.parse(rf.from) : null, toT = rf.to ? Date.parse(rf.to) : null;
    const live = searchKeys2 ? [] : liveRows;
    const rows = live.concat(CC.DATA.runs).filter((r) => {
      if (r.live) {
        if (rf.project) {
          const rp = r.project || "";
          if (rf.project === "__none__" ? rp !== "" : rp !== rf.project) return false;
        }
        if (rf.job && r.id !== rf.job) return false;
        if (rf.status && rf.status !== "running") return false;
        return true;
      }
      if (searchKeys2 && !searchKeys2.has(r.id + "|" + r.start)) return false;
      if (rf.project) {
        const rp = r.project || "";
        if (rf.project === "__none__" ? rp !== "" : rp !== rf.project) return false;
      }
      if (rf.job && r.id !== rf.job) return false;
      if (rf.status && normStatus(r.status) !== rf.status) return false;
      const t = r.start * 1e3;
      if (fromT && t < fromT) return false;
      if (toT && t > toT) return false;
      return true;
    });
    if (sortKey4 !== "when" || sortDir4 !== -1) {
      const cmp = SORTERS[sortKey4] || SORTERS.when;
      rows.sort((a, b) => cmp(a, b) * sortDir4);
    }
    return rows;
  }
  function runsHeaderSubtitle(runs, liveCount) {
    const total = runs.length + liveCount;
    if (!total) return "Nothing recorded yet \u2014 a run appears here the moment a job wakes.";
    const t0 = Math.floor((/* @__PURE__ */ new Date()).setHours(0, 0, 0, 0) / 1e3);
    const today = runs.filter((r) => r.start >= t0).length + liveCount;
    return total + " run" + (total === 1 ? "" : "s") + " on record, " + today + " today.";
  }
  function runsKpis(runs, liveCount) {
    const t0 = Math.floor((/* @__PURE__ */ new Date()).setHours(0, 0, 0, 0) / 1e3);
    const wk = Math.floor(Date.now() / 1e3) - 7 * 86400;
    const total = runs.length + liveCount;
    const finished = runs.length;
    const recent = runs.filter((r) => r.start >= wk);
    const warnCount = recent.filter((r) => normStatus(r.status) === "warning").length;
    const errCount = recent.filter((r) => normStatus(r.status) === "error").length;
    const todayCount = runs.filter((r) => r.start >= t0).length + liveCount;
    return [
      // The server's own cap (see above) makes `total` a FLOOR at that cap,
      // not a true total -- "1000 runs on record" reads as a complete count
      // when the 1001st-oldest run is sitting right there, uncounted, in the
      // same database. `finished` rather than `total`: the live count on top
      // does not change what the journaled cap has already thrown away.
      {
        label: "Total runs",
        value: finished >= 1e3 ? "1000+" : String(total),
        sub: todayCount + " today",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Running now",
        value: String(liveCount),
        sub: liveCount ? "following live" : "none in flight",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Warnings",
        value: String(warnCount),
        sub: "in the last 7 days",
        title: "Runs that finished without failing but did not do the work",
        tone: "",
        filter: "",
        door: false
      },
      {
        label: "Errors",
        value: String(errCount),
        sub: "in the last 7 days",
        title: "Runs that failed",
        tone: "",
        filter: "",
        door: false
      }
    ];
  }
  var KPI_ICONS3 = {
    "Total runs": "layers",
    "Running now": "play",
    "Warnings": "alert",
    "Errors": "xcircle"
  };
  function mountRunsToolbar() {
    const host = $("runstoolbar");
    if (!host || host.dataset.mounted) return;
    const bar = filterBar({
      search: $("searchbox"),
      selects: [$("rprojpick"), $("rjobpick"), $("rstatpick"), $("rdatepick")],
      actions: [$("f-clear"), $("rsizepick")]
    });
    host.insertBefore(bar, $("ractive"));
    host.dataset.mounted = "1";
  }
  function paintRunFilters(shown) {
    paintRunPickers();
    const box = $("ractive");
    box.textContent = "";
    const chips = [];
    if (RF.project) chips.push(["project", "Project: " + (RF.project === "__none__" ? "No project" : RF.project)]);
    if (RF.job) chips.push(["job", "Job: " + RF.job]);
    if (RF.status) chips.push(["status", "Status: " + RF.status]);
    if (RF.from || RF.to) chips.push(["date", "Date: " + runDateLabel()]);
    const q = $("q").value.trim();
    if (q) chips.push(["q", 'Search: "' + q + '"']);
    box.hidden = !chips.length;
    if (chips.length) {
      box.appendChild(el("span", "aflabel", "Active filters:"));
      chips.forEach(([key, label]) => {
        const chip = el("span", "afchip");
        chip.appendChild(document.createTextNode(label));
        const drop = el("button");
        drop.dataset.droprf = key;
        drop.title = "Remove this filter";
        drop.appendChild(icon("x"));
        chip.appendChild(drop);
        box.appendChild(chip);
      });
      box.appendChild(el("span", "aflabel", shown + " of " + (CC.DATA.runs || []).length + " runs"));
    }
    $("f-clear").hidden = !chips.length;
  }
  var sortKey3 = "when";
  var sortDir3 = -1;
  var page3 = 1;
  var pageSize = parseInt(localStorage.ccPageSize || "25", 10) || 25;
  var searchKeys = null;
  var snippets = {};
  var searchSeq = 0;
  function runsSort(key) {
    if (sortKey3 === key) sortDir3 = -sortDir3;
    else {
      sortKey3 = key;
      sortDir3 = key === "job" || key === "status" ? 1 : -1;
    }
    page3 = 1;
    renderRunsPage();
  }
  function runsSetPage(delta) {
    page3 += delta;
    renderRunsPage();
  }
  function runsFilterChanged() {
    page3 = 1;
    renderRunsPage();
  }
  function runsGotoFirstPage() {
    page3 = 1;
  }
  function runsSetPageSize(n) {
    pageSize = n;
    localStorage.ccPageSize = n;
    page3 = 1;
    renderRunsPage();
  }
  function runsPageSize() {
    return pageSize;
  }
  function clearRunFilters() {
    RF.project = RF.job = RF.status = RF.from = RF.to = "";
    $("f-from").value = "";
    $("f-to").value = "";
    $("q").value = "";
    $("q-clear").hidden = true;
    page3 = 1;
    runSearch("");
  }
  async function runSearch(q) {
    const seq = ++searchSeq;
    if (!q || q.trim().length < 2) {
      searchKeys = null;
      snippets = {};
      renderRunsPage();
      return;
    }
    try {
      const r = await fetch("/api/search?q=" + encodeURIComponent(q.trim()), { headers: { "X-CC-Token": TOKEN } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      if (seq !== searchSeq) return;
      searchKeys = /* @__PURE__ */ new Set();
      snippets = {};
      (j.results || []).forEach((x) => {
        const k = x.id + "|" + x.start;
        searchKeys.add(k);
        if (x.snippet) snippets[k] = x.snippet;
      });
      page3 = 1;
      renderRunsPage();
    } catch (e) {
      if (seq === searchSeq) toast("Search failed \u2014 " + e.message, true);
    }
  }
  function runProjectNames() {
    return [...new Set((CC.DATA.runs || []).map((r) => r.project || "").filter(Boolean))].sort();
  }
  function nothingNote(r) {
    const n = r && r.note || "";
    const i = n.indexOf("NOTHING TO DO:");
    return i < 0 ? "" : n.slice(i + "NOTHING TO DO:".length).trim();
  }
  function livePidFor(id) {
    const a = (CC.DATA.active_runs || {})[id] || [];
    return a.length ? a[0].pid : "";
  }
  var STATUS_ICON_NAME = {
    success: "check",
    warning: "alert",
    error: "xcircle",
    idle: "clock",
    running: "timer",
    stopped: "power"
  };
  var CAUSE_LABEL = {
    api_error: ["API", "the API refused a turn \u2014 the provider's fault, not this job's, and it does not count towards the failure backoff"],
    rate_limited: ["limit", "the account is over its rate or usage limit \u2014 it does not count towards the failure backoff"],
    tools_denied: ["blocked", "the agent asked for a tool it is not allowed, so it could not do the work"],
    killed: ["killed", "the run was cut off \u2014 a watchdog, a crash, or a kill \u2014 and never reported a result"],
    agent_error: ["agent", "the agent itself ended in error"]
  };
  function causeTag(rec) {
    const c = CAUSE_LABEL[rec && rec.cause || ""];
    if (!c) return null;
    const tag = el("span", "causetag", c[0]);
    tag.title = c[1];
    return tag;
  }
  var RUN_COLS = [
    ["when", "When"],
    ["job", "Job"],
    [null, "Project"],
    ["status", "Status"],
    ["duration", "Duration"],
    ["cost", "Cost"],
    [null, "Session"],
    [null, ""]
  ];
  function runRow(r) {
    const tr = el("tr");
    const s = normStatus(r.status);
    const snip = searchKeys ? snippets[r.id + "|" + r.start] || "" : "";
    const resumable = s === "error" || s === "warning" || s === "stopped";
    const isSec = String(r.id || "").startsWith("security-");
    const followUp = resumable ? resumeTarget(r.id, r.start) : null;
    const parent = continuedRun(r);
    const tdWhen = el("td", "num");
    const when = el("span", "when-rel", fmtAgo(r.start));
    when.title = fmtWhen(r.start);
    tdWhen.appendChild(when);
    if (r.forced) tdWhen.appendChild(el("span", "trigger-badge", "forced"));
    if (parent) {
      const badge = el("span", "trigger-badge resumed", "resumed");
      badge.dataset.tip = encodeURIComponent(resumedBadgeTip(parent));
      tdWhen.appendChild(badge);
    }
    if (snip) {
      const snipEl = el("div", "snip", snip);
      snipEl.title = snip;
      tdWhen.appendChild(snipEl);
    }
    tr.appendChild(tdWhen);
    const tdJob = el("td");
    tdJob.appendChild(el("code", null, r.id));
    tr.appendChild(tdJob);
    const tdProject = el("td");
    if (r.project) {
      const tag = el("span", "projtag");
      tag.appendChild(icon("folder"));
      tag.appendChild(el("span", "projtag-name", r.project));
      tdProject.appendChild(tag);
    } else {
      tdProject.appendChild(el("span", "muted", "\u2014"));
    }
    tr.appendChild(tdProject);
    const tdStatus = el("td");
    if (r.live) {
      const badge = el("span", "runningbadge" + (isStopping(r) ? " stopping" : ""));
      badge.appendChild(el("span", "pulse"));
      badge.appendChild(document.createTextNode(isStopping(r) ? "stopping\u2026" : "running\u2026"));
      tdStatus.appendChild(badge);
    } else {
      const cell = el("span", "stat-cell s-" + s);
      cell.appendChild(icon(STATUS_ICON_NAME[s] || "clock"));
      cell.appendChild(document.createTextNode(s));
      tdStatus.appendChild(cell);
      const cause = causeTag(r);
      if (cause) tdStatus.appendChild(cause);
      if (resumable && followUp) {
        const badge = el("span", "tipbadge", "?");
        badge.dataset.tip = encodeURIComponent(resumeTip(r.id, r.start));
        tdStatus.appendChild(badge);
      } else {
        const note = nothingNote(r);
        if (note) {
          const badge = el("span", "tipbadge", "?");
          badge.dataset.tip = encodeURIComponent("Nothing was done in this run \u2014 " + note);
          tdStatus.appendChild(badge);
        }
      }
    }
    tr.appendChild(tdStatus);
    const tdDuration = el("td", "num");
    tdDuration.appendChild(document.createTextNode(fmtDur(r.duration)));
    if (r.live) {
      tdDuration.appendChild(document.createTextNode(" "));
      tdDuration.appendChild(el("span", "muted", "so far"));
    }
    tr.appendChild(tdDuration);
    const tdCost = el("td", "num");
    if (r.live) tdCost.appendChild(el("span", "muted", "\u2014"));
    else tdCost.appendChild(document.createTextNode(money(r.cost)));
    tr.appendChild(tdCost);
    const tdSession = el("td");
    tdSession.appendChild(el("code", null, (r.session || "").slice(0, 8) || "\u2014"));
    tr.appendChild(tdSession);
    const tdActs = el("td", "rowacts");
    const view = el("button", "iconbtn" + (r.live ? " live" : ""));
    view.title = r.live ? "Follow this run live" : "View log";
    view.appendChild(icon("eye"));
    view.addEventListener("click", () => openLog(r.id, r.start));
    tdActs.appendChild(view);
    const stop = el("button", "iconbtn" + (r.live ? " danger" : ""));
    stop.appendChild(icon("power"));
    if (r.live) {
      if (isStopping(r)) {
        stop.disabled = true;
        stop.title = "Already stopping \u2014 waiting for it to wind down";
      } else {
        stop.title = "Stop this run";
        stop.dataset.op = "stop";
        stop.dataset.id = r.id;
        stop.dataset.runPid = r.pid || livePidFor(r.id);
      }
    } else {
      stop.disabled = true;
      stop.title = "This run has already finished \u2014 only a running run can be stopped";
    }
    tdActs.appendChild(stop);
    const retry = el("button", "iconbtn retry");
    retry.appendChild(icon("play"));
    if (r.live) {
      retry.disabled = true;
      retry.title = "This run is still going";
    } else if (isSec) {
      retry.disabled = true;
      retry.title = "A security analysis is never resumed \u2014 its request was consumed when it ran. Launch a fresh one from the Security area";
    } else if (resumable) {
      if (!r.session) {
        retry.disabled = true;
        retry.title = "This run recorded no session id, so it cannot be resumed";
      } else if (followUp) {
        retry.disabled = true;
        retry.title = (followUp.running ? "A newer run is in progress" : "This task was already resumed") + " \u2014 see the ? beside the status";
      } else {
        retry.title = "Resume this task \u2014 continue session " + (r.session || "").slice(0, 8) + " where it stopped";
        retry.dataset.op = "resume";
        retry.dataset.id = r.id;
        retry.dataset.session = r.session || "";
        retry.dataset.resumeKey = runKey(r.id, r.start);
      }
    } else {
      retry.disabled = true;
      retry.title = "Only a failed, warning or stopped run can be resumed";
    }
    tdActs.appendChild(retry);
    const del = el("button", "iconbtn" + (r.live || isSec ? "" : " danger"));
    del.appendChild(icon("trash"));
    if (r.live) {
      del.disabled = true;
      del.title = "A running run cannot be deleted \u2014 stop it first";
    } else if (isSec) {
      del.disabled = true;
      del.title = "This run is a security analysis's evidence \u2014 the Security area owns its lifecycle";
    } else {
      del.title = "Delete this run and everything it left behind";
      del.dataset.delId = r.id;
      del.dataset.delStart = r.start;
    }
    tdActs.appendChild(del);
    tr.appendChild(tdActs);
    return tr;
  }
  function renderRunsTable() {
    const all = filteredRuns(RF, unjournaledLive(), searchKeys, sortKey3, sortDir3);
    const total = all.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    if (page3 > pages) page3 = pages;
    if (page3 < 1) page3 = 1;
    const from = total ? (page3 - 1) * pageSize + 1 : 0;
    const to = Math.min(page3 * pageSize, total);
    const slice = all.slice((page3 - 1) * pageSize, page3 * pageSize);
    let rows;
    if (!total) {
      const tr = el("tr");
      const td = el("td", "tblempty");
      td.colSpan = RUN_COLS.length;
      td.appendChild(icon("inbox"));
      td.appendChild(document.createTextNode(
        (CC.DATA.runs || []).length ? searchKeys ? "No runs match this search." : "No runs match the filters." : "No runs recorded yet."
      ));
      tr.appendChild(td);
      rows = [tr];
    } else {
      rows = slice.map((r) => runRow(r));
    }
    const footer = tableFooter({
      // The footer and the pager count the FILTERED set, never the total --
      // test_the_footer_and_pager_count_the_filtered_set_not_the_total pins
      // this the same way.
      shown: { from, to },
      total,
      noun: "run",
      page: page3,
      pages,
      prevId: "runs-pg-prev",
      nextId: "runs-pg-next",
      infoId: "runs-pg-info"
    });
    const card = tableCard({
      columns: RUN_COLS,
      sortKey: sortKey3,
      sortDir: sortDir3,
      sortAttr: "sort",
      rows,
      footer
    });
    const host = $("runs-table");
    host.textContent = "";
    host.appendChild(card);
    paintRunFilters(total);
  }
  function renderRunsPage() {
    mountRunsToolbar();
    const runs = CC.DATA.runs || [];
    const liveCount = unjournaledLive().length;
    const headHost = $("runs-head");
    if (headHost) {
      headHost.textContent = "";
      headHost.appendChild(pageHeader({
        icon: "activity",
        title: "Runs",
        subtitle: runsHeaderSubtitle(runs, liveCount),
        actions: [{ id: "runs-refresh", icon: "radar", label: "Refresh" }]
      }));
    }
    const kpiHost = $("runs-kpis");
    if (kpiHost) {
      kpiHost.textContent = "";
      runsKpis(runs, liveCount).forEach((c) => kpiHost.appendChild(kpiCard({
        icon: KPI_ICONS3[c.label],
        tone: c.tone,
        value: c.value,
        label: c.label,
        sub: c.sub,
        title: c.title,
        filter: c.filter,
        door: c.door
      })));
    }
    renderRunsTable();
  }

  // ui/app/editor-domain.js
  function changedKeys(now, clean) {
    return Object.keys(now).filter((k) => now[k] !== clean[k]);
  }
  var EFFORTS = ["", "low", "medium", "high", "xhigh", "max"];
  function effortIndex(v) {
    return Math.max(0, EFFORTS.indexOf(v || ""));
  }
  function effortFromIndex(raw) {
    return EFFORTS[+raw || 0] || "";
  }
  function dayNumbers(rawValues) {
    return rawValues.map((v) => +v);
  }
  function shapeRepoRows(rawRows) {
    return rawRows.map((r) => ({ name: r.name.trim(), path: r.path.trim(), base: r.base.trim() })).filter((r) => r.name && r.path);
  }
  function projectStepError(k, values) {
    if (k === "project") {
      const n = values.name;
      if (!n) return { ok: false, message: "A project name is required." };
      if (!values.editingProject && values.projects.some((p) => p.name === n))
        return { ok: false, message: "A project with that name already exists." };
      if (!values.cwd)
        return { ok: false, message: "Pick a working directory \u2014 the folder its runs work in." };
    }
    if (k === "repos" && values.multi) {
      const rows = values.repos;
      if (!rows.length)
        return { ok: false, message: "Add a repository, or go back to a single repository." };
      if (!rows.some((r) => r.path === values.cwd))
        return { ok: false, message: "One repo's path must be exactly the working directory from step 1 \u2014 that is the repo the agent starts in. None of these match it." };
    }
    return { ok: true };
  }

  // ui/app/index.js
  function init(cc) {
    bindPage(cc);
  }
  window.CCApp = {
    init,
    visibleJobs,
    jobFilters,
    bulkOn,
    bulkLabel,
    clearJobFilters,
    jobProjectNames,
    // sortJobs and JOB_COLS are Task 2 (phase 2)'s: renderJobTable
    // and renderJobHead in bin/dashboard.html call CCApp.sortJobs
    // and read CCApp.JOB_COLS instead of keeping their own copies,
    // the same "table is the second consumer" reach visibleJobs
    // already has above.
    sortJobs,
    JOB_COLS,
    groupJobs,
    jobsEmptyNote,
    worktreesCard,
    // pageHeader, kpiCard and renderPulse (all three from
    // ./chrome.js and ./overview.js) used to sit on this global
    // for a stated future that landed differently -- Jobs, Runs
    // and Projects all grew their own KPI row by calling
    // kpiCard() through a direct ES import inside their own
    // module, never through window.CCApp, and pageHeader's one
    // caller (bin/dashboard.html's initPageHeaders()) was
    // removed outright. Grepped for CCApp.pageHeader,
    // CCApp.kpiCard and CCApp.renderPulse across bin/ and
    // tests/ before removing all three -- zero readers.
    //
    // pageHeader and kpiCard are back (Phase 4 Task 1), for a
    // real reader this time: ui/security/ is a SEPARATE esbuild
    // bundle that cannot import chrome.js directly (see
    // ui/security/page.js's own comment on why -- a second,
    // never-bound copy of this module's `icon` is the failure
    // mode), so bin/dashboard.html's CC object reads
    // CCApp.pageHeader/CCApp.kpiCard off this global instead and
    // hands them into CCSecurity.init(CC) alongside every other
    // name the area needs. tableFooter joins them for the first
    // time, not a comeback -- nothing has ever read
    // CCApp.tableFooter -- because the same bridge is the one
    // sane way for a later task's own project/recent-analyses
    // pager to reach it too, and adding it now means that task
    // does not have to touch this file again. renderPulse stays
    // off this list: Security has never needed it, and it is
    // still true that nothing else reads it through here.
    pageHeader,
    kpiCard,
    tableFooter,
    renderOverviewHead,
    // jobCard is Task 9's: renderJobCards() in bin/dashboard.html
    // (the Overview's own cards, what used to be inside
    // renderJobs() before the Jobs table forked off it) calls
    // CCApp.jobCard(j) per job instead of building the card as
    // an HTML string. checkList and the kept-session notice are
    // internal to jobCard and have no other caller, so they
    // stay unexported, the same shape as el() above.
    jobCard,
    // renderJobsPage, jobsSort, jobsSetPage and initJobDrag are
    // Phase 2 Task 3's: the Jobs table itself, moved whole out
    // of bin/dashboard.html (renderJobTable/renderJobHead/
    // paintJobFilters and the table branch that used to live
    // inside renderJobs()) into ui/app/jobs-table.js.
    // renderJobsArea() (bin/dashboard.html) calls
    // CCApp.renderJobsPage() once per poll, the same way it
    // calls renderJobCards() for the Overview's own cards; the
    // page's delegated click listener calls CCApp.jobsSort(key)
    // for a sortable header and CCApp.jobsSetPage(delta) for
    // the footer's pager instead of keeping jobSortKey/
    // jobSortDir/page as its own module state.
    renderJobsPage,
    jobsSort,
    jobsSetPage,
    initJobDrag,
    // visibleProjects, projFilters and projectIsolation are
    // Phase 2 Task 4's: the search box's input/clear handlers
    // read and write CCApp.projFilters.query instead of a
    // module-level prjQuery -- the same "table is the second
    // consumer" reach sortJobs/JOB_COLS already have above.
    visibleProjects,
    projFilters,
    projectIsolation,
    // renderProjectsPage, projectsSort and projectsSetPage are
    // Phase 2 Task 5's: the Projects table itself, moved whole
    // out of bin/dashboard.html's renderProjects() into
    // ui/app/projects.js, the same move jobs-table.js already
    // made for Jobs. render() (bin/dashboard.html) calls
    // CCApp.renderProjectsPage() once per poll; the page's
    // delegated click listener calls CCApp.projectsSort(key)
    // for a sortable header and CCApp.projectsSetPage(delta)
    // for the footer's pager, instead of keeping
    // prjSortKey/prjSortDir/page as its own module state.
    renderProjectsPage,
    projectsSort,
    projectsSetPage,
    // filteredRuns (Phase 2 Task 6) and SORTERS both stay
    // internal to ui/app/runs.js's own exports now that Task 7
    // gave the rest of the table a home beside it: nothing in
    // bin/dashboard.html or a test has ever called
    // CCApp.filteredRuns() -- the characterisation tests that
    // pin its behaviour read the function's own source text
    // out of the built bundle (`_app_js` + `_plainfn` in
    // tests/test_page_contract.py), the same as pulseKpis and
    // its neighbours above, so it does not belong on
    // window.CCApp either.
    // RF, renderRunsPage, runsSort, runsSetPage,
    // runsFilterChanged, runsGotoFirstPage, runsSetPageSize,
    // runsPageSize, clearRunFilters, runSearch and
    // runProjectNames are Phase 2 Task 7's: the Runs table
    // itself, moved whole out of bin/dashboard.html
    // (renderRunHead/renderRuns/paintRunFilters/runSearch/
    // clearRunFilters and the four pickers' own onPick bodies)
    // into ui/app/runs.js, the same move jobs-table.js and
    // projects.js already made for their own tables. RF is a
    // single exported object rather than five module-level
    // `let`s for the same reason jobFilters/projFilters are:
    // the four Runs pickers' own onPick callbacks (still in
    // bin/dashboard.html, since they are page-owned stateful
    // widgets) read and write CCApp.RF.project/job/status/
    // from/to directly. render() (bin/dashboard.html) calls
    // CCApp.renderRunsPage() once per poll; the page's
    // delegated click listener calls CCApp.runsSort(key) for a
    // sortable header and CCApp.runsSetPage(delta) for the
    // footer's pager; runsFilterChanged/runsGotoFirstPage are
    // the two shapes every filter change needs (one that also
    // redraws, one that does not because a view switch is about
    // to); runsSetPageSize/runsPageSize back the per-page
    // `<select>`; clearRunFilters and runSearch are `#f-clear`'s
    // and the search box's own click/input handlers.
    RF,
    renderRunsPage,
    runsSort,
    runsSetPage,
    runsFilterChanged,
    runsGotoFirstPage,
    runsSetPageSize,
    runsPageSize,
    clearRunFilters,
    runSearch,
    runProjectNames,
    // changedKeys, EFFORTS, effortIndex, effortFromIndex,
    // dayNumbers, shapeRepoRows and projectStepError are Phase 3
    // Task 2's: the two editor dialogs' own decision/mapping
    // code, pulled out of bin/dashboard.html ahead of their
    // restyle so each can be pinned under Node. makeWizard's own
    // W.changed calls changedKeys; effortSet/effortGet call
    // effortIndex/effortFromIndex and read EFFORTS for the
    // "unset" check; getDays calls dayNumbers; collectRepos
    // calls shapeRepoRows; validateProjectStep calls
    // projectStepError. Every one of them is plain values in,
    // plain values out -- none reaches $, document or CC.DATA,
    // so none needed a page.js entry the way jobs-domain.js's
    // exports do.
    changedKeys,
    EFFORTS,
    effortIndex,
    effortFromIndex,
    dayNumbers,
    shapeRepoRows,
    projectStepError
  };
})();
/* ui-bundle: e3549861f94f008dac747519522b66496257011649f055a8283ae0b3c51a154d */
/* ui-sources: ce629b79cddee3d2aa49ecf32d1f2845ae5d82a8e3633b8839b724a73382e4d5 */
