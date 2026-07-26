# claude-cron · Agent Loop Manager

A small, durable platform for running **Claude Code agents on a loop** on your
Mac. Each job wakes on a schedule, runs a cheap **precheck** to decide whether
there is anything worth doing, and only then spends a Claude session — so idle
loops cost nothing. Jobs run **in parallel**, survive logout and reboot, and are
managed from a local web dashboard (light/dark) with a full run log per run and
full-text search across everything the agents did.

It was built to drive a Jira/Bitbucket development flow (an agent that develops
tickets, one that reviews PRs, one that reworks change-requests), but the engine
is generic: a job is just *a schedule + a precheck + a prompt*.

---

## Requirements

- **macOS** (uses `launchd` and BSD `date` — not Linux/Windows).
- **[Claude Code CLI](https://claude.com/claude-code)** on your `PATH` (`claude --version` must work and be signed in).
- `jq`, `python3`, `curl` (python3 ships with the Xcode command-line tools; `jq` via `brew install jq`).

---

## Install

```bash
cd claude-cron
bash install.sh
```

Use **`bash install.sh`**, not `./install.sh` — if the folder arrived by
download, AirDrop or email, macOS flags it with a quarantine attribute and
`./install.sh` fails with **`operation not permitted`**. Running it through
`bash` sidesteps that, and the installer's first act is to clear the quarantine
flag from the whole folder (so `bin/claude-cron` can run later). If you ever hit
that error anyway, clear it by hand once: `xattr -cr claude-cron`.

It checks dependencies, links `claude-cron` into `~/.local/bin`, seeds a
`config/jobs.json` from the example, and loads two `launchd` agents (a scheduler
that ticks every 60 s and a control server for the dashboard). Both start
automatically on login. Re-run it any time — it is idempotent, and you must
re-run it after moving this folder.

Then open the dashboard:

```bash
claude-cron dashboard
```

It lives at **http://127.0.0.1:8787/** (localhost only).

### What `install.sh` sets up under launchd

The installer runs `claude-cron install`, which writes and loads two macOS
`launchd` agents into `~/Library/LaunchAgents/`:

| Agent | File | Role |
|---|---|---|
| `com.claude-cron.tick` | `com.claude-cron.tick.plist` | runs the scheduler every 60 s (`RunAtLoad` + `StartInterval 60`, `AbandonProcessGroup` so detached runs survive) |
| `com.claude-cron.server` | `com.claude-cron.server.plist` | keeps the dashboard alive on 127.0.0.1 (`KeepAlive`) |

Because they live in `~/Library/LaunchAgents/`, macOS loads both **automatically
on every login** — you do not start anything by hand, and they survive reboots.

### Verify it is running

```bash
claude-cron status                     # shows "launchd: …loaded" and every job
launchctl list | grep claude-cron      # both agents should be listed
```

The dashboard header also shows a green **launchd** badge when the tick agent is
loaded. Logs live in `data/` (`tick.log` = scheduler decisions, `server.log`,
`launchd.out/err.log`).

If something looks off: re-run `./install.sh` (idempotent — it reloads both
agents), and make sure `~/.local/bin` is on your `PATH` and the `claude` CLI is
signed in. To stop everything, `./uninstall.sh`.

### Try it in one minute

The shipped `example-hello` job is disabled. Enable it in the dashboard (or
`claude-cron enable example-hello`), then:

```bash
touch /tmp/claude-cron-hello
```

Within a tick the precheck sees the trigger file, the agent runs once (it clears
the file and replies with a confirmation line), and the run appears in **Recent
runs** — click the 🔍 to see the full trace.

---

## How it works

```
launchd ──60s──▶ claude-cron tick
                     │  for each job that is enabled, in its time window and due:
                     └─▶ launch a DETACHED runner  ─▶  precheck?  ─┬─ exit 1 → idle (no cost)
                                                                   └─ exit 0 → claude -p run
```

- **The tick never blocks.** It launches each due job as a detached process and
  returns, so a 90-minute run never freezes the other jobs' loops.
- **The precheck is the money-saver.** It is a shell script; exit 0 means "there
  is work, wake the agent", exit 1 means "nothing to do, stay idle". A quiet loop
  spends nothing.
- **Run now** (dashboard / `claude-cron run <id>`) bypasses the precheck and the
  daily cap — a deliberate manual override.

Every run is classified **success** / **warning** / **error** (error = the
process failed, the CLI errored, or the agent had tools denied — a blocked agent
doing nothing is a failure, not a success; warning = finished but empty result or
stderr).

---

## Jobs

A job is one object in `config/jobs.json`. Fields:

| field | meaning |
|---|---|
| `id` | unique, `[A-Za-z0-9_-]` |
| `description` | shown on the card |
| `enabled` | `false` to pause without deleting |
| `cwd` | directory the agent runs in |
| `prompt` | the instruction sent to `claude -p` |
| `precheck` | shell command; exit 0 = work, exit 1 = idle (see below) |
| `interval_seconds` | how often to check |
| `active_hours` | `"08:00-20:00"` (empty = 24h) |
| `active_days` | `[1..7]`, 1=Mon |
| `project` | optional group; the job inherits the project's `cwd` (see **Projects**) |
| `model` | an exact model id (`claude-opus-5`, …) or a family (`opus`/`sonnet`/`haiku`/`fable`) |
| `effort` | `low`/`medium`/`high`/`xhigh`/`max` — how hard the model thinks (omit = the CLI decides) |
| `max_budget_usd` | hard ceiling per single run |
| `daily_budget_usd` | ceiling on total spend per day (**omit = no cap**) |
| `stall_timeout_seconds` | kill a run only after this long with **no output** (default 1200) |
| `timeout_seconds` | optional absolute time cap (**omit = no limit**) |
| `permission_mode` | `dontAsk`, `bypassPermissions` (full autonomy, needed for headless tool use), … |

Create and edit jobs entirely from the dashboard (**+ New job** / **Edit**),
including the precheck script, or from the CLI.

### Prechecks

The cheap gate that decides whether to spend a session. Each job's precheck is a
script in `config/prechecks/<id>.sh`. Keep it fast (a `curl`, a `grep`, a file
test) and end it with a test whose exit status is the decision:

```bash
#!/bin/bash
count=$(curl -sf https://api.example.com/queue | jq -r '.pending')
[ "${count:-0}" -gt 0 ]     # exit 0 → work; exit 1 → idle
```

#### The exit status is three-way, not two

| Exit | Meaning | What the engine does |
|---|---|---|
| `0` | there is work | spends a session |
| `1` | nothing to do | stays idle, costs nothing |
| anything else | **the probe itself is broken** | records `precheck_error`, shows the job in red, and backs off |

The third row matters more than it looks. A missing credentials file, a helper
that will not source, a typo, a `command not found` — all of those exit with
something that is neither 0 nor 1. They used to be read as "nothing to do", so a
job could stop working for good while the dashboard kept reporting it as healthy
and up to date. Write prechecks that **fail loudly**: let the error status
escape rather than mapping everything onto `exit 1`.

If your probe genuinely cannot tell (the API is down, and you would rather wait
than guess) that is `exit 1` — "no work found" — and it is right to be quiet
about it. Reserve the other codes for "this probe is not working".

#### A precheck that writes: `CC_PRECHECK_DRY_RUN`

A precheck may do more than look. The useful case is a **claim**: reading a queue
tells you what *was* free, and only a write that succeeds tells you what *is*
yours — so a precheck that atomically takes a ticket is what stops two runs
working the same one. Its output is handed to the agent, which is how the session
learns what was claimed for it.

That makes the precheck **not idempotent**, and the engine runs it in three
places that only mean to *look*: `claude-cron check <id>`, the guard the
dashboard's **Run now** fires before starting a forced run, and a **resume** —
where the session already has its work and the continuation prompt replaces the
precheck's output entirely, so anything claimed there would be claimed for a run
that never reads it. All three export

```bash
CC_PRECHECK_DRY_RUN=1
```

A precheck that writes MUST honour it: report the candidate it *would* take,
keep the same exit status (0 = work, 1 = idle), and touch nothing. Ignoring it
costs you the claim — the probe moves the ticket out of the queue, the run that
follows finds an empty board and reports there is nothing to do, and the ticket
is left claimed with no session behind it.

```bash
if [ -n "${CC_PRECHECK_DRY_RUN:-}" ]; then
  echo "would_claim=$candidate — dry run, the board was untouched"
  exit 0
fi
claim "$candidate"          # the real run: a write, and the lock
```

### Isolation: one worktree per repo, per run

Every run of a project works in its **own directory**, so two agents can never
share a working tree — one `git checkout` would otherwise move the other off its
branch mid-thought. A project that spans several repositories declares them, and
a run gets a worktree of each:

```json
"repos": [
  {"name": "web", "path": "/Users/me/code/web", "base": "develop"},
  {"name": "api", "path": "/Users/me/code/api", "base": "develop"}
],
"worktree": {"enabled": "auto"}
```

```
data/worktrees/<job>/<stamp>/
├── web/        ← the run's cwd: the repo whose path is the project's cwd
├── api/
└── .run.json   ← the manifest: every repo, its worktree, its canonical checkout, its base
```

`base` is the branch each worktree is cut from and the branch a merge request
targets. It is **declared, not observed**: a canonical checkout can be detached
or parked on somebody's feature branch, and neither is a base. A project that
declares no `repos` is the single-repo case — the entry is derived from `cwd`
and its base inferred from the current branch.

The agent finds everything through `$CC_RUN_MANIFEST`. The canonical checkouts
are never modified: they are read to cut worktrees from, nothing more.

`enabled` is `"auto"` (isolate when the cwd is a git repo), `true` or `false`.

A run dir is removed when the run ends — unless a worktree still holds work that
exists nowhere else (uncommitted changes, or commits on no remote), in which case
the whole run dir is kept and the tick log says so.

### Provisioning: `up` and `down`

A fresh worktree has no `.env`, no `vendor/`, no `node_modules/` — they are
gitignored, so no checkout can produce them. Two optional scripts per project
fill that gap:

```
config/provision/<project>.up.sh     # after the worktrees exist, before the agent starts
config/provision/<project>.down.sh   # when the run ends, before they are removed
```

Each runs **once per repo**, with the working directory set to that repo's
worktree and the run described in its environment: `CC_REPO_NAME`,
`CC_REPO_PATH` (the canonical checkout), `CC_WORKTREE`, `CC_BASE`, `CC_RUN_DIR`,
`CC_RUN_MANIFEST`, `CC_PROJECT`, `CC_JOB_ID`. See
`config/provision/example-hello.up.sh`.

A non-zero `up` **aborts the run** — the engine takes down what it provisioned
and never hands a half-built tree to an agent. A hook that outlives
`worktree.provision_timeout_seconds` (default 900) is killed. `down` runs once
per run, even when the run dir is preserved: whatever the hook registered outside
the directory still has to be released.

Every worktree is cut from a freshly fetched base, and that fetch is bounded by
`worktree.fetch_timeout_seconds` (default 120). It has to be: the fetch happens
after the run has taken its slot but before the watchdog exists, so a remote
that accepts the connection and then goes quiet would pin the slot for as long
as the network stayed broken — and with `max_parallel: 1` that is the job dead
until someone notices. On a timeout the base is resolved from the refs already
on disk and the tick log says so.

#### Worktrees that are kept back

When a run ends with commits or changes that exist on no remote, its worktree is
**preserved** rather than removed — the work would otherwise be lost. Nothing
can ever release it on its own, so the dashboard lists every retained run dir
with its size and age, and **Discard** throws one away once you have salvaged
what you need (`claude-cron worktree-drop <job-id> <stamp>` from the CLI). A run
dir a live run is using is never offered, and never dropped.

Anything with a global name must derive it from `$CC_RUN_DIR`, or two concurrent
runs of the same repo collide:

```bash
SITE="${CC_REPO_NAME}-$(basename "$CC_RUN_DIR")"
herd link "$SITE"; docker compose -p "$SITE" up -d      # up
herd unlink "$SITE"; docker compose -p "$SITE" down -v  # down
```

### Budgets

Three ceilings, each answering a different question.

- **Per-run** (`max_budget_usd`) — passed to `claude -p --max-budget-usd`; caps a
  single run. Job value first, else the project's.
- **Per-day, per job** (`daily_budget_usd`) — the engine sums today's runs for
  the job before each scheduled run and skips (status `capped`) once the total
  reaches the cap. Job value first, **else the project's** — so a project with
  six jobs can set one number in one place. Empty = unlimited. The card shows
  **Today: $spent / $cap**.
- **Per-day, everything** (`global_daily_budget_usd`, at the top level of
  `projects.json`) — the ceiling for the whole machine:

  ```json
  { "global_daily_budget_usd": 120,
    "projects": [ … ] }
  ```

  Per-job caps cannot express this. With a job per repo per role, every single
  one can sit correctly under its own limit and the day still cost several times
  what you meant to spend; the only number that answers "what will a bad night
  cost me?" is the sum.

All three are skipped for a **forced** run (Run now), which is a deliberate
override — the same way it bypasses the precheck.

### Backing off a job that keeps failing

A job that errors used to relaunch every interval at full budget, for as long as
it kept failing, with nothing in the loop noticing. Now the engine counts
**consecutive** failures per job:

| Consecutive errors | Wait |
|---|---|
| 0–2 | the configured interval |
| 3 | 2× |
| 4 | 4× |
| 5 | 8× |
| 6+ | 16× (the cap) |

Two failures are treated as noise — a flaky network, a busy remote. From the
third the wait doubles each time, capped at 16× so a job that gets fixed
recovers within one long interval rather than hours later. **Any** run that is
not an error resets the count, so one good run puts the job straight back on its
normal cadence. A broken precheck (see above) counts too. The card says so:
*backing off 4× after 4 failed runs*.

### Telling someone a run ended: `config/hooks/on-run-end.sh`

A loop that can only be checked by opening a web page is not really unattended.
Drop an executable script at `config/hooks/on-run-end.sh` and the engine runs it
after every run, with the outcome in its environment:

| Variable | |
|---|---|
| `CC_JOB_ID` | which job |
| `CC_STATUS` | `success`, `warning` or `error` |
| `CC_COST` | dollars this run spent |
| `CC_NOTE` | why it ended as it did (`BUDGET LIMITED: …`, `NOTHING TO DO: …`, a watchdog reason) |
| `CC_PROJECT`, `CC_SESSION`, `CC_LOG` | |
| `CC_START`, `CC_END`, `CC_DURATION` | epoch seconds, and the span |
| `CC_DASHBOARD` | the dashboard URL |

The engine knows nothing about notifiers, so this is where they go:

```bash
#!/usr/bin/env bash
[ "$CC_STATUS" = error ] || exit 0
terminal-notifier -title "claude-cron: $CC_JOB_ID failed" \
                  -message "${CC_NOTE:-see the run log}" -open "$CC_DASHBOARD"
```

It is detached and time-limited (`CLAUDE_CRON_HOOK_TIMEOUT`, default 60s): a
notifier that hangs must never hold a run's slot open. Its output goes to
`data/exec.log`.

### Tests

Two suites, both offline and free:

```bash
claude-cron selftest        # the engine (bash)
python3 -m pytest tests/    # the control server (python)
```

`selftest` exercises the logic that can end a run early, lose money or corrupt
state: integer parsing from command output, the assertion that decides an
interactive turn is over, token recovery from a transcript with no result event,
the disabled-job guard, the schedule window (including one that wraps midnight),
the failure backoff curve, lock ownership, worktree setup/teardown/provisioning,
and log rotation. It runs entirely inside a scratch directory — it will not
touch `data/`.

`pytest tests/` covers the server: journal ingest and resync, the 24h activity
counters, retained worktrees, the journal lock, and the dashboard page itself
(that its JavaScript parses, that every element it reaches for exists, and that
the backoff curve it recomputes still agrees with the engine's).

Run both after touching either side.

### When a run is killed

A long run is not a hung run, so there is no blind wall-clock timeout by default.
A watchdog polls the run's output instead: while the stream file keeps growing the
agent is alive and is left alone, however many hours it needs. It is killed only
when it has produced **no output** for `stall_timeout_seconds` (a genuine hang),
or when the optional absolute `timeout_seconds` cap is exceeded. Either way the
reason is recorded, and the log rebuilds what the run did from its stream — the
session, the turn count and the agent's last message — so a killed run still
explains itself.

### Models

Pick an exact id (`claude-opus-5`) when a task does not deserve the top model, or
a family (`opus`) to always run that family's newest model. Families are resolved
by the engine, not by the CLI alias: an alias points at the newest model the
*installed CLI* knows, which lags the API right after a release. `claude-cron
resolve-models` probes for the newest of each family and caches the answer in
`config/models.json`; the tick refreshes it roughly once a day on its own.

### Effort

`effort` maps to `claude -p --effort`. Higher levels make the model think longer —
better results, more tokens and more time. The dashboard exposes it as a slider
from *Faster* to *Smarter*; leave it at **Default** to let the CLI decide.

---

## Projects

A project groups jobs and holds settings they inherit — above all the working
directory, so it is written once instead of in every job. Its description is
prepended to every prompt as context, which is a convenient way to tell every
agent in the project what the project is. Create one with **+ New project**;
jobs then just pick it (a job without a project sets its own `cwd`).

Projects live in `config/projects.json` and are personal to your install, so
they are not committed.

### Which Claude account a run signs in as

Claude Code keeps credentials, settings, plugins, MCP servers and past sessions
**per config directory** — one signed-in account each. If you keep two accounts
on the same Mac (a company one and a personal one, say), the directory is the
only thing that chooses between them:

```bash
CLAUDE_CONFIG_DIR=~/.claude-work     claude    # work account
CLAUDE_CONFIG_DIR=~/.claude-personal claude    # personal account
```

Shell aliases for that never reach claude-cron: `launchd` inherits nothing from
your shell, so by default every run signs in as the CLI's own `~/.claude`. There
are two levels:

| Level | Where | Applies to |
|---|---|---|
| default | `CLAUDE_CRON_CLAUDE_CONFIG_DIR` at install time | every run, and the model probes |
| per project | `claude_config_dir` in `config/projects.json` (**Edit project** in the dashboard) | that project's runs and their prechecks |

```bash
CLAUDE_CRON_CLAUDE_CONFIG_DIR=~/.claude-work bash install.sh
```

The value is written into both `launchd` plists, so it survives logout and
reboot; re-running the installer without the variable keeps whatever is already
pinned. A project's own setting wins over it, and an empty one inherits it.

Three things to know before splitting jobs across accounts:

- **Keep a job's account stable.** Sessions are stored per config directory, so
  a resumed run is looked up inside the account that created it — moving a
  project to another account strands anything still open.
- **The account brings its whole environment.** Its `settings.json`, plugins,
  MCP servers and any managed policy come with it, so the same prompt can behave
  differently on the other account. An MCP server authenticated interactively in
  one directory is *not* authenticated in the other.
- **A missing directory is refused, not created.** The run is skipped with
  `claude_config_dir missing` in `data/tick.log` rather than launching a session
  that would stop at a login prompt. Sign that account in once, interactively.

---

## Dashboard

- **Jobs** — one card each: schedule, last check (with the precheck's output),
  checks in the last 24h (proof the loop runs even when idle), last run, today's
  spend vs cap, and **Run now / Enable / Disable / Edit / Delete**. Destructive or
  wasteful actions confirm first.
- **Recent runs** — full-text **search** across run results, per-turn traces and
  precheck output; **Filters** (job, status, date range) behind a button;
  pagination. The 🔍 on each row opens the run: did the precheck pass, which tools
  were blocked, a **timeline with one line per agent turn**, the final answer, and
  stderr.
- **Theme** — light/dark toggle in the header.

---

## CLI

```bash
claude-cron dashboard          # open the control UI
claude-cron status             # jobs + last run + cost, in the terminal
claude-cron run <id>           # force a run now (ignores precheck + daily cap)
claude-cron check <id>         # run only the precheck, report what it saw
claude-cron enable|disable <id>
claude-cron toggle-many true|false   # ids on stdin (JSON array or one per line)
claude-cron create <id>        # JSON object on stdin
claude-cron set-prompt <id>    # prompt on stdin
claude-cron set-precheck <id>  # script on stdin
claude-cron set-field <id> <field>   # value on stdin (interval_seconds, active_hours,
                               #   active_days, model, effort, max_budget_usd,
                               #   daily_budget_usd, stall_timeout_seconds,
                               #   timeout_seconds, permission_mode, description,
                               #   cwd, project)
claude-cron delete <id>        # remove the job (its logs are kept)
claude-cron project-set        # create/update a project (JSON on stdin)
claude-cron project-list | project-delete <name>
claude-cron provision-set <project> up|down   # worktree provisioning script (stdin)
claude-cron provision-get <project> up|down
claude-cron worktree-drop <id> <stamp>   # discard a preserved run dir for good
claude-cron resolve-models     # refresh which model each family points at
claude-cron selftest           # offline checks of the logic that can kill a run
claude-cron install | uninstall
```

Environment overrides: `CLAUDE_CRON_PORT`, `CLAUDE_CRON_CONFIG`,
`CLAUDE_CRON_DATA`, `CLAUDE_CRON_CLAUDE_BIN`, `CLAUDE_CRON_CLAUDE_CONFIG_DIR`,
`CLAUDE_CRON_PYTHON`, `CLAUDE_CRON_JQ`, `CLAUDE_CRON_LOG_MAX` (log rotation
threshold, default 4 MiB), `CLAUDE_CRON_HOOK_TIMEOUT`, `CLAUDE_CRON_LOCK_GRACE`.

---

## Storage

Files are written by the engine and are crash-safe; **`data/index.db`** (SQLite,
WAL + FTS5) is the canonical run history and powers search. The engine appends a
tiny journal line per run (`data/runs.ndjson`, ~300 B) plus the run's raw
artifacts under `data/logs/`; the control server absorbs both into the DB and
then deletes the bulky artifact files. **To back up or migrate: copy
`data/index.db`** (plus the journal). Disk usage ≈ the DB size, shown in the
dashboard footer. Deleting `index.db` only loses runs whose files were already
pruned.

**Logs.** `data/tick.log` (scheduler decisions) and `data/exec.log` (detached
runner and provisioning-hook output) are append-only and are rotated by the tick
once either passes `CLAUDE_CRON_LOG_MAX` (4 MiB). Exactly one previous
generation is kept, as `.1` — the chain never grows.

---

## Security

The control server binds **127.0.0.1 only** and is never reachable from the
network. Every `/api/*` call requires a secret token (`config/control.token`,
chmod 600) that is embedded only in the same-origin page; cross-origin requests
are rejected and a custom header forces a CORS preflight the server refuses — so
no web page open in your browser can drive your agents. Every mutation shells out
to the `claude-cron` CLI, so the bash engine stays the single source of truth.

**Autonomous agents act with your Claude credentials.** A job with
`permission_mode: bypassPermissions` runs tools without prompting. Give such jobs
a `daily_budget_usd`, watch the run log, and use the kill switch
(`claude-cron disable <id>`) freely.

---

## Layout

```
claude-cron/
├── bin/claude-cron            # the engine + CLI (bash)
├── bin/claude-cron-server     # the dashboard control server (python, stdlib)
├── config/
│   ├── jobs.json              # your jobs (created from the example on install)
│   ├── jobs.example.json      # a disabled demo job
│   ├── projects.json          # your projects (generated)
│   ├── models.json            # cached family→model resolutions (generated)
│   ├── prechecks/<id>.sh      # one precheck per job
│   ├── provision/<project>.{up,down}.sh   # per-repo worktree provisioning
│   └── control.token          # dashboard secret (chmod 600, generated)
├── data/                      # index.db, journal, logs, state — all local
├── install.sh · uninstall.sh
└── README.md
```

Everything generated or personal (`data/`, `dist/`, your jobs, projects, model
cache and token) is git-ignored, so a clone starts clean.

The two `launchd` agents are the only thing outside this folder — macOS loads
them from `~/Library/LaunchAgents/com.claude-cron.*.plist`. The scripts resolve
their own location, so you can move this folder anywhere and re-run `install.sh`.

---

## Uninstall

```bash
./uninstall.sh
```

Removes the agents and the `~/.local/bin` symlinks; keeps your `config/` and
`data/`. Delete the folder to remove everything.
