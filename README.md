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

#### A precheck that writes: `CC_PRECHECK_DRY_RUN`

A precheck may do more than look. The useful case is a **claim**: reading a queue
tells you what *was* free, and only a write that succeeds tells you what *is*
yours — so a precheck that atomically takes a ticket is what stops two runs
working the same one. Its output is handed to the agent, which is how the session
learns what was claimed for it.

That makes the precheck **not idempotent**, and the engine runs it standalone in
two places that only mean to *look*: `claude-cron check <id>`, and the guard the
dashboard's **Run now** fires before starting a forced run. Both export

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

### Budgets

- **Per-run** (`max_budget_usd`) — passed to `claude -p --max-budget-usd`; caps a
  single run.
- **Per-day** (`daily_budget_usd`) — the engine sums today's runs for the job
  before each scheduled run and skips (status `capped`) once the total reaches
  the cap. Empty = unlimited. The card shows **Today: $spent / $cap**.

### Self-test

`claude-cron selftest` exercises, offline and without spending anything, the
logic that can end a run early or hide what it cost: numbers parsed from command
output, the assertion that decides an interactive turn is over, token recovery
from a transcript with no result event, and the disabled-job guard. Run it after
touching the engine.

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
claude-cron resolve-models     # refresh which model each family points at
claude-cron selftest           # offline checks of the logic that can kill a run
claude-cron install | uninstall
```

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
