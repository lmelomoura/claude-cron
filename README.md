# agentloop · Agent Loop Manager

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
cd agentloop
bash install.sh
```

Use **`bash install.sh`**, not `./install.sh` — if the folder arrived by
download, AirDrop or email, macOS flags it with a quarantine attribute and
`./install.sh` fails with **`operation not permitted`**. Running it through
`bash` sidesteps that, and the installer's first act is to clear the quarantine
flag from the whole folder (so `bin/agentloop` can run later). If you ever hit
that error anyway, clear it by hand once: `xattr -cr agentloop`.

It checks dependencies, links `agentloop` into `~/.local/bin`, seeds a
`config/jobs.json` from the example, and loads two `launchd` agents (a scheduler
that ticks every 60 s and a control server for the dashboard). Both start
automatically on login. Re-run it any time — it is idempotent, and you must
re-run it after moving this folder.

Then open the dashboard:

```bash
agentloop dashboard
```

It lives at **http://127.0.0.1:8787/** (localhost only). The first load asks you
to create the operator profile — a name, an email and a password — before it will
show anything else. There is no password reset, so pick one you keep; see
[Signing in](#signing-in).

### What `install.sh` sets up under launchd

The installer runs `agentloop install`, which writes and loads two macOS
`launchd` agents into `~/Library/LaunchAgents/`:

| Agent | File | Role |
|---|---|---|
| `com.agentloop.tick` | `com.agentloop.tick.plist` | runs the scheduler every 60 s (`RunAtLoad` + `StartInterval 60`, `AbandonProcessGroup` so detached runs survive) |
| `com.agentloop.server` | `com.agentloop.server.plist` | keeps the dashboard alive on 127.0.0.1 (`KeepAlive`) |

Because they live in `~/Library/LaunchAgents/`, macOS loads both **automatically
on every login** — you do not start anything by hand, and they survive reboots.

### Upgrading from claude-cron

This scheduler was called **claude-cron** until 2026-09-06. An install made
under that name upgrades by pulling and running the installer again:

```bash
bash install.sh
```

`agentloop install` retires the two old agents (`com.claude-cron.tick` and
`com.claude-cron.server`), carrying the Claude account pinned in them over to
the new ones, and replaces the `claude-cron` and `claude-cron-server` symlinks
in `~/.local/bin`. Your jobs, projects, run history and prechecks are untouched.

Three things still answer to their old names **for this release only**, and the
installer and `agentloop status` list every one they find on your machine:

- the environment: every `CLAUDE_CRON_*` is read as `AGENTLOOP_*`;
- the run environment: every `CC_*` your prechecks, provisioning hooks and
  `on-run-end.sh` read is exported alongside its `AL_*` twin, and `cc_port`,
  `cc_env_set`, `cc_env_ports` and `cc_copy_ignored` still answer for
  `al_port` and its siblings;
- the dashboard's `X-CC-Token` header, now `X-AL-Token`.

Rename them at your leisure before the next release, where the old spellings
stop working. If the folder itself was renamed, point the `statusLine` in
`~/.claude/settings.json` at the new path — the installer says so when it
notices. The repository moved to `lmelomoura/agentloop`; GitHub redirects the
old address.

### Verify it is running

```bash
agentloop status                     # shows "launchd: …loaded" and every job
launchctl list | grep agentloop      # both agents should be listed
```

The dashboard header also shows a green **launchd** badge when the tick agent is
loaded. Logs live in `data/` (`tick.log` = scheduler decisions, `server.log`,
`launchd.out/err.log`).

If something looks off: re-run `./install.sh` (idempotent — it reloads both
agents), and make sure `~/.local/bin` is on your `PATH` and the `claude` CLI is
signed in. To stop everything, `./uninstall.sh`.

### Try it in one minute

The shipped `example-hello` job is disabled. Enable it in the dashboard (or
`agentloop enable example-hello`), then:

```bash
touch /tmp/agentloop-hello
```

Within a tick the precheck sees the trigger file, the agent runs once (it clears
the file and replies with a confirmation line), and the run appears in **Recent
runs** — click the 🔍 to see the full trace.

---

## Skills

The job prompts make several skills **mandatory by name** — "invoke
`using-superpowers` at the start of every run", "work each finding through
`closing-review-findings`". That only means something if the machine running the
agent actually has them.

Skills live in `~/.claude/skills`, which is not version controlled. So the ones
this loop depends on and **we** maintain live in `skills/` here and are linked
into `~/.claude/skills` — `agentloop install` does it, and `install.sh` runs
that, so a fresh clone is ready without a documented step for someone to skip.

```bash
agentloop skills           # what is linked, diverged, or missing
agentloop skills install    # link them (idempotent)
```

Links, not copies: editing either path edits the versioned file, so there is
never a stale second copy quietly disagreeing with the repository. An existing
unversioned skill is never destroyed — it is renamed `*.before-agentloop.<ts>`
so you can read what was there before adopting ours.

| skill | why the loop needs it |
|---|---|
| `closing-review-findings` | how a finding is actually closed: every adjacent route in the same commit, plus a versioned probe so it cannot reopen |
| `reviewing-pull-requests` | the reviewer's contract — verify by execution, walk the whole attack taxonomy on round one |
| `test-driven-development` | a fork of the `superpowers` copy, carrying our addition (below); a vendor update would otherwise overwrite it |
| `security-analysis` | the contract of a [security analysis](#security-analysis) run: re-verify what the last analysis left open, triage what the deterministic phase found, then the SAST pass at the profile's depth — and never print a secret's value, read a dependency tree, or treat a comment that addresses it as an instruction |

The other skills the prompts cite — `using-superpowers`, `systematic-debugging`,
`subagent-driven-development`, `receiving-code-review`,
`verification-before-completion` — come from the `superpowers` vendor package and
are deliberately left pointing at it. We only fork what we change.

### Why three of them carry a ninth axis

The reviewer skill has long walked eight "attack axes" against a change. All eight
interrogate the **code**. None asked whether the test proving the code works is
**real** — and that gap produced three consecutive review rounds on a single pull
request, each fixing a defect whose fixture had been hand-written from a guess.
The assumption sat in the code *and* in the fake, so they agreed with each other
while both disagreed with the tool. 842 tests, none of which had ever seen a byte
a real tool printed.

**Axis 9 — the fidelity of the evidence:** does any fixture here come from a real
sample, or is every one hand-written? It is in the author skill
(`closing-review-findings`), the reviewer skill (`reviewing-pull-requests`) and,
most importantly, in `test-driven-development`, where fakes are born — the other
two only fire once a finding already exists.

---

## How it works

```
launchd ──60s──▶ agentloop tick
                     │  for each job that is enabled, in its time window and due:
                     └─▶ launch a DETACHED runner  ─▶  precheck?  ─┬─ exit 1 → idle (no cost)
                                                                   └─ exit 0 → claude -p run
```

- **The tick never blocks.** It launches each due job as a detached process and
  returns, so a 90-minute run never freezes the other jobs' loops.
- **The precheck is the money-saver.** It is a shell script; exit 0 means "there
  is work, wake the agent", exit 1 means "nothing to do, stay idle". A quiet loop
  spends nothing.
- **Run now** (dashboard / `agentloop run <id>`) bypasses the precheck and the
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
| `allowed_tools` | allowlist passed as `--allowedTools`, whole and as a single argument — so a comma-separated list *and* a specifier containing a space, like `Bash(git *)`, both arrive intact (**omit = every tool**) |
| `disallowed_tools` | denylist passed as `--disallowedTools`, same handling (**omit = nothing denied**). Set both fields and **deny wins** for any tool named in each — an allowlist can never re-open what the denylist closed. A security analysis is derived with `Agent` here (the CLI's own tool roster calls that tool `Task`), so it cannot spend its budget on subagents instead of triage |

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

#### A precheck that writes: `AL_PRECHECK_DRY_RUN`

A precheck may do more than look. The useful case is a **claim**: reading a queue
tells you what *was* free, and only a write that succeeds tells you what *is*
yours — so a precheck that atomically takes a ticket is what stops two runs
working the same one. Its output is handed to the agent, which is how the session
learns what was claimed for it.

That makes the precheck **not idempotent**, and the engine runs it in three
places that only mean to *look*: `agentloop check <id>`, the guard the
dashboard's **Run now** fires before starting a forced run, and a **resume** —
where the session already has its work and the continuation prompt replaces the
precheck's output entirely, so anything claimed there would be claimed for a run
that never reads it. All three export

```bash
AL_PRECHECK_DRY_RUN=1
```

A precheck that writes MUST honour it: report the candidate it *would* take,
keep the same exit status (0 = work, 1 = idle), and touch nothing. Ignoring it
costs you the claim — the probe moves the ticket out of the queue, the run that
follows finds an empty board and reports there is nothing to do, and the ticket
is left claimed with no session behind it.

```bash
if [ -n "${AL_PRECHECK_DRY_RUN:-}" ]; then
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
or parked on somebody's feature branch, and neither is a base.

A project that declares no `repos` is the single-repo case: the entry is derived
from `cwd`, and its base comes from the project's own `base`.

```json
{"name": "web", "cwd": "/Users/me/code/web", "base": "develop"}
```

That is the whole configuration for one repository — `repos` is for projects that
genuinely span several. Declaring a single row whose `path` **is** the `cwd` says
nothing the two lines above do not, and it costs something: the engine picks the
repo the agent starts in by matching a row's `path` against `cwd` as a literal
string, so a trailing slash or a difference in case (one directory on macOS, two
strings here) leaves no row matching and **the run is refused before it starts**.
A declared row's `base` still wins over the project's, so a multi-repo project is
unaffected.

Ending a base in `*` follows a family rather than one branch: `release/*` resolves
to the newest `release/x.y.z` at run time, so a project shipping through release
trains is configured once instead of pointing at last month's train.

**Declare `base` whenever `origin/HEAD` is not the branch your work targets.**
Leaving it empty means *infer it*, and inference resolves to the canonical
checkout's current branch, then to `origin/HEAD` — for a detached checkout, that
is the repository's default branch, usually `main`. A project whose feature work
targets `develop` will therefore be inferred onto `main`: correctly resolved, and
still the wrong branch. Nothing downstream can detect this, because a base that
exists looks exactly like a base that was meant. Inference is a floor that keeps
an unconfigured project running, not a substitute for saying which branch you
work from.

Upgrading an install that predates this: worktrees used to be cut from the
canonical checkout's `HEAD`, and the run then left that checkout **detached**.
Both facts compound — agents built on whatever commit the last run happened to
leave behind, drifting further from the branch with every run, invisibly. Runs no
longer detach anything, but nothing repairs a checkout already in that state.
Once per canonical checkout, put it back on its branch:

```bash
git -C /Users/me/code/web status --short --branch | head -1   # "HEAD (no branch)" == detached
git -C /Users/me/code/web checkout develop
```

The only symptom of skipping this is agents working from a stale base, so it is
worth checking even where nothing looks wrong.

The agent finds everything through `$AL_RUN_MANIFEST`. The canonical checkouts
are never modified: they are read to cut worktrees from, nothing more.

`enabled` is `"auto"` (isolate when the cwd is a git repo), `true` or `false`.

A run dir is removed when the run ends. A run that was cut short keeps its dir
until it is resumed or expires — see [Sessions that are still open](#sessions-that-are-still-open).

### Provisioning: `up` and `down`

A fresh worktree has no `.env`, no `vendor/`, no `node_modules/` — they are
gitignored, so no checkout can produce them. Two optional scripts per project
fill that gap:

```
config/provision/<project>.up.sh     # after the worktrees exist, before the agent starts
config/provision/<project>.down.sh   # when the run ends, before they are removed
```

Each runs **once per repo**, with the working directory set to that repo's
worktree and the run described in its environment: `AL_REPO_NAME`,
`AL_REPO_PATH` (the canonical checkout), `AL_WORKTREE`, `AL_BASE`, `AL_RUN_DIR`,
`AL_RUN_MANIFEST`, `AL_PROJECT`, `AL_JOB_ID`, plus `AL_PORT_BASE`,
`AL_PORT_SPAN` and `AL_PROVISION_LIB` (below). See
`config/provision/example-hello.up.sh`.

A non-zero `up` **aborts the run** — the engine takes down what it provisioned
and never hands a half-built tree to an agent. A hook that outlives
`worktree.provision_timeout_seconds` (default 900) is killed. `down` runs once
a run's worktrees are actually removed — which a **preserved** run dir's are
not: an open session keeps its services running so a resume has something to
continue in, and `down` waits until the session closes (by finishing,
expiring, or being discarded by hand) before it ever runs.

A `down` hook must never call `agentloop worktree-drop` itself, directly or
indirectly: both the automatic sweep and `worktree-drop` hold an internal lock
across their own call into `down`, and it is the same lock `worktree-drop`
needs before it can run — so a `down` hook that reaches for it deadlocks
against its own caller, until `worktree.provision_timeout_seconds` kills the
hook, wedging every other job's resume and drop behind that same lock for as
long as it takes to time out.

Every worktree is cut from a freshly fetched base, and that fetch is bounded by
`worktree.fetch_timeout_seconds` (default 120). It has to be: the fetch happens
after the run has taken its slot but before the watchdog exists, so a remote
that accepts the connection and then goes quiet would pin the slot for as long
as the network stayed broken — and with `max_parallel: 1` that is the job dead
until someone notices. On a timeout the base is resolved from the refs already
on disk and the tick log says so.

#### Sessions that are still open

A session's worktrees are removed only once the session is **done**: the agent
declared how its run ended (a `RUN COMPLETE:`, `NOTHING TO DO:` or `BLOCKED:`
line in its final answer) *and* left nothing behind that exists on no remote.
Anything short of that keeps the run dir, and keeps its provisioned services
**up**, because `agentloop resume <job> <session>` continues in that same
directory: the agent's conversation remembers the files it edited, and a
fresh checkout of the base would not have them. Two ways a session ends up
open:

- A run that was **cut short** — killed, crashed, stopped by a watchdog, or
  simply never said it was finished — never reaches the declaration a done
  session needs.
- A run that ends holding commits or changes that exist on no remote is
  reported as a `warning` on the card (`UNDELIVERED: unpushed commits in
  api`) and its tree is kept too, whether or not it declared an ending —
  pushing is how work is delivered, and a resume is how the ticket gets back
  to a state where it can be.

Exit code, stderr and a spent budget cap describe how *well* a run went, not
whether its session has more to do, so none of them decide this.

An open session that nobody resumes expires after **24 hours**
(`AGENTLOOP_SESSION_TTL`, in seconds), at which point the sweep runs its `down`
hooks and removes it like any other finished run. The dashboard lists every open
session with its size, its age and the time it has left, and **Discard** ends one
early (`agentloop worktree-drop <job-id> <stamp>` from the CLI). A run dir a
live run is using is never offered, and never dropped.

Anything with a global name must derive it from `$AL_RUN_DIR`, or two concurrent
runs of the same repo collide:

```bash
SITE="${AL_REPO_NAME}-$(basename "$AL_RUN_DIR")"
herd link "$SITE"; docker compose -p "$SITE" up -d      # up
herd unlink "$SITE"; docker compose -p "$SITE" down -v  # down
```

#### Ports: `AL_PORT_BASE` and `bin/provision-lib.sh`

A unique compose project name stops two runs sharing containers. It does nothing
about **published ports**: both runs bring up the same stack, both try to publish
5432, and the second dies on "address already in use" — which reads as a broken
test suite and is nothing of the kind. Worktrees settle the filesystem; ports are
the other half.

So every isolated run is given a block of ports no live run holds — `AL_PORT_BASE`
and `AL_PORT_SPAN` (100 by default) — allocated under a lock and released with the
run's slot. `bin/provision-lib.sh` turns that block into numbers:

```bash
source "$AL_PROVISION_LIB"

al_copy_ignored .env            # the canonical checkout's gitignored files, into this worktree
al_env_ports .env               # every *_PORT the file already declares moves into this run's block
al_port POSTGRES_PORT           # or one at a time -> 21003, and the same number if asked again
al_env_set .env APP_URL "http://localhost:$(al_port APP_PORT)"
```

`al_env_ports` only rewrites keys the file **already has**: inventing ports for
services a project does not run would publish things nobody asked for. Nothing
here is Docker-specific — this is the general shape of "two copies of one stack at
once", which every project that isolates eventually meets.

`AGENTLOOP_PORT_RANGE_START` (21000), `AGENTLOOP_PORT_SPAN` (100) and
`AGENTLOOP_PORT_BLOCKS` (60) move or resize the range if it is already in use.

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

### Is the usage gate awake? `agentloop usage`

The scheduler holds scheduled runs back when a usage window is spent. That gate
reads a figure the CLI only volunteers once it has decided to warn (at 0.75), so
`bin/statusline-rate-limits.sh` keeps it fresh from your own interactive
sessions. Both halves are invisible when they work and invisible when they do
not, which is a bad way to run a fleet — so the command says which:

```
$ agentloop usage
five_hour: 62% used, resets in 118 min
  read 3 min ago from the statusline
seven_day: 97% used, resets in 2311 min
  read 3 min ago from the statusline, overage off (the ceiling is a dead stop)

SCHEDULED RUNS ARE BEING HELD BACK: the seven_day window is 97% used and
overage is off, so the ceiling is a dead stop -- it resets in 2311 min
  (`agentloop run <job>` still overrides this, as it does the budget.)

statusline: wired to /path/to/agentloop/bin/statusline-rate-limits.sh
  and it has fed the gate — readings above are live.
```

It names the wiring mistakes rather than leaving you to find them: a statusLine
that is not configured, one pointing at some other script, one whose path does
not exist (every session's status line failing in silence), and one that is
correctly wired but has never fired — the statusLine is read when a session
*starts*, so a session that was already open when you wired it never calls it.

To wire it, in `~/.claude/settings.json`:

```json
"statusLine": { "type": "command",
                "command": "/path/to/agentloop/bin/statusline-rate-limits.sh" }
```

It prints `5h 62% · 7d 18%`, so it still earns its place as a status line.

### Telling someone a run ended: `config/hooks/on-run-end.sh`

A loop that can only be checked by opening a web page is not really unattended.
Drop an executable script at `config/hooks/on-run-end.sh` and the engine runs it
after every run, with the outcome in its environment:

| Variable | |
|---|---|
| `AL_JOB_ID` | which job |
| `AL_STATUS` | `success`, `warning` or `error` |
| `AL_COST` | dollars this run spent |
| `AL_NOTE` | why it ended as it did (`BUDGET LIMITED: …`, `NOTHING TO DO: …`, a watchdog reason) |
| `AL_PROJECT`, `AL_SESSION`, `AL_LOG` | |
| `AL_START`, `AL_END`, `AL_DURATION` | epoch seconds, and the span |
| `AL_DASHBOARD` | the dashboard URL |

The engine knows nothing about notifiers, so this is where they go:

```bash
#!/usr/bin/env bash
[ "$AL_STATUS" = error ] || exit 0
terminal-notifier -title "agentloop: $AL_JOB_ID failed" \
                  -message "${AL_NOTE:-see the run log}" -open "$AL_DASHBOARD"
```

It is detached and time-limited (`AGENTLOOP_HOOK_TIMEOUT`, default 60s): a
notifier that hangs must never hold a run's slot open. Its output goes to
`data/exec.log`.

### When nothing runs at all: `config/hooks/on-fleet-stalled.sh`

The hook above fires when a run **ends**, which covers every way a run can go
wrong and none of the ways the fleet can stop having runs at all. If the usage
gate holds everything back for four hours, or a precheck fails on every tick
because the board credentials expired, or a slot left by a dead process blocks a
job for ever, then no run ever ends — the loop keeps ticking, the dashboard
keeps saying it is awake, and the work simply does not happen. That silence is
the most expensive failure this scheduler has, and it used to have no notifier.

Once per stall, the engine runs `config/hooks/on-fleet-stalled.sh` with:

| Variable | |
|---|---|
| `AL_REASON` | one sentence naming which of the four it is |
| `AL_STALL_HOURS` | the window that had no runs in it (`AGENTLOOP_STALL_HOURS`, default 4) |
| `AL_DASHBOARD` | the dashboard URL |

No dependencies needed — `osascript` ships with macOS:

```bash
#!/usr/bin/env bash
osascript -e "display notification \"$AL_REASON\" with title \"agentloop: nothing is running\""
```

**A quiet loop is not a stalled one.** `precheck found nothing to do` is
deliberately not a stall: a loop with nothing to do is the loop working, and
paging somebody for it trains them to ignore the message that matters. Nor is a
long run that outlasts the window — the slots are asked, not just the log, so
the run that is the *reason* there have been no new ones cannot be mistaken for
their absence.

It fires **once** per stall and re-arms the moment a run starts again, so a
fleet that stays stuck does not notify every minute until you turn it off.

### Tests

Two suites, both offline and free:

```bash
agentloop selftest        # the engine (bash)
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
counters, retained worktrees, the journal lock, the operator profile (what the
avatar column will and will not accept, and that changing a password needs the
current one), and the dashboard page itself — that its JavaScript parses, that
every element it reaches for exists, that the backoff curve it recomputes still
agrees with the engine's, and that its riskier save paths behave: they run the
page's real functions over a stub DOM in `node`, so a save that would wipe a
provisioning hook fails the suite rather than the operator's config.

`tests/security/` is run **twice**. It is pinned to the built-in secret scanner
(`AL_SECURITY_ENGINES=off`) so that a test planting a credential exercises one
scanner rather than whichever binaries a laptop happens to have installed — and
then, on a machine where **any** of `gitleaks`, `trivy`, `semgrep` or `syft` is
installed, one test runs the whole security package again with
`AL_SECURITY_ENGINES=on`, which is the configuration every real analysis uses.
All four are gated by the same switch — it decides the secret scanner, the
dependency source, the SAST pre-pass, the IaC phase and the SBOM producer — so
the second configuration is real on a machine with only one of them. The second
run roughly triples that package's time (about four minutes here, against ninety
seconds). It is the price of not discovering in production that the suite was
green only in a configuration nothing ships in — which is exactly what had
happened: the engines-on run was red for the entire life of the engine path and
nothing said so.

While iterating on that package, deselect the second run rather than switching
it off — there is deliberately **no** opt-out environment variable, because that
is the kind of switch that gets exported once and silently disables the gate:

```bash
python3 -m pytest tests/security/ -q \
  --deselect tests/security/test_both_configurations.py::test_the_security_suite_is_green_with_the_engines_on
```

Run both after touching either side.

**On a pull request this no longer depends on who is typing.**
`.github/workflows/ci.yml` installs `gitleaks`, `trivy`, `syft` and `semgrep` at
pinned versions and runs `tests/security/` as two named jobs, one per
configuration — plus `agentloop selftest` and the server suite. It **refuses
to be green over a skip**: every engine-gated test skips rather than fails when
its binary is absent (measured: 45 skips in `test_adapters.py` alone, and the
run still reports "passed"), so the workflow checks each engine's reported
version before starting and then fails the job on any skip other than the one
self-spawn guard. An unpinned engine would change what an analysis finds between
two runs of the same commit; bumping one is a deliberate commit that re-runs the
measurements those adapters cite.

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
*installed CLI* knows, which lags the API right after a release. `agentloop
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
they are not committed. The editor is a three-step form — the project, its repos
and worktrees, its provisioning — and every step is reachable at any time, so
fixing one field never means walking the other two.

```json
{
  "name": "web",
  "cwd": "/Users/me/code/web",
  "base": "develop",
  "worktree": {"enabled": "auto"}
}
```

`base` is the branch its runs are cut from — see
[Isolation](#isolation-one-worktree-per-repo-per-run) for what an empty one falls
back to and why that is usually not what you want. Add `repos` only when one
ticket really does touch several repositories.

### Which Claude account a run signs in as

Claude Code keeps credentials, settings, plugins, MCP servers and past sessions
**per config directory** — one signed-in account each. If you keep two accounts
on the same Mac (a company one and a personal one, say), the directory is the
only thing that chooses between them:

```bash
CLAUDE_CONFIG_DIR=~/.claude-work     claude    # work account
CLAUDE_CONFIG_DIR=~/.claude-personal claude    # personal account
```

Shell aliases for that never reach agentloop: `launchd` inherits nothing from
your shell, so by default every run signs in as the CLI's own `~/.claude`. There
are two levels:

| Level | Where | Applies to |
|---|---|---|
| default | `AGENTLOOP_CLAUDE_CONFIG_DIR` at install time | every run, and the model probes |
| per project | `claude_config_dir` in `config/projects.json` (**Edit project** in the dashboard) | that project's runs and their prechecks |

```bash
AGENTLOOP_CLAUDE_CONFIG_DIR=~/.claude-work bash install.sh
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

## Security analysis

Point it at a project and a branch and it reads the code: credentials committed
to the repository, dependencies with published CVEs, faults in the repository
itself, and a **SAST pass done by an agent** that reads the code around a match
and decides whether the input is reachable at all — so the noise a
context-blind scanner produces is never generated, rather than filtered
afterwards. Fix what it found, run it again, and the second analysis says what
closed, what did not, what closed halfway, and what is new.

**It needs no jobs.** A project can be registered for this and nothing else — no
schedule, no precheck, no prompt, no entry in `config/jobs.json`. Switch it on
in **Edit project → Security**, open **Security** in the sidebar, pick a branch
and press **Analyse**. The dashboard is the intended interface; the CLI at the
end of this section is the same thing without the page.

### Four screens

The area used to be one list of projects and, under whichever one you clicked, a
single analysis. Everything else it knew — the other branches, the findings of
the analysis before this one, who accepted what and when — was in the ledger and
on no screen. It is now four:

| screen | what it answers |
|---|---|
| **Index** | across the whole fleet: how many projects, how many analyses, what is critical and high across every project's latest analysis, what share of analyses finished clean, one row per project with its branch's posture, the newest analyses, and a severity donut with the rules that produced it |
| **Project** | one project, behind five tabs — **Overview** (one branch's posture and its checklist), **Runs** (every analysis of the project, filterable by state, each opening the single-analysis detail), **Branches** (one row per branch with a finished analysis: its own posture, how many analyses, a 30-day trend), **Findings**, **Reports** (one row per analysis, whatever its state, with all four downloads) — plus a sidebar with the project-wide donut and the last five things that happened |
| **Findings** | every finding of the project in one filterable, paginated table: severity, state, category, branch, analysis, path and free text over title/rule/rationale/file |
| **Activity** | what happened and when, every project or one, filterable by kind |

**Each screen fills itself from one request** — `/api/security/index`,
`/api/security/project`, `/api/security/findings`, `/api/security/activity`, each
behind one CLI verb. The project's header, its sidebar and four of its five tabs
come back in that single call; the findings browser keeps its own, because its
sorting, filtering and paging are all resolved server-side. What this replaces is
a page that spent one `security list` per project on every load and every
refresh, plus a `security checklist` for each one that had ever finished — a
subprocess per project, mostly to redraw numbers that had not moved.

Findings is the one of the four that is not its own destination: it is a single
module mounted where it is needed, so the project's Findings tab and the
dialog that opens when you click a decision's fingerprint on Activity are the
same browser, filtered differently, and not two tables to drift apart. Both can
be open at once, and each keeps its own filters.

`total` and `unique` are shown as two labelled numbers above it, never collapsed
into one: the same finding open on `main` and on `develop` is two rows and one
problem, so 189 findings can be 93 problems, and a single number silently
answers whichever question you were not asking.

**Saved filters.** The view somebody works from every day — say critical and
high, secrets only, resolved hidden, sorted by branch — is saved under a name per
project, sort column and direction included, and restored in one click.
Re-saving a name replaces it rather than leaving the old version behind under the
same label, and a name longer than 80 characters is *refused* rather than
truncated: truncation used to run before the key saw it, so two different names
sharing their first 80 characters overwrote each other, and neither could be
deleted by what you had actually typed.

### Every number on those screens is current posture

Not a running total of everything ever found — that only grows, and a number
that only grows says nothing about whether you are winning. Every count is read
off the **latest finished analysis** of the scope it describes, with three
stated exceptions, all honest all-time totals: the index's *Analyses* card
(which says so on the card itself), the *Analyses* column of the index's
project table (`queries.project_rows`, a `COUNT(*)` over every analysis of the
project regardless of state), and the *Analyses* column of the Branches tab
(`queries.branch_rows`, a `COUNT(*)` over every finished analysis of that
branch, ever — not just the latest).

**Open** means every state that is not `fixed`, `accepted` or `false_positive` —
so `new`, `open`, `partial`, `regressed` **and `pending`**. A finding nobody
re-checked is exposure nobody closed, and filing it with the resolved would be
the same lie as a premature `fixed`.

**Success rate** is `done` over *finished*, where finished is `done` + `capped` +
`failed`. A `capped` analysis reached its ceiling and a `failed` one did not
complete, so neither is a success; a `running` one is not a verdict yet and is in
neither half. With nothing finished the card shows a **dash, never `0%`** — no
finished analysis and a zero-percent success rate are different facts.

**A screen can show two different postures, and both are right.** The project's
Overview panel describes **one branch** (the project's declared base, or the
branch it fell back to, named either way). The sidebar's donut and its category
ranking describe **every analysed branch**, collapsed to one entry per
fingerprint — because a secret reachable on `main` and on `develop` is one
rotation, not two. The Branches tab counts the same finding once *per branch*,
because that is what "this branch's posture" means. Each of the three says which
question it is answering rather than being forced to agree with the others.

**Lines of code** sits in the project header, and is a by-product of the
deterministic walk rather than a second pass over the tree: the secret scan is
already reading every file, so it counts the lines of the ones it actually
opened. A file that was skipped — too big, unreadable, or matched by
`ignore_paths` — contributes nothing, so the number describes what was analysed,
not what is on disk. It is a count and never the text: nothing about it can put a
file's contents into the ledger. An analysis that never counted (every analysis
older than the column) shows a **dash**, not `0`, which would read as an empty
repository.

### The event log, and why it has no user column

Five things are recorded, each with the project, a one-line detail and what it
relates to:

| kind | filed when |
|---|---|
| `analysis_started` | the ledger row is opened, naming the profile and branch |
| `analysis_finished` | the row is closed, naming how (`done · standard on main`) |
| `decision_made` | *Accept risk* / *False positive*, carrying the written reason and the first 12 characters of the fingerprint |
| `settings_changed` | a project is saved **and has security enabled** — a save on a project this area knows nothing about is not this area's history |
| `report_exported` | a Markdown, JSON, HTML or SBOM report is actually rendered — filed after the render succeeds, never on the click |

**There is no user column and no IP column**, and that is a decision rather than
an omission. This install has exactly one operator — `app.db` enforces it with a
`CHECK (id = 1)` — so a `who` column could only ever hold one value, and a column
with one value teaches nothing while looking like it teaches something. The
server binds loopback only, so there is no address worth recording either. For
the same reason the Activity screen has no "most active users" panel; it ranks
the busiest **projects** instead, which is a question with more than one possible
answer.

Filing an event is best-effort at every one of those five sites: a busy ledger
must never turn a successful decision, or a successful close, into a traceback.
The audit trail is not the thing being audited.

### The branch is chosen per analysis, and the worktree is cut clean

Every other run takes its base from the project's declared config. An analysis
targets whatever is under review — `main` today, `release/2.1` tomorrow — so the
branch is a choice made when you run it, not a field written into the project
beforehand. The picker lists what the checkout actually has, local heads and
`origin/` alike, with a free-text field beside it for a branch pushed a minute
ago. A branch that resolves to nothing is refused before anything is cut:
analysing `main` when you asked for `release/2.1` would produce a report that
reads as correct and is about the wrong code entirely.

The worktree is cut from that branch and **nothing is provisioned** — reading
code needs no `.env`, no `vendor/`, no containers, so an analysis neither pays
for a project's `up` hook nor is stopped by one that fails. The canonical
checkout is read to cut from and never modified, as in every other run, and the
tree is removed when the analysis ends.

The profile decides how far the **agent** reads. The deterministic half below
runs in full in all three:

| profile | the SAST pass covers |
|---|---|
| `quick` | only code that touches external input — HTTP handlers, CLI entry points, queue consumers, deserialisation, SQL, `exec`/`eval` |
| `standard` | that, plus the code those reachable paths call, following the calls in depth |
| `deep` | all versioned code, including paths nothing currently invokes |

A monorepo's baseline is the expensive analysis; the ones after it are mostly a
diff. `quick` is there so you can look before deciding to spend.

### What is found before the agent is even launched

Secrets across the whole tree, and across the branch's whole git history on
**every** analysis. A dependency inventory read from the lockfiles it knows
(`package-lock.json`, `requirements.txt`, `poetry.lock`, `composer.lock`,
`go.sum`), a CycloneDX SBOM built from that, repository hygiene (a committed
`.env`, a file whose first bytes are a private key, a world-writable file),
and infrastructure-as-code misconfigurations in any Dockerfile, Terraform
module, Kubernetes manifest, Helm chart or CloudFormation template committed
to the repository. All of it runs by pattern, so it takes seconds and costs
nothing.

It is written to the ledger **moments after the agent starts** — `prepare` is
the agent's first command, named in the prompt and in the skill — which is why
the page fills with secrets and CVEs within seconds of the click while the SAST
pass is still going. Nothing engine-side runs it, so the engine checks instead
that it ran: an analysis whose deterministic phases never happened is closed
**`capped`, never `done`**, with a coverage note saying so. A report with
nothing behind it must not become the baseline the next analysis is diffed
against.

The agent's own contract is versioned rather than typed into a prompt
(`skills/security-analysis/SKILL.md`) and it does three things in this order:
re-verify the findings the previous analysis left open — the cheapest of the
three and the most valuable, so it goes first — triage what the deterministic
phase found (is that "secret" an example in the documentation? is that CVE on a
path anything reaches?), then the SAST pass at the profile's depth. It never
writes to the database: every finding goes through `agentloop security
report-finding`, which validates before it stores. The agent is
non-deterministic, and the history that produces the checklist cannot be only as
trustworthy as the last JSON it happened to type.

### The checklist: eight states, six of them derived

| state | what it says |
|---|---|
| `new` | not in the previous analysis of this branch |
| `open` | it was here last time too, unchanged |
| `partial` | some of its places are gone, or the agent recorded it as mitigated but not eliminated |
| `pending` | it was here last time and **this** analysis has not re-checked it yet |
| `fixed` | gone since the previous analysis, *and* the phase that would have re-found it finished |
| `regressed` | it was fixed once, and it is back |
| `accepted` | you accepted the risk |
| `false_positive` | you said it is not real |

The first six are **derived** by comparing this analysis with the previous
*finished* one of the same branch, and not one of them is stored — a stored
state is a state that can end up disagreeing with the findings it describes. The
last two are the only judgements the ledger keeps, because they are the only
ones a human made.

**`pending` is the state that keeps `fixed` honest.** Absence is only evidence
once the looking has finished, and a checklist rendered nine seconds into a run
has looked at nothing — it used to declare the entire baseline `fixed`, 43
findings "resolved" before `prepare` had written a byte, and a `capped` run told
the same lie at the end about the code its SAST pass never reached. A baseline
finding missing from this analysis is `fixed` only when its absence is *proven*:
for the deterministic categories (secrets, dependencies, hygiene, IaC) once `prepare`
has completed, for everything the agent reads only when the analysis closes
`done` with full coverage. Anything short of that is `pending` — a statement
about this analysis, never about the code — and it is counted with the open
exposure, never with the resolved.

**`regressed` is the row that earns its keep.** Without it the finding comes back
as `new`, and `new` hides exactly what you need: this was closed once and it has
returned, which usually means the fix closed the symptom and not the route. It
needs no stored state to derive — the fingerprint reappears, and an older
analysis of this branch already carried it.

`partial` has an objective half and a judged half. The objective half is a set
difference over the **files**, never a subtraction of two counts: three hits in
one file dropping to two is the same file still holding the same hole, while one
hit moving from `auth.py` to `admin.py` is one place genuinely closed and
another opened — and counting calls the first progress and the second nothing at
all. The judged half is the agent's note, which catches the fix that makes the
pattern disappear without closing the hole.

### A fact belongs to a branch; a decision belongs to the project

Comparing `main` against `develop` would report half a repository as new, so
findings are only ever compared **within one branch**. But dismissing a false
positive on `develop` and watching it resurrect on `main` would make the area
unusable, so a **decision** — *Accept risk* or *False positive* — is recorded
against the **project** and follows that finding onto every branch and every
analysis after it.

**A decision needs a written reason.** The dialog asks for one and the API
refuses a blank one, so the refusal is never how somebody discovers the rule. In
three months that sentence is the only thing that says whether this was a
judgement or a slip. Who decided is taken from the signed-in operator, never
from the request body.

**Change the code around a decided finding and it comes back as `new`.** A
finding's identity is a sha256 over its category, rule, path and a
whitespace-normalised snippet — so reformatting a file does not resurrect the
whole report, and the line number is left out so that an import added above a
finding does not either. Change what the code actually *says* and it is
different code, which deserves a fresh judgement rather than an inherited one.
Surprising the first time it happens; correct.

### A secret's value is never stored, and never shown

Not in the ledger, and not in any of the report formats it renders from it.
Not masked, not truncated, not partially quoted. (The run's live stream is the
agent's own output and this engine does not filter it — the contract that the
agent never prints a value is in `skills/security-analysis/SKILL.md`, not in
code. What the code owns is the ledger and everything generated from it.) What you get is the
credential's type, the file, the line and a fingerprint — enough to act on, and
nothing worth leaking. The identity of a secret finding is deliberately its
**type and its file**: hashing the value would put a weak but real oracle for
the secret into a database, and anchoring on a position would make an untouched
credential look `fixed` and `new` again the moment an unrelated line moved above
it.

**Rotating the credential is human work, and the report says so.** Deleting the
line does not help while the value is still reachable in the history — which is
why the history is swept on **every** analysis, not only the first. A key
committed on Monday and deleted on Tuesday is still compromised, it is the case
that leaks most often, and it is precisely the one a working-tree scan cannot
see.

**A history finding never becomes `fixed`, because git history does not
shrink.** It is reported `new` once and `open` on every analysis after it, for
as long as the commit exists — deleting the file changes nothing about it, and
a checklist that said `fixed` there would be congratulating you for the exact
act the remediation calls insufficient. The only honest close is the human one:
rotate the credential at the provider, then *Accept risk* with that as the
written reason. (The sweep is `git log -p` and plain Python: seconds, and no
tokens. The old reasoning — that re-reading commits already read is wasted
wall-clock — was right about the seconds and wrong about the report: nothing
re-emitted the finding, so it read as `fixed` on the second analysis and
vanished from the third.)

A secret that is in the working tree **and** in the history is one finding, not
two — same rule, same path, therefore one identity. The working-tree reading is
the one you see, because it carries the real line number; the remediation is
the history's either way.

### CVEs need OSV.dev, and every way of missing it says so

Everything else here runs on your machine. A vulnerability database does not
exist unless somebody publishes it, so the inventory is queried against the
public OSV.dev API: **package names and versions leave the machine; code never
does.** No dependency's source is read at all — not `node_modules/`, not
`vendor/` — it is noise, and it is the only code in a checkout that nobody there
wrote.

Whichever way OSV.dev goes unconsulted, **the analysis carries on** rather than
failing outright, and the report opens with the gap in writing — three distinct
wordings for three distinct cases, never one generic warning standing in for
all of them:

- **Deliberately offline** (`prepare --offline`, networking disabled on
  purpose): *"Dependency CVEs were NOT checked against OSV.dev: this analysis
  ran with networking disabled."*
- **Unreachable outright** — no chunk of the inventory got a usable answer:
  *"Dependency CVEs were NOT checked: the OSV.dev lookup did not complete
  (`{reason}`). Everything else in this report is complete."*
- **Stopped partway** — some chunks answered before one failed, and their
  findings are kept, not discarded: *"OSV.dev stopped answering partway
  (`{reason}`): `{checked}` of `{total}` components were checked and their
  findings are included; the remaining `{total - checked}` were NOT checked."*

Each names the source that did not answer rather than leaving you to guess
which question the report cannot be asked. A stated gap is useful; a silent one
makes you trust a report that never looked at your dependencies. The same
channel carries every other kind of incompleteness — an analysis that hits its
ceiling closes as `capped` and says what it did not reach, instead of
presenting a partial read as coverage.

### The `security` block on a project

```json
"security": {
  "enabled": true,
  "model": "opus",
  "effort": "",
  "permission_mode": "bypassPermissions",
  "claude_config_dir": "",
  "default_profile": "standard",
  "max_budget_usd": 5,
  "daily_budget_usd": 20,
  "min_severity": "medium",
  "ignore_paths": ["tests/fixtures/**"]
}
```

The **Security** tab of the project editor writes all of it. A project with no
block gets no analysis, and no derived job either.

The engine reads `enabled`, `model`, `effort`, `permission_mode`,
`claude_config_dir`, `max_budget_usd`, `daily_budget_usd` and `ignore_paths` —
`permission_mode` defaults to `bypassPermissions` when absent (an unrecognised
value falls back to it too, with a warning) and is carried onto the derived
job the same way. `default_profile` and `min_severity` belong to the
**dashboard** alone — the profile Analyse offers first, and a display floor —
and no part of the engine looks at either.

`model` left empty means the `opus` family; `effort` left empty leaves the
decision to the CLI, as in a job. `claude_config_dir` is carried on the derived
job — the only place an analysis has to carry it, there being no jobs.json row
to edit — and the job's own value is what a run resolves first; left empty it
inherits the project's, which inherits the install's — see [Which Claude account
a run signs in as](#which-claude-account-a-run-signs-in-as). Set it here only
when the analysis itself should sign in as somebody else.

**Some noise is filtered before you configure anything.** A `fixtures`,
`__fixtures__` or `testdata` directory — at any depth, and whatever its case —
is outside the analysis by default. In a file ending `.example`, `.sample`,
`.template` or `.dist` — a committed template of a configuration rather than a
leak — the **two rules that over-fire on templates** are held back: the generic
`password = <blob>` rule and the AWS access-key rule, which is what
`AKIAIOSFODNN7EXAMPLE` in a `.env.example` trips. **Every other credential
shape is still reported from a template, a private key included** — a PEM body
is not a placeholder, and a real key committed as `server.key.example` is a real
leak. Both defaults reach every phase and both scanners, and the coverage note
says so on every report, because "nothing was found there" and "we never looked
there" are the same silence otherwise. **`tests/**` is deliberately not
covered:** a credential hard-coded in a test file is in the repository and
readable by everyone with a clone, so it is still reported. A project that keeps
real credentials in a fixture it *wants* reported adds the entry `!defaults` to
`ignore_paths` and gets both halves back — it cancels the built-in default only,
never the globs you wrote yourself. `!defaults` is the **only** `!` entry that
means anything: any capitalisation of it works, and anything else beginning with
`!` (`!default`, `!defaults/**`) is dropped, never treated as a path, and named
in the coverage note as having done nothing — the default is still on. Note that
turning the default on for the first time makes any fixture finding already in
the ledger show up as `fixed` once, and a human decision recorded against one is
only reachable again with `!defaults` set.

**`ignore_paths` and `min_severity` are two different filters, and confusing
them is expensive.** `ignore_paths` excludes globs from the **analysis**: the
working-tree secret scan, the git-history secret sweep, the hygiene pass, the
infrastructure-as-code check and the SAST pre-pass all obey the same globs, so a
fixtures directory full of deliberately fake credentials never becomes a finding
at all — from any of the five, and the dependency findings read out of a
lockfile under one of those globs are filtered too. The one deterministic phase
it deliberately does **not** filter is
the dependency **inventory**: a lockfile under an ignored glob still declares
packages this project ships, so the SBOM stays complete wherever the file sits.
The *findings* from that lockfile **are** filtered, which is a real gap between
two things you can download — an SBOM listing lodash 4.17.20 beside a report
with no dependency findings does **not** mean lodash 4.17.20 is clean. When it
happens the coverage note says so, with the count and the lockfiles.
`min_severity`
filters only what is **shown**: everything found is kept in the ledger whatever
its severity, so lowering the floor later reveals what was recorded all along
instead of forcing a re-analysis, and the page says how many findings it is
holding back. A `fixed` finding is shown whatever the floor — the one job of a
checklist is to say what closed. **The downloads are not filtered at all**:
every recorded finding is in the file whatever the floor on screen shows, and
the page says so next to the buttons.

**`info` is the floor's whole point.** Below `low` there is a fifth severity for
findings that are advice rather than exposure — nothing is leaking, but this is
how the next thing leaks. The deterministic phase emits exactly one today: a
repository with **no `.gitignore` at all**, because without one the first `.env`,
key or credential file somebody adds is committed by default. The agent may
report at `info` too, and the ledger takes it like any other severity. It sits
below every floor the editor resolves to on its own — a new project starts at
Medium, and an existing project that never set one reads as Low — so an
informational finding is recorded, kept, and stays out of the way until you drop
the floor to **Info** and go looking for it. That is the arrangement worth
having: recording it costs nothing, and a report that opens with a `.gitignore`
lecture above a committed private key is a report nobody finishes reading.

**The per-analysis cap is the one that actually bites.** An analysis always runs
forced, the way **Run now** does, so it skips the usage gate, the daily cap and
the global cap: `max_budget_usd` is the only ceiling left standing over it. That
is also why a `max_budget_usd` the engine cannot read as a number is not simply
dropped the way an unusable `daily_budget_usd` is — it falls back to a
conservative **$2** and says so in `tick.log`, because dropping it would run the
analysis with no ceiling at all.

### An analysis is a run, with no job behind it

A project with security enabled has a job **derived in memory** the moment
anything asks to run one, with the id `security-<project>`. It is not in
`config/jobs.json` and never will be: the tick, the dashboard's Jobs area and
every write of the jobs file read that file directly, so none of them can see a
derived job — not by discipline, but because those paths never meet one. Delete
the security block and the job is gone with it.

What that buys is everything a run already has: the watchdog, the spending caps,
the live stream, the timeline with one line per agent turn, and full-text
search. **An analysis that goes strange is investigated in Recent runs, beside
everything else** — there is no second place to learn to look, and each analysis
on the Security page links straight to its run.

Two consequences worth knowing:

- **One analysis per project at a time.** The derived job carries
  `max_parallel: 1`, and `security analyze` refuses a second one with a sentence
  on your terminal rather than a line in the tick log and a silent exit 0.
  Different projects analyse in parallel, taking engine slots like any other
  run: an analysis has no priority over the jobs, nor they over it.
- **The `security-` prefix is reserved.** `create` and `rename` refuse it, so a
  real job can never collide with a derived one, and every by-id write —
  `delete`, `enable`/`disable`, `toggle-many`, `reorder`, `set-prompt`,
  `set-field`, `set-precheck` — refuses a derived id and tells you to configure
  it on the project instead. `run`, `resume`, `stop` and `say` are untouched: a
  derived job exists to be run.

**A project with one checkout keeps one history.** An analysis is filed under a
`repo`, and a single-repo project declares no `repos` rows, so the argument
names nothing — the label is normalised to the project's own name, in the page
and in the terminal alike. Without that, one hand-typed spelling opens a second,
parallel history the dashboard never shows beside the first.

### From the terminal

```bash
agentloop security analyze [--detach] <project> <repo> <branch> [profile]
```

`<repo>` is the project's own name when it declares a single checkout — anything
else is normalised to it — and `[profile]` defaults to `standard`. Without
`--detach` the analysis runs in the foreground. With it, every refusal (security
not enabled, no such branch, one already running) still happens synchronously,
then the run is handed to a background process and the command prints
`{"analysis_id": n}` and returns. That is the path the dashboard's **Analyse**
button takes: the control server gives a CLI call thirty seconds before it kills
it, and an analysis is minutes of work — the button used to spin, report a
timeout, and leave the row `running` for ever with the agent orphaned behind it.

The rest of the vocabulary is the ledger's own and belongs to the agent and the
page. The agent's half is `prepare`, `findings`, `fingerprint`,
`report-finding`, `checklist`, `render` and `finish`; the engine's and the
operator's are `open-analysis`, `decide`, `rename-project`, `migrate-rules`,
`list` and `event`. `migrate-rules` is the one that is run after a release
rather than during an analysis: a rule's name is part of every finding's
fingerprint, so renaming a detector's rule would report each finding under it
as fixed *and* new in the same report and strand every human decision on an
identity nothing will produce again. `taxonomy.RULE_RENAMES` records that the
two names are one rule and this verb walks the ledger, carrying each finding
and its decision to the new identity. It takes no arguments, it is safe to run
twice, and it is refused for the categories whose fingerprint cannot be rebuilt
from what the ledger stores — `sast` (built from the code snippet, which is
never stored) and `dependency` (a CVE id nobody renames).
It is also refused on a machine without gitleaks, or with
`AL_SECURITY_ENGINES` switched off. The secret renames exist to move findings
onto *gitleaks'* rule names, and such a machine falls back to the built-in
pattern scanner, which mints the old names again on the very next analysis:
every migrated secret would then be reported fixed *and* new in one report,
with the human decision on each side stranded — the exact damage this verb
exists to prevent. Install gitleaks first, then migrate.
Each of the four screens has one read verb behind it — `index-data`,
`project-data`, `findings-page`, `activity-data` — answering that whole screen in
a single call, plus `analysis`, `events` and `filters list` for the smaller
reads. `filters save` and `filters delete` are writes, not reads — they are in
`AGENT_FORBIDDEN` for exactly that reason. `agentloop security render
--analysis <id> --format md|json|html|sbom` is what the four download buttons
call.
`sbom` is the odd one out: it is not a report over the checklist but the stored
CycloneDX inventory itself, downloaded as `.cdx.json` — the suffix the tools
that consume one recognise. It is kept per branch with the most recent
analysis's document, so asking an older analysis for it hands back the current
one for that branch rather than a reconstruction of what the tree held that
day, and a project with no lockfile the inventory can read has none to give and
says so. During an
analysis run, `decide`, `rename-project`, `open-analysis`, `event`, `filters
save` and `filters delete` are refused — the agent that reports a finding does
not get to dismiss it, rename the ledger out from under the project, open
analyses of its own, write straight into the audit trail that exists to say what
it did, or edit the working set a human curated. The read verbs beside them
(`events`, `filters list`) are deliberately *not* refused: there is nothing there
for the flag to protect, only a query the agent may legitimately want.

**That refusal is a guardrail against mistake, not a boundary against malice,
and it is worth saying which.** It works off `AL_SECURITY_AGENT`, a variable in
the agent's own environment, and the agent has a shell: `env -u
AL_SECURITY_AGENT agentloop security decide …` walks straight past it. What
it stops is the failure that actually happens — a model deciding, in good
faith, that retiring the finding it just filed is the helpful thing to do — and
it stops that cold. Nothing here is load-bearing against an agent that is
trying. The one check that does not depend on the environment is `decide`'s
own: **while any analysis of the project is `running` — not only the newest
one — a decision is refused whoever is asking.** That window is exactly when
an agent of that project is alive, and it costs a human nothing to wait — the
checklist is rebuilt when the analysis closes, so a decision taken mid-run
would not have changed that run's report anyway. Still a guardrail, not a
lock nothing can pick: an agent with direct access to the ledger file could
write a decision without going through this door at all.

### Changing the UI: `ui/` is the source, and the built files are committed

`ui/` holds three kinds of source, one per built artifact. The four security
screens are ES modules under **`ui/security/`**, bundled into
**`bin/static/security.js`**. The Overview's renderers are ES modules under
**`ui/app/`**, bundled into **`bin/static/app.js`** — both by the same pinned
esbuild. The stylesheet itself is plain CSS under **`ui/css/`**
(`tokens.css`, `components.css`, `pages.css`), and becomes
**`bin/static/app.css`** by concatenation, not a bundle: CSS has no imports and
no module graph for esbuild to resolve, so running it through a bundler would
buy nothing but a minifier's opinions on a diff that should stay readable. The
three files are concatenated in the order a reader would need them — tokens
first, since everything below reads them; components before pages, so a page
rule wins a tie against the component it specialises.

**All three built files are committed to the repository.** That is the whole
trade: installing agentloop still needs only **jq, python3 and curl** — Node
is a developer dependency, and the day it becomes an install dependency is the
day this stops being worth it.

The price of a build output in git is that it can be forgotten, and a stale
artifact is a dashboard silently running last week's code — or last week's
styles — with nothing on screen to say so. So:

```bash
bash build/build-ui.sh          # in the SAME change as any edit under ui/
node --check bin/static/security.js
node --check bin/static/app.js
```

and `agentloop selftest` refuses a tree where that did not happen, for each
of the three artifacts in turn. The assertion is **"the committed UI artifact
matches the sources it was built from, and has not been touched since"**; the
first half fails with `bin/static/app.css is stale — run build/build-ui.sh` (or
whichever of the three drifted), the second with `...has been MODIFIED since it
was built`. It works off two content fingerprints that `build/build-ui.sh`
stamps onto each artifact's last two lines as block comments — `/* ui-sources:
<sha256> */` and `/* ui-bundle: <sha256> */` — block, not `//`, because
`bin/static/` holds CSS as well as JavaScript and CSS has no line comment; `/*
… */` is valid in both, ignored by every browser, and greppable without parsing
anything. `ui-sources` is what the artifact was built **from**, recomputed by
the selftest with `build/ui-digest.sh`; `ui-bundle` is a hash of the artifact's
**own body**, taken before either stamp is appended, recomputed with
`build/ui-bundle-digest.sh` — the one that catches code injected straight into
the committed bytes with every source left untouched. Two definitions, each
read from two sides: written twice, the day either drifted from its reader the
check would be reporting on nothing.

Two details of that fingerprint are load-bearing. It hashes each file's **path as
well as its bytes**, so a module added, renamed or deleted changes the answer
even when the total content has not. And it hashes `build/build-ui.sh` and
`package.json` alongside **every file under `ui/`** — not a `*.js` glob, so
`ui/css/*.css` counts too — because those are inputs to the build too: a
changed `--target`, a changed `--format` or a bumped esbuild pin changes what
the committed bytes should be without touching a single source file, and
hashing only some of the sources would let any of them land under a green
"matches its sources".

It is **content, never mtime**. Git does not record mtimes, and a checkout writes
paths in index order — every `bin/…` before every `ui/…` — so on a fresh clone
the sources are always newer than the artifacts built from them. An mtime rule
would fail for every person who had changed nothing at all, which is the
fastest way to teach everybody to ignore a selftest.

---

## Dashboard

- **Jobs** — one card each: schedule, last check (with the precheck's output),
  checks in the last 24h (proof the loop runs even when idle), last run, today's
  spend vs cap, and **Run now / Enable / Disable / Edit / Delete**. Destructive or
  wasteful actions confirm first. A job holding a session from a run that was
  cut short says so right on the card — when it expires, and a **Resume**
  button when there is a session id to continue — rather than only a count on
  the Sessions tab below.
- **Recent runs** — full-text **search** across run results, per-turn traces and
  precheck output; **Filters** (job, status, date range) behind a button;
  pagination. The 🔍 on each row opens the run: did the precheck pass, which tools
  were blocked, a **timeline with one line per agent turn**, the final answer, and
  stderr.
- **Sessions** — every run directory still on disk, kept because its session
  was cut short or still holds work that exists on no remote; see [Sessions
  that are still open](#sessions-that-are-still-open). Size, age and time left
  per row, and **Discard** ends one early.
- **Security** — the four screens of the [security analysis](#four-screens)
  area: the fleet index, a project with its five tabs, the findings browser and
  the activity log. It needs no jobs, and nothing here appears until a project
  turns it on.
- **Theme** — light/dark toggle in the header.

### Signing in

The dashboard has one account — the person running this install — kept in
`data/app.db`. A fresh install asks for a name, email and password before it will
open anything; an existing install asks on the first load after updating. The
password is stored PBKDF2-hashed and **cannot be recovered**: nothing on the
machine can read it back, and there is no reset.

A session lasts 12 idle hours, or forever with **Keep me signed in**. Signing out
ends it everywhere. Clicking your name at the foot of the sidebar opens the
profile: name, email, photo, and a password change that asks for the current one
(a signed-in tab is not proof of who is at the keyboard). The photo is stored
inline in the database, scaled to 256 px in the browser first, so there is no file
to serve and nothing left behind when it is replaced.

This is a lock on the **page**, not a second lock on the port. The server has
always bound loopback only and required its token; the account is what stops
someone at your unlocked desk from starting a run that spends money. Anyone who
can already run commands as you can read `data/app.db` and mint their own session
— treat it as it is.

---

## CLI

```bash
agentloop dashboard          # open the control UI
agentloop status             # jobs + last run + cost, in the terminal
agentloop run <id>           # force a run now (ignores precheck + daily cap)
agentloop check <id>         # run only the precheck, report what it saw
agentloop enable|disable <id>
agentloop toggle-many true|false   # ids on stdin (JSON array or one per line)
agentloop create <id>        # JSON object on stdin
agentloop set-prompt <id>    # prompt on stdin
agentloop set-precheck <id>  # script on stdin
agentloop set-field <id> <field>   # value on stdin (interval_seconds, active_hours,
                               #   active_days, model, effort, max_budget_usd,
                               #   daily_budget_usd, stall_timeout_seconds,
                               #   timeout_seconds, permission_mode, description,
                               #   cwd, project)
agentloop delete <id>        # remove the job (its logs are kept)
agentloop project-set        # create/update a project (JSON on stdin)
agentloop project-list | project-delete <name>
agentloop provision-set <project> up|down   # worktree provisioning script (stdin)
agentloop provision-get <project> up|down
agentloop worktree-drop <id> <stamp>   # discard a preserved run dir for good
agentloop security analyze [--detach] <project> <repo> <branch> [profile]
                               #   run an analysis (see Security analysis)
agentloop security-branches <project> <repo>   # branches that checkout has
agentloop resolve-models     # refresh which model each family points at
agentloop skills             # show / link the skills the agent prompts require
agentloop selftest           # offline checks of the logic that can kill a run
agentloop install | uninstall
```

Environment overrides: `AGENTLOOP_PORT`, `AGENTLOOP_CONFIG`,
`AGENTLOOP_DATA`, `AGENTLOOP_CLAUDE_BIN`, `AGENTLOOP_CLAUDE_CONFIG_DIR`,
`AGENTLOOP_PYTHON`, `AGENTLOOP_JQ`, `AGENTLOOP_LOG_MAX` (log rotation
threshold, default 4 MiB), `AGENTLOOP_HOOK_TIMEOUT`, `AGENTLOOP_LOCK_GRACE`,
`AGENTLOOP_SESSION_TTL` (open-session expiry, in seconds, default 86400).

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

**`data/app.db`** is the other database, and the only one that is *not* derived:
it holds your profile, your live sessions and the dashboard's preferences. Delete
`index.db` and it rebuilds from the journal; delete `app.db` and the next load
asks you to create a profile again. Back it up with the rest of `data/`.

**`data/security.db`** is the [security analysis](#security-analysis) ledger, and
is not derived either: every analysis with the branch and commit it read (and
how many lines of it were walked), the findings and the places each one was
found, the decisions you recorded (keyed by the project, so they outlive a
branch), the [event log](#the-event-log-and-why-it-has-no-user-column), your
saved filters, and one SBOM per repo and branch — the
latest, replaced on every analysis, because it is the only large artefact here
while the analyses themselves are tiny and all kept. **Reports are not files**:
Markdown, JSON and HTML are generated from the ledger at the moment you download
one, so a risk accepted after the analysis ran shows as accepted in the file you
get, instead of a frozen artefact that disagrees with the page you have open.

**Logs.** `data/tick.log` (scheduler decisions) and `data/exec.log` (detached
runner and provisioning-hook output) are append-only and are rotated by the tick
once either passes `AGENTLOOP_LOG_MAX` (4 MiB). Exactly one previous
generation is kept, as `.1` — the chain never grows.

---

## Security

The control server binds **127.0.0.1 only** and is never reachable from the
network. Every `/api/*` call requires a secret token (`config/control.token`,
chmod 600) that is embedded only in the same-origin page; cross-origin requests
are rejected and a custom header forces a CORS preflight the server refuses — so
no web page open in your browser can drive your agents. Every mutation shells out
to the `agentloop` CLI, so the bash engine stays the single source of truth.

On top of that the page requires a **signed-in operator**: every `/api/*`
endpoint but `/api/session` and `/api/login` refuses until there is one, and the
sign-in and first-run screens are what you get instead. Two routes answer
before that gate is even checked: `/health` always has, and `/static/*` does
too, deliberately — the bundle it serves is not secret (it ships in git, in
every install) and it is the same page that draws the login screen, so gating
it would leave a signed-out browser holding a page whose own code it is not
allowed to fetch. Passwords are PBKDF2-HMAC-SHA256 at
600k rounds; the session cookie is `HttpOnly` and `SameSite=Strict`, and the table
stores only its SHA-256 digest, so reading `app.db` hands over no live session.
None of this defends against someone who can already run commands as you — they
can write the database. It defends against the tab left open on an unlocked
machine, which is the realistic way an unattended agent gets started by the wrong
person.

**Autonomous agents act with your Claude credentials.** A job with
`permission_mode: bypassPermissions` runs tools without prompting. Give such jobs
a `daily_budget_usd`, watch the run log, and use the kill switch
(`agentloop disable <id>`) freely.

---

## Changing this scheduler

Other people run this on their own projects, so three rules hold for every change
that reaches `main`:

1. **Fill in `CHANGELOG.md` in the same commit as the code.** Not afterwards, not
   batched at release time — written while the reason is still known. An entry
   says what behaviour changed and what it cost to not have it: *"a long tool call
   is no longer read as a hang — a 40-minute suite used to be killed at the stall
   timeout"*, never *"fixed watchdog"*. `agentloop selftest` fails when `bin/`,
   `skills/` or `test/` moved after the last changelog entry.

2. **A rule the code enforces must travel with the code.** `config/` is
   git-ignored — personal paths, repositories, tracker ids, budgets — and rightly
   so. Anything the scheduler *depends on* therefore cannot live only there. This
   was learned the hard way twice: a run classifier that demanded a `RUN COMPLETE:`
   marker shipped while the contract teaching agents to write one sat in a local
   `jobs.json`, so every other user's runs would have been filed `warning`; and
   prompts citing skills by name shipped while the skills themselves lived only in
   an unversioned `~/.claude/skills`. Versioned code, an injected prompt contract,
   or a `selftest` assertion — never prompt prose in a personal config file.

3. **Edit `ui/`, rebuild `bin/static/` in the same commit.** All three built
   files — the Security bundle, the Overview bundle and the stylesheet — are
   build output that lives in git so that installing needs no Node — see
   [Changing the UI](#changing-the-ui-ui-is-the-source-and-the-built-files-are-committed).
   `agentloop selftest` names the enforcer out loud: *the committed UI
   artifact matches the sources it was built from*.

Run the checks before pushing:

```bash
agentloop selftest        # includes test/round-cap.test.sh and the artifact check
python3 -m pytest tests/
bash build/build-ui.sh      # only if you touched ui/ — then commit bin/static/
```

**Contributions are welcome.** Fork it, branch, and open a pull request against
`main` — which is protected: no force-pushes, no deletions, one approval to merge.
`CONTRIBUTING.md` has the workflow and the reasoning behind the rules, and the
pull request description is pre-filled from `.github/pull_request_template.md`.

---

## Layout

```
agentloop/
├── bin/agentloop            # the engine + CLI (bash)
├── bin/agentloop-server     # the dashboard control server (python, stdlib)
├── bin/worktree-lib.sh        # worktree setup, teardown and provisioning
├── bin/provision-lib.sh       # helpers a provisioning hook sources (ports, dotenv, gitignored files)
├── bin/security/              # the security analysis engines (python, stdlib): secrets, deps +
│                              #   SBOM, OSV lookups, hygiene, fingerprints, the ledger, the
│                              #   checklist diff, the reports — behind cli.py, its one door
├── bin/dashboard.html         # the dashboard page (Overview, Jobs, Runs, Projects, the editors)
├── bin/static/security.js     # the Security area, BUILT from ui/security/ and COMMITTED — see
│                              #   `Changing the UI` above
├── bin/static/app.js          # the Overview's renderers, BUILT from ui/app/ and COMMITTED
├── bin/static/app.css         # the stylesheet, CONCATENATED from ui/css/ and COMMITTED
├── ui/security/               # the source of security.js: the four screens, as ES modules
├── ui/app/                    # the source of app.js: the Overview's renderers, as ES modules
├── ui/css/                    # the source of app.css: tokens.css, components.css, pages.css
├── build/build-ui.sh          # rebuilds all three (pinned esbuild); run it with any ui/ edit
├── build/ui-digest.sh         # the content fingerprint build and selftest both read
├── config/
│   ├── jobs.json              # your jobs (created from the example on install)
│   ├── jobs.example.json      # a disabled demo job
│   ├── projects.json          # your projects (generated)
│   ├── models.json            # cached family→model resolutions (generated)
│   ├── prechecks/<id>.sh      # one precheck per job
│   ├── provision/<project>.{up,down}.sh   # per-repo worktree provisioning
│   └── control.token          # dashboard secret (chmod 600, generated)
├── data/                      # index.db (derived), app.db (profile + sessions),
│                              #   security.db (the analysis ledger), journal, logs
├── skills/                    # the skills the agent loop requires, linked into ~/.claude/skills
│   └── security-analysis/     # the contract every security analysis run follows
├── test/round-cap.test.sh     # behavioural suite, run by `agentloop selftest`
├── install.sh · uninstall.sh
├── CHANGELOG.md
└── README.md
```

Everything generated or personal (`data/`, `dist/`, your jobs, projects, model
cache and token) is git-ignored, so a clone starts clean.

The two `launchd` agents are the only thing outside this folder — macOS loads
them from `~/Library/LaunchAgents/com.agentloop.*.plist`. The scripts resolve
their own location, so you can move this folder anywhere and re-run `install.sh`.

---

## Uninstall

```bash
./uninstall.sh
```

Removes the agents and the `~/.local/bin` symlinks; keeps your `config/` and
`data/`. Delete the folder to remove everything.
