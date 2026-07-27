# Changelog

All notable changes to claude-cron.

**This file is filled in with every commit that is pushed to `main`.** Not
afterwards, not in a batch at release time — in the same change as the code, so
the entry is written while the reason is still known. Other people run this
scheduler on their own projects; a fix they cannot see the shape of is a fix they
cannot trust or adopt. `claude-cron selftest` fails when `main` has moved and this
file has not.

How to write an entry, in one line: **say what behaviour changed and what it cost
to not have it.** "Fixed watchdog" is not an entry. "A long tool call is no longer
read as a hang — a 40-minute test suite used to be killed at the stall timeout" is.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **A repo's base branch can be a pattern** — `release/*` resolves to the
  highest-*versioned* matching branch, so a project that ships through release
  trains is configured once instead of edited every release. Sorted by version and
  not as text, because as text `release/0.9.0` beats `release/0.10.0` and the
  project would silently pin itself to the train it had just left. A pattern that
  matches nothing **refuses** rather than falling back to `HEAD` — falling back is
  the silent-wrong-baseline failure this exists to prevent.


- **A run is isolated per *run*, not per repository.** A ticket routinely touches a
  frontend and a backend, and both have to be checked out from the same base at the
  same moment. A project declares `repos[]` (name, path, base) and a run now gets one
  directory holding one worktree per repo, plus a manifest at `CC_RUN_MANIFEST` —
  the only way an agent can learn where its sibling repos are. The slot claims that
  directory and the orphan sweep reaps it as a unit; comparing a slot's breadcrumb
  against a single worktree path would have called every sibling an orphan and
  deleted them under a live agent. A project with no `repos[]` is still the
  single-repo case, synthesised from `cwd`.
- **A repo declares the branch its worktrees are cut from.** Reading the canonical
  checkout's current branch is not a base — the checkout can be detached, or parked
  on somebody's feature branch, and both answers are wrong in a way nothing
  downstream can detect. The base is fetched first, because a review run has to see
  the branch a dev run pushed minutes ago; an unreachable network only degrades the
  answer to local refs and says so, because no run should die of being offline.
  Relatedly, the canonical checkout is no longer detached during a run — the old
  detach never restored, so one isolated run left the operator's own checkout
  headless for good.

  **Upgrading:** two things change how much this matters on an existing install.
  Nothing repairs a checkout already detached, and a detached checkout is precisely
  the case where an empty `base` infers wrongly — resolution falls through to
  `origin/HEAD`, so a project whose work targets `develop` is inferred onto `main`.
  Both are silent: the only symptom is agents building from a stale or wrong base.
  So, once per canonical checkout, `git checkout <your-branch>`; and declare `base`
  per repo wherever `origin/HEAD` is not the branch you work from. Detail in the
  README's isolation section.
- **Provisioning hooks: a project makes each fresh worktree usable**
  (`config/provision/<project>.up.sh` / `.down.sh`, editable from the CLI and the
  project editor). A fresh worktree has no `.env`, no `vendor`, no `node_modules` —
  they are all gitignored, so nothing a checkout produces can supply them, and an
  agent handed such a tree fails at its first test run. `up` runs once per repo with
  the canonical checkout's path in the environment, and is killed if it outlives the
  project timeout: provisioning happens before the agent exists, so the run's own
  watchdog is not up yet and a hanging hook would hold the slot with nothing watching
  it.
- **A project chooses which Claude account its runs sign in as** (`claude_config_dir`,
  with `CLAUDE_CRON_CLAUDE_CONFIG_DIR` setting the install-wide default). Claude Code
  keeps credentials, settings, plugins, MCP servers and past sessions per config
  directory, so this is the only thing that picks between two accounts on one Mac —
  and a shell alias never reaches this tool, because launchd inherits nothing from the
  shell. Every run therefore signed in as `~/.claude` however the work was split:
  client work billed the personal account and ran with the wrong account's plugins and
  MCP servers, with nothing in the run record saying so. The default is taken only
  from the explicit variable, never from an ambient `CLAUDE_CONFIG_DIR`, because
  installing from inside a Claude session would otherwise pin that session's account
  for every job, silently and for good.
- **A daily ceiling for the whole machine, and `daily_budget_usd` inherited from the
  project.** Setting a daily budget on a project did nothing whatsoever — quietly,
  which is the worst way for a budget control to fail, and the natural place to put it
  when a project owns six jobs. Per-job caps also cannot express the thing you
  actually want to know: with a job per repo per role, every one can sit correctly
  under its own limit and the day still cost several times what you meant to spend.
  The only number that answers "what will a bad night cost me?" is the sum.
- **A job that only ever fails backs off instead of retrying at full price.** An
  errored job relaunched every interval, at full budget, for as long as it kept
  failing — the loop had no notion of "this is not working". With fourteen dev and
  review jobs on a five-minute interval that is a lot of money to spend discovering
  the same breakage overnight. Two failures are still treated as noise; from the third
  the wait doubles, capped at 16×, and any non-error run resets the count.
- **The loop can tell someone a run ended** (`config/hooks/on-run-end.sh`). A pipeline
  that can only be checked by opening a web page is not really unattended: a job can
  fail every five minutes all night and the first anyone knows is the next morning.
  The hook is detached and time-limited for the same reason the provisioning hook is —
  a run must not be kept alive by something whose only job is to report on it.
- **Retained run dirs are visible and discardable.** When a run ends with commits that
  exist on no remote, teardown preserves its worktrees. That is right, but it was also
  permanent and invisible — mentioned only in `tick.log` — so the first symptom of the
  accumulation is a full disk, and the work being protected is never noticed either.
  The dashboard now lists each retained dir with its repos, size and age; the engine
  owns the refusal, so a dir a live run is using is never dropped.
- **Turn a whole set of jobs on or off in one write** (`claude-cron toggle-many`, plus
  a per-project and a per-view button). Disabling a project meant one `disable` per
  job, each rewriting `jobs.json`: a failure halfway leaves the set half applied, and a
  tick landing between two of them launches from a state nobody asked for. Every id is
  resolved before anything is written, and the view-scoped button acts on literally
  what is on screen — acting on the whole board while a filter is on is the one thing a
  control like this must never do.
- **The skills the agent loop depends on now ship with the scheduler** (`skills/`),
  linked into `~/.claude/skills` by `claude-cron install` and inspectable with
  `claude-cron skills`. The prompts make these skills mandatory *by name*; when
  they lived only in an unversioned `~/.claude/skills`, a fresh clone ran agents
  citing standards their machine could not read, and nothing said so — the run
  simply held a lower bar in silence.
- **A ninth attack axis — the fidelity of the evidence** — in
  `closing-review-findings`, `reviewing-pull-requests` and
  `test-driven-development`. The other eight interrogate the code; none asked
  whether the test proving it was real. Three consecutive review rounds on one
  pull request came from fixtures that were hand-written guesses, so the wrong
  assumption sat in the code *and* in the test and they agreed with each other.
- **This changelog**, plus a selftest case that fails when `main` moves without it.
- **`CONTRIBUTING.md` and a pull-request template**, and `main` is protected — no
  force-pushes, no deletion, one approval to merge — so contributions arrive by
  pull request against a branch that cannot be rewritten under them.

### Changed

- **The project moved to <https://github.com/lmelomoura/claude-cron>.** It was
  public on Bitbucket, but inside a private company workspace — and Bitbucket
  refuses to fork a repository out of one, so "public" bought nothing: no outside
  contributor could fork it, and Bitbucket no longer allows creating the separate
  workspace that would have fixed it. Full history moved; the old repository was
  deleted after verifying every commit had arrived.
- **The dashboard reports the loop, not the configuration.** Twenty-one cards each
  repeated the same ten rows — *every 5m 0s, 08:00–20:00 Mon–Fri, never, never,
  disabled, opus, default* — so ten screens of scrolling taught you nothing, while the
  one fact unique to each job sat in a grey footer nobody reads. The top of the page is
  now the loop's last 24 hours, one column per 15 minutes stacked by what the scheduler
  decided, drawn from `tick.log`; it replaces six tiles of which four were zero. A card
  answers three questions in the order you ask them: is it alive, what did it last see,
  what did it cost. The two editors — fifteen fields in 1670px of form inside a 626px
  window — are tabbed, and the tab strip inks a dot only when that section holds
  something changing how the job behaves *right now* (no prompt, no precheck, an active
  backoff, a cap already reached), so tabbing hides no consequence. Delete left the row
  of four equal buttons: it is irreversible and sat one slip from Edit on every card.
- **The dashboard page is a file, not a 2,600-line string** (`bin/dashboard.html`).
  ~150 KB of HTML, CSS and JavaScript lived inside the server as a raw string that no
  editor would highlight, no linter would check and no diff would render usefully — a
  typo in it was invisible to every test and surfaced only as a blank dashboard. The
  served bytes are identical; what it buys is that the script can be handed to
  `node --check`, which the new page tests rely on.
- **`tick.log` is a series the page can draw.** One pass over the same tail now yields
  the per-job counters the cards already read, a 96-bucket band of the whole install,
  and an hourly series per job. Classification of the engine's five decision kinds is a
  named, tested function rather than inline substring tests, because it is the part
  that rots: a reworded log line would silently drop an outcome out of the band with
  nothing to notice it. Lines written *about* a run rather than as a decision to make
  one are explicitly not checks — counting them would have inflated the band until one
  run read as four.

### Performance

- **The 5-second poll no longer re-sends the entire configuration.** `/api/data`
  carried the full prompt of every job, a couple of kilobytes of contract text per
  project, and the body of every precheck script — 135 KB, twelve times a minute, of
  data that changes only when someone edits it. Live and static are now split, and the
  precheck bodies are gone from the payload entirely: only the editor reads one, so it
  fetches the one it needs when it opens. **135 KB → 3.4 KB per poll.** Two forks per
  poll went with it (`date` was pure waste next to `strftime`; `launchctl` is cached) —
  about 34,000 processes a day to answer questions that change when someone runs the
  installer.
- **The tick asked `jq` about every field of every job.** Each `job_get`/`state_get`
  re-reads and re-parses the whole jobs file: 254 processes to evaluate 21 jobs, once a
  minute, for ever, almost always to conclude that nothing is due. It is now 2. The end
  of a run was the same shape in miniature — seven `state_set` calls meant seven turns
  of the state lock to record one event, with every concurrent run queuing behind each;
  they are now a single locked write. `claude-cron status` went from 0.47s to 0.13s.
- **Budget scans are bounded.** Records are appended in time order, so today's are
  always at the end, and reading the whole journal to find them made every run launch
  O(all history ever).

### Fixed

- **The runs table has its Duration and Cost columns back, each sortable on its
  own.** Merging them into one "Duration & cost" column silently dropped the cost
  sort: the comparator was still there, but no header could reach it, so the most
  expensive run of a day was unfindable in a 25-row page. They answer different
  questions — what is slow and what is expensive are rarely the same run.
- **`Run now` carries the accent whether or not its job is enabled**, because it
  works whether or not the job is enabled: it is a deliberate manual override and
  the primary action on the card. Tying the accent to `enabled` made the one
  button that still does something look as inert as the ones that do not.


- **The focus ring is no longer sliced off fields that sit flush against a scroll
  container.** The ring paints 4px outside the border box (2px outline + 2px
  offset) while the project editor's panes clipped at padding 0, so the first
  field of any row lost the left side of its ring — the visible symptom being a
  field that looks half-outlined when tabbed to. Reserving the ring's width costs
  nothing when nothing is focused. `stepper` and `moneyin` are deliberately left
  alone: those wrappers draw the border themselves and their inner field carries
  none, so padding them would break the visual join.
- **A repo row is labelled like every other field in the editor**, with its own
  `Name` / `Path` / `Base branch` captions instead of three unlabelled boxes whose
  meaning could only be recovered by having filled them in before — and the path
  now uses the same folder picker as the working directory on the first tab, so a
  mistyped path fails at edit time rather than hours later inside a run.
- **`syncCwdField` addresses its own Browse button** rather than the first
  `.cwd-browse` in the document. That only ever worked because the job editor
  happens to come first in source order, which no one maintains on purpose, and
  it breaks the moment another Browse button is added earlier.


- **The Claude account is no longer taken from an ambient `CLAUDE_CONFIG_DIR`.** The
  installer already refused it; the runtime did not, and the two have to agree. These
  commands are typed inside a Claude Code session as a matter of course, and a session
  exports its own account — so `claude-cron run <job>` and `check <job>` signed in as
  whoever happened to open that terminal: another account's billing, plugins and MCP
  servers, with nothing in the run record saying which. Scheduled runs were never
  affected, launchd inheriting no shell environment, which is exactly why this could
  sit unnoticed: the failure only appeared on the path a human drives. Only
  `CLAUDE_CRON_CLAUDE_CONFIG_DIR` and a project's `claude_config_dir` select an
  account now; with neither set the variable is unset rather than passed through, so a
  run lands on the CLI's own default. Pinned by a selftest case that sources the real
  script under a polluted environment — the rule was never wrong, the wiring was, so
  only an end-to-end probe catches it coming back.
- **A loop invariant with nothing to match no longer reports total non-compliance.**
  The dev/review guards find their subjects by an id convention (`*-dev-agent`,
  `*-reviewer-agent`); an install naming its jobs otherwise matched nothing, and
  `0 of 0` was arithmetic that failed open into `bad`. `selftest` was therefore red on
  every such install, for a rule none of its jobs were breaking — and a suite that is
  always red is a suite nobody reads. An empty set now passes, naming the convention it
  looked for so a check that examined nothing says so out loud rather than passing
  quietly.

- **A precheck that could not run no longer reads as "nothing to do".** The gate
  treated every non-zero exit as idle, collapsing the two failures that matter into the
  one healthy outcome: a probe that ran and found no work was indistinguishable from a
  probe that could not run at all — missing credentials, an unsourceable helper, a
  typo. A job could therefore stop working for good while its card kept reporting it as
  healthy and up to date, which is the worst failure mode an unattended loop has. The
  contract is now three-way (0 work, 1 idle, anything else broken), with its own
  `precheck_error` status that turns the card's last check red.
- **`jq` was hard-coded to a path only recent macOS guarantees.** The engine ran
  `/usr/bin/jq` while the installer checked for `jq` on `PATH`. Those are the same file
  only on macOS 15 and later; before that jq comes from Homebrew, at a path that
  differs between Apple Silicon and Intel. An install could pass every dependency check
  and then have every single run fail, with nothing connecting the two. The installer
  now prints the path it found for each dependency, and checks `git` too — the worktree
  isolation has always needed it.
- **A lock was broken on elapsed time rather than on its owner being gone.** Every
  `mkdir` lock broke itself after about four seconds without ever asking whether the
  holder was alive. That inverts the point of a lock: the slowest legitimate holder is
  the one most likely to be robbed, and the slowest holder is a rewrite of a long
  journal — so the record a run had just appended could be lost to the very mechanism
  meant to protect it. A live holder is now waited for. Writing the test first turned up
  a second bug on the server side, whose breaker used `rmdir()` and so could not remove
  a directory containing the holder's pid file; the failure was swallowed and the loop
  retried for ever, inside an HTTP handler.
- **A hung fetch held a run's slot for ever.** Every worktree is cut from a freshly
  fetched base, and that fetch had no bound. It happens after the run has taken its slot
  but *before* the watchdog exists, so a remote that accepts the connection and then
  goes quiet pinned the slot for as long as the network stayed broken — with
  `max_parallel 1`, that is the job dead until a human notices. The bounded-run helper
  closes the child's stdout deliberately: killing a process does not kill its children,
  and a caller inside `$( )` blocks until every process holding the pipe exits, so an
  orphaned grandchild keeps the substitution waiting for the full original duration and
  the timeout buys nothing at all.
- **Provisioning residue is not the agent's work, and `down` runs once.** `up` copies a
  `.env` and a `vendor/` into a fresh worktree, so `git status` is never clean
  afterwards — and "dirty" was the whole test for "the agent left work here". Every run
  dir was therefore preserved, nothing was ever reaped, and the disk grew for ever. The
  fingerprint is now taken at the *end* of provisioning and compared at teardown. `down`
  was also running on every sweep, so a `docker compose down -v` would have fired once a
  minute for as long as unpushed work sat there.
- **A resumed run must not let its precheck claim anything.** A precheck may take a
  ticket, and the engine hands what it took to the session — but on a resume the
  continuation prompt *replaces* that output entirely, so a claiming precheck moved a
  ticket out of the queue for a run that was never going to look at it, leaving it
  claimed with nobody working it.
- **Nothing rotated the logs, and the 24h counters truncated a busy day.** `tick.log`
  and `exec.log` were append-only for the life of an install. And the 24h counters read
  the *whole* of `tick.log` and then kept the last 6,000 lines — about one day at 21
  jobs on a five-minute interval, so a busy install silently under-reported precisely
  when it had the most to report.
- **The `max_parallel` comment claimed a default the code does not use** — it said
  "default 1, so review/promote stay single" while both call sites default it to 3.
  Anyone reading it before deciding whether to set the field would conclude their job
  was already single-threaded, which bites hardest for exactly the jobs it names.
- **The selftest wrote into production history.** The suite exercises worktree setup,
  teardown and provisioning for real, and those write through `log_tick` — pointed at
  the live data dir it appended invented jobs to the very `tick.log` the dashboard
  parses for its activity counts, on every run. The data dir is now shadowed at
  function scope, and the suite asserts at the end that the real logs are byte-identical.
- **Workflow transition ids are resolved by name, never trusted from a prompt.**
  Both reviewer prompts carried ids that were right *from* `Review - DEV` and wrong
  from `In Review - DEV` — and the precheck claims a ticket by moving it to the
  latter before the session begins, so every closing transition used a stale
  number. Ids are per source state and boards get edited; the injected contract
  now tells every run to `GET /transitions` and match on `to.name`, with quoted
  ids demoted to recognition hints.

- **A human moving a card into the ready column is an answer, not a board glitch.**
  The round cap parks an exhausted ticket and waits for a human; the human's reply
  is the board move. A run then read the spent rounds, decided the card's presence
  there was an anomaly it would be exploiting, and escalated it straight back to
  Blocked — so the only lever that moved the ticket forward was undone every time
  it was pulled. `rc_develop_note` and the injected run contract now both say that
  the move *is* the decision, while keeping blocking available for genuinely new
  blockers.
- **The run-ending contract ships with the code**, not with one machine's
  `jobs.json`. The classifier that *demands* a `RUN COMPLETE:` marker was
  versioned; the contract that teaches agents to write one was not, so every run
  by anyone else would have been filed `warning` with nothing explaining why.
- **A long tool call is no longer mistaken for a stall.** The watchdog measured
  only the event stream, which goes quiet for the entire duration of a single tool
  call — so a test suite longer than `stall_timeout_seconds` was killed for taking
  the time it was asked to take. CPU burnt across the run's process tree is now a
  second, independent proof of life.
- **A run that stops talking is no longer recorded as a success.** A headless run
  ends the moment the model returns text without a tool call, so an agent that
  said "I'll wait for the suite and then commit" abandoned its ticket mid-task —
  and produced a textbook-clean record while doing it. A clean exit must now be
  claimed (`RUN COMPLETE:` / `NOTHING TO DO:` / `BLOCKED:`); an undeclared ending
  is a warning naming what to check.

## [0.1.0] — 2026-07-26

The scheduler as it stood before this changelog began: launchd tick and control
server, per-job prompts and prechecks, budgets and daily caps, git-worktree
isolation per run, the dev/review round cap, and the dashboard on 127.0.0.1.
Earlier history is in `git log`.
