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

### Fixed

- **A detached analysis is a real process, so the engine can tell it is alive.**
  It ran inside a `( subshell )`, where bash 3.2 freezes `$$` at the parent's
  pid and offers no `BASHPID` — so the run's own slot recorded a process that
  exited seconds after launching it. Everything downstream then read the run
  as dead: `max_parallel` stopped gating (two analyses of one project could
  overlap), the dashboard never saw a live run, and the Security page called a
  healthy analysis dead after three minutes. The detached half now re-execs the
  script as a new process, where `$$` is honest, and a structural assertion
  keeps it from being folded back into a subshell.

- **The page can finally see a live security run.** `active_runs` was built
  from the jobs file, which by design never contains a derived job — so a
  running analysis had no "Open the run" button for its whole life, and the
  Security page's dead-run warning fired against every healthy run after
  three minutes. The derived ids are now unioned in from the lock directory.
  On the Runs page a `security-*` row is observed, never managed: the eye and
  Stop stay live, resume and delete are disabled with the reason on the
  tooltip — a resume would rerun a consumed request, and a delete would erase
  the transcript the analysis links to.

- **The checklist no longer declares the whole baseline `fixed` nine seconds
  into a run.** A running analysis has written nothing yet, and the diff read
  that absence as 43 findings resolved; a capped run's unreached code-review
  findings told the same lie at the end. Absence is only evidence when the
  looking finished: a baseline finding missing from the current analysis is
  `fixed` only once its absence is proven — deterministic categories after
  `prepare` completes, code-review findings only when the analysis closes
  `done` — and until then it is `pending`, "not re-checked yet", counted with
  the open exposure, never with the resolved. The page also names the
  pre-agent phase (fetching the branch, cutting the worktree) instead of
  showing a button-less void until the run's trace exists.

- **A detached security analysis survives the control server restarting.** The
  server exits whenever its own file changes on disk — routine on every code
  update — and its launchd plist, unlike the tick's, did not carry
  `AbandonProcessGroup`, so that restart had launchd SIGKILL the server's whole
  process group: a live analysis died mid-SAST with no journal, no teardown and
  a ledger row stuck on `running`. The plist now carries the key (re-run
  `bash install.sh` to apply it), and the detach itself takes its own process
  group (`set -m`) so it also survives a parent that lacks it.
- **"Open the run" on a running analysis can no longer open a dead previous
  attempt.** The link matched by nearest start within 15 minutes across the
  journal too, so a running analysis whose run had just died showed the
  PREVIOUS attempt's BLOCKED transcript as if it were live. A running analysis
  now only links a live run, the window is 120 s, and when a running analysis
  has had no live run behind it for three minutes the page says so instead of
  showing "Analysing…" indefinitely.

- **The dashboard no longer empties itself the first time the new server
  ingests a run.** The `cause` column arrived in the journal INSERT without
  its placeholder — 22 columns, 21 `?` — so nothing broke until the first
  NEW journal line reached the new code; then every ingest raised, the
  page's run list fell back to empty in silence, and the dashboard said
  "No runs recorded yet" over an intact 223-line journal. The failure now
  also names itself in server.log instead of hiding behind the fallback.

### Changed

- **A security analysis can actually run: the derived job now defaults to
  `bypassPermissions`, the fleet's own headless default, instead of `dontAsk`.**
  Headless `dontAsk` denies every tool outside an allowlist, and a fresh
  worktree has none — the first live analysis spent $0.56 over 18 turns
  probing the walls, could not run one command, and ended BLOCKED.
  Containment never came from the permission mode: the worktree is
  disposable, the ledger only accepts writes through the CLI's validating
  door, and the human-authority verbs stay shut to the agent's environment.
  A project that wants a tighter mode sets `security.permission_mode` (now
  in the project editor's Security tab, same control as the job editor's),
  and a value the CLI does not know falls back with a warning instead of
  launching a run that dies at its first tool call.

- **The Security tab picks its model and effort with the job editor's own
  controls.** It shipped with a free-text model field and a bare effort
  dropdown, so the two screens drifted: the job editor offered the resolved
  model list grouped by family and the Faster–Smarter slider, while the
  security block asked you to remember an exact id and pick an effort word
  from a list. Same combo (fed by the same `/api/models` refresh, with the
  same hand-typed escape hatch for an id the CLI does not list yet), same
  slider, one difference kept on purpose: empty stays a real choice here,
  because an unset model means "the engine's default", not "opus now and
  whatever the field remembers later".

### Added

- **An analysis records how much code it read.** Counted during the walk the
  deterministic phase already does, with the same files skipped, so the number
  says what was analysed rather than what happens to be in the directory.

- **`claude-cron security` — analyse a project's code on a branch you choose.**
  Secrets (the working tree and the whole git history, every analysis),
  dependency CVEs from OSV.dev, a CycloneDX SBOM and repository hygiene run in
  seconds and cost no tokens; a Claude run then does the SAST, triages what the
  deterministic phase found, and re-verifies what was left open last time. The
  second analysis of a branch says what closed, what did not, what closed
  halfway, what is new and what regressed.

  Everything goes through one door, `bin/security/cli.py`, and so does the
  agent: `report-finding` validates before it writes and refuses a finding with
  no fingerprint or an invented severity. The agent is non-deterministic, and
  the integrity of the history that produces the checklist cannot depend on it
  having written the right JSON. The analysis row is opened *before* the run
  starts, so an agent that dies on launch still leaves a failed analysis the
  page can show for a button somebody pressed; it is closed with the run's own
  verdict and real cost at the same point in `run_job` where the end-of-run
  hook fires — before it, and synchronously, because that hook is optional and
  detached and an analysis must not be left `running` for ever on an install
  that has none. A second analysis of the same project is refused with a
  sentence on the terminal rather than one line in the tick log.

  **The agent's contract is versioned with the code, not hand-typed into a
  prompt.** `skills/security-analysis/SKILL.md` is what tells the agent, in
  order, to re-verify what was left open (cheapest and most valuable, so
  first), triage what the deterministic phase found, then run the SAST pass
  scoped by profile — and never to print a secret's value, read a dependency
  tree, or treat a comment that addresses it as anything but a finding to
  report. It ships and links the same way the other loop-mandatory skills do,
  so a prompt that names it by name is never naming a skill the machine does
  not have. The re-verification step now goes through `checklist`, because
  `findings` returns only the running analysis's own rows and so can never
  show the agent a finding the previous analysis carried over.

  It also gets its own fingerprint, rather than inventing one: `claude-cron
  security fingerprint --category <c> --rule <r> --path <p> [--snippet <s>]`
  runs the exact same recipe `report-finding` validates a fingerprint
  against — `secret_fingerprint` for a secret, `fingerprint` for everything
  else — so the agent is never one typo away from minting a fresh identity
  for the same hole on every run. Read-only, so it stays allowed under
  `CC_SECURITY_AGENT` alongside `finish`.

  **The close tells a truncated analysis from a finished one.** `warning` is
  two different runs wearing one word: stray bytes on stderr is a run that
  worked, while `UNDECLARED ENDING`, `BUDGET LIMITED` and undelivered work all
  mean the agent stopped part-way through the code. Both used to close the
  analysis `done`, so a half-read repository became the baseline the next
  analysis was diffed against — a report reading `fixed: 1, critical: 0` with
  no banner, and everything the agent never reached coming back as `regressed`
  the run after. Those three now close it `capped`, and a close can only ever
  lower the verdict: an agent's own `finish --state capped` is never upgraded
  to `done` by the engine's `success` (which means only that the process
  exited cleanly), while the engine can still downgrade an agent's `done`.
  The row id the close writes to travels with the run instead of through the
  shared request file, which the *next* analysis of the same project rewrites
  — a close could land on another analysis's row and leave its own running for
  ever. A failed analysis no longer feeds the history the checklist reads, so
  the first good analysis after a failed one stops reporting everything the
  failed attempt happened to reach as `regressed`.

  **The agent cannot vote on its own findings.** It reaches the ledger through
  the identical command an operator types, and the door validated the shape of
  what was written, never who was writing: from its own tool shell, `security
  decide --state false_positive` permanently suppressed a committed AWS key
  (signed `decided_by: security team`), and `security rename-project` moved the
  whole ledger out from under the project being analysed. The analysis run now
  carries `CC_SECURITY_AGENT=1`, and `decide`, `rename-project` and
  `open-analysis` are refused while it is set, with a sentence saying why;
  `finish` stays allowed, because the engine's own close-out runs inside that
  same run. `report-finding` and `prepare` are also refused on an analysis that
  is already closed — it is the next run's baseline, and writing into it
  rewrites what the previous run is remembered as having found — a fingerprint
  must be a real sha256 (one the agent invents is a new identity every run, so
  the same hole is `new` for ever and no decision ever sticks to it), the text
  fields are capped at 10k characters, and `prepare --root` refuses `/` and
  your home directory rather than filing every file you own as a finding of
  this project.

  **Renaming a project no longer orphans its security history.** A rename
  re-derives the analysis job's id (`security-web` → `security-web-two`), and
  the analysis in flight sits behind a `max_parallel=1` gate on the *old* id:
  the rename is now refused while one is running, the pending request file
  follows the new id, and every past analysis, accepted risk and SBOM — all
  keyed by the project *name*, there being no id to key them by — is carried
  onto the new name instead of stranded under one no project has any more.

- **The engines behind an analysis, and the ledger that remembers them —
  `bin/security/`.** Eight modules of stdlib Python, no dependency added, behind
  the single door of `cli.py`. This is the half of an analysis that costs no
  tokens and the half that makes running a second one worth anything.

  `secrets.py` finds credentials by *shaped* patterns with an entropy gate, not
  by entropy alone — entropy alone flags every hash, UUID and minified bundle in
  a repository, which is how a secret scanner becomes something people switch
  off. It sweeps the git history as well as the working tree on every analysis,
  because a key committed on Monday and deleted on Tuesday is still compromised
  and is the case that actually leaks. The value never leaves the
  module: not into a return value, not into a finding, not masked. `deps.py`
  reads names and versions out of `package-lock.json`, `requirements.txt`,
  `poetry.lock`, `composer.lock` and `go.sum` — never a dependency's code, which
  is noise and is the only code in a checkout nobody there wrote — and builds a
  CycloneDX SBOM from them; a lockfile too malformed to parse costs that one
  file, never the analysis. `osv.py` asks OSV.dev about that inventory and turns
  every failure mode into a *coverage note* rather than an exception, so a
  network that is down costs the report a stated gap instead of costing it the
  secrets and hygiene findings already collected. `hygiene.py` reports the
  committed `.env`, the file whose first bytes are a PEM private key, and the
  world-writable file.

  `fingerprint.py` is what makes a second analysis mean anything: identity is a
  sha256 over category, rule, path and a whitespace-normalised snippet, so
  reformatting a file does not resurrect the entire report, and the line number
  is excluded, so an import added above a finding does not either. A secret's
  identity excludes its value — a hash of it would be an oracle for the secret,
  weak but real, sitting in a database — and excludes its position, which would
  move whenever an unrelated line did and make an untouched, already-triaged
  credential read as `fixed` and `new` on the very next run.

  `ledger.py` is the SQLite store (`data/security.db`): analyses, findings,
  the places each one was found, and decisions keyed by the **project** rather
  than the branch, because dismissing a false positive on `develop` and watching
  it resurrect on `main` would make the whole area unusable. A decision with no
  written reason is refused at this level, not just in the page. `diff.py`
  derives the checklist — `new`, `open`, `partial`, `fixed`, `regressed` —
  against the previous *finished* analysis of the same branch and stores none of
  it: a stored state is a state that can end up disagreeing with the findings it
  describes. `partial` is a set difference over the files, never a subtraction
  of counts, so two hits in one file becoming one is not read as progress while
  a hole moving from `auth.py` to `admin.py` is not read as nothing.
  `report.py` renders Markdown, JSON and HTML from the ledger at download time
  and writes no file at all — a stored report is a frozen document that starts
  disagreeing with the page the moment somebody accepts a risk.

  Without this layer an analysis had nowhere to put what it found, no way to say
  "this is the same finding as last time", and therefore no answer to the only
  question that makes the feature worth having: what did I actually fix since
  the last one?

- **A security analysis can cut its worktree from a branch chosen at run time,
  and skips the project's provisioning.** Every other run takes its base from
  the project's declared config; an analysis needs to target whatever branch
  is under review — `main`, `develop`, a PR's `release/2.1` — and that is
  decided per run, not written into the project ahead of time. `CC_BASE_OVERRIDE`
  now wins over the declared base in `wt_base_ref`, and a branch that does not
  resolve is refused outright rather than silently falling back to the base:
  analysing `main` when the user asked for `release/2.1` would produce a report
  that reads as correct while being about the wrong code entirely.

  `CC_SKIP_PROVISION=1` skips the project's `up` hook in `wt_setup`. Reading
  code needs no `.env` and no containers, and an analysis must neither pay for
  a project's provisioning nor be blocked by it failing. Resuming a session
  honours that same opt-out: `CC_SKIP_PROVISION` is an env var on the original
  invocation and is gone again by the time a killed or rebooted analysis gets
  reattached, so the reattach path now recognises a derived security job by
  its ID and skips the `up` replay there too — a resume was re-provisioning
  the project it had explicitly promised not to touch.

- **Projects can now carry a `security` block.** It is what a security analysis
  is configured by — which model and account it runs as, its spending cap, the
  profile it defaults to. Without it there was no way to say which Claude an
  analysis should sign in as, and it would have run as whatever the scheduler's
  default happened to be.

- **A security analysis runs as a normal run, with no job behind it.** Projects
  with security enabled get a job derived in memory by `jobs_json`, so an
  analysis gets the watchdog, the spending caps, the live stream and the
  turn-by-turn trace for free — and `config/jobs.json` never grows an entry
  nobody created. The tick, the dashboard's Jobs area and every write of the
  jobs file read that file directly, and so never see one. A `security` block
  the scheduler cannot use costs that project according to what's actually
  wrong with it, and says so in `tick.log` once per change rather than on
  every read. A name that slugs to nothing, or two projects claiming one id,
  costs that project its derived job entirely. A `max_budget_usd` typed as
  `"abc"` costs it neither the job nor the cap: a derived run always carries
  `--force`, which skips the rate-limit gate, the daily cap and the global
  cap, so `max_budget_usd` is the one spend gate that actually applies to it —
  a value that fails to parse falls back to a conservative default ($2)
  instead of running with no ceiling at all.

  A by-id command is the one place a derived id can still be typed — `job_exists`
  answers through `jobs_json`, so it says yes. Each of them now refuses it:
  `delete`, `rename`, `enable`/`disable`, `toggle-many`, `reorder`, `set-prompt`,
  `set-field` and `set-precheck` answer `'security-web' is a derived security job
  — configure it on its project, not on the job`. Without that, `delete
  security-web` printed "deleted", left jobs.json alone as there was nothing in
  it to remove, and still deleted the job's state entry and `rm -rf`'d its lock
  dir — the lock dir being what holds the `max_parallel=1` gate of an analysis
  in flight. `rename` was worse: it moved that job's `runs.ndjson` history, log
  dir and state onto an id nothing will ever derive again. `run`, `resume`,
  `stop` and `say` are untouched: a derived job is meant to run.

  **The control server can now drive a security analysis.** `GET /api/security`
  lists a project's analyses, `/checklist` and `/report` return one of them (the
  latter as a download — `Content-Disposition: attachment`, with a filename
  built only from the validated int id and format, never a string the caller
  typed), and `/branches` lists a checkout's branches for a picker (a new
  `claude-cron security-branches <project> <repo>`, since the server never
  runs `git` itself). `POST /api/action` gained `security_analyze` and
  `security_decide`. A branch name is checked against an allowlist at this
  edge rather than quoted somewhere downstream and hoped about — and a
  leading `-` and a `..` are refused explicitly even though both characters
  are in the allowed set, the first because it sits in an option position
  next to plumbing and the second for the traversal it can smuggle into a
  ref. A decision with a blank reason or a state the ledger does not know is
  refused here too, mirroring `security/ledger.py`, so the page gets a
  sentence instead of a 500 from a CLI that exited non-zero; `decide`'s `by`
  always comes from the signed-in operator's own profile, never from the
  request body, so nothing typed into the page can sign a decision as anyone
  else.

  **And the dashboard has a Security area to drive it from.** Its own entry in
  the sidebar, between Projects and Settings, listing *projects* rather than
  jobs — a project can be registered for this and have no job at all — each
  with what is still open on it by severity and when it was last analysed. A
  project without the security block is still in the list, with one line saying
  where to switch it on, instead of a row that opens a page that does nothing.
  Open one and you get the repo (only when there is more than one), the
  branches the checkout actually has plus a field for one it does not, the
  profile, and Analyse. While it runs the page follows it: the deterministic
  phase writes before the agent is launched, so secrets and CVEs land on screen
  within seconds of pressing the button while the SAST is still going. Then the
  severity summary, the checklist across all seven states as filters, the
  findings, the report in Markdown, JSON or HTML, and the earlier analyses of
  that branch — each linking to the run that produced it.
  `min_severity` is applied here and only here: everything found is still in
  the ledger, the page says how many it is holding back, and a *fixed* finding
  is shown whatever its severity, because the one job of a checklist is to say
  what closed.

  **Nothing an analysis produced is ever written to the page as markup.** A
  finding's title and file paths come out of analysed code, and — the one
  nobody expects — so does a branch name: git allows `<`, `>` and `&` in a ref,
  so `feature/<svg/onload=…>` is a branch a repository can create and this page
  will list in a picker. Every string goes in as text; the only `innerHTML` in
  the whole block puts an icon from the page's own table into a span, and a
  test pins that so the pattern cannot come back. The branch picker can offer a
  name the engine will refuse — its allowlist is narrower than git's — so the
  refusal is shown as the sentence the server sent, not as a generic failure.
  The report downloads are fetched with the control token and saved from a
  Blob, because a plain link cannot carry the header and would have handed
  somebody a 403 as a file.

- **The project editor has a Security tab.** A fourth pane, alongside Repos and
  Provisioning: whether analysis is on, the model and effort it runs with,
  which Claude account signs it, the profile Analyse defaults to, the
  per-analysis and daily spending caps, the minimum severity the Security page
  shows, and the globs excluded from analysis. Without it, the only way to turn
  security on for a project — or to change any of it — was to hand-edit
  `projects.json`; the Security page's own "turn it on in the project editor,
  on the Security tab" pointed at a tab that did not exist yet. `ignore_paths`
  and `min_severity` are two different filters and the pane says so: the first
  keeps a path out of the analysis itself (no tokens spent on it, and it never
  reaches the ledger), the second only hides what is already there — lowering
  it later reveals findings that were recorded all along, never re-runs
  anything.

  Every field the pane owns is always sent on save, never omitted, matching
  how `claude_config_dir` and `worktree` already work on the other panes:
  `project-set` merges (`. * $p`) rather than replaces, and a merge cannot
  drop a key that is simply missing — so an emptied field has to arrive as an
  explicit `""` to actually clear, or it would keep whatever was saved before
  for ever. `enabled` is always sent as a real boolean; the engine (see below)
  and the page's own `secEnabled` both also accept a hand-typed `"true"`
  string, but the pane itself has no reason to ever write one.

- **A fifth severity, `info`, for findings worth recording that need no action.**
  It sits below the default floor, so it files without adding noise, and it
  arrives with producers rather than as an always-zero column: a repository
  with no `.gitignore`, and the agent's own observations. The dashboard's own
  severity vocabulary now ranks it too — below `low`, not above `critical` —
  since an unextended `SEV_ORDER` fell back to the rank reserved for
  corrupted data: an `info` finding was unhideable at every `min_severity`
  floor and sorted above every critical finding on the page.

### Fixed

- **A secret in the git history no longer reads as `fixed` the moment somebody
  deletes the file.** The history sweep ran only on a branch's *first*
  analysis, on the reasoning that re-reading commits already read is wasted
  wall-clock. Nothing re-emitted those findings afterwards, so the checklist
  compared analysis 2 against analysis 1, did not see them, and reported them
  `fixed` — congratulating you for the exact act the finding's own remediation
  calls insufficient — and by analysis 3 they were out of the report
  altogether:

  ```
  run 1: aws_access_key=new
  run 2: aws_access_key=fixed        <- deleting the file "fixed" it
  run 3: (no findings at all)
  ```

  The sweep now runs on **every** analysis. It is `git log -p` and plain
  Python — seconds, and no tokens — and the finding stays `open` run after run
  until the credential is rotated at the provider and a human closes it with
  *Accept risk*, which is the only honest close: git history does not shrink.
  A secret that is in the working tree *and* in the history is still one
  finding, but the working tree's reading now wins the tie, so a live
  credential is reported at its real line and in the present tense instead of
  being overwritten by a line-0 note about the past.

- **An analysis can no longer close `done` without ever having looked at
  anything.** Nothing engine-side ran the deterministic phases — `prepare` is
  the agent's first command, named in the prompt and in the skill — so an agent
  that simply skipped it exited cleanly, the engine closed the row `done` on
  the run's own `success`, and the result was a report with zero findings, an
  empty coverage note and no banner anywhere saying the repository had never
  been scanned. It then became the *baseline* every later analysis is diffed
  against, so the next run's real findings all arrived as `new`. `prepare` now
  marks the row, and a `done` close of an unmarked row is downgraded to
  `capped` with a coverage note saying the deterministic phases never ran —
  which is what makes the report print its INCOMPLETE banner.

- **`ignore_paths` reaches every deterministic phase, not just one.** The globs
  lived inside the working-tree secret scan, so the git-history sweep and the
  hygiene pass never saw them: a fixtures directory full of deliberately fake
  credentials disappeared from one section of the report and was listed in full
  in two others. The dependency inventory still ignores them deliberately — a
  lockfile under an ignored glob declares packages the project ships, and a CVE
  against one of them is real wherever the file sits.

- **A deterministic phase that fails says so instead of answering "clean".**
  The history sweep returned an empty list for a timeout, an unrunnable `git`
  and a non-zero `git` exit — the identical value it returns for a repository
  with nothing in its history, so the one failure mode that hides the findings
  it exists to produce read as the best possible news. It now states the gap in
  the coverage note, alongside the files the working-tree scan never opened
  (over 2 MB, or not readable as UTF-8), which were also being skipped in
  silence. Every phase writes into that one note, in phase order, so a run that
  could not sweep the history *and* could not reach OSV.dev reports both.

- **`security.claude_config_dir` actually signs the analysis in as that
  account.** The derived job is the only place an analysis can carry a config
  dir — there is no `jobs.json` row to edit — and the derivation put it there
  correctly, but `run_job` read only the *project's* field and never the job's.
  Setting it produced no error and no effect: the analysis quietly signed in as
  the project's account, which for anyone pointing a client's code at a client's
  login is the whole reason the field exists. The config dir now resolves the
  way every other inherited field does, job first. Nothing changes for a real
  job: `claude_config_dir` is not a field a job can have — absent from
  `config/jobs.example.json`, absent from `set-field`'s allowlist, and never
  written by the dashboard's job editor.

- **An analysis no longer tears down a stack it never brought up.** The run is
  launched with provisioning skipped, precisely so a read-only code review does
  not run the project's `.env`, container and service hooks — but teardown had
  no such guard, so the `down` hook fired at the end of every analysis. On a
  project whose hooks stop containers, release ports and unlink services, an
  analysis took the *developer's own environment* down with it on the way out.
  The teardown is guarded by the job's identity, not by the environment
  variable, because teardown can happen from a later process entirely (the
  orphan sweep, an explicit worktree drop) where that variable is long gone.

- **The SBOM can be downloaded.** `prepare` built a CycloneDX inventory on
  every analysis with a lockfile in it and stored it, and nothing anywhere
  could read it back — not the CLI, not the API, not the page. An inventory
  nobody can get out does not exist for the one job an SBOM has, which is being
  handed to somebody else. `claude-cron security render --analysis <id>
  --format sbom` prints it, `/api/security/report?format=sbom` serves it, and
  the Security page has a fourth download button. It comes down as
  `.cdx.json` — the suffix the tools that consume one recognise.

- **`decide` is refused while any analysis of the project is running,
  whoever is asking.** The existing refusal works off `CC_SECURITY_AGENT`, a
  variable in the agent's own environment, and the agent has a shell —
  `env -u CC_SECURITY_AGENT …` walks past it. That guard is worth having (the
  failure that actually happens is a model deciding, in good faith, that
  retiring the finding it just filed is helpful) but it was being described as
  though it were a boundary, in the README and in the code. It is now described
  as what it is, and the ledger has one check that does not depend on the
  environment at all: no decision on a project with any analysis still
  `running`. It costs a human nothing to wait — the checklist is rebuilt when
  the analysis closes, so a decision taken mid-run would not have changed that
  run's report.

- **Three loose ends from that same finding, closed together.** The
  `running`-analysis check above queried the project's *latest* analysis only,
  which had a two-command bypass: open a second analysis of the same project
  and close it, and the latest reads `done` while the original — the one an
  agent is still working inside of — sits `running`, unseen. It now checks for
  *any* analysis of the project still `running`; a row left behind by a run
  that genuinely died is still swept before the project's next analysis opens,
  so this cannot wedge triage. `prepare --root` was not bound to the analysis's
  own worktree either — pointed at any other valid checkout on the machine, it
  scanned that instead and the analysis closed `done` having never looked at
  its own scope; it is now required to resolve inside the run's own directory
  whenever the run is isolated (`CC_RUN_MANIFEST` names it), unchanged for a
  human running `prepare` by hand. And the downloaded report's `capped`
  banner unconditionally claimed "it reached its spending cap", which became
  a second, contradicting cause once a `done` close could be downgraded for
  never having run `prepare` at all — the banner now says only what is true of
  every `capped` cause; the specific one is the coverage note right after it.

- **The page says a truncated analysis is truncated.** A `capped` or `failed`
  analysis is a partial read of the repository, and the numbers under it are
  the numbers of a partial read — `critical: 0` there means "none found before
  it stopped", not "none". Every downloaded report opened with that notice; the
  screen everybody actually looks at did not, so the one place a truncated
  analysis was presented as a finished one was the page. It also now says, next
  to the download buttons, that the files contain every recorded finding
  whatever `min_severity` is hiding on screen.

- **The Analyse button starts the run and lets go of it, and a crashed run can
  no longer brick it.** The control server gives a CLI call thirty seconds and
  then SIGKILLs the shell it started; an analysis is minutes of work. So the
  button spun for half a minute, showed a timeout, and the killed shell never
  reached the close — the analysis stayed `running` in the ledger *for ever*,
  which is exactly what the page reads to decide that Analyse must stay
  disabled for that project. One click, and that project could never be
  analysed from the dashboard again, with a Claude process still running that
  nothing was waiting for.

  `security analyze` now takes `--detach`: every refusal (security not enabled,
  no such branch, one already running), the analysis row and the request file
  are still synchronous, so the page keeps getting the engine's own sentence
  when it asks for something impossible — only the run is handed to a
  backgrounded subshell, and the command prints `{"analysis_id": n}` and
  returns. The close travels with the detached half, so a run that ends at one
  of `run_job`'s early returns still closes its row. Backgrounding the whole
  call instead would have fixed the timeout and lost every refusal: a
  fire-and-forget launch can only ever answer "started".

  And the rows already stuck that way are swept. Before it opens anything,
  `security analyze` closes any analysis of the project that says `running`
  while the derived job holds no live slot — no live slot means no live run,
  whatever the ledger says — as `failed`, with `engine: the run behind this
  analysis is gone` on the row. A row younger than
  `CLAUDE_CRON_SECURITY_STALE_GRACE` (120s) is left alone: a detached run needs
  a second or two to reach its slot, and sweeping inside that window would fail
  the analysis that is about to start.

- **A project with one checkout keeps one security history.** `security analyze
  <project> <repo> <branch>` ignores `<repo>` when the project declares no
  `repos` — there is one checkout and the argument names nothing — but the
  ledger still filed the analysis under whatever was typed. The dashboard files
  these under the project's own name, so a hand-typed `security analyze web
  repo main` opened a second, parallel history the page never showed beside the
  first. The repo argument is now normalised to the project name in that case,
  for the page and the terminal alike.

- **Leaving the Security view stops the analysis poll.** It started and stopped
  on "is an analysis running", so a reload already in the air when the view was
  left re-armed the four-second interval a moment after leaving cleared it —
  two subprocess-backed GETs every four seconds, from the Overview or the Jobs
  page, for as long as the analysis ran. "Open the run" also works *while* the
  analysis runs now: it was reading only the journal, which a run reaches when
  it ends, so the link was missing for exactly the minutes somebody wants to
  watch it. The project rows cache the findings rather than the posture
  computed from them, so changing a project's `min_severity` repaints the right
  counts; opening a project carries a generation guard, so a slow answer for
  the project you left cannot fill the pickers of the one you are looking at;
  and the page now agrees with the engine on what `security.enabled` means
  (`true` or `"true"`, and nothing else — it used to accept `1`, which the
  engine reads as off).

- **`/api/security/branches` no longer answers a checkout with no branches
  yet with a blank error.** An empty repository answers with an empty branch
  list instead.

- **The engine no longer disagrees with itself about `"enabled": "true"`.**
  `security_enabled()` reads the field through `jq -r`, which prints the
  boolean `true` and the string `"true"` identically, so it already accepted
  both — a hand-edited project with the string form passed
  `cmd_security_analyze`'s own gate. But `security_derived_jobs`' fast path,
  which decides in ONE jq call whether to run the per-project loop at all,
  tested `== true`, boolean only: a project with only the string spelling
  looked like "nobody has security on" there, so the loop that would have
  derived its job never ran. Both spellings now pass the fast path too, and a
  project written either way derives its job.

### Changed

- **A provider outage no longer slows a job down for the rest of the day.**
  Every failed run was `error`, and the failure backoff counted them all the
  same — so a 529 the API returned, an agent whose tools were denied, and a run
  killed by the watchdog each doubled the wait, up to 16x. On 2026-08-19 a 529
  killed a 100-minute run and the retry straight after it met the same overload;
  under the old rule that job would have been crawling for hours over something
  it had no part in, while the work sat waiting.

  Each failed run now carries a `cause` — `api_error`, `rate_limited`,
  `tools_denied`, `killed` or `agent_error` — and the two that are the
  provider's leave the streak exactly where it was. Not reset either: a job that
  is genuinely broken and also meets an outage is still broken. Every other
  cause counts as it always did, so a failing job still backs off.

  The cause is on the run record, on the `finished` line in `tick.log`, and next
  to the status in the Runs table, because the reader's next move differs by
  cause: an API failure is a wait, denied tools are a permission to fix, a kill
  is a log to open.

- **The run-ending contract now tells the agent what its marker decides.** It
  said the marker classifies the run, which was the whole truth until the
  worktree started belonging to the session. Now the same sentence decides
  whether the working tree is torn down or kept for a day with its services
  still running — so an agent that simply forgot to say it was done was holding
  a full checkout and a live database per repo, on a machine running several at
  once, and had no way to know. The contract says so, and says the cheap way out
  is to push what you finished and declare how you ended.

### Added

- **The fleet now says when it has stopped running anything.** `on-run-end.sh`
  fires when a run *ends*, which covers every way a run can go wrong and none of
  the ways the fleet can stop having runs at all. If the usage gate holds
  everything back for four hours, a precheck fails on every tick because the
  board credentials expired, or a slot left by a dead process blocks a job for
  ever, then no run ever ends and nothing ever tells anybody: the loop keeps
  ticking, the dashboard keeps saying it is awake, and the work does not happen.
  That silence is the most expensive failure this scheduler has, and it was the
  one with no notifier.

  `fleet_stall_reason` names which of the four it is, and
  `config/hooks/on-fleet-stalled.sh` is run once per stall with that sentence in
  `CC_REASON`. A new hook file rather than an extra variable on the existing
  one: a hook already on disk was written against that contract, and handing it
  events it never expected would make it lie about what happened.

  Two things it deliberately does not call a stall. `precheck found nothing to
  do` is the loop *working*, and paging somebody for it trains them to ignore
  the message that matters. And a long run that outlasts the window is the
  reason there have been no new ones — so the slots are asked, not just the log.
  It fires once and re-arms the moment a run starts again, so a fleet that stays
  stuck does not notify every minute until somebody turns it off.

  The phrases it matches are the control server's own `classify_tick` strings;
  `selftest` now asserts every one of them still exists there, because a rename
  on that side would blind this without breaking anything visible.

- **`claude-cron usage` — the gate can now say whether it is switched on.** The
  usage gate and the statusline that feeds it are both invisible when they work
  and invisible when they do not, and the only way to tell them apart was a
  hand-written one-liner over `data/rate-limits.json`. That puts the job of
  verifying the product on the person using it: a feature that cannot say
  whether it is on is a feature nobody can trust.

  The command prints how full each window is, how old the reading is and where
  it came from, whether runs are being held back right now (and that `run` still
  overrides), and then the wiring: statusLine not configured, configured but
  pointing at some other script, pointing at a path that does not exist — every
  session's status line failing in silence, which is what happens if you wire it
  to a checkout and then change branch — or correctly wired but never fired,
  because the statusLine is read when a session *starts* and one already open
  when you wired it will never call it.

- **The usage gate can now see the window before it is nearly full.**
  `rl_gate` shipped armed and blind: the run stream carries a utilisation figure
  ONLY once the CLI has decided to warn (at 0.75), and below that it reports
  `status: "allowed"` with no number at all — so through the whole quiet stretch
  where "should I start a 100-minute run?" is worth asking, there was nothing to
  answer with. `bin/statusline-rate-limits.sh` reads `rate_limits` off the
  statusLine payload, where the figure rides along on a response the session had
  already paid for, and folds it into the same `data/rate-limits.json` the gate
  reads.

  Measured, not assumed: **the statusLine is not invoked in headless mode** —
  neither `-p --output-format json` nor `-p --output-format stream-json
  --verbose` runs it, because there is no status line to draw. So this cannot be
  fed by the scheduler's own runs. It is fed by the operator's interactive
  sessions on the same account, which is what makes it worth having: you work in
  Claude Code during the day and the fleet learns how full the window is without
  spending a token to find out. Opt-in — it changes nothing until you point
  `statusLine` at it in `~/.claude/settings.json`.

  It merges rather than overwrites: `status` and `overage` come only from a run
  stream and describe the window that was measured, so they are carried forward
  while `resets_at` says it is the same window and dropped the moment it is not.
  Writes are floored at 15s, because the statusLine fires several times a second
  while a turn streams.

- **The scheduler now knows about the usage window, and holds runs back when it
  is spent.** The only ceiling it understood was money — `daily_budget_usd` and
  `max_budget_usd` — and on a subscription that is not the ceiling that stops
  you: the 5-hour and 7-day usage windows are. The API had been reporting them
  on the stream all along (59 of the last 60 runs carry a `rate_limit_event`)
  and nothing read it. On 2026-07-30 the seven-day window sat at 98% while the
  loop kept waking runs into it; on 2026-08-19 a 100-minute run died at the
  ceiling with ten commits unpushed. Both were legible in a file already on
  disk.

  `rl_capture` folds every window reading out of a finished run's stream into
  `data/rate-limits.json` (newest per window wins, and a killed run's truncated
  last line costs nothing). `rl_gate` reads it before a **scheduled** run is
  launched and holds it back when the API has stopped saying `allowed`, or when
  utilisation is at or past `CLAUDE_CRON_RATE_LIMIT_STOP_AT` (0.95 by default).
  `overageStatus: rejected` is what makes it worth gating rather than merely
  showing: with no overage to fall through to, reaching the ceiling is a dead
  stop mid-run, not a slowdown.

  A reading only speaks for the window it was taken in — once `resets_at` has
  passed it is ignored — so the gate lets go by itself, with no operator action
  and no clock of its own. `Run now` overrides it, exactly as it overrides the
  budget and the precheck. The tick band gained its own `rate_limited` outcome
  rather than folding into `capped`, because the next move differs: a dollar cap
  is a number you chose and can raise, a spent window is a wait.

  Known gap: the CLI only puts a number on the stream once it has decided to
  warn (at 0.75 utilisation), so a quieter window is invisible and only the
  refusal path can act on it. Reading `rate_limits` off the Claude Code
  statusline would give the figure on every turn, for free — see
  `docs/superpowers/plans/2026-08-19-rate-limit-gate.md`.

- **A whole run is now tested end to end** (`test/e2e.test.sh`, run by
  `claude-cron selftest`). Every suite before it was unit-level: it called
  `wt_setup`, the classifier and the sweep directly, and never drove a run
  through the engine. That gap is where the expensive defects lived — a marker
  written before the status was final, a resume that could not find the
  directory its own session was bound to, an upgrade that reaped what the
  previous version had been preserving. None of those is visible to a test that
  never runs a run. Thirteen checks now cover a clean ending, a run cut short,
  a resume reattaching to the same tree, work on no remote being reported, an
  open session expiring, a pre-upgrade directory surviving the first tick, and
  a slot from an earlier boot protecting nothing.

  It stays offline and free: `test/fake-claude` stands in for the CLI and emits
  the same `stream-json` shape, so no session is ever spent. It redirects
  `CLAUDE_CRON_CONFIG` and `CLAUDE_CRON_DATA` into a sandbox it deletes on the
  way out, so an operator's jobs, projects and run history are neither read nor
  written. Adds roughly 13s to `selftest`.

### Changed

- **The dashboard tab for kept run directories is now labelled Sessions, not
  Worktrees.** Its own blurb already talked about sessions throughout —
  "Worktrees" was the tab's original name, left behind once this branch gave a
  cut-short session its own lifecycle. Worktree is the isolation mechanism
  underneath; session is the thing actually being kept, and the word the
  README and the rest of the dashboard already use for it. Label only: the
  tab's id, its `data-tab` value and its pane were left exactly where every
  other part of the page already looks for them.

- **The filter-picker example names a generic project, not a real one.** A code
  comment illustrated the control with a live client project name. This is a
  public repository, so an example is a publication: it now uses the same
  placeholder the README does.

### Fixed

- **A usage reading with no status no longer reads as a refusal.** `rl_gate`
  treated "does not start with `allowed`" as the API having refused — and an
  absent status is not a refusal, it is silence. The statusline reports
  utilisation without any status at all, so installing it would have held back
  every scheduled run on a perfectly healthy window. Only a status that is
  present AND not `allowed*` counts as spent.

- **A resume that died young can be resumed again.** A resumed run carries the
  session it continued in `resumed_from` AND in `session` — it is the same
  conversation — and the Runs table's "has this task been continued already?"
  check matched on `resumed_from` without a "later than this run" guard. So a
  resume found ITSELF among its own continuations, and the table greyed out its
  Resume button under "this task was already resumed", pointing at the row the
  operator was looking at. The one row it locked was the one most worth firing
  again: an API overload killed a resume at 3m37s and $0.00 without the agent
  taking a single turn, and from then on neither that row nor the run it
  continued would offer the button — the task was unreachable from the
  dashboard, with its worktree and its ten unpushed commits sitting there. Both
  clauses are now guarded by `start > after`. A run that really was continued
  still says so, and still points at what continued it.

- **Opening a run no longer drops the sidebar down the page.** The modal scroll
  lock put `overflow:hidden` on `<html>` *and* on `<body>`. Only the one on
  `<html>` does the locking — it is what propagates to the viewport — while the
  one on `<body>` turned the body into a scroll container, and a scroll
  container is the nearest scrollport for every `position:sticky` inside it. The
  sidebar and the topbar were then sticking to a box scrolled to 0 while the
  page behind them sat at the reader's scroll offset, so opening a run from
  halfway down the Runs table pushed the sidebar that many pixels down and out
  of view. The lock now names `<html>` alone: the page behind is still just as
  inert — the scrollbar still goes away, the wheel still does nothing — and the
  rail stays where the reader left it.

- **A run the API killed now says so, instead of blaming the model.** A 529
  ended a 100-minute run mid-work, and the CLI reported it with
  `stop_reason: "stop_sequence"`, `subtype: "success"` and `terminal_reason:
  "completed"` — every field the run modal reads agreeing that nothing had gone
  wrong. So the one line whose whole job is to say why a run stopped said "Stop
  sequence — the model hit a configured stop sequence": a sentence about a
  choice the agent made, for a fault on the API's side, with the $32 and the
  unpushed branch left unexplained. The CLI does report the truth, in
  `api_error_status`; the server was forwarding a fixed list of fields that did
  not include it. It does now, and the modal reads it FIRST, before the
  protocol's own stop reason — "API error 529 — the API was overloaded on its
  own side… resume it to carry on where it stopped". Runs recorded before this
  still get it, read back out of the error text. A run that really did hit a
  stop sequence reads exactly as it did.

- **A run the API is bouncing no longer looks like a run that is merely slow.**
  Resuming that session hit the same overload: ten `api_retry` events, HTTP 529
  every time, then the CLI gave up at its retry ceiling. On screen that was a
  black rectangle under the word "live" and the words "Waiting for the first
  turn…" — indistinguishable from a healthy run still loading, for three
  minutes, and then a finished run with no transcript and no reason. The retry
  events were in the stream the panel was already tailing; nothing read them.
  The Terminal now names what is happening while it happens ("The API is
  refusing this run's turns — 3 retries so far, the last one HTTP 529… Attempt
  3 of 10"), and afterwards says the ceiling is why there is no transcript.

- **A live run with a large tool roster shows its session again.** The dashboard
  reads a running row's session id out of the transcript, and it read the first
  8 KB of it rather than the first lines. The init event carries the run's whole
  tool roster; with a few MCP servers attached it passes 8 KB on its own, so the
  window cut it mid-object, the parse failed on the fragment, and the Session
  column showed a dash. The transcript is append-only, so those first bytes never
  changed — the dash stayed for the life of the run, on exactly the busiest
  agents. The engine hit the same thing on its own side of this and was fixed by
  reading lines; this is the other half, so neither side can now see less than
  the other. Display only: the resume path never used this value.

- **A run stopped from the dashboard mid-work can now be resumed from the
  Runs table, not just from its job card.** It never declares an ending, so
  its worktree and its services are kept exactly the way an error's or a
  warning's are — but the Resume button only lit up for those two, so the
  one status whose whole run dir sits there waiting had no way to reach it.
  `run_record_stopped_early` also used to file every stopped run's session
  as empty, unconditionally, even when the agent had already reported one —
  so even widening the button on its own would have left it permanently
  disabled for a real, resumable session. It now reads the run dir's own
  `.session` when the agent had actually started (`$slot/child`), and still
  reports none when it had not, or when the stop landed before that agent's
  own session was bound — a stale id left over from an earlier resume of the
  same directory is never claimed for a launch that never got that far.

- **A resume and a fresh run can no longer end up bound to the same port
  block.** A resume checked `port_base_free` and wrote its claim afterwards
  with no lock held; a fresh run's `alloc_port_base` — which does hold
  `$LOCK_DIR/.ports` across its own scan and write — could land in the gap
  between the two and hand the same block to both. Two live runs then
  published the same ports, which read as a broken service, not as a
  scheduling race. `port_base_reclaim` now holds that identical mutex across
  its own scan and write, the same idiom `alloc_port_base` already used for
  its side of this.

  A write that failed inside that claim used to be reported as a success
  anyway (`|| true` swallowed it) — a block found free but never actually
  written to `$slot/portbase` is invisible to `alloc_port_base`'s own later
  scan, which reads that file, not what `port_base_reclaim` believes it did.
  A failed write now drops the lock and refuses the resume, the same as a
  block that turned out to be held.

- **Two overlapping ticks can no longer run `down` hooks for two different
  directories at once.** The orphan sweep takes and drops `$LOCK_DIR/.resume`
  once per directory, not once for the whole sweep, and `cmd_tick` had no
  mutex against itself — so a second tick starting while the first was still
  sweeping (a launchd interval firing again before the first returned, or a
  manual `claude-cron tick`) could interleave with it: each sweep holding
  `.resume` only briefly, per directory, let tick A run one directory's
  `down` hook — a `docker compose down -v`, seconds to minutes — at the same
  moment tick B ran a *different* directory's own, work the sweep's serial,
  one-directory-at-a-time design never accounted for. `cmd_tick` now takes
  its own `$LOCK_DIR/.tick` around the whole tick, so a second one simply
  waits for the first to finish before it starts. Narrowing `.resume` itself
  to cover only the sweep's decision, not the hook, was considered and
  rejected: that lock is also what stops a resume claiming a directory the
  sweep is mid-way through removing (the same reason `cmd_worktree_drop`
  holds it the identical way for a human's drop), and narrowing it would
  have reopened a resume claiming a directory between the sweep marking it
  done and the hook actually finishing — an agent launched into a cwd being
  deleted under it.

- **An unreadable or empty `.session` file no longer re-logs on every
  dashboard poll.** `retained_worktrees()` backs `/api/data`, polled every 5
  seconds, and `_session_bound_to` logged on both of those conditions every
  time — one bad file wrote a fresh line every 5 seconds until the TTL
  reclaimed its directory, up to 24 hours of an already-diagnosed condition.
  It now logs once per standing condition and stays quiet on repeats, kept
  in memory (the server is long-lived; nothing here needs to survive a
  restart) and cleared the moment a directory's condition changes or
  resolves, so a later recurrence — even the identical condition — is still
  reported.

  The throttle's own prune loop was not thread-safe: the dashboard is served
  by `ThreadingHTTPServer`, so two tabs polling at once — or one poll simply
  outrunning the next one's 5-second interval — genuinely ran
  `retained_worktrees()` on more than one thread at the same time, and the
  loop iterated its cache directly while another thread could be adding to
  or removing from that same cache underneath it. That raised
  `RuntimeError: dictionary changed size during iteration` or `KeyError`,
  killing the request — the exact failure this whole throttle exists to
  prevent, reintroduced by the throttle itself. It now snapshots the cache
  before iterating it and tolerates a key another thread already removed.

### Added

- **A job whose last run is being held for a resume now says so on its own
  card**, with a Resume button whenever there is a session to continue. Until
  now the only sign a run dir was being kept was a count on the Sessions tab —
  something an operator had to already suspect before they would go looking
  for it, then match back to the job by hand. The card reads the same
  `retained_worktrees()` list the Sessions tab does, filtered to that job, and
  the button is the Runs table's own Resume op, not a second one: it shares
  the same in-flight guard (a resume already running for that session), so
  the two cannot fall out of agreement about when the button is safe to press.
  A run dir held with no `.session` at all — the run died before its agent
  ever got far enough to report one — says so honestly instead of offering a
  button that could only ever be refused.

  The id is read as bytes and decoded with `errors="replace"`, not
  `Path.read_text()`: a session id is written by a single `printf` and should
  always be plain ASCII, but `.read_text()` raises `UnicodeDecodeError` — a
  `ValueError`, not an `OSError` — on a byte that is not valid UTF-8, which the
  unreadable-file handling above did not catch. Uncaught, that would have
  crashed `retained_worktrees()` and blanked the whole dashboard poll over one
  corrupted file, not just its own row — the same fix `_load_artifacts`
  already needed, elsewhere in this file, for the same reason.

- **A run directory now records the session working in it** (`.session`). The id
  arrives in the transcript's first event and is bound to the run directory as
  soon as the watchdog notices it, plus a final pass right after the run exits —
  so a run that crashes inside the watchdog's first 30-second poll window still
  ends up bound instead of being lost for good, with the id sitting unread in a
  transcript nothing ever looks at again. The write goes through a temp file and
  rename, since a resume will look run directories up by this file while runs
  are still live. That temp file is now named by `mktemp`, not `$$` — bash 3.2
  never reseeds `$$` inside a subshell, so the watchdog's write and the
  post-wait write were silently computing the identical path, correct only
  because both always resolved to the same id. `selftest` also now checks
  structurally that both binding call sites remain in `run_job`, since a
  behavioural test of `bind_session` alone cannot see which callers still reach
  it. Nothing reads the file yet; it is what the resume and the teardown below
  are built on.

- **A precheck can tell "no work" apart from "I cannot see the work"**
  (`bin/board-probe.sh`). Both used to end the same way — zero keys and the line
  "nothing to do" — so a fleet whose Jira access had broken filed itself as idle,
  indefinitely, and the tick chart and the greeting agreed with it. Observed for
  real: a token that authenticates but is scoped away from the project makes the
  search endpoint answer `200 {"issues":[]}`, a valid empty answer, while 49
  tickets sit on the board. `bp_board_visible` now proves both halves —
  credentials AND the project — before absence of work is reported at all, and
  `bp_search` returns non-zero for a query that failed rather than passing it off
  as a quiet one. A precheck that cannot look now says so instead of saying there
  was nothing to see.

- **The dashboard has an operator, and a way in and out.** It used to be that
  anything reaching port 8787 got a working control panel — the token that
  guarded the API was embedded in the page the server handed to whoever asked.
  There is now a profile (name, email, password, avatar) in `data/app.db`, and a
  session behind a cookie. The token still proves a request came from our own
  page, which is the anti-CSRF gate and is unchanged; the session proves somebody
  signed in, and every endpoint but `/api/session` refuses without one. So "sign
  out" now removes something rather than hiding it.

  The password is PBKDF2-HMAC-SHA256 at 600k rounds with a per-profile salt, and
  the cookie is stored only as a digest — reading `app.db` hands over neither a
  password nor a live session. There is **no reset**: nothing on the machine can
  read the password back.

  Sessions expire after 12 hours *idle*, pushed forward by every authenticated
  call — absolute expiry would sign an operator out mid-run for nothing, on a
  port only reachable from loopback. **Keep me signed in** stores no expiry at
  all, and that session lives until it is signed out.

  Not in `data/index.db`: that file is documented as a derived index and safe to
  delete, and an account destroyed by a `rm` the README recommends is a trap.

- **Setup happens on first open, not in the installer.** An existing install
  never re-runs `install.sh`, so putting profile creation there would have left
  every upgrade with no operator and no way to make one. The same screen serves a
  fresh install and one that just pulled: no profile → nothing else is reachable
  until name, email and a confirmed password exist. The confirmation is checked
  on the server too — a confirmation only the page enforces is decoration, and
  this password cannot be recovered.

- **Overview opens with a line written for a person, and counters you can
  compare.** The 24-hour panel is two columns now: what the loop did on the left,
  what it cost on the right. Checks, woke-a-run and errors are figures with their
  own denominator ("48% of checks", "0% error rate") instead of a sentence above
  the chart, where a bare number sat with nothing to be read against. A
  percentage of nothing prints as `—`, not a confident `0%` divided by an empty
  denominator.

  Above it, a greeting derived from the same tally the panel draws — one tally,
  because two independent counts of one thing is how a page ends up contradicting
  itself. It says what actually happened (nothing ran, everything is disabled,
  three errors are waiting, the agents spent $110 today), and it is pinned to the
  hour: this panel repaints every five seconds, and a line that rerolled each
  time would read as the page glitching.

- **Jobs and Runs have one filtering language instead of two.** Both pages now
  carry the same toolbar — a search box, a dropdown per axis, Clear filters, and
  a row of chips naming every filter that is on, each removable on its own. The
  chip row is the part that was missing: two dropdowns reading "All projects"
  and "Disabled" do not add up to "you are looking at a subset", and the old
  collapsed Filters panel meant the answer to "why is this table short" was
  behind a click. Jumping from a job to its runs now lands with that chip
  already saying which job, rather than springing open a filter panel.

  Runs keeps its date range: presets for the answer you usually want, the two
  exact fields underneath for the one time you do not, and a single chip either
  way — "Last 7 days" and a hand-typed range are the same filter, and two chips
  for it would imply two.

- **The project dropdown pages, and remembers.** Recent shows the last three you
  filtered by; All projects loads five at a time as you scroll, with the footer
  counting up as they arrive. The first page is topped up until the list
  actually overflows its box — five rows that fit exactly leave nothing to
  scroll, so the second page could never be asked for and the list would sit at
  five for ever under a footer promising sixteen.

- **A job card is two columns, and the precheck counts have a panel.** They were
  a list trailing off the end of the "probed 7h ago" line — the densest thing on
  the card, and the reason you are looking at it, tucked behind a timestamp.
  "8 spec ready, 0 blocked" is the answer; when the probe ran is the label on it.

  The card grid follows from a real minimum width rather than a fixed three
  columns: three across a 1230px page is 380px each, which is under the width
  where that split reads, so it silently stacked. On a wide screen it is still
  three or four.

- **A project can be starred, and starred projects sort to the top.** The star
  is on the project card, where you are already looking at its jobs. It is
  stored per operator in `data/app.db`, not in localStorage: favourites that
  vanish in another browser read as data loss, not as a cache miss.

- **Three destinations, three jobs to do.** The dashboard is the greeting, the
  24-hour band and — under its own tabs — whichever list you were last reading.
  They belong together: you see three warnings in the band, click, and the runs
  that caused them are on the screen you were already looking at, with a chip
  saying why the table is short. Putting a navigation step in the middle of that
  single thought was the wrong shape.

  Jobs and Runs in the sidebar are the narrowed views — that list and nothing
  else, no band and no tabs. The dashboard's tabs move only the dashboard: they
  are not the menu, so they no longer move the menu highlight and claim you
  navigated when you did not.

- **Projects has a page.** A table beside Jobs and Runs — name, how many jobs
  inherit from it, the working directory, how many repos, whether runs get their
  own worktree — sortable, searchable, with edit and delete inline on each row
  and the favourite star where the project is. New project lives here, which
  closes the gap left when it came off the Jobs toolbar: creating one had no
  entry point at all.

  Deleting says what it costs before it happens: a project's jobs survive it but
  lose everything they inherited — directory, repos, account, provisioning — and
  the confirmation counts them.

- **One wizard, two dialogs.** Jobs and projects are configured the same way and
  now behave the same way, from one implementation rather than two that drift:
  the steps, the numbered strip, the create-walks/edit-navigates split, the
  unsaved-changes dot and footer, the confirm-on-close, and the step marked when
  a save is refused. The second copy of that would have been the one that
  quietly stopped confirming a discard.

- **One job editor, two modes.** Creating and editing want opposite things, so
  the same five-step dialog behaves differently in each rather than being two
  screens to keep in sync.

  **Creating is a walk.** Five decisions in order, each narrowing the next, and a
  half-filled job is not something the engine can run: Back and Next, the primary
  button naming where it goes ("Next: When it runs"), validation before each
  advance, and Create job at the end. A completed step is clickable, so a mistake
  two steps ago costs a click rather than a cancel and a restart.

  **Editing is navigation.** You already know which field you came for, so every
  step opens immediately, there is no Back, and Save changes is always the button
  — no walking to the end to commit one edit. Steps you have touched carry a dot
  and the footer says "Unsaved changes", because with five steps the change you
  made is usually not on the step you are looking at; closing with edits pending
  asks first, including on Escape, which would otherwise drop them silently.

  Required fields carry the same `*` the sign-in screen uses, the reason a save
  or a step was refused sits beside the button that refused it, and the step at
  fault is marked in the strip — a sentence in the footer cannot say which of the
  five it means. Save re-checks **every** step in both modes: a field can be
  emptied after its step was passed, and in edit mode most steps were never
  opened at all. That last one was hiding a real fault — clearing the prompt and
  saving used to do nothing at all, silently, because the save path only sends a
  field it can see a value in.

- **The prompt and precheck boxes can actually be resized.** Both drew a resize
  grip and neither moved: they were flex items with a basis of `0`, so their own
  height was ignored entirely and the inline height a drag writes did nothing —
  a handle on a box that could not be resized. The basis is `auto` now, and the
  pane grows past the dialog with the panes scrolling, rather than the two boxes
  splitting a fixed budget until one hits its minimum and the handle goes dead
  again. Their starting heights are deliberately under what fits, so `grow`
  fills the pane exactly and no scrollbar appears until you ask for one.

- **Dragging a box taller scrolls to follow it.** The browser grows the element
  and leaves the view where it was, so the grip slides under the fold and you
  carry on resizing something you can no longer see. The pane now keeps the
  dragged box's bottom edge in view — downwards only, and only when the drag
  started on the corner grip, so clicking into the middle of a textarea does not
  yank the pane about.

- **No form in either wizard hides its explanation behind a disclosure.** Six
  `<details>` — what interactive changes, how the limits interact, which account
  a run signs in as, when to add repos, why isolation matters, what the
  provisioning scripts get — are now plain hints under the field they describe,
  like every other field. A collapsed summary asks you to guess whether it is
  worth opening; the sentence that stops you configuring something wrongly
  should not be one click away from a field you are filling in right now.

- **The job form says what each field is for.** Every field carries the sentence
  that stops it being filled in wrongly; a label of three uppercase words could
  not. The description is a three-line prose box rather than a single-line input
  wearing a 170px monospace slab meant for prompts.

- **Jobs has a table of its own.** Cards are for the dashboard, where you are
  glancing at a handful; a table is for the page you opened *because* of the
  jobs, and it sorts — by job, project, status, last run, next or today's spend.
  Job, project, status, schedule, last run, next and today's spend, and nothing
  else: a row carrying everything a card carries is unreadable at the twenty
  rows where a table starts to win. The rest is one click into Edit, and New job
  is in the toolbar.

  Four flat actions per row — run, enable, edit, delete — instead of two of them
  behind an overflow menu. In a table the row already is the list, so the menu
  was a layer of chrome hiding half the actions; delete still confirms, which is
  what actually keeps it off the edge of a slip.

- **A sortable column now looks sortable.** The caret only inked on hover, which
  on a trackpad means never — so the only column that appeared sortable was
  whichever one already was, and the other five may as well not have existed.

  A column with no answer for a row — never run, or disabled so never next —
  sorts to the bottom whichever way the arrow points. Treating "never" as a very
  large number is what put seventeen disabled jobs above the ones actually due
  the moment you reversed the column.

  The card and the table read one `jobFacts()`: two renderings of one set of
  facts, so a "next check" cannot differ between them — a bug nobody would see
  without opening both at once.

  Relatedly, `fmtAgo` could only look backwards, so a check due in five minutes
  rendered as "0s ago" — in the one column where the number is the entire point.

- **Navigation moved into a sidebar: Overview, Jobs, Runs, Projects, Settings.**
  Five destinations do not fit in a two-tab strip. Projects and Settings say
  plainly that they are not built yet rather than showing an empty panel that
  reads as a failed load. The hamburger collapses the sidebar to an icon rail on
  a desktop and slides it off-canvas on a phone — one control, because 236px is
  cheap on one and a quarter of the screen on the other.

### Fixed

- **Five comments and a README section that described behaviour this branch
  had already revoked.** `down` was documented as running "even when the run
  dir is preserved" — exactly backwards: a preserved run dir is the one case
  where `down` does *not* run, on purpose, so the resume it is being kept
  for finds its services still up. "Sessions that are still open" said
  undelivered work was the one thing that did *not* keep a directory; since
  Task 6 it has been the opposite. `cmd_tick`'s own comment, the server's
  `worktree_drop` handler and `wt_remove_all`'s header all still explained
  keep/remove in terms of the pre-Task-6 "unpushed work" rule, superseded
  first by the status-based one and now by declared-ending-and-delivered.
  Two comments in `worktree-lib.sh` named a container-orchestration tool and
  a local-dev-environment tool by name — the one file in this codebase whose
  own header says it must never couple to a specific tool or language, since
  every project-specific detail belongs in `projects.json` instead. Reworded
  to describe what a project's own hooks start, generically, the way the
  rest of the file already does.

### Changed

- **A broken `.git` pointer is reported, not read as a clean tree.**
  `wt_dirt_sha` hashes `git status --porcelain`'s output, and that command
  prints nothing both for a clean worktree and for one it cannot read at
  all — so hashing the silence gave the exact same fingerprint either way
  (measured: `da39a3ee5e6b4b0d3255bfef95601890afd80709` for a clean repo, a
  missing path, and a non-repo alike). Reachable when an operator moves or
  renames a canonical checkout, which breaks every one of its linked
  worktrees' `.git` pointers at once. Survivable while the answer only
  decided a note on a card; since 9.3 made `.ended` depend on it, the same
  collision authorised `git worktree remove --force` on a tree holding real,
  uncommitted work. `wt_dirt_sha` now returns non-zero, and prints nothing,
  when git cannot answer, and `wt_undelivered_work` reports "cannot read
  git" as undelivered rather than comparing a hash it never got. The same
  reasoning closes the adjacent `[ -n "$head" ] || continue`: a `rev-parse`
  that fails is "could not look", not "no commits", and is now reported too
  — the two blind spots share one cause, a worktree git cannot read, and are
  now closed together. Proved against a real worktree holding real
  uncommitted work with its `.git` file broken: without the fix
  `wt_undelivered_work` reports nothing; with it, the note names both the
  unreadable status and the unreadable history.

- **A reattach's second dirt_sha refresh no longer discards a stale-but-valid
  snapshot when the fresh reading itself fails.** Found reviewing the
  `wt_dirt_sha` fix above, not in the original finding: 9.10 taught the
  reattach branch's dirt_sha merge to fall back to a repo's EXISTING
  snapshot when a fresh reading is missing, specifically so an unreadable
  one would not be misread as "nothing recorded" and fall into
  `wt_undelivered_work`'s strict, no-snapshot check — which would then flag
  ordinary provisioning residue as the agent's own work. That fallback
  relied on jq's `//`, which only falls through on `null` — but a repo whose
  `wt_dirt_sha` now fails during the re-up pass still gets a line in the
  merge's tsv, just with an empty value, which is present, not absent. The
  merge kept that `""` and silently discarded the good, stale value it was
  supposed to fall back to. The merge now treats an empty fresh reading the
  same as a missing one before falling back.

- **The control server's journal lock is boot-aware too, matching the
  engine's own lock.** `journal_lock` and `lock_take` are the same mkdir
  lock, taken on `.journal.lock` by the same name, and 9.6 made `lock_take`
  refuse to wait forever on a pid recycled across a reboot — but the
  server's own `_alive` stayed a bare `os.kill`, unable to tell the
  difference. A `.journal.lock` left behind by the server across a reboot
  falls into `lock_take`'s deliberate no-boot-file fallback, sees a
  live-looking recycled pid, and waits forever inside `record_run`, before
  `run_cleanup` ever runs — the run's slot is never released and its record
  never written, the exact silent stall Task 1 was chartered to remove. The
  server now writes a `boot` file alongside its `pid` on take, and checks it
  in `_alive` the same way `slot_alive` already does. Proved against a lock
  naming this test process's own (genuinely alive) pid but a boot id from a
  different boot: taken at once with the fix; without it, waits the full
  30s timeout and raises.

- **A resume that cannot find its own tree refuses, instead of quietly
  starting a fresh one.** Widening the dashboard's Resume button to
  `error`-or-`warning` (9.7) lit it up for `NOTHING TO DO:` runs too — but
  those end `warning` *and* `.ended=done` (9.3), so `run_cleanup` has
  already removed the tree before the dashboard's next poll. Clicking
  Resume reached `wt_find_by_session`, found nothing, and fell straight
  through to the fresh-worktree branch: a whole new agent session spent on
  a task that had already said there was nothing to do, with nothing
  telling the operator that is what happened. `run_job` now refuses a
  resume whose session directory cannot be found, the same way it already
  refuses an already-claimed tree or a missing primary worktree — logging
  why, and leaving nothing half-started, since the refusal sits before
  either branch has written to the run's slot. This also closes the case,
  previously open, of a resume whose directory was deleted by hand.

- **A run's second ending restarts its ttl clock too, not just a resume's
  first claim.** The first time `.ended` is written, creating the file
  bumps its run dir's own mtime for free. Overwriting an EXISTING
  `.ended` — a resumed run ending a second time — only touches the file's
  content, not the directory entry, so the clock stayed wherever the
  reattach's own claim-time touch (9.4) left it: `ttl` minus however long
  the resumed run took, not a fresh window. A session resumed near the end
  of its first ttl that then ran long enough on its own could read as
  already expired the moment it stopped, with the very next sweep
  reclaiming it while the operator was still reading a card that promised
  a full day. The classifier now touches the run dir alongside every
  `.ended` write, so a first ending and any later one measure the same
  event.

- **A reattach's second provisioning pass no longer frames its own residue
  as the resumed agent's work.** `wt_undelivered_work` tells a hook's
  leftovers from the agent's own changes by comparing the worktree's current
  `dirt_sha` against the snapshot taken right after provisioning — but a
  reattach re-runs `up` (to put a stack back that a reboot took down) without
  ever refreshing that snapshot. A second pass can legitimately leave
  different residue than the first (a regenerated `.env`, a compose lockfile
  or temp dir named after its own pid), and every byte of that difference was
  attributed to the agent and reported `UNDELIVERED` on a run that may not
  have touched the repo at all. The reattach branch now recomputes and
  records `dirt_sha` after its own `up` pass, exactly the way `wt_setup`'s
  first pass already does.

- **Two single-line deletions that used to revert whole tasks silently now
  fail the suite.** Deleting the line that computes `reattached` from
  `wt_find_by_session` (leaving `local reattached=""`, which alone satisfies
  `set -u`) turns the entire reattach branch into dead code — every resume
  falls through to a fresh worktree — while the existing ordering assertion
  for that branch stays green, because it only checks the order of lines
  *inside* a branch that has quietly become unreachable. Deleting `cmd_tick`'s
  own call to `wt_prune_canonicals` reverts the stale-registration cleanup
  the same way, while its behavioural test — which calls the function
  directly, the way a test has to — keeps passing for the same reason. Two
  new structural assertions close both, the same way an existing one already
  protects `bind_session`'s two call sites: not by testing the function
  (already covered elsewhere), but by testing that something still calls it.

- **The dashboard's Resume button lights up for a `warning` run, not just
  `error`.** `UNDELIVERED`, `UNDECLARED ENDING` and `BUDGET LIMITED` all end a
  run `warning`, and every one of their own notes tells the operator to pick
  the run back up — UNDECLARED ENDING and BUDGET LIMITED both say "resume
  this run to continue with its context", UNDELIVERED says "resume this run
  to finish it" — while the engine keeps that run's worktree and its
  services up specifically so a resume has something to continue in. The
  button read only `error`, so the far more common case showed a dead icon
  with "Only a failed run can be resumed" next to a note telling the operator
  to do exactly that. `success` and `stopped` stay off. The already-resumed
  guard (grey the button out once another run has picked the session back
  up, so a second click cannot duplicate the work) now also applies to a
  `warning` run's Resume button, not only an `error` one's — it reads the
  same `resumeTarget` lookup, just no longer gated to one status. The
  `error`-or-`warning` test itself is now a single `resumable` value read at
  all three sites that need to agree, not three separate copies of the same
  comparison — three places to keep in sync is exactly how this went from
  `error`-only to `error`-or-`warning` in the first place.

- **A retained run dir cannot be dropped out from under a resume that just
  claimed it.** `worktree-drop` checked `wt_is_claimed`, then ran
  `wt_down_all` — a provisioning `down` hook, seconds to minutes — and only
  then removed the directory, without ever taking the lock a reattach claims
  its tree under. A resume claiming the same directory inside that window
  could start its agent with a valid cwd and then have the drop's removal
  delete that cwd out from under the now-running agent. `worktree-drop` now
  takes `$LOCK_DIR/.resume` before checking the claim and holds it through
  the removal — the same lock, so whichever side gets there first completes
  its whole check-then-act sequence before the other can even look.

  The identical race existed on the *automatic* side too, found in this same
  task's self-review: `wt_prune_orphans` — the sweep every tick runs — read
  `wt_is_claimed` unsynchronized, so it could see "not claimed yet" in the
  same narrow window a reattach is inside its own lock but has not yet
  written its claim, age-check the directory, and remove it out from under
  a reattach that was mid-way through claiming it. `wt_prune_orphans` now
  takes the same `$LOCK_DIR/.resume` lock too, per directory rather than
  once for the whole sweep — a global lock held for the entire sweep would
  serialize every job's resume behind however many directories that tick
  happens to expire, combined, rather than behind just the one it actually
  contends with.

- **A resume restarts its session's ttl clock.** The expiry sweep reads a
  kept-open run dir's age from the directory's own mtime, and rewriting
  `.ended` on exit does not touch a directory entry — so without this, the
  second cycle's window was `ttl − (age when the resume started)`. A session
  resumed near the end of its first TTL window that then ran for a few more
  hours was already past the ttl the moment it stopped, and the very next
  sweep deleted it while the operator was looking at a card that said "resume
  this run to continue with its context". The claim now touches the run dir
  the moment it succeeds, giving every resume a full, fresh window — but only
  the moment it succeeds: a refused claim (another live run already holds the
  tree) returns before reaching it, so a run that never gets to keep the
  directory never resets a clock for it either.

- **A session is done when the agent says so and delivers everything — not
  when the run merely looks good.** `.ended` used to come from the run's
  quality verdict: only `success` wrote `done`. But `warning` fires for
  `NOTHING TO DO:`, an undeclared ending, a spent budget cap, a stray byte of
  stderr, an empty result, and now `UNDELIVERED`; `stopped` and `error` also
  land `warning`-adjacent as far as this was concerned. Every one of those
  kept its worktrees **and left its services running** for a full TTL window,
  and `alloc_port_base` only skips port blocks held by a *live slot* — a
  retained session has none — so the next run was routinely handed the port
  block of a stack that was still up and listening. On one real install this
  was roughly a quarter of all runs.

  `.ended` now asks two questions instead: did the agent declare how its run
  ended (`RUN COMPLETE:` / `NOTHING TO DO:` / `BLOCKED:`), and did it leave
  anything undelivered? Both true is `done`; anything else is `open`. Exit
  code, stderr and the budget cap say how *well* a run went, not whether the
  session still has work to pick back up, so none of them feed this anymore.
  The declaration check itself now runs unconditionally rather than only
  while the status is still `success` — a run this classifier calls
  `warning` for an unrelated reason (stray stderr, say) can still have said
  exactly how it ended, and the old gating silently discarded that fact for
  precisely the runs where `.ended` most needed it.

  The other half of the question — did it leave anything undelivered — is
  now unconditional too, caught in this same task's own self-review (three
  independent passes converged on it) rather than in the original finding:
  `wt_undelivered_work` was still only called inside a
  `case "$status" in success|warning)` arm the note it feeds has always been
  scoped to, which left `undelivered` at its default empty value for `error`
  or `stopped` — read by the `.ended` gate as "nothing undelivered" without
  ever having been asked. An agent run that trips one denied tool call
  (`status=error`, unrelated to whether anything got pushed) but still
  finishes and says `RUN COMPLETE:` would have satisfied the gate and had
  its uncommitted work force-removed on the next tick, unreported. The check
  is now unconditional; only the note it can add and the bump to `warning`
  stay scoped to success/warning, so a `stopped` or `error` record is still
  never overwritten with a less informative one.

- **`lock_take` no longer waits forever for a recycled pid.** `.state.lock`,
  `.journal.lock`, `.ports` and the resume lock all live under `data/`, so
  they survive a reboot exactly like a run slot — and the kernel reissues
  pids from 1 on the way up, so a live-looking pid in one of these lock
  directories can belong to an entirely different process than the one that
  took the lock. The bare `kill -0` this function used to check a holder with
  cannot tell the difference, and a *live* holder is waited for indefinitely
  by design (that is the fix for the lock-broken-purely-on-elapsed-time bug),
  so a false positive here wedges the scheduler on every write these locks
  serialize — state, the journal, port allocation, a resume — with no escape.
  This is the identical defect Task 1 removed from the run slots, reopened
  here on a different kind of directory. `lock_take` now checks `slot_alive`
  instead, which also refuses a pid from an earlier boot, and writes its own
  `boot` file when it takes the lock, the same way a slot does. Proved by
  reverting to the bare `kill -0` and watching `lock_take` spin forever on a
  lock whose pid file names the calling process's own (genuinely alive, but
  from a fabricated earlier boot) pid — confirmed hung via `ps`, not inferred.

- **Upgrading onto a directory this branch never created does not delete
  it.** A run directory the OLD teardown had kept — because git said it held
  commits or changes that exist on no remote — has no `.ended` and no
  `.session`; neither file existed before this branch. `wt_prune_orphans` read
  such a directory's age from its mtime, which is whenever that old run last
  touched it, found it past the TTL on the very first post-upgrade tick,
  wrote `done`, and `wt_teardown` ran `git worktree remove --force` —
  discarding, unreported, exactly the work the old code was keeping the
  directory alive to protect. A directory this engine never bound to a
  session now has no age it can trust: the first sweep that finds one with
  neither file **adopts** it instead of judging it — marks it `open`,
  restarts its clock, and lets it stand for a full TTL window, so it shows up
  on the dashboard with a countdown instead of vanishing silently on upgrade.
  Proved against a fixture shaped exactly like a pre-upgrade install: a real
  git worktree holding a real commit on no remote, no marker files, an mtime
  set weeks in the past. Without this fix the commit is gone after one sweep;
  with it, the directory and the commit both survive.

  The tick log for an adopted directory names the *condition* it was adopted
  on ("no `.ended`, no `.session` found"), not a cause it never verified: the
  shape is a strong signal a directory predates this branch, but nothing
  here actually checks that, and a future log line claiming "from before
  this version" for a directory that reached the same shape some other way
  would misdirect whoever reads it.

- **A run killed with `-9` is resumable again.** `wt_find_by_session` alone
  demanded the literal string `open` in `.ended`, while every other reader of
  that file — `wt_teardown`, `wt_prune_orphans`, `run_cleanup`, `wt_setup`'s
  own rollback, the server's `expires_in` — already reads an absent marker as
  open, which is what a SIGKILL, an OOM kill or a reboot leaves behind: no
  exit path runs, so no marker is ever written. The mismatch meant the one
  session a resume most needs back — one nothing had the chance to close —
  was refused by the one function whose job is to find it. `run_job` fell
  through to a fresh worktree with no error at all: the tick log said
  `isolated in …` instead of `resumed … in its own tree`, so nothing anywhere
  recorded that a session had been dropped and the agent's next turn carried a
  conversation remembering edits its checkout did not have. Found in the final
  whole-branch review, not by any single task's own tests: `.session` is
  already written by the time a SIGKILL lands (the watchdog binds it on its
  first pass), so this was reachable on the very first crash after Task 7
  shipped.

- **An open session expires instead of waiting for a human.** Keeping a cut-short
  run's tree so a resume can use it would have swapped one permanent directory
  for another: a session nobody ever resumes is exactly as immortal as the
  unpushed work it replaced. Open sessions now expire after 24 hours
  (`CLAUDE_CRON_SESSION_TTL`), and expiring closes the session so the ordinary
  path runs its `down` hooks and removes the tree like any other finished run.
  The dashboard shows how long each has left, so the list reads as a queue with
  an end rather than a pile.

  The dashboard's countdown reads `WORKTREE_SESSION_TTL`, not `SESSION_TTL`:
  the control server already used that name for the HTTP sign-in idle timeout
  (12h), and a second module-level assignment of one name does not fail — it
  just wins silently at import, with the first one gone. `retained_worktrees()`
  would have computed every `expires_in` against that unrelated 12-hour
  constant instead of the sweep's real one, so the Expires column would have
  read "due now" up to twelve hours before the sweep was ever going to reclaim
  anything. A test asserting only `expires_in > 0` cannot see that; the fix
  pins the actual number.

- **A resume continues in the tree its session was working in.** `run_job`
  computed a fresh timestamp and cut new worktrees from the base with no special
  case for a resume at all — so `claude-cron resume` handed the agent a
  conversation that remembered editing files and a checkout that had none of
  them, while the crashed run's directory sat preserved on disk for nobody. The
  resume now finds the directory by the session id recorded in it, takes back the
  same port block (and refuses outright if a live run holds it, rather than
  pointing the agent's config at ports nothing is listening on), and re-runs the
  provisioning hooks so a stack a reboot took down comes back.

  It reads the run's manifest and never re-derives the repo set from
  `projects.json`, which fixes that set for the session's life: editing a
  project's `repos` no longer changes what an already-open session is working on.
  Provisioning hooks must therefore tolerate being run twice on the same tree —
  `cc_copy_ignored`, `cc_env_ports`, `herd link` and `compose up -d` all do.

  Two `claude-cron resume` calls for the same session — a double click, a
  retried automation — used to both reach this point and both launch an agent
  into the same tree: nothing stopped them, and `max_parallel` does not help
  since it defaults to 3. A resume now claims its tree under a lock, checking
  whether another live run already holds it *before* writing its own slot's
  breadcrumb (checking after would make it see its own claim and refuse
  itself) — a second, concurrent resume is refused instead, cleanly, with
  nothing written for it to clash with, and with its own start time and status
  recorded rather than the previous attempt's left in place. The lock itself
  is dropped on both exits from that check — a refusal releases it
  immediately rather than holding it until the run's own cleanup gets there.

  A manifest whose `primary` field is empty — missing, unparseable, or from
  before this field existed — used to pass the worktree-exists check anyway:
  an empty name turns it into `-d "$run_dir/"`, and the run dir itself always
  exists. The resume would then launch its agent with its cwd set to the
  folder holding the worktrees, not to a checkout. An empty primary is now
  refused explicitly, the same way a missing directory already was.

  A freshly allocated port block — the manifest predates this field, or could
  not be read — is now written back into the manifest, not just handed to the
  environment: the orphan sweep's `down` reads the block from there first,
  with no ambient `CC_PORT_BASE` to fall back on, and a block that was only
  ever in the environment would leave it releasing ports this run never took.

- **Teardown asks whether the session is done, not whether the tree looks
  precious.** A run directory was kept when git said it held work that existed
  nowhere else — a verdict the sweep re-reached every tick, so nothing ever
  released it, and one only a human could end. Directories are now marked with
  how their run ended: a finished session is torn down and removed
  unconditionally, and a run cut short is kept **with its services still up**,
  because the resume continues in that same directory and would otherwise get a
  provisioned tree with nothing running behind it.

  A run that died before marking anything counts as **open**, not finished. The
  tidier default would delete it, and it would delete work: a SIGKILL, an OOM
  kill or a reboot runs no exit path, so no marker is written and the classifier
  never fires — which means the `UNDELIVERED` report that justifies removing a
  tree never runs either. The first tick after a reboot would have reclaimed
  every run that was in flight, silently, with nothing anywhere saying what was
  in them. The leak that default was avoiding is closed by the expiry instead.

  A failed provisioning hook still leaves nothing behind, which "no marker
  means open" would otherwise have quietly undone: `wt_setup`'s own rollback
  reuses `wt_teardown` for removal, and a setup that never got as far as
  launching an agent has no session to be open FOR. Its five rollback paths now
  mark the directory done, themselves, before handing it to teardown — a setup
  failure is a known, finished outcome, not an uncertain one waiting on a
  resume.

  Stopping a run from the dashboard closes it only when no agent had started
  yet. `claude-cron stop` signals the run wrapper whenever the agent pid is not
  *alive* — which includes an agent that has already finished — so a Stop
  clicked during the seconds of post-agent bookkeeping used to look identical to
  a Stop clicked before the agent ever existed. Telling them apart takes the
  presence of the spawned agent, not the stop.

  The record that same Stop leaves behind used to lie about it: whatever
  ended the run early, `run_record_stopped_early` always filed "no work was
  done and nothing was spent" — so a Stop clicked mid-classifier now correctly
  kept the tree, while the only surviving record of that run denied there was
  anything in it, on a dashboard whose one remaining exit is Discard. It reads
  the presence of a spawned agent the same way teardown does, and says instead
  that the run's outcome was never classified and its directory is being kept.

  Discarding a kept directory now runs its `down` hooks first. An open session
  deliberately never reaches them in teardown, so the drop is the only chance
  its compose stack and its ports have to be released — and the manifest naming
  them leaves with the directory. It resolves which project's hook to run from
  the manifest itself, falling back to the live job only if that is missing:
  a kept-open directory is exactly the kind a job can outlive, and resolving
  its project from a job that may no longer exist would run no hook at all,
  silently, for the directories most likely to be dropped by hand.

- **A run that ends with work on no remote is reported, not filed away.**
  `wt_unsafe_to_remove` is now `wt_undelivered_work`: it asks the same question —
  are there commits or changes here that exist nowhere else? — but its answer no
  longer decides what stays on disk. It decides the run's status. Keeping the
  directory preserved the work for nobody: a resume cuts a fresh worktree from
  the base, so the folder was never handed back to anyone, and only a human
  clicking Discard ever ended it. The run now finishes `warning` with
  `UNDELIVERED: unpushed commits in api` on the card. Push is the delivery
  channel, and not pushing is a run that did not deliver.

  The check runs LAST among the classifier's rules, and appends rather than
  replaces. `UNDECLARED ENDING` and `BUDGET LIMITED` both only fire while the
  status is still `success`, so setting `warning` any earlier would have
  silently disabled both the moment this one found something — a run that
  spent its whole cap AND pushed nothing would have reported only whichever
  rule ran last, hiding the other half of the story. It also never overrides a
  run the operator stopped on purpose: a `STOPPED` record already says the run
  did not finish, and replacing it with a generic "you did not push" would be
  less information, not more. Both the ordering and the stopped-exclusion are
  guarded by a structural selftest assertion, comparing the guard's status
  list for exact equality rather than a pattern it could still match with
  `stopped` slipped back in — `run_job` cannot be exercised behaviourally here
  without mocking the agent CLI itself.

### Fixed

- **A run directory removed by hand no longer wedges its canonical checkout.**
  `git worktree remove` was only ever reached through the engine's own teardown,
  so a run dir deleted with `rm -rf` — which the dashboard invites, by listing
  each one with its size — left the registration in `.git/worktrees/`. Git went
  on believing the branch was checked out somewhere, and the canonical checkout
  could not have it back: `git checkout <branch>` failed with "already checked
  out" against a directory that no longer existed. The tick now prunes every
  canonical checkout the projects declare. The de-duplication that shipped with
  it was itself broken on this platform: it matched seen paths with a glob over
  a space-joined string, so a canonical checkout under a home directory with a
  space in it — routine on macOS — matched *inside* a longer path that started
  the same way, and was silently skipped, every tick, forever. A single
  malformed `repos` entry had the same silent-drop shape: jq exits mid-stream on
  it, and every project declared after it stopped being pruned. Both are now
  `sort -u` over whole lines, filtered by jq type, so one bad entry cannot take
  its neighbours down and a path is a path no matter what character it
  contains. Verified end to end against two real canonical checkouts shaped
  exactly like the failure case — one path a literal, space-truncated prefix
  of the other — not only against the de-duplication logic in isolation.

- **A crashed run's `down` hook knows which ports it bound.** `wt_provision`
  read `CC_PORT_BASE` from the environment, but `down` also runs from the orphan
  sweep — which fires from the tick, and a run dir is an orphan precisely because
  its slot is gone. So the one path that exists to clean up after a crash ran the
  hook with no port block at all, and a hook computing what to release with
  `cc_port` released numbers it had never bound: the compose stack from the
  crashed run stayed up, holding the ports the next run wanted. The block is now
  recorded in `.run.json` next to `fork_sha`, and the hook reads it from there.
  Teardown is reconstructible from the disk alone, which is the whole point of
  having a sweep.

- **A stop can no longer be aimed at a whole process group.** `claude-cron
  stop` reads the agent's pid from the slot's `child` file and checked only
  that it was non-empty before handing it to `kill -0` and `kill -TERM` —
  never that it was actually a pid. Both treat pid `0` as *every process in
  the caller's own group*, not as "no such process," so a `child` file that
  ever held a literal `0` would have sent a real stop signal to `claude-cron`
  itself and everything sharing its group, not to the one agent being
  stopped. A slot's own claim pid gets the same refusal, closing the same gap
  in the other place `stop` reads a pid from a file.

- **A run slot is a lease pinned to a boot, not a bare pid.** `data/locks` lives
  under `data/`, so slots survive a reboot — and the kernel reissues pids from 1
  on the way up, so a recycled pid made a dead slot answer `kill -0`. One false
  positive leaked three ways at once: the phantom counted against `max_parallel`
  and the job silently stopped running with nothing on the card saying why; the
  sweep read the orphaned worktree as claimed and never reaped it; and the port
  block it named was never handed back. Every slot now records the boot it was
  taken in — the kernel's own opaque per-boot session id, not a boot timestamp,
  because a boot timestamp moves under a slot whenever the calendar clock is
  stepped (NTP resync, wake from sleep), which would read a live run's slot as
  belonging to another boot — and a slot from an earlier boot is dead however
  healthy its pid looks. Slots written before this change carry no boot and
  still fall back to the pid, so an upgrade does not reap the runs it finds in
  flight. A pid of literal `0` gets the same refusal as an empty or
  non-numeric one: `kill -TERM 0` does not name a process, it names the
  caller's whole process group, not a value a lease can afford to pass
  through unchecked.

- **A run's transcript is no longer deleted when nothing was stored.** A
  37-minute, $7.27 reviewer run had no timeline, no answer and no terminal, and
  was filed as success. Two defects combined: the artifact reader wrapped four
  reads in one `try/except` with a bare `pass`, so a single undecodable byte
  anywhere in a multi-megabyte stream returned four empty strings silently; and
  the pruner then deleted the files unconditionally, treating an empty row as
  proof there had been nothing to keep. Artifacts are now read per file, as bytes
  decoded with `errors="replace"` — a mangled character costs a character, not a
  run — and pruning checks what actually landed in the database first, keeping
  the files and saying so on stderr when the answer is nothing.

- **A tick that found the job busy no longer reads as a configuration ceiling.**
  The loop band labelled it "at its parallel limit", which with `max_parallel: 1`
  — the common case — sounds like a limit worth raising, when all it means is
  that the previous run had not finished. It now says "already running", which is
  true at every limit.

- **A run you stop is `stopped`, and it is never lost.** Two separate faults, one
  cause — the engine had no way to say "the operator decided this".

  A TERM'd agent exits non-zero, so a deliberate stop was classified `error`:
  counted in the error tile, and feeding the failure backoff, which slowed the
  job down as punishment for a decision its owner made on purpose. `stopped` is
  now its own status, set from a marker the stop leaves behind, and it overrides
  the exit code precisely because a kill guarantees that code. The work is
  untouched — the stream, the log and the turns already written stay where they
  are; only the verdict changes, and the record carries a line saying it was
  interrupted rather than failed.

  Stopping in the seconds between claiming a slot and spawning the agent used to
  delete the slot and write nothing at all: the row vanished from the table with
  no run, no log and no record it had ever been asked for, which reads as the
  dashboard losing work rather than as a stop being obeyed. The stop now signals
  the run wrapper, whose exit path files a `stopped` record with a log body
  explaining itself. A `journaled` breadcrumb keeps a run that reached its own
  ending from being recorded twice.

- **Every ending reads the same way: a badge, then the sentence.** `end_turn` is
  a protocol word, not an answer — the most common way a headless run ends, and
  printed raw it told the operator nothing and looked like a fault. The badge
  carries the plain-English label ("Normal end") and the protocol token moves to
  its tooltip, for whoever is matching this against a log. The scheduler's own
  reasons take the same shape: their shouted prefix becomes the badge
  (`STOPPED:` → "Stopped by you") and the rest becomes the sentence, so a stop
  and a normal ending are not two different layouts to read.

- **The run modal was throwing away the reason it had.** `/api/log` did not carry
  the record's note, so when the agent log held no stop reason of its own the
  modal showed a dash — for a run whose journal entry said, in words, exactly why
  it ended. For anything the scheduler decided (stopped by the operator,
  budget-limited, nothing to do) the note IS the reason.

- **The model is named once.** `claude-sonnet-5 → claude-sonnet-5` drew a
  resolution step for a job that never took one: the arrow belongs to a job
  pinned to an ALIAS, and now only appears when the two sides actually differ. A
  job pinned to a concrete id no longer gets "(resolved id not recorded)" either
  — it ran that model by definition.

- **The model picker groups by family and generation.** A flat list of a dozen
  near-identical strings put the one distinction that matters — which generation
  of which family — in the middle of each id, to be read out character by
  character. Newest generation first, and a pinned snapshot sits under the alias
  it pins: `claude-opus-4-20250514` used to sort above every current model in its
  group, because the date after the family was being read as a version number
  twenty million high.

- **A run stopped before its agent started records its model and its reason.**
  The record carried neither, so the run modal showed `—` twice — which reads as
  missing data rather than as a run that never got far enough to have any. It now
  names the model it would have run, and writes its log body even when the stop
  landed before the slot had a logfile breadcrumb to write to.

- **One run, one row — and one number.** The runs table draws from two sources:
  the journal, and rows synthesized from the lock slots of runs in flight. They
  overlap. A run writes its record and only THEN releases its slot, so for those
  seconds it is in both — which is how stopping a run put it on screen twice,
  `stopping…` sitting above `stopped`, and why the Runs counter briefly read one
  too many. The journal is the record: a live slot for a run already in it is the
  same run, already over, and the slot is merely the last thing to be cleared.
  Everything that lists or counts runs now de-duplicates on that.

- **Stop stays stopped.** A kill is not instant — the wrapper has to wind down —
  and for those seconds the row repainted every 5s with a live stop button, so a
  second click sent a second kill at a pid that was already dying. The run is now
  marked stopping the moment the request succeeds: the button stays down, the
  status says `stopping…` rather than continuing to claim it is running, and the
  mark is dropped as soon as that pid stops being live so a reused slot is not
  born disabled.

- **Kept worktrees are a tab, not a banner that comes and goes.** A directory
  holding the only copy of some work is not a notification — it is something you
  have to deal with, and it has to still be there when you come back to deal with
  it. It sits beside Jobs and Runs with the same table furniture, the count on
  the tab in the warning colour, and Discard on every row. Previously it appeared
  above the dashboard and vanished again the moment the sweep reached the
  directory, which read as a glitch.

  The copy no longer overstates what the server knows. It lists every run
  directory no live run has claimed — not the ones git says hold unpushed work —
  so a run cancelled before its agent started leaves an empty directory that
  lands there too. That row now reads `0 B · nothing in it` instead of being
  described as commits that exist nowhere else.

- **The row separator runs all the way across.** `.rowacts` set `display:flex` on
  a `<td>`, which takes the cell out of the table's row box: it then sizes to its
  own content, and its border-bottom landed 36px above every other cell's. Both
  tables had carried this from the start and it never showed, because every cell
  in them was one line tall — the jobs table, whose first cell has a description
  under the name, is where the step appeared. The cell is a cell again; the
  buttons space themselves.

- **The jobs table aligns, and no column swallows the slack.** `table-layout` was
  `auto`, so the content set the minimum widths: the cap on the description
  column was only a hint, the seven other columns added their own on top, and the
  table came out 1106px inside a 983px box — scrolling sideways, with the actions
  past the right edge and the header ending somewhere the rows did not. Declaring
  only the narrow columns then left Job as the single elastic one, so it took
  everything going: 64px in a narrow window, 730px in a wide one, where one job's
  description ran on for half the table while six columns stayed cramped. Every
  column is a percentage now and they hold their proportions at any width.

- **The favourite star is filled, not outlined.** The icon set draws with
  `stroke:currentColor` and the rule beside it paints the row's icons accent, so
  an amber fill came out under a 2px indigo outline — which at 11px is neither
  amber nor indigo but a muddy pink.

- **A disabled row no longer washes out the things that carry meaning by their
  colour.** `opacity` on the whole cell dimmed everything inside it, so the
  status pill and the favourite star came out pale pink and pale amber — next to
  the same pill and the same star on the dashboard, that read as two different
  colours for one thing. The prose is muted; the pill and the star are not.

- **The warnings and errors counters wrap as a pair.** "3 warnings, 0 errors" is
  one fact about the week, and a narrow panel used to strand one of them a line
  above the other.

- **The job card's edge is a border rather than a strip laid over one.** The
  state bar was absolutely positioned on top of the 1px border inside a 13px
  radius, so at both left corners its square end and the border's curve did not
  meet and the edge came out visibly broken. It is now `border-left`, which
  cannot disagree with the border it is part of. The card border also carries the
  accent: a board of grey rectangles reads as chrome rather than as the thing you
  came to look at.

- **The server restarts itself when its own file changes.** `dashboard.html` is
  re-read per request but the Python is not, so a `git pull` left a new page
  talking to old code — and the two then disagree about what the API offers. It
  cost a real debugging round: the profile screen appeared immediately, posted an
  op the running server had never heard of, and came back `bad id`. Every request
  now compares the file on disk against what the process loaded and steps aside
  for launchd, which brings it straight back on the new code.

  **Every request, not one route.** The check first hung off `/api/data`, and
  putting that route behind the session gate broke it within the hour: a
  signed-out page polls nothing, so a stale server could never learn it was
  stale — and the deadlock was total, because the version it was stuck on had no
  `/api/login` to sign in with. Staleness is a property of the process.

  Only when launchd is holding *this* pid. Matching the agent's label alone was
  not enough: a server started by hand on a machine that also has the agent
  installed saw the label, believed it was supervised, and would have exited for
  good with nothing to bring it back.

- **An element with its own `display` is not hidden by the `hidden` attribute.**
  The author rule wins over the browser's, so the first-run screen stayed up
  after creating the profile — the profile existed, the screen asking for it did
  not go away, and the dashboard was unreachable. The codebase had been carrying
  this fix one selector at a time (`.view[hidden]`, `.menu-pop[hidden]`,
  `#bulk-all[hidden]`), which is why both new Clear-filters buttons shipped
  visible with nothing to clear. It is now written for the button classes rather
  than per id.

- **The profile is editable.** Clicking your name, email or picture at the foot
  of the sidebar opens a modal for all four: name, email, password and photo.
  Sign out lives inside that same block and keeps its own click, so it does not
  open the editor on the way out.

  The photo is stored inline in the operator row as a `data:` URI rather than as
  a file, so there is nothing to serve, nothing to name and nothing left behind
  when it is replaced — which only stays reasonable while it is small. The page
  centre-crops to a square, scales to 256&nbsp;px and re-encodes as JPEG before
  uploading; a 1 MB photo lands as about 3 KB. The server enforces its own
  ceiling and accepts only inline raster images, SVG included in what it turns
  away: it is an image an `<img>` will render and a document that can carry a
  `<script>`, and this column is handed back to the page.

  Changing the password asks for the current one. The session is not enough on
  its own — it may be an unattended tab — and there is no reset to fall back on.
  Name, email and photo save without it; the three password boxes left empty
  mean "keep the one I have". And `avatar` is tri-state on the wire (absent,
  empty, or a URI) so that fixing a typo in a name cannot silently delete a
  photo the form never touched.

- **The dashboard no longer flashes past the login screen.** The sign-in and
  first-run cards are raised by `applyGates()`, which cannot run until
  `/api/session` answers — so every refresh of the login page painted the shell
  first and swapped it a round-trip later. It looked exactly like what it was: a
  curtain arriving after the room was already on show.

  The server knows which of the three states applies while it is still writing
  the response, so it now says so in a class on `<html>`, and CSS holds the shell
  back and puts the right card up before a line of script has run. `applyGates()`
  drops the class once it has the real answer. Nothing about what is *protected*
  changed — the gate was never the overlay, it is the server refusing every
  endpoint behind it — but a dashboard that strobes past on the way to a login
  box invites exactly the wrong conclusion about that.

- **The brand mark is the claude-cron robot.** It replaces the white line-art
  robot in the three places that carry the mark: the top of the sidebar, the
  sign-in card and the first-run profile card. The indigo tile behind it is
  gone — that square existed to make white line art legible, and the logo brings
  its own colour and silhouette.

  Defined once as an SVG `<symbol>` and referenced where it is needed: its
  gradients carry ids, so inlining the artwork three times would put three
  `id="cc-g1"` into one document. It also moved from JavaScript into the markup,
  so the mark is painted with the first frame instead of after the script runs.
  The favicon is deliberately untouched.

  The sign-in and first-run cards carry the full lockup — robot, wordmark and
  tagline — since they have the width for it. The sidebar header carries a
  compact one with no tagline, sized to the 172px the burger leaves it, and
  falls back to the robot alone once collapsed: the rail is 48px wide and
  nothing else fits. Both are in the markup at once and swapped by CSS, and the
  `<h1>` stays in the document, hidden from view rather than removed, so the page
  keeps a heading now that its words are artwork.

  Each `<use>` carries the artwork's `viewBox`: without it the outer `<svg>` has
  no intrinsic ratio, `height:auto` falls back to the 150px CSS default for a
  replaced element, and the lockup floats in 80px of dead space above the
  heading. The menu wordmark also draws with `currentColor` instead of the
  near-black it shipped with, which would have been black on `#151a23` in the
  dark theme.

- **A single-repo project stops describing itself twice.** To pin its base branch
  a project had to declare a `repos[]` row — and that row's other two fields were
  a copy of what it had already said: the name is `basename .cwd`, the path IS
  `.cwd`. Only the base carried information, so the form asked for the path a
  second time to accept one new value.

  That was not merely untidy. The engine picks the repo the agent starts in by
  matching a row's path against `.cwd` as a literal string, and aborts the run
  when none matches — so the duplicated path was the exact place a trailing slash
  or a case difference (`/G/` and `/g/` are one directory on APFS) could kill
  every run of a project, reported only in the tick log.

  Projects now take a `base` of their own, used for the row the engine
  synthesises when no `repos[]` is declared. Step 1 asks for it beside the
  working directory; step 2 states that the project works in one repository and
  offers *Several repositories…* for when a ticket really does span more, seeding
  the first row from the cwd so the list starts valid rather than empty. Going
  back carries the base with it. A declared row still wins over the project's
  base, so nothing about an existing multi-repo project changes.

  Projects saved the old way open in the new form with their base already in it
  and no row to see — the row is shed on the next save. One that says anything
  `.cwd` does not (a second repo, a custom worktree name, a path that is not the
  cwd) keeps the list open, including a path differing only by a trailing slash:
  that project is already broken, and silently rewriting it would hide the break
  rather than show it. Saving a multi-repo project now also refuses a list where
  no row matches the cwd, which is the run-time abort moved to where both paths
  are on screen.

- **Settings is hidden from the sidebar** until the page behind it exists. The
  markup and the view stay put, and `VIEWS` drops the entry so anyone whose last
  view was Settings is restored to the overview rather than to a blank pane with
  no nav item to leave by.

- **The repos hint contradicted itself.** It opened with "leave it empty for a
  single-repo project" and closed with "Base is declared here, not read from the
  checkout" — both true, but never at once: leave the list empty and the base
  *is* read from the checkout, whatever branch it happens to be on. On a project
  pinned to `release/*` that is the difference between cutting from the current
  release train and cutting from `develop`, which is the one thing its agents are
  told never to do. The hint now says which of the two you are choosing, and
  documents the `*` suffix it never mentioned.

- **Opening a project no longer claims unsaved changes it does not have — and
  saving one no longer deletes its provisioning.** The up/down hooks are files
  on disk rather than fields of the project, so the editor fetches them after
  the modal is already up. The baseline for "what changed?" was taken before
  they arrived, so every project opened already flagged as edited, with the dot
  on Provisioning: the scripts landing in their textareas looked exactly like
  typing.

  The same gap was quietly dangerous. `provision_set` with an empty script
  deletes the hook file, and the save sent whatever the textarea held — which,
  in the window before the fetch resolved, was nothing. Opening a project and
  hitting Save straight away erased both scripts. Now a hook that has not
  loaded is held as `null`, distinct from a hook the operator genuinely
  emptied, and a save skips it rather than writing over it; the textareas say
  `loading…` and stay disabled until the real content is there.

  A third bug in the same three lines: nothing tied a response to the project
  that asked for it, so opening A and then B could drop A's script into B's
  form and save it there. The response now checks it is still wanted.

- **Every isolated run gets a block of ports nobody else holds.** Worktree
  isolation settles the filesystem and says nothing about ports, which is half
  the problem: two runs of one repo each bring up the same stack, both publish
  5432, and the second dies on "address already in use" — a failure that reads
  as a broken test suite and is nothing of the kind. The worktree name makes a
  compose PROJECT unique; the published ports stay whatever the config says.

  So the scheduler hands each run `CC_PORT_BASE` (a 100-port block by default),
  allocated under a mutex against the blocks live runs hold, recorded in the
  slot so it is released exactly when the slot is. A dead slot's block goes
  straight back into the pool — otherwise the pool shrinks by one for every run
  that ever ended.

  `bin/provision-lib.sh` turns that into numbers: `cc_port NAME` for one port,
  `cc_env_ports .env` to move every `*_PORT` a dotenv already declares into the
  run's block, and `cc_copy_ignored` for the files a fresh worktree cannot have
  because they are gitignored. None of it is Docker-specific — this is the
  general shape of "two copies of one stack at once", which every project that
  isolates eventually meets. `CLAUDE_CRON_PORT_RANGE_START`, `_SPAN` and
  `_BLOCKS` move the range if 21000 is taken.

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

- **The reload signal tracks the code, not the clock.** An open dashboard already
  reloads itself when the server has moved on, but the id it compared was the
  server's *start time* — which answers the wrong question twice. Restarting
  without changing anything forced every open tab to reload; and, less visibly, it
  tied a real code change to whether a restart happened to follow it. It is now a
  hash of the served page and the server itself: identical across a restart with
  no changes, different the moment either file changes.


- **The action column no longer collapses onto the Session column.**
  `td.rowacts{width:1%}` sized a `display:flex` cell below its own content, so the
  icons overflowed to the left and landed on top of the session id — showing as
  `e6 [eye] 55`, the text passing under the buttons, with the row's horizontal
  rule stopping short for the same reason. The original had no such rule: the
  table sizes that column from its content. Removed, along with the leftover
  `.jobcell` CSS from the version that put the session inside the Job cell.
- **The changelog check no longer fires on merge commits.** A merge touches
  `bin/` by definition and is always newer than the entry that arrived with the
  branch it merges, so the check failed after every merge with the entry
  correctly in place — and a check that cries wolf on a healthy repository is one
  people learn to ignore.


- **The runs table is back to the shape it had before the rewrite** — `When ·
  Job · Project · Status · Duration · Cost · Session · actions`, eight columns,
  at its previous density. The rewrite had folded Duration and Cost into one
  column and moved Session inside the Job cell; merging the two silently dropped
  the cost sort (the comparator survived, but no header could reach it, so the
  most expensive run of a day was unfindable in a 25-row page), and the row grew
  tall enough to cost about four rows of a screenful.

  The four action icons are rendered on **every** row again, greyed where they do
  not apply, rather than collapsing to empty slots. A toolbar whose icons move
  between rows is one you have to re-read each time — the eye sits in a different
  place on a finished run than on a live one — and a greyed button still teaches
  that the action exists, which an empty slot does not. The reason each one is
  unavailable stays on its tooltip.

  The one thing deliberately NOT reverted is **When**, which keeps the relative
  form (`1h ago`) rather than the full timestamp: what you read that column for
  is recency, and the stamp to the second is one hover away.
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
