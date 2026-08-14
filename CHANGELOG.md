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

### Changed

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
