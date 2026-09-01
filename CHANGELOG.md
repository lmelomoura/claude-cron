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

- **A security finding now carries a CWE and an OWASP class, and its SAST
  rule name comes from a closed vocabulary of 21.** The rule name is part
  of a finding's fingerprint, so free text meant one hole could arrive
  under two identities: an agent that wrote `sql-injection` on one run and
  `sqli` on the next produced a report showing the same vulnerability as
  both `fixed` and `new`, and an *Accept risk* decision recorded against
  the first never matched the second again. `report-finding` and
  `fingerprint` now refuse anything outside the vocabulary — both doors,
  so the agent learns before it builds a payload rather than after — and
  name the alternatives in the refusal. The classification is derived from
  the rule and ignored if sent, because a CWE that disagrees with the rule
  beside it is worse than none. `other` exists for a real finding that
  fits nothing else: an agent forced to pick the nearest wrong name
  mislabels everything downstream of it. Markdown and HTML reports show
  the class when there is one and stay silent when there is not; JSON
  always carries the keys.

- **`claude-cron security migrate-rules` renames a rule without losing its
  history.** A rule's name feeds the fingerprint, so renaming one used to
  mean every finding under it changed identity — reported as `fixed` and
  `new` at once, with every human `accepted` / `false_positive` decision
  left pointing at an identity no analysis will produce again. The verb
  recomputes each fingerprint the way the module that produces it does,
  moves the decisions — and the `decision_made` events that record a human
  took them, whose Activity link would otherwise resolve to nothing —
  across in the same transaction, and is safe to run twice. It refuses
  `sast` and `dependency` rather than guessing: their identity depends on
  the code snippet and on the package version, which the ledger does not
  store, so a rename there would mint an identity nothing can match and
  say nothing about it. It also refuses a finding whose occurrence carries
  no path, for the same reason, and refuses to run at all while any
  analysis is still going: rewriting identities under a live agent makes
  its next re-report file a second row for a hole it already reported.

### Fixed

- **The running badge sits beside Runs, not Jobs.** It counts runs in
  flight, and the Runs counter already includes them — beside the job
  count it read as "1 of these 8 jobs is running", which is not what it
  measures. One job can have several runs in flight, and a run in flight
  may belong to no job at all: a security analysis runs on a derived job
  the Jobs area deliberately never lists.

- **Three doors into the security ledger stopped being one character
  wide.** `report-finding` never validated `category`, so `Sast` with a
  capital skipped the rule check entirely and landed a free-text rule with
  no classification. `fingerprint --category` had the same hole, and worse:
  `Secret` fell through to the branch that hashes the snippet, which for a
  secret finding means hashing the credential's value — the thing
  `secret_fingerprint` exists to avoid. Both now validate against one
  shared set. Both verbs also scan the `rule` and `category` they quote
  back before quoting them: a refusal is written to stderr and stderr
  reaches the run log, so echoing a credential pasted into either field
  would have defeated the refusal that was rejecting it.

- **Full-system review pass: one wording for the fell-back branch, and
  orphaned CSS pruned.** The index's fleet table said "the default branch
  was never analysed" while the project header said "the declared base
  was never analysed" for the identical fact — the index now uses the
  header's sentence. The findings pane's dead header-title CSS (the
  heading moved into the page title row) is gone. The review walked every
  screen live at 1550px and 1100px in both themes — the four app pages,
  the Security index, all five project tabs, the Activity screen, the
  launch/editor/log dialogs, history navigation, filters, sorts,
  downloads and every View-all door — with a geometry probe on each
  (nothing outside its card, no body scroll) and a clean console
  throughout; these two were the only defects found.

- **Every donut's 12-o'clock seam is clean.** Each segment used to be a
  full circle wearing stroke-dasharray/-dashoffset, and a dash pattern
  repeats: with the dash+gap sum landing a floating-point hair under the
  circumference, each segment painted a sliver of its next repetition
  back at the seam, on top of its neighbours — the mangled red/grey
  knuckle visible at the top of every donut. Segments are real arc paths
  now (one shared secDonutArc, used by the severity donut everywhere and
  the Overview's category donut alike; a 100% segment becomes two
  half-circle arcs, since a full-circle arc degenerates to nothing).
  Verified by rasterising the arcs and sampling the whole ring: five
  contiguous colour blocks in severity order, nothing out of place.

### Changed

- **The Reports table drops its Actions column.** The four FORMAT chips
  already ARE the downloads, so the quick-download icon and the kebab
  beside them were the same four files behind a second door — a
  redundancy the mockup drew and the user called out. Five columns now;
  the table fits a 1550px window with no inner scroll, and the format
  chips sit on one line.

- **The Reports tab meets ProjectReports.png.** The plain five-column
  table became the mockup's card: the run chip opens the analysis on the
  Runs tab, the Profile cell folds the state in ("Deep (Capped)",
  "Standard (Failed)") with the run number beneath, Generated-at sorts
  and carries the on-demand explanation in its tooltip, and the four
  FORMAT chips are the downloads themselves — with the quick-Markdown +
  kebab actions the selected run's header already wears, and a numbered
  footer. Downloads now appear only on a FINISHED analysis: a failed row
  says "No report generated" and a running one "Not finished yet"
  (the mockup's rule, and the better one — a report generated over a
  half-run reads as a complete document; the Runs tab's own
  single-analysis downloads still cover any state). The SBOM caveat (the
  branch's CURRENT document, not a snapshot) rides every SBOM control's
  tooltip instead of a paragraph above the table. The rail becomes the
  tab's own three cards — the all-branch donut and Top-issue-categories
  shared with the Branches rail (extracted, one copy) plus a Reports
  summary. Deliberately not drawn from the mockup, because reports are
  generated on demand from the ledger: a SIZE column and Total-size line
  (no file exists to weigh until the click), Export all (no aggregate
  artifact exists), and "kept for 90 days" (nothing is stored or
  expires — the summary card says the true version). `tabs.reports` rows
  now carry the analysis's profile.

- **The Findings tab meets ProjectFindings.png.** The one-container stat
  strip became seven house KPI cards — Total findings, the five severities
  (each with its share of the total, wearing the same severity icon/tone
  maps the Overview's cards read, now exported from one place so the two
  rows cannot drift), and Unique issues — with every count's
  what-it-counts tooltip intact (rows vs distinct fingerprints). "+ Save
  filter" is its own button now beside Export (it opens the Saved-filters
  popover, where the name-and-save flow already lived), the title row
  wears the area's shield, the page size defaults to the mockup's 25, the
  table's title cells clamp at two lines with the full sentence one hover
  away (real titles are whole sentences where the sample says "SQL
  Injection"), and the severity pills wear Title Case. The filter bar,
  table columns and footer already matched — they were built to the same
  drawing's earlier crop.

### Fixed

- **The project screen's two internal splits now stack by CONTAINER
  queries, not viewport breakpoints.** The Runs list/detail pair and the
  Overview main/side grid measure the main column's own width
  (`container-type:inline-size` on it): how much room they really have
  depends on the collapsible app sidebar and on whether the 330px rail
  sits beside or below, which no viewport number can know — the freshly
  chosen 1280px breakpoint still left a band (~1281–1330px windows,
  sidebar open) where the run card overflowed and the rail painted over
  it. The Runs pair stacks below 830px of column (its columns' real
  minima), the Overview grid below 1160px.

- **Two more mid-width breakages on the project screen.** The Runs tab's
  two-column split stacked only below a 900px window while its list column
  is deliberately unshrinkable (450px) — between ~900 and ~1250px the
  selected-run card overflowed the main column and the rail painted OVER
  it; the stack point is now 1280px, matched to what the columns actually
  need beside the rail. And the stacked Overview's cards rendered as
  ~430px slivers with the rest of the window empty: the grid keeps the row
  layout's `align-items:flex-start`, which in a column direction makes a
  child hug its content width — both stacked children are now told
  `width:100%` outright.

- **Six project-screen defects called out from a narrow-window review,
  closed together.** The Branches and Top-findings tables now carry the
  min-width every other wide table already had, so below it the wrapper
  scrolls sideways instead of crushing eight columns into unlabelled
  slivers. Every tab wears its OWN title and subtitle (SEC_TAB_TITLES now
  covers all five, pinned by a no-two-tabs-alike test): Overview keeps the
  project's identity with the mockup's own sentence, Runs/Findings/Reports
  join Branches with their tab's name and sentence — and the findings
  pane's internal "All findings" heading, which would have said the same
  thing twice, became a plain actions row. The tab strip moved out of the
  left column to span the screen ABOVE the two-column body, so the rail's
  first card sits level with the pane's cards instead of floating beside
  the tabs. The rail's visible "Posture and categories below span…"
  caption is gone everywhere — on the Runs tab it was flatly wrong,
  describing the all-branch scope over cards that are the selected run's
  own — replaced by scope tooltips on the cards that carry the numbers
  (the Runs donut says "the selected run's own", Branches says "(all
  branches)", the remaining tabs' donut block carries the branch-count
  sentence), with the severity-floor note riding each one. And the
  Overview's two-column grid stacks at 1440px instead of 1280px, with the
  rail column allowed to shrink and card heads allowed to wrap, so a
  ~1300px window no longer renders the trend card's title as a five-line
  sliver beside its severity control.

### Changed

- **The Branches tab is rebuilt to ProjectBranches.png.** What used to be a
  six-column table under a paragraph of caption prose is now the mockup's
  screen: five KPI cards (branches analyzed in 30 days; active branches by
  one written rule — latest finished analysis at most 7 days old, the same
  rule the Status column and filter read, pinned by its own boundary test;
  the declared base's critical count; total findings across all branches as
  distinct fingerprints, agreeing with the rail donut beside it; and
  default-branch coverage read honestly off the analysis state — 100% for a
  clean finish, Partial for a capped one, a dash for none), a filter bar
  (search, Status and Last-analysis pickers on the house details-popover
  widget, Refresh), and an eight-column table: Branch with the Default badge
  on the DECLARED base only (never a fallen-back one), Status dots, Last
  analysis, Total findings, the five-chip severity breakdown, a 30-day bar
  sparkline whose cell title is still secBranchTrendText's whole honest
  sentence (hollow bars for capped reads), Last commit (the sha the newest
  analysis recorded — the header's title says it is not read from git now),
  and View + kebab (open the branch's latest analysis; findings browser
  deep-linked to the branch; report download). `queries.branch_rows` now
  includes branches whose every attempt failed — a dash and "Analysis
  failed" instead of the absence that hid exactly the branches most worth a
  look — carrying two timestamps (newest attempt vs newest finished) so
  recency rules cannot count a branch as fresher the more it fails. The
  tab's rail is its own three cards (all-branch severity donut with the
  scope in its title, top categories with the View-all-findings door, and
  Branch coverage against the repository's real branch list, reusing the
  launcher's own fetch), and the page title row now follows the tab
  (gitbranch icon, "Branches", the mockup's own sentence) with the project's
  name one crumb up.

### Fixed

- **The Findings-trend chart no longer scales its type up with the card.**
  The chart was a fixed 720-unit viewBox stretched to the card's width like
  an image, so on a wide screen its 11px axis labels rendered at 26px and
  the dots grew to match. It is now drawn AT the mount's measured width —
  one SVG unit per CSS pixel, measured after the pane is attached — with a
  redraw on window resize and on re-entering the Overview tab (a render
  that happened while the pane was hidden measures 0 and falls back to a
  guessed width until then). A mount too narrow to seat eight day labels
  drops to every other one instead of letting them collide.

### Changed

- **The project Overview tab is rebuilt to ProjectOverview.png.** What used
  to be a caption, five posture pills and a row of checklist chips is now
  the mockup's own screen: six KPI cards (total + the five severities, each
  icon-tinted from the severity tokens, the total carrying a real
  green/red delta against the previous finished analysis and each severity
  its share of the total — the sample's "vs. previous analysis" sublabel
  under numbers that were plainly shares is rendered honestly instead), a
  "Findings trend" line chart of the last 7 days with a
  Total/Critical/…/Info segmented control (per-severity series served by
  `queries.trend`'s new `by_severity` per point; a capped analysis draws a
  hollow dot saying "(incomplete)"), a "Findings by category" donut over
  rule buckets with a counted, percented legend and an honest grey Other
  remainder (categorical palette tokens `--cat-1…5`/`--cat-other`, sampled
  from the mockup's own legend dots — deliberately not the severity scale),
  a "Top findings" table (severity pill / title / location / "#N (Profile)"
  / first seen, the same cells and the same shared `first_seen_map` the
  findings browser reads, so the two screens can never date a finding
  differently), and the restyled "Recent activity" card (tinted icon box,
  kind badge on a house pill tone via the new `SEC_EVENT_META`, absolute
  dates) that the other tabs' rail now mounts too. Every number on the pane
  reads ONE scope — the latest finished analysis of the branch the header
  names — computed server-side in `cmd_project_data` (`trend`, `previous`,
  `categories`, `top_findings` ride the same payload), so the KPI total,
  the donut centre and the Top findings rows cannot disagree. The
  all-branch rail hides on this tab (its donut answers a different
  question, and two donuts with two different, equally true totals an inch
  apart is exactly the scope confusion this area keeps stamping out); the
  shared header follows the same mockup (breadcrumb gains the active-tab
  segment, the title icon is the area's shield in a tinted box, the green
  always-true "Security enabled" pill gives way to the profile badge, and
  the meta strip's bits wear their icons).

- **Runs tab parity pass 2: the four remaining gaps between the Runs tab and
  ProjectRuns.png, closed.** The repo/branch/profile/Analyse strip that used
  to sit open above the two columns — never pictured in the mockup — is now
  a dialog (`seclaunch`, filed in the render-contract's own `FORM_DIALOGS`
  list) opened by a compact "Analyse" button in the "Analysis runs" card's
  own title row; same combos, same ids, same `secAnalyse` op and its pinned
  `test_an_analysis_is_only_ever_started_through_its_own_op`, closing itself
  on a successful launch and staying open on a refusal, the same convention
  `#projmodal`'s own Save button already follows. The selected run's own
  card no longer draws an empty rounded box above "Run #N" — `#sec-status`'s
  "nothing to show yet" placeholder rendered regardless of content, the same
  `[hidden]`-vs-author-`display` trap `.secfield`/`.secdl`/`.warnline` were
  already told to respect, `.secstat` was not — or the Jobs-board's own
  accent border (missing the `.secpj-plaincard` reset its two sibling cards
  already carry); its spend now lives in the meta grid as a sixth, labelled
  "Cost" cell instead of dangling, unlabelled, under the Profile pill. The
  runs list's own table no longer forces a horizontal scrollbar at every
  viewport width: its card asked for 380px while the table demanded a
  420px floor, a permanent overflow regardless of window size — the card is
  now a non-shrinking 450px (so the selected run's own flexible card can
  no longer squeeze it back down under pressure), and the table's own floor
  is a measured 400px, its "Findings recorded" header now free to wrap
  rather than clip and reopen the same gap from the other side.

- **The project screen's shared header and its Runs tab now match the
  approved mockup: a breadcrumb, a name/badge/description row, and three
  columns instead of one long list over a single detail pane.** The old
  `#sec-title`/`#sec-back` pairing is now a "Security › Minerva" breadcrumb
  (scoped to this screen, not the app's own shared `<header class="topbar">`
  — the identical boundary findings-screen.js's own breadcrumb already drew
  for itself); the project's icon, name, "Security enabled" badge and
  description now paint instantly from the client's own project list,
  before the project-data fetch that used to be the only source for any of
  it even starts. The Runs tab is now "Analysis runs" (state chips, a
  four-column table — Run/Status/Findings recorded/Date, sortable, with a
  per-row severity breakdown reading e.g. "64C 4H 3M 0L" and an accent
  highlight on whichever run is on screen) beside the selected run's own
  card (a meta grid, the incomplete/coverage/live-run notices unchanged,
  a "Findings recorded" strip, and a search/category/state-Filters bar over
  its finding cards, one click's own decision flow unchanged underneath).
  The right rail becomes run-scoped while this tab is open — "Findings by
  severity" and "Top issue categories" now read the SELECTED run's own
  checklist instead of the project's cross-branch rollup, two separate
  cards reusing the index screen's own donut/legend/categories builders
  (newly exported, and the legend gained an opt-in `showZero` reading for
  a severity currently at none) — and fall back to the original project-
  wide donut on every other tab, unchanged. One new field,
  `findings_by_severity` (`queries.finding_severity_by_analysis`, one more
  grouped query alongside the existing per-analysis COUNT(*)), is what
  makes the per-row severity breakdown possible without a query per row;
  everything else in this screen was already in hand client-side. The old
  four-button download row is still in the DOM (every pinned id and call
  the download tests hold it to is untouched) but hidden behind the run
  head's own download icon and kebab, which call the identical
  `secDownloadReport`.

- **A `git pull` under a running server now serves fresh assets on the very
  next reload — no restart required.** The build id stamped into every
  asset's `?v=` (and reported to an already-open tab's own 5-second poll)
  used to be computed once, at process start, into a module-level `BUILD` --
  so pulling new UI code into a live install left every later page load
  stamping `?v=` with the OLD id. Browsers then kept serving the stale
  cached bundle against markup that had just changed underneath it: dead
  listeners, broken layout, fixable only by finding and restarting the
  process by hand. `current_build_id()` replaces that fixed value with a
  cache that is cheap to check (a stat() of the same tracked set the id
  always hashed, on every request) and only pays for a real re-hash when
  that stat says something actually moved -- an unpulled, unedited install
  still hashes its assets exactly once, no matter how many pages or polls it
  serves.

- **The browser's own Back and Forward buttons now stay inside the app.**
  Nothing before this wrote to `history` at all — every sidebar view and
  every screen inside the Security area (the fleet index, a project's own
  tabs, the cross-project Activity feed) repainted in place, so the mouse's
  Back button had nothing of this app's to undo and left the tab on the very
  first press, from anywhere. Every navigation that replaces the main
  surface now pushes one `history` entry with just enough state to repaint
  from — `{view}` for the sidebar, `{view:"security", sec:{screen, project,
  tab}}` for Security's own place inside itself — and a `popstate` restores
  it back through the exact same navigation paths a click already uses,
  never double-fetching and never pushing the entry it is itself restoring
  (that second part matters: a restore that pushed would turn every Back
  press into a one-press-deep loop that never reaches the page a reader is
  trying to leave to). Dialogs — the job editor, the log viewer, confirm,
  the reason prompt — deliberately do not participate: Escape and Cancel
  already close them, and a history entry per open/close would outlive a
  two-second look at one. See bin/dashboard.html's own router comment,
  beside `setView`, for the full contract.

- **The Activity screen's control row speaks the house vocabulary now, and
  a findings table column stopped repeating its own neighbour.** Its
  7/30/90-day and All-time chips were the last `.secchip` row of its kind on
  a filter bar — replaced with the exact `<details>/<summary>/.menu-pop`
  period picker ("Last 30 days ⌄") the Security index's own Findings-overview
  card already draws, both now reading `ACT_PERIODS`'s one four-bucket
  vocabulary. The PROJECT field was this area's last free-text filter input
  — replaced with a `makePicker()` picker ("Project: All ⌄") matching the
  index's own Status/Profile/Branch pickers, listing real project names with
  their event counts for the period rather than asking a reader to already
  know one to type. Reused rather than re-typed: `secFindTriggerLabel`/
  `secFindPositionPop` (findings-screen.js) are now exported and shared by
  this new period picker, which is also why it resyncs `pop.hidden` from the
  `<details>`'s own `open` state on every toggle instead of copying
  `secFindingsPeriodPicker`'s older pattern — THAT widget's card is torn
  down and rebuilt whole every 5-second poll tick, which papers over a
  `closeMenus()` race (a stray click outside hides the popover without
  resetting `open`); the Activity screen never polls while it is open, so a
  stray click there would have left the picker silently un-openable for
  good, the exact race the findings browser's own Saved-filters popover hit
  first. Refresh now right-aligns behind a `.spacer`, the same as every
  other filter bar in the app — it used to just be the last item in a row
  that wrapped unevenly once the period chips changed shape.

  The two sidebar cards (Activity summary, Most active projects) painted
  with a purple outline no other card in the product wears: both borrowed
  the bare `.card` class for its padding/radius/shadow and got that class's
  own accent-tinted border and 3px left rail — a Jobs-board "the thing you
  act on" cue — for free. `.secact-sidecard` (ui/css/pages.css) resets just
  the two border declarations back to the plain `--line` every other card
  in Security already uses. TIME stopped printing a raw locale string
  ("8/27/2026, 7:23:23 AM") and now reads the same two-line pattern this
  area's siblings do: long-form relative on top, the exact moment beneath.

  Separately: the findings table's own CATEGORY column rendered
  `secRuleMeta`'s per-RULE label ("Private keys committed"), duplicating
  TITLE one column to its left — a finding's own title already says that.
  `secCategoryMeta` (ui/security/vocabulary.js) is the coarser, category-
  level reading of the same vocabulary the mockup actually draws there
  ("Secrets", "Dependency", "Hygiene", "SAST"; an unrecognised category
  sentence-cases itself rather than rendering blank). Its icon comes from
  `SEC_CATEGORY_ICON`, factored out of `secRuleMeta`'s own fallback rather
  than a second hand-typed list that could drift from it — `secRuleMeta`
  itself is untouched for its other caller, "Top issue categories", which
  ranks rules, not categories.

- **The findings browser now matches AllFindings.png element for element,
  not just its table.** Three earlier passes treated the mockup's header,
  stat strip, filter bar and footer as furniture around the table that
  already worked; none of the four had actually been built.

  The screen now draws its own breadcrumb (Security › ‹project› › Findings,
  self-contained inside the Findings pane so it never reaches into
  project-screen.js's shared header) and title row, with Export (opens the
  project's own Reports tab — every download this screen offers already
  lives there, nothing new to wire) and Saved filters (the existing
  details-picker, moved into the header and restyled as a button+chevron,
  its Save/Delete controls now inside the one popover that opens them
  rather than three always-visible fields). The stat strip is a real card
  now — Total findings, the five severities as coloured-dot stat blocks
  with a share-of-total percentage each (a dash, not `0.0%`, when the
  denominator is zero), a divider, then Unique issues — replacing the bare
  `N total`/`N unique issues` pills. The filter bar's chip rows and plain
  text fields become six "Label: value ▾" pickers (Severity/Status/Category
  still multi-select; Branch and Analysis run gained real OPTIONS —
  `queries.finding_rows` now also returns `branches`/`analyses`, read off
  values the same per-branch loop already had in hand, no second query;
  File path stays free-text substring search inside its own popover) plus
  a house on/off switch for "Show resolved findings" (no such control
  existed in this app before) and a `Filters (N)` count of active narrows,
  N=1 by default because excluding resolved rows is itself one. The table
  gained Location (split out of Title) and Analysis run (`#id (Profile)`,
  linking to that analysis exactly where the Runs tab's own "#N" button
  already does) columns, a coloured left edge per row, and swapped its two
  always-visible decision buttons for an eye (view) + kebab (Accept
  risk/False positive) actions pair, reusing this app's own established
  eye-for-view and kebab-for-more vocabulary. The footer's pager is
  numbered with ellipsis collapse now (`tableFooter`'s own new `collapse`
  option, ui/app/chrome.js — existing callers untouched, off by default)
  plus a 10/25/50 per-page picker. `--sev-low` (ui/css/tokens.css) was a
  guess, not a sampled colour (Security.png's own comment only names three
  of the five severity dots) — corrected to the blue AllFindings.png's own
  legend actually shows, once, at the token, so every reader of it draws
  the same corrected hue. The project screen's donut/categories/
  recent-activity rail hides for the Findings tab alone (AllFindings.png
  draws the table full-width; that rail is a summary of the other four
  tabs' own posture, repeating the same counts a reader can already see row
  by row in the table beside it).

  Every pinned test's SUBSTANCE survives: markup-never-text, the
  fixed-finding exemption from decision controls (now scoped to the
  kebab's own menu, since every row also carries an unconditional eye
  button), the strip's total-vs-unique labelling and floor counting, sort
  toggling, WeakMap-keyed mount isolation, the severity floor. Not
  self-contained scope: the shared tab strip and profile-header row above
  the Findings pane still render, unlike the mockup's chrome-free frame —
  reshaping those is a bigger change than this task's own file list asked
  for.

- **Phase 4's final review closes its last findings: a warnline that
  overflowed its card, a boot-killing dead-binding trap with no guard, and
  kebab menus that would not close.** Two CRITICAL, four IMPORTANT, six
  MINOR.

  The Findings-overview card's own capped/fell-back warnline was a THIRD
  child of `.secidx-donutcol` (`secIndexDonut`, ui/security/index-screen.js)
  -- harmless in the project sidebar's own column layout, but
  `.secidx-findbody .secidx-donutcol{flex-direction:row}` flips that column
  into a row for this card, and a `flex:none` row item does not shrink: the
  sentence took its own ~670px content width straight through a 424px card,
  clipped mid-word by `.table-card{overflow:hidden}` on any project whose
  latest analysis is capped. It is now `.secidx-donutwrap`'s own third flex
  child instead -- a sibling of the donut+legend column and the categories
  column, never nested inside either -- with a forced 100% flex-basis
  (`.secidx-donutwarn`, ui/css/pages.css) so it always lands on its own full-
  width line below both, and `min-width:0` so its text actually wraps there
  instead of reasserting the same overflow one level up. Verified by
  `getBoundingClientRect()` in a fresh tab at the mockup's own 424px card
  width, both themes: the warnline's right edge sits inside the card's, not
  past it, and the full sentence renders unclipped.

  `ui/security/index.js`'s own `init()` runs inside `CCSecurity.init(CC)`,
  which `bin/dashboard.html` calls BEFORE `CCApp.init()` has bound
  `ui/app/page.js`'s own `icon` -- so calling the bridged `pageHeader`/
  `kpiCard`/`tableFooter` from inside `init()` (or a function it calls
  directly) reads that binding while it is still `undefined` and throws,
  blanking the whole page on load, with every other test in the suite still
  green, because none of them boots the real script in the real order. This
  had no guard. A new source-level test
  (`test_calling_the_bridged_chrome_builders_during_securitys_own_init_does_
  not_reach_a_dead_binding`, tests/test_page_contract.py) extracts `init()`'s
  own body and the bodies of every function it calls directly and
  synchronously at that same top level, and fails if any of them reaches
  `pageHeader(`, `kpiCard(` or `tableFooter(` -- brace-matched and comment-
  stripped the same way the file's own `_plainfn`/`_strip_comments` already
  work, so a comment that merely NAMES one of the three (`init()`'s own
  banner comment does, to explain the trap) is never mistaken for a call to
  it. Falsified against itself: adding a bare `pageHeader({})` to `init()`
  turns it red, naming exactly that call; reverted, it is green again.
  Honest limit stated in the test's own docstring: synchronous, direct
  callees only, one level deep -- a callback handed to `addEventListener`
  runs later, off an event, and is not traced into.

  The `<details>`-based row kebab (the fleet table's own "More actions",
  `secIndexProjectRow`) did not close when a reader opened a DIFFERENT row's
  kebab: its own `summary.onclick` calls `e.stopPropagation()` to keep the
  click from also firing the row's click-to-open underneath it, which as a
  side effect also kept that click from ever reaching `document`, where
  `bin/dashboard.html`'s `closeMenus()` is normally reached from. `closeMenus`
  is now bridged into `ui/security/` the same direction `makePicker`/
  `createCombo` already are, and the kebab's own summary calls it directly,
  synchronously, on every open -- closing any OTHER already-open row kebab
  the instant this one is clicked, never itself (at that exact point its own
  `.open` has not toggled yet). `closeMenus()` itself gained one more clause,
  `details.secidx-kebab[open]` -> `.open = false`, so the existing
  document-level Escape and background-click paths -- unchanged otherwise --
  close it too. The kebab's own `ontoggle` now also resyncs
  `pop.hidden = !kebab.open` on every toggle (the identical fix
  `secFindSavedFilters`'s own `ontoggle` already carried, for the identical
  race: `closeMenus()`'s first line marks every `.menu-pop` in the document
  hidden on any click, including one about to open, and without this resync
  a kebab could end up `.open === true` with its own popup still marked
  `[hidden]` -- open, and painting nothing). Verified with real, separately-
  dispatched click and Escape events in a fresh tab: opening kebab A then
  kebab B closes A and leaves B's popup genuinely visible; a background
  click closes B; reopening and pressing Escape closes it.

  The Security index's own Critical/High KPI cards now wear the severity
  scale (`sev-crit`/`sev-high`, two new `kpiCard` tone classes,
  ui/css/components.css) instead of the app's status tones (`err`/`warn`,
  which stay reserved for a card reporting a STATUS -- Overview's own
  Warnings/Errors, this same screen's own Success-rate): these two COUNT
  severities, a different fact, and the mockup's own drawing samples them
  from the severity tokens, not the status ones. No `-soft` companion token
  exists for a severity hue, so the icon square's tint is `color-mix()` of
  the token itself, the identical idiom `.secidx-sev3`'s own chips already
  use. No other card's tone changes.

  The Activity screen filled BOTH `#sec-act-title` (a small-caps eyebrow)
  and its own `pageHeader()` with the identical computed title -- the
  mockup draws exactly one heading. The eyebrow fill is gone, and so is its
  now-permanently-empty element in `bin/dashboard.html`; back navigation
  (`#sec-act-back`, in the same `.secthead` wrapper) is untouched.

  Six stale claims fixed where they stood rather than corrected on top: this
  file's own account of the Findings-overview period picker ("never changes
  the totals", "drops the parenthetical") and of "Top issue categories"
  guessing an icon from the raw rule string and severity being a `color-mix`
  of `--err`/`--warn`, all superseded by later entries already in this same
  file; two stale code comments making the identical now-false claims
  (`secIndexCategories`'s own comment, ui/security/index-screen.js; the
  `.secidx-sev3` comment, ui/css/pages.css); `secRuleMeta`'s own ordering
  comment (vocabulary.js), which still said `top_categories` carried no
  `category` at all; and `ui/security/page.js`'s own claim that `tableFooter`
  "has no caller under ui/security/ yet" -- it has four. The missing entry
  this pass adds: `GET /api/security/index` gained `days` and `recent_page`
  query parameters and two 400 responses (`bin/claude-cron-server`), the
  HTTP end of the period picker and the Recent-analyses pager.

  Six smaller ones: the five severity tokens (ui/css/tokens.css) were
  declared twice, verbatim -- the duplicate is gone, with a comment stating
  dark mode deliberately keeps the same bright hues rather than dimming
  them. `secHumaniseRule` (vocabulary.js) split only on `-`; the agent that
  writes the open "sast" vocabulary is not promised to prefer kebab-case
  over snake_case, so it now splits on either, pinned with a snake_case
  in/out pair beside the existing kebab-case one. An empty Trend (30d) cell
  gained a `title` naming which of "no declared base" or "a declared base
  never analysed" it is, in `trend_series`'s own vocabulary, rather than
  leaving a reader to guess why one row's own cell is blank. The findings
  browser's own "Actions" header read UPPERCASE while every sortable
  sibling beside it read sentence case -- not by a class opting them out,
  but because each sibling's label sits inside a `<button>`, and the
  browser's own default stylesheet resets a form control's `text-transform`
  before this file ever touches it; "Actions" now sits inside the identical
  non-sortable button, matching size, weight and colour along with the
  case, not just the one property a hand-picked override would have left
  the rest of mismatched. The project screen's own Runs tab printed an
  analysis's `state` as a bare lowercase word; it now reads the index
  screen's own `secIndexRunStatusPill`/`SEC_RUN_STATUS_LABEL` (exported for
  this, ui/security/index-screen.js) so the same fact reads in the same
  Title-Cased pill register on both tables. The Activity sidebar's own
  summary card read "This period"; the mockup's own wording, already cited
  by this file's own `.secpj-cardhead h3` CSS comment, is "Activity
  summary".

  `tests/test_page_contract.py`'s own Runs-header test now extracts
  `secIndexRunStatusPill`/`SEC_RUN_STATUS_LABEL` alongside `secRunRow`,
  since that row now calls the former for real; the humaniser test above
  gained its snake_case pair. Verified live throughout against a fabricated
  two-project fleet (one capped) served from a throwaway harness page --
  the real built bundles and the real static markup, booted with a captured
  `index-data`/`project-data`/`findings-page`/`activity-data` response in
  place of the real server, since scripting through this app's own
  operator login was not this task's to do.

- **Phase 4 Task 6's furniture pass reaches the project, findings and
  activity screens.** Each of `ProjectDetails.png`/`AllFindings.png`/
  `FullActivity.png`, followed for the same moves the index screen (Phase 4
  Tasks 1-5) already made, closing this phase's remaining three inner
  screens. Table footers: the Runs tab's own analyses table
  (`ui/security/project-screen.js`) and the findings browser's table
  (`ui/security/findings-screen.js`) get the bridged `tableFooter()` inside a
  proper `.table-card`, replacing a bare, footer-less `.tablewrap` for Runs
  and a `.pager` sibling below the table for Findings — each earns its own
  scoped width class (`.secpj-runstable`/`.secfind-table`) and joins
  `test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column`'s
  parametrize, with a `min-width` safety net measured live against real
  header text (several clipped silently under `#view-security table{table-
  layout:fixed}` at this view's own width, e.g. "Findings recorded" to
  "Findings reco" — invisible to the width-guard test itself, which checks
  only that every column sums to 100%, not that a header's own text fits
  it). The Activity table (`ui/security/activity-screen.js`) gets the
  identical `.table-card` look, hand-built rather than through `tableFooter()`
  itself since `cmd_activity_data` deliberately carries no `total` to build
  its "Showing X to Y of N" sentence from — this footer says "Page N"
  instead, the Prev/Next mechanism otherwise unchanged. The Activity screen's
  loose `<p class="paneblurb">` becomes a `pageHeader()`, the same conversion
  the index screen's own header already made in an earlier task; no Export/
  Filters actions, since the mockup's own two have no working handler behind
  them yet, and a button with nothing behind it is worse furniture than none.
  "Recent activity" (the project sidebar), "This period" and "Most active
  projects" (the activity sidebar) pick up the index screen's own bold,
  sentence-case card-title style through one shared CSS opt-out on
  `.secpj-cardhead h3`, rather than three separate fixes. The findings
  browser's own top-strip severity pills join the severity tokens in a new
  `.secfind-sev3` dialect — critical/high/medium each a distinct hue, low/
  info left in their existing muted look — the identical choice, and the
  identical reason, `.secidx-sev3` already made: this design's tokens have no
  blue, and the mockup's own Low dot is blue. The project sidebar's own
  floor-scope caveat (`secSidebarCaption`) moves from visible prose into a
  `title`, matching the index screen's own identical note; the branch-count
  sentence beside it stays visible text, a different pinned test's own
  substance. Incidental: the findings table's header and body cells
  disagreed about column order (State and First seen swapped) since before
  this task — found while giving the table its own width class, fixed by
  reordering `FIND_SORT_COLUMNS` to match both the body and the mockup. Not
  done, and noted in the task report rather than attempted: the mockups' own
  fuller project header (icon, title, a "Security enabled" badge, a
  description), the Runs tab's own KPI-card summary row and sparkline, and
  the findings table's own per-row severity pill and left-edge colour bar —
  none of these exist in any form on the current screens today, so building
  them from nothing is information architecture, not furniture. (The Runs
  tab's own analysis-state pill, listed here as undone at the time, is
  fixed later in this file's own Unreleased section — it reuses the index
  screen's existing vocabulary rather than inventing new information
  architecture, which is what this paragraph is actually about.)

- **The last seven native `<select>`s in the product become the house
  `.picker` or `.combo`, and a test keeps the count at zero.** Two user
  reports named the same defect twice on this branch: a bare `<select>`
  renders as a grey OS menu wearing its own browser-drawn indicator right
  next to a hand-drawn chevron, which is what made the Security index's own
  filter bar (Phase 4 Task 3) wrap under Refresh at the pane's own width.
  `secpj-filter-status`/`-profile`/`-branch` (`ui/security/index-screen.js`)
  are now `makePicker()` pickers — one chevron each, counts per option,
  built at runtime the way this screen's own DOM already is, wired through a
  new bridge: `makePicker`/`createCombo` (both hoisted `function`s native to
  `bin/dashboard.html`, no ui/-side source to import) join
  `CCSecurity.init(CC)` exactly like Task 1's `pageHeader`/`kpiCard` did, the
  opposite direction of that same bridge — the widget is the page's, the
  behaviour is the area's. `secInitProjectFilterPickers` wires them only
  after their markup is attached to the live document, since makePicker's
  own constructor looks its ids up with `$()`/`getElementById`, which finds
  nothing on a still-detached fragment. The Analyse launcher's
  `sec-repo`/`sec-branch`/`sec-profile` (`ui/security/analysis.js`) follow
  `ed-perm`'s exact combo shape — hidden input keeping the original id, so
  `secScope`/`secAnalyse`/the branches fetch read `$("sec-repo").value` etc.
  completely unchanged; `secInitLaunchCombos` wires the three combos'
  `onPick` to exactly what the old `change` listeners did (reload branches,
  clear the typed override, re-sync scope), which a hidden input's own
  `.value` — never touched by a person — would otherwise silently stop
  answering. A seventh `<select>`, unnamed in the original plan, turned up
  under the same sweep that wrote the guard: the findings browser's own
  "Saved filters" dropdown (`secFindSavedFilters`,
  `ui/security/findings-screen.js`), mounted in two places at once (the
  Findings tab and the Activity screen's fingerprint dialog) and rebuilt on
  every filter change with nothing to page through — a poor fit for
  makePicker's own once-per-page-life registry, so it becomes the
  `<details>/<summary>/.menu-pop` popover `secIndexProjectRow`'s kebab and
  `secFindingsPeriodPicker` already established for exactly that shape.
  Building it exposed a latent race in that shared pattern: `closeMenus()`
  (`bin/dashboard.html`) hides every `.menu-pop` in the document that is not
  already marked hidden on ANY click outside one, including a popover this
  function had only just built and never opened — the two older instances
  self-heal within one 5-second poll tick that rebuilds them hidden-free
  again, but this table fetches on demand, so its own picker could go
  silently un-openable until the next filter change. Fixed by setting the
  pop's `hidden` from the trigger's own open/close state on every toggle,
  instead of trusting whatever an earlier stray click left behind.
  `test_the_page_and_every_ui_module_are_free_of_native_selects` (and its
  own falsification companion) is the guard: no literal `<select` anywhere
  in the rendered page (HTML comments naming what used to be one, stripped
  first — the rule is about what the browser renders, not five characters
  in a sentence) and no `createElement("select"` under any module in `ui/`.
  `secFill` (`ui/security/dom.js`), the last helper that ever populated a
  bare `<select>`, has no callers left and is gone.

- **"Top issue categories" shows a human label and a rule-specific icon
  instead of the raw rule string.** `SEC_RULE_META` and `secRuleMeta`
  (ui/security/vocabulary.js) are a new curated vocabulary for exactly the
  rules the deterministic engines can write — the eight secrets.py
  patterns (`private_key` → "Private keys committed", `generic_secret` →
  "Hardcoded secrets", and one labelled entry each for the AWS/GitHub/
  Slack/Stripe/OpenAI/Google key shapes) and the four hygiene.py findings
  (`.env file committed`, `Private key file committed`, `No .gitignore in
  the repository` — worded from that rule's own rationale, which is about a
  stray credential slipping in, not about build output — and
  `World-writable file`). A dependency rule keeps itself as the label
  unconditionally (`GHSA-...`/`CVE-...` are already names, exactly as the
  mockup keeps "GHSA-8xcm-r25x-g524" verbatim), and a sast rule — the one
  open vocabulary, since the analysis agent writes its own kebab-case id
  per finding — is humanised instead of shown as a raw slug
  ("auth-gate-fails-open" → "Auth gate fails open"). Icons follow the same
  logic: `private_key` and `committed_key_file` both draw the new `key`
  icon (a key found by content or by filename is still a key), the other
  secret rules and any future one this map has not been told about yet draw
  `lock`, an advisory id or any other dependency rule draws `shield` or the
  new `package` icon, hygiene draws the existing `hammer`, sast draws the
  existing `code`, and anything truly unrecognised falls back to `shield`
  rather than a blank glyph. `key` and `package` are new entries in
  bin/dashboard.html's icon table, plain stroke paths in the same 24×24/
  stroke-2 style as the rest of it. The raw rule id is never dropped, only
  demoted to the row's own `title`, so an operator who greps the ledger by
  rule id still finds it one hover away. This replaces `secIndexCatIcon`, a
  substring heuristic over the rule string that shipped one task earlier and
  showed the bare rule id as the row's name regardless — a deliberate
  choice at the time ("data truth, not an invented translation table") that
  this task reverses now that the translation is sourced from the engines'
  own rationale rather than guessed. (`top_categories` grouped by rule alone
  at the time, with no `category` of its own to hand this card — closed two
  commits later, this same file's own entry on that fix.)

- **The Security index's projects table becomes the approved mockup's, and
  a client-side filter bar arrives above it.** Phase 4 Task 3, the largest
  of the phase. The table grows from five columns to eight — Project
  (folder icon, bold name, an unconditional green "security enabled"
  badge, a two-line clamped description), Last analysis (relative time,
  "profile · branch" beneath, the fallen-back note now living in that
  sub-line instead of a dedicated Branch column), Profile (a new
  `.pill.profile` accent pill), Last run (a coarser "2h 15m"/"45m" duration
  than the shared `fmtDur`'s "135m 0s", its own date beneath), Findings
  (three FIXED severity chips — critical/high/medium, always in that
  order, even at zero — plus "N total" from posture's own total, which can
  exceed what the three chips show since low/info count toward it with no
  chip of their own), Trend (30d) (a bar sparkline over `trend_series`'s
  30-day series, `createElementNS`, accent bars, baseline-aligned, an
  honest muted dash for an empty list rather than a fabricated flat line),
  Status (Active/Disabled, reading a new `enabled` field the real payload
  never actually sends false today — every row here is security-enabled by
  construction — but the branch is real, not dead code, for whenever a
  future payload does) and Actions (a solid View plus a kebab holding two
  already-existing actions, View activity and Edit project, scoped to that
  row's own project). Every pinned cue survives the reshape: a capped
  analysis's "incomplete" badge moved from the old Posture cell to
  Findings, where the counts it qualifies now live; a fallen-back branch
  still names itself in the open, never just a bare "(fell back)"; never-
  analysed still reads the one `SEC_NEVER` sentence. The filter bar (Search
  projects + Status + Profile + Branch pickers + Refresh) is plain
  `<select>`s at this point, not `ui/app/chrome.js`'s real `.picker` widget —
  that widget's pickers are static markup wired inside `bin/dashboard.html`
  itself, and porting it across the `ui/security`/`ui/app` bundle split for
  four new ones was a bigger migration than this table's own redesign asked
  for at the time (a later task closes it — see this same file's own entry
  on the product's last native selects). Filtering itself
  (`secFilterProjects`) is a pure function, unit
  tested directly. Getting the live search box to survive this screen's
  five-second poll took two tries: the first attempt gated a remount on a
  `dataset.mounted` flag, which missed that `secLoadIndex`'s own
  pre-existing "Loading…" placeholder clears the very same host on an
  explicit Refresh or `secBack()`, leaving the guard permanently skipping a
  remount it now actually needed — found live, as a Security screen stuck
  on "Loading…" after returning from a project. The fix checks whether the
  slot is still ACTUALLY attached to the DOM, not a flag that survives the
  wipe. The kebab's own popup hit a second, unrelated ceiling live: `.table-
  card{overflow:hidden}` (its own rounded-corner clip) and the generic
  per-cell overflow guard both clip a plain `position:absolute` popup
  along with anything else escaping the row's box, so it opened (`.open`
  true, a correctly laid-out rect) and painted nothing — fixed by
  recomputing `position:fixed` coordinates from the button's own screen
  position on every open, which escapes the clip the way `absolute` never
  can. Two new icons (`shieldcheck`, `gitbranch`) join `bin/dashboard.
  html`'s shared table, the same reason `alertcircle` joined it in Task 1:
  the mockup needed a shape nothing already had.

- **`queries.py` gains `trend_series`, and a project's index row carries
  `trend` again.** Phase 4 Task 2: the 30-day open-findings series
  `8c0eaf8` deleted for having no reader is back, ready for the Trend
  sparkline a later task renders — but not as `8c0eaf8`'s own line
  un-deleted. That line called `trend()` with the branch
  `default_branch_posture` had already resolved for the row's posture
  cards, fallback included; a project whose declared base had never been
  analysed would have plotted another branch's history under it, silently.
  `trend_series(conn, project, days=30)` reads the project's DECLARED base
  alone and returns `[]` instead — the same discipline `branch_fell_back`
  already gives the row's own posture, just with no cell of its own to say
  a fallback happened. It delegates entirely to the existing `trend()` for
  the SQL, the window and the `done`/`capped` treatment (a `capped`
  analysis still counts, exactly as `posture` already treats one), keeping
  only each point's `open` count. Cost: one query per project (`trend`'s
  own `SELECT`) plus one `checklist()` per finished analysis actually
  inside the window — and the declared branch's newest such analysis is
  already cached by `project_rows`'s own `posture()` call on the same
  connection, so the common case (one analysis in 30 days) adds nothing
  beyond that one `SELECT`, pinned by a query-count test the same way
  `finding_counts_by_analysis` already is. `bin/security/cli.py`'s
  no-ledger fallback and both test layers carry the field through too —
  always a list, never null or absent.

- **The Security index gets a real page header and five KPI cards matching
  the approved mockup, through a new runtime bridge into `ui/app/`'s shared
  chrome.** The loose intro paragraph and its bare toolbar are gone,
  replaced by `pageHeader()` (shield icon, "Security", "Vulnerability
  analysis across your projects.", Activity and Refresh as its own actions
  at this point — both later moved out, then Activity dropped for good; see
  this same file's later entries) and the same `kpiCard()` every other
  page's KPI row already
  uses: Projects/"with security enabled", Total analyses/"across all
  projects", Critical findings/"needs immediate attention" (`err` tone),
  High severity/"requires review" (`warn` tone), Success rate/"analyses
  completed" (a new `ok` tone, joining `warn`/`err` on `kpi-card-ic`).
  `ui/security/` and `ui/app/` stay two separate esbuild bundles —
  importing `chrome.js` directly would give the Security bundle a second,
  never-bound copy of `ui/app/page.js`'s own `icon` — so `bin/dashboard.
  html`'s `CC` object now hands `CCApp.pageHeader`/`CCApp.kpiCard`/
  `CCApp.tableFooter` into `CCSecurity.init(CC)` at runtime, and
  `ui/security/page.js` declares and binds all three like every other name
  the area is given; `ui/security/index-screen.js`'s new `secRenderHead()`
  and `secIndexCards()` are the only two callers, both reached off a poll
  tick or a resolved fetch, never from `init()` itself, which runs before
  `CCApp.init()` has bound that `icon`. The Critical/High cards' own
  capped-analysis and fallen-back-branch caveats move from a visible
  `.secidx-note` line into the card's own `.title` tooltip — the mockup's
  fixed, short sub-caption for both leaves no room for a sentence that
  long — and Activity/Refresh are answered by `bin/dashboard.html`'s central
  delegated click listener rather than a listener attached directly to
  either button, the same split every other page's own `pageHeader()`
  actions already use. The old `.secidx-kpis`/`.secidx-card`
  markup and CSS are gone; the KPI grid now shares `.kpi-grid`/`.kpi-card`
  with every other page, and a new `alertcircle` icon covers the one shape
  (a ringed exclamation mark) nothing in the existing set already drew.

- **The job and project editor dialogs close their last four gaps against
  the approved artboards (`JobEditor.view.html`/`ProjectEditor.view.html`
  in the design canvas), found by comparing the shipped dialogs to the
  canvas pane by pane.**

  Edit mode now draws the same flat, underlined text tabs every other
  page's `.tabs`/`.tab` already draw — no numbered stepper, no per-tab step
  number — while CREATE mode keeps the numbered stepper exactly as it was
  (its numbers and check-ticks carry real gating semantics there).
  `makeWizard`'s `paintTabs` (`bin/dashboard.html`) now branches on
  `W.creating`; `paintNav`'s gating and `goto`/`forward`/`onTabClick` are
  untouched, so `test_the_wizard_gates_advancing_on_validation_but_
  editing_reaches_any_tab` stays green unedited. `.tab.bad`/`.tab.edited`
  used to live only on `.tabs.wiz`'s numbered circle — a corner-badge on
  the `stepn` span a flat tab no longer renders — so both get a non-wiz
  twin in `ui/css/pages.css`: a reddened tab for a step that failed
  validation, and a small dot after the label for a step with unsaved
  edits, so neither signal silently disappears now that editing has no
  stepper.

  The job editor's footer gains `ed-delete` ("Delete job"), first in
  `.dlg-f` like `pj-delete` already is, visible only while editing (shown
  in `openEditor`, hidden in `openCreator` — creating has no job yet to
  delete). It calls the exact confirm copy and the exact `api("delete",
  ...)` the Jobs table row's own `data-op="delete"` button already uses —
  one delete path, not two that could drift apart — and closes the dialog
  on success.

  "The job" pane pairs Project and Working directory in one `.row2`
  (Description now follows the pair instead of sitting between the two
  fields), matching the artboard's own field order. Every id and every
  help line is untouched; only the grouping and the order moved.

  The Security pane's "Enable security analysis" checkbox becomes a
  two-segment Enabled/Disabled control (`.segctl`) over the exact same
  `#sec-enabled` — now a real checkbox kept in the DOM with the `hidden`
  attribute, not removed, so `saveProject` and `openProjectEditor` read and
  set it exactly as before. `paintSecEnabled()` keeps the two segments in
  step with it, called right after `openProjectEditor` sets `.checked` the
  same way the combos' own `.set()` calls are hooked; a segment click flips
  the hidden checkbox and dispatches a bubbling `change`, so `#projmodal`'s
  own delegated change listener (dirty tracking) keeps firing exactly as it
  did when this was a visible checkbox. Grepping the tree first turned up
  no OTHER listener keyed on `#sec-enabled` — no dependent-fields gate
  existed to preserve beyond that one.

  Three artboard divergences are deliberate and untouched: the "Branch to
  analyse" field (the Security launcher picks the branch per-analysis), the
  3-segment Effort control (the product has 6 levels shared with the job
  editor's own slider by a pinned rule), and the Categories pills (the
  product uses profiles instead).

  `readForm`/`fill`/`saveProject`/`saveEditor` and every existing element
  id are untouched. Eight new pinned tests (`tests/test_page_contract.py`)
  drive the real `paintTabs`/`paintSecEnabled` under Node and check the new
  markup and wiring by source, one to three per divergence. Verified live
  in both themes and both editor modes, side by side with the artboards at
  the same width: edit mode flat with an underline and create mode
  numbered, and reopening the same dialog in the other mode repaints
  correctly both ways; Delete job confirms, deletes a scratch job and
  closes; toggling the segments enables/disables exactly as the checkbox
  did (dirty tracking still fires), and `security.enabled` round-trips
  `true` → `false` → `true` through scratch `projects.json`, saved as a
  real JSON boolean both times.

- **The Security pane's last two native `<select>`s — default analysis
  profile and minimum severity shown — become the house combo, so the
  project editor no longer drops into a grey OS menu right next to every
  other dropdown in the product.** `sec-profile-default` and
  `sec-min-severity` in `bin/dashboard.html` now follow `ed-perm`'s exact
  shape: `.combo` wrapper, searchable popover, and a hidden input keeping
  the original id, so `saveProject`'s reads and the two fields'
  `CCSecurity`-validated fallbacks at open time are untouched. Their
  option lists are `CCSecurity.SEC_PROFILES` and `CCSecurity.SEV_ORDER`
  themselves, each run through one new one-line `titleOpt` helper — not a
  third hand-typed copy of either vocabulary. The open path's existing
  validation lines write the hidden input exactly as before; a new
  `if(secProfileCombo) secProfileCombo.set(...)` (and the same for
  severity) right after each keeps the visible label in step with it —
  without it, reopening a project with a non-default stored value showed
  the wrong label while still saving the right one underneath.

  `test_the_min_severity_dropdown_offers_info_as_the_lowest_option` is
  rewritten to read the combo's option source — `CCSecurity.SEV_ORDER.map
  (titleOpt)`, executed against the real vocabulary — instead of a
  `<select>`'s markup; same substance pinned: info lowest, medium the
  default. `test_the_project_editor_has_a_security_pane` and
  `test_saving_always_sends_the_whole_security_block_with_a_real_boolean`
  stay green and unedited. Verified live in both themes on a project with
  non-default stored values (Deep/Low): both fields render as combos, not
  native menus; search filters ("de" narrows to Deep); a severity change
  survives a save round-trip into `projects.json` and back; and the
  popover is not clipped by the dialog's own scrolling body, including at
  a ~900px-tall viewport.

- **The project editor gains the same artboard furniture as the job
  editor, and the Security pane's model/effort controls stay provably
  identical to the job editor's own.** `bin/dashboard.html`'s
  `<dialog id="projmodal">` reuses every class Task 3 already put in
  `ui/css/pages.css` — none of it is new — extended there to also match
  `#projmodal`: the 13px/600 labels, the plain 12.5px help line, and the
  40px/9px control height/radius on every text input, select and combo
  trigger across all four panes (project, repos, provisioning, security).
  `.row2`, `.day-btn`(unused here) and the tab strip's 13px/600 were
  already bare rules from Task 3, so the project editor picked those up
  the moment they shipped. The one addition: `.repo-f>label` keeps the
  small-caps NAME/PATH/BASE BRANCH scale a repeated repo row needs — the
  new field-label size would have doubled a two-repo project's row
  height for no reason.

  Nine more `.fieldhelp` paragraphs shrink to one sentence each, three of
  them former multi-clause paragraphs carrying `<b>`/`<code>` emphasis
  that the flat, one-line convention drops in favour of plain prose (code
  literals like `*`/`release/*`/the `CC_*` environment names stay
  `<code>`, since those are syntax, not emphasis): the base-branch note,
  the Claude-account note, the single- and multi-repo notes, the
  worktree-isolation warning, the provisioning script note, and the
  Security pane's model/permission-mode/Claude-account notes. Two
  `.fieldhelp`s were already one sentence and are untouched (the
  `--force` budget note, the min-severity note).

  `test_the_project_editor_has_a_security_pane`,
  `test_security_model_and_effort_use_the_job_editors_controls`, the
  min-severity and whole-security-block tests, and the repo-save
  round-trip tests all stay green and unedited; verified live in both
  themes, editing and the four-step numbered create wizard (with its own
  validation refusal), the repos pane with one and with two rows, and a
  save round-trip against a real project's description.

- **The job editor speaks the artboards' furniture: 40px/9px controls,
  13px/600 labels, one plain grey help line per field, pill day-buttons.**
  `bin/dashboard.html`'s `<dialog id="editor">` markup is unchanged in
  structure — every id, `readForm` and `fill` untouched — the look comes
  from a new `/* ---- dialog forms ---- */` section of `ui/css/pages.css`,
  tokens only. `.row2`'s pairs go from 12px to 18px apart, `.day-btn`
  becomes a full pill, and the tab strip (`.tabs.wiz .tab`, drawn by the
  shared `makeWizard`) moves to the same 13px/600 scale a KPI card's own
  label uses. These three, plus `.combo-trigger`/`.stepper`/`.moneyin`,
  are bare rules: nothing outside the two editor dialogs' shared wizard
  ever reaches them. `.fieldhelp` and the bare `.dlg-b label`/`input`/
  `select` rules are a different story — the profile modal, the log modal
  and the finding-reason box use them too — so their restyle (13px/600
  sentence-case labels, a plain 12.5px help line instead of an italic one)
  is scoped to `#editor` alone; the project editor's own turn is next.

  Five `.fieldhelp` paragraphs were two sentences or more; each shrinks to
  one, wording only — the job id's ("Unique identifier for this job. Use
  letters, numbers, - and _ only." → "...— letters, numbers, - and _
  only."), the project combo's, the working-directory note's
  (`ed-cwd-help`), the precheck script's, and the max-simultaneous-runs
  one, which folds three sentences (what it controls, the 0-for-no-limit
  default, and that Run now/Resume refuse at the cap) into one without
  dropping any of the three. The footer (Cancel, then Save changes; no
  destructive action lives in this dialog — a job is deleted from its row
  in the table, not from its own editor) already matched the artboard's
  order and needed no markup change.

  `test_the_poll_never_reaches_into_a_form_dialog` and every wizard/
  dirty-tracking/day/effort test pinned ahead of this restyle stay green
  and unedited; verified live in both themes and both the numbered-stepper
  (create) and numbered-tab (edit) navigations, including a save round-trip
  against a real job's description.

- **The Security index gets its own Recent analyses table and Findings
  overview card, side by side, closing Phase 4.** The old plain feed
  (project · repo @ branch, one line per analysis) becomes a table matching
  the mockup's own columns — Run (#N), Project, Profile, Branch, Findings,
  Status, Date (relative time, the exact timestamp beneath) — paginated five
  at a time through the shared `tableFooter()`. Its Findings cell says the
  one true number `recent_analyses` actually hands a historical row (a
  combined open-findings count) rather than fabricating the fleet table's
  own three severity chips from a per-severity breakdown that query was
  never given; Status reads a new four-way pill vocabulary (Completed/
  Capped/Failed/Running, `.pill.done/.capped/.failed/.running`) rather than
  reusing `.pill.on`/`.pill.off`, which stay reserved for a project's own
  active/launchd-fault reading. Findings overview keeps the donut, its
  categories list (now "Top issue categories", an icon and a right-aligned
  count, no more width-scaled bar) and adds a legend a reader can actually
  total: a coloured dot, the severity name, its count AND its percentage
  share of the whole ("45 critical (23.8%)") — computed from the same donut
  totals the mockup's own arithmetic uses (per-severity share of the total,
  which is why the mockup's own three percentages do not sum to 100). Both
  card titles drop the page's usual small-caps eyebrow style for the
  mockup's own bold, sentence-case reading, and a period picker (Last 7/30/
  90 days, All time — the Activity screen's own vocabulary, now exported
  and shared rather than re-typed) sits beside the second card's title as a
  real popover, not a `<select>`, using the identical `<details>`/
  `position:fixed` mechanism the projects table's own row kebab already
  relies on to escape `.table-card`'s corner clip.

  The picker's own selection does not change the totals beneath it at this
  point: `queries.severity_totals` and `top_categories` used to accept a
  `days` parameter, ignore it completely, and were never passed one by
  either caller — a POSTURE is what is open right now, off each branch's
  latest finished analysis, and windowing it would not narrow the answer, it
  would drop quiet branches out of it and report them clean (see this same
  file's own entry on that fix). Reusing the mockup's own "Findings overview
  (30 days)" caption verbatim would have resurrected exactly the claim that
  fix removed, so the card's title drops the parenthetical instead, at this
  point — a named divergence, not an oversight. (A later task makes the
  window real and the parenthetical honest again — see this same file's own
  entry on `queries.severity_totals`/`top_categories` gaining a real `days`
  window.)

  Two more named divergences, both forced by what the payload actually
  carries rather than chosen for taste: `tableFooter` has no numbered pager
  (the mockup's own "1 2 3"), only Prev/Next, and forking a second footer
  component for one card was a bigger yak than this task asked for; and
  `recent_analyses` defaults to its own top 5 with no total count or paging
  parameter, so the footer reads "Showing 1 to 5 of 5 runs" against a real
  server today, not the mockup's own "of 12" — the pagination logic is real
  and covers whatever length a payload actually hands it (exercised here
  against fabricated longer lists), but nothing live can reach a second page
  yet. "View all analyses" opens the Activity screen straight onto its own
  Analyses tab (today's nearest equivalent navigation, kept rather than
  invented); "View full report" opens the most recent analysis's own
  project on its Reports tab, honestly disabled when there is no analysis
  yet to open one for — there is no report spanning every project, only one
  per project's own checklist.

- **The Security index closes the last gaps against its own mockup — a real
  time window, real paging, three severity tones, and the numbered pager
  both its tables were still missing.** Phase 4 Task 5, and the third and
  last pass this screen needed: the previous two tasks each shipped a
  handful of individually-reasoned divergences (consistency with the rest
  of the app, "the payload does not carry that", a pinned test's own
  wording), and side by side with the mockup none of them held up. This
  task closes every one, `docs/superpowers/specs/2026-08-27-app-redesign-
  phase-4-security-index-design.md`'s own four Decisões and two further
  practical exceptions (the Activity button; the Refresh icon) aside.

  `queries.severity_totals`/`top_categories` gain a REAL `days` window —
  reversing this file's own earlier entry ("the two posture rollups no
  longer accept a time window they never applied"), which was correct
  about that OLD parameter (accepted, ignored, dead) but became the reason
  two later tasks left the Findings-overview card's period picker
  filtering nothing. The default (`days=0`) is unchanged: every existing
  caller (the project sidebar's own donut, chiefly) still gets the as-of-
  now posture it always has, read off each branch's latest finished
  analysis with no window at all. Only `cmd_index_data` asks for a real
  one now (`--days`, 30 by default, forwarded from the picker), and
  windowing means "the branches whose newest finished analysis itself
  falls in the period" — the identical `>=` boundary `trend` already uses,
  at no extra query cost (still one `_latest_finished` read and at most one
  `checklist()` per analysed scope; a scope with nothing recent contributes
  nothing, never a stale reading from further back). Picking a different
  period now genuinely re-renders the donut, legend and categories, and the
  card's own title says which one — "Findings overview (7 days)" — instead
  of dropping the parenthetical the mockup asks for.

  `queries.recent_analyses` returns `{rows, total}` and pages the SQL
  itself (`LIMIT`/`OFFSET`, five at a time) instead of a bare list capped
  at five with no way to ask for a second page — the footer reads "Showing
  6 to 10 of 12 analyses" against a real server now, not "of 5". Each row
  also carries `severities` (critical/high/medium, tallied from the same
  `checklist()` call its `open` count already made), so its own Findings
  cell draws the mockup's three fixed chips instead of one undifferentiated
  count with a tooltip pointing elsewhere. Cost: one extra `COUNT(*)` per
  `index-data` call (polled every 5 seconds); the `checklist()` volume is
  unchanged, since the page size served was already five.

  Findings chips (both tables) and the donut's own legend move off the
  two-tone grouping (critical and high sharing one colour) onto three —
  critical (`--err`), high (`color-mix(in srgb, var(--err) 50%, var(--warn)
  50%)`, the one new expression at this point, not a new hex literal — this
  design's tokens had no third hue of their own yet), medium (`--warn`) —
  scoped to this screen alone (`.secidx-sev3`) so the findings browser, the
  branches tab and a project's own Overview, none of them touched by this
  task, keep the grouping they already had. (A later task replaces all
  three with dedicated `--sev-crit`/`--sev-high`/`--sev-med` tokens sampled
  from the mockup's own pixels — see this same file's own "Four gaps"
  entry.) The donut's own legend is redrawn as the mockup's own row — a
  coloured dot, the severity's name, a right-aligned "count (pct%)" — its
  own element now, not a `.sevpill` wearing a percentage the way the
  previous task built it (the pinned test that shape carried moved with it:
  `test_the_findings_overview_legend_states_each_severitys_share_of_the_
  total`, `tests/test_page_contract.py`). "Top issue categories" gets a
  per-row icon guessed from the rule string at this point (secrets → lock,
  GHSA/dependency → shield, injection/XSS → code, hygiene → hammer, anything
  else → the same generic alert glyph every row drew before) — replaced two
  tasks later by `secRuleMeta`'s curated map, keyed off the rule's own
  rationale rather than a guess (see this same file's own entry on "Top
  issue categories" earning a human label) — and the Total-analyses KPI card
  gets its own trend-line icon instead of
  reusing the unrelated activity pulse — three new icons in
  `bin/dashboard.html`'s own table (`trend`, `lock`, `code`), shield and
  hammer reused as they already were.

  `tableFooter` (`ui/app/chrome.js`) gains an optional numbered "‹ 1 2 3 ›"
  pager — the mockup's own, in place of the Prev/Next-with-text shape a
  previous task kept rather than fork a second footer component — and,
  numbered with only one page, no pager at all, matching the fleet table's
  own "Showing 1 to 2 of 2 projects" with nothing to click. Existing
  Prev/Next callers (Jobs, Runs, the OTHER Projects page) never pass the
  new option and are untouched. Found live, verifying against the mockup:
  the footer's own pluraliser is a bare `noun + "s"`, which reads "Showing
  1 to 5 of 12 analysiss" the moment a caller's noun is this one irregular
  plural — `plural`, an optional override, fixes the sentence without a
  general pluraliser this function does not need for anything else it
  draws, pinned by `test_table_footer_takes_an_irregular_plural_and_a_
  numbered_pager`.

  `fmtAgo` (`bin/dashboard.html`, threaded through both page interfaces)
  gains an optional long-form reading — "2 hours ago", "1 day ago" — for
  this screen's Last-analysis and Recent-analyses cells; every other page
  keeps calling it with one argument and keeps the short form it always
  had.

- **`GET /api/security/index` gains `days` and `recent_page` query
  parameters, the HTTP end of the same period picker and Recent-analyses
  pager this file's own entry above describes.** `security_index`
  (`bin/claude-cron-server`) forwards both straight through to
  `index-data`'s own `--days`/`--recent-page`: `days` absent defaults to
  `SECURITY_INDEX_DEFAULT_WINDOW_DAYS` (30, the mockup's own "Last 30 days")
  rather than `queries.py`'s own all-time default, so a caller that never
  asks for a period still gets the mockup's own window; `days=0` ("All
  time") is passed through explicitly rather than collapsed into "absent"
  — the identical trap `security_activity`'s own `since` parameter already
  refuses, since folding the two together would make "All time" silently
  mean "30 days" instead. A `days` that will not parse as an integer is a
  400 (`{"error": "days must be an integer"}`); a negative one clamps to 0
  rather than erroring, since a negative window has an obvious honest
  reading ("no window") a non-numeric one does not. `recent_page` absent or
  unparseable reads as page 1 — the same clamp-not-reject treatment
  `security_activity` already gives its own `page` — except a value that
  will not parse as an integer AT ALL, which is the second 400
  (`{"error": "recent_page must be an integer"}`); a parseable one below 1
  clamps up to 1 instead of erroring.

### Added

- **The two editor dialogs' decision/mapping logic is pinned and pulled out
  into `ui/app/editor-domain.js`, ahead of Phase 3 restyling either one.**
  The job editor and the project editor share one wizard
  (`makeWizard`, `bin/dashboard.html`) for dirty tracking and dual-mode
  navigation — a numbered stepper that validates each step while creating,
  numbered tabs all reachable at once while editing — plus a handful of small
  form↔job mappings (`getDays`, the effort slider's `effortGet`/`effortSet`)
  and `validateProjectStep`'s own per-step rules. All of it read `$("...")`
  or `document` directly, which is exactly what a characterisation test
  cannot drive without a browser, so only the DOM-free half of each moved:
  `changedKeys` (the snapshot comparison behind `edIsDirty` — compared key
  by key, never the two snapshot objects by reference, since `snapshot()`
  returns a fresh object on every call), `effortIndex`/`effortFromIndex`
  (the slider position ↔ CLI value table), `dayNumbers`, `shapeRepoRows`
  (`collectRepos`' row-to-list shaping) and `projectStepError`
  (`validateProjectStep`'s rules, given the gathered values). Every export
  is plain values in, plain values out — none reaches `$`, `document` or
  `CC.DATA` — extracted verbatim, not rewritten: same comparisons, same
  messages, same table. `makeWizard` itself stayed in `bin/dashboard.html`,
  shared by both dialogs as before. Four characterisation tests in
  `tests/test_page_contract.py` pin the behaviour this move must not
  change, each proved falsifiable by hand (break the thing the test is
  named for, watch it fail, revert) before this shipped.

- **A test now fails if `render()`'s 5-second poll ever reaches into a form
  dialog's own field.** `editor`, `projmodal`, `profmodal`, `confirm`,
  `secreason` and `fsmodal` hold a form a person may be mid-typing into —
  each is mounted once, filled by its own "open" function, and was never
  touched again by the poll, but until now only by accident of how the code
  happened to be laid out, not because anything enforced it. Phase 3 is
  about to restyle these dialogs, so
  `test_the_poll_never_reaches_into_a_form_dialog`
  (`tests/test_page_contract.py`) turns the accident into a contract: it
  scans `render()` and the functions it calls directly — on the page and in
  the `ui/app/`/`ui/security/` bundles — for a `$("<id>")` read of any id
  belonging to one of those dialogs. `wtmodal` and `logmodal` are
  deliberately exempt — both live-update by design (a running agent's own
  log, the worktrees table) — and the comment beside `render()` in
  `bin/dashboard.html` says why, so the exemption cannot be mistaken for an
  oversight later.

- **A test now fails if `bin/dashboard.html` ships the temporal-dead-zone bug
  a third time by itself becoming a fourth.** `CCApp.init(...)` and
  `CCSecurity.init(...)` each build one object naming dozens of functions
  the moved-out `ui/app/` and `ui/security/` modules call back into, read
  the instant that object literal is built — and three times now, a name in
  one of them (`activeRunsOf`, `backoffMultiplier`, `runKey`) turned out to
  be a `const NAME = (...) => {...}` declared BELOW the object that reads
  it. `const`/`let` are hoisted by name but not by value, so reading one
  before its own declaration line throws a `ReferenceError` from the
  temporal dead zone — during boot, before a single row of the page's own
  JavaScript a test could exercise has run. Nothing in the suite loads the
  page the way a browser does, so all three were only ever caught by
  opening it and watching it crash — `runKey` as recently as the previous
  task. `test_every_name_ccapp_and_ccsecurity_init_pass_is_already_usable`
  (`tests/test_page_contract.py`) is a static stand-in for that: it never
  executes the script, only extracts every bare-name property either
  interface object reads eagerly (a shorthand, or a `key: value` pair whose
  value is a plain identifier or a dotted chain of them — a method,
  getter/setter or inline function value is correctly left unchecked, since
  none of those read anything until called, well after boot) and fails if
  that name is declared `const`/`let` anywhere below the point its object
  is built; a `function` declaration is never flagged, since it is exactly
  the fix all three past occurrences converged on. Proved able to fail by
  reverting `runKey` to the `const` arrow it used to be, in place, and
  watching this test name it before reverting the change back. A pass over
  the rest of the file found no second instance of the class: every other
  name read at the top level as the script boots (`initSidebar()`,
  `initPickers()`, the `submitLogin`/`submitSetup` handlers, the closing
  `boot()` IIFE and the rest) resolves to a hoisted `function` declaration
  today, not a `const`.

- **The Security area has an Activity screen.** What happened and when,
  every project unless scoped to one, filterable by kind — All activity,
  Analyses, Findings, Settings — and by a period selector (7 days, 30 days,
  90 days, All time; 30 days by default), from one new endpoint, `GET
  /api/security/activity`, backed by a new CLI verb, `security
  activity-data`, itself just `ledger.events_for` (Task 3) plus
  `queries.activity_summary` (Task 5) plus which projects were busiest,
  bundled the same one-call way every sibling screen in this area already
  answers itself. `kind` narrows the table only; `project` narrows the
  table, the sidebar's per-kind counts AND its most-active-projects list —
  a real change of scope, unlike a tab, so filtering to "Analyses" does not
  also zero out what the Findings/Settings counts say happened. No user
  column and no IP column, anywhere: this install has one operator (`app.db`'s
  own `CHECK (id = 1)`), a column that can only ever hold one value teaches
  nothing, and a loopback-only server has no IP worth logging either. No
  "top active users" panel for the same reason — a list of one operator is
  not an insight; "most active projects" earns its place instead, since
  several projects genuinely can disagree about which is busiest. An
  analysis id in the table's own "Related" column links straight to that
  analysis (opens its project, switches to Runs, focuses the row — the
  existing single-analysis view, reused rather than rebuilt); a decision's
  fingerprint prefix opens a *second*, independent mount of the findings
  browser in its own dialog, filtered to that one fingerprint — the exact
  two-mounts-at-once case `findings-screen.js` was rebuilt host-keyed for
  in the previous entry below, now with a real second caller.
  `queries.finding_rows` gained a `fingerprint` filter (a PREFIX match, not
  the full 64-character shape a written finding is validated against — an
  event's `related` only ever carries the first 12 characters) to make that
  link possible without a second copy of a filterable table. The empty
  state names the period actually searched ("No activity recorded … in the
  last 30 days") rather than leaving a blank screen that could be mistaken
  for broken — the case every project sees today, since the event log
  landed after Minerva's own analyses ran and its ledger has recorded none.

- **The Security area has a findings browser.** Every finding of a project in
  one filterable, paginated table — severity, state, category, branch,
  analysis and path filters, plus free-text search across title/rule/
  rationale/file, all resolved server-side by `queries.finding_rows` behind a
  new endpoint, `GET /api/security/findings`, backed by a new CLI verb,
  `security findings-page`. A row's state is the state its OWN branch's
  latest finished analysis gives it — a list that crosses branches has to say
  which analysis it is speaking about, so Branch and First seen sit beside
  State rather than a bare severity/title pair. The strip above the table
  shows `total` and `unique` as two separately labelled numbers (189 findings
  can be 93 problems, the same distinction the index screen's donut already
  draws) alongside the five severities. `min_severity` stays a display-only
  floor living entirely in the page: it says how many rows it is hiding —
  counted from the whole filtered set `by_severity` describes, not just the
  page on screen, so the count is exact regardless of which page is open —
  and a caption beside it says downloads always carry every recorded finding
  regardless of what the floor shows. Accept risk/False positive act through
  the existing `security_decide` op and are refused while an analysis of the
  project is running, exactly as the CLI already refuses it. Saved filters (a
  named set of criteria per project) get a picker plus save/delete, backed by
  two new ops, `security_filter_save`/`security_filter_delete`, and the
  existing `ledger.saved_filters`. Sort column, direction, page size and the
  severity/state/category vocabularies are all validated at the route before
  a subprocess is ever spawned — a bad value is a 400 with a sentence, never
  a 500 built from a CLI that exited non-zero or a raw SQL fragment that
  never even reached the query. The screen is one module exporting one mount
  function, `renderFindings(host, project, initialFilters)`: the project
  screen's new fifth tab mounts it today, written so a future caller does not
  mean a second copy of a filterable table to drift the way a duplicated
  download function, and a duplicated state machine before it, already have.

  A follow-up review closed three more issues before this shipped. The
  severity floor used to apply uniformly, with no exception for a finding
  that had just been marked FIXED — so with "Show resolved" checked, a
  low-severity fix disappeared under a medium floor exactly like an open
  finding would, hiding the one thing this view exists to confirm: that the
  fix actually landed. It now shares the same exemption `secVisible` already
  gives the single-analysis checklist (a fixed row is shown regardless of
  severity), and the strip's own "N hidden" count excludes it too, via a new
  `fixed_by_severity` field on `queries.finding_rows`, so the two numbers
  stay consistent with each other. The search field's label promised less
  than the search does — it read "Search title / rule / CVE / file", but the
  filter searches `title`/`rule`/`rationale`/every occurrence's file path,
  and "CVE" is not a field of its own (it is folded into `rule` for a
  dependency finding); the label now names what is actually searched. And
  every piece of this screen's state (filters, sort, page, the fetch
  generation) is now keyed by the mounted host in a `WeakMap`, not held in
  module-level variables — a real gap once the Activity screen's planned
  fingerprint link opens a second mount of this same browser beside the
  Findings tab's own one, where the older of two overlapping fetches used to
  fail its own staleness guard and leave that pane frozen on "Loading…"
  forever.

- **The Security area has an index screen.** Five KPI cards (projects, total
  analyses, critical, high, success rate), a table of every security-enabled
  project with its default branch's current posture, a fleet-wide feed of
  recent analyses, and a severity donut with the rules producing the open
  findings behind it — all from one new endpoint, `GET /api/security/index`,
  backed by a new CLI verb, `security index-data`. The old per-project list
  cost one subprocess per project on every load and every Refresh (`security
  list`, plus `security checklist` for whichever project had a finished
  analysis) — this is the whole screen in a single call, however many
  projects are configured. The numbers are current posture, never all-time
  sums: "critical" and "high" are what is open in each project's *latest*
  analysis, not everything ever found, which only grows and says nothing;
  "analyses" is named as the one exception, an honest historical total. A
  project whose default branch was never analysed shows the branch it
  actually fell back to, with the name visible next to the note — postures
  of different branches must never be confused in silence. No finished
  analysis shows a dash on the success-rate card, not `0%`: those are
  different facts, and a project that has never finished a run is not a
  project with a zero-percent success rate. `index-data` opens the ledger
  through `queries.read_only`, never `ledger.connect`, so asking for the
  index before anyone has ever run an analysis answers an empty screen with
  a sentence rather than conjuring the ledger file into existence or a 500.
  A follow-up review caught two more issues before this shipped. A capped
  analysis — a PARTIAL read of the repository, whose "critical: 0" means
  "none found before it stopped," not "none" (the identical distinction the
  analysis screen's own notice already makes) — used to feed these numbers
  with no cue at all, not even the state word; the project row now carries a
  small "incomplete" badge when its latest analysis stopped short, with a
  `title` explaining why, and the Critical/High cards say how many
  contributing projects are in that state instead of presenting a fleet
  total that looks complete. And three of the five panels — the severity
  donut, its categories, and the recent-analyses feed — read the WHOLE
  ledger regardless of `--projects`, so a project disabled or removed from
  projects.json still contributed to them even though the summary and
  project table already said it did not exist; all five panels are now
  scoped to exactly the given projects. A later review found the donut and
  its category rollup still double-counted: both summed each branch's own
  posture/rule totals, and a fingerprint never includes the branch, so the
  same committed secret reachable on `main` and `develop` showed as two
  criticals and its rule as two occurrences — on a screen whose own findings
  browser, just below, already draws the opposite line (`total` vs `unique`:
  189 findings can be 93 problems). Both now count DISTINCT FINGERPRINTS
  across every scoped branch instead: a finding open on several branches
  contributes once, using the more severe of two conflicting per-branch
  severities (the agent can re-triage a finding's severity between runs),
  and a finding resolved on one branch but still open on another still
  counts, as open.

- **The Security area has a project screen.** Opening a project now leads to
  a header — its declared profile, the branch its posture is shown for (with
  the same "fell back" cue the index screen already gives when the project's
  own base was never analysed), how much code it is, when it was last
  analysed, and a **Project settings** button that opens this same project's
  editor on the main dashboard, so a setting does not need a trip back
  through the index to reach — and the run history behind two tabs instead
  of one long column, all from one new endpoint,
  `GET /api/security/project?project=<name>`,
  backed by a new CLI verb, `security project-data`. **Overview** shows the
  current posture and what changed since the previous analysis (the
  checklist's new/open/partial/pending/fixed/regressed/accepted/false-positive
  counts); a capped latest analysis carries the identical "INCOMPLETE"
  notice the index screen and the analysis view already give, because a
  capped run is a partial read and its zero counts mean "none found before
  it stopped," not "none." **Runs** is the analyses table — run id, profile,
  branch, commit, duration, findings, state, date — filterable by state, and
  checked to list exactly what `security list --project <name>` lists: same
  rows, same order, each row's own findings-recorded count folded in — how
  many findings that analysis recorded, not how many are open now. `Analyse`
  is the same button calling the same `security_analyze` op as before —
  never a bare run of the derived job, whose request file a second run would
  re-use. Lines of code shows a dash for `0`, not a number: every analysis
  before that column existed carries a zero there, and a repository with no
  code must not look the same as a count nobody ever took. The sidebar
  carries the severity donut, the open-findings-by-rule rollup, and the
  project's last few activity events, with a "view all" link into the
  Activity screen (added above, in this same section) scoped to this
  project. The old per-project detail — the repo/branch/profile picker, the
  live status line, the severity pills, the checklist
  chips, the downloads, the findings list with its accept/false-positive
  controls — is untouched and still works exactly as it did; it now lives
  nested under the Runs tab, reached by clicking a row in the new table the
  same way its own "earlier analyses" list already let you drill into one.
  `ui/security/projects.js`, dead since the index screen replaced it and no
  longer imported by anything, is removed along with the one test that
  pinned its internals.

  A follow-up review closed four issues before this shipped. The Overview's
  one-branch posture and the sidebar's every-analysed-branch donut/
  categories are two different, equally true answers to two different
  questions — a two-branch project used to show both with nothing saying
  why they disagreed. The Overview now names which branch its posture
  describes (with the same fell-back cue the header already carries), and
  the sidebar says how many analysed branches its own numbers span, never
  implying more than one when a project has exactly one. The Runs tab's
  FINDINGS column used to cost one `checklist()` call — two `findings_of`
  passes, a fingerprint-history scan, `decisions_for` — per done/capped row:
  169 SQL statements for Minerva's own two finished analyses, growing with
  every analysis a project ever accumulates (270, for a synthetic 15-analysis
  history built for this fix), and recomputed from scratch by the page's own
  4-second poll for the whole length of every live analysis. A single
  grouped `COUNT(*)` (`finding_counts_by_analysis`) replaces it — 124 and 27
  SQL statements respectively — and the number it reports is now what an
  analysis actually recorded, not an `is_open` filter that quietly shrank an
  already-closed run's own row the moment a later decision resolved one of
  its findings. The poll itself no longer re-fetches the whole payload every
  tick either: a tick that finds the same running/not-running shape as the
  one before it skips the refresh, since nothing in the header, tabs or
  sidebar can have moved until a run actually finishes; every other caller
  (opening the project, an action just taken) still forces it. And a project
  whose every analysis failed used to read "Never analysed" exactly like one
  that had never been touched, even though its own Runs tab listed the
  attempts — the header and the Overview pane now fall back to the most
  recent attempt of any state and say when it happened, and the index
  screen's project table (which had the identical gap) gets the same
  one-line fix.

  A later review found the Runs table disagreeing with itself: its FINDINGS
  column is `finding_counts_by_analysis`'s plain per-run `COUNT(*)`, but
  clicking a row renders that same analysis's checklist chips from
  `checklist()`, which also carries forward findings that disappeared since
  the branch's previous analysis, marked `fixed` or `pending` — so a row
  reporting "1" could sit above chips totalling two. Both numbers are
  correct; they answer different questions, exactly like the Overview/
  sidebar split two paragraphs up. The column is renamed to FINDINGS
  RECORDED, with a title spelling out why its own chips can total more,
  rather than changing either number to match the other.

- **The findings browser has a query.** `queries.finding_rows` unions one
  checklist per branch — the latest finished analysis of each — which is what
  lets the browser show a state at all: it is the state that branch's newest
  analysis gives the finding, not a column stored anywhere. Resolved findings
  (`fixed`/`accepted`/`false_positive`) are hidden unless `show_resolved` is
  asked for, `unique` counts distinct fingerprints while `total` counts rows
  (189 findings across branches can be 93 actual problems, and the screen
  shows both), and `first_seen` is the oldest analysis carrying the
  fingerprint, from one grouped query rather than one per row. Filtering
  (severity, state, category, branch, analysis id, path, free text) runs in
  Python after `checklist()`, not as SQL — a finding's state is computed by
  comparing an analysis with the previous one of the same branch, and
  rebuilding that comparison as a SQL `CASE` would be a third copy of a state
  machine this repository has already been bitten by duplicating twice.
  `sort` is checked against an allowlist (`SORTABLE`) and `direction` against
  `("asc","desc")`, both raising rather than falling back to a default:
  filter values travel as parameters, but a sort column is interpolated by
  nature, and it is the one route parameters cannot protect. `per_page` is
  capped at `MAX_PER_PAGE` so one request cannot ask for the whole table. A
  follow-up review caught three more issues before this shipped. `page` had
  no floor: `page=0` or a negative page silently served page 1's rows while
  the returned `page` field echoed the raw invalid number back, so a pager
  trusting that field showed a number that disagreed with the rows under it —
  `page` is now clamped to at least 1 and the field always reports the page
  actually served, while a non-numeric page still raises exactly as an
  unrecognised `sort` does. `first_seen`'s own grouped query had no `state IN
  ('done','capped')` filter, unlike every sibling query in this module
  (`_latest_finished`, this function's own branch query, `checklist`'s
  `history`) — a crashed or still-running analysis that recorded a finding
  before dying could set `first_seen` earlier than any analysis ever
  confirmed the finding held, making it look older than the evidence
  supports; it is now filtered the same way, and the generic sort key no
  longer turns a legitimate `first_seen` of `0` into `""` and crashes a
  str/int comparison mid-sort.

- **The project screen has Branches and Reports tabs.** Branches answers the
  question the single-branch Overview cannot: where is this project actually
  exposed, given `main` and `develop` can have different answers. One row per
  branch that has ever been analysed — last analysis, open findings by
  severity, how many analyses, a 30-day trend — from `queries.branch_rows`,
  which was already written (Task 5) and unused until now; every number comes
  from the same `checklist()` the rest of this screen uses. A branch's own
  open count here is not the sidebar donut's question, though: the donut
  collapses every analysed branch's open findings into one count per
  fingerprint, project-wide, while a row here counts that branch alone — so
  these rows can add up to more than the sidebar's own total, and the tab
  says so in the same voice the Overview/sidebar captions already use for the
  identical kind of fact. Reports gathers the four downloads (Markdown, JSON,
  HTML, SBOM) that used to be reachable only from whichever single analysis
  happened to be open under Runs, one row per analysis whatever its state.
  It says, plainly, what the README already knows and a reader of the page
  could not: SBOM is not a report over any one analysis's checklist, it is
  the stored CycloneDX inventory itself, kept per branch with only the most
  recent document — so the SBOM button on an older row still downloads that
  branch's CURRENT document, not a snapshot of what that analysis saw.
  `project-data` grows two more tab keys to serve this: `branches` is exactly
  `branch_rows`'s own rows, and `reports` is a thin projection of the `runs`
  rows already fetched (analysis id, branch, started, state) rather than a
  second query over `analysis`.

  A follow-up review closed four more issues before this shipped. The trend
  text used to read only the first and last of a branch's 30-day points, so a
  branch that spiked to forty open findings and got mostly fixed (5, 40, 6)
  rendered "5 → 6 ... (rising)" — the opposite of what happened, and untested
  because nothing in the diff ever drove it with three points. A direction
  word is now kept only when it holds for every step of the series, not just
  its ends; when the points disagree, the line names the peak or trough the
  endpoints alone would hide ("peaked at 40", "dipped to 5") instead of
  forcing a false direction on data that went both ways. The Branches tab's
  empty state used to say "no branch has been analysed yet" whether nothing
  was ever attempted or every attempt failed, even though the identical
  `tabs.overview.attempted` flag the Overview panel already uses for this
  exact distinction was sitting unused in the same payload — it is now
  threaded through, so a project whose every analysis failed no longer shows
  two sibling tabs contradicting each other. And `secDownloadAnalysisReport`
  in reports-tab.js, a near-verbatim copy of actions.js's `secDownload` kept
  apart only because two tests extracted `secDownload`'s literal source and
  asserted substrings inside it, is now one shared `secDownloadReport` both
  callers use — the two tests were re-pointed at the shared function, since
  neither property they guard ("downloads carry the token", "the SBOM
  filename matches REPORT_EXTENSIONS") was ever about a function's name.
  Finally, the Branches caption explained why a branch's own count differs
  from the sidebar donut but never that a branch only gets a row once one of
  its analyses reaches `done` or `capped` — the exact confusion the real
  Minerva ledger produces (Branches shows one row where Reports shows four
  analyses across two branches); the caption now says so.

### Fixed

- **The run card's second analysis list folds away.** "Earlier analyses of
  this branch" rendered as a permanent block under the selected run — a
  second list beside the one the runs table already is, and the approved
  mockup shows no such thing. It survives as a closed-by-default disclosure
  at the bottom of the card: the branch-scoped slice is one click away, and
  the pinned behaviour (the history follows the analysis on screen, never
  the picker) is untouched by the fold.

- **Wide monitors get their width back.** The page wrapper capped content at
  1560px and centred it, leaving dead margins on both sides of exactly the
  screens with the most room — every approved mockup, the 2000px-wide Runs
  one most explicitly, anchors at the sidebar's gutter and uses the whole
  width. The cap is gone, app-wide. On the Runs tab the analysis list also
  stops growing (it only stretched four narrow columns of numbers) — the
  selected run's card takes every spare pixel instead — and the right rail
  widens to the mockup's 330px, which its own legend rows were already
  noted as needing.

- **The Findings tab stops showing two breadcrumbs.** The project header now
  carries "Security › project" for every tab, and the Findings pane still
  drew its own trail beneath it. The pane's copy — and its orphaned CSS —
  are gone; one breadcrumb, owned by the header.

- **Back no longer stops on a duplicate of the screen it is already showing.**
  Two navigation paths could fire for one gesture — opening the Activity
  screen re-asserts the security view on its way — and each pushed the same
  history state, so one press of Back appeared to do nothing. `pushNav` now
  drops a push whose state equals the current entry; an A→B→A walk still
  stacks all three.

- **"1 of 2 branchs" reads "branches" again.** The capped-scope note's
  naive `+s` pluraliser met the word "branch" on the branches tab; nouns
  ending in ch/sh/s/x/z now take "es".

- **Three more user-caught gaps on the Security index's lower half.** The
  Recent-analyses card now genuinely fills the row's height — the first
  stretch fix targeted a child class that does not exist, so the wrapper
  stretched while the card inside stopped short (scratch data hid it: the
  left side happened to be the tall one there). The Findings-overview card
  takes the mockup's own width — 424px, no grow — instead of splitting the
  row almost evenly at twice the drawing's width. And the fleet's View
  button and kebab sit dead-centre in their row again: an area rule had set
  `display:flex` on the actions `<td>`, which stops a cell being a table
  cell at all, so `vertical-align:middle` was silently ignored and the
  buttons rode the top of every tall row.

- **Four gaps the user's side-by-side with the mockup caught on the Security
  index.** Severity now has its own colour tokens, sampled from the approved
  mockup's actual pixels (critical `#e3302b`, high `#f79b38`, medium
  `#edb425`) — the donut, its legend and the findings chips all read the
  same scale, replacing the muddy err/warn mixes that made medium a dark
  brown. The two bottom cards stretch to one height like the drawing. The
  Recent-analyses table stops wearing the fleet table's column widths — one
  shared `#view-security th:nth-child` set gave its RUN column the fleet's
  22% Project width and forced a sideways scroll in a half-width card; each
  table now declares its own set, and the width guard checks the two
  separately. And the filter bar's Activity button, which the mockup does
  not have, is gone — the Activity screen is reached through "View all
  analyses", where the drawing puts the door.

- **Three details the user's side-by-side with the mockup caught on the
  Security index.** The findings chips gained the mockup's subtle tint
  border (the flat soft background alone reads unfinished); the last column
  header now says "Actions" instead of standing empty; and every table cell
  across the app now centres vertically in its row — the mockups always
  drew it that way, and a tall two-line identity cell beside a one-line
  duration read staggered with the old top alignment.

- **An unknown rule id in Top issue categories humanises instead of showing
  raw.** The resolver humanised only rules whose category was `sast`; a rule
  arriving under any other or unknown category rendered its raw kebab id.
  Advisory ids (GHSA-*/CVE-*) are names and stay verbatim; everything else
  unknown now reads in sentence case, with the raw id kept in the row's
  `title` for the operator who greps by it.

- **Top issue categories no longer guesses a rule's category from the shape
  of its id.** The ranked rows carried only `rule` and `count`, so the page's
  label/icon resolver told SAST and hygiene apart by kebab-case versus
  snake_case — an accident of naming convention an agent-authored rule could
  break tomorrow. Each row now carries its own `category` from the ledger,
  and the resolver reads it.

- **The Security index's last stray paragraph moved into a tooltip.** The
  severity-floor scope note — the sentence explaining that posture totals are
  never narrowed by a project's floor — sat between the KPI cards and the
  filter bar, the one piece of mid-page prose the approved mockup does not
  have. It is now the KPI strip's own `title`, same words, reachable from the
  unfloored numbers it explains, off the page's face. The pin that requires
  the scope to be stated on every screen carrying an unfloored number still
  holds.

- **The project editor's delete button says what it deletes.** The approved
  artboard reads "Delete project"; the button read "Delete", and the job
  editor's new "Delete job" sibling made the inconsistency visible.


- **The product's dropdowns are now one vocabulary — the last native
  `<select>`s on converted pages are gone.** The project editor's Security
  pane rendered its default-profile and minimum-severity fields as grey
  native OS menus, and the Runs page's per-page control was a native select
  sitting in a filter bar whose four neighbours are house pickers. All three
  now use the application's own controls — the two dialog fields as the same
  searchable combo the job editor's fields use (hidden inputs keep their ids,
  so the save and open paths did not change), and per-page as a `makePicker`
  beside its siblings. Three native selects remain, all in the Security
  area's analysis launcher, which the next phase restyles wholesale.

- **An untouched job editor no longer claims to have unsaved changes while
  its precheck script loads.** The clean snapshot was taken before the
  "loading…" placeholder went into the script field, so for the length of
  that fetch — indefinite on a hung backend — Escape and Cancel asked
  "Discard your changes?" over edits that never happened. An operator taught
  to click through that prompt clicks through it on the day it is true. The
  placeholder now goes in first. Also: the poll guard's scan gains
  `worktreesCard` (a direct call of `render()` it had missed), a new test
  pins that every dialog on the page is filed as either form-guarded or
  deliberately live, a stale comment stopped promising a flat tab strip the
  editor has not had for months, and two shortened help texts got their
  dropped hazards back (the stray-branch checkout trap, and
  `CLAUDE_CONFIG_DIR` with its keep-it-stable warning).

- **The effort level a project SAVES is read from the same list as the one it
  SHOWS.** Extracting the editors' vocabulary left the page with its own copy
  of the effort list, read by exactly one call site — the one persisting
  `proj.security.effort` — while the slider's label beside it read the
  canonical `CCApp.EFFORTS`. Both agreed today; the day one changed without
  the other, the user would confirm one effort level on screen and a
  different one would land in the config, silently. The save now routes
  through `effortGet`, the page's one path to the canonical list, the dead
  copy is gone, and a test refuses any `const EFFORTS` on the page so the
  count stays at one.

- **The favourite star on Projects shows its real state again.** The
  redesigned identity cell gained a rule painting its icon accent —
  `.jobcell .ic` — and the descendant selector also reached the star's icon
  nested inside the button. The star fills with `currentColor`, which reads
  the icon's own colour first, so both stars painted accent: filled,
  identical whether favourited or not, and clicking one changed the class
  but not a single pixel. One favourite looked like two, and the toggle
  looked dead. The rule now uses the direct-child combinator, and a test
  refuses the descendant form so it cannot come back.

- **The Runs page's own Warnings and Errors cards now count the same 7-day
  window the Overview's do, and say so.** The Overview's Warnings/Errors
  cards are a door into Runs (`initStatFilters`, `bin/dashboard.html`):
  click one and it lands on Runs' own cards of the same name, same icon,
  same box. The Overview counts the last 7 days and says so (`sub: "in
  the last 7 days"`); Runs counted ALL of `CC.DATA.runs` — the server's
  own 1000-row cap (`bin/claude-cron-server`'s `LIMIT 1000`), far more
  than 7 days at any real job count — and said "N% of finished runs",
  naming no window anywhere on the card. Three warnings from today and
  forty from a month ago read "Warnings 3 / in the last 7 days" on the
  Overview and "Warnings 43" one click later, on the page the door itself
  leads to. `runsKpis` (`ui/app/runs.js`) now filters to the identical
  `Date.now()/1000 - 7*86400` cutoff `render()` (`bin/dashboard.html`)
  already computes against this same `CC.DATA.runs` for the Overview, with
  a matching `sub` and a `title` naming what each counts.
  `test_the_overview_and_runs_warning_cards_name_the_same_window`
  (`tests/test_page_contract.py`) reads both card builders out of the
  built bundle and pins their `sub` text to agree. Separately, "Total
  runs" gained the same honesty: at the server's own 1000-row cap the true
  total is unknown, so it now reads "1000+" rather than a precise-looking
  number that is actually a floor.

- **Starring a project on the Projects page fills its own star
  immediately, instead of up to 5 seconds later.** `toggleFav()`
  (`bin/dashboard.html`) updated the `favorite_projects` preference and
  repainted only Jobs (`renderJobsArea()`) — a star clicked on the
  Projects page itself stayed unfilled, `aria-pressed="false"`, until the
  next poll's `render()` got around to it, long enough to invite a second
  click that silently undoes the first. It now also calls
  `CCApp.renderProjectsPage()`.

- **A long project name ellipsises instead of hard-clipping mid-word, on
  both Jobs and Runs.** `.projtag`'s own truncation rule
  (`ui/css/pages.css`) targeted `#jobrows`, an id `tableCard()`
  (`ui/app/chrome.js`) has not built since Phase 2 Task 3 moved the Jobs
  table's tbody there — it matched nothing, on either table, and a name
  like "Revenue Learning Platform" read as "Revenue Learning Platf" against
  the table-card's own defense-in-depth `overflow:hidden` instead.
  Retargeting the rule alone was not enough, confirmed by actually
  rendering it: `.projtag` is `display:inline-flex` (for the icon/name
  alignment), and `text-overflow` has no effect on a flex container's own
  box, only on a block one. The project name now sits in its own inner
  span, `.projtag-name` (`ui/app/jobs-table.js`, `ui/app/runs.js`), which
  is what actually ellipsises; its icon carries `flex:none`
  (`ui/css/components.css`) so a long name shrinks only the text, never
  distorts the folder icon beside it.

- **The Security column no longer hides behind Projects' own row actions,
  and the Projects KPI cards say what their numbers mean.** `PRJ_COLS`
  (`ui/app/projects.js`) grew a seventh column (Security) and `ui/css/
  pages.css`'s own `#view-projects` width rules were never updated to
  match — five `nth-child` rules plus `th:last-child` already summed to
  100% without it, so the new column had no width rule at all. Under
  `table-layout:fixed` that computes to a hair over 0px, not "whatever is
  left" (confirmed live: `getBoundingClientRect()` on the Security `<th>`
  read 0.03px), and the pill inside it — `white-space:nowrap`, nothing of
  its own to clip it — spilled rightward into the actions column, landing
  on top of the row's own edit/delete buttons. Every `#view-projects`
  column now has a real declared width (`min-width` moves to 1000px,
  matching `#view-jobs`, since a 900px floor sized for six columns never
  had to fit a Security pill), and `.table-card td,.table-card
  th{overflow:hidden}` is added so the same class of mistake — a column
  added to Jobs or Runs later with its own width rule forgotten — degrades
  to a clipped cell rather than one element hiding behind another. Jobs
  itself was never affected: its eight columns already had eight matching
  width rules summing to 100%, checked and confirmed live before touching
  anything. Separately, the "Jobs organised" KPI's sublabel no longer reads
  "4.0 per project" for an exact integer average — `Math.round(ratio *
  10) / 10` replaces `.toFixed(1)`, so the trailing zero only survives
  when the average genuinely has a fractional part. And the "Isolated"
  KPI's sublabel no longer says "none set to never" while the headline
  number counts an entirely different isolation state (`always`) — it now
  names whichever of the other two states (`never`, then `auto`) is
  actually nonzero, so the pair reads as one fact instead of two
  unrelated ones.

- **`ui/app/overview.js`'s banner no longer describes a layout the file does
  not have.** `pageHeader` and `kpiCard` moved out to `ui/app/chrome.js`, and
  three pointers stayed behind: the banner still listed both among the things
  defined below it, and two comments sent a reader to `kpiCard`'s explanation
  without saying which file now holds it. The comments in this file carry the
  reasoning behind its isolation rule and its deliberate duplications, so one
  that misdescribes the file's own shape costs more than no comment at all.

- **The Overview's job groups no longer butt up against the 24-hour band.**
  The band's panel carried no bottom margin, because until this redesign it was
  the last thing in the Overview's top block and nothing sat below it to clear.
  With the job cards moved directly beneath it, the two touched. It now carries
  the same 20px section gap the KPI grid above it already used.

- **Filtering the Overview down to "Standalone" no longer drops the
  "Standalone jobs" group header.** `groupJobs(jobs, favSet)`, extracted
  from `renderJobCards` one commit ago, only ever saw the already-filtered
  job list, so its "none of these jobs carry a project → no groups" rule
  fired for the Standalone filter itself — the one view guaranteed to make
  every visible job project-less — and the header, its folder icon, its
  count and its per-group bulk-toggle button vanished into a bare grid on
  any install with more than one project. `groupJobs` now takes the
  install's unfiltered project list as an optional third argument;
  `renderJobCards` passes its own `allProjects`, so the standalone group
  still gets built when the install has projects elsewhere even though the
  current view does not. Omitted, the third argument leaves the original
  two-argument behaviour untouched — the three characterisation tests
  pinning that shape were not changed.

- **A dark-mode user no longer sees a white flash on every load.**
  `applyTheme(themePref())` ran in the script at the end of the body and read
  `localStorage`; until that ran, the CSS sat in its light default. With 6,725
  lines of page and a 93 KB bundle ahead of it, that first frame painted light
  regardless of the stored preference, then snapped to dark once the body
  script finally reached it. Three lines now run in the `<head>`, ahead of the
  render-blocking stylesheet, setting `document.documentElement.dataset.theme`
  before anything can paint. `themePref()` now reads that attribute back
  instead of restating "localStorage, else the media query" a second time —
  two copies of one preference rule would eventually disagree, and the page
  would then correct a correct first frame to the wrong theme.

- **The UI bundle's modified-body guard can no longer be defeated by a
  single crafted line.** The previous commit moved both freshness stamps
  from `//` line comments to `/* … */` block comments so a CSS artifact
  could carry them too — but a block comment can be closed and reopened
  mid-line, which `//` cannot. One physical line shaped
  `/* ui-bundle: <real hash> */<injected code>/* ui-bundle: <fake hash> */`
  counted as exactly one stamp, so the "more than one is refused" check
  never fired, and the greedy pattern that stripped stamps before hashing
  deleted that whole line — injected code included — leaving a tampered
  `bin/static/security.js` hashing byte-identical to the untampered one and
  the selftest reporting it clean. `build/ui-bundle-digest.sh` and the
  selftest's own reads in `bin/claude-cron` now anchor the captured value to
  the fixed SHA-256 shape, `[0-9a-f]\{64\}`, in place of `.*`: a line
  carrying anything beyond those 64 hex characters no longer matches the
  stamp pattern at all, so it stays in the body and the ordinary
  hash-mismatch branch catches it instead. Said plainly: for one commit, a
  freshness guard whose entire purpose is to catch a modified build
  artifact could itself be defeated by a one-line edit.
  `build/ui-bundle-digest.sh` is itself one of the files `build/ui-digest.sh`
  hashes into the bundle's `ui-sources` fingerprint — it decides what the
  *other* stamp means, so a change to it has to read as "stale, rebuild"
  rather than surfacing one command later as "this bundle has been
  modified" — so the committed `bin/static/security.js` is rebuilt in the
  same change; only its `ui-sources` stamp moves, since no source under
  `ui/` changed and the bundle's own body is byte-for-byte the same.

- **A changed stylesheet is no longer served out of an open tab's cache
  forever.** Every asset under `bin/static/` is requested with
  `?v=<build id>`, and the build id is derived from the bytes of the files in
  that directory — but it globbed `*.js` alone, from when the Security bundle
  was the only thing there. A stylesheet is about to join it, and one that
  cannot move the id is one a running dashboard never picks up: no reload
  clears it, because the URL never changes. The fingerprint now reads
  `STATIC_TYPES`, the same table that decides what this route may serve at
  all, so a third asset type added there is covered without anybody
  remembering to come back.

- **The UI bundle's freshness guard can now detect a MODIFIED bundle, not
  only a stale one.** `bin/static/security.js` is a build output committed to
  git — the price of never needing Node to install claude-cron — and
  `claude-cron selftest` is what is supposed to stop a bad one shipping.
  Nothing hashed the committed bytes: code injected straight into the bundle,
  with every source and every toolchain file untouched, passed the check
  without a word. And the stamp saying what it was built from was read with
  `tail -1`, so appending a second `// ui-sources:` line carrying a freshly
  computed digest satisfied the check while the real stamp sat ignored one
  line above it. The honest-mistake case (edit `ui/`, forget to rebuild) was
  always caught; the case the guard's own sentence claims to prevent — a
  committed artifact that does not match anything anybody wrote, which is what
  a mangled merge conflict inside a 90 KB generated file looks like — was not.
  The bundle now carries a hash of its own body — computed by a new
  `build/ui-bundle-digest.sh` and stamped as `// ui-bundle:`, alongside the
  existing `build/ui-digest.sh` source fingerprint's `// ui-sources:` — the
  selftest recomputes both, and a stamp that appears more than once is
  refused rather than resolved by picking one.
- **The source fingerprint covers what the build actually reads.** It hashed
  `ui/**/*.js` only, while esbuild follows whatever `ui/security/index.js`
  imports and resolves `.ts`, `.tsx`, `.jsx`, `.json` and `.css` just as
  readily — so a shared `.json` or a stylesheet could change the committed
  bytes without changing the digest describing them. It now covers every file
  under `ui/`. It also streamed each file as `path` + raw bytes with no
  boundary between them, so a file whose last byte is not a newline ran
  straight into the next file's path line and two genuinely different trees
  could fingerprint identically; each file contributes a fixed-width digest
  now, which no content can imitate.
- **A file git is ignoring no longer reddens the selftest.** A stray
  untracked, ignored file under `ui/` — a scratch script, an editor backup, a
  `.DS_Store` — is not an input to anything and is in nobody else's checkout,
  yet it changed the fingerprint: the selftest failed over a tree `git status`
  called clean, and the only way out was to find and delete a file nothing had
  named. Untracked-and-ignored paths are now skipped; a *tracked* file can
  never be dropped, whatever an over-broad ignore pattern says about it.
- **The Security index's KPI cards and its own project table no longer
  describe different branches.** The cards summed each project's posture with
  no preferred branch handed in, so they *always* took the fallback path —
  "the latest finished analysis of this project, whatever branch it is on" —
  while the table three inches below honoured the project's declared base. A
  project whose base branch (`main`) stopped early holding one high finding,
  with a later clean analysis on `develop`, read "High 0" on the card and
  "High 1 · incomplete" in the row underneath it, and the card's own
  undercount warning never fired because it had resolved a different branch's
  state. Both halves are now handed the identical project records, so they
  pick the same branch by construction. The cards also say when a total was
  read off a branch nobody declared — the table has always named that per
  row, and a fallback branch is never silent in this area.
- **The Branches tab can say a branch's last analysis stopped early.** It is
  the one screen whose entire purpose is per-branch posture, and it was the
  only posture surface in the product that could not express `capped`: the
  rows admitted `done` and `capped` alike and then carried no state, so a
  partial read presented as a finished one, and the 30-day trend line would
  say "falling" off a run that simply ran out of room before finding
  anything. Each row now carries a "Last state" column and the same
  `incomplete` badge the index table uses, and the trend line refuses a
  direction word across a partial point instead of inventing one — the
  recorded numbers still show, since they are what was recorded.
- **The Findings tab no longer shows a green all-clear for a project nobody
  has ever analysed.** The payload carried no never-analysed signal at all,
  so an empty result rendered as an ok-green "nothing matches" beside "0
  total" and the table blamed filters the reader never set — over a project
  with no analysis behind it whatsoever. It now draws the same three-way
  distinction the Overview and Branches tabs already draw (never analysed /
  attempted but nothing finished / genuinely empty), in the same words.
- **"Earlier analyses of this branch" lists the branch you are looking at.**
  It filtered on the repo/branch *picker* at the top of the screen rather
  than on the analysis actually on display, so opening a `develop` run from
  the Runs table (or following the Activity screen's deep link into one)
  while the picker still said `main` printed "develop" in the status line
  over `main`'s history. And the 4-second poll recomputed what to show from
  that same picker, so a deliberately opened analysis was swapped out from
  under the reader within four seconds of arriving. The history follows the
  analysis on screen; the poll refreshes a deliberately opened analysis by its
  own id instead of replacing it, and still follows the branch's newest one
  whenever nobody has chosen otherwise.
- **The severity floor's scope is stated where the unfloored numbers are.** A
  project's `min_severity` narrowed two surfaces (the single-analysis
  checklist and the findings table) and was ignored by six (Overview chips,
  the index KPIs and posture pills, the Branches tab's "Open", both donuts) —
  and only the two that applied it said anything, so the drill-down of an
  analysis could show fewer findings than the panel above it with nothing on
  screen explaining why. The decision, now written down and said once per
  screen: the floor is a **drill-down reading aid** and never narrows a
  posture total, because a recorded finding below somebody's triage threshold
  is still exposure and a security total that quietly dropped it would be
  under-reporting.
- **Numbers that answer different questions say which one.** The findings
  strip's per-severity pills are *rows* and the sidebar donut's are *distinct
  fingerprints* — identical markup, on screen together (the sidebar is a
  sibling of the tab panes, not part of them), and only the strip's
  `total`/`unique` pair was labelled. Both sets now name their own scope. The
  index's "Success rate" card, an all-time ratio sitting between two cards
  that say "open now", is labelled "All time" the same way its neighbour
  "Analyses" already was.
- **Smaller things on the same screens.** "Never analysed" had six near-
  variants across four modules, three of which told you what to do next and
  three of which did not — one wording now, at two densities, so every
  occurrence names the next step. The donut's `info` segment was painted the
  same colour as its own empty track, invisible while the legend listed its
  count. "Lines of code: —" now says the dash means "not counted", not zero.
  The Activity screen's fingerprint dialog is titled by its project, so the
  title cannot outlive the filter it used to name after "Clear filters" drops
  it. And the index donut and the findings strip carry the partial-read
  caveat the cards and rows beside them already did.
- **`security decide` refuses a fingerprint that is not a finding's
  identity.** There was no shape check anywhere — not at the CLI, not at the
  route, which only tested for non-empty. A malformed value ("aws-key in
  prod.env") wrote a decision row *and* a `decision_made` event, so the
  Activity screen told the operator the risk had been accepted while the
  finding stayed open on every other screen, because nothing can ever match
  that identity. Both doors now enforce the 64-hex shape `report-finding`
  has always enforced on a written fingerprint.
- **`security finish --note` is held to the same credential check the rest of
  an analysis's free text is.** `--note` lands in `coverage_note`, reaches all
  four report formats and the analysis page, and is deliberately reachable by
  the agent — closing the row is the one thing that must always work — yet it
  was the only agent-writable free-text channel with no `looks_like_a_secret`
  gate on it, while its near-identical twin `partial_note` had one. A live
  AWS key written there travelled straight to the report you hand someone
  else. It is now refused before anything is written, with the same message
  that names the field and the rule and never echoes the text back.
- **The audit trail prints the state word a reader sees.** A decision's event
  detail was built from the raw token, so Activity showed
  `false_positive: duplicate…` where every other screen in the area shows
  "False positive".
- **The security skill lists all six verbs the door refuses mid-run.** The
  README had been updated to the full set; the skill — which is what the
  *agent* reads — still named three, so an agent reaching for `event`,
  `filters save` or `filters delete` met a hard exit its own instructions
  said could not happen. A test now pins the skill against the refusal tuple
  itself, in both directions, so the two cannot drift again.
- **The two posture rollups no longer accept a time window they never
  applied.** `queries.severity_totals` and `queries.top_categories` took a
  `days=30` parameter, ignored it completely, and were never passed one by
  either caller — a signature promising a filter the body does not apply,
  which is worse than no parameter at all: the first person to write
  `days=7` would have got an all-time answer that looked like a weekly one,
  with nothing failing to say so. It came from a mockup panel captioned
  "Findings overview (30 days)", and that caption was the mistake, not the
  missing code. A **posture** number answers "what is open right now" and is
  as-of-now by construction — it is read off each branch's *latest finished*
  analysis, whether that ran an hour ago or last spring, and a critical
  finding does not stop being open because nobody re-analysed the branch this
  month. Windowing it would not narrow the answer, it would drop quiet
  branches out of it and report them clean. The parameter is gone rather than
  implemented, pinned by a test that fails if it comes back, and no caption on
  any of the four screens ever claimed a window for these panels — the ones
  that do have windows (`trend`'s 30-day series, `activity_summary`'s period
  chips) keep their `days`, because both of them use it.

- **`report-finding` now refuses a title, rationale, remediation or
  partial_note that contains something shaped like a live credential.** The
  deterministic categories cannot leak a secret's value by construction — the
  `occurrence` table has no column for it, `secrets.py` never returns matched
  text, `secret_fingerprint` takes no value argument — but a SAST finding's
  free text was validated for shape only (required keys, severity in the
  allowlist, length under `MAX_TEXT`), never for content. Nothing stopped an
  agent from writing a matched AWS key or GitHub token straight into a
  rationale; the only thing that ever did was a sentence in the skill telling
  it not to, in exactly the scenario the feature exists for — an agent
  reading a repository whose contents it does not control. A new
  `secrets.looks_like_a_secret` reuses the scanner's own `_RULES` (one home
  for the patterns, not a second copy) and its placeholder gate, so a
  described placeholder like `password = "changeme..."` still passes; a
  field that matches is refused before anything is written, naming the field
  and the rule and never echoing the text back, and the skill now says the
  fix is to describe the credential, not quote it.

- **A malformed or pathological JSON body on stdin now exits with a sentence
  instead of a traceback.** Both `security report-finding` and `security filters
  save` read JSON from stdin; a deeply nested structure used to raise
  `RecursionError` uncaught, printing a raw Python traceback with exit code 1,
  while the module's own docstring promises "every failure here exits non-zero
  with a sentence on stderr". Both verbs now read stdin as text first, refuse
  bodies over 1MB (far beyond any real finding or filter, but small enough that
  nothing pathological gets as far as the parser), and catch `RecursionError`
  alongside `ValueError` when parsing, exiting with a sentence rather than a
  traceback.

- **Filing a security event could fail the thing it was filing.** `record_event`
  ran unguarded at its three literal-kind call sites, and `security.db` is
  shared across every project with the default 5s busy timeout — a lock
  contention hiccup writing `analysis_started` used to propagate as an
  unhandled traceback with no stdout, *after* the `running` row was already
  committed. `cmd_security_analyze`'s `| jq -r '.analysis_id'` then read empty
  and died with "could not open an analysis", leaving the ledger holding a
  row for an analysis that, in fact, had opened. The three sites now catch
  `sqlite3.Error` only — a genuine programming error (an unknown kind) still
  raises.

- **The agent could write its own entry into the audit trail.** `security
  event` — the standalone verb that writes into the ledger's record of what
  happened — was reachable by the agent under review. Nothing in its skill
  ever told it to call it, and both audit-worthy things the agent causes were
  already filed as side effects (`analysis_started` by `open-analysis`, which
  it cannot call; `analysis_finished` by `finish`, which files the event
  itself) — so a forged `settings_changed` or `decision_made` had nothing
  legitimate behind it and would have corrupted the one artifact whose whole
  purpose is to say what actually happened. `event` now joins `decide`,
  `rename-project` and `open-analysis` in the set CC_SECURITY_AGENT refuses;
  `events` (read-only) stays open.

- **A report download's audit event no longer pays for a full checklist.**
  Filing `report_exported` under the right project used to call `security
  checklist` purely to read `analysis.project` — which runs two
  `findings_of` calls, a `latest_analysis` query, a history query across
  every prior analysis and `decisions_for`, all to answer one string. A new
  read-only verb, `security analysis --id N`, prints just the row.

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

- **A disabled job no longer paints as a failure on the Overview or the Jobs
  table.** `.pill.off` carried two unrelated meanings at once: "the
  scheduler service is not loaded" (a real fault, red) on the topbar's
  launchd pill, and "nobody switched this job on" (a choice, not a fault)
  on the job card and the Jobs table's state pill. On an install with
  several jobs disabled, the Overview read as a wall of errors — eight
  disabled jobs, eight red pills. The job card (`ui/app/overview.js`) and
  the Jobs table (`bin/dashboard.html`) now resolve a disabled job to a new
  `.pill.disabled` class, styled grey — the same panel/muted treatment
  `.sevpill.low`/`.sevpill.info` already use for "not urgent" elsewhere on
  this page — while `.pill.off` (red) stays reserved for the one place it
  is genuinely a fault, the launchd pill. `.pill.idle` (amber, enabled but
  outside its active window) is unchanged. A new test,
  `test_the_job_disabled_pill_and_the_launchd_off_pill_use_different_classes`,
  reads all three pill ternaries from source and fails if a future edit
  ever reunites the job-disabled class with the launchd-fault class.

### Changed

- **The Overview's own arithmetic — the five KPI numbers, the band's empty
  states, the probe's three verdicts, the spend bar's two thresholds,
  favourite-first project grouping, the two "no jobs" emptinesses, and what
  the backoff/window note says — moved out of `pulseHtml`, `jobCard` and
  `renderJobCards` into seven pure functions in a new `ui/app/overview.js`
  (`pulseKpis`, `bandEmptyReason`, `probeVerdict`, `spendTone`, `groupJobs`,
  `jobsEmptyNote`, `nextRunNote`), reached from the page as
  `CCApp.pulseKpis` and so on.** Ten characterisation tests pin exactly what
  each one says today, ahead of a redesign that rebuilds the KPI panel into
  cards and the job card from an HTML string into DOM nodes — the point of
  pinning it first is that neither rebuild can silently change a number, a
  verdict or an empty-state sentence on the way. Two of the seven
  (`probeVerdict`, `nextRunNote`) return DOM nodes built with
  `createElement`/`createTextNode`, the same rule `ui/security/`'s screens
  already follow, and the renderers that still build HTML strings splice
  them in with a serialised copy of the node. `groupJobs` folds
  `renderJobCards`'s per-vis "no projects → flat grid" check into its own
  "none of these jobs carry a project → no groups" one, which is almost the
  same rule but not quite: filtering a multi-project install down to
  Standalone only used to render a "Standalone jobs" group with its own
  header chrome, and now falls back to the same flat grid an install with
  no projects at all gets — a group header lost, not a job hidden, and
  narrower than what was there before on purpose rather than by accident.

  Folded into the same change: `backoffMultiplier` was a `const` arrow
  sitting above `CCApp.init`'s interface object rather than below it, so —
  unlike `activeRunsOf`, converted away from the same shape one commit ago
  because it genuinely sat below its own use point and threw — this one
  never had a live temporal-dead-zone error. What it did have: a `const`
  arrow here worked only because of where it happened to sit in the file,
  and moving this helper block down, or moving `init` up as boot sequencing
  gets consolidated in a later phase, would have reintroduced the identical
  error. It is now a hoisted `function` declaration too, closing that
  dormant, order-dependent fragility before it could bite rather than
  fixing a live bug.

- **The jobs domain moved out of `bin/dashboard.html` into `ui/app/`, bundled
  into a committed `bin/static/app.js` the same way `ui/security/` becomes
  `bin/static/security.js`.** `jobFacts` (state, next run, budget cap,
  backoff) and `visibleJobs` (the toolbar's filtered set) are read by both the
  Overview's job cards and the Jobs table that a later phase adds as their
  second consumer — moving only the Overview's screens now would have left
  that arithmetic duplicated until the table followed, the exact
  drifting-vocabulary defect this branch has already paid for twice, so the
  whole domain moves in one piece instead. `bulkOn`, `bulkLabel`,
  `clearJobFilters`, `jobProjectNames`, `nextCheckAt` and `inWindow` travel
  with it. The three separate `jobProjectFilter`/`jobStatusFilter`/`jobQuery`
  module-level bindings become one exported `jobFilters` object — three
  `let`s can only cross a module boundary as three getters and three setters,
  where an object is read and written through one reference from either side,
  which is what the page's toolbar and the moved `visibleJobs` both need. The
  page states what it hands the module in `ui/app/page.js`, the same
  interface contract `ui/security/page.js` already keeps: a name missing from
  that list is a bind-time failure naming itself, not an `undefined is not a
  function` three screens later. Without this move, the Overview's redesign
  in the next phase would have had to choose between reading the arithmetic
  out of a page it no longer draws, or copying it — paying the same
  duplication cost from the other direction.

- **The dashboard's stylesheet moved out of `bin/dashboard.html` into
  `ui/css/`, and no rule's text changed.** 1415 lines and 789 rules that used
  to sit in a `<style>` block are now three files — `tokens.css` (the two
  `:root` blocks), `components.css` (the shared vocabulary: page header, KPI
  stat line, filter bar, table card, pager, pills, buttons, tabs, the
  project-screen right rail, plus the generic element rules) and `pages.css`
  (everything that names one page or one dialog: the shell, the job cards,
  the pulse panel, every dialog, every `@media`/`@container` query) —
  concatenated in that order by `build/build-ui.sh` into a committed
  `bin/static/app.css` and linked from the head with `?v=<build id>`. Not
  bundled: the stylesheet has no imports, so esbuild would buy nothing and add
  a minifier's opinions to a diff that should stay readable. The move is
  proven mechanical by `test_no_class_the_shipped_ui_uses_lacks_a_css_rule`,
  checked against the *built* artifact rather than the sources: every class
  the shipped UI reaches for must have a matching rule in `bin/static/app.css`,
  so a rule that lands in a file the build forgets to concatenate — or is
  dropped outright, in this move or a later one — still fails the test.
  Without this split, later restyling of the
  dashboard's Overview and any new shared component would have meant editing
  one 1400-line block that mixed tokens, reusable widgets and one-page layout
  with no seam between them. The selftest's freshness check — was this artifact
  built from the sources sitting next to it, and does its own body still hash
  to its own stamp — is now a `check_ui_artifact` function called once per
  artifact instead of carried inline for `bin/static/security.js` alone; written
  out a second time for `app.css` it would have been a second place for the
  next fix to reach only one of.

- **Build artifacts carry one stamp form, valid in JavaScript and CSS
  alike.** The two freshness stamps every committed artifact carries — what
  it was built from, and what it is — were written as `//` line comments,
  which CSS has no equivalent of. With a stylesheet about to be built into
  `bin/static/`, the alternative was a line form for one language and a block
  form for the other: two spellings for `build/build-ui.sh` to write,
  `build/ui-bundle-digest.sh` to strip and the selftest to parse, and one of
  them to forget on the next artifact. Both now use `/* … */`. The
  exactly-one-of-each rule — what stops a freshly computed stamp being
  appended below the real one and read instead of it — carries over unchanged.

- **The README documents the Security area that now exists, not the one it
  shipped with.** The section described a single project list and a single
  analysis; it now covers the four screens and what each answers, that every
  number on them is *current posture* rather than an all-time sum, and the two
  definitions a reader cannot guess: **open** is every state that is not
  `fixed`/`accepted`/`false_positive`, so it includes `pending` — a finding
  nobody re-checked is exposure nobody closed — and **success rate** is `done`
  over finished (`done` + `capped` + `failed`), with a dash rather than `0%`
  when nothing has finished. Also newly written down: the `info` severity and
  the one deterministic rule that emits it (a repository with no `.gitignore`),
  and that it sits below every floor the editor resolves to on its own until
  you lower `min_severity` to **Info**; lines of code, counted as a by-product
  of the deterministic walk and shown as a dash when an analysis never counted;
  the event log's five kinds and why it has **no user column and no IP column**
  (one operator, enforced by `app.db`'s `CHECK (id = 1)`, and a loopback-only
  server); saved filters; and **the build** — `ui/` is the source,
  `bin/static/security.js` is the committed bundle, `bash build/build-ui.sh`
  must run in the same change as any UI edit, and `claude-cron selftest` is the
  enforcer, named in the README by the assertion it prints. Two things the
  section had gone stale on are corrected rather than left: the checklist table
  listed seven states and omitted `pending` entirely, and the list of verbs an
  analysis run refuses to the agent had not grown with `event`, `filters save`
  and `filters delete`. Documentation drift of that kind is not cosmetic here —
  the README is the only description of this area anybody outside the
  repository reads.

- **The Security area moved out of `dashboard.html` into `ui/security/`, and
  nothing it does changed.** The page was 7,333 lines with the whole app in one
  `<script>`; the Security area was 874 of them, with four more screens still
  to come — all of which have since landed, elsewhere in this same section.
  It is now fifteen ES modules bundled by a pinned esbuild into
  `bin/static/security.js` and served by a new `/static/*` route, by a new
  `package.json` (`esbuild` as its one `devDependency`, and a `build` script
  that is just `bash build/build-ui.sh`) added alongside them — the same
  script has to run in the same commit as any edit under `ui/`. **The bundle
  is committed**, so installing claude-cron still needs only jq, python3 and
  curl — Node is a developer dependency, and the day it becomes an install
  dependency is the day this stops being worth it (`node_modules/`, a build
  input and nothing else, is a new line in `.gitignore`). `claude-cron
  selftest` refuses a bundle whose sources have moved on — `package.json`
  itself counts as one, since it decides what the build produces as much as
  anything under `ui/` does — a stale committed bundle is a dashboard
  silently running last week's code, with nothing on screen to say so. What
  the area used to read out of the page's scope — `DATA`, `$`,
  `toast`, `api` and eleven more — is now one stated interface object the page
  hands in, with `DATA` and `currentView` read through getters because both are
  reassigned while the page runs and a copy of either would freeze the area on
  an empty dataset and the startup view. The page-contract scan followed the
  code out: left pointing at the block it used to read it would have gone on
  passing while watching nothing, which is how a guard becomes decoration.

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

- **The Overview's greeting line, three loose tiles and a footer strip become
  a page header and five KPI cards; the 24-hour band takes the width they
  leave behind.** `pageHeader({icon, title, subtitle, actions})` and
  `kpiCard({icon, tone, value, label, sub, filter})`, DOM builders added to
  `ui/app/overview.js` alongside the pure functions Task 6 pinned, replace
  `pulseHtml` and `helloHtml` outright — along with `tickTotals` and
  `pickLine`, the two functions Task 7 left behind because nothing still
  called them standing alone. Both builders are written generically —
  nothing in either assumes it is drawing the Overview — because Phases 2
  and 3 put one of each on every remaining page. The ten characterisation
  tests pinned earlier
  in this phase hold across the rewrite unedited: the five numbers still come
  from `pulseKpis`, and Warnings/Errors still carry `data-statfilter` into a
  card that is a real, clickable `<button>` when its count is nonzero and a
  disabled one when it is not — the exact door behaviour a chip used to
  provide with a `title` attribute nobody could discover without hovering.
  Every card, and the band's own bars and axis, are built with
  `createElement`/`createTextNode`; a repository name or a branch containing
  `<img onerror=…>` was never a real risk here, but the discipline that
  stopped it being one anywhere else in this app now covers `ui/app/` too.
  What it cost not to have this: a card was free to grow a second number
  beside its first because nothing said it could not — the "one number per
  label" rule this design exists to enforce is the fix for a mistake six
  cards had already made once, in an earlier phase of this project, before
  it was written down as a rule rather than a habit.

- **A controller's visual pass on the KPI cards Task 8 shipped caught three
  things the tests and review could not see.** (1) The card's first line
  paired the icon with the LABEL, not the number — every card led with its
  caption instead of the value the eye is meant to land on beside the icon.
  `kpiCard` now puts the icon square and the number on that first line, the
  label beneath, the sublabel beneath that; the type scale (27px/700 number,
  13.5px/600 label, 12.5px muted sublabel) is unchanged. (2) All five cards
  rendered as `<button disabled>` on a quiet install, greying out Checks/
  Woke a run/Spent today as if the page were broken — three cards that have
  no `filter` and never will, and were never doors into Runs. `filter`
  alone cannot say so: it is empty both for a card that never navigates and
  for a door (Warnings/Errors) whose own count happens to be zero.
  `pulseKpis` now hands every card a `door` flag (true only for Warnings/
  Errors, always, regardless of count) and `kpiCard` renders a non-door card
  as a plain, always-full-contrast, non-interactive element — never a
  `<button>`, never `disabled` — reserving `disabled` for the one case it is
  meant for: a door with nothing behind it. (3) The `pulse-f` strip Task 8
  removed said "Today `<n>` runs `<$x>` · 7 days `<n>` runs `<$y>`";
  `pulseKpis` kept `spentWeek` as an input but returned an empty `sub` for
  "Spent today", so the week's spend was nowhere on the page. It is now that
  card's own sublabel (`"$41.02 over 7 days"`) — the "one number per label"
  rule applied to the pair it was always part of. The two run counts
  (`runsToday`/`runsWeek`) are deliberately left off every card: cramming
  either onto "Spent today" (a money card) or "Checks" (a probe count, not a
  run count) would misattribute the number to the wrong card, and every run
  stays one click away, in full, on the Runs page. Two tests guard this —
  `test_a_card_that_is_not_a_door_is_never_a_disabled_button` and
  `test_the_spent_today_card_carries_the_week_in_its_sublabel` — alongside
  the ten characterisation tests Task 6 pinned, all still passing unedited.

- **The job card — 164 lines of HTML-string concatenation, the last one left
  in the Overview — is rebuilt as DOM nodes, in `CCApp.jobCard(j)`.** The
  exposure this closes was real: `checkList` rendered the FIRST LINE OF AN
  ARBITRARY PROBE SCRIPT'S OWN STDOUT, and a job's id/description and its
  project's name all flow through from files an operator edits and Jira
  ticket titles. `esc()` held that safely before, by discipline; a `<li>`
  built with `createElement`/`createTextNode` holds it by construction —
  there is no HTML parser between a probe's output and the screen left for a
  crafted string to reach. `probeVerdict` and `nextRunNote`, the two DOM
  builders Task 6 pinned ahead of this exact rewrite, get their first real
  caller here. Every fact the string version showed still shows: the state
  pill, the probe verdict and its check-count panel, the 24h sparkline (plain
  `<i>` bars, the same mechanism `renderPulse`'s own band already draws with
  — this stylesheet has never had an SVG sparkline), the spend bar against
  the daily cap, the next-run note with its backoff multiplier, every kept
  session's own notice (a working Resume button, a "cannot be resumed"
  notice, or a "resuming…" badge, depending on which of three truths that
  run directory holds), and the run/enable/edit/delete/show-runs controls —
  unchanged, since every `data-op`/`data-menu`/`data-jobruns` a card carries
  is read by `bin/dashboard.html`'s one delegated click listener regardless
  of whether a real DOM attribute came from `.dataset` or from string
  concatenation. `renderJobCards`'s own grouping chrome (the collapsible
  project header, the star, the bulk button) stayed in the page: it builds
  markup from project names and counts the page already chose, never from a
  job's own fields, so it carries none of the exposure that moved `jobCard`
  out in the first place — `renderJobs()` now paints that shell via
  `innerHTML` as before and appends each group's real `CCApp.jobCard()`
  Elements into it in a second pass, found by the `data-group` attribute the
  shell already carried. `sessionLines`/`keptSessionsOf` became `jobCard`'s
  own `sessionNotices()`; `fmtExpiresIn` and `resumeInFlight` stayed in the
  page (the Sessions tab and `resumeTarget`'s own live-slot branch still call
  them directly) and joined `ui/app/page.js`'s stated interface alongside the
  new `effortLabel`, rather than growing a second copy of either.

  A visual pass caught one piece of drift the tests could not: `jobCard` was
  still computing `.st-run`/`.st-on`/`.st-idle` on the card's own left edge,
  three classes with no CSS rule behind them since an earlier commit in this
  redesign deliberately moved state onto the pill instead ("state is not on
  this edge any more" — see `.card.st-off`'s own comment in `ui/css/
  pages.css`). `test_no_class_the_shipped_ui_uses_lacks_a_css_rule`, new in
  this same change, caught it the moment the code doing this moved from
  `bin/dashboard.html` (which that scan does not read for dynamic classes)
  into `ui/app/` (which it does) — `jobCard` now only ever computes `st-off`,
  the one of the four with a rule still behind it. `probeVerdict` and
  `nextRunNote` also traded an inline `style.color` each for the matching
  `.s-success`/`.s-warning`/`.s-error` type-role class already shared by the
  Runs table's own status cells, rather than a second, unshared spelling of
  the same colour.

  Two new tests drive the rewrite: `test_the_job_card_is_built_from_nodes_
  and_shows_what_it_always_showed` builds a real card under Node from the
  shipped bundle and confirms it names its own job; `test_a_probe_line_
  containing_markup_stays_text` feeds `checkList` a line carrying
  `<img src=x onerror=…>` and confirms the markup survives as literal text,
  never as a tag. A third, pre-existing test — `test_a_job_card_shows_every_
  kept_session_honestly` — moved with `sessionLines` into this same DOM
  shape rather than staying pinned to a function that no longer exists.

- **The Overview's own tab strip is gone, and Worktrees stops being a tab
  that is always there to say there is nothing.** Jobs and Runs are already
  destinations in the sidebar; the three-button `#viewtabs` beneath the KPI
  cards and the 24-hour band reached the same two lists a second way, and
  was the one that could silently disagree with the sidebar about which was
  selected — `dashTab` and `currentView` were two separate pieces of state
  with nothing keeping them in step. `setDashTab`, `paintDashPanes` and
  `dashTab` are gone; `#pane-jobs`/`#pane-runs`/`#pane-worktrees` and their
  `paneblurb` paragraphs go with them — what each said is now that page's
  own header sentence (`CCApp.pageHeader`, new on the Jobs and Runs pages).
  The Overview's job cards render straight into `#jobs`. The Warnings and
  Errors KPI cards, and a job card's own "Show this job's runs" menu item,
  now call `setView("runs")` — the sidebar's real Runs page — instead of
  switching a tab that no longer exists. `jobstoolbar` and `runsblock`, the
  two blocks `relocate()` used to shuttle between a dashboard pane and their
  own page on every navigation, now live only on their own page; `relocate()`
  and the `slot-dash-*`/`slot-page-*` indirection are gone with the panes
  that made the shuttling necessary.

  Worktrees: a directory holding the only copy of some work is a thing to
  deal with; an install with none kept is not news, so `worktreesCard`
  (new, `ui/app/overview.js`) returns `null` on an empty list rather than
  rendering a permanent, usually-empty fixture. With something kept, it is
  a summary card — up to four directories with their sizes, right-aligned —
  and a footer button that opens the same table the tab used to show, now a
  dialog (`#wtmodal`) rather than a pane, since nothing else on the page
  needed it to be a whole tab away. `renderRetained()` is unchanged: it
  still targets `wt-blurb`/`wthead`/`wtrows` by id, regardless of which
  element contains them. Two new tests: `test_the_overview_has_no_tabs_of_
  its_own` pins the tab strip and its three buttons gone from the page;
  `test_the_worktrees_card_appears_only_when_there_is_something_on_disk`
  drives `worktreesCard` under Node, both on an empty list and on one
  retained directory. A third, pre-existing test —
  `test_the_sessions_tab_is_labelled_for_what_it_shows` — moved with the
  label from the tab to the card, the same "moved rather than left behind"
  treatment task 9's own job-card rewrite already gave
  `test_a_job_card_shows_every_kept_session_honestly`.

- **The Warnings and Errors KPI cards name their own time window even when
  there is something on them to read.** Both count the last 7 days and sit
  beside two 24-hour cards (Checks, Woke a run), directly above a band
  titled "Last 24 hours" — and their sub said "in the last 7 days" only in
  the empty sentence ("No warnings in the last 7 days"), dropping it exactly
  where an operator was reading a real count ("Runs that finished without
  failing but did not do the work — open them in Runs"). A run that failed
  on Monday and nothing since read, on Friday, as though it had happened
  today: the one neighbouring band that could have supplied the missing
  context is titled for a different window entirely. Both cards now say "in
  the last 7 days" at every count, not only at zero.
  `test_warnings_and_errors_name_their_window_when_there_is_something_to_read`,
  new in this change, pins it.

- **"Woke a run" no longer reads "— of checks" on a fresh install.**
  Extracting `pulseKpis` out of `pulseHtml` turned
  `checks ? pct(per.woke) + " of checks" : "—"` into
  `pct(per.woke || 0) + " of checks"`, unconditionally appending the
  " of checks" suffix that `pct()`'s own "—" was never meant to carry — so a
  quiet install with zero checks read "0 / Woke a run / — of checks", a dash
  with a dangling preposition, instead of the original's plain "—". The
  whole sub is a bare "—" again when there are no checks yet.
  `test_a_percentage_of_nothing_is_a_dash_not_zero_percent` is tightened
  from a substring check (`"—" in sub`, which the dangling text also
  satisfied and so never caught this) to an exact match on the card's own
  sub.

- **The Warnings and Errors KPI cards no longer grow taller than their
  neighbours the moment there is something to read.** The previous fix
  named the 7-day window at a non-zero count by splicing it into the middle
  of the cards' existing explanatory sentence — "Runs that finished without
  failing but did not do the work in the last 7 days — open them in Runs"
  (96 characters) and "Runs that failed in the last 7 days — open them in
  Runs" (55 characters) — which measured at 200px and 165px against a
  normal card's 130px, so the row of five went ragged the instant a
  warning or error existed. The sublabel now carries the window alone —
  "in the last 7 days", the same string whether the count is zero or
  not — and the definition of what a warning or an error IS moves to the
  card's own `title` attribute (a native tooltip), where a full sentence
  costs nothing. "open them in Runs" is dropped rather than moved: the card
  is already a button, and a disabled one already says there is nothing
  behind it. All five cards now render at the same height regardless of
  count — measured at 130px in both themes.

- **Swapping two committed UI artifacts used to pass the freshness guard
  clean.** `ui-bundle` hashed a built file's own body against itself with
  no mention anywhere of WHICH artifact that body was supposed to be, so
  `cp bin/static/app.js bin/static/app.css` left `app.css` holding
  JavaScript, byte for byte, under a stamp that verified perfectly — the
  digest was blind to the file's own name, and the body it was asked to
  check was, genuinely, the body that stamp described. A botched rebase or
  a copy-paste in `build/` swapping two outputs would have shipped a
  dashboard loading JavaScript as a stylesheet, rendering with no styling
  at all, while `claude-cron selftest` reported every artifact fine.
  `build/ui-bundle-digest.sh` now hashes the artifact's own basename ahead
  of its body, so a stamp only ever verifies against a file of the same
  name it was written for — `build/build-ui.sh` and `check_ui_artifact` in
  `bin/claude-cron` both delegate to this one script, so there is exactly
  one place that decides what "the artifact's own name" means rather than
  two call sites that could drift apart.
  `test_a_files_own_stamp_does_not_verify_under_a_different_name`
  (`tests/test_page_contract.py`) and a new `check_ui_artifacts()` case in
  `cmd_selftest` (`bin/claude-cron`) both reproduce the swap directly and
  pin the fix.
- **`el`, `pageHeader` and `kpiCard` move to their own file.** All three
  were written generically from the start — nothing in any of them assumes
  it is drawing the Overview — because Phases 2 and 3 put one of each on
  every remaining page; `ui/app/overview.js` was only ever meant to hold
  the Overview's own arithmetic and markup. Six pages importing generic
  builders out of a file named `overview.js` would have been a name lying
  six times over, so the three move to a new `ui/app/chrome.js` now, while
  `overview.js` is still the only consumer to update. No function body
  changed in the move; the characterisation tests that read these
  functions out of the built bundle's own source text still find them,
  since `_app_js` (`tests/test_page_contract.py`) concatenates every `.js`
  under `ui/app/` regardless of which file a function lives in.
- **The Jobs table's sort moves to `ui/app/jobs-domain.js`, pinned by five
  characterisation tests ahead of the redesign that rebuilds this table into
  a DOM module.** `renderJobTable`/`renderJobHead` (`bin/dashboard.html`)
  built the sort inline and declared the column map beside it; both are now
  `sortJobs(rows, key, dir)` and `JOB_COLS`, reached as `CCApp.sortJobs`/
  `CCApp.JOB_COLS` the same way the page already reaches `jobFacts` and
  `visibleJobs` in the same file — no comparator, tiebreak or `missing`
  predicate changed in the move. The five tests pin what the table already
  does, so neither this move nor the redesign that follows it can quietly
  change it: every column sorts as expected in both directions; a job that
  has never run, or a disabled job's absent "next", sorts to the BOTTOM of
  its column regardless of which way the arrow points, rather than reading
  as an extreme number; sorting by project keeps two jobs of the same
  project in the same relative order whichever way the column points,
  because the id tiebreak is deliberately applied outside the direction
  flip the comparator itself gets; the project, status and search filters
  narrow one set in sequence, so the three together can never show a job
  any one of them alone would have hidden; and the table's own empty row
  tells "no jobs exist yet" apart from "the filters left nothing", the same
  distinction `jobsEmptyNote` already draws for the card view.
- **The Jobs page speaks the Overview's visual language, and its table moves
  to `ui/app/jobs-table.js`.** A page header written from the real numbers
  (total jobs, projects, how many disabled) with Refresh and New job
  trailing right; four KPI cards — total, enabled, running now, spent
  today — each a plain element rather than a disabled button, since none of
  them is a door into anywhere else; the existing search box and the two
  project/status pickers, repainted rather than rebuilt; the same seven
  columns as before, now built with `el()` instead of an HTML string; and a
  footer reading "Showing X to Y of N" with a real pager, which the Jobs
  table never had at all before this. `renderJobTable`, `renderJobHead`,
  `paintJobFilters` and the branch inside the old `renderJobs()` that forked
  between the cards and the table all leave `bin/dashboard.html` for the new
  module; `initJobDrag` (drag-to-reorder within a project's cards) moves
  with it too, even though it still drags cards on the Overview, not this
  table's rows, because it is job-domain code rather than page furniture.
  The Overview's own card grid keeps its old logic under a new name,
  `renderOverviewJobs`, since the old `renderJobs` described a function that
  drew either the cards or the table depending on the page — a fork that no
  longer exists now that the table redraws itself.

  Two things the previous task's pins flagged, closed here: the table's own
  empty row used to duplicate `jobsEmptyNote`'s two sentences character for
  character in an inline ternary instead of calling it — it now calls it,
  same as the card view always has. The `state` column's id tiebreak
  reverses with the sort direction while `project`'s deliberately does
  not — a real inconsistency in `JOB_SORTERS` — is left exactly as pinned:
  `project`'s comparator is the one that matches its own stated intent
  ("stay A→Z whichever way the arrow points"), so `state` should eventually
  move its id fallback out of `cmp` and into its own `tie` to match it, but
  that is a deliberate follow-up, not a change smuggled into a restyle.
- **`ui/app/chrome.js` gains the three builders Projects and Runs will need
  too — `filterBar`, `tableCard`, `tableFooter` — and the Jobs table adopts
  all three, closing two divergences an inspection found in the previous
  task's own first pass.** The table's footer used to be a loose
  `<div class="pager">` sibling below `.tablewrap` — no border, no
  background, floating under the card instead of belonging to it — and the
  card's own corner radius was 12px where every other card in this
  language (`.card`, `.kpi-card`) is 13px. `tableCard()` now builds
  `.table-card > .table-scroll > table`, with the footer `tableFooter()`
  returns as a second child of the card rather than a sibling of it,
  separated from the rows by its own `border-top`; `.tablewrap` itself
  moves to 13px too, for free, for every one of its other users (Runs,
  Projects, the Sessions dialog, six `ui/security/*.js` screens). The
  toolbar's own search box and two pickers are no longer static markup the
  table's module reaches into by id and repaints in place — `filterBar()`
  lays them out into one `.toolbar` it builds, called once rather than
  every poll (`mountJobsToolbar()`, guarded), so the live search input is
  moved rather than rebuilt and never drops a keystroke an operator was
  mid-typing. The sort click and the pager click are still answered by
  `bin/dashboard.html`'s one existing delegated listener, unchanged — these
  three builders place the same ids and `data-` attributes it already
  reads, never a listener of their own, the same "markup carries the hook"
  split `pageHeader`/`kpiCard` already use. See
  `.superpowers/sdd/chrome-tablecard-report.md` for the three signatures
  and what was checked in Projects' and Runs' own still-unconverted markup
  before settling them.
- **Projects' own arithmetic — the per-project job count, and the
  three-state isolation read (always / never / automatic) — moves out of
  `bin/dashboard.html`'s `visibleProjects()` and `renderProjects()`'s own
  inline ternary into two pure functions in a new `ui/app/projects.js`
  (`visibleProjects`, `projectIsolation`), reached from the page as
  `CCApp.visibleProjects`/`CCApp.projectIsolation`, the same "table is the
  second consumer" reach `sortJobs`/`JOB_COLS` already have.** Four
  characterisation tests pin exactly what the Projects table already does
  today, ahead of the redesign that gives it the Overview's visual language
  and a new Security column: the Jobs column counts only the jobs that
  actually name a project, never the whole fleet; a favourited project
  (`groupJobs`, already in `ui/app/overview.js`) sorts first, and which
  project comes first changes with which one is starred, not a fixed
  position; the isolation read distinguishes "always", "never" and
  "automatic" as three genuinely different facts, where "automatic" is also
  what a project with no `worktree` block, or the literal config string
  `"auto"`, gets; and the search box reaches a project's description and
  working directory, not only the name it was set up under. The three
  module-level `prjSortKey`/`prjSortDir` and `PRJ_COLS`/`PRJ_SORTERS` stay
  in the page for now — Task 4's four tests are none of them about column
  sorting — and move with the rest of the table in the task that restyles
  it. The single `prjQuery` binding becomes an exported `projFilters`
  object, mirroring `jobFilters` for the same reason: an ES module cannot
  let an importer reassign a plain binding, only read and write through one
  shared reference.
- **Projects speaks the Overview's visual language, moves to
  `ui/app/projects.js`, and gains a Security column — the only new
  information this whole phase adds.** A page header written from the real
  numbers, four KPI cards (projects, jobs organised, security enabled,
  isolated), the existing search box repainted rather than rebuilt, the
  same six data columns built with `el()` instead of an HTML string, plus a
  seventh, and a footer with real pagination the table never had before
  ("Showing X to Y of N"). `renderProjects()`'s inline row markup and its
  `PRJ_COLS`/`PRJ_SORTERS`/sort state move whole into the new module, the
  same move `jobs-table.js` already made for Jobs; "New project" moves into
  the page header's own actions, the same move "New job" already made.

  The Security column distinguishes three facts, not two: disabled
  (`.pill.disabled`), enabled but never analysed (`.pill.idle`, "Never
  analysed"), and enabled with at least one analysis on record (`.pill.on`,
  "Analysed", with a "last analysed" timestamp). Reading `/api/config`'s own
  `security` block (enabled or not, nothing about outcomes) plus `DATA.runs`
  — already fetched every poll, and already correctly attributed to a
  project by the derived job's own `project` field — is enough to tell
  "never analysed" apart from "analysed" honestly, without a new fetch to
  the ledger-backed `GET /api/security/index`, whose per-call subprocess
  cost this page's 5-second poll has no business paying. What the column
  deliberately does NOT show is a severity or a finding count: a real
  project's most recent analysis run in this branch's own ledger said
  "success" while it had recorded 6 high and 33 medium findings, so a
  completed run's own status is not read as a stand-in for posture —
  showing it that way would have been this page's own version of the error
  the Security area already paid for once, absence read as proof. Seeing
  the actual posture still means opening the Security area.

- **The Runs table's own filter, search and sort arithmetic moves to a new
  `ui/app/runs.js` (`filteredRuns`, `SORTERS`), pinned by four
  characterisation tests ahead of the redesign that rebuilds this table into
  a DOM module — the largest of the three, and the last before that
  redesign.** `filteredRuns()` (`bin/dashboard.html`) merged live and
  journaled runs, filtered both by the picker/search state and re-sorted the
  result; it is now reached as `CCApp.filteredRuns(rf, liveRows, searchKeys,
  sortKey, sortDir)`, with the filter object (`RF`), the sort state and
  `RUN_COLS` all left in the page for now, unlike `jobFilters`/`projFilters`
  — RF has five fields read from four picker call sites apiece, around forty
  references in `bin/dashboard.html`, and none of Task 6's own four tests
  are about who owns that state, only what the algorithm does with it; it
  moves with the rest of the table in the task that restyles it, the same
  deferral Task 4 already made for `PRJ_COLS`/`prjSortKey`/`prjSortDir`. The
  four tests pin what the table already does: a filter (or a search) that
  narrows the visible runs below the page an operator is already on pulls
  `page` back to the last real one rather than leaving them looking at a
  page that no longer exists; the footer and the pager read the FILTERED
  count, never `DATA.runs.length`, so a filter that narrows the table to
  nothing still says so truthfully instead of claiming to show everything;
  a run the server's own search index matched purely by something its LOG
  said — sharing nothing with the query text in its id — still surfaces,
  because the client trusts that result set whole rather than re-checking
  names on top of it; and Duration and Cost sort independently, since the
  slowest run of a day and the most expensive one are rarely the same run —
  the two were once merged into one column, which silently dropped the cost
  sort entirely (the comparator still existed; no header could reach it),
  making the priciest run of a 25-row page unfindable. `normStatus`
  (`bin/dashboard.html`) joins `ui/app/page.js`'s shared interface for
  `SORTERS.status`'s own sake, the same "one implementation, reached from
  every caller" rule `eff`/`backoffMultiplier`/`activeRunsOf` already
  follow, rather than a second copy living in the new module.

- **Runs speaks the Overview's visual language and moves to
  `ui/app/runs.js`, closing out Phase 2.** A page header, four KPI cards
  (total runs, running now, warnings, errors), the existing search box and
  four pickers repainted rather than rebuilt (its placeholder already said
  what it has always done — "Search runs & log content…", reaching a run's
  log as well as its name — and stays exactly as it was), the same seven
  data columns built with `el()` instead of an HTML string, plus the footer
  and pager Runs — unlike Jobs and Projects before their own moves — already
  had, now rebuilt through `tableCard()`/`tableFooter()` the identical way.
  `RF`, the sort/page state and `RUN_COLS` — deliberately left in the page
  by Task 6 — move the rest of the way now, the same way `PRJ_COLS`/
  `prjSortKey`/`prjSortDir` finished moving in Task 5: the four Runs
  pickers' own `onPick` callbacks (still page-owned static widgets) now
  read and write `CCApp.RF.project`/`job`/`status`/`from`/`to` directly.
  `runKey` — one of several small helpers the moved row now reaches through
  `ui/app/page.js`'s shared interface — had to become a hoisted `function`
  declaration rather than a `const` arrow: `CCApp.init`'s interface object
  referenced it by name well above its own declaration, which a `const`
  arrow cannot survive (the exact temporal-dead-zone trap `activeRunsOf`
  and `backoffMultiplier` were already converted for, caught here live in a
  browser before it shipped — the whole reason this phase's own gate ends
  with looking at the page, not just running the suite). The "view log"
  button no longer carries a `data-log-id` attribute for the page's central
  click dispatcher to read; it calls the page's `openLog` directly instead,
  the same "reach a page-owned function directly when a static attribute
  is not enough" precedent `initJobDrag` already set for its own
  save-then-refresh round trip.

  **The log modal does not move.** `renderLog`, `paintLog` and `openLog`
  stay in `bin/dashboard.html`, unchanged, reached by the new module
  through the page interface. This is a deliberate decision, not an
  oversight: the modal is not a table, it is a terminal with live-tail
  scrolling, syntax highlighting and an input box, and turning its 191
  lines of HTML-string markup into DOM builders is a reimplementation of
  exactly the kind of component where behaviour goes missing quietly —
  a scroll-follow condition translated wrong, a lost `keydown` capture, a
  "live" state that drops mid-rebuild. It also renders whatever an agent
  wrote, which is untrusted input, so the HTML-parsing sink it uses to
  render that is worth removing on its own terms — with its own tests and
  its own falsifiability pass — not as a rushed sub-step of the largest,
  last task of this phase. Tracked as a task of its own; see the design
  spec's own note on why (`docs/superpowers/specs/2026-08-23-app-redesign-
  phase-2-tables-design.md`).

  `test_the_jobs_projects_and_runs_tables_declare_a_width_for_every_column`
  (renamed from its Jobs-and-Projects-only name) now also guards Runs'
  own eight columns — `#view-runs` gained its own `table-layout:fixed` and
  a width rule per column in `ui/css/pages.css`, the identical shape the
  Security column's own missing rule broke Projects with once already.
  `clearRunFilters`, read before moving as this task's own first step,
  turned out to be 6 lines doing one job (reset every filter, the two date
  inputs and the search box, then re-run the now-empty search) — not the
  104 lines carrying three responsibilities the plan expected; the design
  spec is corrected to say so, with the mis-measurement named as the cause
  rather than left looking like the code once carried more than it does.

### Added

- **A read-only query layer for the Security dashboard.** `security/queries.py`
  opens `data/security.db` with `mode=ro` in the connection URI, so a `SELECT`
  with a typo cannot write to the ledger even by accident — every write stays
  behind `cli.py`'s validating door. It holds every aggregation the four new
  screens need: posture by branch (falling back to the most recently analysed
  branch when the project's own has none, and saying so), a project index
  summary with a success rate that excludes running analyses from both sides
  (`None`, not `0.0`, when nothing has finished), trend lines, the top open
  categories, and per-kind event activity. `_checklist` — the one state
  machine that turns a finding's history into `new`/`open`/`partial`/
  `pending`/`fixed`/`regressed` — moves out of `cli.py` into `queries.py` as
  `checklist()` unchanged, so both `cli.py`'s callers and every new
  aggregation share the one implementation instead of a `CASE` expression
  reimplementing it in SQL, which is exactly how `report.STATES` became a
  third copy of a list nobody kept in step. `branch_rows`' grouped query
  needed a real fix along the way: ordering by `MAX(started) DESC` alone ties
  whenever two branches are analysed within the same wall-clock second
  (`started` has 1-second resolution), and the tie broke the wrong way on this
  branch's own test — `MAX(id) DESC` as the secondary key, the same tiebreak
  `recent_analyses` already used, makes "newest first" mean what it says.
  Measured against the real `data/security.db` (4 analyses, 108 findings),
  every query answers in under 3 ms, so no index was added beyond the
  existing `analysis_by_scope(project, repo, branch)`. A follow-up review
  caught two more of the same shape before either screen shipped. `critical`
  and `high` in `index_summary` were already scoped to the project list they
  were given, but `analyses` and `success_rate` were computed over the WHOLE
  `analysis` table — nothing prunes the ledger when a project is renamed or
  removed, so one stale project's analyses were enough to quietly inflate
  both numbers on the index screen forever; all four are now scoped the same
  way, and an empty project list reads as an explicit empty summary rather
  than whatever SQLite happens to do with `WHERE project IN ()`. `trend()`
  had the identical ordering gap `branch_rows` was fixed for — `ORDER BY
  started` alone, no `id` to break a tie — and gets the same `ORDER BY
  started, id` fix, so a trend line's "oldest first" is guaranteed rather
  than incidental.

- **A named set of filters per project.** Rebuilding the view somebody works
  from every day — severity, category, state, whatever the day calls for —
  used to cost six clicks against the findings browser on every visit. A new
  `saved_filter` table (keyed by project and name) and `security filters
  list|save|delete` let it be saved once and reapplied in one. A filter
  stores a *query*, never findings — saving one records only the shape of
  the question being asked, nothing about what it turned up. A filter
  nobody can parse (a hand-edited row, a future query shape an older reader
  does not understand) stays visible with an empty query instead of taking
  the whole list down, so it can still be deleted. Saving and deleting join
  `decide`, `rename-project`, `open-analysis` and `event` in the set
  `CC_SECURITY_AGENT` refuses — a working set is a human's, not something
  an analysis decides — while `filters list` stays open, the same
  reasoning that keeps `events` and `findings` open. A name over 80
  characters is refused, naming the limit, rather than silently truncated
  to `name[:80]` — the truncation used to make a long name undeletable by
  what was actually typed, and let two names sharing their first 80
  characters silently overwrite each other before the primary key ever saw
  the difference.

- **The Security area records what happened, in a new `event` table.**
  Analyses started and finished, decisions with the reason behind them,
  settings changed, reports exported — the history a security posture needs
  to be auditable at all. Written through `ledger.record_event` and read back
  through two new CLI verbs, `security event` (a standalone write, refused to
  the agent) and `security events` (the read side, open to everyone). Without
  a user column or an IP: this install has one operator, and a column that
  can only hold one value teaches nothing.

  **`claude-cron project-set` — an existing command — is now also a writer
  to `security.db`.** A settings save on a security-enabled project files a
  `settings_changed` event, best-effort and never the reason the save itself
  fails; one on a project with security off files nothing. Nobody who only
  ever touches `config/projects.json` needs to know `security.db` exists,
  but a project that has opted in now has both files change on one save.

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
  `bin/security/`.** Twelve modules of stdlib Python, no dependency added, behind
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
  floor and sorted above every critical finding on the page. The "Minimum severity
  shown" dropdown in the project editor now offers `Info` as the lowest option, so
  the floor can be lowered to it through the UI.

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

- **The Activity screen's "All time" period actually returns everything.**
  `secActSince()` sends `since=0` on the wire for "All time" — the client's
  only way to ask for no lower bound — but `security_activity` read an
  absent `since` and an explicit `since=0` as the identical case, and
  rewrote both to the same 30-day window meant for a caller who asked for
  nothing. "All time" therefore returned exactly what "30 days" returns,
  silently, with no error — an audit reaching back further than a month got
  a partial answer that looked complete. An absent `since` still defaults
  to 30 days; an explicit `0` no longer gets folded into that window. A
  negative value never reaches `ledger.events_for` at all — both
  `security_activity` and `cmd_activity_data` clamp it up to `0` first — so
  what the store actually sees is always `0`, which is what "no lower bound"
  already means there.

- **`security findings-page --fingerprint` refuses a malformed value
  instead of silently matching nothing.** Its sibling filters — `--severity`,
  `--state`, `--category` — get `invalid choice: ...` from argparse the
  moment a typo reaches them; `--fingerprint` cannot use the same mechanism
  (it is a prefix match, not a closed set of values) and had no validation
  at all, so a mistyped value returned zero rows exactly as fast as a
  fingerprint that is simply not open right now, indistinguishable from
  each other. It is now checked against the same shape the server's own
  route already enforces (1 to 64 lowercase hex characters) and refused
  with a sentence on a mismatch, before the database is even opened.

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
