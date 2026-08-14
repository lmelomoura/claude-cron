# shellcheck shell=bash
# ---------------------------------------------------------------------------
# worktree-lib.sh — generic, language-agnostic git-worktree isolation for
# claude-cron runs. Sourced by `claude-cron`; defines functions only.
#
# WHY: every job of a project shares one checkout (projects.json .cwd). Two runs
# there — a dev agent and a review agent, say — race on the working tree: one
# `git checkout` clobbers the other's branch and work is lost. Each run instead
# gets its OWN git worktree (a linked working tree over the same .git), so their
# checkouts never touch each other. The canonical checkout is kept detached so it
# never holds a branch a worktree needs.
#
# NOT COUPLED TO ANY PROJECT. Nothing here names a repo or a language. Every
# project-specific detail is declared in projects.json under `.worktree`:
#
#   "worktree": {
#     "enabled": "auto",            # "auto" = isolate when .cwd is a git repo;
#                                   #  true = always; false = never (run in .cwd)
#     "venv": "{repo}/.venv",       # optional: activate this venv inside the
#                                   #  worktree (exports VIRTUAL_ENV, prepends
#                                   #  <venv>/bin to PATH)
#     "env": {                      # optional: extra env vars for the run,
#       "PYTHONPATH": "{worktree}/src"   #  with {repo}/{worktree} expanded
#     }
#   }
#
# A project with no `.worktree` block and a git .cwd is isolated with no env
# tweaks. A non-git .cwd is left to run in place. Adding a future project is a
# projects.json entry, never a code change here.
#
# Depends on the sourcing script for: JQ, CONFIG_DIR, DATA_DIR, WORKTREES_DIR, LOCK_DIR,
# projects_json, project_get, job_get, resolve, lock_active, slot_alive, state_get,
# log_tick, num, now_epoch.
# Targets bash 3.2 (macOS system bash) under `set -u`: no mapfile, no
# associative arrays, empty arrays expanded as ${a[@]+"${a[@]}"}.
# ---------------------------------------------------------------------------

# Is <dir> inside a git working tree?
wt_is_git_repo() { git -C "${1:-}" rev-parse --is-inside-work-tree >/dev/null 2>&1; }

# Run a command SILENTLY with a wall-clock ceiling. macOS ships no timeout(1),
# so this is the killer-subshell pattern the provisioning hook already relied
# on, lifted out so anything that can block on the network uses the same guard.
# Returns the command's status, or non-zero when it was killed.
#
# The child's stdout is closed deliberately, not as tidiness. Killing a process
# does NOT kill its children, and a caller inside `$( … )` blocks until every
# process holding the pipe exits — so an orphaned grandchild (the `sleep` in a
# wrapper script, a `git` subprocess) keeps the command substitution waiting for
# the full original duration and the timeout buys nothing at all. Neither caller
# wants the output; both write what they need to a log themselves.
wt_run_limited() { # wt_run_limited <seconds> <command...>
  local t="${1:-60}"; shift
  local pid killer rc
  "$@" >/dev/null 2>&1 & pid=$!
  ( sleep "$t"; kill -TERM "$pid" 2>/dev/null ) >/dev/null 2>&1 & killer=$!
  wait "$pid"; rc=$?
  kill "$killer" 2>/dev/null; wait "$killer" 2>/dev/null
  return "$rc"
}

# Every repo this project spans: name<TAB>canonical path<TAB>base branch.
# A project that declares `.repos[]` is taken at its word — that list is what a
# run gets a worktree of. One that declares none is the single-repo case: the
# row is synthesised from `.cwd`, taking its base from the project's `.base`.
#
# That project-level `.base` exists because the row a single-repo project had to
# declare to pin its base was a copy of what `.cwd` already said: the name is
# `basename .cwd` and the path IS `.cwd`, so only the base carried information —
# and re-typing the path is exactly where a trailing slash creeps in and stops
# the row matching `.cwd` at all. An EMPTY base still means "infer it"
# (wt_base_ref decides), so a project that declares neither behaves as before.
wt_repos() { # <project> <canonical_cwd>
  local project="${1:-}" cwd="${2:-}" n
  n="$(projects_json | "$JQ" -r --arg n "$project" \
        '[.projects[] | select(.name==$n) | .repos // [] | .[]] | length' 2>/dev/null)"
  case "$n" in ''|null|*[!0-9]*) n=0 ;; esac
  if [ "$n" -gt 0 ]; then
    projects_json | "$JQ" -r --arg n "$project" '
      .projects[] | select(.name==$n) | .repos[]
      | [(.name // ""), (.path // ""), (.base // "")] | @tsv' 2>/dev/null
    return 0
  fi
  printf '%s\t%s\t%s\n' "$(basename "$cwd")" "$cwd" "$(project_get "$project" '.base' '')"
}

# Should this run be isolated in a worktree? 0 = yes.
wt_isolation_enabled() { # <project> <canonical_cwd>
  local project="${1:-}" cwd="${2:-}" mode
  mode="$(project_get "$project" '.worktree.enabled' 'auto')"
  case "$mode" in
    false) return 1 ;;
    true)  return 0 ;;
    *)     wt_is_git_repo "$cwd" ;;   # "auto" / anything else
  esac
}

# The ref a repo's worktree is cut from. A declared base wins; an empty one is
# inferred from the canonical's current branch, then from the remote's default.
#
# It fetches first, because a review run has to see the branch a dev run pushed
# minutes ago -- but a network that is down must never fail a run: fall back to
# what is already local and say so in the tick log.
wt_base_ref() { # <canonical> <base> [fetch-timeout] -> prints a ref; non-zero if nothing resolves
  local repo="${1:-}" base="${2:-}" ref
  # A remote that accepts the TCP connection and then goes quiet does not fail —
  # it hangs, and this runs before the watchdog exists, so it would hold the
  # run's slot for as long as the network stayed broken. Bound it: a stale base
  # resolved from local refs is worth far more than a wedged job.
  local ft; ft="$(num "${3:-}" 120)"
  wt_run_limited "$ft" git -C "$repo" fetch --prune --quiet 2>/dev/null \
    || log_tick "worktree: fetch failed or timed out (${ft}s) in $repo — resolving the base from local refs"
  if [ -z "$base" ]; then
    base="$(git -C "$repo" symbolic-ref --short --quiet HEAD 2>/dev/null || true)"
    if [ -z "$base" ]; then
      ref="$(git -C "$repo" symbolic-ref --short --quiet refs/remotes/origin/HEAD 2>/dev/null || true)"
      base="${ref#origin/}"
    fi
  fi
  # A base ending in `*` names a FAMILY of branches rather than one -- `release/*`
  # on a project that ships through release trains. A literal `release/0.9.0` is
  # correct for exactly as long as 0.9.0 is current and then silently keeps
  # cutting worktrees from last month's train: the value rots, nothing reports
  # it, and the only symptom is agents working from the wrong baseline. Resolving
  # the pattern means the setting is written once and stays true.
  case "$base" in
    *'*')
      if ref="$(wt_latest_matching "$repo" "$base")"; then
        printf '%s\n' "$ref"; return 0
      fi
      # Falling through to HEAD here would be the silent-wrong-baseline failure
      # this exists to prevent, so refuse instead and let the caller report it.
      log_tick "worktree: base pattern '$base' matched no branch in $repo"
      return 1 ;;
  esac
  if [ -n "$base" ]; then
    if git -C "$repo" rev-parse --verify --quiet "origin/$base^{commit}" >/dev/null 2>&1; then
      printf 'origin/%s\n' "$base"; return 0
    fi
    if git -C "$repo" rev-parse --verify --quiet "$base^{commit}" >/dev/null 2>&1; then
      printf '%s\n' "$base"; return 0
    fi
  fi
  git -C "$repo" rev-parse --verify --quiet HEAD >/dev/null 2>&1 || return 1
  printf 'HEAD\n'
}

# wt_latest_matching <repo> <pattern> -> the highest-versioned branch matching it.
#
# "Highest" is by VERSION, not by string: sorted as text, release/0.9.0 beats
# release/0.10.0, which would quietly pin a project to an abandoned train right
# after the version that needed it most. `git for-each-ref --sort=-v:refname`
# understands the numbering; nothing else here has to.
#
# Remote branches are the source of truth -- a release exists once it is pushed,
# and a stale local ref must never outrank it. Local refs are consulted only when
# the remote knows nothing, which is the offline case the fetch above already
# degrades to.
wt_latest_matching() { # <repo> <pattern like release/*>
  local repo="${1:-}" pat="${2:-}" out
  [ -n "$pat" ] || return 1
  out="$(git -C "$repo" for-each-ref --sort=-v:refname --count=1 \
          --format='%(refname:short)' "refs/remotes/origin/${pat}" 2>/dev/null)"
  if [ -n "$out" ]; then printf '%s\n' "$out"; return 0; fi
  out="$(git -C "$repo" for-each-ref --sort=-v:refname --count=1 \
          --format='%(refname:short)' "refs/heads/${pat}" 2>/dev/null)"
  [ -n "$out" ] || return 1
  printf '%s\n' "$out"
}

# Expand {repo} and {worktree} placeholders in a template.
wt_subst() { # <template> <repo> <worktree>
  local t="${1:-}" repo="${2:-}" wt="${3:-}"
  t="${t//\{repo\}/$repo}"
  t="${t//\{worktree\}/$wt}"
  printf '%s' "$t"
}

# Emit the env assignments (KEY=VALUE, one per line) for a project's worktree
# run: the optional venv (VIRTUAL_ENV + PATH), then any explicit env vars.
wt_env_line() { # <project> <repo> <worktree>
  local project="${1:-}" repo="${2:-}" wt="${3:-}" venv k v
  venv="$(project_get "$project" '.worktree.venv' '')"
  if [ -n "$venv" ] && [ "$venv" != "null" ]; then
    venv="$(wt_subst "$venv" "$repo" "$wt")"
    printf 'VIRTUAL_ENV=%s\n' "$venv"
    printf 'PATH=%s/bin:%s\n' "$venv" "${PATH}"
  fi
  # `.worktree.env` is an object; emit key\tvalue and expand placeholders.
  while IFS="$(printf '\t')" read -r k v; do
    [ -n "$k" ] || continue
    printf '%s=%s\n' "$k" "$(wt_subst "$v" "$repo" "$wt")"
  done < <(projects_json | "$JQ" -r --arg n "$project" '
      .projects[] | select(.name==$n) | .worktree.env // {}
      | to_entries[] | .key + "\t" + (.value|tostring)' 2>/dev/null)
}

# Run a project's provisioning hook for ONE repo, in that repo's worktree.
# A missing script means "nothing to provision" and is not an error.
#
# The hook is killed if it outlives the project's timeout: it runs before the
# agent exists, so nothing else is watching it, and a `composer install` that
# hangs on a dead mirror would hold the run's slot for ever. macOS ships no
# timeout(1), hence the killer subshell.
wt_provision() { # <up|down> <project> <id> <run_dir> <name> <canonical> <worktree> <base>
  local phase="${1:-}" project="${2:-}" id="${3:-}" run_dir="${4:-}"
  local name="${5:-}" repo="${6:-}" wt="${7:-}" base="${8:-}"
  local script t rc pb
  script="$CONFIG_DIR/provision/$project.$phase.sh"
  [ -f "$script" ] || return 0
  t="$(project_get "$project" '.worktree.provision_timeout_seconds' '900')"
  case "$t" in ''|null|*[!0-9]*) t=900 ;; esac
  # The manifest is the source of truth for the port block, not the environment.
  # `down` also runs from the orphan sweep, which has no slot and so no ambient
  # CC_PORT_BASE — a hook that asked cc_port there got different numbers from
  # the ones `up` bound, and released nothing.
  pb="$("$JQ" -r '.port_base // ""' "$run_dir/.run.json" 2>/dev/null)"
  case "$pb" in null) pb="" ;; esac
  [ -z "$pb" ] && pb="${CC_PORT_BASE:-}"
  _wt_hook() {
    cd "$wt" 2>/dev/null || return 1
    CC_REPO_NAME="$name" CC_REPO_PATH="$repo" CC_WORKTREE="$wt" CC_BASE="$base" \
    CC_RUN_DIR="$run_dir" CC_RUN_MANIFEST="$run_dir/.run.json" \
    CC_PROJECT="$project" CC_JOB_ID="$id" \
    CC_PORT_BASE="$pb" CC_PORT_SPAN="${CC_PORT_SPAN:-100}" \
    CC_PROVISION_LIB="${CC_PROVISION_LIB:-}" \
      bash "$script" >>"$DATA_DIR/exec.log" 2>&1
  }
  wt_run_limited "$t" _wt_hook; rc=$?
  unset -f _wt_hook
  [ "$rc" -eq 0 ] || log_tick "$id: provision $phase failed for $name (rc=$rc) — see exec.log"
  return "$rc"
}

# The canonical checkout that owns a linked worktree. `git worktree list` names
# the main worktree first, from any of them, which is how teardown finds the repo
# to remove from without depending on the manifest.
wt_main_of() { # <worktree>
  git -C "${1:-}" worktree list --porcelain 2>/dev/null | awk 'NR==1{print $2; exit}'
}

# A fingerprint of everything git currently calls dirty in a worktree. Taken
# once after provisioning and again at teardown: what provisioning left behind
# is not the agent's work, and mistaking the two preserves every run dir for
# ever. Comparing fingerprints rather than listing paths keeps this O(1) to
# store, and "created then deleted" correctly reads as "nothing changed".
wt_dirt_sha() { # <worktree>
  git -C "${1:-}" status --porcelain 2>/dev/null | shasum | awk '{print $1}'
}

# Every worktree a run dir currently holds. Reads the DISK, not the manifest, so
# it is still correct when setup died before writing one.
wt_run_worktrees() { # <run dir>
  local run_dir="${1:-}" d
  [ -d "$run_dir" ] || return 0
  for d in "$run_dir"/*/; do
    [ -d "$d" ] || continue
    printf '%s\n' "${d%/}"
  done
}

# Create this run's dir and one worktree per repo the project spans, provision
# each, and write the manifest. Prints the PRIMARY worktree (the repo whose path
# is the project's .cwd) — that becomes the agent's cwd. Returns non-zero if
# anything fails, having left nothing behind (the caller must then abort the run,
# never fall back to the shared checkout — that is the race we are removing).
#
# ORDER MATTERS: every worktree is created first, then the manifest, and only
# then does `up` run. A hook therefore always sees a complete $CC_RUN_MANIFEST
# and can reach a sibling repo's worktree. It also means "no manifest" implies
# "no hook ran", which is what lets teardown skip `down` after a half-built run.
#
# The canonical checkout is NEVER modified: the base is declared, so there is
# nothing to free by detaching it, and a detach it never undoes would leave the
# operator's own repo headless for good.
wt_setup() { # <id> <project> <canonical_cwd> <stamp> [port_base]
  local id="${1:-}" project="${2:-}" cwd="${3:-}" stamp="${4:-}" port_base="${5:-}"
  local run_dir="$WORKTREES_DIR/$id/$stamp" tsv="$WORKTREES_DIR/$id/.$stamp.tsv"
  local name repo base ref wt sha primary=""
  # How long a single repo's fetch may block before the base is resolved from
  # local refs instead. Declared per project, like every other worktree knob.
  local fetch_t; fetch_t="$(num "$(project_get "$project" '.worktree.fetch_timeout_seconds' '120')" 120)"
  mkdir -p "$run_dir" || { log_tick "$id: cannot create the run dir $run_dir"; return 1; }
  : > "$tsv"
  while IFS="$(printf '\t')" read -r name repo base; do
    [ -n "$name" ] || continue
    if [ ! -d "$repo" ]; then
      log_tick "$id: repo path missing ($name -> $repo)"
      rm -f "$tsv"; wt_teardown "$id" "$project" "$run_dir"; return 1
    fi
    if ! ref="$(wt_base_ref "$repo" "$base" "$fetch_t")"; then
      log_tick "$id: no base ref resolvable in $repo"
      rm -f "$tsv"; wt_teardown "$id" "$project" "$run_dir"; return 1
    fi
    wt="$run_dir/$name"
    git -C "$repo" worktree prune >/dev/null 2>&1 || true
    if ! git -C "$repo" worktree add --detach "$wt" "$ref" >/dev/null 2>>"$DATA_DIR/exec.log"; then
      log_tick "$id: worktree add failed ($wt from $ref) — see exec.log"
      rm -f "$tsv"; wt_teardown "$id" "$project" "$run_dir"; return 1
    fi
    sha="$(git -C "$wt" rev-parse HEAD 2>/dev/null || true)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$repo" "$wt" "${base:-$ref}" "$ref" "$sha" >> "$tsv"
    [ "$repo" = "$cwd" ] && primary="$wt"
  done < <(wt_repos "$project" "$cwd")

  if [ -z "$primary" ]; then
    log_tick "$id: no repo matches the project's cwd ($cwd) — cannot choose a primary"
    rm -f "$tsv"; wt_teardown "$id" "$project" "$run_dir"; return 1
  fi

  "$JQ" -Rn --arg job "$id" --arg project "$project" --arg run_dir "$run_dir" \
        --arg primary "$(basename "$primary")" --arg port_base "$port_base" '
    {job:$job, project:$project, run_dir:$run_dir, primary:$primary,
     # The port block for this run. Recorded here and not left to the environment
     # because `down` also runs from the orphan sweep, which has no slot and
     # therefore no CC_PORT_BASE: a hook computing what to release from
     # cc_port would have released numbers it never bound. Everything teardown
     # needs must be reconstructible from disk alone.
     port_base:$port_base,
     repos: [inputs | split("\t")
             | {name:.[0], canonical:.[1], worktree:.[2],
                base:.[3], base_ref:.[4], fork_sha:.[5]}]}' "$tsv" > "$run_dir/.run.json"
  rm -f "$tsv"

  : > "$tsv"
  while IFS="$(printf '\t')" read -r name repo wt base; do
    [ -n "$name" ] || continue
    if ! wt_provision up "$project" "$id" "$run_dir" "$name" "$repo" "$wt" "$base"; then
      log_tick "$id: provisioning failed for $name — aborting the run"
      rm -f "$tsv"; wt_teardown "$id" "$project" "$run_dir"
      return 1
    fi
    printf '%s\t%s\n' "$name" "$(wt_dirt_sha "$wt")" >> "$tsv"
  done < <("$JQ" -r '.repos[] | [.name,.canonical,.worktree,.base] | @tsv' "$run_dir/.run.json" 2>/dev/null)

  # Record what the tree looked like once provisioning was done, so teardown can
  # tell the hook's leftovers from anything the agent went on to write.
  if "$JQ" -R -n --slurpfile mf "$run_dir/.run.json" '
        ([inputs | split("\t") | {(.[0]): .[1]}] | add // {}) as $d
        | $mf[0] | .repos = [.repos[] | . + {dirt_sha: ($d[.name] // "")}]' \
        "$tsv" > "$run_dir/.run.json.new" 2>/dev/null; then
    mv "$run_dir/.run.json.new" "$run_dir/.run.json"
  else
    rm -f "$run_dir/.run.json.new"
  fi
  rm -f "$tsv"

  printf '%s\n' "$primary"
}

# 0 = this run dir holds work that must be preserved. ALL-OR-NOTHING: if any one
# repo has uncommitted changes, or commits that exist on no remote, the whole run
# dir stays. Removing some repos of a run and keeping others produces a half-run
# nobody can reason about.
wt_unsafe_to_remove() { # <run dir>
  local run_dir="${1:-}" mf="${1:-}/.run.json" wt head fork snap
  [ -d "$run_dir" ] || return 1
  while IFS= read -r wt; do
    [ -n "$wt" ] || continue
    # Dirty compared to the END OF PROVISIONING → the agent wrote something → keep.
    # Compared to a pristine checkout it is always dirty: the hook just copied a
    # .env and a vendor/ in. With no snapshot (setup died before provisioning)
    # fall back to the strict reading and keep anything dirty at all.
    snap=""
    [ -f "$mf" ] && snap="$("$JQ" -r --arg w "$wt" \
        '.repos[] | select(.worktree==$w) | .dirt_sha // ""' "$mf" 2>/dev/null)"
    if [ -n "$snap" ]; then
      [ "$(wt_dirt_sha "$wt")" != "$snap" ] && return 0
    else
      [ -n "$(git -C "$wt" status --porcelain 2>/dev/null)" ] && return 0
    fi
    head="$(git -C "$wt" rev-parse --verify --quiet HEAD 2>/dev/null || true)"
    [ -n "$head" ] || continue
    fork=""
    [ -f "$mf" ] && fork="$("$JQ" -r --arg w "$wt" \
        '.repos[] | select(.worktree==$w) | .fork_sha' "$mf" 2>/dev/null)"
    # No new commits since the fork point → nothing was made here → safe.
    [ -n "$fork" ] && [ "$fork" = "$head" ] && continue
    # New commits exist: safe only if they already live on some remote branch.
    [ -n "$(git -C "$wt" branch -r --contains "$head" 2>/dev/null)" ] && continue
    return 0   # new local commits, on no remote → preserve
  done < <(wt_run_worktrees "$run_dir")
  return 1
}

# Finish a run's directory: `down` for every repo (in reverse declaration order,
# while the worktrees still exist), then remove them if that is safe.
#
# `down` runs even when the run dir is preserved: whatever the hook registered
# outside the directory -- a herd site, a compose stack -- has to be released
# when the run ends, whether or not a human still wants the files.
#
# No manifest means setup never got as far as provisioning, so there is nothing
# to take down; the worktrees are still removed.
wt_teardown() { # <id> <project> <run dir>
  local id="${1:-}" project="${2:-}" run_dir="${3:-}" mf="${3:-}/.run.json"
  local name repo wt base main
  [ -n "$run_dir" ] && [ -d "$run_dir" ] || return 0
  # ONCE per run dir. A preserved run dir is swept again on every tick, and
  # `down` is not a query: re-running it would take the same compose stack down
  # every minute for as long as the unpushed work sits there. The marker lives
  # in the run dir, so it disappears exactly when the run does.
  if [ -f "$mf" ] && [ ! -f "$run_dir/.down" ]; then
    : > "$run_dir/.down"
    while IFS="$(printf '\t')" read -r name repo wt base; do
      [ -n "$wt" ] && [ -d "$wt" ] || continue
      wt_provision down "$project" "$id" "$run_dir" "$name" "$repo" "$wt" "$base" || true
    done < <("$JQ" -r '.repos | reverse | .[] | [.name,.canonical,.worktree,.base] | @tsv' \
                "$mf" 2>/dev/null)
  fi
  if wt_unsafe_to_remove "$run_dir"; then
    log_tick "$id: run dir kept — unpushed or uncommitted work at $run_dir"
    return 0
  fi
  wt_remove_all "$run_dir"
}

# Take a run dir off disk unconditionally, leaving git with no stale worktree
# registrations. Split out of wt_teardown so an explicit, human-initiated drop
# can reuse exactly the same removal — the ONLY difference being that it does
# not consult wt_unsafe_to_remove first.
wt_remove_all() { # <run dir>
  local run_dir="${1:-}" wt main
  [ -n "$run_dir" ] && [ -d "$run_dir" ] || return 0
  while IFS= read -r wt; do
    [ -n "$wt" ] || continue
    main="$(wt_main_of "$wt")"
    if [ -n "$main" ]; then
      git -C "$main" worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"
      git -C "$main" worktree prune >/dev/null 2>&1 || true
    else
      rm -rf "$wt"
    fi
  done < <(wt_run_worktrees "$run_dir")
  rm -rf "$run_dir"
}

# Sweep the run dirs whose owning run is no longer active (a killed or crashed
# run, or a tick that died between setup and launch), tearing each down safely.
# Called at the top of every tick.
wt_prune_orphans() {
  [ -d "$WORKTREES_DIR" ] || return 0
  local iddir id d project
  for iddir in "$WORKTREES_DIR"/*; do
    [ -d "$iddir" ] || continue
    id="$(basename "$iddir")"
    for d in "$iddir"/*; do
      [ -d "$d" ] || continue                 # skips the .<stamp>.tsv scratch files
      # Claimed by a LIVE run? Ask the run slots, which is where that fact
      # lives: every running job holds a slot naming its run dir. Asking the
      # old single mutex (or the state's one cur_worktree, which cannot describe
      # several concurrent runs) said "nobody owns this" for worktrees that were
      # very much in use — and the sweep deleted them out from under the agents.
      wt_is_claimed "$id" "$d" && continue
      project="$(job_get "$id" '.project' '')"
      wt_teardown "$id" "$project" "$d"
    done
  done
}

# Clear stale worktree registrations from every canonical checkout a project
# names. wt_remove_all prunes the one repo it just removed from, which covers
# every path this engine controls — but not the one a human takes: the dashboard
# lists each retained run dir with its size, so sooner or later somebody reaches
# for `rm -rf`. Git then keeps the registration in .git/worktrees/ and, worse,
# still believes the branch is checked out, so the canonical cannot have it back.
# Pruning is idempotent and costs a fork per repo per tick.
wt_prune_canonicals() {
  local path
  # `sort -u` is the de-duplication (a repo two projects share is pruned once).
  # Accumulating seen paths in a space-delimited string and matching them with a
  # glob is the obvious alternative and it is wrong on this platform: a macOS
  # home directory routinely has a space in it, and `/Users/Jane` then matches
  # inside `/Users/Jane Doe/repo-a`, so a real second checkout is silently
  # skipped for ever. A whole line is a whole path, so sorting lines cannot
  # make that mistake.
  #
  # `objects` and `strings` are load-bearing too. A single malformed entry —
  # `"repos": ["not-an-object"]` — makes jq exit 5 mid-stream, and with the
  # error swallowed by 2>/dev/null every project declared AFTER it silently
  # stops being pruned. Filtering by type keeps one bad entry from taking its
  # neighbours down with it.
  while IFS= read -r path; do
    [ -n "$path" ] && [ -d "$path" ] || continue
    git -C "$path" worktree prune >/dev/null 2>&1 || true
  done < <(projects_json | "$JQ" -r '
    .projects[]? | ((.repos // [])[]? | objects | .path), .cwd
    | strings | select(. != "")' 2>/dev/null | sort -u)
}

# Is this run dir the working directory of a run that is alive right now?
wt_is_claimed() { # <id> <run dir>
  local id="$1" wt="$2"
  local base="$LOCK_DIR/$id" slot owner
  [ -d "$base" ] || return 1
  for slot in "$base"/*/; do
    [ -d "$slot" ] || continue
    slot_alive "${slot%/}" || continue
    owner="$(cat "$slot/worktree" 2>/dev/null || true)"
    [ "$owner" = "$wt" ] && return 0
  done
  return 1
}
