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
# Depends on the sourcing script for: JQ, DATA_DIR, WORKTREES_DIR, LOCK_DIR,
# projects_json, project_get, job_get, resolve, lock_active, state_get, log_tick.
# Targets bash 3.2 (macOS system bash) under `set -u`: no mapfile, no
# associative arrays, empty arrays expanded as ${a[@]+"${a[@]}"}.
# ---------------------------------------------------------------------------

# Is <dir> inside a git working tree?
wt_is_git_repo() { git -C "${1:-}" rev-parse --is-inside-work-tree >/dev/null 2>&1; }

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

# Create the worktree for a run and print its path on stdout. Returns non-zero
# if creation fails (the caller must then abort the run, never fall back to the
# shared checkout — that is the race we are removing).
wt_setup() { # <id> <project> <canonical_cwd> <stamp>
  local id="${1:-}" project="${2:-}" cwd="${3:-}" stamp="${4:-}" wt
  wt="$WORKTREES_DIR/$id/$stamp"
  mkdir -p "$WORKTREES_DIR/$id"
  # Free any branch the canonical checkout is holding so worktrees can check
  # branches out — but never disturb a canonical that has uncommitted work
  # (that would be a crashed run's unsaved changes).
  if [ -z "$(git -C "$cwd" status --porcelain 2>/dev/null)" ]; then
    git -C "$cwd" checkout --detach --quiet 2>/dev/null || true
  fi
  git -C "$cwd" worktree prune >/dev/null 2>&1 || true
  if ! git -C "$cwd" worktree add --detach "$wt" HEAD >/dev/null 2>>"$DATA_DIR/exec.log"; then
    log_tick "$id: worktree add failed ($wt) — see exec.log"
    return 1
  fi
  # Remember the fork point so teardown can tell "made no commits" (safe to drop)
  # from "made commits, not pushed" (must preserve).
  git -C "$wt" rev-parse HEAD > "$wt.base" 2>/dev/null || true
  printf '%s\n' "$wt"
}

# 0 = the worktree holds work that must be preserved (do NOT remove).
wt_unsafe_to_remove() { # <worktree>
  local wt="${1:-}" base head
  [ -d "$wt" ] || return 1
  # Uncommitted or untracked changes → keep.
  [ -n "$(git -C "$wt" status --porcelain 2>/dev/null)" ] && return 0
  head="$(git -C "$wt" rev-parse --verify --quiet HEAD 2>/dev/null || true)"
  [ -n "$head" ] || return 1
  base=""
  [ -f "$wt.base" ] && base="$(cat "$wt.base" 2>/dev/null || true)"
  # No new commits since the fork point → nothing was made here → safe.
  [ -n "$base" ] && [ "$head" = "$base" ] && return 1
  # New commits exist: safe only if they already live on some remote branch.
  if [ -n "$(git -C "$wt" branch -r --contains "$head" 2>/dev/null)" ]; then
    return 1
  fi
  return 0   # new local commits, on no remote → preserve
}

# Remove a run's worktree if it is safe, else leave it and say so.
wt_teardown() { # <id> <project> <canonical_cwd> <worktree>
  local id="${1:-}" project="${2:-}" cwd="${3:-}" wt="${4:-}"
  [ -n "$wt" ] && [ -d "$wt" ] || return 0
  if wt_unsafe_to_remove "$wt"; then
    log_tick "$id: worktree kept — unpushed/uncommitted work at $wt"
    return 0
  fi
  git -C "$cwd" worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"
  rm -f "$wt.base"
  git -C "$cwd" worktree prune >/dev/null 2>&1 || true
}

# Sweep worktrees whose owning run is no longer active (a killed or crashed run),
# tearing each down safely. Called at the top of every tick.
wt_prune_orphans() {
  [ -d "$WORKTREES_DIR" ] || return 0
  local iddir id d cur project cwd
  for iddir in "$WORKTREES_DIR"/*; do
    [ -d "$iddir" ] || continue
    id="$(basename "$iddir")"
    for d in "$iddir"/*; do
      case "$d" in *.base) continue ;; esac   # sidecars, not worktrees
      [ -d "$d" ] || continue
      # Live only if the owning run is active AND this is its current worktree.
      if lock_active "$id"; then
        cur="$(state_get "$id" cur_worktree '')"
        [ "$cur" = "$d" ] && continue
      fi
      project="$(job_get "$id" '.project' '')"
      cwd="$(resolve "$id" cwd "$HOME")"
      wt_teardown "$id" "$project" "$cwd" "$d"
    done
  done
}
