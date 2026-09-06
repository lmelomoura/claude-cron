#!/usr/bin/env bash
# Helpers for a project's provisioning hooks — source it, do not run it:
#
#     source "$AL_PROVISION_LIB"
#
# Isolation gives a run its own worktree, which settles the filesystem. It says
# nothing about PORTS. Two runs of the same repo each bring up the same stack,
# both publish 5432, and the second dies on "address already in use" — a failure
# that looks like a broken test suite and is nothing of the kind.
#
# The scheduler hands every isolated run a block of ports nobody else holds
# (AL_PORT_BASE, AL_PORT_SPAN wide). These turn that block into concrete numbers.
# Nothing here is Docker-specific: it is the general shape of "two copies of one
# stack at the same time", which every project that isolates eventually meets.

# A port from this run's block. Each NAME gets its own offset, assigned in the
# order asked for and remembered, so calling twice for the same name gives the
# same port and two names never collide.
#
#     al_port POSTGRES_PORT      -> 21003
#
# Outside a run (no AL_PORT_BASE) it echoes the fallback, so a hook can be tried
# by hand without pretending to be a run.
al_port() { # <NAME> [fallback]
  local name="${1:?al_port needs a name}" fallback="${2:-}"
  # AL_PORT_BASE, or its pre-rename spelling, for one release.
  local base="${AL_PORT_BASE:-${CC_PORT_BASE:-}}"
  if [ -z "$base" ]; then printf '%s\n' "$fallback"; return 0; fi
  local span="${AL_PORT_SPAN:-${CC_PORT_SPAN:-100}}" file="${TMPDIR:-/tmp}/al-ports.$$.$base"
  local seen n
  seen="$(grep -m1 "^$name " "$file" 2>/dev/null | cut -d' ' -f2 || true)"
  if [ -n "$seen" ]; then printf '%s\n' "$seen"; return 0; fi
  # `wc -l < missing` is a REDIRECTION error, raised by the shell before wc ever
  # runs — so a 2>/dev/null inside the substitution does not silence it, and the
  # first al_port of every run would print a spurious "No such file" into
  # exec.log. Ask whether the file is there instead.
  n=0
  [ -f "$file" ] && n="$(wc -l < "$file" | tr -d ' ')"
  if [ "$n" -ge "$span" ]; then
    echo "al_port: this run has used all $span ports of its block" >&2
    printf '%s\n' "$fallback"; return 1
  fi
  local port=$(( base + n ))
  printf '%s %s\n' "$name" "$port" >> "$file"
  printf '%s\n' "$port"
}

# Set KEY=VALUE in a dotenv file, replacing any existing line for that key.
# Written to a temp file and moved into place, so a hook that dies half-way
# cannot leave a config the agent will then read as though it were finished.
al_env_set() { # <file> <KEY> <VALUE>
  local file="${1:?}" key="${2:?}" val="${3-}" tmp
  tmp="$(mktemp "${file}.XXXXXX")" || return 1
  if [ -f "$file" ]; then grep -v -E "^[[:space:]]*${key}=" "$file" > "$tmp" || true; fi
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$file"
}

# Give every *_PORT key already present in a dotenv file a port from this run's
# block. This is the one-liner most projects want: the compose file already
# reads ${POSTGRES_PORT:-5432}, the checked-in .env sets the developer's value,
# and this rewrites them all so the run cannot collide with the developer's own
# stack or with a sibling run.
#
#     al_env_ports .env
#
# Only keys the file ALREADY has are touched: inventing ports for services this
# project does not run would publish things nobody asked for.
al_env_ports() { # <dotenv-file> [KEY_SUFFIX, default _PORT]
  local file="${1:?}" suffix="${2:-_PORT}" key
  [ -f "$file" ] || return 0
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    al_env_set "$file" "$key" "$(al_port "$key")"
  done < <(grep -oE "^[[:space:]]*[A-Z0-9_]+${suffix}=" "$file" | tr -d ' =' | sort -u)
}

# The canonical checkout's copy of a gitignored file, into this worktree.
# A fresh worktree has no .env, no credentials, no local config — they are
# gitignored, so no checkout produces them. Missing is not an error: a project
# where only some repos carry one is ordinary.
al_copy_ignored() { # <path relative to the repo root> [...]
  local f repo="${AL_REPO_PATH:-${CC_REPO_PATH:-}}"
  for f in "$@"; do
    [ -f "$repo/$f" ] || continue
    mkdir -p "$(dirname "$f")"
    # -c asks APFS for a clone: same bytes, no copy, no extra disk.
    cp -c "$repo/$f" "$f" 2>/dev/null || cp "$repo/$f" "$f"
  done
}

# The pre-rename names of the four helpers above, kept for one release so a
# hook written before 2026-09-06 keeps working. Delete after.
cc_port()         { al_port "$@"; }
cc_env_set()      { al_env_set "$@"; }
cc_env_ports()    { al_env_ports "$@"; }
cc_copy_ignored() { al_copy_ignored "$@"; }
