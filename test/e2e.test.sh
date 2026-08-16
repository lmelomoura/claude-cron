#!/usr/bin/env bash
# End-to-end drive of the session lifecycle.
#
# WHY THIS EXISTS. `selftest` and the pytest suite are both unit-level: they
# call wt_setup, wt_teardown, the classifier and the sweep directly. Nothing
# had ever driven a whole run through the engine -- precheck, worktree, agent,
# classifier, `.ended`, teardown, resume, expiry -- and the defects that cost
# most on the way here were the ones that only appear when those meet.
#
# The one thing it does NOT exercise is the model, and that is deliberate:
# `test/fake-claude` stands in for the CLI and emits the same stream-json shape,
# so the suite stays offline and free. CONFIG and DATA are redirected into a
# sandbox under this directory, so an operator's real jobs, projects and run
# history are never read or written.
set -u

E2E="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$E2E/.." && pwd)"
ROOT="$E2E/sandbox"
trap 'rm -rf "$ROOT"' EXIT
rm -rf "$ROOT"; mkdir -p "$ROOT"/{config,data,remote,work}

export CLAUDE_CRON_CONFIG="$ROOT/config"
export CLAUDE_CRON_DATA="$ROOT/data"
export CLAUDE_CRON_CLAUDE_BIN="$E2E/fake-claude"
CC="$REPO/bin/claude-cron"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; }

# ---------------------------------------------------------------- the fixture
git init -q --bare "$ROOT/remote/origin.git"
git init -q "$ROOT/work/app"
git -C "$ROOT/work/app" remote add origin "$ROOT/remote/origin.git"
printf 'seed\n' > "$ROOT/work/app/README"
git -C "$ROOT/work/app" add -A
git -C "$ROOT/work/app" -c user.email=e2e@local -c user.name=e2e commit -qm seed
git -C "$ROOT/work/app" push -q origin HEAD:refs/heads/main
git -C "$ROOT/work/app" branch -q -M main

cat > "$ROOT/config/projects.json" <<JSON
{"projects":[{"name":"sandbox","cwd":"$ROOT/work/app","base":"main",
              "worktree":{"enabled":true}}]}
JSON

mkjob() { # mkjob <id> <mode>
  printf '{"jobs":[{"id":"%s","project":"sandbox","enabled":false,"prompt":"do the thing",
    "interval_seconds":3600,"permission_mode":"bypassPermissions","max_parallel":1}]}\n' "$1" \
    > "$ROOT/config/jobs.json"
  mkdir -p "$ROOT/config/prechecks"
  printf '#!/bin/bash\nexit 0\n' > "$ROOT/config/prechecks/$1.sh"
  chmod +x "$ROOT/config/prechecks/$1.sh"
}

dirs() { ls -1 "$ROOT/data/worktrees/$1" 2>/dev/null | grep -v '^\.' ; }
ended() { cat "$ROOT/data/worktrees/$1/$2/.ended" 2>/dev/null; }

echo
echo "1. a run that declares a clean ending is torn down and removed"
mkjob j1 complete
FAKE_MODE=complete FAKE_SESSION=sess-clean "$CC" run j1 >/dev/null 2>&1
sleep 2
[ -z "$(dirs j1)" ] && ok "its run directory is gone" || bad "left $(dirs j1)"

echo
echo "2. a run that never declares an ending keeps its tree, marked open"
mkjob j2 undeclared
FAKE_MODE=undeclared FAKE_SESSION=sess-cut "$CC" run j2 >/dev/null 2>&1
sleep 2
d2="$(dirs j2 | head -1)"
[ -n "$d2" ] && ok "its run directory survives ($d2)" || bad "the directory was removed"
[ "$(ended j2 "$d2")" = "open" ] && ok "and is marked open" || bad "marked '$(ended j2 "$d2")'"
[ "$(cat "$ROOT/data/worktrees/j2/$d2/.session" 2>/dev/null)" = "sess-cut" ] \
  && ok "with the session bound to it" || bad "session not bound"

echo
echo "3. a resume continues in that same directory, not a fresh one"
FAKE_MODE=complete FAKE_SESSION=sess-cut "$CC" resume j2 sess-cut >/dev/null 2>&1
sleep 2
grep -q "resumed sess-cut in its own tree" "$ROOT/data/tick.log" 2>/dev/null \
  && ok "the tick log says it reattached" || bad "no reattach line in tick.log"
[ -z "$(dirs j2)" ] && ok "and the finished session took its directory with it" \
  || bad "left $(dirs j2)"

echo
echo "4. work on no remote is reported, and the tree is still kept"
mkjob j3 dirty
FAKE_MODE=dirty FAKE_SESSION=sess-dirty "$CC" run j3 >/dev/null 2>&1
sleep 2
d3="$(dirs j3 | head -1)"
[ -n "$d3" ] && ok "the directory survives" || bad "removed despite undelivered work"
grep -q 'UNDELIVERED' "$ROOT/data/runs.ndjson" 2>/dev/null \
  && ok "and the run says UNDELIVERED" || bad "no UNDELIVERED note in the journal"

echo
echo "5. an open session nobody resumes expires and is reclaimed"
CLAUDE_CRON_SESSION_TTL=0 "$CC" tick >/dev/null 2>&1
sleep 1
[ -z "$(dirs j3)" ] && ok "the sweep reclaimed it once its ttl was up" \
  || bad "still there: $(dirs j3)"
grep -q 'expired after' "$ROOT/data/tick.log" 2>/dev/null \
  && ok "and said so in the tick log" || bad "nothing in tick.log about the expiry"

echo
echo "6. a directory from before this version is adopted, not deleted"
mkdir -p "$ROOT/data/worktrees/j4/20200101T000000Z-1/app"
git init -q "$ROOT/data/worktrees/j4/20200101T000000Z-1/app"
echo "work nobody else has" > "$ROOT/data/worktrees/j4/20200101T000000Z-1/app/keep.txt"
touch -t 202001010000 "$ROOT/data/worktrees/j4/20200101T000000Z-1"
"$CC" tick >/dev/null 2>&1
sleep 1
[ -f "$ROOT/data/worktrees/j4/20200101T000000Z-1/app/keep.txt" ] \
  && ok "the pre-upgrade directory and its work survive the first tick" \
  || bad "an upgrade deleted a retained directory"
[ "$(ended j4 20200101T000000Z-1)" = "open" ] \
  && ok "adopted as open, with a fresh clock" || bad "marked '$(ended j4 20200101T000000Z-1)'"

echo
echo "7. a slot from a previous boot holds nothing"
mkdir -p "$ROOT/data/locks/j5/99999"
echo "$$" > "$ROOT/data/locks/j5/99999/pid"
echo "0"   > "$ROOT/data/locks/j5/99999/boot"
mkdir -p "$ROOT/data/worktrees/j5/stamp-stale"
echo done > "$ROOT/data/worktrees/j5/stamp-stale/.ended"
echo "$ROOT/data/worktrees/j5/stamp-stale" > "$ROOT/data/locks/j5/99999/worktree"
"$CC" tick >/dev/null 2>&1
sleep 1
[ -z "$(dirs j5)" ] && ok "a live pid from an earlier boot does not protect it" \
  || bad "the stale claim kept it alive"

echo
printf '\n  %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
