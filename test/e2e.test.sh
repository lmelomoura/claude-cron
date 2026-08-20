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
              "worktree":{"enabled":true},
              "security":{"enabled":true,"model":"claude-opus-5","max_budget_usd":5}}]}
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

# secid <analyze-stdout> -- the analysis id out of whichever shape it came in:
# bash's own `printf '{"analysis_id":%s}'` (--detach, no space) or Python's
# `json.dumps` (open-analysis, a space after the colon).
secid() { printf '%s' "$1" | grep -Eo '"analysis_id" *: *[0-9]+' | tail -1 | grep -Eo '[0-9]+$'; }
# secstate <project> <analysis-id> -- that one row's state, straight off the
# ledger `security list` reads, never guessed from the run that carried it.
secstate() {
  "$CC" security list --project "$1" 2>/dev/null \
    | jq -r --argjson a "$2" '.[] | select(.id == $a) | .state // empty'
}
# secnote <project> <analysis-id> -- that row's coverage note, the one line a
# reader has to judge the report's blind spots by.
secnote() {
  "$CC" security list --project "$1" 2>/dev/null \
    | jq -r --argjson a "$2" '.[] | select(.id == $a) | .coverage_note // empty'
}

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

# ------------------------------------------------------- security analysis
# The `sandbox` project's own security block (see the fixture above). Unlike
# 1-7, these drive `claude-cron security analyze` rather than `run` -- the
# real path the dashboard's Analyse button takes, over the real run_job and a
# real (fake) agent, not the stubbed run_job the bash-level selftest uses for
# the same three shapes.

echo
echo "8. a detached security analysis returns fast, and the run closes it once it ends"
t0=$(date +%s)
out8="$(FAKE_MODE=complete FAKE_SESSION=sess-sec-done "$CC" security analyze --detach sandbox anything main quick)"
t1=$(date +%s)
[ "$((t1 - t0))" -lt 5 ] && ok "the command returns in $((t1 - t0))s -- not after the run it started" \
  || bad "--detach blocked for $((t1 - t0))s"
aid8="$(secid "$out8")"
[ -n "$aid8" ] && ok "and prints the analysis id it opened: $aid8" || bad "no analysis id in: $out8"
w=0
while [ "$w" -lt 20 ] && [ "$(secstate sandbox "$aid8")" = "running" ]; do sleep 1; w=$((w + 1)); done
[ "$(secstate sandbox "$aid8")" = "done" ] \
  && ok "and the row closes done once the detached run actually finishes (waited ${w}s)" \
  || bad "left '$(secstate sandbox "$aid8")' after ${w}s"
sleep 1   # let run_job's own teardown release the derived job's slot before the next scenario

echo
echo "9. an agent that dies on launch still closes its analysis -- failed, not stuck running"
cat > "$ROOT/dead-claude" <<'SH'
#!/usr/bin/env bash
exit 3
SH
chmod +x "$ROOT/dead-claude"
out9="$(CLAUDE_CRON_CLAUDE_BIN="$ROOT/dead-claude" "$CC" security analyze --detach sandbox anything main quick)"
aid9="$(secid "$out9")"
w=0
while [ "$w" -lt 20 ] && [ "$(secstate sandbox "$aid9")" = "running" ]; do sleep 1; w=$((w + 1)); done
[ "$(secstate sandbox "$aid9")" = "failed" ] \
  && ok "a claude that exits without a word still closes the row failed (waited ${w}s)" \
  || bad "left '$(secstate sandbox "$aid9")' after ${w}s"
sleep 1

echo
echo "10. a row stuck 'running' with no live run cannot brick the button"
sha="$(git -C "$ROOT/work/app" rev-parse HEAD)"
stuck_out="$("$CC" security open-analysis --project sandbox --repo sandbox --branch main \
  --commit "$sha" --profile quick --run-id security-sandbox)"
stuck_id="$(secid "$stuck_out")"
[ "$(secstate sandbox "$stuck_id")" = "running" ] \
  && ok "the stuck row starts out running, exactly like a real one" \
  || bad "open-analysis did not open row $stuck_id running"
# The default grace (120s) would leave a row this young alone -- it may still
# be on its way to acquire_slot -- so the sweep is forced to fire immediately.
CLAUDE_CRON_SECURITY_STALE_GRACE=0 FAKE_MODE=complete FAKE_SESSION=sess-sec-fresh \
  "$CC" security analyze sandbox anything main quick >/dev/null 2>&1
[ "$(secstate sandbox "$stuck_id")" = "failed" ] \
  && ok "the next analyse's own preflight sweeps it before opening a fresh one" \
  || bad "stuck row $stuck_id left '$(secstate sandbox "$stuck_id")'"

echo
echo "11. an agent that never ran the deterministic phases cannot close done"
# Nothing engine-side runs `prepare`. An agent that skips its first command
# exits cleanly, so the engine's own close-out closes the row with `success` --
# and the result was a `done` analysis with no findings, no coverage note and
# no banner, which then became the baseline every later analysis is diffed
# against. The whole path is exercised here, over the real run_job: only the
# LEDGER can tell the two apart, and only after the run has ended.
out11="$(FAKE_MODE=complete FAKE_SKIP_PREPARE=1 FAKE_SESSION=sess-sec-noprep \
  "$CC" security analyze --detach sandbox anything main quick)"
aid11="$(secid "$out11")"
w=0
while [ "$w" -lt 20 ] && [ "$(secstate sandbox "$aid11")" = "running" ]; do sleep 1; w=$((w + 1)); done
[ "$(secstate sandbox "$aid11")" = "capped" ] \
  && ok "a run whose agent skipped prepare closes capped, not done (waited ${w}s)" \
  || bad "left '$(secstate sandbox "$aid11")' after ${w}s -- expected capped"
case "$(secnote sandbox "$aid11")" in
  *"deterministic phases never ran"*) ok "and the report says why, in the coverage note" ;;
  *) bad "no coverage note explaining the downgrade: '$(secnote sandbox "$aid11")'" ;;
esac

echo
printf '\n  %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
