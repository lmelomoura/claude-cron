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

export AGENTLOOP_CONFIG="$ROOT/config"
export AGENTLOOP_DATA="$ROOT/data"
export AGENTLOOP_CLAUDE_BIN="$E2E/fake-claude"
# Here rather than beside the OpenAI scenarios below, because the FIRST `tick`
# of this file already reaches for Codex: with no config/models.json the tick
# finds the catalog stale and detaches `_resolve_models`, which runs `codex
# debug models` through `$(command -v codex)` -- the operator's real CLI,
# against their real ~/.codex. Every `$AL` in this file must see the stand-in.
export AGENTLOOP_CODEX_BIN="$E2E/fake-codex"
export CODEX_HOME="$ROOT/codex-home"        # the stand-in's rollouts; never ~/.codex
# The same for OpenCode: the daily catalog pass would otherwise run the
# operator's real `opencode models --verbose` against their real config.
export AGENTLOOP_OPENCODE_BIN="$E2E/fake-opencode"
# the price source is a fixture: no test reaches the network
export AGENTLOOP_PRICING_URL="file://$REPO/test/fixtures/pricing/litellm-sample.json"
mkdir -p "$CODEX_HOME"
AL="$REPO/bin/agentloop"

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

# What the operator would have switched on in Settings. Explicit rather than
# seeded: the seed is scenario 28's own subject.
cat > "$ROOT/config/platforms.json" <<'JSON'
{"platforms":{"anthropic":{"enabled":true,"bin":"","models":["claude-opus-5"]},
              "openai":{"enabled":true,"bin":"","models":["gpt-5.6-sol"]},
              "opencode":{"enabled":true,"bin":"","models":["opencode/big-pickle","pdm_ai/glm-5.3-flash"]}}}
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
# bash's own `printf '{"analysis_id":%s}'` (--detach, no space), Python's
# `json.dumps` (open-analysis, a space after the colon), or the one line
# `security analyze` prints as it OPENS the analysis -- before the run starts,
# in the foreground and --detach forms alike:
# `analysis N — project/repo @ branch (sha) — job id`.
secid() { printf '%s\n' "$1" | grep -Eo '"analysis_id" *: *[0-9]+|^analysis [0-9]+' | tail -1 | grep -Eo '[0-9]+$'; }
# secstate <project> <analysis-id> -- that one row's state, straight off the
# ledger `security list` reads, never guessed from the run that carried it.
secstate() {
  "$AL" security list --project "$1" 2>/dev/null \
    | jq -r --argjson a "$2" '.[] | select(.id == $a) | .state // empty'
}
# secnote <project> <analysis-id> -- that row's coverage note, the one line a
# reader has to judge the report's blind spots by.
secnote() {
  "$AL" security list --project "$1" 2>/dev/null \
    | jq -r --argjson a "$2" '.[] | select(.id == $a) | .coverage_note // empty'
}

echo
echo "1. a run that declares a clean ending is torn down and removed"
mkjob j1 complete
FAKE_MODE=complete FAKE_SESSION=sess-clean "$AL" run j1 >/dev/null 2>&1
sleep 2
[ -z "$(dirs j1)" ] && ok "its run directory is gone" || bad "left $(dirs j1)"

echo
echo "2. a run that never declares an ending keeps its tree, marked open"
mkjob j2 undeclared
FAKE_MODE=undeclared FAKE_SESSION=sess-cut "$AL" run j2 >/dev/null 2>&1
sleep 2
d2="$(dirs j2 | head -1)"
[ -n "$d2" ] && ok "its run directory survives ($d2)" || bad "the directory was removed"
[ "$(ended j2 "$d2")" = "open" ] && ok "and is marked open" || bad "marked '$(ended j2 "$d2")'"
[ "$(cat "$ROOT/data/worktrees/j2/$d2/.session" 2>/dev/null)" = "sess-cut" ] \
  && ok "with the session bound to it" || bad "session not bound"

echo
echo "3. a resume continues in that same directory, not a fresh one"
FAKE_MODE=complete FAKE_SESSION=sess-cut "$AL" resume j2 sess-cut >/dev/null 2>&1
sleep 2
grep -q "resumed sess-cut in its own tree" "$ROOT/data/tick.log" 2>/dev/null \
  && ok "the tick log says it reattached" || bad "no reattach line in tick.log"
[ -z "$(dirs j2)" ] && ok "and the finished session took its directory with it" \
  || bad "left $(dirs j2)"

echo
echo "4. work on no remote is reported, and the tree is still kept"
mkjob j3 dirty
FAKE_MODE=dirty FAKE_SESSION=sess-dirty "$AL" run j3 >/dev/null 2>&1
sleep 2
d3="$(dirs j3 | head -1)"
[ -n "$d3" ] && ok "the directory survives" || bad "removed despite undelivered work"
grep -q 'UNDELIVERED' "$ROOT/data/runs.ndjson" 2>/dev/null \
  && ok "and the run says UNDELIVERED" || bad "no UNDELIVERED note in the journal"

echo
echo "5. an open session nobody resumes expires and is reclaimed"
AGENTLOOP_SESSION_TTL=0 "$AL" tick >/dev/null 2>&1
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
"$AL" tick >/dev/null 2>&1
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
"$AL" tick >/dev/null 2>&1
sleep 1
[ -z "$(dirs j5)" ] && ok "a live pid from an earlier boot does not protect it" \
  || bad "the stale claim kept it alive"

# ------------------------------------------------------- security analysis
# The `sandbox` project's own security block (see the fixture above). Unlike
# 1-7, these drive `agentloop security analyze` rather than `run` -- the
# real path the dashboard's Analyse button takes, over the real run_job and a
# real (fake) agent, not the stubbed run_job the bash-level selftest uses for
# the same three shapes.

echo
echo "8. a detached security analysis returns fast, and the run closes it once it ends"
t0=$(date +%s)
out8="$(FAKE_MODE=complete FAKE_SESSION=sess-sec-done "$AL" security analyze --detach sandbox anything main quick)"
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
out9="$(AGENTLOOP_CLAUDE_BIN="$ROOT/dead-claude" "$AL" security analyze --detach sandbox anything main quick)"
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
stuck_out="$("$AL" security open-analysis --project sandbox --repo sandbox --branch main \
  --commit "$sha" --profile quick --run-id security-sandbox)"
stuck_id="$(secid "$stuck_out")"
[ "$(secstate sandbox "$stuck_id")" = "running" ] \
  && ok "the stuck row starts out running, exactly like a real one" \
  || bad "open-analysis did not open row $stuck_id running"
# The default grace (120s) would leave a row this young alone -- it may still
# be on its way to acquire_slot -- so the sweep is forced to fire immediately.
AGENTLOOP_SECURITY_STALE_GRACE=0 FAKE_MODE=complete FAKE_SESSION=sess-sec-fresh \
  "$AL" security analyze sandbox anything main quick >/dev/null 2>&1
[ "$(secstate sandbox "$stuck_id")" = "failed" ] \
  && ok "the next analyse's own preflight sweeps it before opening a fresh one" \
  || bad "stuck row $stuck_id left '$(secstate sandbox "$stuck_id")'"

echo
echo "11. an agent that never ran the deterministic phases cannot close done"
# Nothing engine-side runs `prepare` on Claude Code (on Codex the engine does
# -- scenario 24). An agent that skips its first command
# exits cleanly, so the engine's own close-out closes the row with `success` --
# and the result was a `done` analysis with no findings, no coverage note and
# no banner, which then became the baseline every later analysis is diffed
# against. The whole path is exercised here, over the real run_job: only the
# LEDGER can tell the two apart, and only after the run has ended.
out11="$(FAKE_MODE=complete FAKE_SKIP_PREPARE=1 FAKE_SESSION=sess-sec-noprep \
  "$AL" security analyze --detach sandbox anything main quick)"
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
echo "12. the analysis is launched with the Agent tool closed and its prompt intact"
# THE ONE SCENARIO THAT READS AN ARGV. Everything above steers `fake-claude` by
# env var and never looks at how it was invoked -- which is why this suite was
# green while every real analysis died at launch: `--disallowedTools` is
# variadic, it sat immediately before the prompt positional, Commander ate the
# prompt as a second tool name, and the real CLI exited with "Input must be
# provided either through stdin or as a prompt argument when using --print".
# Here the derived security job goes down the real `security analyze` path and
# the launch line is read back off the stand-in's own "$@".
argv="$ROOT/launch-argv"
rm -f "$argv"
FAKE_ARGV_OUT="$argv" FAKE_MODE=complete FAKE_SESSION=sess-sec-argv \
  "$AL" security analyze sandbox anything main quick >/dev/null 2>&1
# <index><TAB><argument>. `at <n>` is the n-th argument, `idx <word>` its index.
at()  { awk -F'\t' -v i="$1" '$1==i {print $2; exit}' "$argv"; }
idx() { awk -F'\t' -v w="$1" '$2==w {print $1; exit}' "$argv"; }
argc="$(awk -F'\t' '$1=="ARGC" {print $2; exit}' "$argv" 2>/dev/null)"
di="$(idx '--disallowedTools' 2>/dev/null)"
[ -n "${di:-}" ] && [ "$(at "$((di + 1))")" = "Agent" ] \
  && ok "the real analysis launch carries --disallowedTools Agent" \
  || bad "no --disallowedTools Agent in the launch argv: $(tr '\n' ' ' < "$argv" 2>/dev/null)"
mi="$(idx '--' 2>/dev/null)"
[ -n "${mi:-}" ] && [ "$((mi + 1))" = "${argc:-0}" ] \
  && ok "and its prompt is the one argument after --, not swallowed by the variadic flag" \
  || bad "the prompt is not a lone positional after -- (-- at '${mi:-none}', argc '${argc:-none}')"

# ------------------------------------------------------- the OpenAI platform
# The same lifecycle over the Codex stand-in: the run goes down a FIFO into
# the normalizer, the classifier reads the normalized stream, the rollout
# under the sandboxed CODEX_HOME exported at the top of this file supplies the
# model that ran.
cp "$REPO/config/pricing.example.json" "$ROOT/config/pricing.json"
# The catalog a slug is validated against, obtained the way a real install
# obtains it: `resolve-models openai` asks the CLI for `debug models`.
"$AL" resolve-models openai >/dev/null 2>&1
jq -e '.openai.models | length > 0' "$ROOT/config/models.json" >/dev/null \
  && ok "resolve-models openai wrote the catalog from the stand-in's debug models" \
  || bad "no openai catalog after resolve-models"
jq -e '([.openai.models[] | select(.visibility=="list") | .slug] | index("gpt-reserve")) == null' \
  "$ROOT/config/models.json" >/dev/null \
  && ok "the hidden gpt-reserve never reaches the visible slug list" \
  || bad "gpt-reserve leaked into the visible models"
jq -e '(.openai.models[] | select(.slug=="gpt-5.6-sol") | .efforts | index("ultra")) != null' \
  "$ROOT/config/models.json" >/dev/null \
  && ok "gpt-5.6-sol's efforts include ultra" \
  || bad "gpt-5.6-sol has no ultra effort"
mkjob_openai() { # mkjob_openai <id> [permission]
  printf '{"jobs":[{"id":"%s","project":"sandbox","enabled":false,"platform":"openai","model":"gpt-5.6-sol","effort":"high","prompt":"do the thing",
    "interval_seconds":3600,"permission_mode":"%s","max_parallel":1}]}\n' "$1" "${2:-workspace-write}" \
    > "$ROOT/config/jobs.json"
  mkdir -p "$ROOT/config/prechecks"
  printf '#!/bin/bash\nexit 0\n' > "$ROOT/config/prechecks/$1.sh"
  chmod +x "$ROOT/config/prechecks/$1.sh"
}
lastrun() { tail -1 "$ROOT/data/runs.ndjson" 2>/dev/null; }
# <index><TAB><argument> readers over a recorded argv file
at_in()  { awk -F'\t' -v i="$2" '$1==i {print $2; exit}' "$1"; }
idx_in() { awk -F'\t' -v w="$2" '$2==w {print $1; exit}' "$1"; }

echo
echo "13. an OpenAI run goes through the Codex stand-in and reads as a clean success"
mkjob_openai j13
FAKE_MODE=complete FAKE_SESSION=thr-clean "$AL" run j13 >/dev/null 2>&1
sleep 2
[ -z "$(dirs j13)" ] && ok "its run directory is gone (declared ending, nothing undelivered)" || bad "left $(dirs j13)"
[ "$(lastrun | jq -r .status)" = "success" ] \
  && ok "status success: the CLI's stdin line was filtered out of stderr" \
  || bad "status $(lastrun | jq -r .status): $(lastrun | jq -r .note)"
[ "$(lastrun | jq -r .session)" = "thr-clean" ] && ok "the session recorded is the thread id" || bad "session $(lastrun | jq -r .session)"
[ "$(lastrun | jq -r .model_id)" = "gpt-5.6-sol-real" ] \
  && ok "model_id is the model the rollout says ran, not the slug asked for" || bad "model_id $(lastrun | jq -r .model_id)"
[ "$(lastrun | jq -r .platform)" = "openai" ] && ok "the journal names the platform" || bad "platform $(lastrun | jq -r .platform)"
[ "$(lastrun | jq -r .cost_basis)" = "estimated" ] && [ "$(lastrun | jq -r .cost)" = "0.031784" ] \
  && ok "the cost is the estimate from the seeded price table (\$0.031784 for 32,675 in / 28,160 cached / 123 out)" \
  || bad "cost $(lastrun | jq -c '{cost,cost_basis}')"
[ "$(lastrun | jq -r '.tokens.input')" = "32675" ] && [ "$(lastrun | jq -r '.tokens.reasoning')" = "0" ] \
  && ok "the token counts ride on the record" || bad "tokens $(lastrun | jq -c .tokens)"
s13="$(ls "$ROOT"/data/logs/j13/*.stream.ndjson 2>/dev/null | head -1)"
[ -f "$s13.raw" ] && grep -q '"thread.started"' "$s13.raw" \
  && ok "the raw Codex stream is kept beside the normalized one" || bad "no .raw copy"
head -1 "$s13" | jq -e '.subtype=="init" and .platform=="openai"' >/dev/null 2>&1 \
  && ok "the normalized stream opens with the init event" || bad "first line: $(head -1 "$s13")"
[ ! -e "$ROOT"/data/logs/j13/*.raw.fifo ] && ok "the FIFO was removed" || bad "FIFO left behind"
jq -e '.openai.five_hour.utilization == 0.05 and .openai.five_hour.source == "rollout"' "$ROOT/data/rate-limits.json" >/dev/null 2>&1 \
  && ok "the run's rollout fed the openai usage windows" || bad "rate-limits.json: $(cat "$ROOT/data/rate-limits.json" 2>/dev/null)"

echo
echo "14. an OpenAI run that never declares an ending keeps its tree, bound to the thread id"
mkjob_openai j14
FAKE_MODE=undeclared FAKE_SESSION=thr-cut "$AL" run j14 >/dev/null 2>&1
sleep 2
d14="$(dirs j14 | head -1)"
[ -n "$d14" ] && [ "$(ended j14 "$d14")" = "open" ] && ok "kept, marked open" || bad "dir '$d14' ended '$(ended j14 "$d14")'"
[ "$(cat "$ROOT/data/worktrees/j14/$d14/.session" 2>/dev/null)" = "thr-cut" ] \
  && ok ".session holds the thread id" || bad ".session not bound to the thread"

echo
echo "15. a resume of that thread reattaches, and launches as exec resume in the process cwd"
argv15="$ROOT/argv-15"; rm -f "$argv15"
FAKE_ARGV_OUT="$argv15" FAKE_MODE=complete FAKE_SESSION=thr-cut "$AL" resume j14 thr-cut >/dev/null 2>&1
sleep 2
grep -q "resumed thr-cut in its own tree" "$ROOT/data/tick.log" && ok "the tick log says it reattached" || bad "no reattach line"
[ -z "$(dirs j14)" ] && ok "and the finished session took its directory with it" || bad "left $(dirs j14)"
[ "$(at_in "$argv15" 1)" = "exec" ] && [ "$(at_in "$argv15" 2)" = "resume" ] \
  && ok "argv opens with exec resume" || bad "argv: $(tr '\n' ' ' < "$argv15")"
[ -z "$(idx_in "$argv15" -C)" ] && ok "no -C on a resume (exec resume refuses it; the cwd is the process's)" || bad "-C passed to exec resume"
[ -n "$(idx_in "$argv15" sandbox_mode=workspace-write)" ] && ok "the sandbox travels as -c sandbox_mode=…" || bad "no sandbox_mode override"
ti="$(idx_in "$argv15" thr-cut)"; mi="$(idx_in "$argv15" --)"
[ -n "$ti" ] && [ -n "$mi" ] && [ "$ti" -lt "$mi" ] \
  && ok "the thread id precedes --, and the prompt follows it" || bad "thread id at '$ti', -- at '$mi'"

echo
echo "16. work on no remote is reported for an OpenAI run too"
mkjob_openai j16
FAKE_MODE=dirty FAKE_SESSION=thr-dirty "$AL" run j16 >/dev/null 2>&1
sleep 2
lastrun | grep -q 'UNDELIVERED' && [ -n "$(dirs j16)" ] && ok "UNDELIVERED, and the tree is kept" || bad "no UNDELIVERED note, or tree gone"

echo
echo "17. the launch line of a fresh OpenAI run, read back off the stand-in's argv"
argv17="$ROOT/argv-17"; rm -f "$argv17"
mkjob_openai j17 read-only
FAKE_ARGV_OUT="$argv17" FAKE_MODE=complete FAKE_SESSION=thr-argv "$AL" run j17 >/dev/null 2>&1
sleep 1
argc17="$(awk -F'\t' '$1=="ARGC" {print $2; exit}' "$argv17")"
[ "$(at_in "$argv17" 1)" = "exec" ] && [ "$(at_in "$argv17" 2)" = "--json" ] && ok "exec --json" || bad "argv: $(tr '\n' ' ' < "$argv17")"
ci="$(idx_in "$argv17" -C)"; cwd17="$(at_in "$argv17" $((ci + 1)))"
# Asserted on the PATH, not with `-d`: this run declares a clean ending, so its
# worktree is torn down by the time the argv is read back here.
case "${ci:+$cwd17}" in
  "$ROOT/data/worktrees/j17/"*) ok "-C names the run's working directory" ;;
  *) bad "-C missing or not the run's worktree: '$cwd17'" ;;
esac
mi="$(idx_in "$argv17" -m)"; [ "$(at_in "$argv17" $((mi + 1)))" = "gpt-5.6-sol" ] && ok "-m carries the slug verbatim" || bad "-m $(at_in "$argv17" $((mi + 1)))"
si="$(idx_in "$argv17" -s)"; [ "$(at_in "$argv17" $((si + 1)))" = "read-only" ] && ok "-s read-only" || bad "-s '$(at_in "$argv17" $((si + 1)))'"
[ -n "$(idx_in "$argv17" approval_policy=never)" ] && ok "-c approval_policy=never, bare" || bad "no bare approval_policy=never"
[ -n "$(idx_in "$argv17" model_reasoning_effort=high)" ] && ok "-c model_reasoning_effort=high, bare" || bad "no bare effort override"
[ -z "$(idx_in "$argv17" --disable)" ] && ok "no --disable flag: it closes nothing (measured)" || bad "--disable was passed"
[ -z "$(idx_in "$argv17" --skip-git-repo-check)" ] && bad "no --skip-git-repo-check" || ok "--skip-git-repo-check"
[ -z "$(idx_in "$argv17" sandbox_workspace_write.network_access=true)" ] \
  && ok "read-only is sealed to the network too: no override" || bad "read-only was given the network"
dd="$(idx_in "$argv17" --)"; [ -n "$dd" ] && [ "$((dd + 1))" = "$argc17" ] \
  && ok "the prompt is the one argument after --" || bad "-- at '$dd', argc $argc17"

echo
echo "17b. a workspace-write run gets back the network AND the git directory its commits write to"
argv17b="$ROOT/argv-17b"; rm -f "$argv17b"
mkjob_openai j17b workspace-write
FAKE_ARGV_OUT="$argv17b" FAKE_MODE=complete FAKE_SESSION=thr-argv-net "$AL" run j17b >/dev/null 2>&1
sleep 1
si="$(idx_in "$argv17b" -s)"; [ "$(at_in "$argv17b" $((si + 1)))" = "workspace-write" ] \
  && ok "-s workspace-write" || bad "-s '$(at_in "$argv17b" $((si + 1)))'"
[ -n "$(idx_in "$argv17b" sandbox_workspace_write.network_access=true)" ] \
  && ok "-c sandbox_workspace_write.network_access=true, bare" || bad "no network override: every API this fleet talks to is unreachable"
# The run works in a `git worktree add` checkout, so its commits write into
# $ROOT/work/app/.git -- outside the tree, and denied without this.
wr17b="$(awk -F'\t' '$2 ~ /^sandbox_workspace_write.writable_roots=/ {print $2; exit}' "$argv17b")"
case "$wr17b" in
  *"\"$ROOT/work/app/.git\""*) ok "-c writable_roots names the canonical repo's git directory" ;;
  *) bad "writable_roots is '${wr17b:-missing}'" ;;
esac

echo
echo "18. a spent OpenAI quota is rate_limited, outside the backoff"
mkjob_openai j18
echo '{"j18":{"fail_streak":2}}' > "$ROOT/data/state.json"
FAKE_MODE=quota FAKE_SESSION=thr-quota "$AL" run j18 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "rate_limited" ] \
  && ok "error / rate_limited" || bad "$(lastrun | jq -c '{status,cause}')"
[ "$(jq -r '.j18.fail_streak' "$ROOT/data/state.json")" = "2" ] && ok "fail_streak untouched" || bad "streak $(jq -r '.j18.fail_streak' "$ROOT/data/state.json")"
[ "$(jq -r '.openai.five_hour.status' "$ROOT/data/rate-limits.json")" = "usage_limit_reached" ] \
  && ok "and the fuller openai window is marked spent until its reset" || bad "window status $(jq -c .openai "$ROOT/data/rate-limits.json")"

echo
echo "19. a stop ends an OpenAI run that will not end by itself"
mkjob_openai j19
FAKE_MODE=hang FAKE_SESSION=thr-hang "$AL" run j19 >/dev/null 2>&1 &
w=0; while [ "$w" -lt 20 ] && ! ls "$ROOT"/data/locks/j19/*/child >/dev/null 2>&1; do sleep 1; w=$((w + 1)); done
sleep 1
"$AL" stop j19 >/dev/null 2>&1
wait
[ "$(lastrun | jq -r .status)" = "stopped" ] && ok "status stopped (waited ${w}s for the slot)" || bad "status $(lastrun | jq -r .status)"
[ ! -e "$ROOT"/data/logs/j19/*.raw.fifo ] && ok "the FIFO was removed" || bad "FIFO left behind"

echo
echo "20. a run that cannot start is refused in tick.log before it costs a slot"
mkjob_openai j20
FAKE_CODEX_LOGGED_OUT=1 "$AL" run j20 >/dev/null 2>&1
grep -q 'j20: openai is not ready (codex is not signed in' "$ROOT/data/tick.log" && ok "no login → refused" || bad "no login refusal line"
[ ! -d "$ROOT/data/logs/j20" ] && ok "and no log was written" || bad "a run started without a login"
sed -i '' 's/"gpt-5.6-sol"/"gpt-nope"/' "$ROOT/config/jobs.json"
"$AL" run j20 >/dev/null 2>&1
grep -q "j20: model 'gpt-nope' is not in the OpenAI catalog" "$ROOT/data/tick.log" && ok "unknown slug → refused" || bad "no catalog refusal"
mkjob_openai j20
sed -i '' 's/"platform":"openai"/"platform":"openai","interactive":true/' "$ROOT/config/jobs.json"
"$AL" run j20 >/dev/null 2>&1
grep -q "j20: interactive is not available on openai" "$ROOT/data/tick.log" && ok "interactive → refused" || bad "no interactive refusal"
mkjob_openai j20
sed -i '' 's/"platform":"openai"/"platform":"openai","disallowed_tools":"Agent"/' "$ROOT/config/jobs.json"
FAKE_MODE=complete FAKE_SESSION=thr-tools "$AL" run j20 >/dev/null 2>&1
grep -q "j20: disallowed_tools is ignored on openai" "$ROOT/data/tick.log" && ok "disallowed_tools → one line, run goes on" || bad "no ignored-tools line"
sleep 2
[ "$(lastrun | jq -r .status)" = "success" ] && ok "and the run itself went on to finish" || bad "status $(lastrun | jq -r .status)"

echo
echo "21. the run-end hook learns the platform, the cost basis and the tokens"
mkdir -p "$ROOT/config/hooks"
printf '#!/bin/bash\nprintf "%%s %%s %%s\\n" "$AL_PLATFORM" "$AL_COST_BASIS" "$AL_TOKENS" > "%s/hook-21.out"\n' "$ROOT" > "$ROOT/config/hooks/on-run-end.sh"
chmod +x "$ROOT/config/hooks/on-run-end.sh"
mkjob_openai j21
FAKE_MODE=complete FAKE_SESSION=thr-hook "$AL" run j21 >/dev/null 2>&1
sleep 3
case "$(cat "$ROOT/hook-21.out" 2>/dev/null)" in
  "openai estimated {"*'"input":32675'*) ok "AL_PLATFORM, AL_COST_BASIS and AL_TOKENS reach the hook" ;;
  *) bad "hook saw: $(cat "$ROOT/hook-21.out" 2>/dev/null)" ;;
esac
rm -f "$ROOT/config/hooks/on-run-end.sh"

echo
echo "22. a session is resumed on the platform it ran on, or not at all"
mkjob_openai j22
FAKE_MODE=undeclared FAKE_SESSION=thr-moved "$AL" run j22 >/dev/null 2>&1
sleep 2
# Moved onto a model Settings switched on (the fixture at the top): the
# stand-in cannot resolve a family, so a bare `opus` would be refused by the
# model gate first, and never reach the resume refusal this scenario is about.
sed -i '' 's/"platform":"openai"/"platform":"anthropic"/; s/"gpt-5.6-sol"/"claude-opus-5"/; s/"workspace-write"/"dontAsk"/; s/"effort":"high"/"effort":"low"/' "$ROOT/config/jobs.json"
"$AL" resume j22 thr-moved >/dev/null 2>&1
grep -q 'j22: refusing to resume thr-moved — this session belongs to openai; the job now runs on anthropic' "$ROOT/data/tick.log" \
  && ok "the resume is refused, naming both platforms" || bad "no refusal line for the moved job"
[ -n "$(dirs j22)" ] && ok "and the open session's tree is left where it was" || bad "the tree was taken"

echo
echo "23. the price table refreshes from the source and names what it could not price"
# The seeded example table prices gpt-5.4-mini and the source does not carry it,
# so its row would simply be KEPT (that rule has its own selftest case). Drop it
# here, so what this scenario asserts is the gap itself: a VISIBLE catalog slug
# with no price at all, named by platforms and in tick.log.
jq 'del(.openai["gpt-5.4-mini"])' "$ROOT/config/pricing.json" > "$ROOT/pricing.seed"
mv "$ROOT/pricing.seed" "$ROOT/config/pricing.json"
: > "$ROOT/data/tick.log"
"$AL" resolve-pricing >/dev/null 2>&1; rp_rc=$?
[ "$rp_rc" -eq 0 ] && ok "resolve-pricing exits 0" || bad "resolve-pricing failed: rc $rp_rc"
jq -e '.openai["gpt-5.6-sol"].cache_write == 5' "$ROOT/config/pricing.json" >/dev/null \
  && ok "gpt-5.6-sol's cache-write price came from the source (5 per 1M)" || bad "sol row $(jq -c '.openai["gpt-5.6-sol"]' "$ROOT/config/pricing.json")"
[ "$(jq -r '._source_url' "$ROOT/config/pricing.json")" = "$AGENTLOOP_PRICING_URL" ] \
  && ok "the table records its source" || bad "source $(jq -r '._source_url' "$ROOT/config/pricing.json")"
[ "$("$AL" platforms | jq -c '.openai.unpriced')" = '["gpt-5.4-mini"]' ] \
  && ok "platforms names the one visible slug the source does not price" || bad "unpriced $("$AL" platforms | jq -c '.openai.unpriced')"
grep -q 'pricing: no price for gpt-5.4-mini' "$ROOT/data/tick.log" && ok "and tick.log says so" || bad "no tick.log line"

echo
echo "24. a security analysis on OpenAI goes through the Codex stand-in, forbids subagents in words, and closes done"
# A second project, on the openai platform, over the same repository. Its
# derived job takes the block's platform and the platform's security default
# (full-access: the ledger lives outside the worktree).
jq --arg cwd "$ROOT/work/app" '.projects += [{"name":"sandbox-oa","cwd":$cwd,"base":"main","worktree":{"enabled":true},
   "security":{"enabled":true,"platform":"openai","model":"gpt-5.6-sol","max_budget_usd":5}}]' \
   "$ROOT/config/projects.json" > "$ROOT/projects.next" && mv "$ROOT/projects.next" "$ROOT/config/projects.json"
# The stand-in does NOT run prepare here (FAKE_SKIP_PREPARE), so a `done`
# close can only mean the ENGINE ran the deterministic phase before launching
# it -- which is what run_job does on openai. AL_SECURITY_ENGINES=off keeps
# that engine-side prepare off the network, the way `--offline` keeps the
# stand-ins' own; the fixture has no lockfile, so nothing else reaches for
# one either.
argv24="$ROOT/argv-24"; prompt24="$ROOT/prompt-24"; rm -f "$argv24" "$prompt24"
out24="$(AL_SECURITY_ENGINES=off FAKE_SKIP_PREPARE=1 FAKE_ARGV_OUT="$argv24" FAKE_PROMPT_OUT="$prompt24" \
  FAKE_MODE=complete FAKE_SESSION=thr-sec \
  "$AL" security analyze sandbox-oa anything main quick 2>&1)"
aid24="$(secid "$out24")"
[ -n "$aid24" ] && ok "the analysis opened: $aid24" || bad "no analysis id in: $out24"
[ "$(secstate sandbox-oa "$aid24")" = "done" ] \
  && ok "and closed done: the engine ran security prepare before the agent, and the close found nothing untriaged" \
  || bad "state '$(secstate sandbox-oa "$aid24")'"
grep -q 'deterministic phase ran before the agent' "$ROOT/data/tick.log" \
  && ok "the engine ran prepare before launching codex" || bad "no engine-side prepare line in tick.log"
[ "$(at_in "$argv24" 1)" = "exec" ] && ok "it went down the Codex launch line" || bad "argv: $(tr '\n' ' ' < "$argv24" 2>/dev/null)"
mi="$(idx_in "$argv24" -m)"; [ -n "${mi:-}" ] && [ "$(at_in "$argv24" $((mi + 1)))" = "gpt-5.6-sol" ] \
  && ok "-m carries the block's model" || bad "-m '$(at_in "$argv24" $((${mi:-0} + 1)))'"
[ -n "$(idx_in "$argv24" --dangerously-bypass-approvals-and-sandbox)" ] \
  && ok "full-access, the security default on openai" || bad "no bypass flag in the launch line"
[ -z "$(idx_in "$argv24" --disallowedTools)" ] && ok "no --disallowedTools: Codex cannot close a tool by flag" || bad "--disallowedTools was passed to codex"
grep -q 'Do not spawn subagents' "$prompt24" && ok "the prompt forbids subagents in words" || bad "no subagent ban in the prompt"
grep -q 'security-analysis/SKILL.md' "$prompt24" && ok "and names the skill file by path" || bad "the prompt does not name the skill file"
grep -q 'Agent. tool' "$prompt24" && bad "the prompt still speaks of the Agent tool" || ok "and never speaks of the Agent tool"
grep -q 'ALREADY RAN for this analysis' "$prompt24" && ! grep -q 'YOUR FIRST COMMAND' "$prompt24" \
  && ok "the prompt says the deterministic phase already ran" || bad "the prompt still asks the agent to run prepare, or never says the engine did"
[ "$(lastrun | jq -r .id)" = "security-sandbox-oa" ] && [ "$(lastrun | jq -r .platform)" = "openai" ] && [ "$(lastrun | jq -r .cost_basis)" = "estimated" ] \
  && ok "the journal has the derived job's run on openai, priced by estimate" || bad "$(lastrun | jq -c '{id,platform,cost_basis}')"
sleep 1

echo
echo "25. the account the installer pinned is the account the agent signs in as"
# The chain nobody had driven end to end: launchd hands the tick the plist's
# EnvironmentVariables, the engine reads AGENTLOOP_CLAUDE_CONFIG_DIR (and
# discards an ambient CLAUDE_CONFIG_DIR on purpose), and the CLI inherits it.
# The plists used to name only the CLI's variable, so the pin died at the door
# and every scheduled run signed in as the default account instead.
mkjob j25
acct25="$ROOT/account-25"; rm -f "$acct25"
FAKE_ACCOUNT_OUT="$acct25" AGENTLOOP_CLAUDE_CONFIG_DIR="$ROOT/pinned-account" \
  FAKE_MODE=complete FAKE_SESSION=sess-acct "$AL" run j25 >/dev/null 2>&1
[ "$(cat "$acct25" 2>/dev/null)" = "$ROOT/pinned-account" ] \
  && ok "the agent runs under the pinned account" || bad "the agent saw '$(cat "$acct25" 2>/dev/null)'"
# ...and an account nobody pinned stays the CLI's own default, so a run never
# borrows whichever account the shell that started it happened to export.
rm -f "$acct25"
FAKE_ACCOUNT_OUT="$acct25" CLAUDE_CONFIG_DIR="$ROOT/someones-session" \
  FAKE_MODE=complete FAKE_SESSION=sess-acct2 "$AL" run j25 >/dev/null 2>&1
[ -z "$(cat "$acct25" 2>/dev/null)" ] \
  && ok "and an ambient one is not borrowed" || bad "the agent inherited '$(cat "$acct25" 2>/dev/null)'"
sleep 1

echo
echo "26. a job on a platform switched off in Settings is skipped before it costs a slot"
mkjob j26
"$AL" platform disable anthropic >/dev/null 2>&1
FAKE_MODE=complete FAKE_SESSION=sess-26 "$AL" run j26 >/dev/null 2>&1
grep -q "j26: anthropic is disabled in Settings (agentloop platform enable anthropic), skipped" "$ROOT/data/tick.log" \
  && ok "the refusal is one line in tick.log" || bad "no refusal line: $(tail -3 "$ROOT/data/tick.log")"
[ -z "$(dirs j26)" ] && ok "and no run directory was cut" || bad "a worktree was cut for a refused run"
"$AL" platform enable anthropic >/dev/null 2>&1 || bad "platform enable anthropic failed over the stand-in"
FAKE_MODE=complete FAKE_SESSION=sess-26b "$AL" run j26 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .session)" = "sess-26b" ] && ok "enabled again, the same job runs" || bad "no run after enable: $(lastrun)"

echo
echo "27. a model switched off in Settings is refused, and the line names what is enabled"
mkjob_openai j27
printf '["gpt-5.6-luna"]' | "$AL" platform set-models openai >/dev/null 2>&1
FAKE_MODE=complete FAKE_SESSION=thr-27 "$AL" run j27 >/dev/null 2>&1
grep -q "j27: model 'gpt-5.6-sol' is not enabled in Settings — openai enables: gpt-5.6-luna, skipped" "$ROOT/data/tick.log" \
  && ok "the refusal names the model and the enabled list" || bad "no model refusal: $(tail -3 "$ROOT/data/tick.log")"
printf '["gpt-5.6-sol"]' | "$AL" platform set-models openai >/dev/null 2>&1

echo
echo "28. upgrade path: no platforms file and an enabled job -> seeded from it, and the run is unchanged"
mkjob j28
jq '.jobs[0].enabled = true | .jobs[0].model = "claude-opus-5"' "$ROOT/config/jobs.json" > "$ROOT/config/jobs.next" && mv "$ROOT/config/jobs.next" "$ROOT/config/jobs.json"
# Scenario 24 left "sandbox-oa" behind with its security block still enabled
# on openai, and platforms_seed's own comment says a platform is seeded
# enabled by EITHER an enabled job or an enabled security block -- left as
# is, that block alone would seed openai as enabled, and the assertion below
# would pass for the wrong reason (a leftover, not a fresh read of j28 alone).
jq '(.projects[] | select(.name == "sandbox-oa") | .security.enabled) = false' \
  "$ROOT/config/projects.json" > "$ROOT/projects.next" && mv "$ROOT/projects.next" "$ROOT/config/projects.json"
rm -f "$ROOT/config/platforms.json"
FAKE_MODE=complete FAKE_SESSION=sess-28 "$AL" run j28 >/dev/null 2>&1
sleep 2
jq -e '.platforms.anthropic.enabled == true and (.platforms.anthropic.models | index("claude-opus-5")) != null' "$ROOT/config/platforms.json" >/dev/null 2>&1 \
  && ok "the file was seeded with the enabled job's platform and model" || bad "seed: $(cat "$ROOT/config/platforms.json" 2>/dev/null)"
# The fixture at the top of this file enables openai; the seed, with no
# enabled openai job or project anywhere in this run, must not. This is the
# one observable that tells "seeded fresh" apart from "the fixture survived
# the rm -f above" -- both would pass the anthropic assertion just above.
jq -e '.platforms.openai.enabled == false' "$ROOT/config/platforms.json" >/dev/null 2>&1 \
  && ok "and openai came out disabled — this is the seed, not the fixture surviving the rm" \
  || bad "openai after reseed: $(cat "$ROOT/config/platforms.json" 2>/dev/null)"
[ "$(lastrun | jq -r .session)" = "sess-28" ] && ok "and the job ran as before" || bad "no run: $(lastrun)"

# Scenario 28 just deleted config/platforms.json to drive the fresh-seed path,
# and platforms_seed hardcodes opencode (and, with no openai job or security
# block left enabled at that moment, openai too) disabled -- job-level
# enablement is this task's own run_job, not that seed. Left as scenario 28's
# reseed wrote it, every job below would be refused before it ever reached
# run_job's own gates. Restore the fixture from the top of this file.
cat > "$ROOT/config/platforms.json" <<'JSON'
{"platforms":{"anthropic":{"enabled":true,"bin":"","models":["claude-opus-5"]},
              "openai":{"enabled":true,"bin":"","models":["gpt-5.6-sol"]},
              "opencode":{"enabled":true,"bin":"","models":["opencode/big-pickle","pdm_ai/glm-5.3-flash"]}}}
JSON

# ------------------------------------------------------- the OpenCode platform
# The same lifecycle over the OpenCode stand-in: the run goes down a FIFO
# into opencode_stream.py, the classifier reads the normalized stream, the
# stand-in's `export` supplies the model that ran, and the permission block
# travels in OPENCODE_CONFIG_CONTENT (read back through FAKE_CONFIG_OUT).
"$AL" resolve-models opencode >/dev/null 2>&1
jq -e '.opencode.models | length == 13' "$ROOT/config/models.json" >/dev/null \
  && ok "resolve-models opencode wrote the catalog from the stand-in's models --verbose" \
  || bad "no opencode catalog after resolve-models"
mkjob_opencode() { # mkjob_opencode <id> [permission] [model] [extra-json-fields]
  printf '{"jobs":[{"id":"%s","project":"sandbox","enabled":false,"platform":"opencode","model":"%s","effort":"high","prompt":"do the thing",
    "interval_seconds":3600,"permission_mode":"%s","max_parallel":1%s}]}\n' "$1" "${3:-pdm_ai/glm-5.3-flash}" "${2:-full-access}" "${4:-}" \
    > "$ROOT/config/jobs.json"
  mkdir -p "$ROOT/config/prechecks"
  printf '#!/bin/bash\nexit 0\n' > "$ROOT/config/prechecks/$1.sh"
  chmod +x "$ROOT/config/prechecks/$1.sh"
}

echo
echo "29. an OpenCode run goes through the stand-in and reads as a clean success"
mkjob_opencode j29 full-access opencode/big-pickle
FAKE_MODE=complete FAKE_SESSION=ses_clean "$AL" run j29 >/dev/null 2>&1
sleep 2
[ -z "$(dirs j29)" ] && ok "its run directory is gone (declared ending, nothing undelivered)" || bad "left $(dirs j29)"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "status success: nothing on stderr, a result on the stream" || bad "status $(lastrun | jq -r .status): $(lastrun | jq -r .note)"
[ "$(lastrun | jq -r .session)" = "ses_clean" ] && ok "the session recorded is the sessionID" || bad "session $(lastrun | jq -r .session)"
[ "$(lastrun | jq -r .model_id)" = "opencode/big-pickle-real" ] \
  && ok "model_id is the model the export says ran, not the id asked for" || bad "model_id $(lastrun | jq -r .model_id)"
[ "$(lastrun | jq -r .platform)" = "opencode" ] && ok "the journal names the platform" || bad "platform $(lastrun | jq -r .platform)"
[ "$(lastrun | jq -r .cost_basis)" = "none" ] && [ "$(lastrun | jq -r .cost)" = "0" ] \
  && ok "a model the catalog prices at zero records an UNKNOWN cost, never a free one" || bad "cost $(lastrun | jq -c '{cost,cost_basis}')"
[ "$(lastrun | jq -r '.tokens.input')" = "11974" ] && [ "$(lastrun | jq -r '.tokens.cached')" = "15488" ] \
  && ok "the token counts are the sum of the steps" || bad "tokens $(lastrun | jq -c .tokens)"
s29="$(ls "$ROOT"/data/logs/j29/*.stream.ndjson 2>/dev/null | head -1)"
[ -f "$s29.raw" ] && grep -q '"step_start"' "$s29.raw" && ok "the raw OpenCode stream is kept beside the normalized one" || bad "no .raw copy"
head -1 "$s29" | jq -e '.subtype=="init" and .platform=="opencode"' >/dev/null 2>&1 \
  && ok "the normalized stream opens with the init event" || bad "first line: $(head -1 "$s29")"
[ ! -e "$ROOT"/data/logs/j29/*.raw.fifo ] && ok "the FIFO was removed" || bad "FIFO left behind"
jq -e 'has("opencode") | not' "$ROOT/data/rate-limits.json" >/dev/null 2>&1 \
  && ok "no usage window was invented for opencode" || bad "rate-limits.json grew an opencode block"

echo
echo "30. an OpenCode run that never declares an ending keeps its tree, bound to the session"
mkjob_opencode j30
FAKE_MODE=undeclared FAKE_SESSION=ses_cut "$AL" run j30 >/dev/null 2>&1
sleep 2
d30="$(dirs j30 | head -1)"
[ -n "$d30" ] && [ "$(ended j30 "$d30")" = "open" ] && ok "kept, marked open" || bad "dir '$d30' ended '$(ended j30 "$d30")'"
[ "$(cat "$ROOT/data/worktrees/j30/$d30/.session" 2>/dev/null)" = "ses_cut" ] && ok ".session holds the sessionID" || bad ".session not bound"

echo
echo "31. a resume reattaches, and launches with -s AND --dir on the session's own directory"
argv31="$ROOT/argv-31"; dir31="$ROOT/dir-31"; rm -f "$argv31" "$dir31"
FAKE_ARGV_OUT="$argv31" FAKE_DIR_OUT="$dir31" FAKE_MODE=complete FAKE_SESSION=ses_cut "$AL" resume j30 ses_cut >/dev/null 2>&1
sleep 2
grep -q "resumed ses_cut in its own tree" "$ROOT/data/tick.log" && ok "the tick log says it reattached" || bad "no reattach line"
[ -z "$(dirs j30)" ] && ok "and the finished session took its directory with it" || bad "left $(dirs j30)"
si="$(idx_in "$argv31" -s)"; [ -n "$si" ] && [ "$(at_in "$argv31" $((si + 1)))" = "ses_cut" ] && ok "-s carries the session id" || bad "no -s: $(tr '\n' ' ' < "$argv31")"
case "$(cat "$dir31" 2>/dev/null)" in
  "$ROOT/data/worktrees/j30/$d30/"*) ok "--dir is the kept worktree the session was born in (any other directory hangs for ever: measured)" ;;
  *) bad "--dir on the resume was '$(cat "$dir31" 2>/dev/null)'" ;;
esac
[ -z "$(idx_in "$argv31" --title)" ] && ok "no --title on a resume (the session has one)" || bad "--title passed on a resume"
[ "$(lastrun | jq -r .session)" = "ses_cut" ] && [ "$(lastrun | jq -r .resumed_from)" = "ses_cut" ] && ok "the journal has the same session, resumed" || bad "$(lastrun | jq -c '{session,resumed_from}')"

echo
echo "32. work on no remote is reported for an OpenCode run too"
mkjob_opencode j32
FAKE_MODE=dirty FAKE_SESSION=ses_dirty "$AL" run j32 >/dev/null 2>&1
sleep 2
lastrun | grep -q 'UNDELIVERED' && [ -n "$(dirs j32)" ] && ok "UNDELIVERED, and the tree is kept" || bad "no UNDELIVERED note, or tree gone"

echo
echo "33. the launch line and the permission block of a fresh OpenCode run, read back off the stand-in"
argv33="$ROOT/argv-33"; cfg33="$ROOT/cfg-33"; dir33="$ROOT/dir-33"; rm -f "$argv33" "$cfg33" "$dir33"
mkjob_opencode j33 full-access pdm_ai/glm-5.3-flash ',"disallowed_tools":"Agent,Bash(git push *)"'
FAKE_ARGV_OUT="$argv33" FAKE_CONFIG_OUT="$cfg33" FAKE_DIR_OUT="$dir33" FAKE_MODE=complete FAKE_SESSION=ses_argv "$AL" run j33 >/dev/null 2>&1
sleep 1
argc33="$(awk -F'\t' '$1=="ARGC" {print $2; exit}' "$argv33")"
[ "$(at_in "$argv33" 1)" = "run" ] && [ "$(at_in "$argv33" 2)" = "--format" ] && [ "$(at_in "$argv33" 3)" = "json" ] && ok "run --format json" || bad "argv: $(tr '\n' ' ' < "$argv33")"
for f in --pure --auto --print-logs; do [ -n "$(idx_in "$argv33" "$f")" ] && ok "$f" || bad "no $f"; done
li="$(idx_in "$argv33" --log-level)"; [ "$(at_in "$argv33" $((li + 1)))" = "ERROR" ] && ok "--log-level ERROR" || bad "log level"
mi="$(idx_in "$argv33" -m)"; [ "$(at_in "$argv33" $((mi + 1)))" = "pdm_ai/glm-5.3-flash" ] && ok "-m carries the id verbatim" || bad "-m $(at_in "$argv33" $((mi + 1)))"
vi="$(idx_in "$argv33" --variant)"; [ "$(at_in "$argv33" $((vi + 1)))" = "high" ] && ok "--variant high (a variant the catalog lists for this model)" || bad "--variant"
case "$(cat "$dir33" 2>/dev/null)" in
  "$ROOT/data/worktrees/j33/"*) ok "--dir names the run's working directory" ;;
  *) bad "--dir was '$(cat "$dir33" 2>/dev/null)'" ;;
esac
ti="$(idx_in "$argv33" --title)"; case "$(at_in "$argv33" $((ti + 1)))" in "agentloop j33 "*) ok "--title names the job and the stamp" ;; *) bad "title '$(at_in "$argv33" $((ti + 1)))'" ;; esac
[ -z "$(idx_in "$argv33" -s)" ] && ok "no -s on a fresh run" || bad "-s on a fresh run"
dd="$(idx_in "$argv33" --)"; [ -n "$dd" ] && [ "$((dd + 1))" = "$argc33" ] && ok "the prompt is the one argument after --" || bad "-- at '$dd', argc $argc33"
[ "$(jq -r .share "$cfg33")" = "disabled" ] && ok "OPENCODE_CONFIG_CONTENT disables sharing" || bad "config: $(cat "$cfg33")"
[ "$(jq -c .permission "$cfg33")" = '{"task":"deny","bash":{"*":"allow","git push *":"deny"}}' ] \
  && ok "and carries the job's denylist: Agent closed task, Bash(git push *) became a bash rule" || bad "permission: $(jq -c .permission "$cfg33")"
grep -q "j33: disallowed_tools is ignored" "$ROOT/data/tick.log" && bad "the lists were called ignored on opencode" || ok "nothing calls the tool lists ignored: they are translated"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "and the run went on to finish" || bad "status $(lastrun | jq -r .status)"

echo
echo "33b. read-only launches with the four denies, and a tool the table does not know is named"
cfg33b="$ROOT/cfg-33b"; rm -f "$cfg33b"
mkjob_opencode j33b read-only pdm_ai/glm-5.3-flash ',"allowed_tools":"Read,Nonesuch"'
FAKE_CONFIG_OUT="$cfg33b" FAKE_MODE=complete FAKE_SESSION=ses_ro "$AL" run j33b >/dev/null 2>&1
sleep 1
[ "$(jq -c '.permission | {edit, write, bash, task, "*": .["*"], read}' "$cfg33b")" = '{"edit":"deny","write":"deny","bash":"deny","task":"deny","*":"deny","read":"allow"}' ] \
  && ok "read-only denies edit, write, bash and task; the allowlist closes the rest and opens read" || bad "permission: $(jq -c .permission "$cfg33b")"
grep -q "j33b: allowed_tools: Nonesuch is not a tool OpenCode has; ignored" "$ROOT/data/tick.log" && ok "the unknown tool name is one line in tick.log" || bad "no note for Nonesuch"

echo
echo "34. a tool denied by rule during the run is tools_denied, like a --disallowedTools hit on Claude"
mkjob_opencode j34
FAKE_MODE=deny FAKE_SESSION=ses_deny "$AL" run j34 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "tools_denied" ] \
  && ok "error / tools_denied (the stream carried the denial: opencode has that capability, Codex never did)" || bad "$(lastrun | jq -c '{status,cause}')"

echo
echo "35. a rate limit is rate_limited, outside the backoff, with no window to mark"
mkjob_opencode j35
echo '{"j35":{"fail_streak":2}}' > "$ROOT/data/state.json"
FAKE_MODE=quota FAKE_SESSION=ses_quota "$AL" run j35 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "rate_limited" ] \
  && ok "error / rate_limited (APIError with statusCode 429)" || bad "$(lastrun | jq -c '{status,cause}')"
[ "$(jq -r '.j35.fail_streak' "$ROOT/data/state.json")" = "2" ] && ok "fail_streak untouched" || bad "streak $(jq -r '.j35.fail_streak' "$ROOT/data/state.json")"
jq -e 'has("opencode") | not' "$ROOT/data/rate-limits.json" >/dev/null 2>&1 && ok "and still no opencode window: the next run comes at the job's own interval" || bad "an opencode window appeared"

echo
echo "35b. an unknown model at run time is an error whose reason is in .err, not on the stream"
mkjob_opencode j35b full-access pdm_ai/glm-5.3-flash ',"max_budget_usd":1'
FAKE_MODE=error FAKE_SESSION=ses_err "$AL" run j35b >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "agent_error" ] \
  && ok "error / agent_error: an UnknownError carries no status" || bad "$(lastrun | jq -c '{status,cause}')"
# A priced model whose run died before its first step has null tokens: the
# cap note blames no price on the model (it has one), it says no step
# reported a cost.
[ "$(lastrun | jq -c .tokens)" = "null" ] && ok "no step_finish, so the tokens are null, not zero" || bad "tokens $(lastrun | jq -c .tokens)"
grep -q 'j35b: max_budget_usd 1 not applied: the cost of this run is unknown (no step reported a cost)' "$ROOT/data/tick.log" \
  && ok "the cap note says no step reported a cost, not no price for a priced model" || bad "cap note: $(grep 'j35b: max_budget' "$ROOT/data/tick.log" | tail -1)"

echo
echo "36. a stop ends an OpenCode run that will not end by itself"
mkjob_opencode j36 full-access pdm_ai/glm-5.3-flash ',"max_budget_usd":1'
FAKE_MODE=hang FAKE_SESSION=ses_hang "$AL" run j36 >/dev/null 2>&1 &
w=0; while [ "$w" -lt 20 ] && ! ls "$ROOT"/data/locks/j36/*/child >/dev/null 2>&1; do sleep 1; w=$((w + 1)); done
sleep 1
"$AL" stop j36 >/dev/null 2>&1
wait
[ "$(lastrun | jq -r .status)" = "stopped" ] && ok "status stopped (waited ${w}s for the slot)" || bad "status $(lastrun | jq -r .status)"
[ ! -e "$ROOT"/data/logs/j36/*.raw.fifo ] && ok "the FIFO was removed" || bad "FIFO left behind"
lastrun | jq -r .note | grep -q 'not applied' && bad "a stopped run got the cap note" || ok "a stopped run gets no cap note: its cost is unknown because it died, not because the model has no price"

echo
echo "37. a run that cannot start is refused in tick.log before it costs a slot"
mkjob_opencode j37
FAKE_OPENCODE_NO_MODELS=1 "$AL" run j37 >/dev/null 2>&1
grep -q 'j37: opencode is not ready (no usable provider' "$ROOT/data/tick.log" && ok "no provider → refused" || bad "no provider refusal line"
[ ! -d "$ROOT/data/logs/j37" ] && ok "and no log was written" || bad "a run started without a provider"
mkjob_opencode j37 full-access opencode/does-not-exist
"$AL" run j37 >/dev/null 2>&1
grep -q "j37: model 'opencode/does-not-exist' is not in the OpenCode catalog" "$ROOT/data/tick.log" && ok "unknown id → refused" || bad "no catalog refusal"
mkjob_opencode j37 full-access pdm_ai/glm-5.3-flash ',"interactive":true'
"$AL" run j37 >/dev/null 2>&1
grep -q "j37: interactive is not available on opencode" "$ROOT/data/tick.log" && ok "interactive → refused" || bad "no interactive refusal"
mkjob_opencode j37 workspace-write
"$AL" run j37 >/dev/null 2>&1
grep -q "j37: permission_mode 'workspace-write' is not an OpenCode mode" "$ROOT/data/tick.log" && ok "a Codex mode → refused (there is no sandbox to promise)" || bad "no permission refusal"
argv37x="$ROOT/argv-37x"; rm -f "$argv37x"
printf '#!/bin/bash\nif [ "$1" = "-" ] && { [ "$2" = "full-access" ] || [ "$2" = "read-only" ]; }; then exit 1; fi\nexec python3 "$@"\n' > "$ROOT/pybroken"
chmod +x "$ROOT/pybroken"
mkjob_opencode j37
AGENTLOOP_PYTHON="$ROOT/pybroken" FAKE_ARGV_OUT="$argv37x" "$AL" run j37 >/dev/null 2>&1
grep -q "j37: could not build the OpenCode permission block, skipped" "$ROOT/data/tick.log" && ok "a broken permission block is refused before a slot is spent" || bad "no permission-block refusal line"
[ ! -e "$argv37x" ] && ok "and no argv was ever written" || bad "the CLI launched anyway"
[ ! -d "$ROOT/data/locks/j37" ] && ok "and no lock directory was left" || bad "a lock directory was left"
argv37="$ROOT/argv-37"; rm -f "$argv37"
mkjob_opencode j37
sed -i '' 's/"effort":"high"/"effort":"ultra"/' "$ROOT/config/jobs.json"
FAKE_ARGV_OUT="$argv37" FAKE_MODE=complete FAKE_SESSION=ses_eff "$AL" run j37 >/dev/null 2>&1
sleep 2
grep -q "j37: effort 'ultra' is not a variant of pdm_ai/glm-5.3-flash — launched without an effort" "$ROOT/data/tick.log" \
  && [ -z "$(idx_in "$argv37" --variant)" ] && ok "an effort the model does not list is dropped, said, and the run goes on" || bad "bad effort: $(grep 'j37: effort' "$ROOT/data/tick.log" | tail -1)"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "and finished" || bad "status $(lastrun | jq -r .status)"

echo
echo "38. the run-end hook learns the platform, the cost basis and the tokens"
mkdir -p "$ROOT/config/hooks"
printf '#!/bin/bash\nprintf "%%s %%s %%s\\n" "$AL_PLATFORM" "$AL_COST_BASIS" "$AL_TOKENS" > "%s/hook-38.out"\n' "$ROOT" > "$ROOT/config/hooks/on-run-end.sh"
chmod +x "$ROOT/config/hooks/on-run-end.sh"
mkjob_opencode j38
FAKE_MODE=complete FAKE_SESSION=ses_hook FAKE_COST=0.0002 "$AL" run j38 >/dev/null 2>&1
sleep 3
case "$(cat "$ROOT/hook-38.out" 2>/dev/null)" in
  "opencode reported {"*'"input":11974'*) ok "AL_PLATFORM, AL_COST_BASIS and AL_TOKENS reach the hook" ;;
  *) bad "hook saw: $(cat "$ROOT/hook-38.out" 2>/dev/null)" ;;
esac
rm -f "$ROOT/config/hooks/on-run-end.sh"

echo
echo "39. a model the catalog prices records the CLI's own cost, reported"
mkjob_opencode j39
FAKE_MODE=complete FAKE_SESSION=ses_paid FAKE_COST=0.0002 "$AL" run j39 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .cost_basis)" = "reported" ] && [ "$(lastrun | jq -r .cost)" = "0.0004" ] \
  && ok "cost 0.0004 reported: two steps at 0.0002, the CLI's number, not an estimate" || bad "cost $(lastrun | jq -c '{cost,cost_basis}')"

echo
echo "40. a per-run cap over an unknown cost says so instead of never firing"
mkjob_opencode j40 full-access opencode/big-pickle ',"max_budget_usd":1'
FAKE_MODE=complete FAKE_SESSION=ses_cap "$AL" run j40 >/dev/null 2>&1
sleep 2
grep -q 'j40: max_budget_usd 1 not applied: the cost of this run is unknown (no price for opencode/big-pickle-real)' "$ROOT/data/tick.log" \
  && ok "tick.log says the cap could not be applied, and why" || bad "no cap note: $(grep 'j40' "$ROOT/data/tick.log" | tail -2)"
lastrun | jq -r .note | grep -q 'max_budget_usd \$1 not applied' && ok "and so does the run's own note" || bad "note: $(lastrun | jq -r .note)"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "without changing the status" || bad "status $(lastrun | jq -r .status)"

echo
echo "41. a run that never writes a byte is killed at the stall timeout, whatever its CPU does"
# Measured on OpenCode (evidence 35): a hung CLI process burns ~1 CPU second
# every 75 s of idling, which the watchdog's "CPU changed" test reads as
# life for ever. A stream still EMPTY after stall_timeout_seconds is the one
# shape both measured hangs share, and no healthy run of any platform has:
# the first event is written in seconds.
mkjob j41
sed -i '' 's/"max_parallel":1/"max_parallel":1,"stall_timeout_seconds":4/' "$ROOT/config/jobs.json"
AGENTLOOP_WATCHDOG_POLL=2 FAKE_MODE=silent FAKE_SESSION=sess-silent "$AL" run j41 >/dev/null 2>&1
sleep 1
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "killed" ] \
  && ok "error / killed" || bad "$(lastrun | jq -c '{status,cause}')"
lastrun | jq -r .note | grep -q 'no output at all for 4s' && ok "the note names the rule: no output at all" || bad "note: $(lastrun | jq -r .note)"

echo
echo "41b. a run that wrote its first event and then went quiet is still judged by the old rule"
mkjob j41b
sed -i '' 's/"max_parallel":1/"max_parallel":1,"stall_timeout_seconds":4/' "$ROOT/config/jobs.json"
AGENTLOOP_WATCHDOG_POLL=2 FAKE_MODE=hang FAKE_SESSION=sess-quiet "$AL" run j41b >/dev/null 2>&1
sleep 1
lastrun | jq -r .note | grep -q 'no output and no CPU for 4s' && ok "killed by the CPU-and-output rule, not the empty-stream one" || bad "note: $(lastrun | jq -r .note)"
lastrun | jq -r .note | grep -q 'no output at all' && bad "the empty-stream rule fired on a run that had written" || ok "the empty-stream rule never touches a run that wrote a byte"

echo
echo "41c. the case that motivated the rule: an OpenCode run whose provider never answers"
mkjob_opencode j41c
sed -i '' 's/"max_parallel":1/"max_parallel":1,"stall_timeout_seconds":4/' "$ROOT/config/jobs.json"
AGENTLOOP_WATCHDOG_POLL=2 FAKE_MODE=silent FAKE_SESSION=ses_silent "$AL" run j41c >/dev/null 2>&1
sleep 1
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "killed" ] && ok "error / killed" || bad "$(lastrun | jq -c '{status,cause}')"
lastrun | jq -r .note | grep -q 'no output at all for 4s' && ok "the empty-stream rule ended it (measured 34b: the CLI itself never would)" || bad "note: $(lastrun | jq -r .note)"
[ ! -e "$ROOT"/data/logs/j41c/*.raw.fifo ] && ok "and the FIFO was removed" || bad "FIFO left behind"

echo
echo "42. a security analysis on OpenCode goes through the stand-in, closes task by rule, and closes done"
jq --arg cwd "$ROOT/work/app" '.projects += [{"name":"sandbox-oc","cwd":$cwd,"base":"main","worktree":{"enabled":true},
   "security":{"enabled":true,"platform":"opencode","model":"pdm_ai/glm-5.3-flash","max_budget_usd":5}}]' \
   "$ROOT/config/projects.json" > "$ROOT/projects.next" && mv "$ROOT/projects.next" "$ROOT/config/projects.json"
argv42="$ROOT/argv-42"; prompt42="$ROOT/prompt-42"; cfg42="$ROOT/cfg-42"; rm -f "$argv42" "$prompt42" "$cfg42"
out42="$(AL_SECURITY_ENGINES=off FAKE_SKIP_PREPARE=1 FAKE_ARGV_OUT="$argv42" FAKE_PROMPT_OUT="$prompt42" FAKE_CONFIG_OUT="$cfg42" \
  FAKE_MODE=complete FAKE_SESSION=ses_sec FAKE_COST=0.0002 \
  "$AL" security analyze sandbox-oc anything main quick 2>&1)"
aid42="$(secid "$out42")"
[ -n "$aid42" ] && ok "the analysis opened: $aid42" || bad "no analysis id in: $out42"
[ "$(secstate sandbox-oc "$aid42")" = "done" ] \
  && ok "and closed done: the engine ran security prepare before the agent, and the close found nothing untriaged" \
  || bad "state '$(secstate sandbox-oc "$aid42")'"
grep -q 'security-sandbox-oc: deterministic phase ran before the agent (prepare' "$ROOT/data/tick.log" \
  && ok "the engine ran prepare before launching opencode (prepare_inline is off)" || bad "no engine-side prepare line"
[ "$(at_in "$argv42" 1)" = "run" ] && ok "it went down the OpenCode launch line" || bad "argv: $(tr '\n' ' ' < "$argv42" 2>/dev/null)"
mi="$(idx_in "$argv42" -m)"; [ -n "${mi:-}" ] && [ "$(at_in "$argv42" $((mi + 1)))" = "pdm_ai/glm-5.3-flash" ] \
  && ok "-m carries the block's model" || bad "-m '$(at_in "$argv42" $((${mi:-0} + 1)))'"
[ "$(jq -r '.permission.task' "$cfg42")" = "deny" ] && ok "task is closed BY RULE in the permission block (Agent -> task: deny)" || bad "permission: $(jq -c .permission "$cfg42")"
[ -n "$(idx_in "$argv42" --auto)" ] && [ "$(jq -r '.permission.bash // "open"' "$cfg42")" != "deny" ] \
  && ok "--auto with bash open: full-access, the security default on opencode" || bad "auto/bash: $(idx_in "$argv42" --auto) / $(jq -c .permission "$cfg42")"
grep -q 'The `task` tool is closed for this run' "$prompt42" && ok "the prompt says the task tool is closed, by rule" || bad "no task paragraph in the prompt"
grep -q 'security-analysis/SKILL.md' "$prompt42" && grep -q 'Invoke the `security-analysis` skill' "$prompt42" \
  && ok "and names the skill by name AND by path (the CLI reads ~/.claude/skills: measured)" || bad "the prompt lacks the skill by name or by path"
grep -q 'ALREADY RAN for this analysis' "$prompt42" && ! grep -q 'YOUR FIRST COMMAND' "$prompt42" \
  && ok "the prompt says the deterministic phase already ran" || bad "the prompt still asks the agent to run prepare"
grep -q 'Do not spawn subagents' "$prompt42" && bad "the Codex-only wording leaked into the opencode prompt" || ok "no Codex wording"
[ "$(lastrun | jq -r .id)" = "security-sandbox-oc" ] && [ "$(lastrun | jq -r .platform)" = "opencode" ] && [ "$(lastrun | jq -r .cost_basis)" = "reported" ] \
  && ok "the journal has the derived job's run on opencode, with the CLI's own cost" || bad "$(lastrun | jq -c '{id,platform,cost_basis}')"
sleep 1

echo
printf '\n  %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
