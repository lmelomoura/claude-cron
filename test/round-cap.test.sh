#!/bin/bash
# Behavioural suite for round-cap.sh against a fake Jira. Every case is a property
# the real loop depends on; each prints PASS/FAIL and the script exits non-zero on
# any failure.
set -uo pipefail
S="$(cd "$(dirname "$0")" && pwd)"
PORT=8971
STATEF="${TMPDIR:-/tmp}/al-round-cap-state.$$.json"
rm -f "$STATEF"

python3 "$S/fakejira.py" "$PORT" "$STATEF" &
FAKE=$!
trap 'kill $FAKE 2>/dev/null' EXIT
for _ in $(seq 40); do curl -sf "http://127.0.0.1:$PORT/rest/api/3/myself" >/dev/null 2>&1 && break; sleep 0.1; done

AUTH="x:y"
JIRA="http://127.0.0.1:$PORT"
JQ=/usr/bin/jq
. "${AL_LIB:-$(cd "$(dirname "$0")/../bin" && pwd)}/round-cap.sh"

fail=0
ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s — %s\n' "$1" "$2"; fail=1; }
eq()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "got '$2' want '$3'"; }

echo "== counting =="
eq "counts zero rounds"            "$(rc_rounds_used T-0)"     "0"
eq "counts one round"              "$(rc_rounds_used T-1)"     "1"
eq "counts two rounds"             "$(rc_rounds_used T-2)"     "2"
eq "counts past page 1 (250 noise)" "$(rc_rounds_used T-PAGE)" "2"
rc_rounds_used T-ERR >/dev/null 2>&1 && bad "unreadable changelog returns error" "it returned success" \
                                     || ok  "unreadable changelog returns error"

echo
echo "== the gate (cap=2) =="
rc_gate_rework T-0 2>/dev/null && ok "round 1 allowed"  || bad "round 1 allowed" "refused"
rc_gate_rework T-1 2>/dev/null && ok "round 2 allowed"  || bad "round 2 allowed" "refused"
rc_gate_rework T-2 2>/dev/null && bad "round 3 refused" "allowed" || ok "round 3 refused"
rc_gate_rework T-PAGE 2>/dev/null && bad "round 3 refused (paginated)" "allowed — TRUNCATION BUG" \
                                  || ok "round 3 refused (paginated)"
rc_gate_rework T-ERR 2>/dev/null && ok "unreadable changelog FAILS OPEN" \
                                 || bad "unreadable changelog FAILS OPEN" "it refused — a blip would park a healthy ticket"
rc_gate_rework T-INDIRECT 2>/dev/null && bad "no direct Blocked route -> refused" "allowed" \
                                      || ok "no direct Blocked route -> refused"
rc_gate_rework T-NOPARK 2>/dev/null && bad "unparkable -> still refused" "allowed" \
                                    || ok "unparkable -> still refused"

echo
echo "== the human-released ticket (rc_develop_note) =="
# The cap parks a ticket and waits for a human. The human's answer is a board
# move into the ready column. QG-15: the next run read the spent rounds, decided
# the board was glitched, and put the card straight back in Blocked -- so the
# human's only lever moved it forward and the agent moved it back, forever.
# A ticket arriving via the READY queue must therefore be told, in words, that
# the move it can see IS the decision, and must not be re-derived from the count.
case "$(rc_develop_note T-2)" in
  *"human-released"*) ok "an over-cap ticket in the ready queue reads as human-released" ;;
  *) bad "over-cap ready ticket" "note was: $(rc_develop_note T-2)" ;;
esac
case "$(rc_develop_note T-2)" in
  *"Do NOT re-park"*) ok "and is told not to re-park it over the round count" ;;
  *) bad "over-cap ready ticket" "no instruction against re-parking" ;;
esac
case "$(rc_develop_note T-2)" in
  *"NEW blocker"*) ok "while a genuinely new blocker still justifies blocking" ;;
  *) bad "over-cap ready ticket" "blocking was removed without saying when it is still right" ;;
esac
case "$(rc_develop_note T-0)" in
  *"no rework cap applies"*) ok "an ordinary ready ticket gets the plain note" ;;
  *) bad "under-cap ready ticket" "note was: $(rc_develop_note T-0)" ;;
esac
# A changelog blip must not turn an ordinary ticket into a "human-released" one:
# that would silently tell a run to ignore a cap that was never reached.
case "$(rc_develop_note T-ERR)" in
  *"human-released"*) bad "unreadable changelog" "claimed human-released on no evidence" ;;
  *) ok "unreadable changelog does not fabricate a human release" ;;
esac
# And reading the note must never move anything.
eq "rc_develop_note left T-2 where it was" "$(rc_current_status T-2)" "$(rc_current_status T-2)"

echo
echo "== re-entrancy: a second tick must not re-comment =="
# The real failure mode: comment lands, transition fails, next tick parks again.
rc_gate_rework T-2 2>/dev/null; rc_gate_rework T-2 2>/dev/null   # two more attempts
rc_gate_rework T-INDIRECT 2>/dev/null

echo
echo "== the cap is configurable =="
# RC_CAP is resolved when the library is sourced, which is how the precheck uses
# it (env set for the job, read at script start) — so test it the same way.
( export AL_ROUND_CAP=5
  AUTH="x:y"; JIRA="http://127.0.0.1:$PORT"; JQ=/usr/bin/jq
  . "${AL_LIB:-$(cd "$(dirname "$0")/../bin" && pwd)}/round-cap.sh"
  [ "$RC_CAP" = "5" ] || exit 2
  rc_gate_rework T-1 2>/dev/null ) \
  && ok "AL_ROUND_CAP=5 raises the cap" || bad "AL_ROUND_CAP=5 raises the cap" "cap not honoured"

echo
echo "== the cap still reads its pre-rename name for one release =="
( export CC_ROUND_CAP=4    # the spelling before AL_ROUND_CAP, honoured for one release
  AUTH="x:y"; JIRA="http://127.0.0.1:$PORT"; JQ=/usr/bin/jq
  . "${AL_LIB:-$(cd "$(dirname "$0")/../bin" && pwd)}/round-cap.sh"
  [ "$RC_CAP" = "4" ] ) \
  && ok "CC_ROUND_CAP alone still raises the cap (read as AL_ROUND_CAP)" \
  || bad "CC_ROUND_CAP alone still raises the cap (read as AL_ROUND_CAP)" "cap not honoured"

echo
echo "== dry run must not write =="
AL_PRECHECK_DRY_RUN=1 rc_gate_rework T-DRY >/dev/null 2>&1 \
  && bad "dry run refuses a capped ticket" "allowed" || ok "dry run refuses a capped ticket"

echo
echo "== board effects =="
kill -USR1 $FAKE; sleep 0.4
python3 - "$STATEF" <<'PY'
import json, sys
st = json.load(open(sys.argv[1]))
fail = 0
def chk(name, cond, detail=""):
    global fail
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f" — {detail}"))
    if not cond: fail = 1

t2 = st["T-2"]
chk("capped ticket ends in Blocked", t2["status"] == "Blocked", f"status={t2['status']}")
chk("three ticks still leave ONE comment", t2["comments"] == 1, f"comments={t2['comments']}")
chk("comment explains the cap", "Round cap reached" in t2["comment_text"], t2["comment_text"])
chk("three ticks still leave ONE move", t2["moves"] == ["Blocked"], f"moves={t2['moves']}")

ti = st["T-INDIRECT"]
chk("indirect park routes via In Progress", ti["moves"] == ["In Progress", "Blocked"], f"moves={ti['moves']}")
chk("indirect park ends in Blocked", ti["status"] == "Blocked", f"status={ti['status']}")
chk("indirect park re-run adds nothing", ti["comments"] == 1, f"comments={ti['comments']}")

td = st["T-DRY"]
chk("dry run wrote nothing", td["moves"] == [] and td["comments"] == 0,
    f"moves={td['moves']} comments={td['comments']}")

tn = st["T-NOPARK"]
chk("unparkable ticket is left alone", tn["moves"] == [], f"moves={tn['moves']}")

t1 = st["T-1"]
chk("under-cap ticket never touched", t1["moves"] == [] and t1["comments"] == 0,
    f"moves={t1['moves']} comments={t1['comments']}")

te = st["T-ERR"]
chk("fail-open ticket never touched", te["moves"] == [] and te["comments"] == 0,
    f"moves={te['moves']} comments={te['comments']}")
sys.exit(fail)
PY
[ $? -eq 0 ] || fail=1

echo
[ $fail -eq 0 ] && echo "ALL PASS" || echo "FAILURES ABOVE"
exit $fail
