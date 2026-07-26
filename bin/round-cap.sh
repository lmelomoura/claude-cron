#!/bin/bash
# round-cap.sh — the dev/review loop's terminator, in shell, before a session exists.
#
# WHY THIS EXISTS, AND WHY IT IS NOT IN A PROMPT.
#
# The dev prompt says the rework loop repeats "until nothing blocks"; the review
# prompt says "until the review is genuinely clean". Neither is a terminating
# condition. The reviewer's mandate is to walk eight attack axes and block on any
# behavioural finding of any severity — give it a perfect pull request and it still
# returns something. So the loop's exit condition is "a process that always has
# output produced no output", and it never fires. Observed: QG-15 at three rounds,
# RP-146 at two and climbing, ~20 minutes and ~$12 a round, until the money ran out.
#
# The counter cannot live in the prompt for the same reason every previous fix
# failed: a prompt is a request, and each round is a fresh session that has no idea
# it is round four. The one place that knows is the Jira changelog, and the one
# actor that runs before a session exists — and therefore cannot be talked out of
# it — is the precheck. Hence: shell.
#
# Note the existing "after 3 failed repair iterations" line in the dev prompt does
# NOT cover this. It counts FAILED attempts at one finding. In the real loop no
# attempt fails: every round successfully closes the finding it was given and the
# reviewer opens a NEW one (on RP-146, the round-1 fix widened a matcher and the
# widening itself became the round-2 finding). That counter can never reach 3.
#
# Contract: source this AFTER the caller has set AUTH, JIRA and JQ.
# Everything here is read-only on the board except rc_gate_rework's park, which
# only ever fires on a card that has already exhausted its rounds.

# Rework rounds a ticket may take before a human decides. The Nth round is
# allowed; round N+1 is refused. 2 => at most two reworks, i.e. three reviews.
RC_CAP="${CC_ROUND_CAP:-2}"

# The status whose entries count as a round. A ticket enters it once per
# change-requested verdict, so counting entries counts rounds.
RC_ROUND_STATUS="${CC_ROUND_STATUS:-Change Requested}"

# rc_rounds_used <KEY> -> prints the number of rework rounds already spent.
# Returns non-zero if the changelog could not be read, so callers can fail OPEN
# (see rc_gate_rework): a network blip must never park a healthy ticket.
#
# Paginated deliberately. `?expand=changelog` on the issue endpoint truncates at
# 100 entries with no warning, and these tickets are exactly the ones with long
# histories — the truncation would silently under-count the tickets that need the
# cap most, which is the one failure mode that matters here.
rc_rounds_used() {
  local k="$1" start=0 total=1 n=0 page got cnt
  while [ "$start" -lt "$total" ]; do
    page="$(curl -sf -u "$AUTH" \
      "$JIRA/rest/api/3/issue/$k/changelog?startAt=$start&maxResults=100" 2>/dev/null)" || return 1
    total="$(printf '%s' "$page" | "$JQ" -r '.total // empty' 2>/dev/null)"
    [ -n "${total:-}" ] || return 1
    cnt="$(printf '%s' "$page" | "$JQ" --arg s "$RC_ROUND_STATUS" \
      '[.values[]?.items[]? | select(.field=="status" and .toString==$s)] | length' 2>/dev/null)"
    n=$(( n + ${cnt:-0} ))
    got="$(printf '%s' "$page" | "$JQ" '.values | length' 2>/dev/null)"
    [ "${got:-0}" -gt 0 ] || break
    start=$(( start + got ))
  done
  echo "$n"
}

# rc_transition_to <KEY> <STATUS NAME> -> 0 when the card is now in that status.
# The id is read, never hard-coded, so a renamed or renumbered workflow surfaces
# as "no route" instead of as a wrong move.
rc_transition_to() {
  local k="$1" s="$2" tid code
  tid="$(curl -sf -u "$AUTH" "$JIRA/rest/api/3/issue/$k/transitions" 2>/dev/null \
        | "$JQ" -r --arg s "$s" '.transitions[]? | select(.to.name==$s) | .id' | head -1)"
  [ -n "${tid:-}" ] || return 1
  code="$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" -X POST \
        "$JIRA/rest/api/3/issue/$k/transitions" -H 'Content-Type: application/json' \
        -d "{\"transition\":{\"id\":\"$tid\"}}" 2>/dev/null)"
  [ "$code" = "204" ]
}

# rc_comment <KEY> <text> — one ADF paragraph per line. Blank lines are dropped:
# an empty paragraph has no content array and Jira rejects the whole document.
rc_comment() {
  local k="$1" body
  body="$("$JQ" -nc --arg t "$2" '{body:{type:"doc",version:1,
    content:($t | split("\n") | map(select(length > 0))
                 | map({type:"paragraph",content:[{type:"text",text:.}]}))}}')" || return 1
  curl -s -o /dev/null -u "$AUTH" -X POST "$JIRA/rest/api/3/issue/$k/comment" \
    -H 'Content-Type: application/json' -d "$body" 2>/dev/null
}

# The first line of the park comment, and the marker that makes parking idempotent.
RC_MARK="Round cap reached"

# rc_already_capped <KEY> -> 0 when the cap notice is already on the ticket.
rc_already_capped() {
  curl -sf -u "$AUTH" "$JIRA/rest/api/3/issue/$1/comment?maxResults=100" 2>/dev/null \
    | "$JQ" -e --arg m "$RC_MARK" \
      '[.comments[]? | select((.body|tostring) | contains($m))] | length > 0' >/dev/null 2>&1
}

# rc_current_status <KEY> -> prints the status name (empty when unreadable).
rc_current_status() {
  curl -sf -u "$AUTH" "$JIRA/rest/api/3/issue/$1?fields=status" 2>/dev/null \
    | "$JQ" -r '.fields.status.name // empty' 2>/dev/null
}

# rc_park_blocked <KEY> <rounds> -> 0 when the card is parked for a human.
#
# Idempotent, because parking is two writes and the second one can fail. When the
# comment lands and the transition does not, the card stays in the queue and the
# next tick parks it again — without this guard that means a fresh copy of the
# same wall of text every few minutes until someone notices.
#
# Comment BEFORE the move: a card that lands in Blocked with no explanation is
# worse than one still looping, because nothing on the board says why it stopped.
rc_park_blocked() {
  local k="$1" used="$2" st
  st="$(rc_current_status "$k")"
  [ "$st" = "Blocked" ] && return 0   # already parked by an earlier attempt
  if rc_already_capped "$k"; then
    rc_transition_to "$k" "Blocked" && return 0
    rc_transition_to "$k" "In Progress" || return 1
    rc_transition_to "$k" "Blocked"
    return $?
  fi
  rc_comment "$k" "$RC_MARK — parked for a human decision.

This ticket has been through $used change-requested rework rounds, which is the cap ($RC_CAP). The autonomous loop stopped here on purpose: it was not converging, and each further round costs a full dev run plus a full review run without a guarantee of ending.

Why a cap exists: the reviewer blocks on any behavioural finding of any severity across eight attack axes, so \"the reviewer finds nothing\" is not a state a real pull request reaches. Left alone the loop runs until the budget is gone.

What a human decides now, on the pull request as it stands:
- ACCEPT — the acceptance criteria are met and the open findings are new surfaces rather than regressions. Move it back to Review - DEV and record the findings as their own tickets.
- FIX — one of the open findings is a genuine regression. Say which one in a comment and return the card to In Progress; the cap counts rounds, so state that this round is authorised.
- RESCOPE — the ticket is too large or its spec is wrong. Send it back to the backlog.

Raise the cap for one ticket by saying so in a comment; raise it fleet-wide with CC_ROUND_CAP."

  rc_transition_to "$k" "Blocked" && return 0

  # No direct route from the card's current column. Every workflow here has one
  # from In Progress, which the caller is entitled to take anyway (it is the
  # rework claim), so go through it rather than leaving the card in the queue —
  # a capped card left in Change Requested is picked again on the very next tick.
  rc_transition_to "$k" "In Progress" || return 1
  rc_transition_to "$k" "Blocked"
}

# rc_gate_rework <KEY> -> 0 = this rework may proceed; 1 = capped, card parked.
#
# Fail-OPEN on an unreadable changelog. A transient Jira error must not park a
# healthy ticket; the cap simply re-applies on the next tick, and the cost of one
# extra round is far below the cost of a ticket stuck behind a network blip.
rc_gate_rework() {
  local k="$1" used
  used="$(rc_rounds_used "$k")" || {
    echo "round-cap: $k changelog unreadable — letting this round through (fail-open)" >&2
    return 0
  }
  if [ "${used:-0}" -lt "$RC_CAP" ]; then
    echo "round-cap: $k at round $(( used + 1 ))/$RC_CAP" >&2
    return 0
  fi
  if [ -n "${CC_PRECHECK_DRY_RUN:-}" ]; then
    echo "round-cap: $k would be PARKED (used $used, cap $RC_CAP) — dry run, board untouched" >&2
    return 1
  fi
  if rc_park_blocked "$k" "$used"; then
    echo "round-cap: $k parked in Blocked after $used rounds (cap $RC_CAP) — awaiting a human" >&2
  else
    echo "round-cap: $k is over cap ($used/$RC_CAP) but could not be parked — skipping it" >&2
  fi
  return 1
}

# rc_round_note <KEY> -> a short phrase for the reviewer's precheck line, telling
# the session whether this is the last round it gets. A reviewer that knows the
# loop ends here weighs "block" against "record as a follow-up ticket" honestly,
# instead of assuming there is always another round to fix things in.
rc_round_note() {
  local k="$1" used
  used="$(rc_rounds_used "$k")" || { echo "rounds=unknown"; return 0; }
  if [ "${used:-0}" -ge "$RC_CAP" ]; then
    echo "rounds=$used/$RC_CAP FINAL-ROUND — a change-requested verdict now parks this ticket for a human, it does NOT start another rework"
  else
    echo "rounds=$used/$RC_CAP"
  fi
}

# rc_develop_note <KEY> -> what a run claiming from the READY queue must be told.
#
# WHY THIS EXISTS. The cap parks an exhausted ticket in Blocked and waits for a
# human. The human's answer is a BOARD MOVE — they drag the card to the ready
# column — because that is the whole interface, and demanding a magic label or a
# comment on top of it would be a second interface to remember and forget.
#
# But the agent that then picks the card up can read the history: it sees three
# closed rounds, a cap of two, and a reviewer's "parks for a human" verdict. A
# careful agent concludes the card's presence in the ready column is a BOARD
# GLITCH it would be exploiting, escalates straight back to Blocked, and the
# ticket is now permanently stuck: the human's only lever moves it, and the
# agent's caution undoes it, forever. Observed on QG-15 — the run reasoned well
# and reached exactly the wrong answer, because nothing told it that the anomaly
# it spotted WAS the decision it was waiting for.
#
# So say it. A ticket in the ready queue got there because a human put it there;
# the cap has already been answered, and re-deriving it from the round count is
# reading the question after it has been answered.
rc_develop_note() { # rc_develop_note <KEY>
  local k="$1" used
  used="$(rc_rounds_used "$k" 2>/dev/null)" || used=""
  if [ -n "$used" ] && [ "${used:-0}" -ge "$RC_CAP" ]; then
    echo "human-released — this ticket had spent its $used/$RC_CAP rework rounds and a human has since moved it into the ready queue. THAT MOVE IS THE HUMAN DECISION the cap was waiting for: it is not a board glitch and not something to re-check. Do the work. Do NOT re-park it in Blocked over the round count — only a NEW blocker (an unanswered business question, a broken assumption) justifies blocking, exactly as it would on any other ticket."
  else
    echo "from the ready queue — no rework cap applies"
  fi
}
