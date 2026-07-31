# shellcheck shell=bash
# board-probe.sh — tell "there is no work" apart from "I cannot see the work".
#
# WHY THIS EXISTS. A precheck's whole job is to answer one question cheaply, and
# its two quiet answers look identical from the outside: an empty column and an
# unreadable board both end with zero keys and the line "nothing to do". So a
# fleet whose Jira access has broken reports itself as idle, forever, and every
# dashboard, tick chart and greeting agrees with it. Observed for real: the
# credentials file lost its classic Jira token, `project = QG` began returning
# `{"issues":[]}` — a valid, authenticated, empty answer — and the prechecks
# cheerfully said there was nothing waiting while 49 tickets sat on the board.
#
# The fix is not more retries. It is refusing to report absence of work until the
# board has been proven visible: authentication AND the project itself. A search
# that returns nothing is only meaningful once you know you could have seen
# something.
#
# Contract: source AFTER the caller has set AUTH, JIRA, JQ and PROJECT.
# Read-only — this never writes to the board.

# bp_board_visible -> 0 = the board is readable and this project is visible.
# On failure it prints ONE line naming which half failed, so the operator reads a
# cause instead of a silence. The caller must exit non-zero WITHOUT claiming
# "nothing to do" — being unable to look is not the same as having looked.
bp_board_visible() {
  local me code
  me="$(curl -sf -u "$AUTH" "$JIRA/rest/api/3/myself" 2>/dev/null)" || {
    echo "board_unreachable — Jira rejected the credentials or could not be reached. NOT the same as an empty queue; the fleet is blind until this is fixed."
    return 1
  }
  printf '%s' "$me" | "$JQ" -e '.accountId' >/dev/null 2>&1 || {
    echo "board_unreachable — Jira answered but not with an account; treating as blind rather than idle."
    return 1
  }
  # Authentication is not visibility. A token can be perfectly valid and still be
  # scoped away from this project, and THAT is the case that reads as "empty":
  # the search endpoint answers 200 with an empty array rather than an error.
  code="$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$JIRA/rest/api/3/project/$PROJECT" 2>/dev/null)"
  if [ "$code" != "200" ]; then
    echo "board_invisible — authenticated, but project $PROJECT reads as HTTP $code. Every query will come back empty and look like an idle board. Check the token's scope."
    return 1
  fi
  return 0
}

# bp_search <jql> -> prints the issue keys, one per line; returns 1 if the query
# itself failed. An empty result and a failed query are different answers, and
# collapsing them is the bug this file exists to prevent, so the caller must test
# the return code before it believes the emptiness.
bp_search() {
  local jql="$1" raw
  raw="$(curl -sf -u "$AUTH" -G "$JIRA/rest/api/3/search/jql" \
        --data-urlencode "jql=$jql" \
        --data-urlencode 'maxResults=50' --data-urlencode 'fields=key' 2>/dev/null)" || return 1
  # A well-formed response always carries an `issues` array, even when it is
  # empty. Anything else — an error object, truncated output, HTML from a proxy —
  # is a failed query wearing the shape of a quiet one.
  printf '%s' "$raw" | "$JQ" -e 'has("issues") and (.issues | type == "array")' >/dev/null 2>&1 || return 1
  printf '%s' "$raw" | "$JQ" -r '.issues[]?.key' 2>/dev/null
  return 0
}
