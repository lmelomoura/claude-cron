#!/bin/sh
# statusline-rate-limits.sh — feed the scheduler's usage-window gate from your
# own interactive Claude Code sessions.
#
# WHY THIS EXISTS. `rl_gate` can only hold a run back when it knows how full the
# usage window is, and the run stream carries that number ONLY once the CLI has
# decided to warn (at 0.75 utilisation). Below that it reports `status:
# "allowed"` with no figure at all, so the gate sits armed and blind through the
# whole quiet stretch where a "should I start a 100-minute run?" answer would
# actually be worth having.
#
# The statusLine payload carries the figure on every turn — `used_percentage`
# for the 5-hour and 7-day windows — piggybacked on a response the session was
# already paying for. It costs nothing, and it never touches the usage endpoint,
# which rate-limits under polling.
#
# The catch, measured rather than assumed: **the statusLine does not run in
# headless mode**. Neither `-p --output-format json` nor `-p --output-format
# stream-json --verbose` invokes it — there is no status line to draw. So this
# cannot be fed by the scheduler's own runs. It is fed by YOUR interactive
# sessions, on the same account, which is exactly what makes it useful: you work
# in Claude Code during the day, and the fleet learns how full the window is
# without spending a token to find out.
#
# INSTALL — add to ~/.claude/settings.json (adjust the path to your checkout):
#   "statusLine": { "type": "command",
#                   "command": "/path/to/claude-cron/bin/statusline-rate-limits.sh" }
#
# It prints a compact `5h 62% · 7d 18%` so the line stays useful as a status
# line, and stays silent when the account reports no windows (API-key users, or
# before the first response of a session).
set -u

DATA_DIR="${CLAUDE_CRON_DATA:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/data}"
OUT="$DATA_DIR/rate-limits.json"
JQ="${CLAUDE_CRON_JQ:-$(command -v jq 2>/dev/null || echo /usr/bin/jq)}"

# The statusline is invoked several times a second while a turn streams. Writing
# every time would be thousands of pointless file writes an hour, so a floor:
# below it, print from what is already on disk and write nothing.
MIN_WRITE_SECONDS="${CLAUDE_CRON_STATUSLINE_MIN_SECONDS:-15}"

payload="$(cat)"
[ -n "$payload" ] || exit 0
[ -x "$JQ" ] || [ -n "$(command -v "$JQ" 2>/dev/null)" ] || exit 0

# A line for the human, built from the payload itself so it is right even when
# the write below is skipped.
line="$(printf '%s' "$payload" | "$JQ" -r '
  [ (.rate_limits.five_hour.used_percentage // empty | "5h \(. | floor)%"),
    (.rate_limits.seven_day.used_percentage // empty | "7d \(. | floor)%") ]
  | join(" · ")' 2>/dev/null)"
[ -n "$line" ] && printf '%s' "$line"

# Nothing to record: not a subscription, or no response yet this session.
printf '%s' "$payload" | "$JQ" -e '.rate_limits | (.five_hour? // .seven_day?) != null' >/dev/null 2>&1 || exit 0

now="$(date +%s)"
if [ -s "$OUT" ]; then
  last="$("$JQ" -r '[.[].seen_at // 0] | max // 0' "$OUT" 2>/dev/null || echo 0)"
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  [ "$(( now - last ))" -lt "$MIN_WRITE_SECONDS" ] && exit 0
fi

mkdir -p "$DATA_DIR" 2>/dev/null || exit 0
[ -s "$OUT" ] || printf '%s' '{}' > "$OUT" 2>/dev/null || exit 0
tmp="$(mktemp "$DATA_DIR/.rl.XXXXXX" 2>/dev/null)" || exit 0

# Merge, never replace. `status` and `overage` only ever come from a run's
# stream, and they belong to the window that was measured — so they are carried
# forward while `resets_at` says it is still the same window, and dropped the
# moment it is not. Keeping a spent window's `status` against a fresh window
# would hold the whole fleet back on a fact that expired.
printf '%s' "$payload" | "$JQ" --slurpfile prev "$OUT" --argjson now "$now" '
  ($prev[0] // {}) as $was
  | .rate_limits as $rl
  | reduce ["five_hour", "seven_day"][] as $w ($was;
      # `// null`, never `// empty`: an update that yields nothing collapses a
      # jq reduce to null, which would truncate the file to the string "null"
      # and lose every window already in it.
      ($rl[$w] // null) as $new
      | if $new == null or $new.used_percentage == null then .
        else
          (.[$w] // {}) as $old
          | (if $old.resets_at == ($new.resets_at // null) then $old else {} end) as $keep
          | .[$w] = {
              status:      ($keep.status // null),
              utilization: (($new.used_percentage) / 100),
              resets_at:   ($new.resets_at // null),
              overage:     ($keep.overage // null),
              seen_at:     $now,
              source:      "statusline"
            }
        end)
' > "$tmp" 2>/dev/null && mv "$tmp" "$OUT" 2>/dev/null
rm -f "$tmp" 2>/dev/null
exit 0
