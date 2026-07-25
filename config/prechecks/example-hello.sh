#!/bin/bash
# Example precheck — no credentials, no network.
# Wakes the agent only when a trigger file exists, then the agent removes it.
# Try it: `touch /tmp/claude-cron-hello` and watch the job run once.
#
# Exit 0 = there is work (run the agent). Exit 1 = nothing to do (stay idle).

[ -f /tmp/claude-cron-hello ]
