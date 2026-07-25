#!/bin/bash
# claude-cron uninstaller. Removes the launchd agents and the ~/.local/bin
# symlinks. Your jobs, prechecks and run history under this folder are KEPT.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "claude-cron · uninstaller"
"$HERE/bin/claude-cron" uninstall || true
rm -f "$HOME/.local/bin/claude-cron" "$HOME/.local/bin/claude-cron-server"
echo "Removed the agents and the PATH symlinks."
echo "Kept: config/ (jobs, prechecks) and data/ (history, index.db) under $HERE."
echo "Delete the whole folder to remove everything."
