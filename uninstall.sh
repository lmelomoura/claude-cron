#!/bin/bash
# agentloop uninstaller. Removes the launchd agents and the ~/.local/bin
# symlinks. Your jobs, prechecks and run history under this folder are KEPT.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "agentloop · uninstaller"
"$HERE/bin/agentloop" uninstall || true
rm -f "$HOME/.local/bin/agentloop" "$HOME/.local/bin/agentloop-server"
echo "Removed the agents and the PATH symlinks."
echo "Kept: config/ (jobs, prechecks) and data/ (history, index.db) under $HERE."
echo "Delete the whole folder to remove everything."
