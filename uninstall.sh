#!/bin/bash
# agentloop uninstaller. Removes the launchd agents and the ~/.local/bin
# symlinks. Your jobs, prechecks and run history under this folder are KEPT.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "agentloop · uninstaller"
# `bin/agentloop uninstall` also retires the symlinks an install made under the
# pre-rename name — but only the ones that point into THIS folder (see
# install_migrate_legacy); nothing here removes a link ungated.
"$HERE/bin/agentloop" uninstall || true
rm -f "$HOME/.local/bin/agentloop" "$HOME/.local/bin/agentloop-server"
echo "Removed the agents and the PATH symlinks."
echo "Kept: config/ (jobs, prechecks) and data/ (history, index.db) under $HERE."
echo "Delete the whole folder to remove everything."
