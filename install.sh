#!/bin/bash
# agentloop installer (macOS). Idempotent — safe to re-run after moving the
# folder or pulling an update.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
say() { printf '  %s\n' "$*"; }

echo "agentloop · installer"
echo

# 1) platform ------------------------------------------------------------
if [ "$(uname)" != "Darwin" ]; then
  echo "This tool targets macOS (it uses launchd and BSD date). Aborting." >&2
  exit 1
fi

# 1b) Gatekeeper quarantine ---------------------------------------------
# A folder that arrived via download / AirDrop / email is flagged
# com.apple.quarantine, which makes the scripts and binaries fail with
# "operation not permitted". Running this file as `bash install.sh` still
# works (bash reads it, no exec), so clear the flag from the whole folder now
# — otherwise launchd could not start bin/agentloop later.
if xattr -rd com.apple.quarantine "$HERE" 2>/dev/null; then
  say "Cleared macOS quarantine from the folder."
fi
chmod +x "$HERE"/bin/* "$HERE"/*.sh 2>/dev/null || true

# 2) dependencies --------------------------------------------------------
echo "Checking dependencies…"
missing=0
for c in bash jq python3 curl git; do
  if command -v "$c" >/dev/null 2>&1; then say "✓ $c ($(command -v "$c"))"; else say "✗ $c (required)"; missing=1; fi
done
if command -v claude >/dev/null 2>&1; then
  say "✓ claude ($(claude --version 2>/dev/null | head -1))"
else
  say "✗ claude — the Claude Code CLI is NOT on your PATH."
  say "  Jobs cannot run until it is. Install it, then re-run this script."
  missing=1
fi
if [ "$missing" -ne 0 ]; then
  echo; echo "Install the missing tools and run ./install.sh again." >&2
  exit 1
fi
echo

# 3) symlinks on PATH ----------------------------------------------------
echo "Linking commands into ~/.local/bin…"
mkdir -p "$HOME/.local/bin"
chmod +x "$HERE/bin/agentloop" "$HERE/bin/agentloop-server"
ln -sf "$HERE/bin/agentloop"        "$HOME/.local/bin/agentloop"
ln -sf "$HERE/bin/agentloop-server" "$HOME/.local/bin/agentloop-server"
say "✓ agentloop -> $HERE/bin/agentloop"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) : ;;
  *) say "⚠ ~/.local/bin is not on your PATH — add this to your shell profile:";
     say "    export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
echo

# 4) seed a jobs file the first time ------------------------------------
if [ ! -f "$HERE/config/jobs.json" ]; then
  cp "$HERE/config/jobs.example.json" "$HERE/config/jobs.json"
  say "Created config/jobs.json from the example (one disabled demo job)."
fi
mkdir -p "$HERE/config/prechecks" "$HERE/data/logs" "$HERE/data/locks"
echo

# 5) launchd agents ------------------------------------------------------
echo "Installing the launchd agents (tick + control server)…"
"$HERE/bin/agentloop" install
echo
echo "Done. Open the dashboard with:"
echo "    agentloop dashboard"
echo "It runs at http://127.0.0.1:8787/ and starts automatically on login."
echo
echo "The first thing it asks for is your operator profile — name, email and a"
echo "password. Nothing else in the dashboard works until that exists, and the"
echo "same screen appears on an existing install the first time it is opened"
echo "after this update. There is no password reset: it is stored hashed."
