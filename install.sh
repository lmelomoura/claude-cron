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
# Only what git tracks as executable: +x on everything under bin/ made the page
# and the sourced libraries executable too, and left the checkout showing four
# modified files after every install.
chmod +x "$HERE/bin/agentloop" "$HERE/bin/agentloop-server" "$HERE/bin/statusline-rate-limits.sh" \
         "$HERE/bin/provision-lib.sh" "$HERE/bin/security/cli.py" "$HERE"/*.sh 2>/dev/null || true

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
# Optional: only a job that says "platform": "openai" needs it. Reported, never
# required -- an install without it runs Claude Code jobs exactly as before.
if command -v codex >/dev/null 2>&1; then
  say "✓ codex ($(codex --version 2>/dev/null | head -1)) — optional, for jobs on the OpenAI platform"
else
  say "· codex — not on your PATH. Optional: only jobs with \"platform\": \"openai\" need it (npm i -g @openai/codex, then codex login)."
fi
# Optional in the same way: only a job that says "platform": "opencode" needs
# it. A CLI of providers, not of one account -- it is ready when `opencode
# models` lists a model, which the free opencode/*-free models do without any.
if command -v opencode >/dev/null 2>&1; then
  say "✓ opencode ($(opencode --version 2>/dev/null | head -1)) — optional, for jobs on the OpenCode platform"
else
  say "· opencode — not on your PATH. Optional: only jobs with \"platform\": \"opencode\" need it (brew install opencode, or npm i -g opencode-ai; then configure a provider or use the free models)."
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
  say "Created config/jobs.json from the example (two disabled demo jobs: one on Claude Code, one on Codex)."
fi
# Only when the file is missing: an existing table is the operator's. That is
# also why an existing install adds the `opencode` rows by hand (the README's
# Platforms section shows the line) -- nothing here, and nothing in
# resolve-pricing, ever writes that block.
if [ ! -f "$HERE/config/pricing.json" ]; then
  cp "$HERE/config/pricing.example.json" "$HERE/config/pricing.json"
  say "Created config/pricing.json from the example — OpenAI runs, and OpenCode models the CLI's catalog does not price, are priced from it; agentloop refreshes the openai rows daily from the price source (agentloop resolve-pricing)."
fi
mkdir -p "$HERE/config/prechecks" "$HERE/data/logs" "$HERE/data/locks"
echo

# 5) launchd agents ------------------------------------------------------
echo "Installing the launchd agents (tick + control server)…"
"$HERE/bin/agentloop" install
# Nothing runs until a platform and at least one of its models are switched
# on -- a fresh install has none, an upgraded one keeps what its jobs use.
if ! "$HERE/bin/agentloop" platforms 2>/dev/null | jq -e '[.[] | objects | select(.usable == true)] | length > 0' >/dev/null 2>&1; then
  echo
  say "No platform is enabled yet. Open the dashboard and enable one in Settings › Platforms"
  say "(and switch on at least one model) before creating jobs."
fi
echo
echo "Done. Open the dashboard with:"
echo "    agentloop dashboard"
echo "It runs at http://127.0.0.1:8787/ and starts automatically on login."
echo
echo "The first thing it asks for is your operator profile — name, email and a"
echo "password. Nothing else in the dashboard works until that exists, and the"
echo "same screen appears on an existing install the first time it is opened"
echo "after this update. There is no password reset: it is stored hashed."
