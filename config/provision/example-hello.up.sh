#!/usr/bin/env bash
# Example provisioning hook. Copy it to <your project>.up.sh and edit.
#
# It runs ONCE PER REPO of the project, with the working directory set to that
# repo's fresh worktree. Everything it needs arrives in the environment:
#
#   AL_REPO_NAME  the repo's name in projects.json  AL_WORKTREE  this worktree (= cwd)
#   AL_REPO_PATH  the canonical checkout            AL_BASE      the branch it was cut from
#   AL_RUN_DIR    the run's directory               AL_PROJECT   AL_JOB_ID
#   AL_RUN_MANIFEST  <run dir>/.run.json — every repo of this run
#
# A non-zero exit ABORTS the run: the engine takes down whatever it already
# provisioned and never hands a half-built tree to an agent.
set -euo pipefail

# Anything registered OUTSIDE the directory must carry the run's stamp, or two
# concurrent runs of the same repo collide on one global name.
SITE="${AL_REPO_NAME}-$(basename "$AL_RUN_DIR")"

case "$AL_REPO_NAME" in
  *)
    # Gitignored dependencies live only in the canonical checkout, so copy them
    # from there. `cp -c` clones on APFS: near-instant, no extra disk.
    [ -f "$AL_REPO_PATH/.env" ] && cp -c "$AL_REPO_PATH/.env" .env
    [ -d "$AL_REPO_PATH/node_modules" ] && cp -cR "$AL_REPO_PATH/node_modules" node_modules
    echo "provisioned $AL_REPO_NAME from $AL_REPO_PATH (site would be $SITE)"
    ;;
esac
