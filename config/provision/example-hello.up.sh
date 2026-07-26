#!/usr/bin/env bash
# Example provisioning hook. Copy it to <your project>.up.sh and edit.
#
# It runs ONCE PER REPO of the project, with the working directory set to that
# repo's fresh worktree. Everything it needs arrives in the environment:
#
#   CC_REPO_NAME  the repo's name in projects.json  CC_WORKTREE  this worktree (= cwd)
#   CC_REPO_PATH  the canonical checkout            CC_BASE      the branch it was cut from
#   CC_RUN_DIR    the run's directory               CC_PROJECT   CC_JOB_ID
#   CC_RUN_MANIFEST  <run dir>/.run.json — every repo of this run
#
# A non-zero exit ABORTS the run: the engine takes down whatever it already
# provisioned and never hands a half-built tree to an agent.
set -euo pipefail

# Anything registered OUTSIDE the directory must carry the run's stamp, or two
# concurrent runs of the same repo collide on one global name.
SITE="${CC_REPO_NAME}-$(basename "$CC_RUN_DIR")"

case "$CC_REPO_NAME" in
  *)
    # Gitignored dependencies live only in the canonical checkout, so copy them
    # from there. `cp -c` clones on APFS: near-instant, no extra disk.
    [ -f "$CC_REPO_PATH/.env" ] && cp -c "$CC_REPO_PATH/.env" .env
    [ -d "$CC_REPO_PATH/node_modules" ] && cp -cR "$CC_REPO_PATH/node_modules" node_modules
    echo "provisioned $CC_REPO_NAME from $CC_REPO_PATH (site would be $SITE)"
    ;;
esac
