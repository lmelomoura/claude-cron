# Contributing to agentloop

This scheduler runs unattended agents that spend real money and write to real
repositories and trackers. A change that is merely plausible is not good enough
here — a bug does not throw an exception, it quietly holds a lower bar for
everyone running it. That is the reason for everything below.

## Before you write code

**Open an issue first** for anything that changes behaviour. A five-line
description of what you hit saves both of us a rewritten pull request.

Small, obvious fixes — a typo, a broken path, a wrong flag — can go straight to a
pull request.

## The workflow

`main` is protected: no force-pushes, no deletion, and a pull request with one
approval to merge. **Working branches are unrestricted** — push `fix/…` and
`feat/…` freely.

1. **Fork** the repository and branch from `main`. Name the branch for what it
   does: `fix/stall-watchdog-cpu`, `feat/skills-link`.

   ```bash
   gh repo fork lmelomoura/agentloop --clone
   cd agentloop && git switch -c fix/your-change
   ```

   (If you have write access, skip the fork and branch directly in the repository.)

2. Make the change.
3. **Run the checks** — they are offline and take seconds:

   ```bash
   agentloop selftest
   ```

   This covers the logic that can kill a run or lose money, plus
   `test/round-cap.test.sh`. It must pass before you open the pull request, and it
   is the first thing a reviewer runs.
4. **Fill in `CHANGELOG.md` in the same commit as the code.** Not afterwards, not
   at release time. `agentloop selftest` fails when `bin/`, `skills/` or `test/`
   moved after the last changelog entry, so a forgotten entry is caught before the
   pull request exists.
5. Open the pull request against `main`. The description is pre-filled from
   `.github/pull_request_template.md` — answer it rather than deleting it.

**CI runs on every pull request** (`.github/workflows/ci.yml`): `agentloop
selftest`, the server suite, and `tests/security/` in **both** of its
configurations against `gitleaks`, `trivy`, `syft` and `semgrep` at pinned
versions. It does not replace step 3 — a red pull request is a slower way to
learn what `selftest` tells you in seconds — and it will not go green over a
skipped test: an engine-gated test skips rather than fails when its binary is
missing, so the workflow fails the job on any skip it does not expect.

## The three rules that actually matter

### 1. A rule the code enforces must travel with the code

`config/` is git-ignored, and rightly so: it holds personal paths, repository
names, tracker ids, budgets and a dashboard token. **Nothing the scheduler depends
on may live only there.**

This has been learned twice, expensively. A run classifier shipped demanding a
`RUN COMPLETE:` marker while the contract that teaches agents to write one sat in
one machine's `jobs.json` — so every run by anyone else would have been filed
`warning`, with nothing explaining why. And prompts shipped citing skills by name
while the skills themselves lived only in an unversioned `~/.claude/skills`.

If your change needs an agent to behave a certain way, it belongs in versioned
code, in the prompt contract the scheduler injects (`run_ending_contract` in
`bin/agentloop`), or as a `selftest` assertion. Never as prose in a personal
config file.

### 2. Validate against reality, not against your own fixtures

A test you wrote, exercising a fake you wrote, proving behaviour you assumed,
cannot fail. It is not evidence — it is your belief restated in code and coloured
green.

Before hand-writing a fixture for anything you did not write — a CLI tool's
output, an API response, a file format — **run the real thing once and capture
it**, including the empty and error cases, which is where these bugs live (`[]` vs
`{}`, zero results vs no output at all). Derive the fake from the capture.

### 3. Write the changelog entry for a reader who was not there

Say what behaviour changed **and what it cost to not have it**.

- ✗ "Fixed watchdog"
- ✓ "A long tool call is no longer read as a hang — a 40-minute test suite used to
  be killed at the stall timeout"

## What never enters the repository

- `config/jobs.json`, `config/projects.json`, `config/models.json`,
  `config/control.token`, `config/prechecks/*.sh` — personal, git-ignored, and
  they stay that way.
- Anything containing a token, a password, or an API key. The repository is
  **public**; assume anything you commit is permanent and indexed.
- `data/` — local runtime state, logs and databases.

Run `git status --short` before committing and confirm every file you see is one
you meant to include.

## Scope of a good pull request

One change, explainable in a sentence. If the description needs "and also", it is
two pull requests.

Behavioural changes need a test. `agentloop selftest` is a plain bash suite —
add a case beside the ones already there, in the same style: a short comment
saying *why the case exists* (what broke, or would break, without it), then the
assertion.

## Review

Every pull request gets a review. Expect questions about the failure mode your
change prevents rather than about style — the code is not uniform and that is
fine, but the reasoning has to hold.

Merging into `main` is done by a maintainer.
