# Changelog

All notable changes to claude-cron.

**This file is filled in with every commit that is pushed to `main`.** Not
afterwards, not in a batch at release time — in the same change as the code, so
the entry is written while the reason is still known. Other people run this
scheduler on their own projects; a fix they cannot see the shape of is a fix they
cannot trust or adopt. `claude-cron selftest` fails when `main` has moved and this
file has not.

How to write an entry, in one line: **say what behaviour changed and what it cost
to not have it.** "Fixed watchdog" is not an entry. "A long tool call is no longer
read as a hang — a 40-minute test suite used to be killed at the stall timeout" is.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **The skills the agent loop depends on now ship with the scheduler** (`skills/`),
  linked into `~/.claude/skills` by `claude-cron install` and inspectable with
  `claude-cron skills`. The prompts make these skills mandatory *by name*; when
  they lived only in an unversioned `~/.claude/skills`, a fresh clone ran agents
  citing standards their machine could not read, and nothing said so — the run
  simply held a lower bar in silence.
- **A ninth attack axis — the fidelity of the evidence** — in
  `closing-review-findings`, `reviewing-pull-requests` and
  `test-driven-development`. The other eight interrogate the code; none asked
  whether the test proving it was real. Three consecutive review rounds on one
  pull request came from fixtures that were hand-written guesses, so the wrong
  assumption sat in the code *and* in the test and they agreed with each other.
- **This changelog**, plus a selftest case that fails when `main` moves without it.

### Fixed

- **A human moving a card into the ready column is an answer, not a board glitch.**
  The round cap parks an exhausted ticket and waits for a human; the human's reply
  is the board move. A run then read the spent rounds, decided the card's presence
  there was an anomaly it would be exploiting, and escalated it straight back to
  Blocked — so the only lever that moved the ticket forward was undone every time
  it was pulled. `rc_develop_note` and the injected run contract now both say that
  the move *is* the decision, while keeping blocking available for genuinely new
  blockers.
- **The run-ending contract ships with the code**, not with one machine's
  `jobs.json`. The classifier that *demands* a `RUN COMPLETE:` marker was
  versioned; the contract that teaches agents to write one was not, so every run
  by anyone else would have been filed `warning` with nothing explaining why.
- **A long tool call is no longer mistaken for a stall.** The watchdog measured
  only the event stream, which goes quiet for the entire duration of a single tool
  call — so a test suite longer than `stall_timeout_seconds` was killed for taking
  the time it was asked to take. CPU burnt across the run's process tree is now a
  second, independent proof of life.
- **A run that stops talking is no longer recorded as a success.** A headless run
  ends the moment the model returns text without a tool call, so an agent that
  said "I'll wait for the suite and then commit" abandoned its ticket mid-task —
  and produced a textbook-clean record while doing it. A clean exit must now be
  claimed (`RUN COMPLETE:` / `NOTHING TO DO:` / `BLOCKED:`); an undeclared ending
  is a warning naming what to check.

## [0.1.0] — 2026-07-26

The scheduler as it stood before this changelog began: launchd tick and control
server, per-job prompts and prechecks, budgets and daily caps, git-worktree
isolation per run, the dev/review round cap, and the dashboard on 127.0.0.1.
Earlier history is in `git log`.
