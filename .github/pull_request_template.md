<!--
These are the questions a reviewer would otherwise ask one round-trip at a time.
Delete any line that genuinely does not apply — an unticked box you explain is
fine, a ticked box that isn't true is not.
-->

## What changes, and what it cost to not have it

<!-- One or two sentences. "A long tool call is no longer read as a hang — a
40-minute suite used to be killed at the stall timeout", not "fixed watchdog". -->

## How I know it works

<!-- What did you RUN? Paste the relevant output. A reviewer verifies findings by
execution, and so should an author: "selftest 42 passed" beats "should be fine". -->

- [ ] `claude-cron selftest` passes
- [ ] `CHANGELOG.md` filled in **in the same commit as the code**

## Checks

- [ ] Nothing personal is committed — no `config/jobs.json`, `projects.json`,
      `models.json`, `control.token`, `config/prechecks/*.sh`, no tokens or
      passwords. (`git status --short` before committing; the repo is **public**.)
- [ ] Anything the scheduler *depends on* lives in versioned code, in the injected
      prompt contract, or as a selftest assertion — never only in personal config.
- [ ] Any fixture standing in for an external tool or API comes from a **real
      captured sample**, including its empty/error case — not hand-written from
      what I assumed the output looks like.
- [ ] Behavioural changes carry a test, with a comment saying what breaks without it.

## Anything you are unsure about

<!-- Say so here rather than leaving the reviewer to guess. A stated doubt is
cheaper than a missed one, and it is not held against the pull request. -->
