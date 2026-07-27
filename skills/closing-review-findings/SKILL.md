---
name: closing-review-findings
description: Use when fixing a finding raised in code review, or hardening any rule or gate that must refuse more than the single route it names — before replying to the reviewer or pushing. Covers closing the adjacent routes in the same commit and promoting each reproduction into a versioned adversarial test so a later fix cannot silently reopen it. Triggers include "address the review comments", "fix the change-requested PR", "harden this check", "the reviewer found another way around the rule".
---

# Closing Review Findings

Fixing the exact case a reviewer named is not closing the finding. On an adversarial rule — anything that must refuse *every* route to an outcome, not only the obvious one — the fix that closes one key and leaves the synonym beside it open is why reviews run to four and five rounds: each round re-finds the same rule through the next key, at a full cycle's cost.

**Core principle:** a finding is closed when two things hold in the same commit — every adjacent route is closed too, and a reproduction lives in the suite so the route cannot reopen. `pytest` going green is neither of those.

## 0. Before you ask for review: attack your own change first

Everything below is cheaper to find yourself than to have a reviewer find, and *far* cheaper than finding it four rounds later, after fixes have been built on top of the wrong assumption. Before opening or updating a pull request, walk the same nine axes the reviewer will walk — they are not a review-side idea, they are where this class of code breaks:

1. **The rule's other routes** — synonym, second mechanism, two names for one thing, declared in two places.
2. **The inputs the rule computes from** — who *supplies* each value the code trusts? A value supplied by the party the rule constrains makes the rule advisory.
3. **The source of truth** — which document/file/ref is read, and does every part read the same one?
4. **Absence and failure** — missing, empty, unreadable, tool errored: trace each to its verdict. Absence that degrades to *pass* is the commonest silent hole.
5. **Identity and collision** — basenames, stripped prefixes, aliases, case: does one thing take or overwrite another's data?
6. **Aggregation** — union, last-wins, overwrite, sum: does a second entry destroy the first? Is a total reconciled with its parts?
7. **Errors where a verdict is required** — a crash is not a refusal; it is the absence of an answer.
8. **The ceiling's own value** — is the bound settable by the party it binds? Is *removing* the thing cheaper than exceeding the limit on it?
9. **The fidelity of your own evidence** — see below. Axes 1–8 interrogate the code; this one interrogates the test that says the code is right, and it is the one that produces repeat rounds.

For each axis: probe it, and if it holds, keep the probe as a control. Say in the PR description which axes you walked. This is not optional polish — a change that has not been attacked by its author is a change whose review will take four rounds.

### Axis 9 in full: is the evidence real, or did you write it?

A suite you wrote, exercising fakes you wrote, proving behaviour you assumed, cannot fail. It is not evidence — it is your belief, restated in Python and coloured green. Every repeat-round failure examined so far has this shape:

| what the test proved | what was actually true |
|---|---|
| the fake **wrote a report file** | the real tool **prints to stdout** |
| the probe fed **truncated JSON** | the real failure was **valid JSON of the wrong shape** |
| the fake emitted `{"files": {}}` | PHP `json_encode` of an empty assoc emits `{"files": []}` |

Three rounds, three fixes, one cause: **the assumption lived in both the code and the test, so they agreed and both were wrong.** A reviewer found each one in minutes by doing the single thing the suite never did — running the real thing (`php -r 'echo json_encode([]);'`).

So, for every external dependency your change reasons about — a CLI tool's output, an API's response body, a file format, another service's payload:

- **Name the assumption.** "phpstan emits `files` as an object." Write it down; an unnamed assumption cannot be checked.
- **Get one real sample.** Run the tool. Call the endpoint. If neither is possible here, find a recorded sample from CI, the vendor's own docs/test fixtures, or the image — and say in the PR which it was. A sample from *anywhere real* beats an object you typed.
- **Check the empty and the error case, not just the populated one.** Most of these bugs live in the empty encoding: `[]` vs `{}`, zero findings vs no report, `null` vs absent. A sample that only shows the "has results" case is half a sample.
- **Derive the fake from the sample.** Do not hand-write it beside the sample and hope they match — generate it, or assert in a test that the fake still matches the recorded sample. A fake that cannot drift is the only fake that keeps proving something.

**The decisive question, asked of your own diff:** *if my assumption about this tool is wrong, does any test in this suite fail?* If the answer is no, you have written no test — you have written a mirror. Fix that before you fix anything else.

## 1. Close the whole rule, not the named key — the adjacency discipline

For every rule you touch, ask the one question a diff-read skips: **what other route reaches the same outcome?** Enumerate the keys adjacent to the one being policed and try each. A rule that matches a *string* rather than an *outcome* is nearly always reachable another way.

The shapes that recur — each has cost real review rounds:

- **A synonym.** The rule rejects `off`; `warn`/`disabled` reach the same place unpoliced.
- **A second mechanism.** One list is measured against a ceiling; another list with the same effect is not.
- **The limit's own value.** The ceiling is enforced — and the ceiling is settable, unbounded, by the party it constrains.
- **Two names for one thing.** A canonical id and its alias, or a `.yml`/`.yaml` spelling, both accepted and treated differently.
- **Declared in two places.** A value fixed in a catalogue *and* settable in the document, with no rule relating them.

Close them all in the **same commit**. A fix that closes one key and cannot say what it did about the neighbours is not finished — it comes back as another round.

## 2. Promote every reproduction into the versioned adversarial suite

A reproduction that lives only in the reviewer's scratch directory protects nothing: the next fix reopens the route and the suite stays green. Move it into the repository.

Keep an adversarial suite versioned with the code — `tests/adversarial/` or the project's idiomatic equivalent — one test per route a rule was ever found reachable through. For every finding you fix, add a probe there:

- A **refusal** probe — the route stays closed.
- A **control** probe — the genuine case stays ACCEPTED. A rule that now rejects everything is not fixed; it is broken the other way, and only a control catches it. (A real fix once regressed a ticket's own acceptance criterion exactly here, by making a refusal so broad it rejected the valid input too.)

### The control must be the NEAREST case, or it protects nothing

This is where §1 turns on you. Closing adjacent routes means widening the rule, and a widened rule is a rule that can now swallow things it must not touch. A control chosen for convenience — something obviously, comfortably outside — passes both before and after your change and therefore tests nothing.

Ask it literally: **what is the closest thing to my new boundary that must stay OUT?** Then probe *that*.

A worked failure. A hook-merging rule identified its own entries by a fixed substring, which missed entries written with a custom path — too narrow, and it duplicated them. The fix replaced the substring with a shape pattern: a quoted project-dir invocation ending in one of three phase words. The suite had a control — a foreign hook ending in `lint` — and it stayed green, because `lint` is nowhere near the boundary. The dangerous neighbour was a foreign hook ending in `capture`: one of the three words, written by somebody else, now silently deleted. **The fix for round 1 was the finding of round 2**, and it cost a full dev run plus a full review run to discover.

So whenever a change makes a rule accept, match, sweep or recognise MORE than before, the same commit lands both sides:

| | what it proves |
|---|---|
| refusal probe | the route the reviewer named is now closed |
| **containment probe** | the nearest case on the OTHER side of the new boundary is still refused / preserved / untouched |

If no containment case comes to mind, do not conclude the boundary is perfect — assume you have not found it yet. Enumerate what the widened rule now matches that the narrow one did not, and ask which of those belongs to somebody else.

Each probe must **FAIL on the code before your change and PASS after**. If it passes before, you have not reproduced the finding — find the real route. Never delete, weaken, or skip a probe to make the suite green; if a probe looks wrong, that is a blocking problem to escalate, not to edit away.

The full test run passing is not sufficient on its own. It is the adversarial probes — failing before, passing after — that stop a later fix silently reopening an earlier one.

## 3. The decisive test: can it become a behavioural probe?

Use this to separate a blocking finding from a merely documentary one — and to tell yourself you are done:

- If you can write a probe that FAILS before the fix and PASSES after **by measuring only what the code accepts, rejects, computes, or reports**, the finding is **behavioural**. Fix it, close the neighbours, land the probe.
- If nothing a probe could measure changes — a code comment, a docstring, a message's wording, a note that belongs on another ticket — it is **documentary**. Write it down and carry it to the ticket that will resolve it; it gets no probe because there is nothing behavioural to hold.

When in doubt, it is behavioural. "Small" is not "documentary".

## 4. Reply with the routes, not just the fix

When you reply to the reviewer, or record the fix, state which adjacent routes you also closed and which you tried and found already safe. The routes that stayed closed are evidence, exactly as a good reviewer lists the routes they probed. This is what lets a re-review verify the *rule* is closed, not just the *example* — and it is what keeps the next round from re-finding what you already handled.

## Setting up the suite in a new project

The pattern is project-agnostic; only the harness is language-specific.

- **One directory the runner discovers.** In Python, `tests/adversarial/` with a parametrised test that runs each probe as its own case, so a failure names the route. Elsewhere, the idiomatic equivalent.
- **One probe per route, named after the route, not the symptom** (`alias_spelled_suppression_list_is_pruned`, not `test_bug_1234`).
- **Refusal probes and control probes side by side.** A probe with no assertion is a gap, not a pass — make the harness fail a probe that recorded nothing.
- **New rounds land here before the finding is called closed.** The suite is how the project remembers what the reviewer already found, so the memory survives the reviewer's scratch directory being deleted.

## Red flags — stop

- About to reply "fixed" with the suite green but no new probe added → the route can reopen; add the probe first.
- Fixed the named key, never enumerated the neighbours → you closed an example, not a rule.
- A probe passes *before* your fix → you have not reproduced the finding; the real route is elsewhere.
- Tempted to weaken or delete a probe to go green → that is the one move that is never yours; escalate instead.
- Your change reasons about an external tool or API and **no test in the suite consumes a real sample of its output** → the suite is a mirror; axis 9.
- About to state a property in a reply that is broader than what a probe demonstrates ("a bad shape errors" when the probe fed only truncated input) → write the probe for the wider claim, or narrow the claim. Overclaiming is what makes a round *look* closed while the neighbouring route stays open.
- A conformance/validation check you just added has only ever been run against hand-written inputs → check it against the tool's real **clean/empty** output before you push. A rule tightened past reality fails the happy path, which is worse than the hole it closed.
