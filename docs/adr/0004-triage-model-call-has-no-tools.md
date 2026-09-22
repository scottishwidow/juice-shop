---
status: superseded by ADR-0007
---

# The triage model call has no tools

ADR-0002 restricts the `triage` job's toolbox to comment creation, because an issue-edit
capability would let it rewrite the alert number that later selects the allow-list entry.
Rather than granting a general toolbox and then narrowing it with an allow-list of tool
names, the model call in #6 is given no tools at all: it is a single request to the
Anthropic Messages API that returns prose, with no function-calling capability of any kind.

The verdict itself (`exploitable`, `not-applicable`, `coupled-needs-decision`) is decided
before the model runs, by the deterministic `determineVerdict` function in
`lib/triageVerdict.ts`, from the coupling markers and the test-code check alone. The model's
only job is to narrate that decision in prose; it is instructed not to restate a different
verdict, and has no way to act on a different one even if it tried.

## Consequences

The comment and the label swap are both performed by the workflow script after the model
call returns, using the job's own `issues: write` permission. The model never holds that
permission and never calls a GitHub API of any kind. A prompt injected through the scanner
message or the issue body can at most influence the prose of one already-decided verdict; it
cannot cause a different verdict, a different label, or a write anywhere else.

This is the narrowest instance of "toolbox limited to comment creation," not the general
case. A job that needs the model to take more than one kind of action (for example,
proposing a diff in #7) still needs an explicit, scoped toolbox rather than no toolbox at
all.
