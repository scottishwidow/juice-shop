---
status: accepted
---

# TaskFlow remediation: an edited checkout, an exclusion rule, and a credential boundary

ADR-0009 replaced `triage` with the SecLab TaskFlow Agent runner and left `remediate`/`gate`
on the bespoke implementation. This ADR replaces them, completing issue #29. It supersedes
[ADR-0005](0005-remediation-input-is-trusted-verdict-only.md) in the parts about pinning
remediation to one base commit and about the allow-list; the part about which comment is
trusted survives unchanged and is the reason `lib/trustedVerdict.ts` is retained. It also
supersedes the two sections of [ADR-0009](0009-taskflow-triage-implementation.md) that
reasoned about the bespoke `remediate`/`gate` - its `VerdictPayload` read-shape argument and
its retention of `lib/parseAlertNumber.ts`; both are marked there.

## The fix is an edited checkout, not a proposed diff

The bespoke patch author asked the model for a unified diff in one tool call. An agent that
cannot read the file it is editing writes diffs that do not apply, and the whole apparatus
that made that workable - the scoped brief, the covering-test excerpts, the allow-list
embedded in the prompt - existed to compensate for it.

The remediation agent instead gets a writable workspace, bind-mounted into the same official
container-shell toolbox triage uses, and edits it over many tool calls. The workspace is a
copy of current `master`'s tracked files, built with `git checkout-index` from the job's own
checkout, with its own throwaway git repository so the agent's `git diff` still works inside
the container. The deliverable is the working tree it leaves behind;
`lib/scripts/securityTriage/remediate.ts` reads the diff after the process exits, using the
job's own (never mounted) git directory against the workspace as an external work tree,
through a throwaway index. The agent's captured `capture: response` output carries only its
account of its own work - a summary and the checks it says it ran - which is a claim,
published as a claim, and never re-run.

Two consequences worth naming:

- The diff must hold only what the agent authored. Building the workspace from the index
  means whatever the job's own `npm install` already dirtied is never in it in the first
  place. The container's exploration tools (ctags, gtags, cscope) can still write their index
  files into the workspace, so those are excluded by pathspec when the diff is collected.
- The mount is read-write, which for triage was a tolerated side effect (ADR-0009) and here
  is the entire point - but it is a copy, never the job's own checkout, so nothing the agent
  writes (including its own `.git/config`) is ever read or run by the job's own git commands.

## No allow-list; an exclusion rule instead

Issue #31 removes the per-file allow-list, the coupling gate, and the regression-patch
machinery. Fixing an intentional Juice Shop vulnerability is the demonstration, so a gate
that refuses to touch coupled routes refuses the demonstration
([ADR-0008](0008-security-demo-scope.md)).

What replaces it is narrower and inverted: `lib/excludedPaths.ts` names what a proposed change
may never touch - workflow and CI definitions, credential and key material, and the security
workflow's own authorization and publishing code. The rule is evaluated by the credentialed
`publish` job against the paths the applied diff actually touches, not by the agent and not
from anything the agent wrote. A change touching any of them is rejected in full: partial
publication would let an excluded edit set the terms of its own review.

The exclusion list names specific `lib/*.ts` modules rather than all of `lib/`, because `lib/`
holds ordinary application code the agent may legitimately need to fix. That makes the list
a maintenance obligation: a new module that decides what this workflow trusts or publishes
must be added to it.

## The credential boundary is a job boundary

`remediate` runs the model and holds nothing: `permissions: {}`, `persist-credentials: false`,
and `CONTAINER_NETWORK: none`. `publish` holds `contents: write`, `pull-requests: write` and
`issues: write` and runs no model. The artifact between them is data - a diff and a JSON
report - and is the only thing that crosses.

`publish` also never executes the proposed tree: it installs dependencies from `master` before
it reads the change, and runs no script, test or build from it. So a proposed change cannot
execute with, or alter, the authority that publishes it. The cost is that `publish` verifies
nothing, which is why the pull request is always a draft and says so.

Because `remediate` cannot post its own failure, it writes the reason to the same artifact and
`publish` - running on `always()` - reports it. Every outcome that opens no pull request
becomes a comment with a run link; none becomes an empty pull request.

## Remediation no longer waits on triage's commit

ADR-0005 required the verdict's base commit to match the commit the patch author checked out,
so that authorization inputs and the patched file came from one tree. With the allow-list gone
there is no authorization input read from that tree, and the requirement now only breaks the
demo: any push to `master` between triage and the remediation label forced a re-triage.

`selectTrustedVerdict` therefore no longer compares base commits, and `base-commit-mismatch`
is gone. The identity check it exists for is unchanged: only a comment posted by
`github-actions[bot]` naming the alert the issue body names selects anything, so a public
comment still cannot choose another alert or another filesystem target. The assessment's base
commit stays in the payload as information for the reader.

## Publication without validation, stated as such

Issue #29's user story 22 requires a pull request even when checks failed or never ran. The
container is a source-access image with no application runtime, so in practice most checks
will be reported `not-run`. The honesty burden moves entirely into the pull request body
(`lib/remediationPr.ts`): agent-reported results are labelled as the agent's, the body states
that the workflow verified none of them, the pull request is always a draft, and the
Affirmation box is never checked. `Closes #<issue>` links the issue; merging is a human act,
and nothing in the workflow merges or closes anything.

## One branch per attempt

`security/alert-<n>-run-<run id>-<attempt>`. Removing and reapplying the label publishes
another pull request rather than colliding with the previous one. Duplicate pull requests are
accepted (issue #29, user story 25); no deduplication, active-attempt tracking, or retry
engine is added.

## Consequences

`remediate.ts`, `gate.ts`, `lib/authorizePatch.ts`, `lib/patchGate.ts`, `lib/diffFacts.ts`,
`lib/gateChecks.ts`, `lib/proposedPatch.ts`, `lib/regressionBaseline.ts`,
`lib/remediationBrief.ts`, `lib/remediationFiles.ts`, `lib/remediationRefusal.ts`,
`lib/prCompliance.ts`, `lib/prBody.ts`, `lib/parseAlertNumber.ts`, `lib/baseRefReader.ts`,
their tests, and the `docs/agents/artifacts/` regression fixtures are deleted. One remediation
implementation remains.

Live verification is again the maintainer's post-merge step: the offline checks here are
`python3 -m seclab_taskflow_agent --lint` on both taskflows (the `lint-taskflow` CI job) and
the deterministic TypeScript units. A real run needs a live `ANTHROPIC_API_KEY`, a real
`docker pull`, and a labelled issue.
