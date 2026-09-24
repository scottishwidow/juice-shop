---
status: accepted
---

> Amended for issue #50. The first version of this decision mounted the job checkout,
> including its `.git` directory, into the container. It excluded the paths that the job had
> changed with a `git status` snapshot. The agent could then write a git config that the git
> of the runner read and ran. The agent now edits a separate workspace, as described below.

# TaskFlow remediation: an edited checkout, an exclusion rule, and a credential boundary

ADR-0009 replaced `triage` with the SecLab TaskFlow Agent runner and left `remediate`/`gate`
on the bespoke implementation. This ADR replaces them, completing issue #29. It supersedes
[ADR-0005](0005-remediation-input-is-trusted-verdict-only.md) in the parts about pinning
remediation to one base commit and about the allow-list; the part about which comment is
trusted survives unchanged and is the reason `trustedVerdict.ts` is retained. It also
supersedes the two sections of [ADR-0009](0009-taskflow-triage-implementation.md) that
reasoned about the bespoke `remediate`/`gate` - its `VerdictPayload` read-shape argument and
its retention of `lib/parseAlertNumber.ts`; both are marked there.

The current TypeScript files this record names are in `.github/security_triage_taskflow/lib/`
and `.github/security_triage_taskflow/scripts/`. Paths that start with `lib/` name files that
were in the root `lib/` directory and are now deleted.

## The fix is an edited checkout, not a proposed diff

The bespoke patch author asked the model for a unified diff in one tool call. An agent that
cannot read the file it is editing writes diffs that do not apply, and the whole apparatus
that made that workable - the scoped brief, the covering-test excerpts, the allow-list
embedded in the prompt - existed to compensate for it.

The remediation agent instead gets a writable workspace. It is mounted into the same official
container-shell toolbox triage uses, and the agent edits it over many tool calls. The
workspace is a copy of the tracked files of current `master`, made with `git checkout-index`.
It has its own throwaway git repository, so `git diff` works for the agent in the container.

The deliverable is the working tree the agent leaves behind. After the process exits,
`remediate.ts` reads the diff. It uses the git directory of the
job, which is never mounted, with the workspace as an external work tree and a throwaway
index. The agent's `capture: response` output holds only its account of its work: a summary
and the checks it says it ran. This is a claim. It is published as a claim, and nothing runs
it again.

Consequences:

- The diff must hold only what the agent wrote. The workspace comes from the index, so what
  the job's `npm install` changed is not in it. The container's exploration tools (ctags,
  gtags, cscope) can write index files into the workspace. A pathspec excludes them from the
  diff.
- The mount is read-write. For triage this was a tolerated side effect (ADR-0009). Here it is
  the purpose. But the git of the runner must not use what the agent wrote. It does not read
  the `.git` at the root of the work tree. It reads attributes from `HEAD`, not from the
  workspace. It refuses a nested repository and does not run git on it.

## No allow-list; an exclusion rule instead

Issue #31 removes the per-file allow-list, the coupling gate, and the regression-patch
machinery. Fixing an intentional Juice Shop vulnerability is the demonstration, so a gate
that refuses to touch coupled routes refuses the demonstration
([ADR-0008](0008-security-demo-scope.md)).

What replaces it is narrower and inverted: `excludedPaths.ts` names what a proposed change
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
(`remediationPr.ts`): agent-reported results are labelled as the agent's, the body states
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
