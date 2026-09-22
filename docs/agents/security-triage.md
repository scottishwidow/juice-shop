# Security triage and remediation workflow

How a CodeQL finding becomes either a reviewed pull request or a reported failure. Terms are
defined in [routes/CONTEXT.md](../../routes/CONTEXT.md). Decisions are recorded in
[docs/adr/0001](../adr/0001-mechanical-coupling-detection.md),
[0002](../adr/0002-authorization-inputs-read-from-base-ref.md),
[0003](../adr/0003-fork-contribution-bots-removed.md),
[0004](../adr/0004-triage-model-call-has-no-tools.md),
[0005](../adr/0005-remediation-input-is-trusted-verdict-only.md),
[0006](../adr/0006-taskflow-runner-not-adopted.md) (superseded),
[0007](../adr/0007-taskflow-security-workflows.md),
[0008](../adr/0008-security-demo-scope.md),
[0009](../adr/0009-taskflow-triage-implementation.md) and
[0010](../adr/0010-taskflow-remediation-implementation.md).

Both halves now run on the SecLab TaskFlow Agent runner: triage since ADR-0009, remediation
since ADR-0010. The bespoke patch author, patch gate, allow-list, regression-patch machinery
and the `sec:nopatch` refusal label are gone.

## Stages

A human pastes one same-repository code-scanning alert URL into an issue and applies
`sec:needs-triage`. Bulk processing is not supported and is not wanted.

| Label | Applied by | Effect |
| --- | --- | --- |
| `sec:needs-triage` | human | starts the `triage` job |
| `sec:triaged` | `triage` job | verdict comment posted; `sec:needs-triage` removed |
| `sec:ready-for-remediation` | human | starts `remediate` and `publish` |

The verdict (`confirmed`, `not-applicable`, `inconclusive`) is written in the comment body, not
encoded as a label. Only a label applied by a human causes a write to the codebase. Both jobs
read the same alert URL the human pasted for triage; no second reference is needed.

Removing and reapplying `sec:ready-for-remediation` starts a fresh attempt. Attempts are not
deduplicated or tracked, and a failed attempt sets no label that blocks the next one.

## Jobs

`triage`/`remediate`/`publish` are triggered by `on: issues: types: [labeled]`.
`lint-taskflow` also runs on `push`/`pull_request` for paths touching the taskflow
configuration, independent of any label and with no secrets.

| Job | Permissions | Does |
| --- | --- | --- |
| `lint-taskflow` | `contents: read` | offline TaskFlow grammar/resource lint of both taskflows, no model call |
| `triage` | `issues: write`, `security-events: read` | reads the alert, runs the TaskFlow agent, posts the assessment |
| `remediate` | `{}` | runs the TaskFlow agent over a checkout, writes its diff to an artifact |
| `publish` | `contents: write`, `pull-requests: write`, `issues: write` | enforces exclusions, opens the pull request or reports the failure |

`security-events: read` is the scope the code-scanning API requires; only `triage` calls it.
`remediate` and `publish` key the finding by the alert number in the issue body and take the
rule and path from the assessment `triage` published, so neither makes a scanner call.

Every job that runs a model holds no credential: `remediate` declares `permissions: {}` and
must check out with `persist-credentials: false`. Every job that holds a credential runs no
model: `publish` and `triage` make no model-driven shell call. The `triage` job's write
permission is comment and label changes only.

## Triage job

Implemented in `.github/workflows/security-triage.yml`, running
`lib/scripts/securityTriage/triage.ts` and the SecLab TaskFlow Agent runner
(`security_triage_taskflow/`), per [ADR-0007](../adr/0007-taskflow-security-workflows.md) and
[ADR-0009](../adr/0009-taskflow-triage-implementation.md).

The human-pasted issue body must contain exactly one same-repository code-scanning alert URL
(`https://github.com/<owner>/<repo>/security/code-scanning/<n>`); `lib/parseAlertUrl.ts` reads
it, distinguishing missing, ambiguous, unsupported (a secret-scanning or Dependabot alert URL)
and cross-repository references so each produces a specific, visible failure comment with a
link to the workflow run. Nothing else about the finding is trusted from the issue: the path
and rule are fetched from the code-scanning API keyed by that number, so editing the issue body
cannot redirect triage at a different file (issue #2, user story 13; issue #29, user story 4).

The verdict comment carries two independent representations of the same decision: prose for a
maintainer to read, and a structured JSON payload (`lib/verdictPayload.ts`) inside an HTML
comment for the `remediate` job to read. The payload states the alert number and the base
commit it was decided against, as well as the rule, path, the agent's reasoning and both
coupling findings. The alert number is what `remediate` binds itself to before it reads
anything; the base commit is recorded for the reader but no longer gates remediation
([ADR-0010](../adr/0010-taskflow-remediation-implementation.md), superseding
[ADR-0005](../adr/0005-remediation-input-is-trusted-verdict-only.md)). Reformatting the prose
paragraph does not affect the payload; a maintainer editing the comment for readability cannot
break the handoff.

The verdict is now derived by an agent that investigates the checked-out base ref (`master`)
through the official container-shell MCP toolbox (`security_triage_taskflow/taskflows/
triage.yaml`), not decided mechanically before the model runs - `lib/couplingEvidence.ts`
(formerly `lib/triageVerdict.ts`) still computes the same challenge-marker/test-path signals,
but only as investigative context handed to the agent and informational evidence in the
payload; it no longer predetermines the verdict (issue #30 acceptance criteria; see
[ADR-0001](../adr/0001-mechanical-coupling-detection.md) for the superseded mechanical
approach and [ADR-0004](../adr/0004-triage-model-call-has-no-tools.md) for the superseded
tool-free model call). The agent's structured output (`lib/taskflowVerdict.ts`) is read back
from the TaskFlow run's own `manifest.json` artifact after the process exits - a plain file
read, never a shell step templated with agent-produced text (see the taskflow file for why).
The workflow script, not the model, posts the comment and swaps `sec:needs-triage` for
`sec:triaged`, using the job's own `issues: write` permission; a parsing or execution failure
produces a distinct visible comment instead and leaves the label unchanged.

## Remediation job

Implemented in `.github/workflows/security-triage.yml`'s `remediate` job, running
`lib/scripts/securityTriage/remediate.ts` and the SecLab TaskFlow Agent runner
(`security_triage_taskflow/taskflows/remediate.yaml`), per
[ADR-0010](../adr/0010-taskflow-remediation-implementation.md).

The job checks out current `master` and mounts it into the same official container-shell
toolbox triage uses. The agent investigates and edits that checkout over many tool calls; the
fix is whatever it leaves in the working tree. It may change any source or test file,
including an intentionally vulnerable route and the tests that assert the vulnerable
behavior. There is no per-file allow-list and no challenge-preservation gate: both were
removed with the bespoke implementation (issue #31; [ADR-0008](../adr/0008-security-demo-scope.md)).

What the agent is given is small and comes from the workflow itself: the alert, and the
assessment this workflow published on the issue. The issue body contributes one thing, an
alert number, read from a same-repository code-scanning alert URL (`lib/parseAlertUrl.ts`).
`selectTrustedVerdict` (`lib/trustedVerdict.ts`) then accepts only a comment posted by
`github-actions[bot]` naming that alert, so a public comment cannot select another alert or
another filesystem target. The commit the assessment was decided against is no longer
compared with the commit remediation checked out: remediation always starts from current
`master`, and a push landing in between must not force a re-triage.

The job declares `permissions: {}` and checks out with `persist-credentials: false`, and the
container has no network. No credential of any kind reaches the model-driven side of the
workflow, so nothing the agent does can reach GitHub by itself.

After the run, `remediate.ts` reads two independent things: the diff, with `git` against the
checkout the agent edited - excluding the container's own index files and whatever the job's
dependency install already dirtied, so the change holds only what the agent authored - and the agent's own account of its work, from the TaskFlow
session's `manifest.json` (`lib/remediationProposal.ts`). The account is a claim, not a
result - nothing re-runs the checks it reports. Both go to a workflow artifact
(`lib/remediationArtifact.ts`), which is the only thing crossing to the credentialed job.

## Publish job

Implemented in `.github/workflows/security-triage.yml`'s `publish` job, running
`lib/scripts/securityTriage/publish.ts`. It holds the workflow's write credentials
(`contents: write`, `pull-requests: write`, `issues: write`) and makes no model call.

It installs dependencies from `master` before it reads the proposed change, and runs no
script, test or build from the proposed tree. A proposed change therefore cannot execute
with, or alter, the authority that publishes it.

The exclusions are enforced here, deterministically, against the paths the diff actually
touches once applied (`lib/excludedPaths.ts`):

| Category | Paths |
| --- | --- |
| workflow | `.github/`, `.husky/` |
| credential | `encryptionkeys/`, `.env*`, `*.pem`/`*.key`/`*.pfx`/`*.p12`/`*.jks`/`*.keystore` |
| authorization policy | `security_triage_taskflow/`, `lib/scripts/securityTriage/`, and the modules deciding what is trusted and published (`lib/excludedPaths.ts`, `lib/trustedVerdict.ts`, `lib/verdictPayload.ts`, `lib/issueComments.ts`, `lib/parseAlertUrl.ts`, `lib/taskflowVerdict.ts`, `lib/remediationArtifact.ts`, `lib/remediationPr.ts`, `lib/remediationProposal.ts`) |

A change touching any of them is rejected in full, with the rejected paths named in a comment
on the issue. Nothing partial is published.

Otherwise the job commits the change under the workflow's own identity with a DCO sign-off,
pushes it to an attempt-specific branch (`security/alert-<n>-run-<run id>-<attempt>`), and
opens a draft pull request against `master` (`develop` upstream). One branch per attempt is
deliberate: removing and reapplying `sec:ready-for-remediation` publishes another pull
request, with no deduplication and no attempt tracking.

## Publication is not validation

The demo publishes a fix pull request even when checks failed or never ran (issue #29, user
story 22; [ADR-0008](../adr/0008-security-demo-scope.md)). This is an explicit exception to
the old publication gate, so the pull request body carries the honesty burden:

- The Validation section reports the agent's checks as the agent's claims, with `passed`,
  `failed` and `not run` reproduced exactly as reported, and states that this workflow
  verified none of them.
- The pull request is always a draft.
- The Affirmation box is never checked, and the body says why.
- The AI Tool Disclosure names the runner, the model, and the instructions the agent had.
- The body links the alert, names the originating issue, and carries `Closes #<issue>` so
  merging - a human decision - closes the issue. The workflow never merges the pull request
  and never closes the issue itself.

## Failure

Every outcome that opens no pull request is reported as a comment on the originating issue,
with a link to the workflow run: an alert URL that does not parse, no trusted assessment, an
agent run that did not finish, an unusable agent report, an unchanged checkout, a diff that
does not apply, an excluded change, and a remediation job that crashed before writing
anything. `remediate` holds no credential and cannot report its own failure, so it writes the
reason to its artifact and `publish` - which runs on `always()` - posts it
(`lib/remediationArtifact.ts`, `lib/remediationPr.ts`).

No failure is fabricated into an empty pull request, and no failure blocks the next attempt:
there is no terminal refusal label. A human removes and reapplies
`sec:ready-for-remediation` to try again.

## Remediation target

CodeQL alert #6, `js/path-injection`, `routes/keyServer.ts:14`, is the workflow's
demonstration target. It is covered by an existing unit test asserting traversal is rejected
rather than sanitized (`test/server/keyServer.unit.test.ts`) and by an API test asserting the
exact string `Error: File names cannot contain forward slashes!`
(`test/api/file-serving.test.ts`), so a reviewer can see quickly whether a proposed fix
changed behavior or only its tests.

The preparatory regression patch, its baseline transcript, and the gate that applied them are
gone with the bespoke implementation: the agent now writes whatever test changes its fix
needs, and those changes are part of the reviewed pull request.
