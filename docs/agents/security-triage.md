# Security triage and remediation workflow

How a CodeQL finding becomes either a reviewed pull request or a recorded refusal. Terms are
defined in [routes/CONTEXT.md](../../routes/CONTEXT.md). Decisions are recorded in
[docs/adr/0001](../adr/0001-mechanical-coupling-detection.md),
[0002](../adr/0002-authorization-inputs-read-from-base-ref.md),
[0003](../adr/0003-fork-contribution-bots-removed.md),
[0004](../adr/0004-triage-model-call-has-no-tools.md),
[0005](../adr/0005-remediation-input-is-trusted-verdict-only.md) and
[0006](../adr/0006-taskflow-runner-not-adopted.md).

## Stages

A human transcribes one code-scanning alert into an issue and applies `sec:needs-triage`.
Bulk processing is not supported and is not wanted.

| Label | Applied by | Effect |
| --- | --- | --- |
| `sec:needs-triage` | human | starts the `triage` job |
| `sec:triaged` | `triage` job | verdict comment posted; `sec:needs-triage` removed |
| `sec:ready-for-remediation` | human | starts `remediate` and `gate` |
| `sec:nopatch` | `gate` job | patch refused, reason in comment, no pull request |

The verdict (`exploitable`, `not-applicable`, `coupled-needs-decision`) is written in the
comment body, not encoded as a label. Only a label applied by a human causes a write to the
codebase.

## Jobs

Triggered by `on: issues: types: [labeled]`.

| Job | Permissions | Does |
| --- | --- | --- |
| `triage` | `issues: write` | reads the alert, calls the model, posts the verdict |
| `remediate` | `{}` | calls the model, writes a patch to an artifact |
| `gate` | `contents: write`, `pull-requests: write` | applies and checks the patch, opens the pull request or records NOPATCH |

`remediate` must check out with `persist-credentials: false`. The `triage` job's write
permission is comment creation only.

## Triage job

Implemented in `.github/workflows/security-triage.yml`, running
`lib/scripts/securityTriage/triage.ts`.

The human-transcribed issue body must contain a case-insensitive `alert #<n>` reference (for
example "CodeQL alert #6"); `lib/parseAlertNumber.ts` reads it. Nothing else about the finding
is trusted from the issue: the path and rule are fetched from the code-scanning API keyed by
that number, so editing the issue body cannot redirect triage at a different file (issue #2,
user story 13).

The verdict comment carries two independent representations of the same decision: prose for a
maintainer to read, and a structured JSON payload (`lib/verdictPayload.ts`) inside an HTML
comment for the `remediate` and `gate` jobs to read. The payload states the alert number and
the base commit it was decided against, as well as the rule, path and both coupling findings.
Those two fields are what `remediate` and `gate` bind themselves to before they read anything
([ADR-0005](../adr/0005-remediation-input-is-trusted-verdict-only.md)). Reformatting the prose
paragraph does not affect the payload; a maintainer editing the comment for readability cannot
break the handoff.

The verdict is decided mechanically by `lib/triageVerdict.ts` against the checked-out base
ref (`master`), before the model runs. The model call carries no tools and drafts only the
prose explanation of that already-decided verdict; see
[ADR-0004](../adr/0004-triage-model-call-has-no-tools.md). The workflow script, not the
model, posts the comment and swaps `sec:needs-triage` for `sec:triaged`, using the job's own
`issues: write` permission.

## Allow-list

The gate computes the allow-list rather than reading a roster:

1. Allow the path the alert names, taken from `most_recent_instance.location.path`.
2. Deny everything if that file has snippet coupling or solve coupling, measured on the base
   ref: `git show "$BASE_SHA:<path>" | grep -c 'vuln-code-snippet'` and the same for
   `challengeUtils.solve`.
3. Apply overrides from `.security-triage/allowlist.yml` on the base ref, if that file exists, reading
   only the entry keyed by the alert's own number. An entry keyed under a different alert
   number grants no paths and authorizes no coupled target for this alert.

The override file's own path is never inside an allow-list, even if listed under an `allow`
key. The override file is created only when a fix needs a path the
default rule does not grant, or when a human has already committed a coupling change that
authorizes patching a coupled file.

Independent of the allow-list, the gate refuses any diff line that adds `eslint-disable`,
`@ts-ignore` or `@ts-expect-error`.

## Gate checks

```
npx tsc --noEmit
npx eslint <allow-listed paths>
npm run test:server
npm run test:api
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit --test-reporter=tap <the target regression test>
```

`npm run rsn` and `npm run lint:config` are not run: the allow-list makes both unreachable.
The frontend build and lint are not run: no allow-listed path can affect them.

## Remediation brief

The patch author receives the alert, the coupling verdict, the allow-list, the JS Standard
Style rule, and the contract of the tests that already cover the target. It does not receive
`CLAUDE.md`, which is written for an agent with the whole repository in scope and a human
reviewing at the end.

Implemented in `.github/workflows/security-triage.yml`'s `remediate` job, running
`lib/scripts/securityTriage/remediate.ts`; brief assembly is the pure `lib/remediationBrief.ts`.
The job declares `permissions: {}` and checks out with `persist-credentials: false`
(issue #7, ADR-0002), so it makes no authenticated GitHub API call of any kind. It reads the
verdict `triage` already posted from an unauthenticated read of the issue's public comments,
paging to the end rather than only the first 30 (issue #16), rather than calling the
code-scanning API a second time from a job with no credentials.

That read is unauthenticated, so anyone can write a comment the job sees. Which comment it
acts on is decided by `selectTrustedVerdict` in `lib/trustedVerdict.ts`, and nowhere else:
the comment must be posted by `github-actions[bot]`, the only identity the `triage` job can
post as, and must name the alert the issue body names and the commit this job checked out.
Each refusal has its own reason (`no-verdict-comment`, `untrusted-verdict-author`,
`malformed-verdict-comment`, `alert-number-mismatch`, `base-commit-mismatch`) and stops the
job before any file is read.

Every base-ref read then goes through `createBaseRefReader` in `lib/baseRefReader.ts`, bound
to that pinned commit: only a regular tracked file of that commit can be read, and absolute
paths, `..` traversal and symlink escapes cannot. The model's reply is validated by
`parseProposedPatch` in `lib/proposedPatch.ts` before anything is written, so a response that
is not a well-formed `propose_patch` call of bounded size produces no artifact at all. See
[ADR-0005](../adr/0005-remediation-input-is-trusted-verdict-only.md).

The allow-list comes from `computeAllowList` in `lib/authorizePatch.ts` (the same function the
gate will use), read against that same pinned base commit. The code style rule and the patch
author's role constraints are extracted from `CONTRIBUTING.md` and this document's compliance
table, both read from that same base ref, rather than duplicated by hand into the script. The
model's only tool is `propose_patch`; its diff is written to `patch-author-output/` and
uploaded as a workflow artifact, never posted, committed, or pushed anywhere.

## Gate job

Implemented in `.github/workflows/security-triage.yml`'s `gate` job, running
`lib/scripts/securityTriage/gate.ts`; the authorization entry point is the pure
`authorizePatch` in `lib/authorizePatch.ts` (issue #5). `decideGateOutcome` in
`lib/patchGate.ts` calls it directly and contains no authorization logic of its own.

The job holds the workflow's write credentials (`contents: write`, `pull-requests: write`,
`issues: write`) and makes no model call. It checks out the base ref fresh, a checkout the
patch author cannot write to, so the proposed diff cannot influence its own validation. Like
`triage`, it reads the target path from the code-scanning API keyed by the alert number
parsed from the issue body, never from the issue body itself. Coupling markers and the
`.security-triage/allowlist.yml` override are read from that same base ref by `authorizePatch`. It
reads the issue's comments in full, paging to the end, with its own token rather than
spending the shared unauthenticated quota `remediate` must use (issue #16).

Issue #8 implements the refusal path; issue #9 implements the allow path: on an authorized
diff, the gate applies the regression and proposal diffs to a validation worktree, runs the
gate checks there, and - if `decideGateOutcome` allows it - applies the same diff to its live
checkout, commits and pushes it under the gate's own identity, and opens the pull request.
On refusal, the gate posts the reason as a comment on the originating issue and applies
`sec:nopatch` (see [Refusal](#refusal) below).

## PR compliance contract

This contract applies to the briefs and gate delivered across issues #6–#9. Removing the
contribution bots does not waive contribution policy.

The patch author reads `CONTRIBUTING.md` and this document's compliance table from the same
trusted base commit used for authorization, and follows them when drafting a proposal. The
proposed diff cannot change the policy used to check itself.

| Role | Required compliance instructions |
| --- | --- |
| Triage (#6) | Report the alert and coupling evidence. Do not claim checks passed or grant policy exceptions. The model call declares no tools; only the workflow script writes the comment. |
| Patch author (#7) | Receive applicable base-ref policy constraints with the scoped brief. Act only on the triage job's own verdict for the named alert and pinned base commit, and read only tracked files of that commit. Return only a diff within the allow-list. Do not change tests or policy, push, sign off for a person, or create or edit PRs. Hold no credentials. |
| Gate (#8–#9) | Validate the proposal and required checks against the base ref, then prepare the commit and PR metadata. Make no model call. |

Before opening a remediation PR, the gate must verify:

- The destination is explicit: `master` for `scottishwidow/juice-shop`, or `develop` for
  upstream `juice-shop/juice-shop`.
- Every proposed commit has a valid DCO sign-off from an authorized contributor identity.
  A configured Git identity or AI co-author trailer alone does not establish authorization.
  Never invent an identity or sign on behalf of a person without authorization.
- The PR names the scanner alert, the authorization rule, and the originating issue.
- AI Tool Disclosure selects AI-generated content and names the tools, known model versions,
  and relevant instructions. Unavailable details are marked unknown.
- Validation results match the actual commands and outcomes. Affirmation is checked only
  when all applicable requirements are met. Draft status does not waive a requirement.
- The required regression test and all gate checks pass. Required PR CI and scanner results
  must pass before merge; pending checks are not reported as passed.

Missing compliance must stop PR creation with a distinguishable refusal, such as
`compliance-identity-unauthorized`, `compliance-signoff-missing`,
`compliance-metadata-incomplete`, or `compliance-validation-failed`. The refusal states the
unmet requirement and follows the terminal NOPATCH path. The gate must not disable checks or
weaken policy to proceed.

Gate tests must cover these refusals and a compliant proposal. They must also prove that a
proposal cannot widen the published diff beyond the trusted regression plus the authorized
proposal, checked against the tree the gate actually applied and is about to push, and that
metadata reports failures accurately. These checks supplement `authorizePatch`; they do not
widen its allow-list or give the patch author credentials.

## Refusal

NOPATCH is terminal. The gate comments the reason and applies `sec:nopatch`; a human removes
the label after reading it. No mechanism feeds a rejection back for a second attempt: a retry
that succeeded would hide that the first was refused, so re-running remediation after a
refusal requires a human to remove `sec:nopatch` and reapply `sec:ready-for-remediation`.

A patch-author refusal is reported the same way, even though `remediate` holds no credential
to post it itself (issue #15). On any refusal - a rejected verdict selection, test-code, an
unreadable target or policy file, or a rejected model proposal - `remediate.ts` writes the
reason to `patch-author-output/refusal.json` (`lib/remediationRefusal.ts`) instead of only
throwing, and still exits non-zero so the failure stays visible in the Actions run. The `gate`
job now runs whether or not `remediate` succeeded (`if: always()`, still gated on the same
label), reads that file before touching any proposed diff, and posts the reason as a comment
distinguishable by its reason code, then applies `sec:nopatch`. A base-commit mismatch between
the two jobs' checkouts - the most likely trigger, since both check out the same moving branch
- produces the same reporting path and its description tells the maintainer to re-run triage.
If `remediate` crashed before writing anything at all, `gate` reports that too rather than
running with missing input.

## Remediation target

This section is working state, not a decision: the target may change if the scanner
clearance experiment below fails.

CodeQL alert #6, `js/path-injection`, `routes/keyServer.ts:14`, is the workflow's
demonstration target.

- Snippet coupling: `git show master:routes/keyServer.ts | grep -c vuln-code-snippet` → `0`.
- Solve coupling: `git show master:routes/keyServer.ts | grep -c 'challengeUtils.solve'` →
  `0`. (`routes/fileServer.ts`, by contrast, has 6 and is excluded.)
- The default allow-list rule above therefore grants exactly `routes/keyServer.ts`.

It is preferred over the other two uncoupled path-injection alerts (#7
`routes/logfileServer.ts`, #8 `routes/quarantineServer.ts`) because it alone is covered by
both an existing unit test asserting traversal is rejected rather than sanitized
(`test/server/keyServer.unit.test.ts`) and an API test asserting the exact string
`Error: File names cannot contain forward slashes!` (`test/api/file-serving.test.ts:157`).
`logfileServer` is registered in `server.ts` as the `vuln-line` of
`accessLogDisclosureChallenge`; `quarantineServer` as a `neutral-line` of
`directoryListingChallenge`.

### Baseline delivery

The maintainer selected the revised delivery plan from specification #2's compliance
follow-up: the preparatory change carries the regression as
[`artifacts/alert-6-regression.patch`](artifacts/alert-6-regression.patch), rather than an
active failing test. This supersedes #4's requirement to land the failing test in the server
test glob. No policy exception is required. The assertions are unchanged, and the original
failure output remains in
[`artifacts/alert-6-regression-baseline.txt`](artifacts/alert-6-regression-baseline.txt).

To reproduce the baseline in a disposable checkout with dependencies installed:

```sh
git apply docs/agents/artifacts/alert-6-regression.patch
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit --test-reporter=tap test/server/keyServerPathTraversal.unit.test.ts
```

Expected result on the unmodified handler: three tests, two passes, and one assertion
failure in `should reject ".." rather than resolve and serve it` (`sendFile` is called
once, expected zero). A loader error, missing test, or different failure is not baseline
evidence.

The gate must read this patch from the trusted base commit before applying the author's
proposal. The gate owns its application; the patch author cannot edit, replace, or omit
the regression. The artifact may add only `test/server/keyServerPathTraversal.unit.test.ts`.
It is a fixed validation input, not an override widening the author's allow-list.

First apply the regression to the unmodified base in an isolated validation checkout and
verify the expected failure. Then apply the authorized handler proposal and require the
regression, server suite, API suite, and other gate checks to pass. A missing or changed
regression, patch application failure, or unexpected baseline result blocks PR creation.
Never skip the regression or accept its failure on the remediated tree.

The successful remediation PR includes the unchanged regression test supplied by the gate
alongside the authorized handler diff. The existing server test glob then runs it in CI.
The gate must verify the final diff contains only the authorized proposal and that exact
test addition. This trusted test addition must be supported in #9 before demonstration #10.

The gate's explicit regression command is:

```
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit --test-reporter=tap test/server/keyServerPathTraversal.unit.test.ts
```
