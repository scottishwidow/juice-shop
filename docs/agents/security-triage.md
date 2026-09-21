# Security triage and remediation workflow

How a CodeQL finding becomes either a reviewed pull request or a recorded refusal. Terms are
defined in [routes/CONTEXT.md](../../routes/CONTEXT.md). Decisions are recorded in
[docs/adr/0001](../adr/0001-mechanical-coupling-detection.md),
[0002](../adr/0002-authorization-inputs-read-from-base-ref.md),
[0003](../adr/0003-fork-contribution-bots-removed.md) and
[0004](../adr/0004-triage-model-call-has-no-tools.md).

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

`remediate` must check out with `persist-credentials: false`. The `triage` toolbox permits
comment creation only.

## Triage job

Implemented in `.github/workflows/security-triage.yml`, running
`lib/scripts/securityTriage/triage.ts`.

The human-transcribed issue body must contain a case-insensitive `alert #<n>` reference (for
example "CodeQL alert #6"); `lib/parseAlertNumber.ts` reads it. Nothing else about the finding
is trusted from the issue: the path and rule are fetched from the code-scanning API keyed by
that number, so editing the issue body cannot redirect triage at a different file (issue #2,
user story 13).

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
3. Apply overrides from `.taskflow/allowlist.yml` on the base ref, if that file exists.

`.taskflow/**` is never inside an allow-list. The override file is created only when a fix
needs a path the default rule does not grant, or when a human has already committed a
coupling change that authorizes patching a coupled file.

Independent of the allow-list, the gate refuses any diff line that adds `eslint-disable`,
`@ts-ignore` or `@ts-expect-error`.

## Gate checks

```
npx tsc --noEmit
npx eslint <allow-listed paths>
npm run test:server
npm run test:api
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit <the target regression test>
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
rather than calling the code-scanning API a second time from a job with no credentials. The
allow-list comes from `computeAllowList` in `lib/authorizePatch.ts` (the same function the
gate will use), read against the checked-out base ref. The code style rule and the patch
author's role constraints are extracted from `CONTRIBUTING.md` and this document's compliance
table, both read from that same base ref, rather than duplicated by hand into the script. The
model's only tool is `propose_patch`; its diff is written to `patch-author-output/` and
uploaded as a workflow artifact, never posted, committed, or pushed anywhere.

## PR compliance contract

This contract applies to the briefs and gate planned in issues #6–#9. Those jobs are not
implemented yet. Removing the contribution bots does not waive contribution policy.

The gate reads `CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md`, and
`docs/agents/issue-tracker.md` from the same trusted base commit used for authorization.
The proposed diff cannot change the policy used to check itself. Missing or unreadable
policy blocks PR creation.

| Role | Required compliance instructions |
| --- | --- |
| Triage (#6) | Report the alert and coupling evidence. Do not claim checks passed or grant policy exceptions. Keep the model toolbox limited to comments. |
| Patch author (#7) | Receive applicable base-ref policy constraints with the scoped brief. Return only a diff within the allow-list. Do not change tests or policy, push, sign off for a person, or create or edit PRs. Hold no credentials. |
| Gate (#8–#9) | Read trusted policy, validate the proposal and required checks, then prepare the commit and PR metadata. Make no model call. |

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
`compliance-policy-unavailable`, `compliance-identity-unauthorized`,
`compliance-signoff-missing`, `compliance-metadata-incomplete`, or
`compliance-validation-failed`. The refusal states the unmet requirement and follows the
terminal NOPATCH path. The gate must not disable checks or weaken policy to proceed.

Gate tests must cover these refusals and a compliant proposal. They must also prove that a
proposal cannot replace base-ref policy and that metadata reports failures accurately.
These checks supplement `authorizePatch`; they do not widen its allow-list or give the
patch author credentials.

## Refusal

NOPATCH is terminal. The gate comments the reason and applies `sec:nopatch`; a human removes
the label after reading it. Feeding a rejection back for a second attempt is implemented but
disabled, because a retry that succeeds on the second attempt hides the refusal.

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
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit test/server/keyServerPathTraversal.unit.test.ts
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
node --import ./test/server/helpers/test-env.mjs --import tsx --test --test-force-exit test/server/keyServerPathTraversal.unit.test.ts
```
