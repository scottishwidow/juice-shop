# Security triage and remediation workflow

How a CodeQL finding becomes either a reviewed pull request or a recorded refusal. Terms are
defined in [routes/CONTEXT.md](../../routes/CONTEXT.md). Decisions are recorded in
[docs/adr/0001](../adr/0001-mechanical-coupling-detection.md),
[0002](../adr/0002-authorization-inputs-read-from-base-ref.md) and
[0003](../adr/0003-fork-contribution-bots-removed.md).

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
node --test <the target regression test>
```

`npm run rsn` and `npm run lint:config` are not run: the allow-list makes both unreachable.
The frontend build and lint are not run: no allow-listed path can affect them.

## Remediation brief

The patch author receives the alert, the coupling verdict, the allow-list, the JS Standard
Style rule, and the contract of the tests that already cover the target. It does not receive
`CLAUDE.md`, which is written for an agent with the whole repository in scope and a human
reviewing at the end.

## Refusal

NOPATCH is terminal. The gate comments the reason and applies `sec:nopatch`; a human removes
the label after reading it. Feeding a rejection back for a second attempt is implemented but
disabled, because a retry that succeeds on the second attempt hides the refusal.
