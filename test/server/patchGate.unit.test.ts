/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type { BaseRefReader } from '../../lib/authorizePatch'
import {
  buildRetryFeedback,
  decidePatchGate,
  decideGateOutcome,
  describeGateRefusal,
  describeOutcomeRefusal,
  RETRY_WITH_FEEDBACK_ENABLED,
  type GateOutcomeInput,
  type OutcomeRefusalReason
} from '../../lib/patchGate'
import { GATE_COMMIT_IDENTITY, type CommitRecord } from '../../lib/prCompliance'
import type { CheckResult } from '../../lib/gateChecks'
import type { TestRunSummary } from '../../lib/regressionBaseline'
import type { IssueComment } from '../../lib/trustedVerdict'

const POLICY_FILES = {
  'CONTRIBUTING.md': '# Contributing',
  '.github/PULL_REQUEST_TEMPLATE.md': '### Description',
  'docs/agents/issue-tracker.md': '# Issue tracker'
}

function diffModifying (path: string, addedLines: string[]): string {
  const hunkBody = addedLines.map(line => `+${line}`).join('\n')
  return [
    `diff --git a/${path} b/${path}`,
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -1,0 +1,${addedLines.length} @@`,
    hunkBody
  ].join('\n')
}

function readerWithFiles (files: Record<string, string>): BaseRefReader {
  return (path: string) => files[path]
}

void describe('decidePatchGate', () => {
  const targetPath = 'routes/keyServer.ts'
  const alertNumber = 6
  const diff = diffModifying(targetPath, ['const x = 1'])

  void it('allows an uncoupled target with a diff confined to its own path when policy is readable', () => {
    const reader = readerWithFiles({ ...POLICY_FILES, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, alertNumber, diff, reader)

    assert.deepEqual(result, { allowed: true })
  })

  void it('delegates a refusal to authorizePatch unchanged', () => {
    const reader = readerWithFiles({ ...POLICY_FILES, [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = decidePatchGate(targetPath, alertNumber, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'solve-coupled' })
  })

  void it('refuses with compliance-policy-unavailable when CONTRIBUTING.md is missing from the base ref', () => {
    const { 'CONTRIBUTING.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, alertNumber, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })

  void it('refuses with compliance-policy-unavailable when the PR template is missing from the base ref', () => {
    const { '.github/PULL_REQUEST_TEMPLATE.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, alertNumber, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })

  void it('refuses with compliance-policy-unavailable when the issue-tracker doc is missing from the base ref', () => {
    const { 'docs/agents/issue-tracker.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, alertNumber, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })

  void it('checks policy availability even when the diff would otherwise be refused', () => {
    const { 'CONTRIBUTING.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = decidePatchGate(targetPath, alertNumber, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })
})

void describe('describeGateRefusal', () => {
  void it('returns a distinguishable, non-empty description for every refusal reason', () => {
    const reasons = [
      'path-not-allowed',
      'snippet-coupled',
      'solve-coupled',
      'lint-suppression-added',
      'type-suppression-added',
      'override-file-modified',
      'compliance-policy-unavailable'
    ] as const

    const descriptions = reasons.map(describeGateRefusal)

    for (const description of descriptions) {
      assert.ok(description.length > 0)
    }
    assert.equal(new Set(descriptions).size, reasons.length)
  })
})

void describe('retry-with-feedback', () => {
  void it('is implemented but disabled', () => {
    assert.equal(RETRY_WITH_FEEDBACK_ENABLED, false)
  })

  void it('builds feedback naming the refusal reason without sending it anywhere', () => {
    const feedback = buildRetryFeedback('routes/keyServer.ts', { allowed: false, reason: 'solve-coupled' })

    assert.equal(feedback.reason, 'solve-coupled')
    assert.match(feedback.message, /routes\/keyServer\.ts/)
    assert.match(feedback.message, /solve coupling/)
  })
})

// --- Issue #9: decideGateOutcome ------------------------------------------------------------

const BASE_COMMIT = '5bc7ce9292a2237e64771a8b2b71b3df730d0800'
const TARGET_PATH = 'routes/keyServer.ts'
const REGRESSION_PATH = 'test/server/keyServerPathTraversal.unit.test.ts'
const REGRESSION_ARTIFACT_PATH = 'docs/agents/artifacts/alert-6-regression.patch'

function diffAddingFile (path: string, addedLines: string[]): string {
  const hunkBody = addedLines.map(line => `+${line}`).join('\n')
  return [
    `diff --git a/${path} b/${path}`,
    'new file mode 100644',
    '--- /dev/null',
    `+++ b/${path}`,
    `@@ -0,0 +1,${addedLines.length} @@`,
    hunkBody
  ].join('\n')
}

function verdictComment (): IssueComment {
  const body = [
    '**Verdict: exploitable**',
    '',
    '- Alert: #6',
    `- Base: \`${BASE_COMMIT}\``,
    '- Rule: `js/path-injection`',
    `- Path: \`${TARGET_PATH}\``,
    '- Snippet coupling: no',
    '- Solve coupling: no',
    '- Test code: no'
  ].join('\n')
  return { body, user: { login: 'github-actions[bot]', type: 'Bot' } }
}

const AUTHORIZED_COMMIT: CommitRecord = {
  authorName: GATE_COMMIT_IDENTITY.name,
  authorEmail: GATE_COMMIT_IDENTITY.email,
  trailer: `Signed-off-by: ${GATE_COMMIT_IDENTITY.name} <${GATE_COMMIT_IDENTITY.email}>`
}

const PASSING_CHECKS: CheckResult[] = [
  { name: 'typecheck', command: 'npx tsc --noEmit', passed: true },
  { name: 'lint', command: 'npx eslint routes/keyServer.ts', passed: true },
  { name: 'test:server', command: 'npm run test:server', passed: true },
  { name: 'test:api', command: 'npm run test:api', passed: true },
  { name: 'regression', command: 'node --test', passed: true }
]

const BASELINE_PRE_EXPECTED: TestRunSummary = {
  passed: ['should serve requested file from folder /encryptionkeys', 'should raise error for slashes in filename'],
  failed: ['should reject ".." rather than resolve and serve it'],
  errored: false
}

const BASELINE_POST_PASSING: TestRunSummary = {
  passed: [
    'should reject ".." rather than resolve and serve it',
    'should serve requested file from folder /encryptionkeys',
    'should raise error for slashes in filename'
  ],
  failed: [],
  errored: false
}

function validInput (overrides: Partial<GateOutcomeInput> = {}): GateOutcomeInput {
  const regressionDiff = diffAddingFile(REGRESSION_PATH, ['regression assertion'])
  const proposedDiff = diffModifying(TARGET_PATH, ['fixed handler line'])
  const files: Record<string, string> = {
    ...POLICY_FILES,
    [TARGET_PATH]: 'export const serveKeyFiles = () => {}',
    [REGRESSION_ARTIFACT_PATH]: regressionDiff
  }

  return {
    repo: 'scottishwidow/juice-shop',
    alertNumber: 6,
    alert: { ruleId: 'js/path-injection', path: TARGET_PATH },
    issueNumber: 9,
    baseCommit: BASE_COMMIT,
    readBaseRef: readerWithFiles(files),
    comments: [verdictComment()],
    proposedDiff,
    regressionDiff,
    finalDiff: [regressionDiff, proposedDiff].join('\n'),
    commits: [AUTHORIZED_COMMIT],
    checkResults: PASSING_CHECKS,
    baselinePreSummary: BASELINE_PRE_EXPECTED,
    baselinePostSummary: BASELINE_POST_PASSING,
    aiDisclosure: { models: ['claude-sonnet-5'], instructionsKnown: true },
    ...overrides
  }
}

void describe('decideGateOutcome', () => {
  void it('allows a fully compliant proposal and returns its PR metadata', () => {
    const outcome = decideGateOutcome(validInput())

    assert.equal(outcome.allowed, true)
    assert.ok(outcome.allowed && outcome.prMetadata.alertNumber === 6)
    assert.ok(outcome.allowed && outcome.prMetadata.destination.base === 'master')
  })

  void it('refuses with compliance-destination-unconfigured for an unrecognized repository', () => {
    const outcome = decideGateOutcome(validInput({ repo: 'someone-else/juice-shop' }))

    assert.deepEqual(outcome, { allowed: false, reason: 'compliance-destination-unconfigured' })
  })

  void it('refuses when no trusted verdict comment is present', () => {
    const outcome = decideGateOutcome(validInput({ comments: [] }))

    assert.deepEqual(outcome, { allowed: false, reason: 'no-verdict-comment' })
  })

  void it('refuses a verdict comment posted by anyone other than the triage job', () => {
    const outcome = decideGateOutcome(validInput({
      comments: [{ ...verdictComment(), user: { login: 'helpful-stranger', type: 'User' } }]
    }))

    assert.deepEqual(outcome, { allowed: false, reason: 'untrusted-verdict-author' })
  })

  void it('refuses with verdict-target-mismatch when the trusted verdict names a different rule than the scanner API', () => {
    const outcome = decideGateOutcome(validInput({ alert: { ruleId: 'js/different-rule', path: TARGET_PATH } }))

    assert.deepEqual(outcome, { allowed: false, reason: 'verdict-target-mismatch' })
  })

  void it('delegates a path-authorization refusal to decidePatchGate unchanged', () => {
    const outcome = decideGateOutcome(validInput({
      readBaseRef: readerWithFiles({
        ...POLICY_FILES,
        [TARGET_PATH]: 'challengeUtils.solve(challenges.someChallenge)',
        [REGRESSION_ARTIFACT_PATH]: diffAddingFile(REGRESSION_PATH, ['regression assertion'])
      })
    }))

    assert.deepEqual(outcome, { allowed: false, reason: 'solve-coupled' })
  })

  void it('refuses with regression-artifact-unavailable when the regression cannot be read from the base ref', () => {
    const outcome = decideGateOutcome(validInput({ regressionDiff: undefined }))

    assert.deepEqual(outcome, { allowed: false, reason: 'regression-artifact-unavailable' })
  })

  void it('refuses with regression-artifact-unavailable when the artifact touches an extra path', () => {
    const widened = [
      diffAddingFile(REGRESSION_PATH, ['regression assertion']),
      diffAddingFile('routes/fileServer.ts', ['extra'])
    ].join('\n')
    const outcome = decideGateOutcome(validInput({
      readBaseRef: readerWithFiles({
        ...POLICY_FILES,
        [TARGET_PATH]: 'export const serveKeyFiles = () => {}',
        [REGRESSION_ARTIFACT_PATH]: widened
      }),
      regressionDiff: widened
    }))

    assert.deepEqual(outcome, { allowed: false, reason: 'regression-artifact-unavailable' })
  })

  void it('refuses with baseline-not-reproduced when the pre-proposal regression run does not show the expected failure', () => {
    const outcome = decideGateOutcome(validInput({ baselinePreSummary: BASELINE_POST_PASSING }))

    assert.deepEqual(outcome, { allowed: false, reason: 'baseline-not-reproduced' })
  })

  void it('refuses with regression-still-failing when the regression does not pass after the proposal', () => {
    const outcome = decideGateOutcome(validInput({ baselinePostSummary: BASELINE_PRE_EXPECTED }))

    assert.deepEqual(outcome, { allowed: false, reason: 'regression-still-failing' })
  })

  void it('refuses with diff-widens-authorized-scope when the final diff touches an extra path', () => {
    const input = validInput()
    const widenedFinal = [input.finalDiff, diffModifying('routes/fileServer.ts', ['sneaky change'])].join('\n')

    const outcome = decideGateOutcome({ ...input, finalDiff: widenedFinal })

    assert.deepEqual(outcome, { allowed: false, reason: 'diff-widens-authorized-scope' })
  })

  void it('refuses a proposal that itself edits the regression test, resisting test replacement', () => {
    const input = validInput()
    const tamperedProposal = [input.proposedDiff, diffModifying(REGRESSION_PATH, ['tampered assertion'])].join('\n')

    const outcome = decideGateOutcome({
      ...input,
      proposedDiff: tamperedProposal,
      finalDiff: [input.regressionDiff, tamperedProposal].join('\n')
    })

    // Caught by authorizePatch's existing allow-list check before the final-diff comparison
    // is ever reached: the proposal touches a path (the regression test) outside the
    // allow-list computed for this alert.
    assert.deepEqual(outcome, { allowed: false, reason: 'path-not-allowed' })
  })

  void it('refuses with compliance-identity-unauthorized when a commit was not authored as the gate identity', () => {
    const outcome = decideGateOutcome(validInput({
      commits: [{ ...AUTHORIZED_COMMIT, authorEmail: 'someone@example.com' }]
    }))

    assert.deepEqual(outcome, { allowed: false, reason: 'compliance-identity-unauthorized' })
  })

  void it('refuses with compliance-signoff-missing for an authorized commit with only an AI co-author trailer', () => {
    const outcome = decideGateOutcome(validInput({
      commits: [{ ...AUTHORIZED_COMMIT, trailer: 'Co-authored-by: Claude <noreply@anthropic.com>' }]
    }))

    assert.deepEqual(outcome, { allowed: false, reason: 'compliance-signoff-missing' })
  })

  void it('refuses with compliance-validation-failed when a required check did not pass (a patch that does not compile)', () => {
    const outcome = decideGateOutcome(validInput({
      checkResults: [{ name: 'typecheck', command: 'npx tsc --noEmit', passed: false }, ...PASSING_CHECKS.slice(1)]
    }))

    assert.deepEqual(outcome, { allowed: false, reason: 'compliance-validation-failed' })
  })

  void it('refuses with compliance-metadata-incomplete when validation results are empty', () => {
    const outcome = decideGateOutcome(validInput({ checkResults: [] }))

    // An empty check list also trivially satisfies allChecksPassed, so this exercises the
    // metadata-completeness gate specifically, not the validation gate above it.
    assert.deepEqual(outcome, { allowed: false, reason: 'compliance-metadata-incomplete' })
  })
})

void describe('describeOutcomeRefusal', () => {
  void it('returns a distinguishable, non-empty description for every full-outcome refusal reason', () => {
    const reasons: OutcomeRefusalReason[] = [
      'path-not-allowed',
      'snippet-coupled',
      'solve-coupled',
      'lint-suppression-added',
      'type-suppression-added',
      'override-file-modified',
      'compliance-policy-unavailable',
      'no-verdict-comment',
      'untrusted-verdict-author',
      'malformed-verdict-comment',
      'alert-number-mismatch',
      'base-commit-mismatch',
      'verdict-target-mismatch',
      'compliance-destination-unconfigured',
      'regression-artifact-unavailable',
      'regression-apply-failed',
      'baseline-not-reproduced',
      'regression-still-failing',
      'diff-widens-authorized-scope',
      'compliance-identity-unauthorized',
      'compliance-signoff-missing',
      'compliance-validation-failed',
      'compliance-metadata-incomplete'
    ]

    const descriptions = reasons.map(describeOutcomeRefusal)

    for (const description of descriptions) {
      assert.ok(description.length > 0)
    }
    assert.equal(new Set(descriptions).size, reasons.length)
  })
})
