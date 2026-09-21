/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  affirmationSatisfied,
  commitIsAuthorizedAndSignedOff,
  everyCommitAuthorizedAndSignedOff,
  finalDiffIsExactlyRegressionPlusProposal,
  GATE_COMMIT_IDENTITY,
  metadataIsComplete,
  resolveDestination,
  type CommitRecord,
  type PrMetadata
} from '../../lib/prCompliance'

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

const AUTHORIZED_COMMIT: CommitRecord = {
  authorName: GATE_COMMIT_IDENTITY.name,
  authorEmail: GATE_COMMIT_IDENTITY.email,
  trailer: `Signed-off-by: ${GATE_COMMIT_IDENTITY.name} <${GATE_COMMIT_IDENTITY.email}>`
}

void describe('commitIsAuthorizedAndSignedOff', () => {
  void it('is true for a commit authored and signed off by the gate identity', () => {
    assert.equal(commitIsAuthorizedAndSignedOff(AUTHORIZED_COMMIT), true)
  })

  void it('is false when the author email does not match the gate identity', () => {
    const commit = { ...AUTHORIZED_COMMIT, authorEmail: 'someone@example.com' }

    assert.equal(commitIsAuthorizedAndSignedOff(commit), false)
  })

  void it('is false when the name matches but the email does not', () => {
    const commit = { ...AUTHORIZED_COMMIT, authorEmail: 'github-actions[bot]@example.com' }

    assert.equal(commitIsAuthorizedAndSignedOff(commit), false)
  })

  void it('is false for an AI co-author trailer without a DCO sign-off', () => {
    const commit = { ...AUTHORIZED_COMMIT, trailer: 'Co-authored-by: Claude <noreply@anthropic.com>' }

    assert.equal(commitIsAuthorizedAndSignedOff(commit), false)
  })

  void it('is false when the sign-off names a different identity than the author', () => {
    const commit = { ...AUTHORIZED_COMMIT, trailer: 'Signed-off-by: A Human <human@example.com>' }

    assert.equal(commitIsAuthorizedAndSignedOff(commit), false)
  })
})

void describe('everyCommitAuthorizedAndSignedOff', () => {
  void it('is ok for a list of authorized, signed-off commits', () => {
    assert.deepEqual(everyCommitAuthorizedAndSignedOff([AUTHORIZED_COMMIT, AUTHORIZED_COMMIT]), { ok: true })
  })

  void it('refuses with compliance-identity-unauthorized for an unauthorized author', () => {
    const commit = { ...AUTHORIZED_COMMIT, authorName: 'A Human', authorEmail: 'human@example.com' }

    assert.deepEqual(everyCommitAuthorizedAndSignedOff([commit]), { ok: false, reason: 'compliance-identity-unauthorized' })
  })

  void it('refuses with compliance-signoff-missing for an authorized author with no trailer', () => {
    const commit = { ...AUTHORIZED_COMMIT, trailer: '' }

    assert.deepEqual(everyCommitAuthorizedAndSignedOff([commit]), { ok: false, reason: 'compliance-signoff-missing' })
  })

  void it('checks every commit, not just the last one', () => {
    const unauthorized = { ...AUTHORIZED_COMMIT, authorEmail: 'someone@example.com' }

    assert.deepEqual(everyCommitAuthorizedAndSignedOff([AUTHORIZED_COMMIT, unauthorized]), { ok: false, reason: 'compliance-identity-unauthorized' })
  })
})

void describe('resolveDestination', () => {
  void it('resolves the fork to master', () => {
    assert.deepEqual(resolveDestination('scottishwidow/juice-shop'), { repo: 'scottishwidow/juice-shop', base: 'master' })
  })

  void it('resolves upstream to develop', () => {
    assert.deepEqual(resolveDestination('juice-shop/juice-shop'), { repo: 'juice-shop/juice-shop', base: 'develop' })
  })

  void it('resolves nothing for an unknown repository', () => {
    assert.equal(resolveDestination('someone-else/juice-shop'), undefined)
  })
})

function completeMetadata (overrides: Partial<PrMetadata> = {}): PrMetadata {
  return {
    alertNumber: 6,
    ruleId: 'js/path-injection',
    targetPath: 'routes/keyServer.ts',
    baseCommit: '5bc7ce9292a2237e64771a8b2b71b3df730d0800',
    issueNumber: 9,
    destination: { repo: 'scottishwidow/juice-shop', base: 'master' },
    aiDisclosure: { models: ['claude-sonnet-5'], instructionsKnown: true },
    validation: [{ name: 'typecheck', command: 'npx tsc --noEmit', passed: true }],
    ...overrides
  }
}

void describe('metadataIsComplete', () => {
  void it('is true for fully populated metadata', () => {
    assert.equal(metadataIsComplete(completeMetadata()), true)
  })

  void it('is false with an invalid base commit', () => {
    assert.equal(metadataIsComplete(completeMetadata({ baseCommit: 'not-a-sha' })), false)
  })

  void it('is false with no validation results', () => {
    assert.equal(metadataIsComplete(completeMetadata({ validation: [] })), false)
  })

  void it('is false with an empty rule id', () => {
    assert.equal(metadataIsComplete(completeMetadata({ ruleId: '' })), false)
  })

  void it('accepts an explicit "unknown" AI disclosure rather than treating it as incomplete', () => {
    assert.equal(metadataIsComplete(completeMetadata({ aiDisclosure: { models: 'unknown', instructionsKnown: false } })), true)
  })
})

void describe('affirmationSatisfied', () => {
  void it('is true only when metadata is complete, checks passed, and identity is ok', () => {
    assert.equal(affirmationSatisfied(completeMetadata(), true, true), true)
  })

  void it('is false when a check failed even if metadata is complete', () => {
    assert.equal(affirmationSatisfied(completeMetadata(), false, true), false)
  })

  void it('is false when identity was not ok even if checks passed', () => {
    assert.equal(affirmationSatisfied(completeMetadata(), true, false), false)
  })

  void it('is false when metadata is incomplete regardless of checks or identity', () => {
    assert.equal(affirmationSatisfied(completeMetadata({ ruleId: '' }), true, true), false)
  })
})

void describe('finalDiffIsExactlyRegressionPlusProposal', () => {
  const regression = diffAddingFile('test/server/keyServerPathTraversal.unit.test.ts', ['regression line one'])
  const proposal = diffModifying('routes/keyServer.ts', ['proposal line one'])

  void it('is true when the final diff is exactly the regression plus the proposal', () => {
    const final = [regression, proposal].join('\n')

    assert.equal(finalDiffIsExactlyRegressionPlusProposal(final, regression, proposal), true)
  })

  void it('is false when the final diff also touches an extra path', () => {
    const widened = [regression, proposal, diffModifying('routes/fileServer.ts', ['extra'])].join('\n')

    assert.equal(finalDiffIsExactlyRegressionPlusProposal(widened, regression, proposal), false)
  })

  void it('is false when the final diff is missing the regression addition', () => {
    assert.equal(finalDiffIsExactlyRegressionPlusProposal(proposal, regression, proposal), false)
  })

  void it('is false when the proposal itself edits the regression test file', () => {
    const tamperedProposal = [proposal, diffModifying('test/server/keyServerPathTraversal.unit.test.ts', ['tampered'])].join('\n')
    const final = [regression, tamperedProposal].join('\n')

    assert.equal(finalDiffIsExactlyRegressionPlusProposal(final, regression, proposal), false)
  })
})
