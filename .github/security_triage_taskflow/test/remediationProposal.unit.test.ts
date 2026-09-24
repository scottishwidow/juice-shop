/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { describeRemediationProposalFailure, parseRemediationProposal } from '../lib/remediationProposal'

void describe('remediation agent report', () => {
  void it('accepts a report that names every check it ran and every check it could not', () => {
    const result = parseRemediationProposal({
      summary: 'Rejected path separators before resolving the requested key.',
      checks: [
        { name: 'unit', command: 'node --test test/server/keyServer.unit.test.ts', result: 'passed', detail: '3 passing' },
        { name: 'lint', command: 'npx eslint routes/keyServer.ts', result: 'failed', detail: 'one style error' },
        { name: 'api', command: 'npm run test:api', result: 'not-run', detail: 'no application runtime in the container' }
      ]
    })

    assert.equal(result.ok, true)
    assert.equal(result.ok && result.proposal.checks.length, 3)
  })

  void it('accepts a report claiming no checks at all', () => {
    const result = parseRemediationProposal({ summary: 'Narrowed the accepted file names.', checks: [] })

    assert.equal(result.ok, true)
    assert.deepEqual(result.ok && result.proposal.checks, [])
  })

  void it('reports a missing captured result separately from a malformed one', () => {
    assert.deepEqual(parseRemediationProposal(undefined), { ok: false, reason: 'no-output' })
    assert.deepEqual(parseRemediationProposal({ checks: [] }), { ok: false, reason: 'malformed-output' })
    assert.deepEqual(
      parseRemediationProposal({ summary: 'x', checks: [{ name: 'unit', command: 'npm test' }] }),
      { ok: false, reason: 'malformed-output' }
    )
  })

  void it('refuses an invented check result rather than publishing it', () => {
    const result = parseRemediationProposal({
      summary: 'Fixed it.',
      checks: [{ name: 'unit', command: 'npm test', result: 'probably-fine', detail: 'looks good' }]
    })

    assert.deepEqual(result, { ok: false, reason: 'invalid-check-result' })
    assert.match(describeRemediationProposalFailure('invalid-check-result'), /passed, failed, not-run/)
  })
})
