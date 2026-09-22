/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import {
  DIFF_FILE,
  PROPOSAL_FILE,
  readRemediationArtifact,
  writeRemediationFailure,
  writeRemediationProposal,
  type RemediationProposalArtifact
} from '../../lib/remediationArtifact'

const DIFF = 'diff --git a/routes/keyServer.ts b/routes/keyServer.ts\n'

const ARTIFACT: RemediationProposalArtifact = {
  alert: {
    number: 6,
    url: 'https://github.com/scottishwidow/juice-shop/security/code-scanning/6',
    ruleId: 'js/path-injection',
    path: 'routes/keyServer.ts'
  },
  verdict: 'confirmed',
  baseCommit: '5bc7ce9292a2237e64771a8b2b71b3df730d0800',
  proposal: { summary: 'Rejected path separators.', checks: [] }
}

function directory (): string {
  return mkdtempSync(path.join(tmpdir(), 'remediation-artifact-'))
}

void describe('remediation artifact handoff', () => {
  void it('round-trips a proposed change between the two jobs', () => {
    const output = directory()
    writeRemediationProposal(output, ARTIFACT, DIFF)

    const artifact = readRemediationArtifact(output)

    assert.equal(artifact.kind, 'proposal')
    assert.equal(artifact.kind === 'proposal' && artifact.diff, DIFF)
    assert.deepEqual(artifact.kind === 'proposal' && artifact.proposal.alert, ARTIFACT.alert)
  })

  void it('round-trips a recorded failure', () => {
    const output = directory()
    writeRemediationFailure(output, { reason: 'no-change', detail: 'nothing was edited' })

    assert.deepEqual(readRemediationArtifact(output), {
      kind: 'failure',
      failure: { reason: 'no-change', detail: 'nothing was edited' }
    })
  })

  void it('prefers a recorded failure over a proposal written before it', () => {
    const output = directory()
    writeRemediationProposal(output, ARTIFACT, DIFF)
    writeRemediationFailure(output, { reason: 'unexpected-error', detail: 'crashed after writing' })

    assert.equal(readRemediationArtifact(output).kind, 'failure')
  })

  void it('reads an empty diff as no artifact rather than as an empty proposal', () => {
    const output = directory()
    writeRemediationProposal(output, ARTIFACT, '   \n')

    assert.deepEqual(readRemediationArtifact(output), { kind: 'missing' })
  })

  void it('reads an unwritten or unparsable directory as missing', () => {
    assert.deepEqual(readRemediationArtifact(directory()), { kind: 'missing' })

    const corrupt = directory()
    writeFileSync(path.join(corrupt, PROPOSAL_FILE), '{ not json')
    writeFileSync(path.join(corrupt, DIFF_FILE), DIFF)

    assert.deepEqual(readRemediationArtifact(corrupt), { kind: 'missing' })
  })
})
