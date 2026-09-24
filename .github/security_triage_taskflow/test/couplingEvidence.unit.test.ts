/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { computeCouplingEvidence, type BaseRefReader } from '../lib/couplingEvidence'

function readerWithFiles (files: Record<string, string>): BaseRefReader {
  return (path: string) => files[path]
}

void describe('computeCouplingEvidence', () => {
  const targetPath = 'routes/keyServer.ts'

  void it('reports an uncoupled handler with neither marker present', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = computeCouplingEvidence(targetPath, reader)

    assert.deepEqual(result, { snippetCoupled: false, solveCoupled: false, isTestCode: false })
  })

  void it('reports snippet coupling independently of solve coupling', () => {
    const reader = readerWithFiles({
      [targetPath]: '// vuln-code-snippet start someChallenge\ncode\n// vuln-code-snippet end someChallenge'
    })

    const result = computeCouplingEvidence(targetPath, reader)

    assert.deepEqual(result, { snippetCoupled: true, solveCoupled: false, isTestCode: false })
  })

  void it('reports solve coupling independently of snippet coupling', () => {
    const reader = readerWithFiles({ [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = computeCouplingEvidence(targetPath, reader)

    assert.deepEqual(result, { snippetCoupled: false, solveCoupled: true, isTestCode: false })
  })

  void it('reports both coupling mechanisms independently when both are present', () => {
    const reader = readerWithFiles({
      [targetPath]: '// vuln-code-snippet start someChallenge\nchallengeUtils.solve(challenges.someChallenge)\n// vuln-code-snippet end someChallenge'
    })

    const result = computeCouplingEvidence(targetPath, reader)

    assert.deepEqual(result, { snippetCoupled: true, solveCoupled: true, isTestCode: false })
  })

  void it('reports a path under test/ as test code regardless of coupling', () => {
    const testPath = 'test/server/keyServer.unit.test.ts'
    const reader = readerWithFiles({ [testPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = computeCouplingEvidence(testPath, reader)

    assert.equal(result.isTestCode, true)
    assert.equal(result.solveCoupled, true)
  })

  void it('reports a path under cypress/ as test code', () => {
    const testPath = 'cypress/e2e/someSpec.ts'
    const reader = readerWithFiles({ [testPath]: 'code' })

    const result = computeCouplingEvidence(testPath, reader)

    assert.equal(result.isTestCode, true)
  })

  void it('treats an absent base-ref file exactly as an empty one', () => {
    const reader = readerWithFiles({})

    const result = computeCouplingEvidence(targetPath, reader)

    assert.deepEqual(result, { snippetCoupled: false, solveCoupled: false, isTestCode: false })
  })
})
