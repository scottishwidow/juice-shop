/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { determineVerdict, type BaseRefReader } from '../../lib/triageVerdict'

function readerWithFiles (files: Record<string, string>): BaseRefReader {
  return (path: string) => files[path]
}

void describe('determineVerdict', () => {
  const targetPath = 'routes/keyServer.ts'

  void it('reports an uncoupled handler as exploitable', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = determineVerdict(targetPath, reader)

    assert.deepEqual(result, {
      verdict: 'exploitable',
      coupling: { snippetCoupled: false, solveCoupled: false },
      isTestCode: false
    })
  })

  void it('reports a snippet-coupled handler as coupled-needs-decision', () => {
    const reader = readerWithFiles({
      [targetPath]: '// vuln-code-snippet start someChallenge\ncode\n// vuln-code-snippet end someChallenge'
    })

    const result = determineVerdict(targetPath, reader)

    assert.equal(result.verdict, 'coupled-needs-decision')
    assert.deepEqual(result.coupling, { snippetCoupled: true, solveCoupled: false })
  })

  void it('reports a solve-coupled handler as coupled-needs-decision', () => {
    const reader = readerWithFiles({ [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = determineVerdict(targetPath, reader)

    assert.equal(result.verdict, 'coupled-needs-decision')
    assert.deepEqual(result.coupling, { snippetCoupled: false, solveCoupled: true })
  })

  void it('reports both coupling mechanisms independently when both are present', () => {
    const reader = readerWithFiles({
      [targetPath]: '// vuln-code-snippet start someChallenge\nchallengeUtils.solve(challenges.someChallenge)\n// vuln-code-snippet end someChallenge'
    })

    const result = determineVerdict(targetPath, reader)

    assert.equal(result.verdict, 'coupled-needs-decision')
    assert.deepEqual(result.coupling, { snippetCoupled: true, solveCoupled: true })
  })

  void it('reports a finding inside test code as not-applicable regardless of coupling', () => {
    const testPath = 'test/server/keyServer.unit.test.ts'
    const reader = readerWithFiles({ [testPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = determineVerdict(testPath, reader)

    assert.equal(result.verdict, 'not-applicable')
    assert.equal(result.isTestCode, true)
  })

  void it('reports a finding inside a cypress test as not-applicable', () => {
    const testPath = 'cypress/e2e/someSpec.ts'
    const reader = readerWithFiles({ [testPath]: 'code' })

    const result = determineVerdict(testPath, reader)

    assert.equal(result.verdict, 'not-applicable')
  })

  void it('treats an absent base-ref file exactly as an empty one', () => {
    const reader = readerWithFiles({})

    const result = determineVerdict(targetPath, reader)

    assert.deepEqual(result, {
      verdict: 'exploitable',
      coupling: { snippetCoupled: false, solveCoupled: false },
      isTestCode: false
    })
  })
})
