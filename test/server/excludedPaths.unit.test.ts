/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { describeExcludedPaths, findExcludedPaths } from '../../lib/excludedPaths'

void describe('remediation path exclusions', () => {
  void it('allows ordinary source and test edits, including an intentionally vulnerable route', () => {
    const excluded = findExcludedPaths([
      'routes/keyServer.ts',
      'routes/fileServer.ts',
      'test/server/keyServer.unit.test.ts',
      'test/api/file-serving.test.ts',
      'frontend/src/app/app.component.ts',
      'package.json'
    ])

    assert.deepEqual(excluded, [])
  })

  void it('rejects a change to the workflow that runs the remediation', () => {
    const excluded = findExcludedPaths(['.github/workflows/security-triage.yml'])

    assert.deepEqual(excluded, [{ path: '.github/workflows/security-triage.yml', category: 'workflow' }])
  })

  void it('rejects credential and key material wherever it sits', () => {
    const excluded = findExcludedPaths([
      'encryptionkeys/jwt.pub',
      '.env',
      '.env.production',
      'config/server.key',
      'nested/dir/cert.pem'
    ])

    assert.deepEqual(excluded.map(entry => entry.category), Array(5).fill('credential'))
  })

  void it("rejects a change to the workflow's own authorization policy and publishing code", () => {
    const excluded = findExcludedPaths([
      'security_triage_taskflow/personalities/remediation_engineer.yaml',
      'lib/scripts/securityTriage/publish.ts',
      'lib/excludedPaths.ts',
      'lib/trustedVerdict.ts'
    ])

    assert.deepEqual(excluded.map(entry => entry.category), Array(4).fill('authorization-policy'))
  })

  void it('reports every excluded path in a change that also touches allowed files', () => {
    const excluded = findExcludedPaths(['routes/keyServer.ts', '.github/workflows/ci.yml', 'lib/utils.ts'])

    assert.deepEqual(excluded, [{ path: '.github/workflows/ci.yml', category: 'workflow' }])
    assert.match(describeExcludedPaths(excluded), /`\.github\/workflows\/ci\.yml` \(workflow and CI definitions\)/)
  })

  void it('does not exclude a path that merely starts with an excluded name', () => {
    assert.deepEqual(findExcludedPaths(['.githubinfo.md', 'encryptionkeys.md', 'libs/keyed.ts']), [])
  })
})
