/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { allChecksPassed, formatValidationSection, type CheckResult } from '../../lib/gateChecks'

void describe('allChecksPassed', () => {
  void it('is true when every check passed', () => {
    const results: CheckResult[] = [
      { name: 'typecheck', command: 'npx tsc --noEmit', passed: true },
      { name: 'test:server', command: 'npm run test:server', passed: true }
    ]

    assert.equal(allChecksPassed(results), true)
  })

  void it('is false when any check failed', () => {
    const results: CheckResult[] = [
      { name: 'typecheck', command: 'npx tsc --noEmit', passed: true },
      { name: 'test:server', command: 'npm run test:server', passed: false }
    ]

    assert.equal(allChecksPassed(results), false)
  })

  void it('is true for an empty list', () => {
    assert.equal(allChecksPassed([]), true)
  })
})

void describe('formatValidationSection', () => {
  void it('never reports a failed check as passed', () => {
    const section = formatValidationSection([
      { name: 'typecheck', command: 'npx tsc --noEmit', passed: false }
    ])

    assert.match(section, /npx tsc --noEmit/)
    assert.match(section, /FAILED/)
    assert.doesNotMatch(section, /— passed/)
  })

  void it('reports a passed check as passed', () => {
    const section = formatValidationSection([
      { name: 'test:api', command: 'npm run test:api', passed: true }
    ])

    assert.match(section, /npm run test:api/)
    assert.match(section, /passed/)
  })
})
