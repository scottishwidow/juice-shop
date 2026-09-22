/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { parseTaskflowVerdict } from '../../lib/taskflowVerdict'

const VALID = {
  verdict: 'confirmed',
  reasoning: 'The handler resolves the path parameter without normalising it first.',
  evidence: [{ file: 'routes/keyServer.ts', note: 'No path traversal check before sendFile.' }]
}

void describe('parseTaskflowVerdict', () => {
  void it('accepts a well-formed verdict', () => {
    const result = parseTaskflowVerdict(VALID)

    assert.deepEqual(result, { ok: true, verdict: VALID })
  })

  void it('accepts each supported verdict value', () => {
    for (const verdict of ['confirmed', 'not-applicable', 'inconclusive']) {
      const result = parseTaskflowVerdict({ ...VALID, verdict })
      assert.equal(result.ok, true)
    }
  })

  void it('rejects an empty evidence array', () => {
    const result = parseTaskflowVerdict({ ...VALID, evidence: [] })

    assert.deepEqual(result, { ok: false, reason: 'malformed-output' })
  })

  void it('returns "no-output" for undefined', () => {
    assert.deepEqual(parseTaskflowVerdict(undefined), { ok: false, reason: 'no-output' })
  })

  void it('returns "no-output" for null', () => {
    assert.deepEqual(parseTaskflowVerdict(null), { ok: false, reason: 'no-output' })
  })

  void it('returns "malformed-output" for a non-object value', () => {
    assert.deepEqual(parseTaskflowVerdict('confirmed'), { ok: false, reason: 'malformed-output' })
  })

  void it('returns "malformed-output" when reasoning is missing', () => {
    const { reasoning, ...withoutReasoning } = VALID
    void reasoning

    assert.deepEqual(parseTaskflowVerdict(withoutReasoning), { ok: false, reason: 'malformed-output' })
  })

  void it('returns "malformed-output" when reasoning is an empty string', () => {
    const result = parseTaskflowVerdict({ ...VALID, reasoning: '' })

    assert.deepEqual(result, { ok: false, reason: 'malformed-output' })
  })

  void it('returns "malformed-output" when evidence is not an array', () => {
    const result = parseTaskflowVerdict({ ...VALID, evidence: 'not an array' })

    assert.deepEqual(result, { ok: false, reason: 'malformed-output' })
  })

  void it('returns "malformed-output" when an evidence item is missing a field', () => {
    const result = parseTaskflowVerdict({ ...VALID, evidence: [{ file: 'routes/keyServer.ts' }] })

    assert.deepEqual(result, { ok: false, reason: 'malformed-output' })
  })

  void it('returns "invalid-verdict" for a verdict value outside the supported set', () => {
    const result = parseTaskflowVerdict({ ...VALID, verdict: 'exploitable' })

    assert.deepEqual(result, { ok: false, reason: 'invalid-verdict' })
  })
})
