/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { parseProposedPatch } from '../../lib/proposedPatch'

function response (block: unknown): unknown {
  return { content: [{ type: 'text', text: 'here you go' }, block] }
}

void describe('parseProposedPatch', () => {
  void it('accepts a well-formed propose_patch call', () => {
    const result = parseProposedPatch(response({
      type: 'tool_use',
      name: 'propose_patch',
      input: { diff: 'diff --git a/x b/x', summary: 'Checks the resolved prefix.' }
    }))

    assert.deepEqual(result, { valid: true, patch: { diff: 'diff --git a/x b/x', summary: 'Checks the resolved prefix.' } })
  })

  void it('refuses a response with no tool call', () => {
    assert.deepEqual(parseProposedPatch({ content: [{ type: 'text', text: 'I refuse.' }] }), { valid: false, reason: 'no-tool-call' })
  })

  void it('refuses a response that is not a Messages API body', () => {
    assert.deepEqual(parseProposedPatch(null), { valid: false, reason: 'no-tool-call' })
    assert.deepEqual(parseProposedPatch({ content: 'nope' }), { valid: false, reason: 'no-tool-call' })
  })

  void it('refuses a call to a tool other than propose_patch', () => {
    const result = parseProposedPatch(response({ type: 'tool_use', name: 'write_file', input: { diff: '', summary: '' } }))

    assert.deepEqual(result, { valid: false, reason: 'unexpected-tool' })
  })

  void it('refuses fields that are not strings', () => {
    const result = parseProposedPatch(response({ type: 'tool_use', name: 'propose_patch', input: { diff: { path: '/etc/passwd' }, summary: 'x' } }))

    assert.deepEqual(result, { valid: false, reason: 'malformed-fields' })
  })

  void it('refuses a missing input object', () => {
    assert.deepEqual(parseProposedPatch(response({ type: 'tool_use', name: 'propose_patch' })), { valid: false, reason: 'malformed-fields' })
  })

  void it('refuses an oversized diff', () => {
    const result = parseProposedPatch(response({
      type: 'tool_use',
      name: 'propose_patch',
      input: { diff: 'x'.repeat(200 * 1024 + 1), summary: 'x' }
    }))

    assert.deepEqual(result, { valid: false, reason: 'oversized-field' })
  })
})
