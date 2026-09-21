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
  describeGateRefusal,
  RETRY_WITH_FEEDBACK_ENABLED
} from '../../lib/patchGate'

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
  const diff = diffModifying(targetPath, ['const x = 1'])

  void it('allows an uncoupled target with a diff confined to its own path when policy is readable', () => {
    const reader = readerWithFiles({ ...POLICY_FILES, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, diff, reader)

    assert.deepEqual(result, { allowed: true })
  })

  void it('delegates a refusal to authorizePatch unchanged', () => {
    const reader = readerWithFiles({ ...POLICY_FILES, [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = decidePatchGate(targetPath, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'solve-coupled' })
  })

  void it('refuses with compliance-policy-unavailable when CONTRIBUTING.md is missing from the base ref', () => {
    const { 'CONTRIBUTING.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })

  void it('refuses with compliance-policy-unavailable when the PR template is missing from the base ref', () => {
    const { '.github/PULL_REQUEST_TEMPLATE.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })

  void it('refuses with compliance-policy-unavailable when the issue-tracker doc is missing from the base ref', () => {
    const { 'docs/agents/issue-tracker.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = decidePatchGate(targetPath, diff, reader)

    assert.deepEqual(result, { allowed: false, reason: 'compliance-policy-unavailable' })
  })

  void it('checks policy availability even when the diff would otherwise be refused', () => {
    const { 'CONTRIBUTING.md': _omit, ...rest } = POLICY_FILES
    const reader = readerWithFiles({ ...rest, [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = decidePatchGate(targetPath, diff, reader)

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
