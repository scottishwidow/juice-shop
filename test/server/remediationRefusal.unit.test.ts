/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, it } from 'node:test'

import {
  describeRemediationRefusal,
  readRemediationRefusal,
  writeRemediationRefusal,
  type RemediationRefusalReason
} from '../../lib/remediationRefusal'

const ALL_REASONS: RemediationRefusalReason[] = [
  'no-alert-reference',
  'no-verdict-comment',
  'untrusted-verdict-author',
  'malformed-verdict-comment',
  'alert-number-mismatch',
  'base-commit-mismatch',
  'test-code-not-applicable',
  'target-unreadable',
  'required-policy-unreadable',
  'no-tool-call',
  'unexpected-tool',
  'malformed-fields',
  'oversized-field',
  'unexpected-error'
]

void describe('remediation refusal', () => {
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'remediation-refusal-'))
  })

  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  void it('describes every reason distinguishably', () => {
    const descriptions = ALL_REASONS.map(describeRemediationRefusal)
    assert.equal(new Set(descriptions).size, descriptions.length)
    for (const description of descriptions) {
      assert.ok(description.length > 0)
    }
  })

  void it('tells the maintainer to re-run triage on a base-commit mismatch', () => {
    assert.match(describeRemediationRefusal('base-commit-mismatch'), /re-run triage/)
  })

  for (const reason of ALL_REASONS) {
    void it(`round-trips ${reason} through the artifact directory`, () => {
      const output = join(root, 'output')
      writeRemediationRefusal(output, reason)
      assert.deepEqual(readRemediationRefusal(output), { reason })
    })
  }

  void it('refuses an existing directory without overwriting it', () => {
    const output = join(root, 'output')
    mkdirSync(output)
    const sentinel = join(output, 'proposed.patch')
    writeFileSync(sentinel, 'keep')

    assert.throws(() => writeRemediationRefusal(output, 'unexpected-error'), { code: 'EEXIST' })
    assert.equal(readRemediationRefusal(output), undefined)
  })

  void it('refuses a symlinked output directory', () => {
    const real = join(root, 'real')
    mkdirSync(real)
    const output = join(root, 'output')
    symlinkSync(real, output)

    assert.throws(() => writeRemediationRefusal(output, 'unexpected-error'), { code: 'EEXIST' })
  })

  void it('returns undefined when no refusal file exists', () => {
    assert.equal(readRemediationRefusal(join(root, 'missing')), undefined)
  })

  void it('returns undefined for a malformed refusal file instead of echoing it', () => {
    const output = join(root, 'output')
    mkdirSync(output)
    writeFileSync(join(output, 'refusal.json'), 'not json')
    assert.equal(readRemediationRefusal(output), undefined)
  })

  void it('returns undefined for an unknown reason instead of trusting arbitrary content', () => {
    const output = join(root, 'output')
    mkdirSync(output)
    writeFileSync(join(output, 'refusal.json'), JSON.stringify({ reason: 'made-up-reason' }))
    assert.equal(readRemediationRefusal(output), undefined)
  })
})
