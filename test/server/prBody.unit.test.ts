/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { buildPrBody, buildPrTitle } from '../../lib/prBody'
import type { PrMetadata } from '../../lib/prCompliance'

function metadata (overrides: Partial<PrMetadata> = {}): PrMetadata {
  return {
    alertNumber: 6,
    ruleId: 'js/path-injection',
    targetPath: 'routes/keyServer.ts',
    baseCommit: '5bc7ce9292a2237e64771a8b2b71b3df730d0800',
    issueNumber: 9,
    destination: { repo: 'scottishwidow/juice-shop', base: 'master' },
    aiDisclosure: { models: ['claude-sonnet-5'], instructionsKnown: true },
    validation: [
      { name: 'typecheck', command: 'npx tsc --noEmit', passed: true },
      { name: 'regression', command: 'node --test ...', passed: false }
    ],
    ...overrides
  }
}

void describe('buildPrTitle', () => {
  void it('names the alert, rule and target path', () => {
    const title = buildPrTitle(metadata())

    assert.match(title, /js\/path-injection/)
    assert.match(title, /routes\/keyServer\.ts/)
    assert.match(title, /#6/)
  })
})

void describe('buildPrBody', () => {
  void it('names the alert, rule, target path, base commit, and originating issue', () => {
    const body = buildPrBody(metadata(), true)

    assert.match(body, /alert #6/)
    assert.match(body, /js\/path-injection/)
    assert.match(body, /routes\/keyServer\.ts/)
    assert.match(body, /5bc7ce9292a2237e64771a8b2b71b3df730d0800/)
    assert.match(body, /Closes #9/)
  })

  void it('reports validation results exactly as given, never claiming a failed check passed', () => {
    const body = buildPrBody(metadata(), false)

    assert.match(body, /npx tsc --noEmit/)
    assert.match(body, /node --test \.\.\./)
    assert.match(body, /FAILED/)
  })

  void it('discloses the AI-generated content and names the known model', () => {
    const body = buildPrBody(metadata(), true)

    assert.match(body, /AI-generated content/)
    assert.match(body, /claude-sonnet-5/)
  })

  void it('marks the AI disclosure unknown rather than guessing when models are unknown', () => {
    const body = buildPrBody(metadata({ aiDisclosure: { models: 'unknown', instructionsKnown: false } }), true)

    assert.match(body, /Models and versions: unknown/)
    assert.match(body, /Key prompts or instructions: unknown/)
  })

  void it('checks the affirmation box only when told the requirements were met', () => {
    const checked = buildPrBody(metadata(), true)
    const unchecked = buildPrBody(metadata(), false)

    assert.match(checked, /- \[x] My code follows/)
    assert.match(unchecked, /- \[ ] My code follows/)
  })
})
