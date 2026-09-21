/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { parseAlertNumber } from '../../lib/parseAlertNumber'

void describe('parseAlertNumber', () => {
  void it('reads the number out of "CodeQL alert #6"', () => {
    assert.equal(parseAlertNumber('CodeQL alert #6, `js/path-injection`, `routes/keyServer.ts:14`'), 6)
  })

  void it('is case-insensitive and tolerates a colon before the number', () => {
    assert.equal(parseAlertNumber('Alert: #42\n\nDetails follow.'), 42)
  })

  void it('reads the number when it is not on the first line', () => {
    assert.equal(parseAlertNumber('## Finding\n\nSee CodeQL alert #123 for detail.'), 123)
  })

  void it('returns undefined when no alert reference is present', () => {
    assert.equal(parseAlertNumber('This issue has no alert reference at all.'), undefined)
  })

  void it('returns undefined for an empty body', () => {
    assert.equal(parseAlertNumber(''), undefined)
  })

  void it('does not match a bare issue reference such as "#6" without the word alert', () => {
    assert.equal(parseAlertNumber('Follow-up to #6.'), undefined)
  })
})
