/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { parseAlertUrl } from '../lib/parseAlertUrl'

const REPO = 'scottishwidow/juice-shop'
const ALERT_URL = `https://github.com/${REPO}/security/code-scanning/6`

void describe('parseAlertUrl', () => {
  void it('reads the alert number out of a same-repository code-scanning alert URL', () => {
    const result = parseAlertUrl(`Please triage this finding: ${ALERT_URL}`, REPO)

    assert.deepEqual(result, { ok: true, alert: { owner: 'scottishwidow', repo: 'juice-shop', alertNumber: 6 } })
  })

  void it('accepts the same URL pasted twice as one reference, not ambiguous', () => {
    const result = parseAlertUrl(`${ALERT_URL}\n\nSame link again: ${ALERT_URL}`, REPO)

    assert.equal(result.ok, true)
  })

  void it('returns "missing" when the issue body has no alert URL', () => {
    const result = parseAlertUrl('This issue has no alert reference at all.', REPO)

    assert.deepEqual(result, { ok: false, reason: 'missing' })
  })

  void it('returns "missing" for an empty body', () => {
    assert.deepEqual(parseAlertUrl('', REPO), { ok: false, reason: 'missing' })
  })

  void it('returns "ambiguous" when two different alerts are referenced', () => {
    const other = `https://github.com/${REPO}/security/code-scanning/7`

    const result = parseAlertUrl(`${ALERT_URL}\n${other}`, REPO)

    assert.deepEqual(result, { ok: false, reason: 'ambiguous' })
  })

  void it('returns "unsupported" for a secret-scanning alert URL', () => {
    const url = `https://github.com/${REPO}/security/secret-scanning/3`

    const result = parseAlertUrl(url, REPO)

    assert.deepEqual(result, { ok: false, reason: 'unsupported' })
  })

  void it('returns "unsupported" for a dependabot alert URL', () => {
    const url = `https://github.com/${REPO}/security/dependabot/3`

    const result = parseAlertUrl(url, REPO)

    assert.deepEqual(result, { ok: false, reason: 'unsupported' })
  })

  void it('returns "cross-repository" for a code-scanning alert URL naming a different repo', () => {
    const url = 'https://github.com/some-other-org/other-repo/security/code-scanning/6'

    const result = parseAlertUrl(url, REPO)

    assert.deepEqual(result, { ok: false, reason: 'cross-repository' })
  })

  void it('does not match a bare issue reference such as "#6" without a URL', () => {
    const result = parseAlertUrl('Follow-up to #6.', REPO)

    assert.deepEqual(result, { ok: false, reason: 'missing' })
  })

  void it('does not match an alert URL embedded in another URL', () => {
    const result = parseAlertUrl(`https://attacker.example/redirect/${ALERT_URL}`, REPO)

    assert.deepEqual(result, { ok: false, reason: 'missing' })
  })

  void it('does not match an alert URL on a lookalike host', () => {
    const result = parseAlertUrl(`https://github.com.attacker.example/${REPO}/security/code-scanning/6`, REPO)

    assert.deepEqual(result, { ok: false, reason: 'missing' })
  })
})
