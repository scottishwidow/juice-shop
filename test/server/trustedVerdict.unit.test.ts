/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { selectTrustedVerdict, type IssueComment } from '../../lib/trustedVerdict'
import { encodeVerdictPayload, type VerdictPayload } from '../../lib/verdictPayload'

const BASE_COMMIT = '5bc7ce9292a2237e64771a8b2b71b3df730d0800'
const OTHER_COMMIT = '0000000000000000000000000000000000000000'
const EXPECTED = { alertNumber: 6 }

function verdictBody (overrides: Partial<VerdictPayload> = {}): string {
  const payload: VerdictPayload = {
    alertNumber: 6,
    baseCommit: BASE_COMMIT,
    ruleId: 'js/path-injection',
    path: 'routes/keyServer.ts',
    verdict: 'exploitable',
    snippetCoupled: false,
    solveCoupled: false,
    isTestCode: false,
    ...overrides
  }
  return [
    '**Verdict: exploitable**',
    '',
    '- This prose is for a maintainer to read; the payload below is what the workflow reads.',
    '',
    encodeVerdictPayload(payload)
  ].join('\n')
}

function fromTriage (body: string): IssueComment {
  return { body, user: { login: 'github-actions[bot]', type: 'Bot' } }
}

function fromOutsider (body: string): IssueComment {
  return { body, user: { login: 'helpful-stranger', type: 'User' } }
}

void describe('selectTrustedVerdict', () => {
  void it('selects the triage job\'s verdict for the expected alert and base commit', () => {
    const selection = selectTrustedVerdict([fromTriage(verdictBody())], EXPECTED)

    assert.equal(selection.selected, true)
    assert.equal(selection.selected && selection.verdict.path, 'routes/keyServer.ts')
  })

  void it('is unaffected by reformatting the maintainer-facing prose paragraph', () => {
    const reformatted = [
      'Reworded for readability: this finding is exploitable and needs attention.',
      '',
      '  * a bullet with completely different wording and layout',
      '',
      encodeVerdictPayload({
        alertNumber: 6,
        baseCommit: BASE_COMMIT,
        ruleId: 'js/path-injection',
        path: 'routes/keyServer.ts',
        verdict: 'exploitable',
        snippetCoupled: false,
        solveCoupled: false,
        isTestCode: false
      })
    ].join('\n')

    const selection = selectTrustedVerdict([fromTriage(reformatted)], EXPECTED)

    assert.equal(selection.selected, true)
    assert.equal(selection.selected && selection.verdict.path, 'routes/keyServer.ts')
  })

  void it('refuses a verdict comment written by anyone other than the triage job', () => {
    const selection = selectTrustedVerdict([fromOutsider(verdictBody({ path: '/etc/passwd' }))], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'untrusted-verdict-author' })
  })

  void it('ignores an outsider comment posted after the triage verdict', () => {
    const selection = selectTrustedVerdict([
      fromTriage(verdictBody()),
      fromOutsider(verdictBody({ path: '../../../../tmp/secret' }))
    ], EXPECTED)

    assert.equal(selection.selected && selection.verdict.path, 'routes/keyServer.ts')
  })

  void it('refuses an account impersonating the triage job without being a bot', () => {
    const impersonator: IssueComment = { body: verdictBody(), user: { login: 'github-actions[bot]', type: 'User' } }

    assert.deepEqual(selectTrustedVerdict([impersonator], EXPECTED), { selected: false, reason: 'untrusted-verdict-author' })
  })

  void it('refuses a trusted verdict for a different alert', () => {
    const selection = selectTrustedVerdict([fromTriage(verdictBody({ alertNumber: 7 }))], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'alert-number-mismatch' })
  })

  void it('accepts a trusted verdict decided against an older base commit', () => {
    const selection = selectTrustedVerdict([fromTriage(verdictBody({ baseCommit: OTHER_COMMIT }))], EXPECTED)

    assert.equal(selection.selected, true)
  })

  void it('refuses when no verdict comment is present at all', () => {
    const selection = selectTrustedVerdict([fromTriage('Looks fine to me.')], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'no-verdict-comment' })
  })

  void it('refuses a trusted comment that is not in the structured format', () => {
    const selection = selectTrustedVerdict([
      fromTriage('**Verdict: exploitable** and nothing else, but claims a payload:\n<!-- security-triage:verdict-payload\n{"broken"\n-->')
    ], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'malformed-verdict-comment' })
  })
})
