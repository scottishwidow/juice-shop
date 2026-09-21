/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { selectTrustedVerdict, type IssueComment } from '../../lib/trustedVerdict'

const BASE_COMMIT = '5bc7ce9292a2237e64771a8b2b71b3df730d0800'
const OTHER_COMMIT = '0000000000000000000000000000000000000000'
const EXPECTED = { alertNumber: 6, baseCommit: BASE_COMMIT }

function verdictBody (overrides: Partial<Record<'alert' | 'base' | 'path', string>> = {}): string {
  const fields = { alert: '6', base: BASE_COMMIT, path: 'routes/keyServer.ts', ...overrides }
  return [
    '**Verdict: exploitable**',
    '',
    `- Alert: #${fields.alert}`,
    `- Base: \`${fields.base}\``,
    '- Rule: `js/path-injection`',
    `- Path: \`${fields.path}\``,
    '- Snippet coupling: no',
    '- Solve coupling: no',
    '- Test code: no'
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
    const selection = selectTrustedVerdict([fromTriage(verdictBody({ alert: '7' }))], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'alert-number-mismatch' })
  })

  void it('refuses a trusted verdict decided against a different base commit', () => {
    const selection = selectTrustedVerdict([fromTriage(verdictBody({ base: OTHER_COMMIT }))], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'base-commit-mismatch' })
  })

  void it('refuses when no verdict comment is present at all', () => {
    const selection = selectTrustedVerdict([fromTriage('Looks fine to me.')], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'no-verdict-comment' })
  })

  void it('refuses a trusted comment that is not in the structured format', () => {
    const selection = selectTrustedVerdict([fromTriage('**Verdict: exploitable** and nothing else')], EXPECTED)

    assert.deepEqual(selection, { selected: false, reason: 'malformed-verdict-comment' })
  })
})
