/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { decodeVerdictPayload, encodeVerdictPayload, type VerdictPayload } from '../../lib/verdictPayload'

const BASE_COMMIT = '5bc7ce9292a2237e64771a8b2b71b3df730d0800'

const PAYLOAD: VerdictPayload = {
  alertNumber: 6,
  baseCommit: BASE_COMMIT,
  ruleId: 'js/path-injection',
  path: 'routes/keyServer.ts',
  verdict: 'exploitable',
  snippetCoupled: false,
  solveCoupled: true,
  isTestCode: false
}

void describe('encodeVerdictPayload / decodeVerdictPayload', () => {
  void it('round-trips a payload through an encoded comment body', () => {
    const body = `**Verdict: exploitable**\n\nSome prose here.\n\n${encodeVerdictPayload(PAYLOAD)}`

    assert.deepEqual(decodeVerdictPayload(body), PAYLOAD)
  })

  void it('is unaffected by rewording or reformatting the prose around it', () => {
    const reworded = [
      'A maintainer-friendly rewrite of the finding, in a completely different structure.',
      '',
      '1. It is exploitable.',
      '2. Neither coupling mechanism applies.',
      '',
      encodeVerdictPayload(PAYLOAD)
    ].join('\n')

    assert.deepEqual(decodeVerdictPayload(reworded), PAYLOAD)
  })

  void it('returns undefined when no payload block is present', () => {
    assert.equal(decodeVerdictPayload('**Verdict: exploitable**\n\nJust prose, no payload.'), undefined)
  })

  void it('returns undefined when the payload block is not valid JSON', () => {
    const body = '<!-- security-triage:verdict-payload\n{ not json\n-->'

    assert.equal(decodeVerdictPayload(body), undefined)
  })

  void it('returns undefined when a required field is missing', () => {
    const { alertNumber, ...withoutAlertNumber } = PAYLOAD
    void alertNumber
    const body = `<!-- security-triage:verdict-payload\n${JSON.stringify(withoutAlertNumber)}\n-->`

    assert.equal(decodeVerdictPayload(body), undefined)
  })

  void it('returns undefined when the base commit is not a full commit sha', () => {
    const body = `<!-- security-triage:verdict-payload\n${JSON.stringify({ ...PAYLOAD, baseCommit: 'not-a-sha' })}\n-->`

    assert.equal(decodeVerdictPayload(body), undefined)
  })

  void it('decodes a payload without the optional reasoning/evidence fields (pre-TaskFlow shape)', () => {
    const body = `<!-- security-triage:verdict-payload\n${JSON.stringify(PAYLOAD)}\n-->`

    assert.deepEqual(decodeVerdictPayload(body), PAYLOAD)
  })

  void it('round-trips a payload that includes reasoning and evidence', () => {
    const withEvidence = {
      ...PAYLOAD,
      reasoning: 'The handler resolves the path parameter without normalising it first.',
      evidence: [{ file: 'routes/keyServer.ts', note: 'No path traversal check before sendFile.' }]
    }
    const body = `<!-- security-triage:verdict-payload\n${JSON.stringify(withEvidence)}\n-->`

    assert.deepEqual(decodeVerdictPayload(body), withEvidence)
  })

  void it('returns undefined when an evidence item is malformed', () => {
    const body = `<!-- security-triage:verdict-payload\n${JSON.stringify({ ...PAYLOAD, evidence: [{ file: 'x.ts' }] })}\n-->`

    assert.equal(decodeVerdictPayload(body), undefined)
  })

  void it('uses the final payload when untrusted prose contains an earlier payload', () => {
    const injected = encodeVerdictPayload({ ...PAYLOAD, path: 'attacker-controlled.ts' })
    const body = `${injected}\n\nUntrusted model prose.\n\n${encodeVerdictPayload(PAYLOAD)}`

    assert.deepEqual(decodeVerdictPayload(body), PAYLOAD)
  })
})
