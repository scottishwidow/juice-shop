/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The verdict comment carries two independent things: the maintainer-facing prose a human
// reads and decides from, and this structured payload the workflow reads. They are not the
// same representation of the same data - the payload is a fenced JSON block inside an HTML
// comment, invisible when the comment renders, so a maintainer editing the prose for
// readability cannot touch it and reformatting the prose never breaks the handoff (issue #19).

export interface VerdictPayload {
  alertNumber: number
  baseCommit: string
  ruleId: string
  path: string
  verdict: string
  snippetCoupled: boolean
  solveCoupled: boolean
  isTestCode: boolean
}

const PAYLOAD_BLOCK = /<!-- security-triage:verdict-payload\n([\s\S]*?)\n-->/

/** Marks a comment as carrying a verdict payload, for the initial candidate filter. */
export const VERDICT_PAYLOAD_MARKER = '<!-- security-triage:verdict-payload'

function isValidPayload (value: unknown): value is VerdictPayload {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  return typeof candidate.alertNumber === 'number' &&
    typeof candidate.baseCommit === 'string' && /^[0-9a-f]{40}$/.test(candidate.baseCommit) &&
    typeof candidate.ruleId === 'string' &&
    typeof candidate.path === 'string' &&
    typeof candidate.verdict === 'string' &&
    typeof candidate.snippetCoupled === 'boolean' &&
    typeof candidate.solveCoupled === 'boolean' &&
    typeof candidate.isTestCode === 'boolean'
}

/** Renders the structured payload as an HTML comment, to be appended to the verdict comment. */
export function encodeVerdictPayload (payload: VerdictPayload): string {
  return `${VERDICT_PAYLOAD_MARKER}\n${JSON.stringify(payload, null, 2)}\n-->`
}

/**
 * Reads the structured payload back out of a verdict comment. Independent of the prose
 * wording and layout above it: only the fenced block matters, so a maintainer reformatting
 * the paragraph, or GitHub normalising whitespace, cannot break the handoff.
 */
export function decodeVerdictPayload (commentBody: string): VerdictPayload | undefined {
  const match = PAYLOAD_BLOCK.exec(commentBody)
  if (match === undefined || match === null) {
    return undefined
  }
  try {
    const parsed: unknown = JSON.parse(match[1])
    return isValidPayload(parsed) ? parsed : undefined
  } catch {
    return undefined
  }
}
