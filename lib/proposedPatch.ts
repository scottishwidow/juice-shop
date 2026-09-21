/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export const PROPOSE_PATCH_TOOL_NAME = 'propose_patch'

const MAX_DIFF_BYTES = 200 * 1024
const MAX_SUMMARY_BYTES = 20 * 1024

export interface ProposedPatch {
  diff: string
  summary: string
}

export type ProposalRefusalReason =
  | 'no-tool-call'
  | 'unexpected-tool'
  | 'malformed-fields'
  | 'oversized-field'

export type ProposedPatchResult =
  | { valid: true, patch: ProposedPatch }
  | { valid: false, reason: ProposalRefusalReason }

const REFUSAL_DESCRIPTIONS: Record<ProposalRefusalReason, string> = {
  'no-tool-call': `The model response contained no ${PROPOSE_PATCH_TOOL_NAME} tool call.`,
  'unexpected-tool': `The model response called a tool other than ${PROPOSE_PATCH_TOOL_NAME}.`,
  'malformed-fields': 'The proposal did not carry a string `diff` and a string `summary`.',
  'oversized-field': 'The proposed diff or summary exceeded the size the job will write to an artifact.'
}

/** A one-sentence explanation of why a model response was not accepted as a proposal. */
export function describeProposalRefusal (reason: ProposalRefusalReason): string {
  return REFUSAL_DESCRIPTIONS[reason]
}

/**
 * Validates a Messages API response before any part of it is written to the artifact the
 * gate later reads. The response is model output and therefore untrusted: its shape, the
 * tool it calls, the types of its fields and their size are all checked here, rather than
 * assumed by the caller (issue #7 security follow-up, ADR-0005). A valid proposal is still
 * only a proposal; the gate decides whether it may become a pull request.
 */
export function parseProposedPatch (responseBody: unknown): ProposedPatchResult {
  const content = (responseBody as { content?: unknown } | null)?.content
  if (!Array.isArray(content)) {
    return { valid: false, reason: 'no-tool-call' }
  }

  const toolUse = content.find(block => (block as { type?: unknown })?.type === 'tool_use') as
    { name?: unknown, input?: unknown } | undefined
  if (toolUse === undefined) {
    return { valid: false, reason: 'no-tool-call' }
  }
  if (toolUse.name !== PROPOSE_PATCH_TOOL_NAME) {
    return { valid: false, reason: 'unexpected-tool' }
  }

  const input = toolUse.input as { diff?: unknown, summary?: unknown } | null
  if (typeof input?.diff !== 'string' || typeof input.summary !== 'string') {
    return { valid: false, reason: 'malformed-fields' }
  }
  if (Buffer.byteLength(input.diff, 'utf8') > MAX_DIFF_BYTES ||
      Buffer.byteLength(input.summary, 'utf8') > MAX_SUMMARY_BYTES) {
    return { valid: false, reason: 'oversized-field' }
  }

  return { valid: true, patch: { diff: input.diff, summary: input.summary } }
}
