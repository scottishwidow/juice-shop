/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { authorizePatch, type AuthorizationResult, type BaseRefReader, type RefusalReason } from './authorizePatch'

export type ComplianceRefusalReason = 'compliance-policy-unavailable'
export type GateRefusalReason = RefusalReason | ComplianceRefusalReason
export type GateDecision = AuthorizationResult | { allowed: false, reason: ComplianceRefusalReason }

// The trusted policy the gate must be able to read before it decides anything (issue #8's
// PR compliance follow-up to issue #2). This is a precondition, not part of #9's full
// compliance check: it only proves the base ref carries the policy the gate will need.
const REQUIRED_POLICY_PATHS = [
  'CONTRIBUTING.md',
  '.github/PULL_REQUEST_TEMPLATE.md',
  'docs/agents/issue-tracker.md'
]

function policyIsReadable (readBaseRef: BaseRefReader): boolean {
  return REQUIRED_POLICY_PATHS.every(path => readBaseRef(path) !== undefined)
}

/**
 * The gate's single authorization entry point. The workflow calls only this function and
 * performs no authorization logic of its own (issue #8). It refuses explicitly when the
 * trusted contribution policy cannot be read from the base ref, rather than silently
 * proceeding against the patched tree; otherwise it delegates entirely to `authorizePatch`.
 */
export function decidePatchGate (targetPath: string, diff: string, readBaseRef: BaseRefReader): GateDecision {
  if (!policyIsReadable(readBaseRef)) {
    return { allowed: false, reason: 'compliance-policy-unavailable' }
  }
  return authorizePatch(targetPath, diff, readBaseRef)
}

const REFUSAL_DESCRIPTIONS: Record<GateRefusalReason, string> = {
  'path-not-allowed': 'The diff touches a path outside the allow-list computed for this alert.',
  'snippet-coupled': 'The target file carries snippet coupling (a `vuln-code-snippet` marker) and is denied by default.',
  'solve-coupled': 'The target file carries solve coupling (a `challengeUtils.solve` call) and is denied by default.',
  'lint-suppression-added': 'The diff adds an `eslint-disable` suppression, which is refused independent of the allow-list.',
  'type-suppression-added': 'The diff adds a `@ts-ignore` or `@ts-expect-error` suppression, which is refused independent of the allow-list.',
  'override-file-modified': 'The diff touches the allow-list override file itself, which is never inside any allow-list.',
  'compliance-policy-unavailable': 'The trusted contribution policy (CONTRIBUTING.md, the PR template, or the issue-tracker doc) could not be read from the base ref.'
}

/** A one-sentence, maintainer-facing explanation of a refusal reason, for the issue comment. */
export function describeGateRefusal (reason: GateRefusalReason): string {
  return REFUSAL_DESCRIPTIONS[reason]
}

// Retry-with-feedback must exist and be disabled (issue #8): a second attempt that succeeds
// would conceal that the first was refused. This flag is the single point that would need to
// change to wire a retry, and nothing in the gate script reads it.
export const RETRY_WITH_FEEDBACK_ENABLED = false

export interface RetryFeedback {
  reason: GateRefusalReason
  message: string
}

/**
 * Composes the feedback a second patch-author attempt would receive after a refusal.
 * Implemented so the mechanism is testable, but never invoked by the gate script: refusal is
 * terminal, and only a human removing `sec:nopatch` after reading the reason starts remediation
 * again.
 */
export function buildRetryFeedback (targetPath: string, decision: { allowed: false, reason: GateRefusalReason }): RetryFeedback {
  return {
    reason: decision.reason,
    message: `The previous proposal for ${targetPath} was refused: ${describeGateRefusal(decision.reason)}`
  }
}
