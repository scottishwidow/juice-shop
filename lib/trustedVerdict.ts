/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { decodeVerdictPayload, VERDICT_PAYLOAD_MARKER, type VerdictPayload } from './verdictPayload'

// The only identity the `triage` job can post as: it comments through the workflow's
// `GITHUB_TOKEN`. A verdict comment from any other account is a comment an outsider could
// write, and selects nothing.
const TRIAGE_AUTHOR_LOGIN = 'github-actions[bot]'

export { VERDICT_PAYLOAD_MARKER }

export interface IssueComment {
  body?: unknown
  user?: { login?: unknown, type?: unknown } | null
}

export interface ExpectedVerdict {
  alertNumber: number
}

export type VerdictRefusalReason =
  | 'no-verdict-comment'
  | 'untrusted-verdict-author'
  | 'malformed-verdict-comment'
  | 'alert-number-mismatch'

export type VerdictSelection =
  | { selected: true, verdict: VerdictPayload }
  | { selected: false, reason: VerdictRefusalReason }

const REFUSAL_DESCRIPTIONS: Record<VerdictRefusalReason, string> = {
  'no-verdict-comment': 'No triage verdict comment was found on this issue; triage must run first.',
  'untrusted-verdict-author': `A verdict comment is present but was not posted by ${TRIAGE_AUTHOR_LOGIN}; only the triage job's own verdict selects a remediation target.`,
  'malformed-verdict-comment': 'The triage verdict comment is not in the expected structured format.',
  'alert-number-mismatch': 'The triage verdict on this issue is for a different alert than the one the issue body names.'
}

/** A one-sentence explanation of why no verdict was accepted, for the job log. */
export function describeVerdictRefusal (reason: VerdictRefusalReason): string {
  return REFUSAL_DESCRIPTIONS[reason]
}

/**
 * Selects the assessment the remediation agent works from. The job reads public issue
 * comments with no credentials, so anyone can write a comment it sees: the selection
 * therefore accepts only a comment posted by the triage job's own identity, and only one
 * bound to the alert the issue body names. That is the whole of the handoff, so it is the
 * only place trust is granted.
 *
 * The commit the verdict was decided against is deliberately not compared with the commit
 * remediation checked out: remediation always starts from current `master`, and a push
 * landing between triage and the remediation label must not force a re-triage (issue #31;
 * see docs/adr/0010-taskflow-remediation-implementation.md).
 */
export function selectTrustedVerdict (comments: IssueComment[], expected: ExpectedVerdict): VerdictSelection {
  const verdictComments = comments.filter(comment =>
    typeof comment.body === 'string' && comment.body.includes(VERDICT_PAYLOAD_MARKER))
  if (verdictComments.length === 0) {
    return { selected: false, reason: 'no-verdict-comment' }
  }

  const trusted = verdictComments.filter(comment =>
    comment.user?.login === TRIAGE_AUTHOR_LOGIN && comment.user?.type === 'Bot')
  const latest = trusted[trusted.length - 1]
  if (latest === undefined) {
    return { selected: false, reason: 'untrusted-verdict-author' }
  }

  const verdict = decodeVerdictPayload(latest.body as string)
  if (verdict === undefined) {
    return { selected: false, reason: 'malformed-verdict-comment' }
  }
  if (verdict.alertNumber !== expected.alertNumber) {
    return { selected: false, reason: 'alert-number-mismatch' }
  }

  return { selected: true, verdict }
}
