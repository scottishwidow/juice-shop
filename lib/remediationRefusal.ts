/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { describeProposalRefusal, type ProposalRefusalReason } from './proposedPatch'
import { describeVerdictRefusal, type VerdictRefusalReason } from './trustedVerdict'

// The patch-author job (`remediate.ts`) holds `permissions: {}` and must keep holding none
// (issue #7, ADR-0002), so it cannot post its own refusal reason to the issue. It writes the
// reason here instead, to the same credential-free artifact directory as a proposed patch,
// and the gate job - which already holds `issues: write` - reports it (issue #15).

export type RemediationRefusalReason =
  | 'no-alert-reference'
  | VerdictRefusalReason
  | 'test-code-not-applicable'
  | 'target-unreadable'
  | 'required-policy-unreadable'
  | ProposalRefusalReason
  | 'unexpected-error'

const OWN_DESCRIPTIONS: Record<
'no-alert-reference' | 'test-code-not-applicable' | 'target-unreadable' | 'required-policy-unreadable' | 'unexpected-error',
string
> = {
  'no-alert-reference': 'The issue body carries no `alert #<n>` reference, so the alert could not be identified.',
  'test-code-not-applicable': 'The triaged finding is test code (not-applicable); remediation does not apply.',
  'target-unreadable': 'The path named by the trusted verdict is not a readable tracked file at the base commit.',
  'required-policy-unreadable': "The code style rule or the patch author's compliance instructions could not be read from the base ref.",
  'unexpected-error': 'The patch author job raised an error before it produced a proposal or a categorized refusal; check the job log.'
}

const VERDICT_REFUSAL_REASONS: readonly VerdictRefusalReason[] = [
  'no-verdict-comment', 'untrusted-verdict-author', 'malformed-verdict-comment', 'alert-number-mismatch', 'base-commit-mismatch'
]

const PROPOSAL_REFUSAL_REASONS: readonly ProposalRefusalReason[] = [
  'no-tool-call', 'unexpected-tool', 'malformed-fields', 'oversized-field'
]

const REMEDIATION_REFUSAL_DESCRIPTIONS: Record<RemediationRefusalReason, string> = {
  ...OWN_DESCRIPTIONS,
  'no-verdict-comment': describeVerdictRefusal('no-verdict-comment'),
  'untrusted-verdict-author': describeVerdictRefusal('untrusted-verdict-author'),
  'malformed-verdict-comment': describeVerdictRefusal('malformed-verdict-comment'),
  'alert-number-mismatch': describeVerdictRefusal('alert-number-mismatch'),
  'base-commit-mismatch': describeVerdictRefusal('base-commit-mismatch'),
  'no-tool-call': describeProposalRefusal('no-tool-call'),
  'unexpected-tool': describeProposalRefusal('unexpected-tool'),
  'malformed-fields': describeProposalRefusal('malformed-fields'),
  'oversized-field': describeProposalRefusal('oversized-field')
}

/** A one-sentence, maintainer-facing explanation of a patch-author refusal reason. */
export function describeRemediationRefusal (reason: RemediationRefusalReason): string {
  return REMEDIATION_REFUSAL_DESCRIPTIONS[reason]
}

const KNOWN_REASONS = new Set<string>([
  'no-alert-reference', 'test-code-not-applicable', 'target-unreadable', 'required-policy-unreadable', 'unexpected-error',
  ...VERDICT_REFUSAL_REASONS,
  ...PROPOSAL_REFUSAL_REASONS
])

/** Thrown by the patch-author job for every categorized refusal; carries the reason to report. */
export class RemediationRefusal extends Error {
  readonly reason: RemediationRefusalReason

  constructor (reason: RemediationRefusalReason, message: string) {
    super(message)
    this.reason = reason
  }
}

const REFUSAL_FILE_NAME = 'refusal.json'

/**
 * Writes the refusal reason to the artifact directory the credential-free `remediate` job
 * already uploads. Mirrors `writeRemediationArtifacts`'s stance: refuses a stale directory or
 * symlink rather than writing into it (`mkdirSync` without `recursive`).
 */
export function writeRemediationRefusal (outputDir: string, reason: RemediationRefusalReason): void {
  mkdirSync(outputDir, { mode: 0o700 })
  writeFileSync(join(outputDir, REFUSAL_FILE_NAME), JSON.stringify({ reason }), { flag: 'wx', mode: 0o600 })
}

export interface RemediationRefusalRecord {
  reason: RemediationRefusalReason
}

/**
 * Reads the refusal reason back in the gate job. The file comes from a downloaded workflow
 * artifact written by the credential-free `remediate` job, not from arbitrary model output:
 * only a `reason` drawn from the closed enum above is accepted, so a malformed or tampered
 * file is treated the same as no refusal having been recorded, never echoed verbatim.
 */
export function readRemediationRefusal (outputDir: string): RemediationRefusalRecord | undefined {
  let raw: string
  try {
    raw = readFileSync(join(outputDir, REFUSAL_FILE_NAME), 'utf8')
  } catch {
    return undefined
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return undefined
  }

  const reason = (parsed as { reason?: unknown } | null)?.reason
  if (typeof reason !== 'string' || !KNOWN_REASONS.has(reason)) {
    return undefined
  }
  return { reason: reason as RemediationRefusalReason }
}
