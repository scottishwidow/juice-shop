/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The remediation agent's structured report, read back from the TaskFlow run's own
// manifest.json (see lib/scripts/securityTriage/remediate.ts). The proposed code change is
// not in here: it is the diff the agent left in the mounted checkout. This is only what the
// agent says it did and what it says it checked, and the check results are its own claims -
// nothing in the workflow re-runs them, so they are published as reported, attributed to the
// agent, and never as verified results (issue #31; docs/adr/0010).

const CHECK_RESULTS = ['passed', 'failed', 'not-run'] as const

export type RemediationCheckResult = typeof CHECK_RESULTS[number]

export interface RemediationCheck {
  name: string
  command: string
  result: RemediationCheckResult
  detail: string
}

export interface RemediationProposal {
  summary: string
  checks: RemediationCheck[]
}

export type RemediationProposalFailureReason = 'no-output' | 'malformed-output' | 'invalid-check-result'

export type RemediationProposalResult =
  | { ok: true, proposal: RemediationProposal }
  | { ok: false, reason: RemediationProposalFailureReason }

const FAILURE_DESCRIPTIONS: Record<RemediationProposalFailureReason, string> = {
  'no-output': 'The TaskFlow run did not produce a captured result for the fix task (no ' +
    'manifest.json, or no `fix` entry in its outputs).',
  'malformed-output': 'The TaskFlow run produced a result that does not match the declared ' +
    'output shape (missing or wrong-typed `summary`/`checks`).',
  'invalid-check-result': 'The TaskFlow run reported a check result outside the supported ' +
    'set (passed, failed, not-run).'
}

export function describeRemediationProposalFailure (reason: RemediationProposalFailureReason): string {
  return FAILURE_DESCRIPTIONS[reason]
}

function isValidCheckResult (value: unknown): value is RemediationCheckResult {
  return typeof value === 'string' && (CHECK_RESULTS as readonly string[]).includes(value)
}

function parseCheck (value: unknown): RemediationCheck | RemediationProposalFailureReason {
  if (typeof value !== 'object' || value === null) {
    return 'malformed-output'
  }
  const candidate = value as Record<string, unknown>
  if (typeof candidate.name !== 'string' || candidate.name.length === 0) {
    return 'malformed-output'
  }
  if (typeof candidate.command !== 'string' || typeof candidate.detail !== 'string') {
    return 'malformed-output'
  }
  if (!isValidCheckResult(candidate.result)) {
    return 'invalid-check-result'
  }
  return { name: candidate.name, command: candidate.command, result: candidate.result, detail: candidate.detail }
}

export function parseRemediationProposal (raw: unknown): RemediationProposalResult {
  if (raw === undefined || raw === null) {
    return { ok: false, reason: 'no-output' }
  }
  if (typeof raw !== 'object') {
    return { ok: false, reason: 'malformed-output' }
  }

  const candidate = raw as Record<string, unknown>
  if (typeof candidate.summary !== 'string' || candidate.summary.length === 0) {
    return { ok: false, reason: 'malformed-output' }
  }
  if (!Array.isArray(candidate.checks)) {
    return { ok: false, reason: 'malformed-output' }
  }

  const checks: RemediationCheck[] = []
  for (const entry of candidate.checks) {
    const parsed = parseCheck(entry)
    if (typeof parsed === 'string') {
      return { ok: false, reason: parsed }
    }
    checks.push(parsed)
  }

  return { ok: true, proposal: { summary: candidate.summary, checks } }
}
