/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { isValidEvidenceItem, type VerdictEvidenceItem } from './verdictPayload'

const VALID_VERDICTS = ['confirmed', 'not-applicable', 'inconclusive'] as const

export type TaskflowVerdictValue = typeof VALID_VERDICTS[number]

export interface TaskflowVerdict {
  verdict: TaskflowVerdictValue
  reasoning: string
  evidence: VerdictEvidenceItem[]
}

export type TaskflowVerdictFailureReason = 'no-output' | 'malformed-output' | 'invalid-verdict'

export type TaskflowVerdictResult =
  | { ok: true, verdict: TaskflowVerdict }
  | { ok: false, reason: TaskflowVerdictFailureReason }

const FAILURE_DESCRIPTIONS: Record<TaskflowVerdictFailureReason, string> = {
  'no-output': 'The TaskFlow run did not produce a captured result for the investigate task ' +
    '(no manifest.json, or no `investigate` entry in its outputs).',
  'malformed-output': 'The TaskFlow run produced a result that does not match the declared ' +
    'output shape (missing or wrong-typed `reasoning`/`evidence`).',
  'invalid-verdict': 'The TaskFlow run produced a `verdict` value outside the supported set ' +
    '(confirmed, not-applicable, inconclusive).'
}

export function describeTaskflowVerdictFailure (reason: TaskflowVerdictFailureReason): string {
  return FAILURE_DESCRIPTIONS[reason]
}

function isValidVerdict (value: unknown): value is TaskflowVerdictValue {
  return typeof value === 'string' && (VALID_VERDICTS as readonly string[]).includes(value)
}

export function parseTaskflowVerdict (raw: unknown): TaskflowVerdictResult {
  if (raw === undefined || raw === null) {
    return { ok: false, reason: 'no-output' }
  }
  if (typeof raw !== 'object') {
    return { ok: false, reason: 'malformed-output' }
  }

  const candidate = raw as Record<string, unknown>
  if (typeof candidate.reasoning !== 'string' || candidate.reasoning.length === 0) {
    return { ok: false, reason: 'malformed-output' }
  }
  if (!Array.isArray(candidate.evidence) || candidate.evidence.length === 0 || !candidate.evidence.every(isValidEvidenceItem)) {
    return { ok: false, reason: 'malformed-output' }
  }
  if (!isValidVerdict(candidate.verdict)) {
    return { ok: false, reason: 'invalid-verdict' }
  }

  return {
    ok: true,
    verdict: { verdict: candidate.verdict, reasoning: candidate.reasoning, evidence: candidate.evidence }
  }
}
