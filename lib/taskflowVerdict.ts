/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Validates the raw value the TaskFlow agent produced for the `investigate` task in
// security_triage_taskflow/taskflows/triage.yaml. That task declares `capture: response` and
// an `outputs` JSON Schema, so the runner already rejects a malformed response before the
// process exits successfully - but `triage.ts` reads the value back out of the run's own
// manifest.json artifact after the process exits (lib/scripts/securityTriage/triage.ts), and
// must not assume that file exists or is well-formed: the process may have crashed, the
// artifact may be missing, or an upstream runner change may alter its shape. This is the
// unit-testable seam for that read, mirroring the refusal-reason pattern in
// lib/trustedVerdict.ts and lib/remediationRefusal.ts.

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

/** A one-sentence, human-readable explanation of why no verdict was accepted, for the issue comment. */
export function describeTaskflowVerdictFailure (reason: TaskflowVerdictFailureReason): string {
  return FAILURE_DESCRIPTIONS[reason]
}

function isValidVerdict (value: unknown): value is TaskflowVerdictValue {
  return typeof value === 'string' && (VALID_VERDICTS as readonly string[]).includes(value)
}

/**
 * Validates `raw` - the `outputs.investigate` value read from a TaskFlow run's manifest.json -
 * against the shape `security_triage_taskflow/taskflows/triage.yaml` declares. The runner
 * itself already validates this before writing the manifest, so a failure here almost always
 * means the manifest is missing or the process crashed before producing one; that is reported
 * as a distinct, visible triage failure rather than a silent inconclusive verdict.
 */
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
  if (!Array.isArray(candidate.evidence) || !candidate.evidence.every(isValidEvidenceItem)) {
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
