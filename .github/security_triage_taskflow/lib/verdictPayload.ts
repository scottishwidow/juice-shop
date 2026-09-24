export interface VerdictEvidenceItem {
  file: string
  lines?: string
  note: string
}

export interface VerdictPayload {
  alertNumber: number
  baseCommit: string
  ruleId: string
  path: string
  verdict: string
  snippetCoupled: boolean
  solveCoupled: boolean
  isTestCode: boolean
  reasoning?: string
  evidence?: VerdictEvidenceItem[]
}

const PAYLOAD_BLOCK = /<!-- security-triage:verdict-payload\n([\s\S]*?)\n-->/g

export const VERDICT_PAYLOAD_MARKER = '<!-- security-triage:verdict-payload'

export function isValidEvidenceItem (value: unknown): value is VerdictEvidenceItem {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  if (candidate.lines !== undefined && typeof candidate.lines !== 'string') {
    return false
  }
  return typeof candidate.file === 'string' && typeof candidate.note === 'string'
}

function isValidPayload (value: unknown): value is VerdictPayload {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  if (
    typeof candidate.alertNumber !== 'number' ||
    typeof candidate.baseCommit !== 'string' || !/^[0-9a-f]{40}$/.test(candidate.baseCommit) ||
    typeof candidate.ruleId !== 'string' ||
    typeof candidate.path !== 'string' ||
    typeof candidate.verdict !== 'string' ||
    typeof candidate.snippetCoupled !== 'boolean' ||
    typeof candidate.solveCoupled !== 'boolean' ||
    typeof candidate.isTestCode !== 'boolean'
  ) {
    return false
  }
  if (candidate.reasoning !== undefined && typeof candidate.reasoning !== 'string') {
    return false
  }
  if (candidate.evidence !== undefined) {
    if (!Array.isArray(candidate.evidence) || !candidate.evidence.every(isValidEvidenceItem)) {
      return false
    }
  }
  return true
}

export function encodeVerdictPayload (payload: VerdictPayload): string {
  return `${VERDICT_PAYLOAD_MARKER}\n${JSON.stringify(payload, null, 2)}\n-->`
}

export function decodeVerdictPayload (commentBody: string): VerdictPayload | undefined {
  const matches = [...commentBody.matchAll(PAYLOAD_BLOCK)]
  for (let index = matches.length - 1; index >= 0; index--) {
    try {
      const parsed: unknown = JSON.parse(matches[index][1])
      if (isValidPayload(parsed)) {
        return parsed
      }
    } catch {
      continue
    }
  }
  return undefined
}
