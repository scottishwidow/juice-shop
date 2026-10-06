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

export const VERDICT_PAYLOAD_MARKER = '<!-- security-triage:verdict-payload'

const TRAILING_PAYLOAD_BODY = /^\n([\s\S]*?)\n-->\s*$/

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

// Only a payload that ends the comment counts: workflow comments that quote agent text end with
// fixed text. JSON.stringify escapes newlines, so the payload cannot contain the marker + "\n".
export function decodeVerdictPayload (commentBody: string): VerdictPayload | undefined {
  const start = commentBody.lastIndexOf(`${VERDICT_PAYLOAD_MARKER}\n`)
  if (start === -1) {
    return undefined
  }
  const block = TRAILING_PAYLOAD_BODY.exec(commentBody.slice(start + VERDICT_PAYLOAD_MARKER.length))
  if (block === null) {
    return undefined
  }
  try {
    const parsed: unknown = JSON.parse(block[1])
    return isValidPayload(parsed) ? parsed : undefined
  } catch {
    return undefined
  }
}
