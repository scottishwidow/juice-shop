import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import type { CouplingEvidence } from './couplingEvidence'
import {
  describeTaskflowVerdictFailure,
  parseTaskflowVerdict,
  type TaskflowVerdict
} from './taskflowVerdict'

export const TRIAGE_ALERT_DIR = 'triage-alert'
export const TRIAGE_VERDICT_DIR = 'triage-verdict'

export const ALERT_FILE = 'alert.json'
export const VERDICT_FILE = 'verdict.json'
export const FAILURE_FILE = 'failure.json'

export interface TriageAlert {
  alertNumber: number
  baseCommit: string
  ruleId: string
  path: string
  message: string
  coupling: CouplingEvidence
}

export interface TriageFailure {
  message: string
}

export type TriageAlertArtifact =
  | { kind: 'alert', alert: TriageAlert }
  | { kind: 'failure', failure: TriageFailure }
  | { kind: 'missing' }

export type TriageVerdictArtifact =
  | { kind: 'verdict', verdict: TaskflowVerdict }
  | { kind: 'failure', failure: TriageFailure }
  | { kind: 'missing' }

function writeJson (directory: string, name: string, value: unknown): void {
  mkdirSync(directory, { recursive: true })
  writeFileSync(path.join(directory, name), `${JSON.stringify(value, null, 2)}\n`)
}

export function writeTriageAlert (directory: string, alert: TriageAlert): void {
  writeJson(directory, ALERT_FILE, alert)
}

export function writeTriageVerdict (directory: string, verdict: TaskflowVerdict): void {
  writeJson(directory, VERDICT_FILE, verdict)
}

export function writeTriageFailure (directory: string, failure: TriageFailure): void {
  writeJson(directory, FAILURE_FILE, failure)
}

function readJson (directory: string, name: string): unknown {
  try {
    return JSON.parse(readFileSync(path.join(directory, name), 'utf8'))
  } catch {
    return undefined
  }
}

function readFailure (directory: string): TriageFailure | undefined {
  const candidate = readJson(directory, FAILURE_FILE) as Record<string, unknown> | undefined
  if (typeof candidate !== 'object' || candidate === null || typeof candidate.message !== 'string') {
    return undefined
  }
  return { message: candidate.message }
}

function isTriageAlert (value: unknown): value is TriageAlert {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  const coupling = candidate.coupling as Record<string, unknown> | undefined
  return Number.isInteger(candidate.alertNumber) &&
    typeof candidate.baseCommit === 'string' && /^[0-9a-f]{40}$/.test(candidate.baseCommit) &&
    typeof candidate.ruleId === 'string' &&
    typeof candidate.path === 'string' &&
    typeof candidate.message === 'string' &&
    typeof coupling === 'object' && coupling !== null &&
    typeof coupling.snippetCoupled === 'boolean' &&
    typeof coupling.solveCoupled === 'boolean' &&
    typeof coupling.isTestCode === 'boolean'
}

export function readTriageAlert (directory: string): TriageAlertArtifact {
  const failure = readFailure(directory)
  if (failure !== undefined) {
    return { kind: 'failure', failure }
  }
  const alert = readJson(directory, ALERT_FILE)
  return isTriageAlert(alert) ? { kind: 'alert', alert } : { kind: 'missing' }
}

// The verdict comes from the job that ran the model, so it is validated again before it is posted.
export function readTriageVerdict (directory: string): TriageVerdictArtifact {
  const failure = readFailure(directory)
  if (failure !== undefined) {
    return { kind: 'failure', failure }
  }
  const raw = readJson(directory, VERDICT_FILE)
  if (raw === undefined) {
    return { kind: 'missing' }
  }
  const outcome = parseTaskflowVerdict(raw)
  return outcome.ok
    ? { kind: 'verdict', verdict: outcome.verdict }
    : { kind: 'failure', failure: { message: describeTaskflowVerdictFailure(outcome.reason) } }
}
