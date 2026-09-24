import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import type { RemediationProposal } from './remediationProposal'

export const REMEDIATION_OUTPUT_DIR = 'remediation-output'

export const PROPOSAL_FILE = 'proposal.json'
export const DIFF_FILE = 'proposed.diff'
export const FAILURE_FILE = 'failure.json'

export type RemediationFailureReason =
  | 'no-alert-reference'
  | 'untrusted-assessment'
  | 'taskflow-failed'
  | 'invalid-agent-output'
  | 'no-change'
  | 'excluded-changes'
  | 'diff-not-applicable'
  | 'missing-artifact'
  | 'publish-error'
  | 'unexpected-error'

export interface RemediationFailure {
  reason: RemediationFailureReason
  detail: string
}

export interface RemediationAlert {
  number: number
  url: string
  ruleId: string
  path: string
}

export interface RemediationProposalArtifact {
  alert: RemediationAlert
  verdict: string
  baseCommit: string
  proposal: RemediationProposal
}

export type RemediationArtifact =
  | { kind: 'proposal', proposal: RemediationProposalArtifact, diff: string }
  | { kind: 'failure', failure: RemediationFailure }
  | { kind: 'missing' }

function writeFile (directory: string, name: string, content: string): void {
  mkdirSync(directory, { recursive: true })
  writeFileSync(path.join(directory, name), content)
}

export function writeRemediationProposal (directory: string, proposal: RemediationProposalArtifact, diff: string): void {
  writeFile(directory, PROPOSAL_FILE, `${JSON.stringify(proposal, null, 2)}\n`)
  writeFile(directory, DIFF_FILE, diff)
}

export function writeRemediationFailure (directory: string, failure: RemediationFailure): void {
  writeFile(directory, FAILURE_FILE, `${JSON.stringify(failure, null, 2)}\n`)
}

function readFile (directory: string, name: string): string | undefined {
  try {
    return readFileSync(path.join(directory, name), 'utf8')
  } catch {
    return undefined
  }
}

function isFailure (value: unknown): value is RemediationFailure {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  return typeof candidate.reason === 'string' && typeof candidate.detail === 'string'
}

function isProposalArtifact (value: unknown): value is RemediationProposalArtifact {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const candidate = value as Record<string, unknown>
  const alert = candidate.alert as Record<string, unknown> | undefined
  if (alert === undefined || typeof alert !== 'object' || alert === null) {
    return false
  }
  return typeof alert.number === 'number' &&
    typeof alert.url === 'string' &&
    typeof alert.ruleId === 'string' &&
    typeof alert.path === 'string' &&
    typeof candidate.verdict === 'string' &&
    typeof candidate.baseCommit === 'string' &&
    typeof candidate.proposal === 'object' && candidate.proposal !== null
}

function parse (raw: string | undefined): unknown {
  if (raw === undefined) {
    return undefined
  }
  try {
    return JSON.parse(raw)
  } catch {
    return undefined
  }
}

export function readRemediationArtifact (directory: string): RemediationArtifact {
  const failure = parse(readFile(directory, FAILURE_FILE))
  if (isFailure(failure)) {
    return { kind: 'failure', failure }
  }

  const proposal = parse(readFile(directory, PROPOSAL_FILE))
  const diff = readFile(directory, DIFF_FILE)
  if (isProposalArtifact(proposal) && diff !== undefined && diff.trim() !== '') {
    return { kind: 'proposal', proposal, diff }
  }

  return { kind: 'missing' }
}

const FAILURE_DESCRIPTIONS: Record<RemediationFailureReason, string> = {
  'no-alert-reference': 'The issue body does not name exactly one same-repository ' +
    'code-scanning alert URL, so there is nothing to remediate.',
  'untrusted-assessment': "No triage assessment posted by this workflow for the issue's own " +
    'alert was found. Run triage first; a comment from anyone else selects nothing.',
  'taskflow-failed': 'The remediation agent did not finish its run.',
  'invalid-agent-output': 'The remediation agent finished but did not report its work in the ' +
    'declared output shape.',
  'no-change': 'The remediation agent left the checkout unchanged, so there is no fix to ' +
    'publish. No empty pull request was opened.',
  'excluded-changes': 'The proposed change touches paths that automatic remediation may ' +
    'never change, so none of it was published.',
  'diff-not-applicable': 'The proposed change did not apply to the publishing checkout of ' +
    '`master`.',
  'missing-artifact': 'The remediation job produced neither a proposed change nor a reason ' +
    'for stopping; it most likely crashed before writing anything.',
  'publish-error': 'The proposed change was accepted, but publishing it failed. The cause is ' +
    'in the publishing job itself - its credential, its permissions, or GitHub - and not in ' +
    'the proposed change.',
  'unexpected-error': 'The remediation job failed with an unexpected error.'
}

export function describeRemediationFailure (reason: RemediationFailureReason): string {
  return FAILURE_DESCRIPTIONS[reason]
}
