/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Everything the `publish` job writes to GitHub, as pure text: the branch it pushes, the
// commit identity it signs off as, and the pull request a human reads before merging.
//
// The demo publishes a fix PR even when checks failed or never ran (issue #29, user story 22),
// so the honesty burden sits here: the body reports the agent's own claims as the agent's own
// claims, states plainly that this workflow verified none of them, and never marks the
// Affirmation. The PR stays a draft for the same reason.

import { describeRemediationFailure, type RemediationAlert, type RemediationFailureReason, type RemediationProposalArtifact } from './remediationArtifact'
import type { RemediationCheck } from './remediationProposal'

// The workflow's GITHUB_TOKEN identity: the only identity the publishing job can commit and
// sign off as, and one a human authorized by applying the remediation label.
export const REMEDIATION_COMMIT_IDENTITY = {
  name: 'github-actions[bot]',
  email: '41898282+github-actions[bot]@users.noreply.github.com'
} as const

export const REMEDIATION_SIGNOFF = `Signed-off-by: ${REMEDIATION_COMMIT_IDENTITY.name} <${REMEDIATION_COMMIT_IDENTITY.email}>`

export interface AttemptIdentity {
  runId: string
  runAttempt: string
}

/**
 * One branch per attempt, so removing and reapplying the label publishes another pull
 * request instead of colliding with the previous one. No deduplication is intended: the
 * demo owner accepts duplicate PRs (issue #29, user story 25).
 */
export function remediationBranchName (alertNumber: number, attempt: AttemptIdentity): string {
  return `security/alert-${alertNumber}-run-${attempt.runId}-${attempt.runAttempt}`
}

export function remediationCommitMessage (alert: RemediationAlert): string {
  return `fix(security): remediate ${alert.ruleId} at ${alert.path} (alert #${alert.number})`
}

export function buildPrTitle (alert: RemediationAlert): string {
  return `fix(security): remediate ${alert.ruleId} at ${alert.path} (alert #${alert.number})`
}

function checkLine (check: RemediationCheck): string {
  const label = check.result === 'not-run' ? 'not run' : check.result
  const command = check.command === '' ? check.name : `\`${check.command}\``
  return `- ${command}: **${label}** - ${check.detail}`
}

function validationSection (checks: RemediationCheck[]): string {
  const reported = checks.length === 0
    ? '- The agent reported no checks for this change.'
    : checks.map(checkLine).join('\n')

  return [
    'Reported by the remediation agent, from inside its isolated container:',
    '',
    reported,
    '',
    'This workflow did not re-run or verify any of the above, and does not claim the change ' +
    'is correct. Publication without passing checks is a deliberate exception for this ' +
    'demonstration (#29); it is not a validation result. Required CI on this pull request is ' +
    'the authoritative check.'
  ].join('\n')
}

export interface PrDestination {
  repo: string
  base: string
}

const UPSTREAM_REPO = 'juice-shop/juice-shop'

/**
 * Where a remediation pull request goes. This fork bases on `master`; upstream bases on
 * `develop` (docs/agents/issue-tracker.md). Always passed explicitly to `gh`, never left to
 * the default branch of whatever repository the job happens to run in.
 */
export function remediationDestination (repo: string): PrDestination {
  return { repo, base: repo === UPSTREAM_REPO ? 'develop' : 'master' }
}

export interface PrBodyInput {
  artifact: RemediationProposalArtifact
  destination: PrDestination
  issueNumber: string
  changedPaths: string[]
  runLink: string
  model: string
}

export function buildPrBody (input: PrBodyInput): string {
  const { artifact, destination, issueNumber, changedPaths, runLink, model } = input
  const { alert } = artifact

  return [
    '### Description',
    '',
    `Remediates code-scanning alert #${alert.number} (\`${alert.ruleId}\`) at \`${alert.path}\`, ` +
    `assessed as **${artifact.verdict}** by the triage agent on issue #${issueNumber}.`,
    '',
    `- Alert: ${alert.url}`,
    `- Originating issue: #${issueNumber}`,
    `- Started from \`${destination.base}\` at \`${artifact.baseCommit}\``,
    runLink === '' ? '- Workflow run: unknown' : `- Workflow run: ${runLink}`,
    '',
    'Agent summary of the change:',
    '',
    artifact.proposal.summary,
    '',
    'Files changed:',
    '',
    ...changedPaths.map(path => `- \`${path}\``),
    '',
    `Closes #${issueNumber}.`,
    '',
    '### Validation',
    '',
    validationSection(artifact.proposal.checks),
    '',
    '### AI Tool Disclosure',
    '',
    '- [x] My contribution includes AI-generated content, as disclosed below:',
    '',
    'AI tools: SecLab TaskFlow Agent, driving an interactive container shell over a checkout ' +
    'of this repository. The pull request itself is opened by deterministic workflow steps ' +
    'that make no model call.',
    `Models and versions: ${model}`,
    'Key prompts or instructions: the remediation taskflow and personality in ' +
    '`security_triage_taskflow/`, plus the alert and the triage assessment this workflow ' +
    'published on the originating issue.',
    '',
    '### Affirmation',
    '',
    `- [ ] My code follows the [CONTRIBUTING.md](https://github.com/${destination.repo}/blob/${destination.base}/CONTRIBUTING.md) guidelines`,
    '',
    'Left unchecked on purpose: no one has verified this change against CONTRIBUTING.md yet. ' +
    'A human reviewer checks it before merging.'
  ].join('\n')
}

export interface FailureCommentInput {
  reason: RemediationFailureReason
  detail: string
  runLink: string
}

/**
 * What a maintainer sees when an attempt produced no pull request. Says which stage stopped
 * and links the run, so a failure is never mistaken for a completed remediation - and never
 * dressed up as an empty pull request.
 */
export function buildFailureComment (input: FailureCommentInput): string {
  const { reason, detail, runLink } = input
  const sections = [
    `**Remediation produced no pull request** (\`${reason}\`)`,
    describeRemediationFailure(reason)
  ]
  if (detail !== '') {
    sections.push(`Details: ${detail}`)
  }
  sections.push(runLink === '' ? 'Workflow run: unknown' : `Workflow run: ${runLink}`)
  sections.push('Remove and reapply `sec:ready-for-remediation` to start a fresh attempt.')
  return sections.join('\n\n')
}

export interface SuccessCommentInput {
  prUrl: string
  alert: RemediationAlert
  runLink: string
}

export function buildSuccessComment (input: SuccessCommentInput): string {
  const { prUrl, alert, runLink } = input
  const sections = [
    `Opened ${prUrl} for alert #${alert.number} (\`${alert.ruleId}\`) at \`${alert.path}\`.`,
    'The pull request is a draft: this workflow verified none of its checks. Review and merge ' +
    'it yourself; this issue stays open until you do.'
  ]
  if (runLink !== '') {
    sections.push(`Workflow run: ${runLink}`)
  }
  return sections.join('\n\n')
}
