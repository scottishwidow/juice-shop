import { execFileSync } from 'node:child_process'
import process from 'node:process'

import type { TaskflowVerdict } from '../lib/taskflowVerdict'
import {
  readTriageAlert,
  readTriageVerdict,
  TRIAGE_ALERT_DIR,
  TRIAGE_VERDICT_DIR,
  type TriageAlert,
  type TriageAlertArtifact,
  type TriageVerdictArtifact
} from '../lib/triageArtifact'
import { encodeVerdictPayload, type VerdictPayload } from '../lib/verdictPayload'

function requireEnv (name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`)
  }
  return value
}

function gh (args: string[]): string {
  return execFileSync('gh', args, { encoding: 'utf8' })
}

function workflowRunLink (repo: string): string {
  const serverUrl = process.env.GITHUB_SERVER_URL ?? 'https://github.com'
  const runId = process.env.GITHUB_RUN_ID
  return runId === undefined ? '' : `${serverUrl}/${repo}/actions/runs/${runId}`
}

function verdictSummary (alert: TriageAlert, verdict: TaskflowVerdict): string {
  return [
    `**Verdict: ${verdict.verdict}**`,
    '',
    `- Alert: #${alert.alertNumber}`,
    `- Base: \`${alert.baseCommit}\``,
    `- Rule: \`${alert.ruleId}\``,
    `- Path: \`${alert.path}\``
  ].join('\n')
}

function evidenceList (verdict: TaskflowVerdict): string {
  return ['', '**Evidence:**', ...verdict.evidence.map(item => {
    const location = item.lines === undefined ? `\`${item.file}\`` : `\`${item.file}\` (${item.lines})`
    return `- ${location}: ${item.note}`
  })].join('\n')
}

function failureComment (message: string, runLink: string): string {
  const suffix = runLink === '' ? '' : `\n\nWorkflow run: ${runLink}`
  return `${message} No verdict was recorded; \`sec:needs-triage\` is unchanged.${suffix}`
}

function verdictComment (alert: TriageAlert, verdict: TaskflowVerdict): string {
  const payload: VerdictPayload = {
    alertNumber: alert.alertNumber,
    baseCommit: alert.baseCommit,
    ruleId: alert.ruleId,
    path: alert.path,
    verdict: verdict.verdict,
    ...alert.coupling,
    reasoning: verdict.reasoning,
    evidence: verdict.evidence
  }
  return [
    verdictSummary(alert, verdict),
    '',
    verdict.reasoning,
    evidenceList(verdict),
    '',
    encodeVerdictPayload(payload)
  ].join('\n')
}

export interface PostVerdictInput {
  repo: string
  issueNumber: string
  runLink: string
}

export interface PostVerdictDependencies {
  readAlert: () => TriageAlertArtifact
  readVerdict: () => TriageVerdictArtifact
  comment: (body: string) => void
  markTriaged: () => void
}

function defaultDependencies ({ repo, issueNumber }: PostVerdictInput): PostVerdictDependencies {
  return {
    readAlert: () => readTriageAlert(TRIAGE_ALERT_DIR),
    readVerdict: () => readTriageVerdict(TRIAGE_VERDICT_DIR),
    comment: body => { gh(['issue', 'comment', issueNumber, '--repo', repo, '--body', body]) },
    markTriaged: () => {
      gh([
        'issue', 'edit', issueNumber, '--repo', repo,
        '--add-label', 'sec:triaged',
        '--remove-label', 'sec:needs-triage'
      ])
    }
  }
}

export function runPostVerdict (
  input: PostVerdictInput,
  dependencies: PostVerdictDependencies = defaultDependencies(input)
): boolean {
  const alertArtifact = dependencies.readAlert()
  if (alertArtifact.kind === 'failure') {
    dependencies.comment(failureComment(alertArtifact.failure.message, input.runLink))
    return false
  }
  if (alertArtifact.kind === 'missing') {
    dependencies.comment(failureComment('The job that reads the alert crashed before writing anything.', input.runLink))
    return false
  }

  const alert = alertArtifact.alert
  const verdictArtifact = dependencies.readVerdict()
  if (verdictArtifact.kind !== 'verdict') {
    const reason = verdictArtifact.kind === 'failure'
      ? verdictArtifact.failure.message
      : 'The triage job produced neither a verdict nor a reason for stopping; it most likely crashed before writing anything.'
    dependencies.comment(failureComment(`Triage execution failed for alert #${alert.alertNumber}: ${reason}`, input.runLink))
    return false
  }

  dependencies.comment(verdictComment(alert, verdictArtifact.verdict))
  dependencies.markTriaged()
  return true
}

function main (): void {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const posted = runPostVerdict({
    repo,
    issueNumber: requireEnv('ISSUE_NUMBER'),
    runLink: workflowRunLink(repo)
  })
  if (!posted) {
    process.exitCode = 1
  }
}

if (require.main === module) {
  try {
    main()
  } catch (error: unknown) {
    console.error(error)
    process.exitCode = 1
  }
}
