import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { createTaskflowDataDir } from '../../taskflowDataDir'
import { parseAlertUrl, describeAlertUrlFailure } from '../../parseAlertUrl'
import { computeCouplingEvidence } from '../../couplingEvidence'
import { encodeVerdictPayload, type VerdictPayload } from '../../verdictPayload'
import { parseTaskflowVerdict, describeTaskflowVerdictFailure, type TaskflowVerdict } from '../../taskflowVerdict'

export interface AlertDetail {
  ruleId: string
  path: string
  message: string
}

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

function fetchAlertDetail (repo: string, alertNumber: number): AlertDetail {
  const raw = gh(['api', `repos/${repo}/code-scanning/alerts/${alertNumber}`])
  const alert = JSON.parse(raw) as {
    rule: { id: string }
    most_recent_instance: { location: { path: string }, message: { text: string } }
  }
  return {
    ruleId: alert.rule.id,
    path: alert.most_recent_instance.location.path,
    message: alert.most_recent_instance.message.text
  }
}

function readBaseRefFile (path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return undefined
  }
}

function baseCommit (): string {
  return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
}

const PUBLISHING_CREDENTIAL_VARIABLES = ['GH_TOKEN', 'GITHUB_TOKEN']

export function agentEnvironment (dataDir: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    ANTHROPIC_API_KEY: requireEnv('ANTHROPIC_API_KEY'),
    CONTAINER_WORKSPACE: process.cwd(),
    LOG_DIR: path.join(dataDir, 'logs'),
    XDG_DATA_HOME: dataDir,
    PYTHONPATH: [process.cwd(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter)
  }
  for (const name of PUBLISHING_CREDENTIAL_VARIABLES) {
    delete environment[name]
  }
  return environment
}

export type TaskflowRunOutcome =
  | { ok: true, verdict: TaskflowVerdict }
  | { ok: false, reason: string }

export function runTaskflow (
  alert: AlertDetail,
  alertNumber: number,
  spawnTaskflow: typeof spawnSync = spawnSync
): TaskflowRunOutcome {
  const dataDir = createTaskflowDataDir('security-triage-taskflow-')

  const result = spawnTaskflow('python3', [
    '-m', 'seclab_taskflow_agent',
    '-t', 'security_triage_taskflow.taskflows.triage',
    '-m', 'security_triage_taskflow.configs.model_config',
    '-g', `alert_number=${alertNumber}`,
    '-g', `rule_id=${alert.ruleId}`,
    '-g', `path=${alert.path}`,
    '-g', `message=${alert.message}`
  ], {
    encoding: 'utf8',
    env: agentEnvironment(dataDir)
  })

  if (result.error !== undefined) {
    console.error(result.error)
  }
  if (result.stdout !== undefined && result.stdout !== '') {
    console.log(result.stdout)
  }
  if (result.stderr !== undefined && result.stderr !== '') {
    console.error(result.stderr)
  }

  if (result.error !== undefined) {
    return { ok: false, reason: `The TaskFlow process failed to start: ${result.error.message}.` }
  }
  if (result.signal !== null) {
    return { ok: false, reason: `The TaskFlow process was terminated by signal ${result.signal}.` }
  }
  if (result.status !== 0) {
    return { ok: false, reason: `The TaskFlow process exited with status ${result.status ?? 'unknown'}.` }
  }

  const artifactsRoot = path.join(dataDir, 'seclab-taskflow-agent', 'artifacts')
  const manifest = readManifest(artifactsRoot)
  const outcome = parseTaskflowVerdict(manifest?.outputs?.investigate)
  if (!outcome.ok) {
    return { ok: false, reason: describeTaskflowVerdictFailure(outcome.reason) }
  }
  return { ok: true, verdict: outcome.verdict }
}

interface RunManifest {
  outputs?: Record<string, unknown>
}

function readManifest (artifactsRoot: string): RunManifest | undefined {
  if (!existsSync(artifactsRoot)) {
    return undefined
  }
  const sessions = readdirSync(artifactsRoot)
  const sessionId = sessions[0]
  if (sessionId === undefined) {
    return undefined
  }
  const manifestPath = path.join(artifactsRoot, sessionId, 'manifest.json')
  if (!existsSync(manifestPath)) {
    return undefined
  }
  try {
    return JSON.parse(readFileSync(manifestPath, 'utf8')) as RunManifest
  } catch {
    return undefined
  }
}

function verdictSummary (alert: AlertDetail, alertNumber: number, base: string, verdict: TaskflowVerdict): string {
  return [
    `**Verdict: ${verdict.verdict}**`,
    '',
    `- Alert: #${alertNumber}`,
    `- Base: \`${base}\``,
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

export interface SecurityTriageInput {
  repo: string
  issueNumber: string
  issueBody: string
  runLink: string
}

export interface SecurityTriageDependencies {
  fetchAlertDetail: (repo: string, alertNumber: number) => AlertDetail
  readBaseRefFile: (path: string) => string | undefined
  baseCommit: () => string
  runTaskflow: (alert: AlertDetail, alertNumber: number) => TaskflowRunOutcome
  comment: (issueNumber: string, repo: string, body: string) => void
  markTriaged: (issueNumber: string, repo: string) => void
}

const DEFAULT_DEPENDENCIES: SecurityTriageDependencies = {
  fetchAlertDetail,
  readBaseRefFile,
  baseCommit,
  runTaskflow,
  comment: (issueNumber, repo, body) => {
    gh(['issue', 'comment', issueNumber, '--repo', repo, '--body', body])
  },
  markTriaged: (issueNumber, repo) => {
    gh([
      'issue', 'edit', issueNumber, '--repo', repo,
      '--add-label', 'sec:triaged',
      '--remove-label', 'sec:needs-triage'
    ])
  }
}

function failureComment (message: string, runLink: string): string {
  const suffix = runLink === '' ? '' : `\n\nWorkflow run: ${runLink}`
  return `${message} No verdict was recorded; \`sec:needs-triage\` is unchanged.${suffix}`
}

export function runSecurityTriage (
  input: SecurityTriageInput,
  dependencies: SecurityTriageDependencies = DEFAULT_DEPENDENCIES
): boolean {
  const { repo, issueNumber, issueBody, runLink } = input

  const parsedAlert = parseAlertUrl(issueBody, repo)
  if (!parsedAlert.ok) {
    dependencies.comment(issueNumber, repo, failureComment(describeAlertUrlFailure(parsedAlert.reason), runLink))
    return false
  }

  const alertNumber = parsedAlert.alert.alertNumber
  let alert: AlertDetail
  try {
    alert = dependencies.fetchAlertDetail(repo, alertNumber)
  } catch {
    dependencies.comment(issueNumber, repo, failureComment(`Triage could not read alert #${alertNumber}.`, runLink))
    return false
  }

  const evidence = computeCouplingEvidence(alert.path, dependencies.readBaseRefFile)
  const base = dependencies.baseCommit()

  const outcome = dependencies.runTaskflow(alert, alertNumber)
  if (!outcome.ok) {
    dependencies.comment(issueNumber, repo, failureComment(
      `Triage execution failed for alert #${alertNumber}: ${outcome.reason}`,
      runLink
    ))
    return false
  }

  const payload: VerdictPayload = {
    alertNumber,
    baseCommit: base,
    ruleId: alert.ruleId,
    path: alert.path,
    verdict: outcome.verdict.verdict,
    snippetCoupled: evidence.snippetCoupled,
    solveCoupled: evidence.solveCoupled,
    isTestCode: evidence.isTestCode,
    reasoning: outcome.verdict.reasoning,
    evidence: outcome.verdict.evidence
  }

  const comment = [
    verdictSummary(alert, alertNumber, base, outcome.verdict),
    '',
    outcome.verdict.reasoning,
    evidenceList(outcome.verdict),
    '',
    encodeVerdictPayload(payload)
  ].join('\n')

  dependencies.comment(issueNumber, repo, comment)
  dependencies.markTriaged(issueNumber, repo)
  return true
}

function main (): void {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const success = runSecurityTriage({
    repo,
    issueNumber: requireEnv('ISSUE_NUMBER'),
    issueBody: process.env.ISSUE_BODY ?? '',
    runLink: workflowRunLink(repo)
  })
  if (!success) {
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
