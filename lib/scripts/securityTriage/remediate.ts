import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

import { createTaskflowDataDir } from '../../taskflowDataDir'
import { fetchIssueCommentsUnauthenticated } from '../../issueComments'
import { parseAlertUrl, describeAlertUrlFailure } from '../../parseAlertUrl'
import {
  REMEDIATION_OUTPUT_DIR,
  writeRemediationFailure,
  writeRemediationProposal,
  type RemediationAlert,
  type RemediationFailure,
  type RemediationProposalArtifact
} from '../../remediationArtifact'
import {
  describeRemediationProposalFailure,
  parseRemediationProposal,
  type RemediationProposal
} from '../../remediationProposal'
import { describeVerdictRefusal, selectTrustedVerdict, type IssueComment } from '../../trustedVerdict'
import type { VerdictPayload } from '../../verdictPayload'

const SOURCE_INDEX_ARTIFACTS = ['tags', 'GPATH', 'GRTAGS', 'GTAGS', 'cscope.out', 'cscope.in.out', 'cscope.po.out']

function requireEnv (name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`)
  }
  return value
}

export interface GitOptions {
  cwd?: string
  env?: NodeJS.ProcessEnv
}

export type RunGit = (args: string[], options?: GitOptions) => string

function git (args: string[], options: GitOptions = {}): string {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options })
}

function baseCommit (): string {
  return git(['rev-parse', 'HEAD']).trim()
}

export interface RemediationContext {
  alert: RemediationAlert
  verdict: string
  assessment: string
}

export type TaskflowRunOutcome =
  | { ok: true, proposal: RemediationProposal }
  | { ok: false, reason: string }

export function runTaskflow (
  context: RemediationContext,
  workspace: string,
  spawnTaskflow: typeof spawnSync = spawnSync
): TaskflowRunOutcome {
  const dataDir = createTaskflowDataDir('security-remediation-taskflow-')

  const result = spawnTaskflow('python3', [
    '-m', 'seclab_taskflow_agent',
    '-t', 'security_triage_taskflow.taskflows.remediate',
    '-m', 'security_triage_taskflow.configs.model_config',
    '-g', `alert_number=${context.alert.number}`,
    '-g', `alert_url=${context.alert.url}`,
    '-g', `rule_id=${context.alert.ruleId}`,
    '-g', `path=${context.alert.path}`,
    '-g', `verdict=${context.verdict}`,
    '-g', `assessment=${context.assessment}`
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: requireEnv('ANTHROPIC_API_KEY'),
      CONTAINER_WORKSPACE: workspace,
      LOG_DIR: path.join(dataDir, 'logs'),
      XDG_DATA_HOME: dataDir,
      PYTHONPATH: [process.cwd(), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter)
    }
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

  const manifest = readManifest(path.join(dataDir, 'seclab-taskflow-agent', 'artifacts'))
  const outcome = parseRemediationProposal(manifest?.outputs?.fix)
  if (!outcome.ok) {
    return { ok: false, reason: describeRemediationProposalFailure(outcome.reason) }
  }
  return { ok: true, proposal: outcome.proposal }
}

interface RunManifest {
  outputs?: Record<string, unknown>
}

function readManifest (artifactsRoot: string): RunManifest | undefined {
  if (!existsSync(artifactsRoot)) {
    return undefined
  }
  const sessionId = readdirSync(artifactsRoot)[0]
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

export function prepareAgentWorkspace (runGit: RunGit = git): string {
  const workspace = mkdtempSync(path.join(tmpdir(), 'security-remediation-workspace-'))
  runGit(['checkout-index', '-a', '-f', `--prefix=${workspace}${path.sep}`])
  runGit(['init', '-q'], { cwd: workspace })
  runGit(['add', '-A', '--force'], { cwd: workspace })
  runGit([
    '-c', 'user.name=security-remediation-agent',
    '-c', 'user.email=security-remediation-agent@localhost',
    '-c', 'commit.gpgsign=false',
    'commit', '-q', '--no-verify', '-m', 'baseline'
  ], { cwd: workspace })
  return workspace
}

export type ProposedDiffOutcome =
  | { ok: true, diff: string }
  | { ok: false, nestedRepositories: string[] }

export function collectProposedDiff (workspace: string, runGit: RunGit = git): ProposedDiffOutcome {
  const nestedRepositories = findNestedRepositories(workspace)
  if (nestedRepositories.length > 0) {
    return { ok: false, nestedRepositories }
  }

  const indexDir = mkdtempSync(path.join(tmpdir(), 'security-remediation-index-'))
  try {
    const env = { ...process.env, GIT_INDEX_FILE: path.join(indexDir, 'index') }
    const workTreeGit = [
      '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
      '--attr-source=HEAD', `--work-tree=${workspace}`
    ]
    const excludes = SOURCE_INDEX_ARTIFACTS.map(name => `:(exclude)${name}`)

    runGit(['read-tree', 'HEAD'], { env })
    runGit([...workTreeGit, 'add', '-A', '--', '.', ...excludes], { env })
    return { ok: true, diff: runGit([...workTreeGit, 'diff', '--cached', '--binary', 'HEAD'], { env }) }
  } finally {
    rmSync(indexDir, { recursive: true, force: true })
  }
}

function findNestedRepositories (workspace: string): string[] {
  const found: string[] = []
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const entryPath = path.join(dir, entry.name)
      if (entry.name === '.git') {
        if (dir !== workspace) {
          found.push(path.relative(workspace, entryPath))
        }
      } else if (entry.isDirectory()) {
        visit(entryPath)
      }
    }
  }
  visit(workspace)
  return found
}

function assessmentText (verdict: VerdictPayload): string {
  const evidence = (verdict.evidence ?? []).map(item => `- ${item.file}: ${item.note}`)
  return [verdict.reasoning ?? 'No reasoning was recorded with this assessment.', ...evidence]
    .join('\n')
}

export interface SecurityRemediationInput {
  repo: string
  issueNumber: string
  issueBody: string
}

export interface SecurityRemediationDependencies {
  fetchComments: (repo: string, issueNumber: string) => Promise<IssueComment[]>
  baseCommit: () => string
  prepareWorkspace: () => string
  runTaskflow: (context: RemediationContext, workspace: string) => TaskflowRunOutcome
  collectProposedDiff: (workspace: string) => ProposedDiffOutcome
  writeProposal: (artifact: RemediationProposalArtifact, diff: string) => void
  writeFailure: (failure: RemediationFailure) => void
}

const DEFAULT_DEPENDENCIES: SecurityRemediationDependencies = {
  fetchComments: fetchIssueCommentsUnauthenticated,
  baseCommit,
  prepareWorkspace: () => prepareAgentWorkspace(),
  runTaskflow: (context, workspace) => runTaskflow(context, workspace),
  collectProposedDiff: workspace => collectProposedDiff(workspace),
  writeProposal: (artifact, diff) => { writeRemediationProposal(REMEDIATION_OUTPUT_DIR, artifact, diff) },
  writeFailure: failure => { writeRemediationFailure(REMEDIATION_OUTPUT_DIR, failure) }
}

export async function runSecurityRemediation (
  input: SecurityRemediationInput,
  dependencies: SecurityRemediationDependencies = DEFAULT_DEPENDENCIES
): Promise<boolean> {
  const { repo, issueNumber, issueBody } = input

  const parsedAlert = parseAlertUrl(issueBody, repo)
  if (!parsedAlert.ok) {
    dependencies.writeFailure({
      reason: 'no-alert-reference',
      detail: describeAlertUrlFailure(parsedAlert.reason)
    })
    return false
  }

  const alertNumber = parsedAlert.alert.alertNumber
  const selection = selectTrustedVerdict(await dependencies.fetchComments(repo, issueNumber), { alertNumber })
  if (!selection.selected) {
    dependencies.writeFailure({
      reason: 'untrusted-assessment',
      detail: describeVerdictRefusal(selection.reason)
    })
    return false
  }

  const verdict = selection.verdict
  const alert: RemediationAlert = {
    number: alertNumber,
    url: `https://github.com/${repo}/security/code-scanning/${alertNumber}`,
    ruleId: verdict.ruleId,
    path: verdict.path
  }

  const workspace = dependencies.prepareWorkspace()
  const outcome = dependencies.runTaskflow({
    alert,
    verdict: verdict.verdict,
    assessment: assessmentText(verdict)
  }, workspace)
  if (!outcome.ok) {
    dependencies.writeFailure({ reason: 'taskflow-failed', detail: outcome.reason })
    return false
  }

  const collected = dependencies.collectProposedDiff(workspace)
  if (!collected.ok) {
    dependencies.writeFailure({
      reason: 'nested-repository',
      detail: `The agent created a git repository inside its workspace: ${collected.nestedRepositories.join(', ')}.`
    })
    return false
  }

  const diff = collected.diff
  if (diff.trim() === '') {
    dependencies.writeFailure({
      reason: 'no-change',
      detail: `The agent reported: ${outcome.proposal.summary}`
    })
    return false
  }

  dependencies.writeProposal({
    alert,
    verdict: verdict.verdict,
    baseCommit: dependencies.baseCommit(),
    proposal: outcome.proposal
  }, diff)
  return true
}

async function main (): Promise<void> {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const published = await runSecurityRemediation({
    repo,
    issueNumber: requireEnv('ISSUE_NUMBER'),
    issueBody: process.env.ISSUE_BODY ?? ''
  })
  if (!published) {
    process.exitCode = 1
  }
}

if (require.main === module) {
  main().catch((error: unknown) => {
    console.error(error)
    writeRemediationFailure(REMEDIATION_OUTPUT_DIR, { reason: 'unexpected-error', detail: String(error) })
    process.exitCode = 1
  })
}
