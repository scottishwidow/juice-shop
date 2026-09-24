/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `remediate` job in .github/workflows/security-triage.yml.
//
// The job declares `permissions: {}` and checks out with `persist-credentials: false`: no
// credential of any kind reaches it, so nothing the agent does here can reach GitHub. It
// reads the assessment this workflow already published (an unauthenticated read of public
// issue comments), runs the remediation taskflow over the checkout, and writes the resulting
// diff - or the reason there is none - to an artifact directory. The credentialed `publish`
// job reads that artifact and does every write (issue #31).
//
// Because the comment read is unauthenticated, anyone can write a comment this job sees.
// `selectTrustedVerdict` alone decides which one it acts on, and the issue body only ever
// contributes an alert number.

import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs'
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

type RunGit = (args: string[], options?: { cwd?: string, env?: NodeJS.ProcessEnv }) => string

function git (args: string[], options: { cwd?: string, env?: NodeJS.ProcessEnv } = {}): string {
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

/**
 * A copy of the job checkout's tracked files, outside the checkout and with its own throwaway
 * git repository, so the agent never gets write access to the job's `.git` directory. Built
 * from the index (`git checkout-index`), so files the job's own dependency install left dirty
 * or untracked never reach it. The baseline commit lets the agent run `git diff` inside its
 * own workspace; it is never read by the job's own git directory afterwards.
 */
export function prepareAgentWorkspace (runGit: RunGit = git): string {
  const workspace = mkdtempSync(path.join(tmpdir(), 'security-remediation-workspace-'))
  runGit(['checkout-index', '-a', '-f', `--prefix=${workspace}${path.sep}`])
  runGit(['init', '-q'], { cwd: workspace })
  runGit(['add', '-A'], { cwd: workspace })
  runGit([
    '-c', 'user.name=security-remediation-agent',
    '-c', 'user.email=security-remediation-agent@localhost',
    '-c', 'commit.gpgsign=false',
    'commit', '-q', '--no-verify', '-m', 'baseline'
  ], { cwd: workspace })
  return workspace
}

/**
 * The proposed change: the job checkout's own git directory diffed against the agent's
 * workspace as an external work tree, through a throwaway index. This never reads or runs
 * anything from the workspace's `.git` - git ignores a work tree's own `.git` at its root -
 * so nothing the agent wrote there, including its git config, is interpreted by the runner.
 * `core.fsmonitor`/`core.hooksPath` are cleared as defence in depth; the trusted config this
 * runs with should never set them. Index files the container's exploration tools (ctags,
 * gtags, cscope) drop into the workspace are excluded, because the agent did not author them.
 */
export function collectProposedDiff (workspace: string, runGit: RunGit = git): string {
  const indexDir = mkdtempSync(path.join(tmpdir(), 'security-remediation-index-'))
  const env = { ...process.env, GIT_INDEX_FILE: path.join(indexDir, 'index') }
  const excludes = SOURCE_INDEX_ARTIFACTS.map(name => `:(exclude)${name}`)

  runGit(['read-tree', 'HEAD'], { env })
  runGit([
    '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
    `--work-tree=${workspace}`, 'add', '-A', '--', '.', ...excludes
  ], { env })
  return runGit([
    '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
    `--work-tree=${workspace}`, 'diff', '--cached', '--binary', 'HEAD'
  ], { env })
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
  collectProposedDiff: (workspace: string) => string
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

  const diff = dependencies.collectProposedDiff(workspace)
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

// Every failure, categorized or not, is written to the artifact this credential-free job
// uploads: it cannot report anything itself, so `publish` reports it (issue #31). The job
// still exits non-zero so the failure stays visible in the Actions run.
if (require.main === module) {
  main().catch((error: unknown) => {
    console.error(error)
    writeRemediationFailure(REMEDIATION_OUTPUT_DIR, { reason: 'unexpected-error', detail: String(error) })
    process.exitCode = 1
  })
}
