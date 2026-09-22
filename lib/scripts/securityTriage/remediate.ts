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
import { existsSync, readdirSync, readFileSync } from 'node:fs'
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

function git (args: string[]): string {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
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
      CONTAINER_WORKSPACE: process.cwd(),
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

/** Every path already modified or untracked in the checkout, before the agent touches it. */
export function dirtyPaths (runGit: (args: string[]) => string = git): string[] {
  return runGit(['status', '--porcelain', '--untracked-files=all'])
    .split('\n')
    .filter(line => line.length > 3)
    .map(line => line.slice(3).trim())
}

/**
 * The proposed change, read from the checkout the agent edited rather than from anything the
 * agent reported. Staging first makes added files part of the diff. Two kinds of path are
 * kept out of it, because the agent did not author them: whatever the job's own dependency
 * install already dirtied before the run, and the index files the container's exploration
 * tools (ctags, gtags, cscope) drop into the mounted workspace.
 */
export function collectProposedDiff (
  preexisting: string[] = [],
  runGit: (args: string[]) => string = git
): string {
  const excludes = [...SOURCE_INDEX_ARTIFACTS, ...preexisting].map(name => `:(exclude)${name}`)
  runGit(['add', '-A', '--', '.', ...excludes])
  return runGit(['diff', '--cached', '--binary', 'HEAD'])
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
  runTaskflow: (context: RemediationContext) => TaskflowRunOutcome
  dirtyPaths: () => string[]
  collectProposedDiff: (preexisting: string[]) => string
  writeProposal: (artifact: RemediationProposalArtifact, diff: string) => void
  writeFailure: (failure: RemediationFailure) => void
}

const DEFAULT_DEPENDENCIES: SecurityRemediationDependencies = {
  fetchComments: fetchIssueCommentsUnauthenticated,
  baseCommit,
  runTaskflow: context => runTaskflow(context),
  dirtyPaths: () => dirtyPaths(),
  collectProposedDiff: preexisting => collectProposedDiff(preexisting),
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

  const preexisting = dependencies.dirtyPaths()
  const outcome = dependencies.runTaskflow({
    alert,
    verdict: verdict.verdict,
    assessment: assessmentText(verdict)
  })
  if (!outcome.ok) {
    dependencies.writeFailure({ reason: 'taskflow-failed', detail: outcome.reason })
    return false
  }

  const diff = dependencies.collectProposedDiff(preexisting)
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
