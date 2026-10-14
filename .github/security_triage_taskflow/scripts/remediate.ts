import { spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

import { git, prepareAgentWorkspace, type RunGit } from '../lib/agentWorkspace'
import { fetchIssueCommentsUnauthenticated } from '../lib/issueComments'
import { parseAlertUrl, describeAlertUrlFailure } from '../lib/parseAlertUrl'
import { requireEnv, runTaskflowProcess } from '../lib/taskflowRun'
import {
  REMEDIATION_OUTPUT_DIR,
  writeRemediationFailure,
  writeRemediationProposal,
  type RemediationAlert,
  type RemediationFailure,
  type RemediationProposalArtifact
} from '../lib/remediationArtifact'
import {
  describeRemediationProposalFailure,
  parseRemediationProposal,
  type RemediationProposal
} from '../lib/remediationProposal'
import { describeVerdictRefusal, selectTrustedVerdict, type IssueComment } from '../lib/trustedVerdict'
import type { VerdictPayload } from '../lib/verdictPayload'

const SOURCE_INDEX_ARTIFACTS = ['tags', 'GPATH', 'GRTAGS', 'GTAGS', 'cscope.out', 'cscope.in.out', 'cscope.po.out']

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
  const run = runTaskflowProcess({
    taskflow: 'remediate',
    globals: {
      alert_number: context.alert.number,
      alert_url: context.alert.url,
      rule_id: context.alert.ruleId,
      path: context.alert.path,
      verdict: context.verdict,
      assessment: context.assessment
    },
    workspace,
    dataDirPrefix: 'security-remediation-taskflow-'
  }, spawnTaskflow)
  if (!run.ok) {
    return run
  }

  const outcome = parseRemediationProposal(run.outputs.fix)
  if (!outcome.ok) {
    return { ok: false, reason: describeRemediationProposalFailure(outcome.reason) }
  }
  return { ok: true, proposal: outcome.proposal }
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
