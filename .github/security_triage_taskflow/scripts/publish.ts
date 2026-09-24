import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

import { describeExcludedPaths, findExcludedPaths } from '../lib/excludedPaths'
import {
  readRemediationArtifact,
  REMEDIATION_OUTPUT_DIR,
  type RemediationArtifact,
  type RemediationFailureReason,
  type RemediationProposalArtifact
} from '../lib/remediationArtifact'
import {
  buildFailureComment,
  buildPrBody,
  buildPrTitle,
  buildSuccessComment,
  remediationBranchName,
  remediationCommitMessage,
  remediationDestination,
  REMEDIATION_COMMIT_IDENTITY,
  type AttemptIdentity
} from '../lib/remediationPr'

export const MODEL = 'claude-sonnet-5'

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

function git (args: string[], options: { input?: string, env?: NodeJS.ProcessEnv } = {}): string {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options })
}

function workflowRunLink (repo: string): string {
  const serverUrl = process.env.GITHUB_SERVER_URL ?? 'https://github.com'
  const runId = process.env.GITHUB_RUN_ID
  return runId === undefined ? '' : `${serverUrl}/${repo}/actions/runs/${runId}`
}

export interface PublishInput {
  repo: string
  issueNumber: string
  runLink: string
  attempt: AttemptIdentity
}

export interface PublishDependencies {
  readArtifact: () => RemediationArtifact
  applyOnBranch: (branch: string, diff: string) => boolean
  stagedPaths: () => string[]
  discard: () => void
  commitAndPush: (branch: string, message: string) => void
  createPullRequest: (options: { branch: string, title: string, bodyPath: string, base: string, repo: string, draft: boolean }) => string
  writeBody: (body: string) => string
  comment: (body: string) => void
}

function applyOnBranch (branch: string, diff: string): boolean {
  git(['checkout', '-b', branch])
  try {
    git(['apply', '--index', '--whitespace=nowarn', '-'], { input: diff })
    return true
  } catch (error) {
    console.error(error)
    return false
  }
}

function defaultDependencies (input: PublishInput): PublishDependencies {
  const { repo, issueNumber } = input
  return {
    readArtifact: () => readRemediationArtifact(process.env.REMEDIATION_OUTPUT_DIR ?? REMEDIATION_OUTPUT_DIR),
    applyOnBranch,
    stagedPaths: () => git(['diff', '--cached', '--name-only']).split('\n').filter(line => line !== ''),
    discard: () => { git(['reset', '--hard', 'HEAD']) },
    commitAndPush: (branch, message) => {
      git(['commit', '-s', '-m', message], {
        env: {
          ...process.env,
          GIT_AUTHOR_NAME: REMEDIATION_COMMIT_IDENTITY.name,
          GIT_AUTHOR_EMAIL: REMEDIATION_COMMIT_IDENTITY.email,
          GIT_COMMITTER_NAME: REMEDIATION_COMMIT_IDENTITY.name,
          GIT_COMMITTER_EMAIL: REMEDIATION_COMMIT_IDENTITY.email
        }
      })
      git(['push', 'origin', branch])
    },
    createPullRequest: options => gh([
      'pr', 'create',
      '--repo', options.repo,
      '--base', options.base,
      '--head', options.branch,
      ...(options.draft ? ['--draft'] : []),
      '--title', options.title,
      '--body-file', options.bodyPath
    ]).trim(),
    writeBody: body => {
      const bodyPath = path.join(mkdtempSync(path.join(tmpdir(), 'remediation-pr-')), 'body.md')
      writeFileSync(bodyPath, body)
      return bodyPath
    },
    comment: body => { gh(['issue', 'comment', issueNumber, '--repo', repo, '--body', body]) }
  }
}

function reportFailure (
  dependencies: PublishDependencies,
  runLink: string,
  reason: RemediationFailureReason,
  detail: string
): false {
  dependencies.comment(buildFailureComment({ reason, detail, runLink }))
  return false
}

function publishProposal (
  input: PublishInput,
  dependencies: PublishDependencies,
  artifact: RemediationProposalArtifact,
  diff: string
): boolean {
  const { repo, issueNumber, runLink, attempt } = input
  const branch = remediationBranchName(artifact.alert.number, attempt)

  if (!dependencies.applyOnBranch(branch, diff)) {
    return reportFailure(dependencies, runLink, 'diff-not-applicable',
      'The diff the remediation agent produced did not apply to this checkout.')
  }

  const changedPaths = dependencies.stagedPaths()
  if (changedPaths.length === 0) {
    dependencies.discard()
    return reportFailure(dependencies, runLink, 'no-change',
      'The proposed diff applied without changing any file.')
  }

  const excluded = findExcludedPaths(changedPaths)
  if (excluded.length > 0) {
    dependencies.discard()
    return reportFailure(dependencies, runLink, 'excluded-changes',
      `Nothing was published. The rejected paths are:\n\n${describeExcludedPaths(excluded)}`)
  }

  const destination = remediationDestination(repo)

  let branchPushed = false
  try {
    dependencies.commitAndPush(branch, remediationCommitMessage(artifact.alert))
    branchPushed = true

    const bodyPath = dependencies.writeBody(buildPrBody({
      artifact,
      destination,
      issueNumber,
      changedPaths,
      runLink,
      model: MODEL
    }))
    const prUrl = dependencies.createPullRequest({
      branch,
      title: buildPrTitle(artifact.alert),
      bodyPath,
      base: destination.base,
      repo: destination.repo,
      draft: true
    })

    dependencies.comment(buildSuccessComment({ prUrl, alert: artifact.alert, runLink }))
    return true
  } catch (error: unknown) {
    console.error(error)
    return reportFailure(dependencies, runLink, 'publish-error',
      describePublishError(error, branchPushed ? branch : undefined))
  }
}

function describePublishError (error: unknown, pushedBranch: string | undefined): string {
  const stderr = (error as { stderr?: unknown }).stderr
  const reported = typeof stderr === 'string' && stderr.trim() !== ''
    ? stderr.trim()
    : error instanceof Error ? error.message : String(error)

  if (pushedBranch === undefined) {
    return reported
  }
  return `${reported}\n\nBranch \`${pushedBranch}\` is pushed and holds the proposed change. ` +
    'No pull request was opened for it.'
}

export function runRemediationPublish (
  input: PublishInput,
  dependencies: PublishDependencies = defaultDependencies(input)
): boolean {
  const artifact = dependencies.readArtifact()

  if (artifact.kind === 'missing') {
    return reportFailure(dependencies, input.runLink, 'missing-artifact', '')
  }
  if (artifact.kind === 'failure') {
    return reportFailure(dependencies, input.runLink, artifact.failure.reason, artifact.failure.detail)
  }
  return publishProposal(input, dependencies, artifact.proposal, artifact.diff)
}

function main (): void {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const published = runRemediationPublish({
    repo,
    issueNumber: requireEnv('ISSUE_NUMBER'),
    runLink: workflowRunLink(repo),
    attempt: {
      runId: process.env.GITHUB_RUN_ID ?? 'local',
      runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? '1'
    }
  })
  if (!published) {
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
