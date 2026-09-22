/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `publish` job in .github/workflows/security-triage.yml.
//
// This job holds the workflow's write credentials and makes no model call. It reads the
// artifact the credential-free `remediate` job produced, applies the proposed diff to its own
// checkout of the base branch, and - only if nothing excluded was touched - commits, pushes
// and opens a draft pull request. Nothing from the proposed change is ever executed here:
// dependencies were installed from the base branch before the diff was read, and no script,
// test or build from the proposed tree is run. A proposed change therefore cannot alter or
// borrow the authority that publishes it (issue #31).
//
// Every outcome is reported on the originating issue, including the ones that open no pull
// request; an attempt that produced nothing never becomes an empty pull request.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

import { describeExcludedPaths, findExcludedPaths } from '../../excludedPaths'
import {
  readRemediationArtifact,
  REMEDIATION_OUTPUT_DIR,
  type RemediationArtifact,
  type RemediationFailureReason,
  type RemediationProposalArtifact
} from '../../remediationArtifact'
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
} from '../../remediationPr'

// Must match `models.claude` in security_triage_taskflow/configs/model_config.yaml; the
// pull request body states it as the AI disclosure. Asserted by modelConfig.unit.test.ts.
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
  /** Stages the proposed diff on a fresh branch; false when it does not apply. */
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
      // A fresh private directory per run, rather than a predictable name in the shared temp
      // directory: nothing else can pre-create or swap the file `gh --body-file` then reads.
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
  dependencies.commitAndPush(branch, remediationCommitMessage(artifact.alert))

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
    // Always a draft: no check on this change has been verified by anything, so it is never
    // presented as ready to merge (docs/agents/issue-tracker.md, PR compliance step 5).
    draft: true
  })

  dependencies.comment(buildSuccessComment({ prUrl, alert: artifact.alert, runLink }))
  return true
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
