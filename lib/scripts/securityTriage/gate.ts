/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `gate` job in .github/workflows/security-triage.yml.
//
// This is the full patch gate (issues #8 and #9). It runs in the gate job's own checkout of
// the base ref, which the patch author cannot write to, and holds the job's write
// credentials; it makes no model call. It reads the target path from the code-scanning API
// keyed by the alert number, never from the issue body, selects the trusted verdict the
// `triage` job posted, and delegates the entire decision - authorization, the regression
// baseline, check results, commit identity and PR metadata - to `decideGateOutcome`. On
// refusal it posts the reason as a comment and applies `sec:nopatch`; a human removes that
// label after reading it. On an authorized diff it applies the diff, runs the gate checks,
// and opens the pull request.

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'

import { computeAllowList } from '../../authorizePatch'
import { createBaseRefReader } from '../../baseRefReader'
import { parseAlertNumber } from '../../parseAlertNumber'
import { decideGateOutcome, describeOutcomeRefusal, type GateOutcome } from '../../patchGate'
import type { CheckResult } from '../../gateChecks'
import { GATE_COMMIT_IDENTITY } from '../../prCompliance'
import { buildPrBody, buildPrTitle } from '../../prBody'
import { parseNodeTestOutput, REGRESSION_TEST_PATH } from '../../regressionBaseline'
import type { IssueComment } from '../../trustedVerdict'

const NOPATCH_LABEL = 'sec:nopatch'
const REGRESSION_COMMAND = [
  'node', '--import', './test/server/helpers/test-env.mjs', '--import', 'tsx',
  '--test', '--test-force-exit', REGRESSION_TEST_PATH
]

interface AlertDetail {
  ruleId: string
  path: string
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

function fetchAlertDetail (repo: string, alertNumber: number): AlertDetail {
  const raw = gh(['api', `repos/${repo}/code-scanning/alerts/${alertNumber}`])
  const alert = JSON.parse(raw) as {
    rule: { id: string }
    most_recent_instance: { location: { path: string } }
  }
  return { ruleId: alert.rule.id, path: alert.most_recent_instance.location.path }
}

function readProposedDiff (path: string): string {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    throw new Error(`Could not read the proposed patch at ${path}; the remediate job's artifact must be downloaded first.`)
  }
}

async function fetchIssueComments (repo: string, issueNumber: string): Promise<IssueComment[]> {
  // Unauthenticated read of the issue's public comments, matching how the credential-free
  // `remediate` job saw them, so both jobs agree on which comment is "the" verdict
  // independent of what this job's own token can additionally do.
  const response = await fetch(`https://api.github.com/repos/${repo}/issues/${issueNumber}/comments`, {
    headers: { accept: 'application/vnd.github+json' }
  })
  if (!response.ok) {
    throw new Error(`Reading issue comments failed: ${response.status} ${await response.text()}`)
  }
  const comments = await response.json() as unknown
  return Array.isArray(comments) ? comments as IssueComment[] : []
}

function runGit (args: string[], cwd?: string): string | undefined {
  try {
    return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, cwd, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return undefined
  }
}

function headCommit (): string {
  const head = runGit(['rev-parse', 'HEAD'])?.trim()
  if (head === undefined || !/^[0-9a-f]{40}$/.test(head)) {
    throw new Error('Could not resolve the checked-out base commit.')
  }
  return head
}

/** Runs a command, capturing stdout/stderr on both success and failure; never throws. */
function runCommand (name: CheckResult['name'], command: string, argv: string[], cwd: string): CheckResult {
  const label = `${command} ${argv.join(' ')}`.trim()
  try {
    const output = execFileSync(command, argv, { encoding: 'utf8', cwd, maxBuffer: 32 * 1024 * 1024 })
    return { name, command: label, passed: true, output }
  } catch (error) {
    const output = (error as { stdout?: string, stderr?: string }).stdout ?? (error as { stderr?: string }).stderr ?? String(error)
    return { name, command: label, passed: false, output }
  }
}

function runRegression (cwd: string): { result: CheckResult, summary: ReturnType<typeof parseNodeTestOutput> } {
  const [command, ...argv] = REGRESSION_COMMAND
  const result = runCommand('regression', command, argv, cwd)
  return { result, summary: parseNodeTestOutput(result.output ?? '') }
}

function applyDiff (cwd: string, diffText: string): boolean {
  try {
    execFileSync('git', ['apply', '--whitespace=nowarn', '-'], { cwd, input: diffText, encoding: 'utf8' })
    return true
  } catch {
    return false
  }
}

function commitTrailerOf (cwd: string, ref: string): string {
  return runGit(['show', '-s', '--format=%an%n%ae%n%B', ref], cwd) ?? ''
}

async function main (): Promise<void> {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const issueNumber = requireEnv('ISSUE_NUMBER')
  const issueBody = process.env.ISSUE_BODY ?? ''
  const proposedPatchPath = process.env.PROPOSED_PATCH_PATH ?? 'patch-author-output/proposed.patch'

  const alertNumber = parseAlertNumber(issueBody)
  if (alertNumber === undefined) {
    gh([
      'issue', 'comment', issueNumber, '--repo', repo, '--body',
      'The gate could not find an alert reference in this issue body (expected text such as ' +
      '`alert #6`). No authorization decision was made.'
    ])
    process.exitCode = 1
    return
  }

  const alert = fetchAlertDetail(repo, alertNumber)
  const proposedDiff = readProposedDiff(proposedPatchPath)
  const baseCommit = headCommit()
  const readBaseRef = createBaseRefReader(baseCommit, (args) => runGit(args))
  const comments = await fetchIssueComments(repo, issueNumber)
  const regressionDiff = readBaseRef(`docs/agents/artifacts/alert-${alertNumber}-regression.patch`)

  let outcome: GateOutcome
  let worktreeDir: string | undefined

  try {
    worktreeDir = mkdtempSync(join(tmpdir(), 'patch-gate-'))
    rmSync(worktreeDir, { recursive: true, force: true })
    execFileSync('git', ['worktree', 'add', '--detach', worktreeDir, baseCommit], { encoding: 'utf8' })
    runGit(['config', 'user.name', GATE_COMMIT_IDENTITY.name], worktreeDir)
    runGit(['config', 'user.email', GATE_COMMIT_IDENTITY.email], worktreeDir)
    execFileSync('ln', ['-s', resolve('node_modules'), join(worktreeDir, 'node_modules')])

    const baselinePre = regressionDiff !== undefined && applyDiff(worktreeDir, regressionDiff)
      ? runRegression(worktreeDir).summary
      : { passed: [], failed: [], errored: true }

    // Reset the worktree before applying the combined diff, so phase 2 starts clean.
    runGit(['checkout', '--', '.'], worktreeDir)
    runGit(['clean', '-fd', '--', REGRESSION_TEST_PATH], worktreeDir)

    const finalDiff = regressionDiff !== undefined ? `${regressionDiff}\n${proposedDiff}` : proposedDiff
    const combinedApplied = regressionDiff !== undefined && applyDiff(worktreeDir, regressionDiff) && applyDiff(worktreeDir, proposedDiff)

    const checkResults: CheckResult[] = []
    let baselinePost = { passed: [] as string[], failed: [] as string[], errored: true }
    if (combinedApplied) {
      const regressionRun = runRegression(worktreeDir)
      checkResults.push(regressionRun.result)
      baselinePost = regressionRun.summary

      const allowList = computeAllowList(alert.path, alertNumber, readBaseRef)
      checkResults.push(runCommand('typecheck', 'npx', ['tsc', '--noEmit'], worktreeDir))
      checkResults.push(runCommand('lint', 'npx', ['eslint', ...allowList.paths], worktreeDir))
      checkResults.push(runCommand('test:server', 'npm', ['run', 'test:server'], worktreeDir))
      checkResults.push(runCommand('test:api', 'npm', ['run', 'test:api'], worktreeDir))
    } else {
      checkResults.push({ name: 'regression', command: REGRESSION_COMMAND.join(' '), passed: false, output: 'Could not apply the regression and proposed diffs together.' })
    }

    // Commit the combined diff on a disposable branch inside the worktree so its own commit
    // metadata (author/committer/trailer) can be inspected before anything is pushed.
    let commits: Array<{ authorName: string, authorEmail: string, trailer: string }> = []
    if (combinedApplied) {
      execFileSync('git', ['add', '-A'], { cwd: worktreeDir })
      try {
        execFileSync('git', [
          'commit', '-s', '-m',
          `fix(security): remediate ${alert.ruleId} at ${alert.path} (alert #${alertNumber})`
        ], { cwd: worktreeDir, encoding: 'utf8' })
        const raw = commitTrailerOf(worktreeDir, 'HEAD')
        const [authorName, authorEmail, ...rest] = raw.split('\n')
        commits = [{ authorName: authorName ?? '', authorEmail: authorEmail ?? '', trailer: rest.join('\n') }]
      } catch {
        // No commit means nothing to authorize; a manifestly unauthorized placeholder record
        // forces the identity check to refuse rather than pass vacuously over an empty list.
        commits = [{ authorName: '', authorEmail: '', trailer: '' }]
      }
    }

    outcome = decideGateOutcome({
      repo,
      alertNumber,
      alert,
      issueNumber: Number(issueNumber),
      baseCommit,
      readBaseRef,
      comments,
      proposedDiff,
      regressionDiff,
      finalDiff,
      commits,
      checkResults,
      baselinePreSummary: baselinePre,
      baselinePostSummary: baselinePost,
      aiDisclosure: { models: ['claude-sonnet-5'], instructionsKnown: true }
    })

    if (outcome.allowed) {
      // Replay the same commit onto the live checkout (the one with push credentials), never
      // pushing directly from the worktree.
      const branchName = `security/alert-${alertNumber}-${baseCommit.slice(0, 12)}`
      execFileSync('git', ['checkout', '-b', branchName], { encoding: 'utf8' })
      if (!applyDiff('.', finalDiff)) {
        throw new Error('The authorized diff applied cleanly in the validation worktree but not in the live checkout.')
      }
      execFileSync('git', ['add', '-A'], { encoding: 'utf8' })
      execFileSync('git', [
        'commit', '-s', '-m', `fix(security): remediate ${alert.ruleId} at ${alert.path} (alert #${alertNumber})`
      ], {
        encoding: 'utf8',
        env: {
          ...process.env,
          GIT_AUTHOR_NAME: GATE_COMMIT_IDENTITY.name,
          GIT_AUTHOR_EMAIL: GATE_COMMIT_IDENTITY.email,
          GIT_COMMITTER_NAME: GATE_COMMIT_IDENTITY.name,
          GIT_COMMITTER_EMAIL: GATE_COMMIT_IDENTITY.email
        }
      })
      execFileSync('git', ['push', 'origin', branchName], { encoding: 'utf8' })

      const bodyPath = join(worktreeDir, '..', `pr-body-${issueNumber}.md`)
      writeFileSync(bodyPath, buildPrBody(outcome.prMetadata, true))

      const prUrl = gh([
        'pr', 'create',
        '--repo', outcome.prMetadata.destination.repo,
        '--base', outcome.prMetadata.destination.base,
        '--head', branchName,
        '--title', buildPrTitle(outcome.prMetadata),
        '--body-file', bodyPath
      ]).trim()

      gh([
        'issue', 'comment', issueNumber, '--repo', repo, '--body',
        `Opened ${prUrl} for alert #${alertNumber} (\`${alert.ruleId}\`) at \`${alert.path}\`.`
      ])
    }
  } finally {
    if (worktreeDir !== undefined) {
      try {
        execFileSync('git', ['worktree', 'remove', '--force', worktreeDir])
      } catch {
        rmSync(worktreeDir, { recursive: true, force: true })
      }
    }
  }

  if (!outcome.allowed) {
    const comment = [
      `**Refused** (\`${outcome.reason}\`)`,
      '',
      describeOutcomeRefusal(outcome.reason),
      '',
      `- Alert: \`${alert.ruleId}\` #${alertNumber}`,
      `- Target: \`${alert.path}\``,
      '',
      'Refusal is terminal: retry-with-feedback exists but is disabled, so a second attempt ' +
      'cannot quietly succeed and conceal that this one was refused. A human should remove ' +
      `\`${NOPATCH_LABEL}\` only after reading this reason.`
    ].join('\n')

    gh(['issue', 'comment', issueNumber, '--repo', repo, '--body', comment])
    gh(['issue', 'edit', issueNumber, '--repo', repo, '--add-label', NOPATCH_LABEL])
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
