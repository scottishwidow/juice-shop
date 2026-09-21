/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `gate` job in .github/workflows/security-triage.yml.
//
// This is the full patch gate (issues #8 and #9). It runs in the gate job's own checkout of
// the base ref, which the patch author cannot write to, and holds the job's write
// credentials; it makes no model call. It reads the target path from the code-scanning API
// keyed by the alert number, never from the issue body, reads the issue's comments in full
// with its own token (issue #16), selects the trusted verdict the `triage` job posted, and
// delegates the entire decision - authorization, the regression baseline, check results,
// commit identity and PR metadata - to `decideGateOutcome`. On refusal it posts the reason as
// a comment and applies `sec:nopatch`; a human removes that label after reading it. On an
// authorized diff it applies the diff, runs the gate checks, and opens the pull request.

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import process from 'node:process'

import { computeAllowList } from '../../authorizePatch'
import { createBaseRefReader } from '../../baseRefReader'
import { fetchIssueCommentsAuthenticated } from '../../issueComments'
import { parseAlertNumber } from '../../parseAlertNumber'
import { decideGateOutcome, describeOutcomeRefusal, type GateOutcome } from '../../patchGate'
import { allChecksPassed, type CheckResult } from '../../gateChecks'
import { affirmationSatisfied, everyCommitAuthorizedAndSignedOff, GATE_COMMIT_IDENTITY, type CommitRecord } from '../../prCompliance'
import { buildPrBody, buildPrTitle } from '../../prBody'
import { parseNodeTestOutput, REGRESSION_TEST_PATH } from '../../regressionBaseline'
import { describeRemediationRefusal, readRemediationRefusal, type RemediationRefusalReason } from '../../remediationRefusal'

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

function buildPatchAuthorRefusalComment (alert: AlertDetail, alertNumber: number, reason: RemediationRefusalReason): string {
  return [
    `**Patch author refused** (\`${reason}\`)`,
    '',
    describeRemediationRefusal(reason),
    '',
    `- Alert: \`${alert.ruleId}\` #${alertNumber}`,
    `- Target: \`${alert.path}\``,
    '',
    'Refusal is terminal: a second attempt is never made automatically, so it cannot ' +
    'quietly succeed and conceal that this one was refused. A human should remove ' +
    `\`${NOPATCH_LABEL}\` only after reading this reason.`
  ].join('\n')
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

  // The `remediate` job holds `permissions: {}` and cannot post its own refusal reason
  // (issue #15); it writes one to this same artifact directory instead, and this job - which
  // already holds `issues: write` - reports it here, before any patch is applied or checked.
  const patchAuthorRefusal = readRemediationRefusal(dirname(proposedPatchPath))
  if (patchAuthorRefusal !== undefined) {
    gh(['issue', 'comment', issueNumber, '--repo', repo, '--body',
      buildPatchAuthorRefusalComment(alert, alertNumber, patchAuthorRefusal.reason)])
    gh(['issue', 'edit', issueNumber, '--repo', repo, '--add-label', NOPATCH_LABEL])
    process.exitCode = 1
    return
  }

  let proposedDiff: string
  try {
    proposedDiff = readProposedDiff(proposedPatchPath)
  } catch {
    // Neither a refusal reason nor a proposal was produced: the job likely crashed before
    // writing anything. Still terminal, still reported - a base-commit mismatch between the
    // two jobs' checkouts is the most likely mundane cause; re-running triage clears it.
    gh(['issue', 'comment', issueNumber, '--repo', repo, '--body', [
      '**Patch author produced no output**',
      '',
      'Neither a proposed patch nor a categorized refusal reason was found for this alert. ' +
      'The most likely cause is a base-commit mismatch between the `remediate` and `gate` ' +
      'checkouts (a push landed between triage and this label); re-run triage and reapply ' +
      'the label. Otherwise, check the `remediate` job log.',
      '',
      `- Alert: \`${alert.ruleId}\` #${alertNumber}`,
      `- Target: \`${alert.path}\``
    ].join('\n')])
    gh(['issue', 'edit', issueNumber, '--repo', repo, '--add-label', NOPATCH_LABEL])
    process.exitCode = 1
    return
  }

  const baseCommit = headCommit()
  const readBaseRef = createBaseRefReader(baseCommit, (args) => runGit(args))
  // This job holds the workflow's write credentials for every other call it makes; reading
  // comments with the same token, instead of anonymously like the credential-free `remediate`
  // job must, spends its own per-job quota rather than the shared per-runner unauthenticated
  // one (issue #16).
  const comments = await fetchIssueCommentsAuthenticated(repo, issueNumber, requireEnv('GH_TOKEN'))
  const regressionDiff = readBaseRef(`docs/agents/artifacts/alert-${alertNumber}-regression.patch`)

  let outcome: GateOutcome
  let worktreeDir: string | undefined

  try {
    worktreeDir = mkdtempSync(join(tmpdir(), 'patch-gate-'))
    rmSync(worktreeDir, { recursive: true, force: true })
    execFileSync('git', ['worktree', 'add', '--detach', worktreeDir, baseCommit], { encoding: 'utf8' })
    execFileSync('ln', ['-s', resolve('node_modules'), join(worktreeDir, 'node_modules')])

    const baselinePre = regressionDiff !== undefined && applyDiff(worktreeDir, regressionDiff)
      ? runRegression(worktreeDir).summary
      : { passed: [], failed: [], errored: true }

    // Reset the worktree before applying the combined diff, so phase 2 starts clean.
    runGit(['checkout', '--', '.'], worktreeDir)
    runGit(['clean', '-fd', '--', REGRESSION_TEST_PATH], worktreeDir)

    const combinedApplied = regressionDiff !== undefined && applyDiff(worktreeDir, regressionDiff) && applyDiff(worktreeDir, proposedDiff)

    // Stage everything the two diffs actually produced in this worktree, so `git diff` below
    // reports the real tree - added files included - rather than only tracked-file edits.
    if (combinedApplied) {
      execFileSync('git', ['add', '-A'], { cwd: worktreeDir })
    }

    // What decideGateOutcome checks against "regression + proposal" is the tree the two diffs
    // actually produced when applied to a clean checkout of the base commit, not a string this
    // script composed by concatenation: an unexpected side effect of applying them - a stray
    // file, a fuzzy-matched hunk landing somewhere unintended - is visible here instead of
    // trivially passing (issue #17).
    const finalDiff = combinedApplied
      ? (runGit(['diff', baseCommit], worktreeDir) ?? '')
      : (regressionDiff !== undefined ? `${regressionDiff}\n${proposedDiff}` : proposedDiff)

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

    // The identity every commit the gate makes carries is set directly, never re-derived: the
    // gate never authors a commit under any identity but its own (the real commit below sets
    // GIT_AUTHOR_NAME/EMAIL to the same constant), so there is nothing to read back and
    // compare (issue #17). An empty list when nothing applied leaves nothing to authorize.
    const commits: CommitRecord[] = combinedApplied
      ? [{
          authorName: GATE_COMMIT_IDENTITY.name,
          authorEmail: GATE_COMMIT_IDENTITY.email,
          trailer: `Signed-off-by: ${GATE_COMMIT_IDENTITY.name} <${GATE_COMMIT_IDENTITY.email}>`
        }]
      : []

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
      // Apply the same authorized diff to the live checkout (the one with push credentials),
      // never pushing directly from the validation worktree.
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

      const affirmationChecked = affirmationSatisfied(
        outcome.prMetadata,
        allChecksPassed(checkResults),
        everyCommitAuthorizedAndSignedOff(commits).ok
      )
      const bodyPath = join(worktreeDir, '..', `pr-body-${issueNumber}.md`)
      writeFileSync(bodyPath, buildPrBody(outcome.prMetadata, affirmationChecked))

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
      'Refusal is terminal: a second attempt is never made automatically, so it cannot ' +
      'quietly succeed and conceal that this one was refused. A human should remove ' +
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
