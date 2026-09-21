/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `gate` job in .github/workflows/security-triage.yml.
//
// This is the refusal half of the patch gate (issue #8). It runs in the gate job's own
// checkout of the base ref, which the patch author cannot write to, and holds the job's
// write credentials; it makes no model call. It reads the target path from the code-scanning
// API keyed by the alert number, never from the issue body, and delegates the entire
// authorization decision to `decidePatchGate`, which itself reads coupling markers and the
// allow-list override from the base ref. On refusal it posts the reason as a comment and
// applies `sec:nopatch`; a human removes that label after reading it. On an authorized diff
// it stops here and says so: applying the diff, running checks, and opening a pull request
// are issue #9.

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import process from 'node:process'

import { decidePatchGate, describeGateRefusal } from '../../patchGate'
import { parseAlertNumber } from '../../parseAlertNumber'

const NOPATCH_LABEL = 'sec:nopatch'

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

function readBaseRefFile (path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return undefined
  }
}

function readProposedDiff (path: string): string {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    throw new Error(`Could not read the proposed patch at ${path}; the remediate job's artifact must be downloaded first.`)
  }
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
  const diff = readProposedDiff(proposedPatchPath)
  const decision = decidePatchGate(alert.path, diff, readBaseRefFile)

  if (!decision.allowed) {
    const comment = [
      `**Refused** (\`${decision.reason}\`)`,
      '',
      describeGateRefusal(decision.reason),
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
    return
  }

  console.log(
    `Alert #${alertNumber}: the proposed diff for ${alert.path} is authorized. ` +
    'The allow path is not yet wired (issue #9): no checks ran and no pull request was opened.'
  )
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
