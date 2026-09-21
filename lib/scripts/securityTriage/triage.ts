/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `triage` job in .github/workflows/security-triage.yml.
//
// Reads the alert number a human transcribed into the labelled issue, fetches the finding
// from the code-scanning API, and decides the verdict mechanically via `determineVerdict`
// against the checked-out base ref. The model call drafts only the prose explanation of a
// verdict that is already decided; it receives no tools, so its only possible output is the
// text of that paragraph. That is the narrowest reading of "the triage toolbox permits
// comment creation only" (docs/agents/security-triage.md,
// docs/adr/0004-triage-model-call-has-no-tools.md).
//
// The workflow itself performs every write (the comment and the label swap), with the
// `issues: write` permission the job holds; the model performs none.

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import process from 'node:process'

import { determineVerdict, type TriageResult } from '../../triageVerdict'
import { parseAlertNumber } from '../../parseAlertNumber'

const ANTHROPIC_MODEL = 'claude-sonnet-5'

interface AlertDetail {
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

async function draftReasoning (alert: AlertDetail, result: TriageResult): Promise<string> {
  const apiKey = requireEnv('ANTHROPIC_API_KEY')
  const brief = [
    `Rule: ${alert.ruleId}`,
    `Path: ${alert.path}`,
    `Scanner message: ${alert.message}`,
    `Verdict (already decided mechanically; do not restate a different one): ${result.verdict}`,
    `Snippet coupling: ${result.coupling.snippetCoupled}`,
    `Solve coupling: ${result.coupling.solveCoupled}`,
    `Test code: ${result.isTestCode}`
  ].join('\n')

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: 500,
      system: [
        'You write one short paragraph of prose for a security maintainer, explaining a triage',
        'verdict that has already been decided mechanically by the workflow. State the verdict',
        'and both coupling findings by name. Never claim a check passed, never grant a policy',
        'exception, and never state a verdict different from the one you were given. You have no',
        'tools available; your only output is this paragraph of plain text.'
      ].join(' '),
      messages: [{ role: 'user', content: brief }]
    })
  })

  if (!response.ok) {
    throw new Error(`Anthropic API request failed: ${response.status} ${await response.text()}`)
  }

  const body = await response.json() as { content: Array<{ type: string, text?: string }> }
  const text = body.content.find(block => block.type === 'text')?.text
  if (text === undefined) {
    throw new Error('Anthropic API response had no text content')
  }
  return text.trim()
}

function verdictSummary (alert: AlertDetail, result: TriageResult): string {
  return [
    `**Verdict: ${result.verdict}**`,
    '',
    `- Rule: \`${alert.ruleId}\``,
    `- Path: \`${alert.path}\``,
    `- Snippet coupling: ${result.coupling.snippetCoupled ? 'yes' : 'no'}`,
    `- Solve coupling: ${result.coupling.solveCoupled ? 'yes' : 'no'}`,
    `- Test code: ${result.isTestCode ? 'yes' : 'no'}`
  ].join('\n')
}

async function main (): Promise<void> {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const issueNumber = requireEnv('ISSUE_NUMBER')
  const issueBody = process.env.ISSUE_BODY ?? ''

  const alertNumber = parseAlertNumber(issueBody)
  if (alertNumber === undefined) {
    gh([
      'issue', 'comment', issueNumber, '--repo', repo, '--body',
      'Triage could not find an alert reference in this issue body (expected text such as ' +
      '`alert #6`). No verdict was recorded; `sec:needs-triage` is unchanged.'
    ])
    process.exitCode = 1
    return
  }

  const alert = fetchAlertDetail(repo, alertNumber)
  const result = determineVerdict(alert.path, readBaseRefFile)
  const reasoning = await draftReasoning(alert, result)

  const comment = `${verdictSummary(alert, result)}\n\n${reasoning}`
  gh(['issue', 'comment', issueNumber, '--repo', repo, '--body', comment])
  gh([
    'issue', 'edit', issueNumber, '--repo', repo,
    '--add-label', 'sec:triaged',
    '--remove-label', 'sec:needs-triage'
  ])
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
