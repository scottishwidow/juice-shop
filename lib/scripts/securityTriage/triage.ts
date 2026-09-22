/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `triage` job in .github/workflows/security-triage.yml.
//
// Reads the one code-scanning alert URL a human pasted into the labelled issue, fetches the
// finding from the code-scanning API, and runs the TaskFlow agent (security_triage_taskflow/)
// to investigate the checked-out base ref and derive a verdict - confirmed, not-applicable, or
// inconclusive (docs/adr/0007-taskflow-security-workflows.md,
// docs/adr/0009-taskflow-triage-implementation.md). Deterministic mechanical coupling markers
// no longer decide the verdict; they are read only as investigative context and informational
// payload evidence (lib/couplingEvidence.ts).
//
// The workflow script itself performs every write (the comment and the label swap), with the
// job's own `issues: write` permission; the model performs none - its output is read back from
// the TaskFlow run's own manifest.json artifact after the process exits, never trusted from a
// shell step templated with agent-produced text (see security_triage_taskflow/taskflows/
// triage.yaml for why `capture: response` plus that file read is the safe mechanism here).

import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync, mkdtempSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

import { parseAlertUrl, describeAlertUrlFailure } from '../../parseAlertUrl'
import { computeCouplingEvidence } from '../../couplingEvidence'
import { encodeVerdictPayload, type VerdictPayload } from '../../verdictPayload'
import { parseTaskflowVerdict, describeTaskflowVerdictFailure, type TaskflowVerdict } from '../../taskflowVerdict'

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

function workflowRunLink (repo: string): string {
  const serverUrl = process.env.GITHUB_SERVER_URL ?? 'https://github.com'
  const runId = process.env.GITHUB_RUN_ID
  return runId === undefined ? '' : `${serverUrl}/${repo}/actions/runs/${runId}`
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

function baseCommit (): string {
  return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
}

type TaskflowRunOutcome =
  | { ok: true, verdict: TaskflowVerdict }
  | { ok: false, reason: string }

/**
 * Runs the triage taskflow against the checked-out base ref and reads its structured verdict
 * back from the run's own manifest.json artifact - never by templating agent-produced text
 * into a further shell step (see security_triage_taskflow/taskflows/triage.yaml).
 */
function runTaskflow (alert: AlertDetail, alertNumber: number): TaskflowRunOutcome {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'security-triage-taskflow-'))

  const result = spawnSync('python3', [
    '-m', 'seclab_taskflow_agent',
    '-t', 'security_triage_taskflow.taskflows.triage',
    '-m', 'security_triage_taskflow.configs.model_config',
    '-g', `alert_number=${alertNumber}`,
    '-g', `rule_id=${alert.ruleId}`,
    '-g', `path=${alert.path}`,
    '-g', `message=${alert.message}`
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

  const artifactsRoot = path.join(dataDir, 'seclab-taskflow-agent', 'artifacts')
  const manifest = readManifest(artifactsRoot)
  const outcome = parseTaskflowVerdict(manifest?.outputs?.investigate)
  if (!outcome.ok) {
    return { ok: false, reason: describeTaskflowVerdictFailure(outcome.reason) }
  }
  return { ok: true, verdict: outcome.verdict }
}

interface RunManifest {
  outputs?: Record<string, unknown>
}

function readManifest (artifactsRoot: string): RunManifest | undefined {
  if (!existsSync(artifactsRoot)) {
    return undefined
  }
  const sessions = readdirSync(artifactsRoot)
  const sessionId = sessions[0]
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

function verdictSummary (alert: AlertDetail, alertNumber: number, base: string, verdict: TaskflowVerdict): string {
  return [
    `**Verdict: ${verdict.verdict}**`,
    '',
    `- Alert: #${alertNumber}`,
    `- Base: \`${base}\``,
    `- Rule: \`${alert.ruleId}\``,
    `- Path: \`${alert.path}\``
  ].join('\n')
}

function evidenceList (verdict: TaskflowVerdict): string {
  if (verdict.evidence.length === 0) {
    return ''
  }
  return ['', '**Evidence:**', ...verdict.evidence.map(item => `- \`${item.file}\`: ${item.note}`)].join('\n')
}

async function main (): Promise<void> {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const issueNumber = requireEnv('ISSUE_NUMBER')
  const issueBody = process.env.ISSUE_BODY ?? ''
  const runLink = workflowRunLink(repo)

  const parsedAlert = parseAlertUrl(issueBody, repo)
  if (!parsedAlert.ok) {
    const suffix = runLink === '' ? '' : `\n\nWorkflow run: ${runLink}`
    gh([
      'issue', 'comment', issueNumber, '--repo', repo, '--body',
      `${describeAlertUrlFailure(parsedAlert.reason)} No verdict was recorded; ` +
      `\`sec:needs-triage\` is unchanged.${suffix}`
    ])
    process.exitCode = 1
    return
  }

  const alertNumber = parsedAlert.alert.alertNumber
  const alert = fetchAlertDetail(repo, alertNumber)
  const evidence = computeCouplingEvidence(alert.path, readBaseRefFile)
  const base = baseCommit()

  const outcome = runTaskflow(alert, alertNumber)
  if (!outcome.ok) {
    const suffix = runLink === '' ? '' : `\n\nWorkflow run: ${runLink}`
    gh([
      'issue', 'comment', issueNumber, '--repo', repo, '--body',
      `Triage execution failed for alert #${alertNumber}: ${outcome.reason} No verdict was ` +
      `recorded; \`sec:needs-triage\` is unchanged.${suffix}`
    ])
    process.exitCode = 1
    return
  }

  const payload: VerdictPayload = {
    alertNumber,
    baseCommit: base,
    ruleId: alert.ruleId,
    path: alert.path,
    verdict: outcome.verdict.verdict,
    snippetCoupled: evidence.snippetCoupled,
    solveCoupled: evidence.solveCoupled,
    isTestCode: evidence.isTestCode,
    reasoning: outcome.verdict.reasoning,
    evidence: outcome.verdict.evidence
  }

  const comment = [
    verdictSummary(alert, alertNumber, base, outcome.verdict),
    '',
    outcome.verdict.reasoning,
    evidenceList(outcome.verdict),
    '',
    encodeVerdictPayload(payload)
  ].join('\n')

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
