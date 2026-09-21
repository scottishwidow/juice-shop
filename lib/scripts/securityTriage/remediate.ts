/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// CLI script run by the `remediate` job in .github/workflows/security-triage.yml.
//
// Holds `permissions: {}` (issue #7, ADR-0002): it makes no authenticated GitHub API call and
// its checkout uses `persist-credentials: false`, so no credential of any kind ever reaches
// this job. It reads the verdict the `triage` job already posted (an unauthenticated read of
// public issue comments), reads the allow-list and target file from the checked-out base ref,
// and proposes a diff. The diff is the only thing this job can produce, and it goes to a
// workflow artifact, never to a comment, label, commit or pull request.
//
// Because the comment read is unauthenticated, anyone can write a comment this job sees. Only
// `selectTrustedVerdict` decides which one it acts on, and every file it reads afterwards is
// a tracked file of the pinned base commit read through `createBaseRefReader` (ADR-0005).

import { execFileSync } from 'node:child_process'
import process from 'node:process'

import { computeAllowList, type BaseRefReader } from '../../authorizePatch'
import { createBaseRefReader } from '../../baseRefReader'
import { readRemediationTests, writeRemediationArtifacts } from '../../remediationFiles'
import { parseAlertNumber } from '../../parseAlertNumber'
import { parseProposedPatch, PROPOSE_PATCH_TOOL_NAME, type ProposedPatch } from '../../proposedPatch'
import { RemediationRefusal, writeRemediationRefusal } from '../../remediationRefusal'
import { selectTrustedVerdict, type IssueComment } from '../../trustedVerdict'
import {
  buildRemediationBrief,
  extractCodeStyleRule,
  extractComplianceInstructions,
  findCoveringTests
} from '../../remediationBrief'

const ANTHROPIC_MODEL = 'claude-sonnet-5'
const OUTPUT_DIR = 'patch-author-output'

function requireEnv (name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`)
  }
  return value
}

function runGit (args: string[]): string | undefined {
  try {
    return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] })
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

async function fetchIssueComments (repo: string, issueNumber: string): Promise<IssueComment[]> {
  // Unauthenticated read of a public issue's comments. This job declares no permissions, so
  // no GitHub token is used here; public issue comments do not require one.
  const response = await fetch(`https://api.github.com/repos/${repo}/issues/${issueNumber}/comments`, {
    headers: { accept: 'application/vnd.github+json' }
  })
  if (!response.ok) {
    throw new Error(`Reading issue comments failed: ${response.status} ${await response.text()}`)
  }
  const comments = await response.json() as unknown
  return Array.isArray(comments) ? comments as IssueComment[] : []
}

async function proposePatch (brief: string): Promise<ProposedPatch> {
  const apiKey = requireEnv('ANTHROPIC_API_KEY')

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    redirect: 'error',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: 4000,
      system: [
        'You propose a single unified diff that remediates one security finding, working',
        'strictly inside the allow-list given to you. You hold no credentials and cannot push,',
        'comment, label, or open a pull request; your only output is the `propose_patch` tool',
        'call. Touch no path outside the allow-list, including the override file. Never add an',
        'eslint-disable, @ts-ignore or @ts-expect-error suppression. Never edit a test file;',
        'the tests given to you state a contract your fix must satisfy, not one you may change.',
        'Follow the code style rule given to you. If you cannot produce a diff that satisfies',
        'every constraint, call the tool with an empty diff and explain why in the summary.'
      ].join(' '),
      tools: [{
        name: PROPOSE_PATCH_TOOL_NAME,
        description: 'Submit the proposed remediation as a unified diff, with a short summary of the change.',
        input_schema: {
          type: 'object',
          properties: {
            diff: { type: 'string', description: 'A unified diff (git format) touching only allow-listed paths.' },
            summary: { type: 'string', description: 'One short paragraph describing the change and why it satisfies the brief.' }
          },
          required: ['diff', 'summary']
        }
      }],
      tool_choice: { type: 'tool', name: PROPOSE_PATCH_TOOL_NAME },
      messages: [{ role: 'user', content: brief }]
    })
  })

  if (!response.ok) {
    throw new Error(`Anthropic API request failed: ${response.status} ${await response.text()}`)
  }

  const result = parseProposedPatch(await response.json())
  if (!result.valid) {
    throw new RemediationRefusal(result.reason, `Nothing was written: ${result.reason}`)
  }
  return result.patch
}

function readRequiredPolicy (readBaseRef: BaseRefReader, path: string, extract: (doc: string) => string | undefined, description: string): string {
  const doc = readBaseRef(path)
  const extracted = doc !== undefined ? extract(doc) : undefined
  if (extracted === undefined) {
    throw new RemediationRefusal('required-policy-unreadable', `Could not read ${description} from ${path} on the base ref.`)
  }
  return extracted
}

async function run (): Promise<void> {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const issueNumber = requireEnv('ISSUE_NUMBER')
  const issueBody = process.env.ISSUE_BODY ?? ''

  const alertNumber = parseAlertNumber(issueBody)
  if (alertNumber === undefined) {
    throw new RemediationRefusal('no-alert-reference', 'Could not find an alert reference in this issue body (expected text such as `alert #6`).')
  }

  const baseCommit = headCommit()
  const readBaseRef = createBaseRefReader(baseCommit, runGit)

  const selection = selectTrustedVerdict(await fetchIssueComments(repo, issueNumber), { alertNumber, baseCommit })
  if (!selection.selected) {
    throw new RemediationRefusal(selection.reason, `No remediation target was selected: ${selection.reason}`)
  }
  const verdict = selection.verdict
  if (verdict.isTestCode) {
    throw new RemediationRefusal('test-code-not-applicable', 'The triaged finding is test code (not-applicable); remediation does not apply.')
  }

  const targetContent = readBaseRef(verdict.path)
  if (targetContent === undefined) {
    throw new RemediationRefusal('target-unreadable', `\`${verdict.path}\` is not a readable tracked file at base commit ${baseCommit}.`)
  }

  const allowList = computeAllowList(verdict.path, alertNumber, readBaseRef)
  const codeStyleRule = readRequiredPolicy(readBaseRef, 'CONTRIBUTING.md', extractCodeStyleRule, 'the code style rule')
  const complianceInstructions = readRequiredPolicy(
    readBaseRef,
    'docs/agents/security-triage.md',
    doc => extractComplianceInstructions(doc, 'Patch author (#7)'),
    "the patch author's compliance row"
  )

  const allTestFiles = readRemediationTests(baseCommit, runGit)
  const coveringTestPaths = findCoveringTests(verdict.path, allTestFiles)
  const coveringTests: Record<string, string> = {}
  for (const path of coveringTestPaths) {
    coveringTests[path] = allTestFiles[path]
  }

  const regressionArtifactPath = `docs/agents/artifacts/alert-${alertNumber}-regression.patch`
  const regressionArtifactContent = readBaseRef(regressionArtifactPath)
  const regressionArtifact = regressionArtifactContent !== undefined
    ? { path: regressionArtifactPath, content: regressionArtifactContent }
    : undefined

  const brief = buildRemediationBrief({
    alertNumber,
    verdict,
    targetContent,
    allowList,
    codeStyleRule,
    complianceInstructions,
    coveringTests,
    regressionArtifact
  })

  const proposal = await proposePatch(brief)

  writeRemediationArtifacts(OUTPUT_DIR, brief, proposal)

  console.log(`Wrote proposal for alert #${alertNumber} at base ${baseCommit} to ${OUTPUT_DIR}/`)
}

// Every refusal, categorized or not, is written to the artifact the credential-free job
// already uploads: the gate job holds `issues: write` and reports it (issue #15). The job
// still exits non-zero so a refusal stays visible in the Actions run itself.
async function main (): Promise<void> {
  try {
    await run()
  } catch (error) {
    const reason = error instanceof RemediationRefusal ? error.reason : 'unexpected-error'
    writeRemediationRefusal(OUTPUT_DIR, reason)
    console.error(error)
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
