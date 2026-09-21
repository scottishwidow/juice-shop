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

import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'

import { computeAllowList } from '../../authorizePatch'
import { parseAlertNumber } from '../../parseAlertNumber'
import {
  buildRemediationBrief,
  extractCodeStyleRule,
  extractComplianceInstructions,
  findCoveringTests,
  parseVerdictComment
} from '../../remediationBrief'

const ANTHROPIC_MODEL = 'claude-sonnet-5'
const OUTPUT_DIR = 'patch-author-output'
const TEST_DIRECTORIES = ['test/server', 'test/api']

function requireEnv (name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`)
  }
  return value
}

function readBaseRefFile (path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return undefined
  }
}

function readTestFiles (): Record<string, string> {
  const files: Record<string, string> = {}
  for (const dir of TEST_DIRECTORIES) {
    for (const entry of readTestFilesIn(dir)) {
      files[entry] = readFileSync(entry, 'utf8')
    }
  }
  return files
}

function readTestFilesIn (dir: string): string[] {
  let entries: Array<{ name: string, isDirectory: () => boolean }>
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return []
  }
  const files: string[] = []
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...readTestFilesIn(path))
    } else if (entry.name.endsWith('.test.ts')) {
      files.push(path)
    }
  }
  return files
}

async function fetchLatestVerdictComment (repo: string, issueNumber: string): Promise<string> {
  // Unauthenticated read of a public issue's comments. This job declares no permissions, so
  // no GitHub token is used here; public issue comments do not require one.
  const response = await fetch(`https://api.github.com/repos/${repo}/issues/${issueNumber}/comments`, {
    headers: { accept: 'application/vnd.github+json' }
  })
  if (!response.ok) {
    throw new Error(`Reading issue comments failed: ${response.status} ${await response.text()}`)
  }
  const comments = await response.json() as Array<{ body: string }>
  const verdictComments = comments.filter(comment => comment.body.includes('**Verdict:'))
  const latest = verdictComments[verdictComments.length - 1]
  if (latest === undefined) {
    throw new Error('No triage verdict comment found on this issue; triage must run first.')
  }
  return latest.body
}

interface ProposedPatch {
  diff: string
  summary: string
}

async function proposePatch (brief: string): Promise<ProposedPatch> {
  const apiKey = requireEnv('ANTHROPIC_API_KEY')

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
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
        name: 'propose_patch',
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
      tool_choice: { type: 'tool', name: 'propose_patch' },
      messages: [{ role: 'user', content: brief }]
    })
  })

  if (!response.ok) {
    throw new Error(`Anthropic API request failed: ${response.status} ${await response.text()}`)
  }

  const body = await response.json() as { content: Array<{ type: string, input?: ProposedPatch }> }
  const toolUse = body.content.find(block => block.type === 'tool_use')?.input
  if (toolUse === undefined) {
    throw new Error('Anthropic API response had no propose_patch tool call')
  }
  return toolUse
}

async function main (): Promise<void> {
  const repo = requireEnv('GITHUB_REPOSITORY')
  const issueNumber = requireEnv('ISSUE_NUMBER')
  const issueBody = process.env.ISSUE_BODY ?? ''

  const alertNumber = parseAlertNumber(issueBody)
  if (alertNumber === undefined) {
    throw new Error('Could not find an alert reference in this issue body (expected text such as `alert #6`).')
  }

  const verdictCommentBody = await fetchLatestVerdictComment(repo, issueNumber)
  const verdict = parseVerdictComment(verdictCommentBody)
  if (verdict === undefined) {
    throw new Error('The latest verdict comment on this issue is not in the expected structured format.')
  }
  if (verdict.isTestCode) {
    throw new Error('The triaged finding is test code (not-applicable); remediation does not apply.')
  }

  const targetContent = readBaseRefFile(verdict.path)
  if (targetContent === undefined) {
    throw new Error(`Could not read ${verdict.path} from the checked-out base ref.`)
  }

  const allowList = computeAllowList(verdict.path, readBaseRefFile)

  const contributingDoc = readBaseRefFile('CONTRIBUTING.md')
  const codeStyleRule = contributingDoc !== undefined ? extractCodeStyleRule(contributingDoc) : undefined
  if (codeStyleRule === undefined) {
    throw new Error('Could not read the code style rule from CONTRIBUTING.md on the base ref.')
  }

  const securityTriageDoc = readBaseRefFile('docs/agents/security-triage.md')
  const complianceInstructions = securityTriageDoc !== undefined
    ? extractComplianceInstructions(securityTriageDoc, 'Patch author (#7)')
    : undefined
  if (complianceInstructions === undefined) {
    throw new Error('Could not read the patch author compliance row from docs/agents/security-triage.md on the base ref.')
  }

  const allTestFiles = readTestFiles()
  const coveringTestPaths = findCoveringTests(verdict.path, allTestFiles)
  const coveringTests: Record<string, string> = {}
  for (const path of coveringTestPaths) {
    coveringTests[path] = allTestFiles[path]
  }

  const regressionArtifactPath = `docs/agents/artifacts/alert-${alertNumber}-regression.patch`
  const regressionArtifactContent = readBaseRefFile(regressionArtifactPath)
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

  mkdirSync(OUTPUT_DIR, { recursive: true })
  writeFileSync(join(OUTPUT_DIR, 'brief.md'), brief)
  writeFileSync(join(OUTPUT_DIR, 'proposed.patch'), proposal.diff)
  writeFileSync(join(OUTPUT_DIR, 'summary.md'), proposal.summary)

  console.log(`Wrote proposal for alert #${alertNumber} to ${OUTPUT_DIR}/`)
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
