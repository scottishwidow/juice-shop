/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import type { AllowList } from './authorizePatch'

export interface ParsedVerdict {
  alertNumber: number
  baseCommit: string
  ruleId: string
  path: string
  verdict: string
  snippetCoupled: boolean
  solveCoupled: boolean
  isTestCode: boolean
}

const VERDICT_LINE = /\*\*Verdict:\s*(\S+)\*\*/
const ALERT_LINE = /^- Alert: #(\d+)$/m
const BASE_LINE = /^- Base: `([0-9a-f]{40})`$/m
const RULE_LINE = /^- Rule: `([^`]+)`$/m
const PATH_LINE = /^- Path: `([^`]+)`$/m
const SNIPPET_LINE = /^- Snippet coupling: (yes|no)$/m
const SOLVE_LINE = /^- Solve coupling: (yes|no)$/m
const TEST_CODE_LINE = /^- Test code: (yes|no)$/m

/**
 * Reads the structured fields the `triage` job posted in its verdict comment
 * (`verdictSummary` in `lib/scripts/securityTriage/triage.ts`). The patch author brief reads
 * the verdict a human already read, rather than recomputing it, so both stages agree on the
 * same finding without a second scanner-API call from a job that holds no permissions.
 *
 * The alert number and base commit are required fields, not decoration: `selectTrustedVerdict`
 * matches them against the alert the issue body names and the commit the job checked out, so a
 * verdict cannot be replayed against a different finding or a moved base ref (ADR-0005).
 */
export function parseVerdictComment (commentBody: string): ParsedVerdict | undefined {
  const verdict = VERDICT_LINE.exec(commentBody)?.[1]
  const alertNumber = ALERT_LINE.exec(commentBody)?.[1]
  const baseCommit = BASE_LINE.exec(commentBody)?.[1]
  const ruleId = RULE_LINE.exec(commentBody)?.[1]
  const path = PATH_LINE.exec(commentBody)?.[1]
  const snippetCoupled = SNIPPET_LINE.exec(commentBody)?.[1]
  const solveCoupled = SOLVE_LINE.exec(commentBody)?.[1]
  const isTestCode = TEST_CODE_LINE.exec(commentBody)?.[1]

  if (verdict === undefined || alertNumber === undefined || baseCommit === undefined ||
      ruleId === undefined || path === undefined || snippetCoupled === undefined ||
      solveCoupled === undefined || isTestCode === undefined) {
    return undefined
  }

  return {
    alertNumber: Number(alertNumber),
    baseCommit,
    verdict,
    ruleId,
    path,
    snippetCoupled: snippetCoupled === 'yes',
    solveCoupled: solveCoupled === 'yes',
    isTestCode: isTestCode === 'yes'
  }
}

/**
 * Extracts one row's instruction text from the compliance table in
 * `docs/agents/security-triage.md`, read from the trusted base ref, so the patch author's
 * brief carries only the constraints written for its own role rather than a copy hand-typed
 * into this script.
 */
export function extractComplianceInstructions (securityTriageDoc: string, roleHeading: string): string | undefined {
  const pattern = new RegExp(`^\\|\\s*${roleHeading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\|\\s*(.+?)\\s*\\|\\s*$`, 'm')
  return pattern.exec(securityTriageDoc)?.[1]
}

/**
 * Extracts the numbered code-style requirement from `CONTRIBUTING.md`, read from the trusted
 * base ref, so the rule the brief states cannot drift from the rule the repository enforces.
 */
export function extractCodeStyleRule (contributingDoc: string): string | undefined {
  const match = /^2\.\s*(.+)$/m.exec(contributingDoc)
  return match?.[1]
}

/**
 * Names the test files, among `testFiles` (path -> source), whose source imports the target
 * module. This is the mechanical, source-level analogue of the coupling-marker greps: it
 * finds tests already committed to the target's current behaviour without a per-target
 * lookup table.
 */
export function findCoveringTests (targetPath: string, testFiles: Record<string, string>): string[] {
  const moduleName = targetPath.replace(/^.*\//, '').replace(/\.[^.]+$/, '')
  const importPattern = new RegExp(`from ['"][^'"]*/${moduleName}['"]`)
  return Object.keys(testFiles)
    .filter(path => importPattern.test(testFiles[path]))
    .sort()
}

export interface RemediationBriefInput {
  alertNumber: number
  verdict: ParsedVerdict
  targetContent: string
  allowList: AllowList
  codeStyleRule: string
  complianceInstructions: string
  coveringTests: Record<string, string>
  regressionArtifact?: { path: string, content: string }
}

/**
 * Assembles the patch author's brief. It carries only what issue #7 requires: the alert, the
 * coupling verdict, the allow-list, the code style rule, and the contract of the tests
 * already covering the target. It excludes CLAUDE.md, which assumes whole-repository scope
 * and a human reviewer at the end (neither applies to a credential-free job under a machine
 * gate).
 */
export function buildRemediationBrief (input: RemediationBriefInput): string {
  const sections: string[] = []

  sections.push(
    '# Patch author brief',
    '',
    `Alert #${input.alertNumber} (\`${input.verdict.ruleId}\`) at \`${input.verdict.path}\`, ` +
    `triaged as \`${input.verdict.verdict}\`.`,
    '',
    `Snippet coupling: ${input.verdict.snippetCoupled ? 'yes' : 'no'}. ` +
    `Solve coupling: ${input.verdict.solveCoupled ? 'yes' : 'no'}.`
  )

  sections.push(
    '',
    '## Allow-list',
    '',
    'Your diff must touch only these paths, and none outside them:',
    '',
    ...input.allowList.paths.map(path => `- \`${path}\``)
  )
  if (!input.allowList.targetAllowed) {
    sections.push(
      '',
      `\`${input.verdict.path}\` itself is not currently allow-listed (reason: ` +
      `\`${input.allowList.couplingReason}\`). A diff touching it will be refused.`
    )
  }

  sections.push(
    '',
    '## Code style',
    '',
    input.codeStyleRule
  )

  sections.push(
    '',
    '## Role constraints',
    '',
    input.complianceInstructions
  )

  sections.push(
    '',
    '## Target file (base ref)',
    '',
    `\`${input.verdict.path}\`:`,
    '',
    '```typescript',
    input.targetContent,
    '```'
  )

  const coveringTestPaths = Object.keys(input.coveringTests).sort()
  if (coveringTestPaths.length > 0) {
    sections.push('', '## Tests already covering the target', '')
    for (const path of coveringTestPaths) {
      sections.push(`\`${path}\`:`, '', '```typescript', input.coveringTests[path], '```', '')
    }
  }

  if (input.regressionArtifact !== undefined) {
    sections.push(
      '## Regression the remediation must satisfy',
      '',
      `\`${input.regressionArtifact.path}\`:`,
      '',
      '```diff',
      input.regressionArtifact.content,
      '```'
    )
  }

  return sections.join('\n')
}
