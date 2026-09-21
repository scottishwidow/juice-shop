/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import type { AllowList } from './authorizePatch'
import type { VerdictPayload } from './verdictPayload'

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
  verdict: VerdictPayload
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
