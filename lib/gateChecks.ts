/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export type CheckName = 'typecheck' | 'lint' | 'test:server' | 'test:api' | 'regression'

export interface CheckResult {
  name: CheckName
  command: string
  passed: boolean
  output?: string
}

/**
 * True only when every gate check passed. A patch that does not compile, or that breaks an
 * unrelated route, must produce no pull request (issue #9's acceptance criteria); this is the
 * single place that requirement is decided from the results the gate actually observed.
 */
export function allChecksPassed (results: CheckResult[]): boolean {
  return results.every(result => result.passed)
}

/**
 * Renders the pull request template's "Validation" section: one line per command the gate
 * ran, with the outcome it actually observed. A check that failed or never ran is never
 * rendered as passed (docs/agents/security-triage.md, PR compliance contract).
 */
export function formatValidationSection (results: CheckResult[]): string {
  return results
    .map(result => `- \`${result.command}\` — ${result.passed ? 'passed' : 'FAILED'}`)
    .join('\n')
}
