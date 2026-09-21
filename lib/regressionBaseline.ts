/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { touchedPathsOf } from './diffFacts'

// The fixed validation input from docs/agents/security-triage.md's "Baseline delivery"
// section: the trusted regression the gate reads from the base ref and owns the application
// of. The patch author cannot edit, replace, or omit it.
export const REGRESSION_TEST_PATH = 'test/server/keyServerPathTraversal.unit.test.ts'
export const EXPECTED_BASELINE_FAILURE_TEST = 'should reject ".." rather than resolve and serve it'

export type BaselineRefusalReason =
  | 'regression-artifact-unavailable'
  | 'regression-apply-failed'
  | 'baseline-not-reproduced'
  | 'regression-still-failing'

export interface TestRunSummary {
  passed: string[]
  failed: string[]
  errored: boolean
}

const TAP_RESULT_LINE = /^[ \t]*(ok|not ok) \d+ - (.+)$/
const TAP_TYPE_LINE = /^[ \t]*type: '(\w+)'$/
const TAP_BLOCK_END = /^[ \t]*\.\.\.\s*$/

/**
 * Parses the TAP13 output of `node --test --test-reporter=tap`, Node's own structured test
 * reporter, into pass/fail test names. Each result line (`ok`/`not ok`) is paired with the
 * `type` field of its own YAML diagnostic block: only `type: 'test'` is a leaf result, so a
 * suite's aggregate roll-up line (`type: 'suite'`) is never counted as one, regardless of how
 * deeply it is nested. `errored` is set when no leaf test result is found at all, which covers
 * a missing test file (empty output); a loader crash instead surfaces as a single failed leaf
 * named after the crashing file, which already fails the exact-name and count checks below -
 * neither is valid baseline evidence (docs/agents/security-triage.md, "Baseline delivery").
 */
export function parseNodeTestOutput (raw: string): TestRunSummary {
  const lines = raw.split(/\r?\n/)
  const passed: string[] = []
  const failed: string[] = []

  for (let i = 0; i < lines.length; i++) {
    const result = TAP_RESULT_LINE.exec(lines[i])
    if (result === null) continue
    const [, status, name] = result

    let type: string | undefined
    for (let j = i + 1; j < lines.length; j++) {
      if (TAP_BLOCK_END.test(lines[j]) || TAP_RESULT_LINE.test(lines[j])) break
      const typeMatch = TAP_TYPE_LINE.exec(lines[j])
      if (typeMatch !== null) {
        type = typeMatch[1]
        break
      }
    }
    if (type !== 'test') continue

    (status === 'ok' ? passed : failed).push(name)
  }

  return { passed, failed, errored: passed.length === 0 && failed.length === 0 }
}

/**
 * The unmodified handler must fail exactly the traversal assertion and pass the two
 * compatibility tests - nothing more, nothing less. A different failure, an additional
 * failure, or no failure at all is not the baseline this regression was written to prove.
 */
export function baselineMatchesExpectation (summary: TestRunSummary): boolean {
  return !summary.errored &&
    summary.failed.length === 1 &&
    summary.failed[0] === EXPECTED_BASELINE_FAILURE_TEST &&
    summary.passed.length === 2
}

/**
 * After the authorized proposal is applied alongside the regression, the regression must
 * pass in full - no failure, no error, all three tests observed
 * (docs/agents/security-triage.md: "require the regression ... to pass alongside everything
 * else").
 */
export function regressionFullyPasses (summary: TestRunSummary): boolean {
  return !summary.errored && summary.failed.length === 0 && summary.passed.length === 3
}

/**
 * The regression artifact is a fixed validation input, not something the gate may apply
 * blindly: it must add exactly `REGRESSION_TEST_PATH`, per the "Baseline delivery" contract
 * ("The artifact may add only test/server/keyServerPathTraversal.unit.test.ts").
 */
export function regressionArtifactTouchesOnlyExpectedPath (diffText: string): boolean {
  const touched = touchedPathsOf(diffText)
  return touched.size === 1 && touched.has(REGRESSION_TEST_PATH)
}
