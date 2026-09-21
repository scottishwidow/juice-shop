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

const RESULT_LINE = /^[ \t]+(✔|✖)\s+(.+?)\s+\([\d.]+ms\)\s*$/gm

/**
 * Parses `node --test` human-readable output into pass/fail test names. Only indented lines
 * are read as leaf test results; a suite's own aggregate line (unindented) is not a test.
 * `errored` is set when no leaf test result is found at all, which covers both a loader crash
 * and a missing test file: neither is valid baseline evidence
 * (docs/agents/security-triage.md, "Baseline delivery").
 */
export function parseNodeTestOutput (raw: string): TestRunSummary {
  const passed: string[] = []
  const failed: string[] = []

  for (const match of raw.matchAll(RESULT_LINE)) {
    const [, symbol, name] = match
    if (symbol === '✔') {
      passed.push(name)
    } else {
      failed.push(name)
    }
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
