/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  baselineMatchesExpectation,
  parseNodeTestOutput,
  regressionArtifactTouchesOnlyExpectedPath,
  regressionFullyPasses,
  REGRESSION_TEST_PATH
} from '../../lib/regressionBaseline'

const EXPECTED_FAILURE_OUTPUT = [
  '▶ keyServer path traversal',
  '  ✖ should reject ".." rather than resolve and serve it (6.428547ms)',
  '  ✔ should serve requested file from folder /encryptionkeys (0.957438ms)',
  '  ✔ should raise error for slashes in filename (0.543817ms)',
  '✖ keyServer path traversal (10.049684ms)'
].join('\n')

const ALL_PASS_OUTPUT = [
  '▶ keyServer path traversal',
  '  ✔ should reject ".." rather than resolve and serve it (6.428547ms)',
  '  ✔ should serve requested file from folder /encryptionkeys (0.957438ms)',
  '  ✔ should raise error for slashes in filename (0.543817ms)',
  '✔ keyServer path traversal (10.049684ms)'
].join('\n')

const LOADER_CRASH_OUTPUT = 'node:internal/modules/cjs/loader:1234\n  throw err;\n  ^\n\nError: Cannot find module \'../../routes/keyServer\''

function diffAddingFile (path: string, addedLines: string[]): string {
  const hunkBody = addedLines.map(line => `+${line}`).join('\n')
  return [
    `diff --git a/${path} b/${path}`,
    'new file mode 100644',
    '--- /dev/null',
    `+++ b/${path}`,
    `@@ -0,0 +1,${addedLines.length} @@`,
    hunkBody
  ].join('\n')
}

void describe('parseNodeTestOutput', () => {
  void it('reads exactly one failure and two passes from the expected baseline failure', () => {
    const summary = parseNodeTestOutput(EXPECTED_FAILURE_OUTPUT)

    assert.deepEqual(summary.failed, ['should reject ".." rather than resolve and serve it'])
    assert.equal(summary.passed.length, 2)
    assert.equal(summary.errored, false)
  })

  void it('reads all three as passing when the regression is fixed', () => {
    const summary = parseNodeTestOutput(ALL_PASS_OUTPUT)

    assert.equal(summary.failed.length, 0)
    assert.equal(summary.passed.length, 3)
    assert.equal(summary.errored, false)
  })

  void it('flags a loader crash as errored rather than a clean run', () => {
    const summary = parseNodeTestOutput(LOADER_CRASH_OUTPUT)

    assert.equal(summary.errored, true)
    assert.equal(summary.passed.length, 0)
    assert.equal(summary.failed.length, 0)
  })

  void it('flags empty output (a missing test) as errored', () => {
    const summary = parseNodeTestOutput('')

    assert.equal(summary.errored, true)
  })
})

void describe('baselineMatchesExpectation', () => {
  void it('is true only for the exact expected failure', () => {
    assert.equal(baselineMatchesExpectation(parseNodeTestOutput(EXPECTED_FAILURE_OUTPUT)), true)
  })

  void it('is false when the regression already passes', () => {
    assert.equal(baselineMatchesExpectation(parseNodeTestOutput(ALL_PASS_OUTPUT)), false)
  })

  void it('is false for a loader crash', () => {
    assert.equal(baselineMatchesExpectation(parseNodeTestOutput(LOADER_CRASH_OUTPUT)), false)
  })
})

void describe('regressionFullyPasses', () => {
  void it('is true only when all three tests pass', () => {
    assert.equal(regressionFullyPasses(parseNodeTestOutput(ALL_PASS_OUTPUT)), true)
  })

  void it('is false while the expected failure still reproduces', () => {
    assert.equal(regressionFullyPasses(parseNodeTestOutput(EXPECTED_FAILURE_OUTPUT)), false)
  })
})

void describe('regressionArtifactTouchesOnlyExpectedPath', () => {
  void it('is true for a diff adding only the fixed regression test', () => {
    const diff = diffAddingFile(REGRESSION_TEST_PATH, ['export const x = 1'])

    assert.equal(regressionArtifactTouchesOnlyExpectedPath(diff), true)
  })

  void it('is false for a diff touching an additional path', () => {
    const diff = [
      diffAddingFile(REGRESSION_TEST_PATH, ['export const x = 1']),
      diffAddingFile('routes/keyServer.ts', ['export const y = 2'])
    ].join('\n')

    assert.equal(regressionArtifactTouchesOnlyExpectedPath(diff), false)
  })

  void it('is false for a diff touching a different path entirely', () => {
    const diff = diffAddingFile('test/server/other.unit.test.ts', ['export const x = 1'])

    assert.equal(regressionArtifactTouchesOnlyExpectedPath(diff), false)
  })
})
