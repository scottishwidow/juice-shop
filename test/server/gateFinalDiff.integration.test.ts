/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Exercises the real-tree check the `gate` job now performs (issue #17): instead of comparing
// two strings it concatenated itself, it applies the regression and proposal diffs to a real
// git worktree and diffs the resulting tree against the base commit. This test proves that
// composition - real `git apply` plus `finalDiffIsExactlyRegressionPlusProposal` - actually
// distinguishes an authorized tree from one that also carries an unauthorized extra change,
// which the old string-concatenation approach could never do because it never looked at a real
// tree at all.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { finalDiffIsExactlyRegressionPlusProposal } from '../../lib/prCompliance'

function git (args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' })
}

function initRepoAtBaseCommit (): { repoDir: string, baseCommit: string } {
  const repoDir = mkdtempSync(join(tmpdir(), 'gate-final-diff-'))
  git(['init', '-q'], repoDir)
  git(['config', 'user.name', 'Test'], repoDir)
  git(['config', 'user.email', 'test@example.com'], repoDir)
  mkdirSync(join(repoDir, 'routes'), { recursive: true })
  writeFileSync(join(repoDir, 'routes', 'keyServer.ts'), 'export const serveKeyFiles = () => {}\n')
  git(['add', '-A'], repoDir)
  git(['commit', '-q', '-m', 'base'], repoDir)
  const baseCommit = git(['rev-parse', 'HEAD'], repoDir).trim()
  return { repoDir, baseCommit }
}

const REGRESSION_PATH = 'test/server/keyServerPathTraversal.unit.test.ts'
const TARGET_PATH = 'routes/keyServer.ts'

function diffAddingFile (path: string, addedLines: string[]): string {
  const hunkBody = addedLines.map(line => `+${line}`).join('\n')
  return [
    `diff --git a/${path} b/${path}`,
    'new file mode 100644',
    '--- /dev/null',
    `+++ b/${path}`,
    `@@ -0,0 +1,${addedLines.length} @@`,
    hunkBody,
    ''
  ].join('\n')
}

function diffModifying (path: string, oldLine: string, newLines: string[]): string {
  return [
    `diff --git a/${path} b/${path}`,
    `--- a/${path}`,
    `+++ b/${path}`,
    '@@ -1,1 +1,' + newLines.length + ' @@',
    `-${oldLine}`,
    ...newLines.map(line => `+${line}`),
    ''
  ].join('\n')
}

/** What gate.ts now does: apply both diffs to a clean worktree, stage, diff against base. */
function capturePublishedDiff (repoDir: string, baseCommit: string, regressionDiff: string, proposalDiff: string): string {
  execFileSync('git', ['apply', '--whitespace=nowarn', '-'], { cwd: repoDir, input: regressionDiff, encoding: 'utf8' })
  execFileSync('git', ['apply', '--whitespace=nowarn', '-'], { cwd: repoDir, input: proposalDiff, encoding: 'utf8' })
  git(['add', '-A'], repoDir)
  return git(['diff', baseCommit], repoDir)
}

void describe('the gate\'s real-tree final-diff check (issue #17)', () => {
  void it('passes when the applied tree is exactly the regression plus the proposal', () => {
    const { repoDir, baseCommit } = initRepoAtBaseCommit()
    try {
      const regressionDiff = diffAddingFile(REGRESSION_PATH, ['regression assertion'])
      const proposalDiff = diffModifying(TARGET_PATH, 'export const serveKeyFiles = () => {}', ['export const serveKeyFiles = () => { /* fixed */ }'])

      const publishedDiff = capturePublishedDiff(repoDir, baseCommit, regressionDiff, proposalDiff)

      assert.equal(finalDiffIsExactlyRegressionPlusProposal(publishedDiff, regressionDiff, proposalDiff), true)
    } finally {
      rmSync(repoDir, { recursive: true, force: true })
    }
  })

  void it('fails when the real tree carries an unauthorized extra change neither diff describes', () => {
    const { repoDir, baseCommit } = initRepoAtBaseCommit()
    try {
      const regressionDiff = diffAddingFile(REGRESSION_PATH, ['regression assertion'])
      const proposalDiff = diffModifying(TARGET_PATH, 'export const serveKeyFiles = () => {}', ['export const serveKeyFiles = () => { /* fixed */ }'])

      execFileSync('git', ['apply', '--whitespace=nowarn', '-'], { cwd: repoDir, input: regressionDiff, encoding: 'utf8' })
      execFileSync('git', ['apply', '--whitespace=nowarn', '-'], { cwd: repoDir, input: proposalDiff, encoding: 'utf8' })
      // An unauthorized change to the tree that neither diff mentions - the scenario a
      // string-concatenation check can never see, because it never inspects the real tree.
      writeFileSync(join(repoDir, 'routes', 'fileServer.ts'), 'export const sneaky = () => {}\n')
      git(['add', '-A'], repoDir)
      const publishedDiff = git(['diff', baseCommit], repoDir)

      assert.equal(finalDiffIsExactlyRegressionPlusProposal(publishedDiff, regressionDiff, proposalDiff), false)
    } finally {
      rmSync(repoDir, { recursive: true, force: true })
    }
  })
})
