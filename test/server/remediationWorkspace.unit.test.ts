/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { prepareAgentWorkspace, collectProposedDiff } from '../../lib/scripts/securityTriage/remediate'

function git (args: string[], cwd: string): string {
  return execFileSync('git', args, { encoding: 'utf8', cwd }).trim()
}

function jobCheckout (): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'security-remediation-job-checkout-'))
  git(['init', '-q'], dir)
  git(['-c', 'user.name=job', '-c', 'user.email=job@localhost', 'config', 'commit.gpgsign', 'false'], dir)
  writeFileSync(path.join(dir, 'tracked.txt'), 'original\n')
  git(['add', '-A'], dir)
  git(['-c', 'user.name=job', '-c', 'user.email=job@localhost', 'commit', '-q', '-m', 'initial'], dir)
  return dir
}

function runGitIn (cwd: string): (args: string[], options?: { cwd?: string, env?: NodeJS.ProcessEnv }) => string {
  return (args, options = {}) => execFileSync('git', args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    cwd: options.cwd ?? cwd,
    env: options.env
  })
}

void describe('the agent workspace stays isolated from the job\'s own git directory', () => {
  void it('never lets the workspace\'s .git config run a command on the runner', () => {
    const checkout = jobCheckout()
    try {
      const workspace = prepareAgentWorkspace(runGitIn(checkout))

      const sentinel = path.join(tmpdir(), `pwned-${Date.now()}.txt`)
      rmSync(sentinel, { force: true })
      writeFileSync(
        path.join(workspace, '.git', 'config'),
        readFileSync(path.join(workspace, '.git', 'config'), 'utf8') +
          `\n[core]\n\tfsmonitor = "touch ${sentinel}"\n`
      )
      writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')

      const diff = collectProposedDiff(workspace, runGitIn(checkout))

      assert.equal(existsSync(sentinel), false, 'the runner must never execute a command from the workspace\'s git config')
      assert.match(diff, /-original/)
      assert.match(diff, /\+edited/)
    } finally {
      rmSync(checkout, { recursive: true, force: true })
    }
  })

  void it('carries edits, additions and deletions into the diff, and the diff applies to the job checkout', () => {
    const checkout = jobCheckout()
    try {
      writeFileSync(path.join(checkout, 'to-delete.txt'), 'gone soon\n')
      git(['add', '-A'], checkout)
      git(['-c', 'user.name=job', '-c', 'user.email=job@localhost', 'commit', '-q', '-m', 'add file to delete'], checkout)

      const workspace = prepareAgentWorkspace(runGitIn(checkout))
      writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')
      writeFileSync(path.join(workspace, 'added.txt'), 'new\n')
      rmSync(path.join(workspace, 'to-delete.txt'))

      const diff = collectProposedDiff(workspace, runGitIn(checkout))

      assert.match(diff, /diff --git a\/tracked\.txt b\/tracked\.txt/)
      assert.match(diff, /diff --git a\/added\.txt b\/added\.txt/)
      assert.match(diff, /diff --git a\/to-delete\.txt b\/to-delete\.txt/)
      assert.match(diff, /deleted file mode/)

      const applyTarget = mkdtempSync(path.join(tmpdir(), 'security-remediation-apply-target-'))
      try {
        git(['clone', '-q', checkout, applyTarget], tmpdir())
        writeFileSync(path.join(applyTarget, 'diff.patch'), diff)
        execFileSync('git', ['apply', '--check', 'diff.patch'], { cwd: applyTarget, encoding: 'utf8' })
      } finally {
        rmSync(applyTarget, { recursive: true, force: true })
      }
    } finally {
      rmSync(checkout, { recursive: true, force: true })
    }
  })

  void it('excludes a path already dirtied in the job checkout from the workspace and the diff', () => {
    const checkout = jobCheckout()
    try {
      // Stands in for what `npm install` dirties in the real job, before the agent runs.
      writeFileSync(path.join(checkout, 'package-lock.json'), 'dirtied-by-install\n')

      const workspace = prepareAgentWorkspace(runGitIn(checkout))

      assert.equal(existsSync(path.join(workspace, 'package-lock.json')), false)

      const diff = collectProposedDiff(workspace, runGitIn(checkout))
      assert.doesNotMatch(diff, /package-lock\.json/)
    } finally {
      rmSync(checkout, { recursive: true, force: true })
    }
  })

  void it('keeps the container tools\' own index files out of the diff', () => {
    const checkout = jobCheckout()
    try {
      const workspace = prepareAgentWorkspace(runGitIn(checkout))
      writeFileSync(path.join(workspace, 'tags'), 'ctags output\n')
      writeFileSync(path.join(workspace, 'cscope.out'), 'cscope output\n')
      writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')

      const diff = collectProposedDiff(workspace, runGitIn(checkout))

      assert.doesNotMatch(diff, /\btags\b/)
      assert.doesNotMatch(diff, /cscope\.out/)
      assert.match(diff, /tracked\.txt/)
    } finally {
      rmSync(checkout, { recursive: true, force: true })
    }
  })

  void it('gives the agent its own fresh repository with a single baseline commit', () => {
    const checkout = jobCheckout()
    try {
      const workspace = prepareAgentWorkspace(runGitIn(checkout))

      assert.ok(existsSync(path.join(workspace, '.git')))
      const log = git(['log', '--format=%s'], workspace)
      assert.equal(log, 'baseline')

      const workspaceRoot = git(['rev-parse', '--show-toplevel'], workspace)
      assert.equal(workspaceRoot, execFileSync('realpath', [workspace], { encoding: 'utf8' }).trim())
    } finally {
      rmSync(checkout, { recursive: true, force: true })
    }
  })
})
