/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { afterEach, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import {
  collectProposedDiff,
  prepareAgentWorkspace,
  type ProposedDiffOutcome,
  type RunGit
} from '../../lib/scripts/securityTriage/remediate'

const COMMITTER = ['-c', 'user.name=job', '-c', 'user.email=job@localhost', '-c', 'commit.gpgsign=false']

const temporaryDirs: string[] = []

afterEach(() => {
  for (const dir of temporaryDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
})

function temporaryDir (prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix))
  temporaryDirs.push(dir)
  return dir
}

function git (args: string[], cwd: string): string {
  return execFileSync('git', args, { encoding: 'utf8', cwd }).trim()
}

function commitAll (dir: string, message: string): void {
  git(['add', '-A', '--force'], dir)
  git([...COMMITTER, 'commit', '-q', '-m', message], dir)
}

function jobCheckout (): string {
  const dir = temporaryDir('security-remediation-job-checkout-')
  git(['init', '-q'], dir)
  writeFileSync(path.join(dir, 'tracked.txt'), 'original\n')
  commitAll(dir, 'initial')
  return dir
}

function runGitIn (cwd: string): RunGit {
  return (args, options = {}) => execFileSync('git', args, {
    encoding: 'utf8',
    cwd: options.cwd ?? cwd,
    env: options.env
  })
}

function agentWorkspace (checkout: string): string {
  const workspace = prepareAgentWorkspace(runGitIn(checkout))
  temporaryDirs.push(workspace)
  return workspace
}

function proposedDiff (outcome: ProposedDiffOutcome): string {
  assert.ok(outcome.ok, 'the diff should have been collected')
  return outcome.diff
}

function sentinelPath (): string {
  return path.join(temporaryDir('security-remediation-sentinel-'), 'pwned')
}

void describe('the agent workspace stays isolated from the job\'s own git directory', () => {
  void it('never lets the workspace\'s .git config run a command on the runner', () => {
    const checkout = jobCheckout()
    const workspace = agentWorkspace(checkout)
    const sentinel = sentinelPath()
    appendFileSync(path.join(workspace, '.git', 'config'), `\n[core]\n\tfsmonitor = "touch ${sentinel}"\n`)
    writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')

    const diff = proposedDiff(collectProposedDiff(workspace, runGitIn(checkout)))

    assert.equal(existsSync(sentinel), false, 'the runner must never execute a command from the workspace\'s git config')
    assert.match(diff, /-original/)
    assert.match(diff, /\+edited/)
  })

  void it('never lets the workspace\'s .gitattributes select a filter driver the runner defines', () => {
    const checkout = jobCheckout()
    const sentinel = sentinelPath()
    git(['config', 'filter.runnerdefined.clean', `touch ${sentinel}; cat`], checkout)
    const workspace = agentWorkspace(checkout)
    writeFileSync(path.join(workspace, '.gitattributes'), '* filter=runnerdefined\n')
    writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')

    const diff = proposedDiff(collectProposedDiff(workspace, runGitIn(checkout)))

    assert.equal(existsSync(sentinel), false, 'the runner must never run a filter the workspace\'s attributes select')
    assert.match(diff, /\+edited/)
    assert.match(diff, /\+\* filter=runnerdefined/)
  })

  void it('refuses a nested repository without reading its config', () => {
    const checkout = jobCheckout()
    const workspace = agentWorkspace(checkout)
    const sentinel = sentinelPath()
    const nested = path.join(workspace, 'vendor', 'lib')
    mkdirSync(nested, { recursive: true })
    git(['init', '-q'], nested)
    writeFileSync(path.join(nested, 'file.txt'), 'nested\n')
    commitAll(nested, 'nested')
    appendFileSync(path.join(nested, '.git', 'config'), `\n[core]\n\tfsmonitor = "touch ${sentinel}"\n`)
    mkdirSync(path.join(workspace, 'linked'))
    writeFileSync(path.join(workspace, 'linked', '.git'), 'gitdir: /nonexistent\n')

    const outcome = collectProposedDiff(workspace, runGitIn(checkout))

    assert.equal(existsSync(sentinel), false)
    assert.equal(outcome.ok, false)
    assert.deepEqual(
      outcome.ok ? [] : [...outcome.nestedRepositories].sort(),
      [path.join('linked', '.git'), path.join('vendor', 'lib', '.git')]
    )
  })

  void it('carries edits, additions and deletions into the diff, and the diff applies to the job checkout', () => {
    const checkout = jobCheckout()
    writeFileSync(path.join(checkout, 'to-delete.txt'), 'gone soon\n')
    commitAll(checkout, 'add file to delete')

    const workspace = agentWorkspace(checkout)
    writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')
    writeFileSync(path.join(workspace, 'added.txt'), 'new\n')
    rmSync(path.join(workspace, 'to-delete.txt'))

    const diff = proposedDiff(collectProposedDiff(workspace, runGitIn(checkout)))

    assert.match(diff, /diff --git a\/tracked\.txt b\/tracked\.txt/)
    assert.match(diff, /diff --git a\/added\.txt b\/added\.txt/)
    assert.match(diff, /diff --git a\/to-delete\.txt b\/to-delete\.txt/)
    assert.match(diff, /deleted file mode/)

    const applyTarget = temporaryDir('security-remediation-apply-target-')
    git(['clone', '-q', checkout, applyTarget], tmpdir())
    writeFileSync(path.join(applyTarget, 'diff.patch'), diff)
    git(['apply', '--check', 'diff.patch'], applyTarget)
  })

  void it('records a symlink the agent adds as a link, without reading its target', () => {
    const checkout = jobCheckout()
    const workspace = agentWorkspace(checkout)
    const outside = path.join(temporaryDir('security-remediation-outside-'), 'secret.txt')
    writeFileSync(outside, 'runner secret\n')
    symlinkSync(outside, path.join(workspace, 'leak'))

    const diff = proposedDiff(collectProposedDiff(workspace, runGitIn(checkout)))

    assert.match(diff, /new file mode 120000/)
    assert.doesNotMatch(diff, /runner secret/)
  })

  void it('keeps paths already changed in the job checkout out of the workspace and the diff', () => {
    const checkout = jobCheckout()
    // Stands in for what `npm install` changes in the real job, before the agent runs.
    writeFileSync(path.join(checkout, 'package-lock.json'), 'created-by-install\n')
    writeFileSync(path.join(checkout, 'tracked.txt'), 'changed-by-install\n')

    const workspace = agentWorkspace(checkout)

    assert.equal(existsSync(path.join(workspace, 'package-lock.json')), false)
    assert.equal(readFileSync(path.join(workspace, 'tracked.txt'), 'utf8'), 'original\n')
    assert.equal(proposedDiff(collectProposedDiff(workspace, runGitIn(checkout))), '')
  })

  void it('keeps the container tools\' own index files out of the diff', () => {
    const checkout = jobCheckout()
    const workspace = agentWorkspace(checkout)
    writeFileSync(path.join(workspace, 'tags'), 'ctags output\n')
    writeFileSync(path.join(workspace, 'cscope.out'), 'cscope output\n')
    writeFileSync(path.join(workspace, 'tracked.txt'), 'edited\n')

    const diff = proposedDiff(collectProposedDiff(workspace, runGitIn(checkout)))

    assert.doesNotMatch(diff, /\btags\b/)
    assert.doesNotMatch(diff, /cscope\.out/)
    assert.match(diff, /tracked\.txt/)
  })

  void it('gives the agent its own fresh repository with a single baseline commit', () => {
    const checkout = jobCheckout()
    const workspace = agentWorkspace(checkout)

    assert.equal(git(['log', '--format=%s'], workspace), 'baseline')
    assert.equal(git(['rev-parse', '--show-toplevel'], workspace), realpathSync(workspace))
  })

  void it('includes tracked but ignored files in the baseline, so the agent\'s own git diff shows edits to them', () => {
    const checkout = jobCheckout()
    writeFileSync(path.join(checkout, '.gitignore'), '*.pyc\n')
    writeFileSync(path.join(checkout, 'compiled.pyc'), 'original\n')
    commitAll(checkout, 'add tracked but ignored file')

    const workspace = agentWorkspace(checkout)
    writeFileSync(path.join(workspace, 'compiled.pyc'), 'edited\n')

    assert.match(git(['diff'], workspace), /\+edited/)
    assert.match(proposedDiff(collectProposedDiff(workspace, runGitIn(checkout))), /compiled\.pyc/)
  })
})
