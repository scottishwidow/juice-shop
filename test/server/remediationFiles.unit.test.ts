/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, it } from 'node:test'

import { readRemediationTests, writeRemediationArtifacts } from '../../lib/remediationFiles'

void describe('remediation files', () => {
  let root: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'remediation-files-'))
  })

  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  void it('reads only regular tests from the pinned commit despite working-tree changes and symlinks', () => {
    const git = (args: string[]): string => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
    git(['init'])
    mkdirSync(join(root, 'test/server'), { recursive: true })
    mkdirSync(join(root, 'test/api'), { recursive: true })
    const tracked = join(root, 'test/server/target.unit.test.ts')
    const secret = join(root, 'secret.txt')
    writeFileSync(tracked, 'committed test')
    writeFileSync(join(root, 'test/api/target.test.ts'), 'committed API test')
    writeFileSync(join(root, 'test/server/helper.ts'), 'not a test')
    writeFileSync(secret, 'private working-tree data')
    symlinkSync(secret, join(root, 'test/server/link.test.ts'))
    git(['add', 'test'])
    const tree = git(['write-tree']).trim()
    const commit = git(['-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit-tree', tree, '-m', 'fixture']).trim()

    writeFileSync(tracked, 'modified working-tree data')
    writeFileSync(join(root, 'test/server/untracked.test.ts'), 'untracked data')
    symlinkSync(root, join(root, 'test/server/loop'))

    assert.deepEqual(readRemediationTests(commit, git), {
      'test/api/target.test.ts': 'committed API test',
      'test/server/target.unit.test.ts': 'committed test'
    })
  })

  void it('refuses an unavailable base tree', () => {
    assert.throws(() => readRemediationTests('base', () => undefined), /Could not list tests/)
  })

  void it('refuses an unreadable tracked test instead of silently dropping its contract', () => {
    assert.throws(() => readRemediationTests('base', args => args[0] === 'ls-tree'
      ? `100644 blob ${'a'.repeat(40)}\ttest/server/target.test.ts\0`
      : undefined), /Could not read test/)
  })

  void it('refuses an oversized tracked test', () => {
    assert.throws(() => readRemediationTests('base', args => {
      if (args[0] === 'ls-tree') return `100644 blob ${'a'.repeat(40)}\ttest/server/target.test.ts\0`
      return args[1] === '-t' ? 'blob' : 'x'.repeat(256 * 1024 + 1)
    }), /Could not read test/)
  })

  void it('writes only the three inert artifact files and preserves the proposal for the gate', () => {
    const output = join(root, 'output')
    const proposal = { diff: 'untrusted proposal', summary: 'untrusted summary' }
    writeRemediationArtifacts(output, 'brief', proposal)

    assert.deepEqual(readdirSync(output).sort(), ['brief.md', 'proposed.patch', 'summary.md'])
    assert.equal(readFileSync(join(output, 'brief.md'), 'utf8'), 'brief')
    assert.equal(readFileSync(join(output, 'proposed.patch'), 'utf8'), proposal.diff)
    assert.equal(readFileSync(join(output, 'summary.md'), 'utf8'), proposal.summary)
  })

  for (const symlink of [false, true]) {
    void it(`refuses an existing ${symlink ? 'symlink' : 'directory'} without overwriting files`, () => {
      const existing = join(root, 'existing')
      mkdirSync(existing)
      const sentinel = join(existing, 'proposed.patch')
      writeFileSync(sentinel, 'keep')
      const output = symlink ? join(root, 'output') : existing
      if (symlink) symlinkSync(existing, output)

      assert.throws(() => writeRemediationArtifacts(output, 'brief', { diff: 'overwrite', summary: '' }), { code: 'EEXIST' })
      assert.equal(readFileSync(sentinel, 'utf8'), 'keep')
      assert.deepEqual(readdirSync(existing), ['proposed.patch'])
    })
  }
})
