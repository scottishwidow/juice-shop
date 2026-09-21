/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createBaseRefReader, isRepoRelativePath } from '../../lib/baseRefReader'

const BASE_COMMIT = '5bc7ce9292a2237e64771a8b2b71b3df730d0800'

function fakeGit (objects: Record<string, { type: string, content: string }>): { run: (args: string[]) => string | undefined, calls: string[][] } {
  const calls: string[][] = []
  return {
    calls,
    run (args: string[]) {
      calls.push(args)
      const entry = objects[args[args.length - 1]]
      if (entry === undefined) {
        return undefined
      }
      return args[1] === '-t' ? `${entry.type}\n` : entry.content
    }
  }
}

void describe('isRepoRelativePath', () => {
  void it('accepts a path inside the checkout', () => {
    assert.equal(isRepoRelativePath('routes/keyServer.ts'), true)
  })

  for (const path of ['/etc/passwd', '../../etc/passwd', 'routes/../../etc/passwd', 'C:\\secrets.txt', '\\\\host\\share', '--output=x', '', 'routes/key\0Server.ts']) {
    void it(`rejects ${JSON.stringify(path)}`, () => {
      assert.equal(isRepoRelativePath(path), false)
    })
  }
})

void describe('createBaseRefReader', () => {
  void it('reads a tracked file from the pinned commit', () => {
    const git = fakeGit({ [`${BASE_COMMIT}:routes/keyServer.ts`]: { type: 'blob', content: 'export const serveKeyFiles = () => {}' } })

    assert.equal(createBaseRefReader(BASE_COMMIT, git.run)('routes/keyServer.ts'), 'export const serveKeyFiles = () => {}')
  })

  void it('never invokes git for a path that could leave the checkout', () => {
    const git = fakeGit({})

    assert.equal(createBaseRefReader(BASE_COMMIT, git.run)('/tmp/sentinel.txt'), undefined)
    assert.deepEqual(git.calls, [])
  })

  void it('returns undefined for a path that is not a tracked file of that commit', () => {
    const git = fakeGit({})

    assert.equal(createBaseRefReader(BASE_COMMIT, git.run)('untracked/secret.env'), undefined)
  })

  void it('returns undefined for a directory', () => {
    const git = fakeGit({ [`${BASE_COMMIT}:routes`]: { type: 'tree', content: 'keyServer.ts\n' } })

    assert.equal(createBaseRefReader(BASE_COMMIT, git.run)('routes'), undefined)
  })

  void it('returns undefined for a file larger than the read limit', () => {
    const git = fakeGit({ [`${BASE_COMMIT}:big.txt`]: { type: 'blob', content: 'x'.repeat(256 * 1024 + 1) } })

    assert.equal(createBaseRefReader(BASE_COMMIT, git.run)('big.txt'), undefined)
  })
})
