/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { authorizePatch, type BaseRefReader } from '../../lib/authorizePatch'

function diffModifying (path: string, addedLines: string[]): string {
  const hunkBody = addedLines.map(line => `+${line}`).join('\n')
  return [
    `diff --git a/${path} b/${path}`,
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -1,0 +1,${addedLines.length} @@`,
    hunkBody
  ].join('\n')
}

function diffTouchingTwoPaths (firstPath: string, secondPath: string): string {
  return [
    diffModifying(firstPath, ['first path change']),
    diffModifying(secondPath, ['second path change'])
  ].join('\n')
}

function readerWithFiles (files: Record<string, string>): BaseRefReader {
  return (path: string) => files[path]
}

void describe('authorizePatch', () => {
  const targetPath = 'routes/keyServer.ts'

  void it('allows an uncoupled target with a diff confined to its own path', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = authorizePatch(targetPath, diffModifying(targetPath, ['const x = 1']), reader)

    assert.deepEqual(result, { allowed: true })
  })

  void it('refuses the same target when the diff also reaches a second path', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = authorizePatch(targetPath, diffTouchingTwoPaths(targetPath, 'routes/fileServer.ts'), reader)

    assert.deepEqual(result, { allowed: false, reason: 'path-not-allowed' })
  })

  void it('refuses a snippet-coupled target', () => {
    const reader = readerWithFiles({ [targetPath]: '// vuln-code-snippet start someChallenge\ncode\n// vuln-code-snippet end someChallenge' })

    const result = authorizePatch(targetPath, diffModifying(targetPath, ['const x = 1']), reader)

    assert.deepEqual(result, { allowed: false, reason: 'snippet-coupled' })
  })

  void it('refuses a solve-coupled target', () => {
    const reader = readerWithFiles({ [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })

    const result = authorizePatch(targetPath, diffModifying(targetPath, ['const x = 1']), reader)

    assert.deepEqual(result, { allowed: false, reason: 'solve-coupled' })
  })

  void it('allows a coupled target with an explicit override present', () => {
    const reader = readerWithFiles({
      [targetPath]: 'challengeUtils.solve(challenges.someChallenge)',
      '.taskflow/allowlist.yml': [
        '6:',
        '  allow:',
        `    - ${targetPath}`
      ].join('\n')
    })

    const result = authorizePatch(targetPath, diffModifying(targetPath, ['const x = 1']), reader)

    assert.deepEqual(result, { allowed: true })
  })

  void it('refuses a diff adding a lint suppression inside an allowed path', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = authorizePatch(targetPath, diffModifying(targetPath, ['// eslint-disable-next-line', 'const x = 1']), reader)

    assert.deepEqual(result, { allowed: false, reason: 'lint-suppression-added' })
  })

  void it('refuses a diff adding a type-check suppression', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = authorizePatch(targetPath, diffModifying(targetPath, ['// @ts-expect-error', 'const x = 1']), reader)

    assert.deepEqual(result, { allowed: false, reason: 'type-suppression-added' })
  })

  void it('refuses a diff touching the override file itself', () => {
    const reader = readerWithFiles({ [targetPath]: 'export const serveKeyFiles = () => {}' })

    const result = authorizePatch(
      targetPath,
      diffTouchingTwoPaths(targetPath, '.taskflow/allowlist.yml'),
      reader
    )

    assert.deepEqual(result, { allowed: false, reason: 'override-file-modified' })
  })

  void it('treats an absent override file exactly as an empty one', () => {
    const readerAbsent = readerWithFiles({ [targetPath]: 'challengeUtils.solve(challenges.someChallenge)' })
    const readerEmpty = readerWithFiles({
      [targetPath]: 'challengeUtils.solve(challenges.someChallenge)',
      '.taskflow/allowlist.yml': ''
    })

    const diff = diffModifying(targetPath, ['const x = 1'])

    assert.deepEqual(authorizePatch(targetPath, diff, readerAbsent), { allowed: false, reason: 'solve-coupled' })
    assert.deepEqual(authorizePatch(targetPath, diff, readerEmpty), { allowed: false, reason: 'solve-coupled' })
  })
})
