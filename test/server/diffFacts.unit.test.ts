/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { addedLinesByPath, addedLinesOf, touchedPathsOf } from '../../lib/diffFacts'

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

function diffDeletingFile (path: string, removedLines: string[]): string {
  const hunkBody = removedLines.map(line => `-${line}`).join('\n')
  return [
    `diff --git a/${path} b/${path}`,
    'deleted file mode 100644',
    `--- a/${path}`,
    '+++ /dev/null',
    `@@ -1,${removedLines.length} +0,0 @@`,
    hunkBody
  ].join('\n')
}

void describe('diffFacts', () => {
  void describe('touchedPathsOf', () => {
    void it('reports the path a diff modifies', () => {
      const touched = touchedPathsOf(diffModifying('routes/keyServer.ts', ['const x = 1']))
      assert.deepEqual([...touched], ['routes/keyServer.ts'])
    })

    void it('strips the a/ and b/ prefixes', () => {
      const touched = touchedPathsOf(diffModifying('routes/keyServer.ts', ['const x = 1']))
      assert.equal([...touched].some(path => path.startsWith('a/') || path.startsWith('b/')), false)
    })

    void it('reports every path across multiple files in one diff', () => {
      const diff = [
        diffModifying('routes/keyServer.ts', ['const x = 1']),
        diffModifying('lib/authorizePatch.ts', ['const y = 2'])
      ].join('\n')

      const touched = touchedPathsOf(diff)

      assert.deepEqual([...touched].sort(), ['lib/authorizePatch.ts', 'routes/keyServer.ts'])
    })

    void it('excludes /dev/null for an added file', () => {
      const touched = touchedPathsOf(diffAddingFile('lib/newModule.ts', ['const x = 1']))
      assert.deepEqual([...touched], ['lib/newModule.ts'])
    })

    void it('excludes /dev/null for a deleted file', () => {
      const touched = touchedPathsOf(diffDeletingFile('lib/oldModule.ts', ['const x = 1']))
      assert.deepEqual([...touched], ['lib/oldModule.ts'])
    })
  })

  void describe('addedLinesOf', () => {
    void it('returns every added line across the whole diff', () => {
      const diff = [
        diffModifying('routes/keyServer.ts', ['const x = 1']),
        diffModifying('lib/authorizePatch.ts', ['const y = 2'])
      ].join('\n')

      assert.deepEqual(addedLinesOf(diff), ['const x = 1', 'const y = 2'])
    })

    void it('returns nothing for a diff that only deletes lines', () => {
      assert.deepEqual(addedLinesOf(diffDeletingFile('lib/oldModule.ts', ['const x = 1'])), [])
    })
  })

  void describe('addedLinesByPath', () => {
    void it('groups added lines under their normalized new path', () => {
      const diff = [
        diffModifying('routes/keyServer.ts', ['const x = 1']),
        diffModifying('lib/authorizePatch.ts', ['const y = 2', 'const z = 3'])
      ].join('\n')

      const byPath = addedLinesByPath(diff)

      assert.deepEqual(byPath.get('routes/keyServer.ts'), ['const x = 1'])
      assert.deepEqual(byPath.get('lib/authorizePatch.ts'), ['const y = 2', 'const z = 3'])
      assert.equal(byPath.size, 2)
    })

    void it('holds no entry for a diff that only deletes a file', () => {
      const byPath = addedLinesByPath(diffDeletingFile('lib/oldModule.ts', ['const x = 1']))
      assert.equal(byPath.size, 0)
    })
  })
})
