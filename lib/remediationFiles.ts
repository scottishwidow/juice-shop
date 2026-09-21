/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { createBaseRefReader, type GitRunner } from './baseRefReader'
import type { ProposedPatch } from './proposedPatch'

export function readRemediationTests (commit: string, runGit: GitRunner): Record<string, string> {
  const tree = runGit(['ls-tree', '-r', '-z', commit, '--', 'test/server', 'test/api'])
  if (tree === undefined) {
    throw new Error('Could not list tests at the pinned base commit.')
  }
  const readBaseRef = createBaseRefReader(commit, runGit)
  const files: Record<string, string> = {}
  for (const entry of tree.split('\0')) {
    const match = /^100(?:644|755) blob [0-9a-f]+\t(.+)$/s.exec(entry)
    const path = match?.[1]
    if (path === undefined || !path.endsWith('.test.ts')) continue
    const content = readBaseRef(path)
    if (content === undefined) {
      throw new Error(`Could not read test ${path} at the pinned base commit.`)
    }
    files[path] = content
  }
  return files
}

export function writeRemediationArtifacts (outputDir: string, brief: string, proposal: ProposedPatch): void {
  // Refuse a stale directory or symlink before writing untrusted proposal data.
  mkdirSync(outputDir, { mode: 0o700 })
  for (const [name, content] of [
    ['brief.md', brief],
    ['proposed.patch', proposal.diff],
    ['summary.md', proposal.summary]
  ]) {
    writeFileSync(join(outputDir, name), content, { flag: 'wx', mode: 0o600 })
  }
}
