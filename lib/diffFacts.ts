/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Single owner of unified-diff parsing for the security-triage gate (issue #13). Every module
// that answers a question about a diff - authorizePatch, regressionBaseline, prCompliance -
// reads it from here instead of walking `parsePatch` output itself, so the `a`/`b` prefix
// strip and the `/dev/null` sentinel are decided in exactly one place.

import { parsePatch, type StructuredPatchHunk } from 'diff'

export interface DiffFacts {
  touchedPaths: Set<string>
  addedLinesByPath: Map<string, string[]>
}

function normalizePatchPath (fileName: string | undefined): string | undefined {
  if (fileName === undefined || fileName === '/dev/null') {
    return undefined
  }
  return fileName.replace(/^[ab]\//, '')
}

function addedLinesOfHunks (hunks: StructuredPatchHunk[]): string[] {
  const added: string[] = []
  for (const hunk of hunks) {
    for (const line of hunk.lines) {
      if (line.startsWith('+') && !line.startsWith('+++')) {
        added.push(line.slice(1))
      }
    }
  }
  return added
}

/**
 * Parses a unified diff once and returns every fact the security-triage gate asks of it: which
 * paths it touches (old and new name, `a`/`b`-stripped, `/dev/null` excluded), and which lines
 * it adds, per new path.
 */
export function diffFactsOf (diffText: string): DiffFacts {
  const touchedPaths = new Set<string>()
  const addedLinesByPath = new Map<string, string[]>()

  for (const patch of parsePatch(diffText)) {
    const oldPath = normalizePatchPath(patch.oldFileName)
    const newPath = normalizePatchPath(patch.newFileName)
    if (oldPath !== undefined) touchedPaths.add(oldPath)
    if (newPath !== undefined) touchedPaths.add(newPath)

    if (newPath !== undefined) {
      const added = addedLinesOfHunks(patch.hunks)
      addedLinesByPath.set(newPath, [...(addedLinesByPath.get(newPath) ?? []), ...added])
    }
  }

  return { touchedPaths, addedLinesByPath }
}

/** Every path a diff touches, old and new name, normalized. */
export function touchedPathsOf (diffText: string): Set<string> {
  return diffFactsOf(diffText).touchedPaths
}

/** Every line a diff adds, across every file it touches, in diff order. */
export function addedLinesOf (diffText: string): string[] {
  return [...diffFactsOf(diffText).addedLinesByPath.values()].flat()
}

/** The lines a diff adds, per new path. */
export function addedLinesByPath (diffText: string): Map<string, string[]> {
  return diffFactsOf(diffText).addedLinesByPath
}
