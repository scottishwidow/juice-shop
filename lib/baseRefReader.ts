/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import type { BaseRefReader } from './authorizePatch'

export type GitRunner = (args: string[]) => string | undefined

const MAX_FILE_BYTES = 256 * 1024

/**
 * Decides whether a path may be read at all. The patch author's target path arrives in a
 * comment, so it is attacker-reachable until proven otherwise: absolute paths, Windows drive
 * and UNC forms, `..` traversal, option-like paths and NUL bytes are all rejected before the
 * path reaches any reader (issue #7 security follow-up, ADR-0005).
 */
export function isRepoRelativePath (path: string): boolean {
  if (path === '' || path.length > 4096) {
    return false
  }
  if (path.startsWith('-') || path.startsWith('/') || path.startsWith('\\')) {
    return false
  }
  if (/^[A-Za-z]:/.test(path) || path.includes('\0')) {
    return false
  }
  return !path.split(/[/\\]/).some(segment => segment === '..')
}

/**
 * A `BaseRefReader` bound to one commit. Every read is `git cat-file` against that commit,
 * so only a regular tracked file of the pinned base ref can be read: an untracked file, a
 * directory, a path outside the checkout, and a file added after triage all read as
 * `undefined`. A symlink is a blob in git, so it reads as its own link text and is never
 * followed out of the checkout.
 */
export function createBaseRefReader (commit: string, runGit: GitRunner): BaseRefReader {
  return (path: string) => {
    if (!isRepoRelativePath(path)) {
      return undefined
    }
    const object = `${commit}:${path}`
    if (runGit(['cat-file', '-t', object])?.trim() !== 'blob') {
      return undefined
    }
    const content = runGit(['cat-file', 'blob', object])
    if (content === undefined || Buffer.byteLength(content, 'utf8') > MAX_FILE_BYTES) {
      return undefined
    }
    return content
  }
}
