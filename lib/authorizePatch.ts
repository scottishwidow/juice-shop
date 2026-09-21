/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import yaml from 'js-yaml'

import { addedLinesOf, touchedPathsOf } from './diffFacts'

export type BaseRefReader = (path: string) => string | undefined

export type RefusalReason =
  | 'override-file-modified'
  | 'lint-suppression-added'
  | 'type-suppression-added'
  | 'snippet-coupled'
  | 'solve-coupled'
  | 'path-not-allowed'

export type AuthorizationResult =
  | { allowed: true }
  | { allowed: false, reason: RefusalReason }

const OVERRIDE_FILE_PATH = '.taskflow/allowlist.yml'
const SNIPPET_COUPLING_MARKER = 'vuln-code-snippet'
const SOLVE_COUPLING_MARKER = 'challengeUtils.solve'
const LINT_SUPPRESSION_MARKERS = ['eslint-disable']
const TYPE_SUPPRESSION_MARKERS = ['@ts-ignore', '@ts-expect-error']

interface AllowlistOverrideEntry {
  allow?: string[]
}

function countOccurrences (content: string, marker: string): number {
  return content.split(marker).length - 1
}

function overrideAllowedPaths (readBaseRef: BaseRefReader): Set<string> {
  const allowed = new Set<string>()
  const raw = readBaseRef(OVERRIDE_FILE_PATH)
  if (raw === undefined) {
    return allowed
  }
  const parsed = yaml.load(raw) as Record<string, AllowlistOverrideEntry> | null | undefined
  if (!parsed) {
    return allowed
  }
  for (const entry of Object.values(parsed)) {
    for (const path of entry?.allow ?? []) {
      allowed.add(path)
    }
  }
  return allowed
}

function couplingReasonOf (targetPath: string, readBaseRef: BaseRefReader): RefusalReason | undefined {
  const content = readBaseRef(targetPath) ?? ''
  if (countOccurrences(content, SNIPPET_COUPLING_MARKER) > 0) {
    return 'snippet-coupled'
  }
  if (countOccurrences(content, SOLVE_COUPLING_MARKER) > 0) {
    return 'solve-coupled'
  }
  return undefined
}

export interface AllowList {
  paths: string[]
  targetAllowed: boolean
  couplingReason?: RefusalReason
}

/**
 * Computes the allow-list for `targetPath`: the alert's own path, granted unless the base-ref
 * copy of the file carries snippet or solve coupling, plus any paths granted by
 * `.taskflow/allowlist.yml` on the base ref (see docs/agents/security-triage.md#allow-list).
 * Shared by `authorizePatch` and the remediation brief (issue #7), so both read the same
 * allow-list rather than two independently maintained copies of this logic.
 */
export function computeAllowList (targetPath: string, readBaseRef: BaseRefReader): AllowList {
  const overrideAllowed = overrideAllowedPaths(readBaseRef)
  const couplingReason = couplingReasonOf(targetPath, readBaseRef)
  const targetAllowed = couplingReason === undefined || overrideAllowed.has(targetPath)

  const paths = new Set(overrideAllowed)
  if (targetAllowed) {
    paths.add(targetPath)
  }

  return { paths: [...paths], targetAllowed, couplingReason }
}

/**
 * Decides whether a model-authored patch may become a pull request. Every input is either
 * passed in directly or read from the base ref via `readBaseRef`, never from the patched
 * tree, so a patch cannot widen its own authorization (see
 * docs/adr/0002-authorization-inputs-read-from-base-ref.md).
 */
export function authorizePatch (targetPath: string, diff: string, readBaseRef: BaseRefReader): AuthorizationResult {
  const touchedPaths = touchedPathsOf(diff)

  if (touchedPaths.has(OVERRIDE_FILE_PATH)) {
    return { allowed: false, reason: 'override-file-modified' }
  }

  for (const addedLine of addedLinesOf(diff)) {
    if (LINT_SUPPRESSION_MARKERS.some(marker => addedLine.includes(marker))) {
      return { allowed: false, reason: 'lint-suppression-added' }
    }
    if (TYPE_SUPPRESSION_MARKERS.some(marker => addedLine.includes(marker))) {
      return { allowed: false, reason: 'type-suppression-added' }
    }
  }

  const allowList = computeAllowList(targetPath, readBaseRef)
  const allowedPaths = new Set(allowList.paths)

  for (const path of touchedPaths) {
    if (!allowedPaths.has(path)) {
      if (path === targetPath && allowList.couplingReason !== undefined) {
        return { allowed: false, reason: allowList.couplingReason }
      }
      return { allowed: false, reason: 'path-not-allowed' }
    }
  }

  return { allowed: true }
}
