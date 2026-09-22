/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export type BaseRefReader = (path: string) => string | undefined

export interface CouplingEvidence {
  snippetCoupled: boolean
  solveCoupled: boolean
  isTestCode: boolean
}

const SNIPPET_COUPLING_MARKER = 'vuln-code-snippet'
const SOLVE_COUPLING_MARKER = 'challengeUtils.solve'
const TEST_CODE_PREFIXES = ['test/', 'cypress/']

function countOccurrences (content: string, marker: string): number {
  return content.split(marker).length - 1
}

function isTestCodePath (path: string): boolean {
  return TEST_CODE_PREFIXES.some(prefix => path.startsWith(prefix))
}

/**
 * Reads deterministic, mechanical evidence about a scanner finding's target path, via
 * `readBaseRef` (see docs/adr/0002-authorization-inputs-read-from-base-ref.md): whether the
 * challenge-authoring markers are present, and whether the path is test code. This used to
 * mechanically decide the triage verdict (docs/adr/0001-mechanical-coupling-detection.md); it
 * no longer does (docs/adr/0009-taskflow-triage-implementation.md) - the agent investigating
 * the checkout derives the verdict, and is told these markers do not predetermine it. This
 * function now only supplies investigative context to the agent and informational evidence for
 * the verdict payload that `remediate`/`gate` still read.
 */
export function computeCouplingEvidence (targetPath: string, readBaseRef: BaseRefReader): CouplingEvidence {
  const content = readBaseRef(targetPath) ?? ''
  return {
    snippetCoupled: countOccurrences(content, SNIPPET_COUPLING_MARKER) > 0,
    solveCoupled: countOccurrences(content, SOLVE_COUPLING_MARKER) > 0,
    isTestCode: isTestCodePath(targetPath)
  }
}
