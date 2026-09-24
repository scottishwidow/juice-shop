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

export function computeCouplingEvidence (targetPath: string, readBaseRef: BaseRefReader): CouplingEvidence {
  const content = readBaseRef(targetPath) ?? ''
  return {
    snippetCoupled: countOccurrences(content, SNIPPET_COUPLING_MARKER) > 0,
    solveCoupled: countOccurrences(content, SOLVE_COUPLING_MARKER) > 0,
    isTestCode: isTestCodePath(targetPath)
  }
}
