/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export type BaseRefReader = (path: string) => string | undefined

export type Verdict = 'exploitable' | 'not-applicable' | 'coupled-needs-decision'

export interface CouplingEvidence {
  snippetCoupled: boolean
  solveCoupled: boolean
}

export interface TriageResult {
  verdict: Verdict
  coupling: CouplingEvidence
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
 * Decides the triage verdict for a scanner finding's target path, reading the file's base-ref
 * content via `readBaseRef` (see docs/adr/0002-authorization-inputs-read-from-base-ref.md).
 * Test code is not-applicable regardless of coupling, because it is not shipped. Both
 * coupling mechanisms are always reported, named separately, because they fail in opposite
 * ways (see routes/CONTEXT.md).
 */
export function determineVerdict (targetPath: string, readBaseRef: BaseRefReader): TriageResult {
  const isTestCode = isTestCodePath(targetPath)
  const content = readBaseRef(targetPath) ?? ''
  const coupling: CouplingEvidence = {
    snippetCoupled: countOccurrences(content, SNIPPET_COUPLING_MARKER) > 0,
    solveCoupled: countOccurrences(content, SOLVE_COUPLING_MARKER) > 0
  }

  let verdict: Verdict
  if (isTestCode) {
    verdict = 'not-applicable'
  } else if (coupling.snippetCoupled || coupling.solveCoupled) {
    verdict = 'coupled-needs-decision'
  } else {
    verdict = 'exploitable'
  }

  return { verdict, coupling, isTestCode }
}
