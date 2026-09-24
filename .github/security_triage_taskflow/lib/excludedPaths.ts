/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TASKFLOW_PACKAGE_NAME, TASKFLOW_PACKAGE_PATH } from './taskflowPackage'

// The one rule the remediation agent cannot edit its way around. There is no allow-list any
// more (issue #31): the agent may change any source or test file, including an intentional
// Juice Shop vulnerability. What it may never change is the machinery that decides whether
// its change gets published, or anything holding a credential - otherwise a proposed change
// could widen its own publishing authority in the same run that publishes it.
//
// This is evaluated by the credentialed publishing job against the paths the diff actually
// touches, not by the agent and not from anything the agent wrote.

export type ExclusionCategory = 'workflow' | 'credential' | 'authorization-policy'

export interface ExcludedPath {
  path: string
  category: ExclusionCategory
}

interface ExclusionRule {
  category: ExclusionCategory
  matches: (path: string) => boolean
}

function underAny (...prefixes: string[]): (path: string) => boolean {
  return path => prefixes.some(prefix => path === prefix || path.startsWith(`${prefix}/`))
}

const CREDENTIAL_FILE = /(^|\/)(\.env[^/]*|[^/]*\.(pem|key|pfx|p12|jks|keystore))$/i

const RULES: ExclusionRule[] = [
  // The security workflow's own decision-making code: the taskflow and personality that
  // instruct the agent, the scripts that publish its work, and the modules that decide what
  // is trusted and what is excluded. It sits under .github/, so this rule must precede the
  // workflow rule to keep its category. The runner starts from the repository root, where
  // Python finds a package before any PYTHONPATH entry, so a root copy is excluded as well.
  { category: 'authorization-policy', matches: underAny(TASKFLOW_PACKAGE_PATH, TASKFLOW_PACKAGE_NAME) },
  // Workflow and CI definitions, including the workflow that runs this remediation.
  { category: 'workflow', matches: underAny('.github', '.husky') },
  // Anything that is, or reads, a key.
  { category: 'credential', matches: underAny('encryptionkeys') },
  { category: 'credential', matches: path => CREDENTIAL_FILE.test(path) }
]

/** Every excluded path in the proposed change, with the category that excludes it. */
export function findExcludedPaths (paths: string[]): ExcludedPath[] {
  const excluded: ExcludedPath[] = []
  for (const path of paths) {
    const rule = RULES.find(candidate => candidate.matches(path))
    if (rule !== undefined) {
      excluded.push({ path, category: rule.category })
    }
  }
  return excluded
}

const CATEGORY_DESCRIPTIONS: Record<ExclusionCategory, string> = {
  workflow: 'workflow and CI definitions',
  credential: 'credential and key material',
  'authorization-policy': "the security workflow's own authorization policy and publishing code"
}

/** A maintainer-facing list of what was excluded and why, for the failure comment. */
export function describeExcludedPaths (excluded: ExcludedPath[]): string {
  return excluded
    .map(entry => `- \`${entry.path}\` (${CATEGORY_DESCRIPTIONS[entry.category]})`)
    .join('\n')
}
