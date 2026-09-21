/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { formatValidationSection } from './gateChecks'
import type { PrMetadata } from './prCompliance'

export function buildPrTitle (metadata: PrMetadata): string {
  return `fix(security): remediate ${metadata.ruleId} at ${metadata.targetPath} (alert #${metadata.alertNumber})`
}

/**
 * Fills the structure of .github/PULL_REQUEST_TEMPLATE.md with the facts a reviewer needs to
 * check this PR against its authorization without reading workflow logs: the alert number
 * and authorizing rule (docs/agents/security-triage.md), the originating issue, and the
 * gate's own validation results, reported exactly as observed
 * (docs/agents/security-triage.md, PR compliance contract). The Affirmation checkbox's state
 * is passed in already decided by `affirmationSatisfied`, never recomputed here.
 */
export function buildPrBody (metadata: PrMetadata, affirmationChecked: boolean): string {
  const modelsLine = metadata.aiDisclosure.models === 'unknown'
    ? 'unknown'
    : metadata.aiDisclosure.models.join(', ')
  const instructionsLine = metadata.aiDisclosure.instructionsKnown
    ? 'Scoped remediation brief assembled by lib/remediationBrief.ts from the trusted base ref (docs/agents/security-triage.md).'
    : 'unknown'

  return [
    '### Description',
    '',
    `Remediates CodeQL alert #${metadata.alertNumber} (\`${metadata.ruleId}\`) at ` +
    `\`${metadata.targetPath}\`, authorized against base commit \`${metadata.baseCommit}\`.`,
    '',
    `Closes #${metadata.issueNumber}.`,
    '',
    '### Validation',
    '',
    formatValidationSection(metadata.validation),
    '',
    '### AI Tool Disclosure',
    '',
    '- [x] My contribution includes AI-generated content, as disclosed below:',
    '',
    'AI tools: Anthropic Messages API (patch proposal), the security-triage patch gate (mechanical checks and application, no model call)',
    `Models and versions: ${modelsLine}`,
    `Key prompts or instructions: ${instructionsLine}`,
    '',
    '### Affirmation',
    '',
    `- [${affirmationChecked ? 'x' : ' '}] My code follows the [CONTRIBUTING.md](https://github.com/${metadata.destination.repo}/blob/${metadata.destination.base}/CONTRIBUTING.md) guidelines`
  ].join('\n')
}
