/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildRemediationBrief,
  extractCodeStyleRule,
  extractComplianceInstructions,
  findCoveringTests,
  parseVerdictComment,
  type ParsedVerdict
} from '../../lib/remediationBrief'

function verdictComment (overrides: Partial<Record<'verdict' | 'rule' | 'path' | 'snippet' | 'solve' | 'testCode', string>> = {}): string {
  const fields = {
    verdict: 'exploitable',
    rule: 'js/path-injection',
    path: 'routes/keyServer.ts',
    snippet: 'no',
    solve: 'no',
    testCode: 'no',
    ...overrides
  }
  return [
    `**Verdict: ${fields.verdict}**`,
    '',
    `- Rule: \`${fields.rule}\``,
    `- Path: \`${fields.path}\``,
    `- Snippet coupling: ${fields.snippet}`,
    `- Solve coupling: ${fields.solve}`,
    `- Test code: ${fields.testCode}`,
    '',
    'Some prose explanation follows.'
  ].join('\n')
}

void describe('parseVerdictComment', () => {
  void it('reads all structured fields from a well-formed verdict comment', () => {
    const result = parseVerdictComment(verdictComment({ snippet: 'yes' }))

    assert.deepEqual(result, {
      verdict: 'exploitable',
      ruleId: 'js/path-injection',
      path: 'routes/keyServer.ts',
      snippetCoupled: true,
      solveCoupled: false,
      isTestCode: false
    })
  })

  void it('returns undefined when a required field is missing', () => {
    const malformed = 'Just some prose, no structured verdict here.'

    assert.equal(parseVerdictComment(malformed), undefined)
  })
})

void describe('extractComplianceInstructions', () => {
  const doc = [
    '| Role | Required compliance instructions |',
    '| --- | --- |',
    '| Triage (#6) | Report the alert. |',
    '| Patch author (#7) | Return only a diff within the allow-list. |'
  ].join('\n')

  void it('extracts the instruction text for the named role', () => {
    assert.equal(
      extractComplianceInstructions(doc, 'Patch author (#7)'),
      'Return only a diff within the allow-list.'
    )
  })

  void it('returns undefined when the role is not present', () => {
    assert.equal(extractComplianceInstructions(doc, 'Gate (#8-#9)'), undefined)
  })
})

void describe('extractCodeStyleRule', () => {
  void it('extracts the numbered code style requirement', () => {
    const doc = [
      '1. PRs must be based on master.',
      '2. The code _must_ be compliant with the configured ESLint rules based on the JS Standard Code Style.',
      '3. All PRs should have a dedicated scope.'
    ].join('\n')

    assert.equal(
      extractCodeStyleRule(doc),
      'The code _must_ be compliant with the configured ESLint rules based on the JS Standard Code Style.'
    )
  })

  void it('returns undefined when there is no second requirement', () => {
    assert.equal(extractCodeStyleRule('1. Only one rule here.'), undefined)
  })
})

void describe('findCoveringTests', () => {
  void it('finds a test file importing the target module', () => {
    const testFiles = {
      'test/server/keyServer.unit.test.ts': "import { serveKeyFiles } from '../../routes/keyServer'",
      'test/server/fileServer.unit.test.ts': "import { serveFile } from '../../routes/fileServer'"
    }

    assert.deepEqual(
      findCoveringTests('routes/keyServer.ts', testFiles),
      ['test/server/keyServer.unit.test.ts']
    )
  })

  void it('returns an empty list when no test imports the target module', () => {
    const testFiles = {
      'test/server/fileServer.unit.test.ts': "import { serveFile } from '../../routes/fileServer'"
    }

    assert.deepEqual(findCoveringTests('routes/keyServer.ts', testFiles), [])
  })
})

void describe('buildRemediationBrief', () => {
  const verdict: ParsedVerdict = {
    ruleId: 'js/path-injection',
    path: 'routes/keyServer.ts',
    verdict: 'exploitable',
    snippetCoupled: false,
    solveCoupled: false,
    isTestCode: false
  }

  void it('includes the alert, allow-list, code style, constraints and target content', () => {
    const brief = buildRemediationBrief({
      alertNumber: 6,
      verdict,
      targetContent: 'export const serveKeyFiles = () => {}',
      allowList: { paths: ['routes/keyServer.ts'], targetAllowed: true },
      codeStyleRule: 'The code must follow JS Standard Style.',
      complianceInstructions: 'Return only a diff within the allow-list.',
      coveringTests: {}
    })

    assert.match(brief, /Alert #6 \(`js\/path-injection`\) at `routes\/keyServer\.ts`/)
    assert.match(brief, /- `routes\/keyServer\.ts`/)
    assert.match(brief, /The code must follow JS Standard Style\./)
    assert.match(brief, /Return only a diff within the allow-list\./)
    assert.match(brief, /export const serveKeyFiles = \(\) => \{\}/)
    assert.doesNotMatch(brief, /not currently allow-listed/)
  })

  void it('warns when the target itself is not allow-listed', () => {
    const brief = buildRemediationBrief({
      alertNumber: 6,
      verdict: { ...verdict, snippetCoupled: true, verdict: 'coupled-needs-decision' },
      targetContent: 'export const serveKeyFiles = () => {}',
      allowList: { paths: [], targetAllowed: false, couplingReason: 'snippet-coupled' },
      codeStyleRule: 'The code must follow JS Standard Style.',
      complianceInstructions: 'Return only a diff within the allow-list.',
      coveringTests: {}
    })

    assert.match(brief, /not currently allow-listed \(reason: `snippet-coupled`\)/)
  })

  void it('includes covering tests and the regression artifact when supplied', () => {
    const brief = buildRemediationBrief({
      alertNumber: 6,
      verdict,
      targetContent: 'export const serveKeyFiles = () => {}',
      allowList: { paths: ['routes/keyServer.ts'], targetAllowed: true },
      codeStyleRule: 'The code must follow JS Standard Style.',
      complianceInstructions: 'Return only a diff within the allow-list.',
      coveringTests: { 'test/server/keyServer.unit.test.ts': "import { serveKeyFiles } from '../../routes/keyServer'" },
      regressionArtifact: { path: 'docs/agents/artifacts/alert-6-regression.patch', content: 'diff --git a/x b/x' }
    })

    assert.match(brief, /test\/server\/keyServer\.unit\.test\.ts/)
    assert.match(brief, /diff --git a\/x b\/x/)
  })
})
