/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'

// A taskflow's output schema validates the agent's final message inside the runner, and a
// rejection there exits the run before taskflowVerdict.ts or remediationProposal.ts
// sees anything. Both parsers ignore properties they do not declare, so a schema that closes
// additional properties discards a result the workflow could have published (issue #32).

const TASKFLOWS = ['triage', 'remediate']

function nodesOf (value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) {
    return value.flatMap(nodesOf)
  }
  if (typeof value !== 'object' || value === null) {
    return []
  }
  const node = value as Record<string, unknown>
  return [node, ...Object.values(node).flatMap(nodesOf)]
}

void describe('taskflow output schemas', () => {
  for (const taskflow of TASKFLOWS) {
    void it(`keeps ${taskflow} no stricter than the parser that consumes it`, () => {
      const taskflowPath = path.resolve(__dirname, `../taskflows/${taskflow}.yaml`)
      const document = yaml.load(readFileSync(taskflowPath, 'utf8'))

      const closed = nodesOf(document).filter((node) => node.additionalProperties === false)

      assert.deepEqual(closed, [])
    })
  }
})
