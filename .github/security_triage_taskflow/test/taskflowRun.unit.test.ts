/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { readTaskflowModel } from '../lib/taskflowRun'

function writeConfig (content: string): string {
  const configPath = path.join(mkdtempSync(path.join(tmpdir(), 'model-config-')), 'model_config.yaml')
  writeFileSync(configPath, content)
  return configPath
}

void describe('readTaskflowModel', () => {
  void it('reads the model the taskflows run from the shipped configuration', () => {
    assert.match(readTaskflowModel(), /^claude-/)
  })

  void it('returns the model under models.claude', () => {
    assert.equal(readTaskflowModel(writeConfig('models:\n  claude: claude-test-1\n')), 'claude-test-1')
  })

  void it('rejects a configuration that names no model', () => {
    assert.throws(() => readTaskflowModel(writeConfig('models: {}\n')), /names no model under models.claude/)
  })
})
