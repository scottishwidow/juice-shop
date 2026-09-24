/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'
import { MODEL } from '../scripts/publish'

void describe('taskflow model configuration', () => {
  void it('states the model the taskflows run in the pull request disclosure', () => {
    const configPath = path.resolve(__dirname, '../configs/model_config.yaml')
    const config = yaml.load(readFileSync(configPath, 'utf8')) as { models: { claude: string } }

    assert.equal(MODEL, config.models.claude)
  })
})
