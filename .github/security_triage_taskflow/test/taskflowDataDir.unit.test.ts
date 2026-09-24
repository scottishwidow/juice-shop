/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { statSync, rmSync } from 'node:fs'
import path from 'node:path'
import { createTaskflowDataDir } from '../lib/taskflowDataDir'

void describe('createTaskflowDataDir', () => {
  void it('creates the log directory the agent opens while importing its modules', () => {
    const dataDir = createTaskflowDataDir('taskflow-data-dir-test-')

    try {
      assert.equal(statSync(path.join(dataDir, 'logs')).isDirectory(), true)
    } finally {
      rmSync(dataDir, { recursive: true, force: true })
    }
  })

  void it('returns a distinct directory for each run', () => {
    const first = createTaskflowDataDir('taskflow-data-dir-test-')
    const second = createTaskflowDataDir('taskflow-data-dir-test-')

    try {
      assert.notEqual(first, second)
    } finally {
      rmSync(first, { recursive: true, force: true })
      rmSync(second, { recursive: true, force: true })
    }
  })
})
