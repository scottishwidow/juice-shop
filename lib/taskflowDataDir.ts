/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { mkdtempSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

// The agent opens its render log through `logging.FileHandler` while the module is imported,
// which does not create the parent directory, so `LOG_DIR` has to exist before the process
// starts or the run dies before the first model call.
export function createTaskflowDataDir (prefix: string): string {
  const dataDir = mkdtempSync(path.join(tmpdir(), prefix))
  mkdirSync(path.join(dataDir, 'logs'), { recursive: true })
  return dataDir
}
