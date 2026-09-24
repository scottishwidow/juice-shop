/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'

export const TASKFLOW_PACKAGE_NAME = 'security_triage_taskflow'
export const TASKFLOW_PACKAGE_PATH = `.github/${TASKFLOW_PACKAGE_NAME}`

// The runner imports the package by its dotted module name, so its parent directory goes on
// PYTHONPATH. The security-triage workflow's lint job sets the same value.
export function taskflowPythonPath (): string {
  const packageParent = path.join(process.cwd(), path.dirname(TASKFLOW_PACKAGE_PATH))
  return [packageParent, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter)
}
