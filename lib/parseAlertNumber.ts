/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const ALERT_REFERENCE_PATTERN = /\balert:?\s*#(\d+)\b/i

/**
 * Reads the code-scanning alert number a human transcribed into an issue body. Only the
 * number is trusted from the issue; the finding's path and rule are read from the scanner
 * API keyed by this number, never from the issue body (issue #2, user story 13), so editing
 * the body cannot redirect triage at a different file.
 */
export function parseAlertNumber (issueBody: string): number | undefined {
  const match = ALERT_REFERENCE_PATTERN.exec(issueBody)
  if (match === null) {
    return undefined
  }
  return Number(match[1])
}
