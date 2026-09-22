/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Reads the one code-scanning alert URL a human pasted into a labelled issue body. Only the
// URL's owner/repo/alert-number are trusted from the issue; the finding's rule and path are
// fetched from the code-scanning API keyed by that number, never from the issue body (issue
// #2, user story 13; issue #29, user story 4), so editing the body cannot redirect triage at a
// different file.

const ALERT_URL_PATTERN = /https:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/security\/(code-scanning|secret-scanning|dependabot)\/(\d+)\b/g

export interface ParsedAlertUrl {
  owner: string
  repo: string
  alertNumber: number
}

export type AlertUrlFailureReason = 'missing' | 'ambiguous' | 'unsupported' | 'cross-repository'

export type AlertUrlResult =
  | { ok: true, alert: ParsedAlertUrl }
  | { ok: false, reason: AlertUrlFailureReason }

const FAILURE_DESCRIPTIONS: Record<AlertUrlFailureReason, string> = {
  missing: 'Triage could not find a code-scanning alert URL in this issue body (expected a ' +
    'link such as `https://github.com/<owner>/<repo>/security/code-scanning/<number>`).',
  ambiguous: 'This issue body references more than one scanner alert. Triage supports exactly ' +
    'one alert URL per issue.',
  unsupported: 'This issue references a scanner alert type triage does not support yet (only ' +
    'GitHub code-scanning alerts are supported).',
  'cross-repository': 'The referenced alert belongs to a different repository than this one. ' +
    'Triage only supports same-repository alerts.'
}

/** A one-sentence, human-readable explanation of why no alert was accepted, for the issue comment. */
export function describeAlertUrlFailure (reason: AlertUrlFailureReason): string {
  return FAILURE_DESCRIPTIONS[reason]
}

/**
 * Parses the one code-scanning alert URL a human pasted into `issueBody`, requiring it to name
 * `expectedRepo` (an `owner/repo` string, typically `GITHUB_REPOSITORY`). Distinct URL strings
 * are what count towards "ambiguous" - the same URL pasted twice is still one reference.
 */
export function parseAlertUrl (issueBody: string, expectedRepo: string): AlertUrlResult {
  const matches = [...issueBody.matchAll(ALERT_URL_PATTERN)]
  const distinctUrls = [...new Set(matches.map(match => match[0]))]

  if (distinctUrls.length === 0) {
    return { ok: false, reason: 'missing' }
  }
  if (distinctUrls.length > 1) {
    return { ok: false, reason: 'ambiguous' }
  }

  const [, owner, repo, kind, alertNumber] = matches[0]
  if (kind !== 'code-scanning') {
    return { ok: false, reason: 'unsupported' }
  }
  if (`${owner}/${repo}` !== expectedRepo) {
    return { ok: false, reason: 'cross-repository' }
  }

  return { ok: true, alert: { owner, repo, alertNumber: Number(alertNumber) } }
}
