const URL_PATTERN = /(?:^|[\s(<])(https:\/\/[^\s<>()[\]]+)/gm
const ALERT_PATH_PATTERN = /^\/([^/]+)\/([^/]+)\/security\/(code-scanning|secret-scanning|dependabot)\/(\d+)\/?$/

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

export function describeAlertUrlFailure (reason: AlertUrlFailureReason): string {
  return FAILURE_DESCRIPTIONS[reason]
}

export function parseAlertUrl (issueBody: string, expectedRepo: string): AlertUrlResult {
  const references = [...issueBody.matchAll(URL_PATTERN)].flatMap(match => {
    const candidate = match[1].replace(/[.,;:!?]+$/, '')
    if (!URL.canParse(candidate)) {
      return []
    }
    const url = new URL(candidate)
    const pathMatch = ALERT_PATH_PATTERN.exec(url.pathname)
    if (url.hostname !== 'github.com' || pathMatch === null) {
      return []
    }
    const [, owner, repo, kind, alertNumber] = pathMatch
    return [{ candidate, owner, repo, kind, alertNumber }]
  })
  const distinctUrls = [...new Set(references.map(reference => reference.candidate))]

  if (distinctUrls.length === 0) {
    return { ok: false, reason: 'missing' }
  }
  if (distinctUrls.length > 1) {
    return { ok: false, reason: 'ambiguous' }
  }

  const { owner, repo, kind, alertNumber } = references[0]
  if (kind !== 'code-scanning') {
    return { ok: false, reason: 'unsupported' }
  }
  if (`${owner}/${repo}` !== expectedRepo) {
    return { ok: false, reason: 'cross-repository' }
  }

  return { ok: true, alert: { owner, repo, alertNumber: Number(alertNumber) } }
}
