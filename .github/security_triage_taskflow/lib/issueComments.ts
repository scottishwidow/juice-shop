/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Single reader of an issue's comments for both the credential-free `remediate` job and the
// `gate` job (issue #16). GitHub returns 30 comments per page by default; on a discussion
// longer than that, reading only page one hides the trusted verdict and the workflow reports a
// refusal that names the wrong cause ("no verdict comment") instead of the real one
// ("didn't look far enough"). Both callers page to the end via the response's `Link` header,
// and differ only in which headers they send: `remediate` sends none (it holds no credential),
// `gate` sends its own token instead of spending the shared unauthenticated rate limit.

import type { IssueComment } from './trustedVerdict'

export type FetchImpl = (url: string, init: { headers: Record<string, string> }) => Promise<{
  ok: boolean
  status: number
  text: () => Promise<string>
  json: () => Promise<unknown>
  headers: { get: (name: string) => string | null }
}>

function nextPageUrl (linkHeader: string | null): string | undefined {
  if (linkHeader === null) {
    return undefined
  }
  for (const part of linkHeader.split(',')) {
    const match = /<([^>]+)>\s*;\s*rel="next"/.exec(part.trim())
    if (match !== null) {
      return match[1]
    }
  }
  return undefined
}

/**
 * Reads every comment on an issue, following `Link: rel="next"` until GitHub reports no more
 * pages. A failed page read throws immediately, with the page's own status and body, rather
 * than returning a partial list that would be reported as an absent verdict.
 */
export async function fetchAllIssueComments (
  repo: string,
  issueNumber: string,
  headers: Record<string, string>,
  fetchImpl: FetchImpl = fetch
): Promise<IssueComment[]> {
  const comments: IssueComment[] = []
  let url: string | undefined = `https://api.github.com/repos/${repo}/issues/${issueNumber}/comments?per_page=100`

  while (url !== undefined) {
    const response = await fetchImpl(url, { headers })
    if (!response.ok) {
      throw new Error(`Reading issue comments failed: ${response.status} ${await response.text()}`)
    }
    const page = await response.json() as unknown
    if (Array.isArray(page)) {
      comments.push(...page as IssueComment[])
    }
    url = nextPageUrl(response.headers.get('link'))
  }

  return comments
}

/** The credential-free read `remediate` and `triage` use: no token, public data only. */
export async function fetchIssueCommentsUnauthenticated (
  repo: string, issueNumber: string, fetchImpl?: FetchImpl
): Promise<IssueComment[]> {
  return await fetchAllIssueComments(repo, issueNumber, { accept: 'application/vnd.github+json' }, fetchImpl)
}

/** The `gate` job's own read, spending its own token rather than the shared anonymous quota. */
export async function fetchIssueCommentsAuthenticated (
  repo: string, issueNumber: string, token: string, fetchImpl?: FetchImpl
): Promise<IssueComment[]> {
  return await fetchAllIssueComments(
    repo, issueNumber, { accept: 'application/vnd.github+json', authorization: `Bearer ${token}` }, fetchImpl
  )
}
