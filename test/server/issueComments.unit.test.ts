/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  fetchAllIssueComments,
  fetchIssueCommentsAuthenticated,
  fetchIssueCommentsUnauthenticated,
  type FetchImpl
} from '../../lib/issueComments'
import { selectTrustedVerdict } from '../../lib/trustedVerdict'
import { encodeVerdictPayload } from '../../lib/verdictPayload'

function jsonResponse (body: unknown, linkHeader?: string): Awaited<ReturnType<FetchImpl>> {
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
    json: async () => body,
    headers: { get: (name: string) => (name.toLowerCase() === 'link' ? (linkHeader ?? null) : null) }
  }
}

function pagedFetch (pages: unknown[][]): { impl: FetchImpl, calls: Array<{ url: string, headers: Record<string, string> }> } {
  const calls: Array<{ url: string, headers: Record<string, string> }> = []
  const impl: FetchImpl = async (url, init) => {
    calls.push({ url, headers: init.headers })
    const index = calls.length - 1
    const isLast = index === pages.length - 1
    const link = isLast ? undefined : `<https://api.github.com/next?page=${index + 2}>; rel="next"`
    return jsonResponse(pages[index], link)
  }
  return { impl, calls }
}

void describe('fetchAllIssueComments', () => {
  void it('concatenates every page until the Link header names no next page', async () => {
    const { impl } = pagedFetch([
      [{ body: 'first' }],
      [{ body: 'second' }],
      [{ body: 'third' }]
    ])

    const comments = await fetchAllIssueComments('owner/repo', '9', { accept: 'application/vnd.github+json' }, impl)

    assert.deepEqual(comments.map(c => c.body), ['first', 'second', 'third'])
  })

  void it('finds a verdict comment that only appears on a page past the first', async () => {
    const verdictBody = [
      '**Verdict: exploitable**',
      '',
      encodeVerdictPayload({
        alertNumber: 6,
        baseCommit: '5bc7ce9292a2237e64771a8b2b71b3df730d0800',
        ruleId: 'js/path-injection',
        path: 'routes/keyServer.ts',
        verdict: 'exploitable',
        snippetCoupled: false,
        solveCoupled: false,
        isTestCode: false
      })
    ].join('\n')

    const firstPage = Array.from({ length: 30 }, (_, i) => ({ body: `noise ${i}`, user: { login: 'someone', type: 'User' } }))
    const secondPage = [{ body: verdictBody, user: { login: 'github-actions[bot]', type: 'Bot' } }]
    const { impl } = pagedFetch([firstPage, secondPage])

    const comments = await fetchAllIssueComments('owner/repo', '9', { accept: 'application/vnd.github+json' }, impl)
    const selection = selectTrustedVerdict(comments, {
      alertNumber: 6,
      baseCommit: '5bc7ce9292a2237e64771a8b2b71b3df730d0800'
    })

    assert.equal(selection.selected, true)
  })

  void it('stops paging once a page reports no next link', async () => {
    const { impl, calls } = pagedFetch([[{ body: 'only page' }]])

    await fetchAllIssueComments('owner/repo', '9', { accept: 'application/vnd.github+json' }, impl)

    assert.equal(calls.length, 1)
  })

  void it('throws with the failing page\'s own status and body rather than returning a partial list', async () => {
    const impl: FetchImpl = async () => ({
      ok: false,
      status: 502,
      text: async () => 'upstream error',
      json: async () => { throw new Error('should not be called') },
      headers: { get: () => null }
    })

    await assert.rejects(
      fetchAllIssueComments('owner/repo', '9', { accept: 'application/vnd.github+json' }, impl),
      /502/
    )
  })

  void it('propagates a failure from a later page rather than reporting an absent verdict', async () => {
    const calls: string[] = []
    const impl: FetchImpl = async (url) => {
      calls.push(url)
      if (calls.length === 1) {
        return jsonResponse([{ body: 'page one' }], '<https://api.github.com/next?page=2>; rel="next"')
      }
      return { ok: false, status: 500, text: async () => 'boom', json: async () => { throw new Error('unused') }, headers: { get: () => null } }
    }

    await assert.rejects(
      fetchAllIssueComments('owner/repo', '9', { accept: 'application/vnd.github+json' }, impl),
      /Reading issue comments failed: 500/
    )
  })
})

void describe('fetchIssueCommentsUnauthenticated', () => {
  void it('sends no authorization header', async () => {
    const { impl, calls } = pagedFetch([[]])

    await fetchIssueCommentsUnauthenticated('owner/repo', '9', impl)

    assert.equal(calls[0].headers.authorization, undefined)
  })
})

void describe('fetchIssueCommentsAuthenticated', () => {
  void it('sends the given token as a bearer authorization header', async () => {
    const { impl, calls } = pagedFetch([[]])

    await fetchIssueCommentsAuthenticated('owner/repo', '9', 'gh-token-value', impl)

    assert.equal(calls[0].headers.authorization, 'Bearer gh-token-value')
  })
})
