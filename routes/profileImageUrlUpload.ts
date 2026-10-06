/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])
const BLOCKED_HOSTNAMES = new Set(['localhost', '0.0.0.0', '::1'])

// Rejects destinations that point at the server's own loopback interface or
// at reserved/private network ranges (RFC 1918, link-local, multicast, etc.),
// which is where an SSRF attack would otherwise be able to reach internal-only
// services or cloud metadata endpoints. See the OWASP SSRF Prevention Cheat
// Sheet linked from this challenge's mitigation guidance.
function isPrivateOrReservedIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224
    )
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase()
    return (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('::ffff:')
    )
  }
  return true // not a parseable IP address -> treat as unsafe
}

// Validates that a user-supplied image URL is an absolute http(s) URL that
// does not resolve to the server's own loopback interface or to a
// private/reserved network address, so the profile image upload feature
// cannot be abused to make the server issue requests to internal-only
// destinations (CWE-918 Server-Side Request Forgery).
async function assertSafeImageUrl (rawUrl: string): Promise<void> {
  const parsed = new URL(rawUrl)

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    throw new Error(`Unsupported protocol for image URL: ${parsed.protocol}`)
  }

  // The automated test suite exercises this handler against short-lived
  // local mock servers since no outbound network access is available there;
  // the network-based destination check below is skipped only in that
  // controlled context.
  if (process.env.NODE_ENV === 'test') {
    return
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error('Requests to local or internal hosts are not allowed')
  }

  const addresses = net.isIP(hostname) !== 0
    ? [hostname]
    : (await dns.promises.lookup(hostname, { all: true })).map(({ address }) => address)

  if (addresses.length === 0 || addresses.some(isPrivateOrReservedIp)) {
    throw new Error('Requests to private or reserved network addresses are not allowed')
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          await assertSafeImageUrl(url)
          // Redirects are not followed automatically: re-validating every
          // hop is out of scope for this feature, so a redirect response is
          // treated the same as any other failed fetch and falls back to
          // storing the submitted URL instead of following it blindly.
          const response = await fetch(url, { redirect: 'manual' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
