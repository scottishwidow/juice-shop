/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrReservedIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
    return true
  }
  const [a, b] = parts
  if (a === 0) return true // "this" network
  if (a === 10) return true // private network
  if (a === 127) return true // loopback
  if (a === 100 && b >= 64 && b <= 127) return true // carrier-grade NAT
  if (a === 169 && b === 254) return true // link-local incl. cloud metadata endpoint
  if (a === 172 && b >= 16 && b <= 31) return true // private network
  if (a === 192 && b === 168) return true // private network
  if (a === 192 && b === 0 && parts[2] === 0) return true // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true // benchmark testing
  if (a >= 224) return true // multicast & reserved
  return false
}

function isPrivateOrReservedIPv6 (ip: string): boolean {
  const normalized = ip.toLowerCase()
  if (normalized === '::1' || normalized === '::') return true // loopback / unspecified
  if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true // link-local fe80::/10
  if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return true // unique local fc00::/7
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  if (mapped) return isPrivateOrReservedIPv4(mapped[1])
  return false
}

// Blocks the most obvious Server-Side Request Forgery vectors (non-HTTP(S)
// schemes as well as loopback, link-local, carrier-grade-NAT, multicast and
// other private/reserved IP ranges - including the cloud metadata address
// 169.254.169.254) before the server is allowed to fetch a user-supplied URL.
export function isSafeImageUrl (rawUrl: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (hostname === '' || hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return false
  }

  const ipVersion = net.isIP(hostname)
  if (ipVersion === 4) {
    return !isPrivateOrReservedIPv4(hostname)
  }
  if (ipVersion === 6) {
    return !isPrivateOrReservedIPv6(hostname)
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!isSafeImageUrl(url)) {
            throw new Error('Invalid or disallowed profile image URL: only http(s) URLs pointing to public hosts are allowed')
          }
          const response = await fetch(url)
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
