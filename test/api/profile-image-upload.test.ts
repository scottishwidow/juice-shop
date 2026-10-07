/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import path from 'node:path'
import fs from 'node:fs'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { isSafeImageUrl } from '../../routes/profileImageUrlUpload'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/profile/image/file', () => {
  void it('POST profile image file valid for JPG format', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image file invalid type', async () => {
    const file = path.resolve(__dirname, '../files/invalidProfileImageType.docx')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)

    assert.equal(res.status, 415)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Profile image upload does not accept this file type'))
  })

  void it('POST profile image file forbidden for anonymous user', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const res = await request(app)
      .post('/profile/image/file')
      .attach('file', file)

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST profile image file rejected for unrecognizable file content', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', Buffer.from('not an image, just plain text content'), 'random.bin')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Illegal file type'))
  })
})

void describe('/profile/image/url', () => {
  void it('POST profile image URL valid for image available online', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'cataas.com/cat')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image URL redirects even for invalid image URL', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://notanimage.here/100/100')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image URL forbidden for anonymous user', { skip: 'FIXME runs into "socket hang up"' }, async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .field('imageUrl', 'cataas.com/cat')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST valid image with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .set('Content-Length', '42')
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})

void describe('isSafeImageUrl (SSRF protection)', () => {
  void it('allows plain http(s) URLs pointing to public hostnames', () => {
    assert.equal(isSafeImageUrl('https://example.com/cat.jpg'), true)
    assert.equal(isSafeImageUrl('http://cataas.com/cat'), true)
  })

  void it('rejects non-http(s) schemes', () => {
    assert.equal(isSafeImageUrl('file:///etc/passwd'), false)
    assert.equal(isSafeImageUrl('ftp://example.com/cat.jpg'), false)
    assert.equal(isSafeImageUrl('gopher://example.com/cat.jpg'), false)
  })

  void it('rejects unparsable URLs', () => {
    assert.equal(isSafeImageUrl('not a url'), false)
    assert.equal(isSafeImageUrl('cataas.com/cat'), false)
  })

  void it('rejects localhost and loopback addresses', () => {
    assert.equal(isSafeImageUrl('http://localhost/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://127.0.0.1/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://[::1]/photo.jpg'), false)
  })

  void it('rejects the cloud metadata address and other private/reserved IPv4 ranges', () => {
    assert.equal(isSafeImageUrl('http://169.254.169.254/latest/meta-data/'), false)
    assert.equal(isSafeImageUrl('http://10.0.0.5/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://172.16.0.5/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://192.168.1.5/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://0.0.0.0/photo.jpg'), false)
  })

  void it('rejects private/link-local IPv6 addresses', () => {
    assert.equal(isSafeImageUrl('http://[fe80::1]/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://[fc00::1]/photo.jpg'), false)
    assert.equal(isSafeImageUrl('http://[::ffff:127.0.0.1]/photo.jpg'), false)
  })
})

void describe('/profile/image/url (with mocked fetch target)', () => {
  let token: string
  let userId: number
  let originalFetch: typeof fetch

  before(async () => {
    const { token: userToken } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    token = userToken
    userId = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).data.id
  })

  before(() => {
    originalFetch = global.fetch
  })

  after(() => {
    global.fetch = originalFetch
  })

  function mockFetchWith (imageBuffer: Buffer) {
    (global as any).fetch = mock.fn(async (input: string | URL) => {
      const url = input.toString()
      if (url.includes('non-ok')) {
        return new Response(null, { status: 404 })
      }
      if (url.includes('no-body')) {
        return new Response(null, { status: 204 })
      }
      return new Response(imageBuffer, { status: 200 })
    })
  }

  void it('POST with non-OK response falls back to storing URL as profile image', async () => {
    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))
    mockFetchWith(imageBuffer)

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://example.com/non-ok.jpg')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST with empty-body response (204) falls back to storing URL as profile image', async () => {
    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))
    mockFetchWith(imageBuffer)

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://example.com/no-body.jpg')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST with valid response writes file and redirects to profile', async () => {
    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))
    mockFetchWith(imageBuffer)

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://example.com/photo.jpg')
      .redirects(0)

    assert.equal(res.status, 302)
    assert.ok(res.headers.location?.endsWith('/profile'))
  })

  void it('POST with PNG URL extension saves file using PNG extension', async () => {
    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))
    mockFetchWith(imageBuffer)

    await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://example.com/photo.png')
      .redirects(0)

    assert.ok(
      fs.existsSync(`frontend/dist/frontend/assets/public/images/uploads/${userId}.png`),
      `Expected file frontend/dist/frontend/assets/public/images/uploads/${userId}.png to exist`
    )
  })

  void it('POST with unrecognised URL extension defaults to JPG extension', async () => {
    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))
    mockFetchWith(imageBuffer)

    await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://example.com/photo.bmp')
      .redirects(0)

    assert.ok(
      fs.existsSync(`frontend/dist/frontend/assets/public/images/uploads/${userId}.jpg`),
      `Expected file frontend/dist/frontend/assets/public/images/uploads/${userId}.jpg to exist`
    )
  })

  void it('POST with a URL targeting a private/internal address falls back without making a request', async () => {
    const fetchMock = mock.fn(async () => new Response(Buffer.from('should never be called'), { status: 200 }))
    ;(global as any).fetch = fetchMock

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'http://127.0.0.1:1/internal.jpg')
      .redirects(0)

    assert.equal(res.status, 302)
    assert.equal(fetchMock.mock.calls.length, 0)
  })
})
