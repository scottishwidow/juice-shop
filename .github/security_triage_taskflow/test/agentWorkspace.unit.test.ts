/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { afterEach, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { copyInstalledDependencies } from '../lib/agentWorkspace'

const temporaryDirs: string[] = []

afterEach(() => {
  for (const dir of temporaryDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
})

function temporaryDir (prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix))
  temporaryDirs.push(dir)
  return dir
}

void describe('copyInstalledDependencies', () => {
  void it('gives the workspace its own copy of the installed dependencies', () => {
    const checkout = temporaryDir('security-agent-checkout-')
    mkdirSync(path.join(checkout, 'node_modules', 'hbs', 'lib'), { recursive: true })
    writeFileSync(path.join(checkout, 'node_modules', 'hbs', 'lib', 'hbs.js'), 'original\n')
    const workspace = temporaryDir('security-agent-workspace-')

    copyInstalledDependencies(workspace, checkout)
    writeFileSync(path.join(workspace, 'node_modules', 'hbs', 'lib', 'hbs.js'), 'edited by the agent\n')

    assert.equal(readFileSync(path.join(checkout, 'node_modules', 'hbs', 'lib', 'hbs.js'), 'utf8'), 'original\n')
  })

  void it('keeps relative links relative, so they resolve inside the container', () => {
    const checkout = temporaryDir('security-agent-checkout-')
    mkdirSync(path.join(checkout, 'node_modules', '.bin'), { recursive: true })
    mkdirSync(path.join(checkout, 'node_modules', 'tsx', 'dist'), { recursive: true })
    writeFileSync(path.join(checkout, 'node_modules', 'tsx', 'dist', 'cli.mjs'), '')
    symlinkSync('../tsx/dist/cli.mjs', path.join(checkout, 'node_modules', '.bin', 'tsx'))
    const workspace = temporaryDir('security-agent-workspace-')

    copyInstalledDependencies(workspace, checkout)

    const link = path.join(workspace, 'node_modules', '.bin', 'tsx')
    assert.equal(lstatSync(link).isSymbolicLink(), true)
    assert.equal(readlinkSync(link), '../tsx/dist/cli.mjs')
  })
})
