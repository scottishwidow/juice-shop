/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import yaml from 'js-yaml'

import { createTaskflowDataDir } from './taskflowDataDir'
import { TASKFLOW_PACKAGE_NAME, taskflowPythonPath } from './taskflowPackage'

const MODEL_CONFIG_PATH = path.join(__dirname, '..', 'configs', 'model_config.yaml')

export function requireEnv (name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`)
  }
  return value
}

export function workflowRunLink (repo: string): string {
  const serverUrl = process.env.GITHUB_SERVER_URL ?? 'https://github.com'
  const runId = process.env.GITHUB_RUN_ID
  return runId === undefined ? '' : `${serverUrl}/${repo}/actions/runs/${runId}`
}

export function readTaskflowModel (configPath: string = MODEL_CONFIG_PATH): string {
  const config = yaml.load(readFileSync(configPath, 'utf8')) as { models?: { claude?: unknown } } | undefined
  const model = config?.models?.claude
  if (typeof model !== 'string' || model === '') {
    throw new Error(`${configPath} names no model under models.claude`)
  }
  return model
}

export interface TaskflowProcessOptions {
  taskflow: string
  globals: Record<string, string | number>
  workspace: string
  dataDirPrefix: string
}

export type TaskflowProcessOutcome =
  | { ok: true, outputs: Record<string, unknown> }
  | { ok: false, reason: string }

export function runTaskflowProcess (
  options: TaskflowProcessOptions,
  spawnTaskflow: typeof spawnSync = spawnSync
): TaskflowProcessOutcome {
  const dataDir = createTaskflowDataDir(options.dataDirPrefix)
  const globals = Object.entries(options.globals).flatMap(([name, value]) => ['-g', `${name}=${value}`])

  const result = spawnTaskflow('python3', [
    '-m', 'seclab_taskflow_agent',
    '-t', `${TASKFLOW_PACKAGE_NAME}.taskflows.${options.taskflow}`,
    '-m', `${TASKFLOW_PACKAGE_NAME}.configs.model_config`,
    ...globals
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: requireEnv('ANTHROPIC_API_KEY'),
      CONTAINER_WORKSPACE: options.workspace,
      LOG_DIR: path.join(dataDir, 'logs'),
      XDG_DATA_HOME: dataDir,
      PYTHONPATH: taskflowPythonPath()
    }
  })

  if (result.error !== undefined) {
    console.error(result.error)
  }
  if (result.stdout !== undefined && result.stdout !== '') {
    console.log(result.stdout)
  }
  if (result.stderr !== undefined && result.stderr !== '') {
    console.error(result.stderr)
  }

  if (result.error !== undefined) {
    return { ok: false, reason: `The TaskFlow process failed to start: ${result.error.message}.` }
  }
  if (result.signal !== null) {
    return { ok: false, reason: `The TaskFlow process was terminated by signal ${result.signal}.` }
  }
  if (result.status !== 0) {
    return { ok: false, reason: `The TaskFlow process exited with status ${result.status ?? 'unknown'}.` }
  }

  const manifest = readManifest(path.join(dataDir, 'seclab-taskflow-agent', 'artifacts'))
  return { ok: true, outputs: manifest?.outputs ?? {} }
}

interface RunManifest {
  outputs?: Record<string, unknown>
}

function readManifest (artifactsRoot: string): RunManifest | undefined {
  if (!existsSync(artifactsRoot)) {
    return undefined
  }
  const sessionId = readdirSync(artifactsRoot)[0]
  if (sessionId === undefined) {
    return undefined
  }
  const manifestPath = path.join(artifactsRoot, sessionId, 'manifest.json')
  if (!existsSync(manifestPath)) {
    return undefined
  }
  try {
    return JSON.parse(readFileSync(manifestPath, 'utf8')) as RunManifest
  } catch {
    return undefined
  }
}
