import { spawnSync } from 'node:child_process'
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { copyInstalledDependencies, prepareAgentWorkspace } from '../lib/agentWorkspace'
import { createTaskflowDataDir } from '../lib/taskflowDataDir'
import { taskflowPythonPath } from '../lib/taskflowPackage'
import { parseTaskflowVerdict, describeTaskflowVerdictFailure, type TaskflowVerdict } from '../lib/taskflowVerdict'
import {
  readTriageAlert,
  TRIAGE_ALERT_DIR,
  TRIAGE_VERDICT_DIR,
  writeTriageFailure,
  writeTriageVerdict,
  type TriageAlertArtifact,
  type TriageAlert,
  type TriageFailure
} from '../lib/triageArtifact'

function requireEnv (name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable ${name}`)
  }
  return value
}

export type TaskflowRunOutcome =
  | { ok: true, verdict: TaskflowVerdict }
  | { ok: false, reason: string }

export function runTaskflow (
  alert: TriageAlert,
  workspace: string,
  spawnTaskflow: typeof spawnSync = spawnSync
): TaskflowRunOutcome {
  const dataDir = createTaskflowDataDir('security-triage-taskflow-')

  const result = spawnTaskflow('python3', [
    '-m', 'seclab_taskflow_agent',
    '-t', 'security_triage_taskflow.taskflows.triage',
    '-m', 'security_triage_taskflow.configs.model_config',
    '-g', `alert_number=${alert.alertNumber}`,
    '-g', `rule_id=${alert.ruleId}`,
    '-g', `path=${alert.path}`,
    '-g', `message=${alert.message}`
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      ANTHROPIC_API_KEY: requireEnv('ANTHROPIC_API_KEY'),
      CONTAINER_WORKSPACE: workspace,
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

  const artifactsRoot = path.join(dataDir, 'seclab-taskflow-agent', 'artifacts')
  const manifest = readManifest(artifactsRoot)
  const outcome = parseTaskflowVerdict(manifest?.outputs?.investigate)
  if (!outcome.ok) {
    return { ok: false, reason: describeTaskflowVerdictFailure(outcome.reason) }
  }
  return { ok: true, verdict: outcome.verdict }
}

interface RunManifest {
  outputs?: Record<string, unknown>
}

function readManifest (artifactsRoot: string): RunManifest | undefined {
  if (!existsSync(artifactsRoot)) {
    return undefined
  }
  const sessions = readdirSync(artifactsRoot)
  const sessionId = sessions[0]
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

export interface SecurityTriageDependencies {
  readAlert: () => TriageAlertArtifact
  prepareWorkspace: () => string
  runTaskflow: (alert: TriageAlert, workspace: string) => TaskflowRunOutcome
  writeVerdict: (verdict: TaskflowVerdict) => void
  writeFailure: (failure: TriageFailure) => void
}

const DEFAULT_DEPENDENCIES: SecurityTriageDependencies = {
  readAlert: () => readTriageAlert(TRIAGE_ALERT_DIR),
  prepareWorkspace: () => {
    const workspace = prepareAgentWorkspace()
    copyInstalledDependencies(workspace)
    return workspace
  },
  runTaskflow: (alert, workspace) => runTaskflow(alert, workspace),
  writeVerdict: verdict => { writeTriageVerdict(TRIAGE_VERDICT_DIR, verdict) },
  writeFailure: failure => { writeTriageFailure(TRIAGE_VERDICT_DIR, failure) }
}

export function runSecurityTriage (dependencies: SecurityTriageDependencies = DEFAULT_DEPENDENCIES): boolean {
  const artifact = dependencies.readAlert()
  if (artifact.kind !== 'alert') {
    dependencies.writeFailure({ message: 'The triage job received no alert to investigate.' })
    return false
  }

  const outcome = dependencies.runTaskflow(artifact.alert, dependencies.prepareWorkspace())
  if (!outcome.ok) {
    dependencies.writeFailure({ message: outcome.reason })
    return false
  }

  dependencies.writeVerdict(outcome.verdict)
  return true
}

if (require.main === module) {
  try {
    if (!runSecurityTriage()) {
      process.exitCode = 1
    }
  } catch (error: unknown) {
    console.error(error)
    writeTriageFailure(TRIAGE_VERDICT_DIR, { message: 'The triage job failed with an unexpected error.' })
    process.exitCode = 1
  }
}
