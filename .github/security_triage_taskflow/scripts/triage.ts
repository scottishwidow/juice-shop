import { spawnSync } from 'node:child_process'
import process from 'node:process'

import { copyInstalledDependencies, prepareAgentWorkspace } from '../lib/agentWorkspace'
import { runTaskflowProcess } from '../lib/taskflowRun'
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

export type TaskflowRunOutcome =
  | { ok: true, verdict: TaskflowVerdict }
  | { ok: false, reason: string }

export function runTaskflow (
  alert: TriageAlert,
  workspace: string,
  spawnTaskflow: typeof spawnSync = spawnSync
): TaskflowRunOutcome {
  const run = runTaskflowProcess({
    taskflow: 'triage',
    globals: {
      alert_number: alert.alertNumber,
      rule_id: alert.ruleId,
      path: alert.path,
      message: alert.message
    },
    workspace,
    dataDirPrefix: 'security-triage-taskflow-'
  }, spawnTaskflow)
  if (!run.ok) {
    return run
  }

  const outcome = parseTaskflowVerdict(run.outputs.investigate)
  if (!outcome.ok) {
    return { ok: false, reason: describeTaskflowVerdictFailure(outcome.reason) }
  }
  return { ok: true, verdict: outcome.verdict }
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
