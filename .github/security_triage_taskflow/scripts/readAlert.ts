import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import process from 'node:process'

import { computeCouplingEvidence } from '../lib/couplingEvidence'
import { parseAlertUrl, describeAlertUrlFailure } from '../lib/parseAlertUrl'
import { requireEnv } from '../lib/taskflowRun'
import {
  TRIAGE_ALERT_DIR,
  writeTriageAlert,
  writeTriageFailure,
  type TriageAlert,
  type TriageFailure
} from '../lib/triageArtifact'

export interface AlertDetail {
  ruleId: string
  path: string
  message: string
}

function fetchAlertDetail (repo: string, alertNumber: number): AlertDetail {
  const raw = execFileSync('gh', ['api', `repos/${repo}/code-scanning/alerts/${alertNumber}`], { encoding: 'utf8' })
  const alert = JSON.parse(raw) as {
    rule: { id: string }
    most_recent_instance: { location: { path: string }, message: { text: string } }
  }
  return {
    ruleId: alert.rule.id,
    path: alert.most_recent_instance.location.path,
    message: alert.most_recent_instance.message.text
  }
}

function readBaseRefFile (path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return undefined
  }
}

function baseCommit (): string {
  return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
}

export interface ReadAlertInput {
  repo: string
  issueBody: string
}

export interface ReadAlertDependencies {
  fetchAlertDetail: (repo: string, alertNumber: number) => AlertDetail
  readBaseRefFile: (path: string) => string | undefined
  baseCommit: () => string
  writeAlert: (alert: TriageAlert) => void
  writeFailure: (failure: TriageFailure) => void
}

const DEFAULT_DEPENDENCIES: ReadAlertDependencies = {
  fetchAlertDetail,
  readBaseRefFile,
  baseCommit,
  writeAlert: alert => { writeTriageAlert(TRIAGE_ALERT_DIR, alert) },
  writeFailure: failure => { writeTriageFailure(TRIAGE_ALERT_DIR, failure) }
}

export function runReadAlert (
  input: ReadAlertInput,
  dependencies: ReadAlertDependencies = DEFAULT_DEPENDENCIES
): boolean {
  const parsedAlert = parseAlertUrl(input.issueBody, input.repo)
  if (!parsedAlert.ok) {
    dependencies.writeFailure({ message: describeAlertUrlFailure(parsedAlert.reason) })
    return false
  }

  const alertNumber = parsedAlert.alert.alertNumber
  let detail: AlertDetail
  try {
    detail = dependencies.fetchAlertDetail(input.repo, alertNumber)
  } catch (error: unknown) {
    console.error(error)
    dependencies.writeFailure({ message: `Triage could not read alert #${alertNumber}.` })
    return false
  }

  dependencies.writeAlert({
    alertNumber,
    baseCommit: dependencies.baseCommit(),
    ...detail,
    coupling: computeCouplingEvidence(detail.path, dependencies.readBaseRefFile)
  })
  return true
}

function main (): void {
  const success = runReadAlert({
    repo: requireEnv('GITHUB_REPOSITORY'),
    issueBody: process.env.ISSUE_BODY ?? ''
  })
  if (!success) {
    process.exitCode = 1
  }
}

if (require.main === module) {
  try {
    main()
  } catch (error: unknown) {
    console.error(error)
    writeTriageFailure(TRIAGE_ALERT_DIR, { message: 'Triage failed with an unexpected error while reading the alert.' })
    process.exitCode = 1
  }
}
