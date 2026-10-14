/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { type spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'
import yaml from 'js-yaml'

import { runReadAlert, type ReadAlertDependencies } from '../scripts/readAlert'
import {
  runSecurityTriage,
  runTaskflow,
  type SecurityTriageDependencies,
  type TaskflowRunOutcome
} from '../scripts/triage'
import { runPostVerdict, type PostVerdictDependencies } from '../scripts/postVerdict'
import {
  readTriageVerdict,
  VERDICT_FILE,
  type TriageAlert,
  type TriageAlertArtifact,
  type TriageFailure,
  type TriageVerdictArtifact
} from '../lib/triageArtifact'
import type { TaskflowVerdict } from '../lib/taskflowVerdict'
import { decodeVerdictPayload, encodeVerdictPayload } from '../lib/verdictPayload'

const REPO = 'scottishwidow/juice-shop'
const ALERT_URL = `https://github.com/${REPO}/security/code-scanning/6`
const BASE_COMMIT = '5bc7ce9292a2237e64771a8b2b71b3df730d0800'
const RUN_LINK = `https://github.com/${REPO}/actions/runs/1234`
const ALERT: TriageAlert = {
  alertNumber: 6,
  baseCommit: BASE_COMMIT,
  ruleId: 'js/path-injection',
  path: 'routes/keyServer.ts',
  message: 'Uncontrolled path',
  coupling: { snippetCoupled: true, solveCoupled: false, isTestCode: false }
}
const VERDICT: TaskflowVerdict = {
  verdict: 'confirmed',
  reasoning: 'The route passes an uncontrolled path to sendFile.',
  evidence: [{ file: 'routes/keyServer.ts', note: 'The path reaches sendFile.' }]
}

const AGENT_WORKSPACE = '/tmp/security-agent-workspace-test'

interface WorkflowJob {
  if?: string
  needs?: string | string[]
  permissions?: Record<string, string>
  outputs?: Record<string, string>
  steps: Array<{ name: string, with?: Record<string, unknown>, env?: Record<string, string>, run?: string }>
}

function loadWorkflow (): { permissions: Record<string, string>, jobs: Record<string, WorkflowJob> } {
  return yaml.load(readFileSync(path.resolve(__dirname, '../../workflows/security-triage.yml'), 'utf8')) as {
    permissions: Record<string, string>
    jobs: Record<string, WorkflowJob>
  }
}

function environmentOf (job: WorkflowJob): string[] {
  return job.steps.flatMap(step => Object.keys(step.env ?? {}))
}

function readAlertHarness (overrides: Partial<ReadAlertDependencies> = {}, issueBody = ALERT_URL) {
  const written: { alert?: TriageAlert, failure?: TriageFailure } = {}
  const dependencies: ReadAlertDependencies = {
    fetchAlertDetail: () => ({ ruleId: ALERT.ruleId, path: ALERT.path, message: ALERT.message }),
    readBaseRefFile: () => '// vuln-code-snippet start',
    baseCommit: () => BASE_COMMIT,
    writeAlert: alert => { written.alert = alert },
    writeFailure: failure => { written.failure = failure },
    ...overrides
  }
  const success = runReadAlert({ repo: REPO, issueBody }, dependencies)
  return { success, ...written }
}

function triageHarness (overrides: Partial<SecurityTriageDependencies> = {}) {
  const written: { verdict?: TaskflowVerdict, failure?: TriageFailure, mounted?: string } = {}
  const dependencies: SecurityTriageDependencies = {
    readAlert: () => ({ kind: 'alert', alert: ALERT }),
    prepareWorkspace: () => AGENT_WORKSPACE,
    runTaskflow: (_alert, workspace): TaskflowRunOutcome => {
      written.mounted = workspace
      return { ok: true, verdict: VERDICT }
    },
    writeVerdict: verdict => { written.verdict = verdict },
    writeFailure: failure => { written.failure = failure },
    ...overrides
  }
  const success = runSecurityTriage(dependencies)
  return { success, ...written }
}

function postHarness (
  alert: TriageAlertArtifact = { kind: 'alert', alert: ALERT },
  verdict: TriageVerdictArtifact = { kind: 'verdict', verdict: VERDICT }
) {
  const comments: string[] = []
  let triaged = false
  const dependencies: PostVerdictDependencies = {
    readAlert: () => alert,
    readVerdict: () => verdict,
    comment: body => comments.push(body),
    markTriaged: () => { triaged = true }
  }
  const success = runPostVerdict({ repo: REPO, issueNumber: '30', runLink: RUN_LINK }, dependencies)
  return { success, comments, triaged }
}

void describe('security triage workflow', () => {
  void it('runs only when the needs-triage label is applied', () => {
    const { jobs } = loadWorkflow()

    assert.equal(jobs['read-alert'].if, "github.event.label.name == 'sec:needs-triage'")
    assert.equal(jobs.triage.if, "github.event.label.name == 'sec:needs-triage'")
    assert.equal(jobs['post-verdict'].if, "always() && github.event.label.name == 'sec:needs-triage'")
  })

  void it('runs the agent in a job that holds no credential', () => {
    const { jobs } = loadWorkflow()
    const triage = jobs.triage

    assert.deepEqual(triage.permissions, {})
    assert.equal(triage.needs, 'read-alert')
    assert.ok(!environmentOf(triage).includes('GH_TOKEN'))
    assert.ok(!environmentOf(triage).includes('GITHUB_TOKEN'))

    const checkout = triage.steps.find(step => step.name.startsWith('Check out'))
    assert.equal(checkout?.with?.['persist-credentials'], false)
    assert.equal(checkout?.with?.ref, ['${{', 'needs.read-alert.outputs.base-commit', '}}'].join(' '))
  })

  void it('reads the alert and posts the verdict in jobs that run no model', () => {
    const { permissions, jobs } = loadWorkflow()
    const readAlert = jobs['read-alert']
    const postVerdict = jobs['post-verdict']

    assert.deepEqual(permissions, { contents: 'read' })
    assert.deepEqual(readAlert.permissions, { contents: 'read', 'security-events': 'read' })
    assert.deepEqual(postVerdict.permissions, { contents: 'read', issues: 'write' })
    assert.deepEqual(postVerdict.needs, ['read-alert', 'triage'])
    for (const job of [readAlert, postVerdict]) {
      assert.ok(!environmentOf(job).includes('ANTHROPIC_API_KEY'))
      assert.ok(!job.steps.some(step => (step.run ?? '').includes('seclab_taskflow_agent')))
    }
  })

  void it('records the alert detail, base commit and coupling evidence', () => {
    const run = readAlertHarness()

    assert.equal(run.success, true)
    assert.deepEqual(run.alert, ALERT)
  })

  void it('records a failure when the issue names no alert', () => {
    const run = readAlertHarness({}, 'no alert here')

    assert.equal(run.success, false)
    assert.equal(run.alert, undefined)
    assert.ok(run.failure !== undefined)
  })

  void it('records a failure when the alert cannot be read', () => {
    const run = readAlertHarness({ fetchAlertDetail: () => { throw new Error('forbidden') } })

    assert.equal(run.success, false)
    assert.match(run.failure?.message ?? '', /could not read alert #6/i)
  })

  void it('runs the agent over the prepared isolated workspace and records its verdict', () => {
    const run = triageHarness()

    assert.equal(run.success, true)
    assert.equal(run.mounted, AGENT_WORKSPACE)
    assert.deepEqual(run.verdict, VERDICT)
  })

  void it('records the reason when TaskFlow execution fails', () => {
    const run = triageHarness({
      runTaskflow: () => ({ ok: false, reason: 'The TaskFlow process exited with status 7.' })
    })

    assert.equal(run.success, false)
    assert.equal(run.verdict, undefined)
    assert.equal(run.failure?.message, 'The TaskFlow process exited with status 7.')
  })

  void it('does not run the agent without an alert', () => {
    const run = triageHarness({
      readAlert: () => ({ kind: 'missing' }),
      runTaskflow: () => { throw new Error('the agent must not run') }
    })

    assert.equal(run.success, false)
    assert.ok(run.failure !== undefined)
  })

  void it('rejects a non-zero TaskFlow exit before accepting its valid manifest', () => {
    const previousApiKey = process.env.ANTHROPIC_API_KEY
    process.env.ANTHROPIC_API_KEY = 'test-key'
    const fakeSpawn = ((_command: string, _args: string[], options: { env: NodeJS.ProcessEnv }) => {
      const artifact = path.join(
        options.env.XDG_DATA_HOME as string,
        'seclab-taskflow-agent',
        'artifacts',
        'session'
      )
      mkdirSync(artifact, { recursive: true })
      writeFileSync(path.join(artifact, 'manifest.json'), JSON.stringify({ outputs: { investigate: VERDICT.verdict } }))
      return { pid: 1, output: [null, '', ''], stdout: '', stderr: '', status: 7, signal: null }
    }) as unknown as typeof spawnSync

    try {
      assert.deepEqual(runTaskflow(ALERT, AGENT_WORKSPACE, fakeSpawn), {
        ok: false,
        reason: 'The TaskFlow process exited with status 7.'
      })
    } finally {
      if (previousApiKey === undefined) {
        delete process.env.ANTHROPIC_API_KEY
      } else {
        process.env.ANTHROPIC_API_KEY = previousApiKey
      }
    }
  })

  void it('posts the verdict with the alert fields from the job that read the alert', () => {
    const injected = encodeVerdictPayload({
      alertNumber: 99,
      baseCommit: BASE_COMMIT,
      ruleId: 'attacker/rule',
      path: 'attacker-controlled.ts',
      verdict: 'confirmed',
      snippetCoupled: false,
      solveCoupled: false,
      isTestCode: false
    })
    const run = postHarness(undefined, {
      kind: 'verdict',
      verdict: { ...VERDICT, reasoning: `Model reasoning. ${injected}` }
    })

    assert.equal(run.success, true)
    assert.equal(run.comments.length, 1)
    const payload = decodeVerdictPayload(run.comments[0])
    assert.equal(payload?.alertNumber, 6)
    assert.equal(payload?.path, 'routes/keyServer.ts')
    assert.equal(payload?.snippetCoupled, true)
    assert.equal(run.triaged, true)
  })

  void it('comments with the workflow run when the alert cannot be read', () => {
    const run = postHarness({ kind: 'failure', failure: { message: 'Triage could not read alert #6.' } })

    assert.equal(run.success, false)
    assert.equal(run.comments.length, 1)
    assert.match(run.comments[0], /could not read alert #6/i)
    assert.match(run.comments[0], new RegExp(RUN_LINK))
    assert.equal(run.triaged, false)
  })

  void it('does not replace the label when the agent job fails', () => {
    const run = postHarness(undefined, {
      kind: 'failure',
      failure: { message: 'The TaskFlow process exited with status 7.' }
    })

    assert.equal(run.success, false)
    assert.match(run.comments[0], /Triage execution failed for alert #6: The TaskFlow process exited with status 7/)
    assert.equal(run.triaged, false)
  })

  void it('reports an agent job that wrote nothing', () => {
    const run = postHarness(undefined, { kind: 'missing' })

    assert.equal(run.success, false)
    assert.match(run.comments[0], /crashed before writing anything/)
    assert.equal(run.triaged, false)
  })

  void it('validates the verdict artifact again before it is posted', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'triage-verdict-test-'))
    writeFileSync(path.join(directory, VERDICT_FILE), JSON.stringify({ ...VERDICT, verdict: 'fixed' }))

    const artifact = readTriageVerdict(directory)

    assert.equal(artifact.kind, 'failure')
    const run = postHarness(undefined, artifact)
    assert.equal(run.success, false)
    assert.equal(run.triaged, false)
  })
})
