/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { authorizePatch, type AuthorizationResult, type BaseRefReader, type RefusalReason } from './authorizePatch'
import {
  baselineMatchesExpectation,
  regressionArtifactTouchesOnlyExpectedPath,
  regressionFullyPasses,
  type BaselineRefusalReason,
  type TestRunSummary
} from './regressionBaseline'
import { allChecksPassed, type CheckResult } from './gateChecks'
import {
  everyCommitAuthorizedAndSignedOff,
  finalDiffIsExactlyRegressionPlusProposal,
  metadataIsComplete,
  resolveDestination,
  type AiDisclosure,
  type CommitRecord,
  type DestinationRefusalReason,
  type IdentityRefusalReason,
  type MetadataRefusalReason,
  type PrMetadata
} from './prCompliance'
import { describeVerdictRefusal, selectTrustedVerdict, type IssueComment, type VerdictRefusalReason } from './trustedVerdict'

export type ComplianceRefusalReason = 'compliance-policy-unavailable'
export type GateRefusalReason = RefusalReason | ComplianceRefusalReason
export type GateDecision = AuthorizationResult | { allowed: false, reason: ComplianceRefusalReason }

// The trusted policy the gate must be able to read before it decides anything (issue #8's
// PR compliance follow-up to issue #2). This is a precondition, not part of #9's full
// compliance check: it only proves the base ref carries the policy the gate will need.
const REQUIRED_POLICY_PATHS = [
  'CONTRIBUTING.md',
  '.github/PULL_REQUEST_TEMPLATE.md',
  'docs/agents/issue-tracker.md'
]

function policyIsReadable (readBaseRef: BaseRefReader): boolean {
  return REQUIRED_POLICY_PATHS.every(path => readBaseRef(path) !== undefined)
}

/**
 * The gate's single authorization entry point. The workflow calls only this function and
 * performs no authorization logic of its own (issue #8). It refuses explicitly when the
 * trusted contribution policy cannot be read from the base ref, rather than silently
 * proceeding against the patched tree; otherwise it delegates entirely to `authorizePatch`.
 */
export function decidePatchGate (targetPath: string, alertNumber: number, diff: string, readBaseRef: BaseRefReader): GateDecision {
  if (!policyIsReadable(readBaseRef)) {
    return { allowed: false, reason: 'compliance-policy-unavailable' }
  }
  return authorizePatch(targetPath, alertNumber, diff, readBaseRef)
}

const REFUSAL_DESCRIPTIONS: Record<GateRefusalReason, string> = {
  'path-not-allowed': 'The diff touches a path outside the allow-list computed for this alert.',
  'snippet-coupled': 'The target file carries snippet coupling (a `vuln-code-snippet` marker) and is denied by default.',
  'solve-coupled': 'The target file carries solve coupling (a `challengeUtils.solve` call) and is denied by default.',
  'lint-suppression-added': 'The diff adds an `eslint-disable` suppression, which is refused independent of the allow-list.',
  'type-suppression-added': 'The diff adds a `@ts-ignore` or `@ts-expect-error` suppression, which is refused independent of the allow-list.',
  'override-file-modified': 'The diff touches the allow-list override file itself, which is never inside any allow-list.',
  'compliance-policy-unavailable': 'The trusted contribution policy (CONTRIBUTING.md, the PR template, or the issue-tracker doc) could not be read from the base ref.'
}

/** A one-sentence, maintainer-facing explanation of a refusal reason, for the issue comment. */
export function describeGateRefusal (reason: GateRefusalReason): string {
  return REFUSAL_DESCRIPTIONS[reason]
}

// Retry-with-feedback must exist and be disabled (issue #8): a second attempt that succeeds
// would conceal that the first was refused. This flag is the single point that would need to
// change to wire a retry, and nothing in the gate script reads it.
export const RETRY_WITH_FEEDBACK_ENABLED = false

export interface RetryFeedback {
  reason: GateRefusalReason
  message: string
}

/**
 * Composes the feedback a second patch-author attempt would receive after a refusal.
 * Implemented so the mechanism is testable, but never invoked by the gate script: refusal is
 * terminal, and only a human removing `sec:nopatch` after reading the reason starts remediation
 * again.
 */
export function buildRetryFeedback (targetPath: string, decision: { allowed: false, reason: GateRefusalReason }): RetryFeedback {
  return {
    reason: decision.reason,
    message: `The previous proposal for ${targetPath} was refused: ${describeGateRefusal(decision.reason)}`
  }
}

// --- Issue #9: the full PR-compliance decision, on top of #8's authorization decision -----

export type OutcomeRefusalReason =
  | GateRefusalReason
  | VerdictRefusalReason
  | 'verdict-target-mismatch'
  | DestinationRefusalReason
  | BaselineRefusalReason
  | 'diff-widens-authorized-scope'
  | IdentityRefusalReason
  | 'compliance-validation-failed'
  | MetadataRefusalReason

export interface GateOutcomeInput {
  repo: string
  alertNumber: number
  alert: { ruleId: string, path: string }
  issueNumber: number
  baseCommit: string
  readBaseRef: BaseRefReader
  comments: IssueComment[]
  proposedDiff: string
  regressionDiff: string | undefined
  finalDiff: string
  commits: CommitRecord[]
  checkResults: CheckResult[]
  baselinePreSummary: TestRunSummary
  baselinePostSummary: TestRunSummary
  aiDisclosure: AiDisclosure
}

export type GateOutcome =
  | { allowed: true, prMetadata: PrMetadata }
  | { allowed: false, reason: OutcomeRefusalReason }

/**
 * The gate's full decision on whether an authorized diff may become a pull request. Extends
 * `decidePatchGate` (issue #8's authorization decision) with everything issue #9 and the
 * carried-over ADR-0005 requirements add: the diff must come from the triage job's own
 * trusted verdict, bound to the alert and base commit this run actually resolved; the trusted
 * regression must reproduce its known baseline failure before the proposal is applied and
 * pass in full afterward; the composed diff published to the PR must be exactly that
 * regression plus the authorized proposal; every commit must be authored and signed off by
 * the gate's own identity; every required check must have passed; and the PR metadata must be
 * complete. Each precondition is checked in order and short-circuits on the first failure, so
 * a refusal always names the first thing that was actually wrong.
 */
export function decideGateOutcome (input: GateOutcomeInput): GateOutcome {
  const destination = resolveDestination(input.repo)
  if (destination === undefined) {
    return { allowed: false, reason: 'compliance-destination-unconfigured' }
  }

  const verdictSelection = selectTrustedVerdict(input.comments, {
    alertNumber: input.alertNumber,
    baseCommit: input.baseCommit
  })
  if (!verdictSelection.selected) {
    return { allowed: false, reason: verdictSelection.reason }
  }
  const verdict = verdictSelection.verdict
  if (verdict.path !== input.alert.path || verdict.ruleId !== input.alert.ruleId) {
    return { allowed: false, reason: 'verdict-target-mismatch' }
  }

  const authorization = decidePatchGate(input.alert.path, input.alertNumber, input.proposedDiff, input.readBaseRef)
  if (!authorization.allowed) {
    return authorization
  }

  if (input.regressionDiff === undefined || !regressionArtifactTouchesOnlyExpectedPath(input.regressionDiff)) {
    return { allowed: false, reason: 'regression-artifact-unavailable' }
  }
  if (!baselineMatchesExpectation(input.baselinePreSummary)) {
    return { allowed: false, reason: 'baseline-not-reproduced' }
  }
  if (!regressionFullyPasses(input.baselinePostSummary)) {
    return { allowed: false, reason: 'regression-still-failing' }
  }

  if (!finalDiffIsExactlyRegressionPlusProposal(input.finalDiff, input.regressionDiff, input.proposedDiff)) {
    return { allowed: false, reason: 'diff-widens-authorized-scope' }
  }

  const identity = everyCommitAuthorizedAndSignedOff(input.commits)
  if (!identity.ok) {
    return { allowed: false, reason: identity.reason }
  }

  if (!allChecksPassed(input.checkResults)) {
    return { allowed: false, reason: 'compliance-validation-failed' }
  }

  const prMetadata: PrMetadata = {
    alertNumber: input.alertNumber,
    ruleId: input.alert.ruleId,
    targetPath: input.alert.path,
    baseCommit: input.baseCommit,
    issueNumber: input.issueNumber,
    destination,
    aiDisclosure: input.aiDisclosure,
    validation: input.checkResults
  }
  if (!metadataIsComplete(prMetadata)) {
    return { allowed: false, reason: 'compliance-metadata-incomplete' }
  }

  return { allowed: true, prMetadata }
}

const OUTCOME_REFUSAL_DESCRIPTIONS: Record<OutcomeRefusalReason, string> = {
  ...REFUSAL_DESCRIPTIONS,
  'no-verdict-comment': describeVerdictRefusal('no-verdict-comment'),
  'untrusted-verdict-author': describeVerdictRefusal('untrusted-verdict-author'),
  'malformed-verdict-comment': describeVerdictRefusal('malformed-verdict-comment'),
  'alert-number-mismatch': describeVerdictRefusal('alert-number-mismatch'),
  'base-commit-mismatch': describeVerdictRefusal('base-commit-mismatch'),
  'verdict-target-mismatch': 'The trusted verdict names a different rule or path than the code-scanning API returned for this alert.',
  'compliance-destination-unconfigured': 'This repository is not one of the known PR destinations (scottishwidow/juice-shop -> master, juice-shop/juice-shop -> develop).',
  'regression-artifact-unavailable': 'The trusted regression artifact for this alert could not be read from the base ref, or adds a path other than the fixed regression test.',
  'regression-apply-failed': 'The trusted regression could not be applied to the unmodified base ref.',
  'baseline-not-reproduced': 'Applying the regression alone to the unmodified base did not reproduce exactly the expected failure; the regression is not valid evidence.',
  'regression-still-failing': 'The regression did not pass in full once the authorized proposal was applied alongside it.',
  'diff-widens-authorized-scope': 'The composed diff is not exactly the trusted regression plus the authorized proposal.',
  'compliance-identity-unauthorized': 'A commit in this pull request was not authored as the gate\'s own authorized identity.',
  'compliance-signoff-missing': 'A commit in this pull request is missing a valid DCO sign-off from the gate\'s own authorized identity.',
  'compliance-validation-failed': 'A required gate check (type check, lint, server tests, API tests, or the regression) did not pass.',
  'compliance-metadata-incomplete': 'The pull request metadata (alert, rule, target, base commit, issue, or AI disclosure) is incomplete.'
}

/** A one-sentence, maintainer-facing explanation of a full-outcome refusal reason. */
export function describeOutcomeRefusal (reason: OutcomeRefusalReason): string {
  return OUTCOME_REFUSAL_DESCRIPTIONS[reason]
}
