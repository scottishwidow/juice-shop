/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { parsePatch } from 'diff'
import type { CheckResult } from './gateChecks'

// The one identity this automation is authorized to author and sign commits as: the
// workflow's own machine identity, by direct analogy to `TRIAGE_AUTHOR_LOGIN` in
// lib/trustedVerdict.ts (the only identity the `triage` job can post comments as). It is
// hardcoded, not read from any config or environment variable, so nothing in a diff or a
// misconfigured runner can widen or fabricate it (docs/agents/security-triage.md, PR
// compliance contract: "Never invent an identity or sign on behalf of a person").
export const GATE_COMMIT_IDENTITY = {
  name: 'github-actions[bot]',
  email: '41898282+github-actions[bot]@users.noreply.github.com'
} as const

export interface CommitRecord {
  authorName: string
  authorEmail: string
  trailer: string
}

export type IdentityRefusalReason = 'compliance-identity-unauthorized' | 'compliance-signoff-missing'

const SIGNOFF_LINE = `Signed-off-by: ${GATE_COMMIT_IDENTITY.name} <${GATE_COMMIT_IDENTITY.email}>`

/** A single commit is authorized only if it is authored as the gate's own identity. */
function commitIsAuthorized (commit: CommitRecord): boolean {
  return commit.authorName === GATE_COMMIT_IDENTITY.name && commit.authorEmail === GATE_COMMIT_IDENTITY.email
}

/**
 * A commit's DCO sign-off is valid only when it names the same identity that authored it. An
 * AI co-author trailer, or a sign-off for a different name or email, is not a DCO sign-off
 * (docs/agents/issue-tracker.md, PR compliance step 4).
 */
function commitIsSignedOff (commit: CommitRecord): boolean {
  return commit.trailer.split('\n').some(line => line.trim() === SIGNOFF_LINE)
}

export function commitIsAuthorizedAndSignedOff (commit: CommitRecord): boolean {
  return commitIsAuthorized(commit) && commitIsSignedOff(commit)
}

/**
 * Checks every commit the gate is about to publish, not just the latest one
 * (docs/agents/issue-tracker.md, PR compliance step 4). Returns the first distinguishable
 * refusal reason found: an unauthorized identity is checked before a missing sign-off, since
 * a sign-off from the wrong identity is itself an authorization problem, not a formatting one.
 */
export function everyCommitAuthorizedAndSignedOff (commits: CommitRecord[]):
{ ok: true } | { ok: false, reason: IdentityRefusalReason } {
  for (const commit of commits) {
    if (!commitIsAuthorized(commit)) {
      return { ok: false, reason: 'compliance-identity-unauthorized' }
    }
    if (!commitIsSignedOff(commit)) {
      return { ok: false, reason: 'compliance-signoff-missing' }
    }
  }
  return { ok: true }
}

export type DestinationRefusalReason = 'compliance-destination-unconfigured'

// The only two destinations this contract recognizes (docs/agents/issue-tracker.md, PR
// compliance step 1). An unrecognized repository resolves to nothing rather than a guessed
// default, so the gate never opens a PR against a base branch nobody decided on.
export const KNOWN_DESTINATIONS: Record<string, string> = {
  'scottishwidow/juice-shop': 'master',
  'juice-shop/juice-shop': 'develop'
}

export interface Destination {
  repo: string
  base: string
}

export function resolveDestination (repo: string): Destination | undefined {
  const base = KNOWN_DESTINATIONS[repo]
  return base === undefined ? undefined : { repo, base }
}

export interface AiDisclosure {
  models: string[] | 'unknown'
  instructionsKnown: boolean
}

export interface PrMetadata {
  alertNumber: number
  ruleId: string
  targetPath: string
  baseCommit: string
  issueNumber: number
  destination: Destination
  aiDisclosure: AiDisclosure
  validation: CheckResult[]
}

export type MetadataRefusalReason = 'compliance-metadata-incomplete'

/**
 * All the facts a reviewer needs to check the PR against its authorization without reading
 * workflow logs (docs/agents/security-triage.md: "so a mismatch is visible without reading
 * the workflow logs"). Missing any of them blocks PR creation rather than publishing a PR
 * with an incomplete disclosure.
 */
export function metadataIsComplete (metadata: PrMetadata): boolean {
  return Number.isInteger(metadata.alertNumber) &&
    metadata.ruleId.length > 0 &&
    metadata.targetPath.length > 0 &&
    /^[0-9a-f]{40}$/.test(metadata.baseCommit) &&
    Number.isInteger(metadata.issueNumber) &&
    metadata.validation.length > 0 &&
    (metadata.aiDisclosure.models === 'unknown' || metadata.aiDisclosure.models.length > 0)
}

/**
 * The single place the Affirmation checkbox's truth is computed, so the gate script cannot
 * check it independently of whether the requirements it asserts were actually met
 * (docs/agents/security-triage.md: "Affirmation is checked only when all applicable
 * requirements are met. Draft status does not waive a requirement.").
 */
export function affirmationSatisfied (metadata: PrMetadata, allChecksPassed: boolean, identityOk: boolean): boolean {
  return metadataIsComplete(metadata) && allChecksPassed && identityOk
}

function addedLinesByPath (diffText: string): Map<string, string[]> {
  const result = new Map<string, string[]>()
  for (const patch of parsePatch(diffText)) {
    const fileName = patch.newFileName?.replace(/^[ab]\//, '')
    if (fileName === undefined) continue
    const added: string[] = []
    for (const hunk of patch.hunks) {
      for (const line of hunk.lines) {
        if (line.startsWith('+') && !line.startsWith('+++')) {
          added.push(line.slice(1))
        }
      }
    }
    result.set(fileName, [...(result.get(fileName) ?? []), ...added].sort())
  }
  return result
}

function mapsEqual (a: Map<string, string[]>, b: Map<string, string[]>): boolean {
  if (a.size !== b.size) return false
  for (const [path, lines] of a) {
    const other = b.get(path)
    if (other === undefined || other.length !== lines.length) return false
    if (lines.some((line, index) => line !== other[index])) return false
  }
  return true
}

/**
 * The diff the gate is about to publish must be exactly the trusted regression addition plus
 * the authorized proposal - no more, no less (docs/agents/security-triage.md: "verify the
 * final diff is only that addition plus the authorized proposal. Do not widen the patch
 * author's allow-list."). This is defense in depth on top of `authorizePatch`'s path and
 * suppression checks, guarding the composed diff rather than the proposal alone.
 */
export function finalDiffIsExactlyRegressionPlusProposal (
  finalDiff: string, regressionDiff: string, proposalDiff: string
): boolean {
  const expected = new Map<string, string[]>()
  for (const [path, lines] of addedLinesByPath(regressionDiff)) {
    expected.set(path, [...(expected.get(path) ?? []), ...lines].sort())
  }
  for (const [path, lines] of addedLinesByPath(proposalDiff)) {
    expected.set(path, [...(expected.get(path) ?? []), ...lines].sort())
  }
  return mapsEqual(addedLinesByPath(finalDiff), expected)
}
