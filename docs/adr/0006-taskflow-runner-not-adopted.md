---
status: accepted
---

# The SecLab TaskFlow Agent runner is not adopted; the security-triage workflow stays bespoke

Specification #2 was written in TaskFlow's vocabulary — personality, toolbox, brief, model
config — and the patch-gate override lives at `.taskflow/allowlist.yml`. Nothing delivered on
`feat/taskflow-demo` imports, configures, or invokes that runner: `triage.ts` and
`remediate.ts` call the Anthropic Messages API directly, with hand-managed headers and a
pinned model version; system prompts are string arrays assembled by concatenation in each
script; GitHub access is split between the `gh` CLI and raw `fetch`; the tool-free constraint
on the `triage` call (ADR-0004) is expressed by omitting a request field, not by declaring an
empty toolbox. This repository — its `package.json`, lockfile, `.github/`, and workflow
history — carries no dependency on, or reference to, the runner beyond that borrowed
vocabulary and namespace. There is nothing in this fork's toolchain to adopt it into.

We keep the hand-rolled implementation and stop borrowing the name. The workflow does not
run on the SecLab TaskFlow Agent, and nothing in this repository claims otherwise:

- `.taskflow/allowlist.yml` is renamed to `.security-triage/allowlist.yml`, matching the
  workflow's own name rather than an uninvolved runner's namespace convention.
- "Toolbox" in `docs/agents/security-triage.md` and `triage.ts` named two different things
  under one borrowed word: the `triage` job's GitHub write permission (comment creation only)
  and the model call's declared tool set (empty, per ADR-0004). Both call sites now name the
  one they mean, instead of the word TaskFlow uses for an agent's declared capabilities.
- "Brief" is kept. It names an actual artifact this workflow builds and hands to the patch
  author (`lib/remediationBrief.ts`) — a scoped, plain-English instructions document — and
  that meaning does not depend on TaskFlow using the same word for a job-definition field.
  "Personality" and "model config" do not appear in this repository outside specification #2
  itself, which this ADR does not edit; there is nothing here to rename.
- Issues #22–#24 (running triage and the patch author on the runner, reaching GitHub through
  its toolbox) do not proceed. They depended on this ADR adopting the runner; it does not.

## The archived proof of concept's schema omission is intentional, and stays

An earlier proof of concept for the patch task deliberately gave the model no output schema
for its proposed fix, because the framework's JSON decoding could reject a well-formed
unified diff (embedded newlines and quoting inside a JSON string field are exactly the
content a diff is made of). The delivered `remediate.ts` keeps that same reasoning
independently of the runner question above: `propose_patch` is a single Anthropic tool with
one string parameter carrying the raw diff text, validated after the fact by
`parseProposedPatch` (`lib/proposedPatch.ts`), rather than decoded through a schema that
would need to round-trip a diff through JSON. This is not an oversight inherited from
unfamiliarity with the runner; it is the same constraint that made the proof of concept
bypass structured decoding in the first place, and it holds regardless of which runner (or
none) issues the request.

## Consequences

The deterministic modules — `authorizePatch`, `triageVerdict`, `trustedVerdict`,
`baseRefReader`, `proposedPatch`, `remediationBrief` — take and return plain data and never
import a runner API. That was already required independently, so this ADR changes nothing
about how they are built or tested (spec #2, "developer changing the gate" user stories).

The three-job credential split (ADR-0002) is unaffected: it is a GitHub Actions property,
not something a runner provides either way.

Renaming `.taskflow/allowlist.yml` touches `lib/authorizePatch.ts`, its tests, and
`docs/agents/security-triage.md`; any override file already committed to a base ref under the
old path must move with it.

Reopening this decision later — for example if the runner becomes a real dependency of this
fork for other workflows — starts from a hand-rolled baseline that has already been hardened
issue by issue (#13–#20), not from the unhardened state this ADR closes out.
