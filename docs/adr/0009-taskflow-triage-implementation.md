---
status: accepted
---

# TaskFlow triage implementation: package layout, pinned versions, and compatibility

> Partly superseded by [ADR-0010](0010-taskflow-remediation-implementation.md). The sections
> below marked *Superseded* reasoned about the bespoke `remediate`/`gate` jobs that ADR-0010
> deleted, and no longer describe the code. The pins, the package layout and the
> `capture: response`/`manifest.json` reasoning are unchanged and still current.

ADR-0007 decided to replace `triage` with the SecLab TaskFlow Agent runner and assumed a
released, mutually compatible pair of `seclab-taskflow-agent` and `seclab-taskflows` versions
would carry the native Anthropic backend and the container-shell source-access toolbox. That
assumption does not hold: installing both packages together and reading their actual grammar
models shows the following, verified directly against the installed packages rather than
documentation:

- `seclab-taskflows==0.1.0` (the latest PyPI release) declares an exact dependency on
  `seclab-taskflow-agent==0.4.0`; pip refuses to install it alongside `0.5.0`.
- `seclab-taskflow-agent`'s `anthropic_sdk` model backend - the entire premise of ADR-0007's
  "retain direct Anthropic access" decision - does not exist in `0.4.0`. It was added in
  `0.5.0` (`BackendSdk = Literal['openai_agents', 'copilot_sdk', 'anthropic_sdk']` only from
  that version on).
- The `container_shell_source_access` toolbox is not in the `0.1.0` release's `toolboxes/`
  directory at all. It exists only on `seclab-taskflows`'s unreleased `main` branch, whose own
  `pyproject.toml` has already been bumped to require `seclab-taskflow-agent==0.5.0`.

So there is currently no tagged release pair that has both the native Anthropic backend and the
official container-shell toolbox this fork needs. This ADR fills that gap with the concrete
choices ADR-0007 left open, and records the pin so it can be revisited when upstream cuts a
compatible release.

## Pinned versions

- `seclab-taskflow-agent==0.5.0`, installed from PyPI (a real, tagged release).
- `seclab-taskflows`, installed from commit `b69171affdaa2700ba58f045122937651a2b0a1b` on its
  `main` branch (`pip install "seclab-taskflows @ git+https://github.com/GitHubSecurityLab/seclab-taskflows.git@b69171affdaa2700ba58f045122937651a2b0a1b"`),
  not from PyPI. That commit's own `pyproject.toml` requires `seclab-taskflow-agent==0.5.0`,
  matching the agent pin above. Checked before adopting this: the one module this fork actually
  depends on, `seclab_taskflows.mcp_servers.container_shell`, imports only one small, stable
  helper from `seclab_taskflow_agent` (`path_utils.log_file_name`) - not deep runner internals -
  so pinning to an unreleased commit is a shallower risk than it would be for a module more
  tightly coupled to the agent package.
- The container image the source-access toolbox pulls, pinned by digest rather than the
  floating `:latest` tag upstream ships:
  `ghcr.io/githubsecuritylab/seclab-shell-source-access@sha256:8c503593ce1539669a9bc28b459b5e444f9a760672b50f6ce111206e0027a19c`
  (resolved from `:latest`'s multi-arch index at the time this ADR was written; covers
  linux/amd64 and linux/arm64).

Revisit this pin when `seclab-taskflows` cuts a release whose `pyproject.toml` requires
`seclab-taskflow-agent>=0.5.0`, and when re-pinning the image digest periodically.

## Package layout

`security_triage_taskflow/` is a plain Python package at the repository root (mirroring `lib/`,
`routes/` as top-level concerns), resolved by the runner's dotted-module-path convention
(`importlib.resources.files(package).joinpath(filename + '.yaml')` -
`seclab_taskflow_agent/available_tools.py`), which requires each directory to be an importable
package rather than a plain file path:

- `configs/model_config.yaml` - `anthropic_sdk` backend, `endpoint: https://api.anthropic.com`,
  `token: ANTHROPIC_API_KEY`. The endpoint is `api.anthropic.com`, not GitHub's Copilot CAPI
  proxy, so the backend's provider-registry lookup resolves to native `x-api-key` auth rather
  than Copilot's bearer-auth route (confirmed by reading
  `seclab_taskflow_agent/sdk/anthropic_sdk/backend.py`), matching the existing
  `ANTHROPIC_API_KEY` secret with no custom authentication adapter.
- `toolboxes/container_shell_source_access.yaml` - a vendored copy of upstream's toolbox with
  `CONTAINER_IMAGE` pinned to the digest above; everything else (network: none, workspace mount
  via `CONTAINER_WORKSPACE`) is unchanged from upstream. `CONTAINER_WORKSPACE` and `LOG_DIR`
  are required (no fallback default) - `lib/scripts/securityTriage/triage.ts` always sets both
  before invoking the runner.
- `personalities/triage_investigator.yaml` - the investigator's system prompt, explicitly told
  that challenge markers and test-path location do not by themselves decide a verdict.
- `taskflows/triage.yaml` - one task, `capture: response` with an `outputs` JSON Schema.

## Why `capture: response`, and why the wrapper reads `manifest.json` instead of templating a shell step

The container-shell toolbox's tools are shell commands (ripgrep, tree, git, ...); the task's
*last* tool call in the default `capture: tool_result` mode would be whatever shell command the
agent happened to run last, not necessarily JSON matching the verdict schema. `capture:
response` instead validates the agent's final message text, which the prompt instructs to be
exactly one JSON object - a deliberate, documented runner feature for exactly this shape of
task, not a workaround.

A more literal reading of "read the agent's output back into the workflow" would use a trailing
`run:` shell task templated with `{{ outputs.investigate.reasoning }}` /
`{{ outputs.investigate.evidence }}`. Reading `seclab_taskflow_agent/shell_utils.py` shows `run:`
tasks are Jinja-rendered and then written verbatim to a temp file executed with `bash` - so
templating agent-produced free text (which routinely contains quotes, backticks, and `$()` when
explaining source code) directly into that file is a shell-injection vector on a job that holds
`issues: write`. This fork does not do that.

Instead, `lib/scripts/securityTriage/triage.ts` reads the run's own session manifest after the
`python3 -m seclab_taskflow_agent` process exits: `TaskflowSession.mark_finished()` (and
`mark_failed()`) already write `<data dir>/artifacts/<session id>/manifest.json`, containing
`outputs.investigate` - the schema-validated value - as plain JSON
(`seclab_taskflow_agent/session.py`, `manifest()`, documented as containing "no endpoints or
secrets"). The wrapper sets `XDG_DATA_HOME` to a fresh temporary directory per run so that
directory holds exactly one session, and validates what it reads with
`lib/taskflowVerdict.ts::parseTaskflowVerdict` regardless - a missing or malformed manifest is
reported as a distinct triage-execution failure, not assumed away.

## `VerdictPayload` keeps its existing shape

*Superseded by [ADR-0010](0010-taskflow-remediation-implementation.md): `gate`,
`lib/remediationBrief.ts` and the allow-list are gone, and the coupling flags this section
treats as a read-shape dependency now have no reader at all. The payload shape itself is
unchanged, and `lib/trustedVerdict.ts` still selects the comment; what follows is the
reasoning as it stood for issue #30.*

`remediate`/`gate` (unchanged; issue #31's scope) read `triage`'s verdict comment through
`lib/trustedVerdict.ts` and `lib/verdictPayload.ts`, and `lib/remediationBrief.ts` interpolates
`verdict.ruleId`, `.path`, `.verdict` and both coupling flags into the patch author's brief.
None of that is authorization logic - `gate` recomputes its own allow-list from the base ref -
so this is purely a read-shape dependency. `lib/verdictPayload.ts` therefore gains only
optional `reasoning`/`evidence` fields; every existing required field, and `isValidPayload`'s
validation of them, is unchanged, so a payload without the new fields still decodes and
`remediate`/`gate` need no changes for issue #30.

## `parseAlertNumber` is retained, not replaced

*Superseded by [ADR-0010](0010-taskflow-remediation-implementation.md), which deleted
`lib/parseAlertNumber.ts` and moved `remediate` onto `lib/parseAlertUrl.ts`. The consequence
described below no longer holds: a demo issue needs only the alert URL, and no `alert #<n>`
text.*

Issue #29 changes the *triage* input format from a transcribed `alert #<n>` text reference to a
pasted alert URL. `remediate.ts` and `gate.ts` are unchanged (issue #31's scope) and still call
`lib/parseAlertNumber.ts` to read `alert #<n>` text from the issue body - so that file is a
retained caller, not dead code, and stays. `lib/parseAlertUrl.ts` is new, used only by `triage`.
The practical consequence, until issue #31 aligns the two: an issue must carry both an alert
URL (for `triage`) and `alert #<n>` text (for `remediate`/`gate`) to go all the way through the
demo loop today. Documented in `docs/agents/security-triage.md`.

## Mount write access is not restricted, and the job's own credential is withheld instead

The container-shell source-access toolbox bind-mounts `CONTAINER_WORKSPACE` read-write (upstream
does not offer a read-only mount option), so a shell command the agent runs could in principle
modify or delete files in the `triage` job's checkout. Nothing in the workspace is published:
`contents: write` is not granted, the checkout uses `persist-credentials: false`,
`CONTAINER_NETWORK: none` blocks egress, and the runner VM is discarded at the end of the job.
Restricting the mount further is not pursued in this pass.

The credential the job does hold is the concern the mount is not. Unlike `remediate`, `triage`
both drives a tool-using agent and posts the verdict, so its `GH_TOKEN` (`issues: write`,
`security-events: read`) is in the job's environment while the agent runs. `agentEnvironment`
in `lib/scripts/securityTriage/triage.ts` therefore removes `GH_TOKEN` and `GITHUB_TOKEN`
from the environment handed to the TaskFlow process, so the token stays with the `gh` calls
the wrapper script makes itself and never reaches the agent's process tree. That is weaker
than the job boundary ADR-0010 gives remediation, and splitting `triage` into an uncredentialed
agent job and a credentialed publishing job is the way to close the gap; it is not done here.

## Live-run verification is deferred

Verifying real Anthropic authentication and real container-shell source access end-to-end
(issue #30's "verify... in a live run" acceptance criterion) requires a live `ANTHROPIC_API_KEY`
and a real `docker pull` of the pinned image in GitHub Actions. This implementation is validated
offline - `python3 -m seclab_taskflow_agent --lint` against the files above (wired into CI as
the `lint-taskflow` job) and the deterministic TypeScript units - but the live run itself is the
maintainer's post-merge step, by explicit choice, not something this change claims to have done.

## Consequences

`security_triage_taskflow/` and its pinned dependencies are a new, security-relevant supply
chain surface: a commit-SHA pin on an unreleased branch instead of a tagged release, and a
digest pin on a container image this fork does not build. Both are recorded here so they are
easy to find and revisit, rather than silently drifting. `remediate`, `gate`, its allow-list
computation (`lib/authorizePatch.ts`), `lib/patchGate.ts`, `lib/remediationBrief.ts`,
`lib/remediationRefusal.ts` and `lib/baseRefReader.ts` are unaffected by this change - and
were deleted shortly afterwards by
[ADR-0010](0010-taskflow-remediation-implementation.md).
