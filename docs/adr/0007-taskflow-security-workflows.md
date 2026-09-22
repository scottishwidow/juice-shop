---
status: accepted
---

# Use TaskFlow for security triage and remediation

The replacement will use SecLab TaskFlow Agent for separate triage and remediation
taskflows, invoked by GitHub Actions. Reuse its runner, model configuration, MCP integration,
and task execution instead of maintaining direct model calls and a custom agent loop.
The upstream [documentation](https://github.com/GitHubSecurityLab/seclab-taskflow-agent)
is the source of truth for supported capabilities.

Agents investigate repository code and, after human authorization, produce proposed fixes.
Deterministic workflow steps publish verdicts, update labels, push branches, and open pull
requests; publishing credentials remain separate from model-driven code execution.
Humans select alerts, authorize remediation, and merge pull requests.

The first version supports one same-repository code-scanning alert URL per issue and fetches
alert details from GitHub. Triage reports confirmed, not applicable, or inconclusive with
evidence, then the workflow applies `sec:triaged`.
An execution failure does not qualify an issue as triaged. Retain direct Anthropic access
through TaskFlow's `anthropic_sdk` backend, an explicit `https://api.anthropic.com` endpoint,
and a token environment variable configured in the model settings. The upstream README
describes bearer authentication for CAPI, but the current upstream
[backend](https://github.com/GitHubSecurityLab/seclab-taskflow-agent/blob/main/src/seclab_taskflow_agent/sdk/anthropic_sdk/backend.py)
and [provider selection](https://github.com/GitHubSecurityLab/seclab-taskflow-agent/blob/main/src/seclab_taskflow_agent/capi.py)
use native API-key authentication for custom endpoints. Verify the pinned version and
selected model with a live smoke test; no custom authentication adapter is planned.

This decision supersedes ADR-0004 and ADR-0006 for the replacement. The existing implementation
remains unchanged until the replacement design is complete. ADR-0008 defines the demo scope
and the old gates that will not carry forward. Publishing credentials remain separate;
the detailed handoff between stages remains to be designed.
