---
status: accepted
---

# Authorization inputs are read from the base ref

The patch gate decides whether a model-authored patch may become a pull request. Every input
to that decision is read from the base ref, never from the patched tree: the coupling greps,
the allow-list overrides in `.taskflow/allowlist.yml`, and the finding's own path, which
comes from the code-scanning API keyed by alert number. A patch that deletes a
`vuln-code-snippet` marker, or adds an allow-list file, therefore cannot widen its own
authorization.

## Consequences

The workflow splits into three jobs so that no model call holds a credential that can reach
an authorization input. `triage` holds `issues: write`, `remediate` holds `permissions: {}`
and passes its patch out as an artifact, and `gate` holds the write credentials but makes no
model call. `remediate` must set `persist-credentials: false` on checkout, or the default
token is left in `.git/config` inside the model's own job and the separation is void.

The `triage` job is still a model call sitting next to a token. Its toolbox is restricted to
comment creation, because an issue-edit capability would let it rewrite the alert number
that selects the allow-list entry. The gate echoes the alert number and the authorizing rule
into the pull request body so that a mismatch is visible.
