# Mechanical coupling detection instead of intent profiles

The original specification classified each finding with a `training-preservation` or
`remediation-exercise` profile, because it was written for a Terraform repository where the
intent behind an insecure line was a judgment call. In this repository the relationship
between a finding and the challenge catalogue is mechanical and greppable:
`vuln-code-snippet` markers for snippet coupling, `challengeUtils.solve*` call sites for
solve coupling. We therefore removed the profile machinery and rely on these two greps plus
the patch gate.

## Consequences

Coupling is reported as two independent booleans, named for the mechanism rather than for a
severity, because snippet coupling fails loudly through `npm run rsn` while solve coupling
fails silently. A single collapsed flag would lose the property a remediator needs.

Intent that is genuinely a judgment call has nowhere to live. Where the catalogue must
change, a human commits that change to the base branch before the agent runs, with a
recorded allowlist of affected tests.
