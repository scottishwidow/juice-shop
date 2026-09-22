---
status: accepted
---

# Optimize the security workflow for demonstration

This fork demonstrates code-based AI triage followed by human-authorized remediation that
submits a pull request. Challenge preservation is not a requirement: the agent may fix
intentional vulnerabilities. A submitted fix PR completes the remediation demonstration;
passing tests, lint, or RSN is not a prerequisite for publication, and the PR must report
what validation actually ran.

Remediation starts from current `master` without requiring a fresh triage verdict when the
branch advances. The human accepts this stale-assessment risk. Relevant supporting source
and test changes are allowed without a per-file allow-list; workflow, credential, and
authorization-policy changes remain outside automatic remediation.

Removing and reapplying a trigger label starts a fresh attempt. Duplicate work and multiple
PRs are acceptable during debugging; duplicate prevention is not required.

For the replacement, these choices remove the challenge-preservation gates of ADR-0001,
the per-file authorization gate of ADR-0002, and the exact triage-commit binding of
ADR-0005. ADR-0007 retains separation of publishing credentials from agent execution.
The old implementation remains unchanged until the replacement is built.
