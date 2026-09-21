---
status: accepted
---

# Upstream contribution bots removed from this fork

`pr-compliance.yml`, `lint-fixer.yml` and `rebase.yml` police the upstream project's public
contributor funnel, which this fork does not have. Each one obstructs an automated
remediation workflow: the compliance check closes any pull request targeting `master`, the
lint fixer auto-commits to a branch after the patch gate has already validated it, and the
rebase workflow starts a run on every issue comment the agent posts. They are removed rather
than worked around.

`ci.yml` and `codeql-analysis.yml` are kept: they are the test suite and the scanner the
workflow depends on.

`stale.yml` is removed for the same reason, though it is not one of the three named above. Its
acceptance criterion is that no remaining workflow writes to a pull request it did not open; this
one comments on and closes any PR idle for 14 days, and its `exempt-assignees` list names
upstream maintainers only, none of whom are active on this fork.
