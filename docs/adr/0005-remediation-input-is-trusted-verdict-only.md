---
status: partially superseded by ADR-0010
---

# The patch author acts only on a trusted verdict, pinned to one base commit

**ADR-0010 supersedes the base-commit pinning and the allow-list described below. The rule
that only the triage job's own verdict comment selects anything survives and is still
implemented in `trustedVerdict.ts`, in `.github/security_triage_taskflow/lib/`.**

The `remediate` job holds no credentials (ADR-0002), so it reads the triage verdict from an
unauthenticated GET of the issue's public comments. Anyone who can comment on a public issue
can therefore write a comment that job reads. The first implementation selected the last
comment containing the `**Verdict:` marker and used its `- Path:` field directly as a
filesystem read, so a comment from any account could name any path the runner could read,
and that file's contents reached both the model request and the uploaded `brief.md`
artifact. CodeQL reported the chain as alerts 61-64 on PR #11; a local reproduction
confirmed it end to end.

Three rules close it, and each is a separate testable function rather than a check inside
the script:

1. **Only the triage job's own verdict selects a target.** `selectTrustedVerdict`
   (`trustedVerdict.ts`) accepts a comment only from `github-actions[bot]`, the single
   identity the `triage` job can post as, and only one whose `- Alert:` field matches the
   alert the issue body names and whose `- Base:` field matches the commit this job checked
   out. The verdict comment carries both fields for that reason. Every other comment,
   however well formed, selects nothing.
2. **Every base-ref read is a tracked file of the pinned commit.** `createBaseRefReader`
   (`lib/baseRefReader.ts`) rejects absolute paths, `..` traversal, drive and UNC forms and
   option-like paths, then reads through `git cat-file` against that commit. An untracked
   file, a directory, a path outside the checkout, and a file added after triage are all
   unreadable, and a symlink reads as its link text instead of being followed.
3. **The model's response is validated before anything is written.**
   `parseProposedPatch` (`lib/proposedPatch.ts`) requires a `propose_patch` tool call with
   string `diff` and `summary` fields inside a size limit. A response of any other shape
   writes nothing.

## Consequences

Path validation alone was not enough, which is why rule 1 exists: a forged comment
constrained to repository-relative paths could still redirect the job at a different
repository file, and the brief is an uploaded artifact. Trust is granted in exactly one
place, and the file boundary is defence in depth behind it.

Binding the verdict to a base commit makes a moved `master` a refusal
(`base-commit-mismatch`) rather than a silent remediation of a file that has changed since a
human read the verdict. Re-running triage is the recovery path.

The rules narrow what the patch author may read; they do not widen what it may produce. The
gate (#8, #9) still treats the proposal as untrusted and decides authorization from the base
ref alone. Data-flow alerts from the brief to the artifact may remain after this change,
because sending allow-listed source to the model is the job's purpose; they are triaged on
evidence, not suppressed.
