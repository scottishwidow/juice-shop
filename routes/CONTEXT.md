# Routes

Express request handlers. Some handlers have insecure behaviour that something outside the
file depends on. A handler therefore cannot be judged on its code alone: its relationship to
those dependants decides whether a change is a fix or a regression.

## Language

**Coupling**:
A dependency of something outside a handler on that handler's insecure behaviour. Always
qualified by mechanism, never used bare, because the mechanisms fail in opposite ways. This
repository has two, both detectable by text search; elsewhere the same class of constraint
is usually undocumented.
_Avoid_: Linked, tied, dependent

**Snippet coupling**:
A handler enclosed in `vuln-code-snippet` comments, so its source is served as a coding
exercise and mirrored in `data/static/codefixes/`. Fails loudly: `npm run rsn` reports drift
against `rsn/cache.json`.
_Avoid_: RSN coupling, code-snippet link

**Solve coupling**:
A handler containing a `challengeUtils.solve*` call site, so reaching it records a challenge
as solved. Fails silently: the challenge becomes unreachable and no check reports it.
_Avoid_: Challenge coupling, solve hook

**Uncoupled finding**:
A scanner finding on a handler with neither detected snippet nor detected solve coupling.
This absence does not establish exploitability, intent, or permission to remediate.
_Avoid_: Safe finding, free finding

**Excluded path**:
A path automatic remediation may never change: workflow and CI definitions, credential and
key material, and the security workflow's own authorization and publishing code. Enforced by
the credentialed publishing job against the paths a change actually touches. A change
touching one is rejected in full.
_Avoid_: Blacklist, forbidden files, allow-list

**Trusted verdict**:
The triage job's own verdict comment for a named alert. The only comment the remediation
agent acts on: it selects the remediation target, and nothing else on the issue does,
however well formed. The commit it was decided against does not restrict remediation, which
always starts from current `master`.
_Avoid_: The verdict comment, the latest verdict

**Remediation attempt**:
One run of the remediation agent, started by a human applying the remediation label. Each
attempt has its own branch, and produces either a draft pull request or a reported failure.
Removing and reapplying the label starts another attempt; attempts are not deduplicated.
_Avoid_: Retry, the remediation

**Reported failure**:
An attempt that opened no pull request, recorded as a comment naming the stage that stopped
and linking the workflow run. It blocks nothing and sets no label.
_Avoid_: NOPATCH, refusal, rejection
