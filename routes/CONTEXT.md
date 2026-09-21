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
A scanner finding on a handler with neither snippet nor solve coupling. Remediable without a
preceding human decision.
_Avoid_: Safe finding, free finding

**Patch gate**:
The check that decides whether a model-authored patch may become a pull request. Runs in a
checkout the patch author cannot write to, and reads every input to an authorization
decision from the base ref.
_Avoid_: Validator, verifier, CI check

**Allow-list**:
The set of paths a patch may touch. Defaults to the file the scanner finding names, and is
empty when that file has either coupling. Widened only by a human commit to the base ref.
_Avoid_: Whitelist, permitted files

**NOPATCH**:
The patch gate's rejection outcome. Recorded as a comment on the originating issue; no pull
request is opened.
_Avoid_: Failure, rejection, blocked
