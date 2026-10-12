# Security Triage

Human-selected security findings move through assessment and human-authorized remediation.

## Language

**Security alert**:
A finding reported through GitHub security features and selected by a human for assessment.

**Code-scanning alert**:
A security alert produced by static analysis of repository code. It is the alert category
supported by the initial rewrite.

**Security issue**:
A human-created GitHub issue containing one selected code-scanning alert URL from the same
repository. It holds the assessment and the human decision about remediation.

**Triage verdict**:
An evidence-based assessment of a security alert against the repository code, including
uncertainty where the evidence does not support a conclusion.
_Avoid_: Remediation approval

**Triaged issue**:
A security issue with a published triage verdict: confirmed, not applicable, or
inconclusive. An execution failure is not a completed assessment.

**Remediation authorization**:
A human decision to let the agent attempt a fix after reviewing the triage verdict.
It does not authorize merging the fix.

**Security fix**:
A proposed code change that addresses the selected security alert and is submitted for
human review in a pull request.
