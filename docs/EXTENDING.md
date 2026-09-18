# Adding a check without turning the agent into an unrestricted shell

Begin with a precise observable condition, permitted scope, safe input shape, and explicit
non-claims. A missing mitigation must not become an assertion that an exploit succeeded.

1. Add a small reviewed probe to `ProbeClient`, reusing numeric-IP pinning and the shared budget.
   Never let the model choose arbitrary hosts, paths, methods, headers or command strings.
2. Normalize the result into typed evidence. Do not introduce body/credential sharing silently.
   Update the data-sharing contract and consent flow before collecting additional information.
3. Add a deterministic rule in `rules.py` with an ID, severity, evidence, interpretation,
   remediation, probe classification and a primary-source reference.
4. Add an independently implemented replay predicate to `poc_template.py`. Include positive,
   negative, inapplicable, timeout and changed-between-samples fixtures.
5. Update tool schemas only when the model genuinely needs a new capability. Validate both
   schemas and runtime arguments. Keep loops and request counts bounded.
6. Add an explicit operator gate for any new side effect. Treat authentication, state-changing
   HTTP methods, browser execution, code generation, repository mutation and external scanners
   as separate threat-model changes, not a reason to add a generic shell tool.

The current rule list deliberately excludes CORS findings inferred from a wildcard alone,
HTML-only findings on API responses, cookie impact assumptions, and version-to-CVE guesses.
Present-but-weak policies are mostly not analyzed. A browser or authenticated business-flow
check would need additional reviewed machinery and is not part of this MVP.

## Suggested evolution

Use declarative per-project scope files, a durable job/state store, cancellation/deadline
handling, a dedicated egress-restricted worker, signed evidence bundles and policy-approved
read-only check plugins before considering broader autonomy. A separate, reviewable PR can
be safer than automatically pushing reports to a shared branch. These are design directions,
not implemented features.
