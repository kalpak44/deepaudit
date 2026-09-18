# Roadmap

## The architectural commitment

> **The LLM does research and builds hypotheses; a deterministic controller decides a
> vulnerability's status on the basis of verifiable evidence.**

DeepSeek may search for a call path, read an advisory, analyse a patch and propose a PoC.
It may not assign `CONFIRMED_APPLICABLE`. That separation is what the evidence ladder
encodes, and every item below is constrained by it.

The long-term goal, in one sentence:

> DeepAudit aims to evolve from an autonomous repository analysis agent into an
> evidence-driven vulnerability applicability engine that can discover known CVEs,
> determine whether their exploitation conditions exist in the target codebase, and safely
> reproduce applicable issues before proposing and verifying a fix.

The aim of the next stage is to teach the agent to distinguish a formal version match from
a vulnerability that genuinely applies to a particular repository, and where possible to
confirm it with a local, reproducible PoC.

## Releases

```text
v0.1  Endpoint agent      HTTP/TLS observations, PoC, verification, git workflow   shipped
v0.2  CVE discovery       SBOM + OSV + version matching + evidence model           shipped
v0.3  Applicability       config/platform checks + vulnerable API reachability
v0.4  Reproduction        isolated PoC + before/after verification
v0.5  Deep applicability  data flow, patch-aware analysis, vendored/backported code
v0.6  Prioritization      KEV/EPSS + richer evidence reports + CI/PR policy gates
```

## The evidence model

Rather than a binary `vulnerable / not vulnerable`, findings carry a ladder of states:

```text
VERSION_MATCH
    ↓
CONDITIONS_MATCH
    ↓
REACHABLE
    ↓
EXTERNALLY_REACHABLE
    ↓
REPRODUCED
```

and resolve to one status:

```text
POTENTIAL
LIKELY_APPLICABLE
CONFIRMED_APPLICABLE
NOT_APPLICABLE
INSUFFICIENT_EVIDENCE
```

Implemented in v0.2, including the rungs no release has earned yet: each reports
`not_evaluated`, which is a gap in the evidence and never a pass. `status_for` in
`applicability.py` is the only function that assigns a status.

## The items

**1. Dependency and CVE discovery — shipped in v0.2.** Builds a dependency inventory and an
SBOM, integrates OSV/GHSA, and normalizes advisory data. It answers exactly one question:
which known CVEs potentially relate to the component versions actually in use. Matches are
re-derived locally from the advisory's own ranges rather than taken on the database's word.

**2. Applicability engine — v0.3.** Check the conditions for exploitation: platform, feature
flags, runtime configuration, optional dependencies, run mode and the other preconditions an
advisory states. The result must be evidence-based, not a model's conclusion.

**3. Code reachability — v0.3.** For CVEs affecting specific APIs or functions, analyse
imports, the call graph and the use of the vulnerable code. Later extended to data-flow
analysis and to whether untrusted data reaches the dangerous API.

**4. Patch-aware analysis — v0.5.** For a CVE with a known upstream fix, analyse the fixing
commit or diff. This identifies the vulnerable pattern more precisely than a version number
can, and it works for forks, vendored code and backported patches.

**5. Controlled reproduction — v0.4.** Generate a safe local PoC or regression test in an
isolated environment. It must check one concrete observable behaviour, carry timeout and
resource limits, and run without external network access where possible.

**6. Before/after verification — v0.4.** In remediation mode the same PoC must confirm the
problem on the original revision and stop reproducing after the dependency is updated or
patched. This is the criterion for `CONFIRMED_APPLICABLE`.

**7. Evidence model and confidence states — shipped in v0.2.** See above.

**8. Reporting and prioritization — v0.6.** Report not only the CVE and CVSS but the
evidence for applicability: the installed version, the conditions that matched, the call
path, the source of external input, the PoC status, the recommended fix and the result of
re-verification. KEV/EPSS and other external priority signals are shown separately, never
mixed into the evidence for applicability.

## What v0.2 deliberately does not do

It runs no resolver, so a dependency declaring a range keeps no version and is reported as
a coverage gap. It reads committed manifests rather than an installed environment. It does
not detect vendored or backported code, so a patched fork still matches its upstream range.
And it involves no model at all: every status is a version comparison a reader can repeat
by hand. The rungs above `VERSION_MATCH` are where a model earns its place.
