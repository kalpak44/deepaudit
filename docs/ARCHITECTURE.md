# Architecture

```text
operator: immutable target + authorization + data-sharing consent + budgets
    |
    v
Target.parse -> Scope.resolve -> numeric-IP-pinned ProbeClient
    |                                |
    |                                +-> GET headers -> typed signals only
    |                                +-> verified TLS -> normalized metadata
    v
DeepSeek chat completions <-> bounded tool loop <-> AuditTools
    |                                              |
    | advisory final text                          +-> deterministic rules
    |                                              +-> fresh second sample
    v                                              v
AI_NOTES.txt                                evidence + findings
                                                   |
                                                   v
                             fixed PoC templates -> isolated offline subprocesses
                                                   |
                                                   v
                               report + manifest + trace + SHA256SUMS
                                                   |
                                                   v
                              optional local git commit (no push)
```

## Why a planner plus deterministic verification

An unconstrained model that claims an issue, writes an arbitrary program, executes it, and
judges its own success can confuse a hypothesis with a confirmed condition. Here the model
selects tools and explains results. Actual observations and reproducibility labels come from
application-owned rules and fresh measurements. A separate static predicate implementation
replays both snapshots in subprocesses. This does not establish exploitability or business impact.

`work` is a one-shot alias for `run`, not a daemon, background task, or a special IDE mode.
It completes the available pipeline without further prompts after the operator supplies the
required scope/consent flags. There is no resume or arbitrary multi-repository editing in v0.1.

## The dependency-applicability pipeline

```text
operator: repository path + optional advisory-fetch consent
    |
    v
inventory.collect -> committed manifests and lockfiles only, no resolver, no network
    |
    +-> sbom.cyclonedx           components that carry a resolved version
    |
    v
advisories.fetch (consent-gated)  OSV batch narrows, then one query per flagged component
    |
    v
applicability.assess              evidence ladder, re-derived locally from the ranges
    |
    v
inventory + sbom + advisories + applicability + report + SHA256SUMS
```

This pipeline shares the artifact layout, integrity manifest and `verify` command with the
endpoint audit, and nothing else. It has no target, no IP pinning and no probe budget,
because it makes no request to the subject of the audit.

**The model has no role in it yet.** Every status is a version comparison a reader can
repeat by hand, so there is nothing for a planner to decide. The rungs above
`VERSION_MATCH` are where a model earns its place, and they arrive with those releases.

## The evidence ladder

`VERSION_MATCH -> CONDITIONS_MATCH -> REACHABLE -> EXTERNALLY_REACHABLE -> REPRODUCED`

Each rung is independently `confirmed`, `refuted`, or `not_evaluated`, and `status_for` is
the only function that turns them into a status. The separation matters: `not_evaluated`
must never collapse into "not applicable", because that collapse is how an unimplemented
check becomes a false clean result. A release that has not implemented a rung reports it as
not evaluated, in the artifact and in the report.

Local range evaluation re-derives the advisory database's own claim rather than trusting
it. A disagreement resolves to `not_evaluated`, not `refuted` — the matcher may be wrong,
and clearing a real advisory on that basis is the costlier mistake.

## Module map

| Module | Responsibility |
| --- | --- |
| `policy.py` | Strict URL parsing, private-address policy, immutable scope, DNS pinning |
| `transport.py` | Numeric sockets, original Host/SNI, TLS trust, typed header evidence, budgets |
| `rules.py` | Eight deterministic observations with severity, limitations, and remediation |
| `tools.py` | Six argument-free tools, memoization, one fresh recheck, coverage tracking |
| `llm.py` | DeepSeek HTTPS API client, response validation, retries, reported token usage |
| `agent.py` | Bounded tool loop, call-ID validation, unknown-tool rejection, fallback |
| `poc_template.py` | Standalone offline predicates; explicitly authorized optional live mode |
| `artifacts.py` | Fixed filesystem layout, subprocess verification, hashes, report |
| `gitops.py` | Staging preflight, heuristic secret check, scoped local commit |
| `demo.py` | Loopback-only HTTP fixture, intentionally incomplete hardening headers |
| `cli.py` | Run/demo/verify/deps commands, consent gates, exit statuses |
| `inventory.py` | Manifest and lockfile parsing, bounded repository scan, deduplication |
| `versions.py` | PEP 440 and semver ordering, OSV range evaluation, None on unparseable |
| `advisories.py` | OSV client, request budget, advisory normalization, partial results |
| `applicability.py` | Evidence ladder, per-rung verdicts, the single status derivation |
| `sbom.py` | CycloneDX export of components with a resolved version |
| `deps.py` | Dependency pipeline, artifacts, report |

## Failure semantics

An unavailable tool returns structured evidence with `status: error`, not a fabricated success.
A header rule is not evaluated against a failed request. TLS certificate rejection is itself
an observable validation result; unavailable HTTPS header evidence remains a coverage gap.

When the model returns an early final message, malformed/truncated calls, excessive calls,
repeated call IDs, or the API fails, the coordinator completes the remaining deterministic
checks and writes a report marked as degraded. No unverified arbitrary program is executed.
Degraded/partial runs return exit code 3 and are not auto-committed.

Unknown tool names or non-empty arguments receive an error tool result. The batch envelope
is validated before executing any calls. Tool result messages preserve the matching call ID.
Any provider reasoning is replayed in API conversation memory when present, never in artifacts.
The default request explicitly disables thinking mode to keep this MVP's loop simple.

## API references checked on 2026-09-18

- https://api-docs.deepseek.com/
- https://api-docs.deepseek.com/api/create-chat-completion/
- https://api-docs.deepseek.com/guides/tool_calls/
- https://api-docs.deepseek.com/guides/thinking_mode/

The default documented model was `deepseek-flash` at verification time. Set `DEEPSEEK_MODEL`
or `--model` when the provider changes its catalog. The client uses standard-library HTTPS,
not the OpenAI SDK. Live provider authentication and behavior require your own funded API key;
the shipped validation uses mocked provider responses, not a billed DeepSeek session.
