# Security boundary and responsible use

Use DeepAudit only on endpoints you own or are explicitly authorized to test.
`--authorized` records your assertion; it does not verify ownership or grant permission.
The selected GET endpoint must be safe to call. An application can give GET requests side effects.

This is an MVP configuration-audit agent, not a penetration-testing framework or a production
sandbox. It does not exploit targets, generate arbitrary exploit code, crawl, discover assets,
run external scanners, execute model-generated code, or expose a general shell to the model.
No claim of comprehensive vulnerability coverage is made.

## Data and capabilities

The model receives the exact target URL, pinned IP addresses, selected IP, normalized header
booleans, cookie attribute flags (without names/values), basic TLS metadata, and rule results.
Explicit `--share-with-llm` is required. The API key is used only in the HTTPS Authorization
header sent to `api.deepseek.com`; it is not inserted into messages or trace files. The endpoint
is fixed and does not follow redirects. `.env` files are not automatically loaded.

HTTP response bodies, raw headers, cookie names/values, login state and credentials are not
retained. Arbitrary header text cannot become a model instruction because only typed signals
cross that boundary. Provider reasoning, if returned, stays in conversation memory and is not
published. Final model commentary is stored only as an explicitly unverified `.txt` file.
Reports can still reveal sensitive target metadata. Review sharing policies and use a private repo.

## Network boundaries

Scope is one immutable scheme/host/port/path. The operator cannot provide URL credentials,
queries, fragments, control characters, or non-HTTP(S) schemes. A bare target defaults to HTTPS.
DNS is resolved once. Every address is validated; mixed public/disallowed answers fail closed.
Only the first approved numeric address is connected to. Original Host and TLS SNI/certificate
identity are preserved. Proxies and all redirects are ignored rather than followed.

Private RFC1918/ULA/loopback addresses require `--allow-private`; demo mode supplies it only for
its own loopback fixture. Link-local/metadata, multicast, unspecified, reserved and unsupported
transition addresses remain blocked. This is an application policy, not an OS egress firewall.
For production, additionally isolate the runner with an explicit network allowlist.

Defaults: six target connections, eight model steps, eight API HTTP attempts, and 1,500 maximum
output tokens per API call. HTTP uses one GET per phase; TLS uses one handshake per phase.
Failures consume the connection budget. Tool retries use cached results, except the one explicit
recheck. The API client allows one retry on selected transient HTTP statuses, within its shared
attempt budget. There is no network-timeout retry, since a timed-out request may be billed.

Target timeouts are per socket operation. System DNS resolution and a slow stream of protocol
bytes are not governed by a single total deadline. Wrap production jobs in an external watchdog.
The included GitHub job has a ten-minute job timeout. Request/output limits are NOT a monetary
spending cap; use account billing controls and monitor usage separately.

## Files, execution, and Git

Artifacts go into a unique subdirectory of the operator-selected repository. Model-controlled
paths, executables, shell arguments, and arbitrary file writes do not exist. Output path traversal
and pre-existing output-directory symlinks are rejected. PoC scripts are fixed application
templates. Offline verification checks template bytes before launching isolated Python children
without API credentials. Checksum verification also checks the file inventory.

SHA256SUMS detects accidental changes, not an attacker who can replace files and hashes.
The snapshot verifier demonstrates consistency with saved data, not cryptographic authenticity
or the existence of a working exploit. A live recheck requires fresh authorization flags.

`--git-commit` is opt-in. It requires complete coverage, successful agent/baseline completion,
reproduced observations, matching artifacts and an initially empty staging index. Only the new
run directory is staged. Existing unrelated unstaged edits are left alone. Git hooks, signing,
and fsmonitor are disabled for commit operations. Known API-token/private-key patterns block
commits. This heuristic is NOT a general-purpose secret scanner. No push is implemented.

Use ONLY trusted repositories and Git configuration: Git attributes/filters and local configuration
are not comprehensively sandboxed. Do not mutate the repository concurrently with an audit/commit.
A failed Git operation can leave generated files staged; inspect `git status` rather than resetting
user work automatically. Local filesystem race attacks and a compromised Python/Git runtime are
outside this MVP's threat model.

## Reporting a problem

Do not publish target secrets or live credentials in a public issue. Contact the maintainer of
your deployed fork privately or enable GitHub private vulnerability reporting for that fork.
No hosted service, maintainer email, or support SLA is provided by this generated project.
