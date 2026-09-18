# Verification record

Verified locally on 2026-09-18 with Python 3.13.5 on Linux.

- Tests executed: **81**.
- Failures: **0**. Errors: **0**. Skipped: **0**.
- Full suite result: **PASS**.
- Wheel build without dependency downloads: **PASS**.
- Wheel installation in a fresh virtual environment: **PASS**.
- Installed console command smoke check: **PASS**.
- Bundled sample checksum/inventory verification: **PASS**.
- Independent offline PoCs in the bundled sample: **5/5 reproduced**.

Machine-readable record: `test-results.json`. Actual test output: `test-output.txt`.

## Covered scenarios

Strict target parsing; authorization before DNS; public/private address policy; mapped IPv4
and IPv6 edge cases; mixed DNS answers; numeric-IP pinning with original Host; redirects not
followed; response/cookie data minimization; target budgets; HTML versus API applicability;
TLS certificate trust and expiration; fresh repeat observations; changed/inconclusive results;
argument validation; unknown tools; cached tool calls; bounded loops; duplicate call IDs;
truncated API responses; API retry budgets; API errors; early model termination; fallback;
provider reasoning excluded from logs; output traversal and symlinks; checksum/inventory
modification; static PoC template integrity; independent subprocess replay; preservation of
unrelated Git edits; refusal of existing staged changes; disabled Git hooks; heuristic secret
rejection; full local agent-to-artifact-to-commit flow with a mocked provider transport.

HTTP/HTTPS network integration tests use loopback fixtures only. TLS tests generate temporary
certificates with the OpenSSL CLI; they are skipped on machines without that CLI. No test
private keys are included in the project. The Git integration uses temporary repositories.
Selected artifact setup helpers use mocks to avoid repeatedly launching identical subprocesses;
the explicit replay and end-to-end tests execute the actual fixed PoC scripts.

## Not verified here

No live authenticated DeepSeek API call was made. Successful API integration requires your own
key, account access and provider availability. Mock tests validate request shape, response handling
and orchestration, not provider uptime, billing, account permissions or model planning quality.

The GitHub workflow files were created and their YAML parsed locally, but were not executed in
your account. The configured Python 3.11/3.12/3.13 CI matrix is not a claim that all versions were
run locally; this delivery environment used Python 3.13.5. Other operating systems,
production egress controls, real-world target coverage and adversarial filesystem races were
not certified. This is not an external penetration test or a security guarantee.

## Reproduce

```bash
python -m unittest discover -s tests -v
python -m deepaudit demo
python -m deepaudit verify examples/sample-run
```

The last command is completely offline. A baseline audit still connects to its selected target.
