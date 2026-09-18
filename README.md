# DeepAudit MVP

An autonomous CLI agent built on the DeepSeek API for **authorized HTTP/TLS checks against a single domain or IP**. The agent calls tools, collects observations, repeats its checks, and writes PoCs and documentation into the repository. Behind a separate flag it commits only the results of a completed run.

This is a working, deliberately limited MVP — not a general-purpose Codex equivalent and not a generator of arbitrary exploits. A PoC here is a reproducible check of one specific configuration observation. A missing CSP is not by itself declared to be XSS; missing framing-protection headers are not declared to be proven clickjacking.

## Quick start without an API key

Requires Python 3.11+. There are no runtime dependencies outside the standard library. From the root of the project:

```bash
python -m deepaudit demo
```

The command starts a local server on a random port on `127.0.0.1`, checks it, produces a report and five PoCs, runs them offline, and shuts the server down. A normal demo is expected to reproduce `5/5` observations. For a comparison run with protective headers in place:

```bash
python -m deepaudit demo --hardened
```

In that example one observation remains: the test server still serves over HTTP.

A previously saved result is included in `examples/sample-run/`:

```bash
python -m deepaudit verify examples/sample-run
python examples/sample-run/pocs/HTML_CSP_ABSENT/poc.py
```

Neither command touches the network or requires an API key. The stored run identifier reflects the original run; the directory was moved to `sample-run` without altering the evidence.

To install the `deepaudit` command and use the live mode of individual PoCs from any directory:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
```

Installing via pip may download build tooling. Running `python -m deepaudit` from the project root requires no installation.

## Autonomous mode with DeepSeek

Set the key through an environment variable; do not write it into source files or git:

```bash
export DEEPSEEK_API_KEY="YOUR_API_KEY"
export DEEPSEEK_MODEL="deepseek-flash"

python -m deepaudit work \
  --target https://your-authorized-host.example/ \
  --authorized \
  --share-with-llm
```

Replace the example with a real address you have permission to check. `work` is a synonym for `run`: a single finite run from data collection through to the report, with no intermediate confirmations once the scope and the consents have been given explicitly. It is not a background daemon.

`--authorized` records your confirmation that you have permission. `--share-with-llm` permits sending DeepSeek the target address, the pinned IPs, the normalized HTTP/TLS observations, and the rule conclusions. Response bodies, raw headers, cookie names and values, and the API key never reach the model's messages.

The Chat Completions API is used, with tool calls. The value `deepseek-flash` was checked against the official documentation on 18 September 2026. The model is changed through `--model` or `DEEPSEEK_MODEL`. Verify the key and the availability of a particular model in your own account. No live, billable API call was made while preparing this project; the protocol and the tool loop were exercised against stubbed responses.

The `.env.example` file is a template only: the application does not load `.env` automatically. Set the variables in your shell or in your CI secret store. Do not publish keys, and do not type a real key into commands that will end up in a shared log.

## Domain, IP, and a local lab

A bare domain or IP is interpreted as HTTPS. A port and a path can be given explicitly. For HTTP, write `http://`:

```bash
python -m deepaudit run \
  --target http://127.0.0.1:8765/ \
  --authorized --allow-private --mode baseline
```

For this example, first run `python -m deepaudit serve-demo --port 8765` in another terminal.

`baseline` does not call the LLM, but it does make network requests to the given target. This is **not an offline mode**. What works offline is `verify` and PoCs run without `--live`.

IPv6 with a port must be enclosed in square brackets: `https://[IPv6-address]:8443/`. For an IP, the certificate of that IP itself is checked; the virtual host of another domain is not substituted. URLs carrying credentials, a query string, a fragment, or control characters are rejected.

## What happens inside

```text
target + authorization + limits
  -> scope check and IP pinning
  -> DeepSeek selects tools
  -> collection of normalized HTTP/TLS data
  -> deterministic rules
  -> fresh recheck
  -> generation of fixed PoCs
  -> independent offline predicates run in subprocesses
  -> report + evidence + log + SHA256SUMS
  -> optional local git commit
```

The model has access to `get_scope`, `inspect_http`, `inspect_tls`, `analyze_evidence`, `verify_findings`, and `list_findings`. None of these tools take a parameter that would let the model change the target, run a shell command, or write an arbitrary file.

If the API is unavailable, a response is cut short, the model finishes too early, or a limit is exhausted, the coordinator completes the baseline checks itself. The report is marked incomplete/degraded, the process returns exit code 3, and no autocommit is performed. The model's text is stored separately from the evidence, in `AI_NOTES.txt`.

## The eight MVP rules

| Rule | What it records |
| --- | --- |
| `HTTP_PLAINTEXT_RESPONSE` | The selected HTTP endpoint returned a successful response rather than an HTTPS redirect |
| `HTML_CSP_ABSENT` | No enforced CSP header is observed on a successful HTML response |
| `HTML_FRAME_GUARD_ABSENT` | No recognized framing restriction is observed in the headers |
| `NOSNIFF_ABSENT` | No `X-Content-Type-Options: nosniff` is observed |
| `HTTPS_HSTS_ABSENT` | An HTTPS response for a domain name carries no HSTS header |
| `COOKIE_FLAGS_REVIEW` | Attributes of some cookies warrant a contextual review; informational level |
| `TLS_CERTIFICATE_REJECTED` | Python's trust store rejected the endpoint's certificate |
| `TLS_CERTIFICATE_EXPIRING` | A verified certificate expires within 30 days |

The list is also available through `python -m deepaudit checks`. Confirmation means the observation is reproducible — not that exploitation or business impact has been proven. A failed request is not treated as a missing header.

## Results in the repository

```text
audits/<run-id>/
  report.md
  manifest.json
  findings.json
  verification.json
  trace.jsonl
  SHA256SUMS
  AI_NOTES.txt                  # only when the model produced final text
  evidence/
    initial.json
    recheck.json
  pocs/<RULE_ID>/
    poc.py
    case.json
    README.md
```

PoCs reproduce the stored observation without network access. For a fresh check against the original endpoint, once the package is installed:

```bash
python audits/<run-id>/pocs/<RULE_ID>/poc.py --live --authorized
```

An authorized private lab additionally needs `--allow-private`. Consent given in an older report is not inherited automatically. The local server from an ordinary `demo` has already been shut down, so its random port is not a persistent live target.

`SHA256SUMS` verifies the integrity of the files and their inventory, but it is not a digital signature and does not prove the authenticity of the measurements.

## Git and GitHub

Once the repository is initialized and `git user.name` / `git user.email` are configured:

```bash
python -m deepaudit work \
  --target https://your-authorized-host.example/ \
  --authorized --share-with-llm --git-commit
```

A commit is permitted only for a completed run whose PoC check succeeded. Pre-staged files cause a refusal; unrelated unstaged changes are left untouched. The application does not run `git add .` and does not push. If Git fails, inspect `git status`: the application does not attempt to roll back your changes automatically.

Instructions for creating a private repository with `gh`, uploading the sources, and running the workflows are in [docs/GITHUB.md](docs/GITHUB.md). CI tests and a manual audit workflow with separate checkboxes for authorization and for sending data to the LLM are included.

## Limits and exit codes

The defaults: 8 model steps, 8 HTTP attempts against the API including retries, 1500 output tokens per request, 6 connections to the target, and a minimum of 0.25 seconds between their starts. A normal run uses 2 connections for HTTP or 4 for HTTPS. Repeated tool calls read from cache; the fresh recheck runs exactly once.

The limits are changed through `--max-steps`, `--max-api-requests`, `--max-tokens`, `--max-connections`, `--timeout`, and `--min-interval`. Upper bounds are built in. Network timeouts are not an absolute deadline for the whole process. The request limit is not a substitute for a spending limit on your account.

`run`/`work` codes: `0` — completed run; `2` — input, configuration, policy, or startup error; `3` — incomplete check, agent fallback, or observations that were not reproduced; `4` — Git error; `130` — interrupted. For `verify`: `0` — check succeeded, `1` — not all observations were reproduced, `2` — integrity or startup error. For an individual PoC: `0` — reproduced, `1` — not_reproduced, `2` — inconclusive/error.

## Scope limits and how the project was checked

One URL, one selected IP, with no redirects, port scanning, site crawling, authentication, HTML body analysis, business logic, browser, or execution of arbitrary code. Policies that are already present but weak may be missed. Even a GET can have a side effect in a badly built application: choose an endpoint that is genuinely read-only. Use only a trusted local repository; this is not a full OS sandbox.

```bash
python -m unittest discover -s tests -v
```

The tests use local HTTP/HTTPS servers, temporary git repositories, and stubbed DeepSeek responses. A summary of an actual run is in [docs/TESTING.md](docs/TESTING.md). Test certificates are created in temporary directories and are not shipped.

Further detail: [architecture](docs/ARCHITECTURE.md), [security boundaries](SECURITY.md), [adding checks](docs/EXTENDING.md).

Primary sources: [DeepSeek API](https://api-docs.deepseek.com/), [tool calls](https://api-docs.deepseek.com/guides/tool_calls/), [OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

License: MIT.
