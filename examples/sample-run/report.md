# DeepAudit report

Target: `http://127.0.0.1:38333/`

Run: `20260918T071531Z_127-0-0-1_84fd7c6b`

## Summary

- Configuration observations: **5**.
- Independent offline replay: **5/5 reproduced**.
- Target connections: **2/6**.
- Agent status: **baseline**; deterministic fallback: **False**.
- Probe coverage complete: **True**.

Reproduced observations are not proof of exploitable vulnerabilities. Missing headers are
hardening observations, not proof of XSS, clickjacking, or compromise.

## Evidence and coverage

Both normalized snapshots are in `evidence/`. `trace.jsonl` records tool execution without
model reasoning, raw response content, or credentials. `verification.json` contains actual
subprocess replay outcomes. `AI_NOTES.txt`, when present, is unverified model commentary.

One URL, one selected IP; no other pages, ports, virtual hosts, or TLS versions enumerated.

## Observations

### HTTP_PLAINTEXT_RESPONSE: The selected HTTP endpoint serves a successful plaintext response

Severity: **low**. Recheck: **reproduced**.

This response was not an HTTPS redirect. It does not prove HTTPS is unavailable on another endpoint.

Evidence:

```json
{
  "status_code": 200
}
```

Remediation: For a public production endpoint, consider redirecting HTTP to HTTPS; review exceptions for local labs and health checks.

Replay: `python pocs/HTTP_PLAINTEXT_RESPONSE/poc.py`

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### HTML_CSP_ABSENT: No enforced CSP header was observed on this HTML response

Severity: **low**. Recheck: **reproduced**.

A hardening observation, not evidence of XSS. A meta-delivered CSP may exist; response bodies are not inspected.

Evidence:

```json
{
  "html": true,
  "csp_present": false
}
```

Remediation: Design and test an application-specific Content-Security-Policy, initially in report-only mode where appropriate.

Replay: `python pocs/HTML_CSP_ABSENT/poc.py`

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### HTML_FRAME_GUARD_ABSENT: No recognized frame restriction header was observed

Severity: **low**. Recheck: **reproduced**.

Neither a CSP frame-ancestors directive nor a recognized X-Frame-Options value was seen. No clickjacking impact was demonstrated.

Evidence:

```json
{
  "frame_ancestors_present": false,
  "xfo_restrictive": false
}
```

Remediation: When embedding is not required, configure CSP frame-ancestors; otherwise explicitly allow the required embedding origins.

Replay: `python pocs/HTML_FRAME_GUARD_ABSENT/poc.py`

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### NOSNIFF_ABSENT: X-Content-Type-Options: nosniff was not observed

Severity: **low**. Recheck: **reproduced**.

A missing hardening control on this successful response, not a demonstrated content-sniffing exploit.

Evidence:

```json
{
  "nosniff": false
}
```

Remediation: Serve the correct Content-Type and configure X-Content-Type-Options: nosniff.

Replay: `python pocs/NOSNIFF_ABSENT/poc.py`

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

### COOKIE_FLAGS_REVIEW: Some response cookie attributes need a context-specific review

Severity: **info**. Recheck: **reproduced**.

Cookie values, names, and purpose are unknown. JavaScript-readable cookies and default SameSite behavior can be intentional; no session compromise is claimed.

Evidence:

```json
{
  "cookie_indexes": [
    1
  ]
}
```

Remediation: For sensitive cookies, review Secure, HttpOnly, and SameSite against the application requirements.

Replay: `python pocs/COOKIE_FLAGS_REVIEW/poc.py`

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

## Limitations

Only the selected URL and first approved DNS address were sampled twice. GET must be
safe on the endpoint you authorize; the tool cannot determine application side effects.
No browser, login, body analysis, crawling, port scan, exploitation, subdomain expansion,
HSTS preload lookup, meta-CSP analysis, or TLS cipher/version enumeration is performed.
No redirect is followed, including same-origin redirects. A JSON/API response does not
receive HTML-only findings. Cookie purpose and sensitivity are unknown. Policies that
are present but malformed or permissive can be missed. Private CA validation depends
on the Python runtime trust store. Repeated evidence does not establish business impact.

Review reports before sharing. Target names, selected IPs, paths and security observations
can be confidential even though bodies and credential values are not collected.
