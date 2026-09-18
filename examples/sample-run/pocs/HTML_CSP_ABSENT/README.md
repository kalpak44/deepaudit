# HTML_CSP_ABSENT

No enforced CSP header was observed on this HTML response

**Interpretation:** A hardening observation, not evidence of XSS. A meta-delivered CSP may exist; response bodies are not inspected.

**Observed twice:** reproduced. This is not a demonstration of exploitation.

## Replay saved evidence (no network or API key)

Run from this folder:

```bash
python poc.py
```

Exit codes: 0 reproduced; 1 not reproduced; 2 inconclusive/error.
The script uses independent, fixed predicates against both normalized snapshots.
It does not prove the snapshots are authentic. SHA256SUMS detects accidental modifications,
not malicious changes by someone who can rewrite the manifest.

## Re-check the original target

Install DeepAudit from the repository first (`python -m pip install -e .`). Then:

```bash
python poc.py --live --authorized
```

For a private/loopback lab only, also pass `--allow-private`. Authorization is not inherited
from the saved report. The original hostname is resolved again; redirects are not followed.
The live test issues at most one GET or one TLS handshake. The bundled demo server normally
stops after the demo run, so its saved ephemeral URL is not a persistent live target.

## Remediation

Design and test an application-specific Content-Security-Policy, initially in report-only mode where appropriate.

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
