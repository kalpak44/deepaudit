# HTML_FRAME_GUARD_ABSENT

No recognized frame restriction header was observed

**Interpretation:** Neither a CSP frame-ancestors directive nor a recognized X-Frame-Options value was seen. No clickjacking impact was demonstrated.

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

When embedding is not required, configure CSP frame-ancestors; otherwise explicitly allow the required embedding origins.

Reference: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
