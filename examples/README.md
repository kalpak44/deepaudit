# Included example

`sample-run/` is an intact result of the real loopback demo run made while preparing this
project. Its original run ID and timestamps remain in the manifest. The server has stopped;
the ephemeral address is not a persistent service.

From the project root, verify it without network or a key:

```bash
python -m deepaudit verify examples/sample-run
python examples/sample-run/pocs/HTML_CSP_ABSENT/poc.py
```

Generate your own fresh sample with `python -m deepaudit demo`. Use `--hardened` to compare a
fixture with most hardening headers enabled. It will still produce one plaintext HTTP observation.

No public third-party target was audited to create this example.
