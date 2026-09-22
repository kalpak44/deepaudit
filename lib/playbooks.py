"""Per-technology testing playbooks: concrete, in-scope checklists keyed by what was detected.

Fingerprinting tells the agent *what* the target runs; a playbook tells it *how* to test that
specific stack well. Fetching a playbook by name turns "I see WordPress" into a focused set of
high-signal checks (and which arsenal tools to use), so coverage is systematic instead of
improvised. Guidance only — the agent still runs the tools and grounds every finding; all
checks stay within the one authorized target.
"""
from __future__ import annotations

PLAYBOOKS = {
    "react-spa": """\
Single-page app (React/CRA/Vite) — the logic is client-side, so mine the bundle:
- Fetch and beautify the JS bundles (main.*.js, chunk-*.js). Extract API base URLs, route
  tables and every referenced endpoint (katana can crawl JS; or grep the beautified source).
- Recover source maps: try <bundle>.js.map; if present, reconstruct original sources.
- Extract embedded config/keys (REACT_APP_*, API keys, client IDs, feature flags). Note which
  are public-by-design (Auth0 SPA client id, Firebase config, Google Maps browser key,
  WalletConnect project id) vs. a real secret (server API keys, private tokens). Judge by
  RESTRICTION, not mere presence: is the key origin/referrer/scoped or wide open?
- retire.js on the detected libraries; cross-check versions with cve_lookup.
- trufflehog/gitleaks over the fetched JS for verified secrets.
- Then pivot to the discovered API (see the rest-api playbook).""",

    "rest-api": """\
HTTP/JSON API:
- Enumerate endpoints (from the SPA bundle, /openapi.json, /swagger.json, robots, katana, gau).
- For each: which methods are allowed, is authentication enforced, what does an unauthenticated
  request return (401 vs data)? Look for broken access control / IDOR on object ids.
- CORS: does it reflect arbitrary Origin with Access-Control-Allow-Credentials? That is exposure.
- Error verbosity: stack traces, framework banners, SQL errors in responses.
- Mass assignment, rate limiting, and auth token handling (in URL? weak JWT alg 'none'/HS/RS?).
- Test injection only non-destructively unless deeper exploitation is authorized.""",

    "graphql": """\
GraphQL endpoint (/graphql, /api/graphql):
- Introspection: run the introspection query; if enabled, map the full schema.
- Field suggestions leak even when introspection is off — probe typo'd fields.
- Authorization per field/type (broken access control), batching/alias-based abuse and query
  depth/complexity DoS surface (describe, don't actually DoS).
- Injection through resolver arguments; verbose errors.""",

    "wordpress": """\
WordPress detected:
- wpscan against the target: enumerate core version, plugins, themes and their known CVEs
  (provide --api-token via env if available for vuln data), and users (author enum).
- Check /wp-json/wp/v2/users (REST user enumeration), /xmlrpc.php (pingback/brute amplification),
  /wp-login.php, readme.html (version), /wp-content/ exposures and backup files.
- Feed plugin/theme versions to cve_lookup; prioritize KEV/high-EPSS.""",

    "oauth": """\
OAuth2 / OIDC / Auth0:
- Inspect the authorize request: redirect_uri validation (open redirect / stealing codes),
  response_type (token in URL fragment?), PKCE presence for public clients, state/nonce usage.
- Tenant separation: are dev and prod using the same tenant/client? Are dev endpoints public?
- Token leakage in URLs, logs or Referer; scope over-grant; ID-token audience/issuer checks.""",

    "s3": """\
Cloud object storage (S3/GCS/Azure Blob) referenced by the in-scope host:
- Only test buckets that belong to the target's scope. Check public listing, object ACLs,
  world-readable sensitive objects, and website config. Never touch third-party buckets.""",

    "tls": """\
TLS/transport:
- testssl.sh (or sslyze) for protocol support (SSLv3/TLS1.0/1.1 deprecated), weak/legacy
  ciphers, cert chain validity, hostname match, key size, OCSP/CT, and known TLS CVEs.
- Confirm HSTS (and preload), and that HTTP redirects to HTTPS.""",

    "headers": """\
HTTP security hygiene:
- Baseline headers: Strict-Transport-Security, Content-Security-Policy (and its quality),
  X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy.
- Cookies: Secure, HttpOnly, SameSite on session cookies. Caching of sensitive responses.
- Judge impact by context: a JSON API 401 with no session cookie carries little header risk;
  a browser-rendered authenticated page carries more.""",
}

# Common fingerprint aliases → canonical playbook name.
_ALIAS = {
    "react": "react-spa", "spa": "react-spa", "cra": "react-spa", "vue": "react-spa",
    "angular": "react-spa", "vite": "react-spa", "nextjs": "react-spa",
    "api": "rest-api", "rest": "rest-api", "openapi": "rest-api", "swagger": "rest-api",
    "wp": "wordpress", "auth0": "oauth", "oidc": "oauth", "oauth2": "oauth",
    "ssl": "tls", "https": "tls", "aws-s3": "s3", "bucket": "s3",
    "security-headers": "headers", "csp": "headers", "cookies": "headers",
}


def names() -> list[str]:
    return sorted(PLAYBOOKS)


def get(name: str) -> str:
    key = str(name or "").strip().lower()
    key = _ALIAS.get(key, key)
    return PLAYBOOKS.get(key) or (
        f"No playbook named {name!r}. Available: {', '.join(names())}. "
        "Proceed from the general checklist and your own testing plan.")
