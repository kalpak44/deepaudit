"""Deterministic observations, never model-authored vulnerability claims."""
from __future__ import annotations

from datetime import datetime
from .policy import Target

REFERENCES = {
    "headers": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    "tls": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
}

RULES = {
    "HTTP_PLAINTEXT_RESPONSE": {
        "title": "The selected HTTP endpoint serves a successful plaintext response",
        "severity": "low", "probe": "http",
        "interpretation": "This response was not an HTTPS redirect. It does not prove HTTPS is unavailable on another endpoint.",
        "remediation": "For a public production endpoint, consider redirecting HTTP to HTTPS; review exceptions for local labs and health checks.",
    },
    "HTML_CSP_ABSENT": {
        "title": "No enforced CSP header was observed on this HTML response",
        "severity": "low", "probe": "http",
        "interpretation": "A hardening observation, not evidence of XSS. A meta-delivered CSP may exist; response bodies are not inspected.",
        "remediation": "Design and test an application-specific Content-Security-Policy, initially in report-only mode where appropriate.",
    },
    "HTML_FRAME_GUARD_ABSENT": {
        "title": "No recognized frame restriction header was observed",
        "severity": "low", "probe": "http",
        "interpretation": "Neither a CSP frame-ancestors directive nor a recognized X-Frame-Options value was seen. No clickjacking impact was demonstrated.",
        "remediation": "When embedding is not required, configure CSP frame-ancestors; otherwise explicitly allow the required embedding origins.",
    },
    "NOSNIFF_ABSENT": {
        "title": "X-Content-Type-Options: nosniff was not observed",
        "severity": "low", "probe": "http",
        "interpretation": "A missing hardening control on this successful response, not a demonstrated content-sniffing exploit.",
        "remediation": "Serve the correct Content-Type and configure X-Content-Type-Options: nosniff.",
    },
    "HTTPS_HSTS_ABSENT": {
        "title": "No HSTS header was observed on this HTTPS hostname response",
        "severity": "low", "probe": "http",
        "interpretation": "The browser may already have HSTS state, a preload entry, or a parent policy. IP targets are excluded from this rule.",
        "remediation": "Evaluate an appropriate Strict-Transport-Security policy after validating HTTPS deployment and subdomain readiness.",
    },
    "COOKIE_FLAGS_REVIEW": {
        "title": "Some response cookie attributes need a context-specific review",
        "severity": "info", "probe": "http",
        "interpretation": "Cookie values, names, and purpose are unknown. JavaScript-readable cookies and default SameSite behavior can be intentional; no session compromise is claimed.",
        "remediation": "For sensitive cookies, review Secure, HttpOnly, and SameSite against the application requirements.",
    },
    "TLS_CERTIFICATE_REJECTED": {
        "title": "The runtime trust store rejected the endpoint certificate",
        "severity": "medium", "probe": "tls",
        "interpretation": "Certificate verification failed in this environment. A private CA or local trust-store issue can also explain this result.",
        "remediation": "Check the certificate chain, hostname, validity period, runtime trust store, and any intended private CA configuration.",
    },
    "TLS_CERTIFICATE_EXPIRING": {
        "title": "The verified certificate expires within 30 days",
        "severity": "low", "probe": "tls",
        "interpretation": "An operational warning. Automated certificate rotation may already be configured.",
        "remediation": "Verify certificate renewal automation and alerting before the observed expiry date.",
    },
}


def evaluate(snapshot: dict) -> list[dict]:
    """Pure replayable rule evaluation. No network, files, shell, or LLM."""
    target = Target.parse(snapshot["scope"]["target"])
    http = snapshot.get("http", {})
    tls = snapshot.get("tls", {})
    signals = http.get("signals", {})
    hits: list[tuple[str, dict]] = []
    if http.get("status") == "ok" and 200 <= http.get("status_code", 0) < 300:
        if target.scheme == "http":
            hits.append(("HTTP_PLAINTEXT_RESPONSE", {"status_code": http["status_code"]}))
        if signals.get("html"):
            if not signals.get("csp_present"):
                hits.append(("HTML_CSP_ABSENT", {"html": True, "csp_present": False}))
            if not signals.get("frame_ancestors_present") and not signals.get("xfo_restrictive"):
                hits.append(("HTML_FRAME_GUARD_ABSENT", {"frame_ancestors_present": False, "xfo_restrictive": False}))
        if not signals.get("nosniff"):
            hits.append(("NOSNIFF_ABSENT", {"nosniff": False}))
        if target.scheme == "https" and not target.is_ip and not signals.get("hsts_present"):
            hits.append(("HTTPS_HSTS_ABSENT", {"hsts_present": False}))
        affected = [c["index"] for c in signals.get("cookies", [])
                    if not c["httponly"] or c["samesite"] == "absent_or_invalid"
                    or (target.scheme == "https" and not c["secure"])]
        if affected:
            hits.append(("COOKIE_FLAGS_REVIEW", {"cookie_indexes": affected}))
    if tls.get("status") == "error" and tls.get("error") == "certificate_verification_failed":
        hits.append(("TLS_CERTIFICATE_REJECTED", {"verify_code": tls.get("verify_code")}))
    if tls.get("status") == "ok":
        try:
            remaining = (datetime.fromisoformat(tls["not_after"]) -
                         datetime.fromisoformat(tls["observed_at"])).total_seconds() / 86400
            if 0 <= remaining <= 30:
                hits.append(("TLS_CERTIFICATE_EXPIRING", {"not_after": tls["not_after"], "days_remaining": round(remaining, 2)}))
        except (KeyError, ValueError, TypeError):
            pass
    results = []
    for rule_id, evidence in hits:
        spec = RULES[rule_id]
        results.append({
            "id": rule_id, **spec, "evidence": evidence,
            "classification": "configuration_observation",
            "verification": "not_rechecked",
            "reference": REFERENCES["tls" if spec["probe"] == "tls" else "headers"],
        })
    return results


def verify_observations(initial: dict, recheck: dict) -> list[dict]:
    findings = evaluate(initial)
    second_ids = {f["id"] for f in evaluate(recheck)}
    for finding in findings:
        probe = recheck.get(finding["probe"], {})
        if finding["id"] in second_ids:
            finding["verification"] = "reproduced"
        elif probe.get("status") != "ok":
            finding["verification"] = "inconclusive"
        else:
            finding["verification"] = "not_reproduced"
    return findings
