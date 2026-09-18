"""Read-only, origin-pinned probes. No proxy, cookies, redirects, or response body."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
from http.cookies import SimpleCookie, CookieError
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .policy import PolicyError, Scope


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Budget:
    maximum: int = 6
    timeout: float = 8.0
    delay: float = 0.25
    used: int = 0
    last_request: float = 0.0

    def __post_init__(self) -> None:
        if not 2 <= self.maximum <= 20:
            raise PolicyError("Target connection budget must be between 2 and 20")
        if not 0.1 <= self.timeout <= 30:
            raise PolicyError("Per-operation timeout must be between 0.1 and 30 seconds")
        if not 0.2 <= self.delay <= 10:
            raise PolicyError("Minimum request interval must be between 0.2 and 10 seconds")

    def take(self) -> None:
        if self.used >= self.maximum:
            raise PolicyError("Target connection budget exhausted")
        wait = self.delay - (time.monotonic() - self.last_request)
        if wait > 0:
            time.sleep(wait)
        self.used += 1
        self.last_request = time.monotonic()


def _numeric_socket(scope: Scope, timeout: float) -> socket.socket:
    address = scope.addresses[0]
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, scope.target.port))
        return sock
    except BaseException:
        sock.close()
        raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, scope: Scope, timeout: float):
        super().__init__(scope.target.host, scope.target.port, timeout=timeout)
        self.scope = scope

    def connect(self) -> None:
        sock = _numeric_socket(self.scope, self.timeout)
        try:
            if self.scope.target.scheme == "https":
                # The socket is pinned, while certificate verification and SNI use the original host.
                context = ssl.create_default_context()
                context.set_alpn_protocols(["http/1.1"])
                sock = context.wrap_socket(sock, server_hostname=self.scope.target.host)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


def _signals(headers: list[tuple[str, str]], scope: Scope) -> dict:
    """Reduce untrusted text to typed signals. Never retain cookie names/values or raw headers."""
    total = sum(len(k) + len(v) for k, v in headers)
    if total > 32768:
        raise PolicyError("Response headers exceed the 32 KiB evidence budget")
    values: dict[str, list[str]] = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value)
    types = values.get("content-type", [])
    html = any(value.split(";", 1)[0].strip().lower() in
               ("text/html", "application/xhtml+xml") for value in types)
    csp = values.get("content-security-policy", [])
    frame_ancestors = any(re.search(r"(?:^|;)\s*frame-ancestors\s+[^;\s]", v, re.I) for v in csp)
    xfo = any(v.strip().lower() in ("deny", "sameorigin") for v in values.get("x-frame-options", []))
    hsts = values.get("strict-transport-security", [])
    hsts_age = None
    for value in hsts:
        match = re.search(r'(?:^|;)\s*max-age\s*=\s*"?(\d{1,12})"?\s*(?:;|$)', value, re.I)
        if match:
            hsts_age = int(match.group(1))
            break
    location_class = "absent"
    if values.get("location"):
        try:
            redirect = urlsplit(urljoin(scope.target.url, values["location"][0]))
            host = (redirect.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
            if redirect.scheme == "https" and host == scope.target.host:
                location_class = "same_host_https"
            else:
                location_class = "other_not_followed"
        except (ValueError, UnicodeError):
            location_class = "invalid_not_followed"
    cookies = []
    parse_errors = 0
    for raw in values.get("set-cookie", [])[:20]:
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except CookieError:
            parse_errors += 1
            continue
        if not parsed:
            parse_errors += 1
        for morsel in parsed.values():
            if len(cookies) >= 20:
                break
            same_site = morsel["samesite"].lower()
            cookies.append({
                "index": len(cookies) + 1,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": same_site if same_site in ("lax", "strict", "none") else "absent_or_invalid",
            })
    return {
        "html": html,
        "csp_present": any(bool(v.strip()) for v in csp),
        "frame_ancestors_present": frame_ancestors,
        "xfo_restrictive": xfo,
        "nosniff": any(v.strip().lower() == "nosniff" for v in values.get("x-content-type-options", [])),
        "hsts_present": bool(hsts),
        "hsts_max_age": hsts_age,
        "location_class": location_class,
        "cookies": cookies,
        "cookie_parse_errors": parse_errors,
        "cookie_headers_truncated": len(values.get("set-cookie", [])) > 20,
        "raw_headers_retained": False,
        "body_retained": False,
    }


def _error(exc: Exception) -> dict:
    # Never include a raw server error, URL, certificate subject, or credential in the log.
    if isinstance(exc, ssl.SSLCertVerificationError):
        return {"status": "error", "error": "certificate_verification_failed",
                "verify_code": getattr(exc, "verify_code", None)}
    if isinstance(exc, PolicyError):
        return {"status": "error", "error": "policy_or_budget_limit"}
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return {"status": "error", "error": "timeout"}
    return {"status": "error", "error": "connection_or_protocol_error"}


class ProbeClient:
    def __init__(self, scope: Scope, budget: Budget):
        self.scope = scope
        self.budget = budget

    def http(self) -> dict:
        observed = utc_now()
        conn = None
        try:
            self.budget.take()
            conn = _PinnedHTTPConnection(self.scope, self.budget.timeout)
            conn.request("GET", self.scope.target.path, headers={
                "Host": self.scope.target.authority,
                "User-Agent": "DeepAudit-MVP/0.1 (authorized read-only audit)",
                "Accept": "text/html,application/json;q=0.8,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = conn.getresponse()
            # No response.read(): bodies are neither consumed nor sent to the LLM.
            return {"status": "ok", "observed_at": observed, "status_code": response.status,
                    "signals": _signals(response.getheaders(), self.scope)}
        except (OSError, http.client.HTTPException, PolicyError) as exc:
            return {"observed_at": observed, **_error(exc)}
        finally:
            if conn:
                conn.close()

    def tls(self) -> dict:
        observed = utc_now()
        if self.scope.target.scheme != "https":
            return {"status": "skipped", "observed_at": observed, "reason": "target_is_http"}
        sock = None
        try:
            self.budget.take()
            sock = _numeric_socket(self.scope, self.budget.timeout)
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self.scope.target.host)
            certificate = sock.getpeercert()
            cipher = sock.cipher()
            expiry = ssl.cert_time_to_seconds(certificate["notAfter"])
            return {
                "status": "ok", "observed_at": observed, "verified": True,
                "protocol": sock.version(),
                "cipher": cipher[0] if cipher else None,
                "not_after": datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
            }
        except (OSError, ValueError, KeyError, PolicyError) as exc:
            return {"observed_at": observed, **_error(exc)}
        finally:
            if sock:
                sock.close()
