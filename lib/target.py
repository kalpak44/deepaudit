"""The scope boundary: validate the one authorized target and resolve it to public addresses.

Every capability that touches the network resolves the target through here first. The rules:
one HTTP(S) URL or bare host, no credentials, no query/fragment, and it must resolve only to
globally-routable addresses. This is the guard that keeps an autonomous, tool-installing agent
pointed at the single authorized target and off internal/loopback/link-local infrastructure.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit

BODY_LIMIT = 262_144
_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")


def target_url(target: str) -> str:
    """Normalize a URL/host to a canonical scheme://host[:port]/path, or raise ValueError."""
    if not isinstance(target, str) or not target or len(target) > 2000:
        raise ValueError("Supply one HTTP(S) URL or hostname")
    if any(ord(c) < 33 for c in target) or "\\" in target:
        raise ValueError("Invalid characters in target")
    parsed = urlsplit(target if "://" in target else "https://" + target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target must be an HTTP(S) URL without credentials")
    if parsed.fragment or parsed.query:
        raise ValueError("Target must not contain a query or fragment")
    host = parsed.hostname.encode("idna").decode("ascii")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(_LABEL.fullmatch(s) for s in host.rstrip(".").split(".")):
            raise ValueError("Target must be a single hostname, not flags or a range")
    port = parsed.port  # validates port syntax and range
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def hostname(target: str) -> str:
    return urlsplit(target_url(target)).hostname


# Common multi-label public suffixes where the registrable domain needs one extra label
# (e.g. "shop.example.co.uk" -> "example.co.uk", not "co.uk"). Best-effort, not a full PSL.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.za", "org.za", "net.za", "gov.za",
    "com.mx", "com.sg", "com.hk", "co.kr", "co.il", "com.tr", "com.ar", "com.tw",
}


def registrable_domain(host: str) -> str:
    """Best-effort root registrable domain: shop.example.com -> example.com, an IP -> itself.

    Not a full public-suffix-list implementation, but covers the common cases well enough to
    widen scope from "this one subdomain" to "the whole domain and all its subdomains" when a
    subdomain is given as the target.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def origin(url: str):
    u = urlsplit(url)
    return u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)


def public_address(host: str, port: int) -> str:
    """Resolve to a single globally-routable address, or raise if any resolution is private."""
    addresses = sorted({r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("Target must resolve only to public addresses")
    return next((a for a in addresses if ":" not in a), addresses[0])


def assert_in_scope(candidate: str, target: str) -> str:
    """Confirm a candidate shares the authorized target's registrable root domain. Raise otherwise.

    Scope is the whole domain, not just the exact host given: if the target is a subdomain
    (shop.example.com), the root (example.com) and every other subdomain of it are in scope too.
    """
    root = registrable_domain(hostname(target))
    got = hostname(candidate) if "://" in candidate or "." in candidate else candidate
    if got != root and not (got or "").endswith("." + root):
        raise ValueError(f"out of scope: {candidate!r} is not {root} or a subdomain of it")
    return got


def fetch(url: str, *, method="GET", headers=None, timeout=12) -> dict:
    """One request to the validated public address with the original Host/SNI; no redirects."""
    parsed = urlsplit(url)
    host, port = parsed.hostname, origin(url)[2]
    address = public_address(host, port)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    sock = socket.create_connection((address, port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection.sock = sock
        connection.request(method, urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                           headers={"User-Agent": "DeepAudit/2.0", "Accept-Encoding": "identity",
                                    **(headers or {})})
        response = connection.getresponse()
        raw = response.read(BODY_LIMIT + 1)
        safe_headers = []
        for key, value in response.getheaders():
            if key.lower() == "set-cookie":
                name, _, rest = value.partition("=")
                _, sep, attributes = rest.partition(";")
                value = name + "=<redacted>" + (";" + attributes if sep else "")
            safe_headers.append([key, value])
        return {"url": url, "status": response.status, "headers": safe_headers,
                "body": raw[:BODY_LIMIT].decode("utf-8", errors="replace"),
                "body_truncated": len(raw) > BODY_LIMIT, "connected_address": address}
    finally:
        connection.close()
        sock.close()
