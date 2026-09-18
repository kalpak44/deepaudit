"""Target parsing, exact scope enforcement, and DNS pinning.

The model never supplies a URL, IP, path, method, or request header.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import quote, unquote, urlsplit


class PolicyError(ValueError):
    """An operation does not fit the operator's explicitly selected scope."""


_PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
_PRIVATE_V6 = tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "::1/128"))


def validate_address(value: str, allow_private: bool = False) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PolicyError("Resolver returned an invalid IP address") from exc
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return validate_address(str(ip.ipv4_mapped), allow_private)
        if ip.sixtofour or ip.teredo:
            raise PolicyError("IPv6 transition addresses are not supported")
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        # ::1 is marked reserved by some Python versions, but is a supported lab target.
        if not (allow_private and ip == ipaddress.ip_address("::1")):
            raise PolicyError("Link-local, metadata, multicast, unspecified, or reserved IP blocked")
    if ip.is_global:
        return str(ip)
    nets = _PRIVATE_V4 if ip.version == 4 else _PRIVATE_V6
    if allow_private and any(ip in network for network in nets):
        return str(ip)
    raise PolicyError("Non-public IP blocked; private lab scope requires --allow-private")


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str = "/"

    @classmethod
    def parse(cls, text: str) -> Target:
        if not isinstance(text, str) or not text or len(text) > 2048:
            raise PolicyError("Provide one domain, IP, or HTTP(S) URL")
        if text != text.strip() or any(ord(c) < 33 or ord(c) == 127 for c in text):
            raise PolicyError("Whitespace and control characters are not allowed in the target")
        if "\\" in text:
            raise PolicyError("Backslashes are not allowed in targets")
        raw = text
        if "://" not in raw:
            try:
                ip = ipaddress.ip_address(raw)
                raw = f"https://[{ip}]/" if ip.version == 6 else f"https://{ip}/"
            except ValueError:
                raw = "https://" + raw
        try:
            parts = urlsplit(raw)
            host = parts.hostname
            port = parts.port
        except ValueError as exc:
            raise PolicyError("Invalid URL or port; bracket IPv6 addresses with a port") from exc
        if parts.scheme not in ("http", "https") or not host:
            raise PolicyError("Only HTTP(S) targets are supported")
        if parts.username is not None or parts.password is not None:
            raise PolicyError("Credentials in URLs are not allowed")
        if parts.query or parts.fragment or "?" in raw or "#" in raw:
            raise PolicyError("Query strings and fragments are not supported; use a public, read-only path")
        if "%" in host:
            raise PolicyError("Encoded hosts and IPv6 zone identifiers are not supported")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            try:
                host = host.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise PolicyError("Invalid internationalized domain") from exc
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in host.split(".")
            ):
                raise PolicyError("Invalid domain name")
        actual_port = port if port is not None else (443 if parts.scheme == "https" else 80)
        if not 1 <= actual_port <= 65535:
            raise PolicyError("Port must be between 1 and 65535")
        decoded = unquote(parts.path or "/")
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded) or "\\" in decoded:
            raise PolicyError("Encoded control characters are not allowed")
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        return cls(parts.scheme, host, actual_port, path)

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False


@dataclass(frozen=True)
class Scope:
    target: Target
    addresses: tuple[str, ...]
    allow_private: bool = False

    @classmethod
    def resolve(cls, target: Target, *, authorized: bool, allow_private: bool = False) -> Scope:
        if not authorized:
            raise PolicyError("Confirm authorization with --authorized before any target network access")
        try:
            if target.is_ip:
                candidates = [target.host]
            else:
                infos = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
                candidates = [info[4][0] for info in infos]
        except OSError as exc:
            raise PolicyError("DNS resolution failed") from exc
        # Fail closed on mixed public/private answers. Resolve once, connect only to numeric IPs.
        addresses = tuple(sorted({validate_address(value, allow_private) for value in candidates},
                                 key=lambda value: (":" in value, value)))
        if not addresses:
            raise PolicyError("Target has no usable IP addresses")
        return cls(target, addresses, allow_private)

    def public(self) -> dict:
        return {
            "target": self.target.url,
            "pinned_addresses": list(self.addresses),
            "selected_address": self.addresses[0],
            "allow_private": self.allow_private,
            "methods": ["GET"],
            "follow_redirects": False,
            "authorized_by_operator": True,
        }
