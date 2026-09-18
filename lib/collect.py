"""Evidence-only workflow entrypoint. No LLM, dynamic shell, or arbitrary scanner flags."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from .tool_catalog import SPECS, validate_params

BODY_LIMIT = 65536


def target_url(target: str) -> str:
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
        if len(host) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", s) for s in host.rstrip(".").split(".")):
            raise ValueError("Target must be a single hostname, not flags or a range")
    port = parsed.port  # also validates port syntax and range
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def public_address(host: str, port: int) -> str:
    addresses = sorted({r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("Target must resolve only to public addresses")
    return next((a for a in addresses if ":" not in a), addresses[0])


def origin(url: str):
    u = urlsplit(url)
    return u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)


def fetch(url: str, *, method="GET", headers=None) -> dict:
    """Connect to the validated address with the original Host/SNI; never follow redirects."""
    parsed = urlsplit(url)
    host, port = parsed.hostname, origin(url)[2]
    address = public_address(host, port)
    connection = http.client.HTTPConnection(host, port, timeout=12)
    sock = socket.create_connection((address, port), timeout=12)
    try:
        if parsed.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection.sock = sock
        connection.request(method, urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                           headers={"User-Agent": "DeepAudit/1.0", "Accept-Encoding": "identity", **(headers or {})})
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


def sample(url, **kwargs):
    try:
        return fetch(url, **kwargs)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return {"url": url, "error": str(exc)[:500]}


def compact_response(response: dict, *, preview: bool = False) -> dict:
    body = response.pop("body", "")
    response["sample_sha256"] = hashlib.sha256(body.encode()).hexdigest()
    response["sample_bytes"] = len(body.encode())
    if preview:
        response["body_preview"] = body[:1500]
    return response


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self.scripts = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get")})
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])


def collect_http(url, params):
    u = urlsplit(url)
    path = params["path"] if params["path"] != "/" else (u.path or "/")
    endpoint = urlunsplit((u.scheme, u.netloc, path, "", ""))
    requests = [compact_response(sample(endpoint)), compact_response(sample(endpoint, method="OPTIONS"))]
    if params["cors"]:
        requests.append(compact_response(sample(endpoint, headers={"Origin": "https://deepaudit.invalid"})))
    return {"requests": requests, "limitations": "Unauthenticated responses only; CORS reflection alone does not prove data exposure."}


def collect_crawl(url, params):
    queue, seen, pages = [url], set(), []
    while queue and len(pages) < params["max_pages"]:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        page = sample(current)
        parser = PageParser()
        parser.feed(page.get("body", ""))
        local = []
        for link in parser.links[:200]:
            joined = urlsplit(urljoin(current, link))
            candidate = urlunsplit((joined.scheme, joined.netloc, joined.path or "/", "", ""))
            if origin(candidate) != origin(url) or joined.query:
                continue
            # Do not follow links likely to mutate a session or resource.
            if re.search(r"(?:logout|signout|delete|remove|unsubscribe)", joined.path, re.I):
                continue
            local.append(candidate)
            if candidate not in seen and candidate not in queue and len(queue) < 100:
                queue.append(candidate)
        pages.append({**compact_response(page), "links": local[:50],
                      "forms": parser.forms[:30], "scripts": parser.scripts[:30]})
        if queue:
            time.sleep(params["delay_ms"] / 1000)
    return {"pages": pages, "remaining_urls": len(queue), "limitations": "HTML only; no JavaScript execution, query links, form submission or authenticated pages."}


def collect_exposure(url, params):
    profiles = {
        "discovery": ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/openapi.json", "/swagger.json"],
        "diagnostics": ["/server-status", "/server-info", "/actuator/health", "/actuator/info", "/debug/vars"],
    }
    base = urlsplit(url)
    paths = ["/deepaudit-missing-" + uuid.uuid4().hex, *profiles[params["profile"]]]
    responses = []
    for path in paths:
        response = sample(urlunsplit((base.scheme, base.netloc, path, "", "")))
        responses.append(compact_response(response, preview=True))
        time.sleep(0.5)
    return {"control": responses[0], "endpoints": responses[1:],
            "limitations": "An HTTP 200 is not confirmation; compare control and content. Public documentation may be intentional."}


def collect_tls(url, _params):
    scheme, host, port = origin(url)
    if scheme != "https":
        return {"not_applicable": "The supplied origin is HTTP; TLS was not probed on another port."}
    address = public_address(host, port)
    observations = []
    for label, version in (("default", None), ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
        context = ssl.create_default_context()
        if version:
            context.minimum_version = context.maximum_version = version
        try:
            with socket.create_connection((address, port), timeout=12) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure:
                    observations.append({"probe": label, "trusted": True, "protocol": secure.version(),
                                         "cipher": secure.cipher(), "certificate": secure.getpeercert()})
        except ssl.SSLCertVerificationError as exc:
            observations.append({"probe": label, "trusted": False, "verification_error": exc.verify_message})
        except OSError as exc:
            observations.append({"probe": label, "error": str(exc)[:500]})
    return {"host": host, "port": port, "observations": observations,
            "limitations": "No legacy protocol, exhaustive cipher, revocation or downgrade testing. Handshake errors can be network/client limitations."}


OSV_HOST = "api.osv.dev"


def osv_query(package: dict) -> dict:
    """One OSV /v1/query for a package@version. Fixed third-party host, verified TLS, no target contact."""
    body = {"version": package["version"], "package": {"name": package["name"]}}
    if package.get("ecosystem"):
        body["package"]["ecosystem"] = package["ecosystem"]
    connection = http.client.HTTPSConnection(OSV_HOST, 443, timeout=15)
    try:
        connection.request("POST", "/v1/query", body=json.dumps(body).encode(),
                           headers={"User-Agent": "DeepAudit/1.0", "Content-Type": "application/json",
                                    "Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(500000)
        if response.status != 200:
            return {"error": f"OSV returned HTTP {response.status}",
                    "detail": raw[:300].decode("utf-8", errors="replace")}
        return json.loads(raw.decode("utf-8", errors="replace"))
    finally:
        connection.close()


def summarize_vuln(vuln: dict) -> dict:
    affected = []
    for entry in (vuln.get("affected") or [])[:5]:
        pkg = entry.get("package") or {}
        ranges = []
        for rng in (entry.get("ranges") or [])[:4]:
            events = {k: v for event in (rng.get("events") or []) for k, v in event.items()}
            ranges.append({"type": rng.get("type"), "introduced": events.get("introduced"),
                           "fixed": events.get("fixed"), "last_affected": events.get("last_affected")})
        affected.append({"name": pkg.get("name"), "ecosystem": pkg.get("ecosystem"),
                         "ranges": ranges, "versions_sample": (entry.get("versions") or [])[:5]})
    return {"id": vuln.get("id"), "aliases": (vuln.get("aliases") or [])[:8],
            "summary": (vuln.get("summary") or "")[:400], "details_excerpt": (vuln.get("details") or "")[:400],
            "severity": [s.get("score") for s in (vuln.get("severity") or []) if s.get("score")][:4],
            "published": vuln.get("published"), "modified": vuln.get("modified"),
            "withdrawn": vuln.get("withdrawn"), "affected": affected}


def collect_osv(_url, params):
    packages = params["packages"]
    if not packages:
        raise ValueError("Provide at least one identified package with a version from prior fingerprint evidence")
    results = []
    for package in packages:
        entry = {"query": package}
        try:
            data = osv_query(package)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            entry["error"] = str(exc)[:300]
            results.append(entry)
            continue
        if "error" in data:
            entry.update(data)
        else:
            vulns = data.get("vulns") or []
            entry["match_count"] = len(vulns)
            entry["vulns"] = [summarize_vuln(v) for v in vulns[:20]]
            if len(vulns) > 20:
                entry["truncated"] = f"{len(vulns) - 20} additional advisory records omitted"
        results.append(entry)
        time.sleep(0.3)
    return {"source": "https://api.osv.dev/v1/query", "results": results,
            "limitations": "OSV maps a version to advisory ranges; a match means potentially affected, not confirmed "
                           "exploitable. Distro backports, disputed or withdrawn advisories and imprecise ecosystem "
                           "mapping can over- or under-report. Every queried version must trace to fingerprint evidence."}


def collect_script(params, evidence):
    """Analysis over supervisor-provided evidence only; the target is never contacted here."""
    from . import sandbox
    code = params["code"]
    if not code.strip():
        raise ValueError("Provide Python in `code` that assigns JSON-compatible data to `result`")
    if not isinstance(evidence, dict):
        raise ValueError("Injected evidence bundle was not a JSON object")
    outcome = sandbox.run_user_code(code, evidence)
    if outcome["status"] != "ok":
        raise RuntimeError(outcome.get("error", "analysis failed") +
                           (f" | stdout: {outcome['stdout']}" if outcome.get("stdout") else ""))
    return {"result": outcome["result"], "stdout": outcome.get("stdout", ""),
            "isolation": outcome["isolation"], "analyzed_task_ids": sorted(evidence),
            "limitations": "Computation over previously collected evidence with no network access; results are "
                           "derived, not independently observed. Cite the underlying tool evidence, not only this "
                           "analysis, and treat conclusions as interpretation to be verified."}


def collect_command(tool, url, params):
    u = urlsplit(url)
    address = public_address(u.hostname, origin(url)[2])
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "output.json"
        if tool == "fingerprinter":
            command = ["whatweb", "--color=never", "--quiet", "--follow-redirect=never",
                       "--open-timeout=10", "--read-timeout=10", f"--aggression={params['aggression']}",
                       f"--log-json={output}", url]
        else:
            command = ["nmap", "-sT", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "180s",
                       "--max-rate", str(params["max_rate"]), "--top-ports", str(params["top_ports"]), "-oX", str(output)]
            if params["service_detection"]:
                command.extend(["-sV", "--version-light"])
            if ":" in address:
                command.append("-6")
            command.append(address)
        # A fixed argv (no shell) is the complete command surface.
        result = subprocess.run(command, capture_output=True, text=True, timeout=240, check=False)
        raw = output.read_text(encoding="utf-8", errors="replace")[:200000] if output.exists() else ""
        if result.returncode or not raw:
            raise RuntimeError(f"{tool} exited {result.returncode}: {result.stderr[:600]}")
        if tool == "fingerprinter":
            raw = json.loads(raw)
        return {"output": raw, "resolved_address": address, "command": command[:-1],
                "limitations": "One hostname/address only; shared infrastructure may affect attribution. Versions do not establish exploitability."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("tool", choices=sorted(SPECS))
    p.add_argument("--target", default=os.getenv("TARGET", ""))
    p.add_argument("--params", default=os.getenv("PARAMS", "{}"))
    p.add_argument("--task-id", default=os.getenv("TASK_ID", ""))
    p.add_argument("--evidence", default=os.getenv("EVIDENCE", "{}"))
    p.add_argument("--out", default="evidence.json")
    a = p.parse_args(argv)
    envelope = {"schema_version": 1, "task_id": a.task_id, "tool": a.tool, "target": a.target,
                "collected_at": datetime.now(timezone.utc).isoformat(), "status": "failed"}
    try:
        url = target_url(a.target)
        params = validate_params(a.tool, json.loads(a.params))
        # All collectors validate public resolution again before connecting.
        handlers = {"http": collect_http, "crawl": collect_crawl, "tls": collect_tls,
                    "exposure": collect_exposure, "osv": collect_osv}
        if a.tool == "script":
            # Evidence is injected by the supervisor; the sandbox never touches the target or network.
            output = collect_script(params, json.loads(a.evidence or "{}"))
        elif a.tool in handlers:
            output = handlers[a.tool](url, params)
        else:
            output = collect_command(a.tool, url, params)
        envelope.update(status="ok", params=params, output=output)
    except Exception as exc:
        envelope["error"] = str(exc)[:1000]
    Path(a.out).write_text(json.dumps(envelope, ensure_ascii=True, indent=2), encoding="utf-8")
    print(f"{a.tool}: {envelope['status']} ({a.out})", flush=True)
    return 0 if envelope["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
