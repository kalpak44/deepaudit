"""CVE intelligence: correlate identified packages to advisories, then prioritize by exploitation.

A version match alone is noise. This turns "package X@Y" into a prioritized list by chaining
three public sources (none of them the target):

    OSV.dev   — does this exact version fall in a vulnerable range? which CVE/GHSA ids?
    CISA KEV  — is that CVE *known to be exploited in the wild*? (the strongest signal)
    EPSS      — FIRST.org's probability the CVE will be exploited in the next 30 days

The output ranks findings by (KEV, EPSS, CVSS) so the report leads with what actually matters
instead of a flat wall of version matches. Every queried version must come from real
fingerprint evidence, never assumption — the caller is responsible for that.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl
import time

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_KEV_URL = ("www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_EPSS_HOST = "api.first.org"
_OSV_HOST = "api.osv.dev"
_kev_cache: set[str] | None = None


def _get_json(host: str, path: str, *, method="GET", body=None, timeout=20):
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout,
                                       context=ssl.create_default_context())
    try:
        headers = {"User-Agent": "DeepAudit/2.0", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            conn.request(method, path, body=json.dumps(body).encode(), headers=headers)
        else:
            conn.request(method, path, headers=headers)
        response = conn.getresponse()
        raw = response.read(8_000_000)
        if response.status != 200:
            return {"_error": f"{host} returned HTTP {response.status}"}
        return json.loads(raw.decode("utf-8", "replace"))
    finally:
        conn.close()


def kev_set() -> set[str]:
    """CVE ids in CISA's Known Exploited Vulnerabilities catalog (downloaded once, cached)."""
    global _kev_cache
    if _kev_cache is None:
        try:
            data = _get_json(*_KEV_URL, timeout=30)
            _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}
        except (OSError, ValueError, http.client.HTTPException, KeyError):
            _kev_cache = set()
    return _kev_cache


def epss_scores(cve_ids) -> dict[str, float]:
    """EPSS probability per CVE (0..1). Batched; missing ids simply absent."""
    ids = sorted({c for c in cve_ids if _CVE.fullmatch(c)})
    scores: dict[str, float] = {}
    for start in range(0, len(ids), 100):
        batch = ids[start:start + 100]
        data = _get_json(_EPSS_HOST, "/data/v1/epss?cve=" + ",".join(batch))
        for row in (data.get("data") or []) if isinstance(data, dict) else []:
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError, TypeError):
                continue
        time.sleep(0.2)
    return scores


def osv_query(package: dict) -> dict:
    body = {"version": package["version"], "package": {"name": package["name"]}}
    if package.get("ecosystem"):
        body["package"]["ecosystem"] = package["ecosystem"]
    return _get_json(_OSV_HOST, "/v1/query", method="POST", body=body)


def _cvss(vuln: dict):
    best = None
    for entry in vuln.get("severity") or []:
        score = entry.get("score")
        match = re.search(r"(\d+\.\d+)$", str(score))
        if match:
            best = max(best or 0.0, float(match.group(1)))
    return best


def _ids(vuln: dict) -> list[str]:
    text = " ".join([vuln.get("id", "")] + (vuln.get("aliases") or []))
    return sorted(set(_CVE.findall(text)))


def lookup(packages: list[dict]) -> dict:
    """Full correlation for a list of {ecosystem?, name, version}. Returns prioritized findings."""
    if not packages:
        raise ValueError("Provide at least one identified package with a version from evidence")
    kev = kev_set()
    raw: list[dict] = []
    all_cves: set[str] = set()
    for package in packages[:64]:
        entry = {"package": package}
        try:
            data = osv_query(package)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            entry["error"] = str(exc)[:300]
            raw.append(entry)
            continue
        if "_error" in data:
            entry["error"] = data["_error"]
            raw.append(entry)
            continue
        vulns = []
        for vuln in (data.get("vulns") or [])[:40]:
            cves = _ids(vuln)
            all_cves.update(cves)
            vulns.append({
                "id": vuln.get("id"), "cves": cves,
                "summary": (vuln.get("summary") or "")[:300],
                "cvss": _cvss(vuln),
                "kev": any(c in kev for c in cves),
                "aliases": (vuln.get("aliases") or [])[:8],
                "published": vuln.get("published"), "withdrawn": vuln.get("withdrawn"),
            })
        entry["vulns"] = vulns
        raw.append(entry)
        time.sleep(0.2)
    epss = epss_scores(all_cves)
    findings = []
    for entry in raw:
        for vuln in entry.get("vulns", []):
            vuln["epss"] = max((epss.get(c, 0.0) for c in vuln["cves"]), default=0.0)
            findings.append({"package": entry["package"], **vuln})
    findings.sort(key=lambda v: (v["kev"], v["epss"], v["cvss"] or 0.0), reverse=True)
    return {
        "source": "OSV.dev + CISA KEV + FIRST EPSS",
        "queried": len(packages), "advisories": len(findings),
        "kev_hits": sum(1 for f in findings if f["kev"]),
        "prioritized": findings[:60],
        "errors": [{"package": e["package"], "error": e["error"]} for e in raw if e.get("error")],
        "limitations": "A version-to-advisory match means POTENTIALLY affected, not confirmed "
                       "exploitable: backports, disputed/withdrawn advisories and imprecise ecosystem "
                       "mapping cause noise. KEV = exploited in the wild (act on these first); EPSS is a "
                       "30-day exploitation probability. Confirm with a targeted, authorized check.",
    }
