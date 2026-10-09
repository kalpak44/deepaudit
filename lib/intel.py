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
from urllib.parse import quote

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_KEV_URL = ("www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_EPSS_HOST = "api.first.org"
_OSV_HOST = "api.osv.dev"
_NVD_HOST = "services.nvd.nist.gov"
_POC_HOST = "raw.githubusercontent.com"
_kev_cache: set[str] | None = None


def _get_json(host: str, path: str, *, method="GET", body=None, timeout=20, extra_headers=None):
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout,
                                       context=ssl.create_default_context())
    try:
        headers = {"User-Agent": "DeepAudit/2.0", "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
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


# ---- NVD 2.0 keyword/CPE search (the "search the live internet for the actual CVEs" step) ----
# OSV is precise when you have an exact package+version in a known ecosystem, but it misses
# server software, appliances and fresh disclosures. NVD is the authoritative index: search it
# by product keyword or CPE to surface the CVEs that actually affect the fingerprinted software,
# with their CVSS, CWE and — crucially — reference links that often point straight at a PoC.

def _nvd_cvss(cve: dict):
    """Best (highest) base score + severity across whatever metric versions NVD returns."""
    metrics = cve.get("metrics") or {}
    best_score, best_sev, best_vector = None, None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and (best_score is None or score > best_score):
                best_score = float(score)
                best_sev = data.get("baseSeverity") or metric.get("baseSeverity")
                best_vector = data.get("vectorString")
    return best_score, best_sev, best_vector


def _nvd_parse(cve: dict, kev: set[str]) -> dict:
    cid = cve.get("id", "")
    descs = cve.get("descriptions") or []
    summary = next((d.get("value", "") for d in descs if d.get("lang") == "en"),
                   (descs[0].get("value", "") if descs else ""))
    score, severity, vector = _nvd_cvss(cve)
    cwes = sorted({d.get("value") for w in (cve.get("weaknesses") or [])
                   for d in (w.get("description") or []) if d.get("value")}
                  - {None, "NVD-CWE-noinfo", "NVD-CWE-Other"})
    refs = cve.get("references") or []
    # References tagged by NVD as containing a working exploit are the highest-signal leads.
    exploit_refs = [r.get("url") for r in refs
                    if any("exploit" in str(t).lower() for t in (r.get("tags") or [])) and r.get("url")]
    return {
        "cve": cid, "summary": summary[:400], "cvss": score, "severity": severity,
        "vector": vector, "cwes": cwes[:5], "kev": cid in kev,
        "published": cve.get("published"), "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "exploit_refs": exploit_refs[:8], "references": [r.get("url") for r in refs[:12] if r.get("url")],
    }


def nvd_search(keyword: str = "", cpe: str = "", *, limit: int = 20, api_key: str = "") -> dict:
    """Search NVD 2.0 by product keyword and/or CPE match string. Keyless; an NVD_API_KEY only
    raises the rate limit. Returns CVEs newest-first, each KEV-tagged and EPSS-scored."""
    keyword, cpe = str(keyword or "").strip(), str(cpe or "").strip()
    if not keyword and not cpe:
        raise ValueError("Provide a product keyword (e.g. 'Apache Tomcat 9.0.30') or a CPE match string")
    params = [f"resultsPerPage={max(1, min(int(limit), 50))}"]
    if keyword:
        params.append("keywordSearch=" + quote(keyword))
    if cpe:
        params.append("virtualMatchString=" + quote(cpe))
    headers = {"apiKey": api_key} if api_key else None
    data = _get_json(_NVD_HOST, "/rest/json/cves/2.0?" + "&".join(params),
                     timeout=30, extra_headers=headers)
    if not isinstance(data, dict) or "_error" in data:
        return {"source": "NVD 2.0", "query": keyword or cpe,
                "error": (data or {}).get("_error", "NVD request failed"), "results": []}
    kev = kev_set()
    items = [_nvd_parse(v.get("cve") or {}, kev)
             for v in (data.get("vulnerabilities") or []) if isinstance(v, dict)]
    scores = epss_scores([i["cve"] for i in items])
    for item in items:
        item["epss"] = scores.get(item["cve"], 0.0)
    items.sort(key=lambda i: (i["kev"], i["epss"], i["cvss"] or 0.0), reverse=True)
    return {
        "source": "NVD 2.0 + CISA KEV + FIRST EPSS", "query": keyword or cpe,
        "total": data.get("totalResults", len(items)), "returned": len(items),
        "kev_hits": sum(1 for i in items if i["kev"]), "results": items,
        "limitations": "Keyword search is broad — confirm each CVE actually matches the exact "
                       "build you fingerprinted (version, module, platform) before acting. A match "
                       "is POTENTIALLY affected until a targeted check on the target confirms it.",
    }


# ---- Public-exploit sourcing (the "find the actual exploit to try" step) ----------------------
# Given a CVE id, locate real, public PoCs so the agent can fetch, read and adapt one rather than
# improvise. Keyless: the community nomi-sec/PoC-in-GitHub dataset maps CVE -> GitHub PoC repos
# (with stars/recency), and NVD's own exploit-tagged references add vendor/exploit-db links. The
# agent still fetches and runs the PoC itself via `run`, non-destructively, against the one target.

def poc_in_github(cve_id: str) -> list[dict]:
    """Known public PoC repositories for a CVE, from the nomi-sec/PoC-in-GitHub index."""
    cid = str(cve_id or "").strip().upper()
    if not _CVE.fullmatch(cid):
        return []
    year = cid.split("-")[1]
    data = _get_json(_POC_HOST, f"/nomi-sec/PoC-in-GitHub/master/{year}/{cid}.json", timeout=20)
    if not isinstance(data, list):
        return []
    repos = [{"repo": r.get("full_name"), "url": r.get("html_url"),
              "stars": r.get("stargazers_count", 0), "description": (r.get("description") or "")[:200],
              "updated": r.get("updated_at")}
             for r in data if isinstance(r, dict) and r.get("html_url")]
    repos.sort(key=lambda r: r.get("stars", 0), reverse=True)
    return repos[:15]


def exploit_intel(cve_id: str) -> dict:
    """Where public exploits/PoCs for this CVE live: GitHub PoC repos + NVD exploit-tagged refs."""
    cid = str(cve_id or "").strip().upper()
    if not _CVE.fullmatch(cid):
        raise ValueError("Provide a single CVE id, e.g. CVE-2021-44228")
    try:
        github = poc_in_github(cid)
    except (OSError, ValueError, http.client.HTTPException):
        github = []
    exploit_refs, nvd_summary = [], ""
    try:
        data = _get_json(_NVD_HOST, "/rest/json/cves/2.0?cveId=" + cid, timeout=20)
        for wrapper in (data.get("vulnerabilities") or []) if isinstance(data, dict) else []:
            parsed = _nvd_parse(wrapper.get("cve") or {}, kev_set())
            exploit_refs = parsed.get("exploit_refs", [])
            nvd_summary = parsed.get("summary", "")
            break
    except (OSError, ValueError, http.client.HTTPException, KeyError):
        pass
    return {
        "cve": cid, "summary": nvd_summary,
        "kev": cid in kev_set(), "epss": epss_scores([cid]).get(cid, 0.0),
        "github_pocs": github, "nvd_exploit_refs": exploit_refs,
        "public_exploit_available": bool(github or exploit_refs),
        "next_step": "Fetch a PoC (git clone / raw download the repo above, or `searchsploit -m`, "
                     "or run `nuclei -id " + cid + "`), READ it, adapt it to the authorized target, "
                     "and run it non-destructively via `run`. Capture the raw output with "
                     "add_evidence and cite it as poc_evidence_id/poc_quote on the finding.",
        "caution": "PoC repositories are untrusted third-party code: read before running, never "
                   "paste-and-execute blindly, and keep every request aimed only at the target.",
    }
