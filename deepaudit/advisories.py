"""OSV.dev advisory lookup.

This is the only egress this pipeline performs, and it is reached solely through an
explicit operator consent flag. Querying sends dependency names and versions to a third
party, which for a private repository is itself disclosure — hence the separate gate
rather than folding it into the authorization flag.
"""
from __future__ import annotations

import http.client
import json
import ssl
import time

API_HOST = "api.osv.dev"
BATCH_PATH = "/v1/querybatch"
QUERY_PATH = "/v1/query"
MAX_RESPONSE_BYTES = 8_388_608
BATCH_SIZE = 500

DATA_SHARED = ("package ecosystem, package name and resolved version for each dependency; "
               "no source code, file contents, repository name, or credentials")


class AdvisoryError(RuntimeError):
    pass


class OSVClient:
    def __init__(self, *, timeout: float = 20, max_requests: int = 64):
        if not 1 <= max_requests <= 500:
            raise AdvisoryError("Invalid advisory request budget")
        self.timeout = timeout
        self.max_requests = max_requests
        self.requests = 0

    def _call(self, method: str, path: str, payload: dict | None) -> dict:
        if self.requests >= self.max_requests:
            raise AdvisoryError("Advisory request budget exhausted")
        self.requests += 1
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        for attempt in range(2):
            conn = http.client.HTTPSConnection(API_HOST, timeout=self.timeout,
                                               context=ssl.create_default_context())
            try:
                headers = {"Accept": "application/json", "Connection": "close"}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
            except (OSError, http.client.HTTPException) as exc:
                raise AdvisoryError("OSV connection failed or timed out") from exc
            finally:
                conn.close()
            if len(raw) > MAX_RESPONSE_BYTES:
                raise AdvisoryError("OSV response exceeded the size limit")
            if status in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(1)
                continue
            if status != 200:
                raise AdvisoryError(f"OSV returned HTTP {status}")
            try:
                data = json.loads(raw)
            except ValueError as exc:
                raise AdvisoryError("Invalid OSV response JSON") from exc
            if not isinstance(data, dict):
                raise AdvisoryError("Unexpected OSV response shape")
            return data
        raise AdvisoryError("OSV temporarily unavailable")

    def query_batch(self, components: list[dict]) -> dict[str, list[str]]:
        """Map each component key to the advisory ids OSV reports for it."""
        found: dict[str, list[str]] = {}
        for start in range(0, len(components), BATCH_SIZE):
            chunk = components[start:start + BATCH_SIZE]
            queries = [{"package": {"name": item["name"], "ecosystem": item["ecosystem"]},
                        "version": item["version"]} for item in chunk]
            page_token = None
            while True:
                payload: dict = {"queries": queries}
                if page_token:
                    payload["page_token"] = page_token
                data = self._call("POST", BATCH_PATH, payload)
                results = data.get("results")
                if not isinstance(results, list):
                    raise AdvisoryError("Unexpected OSV batch result shape")
                for item, result in zip(chunk, results):
                    if not isinstance(result, dict):
                        continue
                    key = component_key(item)
                    ids = [v.get("id") for v in (result.get("vulns") or [])
                           if isinstance(v, dict) and isinstance(v.get("id"), str)]
                    if ids:
                        found.setdefault(key, [])
                        found[key].extend(i for i in ids if i not in found[key])
                page_token = data.get("next_page_token")
                if not isinstance(page_token, str) or not page_token:
                    break
        return found

    def query(self, component: dict) -> list[dict]:
        """Full advisory records for one component.

        `querybatch` returns bare ids, so resolving them one GET at a time costs a request
        per advisory — a single mature package can carry dozens and drain the budget before
        anything is written. This returns the whole set in one request instead.
        """
        payload = {"package": {"name": component["name"], "ecosystem": component["ecosystem"]},
                   "version": component["version"]}
        data = self._call("POST", QUERY_PATH, payload)
        vulns = data.get("vulns")
        return [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []


def component_key(component: dict) -> str:
    return f"{component['ecosystem']}|{component['name']}|{component['version']}"


def normalize(raw: dict) -> dict:
    """Keep the advisory fields the report and the matcher need, and drop the rest."""
    aliases = [a for a in (raw.get("aliases") or []) if isinstance(a, str)]
    severities = []
    for entry in raw.get("severity") or []:
        if isinstance(entry, dict) and isinstance(entry.get("score"), str):
            severities.append({"type": entry.get("type"), "score": entry["score"]})
    label = None
    specific = raw.get("database_specific")
    if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
        label = specific["severity"]
    affected = []
    for entry in raw.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        ranges = []
        for item in entry.get("ranges") or []:
            if isinstance(item, dict) and isinstance(item.get("events"), list):
                ranges.append({"type": item.get("type"), "events": item["events"]})
        affected.append({
            "ecosystem": package.get("ecosystem"),
            "name": package.get("name"),
            "ranges": ranges,
            "versions": [v for v in (entry.get("versions") or []) if isinstance(v, str)],
        })
    return {
        "id": raw.get("id"),
        "aliases": aliases,
        "cve": sorted(a for a in aliases if a.startswith("CVE-")),
        "summary": (raw.get("summary") or "")[:500],
        "published": raw.get("published"),
        "modified": raw.get("modified"),
        "withdrawn": raw.get("withdrawn"),
        "severity": severities,
        "severity_label": label,
        "affected": affected,
        "references": [r.get("url") for r in (raw.get("references") or [])
                       if isinstance(r, dict) and isinstance(r.get("url"), str)][:10],
    }


def fetch(components: list[dict], client: OSVClient) -> dict:
    """Look up every component that carries a resolved version.

    Two stages: one batched pass narrows thousands of components down to the few that have
    advisories at all, then each of those is queried once for the full records. A budget
    exhausted partway keeps what was already retrieved and reports the rest as incomplete,
    because discarding it would turn a partial answer into an apparently clean one.
    """
    resolved = [item for item in components if item.get("version")]
    result = {"advisories": {}, "by_component": {}, "requests": 0,
              "incomplete": False, "error": None}
    if not resolved:
        return result
    index = {component_key(item): item for item in resolved}
    try:
        flagged = client.query_batch(resolved)
    except AdvisoryError as exc:
        result["requests"] = client.requests
        result["incomplete"] = True
        result["error"] = str(exc)
        return result
    advisories: dict[str, dict] = {}
    by_component: dict[str, list[str]] = {}
    for key in sorted(flagged):
        component = index.get(key)
        if component is None:
            continue
        try:
            records = client.query(component)
        except AdvisoryError as exc:
            result["incomplete"] = True
            result["error"] = str(exc)
            break
        identifiers = []
        for raw in records:
            entry = normalize(raw)
            if isinstance(entry.get("id"), str):
                advisories[entry["id"]] = entry
                identifiers.append(entry["id"])
        if identifiers:
            by_component[key] = sorted(set(identifiers))
    result.update({"advisories": advisories, "by_component": by_component,
                   "requests": client.requests})
    return result
