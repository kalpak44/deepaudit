"""Collected evidence and the grounding gate that keeps findings honest.

Every observation an agent wants to keep is stored here as a numbered evidence item and
persisted to disk. Findings are then bound to that evidence: a finding must carry an
`evidence_id` and an exact `quote` that actually appears in that item's stored text. This is
the one deterministic check in an otherwise model-driven system — the agent interprets and
prioritizes, but it cannot report an observation no tool produced. `validate_finding` is
enforced identically for the supervisor, workers and the verifier.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")


class Evidence:
    def __init__(self, run_root: Path):
        self.dir = run_root / "evidence"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, dict] = {}
        self._lock = threading.RLock()

    def add(self, source: str, payload, *, task: str = "") -> str:
        with self._lock:
            eid = f"e{len(self._items) + 1:03d}"
            item = {"id": eid, "source": str(source)[:120], "task": task, "payload": payload}
            self._items[eid] = item
            (self.dir / f"{eid}.json").write_text(
                json.dumps(item, ensure_ascii=True, indent=2)[:2_000_000], encoding="utf-8")
        return eid

    def text(self, eid: str) -> str | None:
        item = self._items.get(eid)
        return None if item is None else json.dumps(item["payload"], ensure_ascii=True, indent=2)

    def read(self, eid: str, offset: int = 0, limit: int = 12000) -> dict:
        raw = self.text(eid)
        if raw is None:
            return {"error": "unknown_evidence_id"}
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 16000:
            return {"error": "offset must be >=0; limit must be 1..16000"}
        return {"id": eid, "text": raw[offset:offset + limit], "total_chars": len(raw),
                "next_offset": offset + limit if offset + limit < len(raw) else None}

    def index(self) -> list[dict]:
        with self._lock:
            return [{"id": i["id"], "source": i["source"], "task": i["task"],
                     "chars": len(json.dumps(i["payload"], ensure_ascii=True))}
                    for i in self._items.values()]

    def ground(self, eid: str, quote: str) -> bool:
        raw = self.text(eid)
        return raw is not None and isinstance(quote, str) and quote in raw

    def export(self, ids, *, budget: int = 400_000) -> list[dict]:
        """Export selected evidence items (for a worker to hand back), bounded in total size."""
        out: list[dict] = []
        with self._lock:
            for eid in dict.fromkeys(ids):  # de-dupe, preserve order
                item = self._items.get(eid)
                if item is None:
                    continue
                blob = json.dumps(item["payload"], ensure_ascii=True)
                if budget - len(blob) < 0:
                    out.append({"id": eid, "source": item["source"],
                                "payload": {"_truncated": True, "text": blob[:budget]}})
                    break
                budget -= len(blob)
                out.append({"id": item["id"], "source": item["source"], "payload": item["payload"]})
        return out


def validate_finding(entry: dict, evidence: Evidence) -> dict:
    """Return a normalized finding record or raise ValueError. Enforces evidence grounding."""
    if not isinstance(entry, dict):
        raise ValueError("finding must be an object")
    for key in ("title", "summary", "remediation", "evidence_id", "quote", "severity"):
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"finding requires a non-empty {key}")
    if entry["severity"] not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    quote = entry["quote"]
    if not 8 <= len(quote) <= 2000:
        raise ValueError("quote must be an exact 8..2000 char excerpt of the cited evidence")
    if not evidence.ground(entry["evidence_id"], quote):
        raise ValueError("quote does not appear in the cited evidence_id; read_evidence and quote exactly")
    record = {
        "title": entry["title"][:200], "summary": entry["summary"][:2000],
        "remediation": entry["remediation"][:2000], "severity": entry["severity"],
        "evidence_id": entry["evidence_id"], "quote": quote[:2000],
        "verification": "unreviewed",
    }
    for optional in ("cve", "cvss", "epss", "kev", "reproduction", "impact"):
        if entry.get(optional) not in (None, ""):
            record[optional] = entry[optional] if optional in ("cvss", "epss", "kev") else str(entry[optional])[:3000]
    return record
