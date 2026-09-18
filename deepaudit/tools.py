"""The agent's entire capability set: typed, argument-free, scoped tools."""
from __future__ import annotations

import json
from collections.abc import Callable

from .policy import PolicyError
from .rules import evaluate, verify_observations
from .transport import ProbeClient, utc_now

DESCRIPTIONS = {
    "get_scope": "Return the operator-approved target, pinned IP, and limits. Scope cannot be changed.",
    "inspect_http": "Read normalized HTTP response-header signals for the approved URL. Cached after first call. No body or redirects.",
    "inspect_tls": "Check certificate trust and expiration for the approved HTTPS endpoint. Cached; skipped for HTTP.",
    "analyze_evidence": "Collect missing initial evidence and evaluate built-in configuration rules. No exploitation claims.",
    "verify_findings": "Independently re-fetch the same HTTP/TLS observations once, then label reproducibility. Cached after first call.",
    "list_findings": "Return evidence-backed findings and recheck status, completing the bounded checks if needed.",
}

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    }} for name, description in DESCRIPTIONS.items()
]


class AuditTools:
    def __init__(self, probes: ProbeClient, progress: Callable[[str], None] | None = None):
        self.probes = probes
        self.initial = {"schema_version": 1, "scope": probes.scope.public()}
        self.recheck: dict | None = None
        self.findings: list[dict] = []
        self.events: list[dict] = []
        self.progress = progress or (lambda _: None)

    def event(self, kind: str, **data) -> None:
        self.events.append({"at": utc_now(), "kind": kind, **data})

    def invoke(self, name: str, arguments: str = "{}", *, origin: str = "agent") -> dict:
        if name not in DESCRIPTIONS:
            self.event("tool_rejected", reason="unknown_tool", origin=origin)
            return {"error": "unknown_tool", "allowed_tools": list(DESCRIPTIONS)}
        try:
            if not isinstance(arguments, str) or len(arguments) > 512:
                raise ValueError("invalid arguments")
            parsed = json.loads(arguments)
            if type(parsed) is not dict or parsed:
                raise ValueError("No arguments are allowed")
        except (ValueError, TypeError):
            self.event("tool_rejected", reason="arguments_must_be_empty_object", tool=name, origin=origin)
            return {"error": "arguments_must_be_empty_object"}
        self.progress(f"[{origin}] {name}")
        self.event("tool_start", tool=name, origin=origin)
        result = getattr(self, "_" + name)()
        self.event("tool_end", tool=name, origin=origin, connections_used=self.probes.budget.used)
        return result

    def _get_scope(self) -> dict:
        return {**self.probes.scope.public(), "connection_limit": self.probes.budget.maximum,
                "response_bodies": "never collected", "scope_mutable": False}

    def _inspect_http(self) -> dict:
        if "http" not in self.initial:
            self.initial["http"] = self.probes.http()
        return self.initial["http"]

    def _inspect_tls(self) -> dict:
        if "tls" not in self.initial:
            self.initial["tls"] = self.probes.tls()
        return self.initial["tls"]

    def _analyze_evidence(self) -> dict:
        self._inspect_http()
        self._inspect_tls()
        self.findings = (verify_observations(self.initial, self.recheck)
                         if self.recheck is not None else evaluate(self.initial))
        return {"findings": self.findings, "count": len(self.findings),
                "note": "Confirmed observations are not proof of exploitability."}

    def _verify_findings(self) -> dict:
        self._analyze_evidence()
        if self.recheck is None:
            self.recheck = {"schema_version": 1, "scope": self.probes.scope.public(),
                            "http": self.probes.http(), "tls": self.probes.tls()}
        self.findings = verify_observations(self.initial, self.recheck)
        return {"findings": self.findings, "count": len(self.findings), "coverage": self.coverage()}

    def _list_findings(self) -> dict:
        return self._verify_findings()

    def complete(self, origin: str = "coordinator") -> None:
        self.invoke("verify_findings", origin=origin)

    def coverage(self) -> dict:
        missing = []
        for phase, snapshot in (("initial", self.initial), ("recheck", self.recheck or {})):
            for probe in ("http", "tls"):
                item = snapshot.get(probe, {})
                supported_skip = probe == "tls" and self.probes.scope.target.scheme == "http"
                certificate_result = probe == "tls" and item.get("error") == "certificate_verification_failed"
                if item.get("status") != "ok" and not supported_skip and not certificate_result:
                    missing.append(f"{phase}.{probe}")
        return {"complete": not missing, "unavailable": missing,
                "scope_note": "One URL, one selected IP; no other pages, ports, virtual hosts, or TLS versions enumerated."}
