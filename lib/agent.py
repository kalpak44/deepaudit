"""Shared audit state and the common tool surface every acting agent gets.

The supervisor and each worker are the same kind of acting agent: they install and run tools,
look up CVEs, save evidence, and record grounded findings. That common surface lives here so
both roles expose identical, consistently-validated tools. Roles differ only in the extra
tools they add (the supervisor can fan out and finish; a worker completes its session).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from . import intel, playbooks
from .evidence import Evidence, SEVERITIES, validate_finding
from .run import Runner

STRING = {"type": "string"}


def schema(description, properties=None, required=()):
    return {"description": description,
            "parameters": {"type": "object", "properties": properties or {},
                           "required": list(required)}}


PACKAGE = {"type": "object", "properties": {
    "ecosystem": {"type": "string", "description": "OSV ecosystem, e.g. npm, PyPI, Debian; optional."},
    "name": STRING, "version": STRING}, "required": ["name", "version"]}

RUN_SCHEMA = schema(
    "Install tools and run a bash or python script against the authorized target. `setup` names "
    "arsenal tools to install; apt/pip/go/npm add extra packages. $AUDIT_TARGET/$AUDIT_HOST/"
    "$AUDIT_ADDR and $OUT (write JSON there) are in the environment. Batch installs; few big calls.",
    {"setup": {"type": "array", "items": STRING, "description": "Arsenal tool names to install."},
     "apt": {"type": "array", "items": STRING}, "pip": {"type": "array", "items": STRING},
     "go": {"type": "array", "items": STRING}, "npm": {"type": "array", "items": STRING},
     "lang": {"type": "string", "enum": ["bash", "python"], "default": "bash"},
     "code": STRING, "timeout": {"type": "integer", "minimum": 1, "maximum": 1500, "default": 240}},
    ("code",))

CVE_SCHEMA = schema(
    "Correlate identified packages/versions to advisories (OSV) and prioritize by real-world "
    "exploitation (CISA KEV) and probability (EPSS). Versions MUST come from fingerprint evidence.",
    {"packages": {"type": "array", "items": PACKAGE}}, ("packages",))

FINDING = {"type": "object", "properties": {
    "title": STRING, "summary": STRING, "remediation": STRING,
    "severity": {"type": "string", "enum": list(SEVERITIES)},
    "evidence_id": {"type": "string", "description": "Id from add_evidence/read_evidence."},
    "quote": {"type": "string", "description": "Exact 8..2000 char excerpt of that evidence."},
    "cve": STRING, "cvss": {"type": "number"}, "epss": {"type": "number"},
    "kev": {"type": "boolean"},
    "impact": STRING,
    "reproduction": {"type": "string", "description": "Optional non-destructive repro grounded in evidence."}},
    "required": ["title", "summary", "remediation", "severity", "evidence_id", "quote"]}

FINDING_SCHEMA = schema("Record one confirmed, evidence-grounded finding.",
                        FINDING["properties"], FINDING["required"])


class AuditState:
    """Everything a running audit accumulates. Thread-safe for parallel fan-out."""

    def __init__(self, target: str, run_root: Path, console):
        self.target = target
        self.run_root = run_root
        self.console = console
        self.evidence = Evidence(run_root)
        self.runner = Runner(target, console)
        self.findings: list[dict] = []
        self.notes: list[dict] = []
        self.hypotheses: list[dict] = []
        self.plan: dict = {}
        self._lock = threading.RLock()

    # -- evidence & findings ---------------------------------------------------
    def add_evidence(self, source: str, payload, *, task="") -> str:
        return self.evidence.add(source, payload, task=task)

    def record_finding(self, entry: dict, *, who: str) -> dict:
        try:
            record = validate_finding(entry, self.evidence)
        except ValueError as exc:
            return {"error": str(exc)}
        with self._lock:
            if len(self.findings) >= 200:
                return {"error": "finding budget exhausted; summarize the rest as limitations"}
            duplicate = next((f for f in self.findings
                              if f["title"] == record["title"] and f["evidence_id"] == record["evidence_id"]), None)
            if duplicate:
                return {"accepted": True, "id": duplicate["id"], "duplicate": True}
            record.update(id=f"F{len(self.findings) + 1:03d}", reporter=who)
            self.findings.append(record)
            self.save()
        self.console.event("FINDING", record["id"], severity=record["severity"], title=record["title"][:80])
        return {"accepted": True, "id": record["id"]}

    def note(self, who: str, message: str) -> dict:
        if not isinstance(message, str) or not 1 <= len(message) <= 2000:
            return {"error": "message must be 1..2000 chars"}
        with self._lock:
            self.notes.append({"who": who, "message": message})
            self.save()
        self.console.agent(who, "note: " + message)
        return {"accepted": True}

    # -- hypotheses (the reasoning ledger) -------------------------------------
    def add_hypothesis(self, who: str, statement: str, surface: str = "") -> dict:
        if not isinstance(statement, str) or not 4 <= len(statement) <= 1000:
            return {"error": "statement must be 4..1000 chars"}
        with self._lock:
            if len(self.hypotheses) >= 120:
                return {"error": "hypothesis budget exhausted"}
            hid = f"H{len(self.hypotheses) + 1:03d}"
            self.hypotheses.append({"id": hid, "statement": statement[:1000],
                                    "surface": str(surface)[:120], "status": "proposed",
                                    "note": "", "evidence_ids": [], "by": who})
            self.save()
        self.console.event("HYPOTHESIS", hid, status="proposed", statement=statement[:100])
        return {"accepted": True, "id": hid}

    def update_hypothesis(self, args: dict) -> dict:
        hyp = next((h for h in self.hypotheses if h["id"] == args.get("id")), None)
        status = args.get("status")
        if hyp is None or status not in ("proposed", "testing", "confirmed", "refuted"):
            return {"error": "provide an existing hypothesis id and status "
                    "(proposed|testing|confirmed|refuted)"}
        with self._lock:
            hyp["status"] = status
            if isinstance(args.get("note"), str):
                hyp["note"] = args["note"][:1000]
            eid = args.get("evidence_id")
            if isinstance(eid, str) and eid and eid not in hyp["evidence_ids"]:
                hyp["evidence_ids"].append(eid)
            self.save()
        self.console.event("HYPOTHESIS", hyp["id"], status=status)
        return {"accepted": True, "id": hyp["id"], "status": status}

    def record_plan(self, args: dict) -> dict:
        plan = {k: args.get(k) for k in ("objective", "surfaces", "waves", "stop_criteria") if k in args}
        if not plan:
            return {"error": "provide at least objective/surfaces/waves/stop_criteria"}
        with self._lock:
            self.plan = {**self.plan, **plan, "revised": self.plan.get("revised", 0) + 1}
            self.save()
        self.console.event("PLAN", "recorded", revision=self.plan["revised"])
        return {"accepted": True, "revision": self.plan["revised"]}

    def import_worker(self, worker_result: dict, *, focus: str) -> int:
        """Re-ground a worker's findings in this store: import its evidence, remap ids, revalidate."""
        remap = {}
        for item in worker_result.get("evidence", []) or []:
            if isinstance(item, dict) and "id" in item:
                remap[item["id"]] = self.add_evidence(
                    item.get("source", f"worker:{focus}"), item.get("payload"), task=focus)
        imported = 0
        for finding in worker_result.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            entry = dict(finding)
            entry["evidence_id"] = remap.get(finding.get("evidence_id"), finding.get("evidence_id"))
            if self.record_finding(entry, who=f"worker:{focus}").get("accepted"):
                imported += 1
        for message in worker_result.get("notes", []) or []:
            self.note(f"worker:{focus}", str(message)[:2000])
        return imported

    # -- persistence -----------------------------------------------------------
    def save(self):
        for name, data in (("findings", self.findings), ("notes", self.notes),
                           ("hypotheses", self.hypotheses), ("plan", self.plan)):
            (self.run_root / f"{name}.json").write_text(
                json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")

    # -- common tool surface ---------------------------------------------------
    def common_tools(self, who: str) -> dict:
        return {
            "run": (RUN_SCHEMA, self.runner.run),
            "cve_lookup": (CVE_SCHEMA, lambda a: self._cve(a)),
            "add_evidence": (schema(
                "Save an observation as a numbered evidence item you can cite in findings.",
                {"source": STRING, "data": {"description": "JSON observation (tool output, response, etc.)"}},
                ("source", "data")),
                lambda a: {"evidence_id": self.add_evidence(a.get("source", "note"), a.get("data")),
                           "accepted": True}),
            "read_evidence": (schema("Read a saved evidence item in bounded pages to quote it exactly.",
                {"evidence_id": STRING, "offset": {"type": "integer"}}, ("evidence_id",)),
                lambda a: self.evidence.read(a.get("evidence_id"), a.get("offset", 0))),
            "list_evidence": (schema("List saved evidence items with their ids and sizes."),
                lambda _: {"evidence": self.evidence.index()}),
            "record_finding": (FINDING_SCHEMA, lambda a: self.record_finding(a, who=who)),
            "list_findings": (schema("List findings recorded so far."),
                lambda _: {"findings": [{k: f[k] for k in ("id", "title", "severity", "verification")}
                                        for f in self.findings]}),
            "note": (schema("Record a short note/observation for the report and peers.",
                {"message": STRING}, ("message",)), lambda a: self.note(who, a.get("message", ""))),
            "add_hypothesis": (schema(
                "Propose a testable hypothesis about the target (an attack idea or weakness to check). "
                "Track it, then test it deliberately instead of scanning blindly.",
                {"statement": STRING, "surface": STRING}, ("statement",)),
                lambda a: self.add_hypothesis(who, a.get("statement", ""), a.get("surface", ""))),
            "update_hypothesis": (schema(
                "Advance a hypothesis: proposed -> testing -> confirmed|refuted, with a note and the "
                "evidence_id that decided it. A confirmed hypothesis usually becomes a finding.",
                {"id": STRING, "status": {"type": "string",
                 "enum": ["proposed", "testing", "confirmed", "refuted"]},
                 "note": STRING, "evidence_id": STRING}, ("id", "status")), self.update_hypothesis),
            "list_hypotheses": (schema("List the hypothesis ledger with statuses."),
                lambda _: {"hypotheses": self.hypotheses}),
            "playbook": (schema(
                "Get a concrete testing playbook for a detected technology/surface "
                "(e.g. wordpress, react-spa, graphql, rest-api, oauth, s3, tls, headers).",
                {"name": STRING}, ("name",)),
                lambda a: {"name": a.get("name"), "playbook": playbooks.get(a.get("name", "")),
                           "available": playbooks.names()}),
        }

    def _cve(self, args: dict) -> dict:
        packages = args.get("packages")
        if not isinstance(packages, list) or not packages:
            return {"error": "provide packages: [{name, version, ecosystem?}] from evidence"}
        try:
            result = intel.lookup([{"ecosystem": str(p.get("ecosystem", "")),
                                    "name": str(p["name"]), "version": str(p["version"])}
                                   for p in packages if isinstance(p, dict) and p.get("name") and p.get("version")])
        except (ValueError, KeyError) as exc:
            return {"error": str(exc)}
        eid = self.add_evidence("cve_lookup", result)
        return {"evidence_id": eid, "kev_hits": result["kev_hits"],
                "advisories": result["advisories"], "prioritized": result["prioritized"][:20],
                "note": "Cite this evidence_id when recording a CVE finding. KEV first, then EPSS."}
