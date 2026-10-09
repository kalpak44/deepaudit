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
    "reproduction": {"type": "string", "description": "Human-readable repro narrative/steps. "
        "Unverified prose unless poc_evidence_id/poc_quote are also given."},
    "poc_evidence_id": {"type": "string", "description": "Id of the evidence item holding the "
        "RAW captured output of actually executing the reproduction via `run` (not a description "
        "of it). Required, with poc_quote, for a PoC to show as verified in the report."},
    "poc_quote": {"type": "string", "description": "Exact 8..2000 char excerpt of poc_evidence_id "
        "proving the PoC ran and what it returned (e.g. the reflected payload, leaked value, "
        "command output)."},
    "mutation_id": {"type": "string", "description": "Dangerous mode only: id from begin_mutation "
        "if this PoC required a state-changing action. Only accepted once confirm_revert has "
        "marked that mutation 'reverted'."}},
    "required": ["title", "summary", "remediation", "severity", "evidence_id", "quote"]}

FINDING_SCHEMA = schema("Record one confirmed, evidence-grounded finding. For exploitable "
                        "findings, actually run the non-destructive PoC via `run`, save its raw "
                        "output with `add_evidence`, and cite it as poc_evidence_id/poc_quote — "
                        "a narrated `reproduction` alone is reported as unverified.",
                        FINDING["properties"], FINDING["required"])

RESOURCE_STATUSES = ("discovered", "testing", "tested", "skipped")
MUTATION_STATUSES = ("pending_revert", "reverted", "revert_failed")


class AuditState:
    """Everything a running audit accumulates. Thread-safe for parallel fan-out."""

    def __init__(self, target: str, run_root: Path, console, *, dangerous: bool = False):
        self.target = target
        self.run_root = run_root
        self.console = console
        self.dangerous = dangerous
        self.evidence = Evidence(run_root)
        self.runner = Runner(target, console)
        self.findings: list[dict] = []
        self.notes: list[dict] = []
        self.hypotheses: list[dict] = []
        self.resources: list[dict] = []
        self.mutations: list[dict] = []
        self.plan: dict = {}
        self._lock = threading.RLock()

    # -- evidence & findings ---------------------------------------------------
    def add_evidence(self, source: str, payload, *, task="") -> str:
        return self.evidence.add(source, payload, task=task)

    def record_finding(self, entry: dict, *, who: str) -> dict:
        mutation_id = entry.get("mutation_id")
        if mutation_id is not None:
            mutation = next((m for m in self.mutations if m["id"] == mutation_id), None)
            if mutation is None or mutation["status"] != "reverted":
                return {"error": "mutation_id must reference a mutation already confirm_reverted "
                        "(status=reverted) — revert the state change before citing it on a finding"}
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
            if mutation_id:
                record["mutation_id"] = mutation_id
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

    # -- resource inventory (what was actually found and covered) --------------
    def add_resource(self, who: str, kind: str, name: str, *, detail: str = "") -> dict:
        if not isinstance(kind, str) or not kind.strip() or not isinstance(name, str) or not name.strip():
            return {"error": "kind and name are required (e.g. kind=subdomain, name=api.example.com)"}
        with self._lock:
            if len(self.resources) >= 500:
                return {"error": "resource budget exhausted"}
            duplicate = next((r for r in self.resources
                              if r["kind"] == kind.strip()[:60] and r["name"] == name.strip()[:300]), None)
            if duplicate:
                return {"accepted": True, "id": duplicate["id"], "duplicate": True}
            rid = f"R{len(self.resources) + 1:03d}"
            self.resources.append({"id": rid, "kind": kind.strip()[:60], "name": name.strip()[:300],
                                   "status": "discovered", "detail": str(detail)[:500],
                                   "evidence_ids": [], "by": who})
            self.save()
        self.console.event("RESOURCE", rid, resource_kind=kind[:60], name=name[:120])
        return {"accepted": True, "id": rid}

    def update_resource(self, args: dict) -> dict:
        res = next((r for r in self.resources if r["id"] == args.get("id")), None)
        status = args.get("status")
        if res is None or status not in RESOURCE_STATUSES:
            return {"error": f"provide an existing resource id and status {RESOURCE_STATUSES}"}
        with self._lock:
            res["status"] = status
            if isinstance(args.get("detail"), str):
                res["detail"] = args["detail"][:500]
            eid = args.get("evidence_id")
            if isinstance(eid, str) and eid and eid not in res["evidence_ids"]:
                res["evidence_ids"].append(eid)
            self.save()
        self.console.event("RESOURCE", res["id"], status=status)
        return {"accepted": True, "id": res["id"], "status": status}

    # -- mutations (dangerous-mode state changes, must be declared and reverted) -
    def begin_mutation(self, who: str, description: str, revert_plan: str) -> dict:
        if not isinstance(description, str) or not 4 <= len(description) <= 1000:
            return {"error": "description must be 4..1000 chars: exactly what you are about to change"}
        if not isinstance(revert_plan, str) or not 4 <= len(revert_plan) <= 1000:
            return {"error": "revert_plan must be 4..1000 chars: exactly how you will undo it"}
        with self._lock:
            if len(self.mutations) >= 50:
                return {"error": "mutation budget exhausted"}
            mid = f"M{len(self.mutations) + 1:03d}"
            self.mutations.append({"id": mid, "description": description.strip()[:1000],
                                   "revert_plan": revert_plan.strip()[:1000], "status": "pending_revert",
                                   "revert_evidence_id": None, "note": "", "by": who})
            self.save()
        self.console.event("MUTATION", mid, status="pending_revert")
        return {"accepted": True, "id": mid,
                "note": "Make the minimal change now, add_evidence proof it worked, revert it "
                        "immediately, then call confirm_revert with evidence of the revert before "
                        "you can cite this mutation_id on a finding or finish/complete_session."}

    def confirm_revert(self, args: dict) -> dict:
        mutation = next((m for m in self.mutations if m["id"] == args.get("id")), None)
        if mutation is None:
            return {"error": "unknown mutation id"}
        evidence_id = args.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            return {"error": "evidence_id is required: proof the revert actually happened, not "
                    "just a claim that it did"}
        success = args.get("success", True) is not False
        with self._lock:
            mutation["revert_evidence_id"] = evidence_id
            mutation["status"] = "reverted" if success else "revert_failed"
            if isinstance(args.get("note"), str):
                mutation["note"] = args["note"][:1000]
            self.save()
        self.console.event("MUTATION", mutation["id"], status=mutation["status"])
        return {"accepted": True, "id": mutation["id"], "status": mutation["status"]}

    def pending_mutations(self) -> list[str]:
        return [m["id"] for m in self.mutations if m["status"] == "pending_revert"]

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
        mutation_remap = {}
        for m in worker_result.get("mutations", []) or []:
            if isinstance(m, dict) and m.get("id"):
                with self._lock:
                    new_id = f"M{len(self.mutations) + 1:03d}"
                    self.mutations.append({**m, "id": new_id, "by": m.get("by", f"worker:{focus}")})
                    self.save()
                mutation_remap[m["id"]] = new_id
        imported = 0
        for finding in worker_result.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            entry = dict(finding)
            entry["evidence_id"] = remap.get(finding.get("evidence_id"), finding.get("evidence_id"))
            if entry.get("poc_evidence_id"):
                entry["poc_evidence_id"] = remap.get(entry["poc_evidence_id"], entry["poc_evidence_id"])
            if entry.get("mutation_id"):
                entry["mutation_id"] = mutation_remap.get(entry["mutation_id"], entry["mutation_id"])
            if self.record_finding(entry, who=f"worker:{focus}").get("accepted"):
                imported += 1
        for message in worker_result.get("notes", []) or []:
            self.note(f"worker:{focus}", str(message)[:2000])
        for res in worker_result.get("resources", []) or []:
            if isinstance(res, dict) and res.get("kind") and res.get("name"):
                imported_id = self.add_resource(f"worker:{focus}", str(res["kind"]), str(res["name"]),
                                                detail=str(res.get("detail", ""))).get("id")
                if imported_id and res.get("status") in RESOURCE_STATUSES and res["status"] != "discovered":
                    self.update_resource({"id": imported_id, "status": res["status"]})
        return imported

    # -- persistence -----------------------------------------------------------
    def save(self):
        for name, data in (("findings", self.findings), ("notes", self.notes),
                           ("hypotheses", self.hypotheses), ("resources", self.resources),
                           ("mutations", self.mutations), ("plan", self.plan)):
            (self.run_root / f"{name}.json").write_text(
                json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")

    # -- common tool surface ---------------------------------------------------
    def common_tools(self, who: str) -> dict:
        tools = {
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
            "add_resource": (schema(
                "Register a discovered asset in the resource inventory (subdomain, endpoint, "
                "service, open port, technology/CMS, API route, file, etc.). Do this as you find "
                "things during recon/content-discovery, BEFORE you decide whether to test them — "
                "it is how coverage gets tracked and reported, independent of whether a finding "
                "ever comes from it.",
                {"kind": STRING, "name": STRING, "detail": STRING}, ("kind", "name")),
                lambda a: self.add_resource(who, a.get("kind", ""), a.get("name", ""), detail=a.get("detail", ""))),
            "update_resource": (schema(
                "Advance a resource's status as you cover it: discovered -> testing -> "
                "tested|skipped. Attach the evidence_id that shows what you did with it.",
                {"id": STRING, "status": {"type": "string", "enum": list(RESOURCE_STATUSES)},
                 "detail": STRING, "evidence_id": STRING}, ("id", "status")), self.update_resource),
            "list_resources": (schema("List the resource inventory with coverage status."),
                lambda _: {"resources": self.resources}),
            "playbook": (schema(
                "Get a concrete testing playbook: either for a detected technology/system "
                "(e.g. wordpress, react-spa, graphql, rest-api, oauth, s3, tls, headers, "
                "apache-tomcat, jenkins, elastic, exposed-databases, container-orchestration, "
                "atlassian, spring, grafana, php), or a safe non-destructive PoC recipe for a "
                "vuln class/CVE you're hypothesizing about (e.g. poc, sql-injection, xss, ssrf, "
                "idor, command-injection, path-traversal, deserialization, secrets-exposure, "
                "log4shell, ssti, xxe, ldap-injection, jwt). The response includes the full "
                "`available` list — call with any name (or an unknown one) to see it. Always "
                "call the matching vuln-class one before you execute a PoC, to confirm impact "
                "the safe way.",
                {"name": STRING}, ("name",)),
                lambda a: {"name": a.get("name"), "playbook": playbooks.get(a.get("name", "")),
                           "available": playbooks.names()}),
        }
        if self.dangerous:
            tools.update({
                "begin_mutation": (schema(
                    "DANGEROUS MODE: declare a state-changing action you are about to take "
                    "against the target, and exactly how you will undo it, BEFORE you do it. "
                    "Required before any such change; a finding may not cite it until reverted.",
                    {"description": STRING, "revert_plan": STRING},
                    ("description", "revert_plan")),
                    lambda a: self.begin_mutation(who, a.get("description", ""), a.get("revert_plan", ""))),
                "confirm_revert": (schema(
                    "DANGEROUS MODE: confirm a declared mutation has been undone, citing "
                    "evidence that proves it (not just a claim). Pass success=false with a note "
                    "if it could not be fully reverted — reported as a critical unresolved item.",
                    {"id": STRING, "evidence_id": STRING,
                     "success": {"type": "boolean", "default": True}, "note": STRING},
                    ("id", "evidence_id")), self.confirm_revert),
                "list_mutations": (schema("List declared state changes and their revert status."),
                    lambda _: {"mutations": self.mutations}),
            })
        return tools

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
