"""Offline coverage of the audit logic: scope, grounding, the agent loop, worker import,
verification and reporting — all driven by a scripted fake model, with no network or tools run."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib import report
from lib.agent import AuditState
from lib.console import Console
from lib.evidence import Evidence, validate_finding
from lib.target import assert_in_scope, target_url
from lib.verify import run_verifier
from lib.worker import run_worker


class FakeClient:
    """Pops scripted assistant messages in order. Shared across nested agent loops."""

    def __init__(self, script):
        self.script = list(script)
        self.usage = {"total_tokens": 0}
        self.models = {"fast": "fake", "strong": "fake"}

    def complete(self, messages, tools=None, *, tier="fast"):
        if not self.script:
            return {"role": "assistant", "content": "done"}
        return self.script.pop(0)


def call(name, **args):
    return {"role": "assistant", "tool_calls": [
        {"id": f"c_{name}", "function": {"name": name, "arguments": json.dumps(args)}}]}


class TargetScope(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(target_url("example.com"), "https://example.com/")
        for bad in ("http://user:pw@x.com", "https://x.com/?q=1", "not a host"):
            with self.assertRaises(ValueError):
                target_url(bad)

    def test_scope(self):
        self.assertEqual(assert_in_scope("api.example.com", "https://example.com"), "api.example.com")
        with self.assertRaises(ValueError):
            assert_in_scope("evil.com", "https://example.com")

    def test_scope_widens_subdomain_target_to_root_and_siblings(self):
        # Given a subdomain as the target, the root domain and sibling subdomains are in scope too.
        self.assertEqual(assert_in_scope("example.com", "https://shop.example.com"), "example.com")
        self.assertEqual(assert_in_scope("api.example.com", "https://shop.example.com"), "api.example.com")
        with self.assertRaises(ValueError):
            assert_in_scope("evil.com", "https://shop.example.com")

    def test_registrable_domain_handles_multi_label_suffixes(self):
        from lib.target import registrable_domain
        self.assertEqual(registrable_domain("shop.example.com"), "example.com")
        self.assertEqual(registrable_domain("example.com"), "example.com")
        self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("203.0.113.5"), "203.0.113.5")


class Grounding(unittest.TestCase):
    def setUp(self):
        self.ev = Evidence(Path(tempfile.mkdtemp()))
        self.eid = self.ev.add("whatweb", {"server": "nginx/1.18.0"})

    def test_accepts_exact_quote(self):
        rec = validate_finding({"title": "t", "summary": "s", "remediation": "r",
                                "evidence_id": self.eid, "quote": "nginx/1.18.0",
                                "severity": "medium"}, self.ev)
        self.assertEqual(rec["verification"], "unreviewed")

    def test_rejects_absent_quote(self):
        with self.assertRaises(ValueError):
            validate_finding({"title": "t", "summary": "s", "remediation": "r",
                              "evidence_id": self.eid, "quote": "apache/2.4",
                              "severity": "medium"}, self.ev)

    def test_rejects_bad_severity(self):
        with self.assertRaises(ValueError):
            validate_finding({"title": "t", "summary": "s", "remediation": "r",
                              "evidence_id": self.eid, "quote": "nginx/1.18.0",
                              "severity": "apocalyptic"}, self.ev)

    def test_accepts_grounded_poc(self):
        poc_eid = self.ev.add("run:curl", {"stdout": "X-Reflected: <script>alert(1)</script>"})
        rec = validate_finding({"title": "t", "summary": "s", "remediation": "r",
                                "evidence_id": self.eid, "quote": "nginx/1.18.0", "severity": "medium",
                                "reproduction": "curl with payload", "poc_evidence_id": poc_eid,
                                "poc_quote": "X-Reflected: <script>alert(1)</script>"}, self.ev)
        self.assertTrue(rec["poc_verified"])
        self.assertEqual(rec["poc_evidence_id"], poc_eid)

    def test_rejects_ungrounded_poc_quote(self):
        poc_eid = self.ev.add("run:curl", {"stdout": "HTTP/1.1 200 OK"})
        with self.assertRaises(ValueError):
            validate_finding({"title": "t", "summary": "s", "remediation": "r",
                              "evidence_id": self.eid, "quote": "nginx/1.18.0", "severity": "medium",
                              "poc_evidence_id": poc_eid, "poc_quote": "not present anywhere"}, self.ev)

    def test_rejects_partial_poc_fields(self):
        with self.assertRaises(ValueError):
            validate_finding({"title": "t", "summary": "s", "remediation": "r",
                              "evidence_id": self.eid, "quote": "nginx/1.18.0", "severity": "medium",
                              "poc_evidence_id": "e001"}, self.ev)

    def test_unverified_reproduction_flagged(self):
        rec = validate_finding({"title": "t", "summary": "s", "remediation": "r",
                                "evidence_id": self.eid, "quote": "nginx/1.18.0", "severity": "medium",
                                "reproduction": "did it manually"}, self.ev)
        self.assertFalse(rec["poc_verified"])


def make_worker_result():
    script = [
        call("add_evidence", source="headers", data={"server": "nginx/1.18.0"}),
        call("record_finding", title="Outdated nginx", summary="old", remediation="upgrade",
             severity="high", evidence_id="e001", quote="nginx/1.18.0", cve="CVE-2021-23017", kev=True),
        call("complete_session", summary="Fingerprinted nginx 1.18.0 and flagged a KEV CVE."),
    ]
    root = Path(tempfile.mkdtemp()) / "worker-w1"
    root.mkdir(parents=True)
    return run_worker(target="https://example.com/", task="fingerprint", focus="fp",
                      run_root=root, client=FakeClient(script), console=Console())


class WorkerRun(unittest.TestCase):
    def test_worker_records_and_exports(self):
        result = make_worker_result()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(len(result["evidence"]), 1)
        self.assertEqual(result["evidence"][0]["id"], result["findings"][0]["evidence_id"])


class SupervisorImportAndVerify(unittest.TestCase):
    def test_import_reground_then_verify_reject(self):
        worker_result = make_worker_result()
        root = Path(tempfile.mkdtemp()) / "audit-1"
        root.mkdir(parents=True)
        state = AuditState("https://example.com/", root, Console())
        imported = state.import_worker(worker_result, focus="fp")
        self.assertEqual(imported, 1)
        # re-grounding: the imported finding's quote must exist in the supervisor's own store
        f = state.findings[0]
        self.assertTrue(state.evidence.ground(f["evidence_id"], f["quote"]))

        verifier = FakeClient([
            call("review_finding", id="F001", verdict="rejected", reason="distro backport; not vulnerable"),
            call("complete_session"),
        ])
        summary = run_verifier(state, verifier, log=lambda _: None)
        self.assertEqual(summary["verdicts"]["rejected"], 1)
        self.assertEqual(state.findings[0]["verification"], "rejected")

    def test_unreached_finding_marked_manual(self):
        worker_result = make_worker_result()
        root = Path(tempfile.mkdtemp()) / "audit-2"
        root.mkdir(parents=True)
        state = AuditState("https://example.com/", root, Console())
        state.import_worker(worker_result, focus="fp")
        # verifier completes without reviewing → the finding must not be silently trusted
        verifier = FakeClient([call("complete_session")])
        run_verifier(state, verifier, log=lambda _: None)
        self.assertEqual(state.findings[0]["verification"], "needs_manual_review")


class ConcurrentToolCalls(unittest.TestCase):
    def test_batch_executes_all_in_order(self):
        from lib.llm import agent_loop
        seen = []
        multi = {"role": "assistant", "tool_calls": [
            {"id": "a1", "function": {"name": "add", "arguments": json.dumps({"x": 1})}},
            {"id": "a2", "function": {"name": "add", "arguments": json.dumps({"x": 2})}},
            {"id": "a3", "function": {"name": "add", "arguments": json.dumps({"x": 3})}}]}
        done = {"role": "assistant", "tool_calls": [
            {"id": "d", "function": {"name": "done", "arguments": "{}"}}]}
        tools = {
            "add": ({"description": "", "parameters": {"type": "object", "properties": {}}},
                    lambda a: seen.append(a["x"]) or {"ok": a["x"]}),
            "done": ({"description": "", "parameters": {"type": "object", "properties": {}}},
                     lambda _: {"accepted": True}),
        }
        out = agent_loop(FakeClient([multi, done]), "s", "t", tools, terminal_tools=("done",))
        self.assertEqual(out["stopped"], "done")
        self.assertEqual(sorted(seen), [1, 2, 3])  # every batched call ran


class AsyncDispatcher(unittest.TestCase):
    def test_spawn_then_gather(self):
        from lib.dispatch import Dispatcher
        d = Dispatcher(repo="o/r", ref="main", target="https://example.com/",
                       run_root=Path(tempfile.mkdtemp()), console=Console(), sleep=lambda _: None)

        def fake_bg(task_id, task, focus):  # stand in for the gh dispatch/watch/collect
            d.results[task_id] = {"status": "ok", "focus": focus, "findings": [],
                                  "evidence": [], "notes": [f"did {focus}"]}
            d.records[task_id]["status"] = "ok"
        d._run_bg = fake_bg
        a = d.spawn({"focus": "recon", "task": "enumerate"})
        b = d.spawn({"focus": "tls", "task": "check tls"})
        self.assertEqual(a["status"], "running")
        result = d.gather({})
        self.assertEqual(set(result["gathered"]), {a["task_id"], b["task_id"]})
        self.assertEqual(result["gathered"][a["task_id"]]["status"], "ok")


class HypothesesAndPlaybooks(unittest.TestCase):
    def test_ledger_and_plan(self):
        state = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console())
        hid = state.add_hypothesis("supervisor", "API allows IDOR on /users/{id}", "rest-api")["id"]
        state.update_hypothesis({"id": hid, "status": "confirmed", "note": "reproduced",
                                 "evidence_id": "e001"})
        self.assertEqual(state.hypotheses[0]["status"], "confirmed")
        self.assertIn("e001", state.hypotheses[0]["evidence_ids"])
        state.record_plan({"objective": "audit", "surfaces": ["a.example.com"],
                           "waves": ["recon", "deep"], "stop_criteria": "dry"})
        self.assertEqual(state.plan["revised"], 1)

    def test_playbook_lookup(self):
        from lib import playbooks
        self.assertIn("wpscan", playbooks.get("wordpress"))
        self.assertIn("SPA", playbooks.get("react"))          # alias react -> react-spa
        self.assertIn("Available", playbooks.get("nonexistent"))

    def test_safe_poc_recipes(self):
        from lib import playbooks
        self.assertIn("poc", playbooks.names())
        for name in ("sql-injection", "xss", "ssrf", "idor", "command-injection",
                     "path-traversal", "deserialization", "secrets-exposure",
                     "log4shell", "ssti", "xxe", "ldap-injection", "jwt"):
            self.assertIn(name, playbooks.names())
            recipe = playbooks.get(name).lower()
            self.assertTrue("never" in recipe or "don't" in recipe or "do not" in recipe)
        self.assertIn("SLEEP(5)", playbooks.get("sqli"))              # alias -> sql-injection
        self.assertIn("reverse shell", playbooks.get("rce").lower())  # alias -> command-injection
        self.assertIn("Read, don't write", playbooks.get("safe-poc"))  # alias -> poc
        self.assertIn("collaborator", playbooks.get("log4j").lower())  # alias -> log4shell

    def test_system_playbooks(self):
        from lib import playbooks
        for name in ("apache-tomcat", "jenkins", "elastic", "exposed-databases",
                     "container-orchestration", "atlassian", "spring", "grafana", "php"):
            self.assertIn(name, playbooks.names())
        self.assertIn("manager", playbooks.get("tomcat").lower())        # alias -> apache-tomcat
        self.assertIn("actuator", playbooks.get("spring-boot").lower())  # alias -> spring
        self.assertIn("redis", playbooks.get("exposed-databases").lower())


class ResourceInventory(unittest.TestCase):
    def test_add_update_dedupe(self):
        state = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console())
        rid = state.add_resource("supervisor", "subdomain", "api.example.com")["id"]
        dup = state.add_resource("supervisor", "subdomain", "api.example.com")
        self.assertTrue(dup["duplicate"])
        state.update_resource({"id": rid, "status": "tested", "evidence_id": "e001"})
        self.assertEqual(state.resources[0]["status"], "tested")
        self.assertIn("e001", state.resources[0]["evidence_ids"])

    def test_import_from_worker(self):
        state = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console())
        imported = state.import_worker({"status": "ok", "findings": [], "resources": [
            {"kind": "endpoint", "name": "/admin", "status": "tested", "detail": "checked auth"}]},
            focus="content")
        self.assertEqual(imported, 0)
        self.assertEqual(len(state.resources), 1)
        self.assertEqual(state.resources[0]["status"], "tested")


class DangerousMode(unittest.TestCase):
    def test_tools_only_exposed_when_dangerous(self):
        safe = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console())
        self.assertNotIn("begin_mutation", safe.common_tools("supervisor"))
        dangerous = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console(), dangerous=True)
        tools = dangerous.common_tools("supervisor")
        self.assertIn("begin_mutation", tools)
        self.assertIn("confirm_revert", tools)
        self.assertIn("list_mutations", tools)

    def test_finding_rejects_unreverted_mutation(self):
        state = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console(), dangerous=True)
        eid = state.add_evidence("probe", {"before": "0"})
        mid = state.begin_mutation("supervisor", "flip debug flag to true",
                                   "flip debug flag back to false")["id"]
        result = state.record_finding({"title": "t", "summary": "s", "remediation": "r",
                                       "evidence_id": eid, "quote": '"before": "0"',
                                       "severity": "medium", "mutation_id": mid}, who="supervisor")
        self.assertIn("error", result)

        proof_eid = state.add_evidence("probe", {"after": "reverted"})
        confirm = state.confirm_revert({"id": mid, "evidence_id": proof_eid})
        self.assertEqual(confirm["status"], "reverted")

        result2 = state.record_finding({"title": "t", "summary": "s", "remediation": "r",
                                        "evidence_id": eid, "quote": '"before": "0"',
                                        "severity": "medium", "mutation_id": mid}, who="supervisor")
        self.assertTrue(result2["accepted"])
        self.assertEqual(state.findings[0]["mutation_id"], mid)

    def test_failed_revert_tracked_as_critical(self):
        state = AuditState("https://example.com/", Path(tempfile.mkdtemp()), Console(), dangerous=True)
        mid = state.begin_mutation("supervisor", "create test user", "delete test user")["id"]
        eid = state.add_evidence("probe", {"delete_attempt": "failed: 500"})
        state.confirm_revert({"id": mid, "evidence_id": eid, "success": False,
                              "note": "delete endpoint returned 500; user 'qa_test_42' still exists"})
        self.assertEqual(state.mutations[0]["status"], "revert_failed")
        self.assertEqual(state.pending_mutations(), [])  # resolved (as failed), not stuck pending

    def test_worker_blocks_completion_until_reverted(self):
        script = [
            call("begin_mutation", description="create a test record via the API",
                 revert_plan="DELETE the created record by id"),
            call("complete_session", summary="done"),  # should be rejected: still pending_revert
            call("add_evidence", source="api", data={"deleted": True, "id": 42}),
            call("confirm_revert", id="M001", evidence_id="e001"),
            call("complete_session", summary="created and reverted a test record to confirm IDOR"),
        ]
        root = Path(tempfile.mkdtemp()) / "worker-dangerous"
        root.mkdir(parents=True)
        result = run_worker(target="https://example.com/", task="confirm idor", focus="idor",
                            run_root=root, client=FakeClient(script), console=Console(), dangerous=True)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["mutations"]), 1)
        self.assertEqual(result["mutations"][0]["status"], "reverted")


class Reporting(unittest.TestCase):
    def test_escapes_and_prioritizes(self):
        result = {
            "target": "https://example.com/", "run_id": "audit-1", "status": "complete",
            "summary": "s", "limitations": "l", "evidence_count": 3, "usage": {}, "agent": {},
            "workers": [], "rejected": [],
            "findings": [
                {"id": "F001", "title": "b <script>", "severity": "low", "verification": "supported",
                 "evidence_id": "e2", "quote": "x", "summary": "s", "remediation": "r"},
                {"id": "F002", "title": "a", "severity": "critical", "verification": "supported",
                 "evidence_id": "e1", "quote": "y", "summary": "s", "remediation": "r", "kev": True,
                 "reproduction": "curl ...", "poc_evidence_id": "e3", "poc_quote": "pwned",
                 "poc_verified": True},
            ],
            "resources": [{"id": "R001", "kind": "subdomain", "name": "api.example.com",
                          "status": "tested", "detail": ""}],
        }
        html = report.html_page(result)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html.split("<title>")[1])
        self.assertIn("Resources audited", html)
        self.assertIn("PoC verified", html)
        md = report.markdown(result)
        self.assertIn("KEV", md)
        self.assertIn("Resources audited", md)
        self.assertIn("PoC verified", md)
        self.assertIn("PoC output", md)

    def test_dangerous_mode_and_unresolved_mutation_banner(self):
        result = {
            "target": "https://example.com/", "run_id": "audit-2", "status": "complete",
            "dangerous": True, "summary": "s", "limitations": "l", "evidence_count": 1,
            "usage": {}, "agent": {}, "workers": [], "rejected": [], "findings": [],
            "mutations": [{"id": "M001", "description": "created a test user",
                          "revert_plan": "delete the test user", "status": "revert_failed",
                          "note": "delete endpoint returned 500"}],
        }
        md = report.markdown(result)
        self.assertIn("DANGEROUS MODE", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("State changes", md)
        self.assertIn("revert_failed", md)
        html = report.html_page(result)
        self.assertIn("DANGEROUS MODE", html)
        self.assertIn("CRITICAL", html)
        self.assertIn("State changes", html)


if __name__ == "__main__":
    unittest.main()
