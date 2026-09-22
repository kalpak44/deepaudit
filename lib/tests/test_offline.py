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
                 "evidence_id": "e1", "quote": "y", "summary": "s", "remediation": "r", "kev": True},
            ],
        }
        html = report.html_page(result)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html.split("<title>")[1])
        md = report.markdown(result)
        self.assertIn("KEV", md)


if __name__ == "__main__":
    unittest.main()
