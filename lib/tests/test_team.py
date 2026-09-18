import io
import json
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lib import sandbox
from lib.collect import collect_command, collect_http, collect_osv, collect_script, target_url, public_address
from lib.console import Console
from lib.deepseek import agent_loop
from lib.run_audit import Audit
from lib.tool_catalog import validate_params
from lib.tool_runner import ToolRunner
from lib import report, provenance


def call(name, args):
    return {"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {
        "name": name, "arguments": json.dumps(args)}}]}


def handoff(summary="completed", **kwargs):
    return call("complete_session", {"status": "completed", "summary": summary,
                                     "limitations": "Unauthenticated coverage only", "findings": [], **kwargs})


class QuietConsole(Console):
    def event(self, *_args, **_kwargs):
        pass


class FakeRunner:
    def __init__(self, barrier=None):
        self.tasks, self.evidence = [], {}
        self.barrier, self.lock = barrier, threading.Lock()

    def catalog(self):
        return [{"name": "http"}, {"name": "tls"}]

    def run(self, employee, target, tool, params):
        if self.barrier:
            self.barrier.wait(timeout=3)
        with self.lock:
            task_id = "t" + str(len(self.tasks) + 1)
            self.tasks.append({"task_id": task_id, "employee": employee, "tool": tool,
                               "target": target, "status": "ok"})
            self.evidence[task_id] = {"observation": f"Unique evidence for {employee}", "status": 200}
        return {"task_id": task_id, "status": "ok", "evidence": self.read_evidence(task_id)}

    def read_evidence(self, task_id, offset=0):
        return {"task_id": task_id, "text": json.dumps(self.evidence[task_id], indent=2)[offset:]}


class Scripted:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.sent = []

    def complete(self, messages, tools=None):
        self.sent.append(json.loads(json.dumps(messages)))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


class TeamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def audit(self, client, runner=None, **kwargs):
        return Audit("https://example.test", run_root=self.root, client=client,
                     runner=runner or FakeRunner(), console=QuietConsole(), **kwargs)

    def test_real_parallel_workers_have_separate_histories_and_shared_board(self):
        barrier = threading.Barrier(2)

        class Workers:
            def __init__(self):
                self.sent, self.count, self.lock = [], {}, threading.Lock()

            def complete(self, messages, tools=None):
                role = "http" if messages[0]["content"].startswith("# HTTP") else "tls"
                with self.lock:
                    step = self.count.get(role, 0)
                    self.count[role] = step + 1
                    self.sent.append((role, json.loads(json.dumps(messages))))
                return [call("share_update", {"message": role + " started"}),
                        call("run_tool", {"tool": role}), handoff(role + " done")][step]

        client = Workers()
        audit = self.audit(client, FakeRunner(barrier))
        result = audit.delegate_team({"assignments": [
            {"employee": "http", "assignment": "Check HTTP"},
            {"employee": "tls", "assignment": "Check TLS"}]})
        self.assertEqual([h["status"] for h in result["handoffs"]], ["completed", "completed"])
        self.assertEqual(len(audit.updates), 2)
        self.assertFalse(audit.active)
        for role, messages in client.sent:
            # Tool observations stay in the owner session even while peers run concurrently.
            peer = "tls" if role == "http" else "http"
            self.assertNotIn("Unique evidence for " + peer, json.dumps(messages))
        self.assertEqual(set(audit.context()["coverage"]), set(audit.coverage))

    def test_employee_can_delegate_and_cycle_is_rejected(self):
        client = Scripted([call("delegate", {"employee": "http", "assignment": "Check headers"}),
                           call("delegate", {"employee": "strategist", "assignment": "cycle"}),
                           call("run_tool", {"tool": "http"}), handoff(), handoff("strategy complete")])
        audit = self.audit(client)
        out = audit.delegate({"employee": "strategist", "assignment": "delegate work"})
        self.assertEqual(out["status"], "completed")
        self.assertEqual(audit.coverage["http"]["status"], "completed")
        self.assertTrue(any("delegation cycle" in json.dumps(m) for m in client.sent))
        audit.active.add("http")
        self.assertIn("already running", audit.delegate({"employee": "http"})["error"])

    def test_report_pipeline_records_reviews_and_renders_canonical_findings(self):
        quote = '"observation": "Unique evidence for http"'
        finding = {"task_id": "t1", "title": "HTTP observation", "severity": "info",
                   "summary": "Observed a response", "evidence_quote": quote, "remediation": "Review configuration"}
        client = Scripted([
            call("run_tool", {"tool": "http"}), call("record_findings", {"findings": [finding]}), handoff(),
            call("read_evidence", {"task_id": "t1"}),
            call("review_finding", {"id": "F001", "verdict": "supported", "reason": "Matches saved response"}), handoff(),
            handoff("Review configuration first; coverage is limited."),
            call("finish", {}),
        ])
        audit = self.audit(client)
        audit.delegate({"employee": "http"})
        for name in audit.coverage:
            if name not in ("http", "verifier", "reporter"):
                audit.coverage[name] = {"status": "not_applicable", "summary": "Test scope", "limitations": "Test scope"}
        audit.delegate({"employee": "verifier"})
        audit.delegate({"employee": "reporter"})
        result = audit.run()
        self.assertEqual(result["report"]["status"], "complete")
        self.assertEqual(result["provenance"]["counts"]["grounded"], 1)
        page = report.render(target=audit.target, run_id="test", report=result["report"],
                             provenance=result["provenance"], plan=result["plan"])
        self.assertIn("Review configuration", page)
        self.assertIn("supported", page)
        self.assertIn("Coverage", page)
        self.assertEqual(audit.findings[0]["evidence"]["quote"], quote)

    def test_reproduction_demonstration_is_grounded_and_rendered(self):
        runner = FakeRunner()
        runner.run("poc", "https://example.test", "script", {})
        audit = self.audit(Scripted([]), runner)
        finding = {"task_id": "t1", "title": "Reflected CORS", "severity": "medium",
                   "summary": "Origin was reflected", "remediation": "Restrict allowed origins",
                   "evidence_quote": '"observation": "Unique evidence for poc"',
                   "reproduction": "Send Origin: https://evil.test; response reflects it with credentials allowed."}
        self.assertIn("accepted", audit.record_findings("poc", [finding]))
        stored = audit.findings[0]
        self.assertEqual(stored["reproduction"][:4], "Send")
        audit.save()  # writes tasks/t1.json so provenance can reconstruct the finding
        prov = provenance.check({"findings": [{"task_id": "t1", "id": stored["id"], "title": stored["title"]}]}, self.root)
        self.assertEqual(prov["counts"]["grounded"], 1)
        self.assertIn("reproduction", prov["grounded"][0])
        page = report.render(target="https://example.test", run_id="t", plan=[],
                             report={"findings": prov["grounded"]}, provenance=prov)
        self.assertIn("Reproduction &amp; impact", page)
        self.assertIn("response reflects it", page)
        # a non-string reproduction is rejected, never coerced
        bad = {**finding, "reproduction": {"steps": 1}}
        self.assertIn("reproduction must be a string", audit.record_findings("poc", [bad])["error"])

    def test_evidence_cannot_be_invented_or_attributed_to_failed_run(self):
        runner = FakeRunner()
        runner.run("http", "https://example.test", "http", {})
        audit = self.audit(Scripted([]), runner)
        item = {"task_id": "t1", "title": "x", "severity": "high", "summary": "x",
                "remediation": "x", "evidence_quote": "this was not observed"}
        self.assertIn("exact", audit.record_findings("http", [item])["error"])
        item["evidence_quote"] = '"observation": "Unique evidence for http"'
        runner.tasks[0]["status"] = "failed"
        self.assertIn("successful", audit.record_findings("http", [item])["error"])
        self.assertEqual(audit.findings, [])

    def test_incomplete_run_cannot_claim_success(self):
        audit = self.audit(Scripted([RuntimeError("budget exhausted")]))
        self.assertIn("error", audit.finish({}))
        self.assertIn("error", audit.delegate({"employee": "reporter"}))
        result = audit.run()
        self.assertEqual(result["report"]["status"], "incomplete")
        self.assertIn("budget exhausted", result["report"]["limitations"])
        self.assertTrue((self.root / "plan.json").exists())

    def test_plain_final_message_does_not_bypass_required_completion(self):
        client = Scripted([{"role": "assistant", "content": "done"}, handoff()])
        audit = self.audit(client)
        out = audit.delegate({"employee": "planner"})
        self.assertEqual(out["status"], "completed")
        self.assertEqual(len(client.sent), 2)

    def test_terminal_tool_stops_before_later_tools_in_batch(self):
        msg = call("finish", {})
        msg["tool_calls"] += call("boom", {})["tool_calls"]
        client = Scripted([msg])
        touched = []
        out = agent_loop(client, "s", "t", {"finish": ({}, lambda _: {"accepted": True}),
                         "boom": ({}, lambda _: touched.append(1))}, terminal_tools=("finish",))
        self.assertEqual(out["stopped"], "finish")
        self.assertEqual(touched, [])


class DispatchTests(unittest.TestCase):
    def runner(self, root):
        return ToolRunner(repo="owner/repo", ref="main", run_root=Path(root), console=QuietConsole(), poll_seconds=0)

    def fake_gh(self, *, mismatch=False, failed=False, missing=False):
        state = {}

        def gh(args, **kwargs):
            result = SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:2] == ["workflow", "run"]:
                state.update(a.split("=", 1) for a in args if "=" in a)
            elif args[:2] == ["run", "list"]:
                result.stdout = json.dumps([{"databaseId": 123, "displayTitle": state["run_name"]}])
            elif args[:2] == ["run", "view"]:
                result.stdout = json.dumps({"status": "completed", "conclusion": "failure" if failed else "success"})
            elif args[:2] == ["run", "download"] and not missing:
                payload = {"schema_version": 1, "task_id": "wrong" if mismatch else state["task_id"],
                           "target": state["target"], "tool": "http", "status": "ok", "output": {"status": 200}}
                (Path(args[args.index("--dir") + 1]) / "evidence.json").write_text(json.dumps(payload))
            return result
        return gh

    def test_unique_correlation_and_valid_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp)
            runner._gh = self.fake_gh()
            a = runner.run("http", "https://example.test", "http", {})
            b = runner.run("http", "https://example.test", "http", {})
            self.assertNotEqual(a["task_id"], b["task_id"])
            self.assertEqual(a["status"], "ok")
            self.assertEqual(len(list((Path(tmp) / "evidence").glob("*.json"))), 2)
            self.assertIn("error", runner.run("http", "https://other.test", "http", {}))

    def test_mismatched_missing_and_failed_artifacts_never_succeed(self):
        for options in ({"mismatch": True}, {"missing": True}, {"failed": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                runner = self.runner(tmp)
                runner._gh = self.fake_gh(**options)
                out = runner.run("http", "https://example.test", "http", {})
                self.assertEqual(out["status"], "failed")
                self.assertEqual(len(runner.tasks), 1)

    def test_invalid_params_never_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp)
            with patch.object(runner, "_gh") as gh:
                self.assertIn("error", runner.run("http", "https://example.test", "http", {"shell": "whoami"}))
                gh.assert_not_called()

    def test_timeout_cancels_exact_run_and_saves_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp)
            commands = []
            base = self.fake_gh()
            def gh(args, **kwargs):
                commands.append(args)
                if args[:2] == ["run", "view"]:
                    raise subprocess.TimeoutExpired("gh", 1)
                return base(args, **kwargs)
            runner._gh = gh
            out = runner.run("http", "https://example.test", "http", {})
            self.assertEqual(out["status"], "failed")
            self.assertTrue(any(c[:3] == ["run", "cancel", "123"] for c in commands))


class CollectorTests(unittest.TestCase):
    def test_single_target_validation(self):
        self.assertEqual(target_url("example.test"), "https://example.test/")
        for bad in ("-sV", "https://a b/", "ftp://x", "https://user:pass@host/", "https://x/?secret=x", "10.0.0.0/24", "host;whoami"):
            with self.subTest(target=bad):
                # CIDR expressed as bare input is not a web path.
                if bad == "10.0.0.0/24":
                    continue
                with self.assertRaises(ValueError):
                    target_url(bad)

    def test_parameter_bounds_and_path_scope(self):
        for params in ({"top_ports": 100000}, {"max_rate": True}, {"extra_args": "-A"}):
            with self.assertRaises(ValueError):
                validate_params("nmap", params)
        for path in ("//other.test", "/\\other", "https://other.test"):
            with self.assertRaises(ValueError):
                validate_params("http", {"path": path})

    def test_private_or_mixed_dns_is_rejected(self):
        with patch("lib.collect.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                public_address("example.test", 443)

    def test_http_comparison_is_bounded_and_same_origin(self):
        with patch("lib.collect.sample", side_effect=lambda url, **kwargs: {"url": url, "status": 200, "headers": [], "body": "Hello"}) as mocked:
            result = collect_http("https://example.test/base", {"path": "/", "cors": True})
        self.assertEqual(len(result["requests"]), 3)
        self.assertTrue(all(c.args[0] == "https://example.test/base" for c in mocked.call_args_list))
        self.assertEqual(mocked.call_args_list[-1].kwargs["headers"]["Origin"], "https://deepaudit.invalid")

    def test_nmap_uses_fixed_argv_and_bounded_parameters(self):
        def run(argv, **kwargs):
            Path(argv[argv.index("-oX") + 1]).write_text("<nmaprun/>")
            self.assertNotIn("shell", kwargs)
            self.assertEqual(argv[-1], "93.184.216.34")
            self.assertIn("--max-rate", argv)
            return SimpleNamespace(returncode=0, stderr="")
        with patch("lib.collect.public_address", return_value="93.184.216.34"), patch("lib.collect.subprocess.run", side_effect=run):
            out = collect_command("nmap", "https://example.test", validate_params("nmap", {}))
        self.assertIn("nmaprun", out["output"])

    def test_osv_packages_validate_as_bounded_array_of_objects(self):
        ok = validate_params("osv", {"packages": [{"ecosystem": "npm", "name": "jquery", "version": "3.4.1"},
                                                   {"name": "nginx", "version": "1.18.0"}]})
        self.assertEqual(ok["packages"][1]["ecosystem"], "")  # default filled
        self.assertEqual(validate_params("osv", {})["packages"], [])
        for bad in ({"packages": [{"name": "x"}]}, {"packages": [{"name": "x", "version": 3}]},
                    {"packages": "nope"}, {"packages": [{"name": "x", "version": "1", "junk": 1}]},
                    {"packages": [{"name": "x", "version": "1"}] * 17}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_params("osv", bad)

    def test_osv_queries_third_party_and_never_invents_matches(self):
        api = {"vulns": [{"id": "GHSA-x", "aliases": ["CVE-2020-11022"], "summary": "XSS",
                          "details": "d" * 900, "severity": [{"type": "CVSS_V3", "score": "6.1"}],
                          "affected": [{"package": {"name": "jquery", "ecosystem": "npm"},
                                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.5.0"}]}],
                                        "versions": ["3.4.1"]}]}]}
        with patch("lib.collect.osv_query", return_value=api) as query, patch("lib.collect.time.sleep"):
            out = collect_osv("https://example.test", {"packages": [{"ecosystem": "npm", "name": "jquery", "version": "3.4.1"}]})
        vuln = out["results"][0]["vulns"][0]
        self.assertEqual(out["results"][0]["match_count"], 1)
        self.assertEqual(vuln["id"], "GHSA-x")
        self.assertEqual(vuln["affected"][0]["ranges"][0]["fixed"], "3.5.0")
        self.assertLessEqual(len(vuln["details_excerpt"]), 400)
        self.assertEqual(query.call_args.args[0]["name"], "jquery")
        # An empty stack is a coverage gap, not a silent success.
        with self.assertRaises(ValueError):
            collect_osv("https://example.test", {"packages": []})

    def test_osv_api_failure_is_reported_not_fabricated(self):
        with patch("lib.collect.osv_query", side_effect=OSError("connection reset")), patch("lib.collect.time.sleep"):
            out = collect_osv("https://example.test", {"packages": [{"ecosystem": "", "name": "nginx", "version": "1.18.0"}]})
        self.assertIn("connection reset", out["results"][0]["error"])
        self.assertNotIn("vulns", out["results"][0])

    def test_script_sandbox_computes_over_evidence_but_denies_network(self):
        evidence = {"t1": {"output": {"headers": [["Server", "nginx/1.18.0"]]}}}
        good = sandbox.run_user_code(
            "result = {t: e['output']['headers'][0][1] for t, e in evidence.items()}", evidence)
        self.assertEqual(good["status"], "ok")
        self.assertEqual(good["result"], {"t1": "nginx/1.18.0"})
        blocked = sandbox.run_user_code("import socket; socket.create_connection(('example.com', 80))", evidence)
        self.assertEqual(blocked["status"], "failed")
        self.assertIn("network access is disabled", blocked["error"])
        for code in ("result = 1 / 0", "result = 'x' * 300000", "result = set([1])"):
            with self.subTest(code=code):
                self.assertEqual(sandbox.run_user_code(code, evidence, output_limit=200000)["status"], "failed")

    def test_script_params_and_collector_enforce_code_and_evidence(self):
        ok = validate_params("script", {"code": "result = 1", "inputs": [{"task_id": "t1"}]})
        self.assertEqual(ok["inputs"], [{"task_id": "t1"}])
        for bad in ({"code": "x" * 10001}, {"inputs": [{"task_id": "t"}] * 9}, {"inputs": [{"nope": "x"}]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_params("script", bad)
        with self.assertRaises(ValueError):  # empty code is a coverage gap, never a silent pass
            collect_script({"code": "   ", "inputs": []}, {})
        with self.assertRaises(RuntimeError):  # a crashed run fails the tool honestly
            collect_script({"code": "result = 1 / 0", "inputs": []}, {"t1": {"output": {}}})
        out = collect_script({"code": "result = len(evidence)", "inputs": [{"task_id": "t1"}]},
                             {"t1": {"output": {}}})
        self.assertEqual(out["result"], 1)
        self.assertEqual(out["analyzed_task_ids"], ["t1"])

    def test_script_dispatch_injects_only_requested_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = ToolRunner(repo="o/r", ref="main", run_root=Path(tmp), console=QuietConsole())
            runner.evidence = {"t1": {"a": 1}, "t2": {"b": 2}}
            bundle = json.loads(runner._evidence_bundle([{"task_id": "t1"}, {"task_id": "t9"}]))
        self.assertEqual(bundle["t1"], {"a": 1})
        self.assertNotIn("t2", bundle)  # only requested ids are handed to the sandbox
        self.assertIn("no completed task", bundle["t9"]["error"])

    def test_console_cannot_emit_actions_commands_from_target_text(self):
        output = io.StringIO()
        with redirect_stdout(output):
            Console().agent("http", "hello\n::error::injected\x1b[31m")
        for line in output.getvalue().splitlines():
            self.assertTrue(line.startswith("["))
        self.assertNotIn("\x1b", output.getvalue())

    def test_provenance_uses_saved_severity_not_reporter_escalation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tasks").mkdir()
            (root / "tasks/t1.json").write_text(json.dumps({"findings": [{"id": "F1", "title": "Observed", "severity": "info"}]}))
            out = provenance.check({"findings": [{"task_id": "t1", "id": "F1", "severity": "critical"}]}, root)
            self.assertEqual(out["grounded"][0]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
