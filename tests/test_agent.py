import unittest
from deepaudit.agent import run_agent, validate_tool_calls
from deepaudit.llm import APIError
from deepaudit.tools import AuditTools
from tests.helpers import FakeLLM, FakeProbes, tool_call


class ToolTests(unittest.TestCase):
    def test_unknown_tool_rejected(self):
        probes = FakeProbes()
        tools = AuditTools(probes)
        self.assertEqual(tools.invoke("run_shell", '{"command":"id"}')["error"], "unknown_tool")
        self.assertEqual(probes.http_calls, 0)

    def test_arguments_cannot_override_scope(self):
        tools = AuditTools(FakeProbes())
        for value in ('{"url":"http://other.test/"}', '[]', 'null', '"x"', '{broken', ' ' * 513):
            with self.subTest(value=value):
                self.assertEqual(tools.invoke("inspect_http", value)["error"], "arguments_must_be_empty_object")
        self.assertEqual(tools.probes.http_calls, 0)

    def test_repeated_calls_use_cached_evidence(self):
        tools = AuditTools(FakeProbes())
        for _ in range(5):
            tools.invoke("inspect_http")
            tools.invoke("verify_findings")
        self.assertEqual(tools.probes.http_calls, 2)
        self.assertEqual(tools.probes.tls_calls, 2)


class AgentTests(unittest.TestCase):
    def test_full_tool_cycle(self):
        client = FakeLLM([
            {"role": "assistant", "content": None, "tool_calls": [tool_call("get_scope")]},
            {"role": "assistant", "content": None, "tool_calls": [tool_call("verify_findings", "call_2")]},
            {"role": "assistant", "content": "Five observations; no exploits demonstrated."},
        ])
        tools = AuditTools(FakeProbes())
        result = run_agent(tools, client)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["fallback_used"])
        self.assertEqual(client.history[1][-1]["tool_call_id"], "call_1")
        self.assertEqual(client.history[2][-1]["tool_call_id"], "call_2")
        self.assertEqual(len(tools.findings), 5)

    def test_early_stop_completes_baseline(self):
        client = FakeLLM([{"role": "assistant", "content": "Done"}])
        tools = AuditTools(FakeProbes())
        self.assertEqual(run_agent(tools, client)["status"], "early_stop")
        self.assertIsNotNone(tools.recheck)

    def test_api_error_fallback(self):
        tools = AuditTools(FakeProbes())
        result = run_agent(tools, FakeLLM([APIError("HTTP 401")]))
        self.assertTrue(result["fallback_used"])
        self.assertEqual(result["status"], "api_or_protocol_error")
        self.assertEqual(len(tools.findings), 5)

    def test_step_limit(self):
        tools = AuditTools(FakeProbes())
        client = FakeLLM([{"role": "assistant", "tool_calls": [tool_call("get_scope")]}])
        self.assertEqual(run_agent(tools, client, max_steps=1)["status"], "step_limit")
        self.assertEqual(tools.probes.http_calls, 2)

    def test_validate_entire_batch_before_any_execution(self):
        tools = AuditTools(FakeProbes())
        client = FakeLLM([{"role": "assistant", "tool_calls": [tool_call("inspect_http"), tool_call("get_scope")]}])
        result = run_agent(tools, client)
        self.assertEqual(result["status"], "api_or_protocol_error")
        self.assertFalse(any(e.get("origin") == "agent" and e["kind"] == "tool_start" for e in tools.events))

    def test_reasoning_not_in_trace_or_summary(self):
        client = FakeLLM([
            {"role": "assistant", "reasoning_content": "PRIVATE_PROVIDER_REASONING",
             "tool_calls": [tool_call("verify_findings")]},
            {"role": "assistant", "content": "Finished"},
        ])
        tools = AuditTools(FakeProbes())
        result = run_agent(tools, client)
        self.assertNotIn("PRIVATE_PROVIDER_REASONING", str(tools.events) + str(result))
        self.assertIn("PRIVATE_PROVIDER_REASONING", str(client.history[1]))

    def test_duplicate_tool_ids_rejected(self):
        seen = set()
        validate_tool_calls([tool_call("get_scope")], seen)
        with self.assertRaises(APIError):
            validate_tool_calls([tool_call("get_scope")], seen)

    def test_excessive_batch_rejected(self):
        with self.assertRaises(APIError):
            validate_tool_calls([tool_call("get_scope", f"call_{i}") for i in range(9)], set())
