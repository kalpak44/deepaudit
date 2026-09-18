import json
import tempfile
import unittest
from pathlib import Path

from lib import provenance, report
from lib.deepseek import DeepSeekError, agent_loop
from lib.orchestrator import Orchestrator
from lib.run_role import interpret
from lib.run_root import run


class ScriptedClient:
    """Returns a queued sequence of assistant messages; records what it was sent."""

    def __init__(self, messages):
        self._queue = list(messages)
        self.model = "mock"
        self.usage = {"total_tokens": 0}
        self.sent = []

    def complete(self, messages, tools=None):
        self.sent.append(list(messages))
        if not self._queue:
            return {"role": "assistant", "content": "done"}
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def tool_call(name, args, call_id="c1"):
    return {"role": "assistant", "tool_calls": [
        {"id": call_id, "type": "function",
         "function": {"name": name, "arguments": json.dumps(args)}}]}


class AgentLoop(unittest.TestCase):
    def test_executes_a_tool_then_finishes(self):
        seen = {}
        client = ScriptedClient([tool_call("ping", {"x": 1}),
                                 {"role": "assistant", "content": "final"}])
        schema = {"description": "d", "parameters": {"type": "object", "properties": {}}}

        def ping(args):
            seen.update(args)
            return {"ok": True}

        out = agent_loop(client, "sys", "task", {"ping": (schema, ping)}, max_steps=5)
        self.assertEqual(out["content"], "final")
        self.assertEqual(out["stopped"], "final_message")
        self.assertEqual(seen, {"x": 1})

    def test_unknown_tool_is_reported_not_crashed(self):
        client = ScriptedClient([tool_call("nope", {}),
                                 {"role": "assistant", "content": "ok"}])
        out = agent_loop(client, "s", "t", {}, max_steps=5)
        self.assertEqual(out["stopped"], "final_message")
        tool_msg = client.sent[-1][-1]
        self.assertEqual(tool_msg["role"], "tool")
        self.assertIn("unknown_tool", tool_msg["content"])

    def test_handler_exception_becomes_a_tool_error(self):
        schema = {"description": "d", "parameters": {"type": "object", "properties": {}}}
        client = ScriptedClient([tool_call("boom", {}),
                                 {"role": "assistant", "content": "recovered"}])

        def boom(_):
            raise RuntimeError("kaboom")

        out = agent_loop(client, "s", "t", {"boom": (schema, boom)}, max_steps=5)
        self.assertEqual(out["content"], "recovered")
        self.assertIn("tool_failed", client.sent[-1][-1]["content"])

    def test_step_budget_is_enforced(self):
        client = ScriptedClient([tool_call("ping", {}) for _ in range(20)])
        schema = {"description": "d", "parameters": {"type": "object", "properties": {}}}
        out = agent_loop(client, "s", "t", {"ping": (schema, lambda a: {})}, max_steps=3)
        self.assertEqual(out["stopped"], "step_limit")
        self.assertEqual(out["steps"], 3)


class FakeGh:
    """Stands in for the gh CLI: records dispatches, serves a canned run list, and
    materializes a result artifact on download."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, args, timeout=60, check=True):
        self.calls.append(args)

        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        r = R()
        if args[:2] == ["run", "list"]:
            # The dispatched run appears under the unique name root passed.
            name = self._run_name
            r.stdout = json.dumps([{"databaseId": 999, "displayTitle": name,
                                    "status": "completed"}])
        if args[:2] == ["run", "download"]:
            out_dir = Path(args[args.index("--dir") + 1])
            (out_dir / "result.json").write_text(json.dumps(self.result), encoding="utf-8")
        if args[:2] == ["workflow", "run"]:
            self._run_name = [a.split("=", 1)[1] for a in args if a.startswith("run_name=")][0]
        return r


class Dispatch(unittest.TestCase):
    def _orchestrator(self, tmp, fake):
        import lib.orchestrator as mod
        mod._gh = fake
        return Orchestrator(repo="o/r", ref="main", run_root=Path(tmp),
                            poll=0, timeout=5, sleep=lambda _s: None,
                            now=self._clock())

    def _clock(self):
        state = {"t": 0.0}

        def now():
            state["t"] += 0.1
            return state["t"]
        return now

    def test_unknown_role_is_refused_before_any_gh_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGh({})
            orch = self._orchestrator(tmp, fake)
            out = orch.dispatch({"role": "does-not-exist", "target": "https://x"})
            self.assertEqual(out["error"], "unknown_role")
            self.assertEqual(fake.calls, [])

    def test_missing_target_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = self._orchestrator(tmp, FakeGh({}))
            self.assertIn("error", orch.dispatch({"role": "fingerprinter", "target": ""}))

    def test_roundtrip_dispatch_persists_the_task_result(self):
        result = {"role": "fingerprinter", "task_id": "t01x",
                  "findings": [{"id": "Next.js 14", "title": "Next.js 14"}]}
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGh(result)
            orch = self._orchestrator(tmp, fake)
            out = orch.dispatch({"role": "fingerprinter", "target": "https://x",
                                 "params": {"depth": "1"}})
            self.assertEqual(out["status"], "ok")
            self.assertEqual(out["result"]["findings"][0]["id"], "Next.js 14")
            saved = list((Path(tmp) / "tasks").glob("*.json"))
            self.assertEqual(len(saved), 1, "result is persisted for provenance")
            self.assertTrue(any(c[:2] == ["workflow", "run"] for c in fake.calls))

    def test_bad_param_key_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = self._orchestrator(tmp, FakeGh({}))
            out = orch.dispatch({"role": "fingerprinter", "target": "https://x",
                                 "params": {"bad key!": 1}})
            self.assertIn("error", out)


class Provenance(unittest.TestCase):
    def _run_root(self, tmp, task_id, findings):
        tasks = Path(tmp) / "tasks"
        tasks.mkdir(parents=True)
        (tasks / f"{task_id}.json").write_text(
            json.dumps({"findings": findings}), encoding="utf-8")
        return Path(tmp)

    def test_grounded_finding_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._run_root(tmp, "t01", [{"id": "CVE-1", "title": "CVE-1"}])
            report_obj = {"findings": [{"task_id": "t01", "id": "CVE-1", "title": "CVE-1"}]}
            result = provenance.check(report_obj, root)
            self.assertTrue(result["ok"])
            self.assertEqual(result["counts"]["grounded"], 1)

    def test_invented_finding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._run_root(tmp, "t01", [{"id": "CVE-1", "title": "CVE-1"}])
            report_obj = {"findings": [{"task_id": "t01", "id": "CVE-9", "title": "CVE-9"}]}
            result = provenance.check(report_obj, root)
            self.assertFalse(result["ok"])
            self.assertEqual(result["rejected"][0]["reason"], "not_in_task_result")

    def test_unknown_task_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._run_root(tmp, "t01", [])
            report_obj = {"findings": [{"task_id": "ghost", "id": "x", "title": "x"}]}
            self.assertFalse(provenance.check(report_obj, root)["ok"])


class RoleInterpretation(unittest.TestCase):
    def test_emit_result_grounds_findings_to_task(self):
        client = ScriptedClient([
            tool_call("emit_result", {"summary": "Next.js site", "stack": ["Next.js"],
                                      "findings": [{"title": "Next.js 14.0.3",
                                                    "severity": "info"}]}),
            {"role": "assistant", "content": "done"}])
        out = interpret("fingerprinter", "t01", "https://x", {},
                        [{"source": "tool_output.json", "content": {"a": 1}}], client)
        self.assertEqual(out["findings"][0]["task_id"], "t01")
        self.assertEqual(out["stack"], ["Next.js"])
        self.assertEqual(out["findings"][0]["title"], "Next.js 14.0.3")


class FakeOrchestrator:
    def __init__(self, results):
        self._results = results
        self.dispatched = []

    def dispatch(self, args):
        record = {"task_id": f"t{len(self.dispatched)+1:02d}", "role": args["role"],
                  "target": args["target"]}
        self.dispatched.append(record)
        return {"task_id": record["task_id"], "role": args["role"], "status": "ok",
                "result": self._results.get(args["role"], {"findings": []})}


class RootRun(unittest.TestCase):
    def test_root_grounds_only_what_a_task_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp)
            # Simulate the fingerprinter task result already persisted by the orchestrator.
            (run_root / "tasks").mkdir()
            (run_root / "tasks" / "t01.json").write_text(
                json.dumps({"findings": [{"id": "Next.js 14.0.3",
                                          "title": "Next.js 14.0.3"}]}), encoding="utf-8")

            class OrchWithPersist(FakeOrchestrator):
                def dispatch(self, args):
                    out = super().dispatch(args)
                    return out

            orch = OrchWithPersist({"fingerprinter": {
                "findings": [{"id": "Next.js 14.0.3", "title": "Next.js 14.0.3"}]}})
            client = ScriptedClient([
                {"role": "assistant", "tool_calls": [
                    {"id": "a", "type": "function",
                     "function": {"name": "list_roles", "arguments": "{}"}}]},
                {"role": "assistant", "tool_calls": [
                    {"id": "b", "type": "function", "function": {
                        "name": "dispatch_role",
                        "arguments": json.dumps({"role": "fingerprinter",
                                                 "target": "https://x"})}}]},
                {"role": "assistant", "tool_calls": [
                    {"id": "c", "type": "function", "function": {
                        "name": "finish", "arguments": json.dumps({
                            "summary": "audited", "limitations": "one role only",
                            "findings": [
                                {"task_id": "t01", "id": "Next.js 14.0.3",
                                 "title": "Next.js 14.0.3", "severity": "info"},
                                {"task_id": "t01", "id": "Invented",
                                 "title": "Invented", "severity": "high"}]})}}]},
                {"role": "assistant", "content": "done"}])

            result = run("https://x", repo="o/r", ref="main", run_root=run_root,
                         client=client, orchestrator=orch, max_steps=8)
            grounded_ids = [f["id"] for f in result["provenance"]["grounded"]]
            self.assertEqual(grounded_ids, ["Next.js 14.0.3"])
            self.assertEqual(result["provenance"]["counts"]["rejected"], 1,
                             "the invented finding is dropped by the deterministic gate")
            self.assertEqual(len(orch.dispatched), 1)

            page = report.render(target="https://x", run_id="root-1",
                                 report=result["report"],
                                 provenance=result["provenance"], plan=orch.dispatched)
            self.assertIn("Next.js 14.0.3", page)
            self.assertNotIn("<h3>Invented</h3>", page)
            self.assertTrue(page.startswith("<!doctype html>"))


class ReportEscaping(unittest.TestCase):
    def test_hostile_strings_are_escaped(self):
        prov = {"grounded": [{"title": "<script>x</script>", "severity": "high",
                              "task_id": "t01", "summary": "a\"b"}],
                "rejected": [], "counts": {"grounded": 1, "rejected": 0}}
        page = report.render(target="<b>t</b>", run_id="r", provenance=prov,
                             report={"summary": "", "findings": prov["grounded"]},
                             plan=[])
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
