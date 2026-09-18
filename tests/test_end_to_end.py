from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from deepaudit.cli import main
from tests.helpers import tool_call
from tests.test_gitops import git, initialize


def response(message, reason="stop", status=200):
    value = MagicMock()
    value.status = status
    value.read.return_value = json.dumps({
        "choices": [{"finish_reason": reason, "message": message}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
    }).encode()
    return value


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class EndToEndTests(unittest.TestCase):
    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "unit-test-token"})
    def test_agent_local_http_artifacts_and_git_with_mock_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initialize(root)
            replies = [
                response({"role": "assistant", "content": None,
                          "tool_calls": [tool_call("get_scope")]}, "tool_calls"),
                response({"role": "assistant", "content": None,
                          "tool_calls": [tool_call("verify_findings", "call_2")]}, "tool_calls"),
                response({"role": "assistant", "content": "Five reproduced configuration observations."}),
            ]
            with patch("deepaudit.llm.http.client.HTTPSConnection") as api:
                api.return_value.getresponse.side_effect = replies
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(["demo", "--mode", "agent", "--share-with-llm", "--repo", tmp, "--git-commit"])
                requests = api.return_value.request.call_args_list
                self.assertEqual(len(requests), 3)
                self.assertEqual(api.call_args.args[0], "api.deepseek.com")
                self.assertEqual(requests[0].args, ("POST", "/chat/completions"))
                self.assertEqual(requests[0].kwargs["headers"]["Authorization"], "Bearer unit-test-token")
                payload = json.loads(requests[1].kwargs["body"])
                self.assertEqual(payload["messages"][-1]["tool_call_id"], "call_1")
            self.assertEqual(code, 0)
            run_dir = next((root / "audits").iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(manifest["agent"]["status"], "complete")
            self.assertEqual(manifest["agent"]["api_requests"], 3)
            self.assertEqual(manifest["offline_verification"]["reproduced"], 5)
            self.assertEqual(git(root, "rev-list", "--count", "HEAD"), "2")
            for path in run_dir.rglob("*"):
                if path.is_file():
                    self.assertNotIn("unit-test-token", path.read_text())

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "unit-test-token"})
    def test_provider_auth_error_writes_degraded_report_but_never_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initialize(root)
            before = git(root, "rev-parse", "HEAD")
            with patch("deepaudit.llm.http.client.HTTPSConnection") as api:
                api.return_value.getresponse.return_value = response({}, status=401)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(["demo", "--hardened", "--mode", "agent", "--share-with-llm", "--repo", tmp, "--git-commit"])
            self.assertEqual(code, 3)
            self.assertEqual(before, git(root, "rev-parse", "HEAD"))
            run_dir = next((root / "audits").iterdir())
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertTrue(manifest["agent"]["fallback_used"])
            self.assertTrue((run_dir / "report.md").exists())
