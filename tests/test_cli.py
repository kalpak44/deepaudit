from contextlib import redirect_stdout, redirect_stderr
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deepaudit.cli import main


class CLITests(unittest.TestCase):
    def call(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    @patch("deepaudit.policy.socket.getaddrinfo")
    def test_authorization_required_before_network(self, resolver):
        code, _, error = self.call(["run", "--target", "example.test", "--mode", "baseline"])
        self.assertEqual(code, 2)
        self.assertIn("--authorized", error)
        resolver.assert_not_called()

    @patch("deepaudit.policy.socket.getaddrinfo")
    def test_agent_data_sharing_requires_consent(self, resolver):
        code, _, error = self.call(["work", "--target", "example.test", "--authorized"])
        self.assertEqual(code, 2)
        self.assertIn("--share-with-llm", error)
        resolver.assert_not_called()

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""})
    @patch("deepaudit.policy.socket.getaddrinfo")
    def test_agent_missing_key_fails_before_network(self, resolver):
        code, _, error = self.call(["run", "--target", "example.test", "--authorized", "--share-with-llm"])
        self.assertEqual(code, 2)
        self.assertIn("DEEPSEEK_API_KEY", error)
        resolver.assert_not_called()

    def test_complete_demo_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, output, _ = self.call(["demo", "--repo", tmp])
            self.assertEqual(code, 0)
            self.assertIn("Observations: 5", output)
            folder = next((Path(tmp) / "audits").iterdir())
            code, output, _ = self.call(["verify", str(folder), "--json"])
            self.assertEqual(code, 0)
            self.assertIn('"all_reproduced": true', output)

    def test_hardened_demo_has_one_http_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, output, _ = self.call(["demo", "--repo", tmp, "--hardened"])
            self.assertEqual(code, 0)
            self.assertIn("Observations: 1", output)

    def test_checks_command(self):
        code, output, _ = self.call(["checks"])
        self.assertEqual(code, 0)
        self.assertIn("TLS_CERTIFICATE_REJECTED", output)
