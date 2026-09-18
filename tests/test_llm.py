import json
import unittest
from unittest.mock import patch
from deepaudit.llm import APIError, DeepSeekClient


def reply(message=None, reason="stop"):
    return json.dumps({"choices": [{"finish_reason": reason,
                                   "message": message or {"role": "assistant", "content": "OK"}}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}}).encode()


class ClientTests(unittest.TestCase):
    def test_empty_key_rejected(self):
        with self.assertRaises(APIError):
            DeepSeekClient("")

    def test_control_char_in_key_rejected(self):
        with self.assertRaises(APIError):
            DeepSeekClient("key\nheader")

    def test_protocol_payload_and_usage(self):
        client = DeepSeekClient("unit-test-token")
        with patch.object(client, "_post", return_value=(200, reply())) as transport:
            result = client.complete([{"role": "user", "content": "Test"}], [])
        payload = transport.call_args.args[0]
        self.assertEqual(payload["thinking"], {"type": "disabled"})
        self.assertEqual(payload["model"], "deepseek-flash")
        self.assertEqual(client.usage["total_tokens"], 12)
        self.assertEqual(result["content"], "OK")
        self.assertNotIn("unit-test-token", str(payload))

    @patch("deepaudit.llm.time.sleep")
    def test_retry_counts_against_budget(self, sleep):
        client = DeepSeekClient("unit-test-token", max_requests=2)
        with patch.object(client, "_post", side_effect=[(429, b"private error"), (200, reply())]):
            client.complete([], [])
        self.assertEqual(client.requests, 2)
        with self.assertRaises(APIError):
            client.complete([], [])

    def test_auth_error_is_not_retried_or_echoed(self):
        client = DeepSeekClient("unit-test-token")
        with patch.object(client, "_post", return_value=(401, b"SECRET_KEY_ERROR_BODY")):
            with self.assertRaises(APIError) as error:
                client.complete([], [])
        self.assertNotIn("SECRET_KEY_ERROR_BODY", str(error.exception))
        self.assertEqual(client.requests, 1)

    def test_truncated_tool_call_never_executed(self):
        client = DeepSeekClient("unit-test-token")
        with patch.object(client, "_post", return_value=(200, reply(reason="length"))):
            with self.assertRaises(APIError):
                client.complete([], [])

    def test_invalid_json(self):
        client = DeepSeekClient("unit-test-token")
        with patch.object(client, "_post", return_value=(200, b"not json")):
            with self.assertRaises(APIError):
                client.complete([], [])

    def test_timeout_not_retried(self):
        client = DeepSeekClient("unit-test-token")
        with patch.object(client, "_post", side_effect=TimeoutError()):
            with self.assertRaises(APIError):
                client.complete([], [])
        self.assertEqual(client.requests, 1)
