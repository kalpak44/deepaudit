"""Small stdlib client for DeepSeek's OpenAI-format Chat Completions API."""
from __future__ import annotations

import http.client
import json
import re
import ssl
import time

DEFAULT_MODEL = "deepseek-flash"
API_HOST = "api.deepseek.com"
API_PATH = "/chat/completions"


class APIError(RuntimeError):
    pass


class DeepSeekClient:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, *,
                 timeout: float = 45, max_requests: int = 8, max_tokens: int = 1500):
        if not api_key or any(ord(c) < 33 or ord(c) > 126 for c in api_key):
            raise APIError("Set DEEPSEEK_API_KEY to a valid API key")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", model):
            raise APIError("Invalid model identifier")
        if not 1 <= max_requests <= 20 or not 128 <= max_tokens <= 4096:
            raise APIError("Invalid API request or output-token budget")
        self._key = api_key
        self.model = model
        self.timeout = timeout
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.requests = 0
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _post(self, payload: dict) -> tuple[int, bytes]:
        conn = http.client.HTTPSConnection(API_HOST, timeout=self.timeout,
                                           context=ssl.create_default_context())
        try:
            conn.request("POST", API_PATH, body=json.dumps(payload).encode("utf-8"), headers={
                "Authorization": "Bearer " + self._key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Connection": "close",
            })
            response = conn.getresponse()
            raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise APIError("API response exceeded the 1 MiB limit")
            return response.status, raw
        finally:
            conn.close()

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        payload = {"model": self.model, "messages": messages, "tools": tools,
                   "tool_choice": "auto", "stream": False,
                   "max_tokens": self.max_tokens, "thinking": {"type": "disabled"}}
        for attempt in range(2):
            if self.requests >= self.max_requests:
                raise APIError("API request budget exhausted")
            self.requests += 1
            try:
                status, raw = self._post(payload)
            except (OSError, http.client.HTTPException) as exc:
                # A timed-out request can still have been billed. No automatic network-error retry.
                raise APIError("DeepSeek connection failed or timed out; baseline fallback is available") from exc
            if status in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(1)
                continue
            if status != 200:
                # Never log raw API error bodies; they may echo sensitive inputs.
                raise APIError(f"DeepSeek returned HTTP {status}")
            try:
                data = json.loads(raw)
                choice = data["choices"][0]
                message = choice["message"]
                finish = choice.get("finish_reason")
                if finish not in ("stop", "tool_calls"):
                    raise APIError("Model output was truncated or interrupted; refusing partial tool calls")
                if not isinstance(message, dict) or message.get("role") != "assistant":
                    raise APIError("Invalid assistant message")
                if message.get("content") is not None and not isinstance(message["content"], str):
                    raise APIError("Invalid assistant content")
                if isinstance(data.get("usage"), dict):
                    for key in self.usage:
                        amount = data["usage"].get(key, 0)
                        if type(amount) is int and amount >= 0:
                            self.usage[key] += amount
                return {key: message[key] for key in ("role", "content", "tool_calls", "reasoning_content")
                        if key in message}
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise APIError("Invalid DeepSeek response JSON") from exc
        raise APIError("DeepSeek temporarily unavailable")
