"""A small standard-library DeepSeek client and a bounded tool-use loop.

This is the whole model harness — no SDK, no Codex dependency. `agent_loop` drives one
role: it sends the role's system prompt plus a task, lets the model call a fixed set of
Python tool handlers, feeds their results back, and stops at a final message or the step
budget. The tools a role is given are its entire capability surface; the model never gets
a shell.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import time
from collections.abc import Callable

DEFAULT_MODEL = "deepseek-flash"
API_HOST = "api.deepseek.com"
API_PATH = "/chat/completions"


class DeepSeekError(RuntimeError):
    pass


class DeepSeekClient:
    def __init__(self, api_key: str | None = None, model: str | None = None, *,
                 timeout: float = 60, max_requests: int = 40, max_tokens: int = 2000):
        api_key = api_key if api_key is not None else os.environ.get("DEEPSEEK_API_KEY", "")
        model = model or os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL)
        if not api_key or any(ord(c) < 33 or ord(c) > 126 for c in api_key):
            raise DeepSeekError("Set DEEPSEEK_API_KEY to a valid API key")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", model):
            raise DeepSeekError("Invalid model identifier")
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
            raw = response.read(2_097_153)
            if len(raw) > 2_097_152:
                raise DeepSeekError("API response exceeded the 2 MiB limit")
            return response.status, raw
        finally:
            conn.close()

    def complete(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        payload = {"model": self.model, "messages": messages, "stream": False,
                   "max_tokens": self.max_tokens, "thinking": {"type": "disabled"}}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        for attempt in range(2):
            if self.requests >= self.max_requests:
                raise DeepSeekError("API request budget exhausted")
            self.requests += 1
            try:
                status, raw = self._post(payload)
            except (OSError, http.client.HTTPException) as exc:
                raise DeepSeekError("DeepSeek connection failed or timed out") from exc
            if status in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(2)
                continue
            if status != 200:
                raise DeepSeekError(f"DeepSeek returned HTTP {status}")
            try:
                data = json.loads(raw)
                choice = data["choices"][0]
                message = choice["message"]
                if not isinstance(message, dict) or message.get("role") != "assistant":
                    raise DeepSeekError("Invalid assistant message")
                if isinstance(data.get("usage"), dict):
                    for key in self.usage:
                        amount = data["usage"].get(key, 0)
                        if type(amount) is int and amount >= 0:
                            self.usage[key] += amount
                return {k: message[k] for k in ("role", "content", "tool_calls")
                        if k in message}
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise DeepSeekError("Invalid DeepSeek response JSON") from exc
        raise DeepSeekError("DeepSeek temporarily unavailable")


Handler = Callable[[dict], dict]


def agent_loop(client, system_prompt: str, task: str, tools: dict[str, tuple[dict, Handler]],
               *, max_steps: int = 12, log: Callable[[str], None] = lambda _: None) -> dict:
    """Run one role to completion.

    `tools` maps a tool name to (json-schema, handler). The handler takes the parsed
    arguments and returns a JSON-serializable result. The loop returns
    {"content", "steps", "tool_calls", "stopped"} where content is the model's final text.
    Handler exceptions become an error tool result rather than crashing the role, so one
    bad call does not abort the whole audit.
    """
    schemas = [{"type": "function", "function": {"name": name, **schema}}
               for name, (schema, _) in tools.items()]
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task}]
    executed = 0
    stopped = "step_limit"
    for step in range(max_steps):
        log(f"[step {step + 1}/{max_steps}]")
        message = client.complete(messages, schemas)
        calls = message.get("tool_calls") or []
        messages.append(message)
        if not calls:
            return {"content": message.get("content") or "", "steps": step + 1,
                    "tool_calls": executed, "stopped": "final_message"}
        if not isinstance(calls, list) or len(calls) > 16:
            raise DeepSeekError("Invalid or excessive tool call batch")
        for call in calls:
            executed += 1
            name = (call.get("function") or {}).get("name")
            raw_args = (call.get("function") or {}).get("arguments") or "{}"
            call_id = call.get("id") or f"call_{executed}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else {}
                if not isinstance(args, dict):
                    raise ValueError("arguments must be a JSON object")
                if name not in tools:
                    result = {"error": "unknown_tool", "allowed": sorted(tools)}
                else:
                    log(f"[tool] {name}")
                    result = tools[name][1](args)
            except Exception as exc:  # a tool failure is data for the model, not a crash
                result = {"error": "tool_failed", "detail": str(exc)[:500]}
            messages.append({"role": "tool", "tool_call_id": call_id,
                             "content": json.dumps(result, ensure_ascii=True)[:200_000]})
    return {"content": "", "steps": max_steps, "tool_calls": executed, "stopped": stopped}
