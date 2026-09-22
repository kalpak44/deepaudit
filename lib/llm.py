"""A dependency-free chat client and a bounded tool-use loop.

This is the whole model harness — no SDK. It speaks the OpenAI-compatible chat-completions
protocol that DeepSeek (the default), and most providers, expose, so the backend is swapped
entirely through environment variables:

    LLM_BASE_URL   default https://api.deepseek.com
    LLM_API_KEY    default $DEEPSEEK_API_KEY
    LLM_MODEL_FAST default deepseek-chat      (recon, parsing, grunt work)
    LLM_MODEL_STRONG default deepseek-reasoner (planning, synthesis, verification)

Two tiers exist because a strong model driving planning/verification and a fast model doing
the bulk tool work is both cheaper and better than one tier for everything. `agent_loop`
runs one agent session: system prompt + task, a fixed set of Python tool handlers, results
fed back, stopping at a final message, a terminal tool, or the step budget. The tools handed
to an agent are its entire capability surface.
"""
from __future__ import annotations

import http.client
import json
import os
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

FAST = "fast"
STRONG = "strong"


class LLMError(RuntimeError):
    pass


class LLMClient:
    """One shared client. Thread-safe: fan-out agents call it concurrently."""

    def __init__(self, *, base_url=None, api_key=None, model_fast=None, model_strong=None,
                 timeout=90, max_requests=600, max_tokens=4000, concurrency=6):
        base_url = base_url or os.environ.get("LLM_BASE_URL", "https://api.deepseek.com")
        api_key = api_key if api_key is not None else (
            os.environ.get("LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY", ""))
        if not api_key or any(ord(c) < 33 or ord(c) > 126 for c in api_key):
            raise LLMError("Set LLM_API_KEY (or DEEPSEEK_API_KEY) to a valid API key")
        split = urlsplit(base_url if "://" in base_url else "https://" + base_url)
        if split.scheme != "https" or not split.hostname:
            raise LLMError("LLM_BASE_URL must be an https URL")
        self._host = split.hostname
        self._port = split.port or 443
        base_path = split.path.rstrip("/")
        self._path = base_path + ("" if base_path.endswith("/chat/completions") else "/chat/completions")
        self._key = api_key
        self.models = {
            FAST: model_fast or os.environ.get("LLM_MODEL_FAST", "deepseek-chat"),
            STRONG: model_strong or os.environ.get("LLM_MODEL_STRONG", "deepseek-reasoner"),
        }
        self.timeout = timeout
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.requests = 0
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(concurrency)
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _post(self, payload):
        conn = http.client.HTTPSConnection(self._host, self._port, timeout=self.timeout,
                                           context=ssl.create_default_context())
        try:
            conn.request("POST", self._path, body=json.dumps(payload).encode("utf-8"), headers={
                "Authorization": "Bearer " + self._key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Connection": "close",
            })
            response = conn.getresponse()
            raw = response.read(4_194_305)
            if len(raw) > 4_194_304:
                raise LLMError("API response exceeded the 4 MiB limit")
            return response.status, raw
        finally:
            conn.close()

    def complete(self, messages, tools=None, *, tier=FAST):
        model = self.models.get(tier, self.models[FAST])
        payload = {"model": model, "messages": messages, "stream": False,
                   "max_tokens": self.max_tokens}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        last = None
        for attempt in range(3):
            with self._lock:
                if self.requests >= self.max_requests:
                    raise LLMError("API request budget exhausted")
                self.requests += 1
            try:
                with self._slots:
                    status, raw = self._post(payload)
            except (OSError, http.client.HTTPException) as exc:
                last = exc
                time.sleep(2 * (attempt + 1))
                continue
            if status in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            if status != 200:
                raise LLMError(f"API returned HTTP {status}: {raw[:200].decode('utf-8', 'replace')}")
            try:
                data = json.loads(raw)
                message = data["choices"][0]["message"]
                if not isinstance(message, dict) or message.get("role") != "assistant":
                    raise LLMError("Invalid assistant message")
                if isinstance(data.get("usage"), dict):
                    with self._lock:
                        for key in self.usage:
                            amount = data["usage"].get(key, 0)
                            if type(amount) is int and amount >= 0:
                                self.usage[key] += amount
                return {k: message[k] for k in ("role", "content", "tool_calls") if k in message}
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise LLMError("Invalid API response JSON") from exc
        raise LLMError(f"Model temporarily unavailable: {last}")


Handler = Callable[[dict], dict]


def _execute_call(call, tools, log, index):
    """Run one tool call and return the message to append. Never raises: failures become data."""
    name = (call.get("function") or {}).get("name")
    raw_args = (call.get("function") or {}).get("arguments") or "{}"
    call_id = call.get("id") or f"call_{index}"
    terminal_accepted = False
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else {}
        if not isinstance(args, dict):
            raise ValueError("arguments must be a JSON object")
        if name not in tools:
            result = {"error": "unknown_tool", "allowed": sorted(tools)}
        else:
            log(f"[tool] {name} " + json.dumps(args, ensure_ascii=True)[:600])
            result = tools[name][1](args)
    except Exception as exc:  # a tool failure is data for the model, not a crash
        result = {"error": "tool_failed", "detail": str(exc)[:600]}
    log(f"[result] {name} " + json.dumps(result, ensure_ascii=True)[:1000])
    if isinstance(result, dict) and result.get("accepted") is True:
        terminal_accepted = True
    return {"role": "tool", "tool_call_id": call_id,
            "content": json.dumps(result, ensure_ascii=True)}, name, terminal_accepted


def agent_loop(client, system_prompt, task, tools, *, tier=FAST, max_steps=16,
               log=lambda _: None, terminal_tools=(), require_terminal=False,
               max_context_chars=320_000, max_parallel_tools=8):
    """Run one agent session to completion.

    `tools` maps a name to (json-schema, handler). The handler takes parsed arguments and
    returns a JSON-serializable result. Handler exceptions become an error tool result rather
    than crashing the session, so one bad call never aborts the whole audit. Returns
    {content, steps, tool_calls, stopped}.
    """
    schemas = [{"type": "function", "function": {"name": name, **schema}}
               for name, (schema, _) in tools.items()]
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task}]
    executed = 0
    for step in range(max_steps):
        if len(json.dumps(messages, ensure_ascii=True)) > max_context_chars:
            _compact(messages)
            if len(json.dumps(messages, ensure_ascii=True)) > max_context_chars:
                return {"content": "", "steps": step, "tool_calls": executed, "stopped": "context_limit"}
        log(f"[step {step + 1}/{max_steps}]")
        message = client.complete(messages, schemas, tier=tier)
        if message.get("content"):
            log("[message] " + str(message["content"]))
        calls = message.get("tool_calls") or []
        messages.append(message)
        if not calls:
            if require_terminal:
                messages.append({"role": "user", "content":
                                 "Continue the assignment and call the completion tool. If blocked, "
                                 "report the limitation explicitly through it."})
                continue
            return {"content": message.get("content") or "", "steps": step + 1,
                    "tool_calls": executed, "stopped": "final_message"}
        if not isinstance(calls, list) or len(calls) > 24:
            raise LLMError("Invalid or excessive tool call batch")
        executed += len(calls)
        # Independent tool calls in one turn (spawn/run/cve — all IO-bound) run concurrently.
        # Results are appended in the model's original call order, as the API requires.
        if len(calls) == 1:
            outcomes = [_execute_call(calls[0], tools, log, executed)]
        else:
            with ThreadPoolExecutor(max_workers=min(len(calls), max_parallel_tools)) as pool:
                outcomes = list(pool.map(
                    lambda ic: _execute_call(ic[1], tools, log, ic[0]), enumerate(calls)))
        terminal = None
        for message_out, name, accepted in outcomes:
            messages.append(message_out)
            if name in terminal_tools and accepted:
                terminal = name
        if terminal is not None:
            return {"content": "", "steps": step + 1, "tool_calls": executed, "stopped": terminal}
    return {"content": "", "steps": max_steps, "tool_calls": executed, "stopped": "step_limit"}


def _compact(messages):
    """Drop the oldest tool results (keeping their call shells) when context grows too large.

    System and user framing stay; the model keeps its own reasoning but loses the bulky raw
    tool payloads it has already summarized into findings and notes.
    """
    trimmed = 0
    for message in messages[2:-8]:
        if message.get("role") == "tool" and len(message.get("content", "")) > 400:
            message["content"] = message["content"][:200] + " …[trimmed; re-read evidence if needed]"
            trimmed += 1
    return trimmed
