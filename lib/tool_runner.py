"""Dispatch workflow tools with unique correlation, bounded waits and persisted evidence."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
import uuid
import threading
from pathlib import Path

from .collect import target_url
from .console import Console
from .tool_catalog import catalog, validate_params

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
MAX_EVIDENCE_BYTES = 1_000_000


class ToolRunner:
    def __init__(self, *, repo: str, ref: str, run_root: Path, console: Console,
                 poll_seconds: int = 8, timeout_seconds: int = 720, max_tasks: int = 24,
                 sleep=time.sleep, now=time.monotonic):
        self.repo, self.ref, self.run_root, self.console = repo, ref, run_root, console
        self.poll_seconds, self.timeout_seconds, self.max_tasks = poll_seconds, timeout_seconds, max_tasks
        self.sleep, self.now = sleep, now
        self.tasks: list[dict] = []
        self.evidence: dict[str, dict] = {}
        self._target = None
        self._lock = threading.RLock()
        self._slots = threading.BoundedSemaphore(4)

    @staticmethod
    def catalog() -> list[dict]:
        return catalog(WORKFLOWS)

    @staticmethod
    def available() -> list[str]:
        return [entry["name"] for entry in catalog(WORKFLOWS)]

    def _gh(self, args: list[str], *, timeout: float = 60, check=True):
        result = subprocess.run(["gh", *args], text=True, capture_output=True,
                                timeout=max(0.1, timeout), check=False)
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip()[:400] or "GitHub CLI command failed")
        return result

    def read_evidence(self, task_id: str, offset: int = 0, limit: int = 12000) -> dict:
        if task_id not in self.evidence:
            return {"error": "unknown_task"}
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 16000:
            return {"error": "offset must be nonnegative; limit must be 1..16000"}
        raw = json.dumps(self.evidence[task_id], ensure_ascii=True, indent=2)
        return {"task_id": task_id, "text": raw[offset:offset + limit], "total_chars": len(raw),
                "next_offset": offset + limit if offset + limit < len(raw) else None}

    def run(self, employee: str, target: str, tool: str, params: dict) -> dict:
        with self._slots:
            return self._run(employee, target, tool, params)

    def _run(self, employee: str, target: str, tool: str, params: dict) -> dict:
        tools = {entry["name"]: entry for entry in self.catalog()}
        if not isinstance(tool, str) or tool not in tools:
            return {"error": "unknown_tool", "available_tools": sorted(tools)}
        try:
            normalized = target_url(target)
            params = validate_params(tool, params)
        except (ValueError, TypeError) as exc:
            return {"error": str(exc)}
        task_id = "t" + uuid.uuid4().hex
        workflow = tools[tool]["workflow"]
        run_name = f"deepaudit {tool} {task_id}"
        record = {"task_id": task_id, "employee": employee, "tool": tool, "target": target,
                  "params": params, "status": "dispatched"}
        with self._lock:
            if self._target and normalized != self._target:
                return {"error": "target is fixed for this audit"}
            if len(self.tasks) >= self.max_tasks:
                return {"error": "workflow budget exhausted"}
            self._target = normalized
            self.tasks.append(record)
        self._persist(record)
        self.console.event("TOOL", "dispatch", **record)
        deadline = self.now() + self.timeout_seconds
        run_id = None
        try:
            dispatch = ["-f", f"target={target}", "-f", "params=" + json.dumps(params),
                        "-f", f"task_id={task_id}", "-f", f"run_name={run_name}"]
            if tool == "script":
                # The sandbox has no network; the supervisor hands it the evidence it may read.
                dispatch += ["-f", "evidence=" + self._evidence_bundle(params.get("inputs"))]
            self._gh(["workflow", "run", workflow, "--repo", self.repo, "--ref", self.ref, *dispatch])
            while self.now() < deadline:
                listed = self._gh(["run", "list", "--repo", self.repo, "--workflow", workflow,
                                   "--event", "workflow_dispatch", "--json", "databaseId,displayTitle",
                                   "--limit", "100"], timeout=min(60, deadline - self.now()))
                matches = [r for r in json.loads(listed.stdout) if r.get("displayTitle") == run_name]
                if matches:
                    run_id = str(matches[0]["databaseId"])
                    break
                self.console.event("WAIT", "waiting for workflow to appear", task_id=task_id)
                self.sleep(self.poll_seconds)
            if run_id is None:
                raise TimeoutError("Dispatched workflow did not appear before the deadline")
            record.update(run_id=run_id, url=f"https://github.com/{self.repo}/actions/runs/{run_id}")
            # Poll via gh rather than buffering a long gh watch: emit live state changes.
            while self.now() < deadline:
                viewed = self._gh(["run", "view", run_id, "--repo", self.repo, "--json", "status,conclusion"],
                                  timeout=min(60, deadline - self.now()))
                state = json.loads(viewed.stdout)
                self.console.event("WAIT", state["status"], task_id=task_id, run_id=run_id)
                if state["status"] == "completed":
                    record["conclusion"] = state.get("conclusion")
                    break
                self.sleep(self.poll_seconds)
            else:
                raise TimeoutError("Workflow exceeded the audit tool deadline")
            with tempfile.TemporaryDirectory() as tmp:
                self._gh(["run", "download", run_id, "--repo", self.repo, "--name",
                          f"evidence-{task_id}", "--dir", tmp], timeout=min(60, deadline - self.now()))
                path = Path(tmp) / "evidence.json"
                if not path.is_file() or path.stat().st_size > MAX_EVIDENCE_BYTES:
                    raise ValueError("Missing or oversized evidence.json")
                payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or any(payload.get(k) != record[k] for k in ("task_id", "tool", "target")):
                raise ValueError("Evidence does not match the dispatched task, tool and target")
            if payload.get("schema_version") != 1 or payload.get("status") not in ("ok", "failed", "partial"):
                raise ValueError("Invalid evidence envelope")
            self.evidence[task_id] = payload
            record["status"] = payload["status"] if record["conclusion"] == "success" else "failed"
            if payload.get("error"):
                record["error"] = payload["error"]
        except Exception as exc:
            record.update(status="failed", error=str(exc)[:700])
            if run_id and isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
                try:
                    self._gh(["run", "cancel", run_id, "--repo", self.repo], check=False)
                except Exception:
                    pass
        self._persist(record)
        self.console.event("TOOL", "complete", **record)
        return {**record, "evidence": self.read_evidence(task_id) if task_id in self.evidence else None}

    def _evidence_bundle(self, inputs, budget: int = 40000) -> str:
        """Resolve requested task_ids to their saved evidence, bounded to fit one workflow input."""
        bundle = {}
        for item in inputs or []:
            task_id = item.get("task_id") if isinstance(item, dict) else None
            payload = self.evidence.get(task_id)
            if payload is None:
                bundle[task_id or "unknown"] = {"error": "no completed task with this id"}
                continue
            text = json.dumps(payload)
            if len(text) > budget:
                bundle[task_id] = {"truncated": True, "note": "evidence exceeded the analysis budget",
                                   "text": text[:budget]}
                budget = 0
            else:
                bundle[task_id] = payload
                budget -= len(text)
        return json.dumps(bundle)[:64000]

    def _persist(self, record):
        directory = self.run_root / "evidence"
        directory.mkdir(parents=True, exist_ok=True)
        payload = {"dispatch": record, "result": self.evidence.get(record["task_id"])}
        (directory / f"{record['task_id']}.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
