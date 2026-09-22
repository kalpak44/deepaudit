"""Autonomous horizontal fan-out: the supervisor launches worker runs of the same workflow.

Scaling wide means running independent subtasks on separate runners at the same time. The
supervisor does that by dispatching `audit.yaml` again in `mode=worker` with a subtask
description, then waiting for that run and collecting its `worker-<task_id>` artifact. One
workflow file, N parallel runners.

Two GitHub facts shape this. A workflow dispatched with the default GITHUB_TOKEN starts no
run, so the supervisor authenticates `gh` with a PAT (GH_ADMIN_TOKEN). And `gh workflow run`
returns nothing identifying the run, so dispatches are correlated by a unique run-name.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

WORKFLOW = "audit.yaml"


class Dispatcher:
    def __init__(self, *, repo: str, ref: str, target: str, run_root: Path, console,
                 poll=12, timeout=2400, max_workers=8, concurrency=4,
                 sleep=time.sleep, now=time.monotonic):
        self.repo, self.ref, self.target = repo, ref, target
        self.run_root, self.console = run_root, console
        self.poll, self.timeout, self.max_workers = poll, timeout, max_workers
        self.sleep, self.now = sleep, now
        self.runs: list[dict] = []
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(concurrency)

    def _gh(self, args, *, timeout=60, check=True):
        result = subprocess.run(["gh", *args], text=True, capture_output=True,
                                timeout=max(1, timeout), check=False)
        if check and result.returncode:
            raise RuntimeError((result.stderr or "gh failed").strip()[:400])
        return result

    def dispatch(self, args: dict) -> dict:
        task = args.get("task")
        focus = str(args.get("focus", "subtask"))[:60]
        if not isinstance(task, str) or not 4 <= len(task) <= 6000:
            return {"error": "task must be a 4..6000 char subtask description"}
        with self._lock:
            if len(self.runs) >= self.max_workers:
                return {"error": "worker budget exhausted", "dispatched": len(self.runs)}
        with self._slots:
            return self._run(task, focus)

    def _run(self, task: str, focus: str) -> dict:
        task_id = "w" + uuid.uuid4().hex[:12]
        run_name = f"deepaudit worker {task_id}"
        record = {"task_id": task_id, "focus": focus, "status": "dispatched"}
        with self._lock:
            self.runs.append(record)
        self.console.event("DISPATCH", "worker", task_id=task_id, focus=focus)
        deadline = self.now() + self.timeout
        try:
            self._gh(["workflow", "run", WORKFLOW, "--repo", self.repo, "--ref", self.ref,
                      "-f", "mode=worker", "-f", f"target={self.target}",
                      "-f", f"task_id={task_id}", "-f", f"task={task}",
                      "-f", f"focus={focus}", "-f", f"run_name={run_name}"])
            run_id = self._await_run(run_name, deadline)
            record["run_id"] = run_id
            record["url"] = f"https://github.com/{self.repo}/actions/runs/{run_id}"
            self._watch(run_id, deadline)
            payload = self._collect(task_id, run_id, deadline)
            record.update(status="ok", findings=len(payload.get("findings", [])))
            self.console.event("DISPATCH", "worker done", task_id=task_id,
                               findings=record["findings"])
            return {"task_id": task_id, "focus": focus, "run_url": record["url"], **payload}
        except Exception as exc:
            record.update(status="failed", error=str(exc)[:400])
            self.console.event("DISPATCH", "worker failed", task_id=task_id, error=str(exc)[:200])
            return {"task_id": task_id, "focus": focus, "status": "failed", "error": str(exc)[:400]}

    def _await_run(self, run_name: str, deadline: float) -> str:
        while self.now() < deadline:
            self.sleep(self.poll)
            listed = self._gh(["run", "list", "--repo", self.repo, "--workflow", WORKFLOW,
                               "--event", "workflow_dispatch", "--json", "databaseId,displayTitle",
                               "--limit", "100"], check=False)
            try:
                for run in json.loads(listed.stdout or "[]"):
                    if run.get("displayTitle") == run_name:
                        return str(run["databaseId"])
            except ValueError:
                continue
        raise TimeoutError("dispatched worker run never appeared")

    def _watch(self, run_id: str, deadline: float):
        while self.now() < deadline:
            viewed = self._gh(["run", "view", run_id, "--repo", self.repo,
                               "--json", "status,conclusion"], check=False)
            try:
                state = json.loads(viewed.stdout)
            except ValueError:
                self.sleep(self.poll)
                continue
            if state.get("status") == "completed":
                return state.get("conclusion")
            self.sleep(self.poll)
        try:
            self._gh(["run", "cancel", run_id, "--repo", self.repo], check=False)
        finally:
            raise TimeoutError("worker run exceeded the dispatch deadline")

    def _collect(self, task_id: str, run_id: str, deadline: float) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            self._gh(["run", "download", run_id, "--repo", self.repo, "--name",
                      f"worker-{task_id}", "--dir", tmp], timeout=120, check=False)
            path = next(Path(tmp).rglob("worker.json"), None)
            if path is None:
                return {"status": "no_result", "findings": [], "summary": "worker produced no artifact"}
            payload = json.loads(path.read_text(encoding="utf-8")[:4_000_000])
            saved = self.run_root / "workers" / f"{task_id}.json"
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
            return {"status": "ok",
                    "summary": str(payload.get("summary", ""))[:4000],
                    "notes": [str(n)[:600] for n in (payload.get("notes") or [])][:20],
                    "findings": payload.get("findings", [])[:40],
                    "evidence": payload.get("evidence", [])[:60]}
