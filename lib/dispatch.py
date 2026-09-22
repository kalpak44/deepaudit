"""Autonomous, asynchronous horizontal fan-out: launch worker runs and collect them as they land.

Scaling wide means many subtasks running on separate runners at once. `spawn` dispatches a
worker run and returns immediately with a task_id — a background thread then watches the run
and collects its `worker-<task_id>` artifact. `poll` reports live status; `gather` blocks only
for the specific workers you ask for (or all). So the supervisor can fire off a wave of
workers, keep doing its own recon, and ingest each result the moment it is ready instead of
waiting on them one at a time.

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
                 poll=12, timeout=3000, max_workers=8, concurrency=6,
                 sleep=time.sleep, now=time.monotonic):
        self.repo, self.ref, self.target = repo, ref, target
        self.run_root, self.console = run_root, console
        self.poll, self.timeout, self.max_workers = poll, timeout, max_workers
        self.sleep, self.now = sleep, now
        self.records: dict[str, dict] = {}   # task_id -> {task_id, focus, status, run_id, url}
        self.results: dict[str, dict] = {}    # task_id -> collected payload (set when finished)
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(concurrency)

    # -- public tool surface ---------------------------------------------------
    def spawn(self, args: dict) -> dict:
        task = args.get("task")
        focus = str(args.get("focus", "subtask"))[:60]
        if not isinstance(task, str) or not 4 <= len(task) <= 6000:
            return {"error": "task must be a 4..6000 char subtask description"}
        with self._lock:
            if len(self.records) >= self.max_workers:
                return {"error": "worker budget exhausted", "spawned": len(self.records)}
            task_id = "w" + uuid.uuid4().hex[:12]
            record = {"task_id": task_id, "focus": focus, "status": "running"}
            self.records[task_id] = record
        thread = threading.Thread(target=self._run_bg, args=(task_id, task, focus), daemon=True)
        self._threads[task_id] = thread
        thread.start()
        self.console.event("SPAWN", "worker", task_id=task_id, focus=focus)
        return {"task_id": task_id, "focus": focus, "status": "running",
                "note": "Running on its own runner. Keep working; call gather_subtasks to collect it."}

    def poll(self, _args=None) -> dict:
        with self._lock:
            return {"workers": [{k: r.get(k) for k in ("task_id", "focus", "status", "url")}
                                for r in self.records.values()],
                    "running": sum(1 for r in self.records.values() if r["status"] == "running"),
                    "done": sorted(self.results)}

    def gather(self, args: dict | None = None) -> dict:
        """Block until the requested (or all) spawned workers finish; return collected payloads."""
        requested = (args or {}).get("task_ids")
        with self._lock:
            targets = [t for t in (requested or list(self.records)) if t in self.records]
        deadline = self.now() + self.timeout
        collected = {}
        for task_id in targets:
            thread = self._threads.get(task_id)
            if thread is not None:
                thread.join(timeout=max(1, deadline - self.now()))
            collected[task_id] = self.results.get(
                task_id, {"status": "timeout", "focus": self.records.get(task_id, {}).get("focus"),
                          "findings": [], "evidence": [], "notes": []})
        return {"gathered": collected}

    def pending(self) -> list[str]:
        with self._lock:
            return [t for t, r in self.records.items() if r["status"] == "running"]

    # -- background worker lifecycle -------------------------------------------
    def _run_bg(self, task_id: str, task: str, focus: str):
        record = self.records[task_id]
        run_name = f"deepaudit worker {task_id}"
        deadline = self.now() + self.timeout
        try:
            with self._slots:
                self._gh(["workflow", "run", WORKFLOW, "--repo", self.repo, "--ref", self.ref,
                          "-f", "mode=worker", "-f", f"target={self.target}",
                          "-f", f"task_id={task_id}", "-f", f"task={task}",
                          "-f", f"focus={focus}", "-f", f"run_name={run_name}"])
                run_id = self._await_run(run_name, deadline)
                record["run_id"] = run_id
                record["url"] = f"https://github.com/{self.repo}/actions/runs/{run_id}"
                self._watch(run_id, deadline)
                payload = self._collect(task_id, run_id)
            self.results[task_id] = {"status": "ok", "focus": focus, **payload}
            record["status"] = "ok"
            self.console.event("SPAWN", "worker done", task_id=task_id,
                               findings=len(payload.get("findings", [])))
        except Exception as exc:
            self.results[task_id] = {"status": "failed", "focus": focus, "error": str(exc)[:400],
                                     "findings": [], "evidence": [], "notes": []}
            record["status"] = "failed"
            self.console.event("SPAWN", "worker failed", task_id=task_id, error=str(exc)[:200])

    def _gh(self, args, *, timeout=60, check=True):
        result = subprocess.run(["gh", *args], text=True, capture_output=True,
                                timeout=max(1, timeout), check=False)
        if check and result.returncode:
            raise RuntimeError((result.stderr or "gh failed").strip()[:400])
        return result

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
        self._gh(["run", "cancel", run_id, "--repo", self.repo], check=False)
        raise TimeoutError("worker run exceeded the dispatch deadline")

    def _collect(self, task_id: str, run_id: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            self._gh(["run", "download", run_id, "--repo", self.repo, "--name",
                      f"worker-{task_id}", "--dir", tmp], timeout=120, check=False)
            path = next(Path(tmp).rglob("worker.json"), None)
            if path is None:
                return {"summary": "worker produced no artifact", "findings": [],
                        "evidence": [], "notes": []}
            payload = json.loads(path.read_text(encoding="utf-8")[:4_000_000])
            saved = self.run_root / "workers" / f"{task_id}.json"
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
            return {"summary": str(payload.get("summary", ""))[:4000],
                    "notes": [str(n)[:600] for n in (payload.get("notes") or [])][:20],
                    "findings": payload.get("findings", [])[:40],
                    "evidence": payload.get("evidence", [])[:60],
                    "url": f"https://github.com/{self.repo}/actions/runs/{run_id}"}
