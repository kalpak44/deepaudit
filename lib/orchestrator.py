"""Root's dispatch tool: run a sub-agent role as a GitHub Actions workflow and wait.

This is the only way root acts on the world, and it is deliberately narrow. The model may
dispatch a role from the known roster with a target and a JSON parameter blob — it cannot
name an arbitrary workflow, pass arbitrary CLI flags, or run a shell. Each dispatch mints a
task_id, starts `role-<name>.yml` with `gh`, waits for that run, and downloads its
`result-<task_id>` artifact as typed JSON.

Two GitHub facts shape this. A workflow dispatched with the default GITHUB_TOKEN starts no
run at all, so root must authenticate `gh` with a PAT (GH_ADMIN_TOKEN). And `gh workflow
run` returns nothing identifying the run, so the dispatch is correlated by a run-name that
carries the task_id rather than by a returned id.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from .roles import role_names

_TASK_RE = re.compile(r"^[a-z0-9]{6,32}$")
_PARAM_KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")
DISPATCH_POLL_SECONDS = 10
DISPATCH_TIMEOUT_SECONDS = 1200


class DispatchError(RuntimeError):
    pass


def _gh(args: list[str], *, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(["gh", *args], capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DispatchError("gh invocation failed or timed out") from exc
    if check and result.returncode:
        raise DispatchError(f"gh {args[0]} failed: {result.stderr.strip()[:300]}")
    return result


def _validate_params(params: dict) -> str:
    if not isinstance(params, dict):
        raise DispatchError("params must be an object")
    blob = json.dumps(params, ensure_ascii=True)
    if len(blob) > 4000:
        raise DispatchError("params blob is too large")
    for key in params:
        if not isinstance(key, str) or not _PARAM_KEY_RE.fullmatch(key):
            raise DispatchError(f"invalid param key: {key!r}")
    return blob


class Orchestrator:
    """Holds the run context (repo, ref, id source) and exposes dispatch as a tool."""

    def __init__(self, *, repo: str, ref: str, run_root: Path,
                 poll: int = DISPATCH_POLL_SECONDS, timeout: int = DISPATCH_TIMEOUT_SECONDS,
                 sleep=time.sleep, now=time.monotonic, counter=None):
        self.repo = repo
        self.ref = ref
        self.run_root = run_root
        self.poll = poll
        self.timeout = timeout
        self._sleep = sleep
        self._now = now
        self._counter = counter if counter is not None else _incrementing()
        self.dispatched: list[dict] = []

    def _task_id(self) -> str:
        return f"t{next(self._counter):02d}{_short()}"

    def dispatch(self, args: dict) -> dict:
        role = args.get("role")
        target = args.get("target")
        params = args.get("params", {})
        if role not in role_names():
            return {"error": "unknown_role", "known_roles": sorted(role_names())}
        if not isinstance(target, str) or not target:
            return {"error": "target must be a non-empty string"}
        try:
            params_blob = _validate_params(params)
        except DispatchError as exc:
            return {"error": str(exc)}
        task_id = self._task_id()
        run_name = f"deepaudit {role} {task_id}"
        _gh(["workflow", "run", f"role-{role}.yml", "--repo", self.repo, "--ref", self.ref,
             "-f", f"task_id={task_id}", "-f", f"target={target}",
             "-f", f"params={params_blob}", "-f", f"run_name={run_name}"])
        record = {"task_id": task_id, "role": role, "target": target}
        self.dispatched.append(record)
        run_id = self._await_run(run_name)
        result = self._collect(task_id, run_id)
        return {"task_id": task_id, "role": role, **result}

    def _await_run(self, run_name: str) -> str:
        """Find the dispatched run by its unique name, then wait for it to finish."""
        deadline = self._now() + self.timeout
        run_id = None
        while self._now() < deadline and run_id is None:
            self._sleep(self.poll)
            listing = _gh(["run", "list", "--repo", self.repo, "--json",
                           "databaseId,displayTitle,status", "--limit", "40"], check=False)
            try:
                for run in json.loads(listing.stdout or "[]"):
                    if run.get("displayTitle") == run_name:
                        run_id = str(run["databaseId"])
                        break
            except ValueError:
                continue
        if run_id is None:
            raise DispatchError(f"dispatched run never appeared: {run_name}")
        _gh(["run", "watch", run_id, "--repo", self.repo, "--exit-status"],
            timeout=self.timeout, check=False)
        return run_id

    def _collect(self, task_id: str, run_id: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            download = _gh(["run", "download", run_id, "--repo", self.repo,
                            "--name", f"result-{task_id}", "--dir", tmp], check=False)
            if download.returncode:
                return {"status": "no_result", "run_id": run_id,
                        "detail": "the role produced no result artifact"}
            result_file = next(Path(tmp).rglob("result.json"), None)
            if result_file is None:
                return {"status": "no_result", "run_id": run_id}
            try:
                payload = json.loads(result_file.read_text(encoding="utf-8"))
            except ValueError:
                return {"status": "bad_result", "run_id": run_id}
            # Persist each sub-agent result so the report's provenance can be checked.
            saved = self.run_root / "tasks" / f"{task_id}.json"
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                             encoding="utf-8")
            return {"status": "ok", "run_id": run_id, "result": payload}


def _incrementing():
    value = 0
    while True:
        value += 1
        yield value


def _short() -> str:
    # A short non-random suffix keeps run names unique without needing entropy that would
    # break resumability; the counter already guarantees per-run uniqueness.
    return "x"
