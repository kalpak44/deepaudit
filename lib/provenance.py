"""The one deterministic gate in an otherwise agent-driven system.

Everything else here is prompts and tools; this is the check that keeps the result honest.
The root agent composes a report, but it may only report findings that a sub-agent actually
produced. `check` verifies that every finding in the report carries a `task_id` naming a
stored task result, and that a matching finding really exists in that result. A finding the
model invented — with no task behind it, or citing a task that never found it — is rejected,
not trusted. This is the descendant of the old design's rule: the model plans and explains,
but cannot conjure evidence.
"""
from __future__ import annotations

import json
from pathlib import Path


def _load_tasks(run_root: Path) -> dict[str, dict]:
    tasks: dict[str, dict] = {}
    tasks_dir = run_root / "tasks"
    if not tasks_dir.is_dir():
        return tasks
    for path in sorted(tasks_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                tasks[path.stem] = payload
        except ValueError:
            continue
    return tasks


def _finding_keys(task_result: dict) -> set[str]:
    keys: set[str] = set()
    for finding in task_result.get("findings", []) or []:
        if isinstance(finding, dict):
            identifier = finding.get("id") or finding.get("title") or finding.get("summary")
            if isinstance(identifier, str) and identifier.strip():
                keys.add(identifier.strip().lower())
    return keys


def check(report: dict, run_root: Path) -> dict:
    """Return {ok, grounded, rejected, findings}. `report` is the root agent's output."""
    tasks = _load_tasks(run_root)
    task_keys = {task_id: _finding_keys(result) for task_id, result in tasks.items()}
    grounded, rejected = [], []
    for finding in report.get("findings", []) or []:
        if not isinstance(finding, dict):
            rejected.append({"reason": "not_an_object", "finding": str(finding)[:120]})
            continue
        task_id = finding.get("task_id")
        identifier = finding.get("id") or finding.get("title") or finding.get("summary")
        key = identifier.strip().lower() if isinstance(identifier, str) else ""
        if task_id not in tasks:
            rejected.append({"reason": "unknown_task", "task_id": task_id, "id": identifier})
        elif key and key in task_keys.get(task_id, set()):
            # Use the recorded observation, never model-rewritten severity/evidence.
            original = next(f for f in tasks[task_id].get("findings", [])
                            if isinstance(f, dict) and str(f.get("id") or f.get("title") or f.get("summary") or "").strip().lower() == key)
            grounded.append({**original, "task_id": task_id})
        else:
            rejected.append({"reason": "not_in_task_result", "task_id": task_id,
                             "id": identifier})
    return {"ok": not rejected, "grounded": grounded, "rejected": rejected,
            "tasks_seen": sorted(tasks), "counts": {"grounded": len(grounded),
                                                    "rejected": len(rejected)}}
