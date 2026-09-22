"""Worker entrypoint: run one focused subtask autonomously and hand back a grounded result.

Dispatched by the supervisor as `audit.yaml` in `mode=worker`. It builds its own audit state,
installs and runs the tools its assignment needs, records grounded findings, and writes
`worker.json` (uploaded as artifact `worker-<task_id>`). The supervisor re-grounds those
findings in its own evidence store, so the single grounding gate stays authoritative.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import prompts
from .agent import AuditState, schema, STRING
from .console import Console
from .llm import FAST, LLMClient, agent_loop
from .target import target_url


def run_worker(*, target, task, focus, run_root, client, console, max_steps=28) -> dict:
    state = AuditState(target, run_root, console)
    captured: dict = {}

    def complete(args: dict) -> dict:
        summary = args.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            return {"error": "provide a non-empty summary of what you ran and found"}
        captured["summary"] = summary[:4000]
        captured["status"] = args.get("status", "completed")
        return {"accepted": True}

    tools = dict(state.common_tools(f"worker:{focus}"))
    tools["complete_session"] = (schema(
        "Finish the subtask with a concise summary of what you ran, found and could not cover.",
        {"summary": STRING, "status": {"type": "string",
         "enum": ["completed", "blocked", "not_applicable"], "default": "completed"}},
        ("summary",)), complete)

    outcome = agent_loop(client, prompts.worker(focus, task),
                         f"Target: {target}\nFocus: {focus}\n\nBegin your assignment.",
                         tools, tier=FAST, max_steps=max_steps, require_terminal=True,
                         terminal_tools=("complete_session",),
                         log=lambda m: console.agent(f"worker:{focus}", m))

    cited = [f["evidence_id"] for f in state.findings]
    result = {
        "task_id": run_root.name, "focus": focus,
        "status": captured.get("status", "incomplete"),
        "summary": captured.get("summary", "Worker ended before summarizing."),
        "findings": state.findings,
        "evidence": state.evidence.export(cited),
        "notes": [n["message"] for n in state.notes],
        "agent": {"steps": outcome["steps"], "stopped": outcome["stopped"]},
    }
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=os.getenv("TARGET", ""))
    parser.add_argument("--task", default=os.getenv("TASK", ""))
    parser.add_argument("--focus", default=os.getenv("FOCUS", "subtask"))
    parser.add_argument("--task-id", default=os.getenv("TASK_ID", "local"))
    parser.add_argument("--out-dir", default="audits")
    parser.add_argument("--out", default="worker.json")
    args = parser.parse_args(argv)
    try:
        target = target_url(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if not args.task.strip():
        parser.error("--task (or $TASK) is required")

    run_root = Path(args.out_dir) / f"worker-{args.task_id}"
    run_root.mkdir(parents=True, exist_ok=True)
    console = Console(run_root / "events.jsonl")
    console.event("WORKER", "started", focus=args.focus, target=target)
    client = LLMClient()
    result = run_worker(target=target, task=args.task, focus=args.focus,
                        run_root=run_root, client=client, console=console)
    result["task_id"] = args.task_id
    Path(args.out).write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    (run_root / "worker.json").write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    console.event("WORKER", result["status"], findings=len(result["findings"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
