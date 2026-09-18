"""Root entrypoint: the tech-lead agent that orchestrates an audit to completion.

Invoked by audit-root.yml with one input, the target. Root reads roles/root/role.md, sees
the roster of dispatchable roles, and drives the audit with three tools: list_roles,
dispatch_role (start a role as a workflow and wait for its typed result), and finish (hand
back the assembled report). It loops until it calls finish or hits its step budget.

Root proposes the report; it does not get the last word on what is true. `provenance.check`
rejects any finding root reports that no dispatched task actually produced, and only the
grounded findings reach the rendered report.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import report as report_render
from . import provenance
from .deepseek import DeepSeekClient, agent_loop
from .orchestrator import Orchestrator
from .roles import list_roles, role_prompt

LIST_SCHEMA = {
    "description": "List the sub-agent roles you can dispatch, with what each does.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}
DISPATCH_SCHEMA = {
    "description": ("Dispatch one sub-agent role as a parallel workflow and wait for its "
                    "typed result. Use only a role from list_roles."),
    "parameters": {"type": "object", "properties": {
        "role": {"type": "string"},
        "target": {"type": "string"},
        "params": {"type": "object"},
    }, "required": ["role", "target"]},
}
FINISH_SCHEMA = {
    "description": ("Finish the audit. Provide the report. Every finding MUST carry the "
                    "task_id of the sub-agent task that produced it; ungrounded findings "
                    "are rejected."),
    "parameters": {"type": "object", "properties": {
        "summary": {"type": "string"},
        "limitations": {"type": "string"},
        "findings": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "id": {"type": "string"},
                "title": {"type": "string"},
                "severity": {"type": "string"},
                "summary": {"type": "string"},
                "evidence": {},
            },
            "required": ["task_id", "title"],
        }},
    }, "required": ["summary", "findings"]},
}


def run(target: str, *, repo: str, ref: str, run_root: Path, client,
        orchestrator, max_steps: int = 20) -> dict:
    captured: dict = {}

    def do_list(_args: dict) -> dict:
        return {"roles": list_roles()}

    def do_finish(args: dict) -> dict:
        captured["report"] = {
            "summary": str(args.get("summary", ""))[:6000],
            "limitations": str(args.get("limitations", ""))[:4000],
            "findings": [f for f in (args.get("findings") or []) if isinstance(f, dict)][:200],
        }
        return {"received": True}

    tools = {
        "list_roles": (LIST_SCHEMA, do_list),
        "dispatch_role": (DISPATCH_SCHEMA, orchestrator.dispatch),
        "finish": (FINISH_SCHEMA, do_finish),
    }
    task = ("Audit this authorized target end to end: " + target + "\n\n"
            "Call list_roles first. Then dispatch the roles you need — you may dispatch "
            "several and use their results to decide what to do next. When you have enough "
            "evidence, call finish with a report whose every finding cites the task_id that "
            "produced it. Do not report anything a task did not return.")
    outcome = agent_loop(client, role_prompt("root"), task, tools,
                         max_steps=max_steps, log=lambda m: print(m, file=sys.stderr))
    report = captured.get("report", {"summary": "", "findings": [],
                                     "limitations": "The audit ended without a report."})
    prov = provenance.check(report, run_root)
    return {"report": report, "provenance": prov, "plan": orchestrator.dispatched,
            "agent": {"steps": outcome["steps"], "stopped": outcome["stopped"],
                      "usage": getattr(client, "usage", {})}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF_NAME", "main"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    parser.add_argument("--out-dir", default="audits")
    args = parser.parse_args(argv)
    if not args.repo:
        print("Set --repo or GITHUB_REPOSITORY", file=sys.stderr)
        return 2

    run_root = Path(args.out_dir) / f"root-{args.run_id}"
    run_root.mkdir(parents=True, exist_ok=True)
    client = DeepSeekClient()
    orchestrator = Orchestrator(repo=args.repo, ref=args.ref, run_root=run_root)

    result = run(args.target, repo=args.repo, ref=args.ref, run_root=run_root,
                 client=client, orchestrator=orchestrator)
    (run_root / "report.json").write_text(
        json.dumps(result["report"], ensure_ascii=False, indent=2), encoding="utf-8")
    (run_root / "provenance.json").write_text(
        json.dumps(result["provenance"], ensure_ascii=False, indent=2), encoding="utf-8")
    page = report_render.render(target=args.target, run_id=run_root.name,
                                report=result["report"], provenance=result["provenance"],
                                plan=result["plan"])
    (run_root / "report.html").write_text(page, encoding="utf-8")

    grounded = result["provenance"]["counts"]["grounded"]
    rejected = result["provenance"]["counts"]["rejected"]
    print(f"Report: {run_root / 'report.html'}")
    print(f"Tasks dispatched: {len(result['plan'])}")
    print(f"Findings grounded: {grounded} | rejected: {rejected}")
    # A report the orchestrator could not ground is not a clean run.
    return 0 if grounded or not result["report"]["findings"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
