"""Supervisor entrypoint: lead the audit end to end and deliver a reviewed, prioritized report.

Runs `audit.yaml` in the default `mode=supervisor`. The supervisor is the strong-tier agent.
It acts directly through `run`/`cve_lookup`, fans out independent work to worker runs on their
own runners via `dispatch_subtask`, records grounded findings, runs the adversarial verifier,
and finishes with a report. Output is delivered as the GitHub job summary plus an HTML
artifact — nothing is committed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import prompts, report as report_render, verify
from .agent import AuditState, schema, STRING
from .console import Console
from .dispatch import Dispatcher
from .llm import STRONG, LLMClient, agent_loop
from .target import target_url

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def run_audit(*, target, repo, ref, run_root, client, console,
              enable_dispatch=True, max_steps=60, dangerous=False) -> dict:
    state = AuditState(target, run_root, console, dangerous=dangerous)
    dispatcher = Dispatcher(repo=repo, ref=ref, target=target, run_root=run_root, console=console,
                            dangerous=dangerous)
    captured: dict = {}

    gathered: set[str] = set()

    def _ingest(gathered_map: dict) -> list[dict]:
        out = []
        for task_id, payload in gathered_map.items():
            if task_id in gathered:
                continue
            gathered.add(task_id)
            imported = (state.import_worker(payload, focus=payload.get("focus", "subtask"))
                        if payload.get("status") == "ok" else 0)
            out.append({"task_id": task_id, "focus": payload.get("focus"),
                        "status": payload.get("status"), "summary": payload.get("summary"),
                        "findings_imported": imported, "notes": payload.get("notes", []),
                        "error": payload.get("error")})
        return out

    def spawn_subtask(args: dict) -> dict:
        if not enable_dispatch:
            return {"error": "fan-out disabled (no GH token / local run); do this work with `run` instead"}
        return dispatcher.spawn(args)

    def gather_subtasks(args: dict) -> dict:
        if not enable_dispatch:
            return {"error": "fan-out disabled"}
        return {"results": _ingest(dispatcher.gather(args)["gathered"])}

    def run_verifier(_args: dict) -> dict:
        return verify.run_verifier(state, client, dangerous=dangerous,
                                   log=lambda m: console.agent("verifier", m))

    def finish(args: dict) -> dict:
        if enable_dispatch and dispatcher.pending():
            _ingest(dispatcher.gather({})["gathered"])  # never lose a still-running worker
        pending_mutations = state.pending_mutations()
        if pending_mutations:
            return {"error": "revert all state changes first (confirm_revert) before finishing",
                    "pending_mutations": pending_mutations}
        unreviewed = [f["id"] for f in state.findings if f.get("verification") == "unreviewed"]
        if unreviewed:
            return {"error": "run_verifier first: findings still unreviewed "
                    "(some may have just arrived from workers)", "unreviewed": unreviewed}
        summary = args.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            return {"error": "provide a prioritized summary"}
        captured["summary"] = summary[:8000]
        captured["limitations"] = str(args.get("limitations", ""))[:6000]
        return {"accepted": True}

    tools = dict(state.common_tools("supervisor"))
    tools.update({
        "get_checklist": (schema("Re-read the systematic coverage checklist."),
            lambda _: {"checklist": prompts.CHECKLIST}),
        "record_plan": (schema(
            "Record (or revise) your structured audit plan. Do this early — after quick recon — "
            "and revise it after each wave as evidence changes priorities.",
            {"objective": STRING,
             "surfaces": {"type": "array", "items": STRING, "description": "Hosts/services/tech in scope to cover."},
             "waves": {"type": "array", "items": STRING, "description": "Ordered parallel waves of work."},
             "stop_criteria": STRING}), state.record_plan),
        "spawn_subtask": (schema(
            "Launch a worker on its own runner for an independent subtask and return immediately "
            "(non-blocking). Spawn several at once to scale wide, keep working, then collect them. "
            "Give a crisp, self-contained assignment.",
            {"focus": STRING, "task": STRING}, ("focus", "task")), spawn_subtask),
        "subtasks_status": (schema("Check which spawned workers are running vs finished."),
            lambda _: dispatcher.poll()),
        "gather_subtasks": (schema(
            "Collect finished workers (blocks until the named ones finish; omit task_ids for all). "
            "Their grounded findings are imported into your findings.",
            {"task_ids": {"type": "array", "items": STRING}}), gather_subtasks),
        "run_verifier": (schema("Adversarially review every recorded finding before finishing."),
            run_verifier),
        "finish": (schema("Finish with a prioritized report summary and honest coverage gaps. "
            "Requires all findings reviewed by run_verifier.",
            {"summary": STRING, "limitations": STRING}, ("summary",)), finish),
    })

    task = (f"Audit this authorized target end to end: {target}\n\n"
            "This is a FULL scan: no scope narrowing, no partial coverage by default. If the "
            "target given is a specific subdomain, that does not limit you to it — enumerate and "
            "cover its registrable root domain AND every subdomain of that root you can "
            "discover, not just the host named in the target. Treat the whole domain footprint "
            "as in scope.\n\n"
            "Plan from the checklist, recon and fingerprint first, then go deep. Look up CVEs on "
            "every version you find. Fan out independent work to workers. Record grounded findings, "
            "run the verifier, then finish with a prioritized report.")
    outcome = agent_loop(client, prompts.supervisor_prompt(dangerous), task, tools, tier=STRONG,
                         max_steps=max_steps, require_terminal=True, terminal_tools=("finish",),
                         log=lambda m: console.agent("supervisor", m))

    confirmed = [f for f in state.findings if f.get("verification") != "rejected"]
    confirmed.sort(key=lambda f: (bool(f.get("kev")), SEVERITY_RANK.get(f["severity"], 0),
                                  f.get("epss") or 0.0), reverse=True)
    complete = outcome["stopped"] == "finish"
    return {
        "target": target, "run_id": run_root.name,
        "status": "complete" if complete else "incomplete",
        "dangerous": dangerous,
        "summary": captured.get("summary") or "The audit ended before a report was synthesized; "
                   "the evidence and findings collected so far are included.",
        "limitations": captured.get("limitations", ""),
        "findings": confirmed,
        "rejected": [f for f in state.findings if f.get("verification") == "rejected"],
        "notes": state.notes,
        "plan": state.plan,
        "hypotheses": state.hypotheses,
        "resources": state.resources,
        "components": state.components,
        "mutations": state.mutations,
        "workers": list(dispatcher.records.values()),
        "evidence_count": len(state.evidence.index()),
        "usage": getattr(client, "usage", {}),
        "agent": {"steps": outcome["steps"], "stopped": outcome["stopped"]},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=os.getenv("TARGET", ""))
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--ref", default=os.getenv("GITHUB_REF_NAME", "main"))
    parser.add_argument("--run-id", default=os.getenv("GITHUB_RUN_ID", "local"))
    parser.add_argument("--out-dir", default="audits")
    parser.add_argument("--dangerous", default=os.getenv("DANGEROUS", ""))
    args = parser.parse_args(argv)
    try:
        target = target_url(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    dangerous = str(args.dangerous).strip().lower() in ("1", "true", "yes", "on")

    run_root = Path(args.out_dir) / f"audit-{args.run_id}"
    run_root.mkdir(parents=True, exist_ok=True)
    console = Console(run_root / "events.jsonl")
    console.event("AUDIT", "started", target=target, repo=args.repo, dangerous=dangerous)
    if dangerous:
        console.event("AUDIT", "DANGEROUS MODE ON — reversible state-changing PoCs are permitted "
                      "and must be reverted before the run can finish")
    client = LLMClient()
    enable_dispatch = bool(args.repo) and bool(os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN"))
    if not enable_dispatch:
        console.event("AUDIT", "fan-out disabled (no repo/token); supervisor works in-runner only")

    result = run_audit(target=target, repo=args.repo, ref=args.ref, run_root=run_root,
                       client=client, console=console, enable_dispatch=enable_dispatch,
                       dangerous=dangerous)

    (run_root / "report.json").write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    (run_root / "report.html").write_text(report_render.html_page(result), encoding="utf-8")
    summary_md = report_render.markdown(result)
    (run_root / "report.md").write_text(summary_md, encoding="utf-8")
    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as stream:
            stream.write(summary_md + "\n")
    console.event("AUDIT", result["status"], findings=len(result["findings"]),
                  evidence=result["evidence_count"], workers=len(result["workers"]))
    unresolved = [m for m in result.get("mutations", []) if m.get("status") == "revert_failed"]
    if unresolved:
        console.event("AUDIT", "CRITICAL: state changes left unreverted on the target — manual "
                      "cleanup required", mutations=[m["id"] for m in unresolved])
    return 0 if result["status"] == "complete" and not unresolved else 1


if __name__ == "__main__":
    raise SystemExit(main())
