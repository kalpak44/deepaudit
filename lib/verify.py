"""The verifier pass: an adversarial reviewer that re-checks every finding before it ships.

False positives are the failure mode of automated scanning. This runs a skeptical agent on
the strong model tier with read-only access to the findings and their evidence. For each
finding it must return a verdict — supported, needs_manual_review, or rejected — and may
correct the severity. Only non-rejected findings reach the report. This is grounding's
qualitative complement: grounding proves the quote is real; verification judges whether the
interpretation and impact are.
"""
from __future__ import annotations

from . import prompts
from .agent import schema, STRING
from .evidence import SEVERITIES
from .llm import STRONG, agent_loop


def run_verifier(state, client, *, max_steps=40, log=lambda _: None) -> dict:
    unreviewed = [f for f in state.findings if f.get("verification") == "unreviewed"]
    if not unreviewed:
        return {"reviewed": 0, "stopped": "nothing_to_review"}
    captured = {"done": False}

    def review(args: dict) -> dict:
        finding = next((f for f in state.findings if f["id"] == args.get("id")), None)
        verdict = args.get("verdict")
        reason = args.get("reason")
        if finding is None or verdict not in ("supported", "needs_manual_review", "rejected") \
                or not isinstance(reason, str) or not reason.strip():
            return {"error": "provide an existing finding id, a valid verdict and a reason"}
        with state._lock:
            finding["verification"] = verdict
            finding["verification_reason"] = reason[:1000]
            severity = args.get("severity")
            if severity in SEVERITIES:
                finding["severity"] = severity
            state.save()
        remaining = [f["id"] for f in state.findings if f.get("verification") == "unreviewed"]
        return {"accepted": True, "id": finding["id"], "verdict": verdict, "remaining": remaining}

    def complete(_args: dict) -> dict:
        if any(f.get("verification") == "unreviewed" for f in state.findings):
            return {"error": "review every finding first"}
        captured["done"] = True
        return {"accepted": True}

    tools = {
        "list_findings": (schema("List all findings with their current verdicts."),
            lambda _: {"findings": state.findings}),
        "read_evidence": (schema("Read a finding's cited evidence in pages.",
            {"evidence_id": STRING, "offset": {"type": "integer"}}, ("evidence_id",)),
            lambda a: state.evidence.read(a.get("evidence_id"), a.get("offset", 0))),
        "review_finding": (schema(
            "Record a verdict for one finding; optionally correct its severity.",
            {"id": STRING, "verdict": {"type": "string",
             "enum": ["supported", "needs_manual_review", "rejected"]},
             "reason": STRING, "severity": {"type": "string", "enum": list(SEVERITIES)}},
            ("id", "verdict", "reason")), review),
        "complete_session": (schema("Finish once every finding has a verdict."), complete),
    }
    task = ("Review these findings adversarially. Try to refute each using only its cited "
            "evidence, then record a verdict. Findings:\n"
            + _digest(state.findings))
    outcome = agent_loop(client, prompts.VERIFIER, task, tools, tier=STRONG,
                         max_steps=max_steps, require_terminal=True,
                         terminal_tools=("complete_session",), log=log)
    for finding in state.findings:  # anything the reviewer never reached is not silently trusted
        finding.setdefault("verification", "unreviewed")
        if finding["verification"] == "unreviewed":
            finding["verification"] = "needs_manual_review"
            finding["verification_reason"] = "verifier did not reach this finding"
    state.save()
    return {"reviewed": len(unreviewed), "stopped": outcome["stopped"],
            "verdicts": {v: sum(1 for f in state.findings if f.get("verification") == v)
                         for v in ("supported", "needs_manual_review", "rejected")}}


def _digest(findings) -> str:
    import json
    return json.dumps([{k: f.get(k) for k in ("id", "title", "severity", "summary",
                        "evidence_id", "quote", "cve")} for f in findings], ensure_ascii=True, indent=1)
