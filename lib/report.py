"""Fill templates/report.template.html from the grounded report.

The template is the editable artifact; this only substitutes escaped values into it. No
value from a sub-agent or the model is ever placed in the page unescaped, because findings
carry attacker-influenced strings (a target's own markup, an advisory summary).
"""
from __future__ import annotations

import html
import json
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "report.template.html"

_TONE = {"critical": "high", "high": "high", "medium": "mid", "moderate": "mid",
         "low": "low", "info": "muted", "informational": "muted"}


def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _tag(label) -> str:
    tone = _TONE.get(str(label).lower(), "muted")
    return f'<span class="tag t-{tone}" style="color:var(--{tone})">{_esc(label)}</span>'


def _findings_html(findings: list[dict]) -> str:
    if not findings:
        return ('<p class="note">No grounded findings were reported. This is not a clean '
                'bill of security — it reflects only what the dispatched roles examined.</p>')
    blocks = []
    for finding in findings:
        title = finding.get("title") or finding.get("id") or "finding"
        block = [f"<h3>{_esc(title)}</h3>",
                 "<p>Severity: " + _tag(finding.get("severity", "unknown"))
                 + f" &middot; from task <code>{_esc(finding.get('task_id'))}</code></p>"]
        if finding.get("summary"):
            block.append(f"<p>{_esc(finding['summary'])}</p>")
        if finding.get("remediation"):
            block.append(f"<p><strong>Remediation:</strong> {_esc(finding['remediation'])}</p>")
        if finding.get("verification"):
            block.append(f"<p><strong>Review:</strong> {_esc(finding['verification'])} — {_esc(finding.get('verification_reason'))}</p>")
        if finding.get("evidence"):
            block.append("<pre><code>"
                         + _esc(json.dumps(finding["evidence"], indent=2)) + "</code></pre>")
        blocks.append("\n".join(block))
    return "\n".join(blocks)


def _rows(pairs: list[tuple[str, str]]) -> str:
    body = "".join(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in pairs)
    return f"<table><tbody>{body}</tbody></table>"


def _run_link(step: dict) -> str:
    url = step.get("url", "")
    if isinstance(url, str) and url.startswith("https://github.com/"):
        return f'<a href="{_esc(url)}">{_esc(step.get("run_id", "View run"))}</a>'
    return ""


def render(*, target: str, run_id: str, report: dict, provenance: dict,
           plan: list[dict]) -> str:
    grounded = provenance["grounded"]
    summary = _rows([
        ("Audit status", _esc(report.get("status", "unspecified"))),
        ("Findings reported", str(len(report.get("findings", []) or []))),
        ("Findings grounded", str(provenance["counts"]["grounded"])),
        ("Findings rejected", str(provenance["counts"]["rejected"])),
        ("Workflow tasks", str(len(plan))),
    ])
    if report.get("summary"):
        summary += f'<p>{_esc(report["summary"])}</p>'
    coverage = report.get("coverage", {})
    if coverage:
        summary += "<h3>Coverage</h3><table><thead><tr><th>Employee</th><th>Status</th><th>Result / limitations</th></tr></thead><tbody>"
        for name, state in coverage.items():
            summary += (f"<tr><td>{_esc(name)}</td><td>{_esc(state.get('status'))}</td>"
                        f"<td>{_esc(state.get('summary'))}<br>{_esc(state.get('limitations'))}</td></tr>")
        summary += "</tbody></table>"

    plan_rows = "".join(
        f"<tr><td><code>{_esc(step.get('task_id'))}</code></td>"
        f"<td>{_esc(step.get('employee', step.get('role')))}</td>"
        f"<td>{_esc(step.get('tool'))}</td><td>{_esc(step.get('status'))}</td>"
        f"<td>{_esc(step.get('target'))}</td><td>{_run_link(step)}</td></tr>"
        for step in plan)
    plan_html = (f"<table><thead><tr><th>Task</th><th>Employee</th><th>Tool</th><th>Status</th><th>Target</th><th>Workflow</th></tr></thead>"
                 f"<tbody>{plan_rows}</tbody></table>" if plan
                 else '<p class="note">No sub-agent was dispatched.</p>')

    if provenance["rejected"]:
        prov = ('<p class="note">Rejected (reported without a matching task result):</p>'
                "<pre><code>" + _esc(json.dumps(provenance["rejected"], indent=2))
                + "</code></pre>")
    else:
        prov = '<p>All reported findings match saved task results. Evidence linkage does not prove exploitability; review verdicts describe remaining uncertainty.</p>'

    limitations = report.get("limitations") or (
        "This audit reflects only the roles the orchestrator chose to run and what their "
        "tools observed. Absence of a finding is not proof of absence of a problem.")

    page = TEMPLATE.read_text(encoding="utf-8")
    for token, value in {
        "{{TARGET}}": _esc(target), "{{RUN_ID}}": _esc(run_id), "{{SUMMARY}}": summary,
        "{{FINDINGS}}": _findings_html(grounded), "{{PLAN}}": plan_html,
        "{{PROVENANCE}}": prov, "{{LIMITATIONS}}": _esc(limitations),
    }.items():
        page = page.replace(token, value)
    return page
