"""Render the audit result two ways: a GitHub job-summary (Markdown) and a standalone HTML page.

Both are built from the same result dict the supervisor returns. Every value that traces back
to the target or the model — titles, quotes, advisory text — is attacker-influenced, so the
HTML escapes all of it and the Markdown fences code/quotes. Nothing is committed to the repo;
the Markdown goes to $GITHUB_STEP_SUMMARY and the HTML is uploaded as an artifact.
"""
from __future__ import annotations

import html

_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
_ORDER = ("critical", "high", "medium", "low", "info")


def _counts(findings):
    counts = {s: 0 for s in _ORDER}
    for finding in findings:
        counts[finding.get("severity", "info")] = counts.get(finding.get("severity", "info"), 0) + 1
    return counts


def _mdq(text: str) -> str:
    return str(text).replace("`", "ʼ").replace("\n", " ").strip()[:400]


def markdown(result: dict) -> str:
    findings = result.get("findings", [])
    counts = _counts(findings)
    kev = sum(1 for f in findings if f.get("kev"))
    lines = [
        f"## 🛡️ DeepAudit — `{_mdq(result.get('target'))}`", "",
        f"**Status:** {result.get('status', 'unknown')} · "
        f"**Findings:** {len(findings)} · **KEV:** {kev} · "
        f"**Evidence items:** {result.get('evidence_count', 0)} · "
        f"**Workers:** {len(result.get('workers', []))}", "",
        "| " + " | ".join(f"{_BADGE[s]} {s}" for s in _ORDER) + " |",
        "|" + "---|" * len(_ORDER),
        "| " + " | ".join(str(counts[s]) for s in _ORDER) + " |", "",
        "### Summary", "", _mdblock(result.get("summary", "")), "",
    ]
    if findings:
        lines += ["### Findings (prioritized)", ""]
        for finding in findings:
            badge = _BADGE.get(finding.get("severity"), "⚪")
            tags = []
            if finding.get("kev"):
                tags.append("**KEV**")
            if finding.get("cve"):
                tags.append(str(finding["cve"]))
            if finding.get("epss"):
                tags.append(f"EPSS {float(finding['epss']):.2f}")
            verdict = finding.get("verification", "unreviewed")
            suffix = f" — {finding.get('cvss')}" if finding.get("cvss") else ""
            lines.append(f"<details><summary>{badge} <b>{html.escape(_mdq(finding.get('title')))}</b> "
                         f"({finding.get('severity')}{suffix}) · {verdict}"
                         + (f" · {' '.join(tags)}" if tags else "") + "</summary>\n")
            lines.append(f"\n{_mdblock(finding.get('summary', ''))}\n")
            if finding.get("impact"):
                lines.append(f"\n**Impact:** {_mdblock(finding['impact'])}\n")
            if finding.get("reproduction"):
                lines.append(f"\n**Reproduction:**\n\n```\n{_fence(finding['reproduction'])}\n```\n")
            lines.append(f"\n**Evidence** (`{finding.get('evidence_id')}`):\n\n```\n{_fence(finding.get('quote', ''))}\n```\n")
            lines.append(f"\n**Remediation:** {_mdblock(finding.get('remediation', ''))}\n")
            if finding.get("verification_reason"):
                lines.append(f"\n*Review: {_mdblock(finding['verification_reason'])}*\n")
            lines.append("</details>\n")
    else:
        lines += ["_No confirmed findings. This is not a clean bill of health — it reflects only "
                  "what was examined; see limitations._", ""]
    if result.get("rejected"):
        lines += ["", f"_Verifier rejected {len(result['rejected'])} candidate finding(s) as "
                  "false positives or unsupported._"]
    lines += ["", "### Coverage & limitations", "", _mdblock(result.get("limitations")
              or "Absence of a finding is not proof of absence of a problem.")]
    if result.get("workers"):
        lines += ["", "### Parallel workers", ""]
        for w in result["workers"]:
            link = f"[run]({w['url']})" if w.get("url") else ""
            lines.append(f"- `{w.get('focus')}` — {w.get('status')} {link}")
    lines += ["", f"<sub>Model usage: {result.get('usage', {})} · agent: {result.get('agent', {})}</sub>"]
    return "\n".join(lines)


def _mdblock(text: str) -> str:
    text = str(text or "").strip()
    return "\n".join("> " + line for line in text.splitlines()) if text else "> —"


def _fence(text: str) -> str:
    return str(text or "").replace("```", "ʼʼʼ")[:2000]


# ---- HTML ---------------------------------------------------------------------
def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


_TONE = {"critical": "#b3123a", "high": "#c2410c", "medium": "#a16207",
         "low": "#1d4ed8", "info": "#4b5563"}


def _finding_html(f: dict) -> str:
    tone = _TONE.get(f.get("severity"), "#4b5563")
    tags = []
    if f.get("kev"):
        tags.append('<span class="tag" style="background:#b3123a">KEV — exploited in the wild</span>')
    if f.get("cve"):
        tags.append(f'<span class="tag">{_e(f["cve"])}</span>')
    if f.get("epss"):
        tags.append(f'<span class="tag">EPSS {float(f["epss"]):.2f}</span>')
    if f.get("cvss"):
        tags.append(f'<span class="tag">CVSS {_e(f["cvss"])}</span>')
    parts = [f'<article class="finding"><h3><span class="dot" style="background:{tone}"></span>'
             f'{_e(f.get("title"))}</h3>',
             f'<p class="meta"><b style="color:{tone}">{_e(f.get("severity"))}</b> · '
             f'verdict: {_e(f.get("verification"))} · from {_e(f.get("evidence_id"))}</p>']
    if tags:
        parts.append('<p>' + " ".join(tags) + '</p>')
    if f.get("summary"):
        parts.append(f'<p>{_e(f["summary"])}</p>')
    if f.get("impact"):
        parts.append(f'<p><b>Impact:</b> {_e(f["impact"])}</p>')
    if f.get("reproduction"):
        parts.append(f'<p><b>Reproduction:</b></p><pre><code>{_e(f["reproduction"])}</code></pre>')
    parts.append(f'<p><b>Evidence:</b></p><pre><code>{_e(f.get("quote"))}</code></pre>')
    parts.append(f'<p><b>Remediation:</b> {_e(f.get("remediation"))}</p>')
    if f.get("verification_reason"):
        parts.append(f'<p class="review">Review: {_e(f["verification_reason"])}</p>')
    return "\n".join(parts) + "</article>"


def html_page(result: dict) -> str:
    findings = result.get("findings", [])
    counts = _counts(findings)
    chips = "".join(
        f'<div class="chip" style="border-color:{_TONE[s]}"><span style="color:{_TONE[s]}">'
        f'{counts[s]}</span>{s}</div>' for s in _ORDER)
    body = "\n".join(_finding_html(f) for f in findings) or (
        '<p class="note">No confirmed findings. This reflects only what was examined.</p>')
    workers = "".join(
        f'<li><code>{_e(w.get("focus"))}</code> — {_e(w.get("status"))} '
        + (f'<a href="{_e(w["url"])}">run</a>' if w.get("url") else "") + "</li>"
        for w in result.get("workers", []))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeepAudit — {_e(result.get('target'))}</title>
<style>
:root{{color-scheme:light dark}}
body{{font:15px/1.6 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;
background:#fff;color:#111}}
@media(prefers-color-scheme:dark){{body{{background:#0d1117;color:#e6edf3}}
pre,.chip,.finding{{background:#161b22 !important;border-color:#30363d !important}}}}
h1{{margin:0 0 .2rem}} .sub{{color:#6b7280;margin:0 0 1.2rem;word-break:break-all}}
.chips{{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}}
.chip{{border:1px solid #ddd;border-radius:8px;padding:.4rem .8rem;font-size:.85rem;
display:flex;flex-direction:column;align-items:center;min-width:64px}}
.chip span{{font-size:1.4rem;font-weight:700}}
.finding{{border:1px solid #e5e7eb;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}}
.finding h3{{margin:.1rem 0 .4rem;display:flex;align-items:center;gap:.5rem}}
.dot{{width:11px;height:11px;border-radius:50%;display:inline-block}}
.meta{{color:#6b7280;font-size:.85rem;margin:.1rem 0 .6rem}}
.tag{{display:inline-block;background:#374151;color:#fff;border-radius:6px;padding:.1rem .5rem;
font-size:.75rem;margin:.1rem}}
pre{{background:#f6f8fa;border:1px solid #e5e7eb;border-radius:8px;padding:.8rem;overflow-x:auto}}
.review{{color:#6b7280;font-style:italic}} .note{{color:#6b7280}}
footer{{color:#9ca3af;font-size:.8rem;margin-top:2rem;border-top:1px solid #e5e7eb;padding-top:1rem}}
</style></head><body>
<h1>🛡️ DeepAudit report</h1>
<p class="sub">{_e(result.get('target'))} · status: {_e(result.get('status'))} · run {_e(result.get('run_id'))}</p>
<div class="chips">{chips}
<div class="chip"><span>{len(result.get('workers', []))}</span>workers</div>
<div class="chip"><span>{result.get('evidence_count', 0)}</span>evidence</div></div>
<h2>Summary</h2><p>{_e(result.get('summary'))}</p>
<h2>Findings</h2>{body}
<h2>Coverage &amp; limitations</h2><p>{_e(result.get('limitations') or 'Absence of a finding is not proof of absence of a problem.')}</p>
{f'<h2>Parallel workers</h2><ul>{workers}</ul>' if workers else ''}
<footer>Authorized audit · findings are evidence-grounded and verifier-reviewed · a version
match is potentially affected, not confirmed exploitable. Model usage: {_e(result.get('usage'))}</footer>
</body></html>"""
