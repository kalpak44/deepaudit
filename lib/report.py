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


# Ownership/attribution fields, in report order: (key, label).
_ATTR_FIELDS = [
    ("organization", "Organization"), ("domain", "Domain"),
    ("registrant_org", "Registrant org"), ("registrant_name", "Registrant name"),
    ("registrant_email", "Registrant email"), ("registrant_country", "Registrant country"),
    ("registrar", "Registrar"), ("created", "Created"), ("updated", "Updated"),
    ("expires", "Expires"), ("dnssec", "DNSSEC"), ("hosting_provider", "Hosting"),
    ("asn", "ASN"), ("ip_country", "IP country"), ("reverse_dns", "Reverse DNS"),
    ("cdn_waf", "CDN / WAF"), ("cert_issuer", "Cert issuer"),
    ("cert_subject_org", "Cert subject org"), ("notes", "Notes"),
]
_ATTR_LISTS = [
    ("nameservers", "Nameservers"), ("ip_addresses", "IP addresses"),
    ("cert_sans", "Cert SANs"), ("emails", "Emails"), ("phones", "Phones"),
    ("addresses", "Addresses"), ("social", "Social"), ("related_domains", "Related domains"),
    ("subdomains_of_interest", "Subdomains of interest"),
]


def _attribution_md(att: dict) -> list:
    if not att:
        return []
    out = ["### 🧭 Ownership & attribution (OSINT)", ""]
    rows = [(label, _mdq(att[key])) for key, label in _ATTR_FIELDS
            if isinstance(att.get(key), str) and att[key].strip()]
    if rows:
        out += ["| Field | Value |", "|---|---|"]
        out += [f"| {label} | {value} |" for label, value in rows]
        out.append("")
    for key, label in _ATTR_LISTS:
        vals = att.get(key)
        if isinstance(vals, list) and vals:
            out.append(f"**{label}:** " + ", ".join(_mdq(v) for v in vals))
    details = att.get("details")
    if isinstance(details, dict) and details:
        out += ["", "**Other details:**"]
        out += [f"- {_mdq(k)}: {_mdq(v)}" for k, v in details.items()]
    srcs = att.get("sources")
    if isinstance(srcs, list) and srcs:
        out += ["", f"_Sources: {', '.join(_mdq(s) for s in srcs)}_"]
    out.append("")
    return out


def _repro_steps_md(steps: list) -> list:
    if not steps:
        return []
    out = ["", "**How to reproduce (step by step):**", ""]
    for i, step in enumerate(steps, 1):
        note = step.get("note")
        head = f"{i}. " + (f"**{_mdq(note)}** — " if note else "")
        out.append(head.rstrip())
        if step.get("command"):
            out += ["", "   ```", *["   " + ln for ln in _fence(step["command"]).splitlines()], "   ```"]
        if step.get("expected"):
            out.append(f"   → expected: {_mdq(step['expected'])}")
        out.append("")
    return out


def _repro_steps_html(steps: list) -> str:
    if not steps:
        return ""
    items = []
    for step in steps:
        inner = (f"<b>{_e(step['note'])}</b><br>" if step.get("note") else "")
        if step.get("command"):
            inner += f"<pre><code>{_e(step['command'])}</code></pre>"
        if step.get("expected"):
            inner += f'<span class="meta">→ expected: {_e(step["expected"])}</span>'
        items.append(f"<li>{inner}</li>")
    return "<p><b>How to reproduce (step by step):</b></p><ol>" + "".join(items) + "</ol>"


def markdown(result: dict) -> str:
    findings = result.get("findings", [])
    counts = _counts(findings)
    kev = sum(1 for f in findings if f.get("kev"))
    mutations = result.get("mutations") or []
    unresolved = [m for m in mutations if m.get("status") == "revert_failed"]
    lines = [
        f"## 🛡️ DeepAudit — `{_mdq(result.get('target'))}`", "",
        f"**Status:** {result.get('status', 'unknown')} · "
        f"**Findings:** {len(findings)} · **KEV:** {kev} · "
        f"**Evidence items:** {result.get('evidence_count', 0)} · "
        f"**Resources:** {len(result.get('resources', []))} · "
        f"**Workers:** {len(result.get('workers', []))}"
        + (" · ⚠️ **DANGEROUS MODE**" if result.get("dangerous") else ""), "",
    ]
    if unresolved:
        lines += ["> 🚨 **CRITICAL — unresolved state change(s) left on the target.** The agent "
                  "could not fully revert one or more PoC mutations. Manual cleanup is required "
                  "before this target is left unattended. See **State changes** below for exactly "
                  "what was changed and the intended revert plan.", ""]
    lines += [
        "| " + " | ".join(f"{_BADGE[s]} {s}" for s in _ORDER) + " |",
        "|" + "---|" * len(_ORDER),
        "| " + " | ".join(str(counts[s]) for s in _ORDER) + " |", "",
        "### Summary", "", _mdblock(result.get("summary", "")), "",
    ]
    if (result.get("scope_allowlist") or "").strip():
        lines += [f"> **Authorized scope allowlist (beyond the domain tree):** "
                  f"`{_mdq(result['scope_allowlist'])}`", ""]
    lines += _attribution_md(result.get("attribution") or {})
    plan = result.get("plan") or {}
    if plan:
        lines += ["### Plan", ""]
        if plan.get("objective"):
            lines.append(f"**Objective:** {_mdq(plan['objective'])}")
        for key in ("surfaces", "waves"):
            if plan.get(key):
                lines.append(f"**{key.capitalize()}:** " + ", ".join(_mdq(x) for x in plan[key]))
        if plan.get("stop_criteria"):
            lines.append(f"**Stop criteria:** {_mdq(plan['stop_criteria'])}")
        lines.append("")
    hyps = result.get("hypotheses") or []
    if hyps:
        lines += ["### Hypotheses tested", "", "| ID | Status | Hypothesis |", "|---|---|---|"]
        for h in hyps:
            lines.append(f"| {h.get('id')} | {h.get('status')} | {_mdq(h.get('statement'))} |")
        lines.append("")
    resources = result.get("resources") or []
    if resources:
        rcounts: dict[str, int] = {}
        for r in resources:
            rcounts[r.get("status", "discovered")] = rcounts.get(r.get("status", "discovered"), 0) + 1
        lines += ["### Resources audited", "",
                  f"**Total:** {len(resources)} · " + " · ".join(f"{k}: {v}" for k, v in rcounts.items()),
                  "", "| ID | Kind | Resource | Status | Detail |", "|---|---|---|---|---|"]
        for r in resources:
            lines.append(f"| {r.get('id')} | {_mdq(r.get('kind'))} | {_mdq(r.get('name'))} | "
                         f"{r.get('status')} | {_mdq(r.get('detail'))} |")
        lines.append("")
    components = result.get("components") or []
    if components:
        lines += ["### Software inventory & CVE status", "",
                  "| ID | Component | Version | CVE status | Source |", "|---|---|---|---|---|"]
        for c in components:
            lines.append(f"| {c.get('id')} | {_mdq(c.get('name'))} | {_mdq(c.get('version'))} | "
                         f"{c.get('cve_status', 'unchecked')} | {_mdq(c.get('source'))} |")
        lines.append("")
    if mutations:
        lines += ["### State changes (dangerous mode)", "",
                  "Every PoC that changed target state, declared and reverted. `revert_failed` "
                  "means manual cleanup is required.", "",
                  "| ID | Change | Revert plan | Status | Note |", "|---|---|---|---|---|"]
        for m in mutations:
            status = m.get("status", "pending_revert")
            badge = "🚨" if status == "revert_failed" else ("✅" if status == "reverted" else "⏳")
            lines.append(f"| {m.get('id')} | {_mdq(m.get('description'))} | "
                         f"{_mdq(m.get('revert_plan'))} | {badge} {status} | {_mdq(m.get('note'))} |")
        lines.append("")
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
            if finding.get("poc_differential"):
                method = finding.get("poc_method", "differential")
                tags.append(f"✅ PoC verified ({method})")
            elif finding.get("poc_verified"):
                tags.append("✅ PoC verified")
            elif "poc_verified" in finding:
                tags.append("⚠️ PoC unverified")
            if finding.get("mutation_id"):
                tags.append(f"🧪 reverted state change ({finding['mutation_id']})")
            verdict = finding.get("verification", "unreviewed")
            suffix = f" — {finding.get('cvss')}" if finding.get("cvss") else ""
            lines.append(f"<details><summary>{badge} <b>{html.escape(_mdq(finding.get('title')))}</b> "
                         f"({finding.get('severity')}{suffix}) · {verdict}"
                         + (f" · {' '.join(tags)}" if tags else "") + "</summary>\n")
            lines.append(f"\n{_mdblock(finding.get('summary', ''))}\n")
            if finding.get("impact"):
                lines.append(f"\n**Impact:** {_mdblock(finding['impact'])}\n")
            if finding.get("reproduction"):
                label = ("Reproduction (verified — PoC actually ran, see output below)"
                         if finding.get("poc_verified") else
                         "Reproduction (narrated by the agent, not independently captured)")
                lines.append(f"\n**{label}:**\n\n```\n{_fence(finding['reproduction'])}\n```\n")
            lines += _repro_steps_md(finding.get("reproduction_steps") or [])
            if finding.get("reproduction_script"):
                lines.append(f"\n**Reproduction script** (copy-paste runnable; in-scope, "
                             f"non-destructive):\n\n```bash\n{_fence(finding['reproduction_script'])}\n```\n")
            if finding.get("poc_baseline_evidence_id"):
                lines.append(f"\n**Baseline / control** (`{finding.get('poc_baseline_evidence_id')}`) — "
                             f"the same request/command WITHOUT the payload:\n\n"
                             f"```\n{_fence(finding.get('poc_baseline_quote', ''))}\n```\n")
            if finding.get("poc_evidence_id"):
                label = ("PoC output (with payload) — compare against the baseline above"
                         if finding.get("poc_differential") else
                         "PoC output — raw result of actually running the PoC")
                lines.append(f"\n**{label}** (`{finding.get('poc_evidence_id')}`):\n\n"
                             f"```\n{_fence(finding.get('poc_quote', ''))}\n```\n")
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
    if f.get("poc_differential"):
        tags.append(f'<span class="tag" style="background:#15803d">✅ PoC verified '
                    f'({_e(f.get("poc_method", "differential"))})</span>')
    elif f.get("poc_verified"):
        tags.append('<span class="tag" style="background:#15803d">✅ PoC verified</span>')
    elif "poc_verified" in f:
        tags.append('<span class="tag" style="background:#92400e">⚠️ PoC unverified</span>')
    if f.get("mutation_id"):
        tags.append(f'<span class="tag" style="background:#6d28d9">🧪 reverted state change '
                    f'({_e(f["mutation_id"])})</span>')
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
        label = ("Reproduction (verified — PoC actually ran, see output below):"
                 if f.get("poc_verified") else
                 "Reproduction (narrated by the agent, not independently captured):")
        parts.append(f'<p><b>{label}</b></p><pre><code>{_e(f["reproduction"])}</code></pre>')
    if f.get("reproduction_steps"):
        parts.append(_repro_steps_html(f["reproduction_steps"]))
    if f.get("reproduction_script"):
        parts.append('<p><b>Reproduction script</b> (copy-paste runnable; in-scope, '
                     f'non-destructive):</p><pre><code>{_e(f["reproduction_script"])}</code></pre>')
    if f.get("poc_baseline_evidence_id"):
        parts.append(f'<p><b>Baseline / control</b> (<code>{_e(f["poc_baseline_evidence_id"])}</code>) '
                     f'— the same request/command WITHOUT the payload:</p>'
                     f'<pre><code>{_e(f.get("poc_baseline_quote"))}</code></pre>')
    if f.get("poc_evidence_id"):
        poc_label = ("PoC output (with payload) — compare against the baseline above"
                     if f.get("poc_differential") else
                     "PoC output — raw result of actually running the PoC")
        parts.append(f'<p><b>{poc_label}</b> (<code>{_e(f["poc_evidence_id"])}</code>):</p>'
                     f'<pre><code>{_e(f.get("poc_quote"))}</code></pre>')
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
    attr = result.get("attribution") or {}
    attr_scalar = "".join(
        f"<tr><td>{_e(label)}</td><td>{_e(attr[key])}</td></tr>"
        for key, label in _ATTR_FIELDS if isinstance(attr.get(key), str) and attr[key].strip())
    attr_lists = "".join(
        f"<tr><td>{_e(label)}</td><td>{_e(', '.join(str(v) for v in attr[key]))}</td></tr>"
        for key, label in _ATTR_LISTS if isinstance(attr.get(key), list) and attr[key])
    attr_details = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>"
        for k, v in (attr.get("details") or {}).items()) if isinstance(attr.get("details"), dict) else ""
    attr_src = (f'<p class="note">Sources: {_e(", ".join(str(s) for s in attr["sources"]))}</p>'
                if isinstance(attr.get("sources"), list) and attr.get("sources") else "")
    attr_html = (f'<h2>🧭 Ownership &amp; attribution (OSINT)</h2><table><tbody>'
                 f'{attr_scalar}{attr_lists}{attr_details}</tbody></table>{attr_src}'
                 if (attr_scalar or attr_lists or attr_details) else "")
    plan = result.get("plan") or {}
    plan_rows = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(', '.join(v) if isinstance(v, list) else v)}</td></tr>"
        for k, v in (("Objective", plan.get("objective")), ("Surfaces", plan.get("surfaces")),
                     ("Waves", plan.get("waves")), ("Stop criteria", plan.get("stop_criteria")))
        if v)
    plan_html = f"<h2>Plan</h2><table><tbody>{plan_rows}</tbody></table>" if plan_rows else ""
    hyps = result.get("hypotheses") or []
    hyp_rows = "".join(
        f'<tr><td><code>{_e(h.get("id"))}</code></td><td>{_e(h.get("status"))}</td>'
        f'<td>{_e(h.get("statement"))}</td></tr>' for h in hyps)
    hyp_html = (f'<h2>Hypotheses tested</h2><table><thead><tr><th>ID</th><th>Status</th>'
                f'<th>Hypothesis</th></tr></thead><tbody>{hyp_rows}</tbody></table>' if hyps else "")
    resources = result.get("resources") or []
    res_rows = "".join(
        f'<tr><td><code>{_e(r.get("id"))}</code></td><td>{_e(r.get("kind"))}</td>'
        f'<td>{_e(r.get("name"))}</td><td>{_e(r.get("status"))}</td><td>{_e(r.get("detail"))}</td></tr>'
        for r in resources)
    res_html = (f'<h2>Resources audited ({len(resources)})</h2>'
                f'<table><thead><tr><th>ID</th><th>Kind</th><th>Resource</th><th>Status</th>'
                f'<th>Detail</th></tr></thead><tbody>{res_rows}</tbody></table>' if resources else "")
    components = result.get("components") or []
    comp_rows = "".join(
        f'<tr><td><code>{_e(c.get("id"))}</code></td><td>{_e(c.get("name"))}</td>'
        f'<td>{_e(c.get("version"))}</td><td>{_e(c.get("cve_status", "unchecked"))}</td>'
        f'<td>{_e(c.get("source"))}</td></tr>' for c in components)
    comp_html = (f'<h2>Software inventory &amp; CVE status ({len(components)})</h2>'
                 f'<table><thead><tr><th>ID</th><th>Component</th><th>Version</th>'
                 f'<th>CVE status</th><th>Source</th></tr></thead><tbody>{comp_rows}</tbody></table>'
                 if components else "")
    mutations = result.get("mutations") or []
    unresolved = [m for m in mutations if m.get("status") == "revert_failed"]
    mut_rows = "".join(
        f'<tr><td><code>{_e(m.get("id"))}</code></td><td>{_e(m.get("description"))}</td>'
        f'<td>{_e(m.get("revert_plan"))}</td>'
        f'<td>{"🚨" if m.get("status") == "revert_failed" else ("✅" if m.get("status") == "reverted" else "⏳")} '
        f'{_e(m.get("status"))}</td><td>{_e(m.get("note"))}</td></tr>' for m in mutations)
    mut_html = (f'<h2>State changes (dangerous mode) ({len(mutations)})</h2>'
                f'<table><thead><tr><th>ID</th><th>Change</th><th>Revert plan</th><th>Status</th>'
                f'<th>Note</th></tr></thead><tbody>{mut_rows}</tbody></table>' if mutations else "")
    banner_html = (
        '<div class="banner">🚨 <b>CRITICAL — unresolved state change(s) left on the target.</b> '
        'The agent could not fully revert one or more PoC mutations. Manual cleanup is required '
        'before this target is left unattended. See <b>State changes</b> below.</div>'
        if unresolved else "")
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
.banner{{background:#b3123a;color:#fff;border-radius:8px;padding:.8rem 1rem;margin:1rem 0;font-weight:600}}
.dangerous{{color:#b3123a;font-weight:700}}
footer{{color:#9ca3af;font-size:.8rem;margin-top:2rem;border-top:1px solid #e5e7eb;padding-top:1rem}}
</style></head><body>
<h1>🛡️ DeepAudit report</h1>
<p class="sub">{_e(result.get('target'))} · status: {_e(result.get('status'))} · run {_e(result.get('run_id'))}
{' · <span class="dangerous">⚠️ DANGEROUS MODE</span>' if result.get('dangerous') else ''}</p>
{banner_html}
<div class="chips">{chips}
<div class="chip"><span>{len(result.get('workers', []))}</span>workers</div>
<div class="chip"><span>{result.get('evidence_count', 0)}</span>evidence</div>
<div class="chip"><span>{len(result.get('resources', []))}</span>resources</div></div>
<h2>Summary</h2><p>{_e(result.get('summary'))}</p>
{f'<p class="note"><b>Authorized scope allowlist (beyond the domain tree):</b> <code>{_e(result.get("scope_allowlist"))}</code></p>' if (result.get('scope_allowlist') or '').strip() else ''}
{attr_html}
{plan_html}
{hyp_html}
{res_html}
{comp_html}
{mut_html}
<h2>Findings</h2>{body}
<h2>Coverage &amp; limitations</h2><p>{_e(result.get('limitations') or 'Absence of a finding is not proof of absence of a problem.')}</p>
{f'<h2>Parallel workers</h2><ul>{workers}</ul>' if workers else ''}
<footer>Authorized audit · findings are evidence-grounded and verifier-reviewed · a version
match is potentially affected, not confirmed exploitable. Model usage: {_e(result.get('usage'))}</footer>
</body></html>"""
