# DeepAudit

An **autonomous, authorized** web/host security audit that runs entirely on GitHub Actions.
You dispatch one workflow with a target; a supervisor agent plans the assessment, installs the
tools it decides it needs, runs them against the target, checks live CVE intelligence, fans
out heavy work to parallel runners, verifies its own findings, and delivers a prioritized
report as the run summary plus an HTML artifact. Nothing is committed to the repository.

```text
you ── dispatch Audit(target, authorized=true)
        │
        ▼
   supervisor agent (mode=supervisor, strong model)
        ├─ run: install & run tools against the target (nuclei, httpx, nmap, testssl, …)
        ├─ cve_lookup: OSV + CISA KEV + EPSS on fingerprinted versions
        ├─ dispatch_subtask ──► worker run (mode=worker) ──► worker run (mode=worker)   ← scale wide
        │                          each installs its own tools, returns grounded findings
        ├─ record_finding: every finding cites an evidence_id + an exact quote
        ├─ run_verifier: adversarial review kills false positives, sets severity from impact
        └─ finish ──► job summary (Markdown) + report.html (artifact)
```

## What makes it strong

- **Autonomous tooling.** The agent installs what it needs at runtime — a curated arsenal
  (nuclei, httpx, subfinder, katana, ffuf, testssl, retire.js, nikto, wpscan, dalfox, sqlmap,
  nmap, trufflehog, …) it can set up by name, plus any extra apt/pip/go/npm package.
- **Real CVE intelligence.** Identified versions are correlated through OSV, then prioritized
  by **CISA KEV** (exploited in the wild) and **EPSS** (exploitation probability) — not a flat
  wall of version matches.
- **Horizontal scale.** The supervisor dispatches this same workflow in `mode=worker` to run
  independent subtasks on separate runners in parallel.
- **False-positive control.** An adversarial **verifier** re-checks every finding; only
  supported/manual-review findings ship.
- **Grounding gate.** Every finding must quote real saved evidence — the deterministic check
  the model cannot talk its way around. A version match is *potentially* affected, never
  *confirmed* until a targeted check proves it.

## Scope & safety

Exactly one target is in scope (`$AUDIT_TARGET` and its subdomains). Active testing and
non-destructive proof-of-concept against that target are permitted; denial-of-service, data
destruction, persistence, pivoting to other hosts, and exfiltration of runner secrets are not.
The runner is ephemeral and its secrets are stripped from tool environments. The target is
validated and must resolve only to public addresses. Run this only against systems you are
authorized to assess — see `SECURITY.md`.

## Running it

Dispatch **DeepAudit** (`.github/workflows/audit.yaml`) with a `target` and the `authorized`
checkbox. Configure:

- Secret `LLM_API_KEY` (or `DEEPSEEK_API_KEY`); optional variables `LLM_BASE_URL`,
  `LLM_MODEL_FAST`, `LLM_MODEL_STRONG` (defaults target DeepSeek).
- Secret `GH_ADMIN_TOKEN` — a PAT with repo + workflow scope, so the supervisor can dispatch
  worker runs. Without it the supervisor still runs, doing all work in its own runner.

Locally (no fan-out): `pip install nothing — standard library only`, then
`TARGET=https://example.com python -m lib.supervisor --target "$TARGET"`.

## Layout

```text
.github/workflows/audit.yaml   one workflow, two modes (supervisor | worker)
lib/
  supervisor.py   entrypoint: plan, act, fan out, verify, report
  worker.py       autonomous specialist for one dispatched subtask
  verify.py       adversarial finding review
  dispatch.py     launch worker runs and collect their results
  agent.py        shared audit state + the common tool surface (run, cve_lookup, evidence…)
  run.py          install tools + execute bash/python against the target
  arsenal.py      the tool catalogue + install recipes
  intel.py        CVE correlation: OSV + CISA KEV + EPSS
  evidence.py     evidence store + the grounding gate
  target.py       target validation + public-only resolution
  prompts.py      role system prompts (scope, arsenal, OWASP checklist baked in)
  report.py       Markdown job summary + standalone HTML
  llm.py          std-lib OpenAI-compatible client (two tiers) + tool-use loop
  console.py      event log
  tests/          offline coverage (scope, grounding, agent loop, verify, report)
```

The offline logic — the agent loop, grounding, worker import, verification, rendering — is
covered by `python -m unittest discover lib/tests`. Live runs make billable model calls and,
for fan-out, need the PAT.

License: MIT.
