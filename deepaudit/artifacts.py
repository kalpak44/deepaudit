"""Controlled artifact paths, static PoCs, subprocess replay, and integrity manifests."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

from . import __version__
from .policy import PolicyError, Target
from .rules import RULES
from .tools import AuditTools
from .transport import utc_now


def make_run_dir(repo: Path, output: str, target: Target | str) -> Path:
    repo = repo.resolve(strict=True)
    if not repo.is_dir():
        raise PolicyError("Repository path is not a directory")
    parts = Path(output).parts
    if not parts or Path(output).is_absolute() or any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", part) for part in parts
    ):
        raise PolicyError("Output must be a relative directory path using letters, numbers, hyphens, or underscores")
    parent = repo
    for part in parts:
        parent = parent / part
        if parent.is_symlink():
            raise PolicyError("Output directory symlinks are not allowed")
        parent.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = target.host if isinstance(target, Target) else str(target)
    slug = re.sub(r"[^A-Za-z0-9_-]", "-", name)[:64] or "run"
    destination = parent / f"{stamp}_{slug}_{uuid.uuid4().hex[:8]}"
    destination.mkdir(mode=0o700)
    return destination


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The run directory is unique. Never silently overwrite existing files.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def _json(path: Path, value: object) -> None:
    _write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _clean_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG"}}


def run_verifiers(run_dir: Path) -> dict:
    template = Path(__file__).with_name("poc_template.py").read_bytes()
    outcomes = []
    directory = run_dir / "pocs"
    if directory.is_symlink():
        raise PolicyError("PoC directory symlinks are not allowed")
    if directory.exists():
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_dir() or path.name not in RULES:
                raise PolicyError("Unexpected PoC path")
            script = path / "poc.py"
            if script.is_symlink() or script.read_bytes() != template:
                raise PolicyError("PoC code differs from the fixed application template; refusing execution")
            try:
                process = subprocess.run([sys.executable, "-I", str(script.resolve()), "--json"],
                                         capture_output=True, text=True, timeout=10,
                                         cwd=run_dir, env=_clean_env(), check=False)
                value = json.loads(process.stdout)
                if value.get("rule_id") != path.name:
                    value = {"rule_id": path.name, "status": "error", "error_type": "invalid_verifier_result"}
                outcomes.append({**value, "exit_code": process.returncode})
            except (OSError, subprocess.TimeoutExpired, ValueError):
                outcomes.append({"rule_id": path.name, "status": "error", "exit_code": 2})
    return {"verifier": "static independent predicates; no network", "cases": outcomes,
            "reproduced": sum(item["status"] == "reproduced" for item in outcomes),
            "total": len(outcomes),
            "all_reproduced": all(item["status"] == "reproduced" for item in outcomes)}


def write_artifacts(run_dir: Path, tools: AuditTools, agent: dict, started_at: str) -> dict:
    if tools.recheck is None:
        raise ValueError("Complete the recheck before publishing artifacts")
    _json(run_dir / "evidence" / "initial.json", tools.initial)
    _json(run_dir / "evidence" / "recheck.json", tools.recheck)
    _json(run_dir / "findings.json", {"schema_version": 1, "findings": tools.findings})
    _write(run_dir / "trace.jsonl", "".join(json.dumps(e, ensure_ascii=True) + "\n" for e in tools.events))
    template = Path(__file__).with_name("poc_template.py").read_text(encoding="utf-8")
    for finding in tools.findings:
        folder = run_dir / "pocs" / finding["id"]
        _write(folder / "poc.py", template)
        _json(folder / "case.json", {"rule_id": finding["id"], "title": finding["title"],
                                     "classification": "configuration_observation"})
        _write(folder / "README.md", f'''# {finding['id']}

{finding['title']}

**Interpretation:** {finding['interpretation']}

**Observed twice:** {finding['verification']}. This is not a demonstration of exploitation.

## Replay saved evidence (no network or API key)

Run from this folder:

```bash
python poc.py
```

Exit codes: 0 reproduced; 1 not reproduced; 2 inconclusive/error.
The script uses independent, fixed predicates against both normalized snapshots.
It does not prove the snapshots are authentic. SHA256SUMS detects accidental modifications,
not malicious changes by someone who can rewrite the manifest.

## Re-check the original target

Install DeepAudit from the repository first (`python -m pip install -e .`). Then:

```bash
python poc.py --live --authorized
```

For a private/loopback lab only, also pass `--allow-private`. Authorization is not inherited
from the saved report. The original hostname is resolved again; redirects are not followed.
The live test issues at most one GET or one TLS handshake. The bundled demo server normally
stops after the demo run, so its saved ephemeral URL is not a persistent live target.

## Remediation

{finding['remediation']}

Reference: {finding['reference']}
''')
    verification = run_verifiers(run_dir)
    _json(run_dir / "verification.json", verification)
    metadata = {key: value for key, value in agent.items() if key != "summary"}
    manifest = {
        "schema_version": 1, "engine_version": __version__, "run_id": run_dir.name,
        "started_at": started_at, "finished_at": utc_now(),
        "scope": tools.probes.scope.public(), "agent": metadata,
        "limits": {"target_connections": tools.probes.budget.maximum,
                   "per_operation_timeout_seconds": tools.probes.budget.timeout,
                   "minimum_request_interval_seconds": tools.probes.budget.delay},
        "target_connections_used": tools.probes.budget.used,
        "coverage": tools.coverage(), "findings_count": len(tools.findings),
        "offline_verification": verification,
        "privacy": "No response bodies, raw headers, cookie values, credentials, or model reasoning are retained.",
    }
    _json(run_dir / "manifest.json", manifest)
    if agent.get("summary"):
        _write(run_dir / "AI_NOTES.txt", "UNVERIFIED MODEL COMMENTARY. Not evidence; never executed.\n\n" +
               agent["summary"] + "\n")
    lines = [
        "# DeepAudit report", "", f"Target: `{tools.probes.scope.target.url}`", "",
        f"Run: `{run_dir.name}`", "",
        "## Summary", "",
        f"- Configuration observations: **{len(tools.findings)}**.",
        f"- Independent offline replay: **{verification['reproduced']}/{verification['total']} reproduced**.",
        f"- Target connections: **{tools.probes.budget.used}/{tools.probes.budget.maximum}**.",
        f"- Agent status: **{agent['status']}**; deterministic fallback: **{agent.get('fallback_used', False)}**.",
        f"- Probe coverage complete: **{tools.coverage()['complete']}**.", "",
        "Reproduced observations are not proof of exploitable vulnerabilities. Missing headers are",
        "hardening observations, not proof of XSS, clickjacking, or compromise.", "",
        "## Evidence and coverage", "",
        "Both normalized snapshots are in `evidence/`. `trace.jsonl` records tool execution without",
        "model reasoning, raw response content, or credentials. `verification.json` contains actual",
        "subprocess replay outcomes. `AI_NOTES.txt`, when present, is unverified model commentary.", "",
        tools.coverage()["scope_note"], "",
    ]
    if tools.coverage()["unavailable"]:
        lines += ["Unavailable probes: " + ", ".join(tools.coverage()["unavailable"]), ""]
    if agent.get("error"):
        lines += ["Agent warning: " + agent["error"], ""]
    lines += ["## Observations", ""]
    if not tools.findings:
        lines += ["No built-in rules matched. This is not a clean bill of security.", ""]
    for finding in tools.findings:
        lines += [f"### {finding['id']}: {finding['title']}", "",
                  f"Severity: **{finding['severity']}**. Recheck: **{finding['verification']}**.", "",
                  finding["interpretation"], "", "Evidence:", "", "```json",
                  json.dumps(finding["evidence"], indent=2), "```", "",
                  "Remediation: " + finding["remediation"], "",
                  f"Replay: `python pocs/{finding['id']}/poc.py`", "",
                  "Reference: " + finding["reference"], ""]
    lines += ["## Limitations", "",
              "Only the selected URL and first approved DNS address were sampled twice. GET must be",
              "safe on the endpoint you authorize; the tool cannot determine application side effects.",
              "No browser, login, body analysis, crawling, port scan, exploitation, subdomain expansion,",
              "HSTS preload lookup, meta-CSP analysis, or TLS cipher/version enumeration is performed.",
              "No redirect is followed, including same-origin redirects. A JSON/API response does not",
              "receive HTML-only findings. Cookie purpose and sensitivity are unknown. Policies that",
              "are present but malformed or permissive can be missed. Private CA validation depends",
              "on the Python runtime trust store. Repeated evidence does not establish business impact.", "",
              "Review reports before sharing. Target names, selected IPs, paths and security observations",
              "can be confidential even though bodies and credential values are not collected.", ""]
    _write(run_dir / "report.md", "\n".join(lines))
    hashes = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            hashes.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(run_dir).as_posix())
    _write(run_dir / "SHA256SUMS", "\n".join(hashes) + "\n")
    return manifest


def check_integrity(run_dir: Path) -> dict:
    checks = []
    seen = set()
    manifest = run_dir / "SHA256SUMS"
    if manifest.is_symlink() or manifest.stat().st_size > 65536:
        raise PolicyError("Invalid checksum manifest")
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        path = Path(relative)
        if relative in seen or relative == "SHA256SUMS":
            raise PolicyError("Duplicate or self-referential checksum entry")
        seen.add(relative)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or path.is_absolute() or ".." in path.parts:
            raise PolicyError("Invalid checksum entry")
        current = run_dir
        for part in path.parts:
            current = current / part
            if current.is_symlink():
                raise PolicyError("Symlink in checksummed path")
        matched = (current.is_file() and current.stat().st_size <= 2_000_000
                   and hashlib.sha256(current.read_bytes()).hexdigest() == digest)
        checks.append({"file": relative, "matched": matched})
    actual = {path.relative_to(run_dir).as_posix() for path in run_dir.rglob("*")
              if path.is_file() and path.name != "SHA256SUMS"}
    inventory_matches = actual == seen
    return {"ok": bool(checks) and inventory_matches and all(item["matched"] for item in checks),
            "inventory_matches": inventory_matches, "files": checks}
