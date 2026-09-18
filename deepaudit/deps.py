"""The dependency-applicability pipeline: inventory -> advisories -> evidence -> report.

Deterministic end to end. The DeepSeek agent has no role in this release: every status
here is derived from a version comparison a reader can repeat by hand, so there is nothing
yet for a model to decide. Research and hypothesis tooling arrives with the rungs above
VERSION_MATCH, which are the ones a model can genuinely help with.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import __version__
from .advisories import DATA_SHARED, AdvisoryError, OSVClient, fetch
from .applicability import (CONFIRMED_APPLICABLE, INSUFFICIENT_EVIDENCE, LADDER,
                            LIKELY_APPLICABLE, NOT_APPLICABLE, POTENTIAL, STATUS_MEANING,
                            assess)
from .artifacts import _json, _write, make_run_dir
from .inventory import collect, resolve_repo
from .sbom import cyclonedx
from .transport import utc_now

STATUS_ORDER = (CONFIRMED_APPLICABLE, LIKELY_APPLICABLE, POTENTIAL,
                INSUFFICIENT_EVIDENCE, NOT_APPLICABLE)


def _summary_lines(inventory: dict, assessment: dict, advisory: dict, consulted: bool) -> list[str]:
    counts = assessment["counts"]
    lines = [
        f"- Components inventoried: **{inventory['counts']['total']}** "
        f"({inventory['counts']['with_version']} with a resolved version).",
        f"- Advisory source: **{'OSV.dev' if consulted else 'none consulted'}**"
        + (f" ({advisory.get('requests', 0)} requests)." if consulted else "."),
        f"- Advisory matches: **{counts['total']}**.",
    ]
    for name in STATUS_ORDER:
        lines.append(f"  - {name}: **{counts[name]}**")
    lines.append(f"- Components with no resolved version: **{counts['unresolved_components']}**.")
    return lines


def _finding_block(finding: dict) -> list[str]:
    component = finding["component"]
    title = f"{component['name']} {component['version']} ({component['ecosystem']}) — {finding['advisory_id']}"
    lines = [f"### {title}", ""]
    if finding["cve"]:
        lines += [f"Aliases: {', '.join(finding['cve'])}", ""]
    lines += [f"Status: **{finding['status']}**. Declared severity: "
              f"**{finding['severity_label'] or 'unstated'}**.", ""]
    if finding["summary"]:
        lines += [finding["summary"], ""]
    lines += [f"Declared in `{component['source']}` as a "
              f"{'direct' if component['direct'] else 'transitive'} dependency "
              f"({component['resolution']}).", "", "Evidence ladder:", ""]
    for item in finding["states"]:
        mark = {"confirmed": "confirmed", "refuted": "refuted", "not_evaluated": "not evaluated"}[item["result"]]
        lines.append(f"- `{item['state']}` — **{mark}**: {item['reason']}")
    lines.append("")
    if finding["references"]:
        lines += ["References:", ""] + [f"- {url}" for url in finding["references"][:5]] + [""]
    return lines


def write_report(run_dir: Path, inventory: dict, assessment: dict, advisory: dict,
                 consulted: bool, started_at: str) -> None:
    counts = assessment["counts"]
    lines = ["# DeepAudit dependency report", "",
             f"Repository: `{inventory['root']}`", "", f"Run: `{run_dir.name}`", "",
             "## Summary", ""]
    lines += _summary_lines(inventory, assessment, advisory, consulted)
    lines += ["",
              "A status is derived from the evidence ladder below, never asserted directly.",
              "`POTENTIAL` means the installed version falls in an affected range and nothing",
              "more was established — it is not a judgement that the issue is exploitable here.", "",
              "## How to read a status", ""]
    for name in STATUS_ORDER:
        lines.append(f"- **{name}** — {STATUS_MEANING[name]}")
    lines += ["", "The ladder is `" + " -> ".join(LADDER) + "`. This release evaluates",
              "`VERSION_MATCH` only; every higher rung reports *not evaluated*, which is a gap",
              "in the evidence and never a pass.", ""]
    if not consulted:
        lines += ["## No advisory source was consulted", "",
                  "This run built an inventory and an SBOM but queried no advisory database, so it",
                  "found no advisories by construction. Zero findings here is not a clean result.",
                  "Re-run with `--allow-advisory-fetch` for an assessment.", ""]
    lines += ["## Findings", ""]
    if not assessment["findings"]:
        lines += ["No advisory matched a resolved component version. This is not a clean bill of",
                  "security: only known advisories for the packages listed below were considered.", ""]
    else:
        for name in STATUS_ORDER:
            group = [f for f in assessment["findings"] if f["status"] == name]
            if not group:
                continue
            lines += [f"## {name} ({len(group)})", ""]
            for finding in group:
                lines += _finding_block(finding)
    if assessment["unresolved_components"]:
        lines += ["## Coverage gaps", "",
                  "These dependencies declare a range rather than an exact version, so no advisory",
                  "range could be evaluated against them. They were not assessed, and their absence",
                  "from the findings above carries no information.", ""]
        for item in assessment["unresolved_components"]:
            lines += [f"- `{item['name']}` ({item['ecosystem']}) in `{item['source']}`"]
        lines.append("")
    lines += ["## Limitations", "",
              "Versions come from committed manifests and lockfiles, not from an installed",
              "environment, so a deployed artifact can differ from what is assessed here. No",
              "resolver is run: a declared range stays undetermined rather than being resolved",
              "against a registry. Vendored, bundled and backported code is not detected, so a",
              "patched fork still matches its upstream advisory range. Exploitation conditions,",
              "code reachability and reproduction are not evaluated in this release.", "",
              "An advisory database is a record of what has been reported. Absence of a match",
              "means nothing was reported for that exact version, not that the code is sound.", ""]
    if consulted:
        lines += ["## Data sharing", "",
                  f"The advisory lookup sent {DATA_SHARED} to `api.osv.dev`.", ""]
    _write(run_dir / "report.md", "\n".join(lines))


def run_deps(args) -> tuple[Path, dict, int]:
    started = utc_now()
    root = resolve_repo(args.repo)
    inventory = collect(root)
    run_dir = make_run_dir(root, args.out, "deps-" + inventory["root"])

    advisory: dict = {"advisories": {}, "by_component": {}, "requests": 0,
                      "incomplete": False, "error": None}
    consulted = False
    error = None
    if args.allow_advisory_fetch:
        try:
            client = OSVClient(timeout=args.timeout, max_requests=args.max_advisory_requests)
            advisory = fetch(inventory["components"], client)
            consulted = True
            error = advisory.get("error")
        except AdvisoryError as exc:
            error = str(exc)
    assessment = assess(inventory, advisory)

    _json(run_dir / "inventory.json", inventory)
    _json(run_dir / "sbom.json", cyclonedx(inventory, started))
    _json(run_dir / "advisories.json", {
        "schema_version": 1, "source": "https://api.osv.dev" if consulted else None,
        "consulted": consulted, "error": error, "requests": advisory.get("requests", 0),
        "incomplete": bool(advisory.get("incomplete")),
        "data_shared": DATA_SHARED if consulted else None,
        "by_component": advisory.get("by_component", {}),
        "advisories": advisory.get("advisories", {})})
    _json(run_dir / "applicability.json", assessment)
    write_report(run_dir, inventory, assessment, advisory, consulted, started)

    complete = (consulted and not advisory.get("incomplete")
                and not assessment["unresolved_components"] and error is None)
    manifest = {
        "schema_version": 1, "engine_version": __version__, "run_id": run_dir.name,
        "pipeline": "dependency-applicability", "started_at": started, "finished_at": utc_now(),
        "repository": inventory["root"], "manifests": inventory["manifests"],
        "advisory_source": "https://api.osv.dev" if consulted else None,
        "advisory_consulted": consulted, "advisory_error": error,
        "advisory_incomplete": bool(advisory.get("incomplete")),
        "advisory_requests": advisory.get("requests", 0),
        "ladder_evaluated": ["VERSION_MATCH"],
        "counts": {**assessment["counts"], "components": inventory["counts"]["total"]},
        "complete": complete,
        "privacy": "No source code, file contents, or credentials leave the machine.",
    }
    _json(run_dir / "manifest.json", manifest)
    hashes = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            hashes.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  "
                          + path.relative_to(run_dir).as_posix())
    _write(run_dir / "SHA256SUMS", "\n".join(hashes) + "\n")

    print("Report: " + str(run_dir / "report.md"))
    print("Components: " + str(inventory["counts"]["total"]))
    print("Advisory matches: " + str(assessment["counts"]["total"]))
    for name in STATUS_ORDER:
        if assessment["counts"][name]:
            print(f"  {name}: {assessment['counts'][name]}")
    print("Advisory source consulted: " + str(consulted))
    print("Complete: " + str(complete))
    if error:
        print("Advisory lookup failed: " + error)
    return run_dir, manifest, 0 if complete else 3
