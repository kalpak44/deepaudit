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
from .htmlreport import bullets, document, esc, heading, links, para, table, tag
from .inventory import collect, resolve_repo
from .sbom import cyclonedx
from .transport import utc_now

STATUS_ORDER = (CONFIRMED_APPLICABLE, LIKELY_APPLICABLE, POTENTIAL,
                INSUFFICIENT_EVIDENCE, NOT_APPLICABLE)


def _finding_block(finding: dict) -> list[str]:
    component = finding["component"]
    parts = [heading(3, f"{component['name']} {component['version']} "
                        f"({component['ecosystem']}) \u2014 {finding['advisory_id']}")]
    parts.append("<p>Status: " + tag(finding["status"]) + " &middot; Declared severity: "
                 + tag(finding["severity_label"] or "unstated") + "</p>")
    if finding["cve"]:
        parts.append(para("Aliases: " + ", ".join(finding["cve"])))
    if finding["summary"]:
        parts.append(para(finding["summary"]))
    parts.append(para(
        f"Declared in {component['source']} as a "
        f"{'direct' if component['direct'] else 'transitive'} dependency "
        f"({component['resolution']})."))
    rows = []
    for item in finding["states"]:
        label = {"confirmed": "confirmed", "refuted": "refuted",
                 "not_evaluated": "not evaluated"}[item["result"]]
        rows.append([f"<code>{esc(item['state'])}</code>", tag(label), esc(item["reason"])])
    parts.append(table(["Evidence", "Verdict", "Reason"], rows))
    if finding["references"]:
        parts.append(links(finding["references"][:5]))
    return parts


def write_report(run_dir: Path, inventory: dict, assessment: dict, advisory: dict,
                 consulted: bool, started_at: str) -> None:
    counts = assessment["counts"]
    rows = [["Components inventoried",
             esc(f"{inventory['counts']['total']} "
                 f"({inventory['counts']['with_version']} with a resolved version)")],
            ["Advisory source", tag("OSV.dev") if consulted else tag("none consulted")],
            ["Advisory requests", esc(advisory.get("requests", 0))],
            ["Advisory matches", esc(counts["total"])]]
    for name in STATUS_ORDER:
        rows.append([name, tag(counts[name]) if counts[name] else esc(0)])
    rows.append(["Components with no resolved version", esc(counts["unresolved_components"])])
    parts = [heading(2, "Summary"), table(["Measure", "Value"], rows)]
    parts.append(para(
        "A status is derived from the evidence ladder, never asserted directly. POTENTIAL "
        "means the installed version falls in an affected range and nothing more was "
        "established \u2014 it is not a judgement that the issue is exploitable here.", "note"))

    parts.append(heading(2, "How to read a status"))
    parts.append(table(["Status", "Meaning"],
                       [[tag(name), esc(STATUS_MEANING[name])] for name in STATUS_ORDER]))
    parts.append(para("The ladder is " + " \u2192 ".join(LADDER) + ". This release evaluates "
                      "VERSION_MATCH only; every higher rung reports not evaluated, which is "
                      "a gap in the evidence and never a pass."))

    if not consulted:
        parts.append(heading(2, "No advisory source was consulted"))
        parts.append(para(
            "This run built an inventory and an SBOM but queried no advisory database, so it "
            "found no advisories by construction. Zero findings here is not a clean result. "
            "Re-run with --allow-advisory-fetch for an assessment.", "note"))

    parts.append(heading(2, "Findings"))
    if not assessment["findings"]:
        parts.append(para(
            "No advisory matched a resolved component version. This is not a clean bill of "
            "security: only known advisories for the listed packages were considered.", "note"))
    else:
        for name in STATUS_ORDER:
            group = [f for f in assessment["findings"] if f["status"] == name]
            if not group:
                continue
            parts.append(heading(2, f"{name} ({len(group)})"))
            for finding in group:
                parts.extend(_finding_block(finding))

    if assessment["unresolved_components"]:
        parts.append(heading(2, "Coverage gaps"))
        parts.append(para(
            "These dependencies declare a range rather than an exact version, so no advisory "
            "range could be evaluated against them. They were not assessed, and their absence "
            "from the findings above carries no information.", "note"))
        parts.append(bullets(
            [f"<code>{esc(item['name'])}</code> ({esc(item['ecosystem'])}) in "
             f"<code>{esc(item['source'])}</code>"
             for item in assessment["unresolved_components"]], plain=True))

    parts.append(heading(2, "Limitations"))
    parts.append(bullets([esc(item) for item in [
        "Versions come from committed manifests and lockfiles, not an installed environment, "
        "so a deployed artifact can differ from what is assessed here.",
        "No resolver is run: a declared range stays undetermined rather than being resolved "
        "against a registry.",
        "Vendored, bundled and backported code is not detected, so a patched fork still "
        "matches its upstream advisory range.",
        "Exploitation conditions, code reachability and reproduction are not evaluated in "
        "this release.",
        "An advisory database records what has been reported. Absence of a match means "
        "nothing was reported for that exact version, not that the code is sound."]],
        plain=True))
    if consulted:
        parts.append(heading(2, "Data sharing"))
        parts.append(para(f"The advisory lookup sent {DATA_SHARED} to api.osv.dev."))
    _write(run_dir / "report.html",
           document("DeepAudit dependency report",
                    f"{inventory['root']} \u00b7 run {run_dir.name}", parts))


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

    print("Report: " + str(run_dir / "report.html"))
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
