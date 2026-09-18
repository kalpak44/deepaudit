"""The evidence ladder and the status it determines.

A model may research and explain; only this module assigns a status, and only from
evidence a later reader can re-derive. Each rung is independently confirmed, refuted, or
not evaluated — "not evaluated" is never collapsed into "not applicable", because that
collapse is exactly how an unimplemented check turns into a false clean result.
"""
from __future__ import annotations

from .versions import ORDERING, in_range, normalize_pypi

CONFIRMED = "confirmed"
REFUTED = "refuted"
NOT_EVALUATED = "not_evaluated"

VERSION_MATCH = "VERSION_MATCH"
CONDITIONS_MATCH = "CONDITIONS_MATCH"
REACHABLE = "REACHABLE"
EXTERNALLY_REACHABLE = "EXTERNALLY_REACHABLE"
REPRODUCED = "REPRODUCED"

LADDER = (VERSION_MATCH, CONDITIONS_MATCH, REACHABLE, EXTERNALLY_REACHABLE, REPRODUCED)

# Which release earns each rung. Rungs above the implemented set report not_evaluated by
# construction, so a report never implies a check that does not exist yet has passed.
IMPLEMENTED_IN = {
    VERSION_MATCH: "0.2", CONDITIONS_MATCH: "0.3", REACHABLE: "0.3",
    EXTERNALLY_REACHABLE: "0.5", REPRODUCED: "0.4",
}

POTENTIAL = "POTENTIAL"
LIKELY_APPLICABLE = "LIKELY_APPLICABLE"
CONFIRMED_APPLICABLE = "CONFIRMED_APPLICABLE"
NOT_APPLICABLE = "NOT_APPLICABLE"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

STATUS_MEANING = {
    POTENTIAL: "The resolved version falls in an affected range; nothing further was established.",
    LIKELY_APPLICABLE: "Exploitation conditions or reachability were positively established.",
    CONFIRMED_APPLICABLE: "A PoC reproduced the issue and stopped reproducing after the fix.",
    NOT_APPLICABLE: "A check positively ruled this advisory out for this component.",
    INSUFFICIENT_EVIDENCE: "The available data could not decide; this is not a clean result.",
}


def state(name: str, result: str, reason: str, evidence: dict | None = None) -> dict:
    return {"state": name, "result": result, "reason": reason,
            "implemented_in": IMPLEMENTED_IN[name], "evidence": evidence or {}}


def pending(name: str) -> dict:
    return state(name, NOT_EVALUATED, f"Not implemented before v{IMPLEMENTED_IN[name]}")


def status_for(states: list[dict]) -> str:
    """Derive one status from the ladder. Pure; the only place a status is decided."""
    by_name = {item["state"]: item["result"] for item in states}
    if by_name.get(VERSION_MATCH) == REFUTED:
        return NOT_APPLICABLE
    if by_name.get(VERSION_MATCH) != CONFIRMED:
        return INSUFFICIENT_EVIDENCE
    if by_name.get(REPRODUCED) == CONFIRMED:
        return CONFIRMED_APPLICABLE
    if any(by_name.get(name) == REFUTED for name in (CONDITIONS_MATCH, REACHABLE, EXTERNALLY_REACHABLE)):
        return NOT_APPLICABLE
    if any(by_name.get(name) == CONFIRMED for name in (CONDITIONS_MATCH, REACHABLE)):
        return LIKELY_APPLICABLE
    return POTENTIAL


def _same_package(ecosystem: str, name: str, entry: dict) -> bool:
    if entry.get("ecosystem") != ecosystem:
        return False
    other = entry.get("name") or ""
    if ecosystem == "PyPI":
        return normalize_pypi(other) == normalize_pypi(name)
    return other == name


def assess_version_match(component: dict, advisory: dict) -> dict:
    """Re-derive OSV's own claim locally instead of trusting the query result.

    A disagreement resolves to not_evaluated rather than refuted: the matcher could be
    wrong, and clearing a real advisory on that basis is the costlier mistake.
    """
    if advisory.get("withdrawn"):
        return state(VERSION_MATCH, REFUTED, "Advisory was withdrawn upstream",
                     {"withdrawn": advisory["withdrawn"]})
    ordering = ORDERING.get(component["ecosystem"])
    version = component.get("version")
    if not ordering or not version:
        return state(VERSION_MATCH, NOT_EVALUATED, "No resolved version or unsupported ecosystem")
    entries = [e for e in advisory.get("affected", []) if _same_package(component["ecosystem"], component["name"], e)]
    if not entries:
        return state(VERSION_MATCH, NOT_EVALUATED,
                     "Advisory lists no affected entry for this package name")
    undecided = False
    for entry in entries:
        if version in entry.get("versions", []):
            return state(VERSION_MATCH, CONFIRMED, "Version is listed explicitly as affected",
                         {"matched_by": "versions", "version": version})
        for item in entry.get("ranges", []):
            if item.get("type") == "GIT":
                undecided = True
                continue
            verdict = in_range(ordering, version, item.get("events", []))
            if verdict is None:
                undecided = True
            elif verdict:
                return state(VERSION_MATCH, CONFIRMED, "Version falls inside an affected range",
                             {"matched_by": "range", "version": version,
                              "range_type": item.get("type"), "events": item.get("events", [])})
        if not entry.get("ranges") and not entry.get("versions"):
            undecided = True
    if undecided:
        return state(VERSION_MATCH, NOT_EVALUATED,
                     "An affected range could not be evaluated for this version")
    return state(VERSION_MATCH, NOT_EVALUATED,
                 "Local range evaluation disagrees with the advisory source",
                 {"source_disagreement": True, "version": version})


def assess(inventory: dict, advisory_data: dict) -> dict:
    """Build one finding per (component, advisory) pair, plus the coverage gaps."""
    advisories = advisory_data.get("advisories", {})
    by_component = advisory_data.get("by_component", {})
    findings = []
    for component in inventory["components"]:
        if not component.get("version"):
            continue
        key = f"{component['ecosystem']}|{component['name']}|{component['version']}"
        for identifier in by_component.get(key, []):
            advisory = advisories.get(identifier)
            if not advisory:
                continue
            states = [assess_version_match(component, advisory), pending(CONDITIONS_MATCH),
                      pending(REACHABLE), pending(EXTERNALLY_REACHABLE), pending(REPRODUCED)]
            findings.append({
                "advisory_id": identifier,
                "cve": advisory.get("cve", []),
                "summary": advisory.get("summary", ""),
                "severity_label": advisory.get("severity_label"),
                "severity": advisory.get("severity", []),
                "references": advisory.get("references", []),
                "component": {k: component[k] for k in
                              ("ecosystem", "name", "version", "purl", "source", "direct", "resolution")},
                "states": states,
                "status": status_for(states),
            })
    # An unpinned dependency is a coverage gap, not an absence of risk.
    gaps = [{k: component[k] for k in ("ecosystem", "name", "source", "resolution")}
            for component in inventory["components"] if not component.get("version")]
    order = {CONFIRMED_APPLICABLE: 0, LIKELY_APPLICABLE: 1, POTENTIAL: 2,
             INSUFFICIENT_EVIDENCE: 3, NOT_APPLICABLE: 4}
    findings.sort(key=lambda f: (order[f["status"]], f["component"]["name"], f["advisory_id"]))
    counts = {name: sum(1 for f in findings if f["status"] == name) for name in order}
    return {
        "schema_version": 1,
        "ladder": list(LADDER),
        "implemented_in": IMPLEMENTED_IN,
        "status_meaning": STATUS_MEANING,
        "findings": findings,
        "unresolved_components": gaps,
        "counts": {**counts, "total": len(findings), "unresolved_components": len(gaps)},
    }
