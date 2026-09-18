"""CycloneDX export of the inventory.

Only components with a resolved version become SBOM entries: a CycloneDX component
without a version reads as a fact about what is installed, and an unpinned range is not
that fact. The unresolved ones stay in the report as a coverage gap instead.
"""
from __future__ import annotations

from . import __version__

SPEC_VERSION = "1.5"

_TYPE = {"PyPI": "library", "npm": "library"}


def cyclonedx(inventory: dict, timestamp: str) -> dict:
    components = []
    for item in inventory["components"]:
        if not item.get("version"):
            continue
        components.append({
            "type": _TYPE.get(item["ecosystem"], "library"),
            "bom-ref": item["purl"],
            "name": item["raw_name"] if item["ecosystem"] == "npm" else item["name"],
            "version": item["version"],
            "purl": item["purl"],
            "scope": "required" if item["direct"] else "optional",
            "properties": [
                {"name": "deepaudit:source", "value": item["source"]},
                {"name": "deepaudit:resolution", "value": item["resolution"]},
                {"name": "deepaudit:direct", "value": str(item["direct"]).lower()},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "deepaudit", "name": "deepaudit", "version": __version__}],
            "component": {"type": "application", "name": inventory["root"]},
        },
        "components": components,
    }
