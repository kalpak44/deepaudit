"""Reviewed workflow contracts; the same parameter validation runs before and after dispatch."""
from __future__ import annotations

import json
from pathlib import Path


def integer(default, minimum, maximum):
    return {"type": "integer", "default": default, "minimum": minimum, "maximum": maximum}


SPECS = {
    "fingerprinter": ("WhatWeb: identify software and observed versions; one page, no redirects.", {
        "aggression": {"type": "integer", "enum": [1, 3], "default": 1}}),
    "nmap": ("Nmap: bounded TCP connect scan and light service identification on one resolved IP.", {
        "top_ports": integer(100, 1, 1000), "max_rate": integer(20, 1, 100),
        "service_detection": {"type": "boolean", "default": True}}),
    "tls": ("Python ssl: certificate trust/expiry, negotiated cipher and TLS 1.2/1.3 support. HTTPS only.", {}),
    "http": ("HTTP response headers, cookie attributes, CORS comparison and OPTIONS; no credentials or redirects.", {
        "path": {"type": "string", "default": "/", "maxLength": 500},
        "cors": {"type": "boolean", "default": True}}),
    "crawl": ("Bounded same-origin HTML mapping: links, forms and script references; never submits forms.", {
        "max_pages": integer(8, 1, 20), "delay_ms": integer(500, 200, 3000)}),
    "exposure": ("Small fixed public endpoint inventory with random-path soft-404 control; no secret file downloads.", {
        "profile": {"type": "string", "enum": ["discovery", "diagnostics"], "default": "discovery"}}),
    "osv": ("OSV.dev advisory lookup for already-identified packages and versions; queries the third-party OSV "
            "database, not the audit target. Versions must come from prior evidence, never assumption.", {
        "packages": {"type": "array", "default": [], "maxItems": 16, "items": {"type": "object", "properties": {
            "ecosystem": {"type": "string", "default": "", "maxLength": 40},
            "name": {"type": "string", "maxLength": 200},
            "version": {"type": "string", "maxLength": 100}}, "required": ["name", "version"]}}}),
    "script": ("Run your own Python over already-collected evidence in a locked-down sandbox: no network, "
               "read-only evidence, bounded CPU/memory. `evidence` is a dict keyed by task_id; assign JSON to "
               "`result`. For parsing, correlating and computing over evidence, not for new target contact.", {
        "code": {"type": "string", "default": "", "maxLength": 10000},
        "inputs": {"type": "array", "default": [], "maxItems": 8, "items": {"type": "object", "properties": {
            "task_id": {"type": "string", "maxLength": 40}}, "required": ["task_id"]}}}),
}


def _scalar(key, value, schema):
    expected = {"integer": int, "boolean": bool, "string": str}[schema["type"]]
    if type(value) is not expected:
        raise ValueError(f"{key} must be {schema['type']}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{key} must be one of {schema['enum']}")
    if expected is int and "minimum" in schema and not schema["minimum"] <= value <= schema["maximum"]:
        raise ValueError(f"{key} is outside the allowed range")
    if expected is str and len(value) > schema.get("maxLength", 500):
        raise ValueError(f"{key} is too long")
    return value


def _array(key, value, schema):
    if not isinstance(value, list) or len(value) > schema.get("maxItems", 16):
        raise ValueError(f"{key} must be an array of at most {schema.get('maxItems', 16)} objects")
    item_props = schema["items"]["properties"]
    required = schema["items"].get("required", [])
    cleaned = []
    for item in value:
        if not isinstance(item, dict) or set(item) - item_props.keys():
            raise ValueError(f"{key} items must be objects with keys {sorted(item_props)}")
        entry = {}
        for name, sub in item_props.items():
            if name not in item and name in required:
                raise ValueError(f"{key} items require {name}")
            entry[name] = _scalar(f"{key}.{name}", item.get(name, sub.get("default")), sub)
        cleaned.append(entry)
    return cleaned


def validate_params(tool: str, params: dict) -> dict:
    if not isinstance(params, dict) or len(json.dumps(params)) > 24000:
        raise ValueError("params must be a JSON object of at most 24000 characters")
    if tool not in SPECS:
        return params  # custom workflows own their validation
    properties = SPECS[tool][1]
    if set(params) - properties.keys():
        raise ValueError("Unsupported parameters: " + ", ".join(sorted(set(params) - properties.keys())))
    values = {key: params.get(key, schema["default"]) for key, schema in properties.items()}
    for key, value in values.items():
        schema = properties[key]
        if schema["type"] == "array":
            values[key] = _array(key, value, schema)
        else:
            _scalar(key, value, schema)
    if "path" in values:
        path = values["path"]
        if not path.startswith("/") or path.startswith("//") or "\\" in path or any(ord(c) < 33 for c in path):
            raise ValueError("path must be a local absolute URL path")
    return values


def catalog(workflows: Path) -> list[dict]:
    entries = {}
    for path in sorted(workflows.glob("tool_*.*")):
        if path.suffix not in (".yaml", ".yml"):
            continue
        name = path.stem[5:]
        import re
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,38}", name):
            continue
        if name in entries:
            raise ValueError(f"Duplicate workflow tool: {name}")
        description, properties = SPECS.get(name, (f"Custom tool {name}; consult its workflow for supported params.", {}))
        entries[name] = {"name": name, "workflow": path.name, "description": description,
                         "parameters": {"type": "object", "properties": properties,
                                        "additionalProperties": name not in SPECS}}
    return list(entries.values())
