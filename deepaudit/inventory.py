"""Deterministic dependency inventory built from committed manifests and lockfiles.

No network, no model, no package-manager invocation. A dependency whose exact version is
not written down keeps `version: None` and is reported as undetermined, because resolving
it would mean running the ecosystem's resolver against a live registry.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

from .policy import PolicyError
from .versions import normalize_pypi

# A repository scan must stay bounded and must never descend into installed trees, which
# hold thousands of files and are not what the manifests declare.
SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
    "dist", "build", ".eggs", "vendor", "third_party", ".terraform", "audits",
}
MAX_DEPTH = 8
MAX_MANIFESTS = 200
MAX_FILE_BYTES = 8_000_000

PYPI = "PyPI"
NPM = "npm"

# `pinned` and `locked` carry an exact version; the others deliberately do not.
PINNED = "pinned"
LOCKED = "locked"
DECLARED_RANGE = "declared_range"

_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<rest>.*)$")


def resolve_repo(path: Path) -> Path:
    root = Path(path).resolve(strict=True)
    if not root.is_dir():
        raise PolicyError("Repository path is not a directory")
    return root


def _read(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def _component(ecosystem, raw_name, version, source, direct, resolution) -> dict:
    name = normalize_pypi(raw_name) if ecosystem == PYPI else raw_name.strip()
    purl = None
    if version:
        kind = "pypi" if ecosystem == PYPI else "npm"
        purl = f"pkg:{kind}/{name}@{version}"
    return {"ecosystem": ecosystem, "name": name, "raw_name": raw_name.strip(),
            "version": version, "purl": purl, "source": source,
            "direct": bool(direct), "resolution": resolution}


def parse_requirements(text: str, source: str) -> list[dict]:
    components = []
    joined = re.sub(r"\\\n", " ", text)
    for line in joined.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # An environment marker decides installation per platform; v0.2 records the
        # dependency and leaves the condition to the applicability engine.
        line = line.split(";", 1)[0].strip()
        if not line or line.startswith(("http:", "https:", "git+", ".", "/")):
            continue
        match = _REQUIREMENT_RE.match(line)
        if not match:
            continue
        rest = match.group("rest").strip()
        exact = re.fullmatch(r"==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)", rest)
        if exact and not exact.group(1).endswith("*"):
            components.append(_component(PYPI, match.group("name"), exact.group(1), source, True, PINNED))
        else:
            components.append(_component(PYPI, match.group("name"), None, source, True, DECLARED_RANGE))
    return components


def parse_pyproject(text: str, source: str) -> list[dict]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    names: list[str] = []
    project = data.get("project")
    if isinstance(project, dict):
        for entry in project.get("dependencies", []) or []:
            if isinstance(entry, str):
                names.append(entry)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                names.extend(item for item in (group or []) if isinstance(item, str))
    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        for key in ("dependencies", "dev-dependencies"):
            section = poetry.get(key)
            if isinstance(section, dict):
                names.extend(item for item in section if item.lower() != "python")
    components = []
    for entry in names:
        match = _REQUIREMENT_RE.match(entry.split(";", 1)[0].strip())
        if match:
            components.append(_component(PYPI, match.group("name"), None, source, True, DECLARED_RANGE))
    return components


def _parse_toml_lock(text: str, source: str) -> list[dict]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    components = []
    for package in data.get("package", []) or []:
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            version = package.get("version")
            components.append(_component(PYPI, package["name"],
                                         version if isinstance(version, str) else None,
                                         source, False, LOCKED if version else DECLARED_RANGE))
    return components


def parse_package_lock(text: str, source: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    components = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        # lockfileVersion 2/3: one flat map keyed by install path.
        for key, entry in packages.items():
            if not isinstance(entry, dict) or not key or entry.get("link"):
                continue
            marker = "node_modules/"
            index = key.rfind(marker)
            if index < 0:
                continue
            name = entry.get("name") if isinstance(entry.get("name"), str) else key[index + len(marker):]
            version = entry.get("version")
            if not isinstance(version, str) or not name:
                continue
            components.append(_component(NPM, name, version, source, False, LOCKED))
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict) and not components:
        # lockfileVersion 1: nested tree.
        def walk(node: dict, depth: int) -> None:
            if depth > MAX_DEPTH:
                return
            for name, entry in node.items():
                if not isinstance(entry, dict) or not isinstance(name, str):
                    continue
                version = entry.get("version")
                if isinstance(version, str):
                    components.append(_component(NPM, name, version, source, False, LOCKED))
                nested = entry.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested, depth + 1)
        walk(dependencies, 0)
    return components


def parse_package_json(text: str, source: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    components = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            for name in section:
                if isinstance(name, str) and name:
                    components.append(_component(NPM, name, None, source, True, DECLARED_RANGE))
    return components


_PARSERS = (
    (lambda n: n == "pyproject.toml", parse_pyproject),
    (lambda n: n in ("poetry.lock", "uv.lock"), _parse_toml_lock),
    (lambda n: n == "package-lock.json", parse_package_lock),
    (lambda n: n == "package.json", parse_package_json),
    (lambda n: n.startswith("requirements") and n.endswith(".txt"), parse_requirements),
)


def _manifests(root: Path) -> list[Path]:
    found: list[Path] = []
    stack = [(root, 0)]
    while stack and len(found) < MAX_MANIFESTS:
        directory, depth = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if depth < MAX_DEPTH and entry.name not in SKIP_DIRECTORIES and not entry.name.startswith("."):
                    stack.append((entry, depth + 1))
            elif any(test(entry.name) for test, _ in _PARSERS):
                found.append(entry)
    return sorted(found)


def collect(root: Path) -> dict:
    """Return the deduplicated inventory plus the manifests it was derived from."""
    root = resolve_repo(root)
    components: list[dict] = []
    sources: list[str] = []
    for path in _manifests(root):
        text = _read(path)
        if text is None:
            continue
        relative = path.relative_to(root).as_posix()
        for test, parser in _PARSERS:
            if test(path.name):
                parsed = parser(text, relative)
                if parsed:
                    components.extend(parsed)
                    sources.append(relative)
                break
    # A package can appear in a manifest and its lockfile; keep the entry that carries a
    # version, because only that one can be matched against an advisory range.
    best: dict[tuple[str, str, str | None], dict] = {}
    for item in components:
        key = (item["ecosystem"], item["name"], item["version"])
        current = best.get(key)
        if current is None:
            best[key] = item
        elif item["direct"] and not current["direct"]:
            best[key] = {**current, "direct": True}
    unique = list(best.values())
    for item in unique:
        if item["version"] is None:
            sibling = any(other["version"] is not None and other["ecosystem"] == item["ecosystem"]
                          and other["name"] == item["name"] for other in unique)
            item["superseded_by_locked_version"] = sibling
    resolved = [item for item in unique if item["version"] is not None]
    undetermined = [item for item in unique
                    if item["version"] is None and not item.get("superseded_by_locked_version")]
    ordered = sorted(resolved + undetermined,
                     key=lambda item: (item["ecosystem"], item["name"], item["version"] or ""))
    return {
        "schema_version": 1,
        "root": root.name,
        "manifests": sorted(set(sources)),
        "components": ordered,
        "counts": {"total": len(ordered), "with_version": len(resolved),
                   "undetermined_version": len(undetermined)},
    }
