"""Discover roles from the filesystem. A role is a folder under roles/ with a role.md.

The role.md is both the documentation and the agent's system prompt: its first paragraph
(everything up to the first blank line after the heading) is the one-line summary the root
agent sees in its roster; the whole file is the prompt handed to the role when it runs.
Adding a capability is adding a folder and a workflow, never editing this file.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROLES_DIR = REPO_ROOT / "roles"

# The root agent orchestrates; it is not itself a dispatchable worker.
ROOT_ROLE = "root"
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,38}$")


def _summary(text: str) -> str:
    lines = [line.strip() for line in text.splitlines()]
    body = [line for line in lines if line and not line.startswith("#")]
    return (body[0] if body else "").strip()[:200]


def role_prompt(name: str) -> str:
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"Invalid role name: {name!r}")
    path = ROLES_DIR / name / "role.md"
    if not path.is_file():
        raise FileNotFoundError(f"No role.md for role {name!r}")
    return path.read_text(encoding="utf-8")


def list_roles() -> list[dict]:
    """Every dispatchable role (root excluded), name + one-line summary, sorted."""
    roles = []
    if not ROLES_DIR.is_dir():
        return roles
    for entry in sorted(ROLES_DIR.iterdir()):
        if not entry.is_dir() or entry.name == ROOT_ROLE:
            continue
        role_md = entry / "role.md"
        if _NAME_RE.fullmatch(entry.name) and role_md.is_file():
            roles.append({"role": entry.name,
                          "summary": _summary(role_md.read_text(encoding="utf-8")),
                          "workflow": f"role-{entry.name}.yml"})
    return roles


def role_names() -> set[str]:
    return {role["role"] for role in list_roles()}
