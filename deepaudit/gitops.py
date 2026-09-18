"""Explicit local commits, only generated artifacts; never a model-exposed tool."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile

from .policy import PolicyError


class GitError(RuntimeError):
    pass


def _git(repo: Path, args: list[str], *, check: bool = True, hooks_dir: str | None = None) -> subprocess.CompletedProcess:
    command = ["git", "--no-pager", "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false"]
    if hooks_dir is not None:
        command += ["-c", "core.hooksPath=" + hooks_dir]
    command += args
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_") and key not in {"DEEPSEEK_API_KEY", "GH_TOKEN", "GITHUB_TOKEN"}}
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(command, cwd=repo, env=env, capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError("Git is unavailable or timed out") from exc
    if check and result.returncode:
        raise GitError("Git operation failed; inspect your trusted repository configuration and identity")
    return result


def preflight(repo: Path) -> None:
    root = _git(repo, ["rev-parse", "--show-toplevel"]).stdout.strip()
    if Path(root).resolve() != repo.resolve():
        raise GitError("--repo must be the Git worktree root")
    if _git(repo, ["diff", "--cached", "--quiet"], check=False).returncode != 0:
        raise GitError("Existing staged changes found; commit or unstage them before --git-commit")
    for key in ("user.name", "user.email"):
        if not _git(repo, ["config", "--get", key], check=False).stdout.strip():
            raise GitError("Configure git user.name and user.email before --git-commit")


def _secret_scan(run_dir: Path) -> None:
    patterns = [r"sk-[A-Za-z0-9_-]{16,}", r"ghp_[A-Za-z0-9]{20,}",
                r"github_pat_[A-Za-z0-9_]{20,}", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"]
    actual = os.environ.get("DEEPSEEK_API_KEY", "")
    for path in run_dir.rglob("*"):
        if path.is_symlink():
            raise GitError("Refusing to commit symlinked artifacts")
        if path.is_file():
            if path.stat().st_size > 2_000_000:
                raise GitError("Artifact is unexpectedly large")
            content = path.read_text(encoding="utf-8")
            if (actual and actual in content) or any(re.search(pattern, content) for pattern in patterns):
                raise GitError("Potential secret in generated artifacts; commit cancelled")


def commit_run(repo: Path, run_dir: Path) -> str:
    preflight(repo)
    _secret_scan(run_dir)
    from .artifacts import check_integrity
    if not check_integrity(run_dir)["ok"]:
        raise GitError("Artifact integrity check failed; commit cancelled")
    try:
        relative = run_dir.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise PolicyError("Only artifacts inside the selected repository can be committed") from exc
    if relative.startswith(".git/") or relative == ".git":
        raise PolicyError("Invalid artifact directory")
    # Serialize only the controlled paths; no `git add .`, push, or shell interpolation.
    with tempfile.TemporaryDirectory(prefix="deepaudit-no-hooks-") as empty_hooks:
        _git(repo, ["--literal-pathspecs", "add", "--", relative], hooks_dir=empty_hooks)
        staged = _git(repo, ["diff", "--cached", "--name-only", "-z"], hooks_dir=empty_hooks).stdout
        if any(not name.startswith(relative + "/") for name in staged.split("\0") if name):
            raise GitError("Unexpected staged paths; commit cancelled")
        _git(repo, ["commit", "-m", "audit: add verified observations " + run_dir.name], hooks_dir=empty_hooks)
        return _git(repo, ["rev-parse", "HEAD"], hooks_dir=empty_hooks).stdout.strip()
