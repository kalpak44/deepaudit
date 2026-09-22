"""The `run` capability: install the tools the agent asks for, then run its code on the target.

This is the agent's hands. It may name arsenal tools to set up, extra apt/pip/go/npm packages
to install, and a bash or python script to run. The script runs in the ephemeral runner with
network access and the authorized target exposed as environment variables. This is general
code execution — it is NOT technically confined to the target — so scope is enforced by the
agent's instructions, the single-target framing, and the fact that inherited secrets are
stripped from the child environment before anything runs.

Environment handed to the script:
    AUDIT_TARGET  the canonical scheme://host[:port]/path
    AUDIT_HOST    the hostname alone
    AUDIT_ADDR    a resolved public IP for the host (private resolutions are refused)
    OUT           a path; write JSON there to return a structured result alongside stdout
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from . import arsenal
from .target import origin, public_address, target_url

_UNSAFE_ENV = re.compile(r"TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|GITHUB_|ACTIONS_|RUNNER_|"
                         r"LLM_|DEEPSEEK|OPENAI|ANTHROPIC|GH_", re.I)
INSTALL_TIMEOUT = 600
MAX_LOG = 6000
MAX_STDOUT = 12000


def _clean_env(target: str, addr: str, out_path: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not _UNSAFE_ENV.search(k)}
    gobin = os.path.join(env.get("GOPATH", os.path.expanduser("~/go")), "bin")
    env["PATH"] = f"{gobin}:{os.path.expanduser('~/.local/bin')}:" + env.get("PATH", "/usr/bin:/bin")
    env.update(AUDIT_TARGET=target, AUDIT_HOST=urlsplit(target).hostname or "",
               AUDIT_ADDR=addr, OUT=out_path, DEBIAN_FRONTEND="noninteractive")
    return env


def _bash(script: str, env: dict, timeout: int, cwd: str) -> dict:
    try:
        proc = subprocess.run(["bash", "-c", script], env=env, cwd=cwd,
                              capture_output=True, text=True, timeout=timeout, check=False)
        return {"returncode": proc.returncode, "ok": proc.returncode == 0,
                "stdout": (proc.stdout or "")[-MAX_STDOUT:], "stderr": (proc.stderr or "")[-MAX_LOG:]}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "timed_out": timeout, "error": f"exceeded {timeout}s",
                "stdout": (exc.stdout or b"")[-MAX_STDOUT:].decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")[-MAX_STDOUT:]}


class Runner:
    """Holds the fixed target and exposes `run` as an agent tool. Thread-safe for fan-out."""

    def __init__(self, target: str, console, *, install_timeout=INSTALL_TIMEOUT):
        self.target = target_url(target)
        self.host, self.port = urlsplit(self.target).hostname, origin(self.target)[2]
        self.console = console
        self.install_timeout = install_timeout

    def _install(self, args, env, cwd) -> dict | None:
        commands = list(arsenal.install_commands(args.get("setup")))
        apt = [p for p in args.get("apt", []) if re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", str(p))]
        pip = [p for p in args.get("pip", []) if re.fullmatch(r"[A-Za-z0-9][\w.\[\]<>=!~,+*-]*", str(p))]
        go = [p for p in args.get("go", []) if re.fullmatch(r"[\w./@-]+", str(p))]
        npm = [p for p in args.get("npm", []) if re.fullmatch(r"[@\w./-]+", str(p))]
        if apt:
            commands = ["sudo apt-get update -qq"] + [f"sudo apt-get install -y -qq {' '.join(apt)}"] + commands
        elif any("apt-get install" in c for c in commands):
            commands = ["sudo apt-get update -qq"] + commands
        if pip:
            commands.append(f"pip install -q --disable-pip-version-check {' '.join(pip)}")
        for module in go:
            commands.append(f"go install -v {module}")
        if npm:
            commands.append(f"sudo npm install -g {' '.join(npm)} >/dev/null 2>&1")
        if not commands:
            return None
        script = "set +e\n" + "\n".join(commands)
        self.console.event("INSTALL", "setup", tools=arsenal.known(args.get("setup")),
                           apt=apt, pip=pip, go=go, npm=npm)
        result = _bash(script, env, self.install_timeout, cwd)
        return {"requested": {"setup": arsenal.known(args.get("setup")), "apt": apt,
                              "pip": pip, "go": go, "npm": npm},
                "log": (result.get("stdout", "") + result.get("stderr", ""))[-MAX_LOG:],
                "ok": result.get("ok", False)}

    def run(self, args: dict) -> dict:
        code = args.get("code", "")
        if not isinstance(code, str) or not code.strip():
            return {"error": "Provide a `code` script (bash or python) to run"}
        lang = args.get("lang", "bash")
        if lang not in ("bash", "python"):
            return {"error": "lang must be 'bash' or 'python'"}
        timeout = args.get("timeout", 240)
        if type(timeout) is not int or not 1 <= timeout <= 1500:
            return {"error": "timeout must be an integer 1..1500 seconds"}
        try:
            addr = public_address(self.host, self.port)
        except ValueError as exc:
            return {"error": str(exc)}
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            env = _clean_env(self.target, addr, out)
            install = self._install(args, env, tmp)
            script_path = Path(tmp) / ("script.sh" if lang == "bash" else "script.py")
            script_path.write_text(code, encoding="utf-8")
            interp = ["bash", str(script_path)] if lang == "bash" else ["python3", str(script_path)]
            self.console.event("RUN", lang, target=self.target, chars=len(code))
            try:
                proc = subprocess.run(interp, env=env, cwd=tmp, capture_output=True,
                                      text=True, timeout=timeout, check=False)
                run = {"returncode": proc.returncode, "ok": proc.returncode == 0,
                       "stdout": (proc.stdout or "")[-MAX_STDOUT:], "stderr": (proc.stderr or "")[-MAX_LOG:]}
            except subprocess.TimeoutExpired:
                run = {"ok": False, "timed_out": timeout, "error": f"script exceeded {timeout}s"}
            if os.path.isfile(out):
                raw = Path(out).read_text(encoding="utf-8", errors="replace")[:200_000]
                try:
                    run["result"] = json.loads(raw)
                except ValueError:
                    run["result_text"] = raw[:12000]
        self.console.event("RUN", "done", ok=run.get("ok"), rc=run.get("returncode"))
        payload = {"lang": lang, "run": run,
                   "note": "General code execution with network in an ephemeral, tokenless runner. "
                           "It is NOT confined to the target — only act against $AUDIT_TARGET. A "
                           "nonzero return code or failed install is a coverage gap, not a pass."}
        if install is not None:
            payload["install"] = install
        return payload
