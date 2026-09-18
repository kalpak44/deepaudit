"""Run model-authored Python over already-collected evidence: no network, bounded CPU/memory/output.

The guarantee is layered. The parent runs the child under `unshare -rn` when available (a private
network namespace with no connectivity, the real block on the Linux audit runner). Inside the child
we additionally set resource limits and neuter the socket module as defense in depth, and the parent's
wall-clock timeout is the final backstop. The environment is stripped of every inherited secret.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# argv: code_path evidence_path out_path ; env: CPU MEM FSIZE OUTPUT (integers)
CHILD = r'''
import json, os, sys, resource, traceback

def _limit(kind, value):
    try:
        resource.setrlimit(kind, (value, value))
    except (ValueError, OSError):
        pass

_limit(resource.RLIMIT_CPU, int(os.environ["CPU"]))
_limit(resource.RLIMIT_AS, int(os.environ["MEM"]))
_limit(resource.RLIMIT_FSIZE, int(os.environ["FSIZE"]))
_limit(resource.RLIMIT_NPROC, 0)

import socket as _socket
def _deny(*a, **k):
    raise OSError("network access is disabled in the analysis sandbox")
_socket.socket = _deny
_socket.create_connection = _deny
_socket.getaddrinfo = _deny

code_path, evidence_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
limit = int(os.environ["OUTPUT"])
evidence = json.load(open(evidence_path, encoding="utf-8"))
namespace = {"evidence": evidence, "result": None, "__name__": "__analysis__"}

def emit(payload):
    open(out_path, "w", encoding="utf-8").write(json.dumps(payload))

try:
    exec(compile(open(code_path, encoding="utf-8").read(), "<script>", "exec"), namespace)
except Exception as exc:
    emit({"error": type(exc).__name__ + ": " + str(exc)[:500], "traceback": traceback.format_exc()[-1500:]})
    sys.exit(2)

try:
    serialized = json.dumps(namespace.get("result"))
except (TypeError, ValueError):
    emit({"error": "result is not JSON-serializable; assign JSON-compatible data to `result`"})
    sys.exit(3)
if len(serialized) > limit:
    emit({"error": f"result is {len(serialized)} bytes, over the {limit} byte cap; summarize before returning"})
    sys.exit(4)
emit({"result": json.loads(serialized)})
'''


def _wrap(argv):
    unshare = shutil.which("unshare")
    if unshare and sys.platform.startswith("linux"):
        return [unshare, "-r", "-n", *argv], "network-namespace"
    return argv, "socket-neutered-only"


def run_user_code(code: str, evidence: dict, *, cpu_seconds: int = 20, mem_bytes: int = 512 * 1024 * 1024,
                  fsize_bytes: int = 1024 * 1024, output_limit: int = 200000, wall_seconds: int = 30) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "code.py").write_text(code, encoding="utf-8")
        (base / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
        (base / "child.py").write_text(CHILD, encoding="utf-8")
        argv, isolation = _wrap([sys.executable, "-I", str(base / "child.py"),
                                 str(base / "code.py"), str(base / "evidence.json"), str(base / "out.json")])
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "CPU": str(cpu_seconds),
               "MEM": str(mem_bytes), "FSIZE": str(fsize_bytes), "OUTPUT": str(output_limit)}
        try:
            proc = subprocess.run(argv, cwd=tmp, env=env, capture_output=True, text=True, timeout=wall_seconds)
        except subprocess.TimeoutExpired:
            return {"status": "failed", "isolation": isolation,
                    "error": f"analysis exceeded the {wall_seconds}s wall-clock limit"}
        stdout = (proc.stdout or "")[-4000:]
        out_path = base / "out.json"
        if not out_path.is_file():
            return {"status": "failed", "isolation": isolation, "stdout": stdout,
                    "error": (proc.stderr or "analysis produced no result")[-700:]}
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        if "error" in payload:
            return {"status": "failed", "isolation": isolation, "stdout": stdout, **payload}
        return {"status": "ok", "isolation": isolation, "stdout": stdout, "result": payload["result"]}
