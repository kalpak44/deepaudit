"""Small, dependency-free event log for readable GitHub Actions output."""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path


class Console:
    def __init__(self, path: Path | None = None):
        self.path = path
        self._lock = threading.Lock()

    def event(self, kind: str, message: str, **data) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        suffix = ""
        if data:
            suffix = " " + json.dumps(data, ensure_ascii=True, sort_keys=True)
        # Prefix every line: target text must never become an Actions workflow command.
        safe = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", message + suffix)
        with self._lock:
            for line in safe.splitlines() or [""]:
                print(f"[{stamp}] {kind:<10} {line}", flush=True)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"time": stamp, "kind": kind, "message": message, **data}, ensure_ascii=True) + "\n")

    def agent(self, employee: str, message: str) -> None:
        self.event("AGENT", f"{employee}: {message}")
