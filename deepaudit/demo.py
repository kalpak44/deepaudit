"""Loopback-only demonstration server; no deliberately exploitable application."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading


class DemoHandler(BaseHTTPRequestHandler):
    hardened = False
    server_version = "DeepAuditDemo"
    sys_version = ""

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            # A TLS-only probe intentionally closes without making an HTTP request.
            pass

    def do_GET(self) -> None:
        body = b"<!doctype html><title>DeepAudit demo</title><h1>Local audit fixture</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.hardened:
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "demo=not-a-secret; HttpOnly; SameSite=Lax; Path=/")
        else:
            self.send_header("Set-Cookie", "demo=not-a-secret; Path=/")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass


def create_server(port: int = 0, *, hardened: bool = False) -> ThreadingHTTPServer:
    handler = type("ConfiguredDemoHandler", (DemoHandler,), {"hardened": hardened})
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


@contextmanager
def local_demo(*, hardened: bool = False):
    server = create_server(hardened=hardened)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
