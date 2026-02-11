from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .detector import scan_text


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests_total = 0
        self.bytes_scanned_total = 0

    def add(self, bytes_count: int) -> None:
        with self._lock:
            self.requests_total += 1
            self.bytes_scanned_total += bytes_count

    def render(self) -> str:
        with self._lock:
            return (
                "# TYPE data_leak_scanner_requests_total counter\n"
                f"data_leak_scanner_requests_total {self.requests_total}\n"
                "# TYPE data_leak_scanner_bytes_scanned_total counter\n"
                f"data_leak_scanner_bytes_scanned_total {self.bytes_scanned_total}\n"
            )


def create_handler(metrics: Metrics):
    class Handler(BaseHTTPRequestHandler):
        def _write_json(self, status: int, body: dict[str, object]) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._write_json(200, {"status": "ok"})
                return
            if self.path == "/metrics":
                body = metrics.render().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._write_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/scan":
                self._write_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length)
                data = json.loads(payload.decode("utf-8"))
                text = str(data.get("text", ""))
                allowlist = list(data.get("allowlist", []))
                result = scan_text(text, allowlist=allowlist)
                metrics.add(len(text.encode("utf-8")))
                self._write_json(200, result)
            except (ValueError, TypeError, json.JSONDecodeError):
                self._write_json(400, {"error": "invalid_payload"})

    return Handler


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), create_handler(Metrics()))
    server.serve_forever()
