from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

from data_leak_scanner.server import Metrics, create_handler


def _start(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), create_handler(Metrics()))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.15)
    return server


def test_scan_api_roundtrip() -> None:
    server = _start(18086)
    try:
        body = json.dumps({"text": "admin@example.com"}).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:18086/v1/scan",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["summary"]["findings_total"] >= 1
    finally:
        server.shutdown()


def test_metrics_endpoint() -> None:
    server = _start(18087)
    try:
        with urllib.request.urlopen("http://127.0.0.1:18087/metrics", timeout=2) as resp:  # noqa: S310
            text = resp.read().decode("utf-8")
        assert "data_leak_scanner_requests_total" in text
    finally:
        server.shutdown()
