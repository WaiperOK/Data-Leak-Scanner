from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detector import scan_text
from .http import split_http_payload
from .server import serve


def cmd_scan(args: argparse.Namespace) -> int:
    text = Path(args.input).read_text(encoding="utf-8")
    result = scan_text(text=text, allowlist=args.allowlist)

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        print(json.dumps(result, indent=2))
    return 0


def cmd_scan_http(args: argparse.Namespace) -> int:
    raw = Path(args.input).read_text(encoding="utf-8")
    _, body = split_http_payload(raw)
    result = scan_text(text=body, allowlist=args.allowlist)

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        print(json.dumps(result, indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    serve(args.host, args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="data-leak-scanner", description="Detect data leaks in HTTP payloads"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan plain text file")
    scan.add_argument("--input", required=True)
    scan.add_argument("--output")
    scan.add_argument("--allowlist", action="append", default=[])
    scan.set_defaults(func=cmd_scan)

    scan_http = sub.add_parser("scan-http", help="Scan raw HTTP payload file")
    scan_http.add_argument("--input", required=True)
    scan_http.add_argument("--output")
    scan_http.add_argument("--allowlist", action="append", default=[])
    scan_http.set_defaults(func=cmd_scan_http)

    server = sub.add_parser("serve", help="Run HTTP service")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8086)
    server.set_defaults(func=cmd_serve)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
