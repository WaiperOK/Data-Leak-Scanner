# Changelog

## v0.2.0 - 2026-02-11
- Rebuilt repository as maintainable Python package under `src/`.
- Added deterministic leak detectors (email/card/AWS key/private key/JWT) and entropy-based secret detector.
- Added CLI commands (`scan`, `scan-http`) and HTTP service mode (`/healthz`, `/v1/scan`, `/metrics`).
- Added Burp adapter module, docs, CI, Docker stack, and tests.
