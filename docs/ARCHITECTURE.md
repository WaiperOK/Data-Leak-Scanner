# Data-Leak-Scanner Architecture

## Components
- Scanner core: deterministic + entropy detectors.
- CLI: batch scans in CI/security review workflows.
- HTTP service: `/v1/scan` for platform integration.
- Burp adapter: optional passive scanner bridge.
- Metrics: Prometheus output on `/metrics`.

## Data flow
```mermaid
flowchart LR
  A["Raw HTTP/Text"] --> B["Detection Engine"]
  C["CLI"] --> B
  D["HTTP API /v1/scan"] --> B
  E["Burp Adapter"] --> B
  B --> F["Findings JSON"]
  B --> G["Severity Summary"]
  B --> H["Metrics /metrics"]
```
