# Threat Model

## Assets
- Captured HTTP payloads.
- Detection reports used by AppSec and incident response.

## Threats
- High-volume payloads causing scanner resource pressure.
- False negatives due to obfuscation/encoding.
- False positives for sanctioned synthetic test data.

## Mitigations
- Deterministic rules plus entropy heuristics.
- Allowlist controls for trusted synthetic patterns.
- Recommendation: route large payload processing via queue workers.
