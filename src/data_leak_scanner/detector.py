from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .models import LeakFinding, Severity


@dataclass(slots=True)
class Detector:
    detector_id: str
    severity: Severity
    label: str
    pattern: re.Pattern[str]


DEFAULT_DETECTORS = [
    Detector(
        detector_id="DLS001",
        severity=Severity.MEDIUM,
        label="Email address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    Detector(
        detector_id="DLS002",
        severity=Severity.HIGH,
        label="Payment card",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    ),
    Detector(
        detector_id="DLS003",
        severity=Severity.HIGH,
        label="AWS access key",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    Detector(
        detector_id="DLS004",
        severity=Severity.HIGH,
        label="Private key block",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    Detector(
        detector_id="DLS005",
        severity=Severity.MEDIUM,
        label="JWT token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(value)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _entropy_candidates(text: str) -> list[LeakFinding]:
    token_re = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
    findings = []
    for match in token_re.finditer(text):
        value = match.group(0)
        if shannon_entropy(value) >= 4.2:
            findings.append(
                LeakFinding(
                    detector_id="DLS006",
                    severity=Severity.MEDIUM,
                    label="High-entropy secret candidate",
                    match=value,
                    start=match.start(),
                    end=match.end(),
                )
            )
    return findings


def _is_allowed(match_value: str, allowlist: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(match_value) for pattern in allowlist)


def scan_text(text: str, allowlist: list[str] | None = None) -> dict[str, object]:
    compiled_allowlist = [re.compile(pattern) for pattern in (allowlist or [])]

    findings: list[LeakFinding] = []
    for detector in DEFAULT_DETECTORS:
        for match in detector.pattern.finditer(text):
            value = match.group(0)
            if _is_allowed(value, compiled_allowlist):
                continue
            findings.append(
                LeakFinding(
                    detector_id=detector.detector_id,
                    severity=detector.severity,
                    label=detector.label,
                    match=value,
                    start=match.start(),
                    end=match.end(),
                )
            )

    for finding in _entropy_candidates(text):
        if _is_allowed(finding.match, compiled_allowlist):
            continue
        findings.append(finding)

    severity_summary: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    for finding in findings:
        severity_summary[finding.severity.value] += 1

    return {
        "summary": {
            "findings_total": len(findings),
            "severity": severity_summary,
        },
        "findings": [item.to_dict() for item in findings],
    }
