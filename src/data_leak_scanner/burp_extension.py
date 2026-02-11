"""Burp extension adapter.

This module keeps a slim Jython-compatible entry point for Burp users.
Core detection logic remains in `detector.py` and is shared with CLI/API.
"""

from __future__ import annotations

from data_leak_scanner.detector import scan_text


class BurpExtender:  # pragma: no cover - runtime-loaded by Burp/Jython
    def registerExtenderCallbacks(self, callbacks):  # noqa: N802
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Data Leak Scanner")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):  # noqa: N802
        response = baseRequestResponse.getResponse()
        if not response:
            return None
        text = self._helpers.bytesToString(response)
        result = scan_text(text)
        if result["summary"]["findings_total"] == 0:
            return None

        return [
            self._callbacks.applyMarkers(
                baseRequestResponse,
                None,
                None,
            )
        ]

    def doActiveScan(self, baseRequestResponse, insertionPoint):  # noqa: N802
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):  # noqa: N802
        return -1 if existingIssue.getIssueName() == newIssue.getIssueName() else 0
