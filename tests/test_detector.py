from data_leak_scanner.detector import scan_text, shannon_entropy


def test_scans_emails_and_cards() -> None:
    payload = "user=alice@example.com card=4111 1111 1111 1111"
    result = scan_text(payload)

    assert result["summary"]["findings_total"] >= 2
    ids = {item["detector_id"] for item in result["findings"]}
    assert "DLS001" in ids
    assert "DLS002" in ids


def test_allowlist_filters_findings() -> None:
    payload = "known@example.com"
    result = scan_text(payload, allowlist=[r"known@example.com"])
    assert result["summary"]["findings_total"] == 0


def test_entropy_function() -> None:
    assert shannon_entropy("AAAAAAAAAAAA") < 1.0
    assert shannon_entropy("pQm9ZsA7Hd3mLw9B2tR5fY6nK1xV0cQ8") > 4.0
