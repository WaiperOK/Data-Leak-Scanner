from __future__ import annotations


def split_http_payload(raw: str) -> tuple[str, str]:
    marker = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    parts = raw.split(marker, maxsplit=1)
    if len(parts) != 2:
        return "", raw
    return parts[0], parts[1]
