from __future__ import annotations

import re
from dataclasses import dataclass

BINARY_PLACEHOLDER = "[REDACTED-BINARY]"
ADDR_PLACEHOLDER = "[REDACTED-ADDR]"
HOST_PLACEHOLDER = "[REDACTED-HOST]"

BINARY_RE = re.compile(r"[^\x20-\x7E\x0A\x0D]+")
IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
FQDN_RE = re.compile(
    r"\b(?=[a-zA-Z0-9.\-]*[a-zA-Z])[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)


@dataclass(frozen=True)
class SanitizedText:
    text: str
    redactions: int


def sanitize_telemetry(text: str) -> SanitizedText:
    redactions = 0
    out, n = BINARY_RE.subn(BINARY_PLACEHOLDER, text)
    redactions += n
    out, n = IPV4_RE.subn(ADDR_PLACEHOLDER, out)
    redactions += n
    out, n = MAC_RE.subn(ADDR_PLACEHOLDER, out)
    redactions += n
    out, n = FQDN_RE.subn(HOST_PLACEHOLDER, out)
    redactions += n
    return SanitizedText(out, redactions)
