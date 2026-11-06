from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

BINARY_PLACEHOLDER = "[REDACTED-BINARY]"
ADDR_PLACEHOLDER = "[REDACTED-ADDR]"
HOST_PLACEHOLDER = "[REDACTED-HOST]"
SECRET_PLACEHOLDER = "[REDACTED-SECRET]"
USER_PLACEHOLDER = "[REDACTED-USER]"
URL_PLACEHOLDER = "[REDACTED-URL]"
EMAIL_PLACEHOLDER = "[REDACTED-EMAIL]"

BINARY_RE = re.compile(r"[^\x20-\x7E\x0A\x0D]+")
PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S
)
TOKEN_RE = re.compile(
    r"\b(?:A(?:KIA|SIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{20,}"
    r"|xox[abpr]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+)\b"
)
BEARER_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I)
SECRET_KV_RE = re.compile(
    r"\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)"
    r"(\"?\s*[=:]\s*\"?)[^\s\"',;&]+",
    re.I,
)
URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\b")
USER_PATH_RE = re.compile(r"([A-Za-z]:\\+Users\\+|/home/|/Users/)([^\\/\s\"']+)")
USER_KV_RE = re.compile(r"\b(user(?:name)?|account)(\"?\s*[=:]\s*\"?)[^\s\"',;&]+", re.I)
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f.]{0,15}){2,}(?:%\w+)?(?![\w:])")
IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
LABELLED_HOST_RE = re.compile(
    r"\b(host(?:name)?|computer|node|workstation)(\"?\s*[=:]?\s*\"?)(?=[\w-]*[\d-])[A-Za-z0-9][\w-]*",
    re.I,
)
FQDN_RE = re.compile(
    r"\b(?=[a-zA-Z0-9.\-]*[a-zA-Z])[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)


@dataclass(frozen=True)
class SanitizedText:
    text: str
    redactions: int


def _ipv6(match: re.Match[str]) -> str:
    candidate = match.group(0).split("%", 1)[0]
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return match.group(0)
    return ADDR_PLACEHOLDER if len(candidate) > 2 else match.group(0)


def sanitize_telemetry(text: str) -> SanitizedText:
    """Redact identifiers and secrets. Order matters: broad forms run before their parts."""
    redactions = 0
    out = text
    steps = (
        (BINARY_RE, BINARY_PLACEHOLDER),
        (PEM_RE, SECRET_PLACEHOLDER),
        (TOKEN_RE, SECRET_PLACEHOLDER),
        (BEARER_RE, rf"\1 {SECRET_PLACEHOLDER}"),
        (SECRET_KV_RE, rf"\1\2{SECRET_PLACEHOLDER}"),
        (URL_RE, URL_PLACEHOLDER),
        (EMAIL_RE, EMAIL_PLACEHOLDER),
        (USER_PATH_RE, rf"\1{USER_PLACEHOLDER}"),
        (USER_KV_RE, rf"\1\2{USER_PLACEHOLDER}"),
        (MAC_RE, ADDR_PLACEHOLDER),
    )
    for pattern, replacement in steps:
        out, n = pattern.subn(replacement, out)
        redactions += n
    before = out.count(ADDR_PLACEHOLDER)
    out = IPV6_CANDIDATE_RE.sub(_ipv6, out)
    redactions += out.count(ADDR_PLACEHOLDER) - before
    out, n = IPV4_RE.subn(ADDR_PLACEHOLDER, out)
    redactions += n
    out, n = LABELLED_HOST_RE.subn(rf"\1\2{HOST_PLACEHOLDER}", out)
    redactions += n
    out, n = FQDN_RE.subn(HOST_PLACEHOLDER, out)
    redactions += n
    return SanitizedText(out, redactions)
