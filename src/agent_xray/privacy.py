"""Outbound HTTP header fingerprint auditor, stripper, and secret egress guard."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Iterable

from . import __version__

SENSITIVE_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "api-key",
    "proxy-authorization",
    "cookie",
    "set-cookie",
}

TELEMETRY_HEADER_PREFIXES = (
    "x-stainless-",
    "x-client-data",
    "x-telemetry-",
    "x- sentry-",
    "sentry-trace",
    "baggage",
)

TELEMETRY_EXACT_HEADERS = {
    "x-client-version",
    "x-sdk-telemetry",
    "openai-organization",
    "openai-project",
}

OS_LEAK_TOKENS = ("darwin", "mac os", "arm64", "aarch64", "x86_64", "linux", "win32")

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API Key", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b")),
    ("OpenAI Project Key", re.compile(r"\bsk-proj-[a-zA-Z0-9_-]{20,}\b")),
    ("GitHub PAT", re.compile(r"\b(?:ghp|github_pat)_[a-zA-Z0-9_]{24,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("PEM Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
]


@dataclass
class HeaderAuditEntry:
    name: str
    display_value: str
    category: str       # "auth" | "telemetry" | "fingerprint" | "protocol"
    action: str         # "redacted" | "stripped" | "normalized" | "forwarded"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class SecretFinding:
    rule: str
    redacted_snippet: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def redact_secret_value(raw: str) -> str:
    clean = raw.strip()
    if clean.lower().startswith("bearer "):
        token = clean[7:].strip()
        return f"Bearer {_mask(token)}"
    return _mask(clean)


def _mask(token: str) -> str:
    if len(token) <= 10:
        return "••••••••"
    return f"{token[:6]}••••{token[-3:]} ({len(token)} chars)"


def audit_and_prepare_headers(
    inbound_headers: Iterable[tuple[str, str]],
    *,
    strip_telemetry: bool = False,
) -> tuple[dict[str, str], list[HeaderAuditEntry]]:
    """Prepares upstream headers while recording a redacted privacy audit trail."""
    hop_by_hop = {"host", "connection", "keep-alive", "transfer-encoding", "content-length"}
    outbound: dict[str, str] = {}
    audit: list[HeaderAuditEntry] = []

    for name, value in inbound_headers:
        lower = name.lower()
        if lower in hop_by_hop:
            continue

        if lower in SENSITIVE_AUTH_HEADERS:
            outbound[name] = value
            audit.append(
                HeaderAuditEntry(
                    name=name,
                    display_value=redact_secret_value(value),
                    category="auth",
                    action="redacted",
                )
            )
            continue

        is_telemetry = lower in TELEMETRY_EXACT_HEADERS or any(
            lower.startswith(p) for p in TELEMETRY_HEADER_PREFIXES
        )
        if is_telemetry:
            if strip_telemetry:
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        display_value=value[:80],
                        category="telemetry",
                        action="stripped",
                    )
                )
            else:
                outbound[name] = value
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        display_value=value[:80],
                        category="telemetry",
                        action="forwarded",
                    )
                )
            continue

        if lower == "user-agent":
            has_os_leak = any(tok in value.lower() for tok in OS_LEAK_TOKENS)
            if strip_telemetry:
                norm_ua = f"agent-xray/{__version__}"
                outbound["User-Agent"] = norm_ua
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        display_value=f"{value[:64]} -> {norm_ua}",
                        category="fingerprint" if has_os_leak else "protocol",
                        action="normalized",
                    )
                )
            else:
                outbound[name] = value
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        display_value=value[:80],
                        category="fingerprint" if has_os_leak else "protocol",
                        action="forwarded",
                    )
                )
            continue

        outbound[name] = value
        audit.append(
            HeaderAuditEntry(
                name=name,
                display_value=value[:80],
                category="protocol",
                action="forwarded",
            )
        )

    return outbound, audit


def scan_body_for_secrets(raw_text: str) -> list[SecretFinding]:
    """Detects live credential patterns in outbound prompt text without storing raw secrets."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()
    for rule_name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(raw_text):
            matched = match.group(0)
            masked = _mask(matched)
            key = (rule_name, masked)
            if key not in seen:
                seen.add(key)
                findings.append(SecretFinding(rule=rule_name, redacted_snippet=masked))
    return findings


def redact_secrets_in_text(text: str) -> str:
    """Scrubs any matched credential pattern out of human-readable prompt previews."""
    if not text:
        return text
    scrubbed = text
    for _, pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub(lambda m: _mask(m.group(0)), scrubbed)
    return scrubbed
