"""Outbound HTTP header fingerprint auditor, stripper, and secret egress guard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

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
    (
        "PEM Private Key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[\r\n].*)",
            re.DOTALL,
        ),
    ),
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-(?![xX]{16,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{12,}"),
    ),
    (
        "OpenAI Project Key",
        re.compile(r"sk-(?:proj|svcacct)-(?![xX]{16,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{12,}"),
    ),
    (
        "OpenRouter API Key",
        re.compile(r"sk-or-v1-(?![xX]{16,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{12,}"),
    ),
    (
        "OpenAI API Key",
        re.compile(
            r"(?<![A-Za-z0-9])sk-(?!(?:ssh|ecdsa|ant|proj|svcacct|or-v1)-)"
            r"(?![xX]{20,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{20,}"
        ),
    ),
    (
        "GitHub PAT",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_(?![xX]{20,}(?![A-Za-z0-9_]))[A-Za-z0-9_]{20,}"),
    ),
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])AKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9A-Za-z-]{16,}"),
    ),
    (
        "Google API Key",
        re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{30,}"),
    ),
    (
        "JWT Token",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
]

_UNCLOSED_PEM_REDACT_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*", re.DOTALL)


@dataclass
class HeaderAuditEntry:
    name: str
    value_length: int
    category: str       # "auth" | "telemetry" | "fingerprint" | "protocol"
    action: str         # "redacted" | "stripped" | "normalized" | "forwarded"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_length": self.value_length,
            "category": self.category,
            "action": self.action,
        }


@dataclass
class SecretFinding:
    rule: str
    field: str = "body"
    redacted_snippet: str = "[REDACTED]"

    def to_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "field": self.field,
        }


def audit_and_prepare_headers(
    inbound_headers: Iterable[tuple[str, str]],
    *,
    strip_telemetry: bool = False,
) -> tuple[dict[str, str], list[HeaderAuditEntry]]:
    """Prepares upstream headers while recording only header names and value lengths."""
    hop_by_hop = {"host", "connection", "keep-alive", "transfer-encoding", "content-length"}
    outbound: dict[str, str] = {}
    audit: list[HeaderAuditEntry] = []

    for name, value in inbound_headers:
        lower = name.lower()
        if lower in hop_by_hop:
            continue
        vlen = len(value)

        if lower in SENSITIVE_AUTH_HEADERS:
            outbound[name] = value
            audit.append(
                HeaderAuditEntry(
                    name=name,
                    value_length=vlen,
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
                        value_length=vlen,
                        category="telemetry",
                        action="stripped",
                    )
                )
            else:
                outbound[name] = value
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        value_length=vlen,
                        category="telemetry",
                        action="forwarded",
                    )
                )
            continue

        if lower == "user-agent":
            has_os_leak = any(tok in value.lower() for tok in OS_LEAK_TOKENS)
            if strip_telemetry:
                outbound["User-Agent"] = f"agent-xray/{__version__}"
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        value_length=vlen,
                        category="fingerprint" if has_os_leak else "protocol",
                        action="normalized",
                    )
                )
            else:
                outbound[name] = value
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        value_length=vlen,
                        category="fingerprint" if has_os_leak else "protocol",
                        action="forwarded",
                    )
                )
            continue

        outbound[name] = value
        audit.append(
            HeaderAuditEntry(
                name=name,
                value_length=vlen,
                category="protocol",
                action="forwarded",
            )
        )

    return outbound, audit


def scan_body_for_secrets(raw_text: str, *, field: str = "body") -> list[SecretFinding]:
    """Detects live credential patterns in text without storing any secret characters."""
    if not raw_text:
        return []
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()
    for rule_name, pattern in SECRET_PATTERNS:
        if pattern.search(raw_text):
            key = (rule_name, field)
            if key not in seen:
                seen.add(key)
                findings.append(SecretFinding(rule=rule_name, field=field))
    return findings


def scan_payload_for_secrets(payload: Any, *, raw_fallback: str = "") -> list[SecretFinding]:
    """Scans parsed JSON payload fields recursively, recording rule and JSON path only."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, str):
            for f in scan_body_for_secrets(node, field=path or "body"):
                key = (f.rule, f.field)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
        elif isinstance(node, dict):
            for k, v in node.items():
                child_path = f"{path}.{k}" if path else str(k)
                _walk(v, child_path)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                child_path = f"{path}[{idx}]" if path else f"[{idx}]"
                _walk(item, child_path)

    if payload is not None:
        _walk(payload, "")

    if raw_fallback:
        found_rules = {f.rule for f in findings}
        for f in scan_body_for_secrets(raw_fallback, field="body"):
            if f.rule not in found_rules:
                findings.append(f)
                found_rules.add(f.rule)

    return findings


def redact_secrets_in_text(text: str) -> str:
    """Replaces all matched credentials and PEM private key blocks before any truncation."""
    if not text:
        return ""
    scrubbed = text
    for _, pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    scrubbed = _UNCLOSED_PEM_REDACT_RE.sub("[REDACTED]", scrubbed)
    return scrubbed
