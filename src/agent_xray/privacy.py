"""Outbound HTTP header fingerprint auditor, stripper, and secret egress guard."""

from __future__ import annotations

import json
import re
import urllib.parse
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from . import __version__

MAX_INSPECTED_BODY_BYTES = 32 * 1024 * 1024

SENSITIVE_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "api-key",
    "proxy-authorization",
    "cookie",
    "set-cookie",
}

# Only upstream authentication credentials needed by Anthropic/OpenAI APIs are
# exempted from --block-secrets value blocking. Other sensitive headers (Cookie,
# Referer, X-Custom-Token, etc.) are still scanned for leaked secrets.
LEGIT_UPSTREAM_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "api-key",
}

TELEMETRY_HEADER_PREFIXES = (
    "x-stainless-",
    "x-client-data",
    "x-telemetry-",
    "x-sentry-",
    "x- sentry-",
    "sentry-trace",
    "baggage",
)

# NOTE: openai-organization and openai-project control upstream billing/routing
# attribution and MUST NEVER be stripped.
TELEMETRY_EXACT_HEADERS = {
    "x-client-version",
    "x-client-telemetry",
    "x-sdk-telemetry",
    "sentry-trace",
    "baggage",
}

OS_LEAK_TOKENS = ("darwin", "mac os", "arm64", "aarch64", "x86_64", "linux", "win32")

_PEM_MATERIAL_HEAD = (
    r"(?:(?i:Proc-Type:|DEK-Info:)|"
    r"[A-Za-z0-9+/=]{4,}(?=[ \t]*(?:\r?\n|(?i:-----END)|$)))"
)
_MAX_UNQUOTE_ROUNDS = 8

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "PEM Private Key",
        re.compile(
            r"(?i:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[ \t]*\r?\n"
            r"(?=" + _PEM_MATERIAL_HEAD + r")"
            r"(?:.*?(?i:-----END [A-Z0-9 ]*PRIVATE KEY-----)|[A-Za-z0-9+/=:\r\n \t,-]+)",
            re.DOTALL,
        ),
    ),
    (
        "Anthropic API Key",
        re.compile(r"(?i:sk-ant-)(?![xX]{8,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{8,}"),
    ),
    (
        "OpenAI Project Key",
        re.compile(r"(?i:sk-(?:proj|svcacct)-)(?![xX]{8,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{8,}"),
    ),
    (
        "OpenRouter API Key",
        re.compile(r"(?i:sk-or-v1-)(?![xX]{8,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{8,}"),
    ),
    (
        "OpenAI API Key",
        re.compile(
            r"(?<![A-Za-z0-9])(?i:sk-(?!(?:ssh|ecdsa|ant|proj|svcacct|or-v1)-))"
            r"(?![xX]{20,}(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{20,}"
        ),
    ),
    (
        "GitHub PAT",
        re.compile(
            r"(?i:(?:ghp|gho|ghu|ghs|ghr|github_pat)_)"
            r"(?![xX]{20,}(?![A-Za-z0-9_]))[A-Za-z0-9_]{20,}"
        ),
    ),
    (
        "AWS Access Key ID",
        re.compile(
            r"(?<![A-Za-z0-9])(?i:AKIA(?!IOSFODNN7EXAMPLE)(?!X{16}(?![0-9A-Z]))[0-9A-Z]{16})(?![A-Za-z0-9])"
        ),
    ),
    (
        "Slack Token",
        re.compile(r"(?i:xox[baprs]-)(?![xX]{16,}(?![0-9A-Za-z-]))[0-9A-Za-z-]{16,}"),
    ),
    (
        "Google API Key",
        re.compile(r"(?<![A-Za-z0-9])(?i:AIza)(?![xX]{30,}(?![0-9A-Za-z_-]))[0-9A-Za-z_-]{30,}"),
    ),
    (
        "JWT Token",
        re.compile(
            r"(?<![A-Za-z0-9])(?i:eyJ)[A-Za-z0-9_-]{8,}\.(?i:eyJ)[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        ),
    ),
]

_UNCLOSED_PEM_REDACT_RE = re.compile(
    r"(?i:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[ \t]*\r?\n(?=" + _PEM_MATERIAL_HEAD + r").*",
    re.DOTALL,
)
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def _unquote_iteratively(
    text: str,
    *,
    max_rounds: int = _MAX_UNQUOTE_ROUNDS,
    plus: bool = False,
) -> list[str]:
    """Iteratively percent-decodes text until stable or max_rounds is reached."""
    if not text:
        return []
    variants = [text]
    cur = text
    decoder = urllib.parse.unquote_plus if plus else urllib.parse.unquote
    for _ in range(max_rounds):
        if "%" not in cur and not (plus and "+" in cur):
            break
        nxt = decoder(cur)
        if nxt == cur:
            break
        variants.append(nxt)
        cur = nxt
    return variants


class HeaderPairs:
    """Ordered HTTP header collection preserving duplicate header lines while supporting dict-style lookup."""

    def __init__(self, initial: Iterable[tuple[str, str]] = ()) -> None:
        self._items: list[tuple[str, str]] = [(str(k), str(v)) for k, v in initial]

    def append(self, name: str, value: str) -> None:
        self._items.append((str(name), str(value)))

    def pairs(self) -> list[tuple[str, str]]:
        return list(self._items)

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def keys(self) -> list[str]:
        return [k for k, _ in self._items]

    def values(self) -> list[str]:
        return [v for _, v in self._items]

    def get_all(self, name: str) -> list[str]:
        target = name.lower()
        return [v for k, v in self._items if k.lower() == target]

    def get(self, name: str, default: str | None = None) -> str | None:
        target = name.lower()
        for k, v in reversed(self._items):
            if k.lower() == target:
                return v
        return default

    def __getitem__(self, name: str) -> str:
        val = self.get(name)
        if val is None:
            raise KeyError(name)
        return val

    def __setitem__(self, name: str, value: str) -> None:
        target = name.lower()
        replaced = False
        updated: list[tuple[str, str]] = []
        for k, v in self._items:
            if k.lower() == target:
                if not replaced:
                    updated.append((str(name), str(value)))
                    replaced = True
            else:
                updated.append((k, v))
        if not replaced:
            updated.append((str(name), str(value)))
        self._items = updated

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        target = name.lower()
        return any(k.lower() == target for k, _ in self._items)

    def __iter__(self) -> Iterator[str]:
        return (k for k, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return bool(self._items)

    def __repr__(self) -> str:
        return f"HeaderPairs({self._items!r})"


@dataclass
class HeaderAuditEntry:
    name: str
    value_length: int
    category: str       # "auth" | "telemetry" | "fingerprint" | "protocol"
    action: str         # "redacted" | "stripped" | "normalized" | "forwarded"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": redact_secrets_in_text(self.name),
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
            "rule": redact_secrets_in_text(self.rule),
            "field": redact_secrets_in_text(self.field),
        }


@dataclass
class RequestSecretScanResult:
    findings: list[SecretFinding]
    inspected_body: bytes
    parsed_payload: Any = None
    compression_error: str | None = None


def audit_and_prepare_headers(
    inbound_headers: Iterable[tuple[str, str]],
    *,
    strip_telemetry: bool = False,
) -> tuple[HeaderPairs, list[HeaderAuditEntry]]:
    """Prepares upstream headers preserving duplicates while recording only names and lengths."""
    hop_by_hop = {"host", "connection", "keep-alive", "transfer-encoding", "content-length"}
    outbound = HeaderPairs()
    audit: list[HeaderAuditEntry] = []

    for name, value in inbound_headers:
        lower = name.lower()
        if lower in hop_by_hop:
            continue
        vlen = len(value)

        if lower in SENSITIVE_AUTH_HEADERS:
            outbound.append(name, value)
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
                outbound.append(name, value)
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
                outbound.append(name, value)
                audit.append(
                    HeaderAuditEntry(
                        name=name,
                        value_length=vlen,
                        category="fingerprint" if has_os_leak else "protocol",
                        action="forwarded",
                    )
                )
            continue

        outbound.append(name, value)
        audit.append(
            HeaderAuditEntry(
                name=name,
                value_length=vlen,
                category="protocol",
                action="forwarded",
            )
        )

    return outbound, audit


def _decompress_bounded(data: bytes, wbits: int, max_bytes: int) -> tuple[bytes, str | None]:
    decomp = zlib.decompressobj(wbits)
    out = bytearray()
    remaining = data
    try:
        while remaining:
            room = (max_bytes + 1) - len(out)
            if room <= 0:
                return bytes(out[:max_bytes]), "decompressed_size_exceeded"
            chunk = decomp.decompress(remaining, room)
            out.extend(chunk)
            if len(out) > max_bytes:
                return bytes(out[:max_bytes]), "decompressed_size_exceeded"
            if decomp.unconsumed_tail:
                remaining = decomp.unconsumed_tail
            elif decomp.eof and decomp.unused_data:
                # Multi-member gzip stream
                remaining = decomp.unused_data
                decomp = zlib.decompressobj(wbits)
            else:
                break
        tail = decomp.flush(max(1, (max_bytes + 1) - len(out)))
        out.extend(tail)
        if len(out) > max_bytes or decomp.unconsumed_tail:
            return bytes(out[:max_bytes]), "decompressed_size_exceeded"
    except zlib.error:
        return b"", "invalid_compressed_body"
    return bytes(out), None


def decode_request_body_for_inspection(
    raw_body: bytes,
    content_encoding: str | None = None,
    *,
    max_bytes: int = MAX_INSPECTED_BODY_BYTES,
) -> tuple[bytes, str | None]:
    """Decompresses a bounded copy of gzip/deflate request bodies for local inspection."""
    if not raw_body:
        return b"", None

    enc_raw = (content_encoding or "").strip().lower()
    if not enc_raw or enc_raw == "identity":
        if len(raw_body) > max_bytes:
            return raw_body[:max_bytes], "decompressed_size_exceeded"
        return raw_body, None

    layers = [part.strip() for part in enc_raw.split(",") if part.strip()]
    current = raw_body
    for enc in reversed(layers):
        if enc == "identity":
            if len(current) > max_bytes:
                return current[:max_bytes], "decompressed_size_exceeded"
            continue
        if enc in ("gzip", "x-gzip"):
            current, err = _decompress_bounded(current, 16 + zlib.MAX_WBITS, max_bytes)
            if err is not None:
                return current, err
            continue
        if enc == "deflate":
            current, err = _decompress_bounded(current, zlib.MAX_WBITS, max_bytes)
            if err == "invalid_compressed_body":
                current, err = _decompress_bounded(raw_body, -zlib.MAX_WBITS, max_bytes)
            if err is not None:
                return current, err
            continue
        return current[:max_bytes], f"unsupported_content_encoding:{enc}"

    return current, None


def _decode_unicode_escapes(text: str) -> str:
    if "\\u" not in text and "\\x" not in text:
        return text

    def _repl(match: re.Match[str]) -> str:
        hex_code = match.group(1) or match.group(2)
        return chr(int(hex_code, 16))

    return _UNICODE_ESCAPE_RE.sub(_repl, text)


def _has_direct_secret_match(text: str) -> bool:
    if not text:
        return False
    for _, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return True
    return bool(_UNCLOSED_PEM_REDACT_RE.search(text))


def _redact_direct_matches(text: str) -> str:
    scrubbed = text
    for _, pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    scrubbed = _UNCLOSED_PEM_REDACT_RE.sub("[REDACTED]", scrubbed)
    return scrubbed


def scan_body_for_secrets(raw_text: str, *, field: str = "body") -> list[SecretFinding]:
    """Detects live credential patterns in text (including multi-round URL-encoded text) without storing secrets."""
    if not raw_text:
        return []
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()
    candidates = _unquote_iteratively(raw_text) if "%" in raw_text else [raw_text]
    for candidate in candidates:
        for rule_name, pattern in SECRET_PATTERNS:
            if pattern.search(candidate):
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
                raw_k = str(k)
                key_loc = f"{path}.<key>" if path else "<key>"
                for fk in scan_body_for_secrets(raw_k, field=key_loc):
                    key_tuple = (fk.rule, fk.field)
                    if key_tuple not in seen:
                        seen.add(key_tuple)
                        findings.append(fk)
                safe_k = redact_secrets_in_text(raw_k)
                child_path = f"{path}.{safe_k}" if path else safe_k
                _walk(v, child_path)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                child_path = f"{path}[{idx}]" if path else f"[{idx}]"
                _walk(item, child_path)

    if payload is not None:
        _walk(payload, "")

    if raw_fallback:
        found_rules = {f.rule for f in findings}
        candidates = [raw_fallback]
        unescaped = _decode_unicode_escapes(raw_fallback)
        if unescaped != raw_fallback:
            candidates.append(unescaped)
        for candidate in candidates:
            for f in scan_body_for_secrets(candidate, field="body"):
                if f.rule not in found_rules:
                    findings.append(f)
                    found_rules.add(f.rule)

    return findings


def scan_request_for_secrets(
    *,
    raw_path: str,
    headers: Iterable[tuple[str, str]] = (),
    raw_body: bytes = b"",
    content_encoding: str | None = None,
    parsed_payload: Any = None,
    max_decompressed_bytes: int = MAX_INSPECTED_BODY_BYTES,
) -> RequestSecretScanResult:
    """Scans URL path, query string, non-auth headers, and (decompressed) request body."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str]] = set()

    def _add(items: Iterable[SecretFinding]) -> None:
        for item in items:
            key = (item.rule, item.field)
            if key not in seen:
                seen.add(key)
                findings.append(item)

    # 1. URL path & query string (iteratively unquoted up to _MAX_UNQUOTE_ROUNDS)
    if raw_path:
        parts = urllib.parse.urlsplit(raw_path)
        for path_variant in _unquote_iteratively(parts.path):
            if path_variant:
                _add(scan_body_for_secrets(path_variant, field="url.path"))
        if parts.query:
            query_rules_before = len(findings)
            for qk, qv in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
                for qk_variant in _unquote_iteratively(qk, plus=True):
                    _add(scan_body_for_secrets(qk_variant, field="url.query.<key>"))
                safe_qk = redact_secrets_in_text(qk) or "param"
                for qv_variant in _unquote_iteratively(qv, plus=True):
                    _add(scan_body_for_secrets(qv_variant, field=f"url.query.{safe_qk}"))
            if len(findings) == query_rules_before:
                for q_variant in _unquote_iteratively(parts.query, plus=True):
                    _add(scan_body_for_secrets(q_variant, field="url.query"))

    # 2. Request headers (exempting only upstream API auth header values)
    for h_name, h_val in headers:
        for hn_variant in _unquote_iteratively(h_name):
            _add(scan_body_for_secrets(hn_variant, field="header.<name>"))
        if h_name.lower() in LEGIT_UPSTREAM_AUTH_HEADERS:
            continue
        safe_h_name = redact_secrets_in_text(h_name)
        field_name = f"header.{safe_h_name}"
        for hv_variant in _unquote_iteratively(h_val):
            _add(scan_body_for_secrets(hv_variant, field=field_name))

    # 3. Request body (with bounded gzip/deflate decompression)
    inspected_body, comp_err = decode_request_body_for_inspection(
        raw_body,
        content_encoding,
        max_bytes=max_decompressed_bytes,
    )
    payload = parsed_payload
    if inspected_body:
        raw_text = inspected_body.decode("utf-8", errors="replace")
        if payload is None:
            try:
                payload = json.loads(raw_text)
            except ValueError:
                payload = None
        _add(scan_payload_for_secrets(payload, raw_fallback=raw_text))

    return RequestSecretScanResult(
        findings=findings,
        inspected_body=inspected_body,
        parsed_payload=payload,
        compression_error=comp_err,
    )


def redact_secrets_in_text(text: str) -> str:
    """Replaces all matched credentials and PEM private key blocks before any truncation."""
    if not text:
        return ""
    scrubbed = _redact_direct_matches(text)
    if "%" in scrubbed:
        stages = _unquote_iteratively(scrubbed)
        if any(_has_direct_secret_match(stage) for stage in stages[1:]):
            return _redact_direct_matches(stages[-1])
    return scrubbed


def normalize_trace_path(raw_path: str) -> str:
    """Strips URL query/fragment components and redacts any secret in the path across iterative percent-decoding."""
    if not raw_path:
        return ""
    stripped = raw_path
    if "?" in stripped or (stripped.startswith("/") and "#" in stripped):
        parts = urllib.parse.urlsplit(stripped)
        stripped = parts.path or "/"
    stages = _unquote_iteratively(stripped)
    if any(_has_direct_secret_match(stage) for stage in stages):
        return _redact_direct_matches(stages[-1])
    return stripped
