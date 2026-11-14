"""SQLite trace store (0600 permissions), model pricing table, and summary aggregator."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .privacy import normalize_trace_path, redact_secrets_in_text

# Model list prices in USD per 1,000,000 tokens.
# Because offline verification does not fetch live vendor pages, rates are marked "unverified"
# ("未核对" in Chinese) alongside the canonical vendor pricing URLs.
# Ordered from most specific prefix to more general family prefix.
PRICING_TABLE_DATE = "unverified"

_ANTHROPIC_PRICING_URL = "https://docs.anthropic.com/en/docs/about-claude/pricing"
_OPENAI_PRICING_URL = "https://openai.com/api/pricing/"


def _rate_entry(
    inp: float,
    cache_read: float,
    cache_write: float,
    out: float,
    source_url: str,
    verified_at: str = "unverified",
    *,
    long_context_threshold_tokens: int | None = None,
    long_context_input_multiplier: float = 1.0,
    long_context_output_multiplier: float = 1.0,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "input": inp,
        "cache_read": cache_read,
        "cache_write": cache_write,
        "output": out,
        "source_url": source_url,
        "verified_at": verified_at,
    }
    if long_context_threshold_tokens is not None:
        entry["long_context_threshold_tokens"] = long_context_threshold_tokens
        entry["long_context_input_multiplier"] = long_context_input_multiplier
        entry["long_context_output_multiplier"] = long_context_output_multiplier
    return entry


MODEL_PRICING_USD_PER_MTOK: list[tuple[str, dict[str, Any]]] = [
    # Anthropic Claude Sonnet 4.6: flat rate ($3 / $0.30 / $3.75 / $15 per MTok; no >200k surcharge)
    ("claude-sonnet-4-6", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),
    ("claude-sonnet-4.6", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),
    # Anthropic Claude Sonnet 4 (4.0) & Sonnet 4.5 ($3 / $0.30 / $3.75 / $15 per MTok <= 200k prompt tokens;
    # > 200,000 prompt tokens: 2x input/cache rates [$6 / $0.60 / $7.50] and 1.5x output [$22.50])
    (
        "claude-sonnet-4-5",
        _rate_entry(
            3.00,
            0.30,
            3.75,
            15.00,
            _ANTHROPIC_PRICING_URL,
            long_context_threshold_tokens=200_000,
            long_context_input_multiplier=2.0,
            long_context_output_multiplier=1.5,
        ),
    ),
    (
        "claude-sonnet-4.5",
        _rate_entry(
            3.00,
            0.30,
            3.75,
            15.00,
            _ANTHROPIC_PRICING_URL,
            long_context_threshold_tokens=200_000,
            long_context_input_multiplier=2.0,
            long_context_output_multiplier=1.5,
        ),
    ),
    (
        "claude-sonnet-4-0",
        _rate_entry(
            3.00,
            0.30,
            3.75,
            15.00,
            _ANTHROPIC_PRICING_URL,
            long_context_threshold_tokens=200_000,
            long_context_input_multiplier=2.0,
            long_context_output_multiplier=1.5,
        ),
    ),
    (
        "claude-sonnet-4.0",
        _rate_entry(
            3.00,
            0.30,
            3.75,
            15.00,
            _ANTHROPIC_PRICING_URL,
            long_context_threshold_tokens=200_000,
            long_context_input_multiplier=2.0,
            long_context_output_multiplier=1.5,
        ),
    ),
    (
        "claude-sonnet-4",
        _rate_entry(
            3.00,
            0.30,
            3.75,
            15.00,
            _ANTHROPIC_PRICING_URL,
            long_context_threshold_tokens=200_000,
            long_context_input_multiplier=2.0,
            long_context_output_multiplier=1.5,
        ),
    ),
    ("claude-3-7-sonnet", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3.7-sonnet", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3-5-sonnet", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3.5-sonnet", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),
    # Anthropic Claude Opus 4.5 / 4.6 ($5 / $0.50 / $6.25 / $25 per MTok)
    ("claude-opus-4-6", _rate_entry(5.00, 0.50, 6.25, 25.00, _ANTHROPIC_PRICING_URL)),
    ("claude-opus-4.6", _rate_entry(5.00, 0.50, 6.25, 25.00, _ANTHROPIC_PRICING_URL)),
    ("claude-opus-4-5", _rate_entry(5.00, 0.50, 6.25, 25.00, _ANTHROPIC_PRICING_URL)),
    ("claude-opus-4.5", _rate_entry(5.00, 0.50, 6.25, 25.00, _ANTHROPIC_PRICING_URL)),
    # Anthropic Claude Opus 4 / 4.1 / 3 ($15 / $1.50 / $18.75 / $75 per MTok)
    ("claude-opus-4", _rate_entry(15.00, 1.50, 18.75, 75.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3-opus", _rate_entry(15.00, 1.50, 18.75, 75.00, _ANTHROPIC_PRICING_URL)),
    # Anthropic Claude Haiku
    ("claude-haiku-4-5", _rate_entry(1.00, 0.10, 1.25, 5.00, _ANTHROPIC_PRICING_URL)),
    ("claude-haiku-4.5", _rate_entry(1.00, 0.10, 1.25, 5.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3-5-haiku", _rate_entry(0.80, 0.08, 1.00, 4.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3.5-haiku", _rate_entry(0.80, 0.08, 1.00, 4.00, _ANTHROPIC_PRICING_URL)),
    ("claude-3-haiku", _rate_entry(0.25, 0.03, 0.30, 1.25, _ANTHROPIC_PRICING_URL)),
    # OpenAI GPT-4o / GPT-4.1 / GPT-5 / o-series / Codex
    ("gpt-4o-mini", _rate_entry(0.15, 0.075, 0.15, 0.60, _OPENAI_PRICING_URL)),
    ("gpt-4o", _rate_entry(2.50, 1.25, 2.50, 10.00, _OPENAI_PRICING_URL)),
    ("gpt-4.1-nano", _rate_entry(0.10, 0.025, 0.10, 0.40, _OPENAI_PRICING_URL)),
    ("gpt-4.1-mini", _rate_entry(0.40, 0.10, 0.40, 1.60, _OPENAI_PRICING_URL)),
    ("gpt-4.1", _rate_entry(2.00, 0.50, 2.00, 8.00, _OPENAI_PRICING_URL)),
    ("gpt-5-nano", _rate_entry(0.05, 0.005, 0.05, 0.40, _OPENAI_PRICING_URL)),
    ("gpt-5-mini", _rate_entry(0.25, 0.025, 0.25, 2.00, _OPENAI_PRICING_URL)),
    ("gpt-5", _rate_entry(1.25, 1.25 / 10, 1.25, 10.00, _OPENAI_PRICING_URL)),
    ("codex-mini", _rate_entry(1.50, 0.375, 1.50, 6.00, _OPENAI_PRICING_URL)),
    ("o4-mini", _rate_entry(1.10, 0.275, 1.10, 4.40, _OPENAI_PRICING_URL)),
    ("o3-mini", _rate_entry(1.10, 0.55, 1.10, 4.40, _OPENAI_PRICING_URL)),
    ("o3", _rate_entry(2.00, 0.50, 2.00, 8.00, _OPENAI_PRICING_URL)),
    ("o1", _rate_entry(15.00, 7.50, 15.00, 60.00, _OPENAI_PRICING_URL)),
]


def _sanitize_nested(val: Any) -> Any:
    """Recursively redacts secrets across strings, dict keys/values, and sequences."""
    if isinstance(val, str):
        return redact_secrets_in_text(val)
    if isinstance(val, dict):
        return {_sanitize_nested(str(k)): _sanitize_nested(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_sanitize_nested(x) for x in val]
    return val


def _sanitize_db_value(val: Any) -> Any:
    """Mandatory storage-boundary sanitizer applied to every SQLite write parameter."""
    if isinstance(val, str):
        return redact_secrets_in_text(val)
    if isinstance(val, bytes):
        return redact_secrets_in_text(val.decode("utf-8", errors="replace")).encode("utf-8")
    if isinstance(val, (dict, list, tuple)):
        return redact_secrets_in_text(json.dumps(_sanitize_nested(val), ensure_ascii=False))
    return val


def resolve_model_pricing(model: str) -> dict[str, Any] | None:
    """Returns per-MTok USD pricing dict for known models, or None if unrecognized."""
    if not model:
        return None
    norm = model.strip().lower()
    if "/" in norm:
        norm = norm.rsplit("/", 1)[-1]
    for prefix, rates in MODEL_PRICING_USD_PER_MTOK:
        if prefix == "claude-sonnet-4":
            if re.match(r"^claude-sonnet-4(?:$|[:]|-latest\b|-20\d{6})", norm):
                return rates
            continue
        if norm == prefix or norm.startswith(prefix + "-") or norm.startswith(prefix + ":"):
            return rates
        if prefix.endswith(("4", "4.1", "4o", "5", "o3", "o1")) and norm.startswith(prefix):
            return rates
    return None


def compute_cache_hit_ratio(
    input_tokens: int,
    cache_read_tokens: int,
    cache_write_tokens: int,
) -> float:
    """Computes cache_read / (input + cache_read + cache_write), bounded to [0.0, 1.0]."""
    denom = max(0, int(input_tokens)) + max(0, int(cache_read_tokens)) + max(0, int(cache_write_tokens))
    if denom <= 0:
        return 0.0
    return round(max(0, int(cache_read_tokens)) / denom, 6)


def compute_turn_cost_usd(
    *,
    model: str,
    status_code: int,
    blocked: bool,
    input_tokens: int,
    cache_read_tokens: int,
    cache_write_tokens: int,
    output_tokens: int,
) -> float | None:
    """Computes exact USD cost from upstream usage, $0.0 on errors, or None on unknown model."""
    if blocked or status_code >= 400 or status_code <= 0:
        return 0.0
    rates = resolve_model_pricing(model)
    if rates is None:
        return None
    in_tok = max(0, int(input_tokens))
    cr_tok = max(0, int(cache_read_tokens))
    cw_tok = max(0, int(cache_write_tokens))
    out_tok = max(0, int(output_tokens))
    prompt_total = in_tok + cr_tok + cw_tok

    in_mult = 1.0
    out_mult = 1.0
    threshold = rates.get("long_context_threshold_tokens")
    if isinstance(threshold, int) and threshold > 0 and prompt_total > threshold:
        in_mult = float(rates.get("long_context_input_multiplier", 1.0))
        out_mult = float(rates.get("long_context_output_multiplier", 1.0))

    cost = (
        (
            in_tok * rates["input"]
            + cr_tok * rates["cache_read"]
            + cw_tok * rates["cache_write"]
        )
        * in_mult
        + out_tok * rates["output"] * out_mult
    ) / 1_000_000.0
    return round(cost, 6)


def default_db_path() -> Path:
    return Path.home() / ".agent-xray" / "traces.db"


def purge_trace_db(db_path: str | Path | None = None) -> tuple[Path, list[Path]]:
    """Deletes the target SQLite trace DB plus any -wal / -shm sidecar files."""
    target = Path(db_path) if db_path is not None else default_db_path()
    removed: list[Path] = []
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{target}{suffix}")
        if candidate.exists():
            candidate.unlink()
            removed.append(candidate)
    return target, removed


class TraceStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            base = default_db_path().parent
            base.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(base, 0o700)
            except OSError:
                pass
            self.db_path = str(base / "traces.db")
        else:
            self.db_path = str(db_path)
            if self.db_path != ":memory:":
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:" and os.path.exists(self.db_path):
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    latency_ms INTEGER NOT NULL,
                    ttft_ms REAL DEFAULT NULL,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    stream_truncated INTEGER NOT NULL DEFAULT 0,
                    buckets_json TEXT NOT NULL,
                    namespaces_json TEXT NOT NULL,
                    usage_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL,
                    secrets_json TEXT NOT NULL,
                    prompt_preview TEXT NOT NULL DEFAULT ''
                )
                """
            )
            existing_cols = {
                str(row[1])
                for row in self._conn.execute("PRAGMA table_info(traces)").fetchall()
            }
            if "ttft_ms" not in existing_cols:
                self._conn.execute("ALTER TABLE traces ADD COLUMN ttft_ms REAL DEFAULT NULL")
            if "stream_truncated" not in existing_cols:
                self._conn.execute(
                    "ALTER TABLE traces ADD COLUMN stream_truncated INTEGER NOT NULL DEFAULT 0"
                )
            self._conn.commit()

    def _execute_write(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        sanitized_params = tuple(_sanitize_db_value(p) for p in params)
        return self._conn.execute(sql, sanitized_params)

    def clear(self) -> None:
        with self._lock:
            self._execute_write("DELETE FROM traces")
            self._conn.commit()
            if self.db_path != ":memory:":
                self._conn.execute("VACUUM")

    def record_turn(
        self,
        *,
        provider: str,
        model: str,
        path: str,
        status_code: int,
        latency_ms: int,
        blocked: bool,
        buckets: dict[str, Any],
        tool_namespaces: list[dict[str, Any]],
        usage: dict[str, int],
        header_audit: list[dict[str, Any]],
        secret_findings: list[dict[str, Any]],
        prompt_preview: str = "",
        store_previews: bool = False,
        ttft_ms: float | None = None,
        stream_truncated: bool = False,
        created_at: float | None = None,
    ) -> int:
        ts = created_at if created_at is not None else time.time()
        safe_path = normalize_trace_path(path)
        safe_ttft: float | None
        if ttft_ms is None or isinstance(ttft_ms, bool):
            safe_ttft = None
        else:
            try:
                safe_ttft = round(float(ttft_ms), 3)
            except (TypeError, ValueError):
                safe_ttft = None
        safe_headers = [
            {
                "name": str(h.get("name") or h.get("header") or ""),
                "value_length": (
                    int(h["value_length"])
                    if "value_length" in h
                    else len(str(h.get("value") or h.get("display_value") or ""))
                ),
                "category": str(h.get("category") or "protocol"),
                "action": str(h.get("action") or "forwarded"),
            }
            for h in header_audit
            if isinstance(h, dict)
        ]
        safe_secrets = [
            {
                "rule": str(s.get("rule") or "Secret"),
                "field": str(s.get("field") or "body"),
            }
            for s in secret_findings
            if isinstance(s, dict)
        ]
        if blocked or not store_previews or not prompt_preview:
            safe_preview = ""
        else:
            safe_preview = redact_secrets_in_text(prompt_preview).strip()[:140]

        with self._lock:
            cur = self._execute_write(
                """
                INSERT INTO traces (
                    created_at, provider, model, path, status_code, latency_ms, ttft_ms,
                    blocked, stream_truncated, buckets_json, namespaces_json, usage_json,
                    headers_json, secrets_json, prompt_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    provider,
                    model,
                    safe_path,
                    status_code,
                    latency_ms,
                    safe_ttft,
                    1 if blocked else 0,
                    1 if stream_truncated else 0,
                    buckets,
                    tool_namespaces,
                    usage,
                    safe_headers,
                    safe_secrets,
                    safe_preview,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def list_traces(self, limit: int = 80) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM traces ORDER BY id ASC LIMIT ?", (limit,)
            ).fetchall()
        result: list[dict[str, Any]] = []
        for idx, r in enumerate(rows, start=1):
            raw_buckets = json.loads(r["buckets_json"])
            has_bucket_breakdown = bool(raw_buckets.get("has_bucket_breakdown", True))
            buckets = {
                "system_prompt": int(raw_buckets.get("system_prompt", 0)),
                "workspace_rules": int(raw_buckets.get("workspace_rules", 0)),
                "mcp_and_tools": int(raw_buckets.get("mcp_and_tools", 0)),
                "tool_results": int(raw_buckets.get("tool_results", 0)),
                "conversation": int(raw_buckets.get("conversation", 0)),
                "total_estimated": int(raw_buckets.get("total_estimated", 0)),
            }
            raw_usage = json.loads(r["usage_json"])
            in_tok = int(raw_usage.get("input_tokens", 0))
            cache_read_tok = int(
                raw_usage.get("cache_read_tokens", 0)
                or raw_usage.get("cache_read_input_tokens", 0)
            )
            cache_write_tok = int(
                raw_usage.get("cache_write_tokens", 0)
                or raw_usage.get("cache_creation_input_tokens", 0)
            )
            out_tok = int(raw_usage.get("output_tokens", 0))
            norm_usage = {
                "input_tokens": in_tok,
                "cache_read_tokens": cache_read_tok,
                "cache_write_tokens": cache_write_tok,
                "output_tokens": out_tok,
            }
            if "reasoning_tokens" in raw_usage:
                norm_usage["reasoning_tokens"] = int(raw_usage["reasoning_tokens"])

            blocked = bool(r["blocked"])
            status_code = int(r["status_code"])
            provider = str(r["provider"])
            model = str(r["model"])

            est_cost = compute_turn_cost_usd(
                model=model,
                status_code=status_code,
                blocked=blocked,
                input_tokens=in_tok,
                cache_read_tokens=cache_read_tok,
                cache_write_tokens=cache_write_tok,
                output_tokens=out_tok,
            )
            hit_ratio = compute_cache_hit_ratio(in_tok, cache_read_tok, cache_write_tok)
            session_key = str(raw_buckets.get("session_id") or f"{provider}:{model}")
            raw_ttft = r["ttft_ms"] if "ttft_ms" in r.keys() else None
            ttft_val = (
                round(float(raw_ttft), 3)
                if isinstance(raw_ttft, (int, float)) and not isinstance(raw_ttft, bool)
                else None
            )
            stream_truncated = (
                bool(r["stream_truncated"]) if "stream_truncated" in r.keys() else False
            )

            result.append(
                {
                    "id": r["id"],
                    "turn_number": idx,
                    "session_id": session_key,
                    "created_at": r["created_at"],
                    "provider": provider,
                    "model": model,
                    "path": r["path"],
                    "status_code": status_code,
                    "latency_ms": r["latency_ms"],
                    "ttft_ms": ttft_val,
                    "blocked": blocked,
                    "stream_truncated": stream_truncated,
                    "has_bucket_breakdown": has_bucket_breakdown,
                    "is_estimated": has_bucket_breakdown,
                    "buckets_are_estimated": has_bucket_breakdown,
                    "bucket_unit": "estimated_tokens" if has_bucket_breakdown else "none",
                    "buckets": buckets,
                    "tool_namespaces": json.loads(r["namespaces_json"]),
                    "usage": norm_usage,
                    "input_tokens": in_tok,
                    "cached_input_tokens": cache_read_tok,
                    "cache_creation_input_tokens": cache_write_tok,
                    "output_tokens": out_tok,
                    "cache_hit_ratio": hit_ratio,
                    "estimated_cost_usd": est_cost,
                    "header_audit": json.loads(r["headers_json"]),
                    "secret_findings": json.loads(r["secrets_json"]),
                    "prompt_preview": r["prompt_preview"].replace("\u2014", "-").replace("\u2013", "-"),
                }
            )
        return result

    def build_summary(self, limit: int = 80) -> dict[str, Any]:
        traces = self.list_traces(limit=limit)
        totals: dict[str, Any] = {
            "turn_count": len(traces),
            "blocked_count": sum(1 for t in traces if t["blocked"]),
            "truncated_count": sum(1 for t in traces if t.get("stream_truncated")),
            "is_estimated": True,
            "buckets_are_estimated": True,
            "bucket_unit": "estimated_tokens",
            "total_estimated_input": 0,
            "total_actual_input": 0,
            "total_cache_read": 0,
            "total_cache_write": 0,
            "total_output_tokens": 0,
            "tool_definition_tokens": 0,
            "mcp_tool_tokens": 0,
            "mcp_tool_share": 0.0,
            "estimated_cost_usd": 0.0,
            "unknown_price_turn_count": 0,
            "pricing_date": PRICING_TABLE_DATE,
            "cache_hit_ratio": 0.0,
            "stripped_header_count": 0,
            "bucket_totals": {
                "system_prompt": 0,
                "workspace_rules": 0,
                "mcp_and_tools": 0,
                "tool_results": 0,
                "conversation": 0,
            },
        }
        ns_agg: dict[str, dict[str, Any]] = {}
        sessions_map: dict[str, dict[str, Any]] = {}
        known_cost_sum = 0.0
        known_billable_turns = 0
        unknown_billable_turns = 0

        for t in traces:
            b = t["buckets"]
            if t.get("has_bucket_breakdown", True):
                for k in totals["bucket_totals"]:
                    totals["bucket_totals"][k] += int(b.get(k, 0))
                totals["total_estimated_input"] += int(b.get("total_estimated", 0))

            u = t["usage"]
            totals["total_actual_input"] += int(u.get("input_tokens", 0))
            totals["total_cache_read"] += int(u.get("cache_read_tokens", 0))
            totals["total_cache_write"] += int(u.get("cache_write_tokens", 0))
            totals["total_output_tokens"] += int(u.get("output_tokens", 0))

            turn_cost = t.get("estimated_cost_usd")
            is_error = bool(t["blocked"]) or int(t["status_code"]) >= 400 or int(t["status_code"]) <= 0
            if turn_cost is None:
                unknown_billable_turns += 1
            else:
                known_cost_sum += float(turn_cost)
                if not is_error:
                    known_billable_turns += 1

            # X10: Count ONLY headers whose action is strictly "stripped" (never "normalized" User-Agent)
            totals["stripped_header_count"] += sum(
                1 for h in t["header_audit"] if h.get("action") == "stripped"
            )

            skey = str(t.get("session_id") or f"{t['provider']}:{t['model']}")
            sslot = sessions_map.setdefault(
                skey,
                {
                    "session_id": skey,
                    "provider": t["provider"],
                    "model": t["model"],
                    "turn_count": 0,
                },
            )
            sslot["turn_count"] += 1
            for ns in t["tool_namespaces"]:
                name = str(ns.get("namespace") or "builtin")
                est_toks = int(ns.get("estimated_tokens", 0))
                if name.startswith("mcp:"):
                    totals["mcp_tool_tokens"] += est_toks
                slot = ns_agg.setdefault(
                    name,
                    {"namespace": name, "max_tools": 0, "cumulative_tokens": 0, "per_turn_tokens": 0},
                )
                slot["max_tools"] = max(slot["max_tools"], int(ns.get("tool_count", 0)))
                slot["per_turn_tokens"] = max(slot["per_turn_tokens"], est_toks)
                slot["cumulative_tokens"] += est_toks

        totals["tool_definition_tokens"] = totals["bucket_totals"]["mcp_and_tools"]
        if totals["total_estimated_input"] > 0:
            totals["mcp_tool_share"] = round(
                totals["mcp_tool_tokens"] / totals["total_estimated_input"],
                4,
            )

        totals["unknown_price_turn_count"] = unknown_billable_turns
        if unknown_billable_turns > 0 and known_billable_turns == 0:
            totals["estimated_cost_usd"] = None
        else:
            totals["estimated_cost_usd"] = round(known_cost_sum, 6)

        totals["cache_hit_ratio"] = compute_cache_hit_ratio(
            totals["total_actual_input"],
            totals["total_cache_read"],
            totals["total_cache_write"],
        )

        top_namespaces = sorted(
            ns_agg.values(), key=lambda x: x["cumulative_tokens"], reverse=True
        )
        return {
            "summary": totals,
            "sessions": list(sessions_map.values()),
            "top_namespaces": top_namespaces,
            "traces": traces,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def build_demo_dataset() -> dict[str, Any]:
    """Deterministic multi-turn coding session fixture for `export-demo` and UI tests."""
    store = TraceStore(":memory:")
    base_ts = 1_794_556_800.0
    common_ns = [
        {"namespace": "mcp:rea", "tool_count": 48, "estimated_tokens": 18420},
        {"namespace": "mcp:playwright", "tool_count": 25, "estimated_tokens": 6840},
        {"namespace": "builtin", "tool_count": 14, "estimated_tokens": 4120},
        {"namespace": "mcp:scholar", "tool_count": 8, "estimated_tokens": 1960},
        {"namespace": "mcp:context7", "tool_count": 2, "estimated_tokens": 510},
    ]
    headers_sample = [
        {"name": "x-api-key", "value_length": 54, "category": "auth", "action": "redacted"},
        {"name": "anthropic-version", "value_length": 10, "category": "protocol", "action": "forwarded"},
        {"name": "User-Agent", "value_length": 32, "category": "fingerprint", "action": "normalized"},
        {"name": "x-stainless-os", "value_length": 5, "category": "telemetry", "action": "stripped"},
        {"name": "x-stainless-arch", "value_length": 5, "category": "telemetry", "action": "stripped"},
        {"name": "x-stainless-runtime-version", "value_length": 8, "category": "telemetry", "action": "stripped"},
    ]

    turns = [
        (3600, 2940, 31850, 0, 420, 3400, 0, 38400, 510, "Audit dist/ bundle for leaked source maps and non-system dylibs", 200, 840, False, []),
        (3600, 2940, 31850, 6420, 980, 14700, 34200, 0, 690, "Read Package.swift and inspect Mach-O load commands", 200, 1120, False, []),
        (3600, 2940, 31850, 14850, 1640, 20300, 38100, 0, 880, "Patch rpath flags in Scripts/build-app.sh and run test suite", 200, 1490, False, []),
        (3600, 2940, 31850, 22900, 2310, 23200, 44600, 0, 620, "Verify codesign --strict output and summarize binary footprint", 200, 960, False, []),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, "", 400, 14, True, [{"rule": "Anthropic API Key", "field": "messages[4].content"}]),
        (3600, 2940, 7490, 18600, 3120, 8400, 29800, 0, 740, "Disabled unused MCP servers - re-run release verification", 200, 780, False, []),
    ]

    for idx, (sys_t, rules_t, mcp_t, res_t, conv_t, in_u, cache_r, cache_w, out_u, preview, code, lat, blk, sec) in enumerate(turns):
        ns = (
            []
            if blk
            else (
                common_ns
                if mcp_t > 10000
                else [
                    {"namespace": "builtin", "tool_count": 14, "estimated_tokens": 4120},
                    {"namespace": "mcp:scholar", "tool_count": 8, "estimated_tokens": 1960},
                    {"namespace": "mcp:context7", "tool_count": 2, "estimated_tokens": 1410},
                ]
            )
        )
        store.record_turn(
            provider="anthropic",
            model="claude-sonnet-4-5",
            path="/anthropic/v1/messages",
            status_code=code,
            latency_ms=lat,
            blocked=blk,
            buckets={
                "system_prompt": sys_t,
                "workspace_rules": rules_t,
                "mcp_and_tools": mcp_t,
                "tool_results": res_t,
                "conversation": conv_t,
                "total_estimated": sys_t + rules_t + mcp_t + res_t + conv_t,
            },
            tool_namespaces=ns,
            usage={
                "input_tokens": in_u,
                "output_tokens": out_u,
                "cache_read_tokens": cache_r,
                "cache_write_tokens": cache_w,
            },
            header_audit=headers_sample,
            secret_findings=sec,
            prompt_preview=preview,
            store_previews=not blk,
            created_at=base_ts + idx * 42,
        )

    data = store.build_summary()
    data["is_demo"] = True
    store.close()
    return data
