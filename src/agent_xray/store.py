"""SQLite trace store (0600 permissions), model pricing table, and summary aggregator."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .privacy import redact_secrets_in_text

# Official list prices in USD per 1,000,000 tokens as of 2026-11.
# Ordered from most specific prefix to more general family prefix.
PRICING_TABLE_DATE = "2026-11"

MODEL_PRICING_USD_PER_MTOK: list[tuple[str, dict[str, float]]] = [
    # Anthropic Claude Sonnet ($3 / $0.30 / $3.75 / $15 per MTok)
    ("claude-sonnet-4", {"input": 3.00, "cache_read": 0.30, "cache_write": 3.75, "output": 15.00}),
    ("claude-3-7-sonnet", {"input": 3.00, "cache_read": 0.30, "cache_write": 3.75, "output": 15.00}),
    ("claude-3.7-sonnet", {"input": 3.00, "cache_read": 0.30, "cache_write": 3.75, "output": 15.00}),
    ("claude-3-5-sonnet", {"input": 3.00, "cache_read": 0.30, "cache_write": 3.75, "output": 15.00}),
    ("claude-3.5-sonnet", {"input": 3.00, "cache_read": 0.30, "cache_write": 3.75, "output": 15.00}),
    # Anthropic Claude Opus 4.5 / 4.6 ($5 / $0.50 / $6.25 / $25 per MTok)
    ("claude-opus-4-6", {"input": 5.00, "cache_read": 0.50, "cache_write": 6.25, "output": 25.00}),
    ("claude-opus-4.6", {"input": 5.00, "cache_read": 0.50, "cache_write": 6.25, "output": 25.00}),
    ("claude-opus-4-5", {"input": 5.00, "cache_read": 0.50, "cache_write": 6.25, "output": 25.00}),
    ("claude-opus-4.5", {"input": 5.00, "cache_read": 0.50, "cache_write": 6.25, "output": 25.00}),
    # Anthropic Claude Opus 4 / 4.1 / 3 ($15 / $1.50 / $18.75 / $75 per MTok)
    ("claude-opus-4", {"input": 15.00, "cache_read": 1.50, "cache_write": 18.75, "output": 75.00}),
    ("claude-3-opus", {"input": 15.00, "cache_read": 1.50, "cache_write": 18.75, "output": 75.00}),
    # Anthropic Claude Haiku
    ("claude-haiku-4-5", {"input": 1.00, "cache_read": 0.10, "cache_write": 1.25, "output": 5.00}),
    ("claude-haiku-4.5", {"input": 1.00, "cache_read": 0.10, "cache_write": 1.25, "output": 5.00}),
    ("claude-3-5-haiku", {"input": 0.80, "cache_read": 0.08, "cache_write": 1.00, "output": 4.00}),
    ("claude-3.5-haiku", {"input": 0.80, "cache_read": 0.08, "cache_write": 1.00, "output": 4.00}),
    ("claude-3-haiku", {"input": 0.25, "cache_read": 0.03, "cache_write": 0.30, "output": 1.25}),
    # OpenAI GPT-4o / GPT-4.1 / GPT-5 / o-series / Codex
    ("gpt-4o-mini", {"input": 0.15, "cache_read": 0.075, "cache_write": 0.15, "output": 0.60}),
    ("gpt-4o", {"input": 2.50, "cache_read": 1.25, "cache_write": 2.50, "output": 10.00}),
    ("gpt-4.1-nano", {"input": 0.10, "cache_read": 0.025, "cache_write": 0.10, "output": 0.40}),
    ("gpt-4.1-mini", {"input": 0.40, "cache_read": 0.10, "cache_write": 0.40, "output": 1.60}),
    ("gpt-4.1", {"input": 2.00, "cache_read": 0.50, "cache_write": 2.00, "output": 8.00}),
    ("gpt-5-nano", {"input": 0.05, "cache_read": 0.005, "cache_write": 0.05, "output": 0.40}),
    ("gpt-5-mini", {"input": 0.25, "cache_read": 0.025, "cache_write": 0.25, "output": 2.00}),
    ("gpt-5", {"input": 1.25, "cache_read": 1.25 / 10, "cache_write": 1.25, "output": 10.00}),
    ("codex-mini", {"input": 1.50, "cache_read": 0.375, "cache_write": 1.50, "output": 6.00}),
    ("o4-mini", {"input": 1.10, "cache_read": 0.275, "cache_write": 1.10, "output": 4.40}),
    ("o3-mini", {"input": 1.10, "cache_read": 0.55, "cache_write": 1.10, "output": 4.40}),
    ("o3", {"input": 2.00, "cache_read": 0.50, "cache_write": 2.00, "output": 8.00}),
    ("o1", {"input": 15.00, "cache_read": 7.50, "cache_write": 15.00, "output": 60.00}),
]


def resolve_model_pricing(model: str) -> dict[str, float] | None:
    """Returns per-MTok USD pricing dict for known models, or None if unrecognized."""
    if not model:
        return None
    norm = model.strip().lower()
    if "/" in norm:
        norm = norm.rsplit("/", 1)[-1]
    for prefix, rates in MODEL_PRICING_USD_PER_MTOK:
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
    cost = (
        max(0, int(input_tokens)) * rates["input"]
        + max(0, int(cache_read_tokens)) * rates["cache_read"]
        + max(0, int(cache_write_tokens)) * rates["cache_write"]
        + max(0, int(output_tokens)) * rates["output"]
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
                    blocked INTEGER NOT NULL DEFAULT 0,
                    buckets_json TEXT NOT NULL,
                    namespaces_json TEXT NOT NULL,
                    usage_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL,
                    secrets_json TEXT NOT NULL,
                    prompt_preview TEXT NOT NULL DEFAULT ''
                )
                """
            )
            self._conn.commit()

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM traces")
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
        created_at: float | None = None,
    ) -> int:
        ts = created_at if created_at is not None else time.time()
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
            cur = self._conn.execute(
                """
                INSERT INTO traces (
                    created_at, provider, model, path, status_code, latency_ms,
                    blocked, buckets_json, namespaces_json, usage_json,
                    headers_json, secrets_json, prompt_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    provider,
                    model,
                    path,
                    status_code,
                    latency_ms,
                    1 if blocked else 0,
                    json.dumps(buckets),
                    json.dumps(tool_namespaces),
                    json.dumps(usage),
                    json.dumps(safe_headers),
                    json.dumps(safe_secrets),
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
                    "blocked": blocked,
                    "has_bucket_breakdown": has_bucket_breakdown,
                    "buckets": buckets,
                    "tool_namespaces": json.loads(r["namespaces_json"]),
                    "usage": norm_usage,
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
