"""SQLite trace store (0600 permissions) and summary aggregator for agent-xray."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .privacy import redact_secrets_in_text


class TraceStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            base = Path.home() / ".agent-xray"
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

    def record_turn(
        self,
        *,
        provider: str,
        model: str,
        path: str,
        status_code: int,
        latency_ms: int,
        blocked: bool,
        buckets: dict[str, int],
        tool_namespaces: list[dict[str, Any]],
        usage: dict[str, int],
        header_audit: list[dict[str, str]],
        secret_findings: list[dict[str, str]],
        prompt_preview: str = "",
        created_at: float | None = None,
    ) -> int:
        ts = created_at if created_at is not None else time.time()
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
                    json.dumps(header_audit),
                    json.dumps(secret_findings),
                    redact_secrets_in_text(prompt_preview)[:160],
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
            buckets = json.loads(r["buckets_json"])
            usage = json.loads(r["usage_json"])
            blocked = bool(r["blocked"])
            in_tok = int(usage.get("input_tokens", 0)) or (0 if blocked else int(buckets.get("total_estimated", 0)))
            cache_tok = int(usage.get("cache_read_tokens", 0) or usage.get("cache_read_input_tokens", 0))
            out_tok = int(usage.get("output_tokens", 0))
            uncached_in = max(0, in_tok - cache_tok)
            est_cost = 0.0 if blocked else round(
                (uncached_in * 3.0 + cache_tok * 0.30 + out_tok * 15.0) / 1_000_000.0,
                4,
            )
            provider = str(r["provider"])
            model = str(r["model"])
            session_key = f"{provider}:{model}"
            result.append(
                {
                    "id": r["id"],
                    "turn_number": idx,
                    "session_id": session_key,
                    "created_at": r["created_at"],
                    "provider": provider,
                    "model": model,
                    "path": r["path"],
                    "status_code": r["status_code"],
                    "latency_ms": r["latency_ms"],
                    "blocked": blocked,
                    "buckets": buckets,
                    "tool_namespaces": json.loads(r["namespaces_json"]),
                    "usage": usage,
                    "estimated_cost_usd": est_cost,
                    "header_audit": json.loads(r["headers_json"]),
                    "secret_findings": json.loads(r["secrets_json"]),
                    "prompt_preview": r["prompt_preview"].replace("\u2014", "-").replace("\u2013", "-"),
                }
            )
        return result

    def build_summary(self, limit: int = 80) -> dict[str, Any]:
        traces = self.list_traces(limit=limit)
        totals = {
            "turn_count": len(traces),
            "blocked_count": sum(1 for t in traces if t["blocked"]),
            "total_estimated_input": 0,
            "total_actual_input": 0,
            "total_cache_read": 0,
            "total_output_tokens": 0,
            "estimated_cost_usd": 0.0,
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
        for t in traces:
            b = t["buckets"]
            for k in totals["bucket_totals"]:
                totals["bucket_totals"][k] += int(b.get(k, 0))
            totals["total_estimated_input"] += int(b.get("total_estimated", 0))
            u = t["usage"]
            totals["total_actual_input"] += int(u.get("input_tokens", 0))
            totals["total_cache_read"] += int(u.get("cache_read_tokens", 0) or u.get("cache_read_input_tokens", 0))
            totals["total_output_tokens"] += int(u.get("output_tokens", 0))
            totals["estimated_cost_usd"] = round(
                totals["estimated_cost_usd"] + float(t.get("estimated_cost_usd", 0.0)),
                4,
            )
            totals["stripped_header_count"] += sum(
                1 for h in t["header_audit"] if h.get("action") in ("stripped", "normalized")
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
                name = ns["namespace"]
                slot = ns_agg.setdefault(
                    name,
                    {"namespace": name, "max_tools": 0, "cumulative_tokens": 0, "per_turn_tokens": 0},
                )
                slot["max_tools"] = max(slot["max_tools"], int(ns.get("tool_count", 0)))
                slot["per_turn_tokens"] = max(slot["per_turn_tokens"], int(ns.get("estimated_tokens", 0)))
                slot["cumulative_tokens"] += int(ns.get("estimated_tokens", 0))

        denom = totals["total_actual_input"] or totals["total_estimated_input"]
        totals["cache_hit_ratio"] = round(totals["total_cache_read"] / max(1, denom), 4) if denom > 0 else 0.0

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
        {"name": "x-api-key", "display_value": "sk-ant••••9fQ (54 chars)", "category": "auth", "action": "redacted"},
        {"name": "anthropic-version", "display_value": "2023-06-01", "category": "protocol", "action": "forwarded"},
        {"name": "User-Agent", "display_value": "claude-cli/2.1.4 (darwin arm64) -> agent-xray/0.2.0", "category": "fingerprint", "action": "normalized"},
        {"name": "x-stainless-os", "display_value": "MacOS", "category": "telemetry", "action": "stripped"},
        {"name": "x-stainless-arch", "display_value": "arm64", "category": "telemetry", "action": "stripped"},
        {"name": "x-stainless-runtime-version", "display_value": "v22.23.4", "category": "telemetry", "action": "stripped"},
    ]

    turns = [
        (3600, 2940, 31850, 0, 420, 41800, 0, 510, "Audit dist/ bundle for leaked source maps and non-system dylibs", 200, 840, False, []),
        (3600, 2940, 31850, 6420, 980, 48900, 34200, 690, "Read Package.swift and inspect Mach-O load commands", 200, 1120, False, []),
        (3600, 2940, 31850, 14850, 1640, 58400, 38100, 880, "Patch rpath flags in Scripts/build-app.sh and run test suite", 200, 1490, False, []),
        (3600, 2940, 31850, 22900, 2310, 67800, 44600, 620, "Verify codesign --strict output and summarize binary footprint", 200, 960, False, []),
        (3600, 2940, 31850, 24100, 2790, 0, 0, 0, "cat .env.production && publish release notes", 400, 14, True, [{"rule": "Anthropic API Key", "redacted_snippet": "sk-ant••••X9A (51 chars)"}]),
        (3600, 2940, 7490, 18600, 3120, 38200, 29800, 740, "Disabled unused MCP servers - re-run release verification", 200, 780, False, []),
    ]

    for idx, (sys_t, rules_t, mcp_t, res_t, conv_t, in_u, cache_u, out_u, preview, code, lat, blk, sec) in enumerate(turns):
        ns = common_ns if mcp_t > 10000 else [
            {"namespace": "builtin", "tool_count": 14, "estimated_tokens": 4120},
            {"namespace": "mcp:scholar", "tool_count": 8, "estimated_tokens": 1960},
            {"namespace": "mcp:context7", "tool_count": 2, "estimated_tokens": 1410},
        ]
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
                "cache_read_tokens": cache_u,
                "cache_write_tokens": 38400 if idx == 0 else 0,
            },
            header_audit=headers_sample,
            secret_findings=sec,
            prompt_preview=preview,
            created_at=base_ts + idx * 42,
        )

    data = store.build_summary()
    store.close()
    return data
