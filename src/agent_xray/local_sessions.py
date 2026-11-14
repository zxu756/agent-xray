"""Read-only local Desktop & CLI coding-agent session importer (zero proxy needed).

Scans per-turn token usage written on disk by OpenCode Desktop (`opencode.db`)
and Claude (`~/.claude/projects/*/*.jsonl`) using strictly read-only SQLite URI
connections. Because local session logs only record aggregate token counts (and
do not retain raw HTTP request wire payloads), 5-bucket breakdown is marked
unavailable (`has_bucket_breakdown = False`) rather than estimated with fixed ratios.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .privacy import redact_secrets_in_text
from .store import TraceStore


def _parse_opencode_model(raw_model: Any, fallback_id: Any = None) -> str:
    if isinstance(raw_model, dict):
        mid = raw_model.get("id") or raw_model.get("modelID")
        if mid:
            return str(mid)
    elif isinstance(raw_model, str):
        s = raw_model.strip()
        if s.startswith("{"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    mid = parsed.get("id") or parsed.get("modelID")
                    if mid:
                        return str(mid)
            except Exception:
                pass
        if s:
            return s
    if fallback_id:
        return str(fallback_id)
    return "opencode-unknown"


def _empty_local_buckets(session_id: str) -> dict[str, Any]:
    return {
        "has_bucket_breakdown": False,
        "session_id": session_id,
        "system_prompt": 0,
        "workspace_rules": 0,
        "mcp_and_tools": 0,
        "tool_results": 0,
        "conversation": 0,
        "total_estimated": 0,
    }


def import_local_desktop_sessions(
    store: TraceStore,
    *,
    home: Path | None = None,
    max_turns: int = 24,
    store_previews: bool = False,
) -> int:
    root = home or Path.home()
    imported = 0
    oc_quota = max(1, max_turns // 2)

    # 1. OpenCode Desktop (`~/.local/share/opencode/opencode.db`, per-turn `session_message`)
    oc_db = root / ".local/share/opencode/opencode.db"
    if oc_db.is_file():
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(f"file:{oc_db}?mode=ro", uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
            has_msg_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_message'"
            ).fetchone()
            if has_msg_table:
                rows = conn.execute(
                    """
                    SELECT id, session_id, time_created, time_updated, data
                    FROM session_message
                    WHERE type = 'assistant'
                    ORDER BY time_created DESC
                    LIMIT ?
                    """,
                    (oc_quota * 3,),
                ).fetchall()
                parsed_turns: list[dict[str, Any]] = []
                for r in rows:
                    try:
                        dobj = json.loads(str(r["data"] or "{}"))
                    except Exception:
                        continue
                    if not isinstance(dobj, dict):
                        continue
                    toks = dobj.get("tokens")
                    if not isinstance(toks, dict):
                        continue
                    cache_obj = toks.get("cache") if isinstance(toks.get("cache"), dict) else {}
                    inp = int(toks.get("input") or 0)
                    out_tok = int(toks.get("output") or 0)
                    reasoning_tok = int(toks.get("reasoning") or 0)
                    cache_r = int(cache_obj.get("read") or 0)
                    cache_w = int(cache_obj.get("write") or 0)
                    if inp + out_tok + cache_r + cache_w <= 0:
                        continue

                    model_name = _parse_opencode_model(dobj.get("model"), dobj.get("modelID"))
                    time_obj = dobj.get("time") if isinstance(dobj.get("time"), dict) else {}
                    t_created = time_obj.get("created") or r["time_created"]
                    t_done = time_obj.get("completed") or time_obj.get("streamed")
                    latency_ms = (
                        max(0, int(t_done - t_created))
                        if isinstance(t_created, (int, float))
                        and isinstance(t_done, (int, float))
                        and t_done >= t_created
                        else 0
                    )
                    ts_sec = (
                        float(t_created) / 1000.0
                        if isinstance(t_created, (int, float)) and t_created > 1e11
                        else float(t_created or time.time())
                    )
                    usage_dict: dict[str, int] = {
                        "input_tokens": inp,
                        "output_tokens": out_tok,
                        "cache_read_tokens": cache_r,
                        "cache_write_tokens": cache_w,
                    }
                    if reasoning_tok > 0:
                        usage_dict["reasoning_tokens"] = reasoning_tok

                    sid = redact_secrets_in_text(str(r["session_id"] or "session"))
                    parsed_turns.append(
                        {
                            "session_id": f"opencode:{sid[:12]}",
                            "model": model_name,
                            "latency_ms": latency_ms,
                            "usage": usage_dict,
                            "created_at": ts_sec,
                        }
                    )
                    if len(parsed_turns) >= oc_quota:
                        break

                for pt in reversed(parsed_turns):
                    store.record_turn(
                        provider="opencode-desktop",
                        model=pt["model"],
                        path="local:opencode.db",
                        status_code=200,
                        latency_ms=pt["latency_ms"],
                        blocked=False,
                        buckets=_empty_local_buckets(pt["session_id"]),
                        tool_namespaces=[],
                        usage=pt["usage"],
                        header_audit=[],
                        secret_findings=[],
                        prompt_preview="",
                        store_previews=False,
                        created_at=pt["created_at"],
                    )
                    imported += 1
        except Exception:
            pass
        finally:
            if conn is not None:
                conn.close()

    # 2. Claude local session transcripts (`~/.claude/projects/*/*.jsonl`)
    claude_dir = root / ".claude/projects"
    if claude_dir.is_dir() and imported < max_turns:
        files = sorted(
            claude_dir.glob("*/*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:6]
        claude_turns: list[dict[str, Any]] = []
        remaining = max_turns - imported

        for jf in reversed(files):
            try:
                dedup_turns: dict[str, dict[str, Any]] = {}
                last_user = ""
                for line_idx, line in enumerate(
                    jf.read_text(encoding="utf-8", errors="replace").splitlines()
                ):
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
                    role = msg.get("role") or obj.get("type")
                    if role == "user":
                        c = msg.get("content")
                        if isinstance(c, str) and c.strip():
                            last_user = c.strip()
                    elif role == "assistant" and isinstance(msg.get("usage"), dict):
                        u = msg["usage"]
                        in_tok = int(u.get("input_tokens") or 0)
                        cache_r = int(u.get("cache_read_input_tokens") or 0)
                        cache_w = int(u.get("cache_creation_input_tokens") or 0)
                        out_tok = int(u.get("output_tokens") or 0)
                        if in_tok + cache_r + cache_w + out_tok <= 0:
                            continue

                        msg_id = str(msg.get("id") or obj.get("messageId") or "")
                        req_id = str(obj.get("requestId") or "")
                        dedup_key = (
                            f"{msg_id}:{req_id}"
                            if (msg_id or req_id)
                            else f"line:{line_idx}"
                        )
                        slot = dedup_turns.get(dedup_key)
                        if slot is None:
                            safe_stem = redact_secrets_in_text(jf.stem)
                            safe_name = redact_secrets_in_text(jf.name)
                            dedup_turns[dedup_key] = {
                                "session_id": f"claude:{safe_stem[:12]}",
                                "model": str(msg.get("model") or "claude-unknown"),
                                "path": f"local:{safe_name}",
                                "in_tok": in_tok,
                                "cache_r": cache_r,
                                "cache_w": cache_w,
                                "out_tok": out_tok,
                                "user_text": last_user if store_previews else "",
                            }
                        else:
                            slot["in_tok"] = max(slot["in_tok"], in_tok)
                            slot["cache_r"] = max(slot["cache_r"], cache_r)
                            slot["cache_w"] = max(slot["cache_w"], cache_w)
                            slot["out_tok"] = max(slot["out_tok"], out_tok)

                file_turns = list(dedup_turns.values())[-remaining:]
                claude_turns.extend(file_turns)
            except Exception:
                continue

        for ct in claude_turns[-remaining:]:
            preview = (
                redact_secrets_in_text(ct["user_text"]).strip()[:140]
                if (store_previews and ct["user_text"])
                else ""
            )
            store.record_turn(
                provider="claude-local",
                model=ct["model"],
                path=ct["path"],
                status_code=200,
                latency_ms=0,
                blocked=False,
                buckets=_empty_local_buckets(ct["session_id"]),
                tool_namespaces=[],
                usage={
                    "input_tokens": ct["in_tok"],
                    "output_tokens": ct["out_tok"],
                    "cache_read_tokens": ct["cache_r"],
                    "cache_write_tokens": ct["cache_w"],
                },
                header_audit=[],
                secret_findings=[],
                prompt_preview=preview,
                store_previews=store_previews,
            )
            imported += 1
            if imported >= max_turns:
                break

    return imported
