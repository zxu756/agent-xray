#!/usr/bin/env python3
"""Tokenizer estimation error calibration harness (offline loopback or XRAY_REAL_API=1)."""

from __future__ import annotations

import json
import os
import statistics
import sys
import urllib.request
from typing import Any

from agent_xray.classifier import classify_request_payload
from agent_xray.proxy import start_background_proxy


def _build_anthropic_sample(idx: int) -> dict[str, Any]:
    return {
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 1,
        "system": [
            {"type": "text", "text": "You are a concise coding assistant. Follow repository conventions."},
            {"type": "text", "text": "<user_rules>Run unit tests before committing.</user_rules>"},
        ],
        "tools": [
            {
                "name": "mcp__scholar__search_papers",
                "description": "Search academic papers by query string.",
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            }
        ],
        "messages": [
            {
                "role": "user",
                "content": f"Calibration prompt #{idx}: " + ("token sample text " * (12 + idx * 8)),
            }
        ],
    }


def _build_openai_sample(idx: int) -> dict[str, Any]:
    return {
        "model": "gpt-4o-mini",
        "max_tokens": 1,
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "mcp_box.shell",
                    "description": "Run shell command in sandbox.",
                    "parameters": {
                        "type": "object",
                        "properties": {"cmd": {"type": "string"}},
                        "required": ["cmd"],
                    },
                },
            }
        ],
        "messages": [
            {"role": "developer", "content": "Follow repo style; see AGENTS.md if needed."},
            {"role": "developer", "content": "# AGENTS.md\nAlways run pytest before completion."},
            {
                "role": "user",
                "content": f"Calibration prompt #{idx}: " + ("token sample text " * (12 + idx * 8)),
            },
        ],
    }


def run_tokenizer_calibration(
    *,
    anthropic_base_url: str = "https://api.anthropic.com",
    openai_base_url: str = "https://api.openai.com/v1",
    anthropic_api_key: str = "",
    openai_api_key: str = "",
    sample_count: int = 5,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Runs sample requests through start_background_proxy and compares total_estimated vs vendor usage."""
    ant_key = anthropic_api_key.strip()
    oai_key = openai_api_key.strip()
    if not ant_key and not oai_key:
        raise ValueError(
            "Tokenizer calibration requires ANTHROPIC_API_KEY and/or OPENAI_API_KEY."
        )

    results: dict[str, Any] = {}
    with start_background_proxy(
        db_path=":memory:",
        anthropic_upstream=anthropic_base_url,
        openai_upstream=openai_base_url,
    ) as proxy:
        if ant_key:
            ant_samples: list[dict[str, Any]] = []
            for idx in range(sample_count):
                body = _build_anthropic_sample(idx)
                est = classify_request_payload("/anthropic/v1/messages", body).buckets.total_estimated
                req = urllib.request.Request(
                    f"{proxy.anthropic_base_url}/v1/messages",
                    data=json.dumps(body).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": ant_key,
                        "anthropic-version": "2023-06-01",
                    },
                )
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                u = resp_json.get("usage") or {}
                actual = (
                    int(u.get("input_tokens") or 0)
                    + int(u.get("cache_read_input_tokens") or 0)
                    + int(u.get("cache_creation_input_tokens") or 0)
                )
                rel_err = abs(est - actual) / max(1, actual)
                ant_samples.append(
                    {"index": idx, "estimated": est, "actual": actual, "relative_error": rel_err}
                )
            errs = [s["relative_error"] for s in ant_samples]
            results["anthropic"] = {
                "samples": ant_samples,
                "mean_error": statistics.mean(errs),
                "median_error": statistics.median(errs),
                "max_error": max(errs),
            }

        if oai_key:
            oai_samples: list[dict[str, Any]] = []
            for idx in range(sample_count):
                body = _build_openai_sample(idx)
                est = classify_request_payload("/openai/v1/chat/completions", body).buckets.total_estimated
                req = urllib.request.Request(
                    f"{proxy.openai_base_url}/chat/completions",
                    data=json.dumps(body).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {oai_key}",
                    },
                )
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    resp_json = json.loads(resp.read().decode("utf-8"))
                u = resp_json.get("usage") or {}
                actual = int(u.get("prompt_tokens") or u.get("input_tokens") or 0)
                rel_err = abs(est - actual) / max(1, actual)
                oai_samples.append(
                    {"index": idx, "estimated": est, "actual": actual, "relative_error": rel_err}
                )
            errs = [s["relative_error"] for s in oai_samples]
            results["openai"] = {
                "samples": oai_samples,
                "mean_error": statistics.mean(errs),
                "median_error": statistics.median(errs),
                "max_error": max(errs),
            }

        recorded_turns = proxy.get_turns()
        expected_turns = (sample_count if ant_key else 0) + (sample_count if oai_key else 0)
        if len(recorded_turns) != expected_turns:
            raise AssertionError(
                f"Expected {expected_turns} recorded proxy turns, got {len(recorded_turns)}"
            )
        results["recorded_turns"] = len(recorded_turns)

    return results


def main() -> int:
    ant_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    oai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not ant_key and not oai_key:
        print(
            "Error: XRAY_REAL_API=1 requires ANTHROPIC_API_KEY and/or OPENAI_API_KEY in environment.",
            file=sys.stderr,
        )
        return 2

    ant_url = os.environ.get("AGENT_XRAY_CALIBRATE_ANTHROPIC_URL", "https://api.anthropic.com")
    oai_url = os.environ.get("AGENT_XRAY_CALIBRATE_OPENAI_URL", "https://api.openai.com/v1")
    sample_count = int(os.environ.get("AGENT_XRAY_CALIBRATE_SAMPLES", "5"))

    report = run_tokenizer_calibration(
        anthropic_base_url=ant_url,
        openai_base_url=oai_url,
        anthropic_api_key=ant_key,
        openai_api_key=oai_key,
        sample_count=sample_count,
    )
    for prov in ("anthropic", "openai"):
        if prov in report:
            p = report[prov]
            print(
                f"ROW 7 [{prov}]: samples={len(p['samples'])}, "
                f"mean_error={p['mean_error']*100:.2f}%, "
                f"median_error={p['median_error']*100:.2f}%, "
                f"max_error={p['max_error']*100:.2f}%"
            )
            if p["max_error"] > 0.25:
                print(
                    f"FAIL: {prov} max_error={p['max_error']*100:.2f}% exceeds 25.00% threshold!",
                    file=sys.stderr,
                )
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
