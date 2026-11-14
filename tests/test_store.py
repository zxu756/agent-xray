from __future__ import annotations

import unittest

from agent_xray.classifier import parse_usage_from_response
from agent_xray.store import MODEL_PRICING_USD_PER_MTOK, PRICING_TABLE_DATE, TraceStore
from agent_xray.ui_html import render_inspector_html


class StorePricingCacheAndLabelsTests(unittest.TestCase):
    def test_sonnet_vs_opus_pricing_cache_write_and_87pct_hit_rate(self) -> None:
        self.assertEqual(PRICING_TABLE_DATE, "unverified")
        self.assertGreaterEqual(len(MODEL_PRICING_USD_PER_MTOK), 8)
        for prefix, meta in MODEL_PRICING_USD_PER_MTOK:
            with self.subTest(model_prefix=prefix):
                self.assertTrue(str(meta.get("source_url", "")).startswith("https://"))
                self.assertEqual(meta.get("verified_at"), "unverified")

        store = TraceStore(":memory:")
        usage = {
            "input_tokens": 200,
            "cache_read_tokens": 8000,
            "cache_write_tokens": 1000,
            "output_tokens": 500,
        }
        buckets = {
            "system_prompt": 1000,
            "workspace_rules": 1000,
            "mcp_and_tools": 4000,
            "tool_results": 2000,
            "conversation": 1200,
            "total_estimated": 9200,
        }
        store.record_turn(
            provider="anthropic",
            model="claude-sonnet-4-5",
            path="/anthropic/v1/messages",
            status_code=200,
            latency_ms=300,
            blocked=False,
            buckets=buckets,
            tool_namespaces=[
                {"namespace": "mcp:rea", "tool_count": 10, "estimated_tokens": 3000},
                {"namespace": "builtin", "tool_count": 5, "estimated_tokens": 1000},
            ],
            usage=usage,
            header_audit=[
                {"name": "User-Agent", "value_length": 24, "category": "fingerprint", "action": "normalized"},
                {"name": "x-stainless-os", "value_length": 5, "category": "telemetry", "action": "stripped"},
            ],
            secret_findings=[],
        )
        store.record_turn(
            provider="anthropic",
            model="claude-opus-4-1",
            path="/anthropic/v1/messages",
            status_code=200,
            latency_ms=420,
            blocked=False,
            buckets=buckets,
            tool_namespaces=[
                {"namespace": "mcp:rea", "tool_count": 10, "estimated_tokens": 3000},
                {"namespace": "builtin", "tool_count": 5, "estimated_tokens": 1000},
            ],
            usage=usage,
            header_audit=[
                {"name": "User-Agent", "value_length": 24, "category": "fingerprint", "action": "normalized"},
            ],
            secret_findings=[],
        )
        summary_data = store.build_summary()
        store.close()

        traces = summary_data["traces"]
        self.assertAlmostEqual(traces[0]["estimated_cost_usd"], 0.01425, places=6)
        self.assertAlmostEqual(traces[1]["estimated_cost_usd"], 0.07125, places=6)
        self.assertNotEqual(traces[0]["estimated_cost_usd"], traces[1]["estimated_cost_usd"])

        expected_hit = 8000 / (200 + 8000 + 1000)
        self.assertAlmostEqual(traces[0]["cache_hit_ratio"], expected_hit, places=5)
        self.assertAlmostEqual(summary_data["summary"]["cache_hit_ratio"], expected_hit, places=5)
        self.assertEqual(round(summary_data["summary"]["cache_hit_ratio"] * 100), 87)
        self.assertAlmostEqual(summary_data["summary"]["estimated_cost_usd"], 0.0855, places=6)

        # Stripped telemetry headers: ONLY the 1 "stripped" header, NOT the 2 "normalized" User-Agent headers!
        self.assertEqual(summary_data["summary"]["stripped_header_count"], 1)

        # MCP Tool Share vs Tool Definition Tokens
        self.assertEqual(summary_data["summary"]["mcp_tool_tokens"], 6000)
        self.assertEqual(summary_data["summary"]["tool_definition_tokens"], 8000)
        self.assertAlmostEqual(summary_data["summary"]["mcp_tool_share"], 6000 / 18400, places=4)

    def test_openai_cached_prompt_tokens_normalization(self) -> None:
        raw = b'{"id":"chatcmpl-1","usage":{"prompt_tokens":1000,"completion_tokens":100,"prompt_tokens_details":{"cached_tokens":800}}}'
        u = parse_usage_from_response(raw, is_sse=False)
        self.assertEqual(u["input_tokens"], 200)
        self.assertEqual(u["cache_read_tokens"], 800)
        self.assertEqual(u["cache_write_tokens"], 0)
        self.assertEqual(u["output_tokens"], 100)

        store = TraceStore(":memory:")
        store.record_turn(
            provider="openai",
            model="gpt-4o",
            path="/openai/v1/chat/completions",
            status_code=200,
            latency_ms=210,
            blocked=False,
            buckets={"system_prompt": 200, "workspace_rules": 0, "mcp_and_tools": 0, "tool_results": 0, "conversation": 800, "total_estimated": 1000},
            tool_namespaces=[],
            usage=u,
            header_audit=[],
            secret_findings=[],
        )
        data = store.build_summary()
        store.close()
        self.assertAlmostEqual(data["summary"]["cache_hit_ratio"], 0.80, places=5)
        # gpt-4o: (200 * 2.50 + 800 * 1.25 + 100 * 10.0) / 1e6 = 0.0025
        self.assertAlmostEqual(data["traces"][0]["estimated_cost_usd"], 0.0025, places=6)

    def test_unknown_model_returns_none_and_failed_status_bills_zero(self) -> None:
        store = TraceStore(":memory:")
        # 1. Failed 429 on known model with huge estimated buckets -> MUST bill $0.0
        store.record_turn(
            provider="anthropic",
            model="claude-opus-4-1",
            path="/anthropic/v1/messages",
            status_code=429,
            latency_ms=40,
            blocked=False,
            buckets={"system_prompt": 10000, "workspace_rules": 0, "mcp_and_tools": 20000, "tool_results": 0, "conversation": 5000, "total_estimated": 35000},
            tool_namespaces=[],
            usage={"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0},
            header_audit=[],
            secret_findings=[],
        )
        # 2. Failed 500 -> MUST bill $0.0
        store.record_turn(
            provider="anthropic",
            model="claude-sonnet-4-5",
            path="/anthropic/v1/messages",
            status_code=500,
            latency_ms=50,
            blocked=False,
            buckets={"system_prompt": 5000, "workspace_rules": 0, "mcp_and_tools": 0, "tool_results": 0, "conversation": 5000, "total_estimated": 10000},
            tool_namespaces=[],
            usage={"input_tokens": 1000, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0},
            header_audit=[],
            secret_findings=[],
        )
        # 3. Unknown model on 200 -> MUST return None ("Unknown price" / "未知价格")
        store.record_turn(
            provider="openai",
            model="totally-unknown-custom-llm-v9",
            path="/openai/v1/chat/completions",
            status_code=200,
            latency_ms=120,
            blocked=False,
            buckets={"system_prompt": 500, "workspace_rules": 0, "mcp_and_tools": 0, "tool_results": 0, "conversation": 500, "total_estimated": 1000},
            tool_namespaces=[],
            usage={"input_tokens": 500, "output_tokens": 100, "cache_read_tokens": 0, "cache_write_tokens": 0},
            header_audit=[],
            secret_findings=[],
        )
        data = store.build_summary()
        store.close()

        self.assertEqual(data["traces"][0]["estimated_cost_usd"], 0.0)
        self.assertEqual(data["traces"][1]["estimated_cost_usd"], 0.0)
        self.assertIsNone(data["traces"][2]["estimated_cost_usd"])
        self.assertIsNone(data["summary"]["estimated_cost_usd"])
        self.assertEqual(data["summary"]["unknown_price_turn_count"], 1)

        html_en = render_inspector_html(data, live_poll=False, lang="en")
        html_zh = render_inspector_html(data, live_poll=False, lang="zh")
        self.assertIn("Unknown price", html_en)
        self.assertIn("未知价格", html_zh)
        self.assertIn("Tool Definition Tokens", html_en)
        self.assertIn("MCP Tool Share", html_en)
        self.assertIn("工具定义占用", html_zh)
        self.assertIn("MCP 工具定义占比", html_zh)
        for banned in ("waste schema", "Wasted Schema", "Context bloat", "Context Bloat", "浪费的", "冗余工具定义", "上下文膨胀"):
            self.assertNotIn(banned, html_en)
            self.assertNotIn(banned, html_zh)


if __name__ == "__main__":
    unittest.main()
