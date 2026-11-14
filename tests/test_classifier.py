from __future__ import annotations

import json
import unittest

from agent_xray.classifier import (
    classify_request_payload,
    estimate_tokens,
    extract_tool_namespace,
    parse_usage_from_response,
)


class ClassifierHonestyTests(unittest.TestCase):
    def test_estimate_tokens_and_namespace_extraction_exact(self) -> None:
        self.assertEqual(estimate_tokens(""), 0)
        self.assertEqual(estimate_tokens("abcd"), 1)
        self.assertEqual(estimate_tokens("a" * 40), 11)
        self.assertEqual(extract_tool_namespace("mcp__scholar__search_papers"), "mcp:scholar")
        self.assertEqual(extract_tool_namespace("mcp_box.shell"), "mcp:box")
        self.assertEqual(extract_tool_namespace("playwright:browser_snapshot"), "mcp:playwright")
        self.assertEqual(extract_tool_namespace("Bash"), "builtin")

    def test_openai_usage_separates_cached_tokens_from_uncached_prompt_tokens(self) -> None:
        # OpenAI chat/completions reports prompt_tokens INCLUSIVE of cached_tokens!
        resp_bytes = json.dumps(
            {
                "id": "chatcmpl_1",
                "usage": {
                    "prompt_tokens": 9200,
                    "completion_tokens": 500,
                    "prompt_tokens_details": {"cached_tokens": 8000},
                },
            }
        ).encode("utf-8")
        usage = parse_usage_from_response(resp_bytes, False)
        self.assertEqual(
            usage,
            {
                "input_tokens": 1200,
                "cache_read_tokens": 8000,
                "cache_write_tokens": 0,
                "output_tokens": 500,
            },
        )

    def test_anthropic_sse_usage_preserves_cache_write_tokens(self) -> None:
        sse = (
            'data: {"type":"message_start","message":{"usage":{"input_tokens":200,"cache_read_input_tokens":8000,"cache_creation_input_tokens":1000}}}\n\n'
            'data: {"type":"message_delta","usage":{"output_tokens":500}}\n\n'
        ).encode("utf-8")
        usage = parse_usage_from_response(sse, True)
        self.assertEqual(
            usage,
            {
                "input_tokens": 200,
                "cache_read_tokens": 8000,
                "cache_write_tokens": 1000,
                "output_tokens": 500,
            },
        )

    def test_store_previews_off_by_default_and_redacts_before_truncation(self) -> None:
        secret = "sk-or-v1-" + ("ab12cd34" * 8)
        payload = {
            "model": "claude-sonnet-4-5",
            "messages": [{"role": "user", "content": ("X" * 135) + secret}],
        }
        default_cls = classify_request_payload("/anthropic/v1/messages", payload)
        self.assertEqual(default_cls.prompt_preview, "")

        opt_in_cls = classify_request_payload("/anthropic/v1/messages", payload, store_previews=True)
        self.assertLessEqual(len(opt_in_cls.prompt_preview), 140)
        self.assertNotIn("sk-or-v1", opt_in_cls.prompt_preview)
        self.assertNotIn("ab12cd34", opt_in_cls.prompt_preview)


if __name__ == "__main__":
    unittest.main()
