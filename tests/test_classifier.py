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

    def test_m1_block_level_and_inline_tag_splitting_across_three_formats(self) -> None:
        # 1. Anthropic Messages: plain system mentioning CLAUDE.md -> system_prompt;
        #    single user block mixing <system-reminder> and user prose -> split!
        ant_payload = {
            "model": "claude-sonnet-4-5",
            "system": [
                {"type": "text", "text": "You are Claude Code. Read CLAUDE.md for repo guidance. " + ("S" * 700)},
            ],
            "tools": [
                {"name": "mcp__rea__open", "description": "D" * 300, "input_schema": {"type": "object"}},
            ],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "<system-reminder>" + ("R" * 750) + "</system-reminder>" + ("U" * 1125)},
                    ],
                },
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "mcp__rea__open", "input": {"p": "X" * 300}},
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "t1", "content": "O" * 1625},
                    ],
                },
            ],
        }
        ant_cls = classify_request_payload("/anthropic/v1/messages", ant_payload)
        b1 = ant_cls.buckets.to_dict()
        self.assertEqual(b1["system_prompt"], estimate_tokens(ant_payload["system"][0]["text"]))
        self.assertEqual(b1["workspace_rules"], estimate_tokens("<system-reminder>" + ("R" * 750) + "</system-reminder>"))
        self.assertEqual(b1["tool_results"], estimate_tokens("O" * 1625, code_heavy=True))
        expected_ant_conv = estimate_tokens("U" * 1125) + estimate_tokens(ant_payload["messages"][1]["content"][0], code_heavy=True)
        self.assertEqual(b1["conversation"], expected_ant_conv)
        self.assertEqual(
            b1["system_prompt"] + b1["workspace_rules"] + b1["mcp_and_tools"] + b1["tool_results"] + b1["conversation"],
            b1["total_estimated"],
        )

        # 2. OpenAI Chat Completions: system mentioning AGENTS.md -> system_prompt;
        #    developer "# AGENTS.md" -> workspace_rules; assistant tool_calls arguments -> conversation!
        chat_payload = {
            "model": "gpt-4o",
            "tools": [
                {"type": "function", "function": {"name": "read", "description": "D" * 300, "parameters": {"type": "object"}}},
            ],
            "messages": [
                {"role": "system", "content": "System prompt mentioning AGENTS.md filename only. " + ("S" * 700)},
                {"role": "developer", "content": "# AGENTS.md\n" + ("R" * 750)},
                {"role": "user", "content": "U" * 375},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "read", "arguments": "A" * 1500}},
                    ],
                },
                {"role": "tool", "tool_call_id": "c1", "content": "O" * 1625},
            ],
        }
        chat_cls = classify_request_payload("/openai/v1/chat/completions", chat_payload)
        b2 = chat_cls.buckets.to_dict()
        self.assertEqual(b2["system_prompt"], estimate_tokens(chat_payload["messages"][0]["content"]))
        self.assertEqual(b2["workspace_rules"], estimate_tokens(chat_payload["messages"][1]["content"]))
        expected_chat_conv = (
            estimate_tokens("U" * 375)
            + estimate_tokens("read", code_heavy=True)
            + estimate_tokens("A" * 1500, code_heavy=True)
        )
        self.assertEqual(b2["conversation"], expected_chat_conv)
        self.assertEqual(b2["tool_results"], estimate_tokens("O" * 1625, code_heavy=True))
        self.assertEqual(
            b2["system_prompt"] + b2["workspace_rules"] + b2["mcp_and_tools"] + b2["tool_results"] + b2["conversation"],
            b2["total_estimated"],
        )

        # 3. OpenAI Responses API: instructions, unclosed <user_rules>, input_text, reasoning,
        #    function_call arguments, and function_call_output!
        resp_payload = {
            "model": "gpt-5",
            "instructions": "Base instructions mentioning CLAUDE.md in prose. " + ("S" * 730),
            "tools": [
                {"type": "function", "name": "mcp_box.sh", "description": "D" * 300, "parameters": {"type": "object"}},
            ],
            "input": [
                {"role": "developer", "content": [{"type": "input_text", "text": "<user_rules>" + ("R" * 740)}]},
                {"role": "user", "content": [{"type": "input_text", "text": "U" * 375}]},
                {"type": "reasoning", "summary": [{"type": "summary_text", "text": "T" * 375}]},
                {"type": "function_call", "call_id": "c1", "name": "mcp_box.sh", "arguments": "A" * 1125},
                {"type": "function_call_output", "call_id": "c1", "output": "O" * 1625},
            ],
        }
        resp_cls = classify_request_payload("/openai/v1/responses", resp_payload)
        b3 = resp_cls.buckets.to_dict()
        self.assertEqual(b3["system_prompt"], estimate_tokens(resp_payload["instructions"]))
        self.assertEqual(b3["workspace_rules"], estimate_tokens("<user_rules>" + ("R" * 740)))
        expected_resp_conv = (
            estimate_tokens("U" * 375)
            + estimate_tokens("T" * 375)
            + estimate_tokens("mcp_box.sh", code_heavy=True)
            + estimate_tokens("A" * 1125, code_heavy=True)
        )
        self.assertEqual(b3["conversation"], expected_resp_conv)
        self.assertEqual(b3["tool_results"], estimate_tokens("O" * 1625, code_heavy=True))
        self.assertEqual(
            b3["system_prompt"] + b3["workspace_rules"] + b3["mcp_and_tools"] + b3["tool_results"] + b3["conversation"],
            b3["total_estimated"],
        )

    def test_m1_incremental_usage_parser_on_2mb_sse_and_gzip_responses(self) -> None:
        import gzip
        from agent_xray.classifier import IncrementalResponseUsageParser

        # 2.4 MB SSE stream split at arbitrary 4096-byte chunk boundaries, with usage in final event
        parser = IncrementalResponseUsageParser(is_sse=True)
        head = (
            b'event: message_start\n'
            b'data: {"type":"message_start","message":{"usage":{"input_tokens":321,"cache_read_input_tokens":654,"cache_creation_input_tokens":98}}}\n\n'
        )
        delta_frame = b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"' + (b"x" * 1000) + b'"}}\n\n'
        tail = (
            b'event: message_delta\n'
            b'data: {"type":"message_delta","usage":{"output_tokens":7777}}\n\n'
            b'event: message_stop\n'
            b'data: {"type":"message_stop"}\n\n'
        )
        stream_bytes = head + (delta_frame * 2300) + tail
        self.assertGreater(len(stream_bytes), 2_200_000)

        for offset in range(0, len(stream_bytes), 4096):
            parser.feed(stream_bytes[offset : offset + 4096])
        usage = parser.finish()
        self.assertEqual(
            usage,
            {
                "input_tokens": 321,
                "cache_read_tokens": 654,
                "cache_write_tokens": 98,
                "output_tokens": 7777,
            },
        )

        # Gzip-compressed OpenAI Responses SSE with response.completed usage
        resp_sse = (
            b'event: response.output_text.delta\n'
            b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'
            b'event: response.completed\n'
            b'data: {"type":"response.completed","response":{"usage":{"input_tokens":1500,"output_tokens":240,"input_tokens_details":{"cached_tokens":1000}}}}\n\n'
        )
        gz_sse = gzip.compress(resp_sse)
        gz_parser = IncrementalResponseUsageParser(is_sse=True, content_encoding="gzip")
        for offset in range(0, len(gz_sse), 37):
            gz_parser.feed(gz_sse[offset : offset + 37])
        self.assertEqual(
            gz_parser.finish(),
            {
                "input_tokens": 500,
                "cache_read_tokens": 1000,
                "cache_write_tokens": 0,
                "output_tokens": 240,
            },
        )

    def test_xr2_readme_cjk_ratio_matches_estimate_tokens_constant(self) -> None:
        import re
        from pathlib import Path

        cjk_1000 = estimate_tokens("中" * 1000)
        self.assertEqual(cjk_1000, 850)
        expected_chars_per_token = round(1000.0 / cjk_1000, 2)  # 1.18

        repo_root = Path(__file__).resolve().parents[1]
        readme_en = (repo_root / "README.md").read_text(encoding="utf-8")
        readme_zh = (repo_root / "README.zh-CN.md").read_text(encoding="utf-8")

        self.assertNotIn("1.55", readme_en)
        self.assertNotIn("1.55", readme_zh)

        m_en = re.search(r"`~([0-9]+\.[0-9]+)`\s*CJK chars/token", readme_en)
        self.assertIsNotNone(m_en, "Missing CJK chars/token figure in README.md")
        self.assertAlmostEqual(float(m_en.group(1)), expected_chars_per_token, places=2)

        m_zh = re.search(r"CJK\s*约\s*`([0-9]+\.[0-9]+)`\s*字符/Token", readme_zh)
        self.assertIsNotNone(m_zh, "Missing CJK 字符/Token figure in README.zh-CN.md")
        self.assertAlmostEqual(float(m_zh.group(1)), expected_chars_per_token, places=2)

    def test_xr3_developer_role_prose_mentioning_agents_or_claude_md_stays_in_system_prompt(self) -> None:
        # 1. Chat Completions: developer prose mentioning AGENTS.md / CLAUDE.md -> system_prompt
        prose = "Follow repo style; see AGENTS.md and CLAUDE.md if needed."
        chat_res = classify_request_payload(
            "/openai/v1/chat/completions",
            {
                "model": "gpt-4o",
                "messages": [
                    {"role": "developer", "content": prose},
                    {"role": "user", "content": "Hello"},
                ],
            },
        )
        b_chat = chat_res.buckets.to_dict()
        self.assertEqual(b_chat["system_prompt"], estimate_tokens(prose))
        self.assertEqual(b_chat["workspace_rules"], 0)
        self.assertEqual(b_chat["conversation"], estimate_tokens("Hello"))

        # 2. Responses API: developer input_text prose mentioning .cursorrules / copilot-instructions.md -> system_prompt
        resp_prose = "Respect repository conventions; check .cursorrules or copilot-instructions.md when present."
        resp_res = classify_request_payload(
            "/openai/v1/responses",
            {
                "model": "gpt-5",
                "input": [
                    {"role": "developer", "content": [{"type": "input_text", "text": resp_prose}]},
                ],
            },
        )
        b_resp = resp_res.buckets.to_dict()
        self.assertEqual(b_resp["system_prompt"], estimate_tokens(resp_prose))
        self.assertEqual(b_resp["workspace_rules"], 0)

        # 3. Developer message mixing prose + <user_rules> tag splits cleanly; standalone "# AGENTS.md" goes to workspace_rules
        mixed_dev = "Developer harness header. <user_rules>Always run pytest first.</user_rules>"
        mixed_res = classify_request_payload(
            "/openai/v1/chat/completions",
            {
                "model": "gpt-4o",
                "messages": [
                    {"role": "developer", "content": mixed_dev},
                    {"role": "developer", "content": "# AGENTS.md\nStrict rule dump body."},
                ],
            },
        )
        b_mixed = mixed_res.buckets.to_dict()
        self.assertEqual(b_mixed["system_prompt"], estimate_tokens("Developer harness header. "))
        self.assertEqual(
            b_mixed["workspace_rules"],
            estimate_tokens("<user_rules>Always run pytest first.</user_rules>")
            + estimate_tokens("# AGENTS.md\nStrict rule dump body."),
        )

    def test_xr1_calibration_routine_executes_against_local_fake_upstream(self) -> None:
        import importlib.util
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[1]
        m1_sh = (repo_root / "Scripts" / "acceptance" / "m1-acceptance.sh").read_text(encoding="utf-8")
        self.assertNotIn("import classify_request\n", m1_sh)
        self.assertNotIn("classify_request(", m1_sh)

        cal_path = repo_root / "Scripts" / "acceptance" / "calibrate_tokenizer.py"
        self.assertTrue(cal_path.is_file(), "Missing Scripts/acceptance/calibrate_tokenizer.py")
        spec = importlib.util.spec_from_file_location("calibrate_tokenizer", cal_path)
        assert spec is not None and spec.loader is not None
        cal_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cal_mod)

        class FakeCalibrationUpstream(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length)
                payload = json.loads(raw.decode("utf-8"))
                est = classify_request_payload(self.path, payload).buckets.total_estimated
                # Simulate vendor tokenizer returning exact token count +10%
                actual_in = max(1, int(round(est * 1.10)))
                if "messages" in self.path and "chat/completions" not in self.path:
                    resp_obj = {
                        "id": "msg_cal",
                        "type": "message",
                        "model": payload.get("model", "claude-3-5-haiku-latest"),
                        "usage": {
                            "input_tokens": actual_in,
                            "cache_read_input_tokens": 0,
                            "cache_creation_input_tokens": 0,
                            "output_tokens": 1,
                        },
                    }
                else:
                    resp_obj = {
                        "id": "chatcmpl_cal",
                        "model": payload.get("model", "gpt-4o-mini"),
                        "usage": {
                            "prompt_tokens": actual_in,
                            "completion_tokens": 1,
                        },
                    }
                body = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeCalibrationUpstream)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            report = cal_mod.run_tokenizer_calibration(
                anthropic_base_url=f"http://127.0.0.1:{port}",
                openai_base_url=f"http://127.0.0.1:{port}/v1",
                anthropic_api_key="test-local-ant-key",
                openai_api_key="test-local-oai-key",
                sample_count=3,
            )
        finally:
            srv.shutdown()
            srv.server_close()

        self.assertEqual(len(report["anthropic"]["samples"]), 3)
        self.assertEqual(len(report["openai"]["samples"]), 3)
        self.assertGreaterEqual(report["anthropic"]["max_error"], 0.0)
        self.assertLess(report["anthropic"]["max_error"], 0.25)
        self.assertGreaterEqual(report["openai"]["max_error"], 0.0)
        self.assertLess(report["openai"]["max_error"], 0.25)


if __name__ == "__main__":
    unittest.main()
