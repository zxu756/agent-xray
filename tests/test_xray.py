from __future__ import annotations

import http.client
import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_xray.classifier import classify_request_payload, extract_tool_namespace, parse_usage_from_response
from agent_xray.privacy import audit_and_prepare_headers, scan_body_for_secrets
from agent_xray.proxy import ProxyConfig, XRayHTTPServer
from agent_xray.store import TraceStore, build_demo_dataset
from agent_xray.ui_html import render_inspector_html


class _MockUpstreamHandler(BaseHTTPRequestHandler):
    received_headers: list[dict[str, str]] = []
    request_count: int = 0

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        type(self).request_count += 1
        length = int(self.headers.get("Content-Length") or "0")
        _ = self.rfile.read(length) if length else b""
        type(self).received_headers.append({k.lower(): v for k, v in self.headers.items()})

        if "stream" in self.path or self.headers.get("x-test-sse") == "1":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            frames = [
                'data: {"type":"message_start","message":{"usage":{"input_tokens":4200,"cache_read_input_tokens":3100}}}\n\n',
                'data: {"type":"content_block_delta","delta":{"text":"Hello"}}\n\n',
                'data: {"type":"message_delta","usage":{"output_tokens":95}}\n\n',
                "data: [DONE]\n\n",
            ]
            for frame in frames:
                self.wfile.write(frame.encode("utf-8"))
                self.wfile.flush()
                time.sleep(0.01)
            return

        resp = {
            "id": "msg_01",
            "usage": {"input_tokens": 1200, "output_tokens": 45, "cache_read_input_tokens": 800},
        }
        raw = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class AgentXRayTests(unittest.TestCase):
    def test_anthropic_five_bucket_and_mcp_grouping(self) -> None:
        payload = {
            "model": "claude-sonnet-4-5",
            "stream": True,
            "system": [
                {"type": "text", "text": "You are an autonomous coding assistant.", "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": "<user_rules>\nLoaded from AGENTS.md workspace instructions\n</user_rules>"},
            ],
            "tools": [
                {"name": "mcp__rea__inspect_macho", "description": "Inspect Mach-O headers", "input_schema": {"type": "object"}},
                {"name": "mcp__rea__decompile_all", "description": "Decompile binary", "input_schema": {"type": "object"}},
                {"name": "mcp__playwright__browser_snapshot", "description": "DOM snapshot", "input_schema": {"type": "object"}},
                {"name": "Bash", "description": "Execute shell command", "input_schema": {"type": "object"}},
            ],
            "messages": [
                {"role": "user", "content": "Audit my release app binary"},
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "t1", "content": "Mach-O 64-bit arm64 executable minos 14.0"},
                    ],
                },
            ],
        }
        res = classify_request_payload("/anthropic/v1/messages", payload)
        self.assertEqual(res.provider, "anthropic")
        self.assertGreater(res.buckets.system_prompt, 0)
        self.assertGreater(res.buckets.workspace_rules, 0)
        self.assertGreater(res.buckets.mcp_and_tools, 0)
        self.assertGreater(res.buckets.tool_results, 0)
        self.assertGreater(res.buckets.conversation, 0)
        self.assertEqual(res.cache_breakpoint_count, 1)

        ns_map = {n.namespace: n.tool_count for n in res.tool_namespaces}
        self.assertEqual(ns_map["mcp:rea"], 2)
        self.assertEqual(ns_map["mcp:playwright"], 1)
        self.assertEqual(ns_map["builtin"], 1)

    def test_openai_responses_classification(self) -> None:
        payload = {
            "model": "gpt-5-codex",
            "instructions": "Follow CLAUDE.md and AGENTS.md strictly.",
            "tools": [
                {"type": "function", "name": "mcp_box.shell", "parameters": {"type": "object"}},
            ],
            "input": [
                {"role": "system", "content": "Core developer harness."},
                {"role": "user", "content": "Run test suite"},
                {"type": "function_call_output", "output": "Ran 12 tests in 0.04s OK"},
            ],
        }
        res = classify_request_payload("/openai/v1/responses", payload)
        self.assertEqual(res.provider, "openai")
        self.assertGreater(res.buckets.workspace_rules, 0)
        self.assertGreater(res.buckets.system_prompt, 0)
        self.assertGreater(res.buckets.tool_results, 0)
        self.assertEqual(extract_tool_namespace("mcp_box.shell"), "mcp:box")

    def test_header_stripping_and_secret_redaction(self) -> None:
        fake_key = "sk-ant-" + ("K" * 32)
        inbound = [
            ("x-api-key", fake_key),
            ("User-Agent", "claude-cli/2.1.0 (Darwin arm64)"),
            ("x-stainless-os", "MacOS"),
            ("x-stainless-arch", "arm64"),
            ("anthropic-version", "2023-06-01"),
        ]
        outbound, audit = audit_and_prepare_headers(inbound, strip_telemetry=True)
        self.assertNotIn("x-stainless-os", outbound)
        self.assertNotIn("x-stainless-arch", outbound)
        self.assertEqual(outbound["User-Agent"], "agent-xray/0.1.0")
        self.assertEqual(outbound["x-api-key"], fake_key)

        audit_dump = json.dumps([a.to_dict() for a in audit])
        self.assertNotIn(fake_key, audit_dump)

        findings = scan_body_for_secrets(f" accidentally pasted {fake_key} in prompt ")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "Anthropic API Key")
        self.assertNotIn(fake_key, findings[0].redacted_snippet)

    def test_sse_streaming_passthrough_and_secret_block(self) -> None:
        _MockUpstreamHandler.received_headers = []
        _MockUpstreamHandler.request_count = 0
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _MockUpstreamHandler)
        up_port = upstream.server_address[1]
        up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        up_thread.start()

        store = TraceStore(":memory:")
        cfg = ProxyConfig(
            host="127.0.0.1",
            port=0,
            anthropic_upstream=f"http://127.0.0.1:{up_port}",
            openai_upstream=f"http://127.0.0.1:{up_port}",
            strip_telemetry_headers=True,
            block_secrets=True,
        )
        proxy = XRayHTTPServer(cfg, store)
        px_port = proxy.server_address[1]
        px_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        px_thread.start()

        try:
            # 1. Clean SSE streaming request
            conn = http.client.HTTPConnection("127.0.0.1", px_port, timeout=10)
            clean_body = json.dumps(
                {
                    "model": "claude-sonnet-4-5",
                    "stream": True,
                    "system": "System prompt",
                    "tools": [{"name": "mcp__rea__open_binary", "input_schema": {"type": "object"}}],
                    "messages": [{"role": "user", "content": "Check binary"}],
                }
            ).encode("utf-8")
            auth_val = "sk-ant-" + ("Q" * 30)
            conn.request(
                "POST",
                "/anthropic/v1/messages",
                body=clean_body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": auth_val,
                    "x-stainless-os": "MacOS",
                    "User-Agent": "claude-cli/2.1 (Darwin arm64)",
                    "x-test-sse": "1",
                },
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            sse_bytes = resp.read()
            conn.close()
            self.assertIn(b"content_block_delta", sse_bytes)
            self.assertEqual(_MockUpstreamHandler.request_count, 1)
            self.assertNotIn("x-stainless-os", _MockUpstreamHandler.received_headers[0])
            self.assertEqual(_MockUpstreamHandler.received_headers[0]["user-agent"], "agent-xray/0.1.0")

            # 2. Secret-leaking request must be blocked with 400 BEFORE hitting upstream
            leaked_tok = "ghp_" + ("9" * 30)
            conn2 = http.client.HTTPConnection("127.0.0.1", px_port, timeout=10)
            leak_body = json.dumps(
                {
                    "model": "claude-sonnet-4-5",
                    "messages": [{"role": "user", "content": f"Deploy using token {leaked_tok}"}],
                }
            ).encode("utf-8")
            conn2.request(
                "POST",
                "/anthropic/v1/messages",
                body=leak_body,
                headers={"Content-Type": "application/json"},
            )
            resp2 = conn2.getresponse()
            self.assertEqual(resp2.status, 400)
            _ = resp2.read()
            conn2.close()
            # Upstream request_count must STILL be 1!
            self.assertEqual(_MockUpstreamHandler.request_count, 1)

            # 3. Verify SQLite summary & HTML inspector endpoint contain zero raw secrets
            conn3 = http.client.HTTPConnection("127.0.0.1", px_port, timeout=10)
            conn3.request("GET", "/_xray/api/summary")
            sum_resp = conn3.getresponse()
            self.assertEqual(sum_resp.status, 200)
            raw_summary = sum_resp.read().decode("utf-8")
            conn3.close()
            self.assertNotIn(auth_val, raw_summary)
            self.assertNotIn(leaked_tok, raw_summary)
            summary_obj = json.loads(raw_summary)
            self.assertEqual(summary_obj["summary"]["turn_count"], 2)
            self.assertEqual(summary_obj["summary"]["blocked_count"], 1)
            self.assertEqual(summary_obj["summary"]["total_cache_read"], 3100)
        finally:
            proxy.shutdown()
            proxy.server_close()
            upstream.shutdown()
            upstream.server_close()
            store.close()

    def test_demo_dataset_and_html_export(self) -> None:
        demo = build_demo_dataset()
        html = render_inspector_html(demo, live_poll=False)
        self.assertIn("Turn-by-turn context token flamegraph", html)
        self.assertIn("mcp:rea", html)
        self.assertGreater(len(html), 6000)


if __name__ == "__main__":
    unittest.main()
