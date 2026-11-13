from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_xray import __version__
from agent_xray.classifier import classify_request_payload, extract_tool_namespace, parse_usage_from_response
from agent_xray.cli import main
from agent_xray.i18n import resolve_html_lang_mode, resolve_lang
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
        self.assertEqual(outbound["User-Agent"], "agent-xray/0.2.0")
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
            self.assertEqual(_MockUpstreamHandler.received_headers[0]["user-agent"], "agent-xray/0.2.0")

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
            self.assertGreaterEqual(summary_obj["summary"]["estimated_cost_usd"], 0.0)

            # 4. Verify live /_xray/?lang=zh UI rendering on proxy server
            conn4 = http.client.HTTPConnection("127.0.0.1", px_port, timeout=10)
            conn4.request("GET", "/_xray/?lang=zh")
            ui_resp = conn4.getresponse()
            self.assertEqual(ui_resp.status, 200)
            ui_zh_body = ui_resp.read().decode("utf-8")
            conn4.close()
            self.assertIn('lang="zh-CN"', ui_zh_body)
            self.assertIn("逐轮上下文 Token 构成火焰图", ui_zh_body)
        finally:
            proxy.shutdown()
            proxy.server_close()
            upstream.shutdown()
            upstream.server_close()
            store.close()

    def test_demo_dataset_and_html_export(self) -> None:
        demo = build_demo_dataset()
        html_en = render_inspector_html(demo, live_poll=False, lang="en")
        self.assertIn('lang="en"', html_en)
        self.assertIn('data-default-lang="en"', html_en)
        self.assertIn("Turn-by-turn context token flamegraph", html_en)
        self.assertIn("mcp:rea", html_en)
        self.assertIn('data-lang-switch="zh"', html_en)
        self.assertIn('data-lang-switch="en"', html_en)
        self.assertIn('id="session-select"', html_en)
        self.assertIn('id="scan-desktop-btn"', html_en)
        self.assertNotIn("\u2014", html_en)
        self.assertNotIn("\u2013", html_en)
        self.assertGreater(len(html_en), 6000)

        html_zh = render_inspector_html(demo, live_poll=False, lang="zh")
        self.assertIn('lang="zh-CN"', html_zh)
        self.assertIn('data-default-lang="zh"', html_zh)
        self.assertIn("逐轮上下文 Token 构成火焰图", html_zh)
        self.assertIn("扫描桌面端", html_zh)
        self.assertIn("MCP 与工具定义 Token 排行榜", html_zh)
        self.assertIn("出站请求头与密钥外泄审计", html_zh)
        self.assertNotIn("\u2014", html_zh)
        self.assertNotIn("\u2013", html_zh)

    def test_version_and_bilingual_cli_lang_support(self) -> None:
        self.assertEqual(__version__, "0.2.0")

        # Precedence: CLI flag > AGENT_XRAY_LANG > LC_ALL / LANG > en
        self.assertEqual(resolve_lang("zh", {"AGENT_XRAY_LANG": "en", "LC_ALL": "en_US.UTF-8"}), "zh")
        self.assertEqual(resolve_lang("en", {"AGENT_XRAY_LANG": "zh", "LC_ALL": "zh_CN.UTF-8"}), "en")
        self.assertEqual(resolve_lang("auto", {"AGENT_XRAY_LANG": "zh-CN", "LC_ALL": "en_US.UTF-8"}), "zh")
        self.assertEqual(resolve_lang("auto", {"AGENT_XRAY_LANG": "en", "LC_ALL": "zh_CN.UTF-8"}), "en")
        self.assertEqual(resolve_lang("auto", {"LC_ALL": "zh_CN.UTF-8"}), "zh")
        self.assertEqual(resolve_lang("auto", {"LANG": "zh_TW.UTF-8"}), "zh")
        self.assertEqual(resolve_lang("auto", {"LANG": "en_US.UTF-8"}), "en")
        self.assertEqual(resolve_lang("auto", {}), "en")

        self.assertEqual(resolve_html_lang_mode("zh", {}), ("zh", "zh"))
        self.assertEqual(resolve_html_lang_mode("en", {}), ("en", "en"))
        self.assertEqual(resolve_html_lang_mode("auto", {"LANG": "en_US.UTF-8"}), ("en", "auto"))
        self.assertEqual(resolve_html_lang_mode("auto", {"LC_ALL": "zh_CN.UTF-8"}), ("zh", "zh"))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "trace.sqlite"
            store = TraceStore(db_path)
            payload = {
                "model": "claude-sonnet-4-5",
                "system": "System instructions",
                "tools": [{"name": "mcp__rea__open_binary", "input_schema": {"type": "object"}}],
                "messages": [{"role": "user", "content": "Inspect Mach-O binary"}],
            }
            cls = classify_request_payload("/anthropic/v1/messages", payload)
            store.record_turn(
                provider=cls.provider,
                model=cls.model,
                path="/anthropic/v1/messages",
                status_code=200,
                latency_ms=142,
                blocked=False,
                buckets=cls.buckets.to_dict(),
                tool_namespaces=[n.to_dict() for n in cls.tool_namespaces],
                usage={"input_tokens": 1800, "output_tokens": 90, "cache_read_input_tokens": 600},
                header_audit=[{"header": "x-stainless-os", "value": "MacOS", "action": "stripped"}],
                secret_findings=[],
                prompt_preview="Inspect Mach-O binary",
            )
            store.close()

            old_env = os.environ.get("AGENT_XRAY_LANG")
            os.environ["AGENT_XRAY_LANG"] = ""
            try:
                err_zh = io.StringIO()
                with contextlib.redirect_stderr(err_zh):
                    rc = main(["--lang", "zh", "report", "--db", str(db_path)])
                self.assertEqual(rc, 0)
                self.assertIn("会话摘要", err_zh.getvalue())
                self.assertIn("个工具", err_zh.getvalue())

                err_en = io.StringIO()
                with contextlib.redirect_stderr(err_en):
                    rc2 = main(["report", "--lang", "en", "--db", str(db_path)])
                self.assertEqual(rc2, 0)
                self.assertIn("Session summary", err_en.getvalue())
                self.assertIn("tools", err_en.getvalue())

                out_html = tmp / "demo-zh.html"
                out_buf = io.StringIO()
                with contextlib.redirect_stdout(out_buf):
                    rc3 = main(["export-demo", "--lang", "zh", "--out", str(out_html)])
                self.assertEqual(rc3, 0)
                self.assertIn("已导出静态演示检查器至", out_buf.getvalue())
                self.assertIn('lang="zh-CN"', out_html.read_text(encoding="utf-8"))
            finally:
                if old_env is None:
                    os.environ.pop("AGENT_XRAY_LANG", None)
                else:
                    os.environ["AGENT_XRAY_LANG"] = old_env


if __name__ == "__main__":
    unittest.main()
