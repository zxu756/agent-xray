from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from agent_xray.cli import main
from agent_xray.store import TraceStore


class _FakeAnthropicHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        body = json.dumps(
            {
                "id": "msg_cli_1",
                "model": "claude-sonnet-4-5",
                "usage": {
                    "input_tokens": 200,
                    "cache_read_input_tokens": 8000,
                    "cache_creation_input_tokens": 1000,
                    "output_tokens": 500,
                },
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CliHonestyTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            try:
                rc = main(argv)
            except SystemExit as exc:
                rc = int(exc.code) if isinstance(exc.code, int) else 2
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def test_serve_allow_lan_without_auth_token_fails_en_and_zh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_en = Path(tmp) / "lan_en.db"
            rc_en, _, err_en = self._run_cli(["--lang", "en", "serve", "--allow-lan", "--db", str(db_en)])
            self.assertNotEqual(rc_en, 0)
            self.assertIn("--auth-token", err_en)
            self.assertFalse(db_en.exists())

            db_zh = Path(tmp) / "lan_zh.db"
            rc_zh, _, err_zh = self._run_cli(["--lang", "zh", "serve", "--allow-lan", "--db", str(db_zh)])
            self.assertNotEqual(rc_zh, 0)
            self.assertIn("--auth-token", err_zh)
            self.assertIn("局域网", err_zh)
            self.assertFalse(db_zh.exists())

    def test_report_honest_labels_cache_hit_exact_costs_and_unknown_price_en_and_zh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # 1. Sonnet 200 / 8000 / 1000 / 500 -> 87% cache hit, $0.01425, honest labels
            db_sonnet = Path(tmp) / "sonnet.db"
            store = TraceStore(db_sonnet)
            store.record_turn(
                provider="anthropic",
                model="claude-sonnet-4-5",
                path="/v1/messages",
                status_code=200,
                latency_ms=400,
                blocked=False,
                buckets={
                    "system_prompt": 1000,
                    "workspace_rules": 500,
                    "mcp_and_tools": 6000,
                    "tool_results": 1500,
                    "conversation": 1000,
                    "total_estimated": 10000,
                },
                tool_namespaces=[
                    {"namespace": "mcp:rea", "tool_count": 10, "estimated_tokens": 4000},
                    {"namespace": "builtin", "tool_count": 5, "estimated_tokens": 2000},
                ],
                usage={
                    "input_tokens": 200,
                    "cache_read_tokens": 8000,
                    "cache_write_tokens": 1000,
                    "output_tokens": 500,
                },
                header_audit=[
                    {"name": "User-Agent", "value_length": 24, "category": "fingerprint", "action": "normalized"},
                    {"name": "x-stainless-os", "value_length": 5, "category": "telemetry", "action": "stripped"},
                    {"name": "x-stainless-arch", "value_length": 5, "category": "telemetry", "action": "stripped"},
                ],
                secret_findings=[],
            )
            store.close()

            rc_en, _, err_en = self._run_cli(["--lang", "en", "report", "--db", str(db_sonnet)])
            self.assertEqual(rc_en, 0)
            self.assertIn("Tool Definition Tokens: 6,000", err_en)
            self.assertIn("MCP Tool Share: 40%", err_en)
            self.assertIn("87%", err_en)
            self.assertIn("$0.01425", err_en)
            self.assertIn("Stripped Telemetry Headers: 2", err_en)
            self.assertNotIn("Context Bloat", err_en)
            self.assertNotIn("Wasted Schema", err_en)

            rc_zh, _, err_zh = self._run_cli(["--lang", "zh", "report", "--db", str(db_sonnet)])
            self.assertEqual(rc_zh, 0)
            self.assertIn("工具定义占用：6,000", err_zh)
            self.assertIn("MCP 工具定义占比：40%", err_zh)
            self.assertIn("87%", err_zh)
            self.assertIn("$0.01425", err_zh)
            self.assertIn("去掉的遥测头：2", err_zh)
            self.assertNotIn("上下文膨胀", err_zh)
            self.assertNotIn("浪费的 Schema", err_zh)

            # 2. Opus 200 / 8000 / 1000 / 500 -> 87% cache hit, $0.07125
            db_opus = Path(tmp) / "opus.db"
            store_op = TraceStore(db_opus)
            store_op.record_turn(
                provider="anthropic",
                model="claude-opus-4-1",
                path="/v1/messages",
                status_code=200,
                latency_ms=620,
                blocked=False,
                buckets={"total_estimated": 2000, "mcp_and_tools": 500},
                tool_namespaces=[{"namespace": "mcp:scholar", "tool_count": 4, "estimated_tokens": 500}],
                usage={
                    "input_tokens": 200,
                    "cache_read_tokens": 8000,
                    "cache_write_tokens": 1000,
                    "output_tokens": 500,
                },
                header_audit=[],
                secret_findings=[],
            )
            store_op.close()
            _, _, op_en = self._run_cli(["--lang", "en", "report", "--db", str(db_opus)])
            _, _, op_zh = self._run_cli(["--lang", "zh", "report", "--db", str(db_opus)])
            self.assertIn("87%", op_en)
            self.assertIn("$0.07125", op_en)
            self.assertIn("87%", op_zh)
            self.assertIn("$0.07125", op_zh)

            # 3. Unknown model + local desktop no-bucket-breakdown -> Unknown price / No data
            db_unk = Path(tmp) / "unknown.db"
            store_u = TraceStore(db_unk)
            store_u.record_turn(
                provider="opencode-local",
                model="deepseek-v4.1-flash",
                path="local://opencode.db/ses_1#m1",
                status_code=200,
                latency_ms=300,
                blocked=False,
                buckets={"has_bucket_breakdown": False, "total_estimated": 0},
                tool_namespaces=[],
                usage={
                    "input_tokens": 200,
                    "cache_read_tokens": 8000,
                    "cache_write_tokens": 1000,
                    "output_tokens": 500,
                },
                header_audit=[],
                secret_findings=[],
            )
            store_u.close()
            _, _, u_en = self._run_cli(["--lang", "en", "report", "--db", str(db_unk)])
            _, _, u_zh = self._run_cli(["--lang", "zh", "report", "--db", str(db_unk)])
            self.assertIn("Unknown price", u_en)
            self.assertIn("Tool Definition Tokens: No data", u_en)
            self.assertIn("MCP Tool Share: No data", u_en)
            self.assertIn("未知价格", u_zh)
            self.assertIn("工具定义占用：没有数据", u_zh)
            self.assertIn("MCP 工具定义占比：没有数据", u_zh)

    def test_purge_db_removes_db_wal_shm_en_and_zh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "legacy.db"
            for suffix in ("", "-wal", "-shm"):
                Path(f"{db_path}{suffix}").write_text("legacy", encoding="utf-8")

            rc_en, out_en, _ = self._run_cli(["--lang", "en", "purge-db", "--db", str(db_path)])
            self.assertEqual(rc_en, 0)
            self.assertIn("Purged", out_en)
            self.assertIn("3", out_en)
            for suffix in ("", "-wal", "-shm"):
                self.assertFalse(Path(f"{db_path}{suffix}").exists())

            rc_zh, out_zh, _ = self._run_cli(["--lang", "zh", "purge-db", "--db", str(db_path)])
            self.assertEqual(rc_zh, 0)
            self.assertIn("无需清理", out_zh)

    def test_run_prints_startup_token_and_honors_store_previews_flag(self) -> None:
        upstream = HTTPServer(("127.0.0.1", 0), _FakeAnthropicHandler)
        up_port = upstream.server_address[1]
        up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        up_thread.start()
        old_env = os.environ.get("AGENT_XRAY_ANTHROPIC_UPSTREAM")
        os.environ["AGENT_XRAY_ANTHROPIC_UPSTREAM"] = f"http://127.0.0.1:{up_port}"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                client_code = (
                    "import json, os, urllib.request; "
                    "base = os.environ['ANTHROPIC_BASE_URL']; "
                    "secret = 'sk-ant-api03-' + ('SecretTailToken88' * 2); "
                    "msg = ('A' * 160) + ' ' + secret; "
                    "req = urllib.request.Request(base + '/v1/messages', "
                    "data=json.dumps({'model': 'claude-sonnet-4-5', 'messages': [{'role': 'user', 'content': msg}]}).encode(), "
                    "headers={'Content-Type': 'application/json'}); "
                    "urllib.request.urlopen(req, timeout=5).read()"
                )
                db_default = Path(tmp) / "run_default.db"
                rc1, _, err1 = self._run_cli(
                    [
                        "--lang",
                        "en",
                        "run",
                        "--db",
                        str(db_default),
                        "--auth-token",
                        "cli-tok-abc",
                        "--",
                        sys.executable,
                        "-c",
                        client_code,
                    ]
                )
                self.assertEqual(rc1, 0)
                self.assertIn("X-Xray-Token", err1)
                self.assertIn("cli-tok-abc", err1)

                conn1 = sqlite3.connect(db_default)
                prev1 = conn1.execute("SELECT prompt_preview FROM traces").fetchone()[0]
                conn1.close()
                self.assertEqual(prev1, "")

                db_prev = Path(tmp) / "run_previews.db"
                rc2, _, _ = self._run_cli(
                    [
                        "--lang",
                        "en",
                        "run",
                        "--db",
                        str(db_prev),
                        "--store-previews",
                        "--",
                        sys.executable,
                        "-c",
                        client_code,
                    ]
                )
                self.assertEqual(rc2, 0)
                conn2 = sqlite3.connect(db_prev)
                dump2 = "\n".join(conn2.iterdump())
                prev2 = conn2.execute("SELECT prompt_preview FROM traces").fetchone()[0]
                conn2.close()
                self.assertEqual(len(prev2), 140)
                self.assertNotIn("SecretTailToken88", dump2)
                self.assertNotIn("sk-ant", dump2)
        finally:
            if old_env is None:
                os.environ.pop("AGENT_XRAY_ANTHROPIC_UPSTREAM", None)
            else:
                os.environ["AGENT_XRAY_ANTHROPIC_UPSTREAM"] = old_env
            upstream.shutdown()
            upstream.server_close()

    def test_desktop_cli_import_only_isolated_db_and_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            cdir = home / ".claude/projects/demo"
            cdir.mkdir(parents=True)
            (cdir / "s1.jsonl").write_text(
                json.dumps(
                    {
                        "requestId": "r1",
                        "message": {
                            "id": "m1",
                            "role": "assistant",
                            "model": "claude-sonnet-4-5",
                            "content": [{"type": "text", "text": "CONFIDENTIAL_SESSION_TEXT_XYZ"}],
                            "usage": {
                                "input_tokens": 200,
                                "cache_read_input_tokens": 8000,
                                "cache_creation_input_tokens": 1000,
                                "output_tokens": 500,
                            },
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db_desk = Path(tmp) / "desk.db"
            rc, out_s, err_s = self._run_cli(
                [
                    "--lang",
                    "zh",
                    "desktop",
                    "--db",
                    str(db_desk),
                    "--home",
                    str(home),
                    "--import-only",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertNotIn("CONFIDENTIAL_SESSION_TEXT_XYZ", out_s + err_s)
            self.assertIn("工具定义占用：没有数据", err_s)
            self.assertIn("87%", err_s)
            self.assertIn("$0.01425", err_s)

    def test_pyproject_description_does_not_claim_streaming_proxy(self) -> None:
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        desc_lines = [line for line in pyproject.splitlines() if line.strip().startswith("description")]
        self.assertEqual(len(desc_lines), 1)
        self.assertNotIn("streaming", desc_lines[0].lower())


if __name__ == "__main__":
    unittest.main()
