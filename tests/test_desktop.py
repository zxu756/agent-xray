from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_xray.local_sessions import import_local_desktop_sessions
from agent_xray.store import TraceStore
from agent_xray.ui_html import render_inspector_html


class DesktopLocalSessionTests(unittest.TestCase):
    def test_no_fixed_ratios_in_source(self) -> None:
        src_dir = Path(__file__).resolve().parents[1] / "src"
        for py_file in src_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for forbidden_ratio in ("0.12", "0.28", "0.34", "0.14", "0.09"):
                self.assertNotIn(
                    forbidden_ratio,
                    content,
                    f"Found forbidden fixed bucket ratio {forbidden_ratio} in {py_file}",
                )

    def test_opencode_per_turn_import_ignores_session_v2_cumulative_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            oc_dir = home / ".local/share/opencode"
            oc_dir.mkdir(parents=True)
            oc_db = oc_dir / "opencode.db"

            conn = sqlite3.connect(oc_db)
            conn.execute(
                """
                CREATE TABLE session_v2 (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    model TEXT,
                    tokens_input INTEGER,
                    tokens_output INTEGER,
                    tokens_cache_read INTEGER,
                    tokens_cache_write INTEGER,
                    time_updated INTEGER
                )
                """
            )
            # Huge cumulative session row that previously caused $717 cost & 2091% cache hit rate!
            conn.execute(
                """
                INSERT INTO session_v2 VALUES (
                    'ses_cum_1', 'Secret title sk-ant-api03-12345678901234567890',
                    '{"id":"deepseek-v4.1-flash","providerID":"opencode-go"}',
                    99449290, 3104714, 2149521664, 0, 1794603750000
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE session_message (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    type TEXT,
                    seq INTEGER,
                    time_created INTEGER,
                    time_updated INTEGER,
                    data TEXT
                )
                """
            )
            turn1_data = {
                "model": {"id": "claude-sonnet-4-5", "providerID": "anthropic"},
                "time": {"created": 1794603700000, "completed": 1794603701500},
                "tokens": {
                    "input": 200,
                    "output": 80,
                    "reasoning": 0,
                    "cache": {"read": 1800, "write": 0},
                },
            }
            turn2_data = {
                "model": {"id": "deepseek-v4.1-flash", "providerID": "opencode-go"},
                "time": {"created": 1794603710000, "completed": 1794603712200},
                "tokens": {
                    "input": 500,
                    "output": 150,
                    "reasoning": 300,
                    "cache": {"read": 4500, "write": 0},
                },
            }
            conn.execute(
                "INSERT INTO session_message VALUES ('m1', 'ses_cum_1', 'assistant', 1, 1794603700000, 1794603701500, ?)",
                (json.dumps(turn1_data),),
            )
            conn.execute(
                "INSERT INTO session_message VALUES ('m2', 'ses_cum_1', 'assistant', 2, 1794603710000, 1794603712200, ?)",
                (json.dumps(turn2_data),),
            )
            conn.commit()
            conn.close()

            target_db = home / "out.db"
            store = TraceStore(target_db)
            imported = import_local_desktop_sessions(store, home=home, max_turns=20)
            summary_data = store.build_summary()
            store.close()

            self.assertEqual(imported, 2)
            traces = summary_data["traces"]
            self.assertEqual(len(traces), 2)

            # Turn 1: Sonnet exact pricing & zero fake buckets
            self.assertEqual(traces[0]["model"], "claude-sonnet-4-5")
            self.assertFalse(traces[0]["has_bucket_breakdown"])
            self.assertEqual(traces[0]["buckets"]["total_estimated"], 0)
            self.assertEqual(traces[0]["buckets"]["system_prompt"], 0)
            self.assertEqual(traces[0]["buckets"]["mcp_and_tools"], 0)
            self.assertEqual(traces[0]["prompt_preview"], "")
            self.assertEqual(traces[0]["latency_ms"], 1500)
            self.assertAlmostEqual(traces[0]["cache_hit_ratio"], 1800 / 2000, places=5)
            # (200 * 3.0 + 1800 * 0.30 + 80 * 15.0) / 1e6 = 0.00234
            self.assertAlmostEqual(traces[0]["estimated_cost_usd"], 0.00234, places=6)

            # Turn 2: unrecognized model -> None ("Unknown price"), hit ratio 4500 / 5000 = 0.90 <= 1.0
            self.assertEqual(traces[1]["model"], "deepseek-v4.1-flash")
            self.assertIsNone(traces[1]["estimated_cost_usd"])
            self.assertAlmostEqual(traces[1]["cache_hit_ratio"], 4500 / 5000, places=5)
            self.assertLessEqual(summary_data["summary"]["cache_hit_ratio"], 1.0)
            self.assertEqual(summary_data["summary"]["stripped_header_count"], 0)

            html_en = render_inspector_html(summary_data, live_poll=False, lang="en")
            html_zh = render_inspector_html(summary_data, live_poll=False, lang="zh")
            self.assertIn("No 5-bucket breakdown (local session logs only record aggregate tokens)", html_en)
            self.assertIn("没有五桶拆分数据（本地会话记录不含原始请求体）", html_zh)

    def test_claude_jsonl_deduplicates_streaming_blocks_and_preserves_cache_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            proj_dir = home / ".claude/projects/my-repo"
            proj_dir.mkdir(parents=True)
            jf = proj_dir / "session_abc.jsonl"

            secret_prompt = "Deploy key sk-ant-api03-" + ("SecretClaude99" * 3)
            lines = [
                json.dumps({"type": "user", "message": {"role": "user", "content": secret_prompt}}),
                # 3 streaming blocks of the SAME assistant turn (msg_01, req_01)
                json.dumps(
                    {
                        "requestId": "req_01",
                        "message": {
                            "id": "msg_01",
                            "role": "assistant",
                            "model": "claude-opus-4-1",
                            "usage": {
                                "input_tokens": 10,
                                "cache_read_input_tokens": 4000,
                                "cache_creation_input_tokens": 990,
                                "output_tokens": 25,
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "requestId": "req_01",
                        "message": {
                            "id": "msg_01",
                            "role": "assistant",
                            "model": "claude-opus-4-1",
                            "usage": {
                                "input_tokens": 10,
                                "cache_read_input_tokens": 4000,
                                "cache_creation_input_tokens": 990,
                                "output_tokens": 80,
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "requestId": "req_01",
                        "message": {
                            "id": "msg_01",
                            "role": "assistant",
                            "model": "claude-opus-4-1",
                            "usage": {
                                "input_tokens": 10,
                                "cache_read_input_tokens": 4000,
                                "cache_creation_input_tokens": 990,
                                "output_tokens": 120,
                            },
                        },
                    }
                ),
            ]
            jf.write_text("\n".join(lines) + "\n", encoding="utf-8")

            db_path = home / "claude_import.db"
            store = TraceStore(db_path)
            imported = import_local_desktop_sessions(store, home=home, max_turns=20)
            data = store.build_summary()
            store.close()

            # Must deduplicate 3 streaming blocks into 1 turn!
            self.assertEqual(imported, 1)
            tr = data["traces"][0]
            self.assertFalse(tr["has_bucket_breakdown"])
            self.assertEqual(tr["buckets"]["total_estimated"], 0)
            self.assertEqual(
                tr["usage"],
                {
                    "input_tokens": 10,
                    "cache_read_tokens": 4000,
                    "cache_write_tokens": 990,
                    "output_tokens": 120,
                },
            )
            self.assertAlmostEqual(tr["cache_hit_ratio"], 4000 / 5000, places=5)
            # Opus 4.1: (10*15 + 4000*1.5 + 990*18.75 + 120*75) / 1e6 = (150 + 6000 + 18562.5 + 9000) / 1e6 = 0.0337125 -> 0.033712
            self.assertAlmostEqual(tr["estimated_cost_usd"], 0.033712, places=5)
            self.assertEqual(tr["prompt_preview"], "")

            conn = sqlite3.connect(db_path)
            dump = "\n".join(conn.iterdump())
            conn.close()
            self.assertNotIn("SecretClaude99", dump)
            self.assertNotIn("sk-ant", dump)


if __name__ == "__main__":
    unittest.main()
