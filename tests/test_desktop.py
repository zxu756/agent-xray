from __future__ import annotations

import json
import re
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
        ratio_re = re.compile(r"\b0\.(?:12|28|34|14|09)\b")
        for py_file in src_dir.rglob("*.py"):
            if py_file.name == "ui_html.py":
                continue
            content = py_file.read_text(encoding="utf-8")
            m = ratio_re.search(content)
            self.assertIsNone(
                m,
                f"Found forbidden fixed bucket ratio {m.group(0) if m else ''} in {py_file}",
            )

        # W4: UI stylesheet must retain its genuine CSS oklch color values (0.12 / 0.28)
        ui_css = (src_dir / "agent_xray" / "ui_html.py").read_text(encoding="utf-8")
        self.assertIn("oklch(0.515 0.092 188 / 0.12)", ui_css)
        self.assertIn("oklch(0.665 0.175 32 / 0.28)", ui_css)

    def test_opencode_per_turn_import_ignores_session_v2_cumulative_totals(self) -> None:
        schema_path = Path(__file__).resolve().parent / "fixtures" / "opencode_schema.sql"
        schema_sql = schema_path.read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            oc_dir = home / ".local/share/opencode"
            oc_dir.mkdir(parents=True)
            oc_db = oc_dir / "opencode.db"

            conn = sqlite3.connect(oc_db)
            conn.executescript(schema_sql)
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(
                """
                INSERT INTO project (id, worktree, time_created, time_updated, sandboxes)
                VALUES ('proj_1', '/workspace/demo', 1794603600000, 1794603600000, '[]')
                """
            )
            # Huge cumulative session row in authentic 37-column session_v2 table
            # that previously caused $717 cost & 2091% cache hit rate!
            conn.execute(
                """
                INSERT INTO session_v2 (
                    id, project_id, slug, directory, title, version,
                    cost, tokens_input, tokens_output, tokens_reasoning,
                    tokens_cache_read, tokens_cache_write, model,
                    time_created, time_updated
                ) VALUES (
                    'ses_cum_1', 'proj_1', 'demo-slug', '/workspace/demo',
                    'Secret title sk-ant-api03-12345678901234567890', '2.3.0',
                    717.42, 99449290, 3104714, 0,
                    2149521664, 0, '{"id":"deepseek-v4.1-flash","providerID":"opencode-go"}',
                    1794603650000, 1794603750000
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
                "INSERT INTO session_message VALUES ('m0', 'ses_cum_1', 'user', 0, 1794603690000, 1794603690000, '{}')"
            )
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
