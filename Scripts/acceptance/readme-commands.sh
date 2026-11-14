#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export PYTHONDONTWRITEBYTECODE=1
export BROWSER=true

resolve_python() {
  local cand
  for cand in \
    "${AGENT_XRAY_PYTHON:-}" \
    "${ROOT_DIR}/.venv/bin/python" \
    python3.14 python3.13 python3.12 python3.11 python3.10 python3 \
    /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.10 /opt/homebrew/bin/python3; do
    [[ -z "$cand" ]] && continue
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        command -v "$cand"
        return 0
      fi
    fi
  done
  echo "Error: Python >= 3.10 is required." >&2
  exit 1
}

PYTHON="$(resolve_python)"
export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xray-readme-cmds.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_DIR/bin"
if [[ -x "${ROOT_DIR}/.venv/bin/agent-xray" ]]; then
  ln -sf "${ROOT_DIR}/.venv/bin/agent-xray" "$TMP_DIR/bin/agent-xray"
else
  cat > "$TMP_DIR/bin/agent-xray" <<EOF
#!/usr/bin/env bash
exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${ROOT_DIR}/src" "${PYTHON}" -m agent_xray.cli "\$@"
EOF
  chmod +x "$TMP_DIR/bin/agent-xray"
fi

echo "=== agent-xray README.md & README.zh-CN.md Extracted Command Verification ==="
echo "Isolated temp dir: <mktemp>/xray-readme-cmds (cleaned on exit)"

"$PYTHON" - "$ROOT_DIR" "$TMP_DIR" "$PYTHON" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

root_dir = pathlib.Path(sys.argv[1])
tmp_dir = pathlib.Path(sys.argv[2])
python_bin = sys.argv[3]
xray_bin = str(tmp_dir / "bin" / "agent-xray")


def extract_bash_blocks(md_path: pathlib.Path) -> list[list[str]]:
    text = md_path.read_text(encoding="utf-8")
    raw_blocks = re.findall(r"```(?:bash|sh)\n(.*?)```", text, flags=re.DOTALL)
    parsed: list[list[str]] = []
    for blk in raw_blocks:
        cmds: list[str] = []
        for raw_line in blk.splitlines():
            line = raw_line.strip().lstrip(">").strip()
            if not line or line.startswith("#"):
                continue
            cmds.append(line)
        if cmds:
            parsed.append(cmds)
    return parsed


en_blocks = extract_bash_blocks(root_dir / "README.md")
zh_blocks = extract_bash_blocks(root_dir / "README.zh-CN.md")

print(f"Extracted bash blocks: README.md={len(en_blocks)} blocks ({sum(len(b) for b in en_blocks)} commands), "
      f"README.zh-CN.md={len(zh_blocks)} blocks ({sum(len(b) for b in zh_blocks)} commands)")

assert len(en_blocks) == len(zh_blocks) == 6, (len(en_blocks), len(zh_blocks))
assert [len(b) for b in en_blocks] == [len(b) for b in zh_blocks], (
    [len(b) for b in en_blocks],
    [len(b) for b in zh_blocks],
)


class FakeLLM(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        payload = json.loads(raw.decode("utf-8"))
        if "responses" in self.path or "chat/completions" in self.path:
            resp = {
                "id": "chatcmpl_readme",
                "model": payload.get("model", "gpt-4o"),
                "usage": {
                    "prompt_tokens": 1200,
                    "completion_tokens": 120,
                    "prompt_tokens_details": {"cached_tokens": 900},
                },
            }
        else:
            resp = {
                "id": "msg_readme",
                "model": payload.get("model", "claude-sonnet-4-5"),
                "usage": {
                    "input_tokens": 300,
                    "cache_read_input_tokens": 2700,
                    "cache_creation_input_tokens": 0,
                    "output_tokens": 110,
                },
            }
        out = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


upstream_srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLM)
upstream_port = upstream_srv.server_address[1]
upstream_thread = threading.Thread(target=upstream_srv.serve_forever, daemon=True)
upstream_thread.start()

# Create two local mock agent scripts to stand in for `<your-agent-command>` / `<你的智能体命令>`:
# 1) mock_agent_normal.py -> sends normal turn WITH query-string secret (verifies metadata recorded + query stripped)
# 2) mock_agent_blocked.py -> sends turn WITH secret in query, model, and body (verifies HTTP 400 + sanitized record)
mock_normal = tmp_dir / "mock_agent_normal.py"
mock_normal.write_text(
    """import json, os, urllib.request
base = os.environ["ANTHROPIC_BASE_URL"]
payload = {
    "model": "claude-sonnet-4-5",
    "system": "You are a coding assistant.\\n<user_rules>Follow AGENTS.md</user_rules>",
    "tools": [
        {"name": "mcp__scholar__search_papers", "description": "Search papers", "input_schema": {"type": "object"}},
        {"name": "Bash", "description": "Run shell command", "input_schema": {"type": "object"}},
    ],
    "messages": [{"role": "user", "content": "Summarize repository test layout"}],
}
req = urllib.request.Request(
    f"{base}/v1/messages?key=sk-ant-api03-ReadmeNormalQuerySecret111111111111",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "x-api-key": "sk-ant-api03-MockAgentSessionKey123456789012",
        "x-stainless-os": "MacOS",
        "User-Agent": "mock-agent/1.0 (Darwin arm64)",
    },
)
with urllib.request.urlopen(req, timeout=5) as resp:
    assert resp.status == 200
""",
    encoding="utf-8",
)

mock_blocked = tmp_dir / "mock_agent_blocked.py"
mock_blocked.write_text(
    """import json, os, urllib.error, urllib.request
base = os.environ["ANTHROPIC_BASE_URL"]
payload = {
    "model": "claude-sk-ant-api03-ReadmeBlockedModelSecret222222222222",
    "messages": [{"role": "user", "content": "leak sk-ant-api03-ReadmeBlockedBodySecret333333333333"}],
}
req = urllib.request.Request(
    f"{base}/v1/messages?key=sk-ant-api03-ReadmeBlockedQuerySecret444444444444",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
)
try:
    urllib.request.urlopen(req, timeout=5)
    raise AssertionError("Expected HTTP 400 from --block-secrets")
except urllib.error.HTTPError as exc:
    assert exc.code == 400, exc.code
""",
    encoding="utf-8",
)


def seed_home_sessions(home_dir: pathlib.Path) -> None:
    schema_sql = (root_dir / "tests" / "fixtures" / "opencode_schema.sql").read_text(encoding="utf-8")
    oc_dir = home_dir / ".local" / "share" / "opencode"
    oc_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(oc_dir / "opencode.db"))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(schema_sql)
    conn.execute(
        "INSERT INTO project (id, worktree, sandboxes, time_created, time_updated) VALUES (?, ?, ?, ?, ?)",
        ("proj_r", "/workspace/readme", "[]", 1762000000000, 1762000000000),
    )
    conn.execute(
        """
        INSERT INTO session_v2 (
            id, project_id, slug, directory, title, version,
            cost, tokens_input, tokens_output, tokens_reasoning,
            tokens_cache_read, tokens_cache_write, time_created, time_updated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("ses_r1", "proj_r", "readme-slug", "/workspace/readme", "README Session", "2.3.0",
         0.0, 0, 0, 0, 0, 0, 1762000000000, 1762000020000),
    )
    for seq_no, (mid, ts, in_t, out_t, cr_t, cw_t) in enumerate(
        (
            ("msg_r1", 1762000010000, 400, 80, 1600, 0),
            ("msg_r2", 1762000020000, 200, 60, 1800, 0),
        ),
        start=1,
    ):
        msg_data = {
            "model": {"id": "claude-sonnet-4-5", "providerID": "anthropic"},
            "tokens": {"input": in_t, "output": out_t, "reasoning": 0, "cache": {"read": cr_t, "write": cw_t}},
            "time": {"created": ts, "completed": ts + 300},
        }
        conn.execute(
            "INSERT INTO session_message VALUES (?, 'ses_r1', 'assistant', ?, ?, ?, ?)",
            (mid, seq_no, ts, ts + 300, json.dumps(msg_data)),
        )
    conn.commit()
    conn.close()

    cl_dir = home_dir / ".claude" / "projects" / "readme-proj"
    cl_dir.mkdir(parents=True, exist_ok=True)
    cl_turn = {
        "type": "assistant",
        "timestamp": "2026-11-12T08:00:00Z",
        "requestId": "req_r_cl",
        "message": {
            "id": "msg_r_cl",
            "role": "assistant",
            "model": "claude-sonnet-4-5",
            "usage": {"input_tokens": 100, "cache_read_input_tokens": 900, "cache_creation_input_tokens": 0, "output_tokens": 50},
        },
    }
    (cl_dir / "readme.jsonl").write_text(json.dumps(cl_turn) + "\n", encoding="utf-8")


def pick_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def assert_db_x15_normal_and_blocked(normal_db: pathlib.Path, blocked_db: pathlib.Path, label: str) -> None:
    # Check normal DB
    conn_n = sqlite3.connect(str(normal_db))
    row_n = conn_n.execute(
        "SELECT provider, model, path, status_code, blocked, buckets_json, headers_json, secrets_json, prompt_preview FROM traces"
    ).fetchone()
    dump_n = "\n".join(conn_n.iterdump())
    conn_n.close()
    assert row_n is not None, f"{label}: normal DB has no trace row"
    assert row_n[2] == "/v1/messages", f"{label}: query string not stripped in normal path: {row_n[2]}"
    assert row_n[3] == 200 and row_n[4] == 0, row_n
    assert row_n[8] == "", f"{label}: prompt_preview should be empty by default: {row_n[8]!r}"
    assert json.loads(row_n[5])["total_estimated"] > 0
    for forbidden in ("sk-ant-", "ReadmeNormalQuerySecret", "MockAgentSessionKey", "Summarize repository test layout"):
        assert forbidden not in dump_n, f"{label}: leaked {forbidden!r} in normal DB dump"

    # Check blocked DB
    conn_b = sqlite3.connect(str(blocked_db))
    row_b = conn_b.execute(
        "SELECT provider, model, path, status_code, blocked, buckets_json, headers_json, secrets_json, prompt_preview FROM traces"
    ).fetchone()
    dump_b = "\n".join(conn_b.iterdump())
    conn_b.close()
    assert row_b is not None, f"{label}: blocked DB has no trace row"
    assert row_b[1] == "claude-[REDACTED]", f"{label}: model secret not redacted on blocked turn: {row_b[1]!r}"
    assert row_b[2] == "/v1/messages", f"{label}: query string not stripped on blocked turn: {row_b[2]!r}"
    assert row_b[3] == 400 and row_b[4] == 1, row_b
    assert row_b[8] == "", row_b[8]
    assert json.loads(row_b[5])["total_estimated"] == 0
    sec_list = json.loads(row_b[7])
    assert len(sec_list) >= 1 and all(set(x.keys()) == {"rule", "field"} for x in sec_list), sec_list
    for forbidden in (
        "sk-ant-",
        "ReadmeBlockedModelSecret",
        "ReadmeBlockedBodySecret",
        "ReadmeBlockedQuerySecret",
    ):
        assert forbidden not in dump_b, f"{label}: leaked {forbidden!r} in blocked DB dump"
    print(f"  [X15 DB ASSERT PASS] {label}: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets={sec_list}, dump_hits=0)")


from agent_xray.store import TraceStore

try:
    for doc_name, blocks in (("README.md", en_blocks), ("README.zh-CN.md", zh_blocks)):
        tag = "en" if doc_name == "README.md" else "zh"
        print(f"\n--- Verifying {doc_name} ---")
        doc_home = tmp_dir / f"home_{tag}"
        doc_tmp = tmp_dir / f"tmp_{tag}"
        doc_home.mkdir(parents=True, exist_ok=True)
        doc_tmp.mkdir(parents=True, exist_ok=True)
        seed_home_sessions(doc_home)

        # Seed default ~/.agent-xray/traces.db via product TraceStore so Block 1 `purge-db` exercises real deletion
        seed_store = TraceStore(doc_home / ".agent-xray" / "traces.db")
        seed_store.record_turn(
            provider="anthropic",
            model="claude-sonnet-4-5",
            path="/anthropic/v1/messages",
            status_code=200,
            latency_ms=10,
            blocked=False,
            buckets={"system_prompt": 10, "total_estimated": 10},
            tool_namespaces=[],
            usage={"input_tokens": 10, "output_tokens": 2},
            header_audit=[],
            secret_findings=[],
        )
        seed_store.close()
        assert (doc_home / ".agent-xray" / "traces.db").exists()

        base_env = os.environ.copy()
        base_env["HOME"] = str(doc_home)
        base_env["PATH"] = f"{tmp_dir / 'bin'}:{base_env.get('PATH', '')}"
        base_env["PYTHONPATH"] = str(root_dir / "src")
        base_env["PYTHONDONTWRITEBYTECODE"] = "1"
        base_env["BROWSER"] = "true"
        base_env["AGENT_XRAY_ANTHROPIC_UPSTREAM"] = f"http://127.0.0.1:{upstream_port}"
        base_env["AGENT_XRAY_OPENAI_UPSTREAM"] = f"http://127.0.0.1:{upstream_port}"

        for b_idx, cmds in enumerate(blocks, start=1):
            for c_idx, cmd_str in enumerate(cmds, start=1):
                # Block 2: git clone / cd / venv / pip install
                if cmd_str.startswith(("git clone ", "cd ", "python3 -m venv ", ".venv/bin/pip install ")):
                    print(
                        f"[SKIP] {doc_name} block#{b_idx}.{c_idx}: `{cmd_str}` -> "
                        "Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly"
                    )
                    continue

                tokens = shlex.split(cmd_str)
                assert tokens[0] == "agent-xray", f"Unexpected command binary in {doc_name}: {cmd_str}"
                tokens[0] = xray_bin
                tokens = [
                    t.replace("/tmp/", f"{doc_tmp}/")
                    .replace("docs/demo-inspector.html", str(doc_tmp / "demo-inspector.html"))
                    for t in tokens
                ]

                # Placeholder `<your-agent-command>` / `<你的智能体命令>`: run BOTH normal & blocked turns
                if tokens[-1] in ("<your-agent-command>", "<你的智能体命令>"):
                    placeholder = tokens[-1]
                    print(
                        f"[SUBSTITUTE] {doc_name} block#{b_idx}.{c_idx}: replacing `{placeholder}` in `{cmd_str}` "
                        "with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)"
                    )
                    prefix = tokens[:-1]
                    db_norm = doc_tmp / f"run_b{b_idx}_c{c_idx}_norm.db"
                    db_blk = doc_tmp / f"run_b{b_idx}_c{c_idx}_blk.db"

                    def with_db(args_list: list[str], db_target: pathlib.Path) -> list[str]:
                        out_args = list(args_list)
                        sep_pos = out_args.index("--")
                        if "--db" in out_args[:sep_pos]:
                            di = out_args.index("--db")
                            out_args[di + 1] = str(db_target)
                        else:
                            out_args = out_args[:sep_pos] + ["--db", str(db_target)] + out_args[sep_pos:]
                        return out_args

                    cmd_norm = with_db(prefix, db_norm) + [python_bin, str(mock_normal)]
                    res_n = subprocess.run(cmd_norm, env=base_env, capture_output=True, text=True, timeout=20)
                    assert res_n.returncode == 0, (cmd_norm, res_n.stdout, res_n.stderr)

                    cmd_blk = with_db(prefix, db_blk) + [python_bin, str(mock_blocked)]
                    res_b = subprocess.run(cmd_blk, env=base_env, capture_output=True, text=True, timeout=20)
                    assert res_b.returncode == 0, (cmd_blk, res_b.stdout, res_b.stderr)

                    assert_db_x15_normal_and_blocked(db_norm, db_blk, f"{doc_name}#b{b_idx}.{c_idx}")
                    continue

                # Long-running `serve` command: launch in background on free port, test normal + blocked turns, SIGINT, assert DB
                if "serve" in tokens:
                    port_idx = tokens.index("--port")
                    free_port = pick_free_port()
                    tokens[port_idx + 1] = str(free_port)
                    db_idx = tokens.index("--db")
                    serve_db = pathlib.Path(tokens[db_idx + 1])

                    proc = subprocess.Popen(tokens, env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        for _ in range(60):
                            try:
                                with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/_xray/api/summary", timeout=1) as r:
                                    if r.status == 200:
                                        break
                            except Exception:
                                time.sleep(0.05)

                        # 1) Normal request with query secret
                        req_ok = urllib.request.Request(
                            f"http://127.0.0.1:{free_port}/anthropic/v1/messages?key=sk-ant-api03-ServeQueryNormal555555555555",
                            data=json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "ping"}]}).encode("utf-8"),
                            headers={"Content-Type": "application/json", "x-stainless-arch": "arm64"},
                        )
                        with urllib.request.urlopen(req_ok, timeout=5) as r_ok:
                            assert r_ok.status == 200

                        # 2) Secret-bearing request -> must return HTTP 400
                        req_bad = urllib.request.Request(
                            f"http://127.0.0.1:{free_port}/anthropic/v1/messages?key=sk-ant-api03-ServeQueryBlocked666666666666",
                            data=json.dumps({
                                "model": "claude-sk-ant-api03-ServeModelBlocked777777777777",
                                "messages": [{"role": "user", "content": "sk-ant-api03-ServeBodyBlocked888888888888"}],
                            }).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                        )
                        try:
                            urllib.request.urlopen(req_bad, timeout=5)
                            raise AssertionError("Expected HTTP 400 from serve --block-secrets")
                        except urllib.error.HTTPError as he:
                            assert he.code == 400
                    finally:
                        proc.send_signal(signal.SIGINT)
                        out_s, err_s = proc.communicate(timeout=10)

                    assert proc.returncode == 0, (proc.returncode, out_s, err_s)
                    conn_s = sqlite3.connect(str(serve_db))
                    rows_s = conn_s.execute("SELECT model, path, status_code, blocked, prompt_preview FROM traces ORDER BY id").fetchall()
                    dump_s = "\n".join(conn_s.iterdump())
                    conn_s.close()
                    assert len(rows_s) == 2, rows_s
                    assert rows_s[0] == ("claude-sonnet-4-5", "/anthropic/v1/messages", 200, 0, ""), rows_s[0]
                    assert rows_s[1] == ("claude-[REDACTED]", "/anthropic/v1/messages", 400, 1, ""), rows_s[1]
                    for forbidden in ("sk-ant-", "ServeQueryNormal", "ServeQueryBlocked", "ServeModelBlocked", "ServeBodyBlocked"):
                        assert forbidden not in dump_s, f"Leaked {forbidden!r} in serve DB dump"
                    print(f"[EXEC PASS] {doc_name} block#{b_idx}.{c_idx}: `{cmd_str}` -> exit=0, rows=2 (200 & 400), dump_secret_hits=0")
                    continue

                # Direct synchronous CLI commands (`--version`, `export-demo`, `desktop`, `report`, `purge-db`)
                res = subprocess.run(tokens, env=base_env, capture_output=True, text=True, timeout=20)
                combined = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
                assert res.returncode == 0, f"Command failed ({doc_name}): {cmd_str}\n{combined}"

                if "--version" in tokens:
                    assert "agent-xray 0.2.0" in combined, combined
                elif "export-demo" in tokens:
                    demo_file = doc_tmp / "demo-inspector.html"
                    html_txt = demo_file.read_text(encoding="utf-8")
                    assert "[DEMO" in html_txt and ("MCP Tool Share" in html_txt or "MCP 工具定义占比" in html_txt)
                elif "desktop" in tokens:
                    assert ("Imported 3 recent" in combined or "已导入 3 条" in combined), combined
                    assert ("No data" in combined or "没有数据" in combined), combined
                elif "report" in tokens:
                    if "--lang" in tokens and tokens[tokens.index("--lang") + 1] == "zh":
                        assert "会话摘要：共 3 轮" in combined and "（未核对）" in combined, combined
                    else:
                        assert "Session summary: 3 turns" in combined and "(unverified)" in combined, combined
                elif "purge-db" in tokens:
                    if "--db" in tokens:
                        purged_target = pathlib.Path(tokens[tokens.index("--db") + 1])
                    else:
                        purged_target = doc_home / ".agent-xray" / "traces.db"
                    assert not purged_target.exists(), f"purge-db did not remove {purged_target}"
                    assert ("Purged SQLite trace database" in combined or "已清理 SQLite 追踪数据库" in combined), combined

                first_line = combined.splitlines()[0] if combined else "(ok)"
                print(f"[EXEC PASS] {doc_name} block#{b_idx}.{c_idx}: `{cmd_str}` -> exit=0 | {first_line}")
finally:
    upstream_srv.shutdown()
    upstream_srv.server_close()

print("\n=== ALL EXTRACTED README.md & README.zh-CN.md COMMANDS & DB ASSERTIONS PASSED ===")
PY
