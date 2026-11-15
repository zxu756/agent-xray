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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xray-m1-accept.XXXXXX")"
PIDS=()
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

export HOME="$TMP_DIR/isolated-home"
mkdir -p "$HOME" "$TMP_DIR/bin"

if [[ -x "${ROOT_DIR}/.venv/bin/agent-xray" ]]; then
  XRAY="${ROOT_DIR}/.venv/bin/agent-xray"
else
  XRAY="$TMP_DIR/bin/agent-xray"
  cat > "$XRAY" <<EOF
#!/usr/bin/env bash
exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${ROOT_DIR}/src" "${PYTHON}" -m agent_xray.cli "\$@"
EOF
  chmod +x "$XRAY"
fi

echo "=== agent-xray M1 Acceptance Suite ==="
echo "Isolated temp dir: <mktemp>/xray-m1-accept (cleaned on exit)"

# ---------------------------------------------------------------------------
# Rows 1, 2, 3, 4, 5, 6 & Part 2 Additions (Independent Reference Oracles)
# ---------------------------------------------------------------------------
"$PYTHON" - "$ROOT_DIR" "$TMP_DIR" "$PYTHON" "$XRAY" <<'PY'
from __future__ import annotations

import gzip
import http.client
import json
import math
import os
import pathlib
import re
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

root_dir = pathlib.Path(sys.argv[1])
tmp_dir = pathlib.Path(sys.argv[2])
python_bin = sys.argv[3]
xray_bin = sys.argv[4]


def pick_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_xray(port: int, timeout_s: float = 8.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/_xray/api/summary", timeout=0.5) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.04)
    raise RuntimeError(f"Timed out waiting for agent-xray on 127.0.0.1:{port}")


def drain_http_request(conn: socket.socket) -> tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        ch = conn.recv(4096)
        if not ch:
            break
        buf += ch
    if b"\r\n\r\n" not in buf:
        return buf, b""
    head, rest = buf.split(b"\r\n\r\n", 1)
    m = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
    if m:
        want = int(m.group(1))
        while len(rest) < want:
            ch = conn.recv(4096)
            if not ch:
                break
            rest += ch
        return head, rest[:want]
    return head, rest


# ===========================================================================
# ROW 1 & ROW 2: Raw TCP Socket SSE Latency (< 50 ms across 20x 100B events
#                every 200 ms) + Mid-Stream Disconnect (Upstream & Client)
# ===========================================================================
print("\n--- [Row 1 & Row 2] True read1 SSE Latency (20x 100B @ 200ms) & Clean Mid-Stream Disconnect ---")

sse_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sse_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sse_srv.bind(("127.0.0.1", 0))
sse_srv.listen(8)
sse_up_port = sse_srv.getsockname()[1]

sent_ts: list[float] = []
client_drop_detected = threading.Event()


def raw_sse_upstream() -> None:
    # Connection 1 (Row 1): 20 SSE events of exactly 100 bytes each, spaced 200 ms apart
    c1, _ = sse_srv.accept()
    c1.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    drain_http_request(c1)
    c1.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    for idx in range(20):
        # Construct exact 100-byte SSE event payload
        prefix = f'event: delta\ndata: {{"seq":{idx:02d},"pad":"'
        suffix = '"}\n\n'
        pad_len = 100 - len(prefix) - len(suffix)
        ev = (prefix + ("a" * pad_len) + suffix).encode("ascii")
        assert len(ev) == 100, len(ev)
        chunk = f"{len(ev):x}\r\n".encode("ascii") + ev + b"\r\n"
        sent_ts.append(time.perf_counter())
        c1.sendall(chunk)
        if idx < 19:
            time.sleep(0.200)
    tail_ev = (
        b'event: message_delta\ndata: {"type":"message_delta","usage":{"input_tokens":140,"output_tokens":20}}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )
    c1.sendall(f"{len(tail_ev):x}\r\n".encode("ascii") + tail_ev + b"\r\n0\r\n\r\n")
    c1.close()

    # Connection 2 (Row 2a): Upstream disconnects after 10 chunked SSE events (no 0\r\n\r\n terminator)
    c2, _ = sse_srv.accept()
    c2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    drain_http_request(c2)
    c2.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    for idx in range(10):
        ev2 = f'event: delta\ndata: {{"seq":{idx:02d}}}\n\n'.encode("ascii")
        c2.sendall(f"{len(ev2):x}\r\n".encode("ascii") + ev2 + b"\r\n")
        time.sleep(0.010)
    c2.close()

    # Connection 3 (Row 2b): Client disconnects mid-stream -> upstream send fails cleanly
    c3, _ = sse_srv.accept()
    c3.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    drain_http_request(c3)
    c3.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
    try:
        for idx in range(60):
            c3.sendall((f'data: {{"tick":{idx},"pad":"' + ("z" * 512) + '"}\n\n').encode("ascii"))
            time.sleep(0.020)
    except OSError:
        client_drop_detected.set()
    finally:
        c3.close()
        client_drop_detected.set()

    # Connection 4 (Health probe after disconnects)
    c4, _ = sse_srv.accept()
    drain_http_request(c4)
    ok_body = b'{"id":"msg_ok","model":"claude-sonnet-4-5","usage":{"input_tokens":10,"output_tokens":5}}'
    c4.sendall(
        f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(ok_body)}\r\n\r\n".encode("ascii")
        + ok_body
    )
    c4.close()


threading.Thread(target=raw_sse_upstream, daemon=True).start()

r1_port = pick_free_port()
r1_db = tmp_dir / "row1_2.db"
r1_env = os.environ.copy()
r1_env["HOME"] = str(tmp_dir / "isolated-home")
r1_proc = subprocess.Popen(
    [
        xray_bin,
        "--lang",
        "en",
        "serve",
        "--port",
        str(r1_port),
        "--db",
        str(r1_db),
        "--upstream",
        f"http://127.0.0.1:{sse_up_port}",
        "--auth-token",
        "m1-r1-tok",
    ],
    env=r1_env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
try:
    wait_for_xray(r1_port)
    req_body = json.dumps(
        {"model": "claude-sonnet-4-5", "stream": True, "messages": [{"role": "user", "content": "stream test"}]}
    ).encode("utf-8")
    raw_req = (
        f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{r1_port}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(req_body)}\r\n\r\n".encode("ascii")
        + req_body
    )

    # Row 1 client timing measurement
    cli1 = socket.create_connection(("127.0.0.1", r1_port), timeout=15)
    cli1.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    cli1.sendall(raw_req)
    buf1 = b""
    while b"\r\n\r\n" not in buf1:
        buf1 += cli1.recv(4096)
    _, body_buf1 = buf1.split(b"\r\n\r\n", 1)
    recv_ts: dict[int, float] = {}
    t_first = time.perf_counter()
    for m in re.finditer(rb'"seq":(\d+)\b.*?\n\n', body_buf1):
        recv_ts.setdefault(int(m.group(1)), t_first)
    while len(recv_ts) < 20:
        ch = cli1.recv(4096)
        if not ch:
            break
        t_now = time.perf_counter()
        body_buf1 += ch
        for m in re.finditer(rb'"seq":(\d+)\b.*?\n\n', body_buf1):
            recv_ts.setdefault(int(m.group(1)), t_now)
    while cli1.recv(4096):
        pass
    cli1.close()

    assert len(recv_ts) == 20, f"Expected 20 SSE events, got {len(recv_ts)}"
    deltas_ms = [(recv_ts[i] - sent_ts[i]) * 1000.0 for i in range(20)]
    min_d = min(deltas_ms)
    med_d = statistics.median(deltas_ms)
    max_d = max(deltas_ms)
    assert max_d < 50.0, f"Row 1 FAILED: max per-event latency {max_d:.2f} ms >= 50.0 ms"
    print(
        f"ROW 1 [PASS]: 20x 100B SSE events @ 200ms -> "
        f"min_delta_ms={min_d:.2f}, median_delta_ms={med_d:.2f}, max_delta_ms={max_d:.2f} (< 50.0 ms)"
    )

    # Row 2a: Upstream mid-stream disconnect after 10 events
    cli2 = socket.create_connection(("127.0.0.1", r1_port), timeout=10)
    cli2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    cli2.sendall(raw_req)
    raw2 = b""
    while True:
        ch = cli2.recv(4096)
        if not ch:
            break
        raw2 += ch
    cli2.close()
    head2, body2 = raw2.split(b"\r\n\r\n", 1)
    assert b"200 OK" in head2.splitlines()[0], head2
    ev_matches = re.findall(rb'data: \{"seq":(\d+)\}\n\n', body2)
    assert [int(x) for x in ev_matches] == list(range(10)), ev_matches
    assert b"HTTP/1.1" not in body2, f"Injected HTTP status line into SSE body: {body2!r}"
    assert b"502" not in body2, f"Injected 502 error into SSE body: {body2!r}"

    # Row 2b: Client mid-stream disconnect + subsequent server health check
    cli3 = socket.create_connection(("127.0.0.1", r1_port), timeout=10)
    cli3.sendall(raw_req)
    _ = cli3.recv(512)
    cli3.close()
    assert client_drop_detected.wait(timeout=5.0), "Upstream did not observe client disconnect cleanup"

    with urllib.request.urlopen(
        urllib.request.Request(
            f"http://127.0.0.1:{r1_port}/anthropic/v1/messages",
            data=req_body,
            headers={"Content-Type": "application/json"},
        ),
        timeout=5,
    ) as r4:
        assert r4.status == 200

    summary_r1 = json.loads(
        urllib.request.urlopen(f"http://127.0.0.1:{r1_port}/_xray/api/summary", timeout=5).read().decode("utf-8")
    )
    # traces in build_summary() are ordered chronologically (turn_number 1..N)
    conn1_trace = summary_r1["traces"][0]
    conn2_trace = summary_r1["traces"][1]
    assert conn1_trace["ttft_ms"] is not None and conn1_trace["ttft_ms"] >= 0.0, conn1_trace
    assert conn1_trace["output_tokens"] == 20 and conn1_trace["input_tokens"] == 140, conn1_trace
    assert conn1_trace["stream_truncated"] is False, conn1_trace
    assert conn2_trace["stream_truncated"] is True, conn2_trace
    assert summary_r1["summary"]["truncated_count"] >= 1, summary_r1["summary"]
    print(
        f"ROW 2 [PASS]: Upstream mid-stream disconnect -> 10 complete events, clean EOF, "
        f"stream_truncated=True (conn1=False), 'HTTP/1.1' in body=0, '502' in body=0; "
        f"client disconnect survived cleanly (recorded ttft_ms={conn1_trace['ttft_ms']:.2f})"
    )
finally:
    r1_proc.send_signal(signal.SIGINT)
    r1_proc.communicate(timeout=10)
    sse_srv.close()


# ===========================================================================
# ROW 3: >2 MB Streaming SSE Usage + Gzip SSE/JSON + Header/Duplicate/Chunked
#        Fidelity + Programmatic `start_background_proxy` Metering API
# ===========================================================================
print("\n--- [Row 3] >2 MB SSE Usage, Gzip Request/Response, Header Fidelity & Programmatic API ---")

from agent_xray.proxy import start_background_proxy

captured_up_requests: list[dict[str, object]] = []


class FidelityAndLargeStreamUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        raw_header_pairs = list(self.headers.items())
        cl = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(cl) if cl else b""
        captured_up_requests.append(
            {
                "path": self.path,
                "headers": raw_header_pairs,
                "body": body,
            }
        )
        mode = self.headers.get("X-Test-Case") or ""
        if mode == "2mb-anthropic-sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(
                b'event: message_start\n'
                b'data: {"type":"message_start","message":{"usage":{"input_tokens":512,"cache_read_input_tokens":2048,"cache_creation_input_tokens":128}}}\n\n'
            )
            delta_block = (
                b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"'
                + (b"m" * 1024)
                + b'"}}\n\n'
            )
            for _ in range(2150):
                self.wfile.write(delta_block)
            self.wfile.write(
                b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":9876}}\n\n'
                b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
            )
            self.wfile.flush()
            return

        if mode == "2mb-openai-responses-sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            delta_block = b'event: response.output_text.delta\ndata: {"delta":"' + (b"r" * 1024) + b'"}\n\n'
            for _ in range(2100):
                self.wfile.write(delta_block)
            done_evt = {
                "type": "response.completed",
                "response": {
                    "usage": {
                        "input_tokens": 1500,
                        "output_tokens": 4321,
                        "input_tokens_details": {"cached_tokens": 1100},
                    }
                },
            }
            self.wfile.write(f"event: response.completed\ndata: {json.dumps(done_evt)}\n\n".encode("utf-8"))
            self.wfile.flush()
            return

        if mode == "gzip-sse-openai-chat":
            sse_plain = (
                b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
                b'data: {"choices":[],"usage":{"prompt_tokens":900,"completion_tokens":77,"prompt_tokens_details":{"cached_tokens":600}}}\n\n'
                b"data: [DONE]\n\n"
            )
            gz_out = gzip.compress(sse_plain)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(gz_out)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(gz_out)
            return

        resp_obj = {
            "id": "msg_echo",
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 55,
                "prompt_tokens_details": {"cached_tokens": 300},
            },
        }
        raw_out = json.dumps(resp_obj).encode("utf-8")
        if "gzip" in (self.headers.get("Accept-Encoding") or "") and mode == "gzip-json":
            gz_json = gzip.compress(raw_out)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(gz_json)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(gz_json)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw_out)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw_out)


fid_srv = ThreadingHTTPServer(("127.0.0.1", 0), FidelityAndLargeStreamUpstream)
fid_port = fid_srv.server_address[1]
threading.Thread(target=fid_srv.serve_forever, daemon=True).start()

try:
    with start_background_proxy(
        upstream=f"http://127.0.0.1:{fid_port}",
        strip_telemetry=True,
        block_secrets=True,
    ) as px:
        # 3a: 2.3 MB Anthropic SSE stream (client omits Accept-Encoding -> proxy must NOT inject Accept-Encoding: identity)
        ant_req = json.dumps(
            {"model": "claude-sonnet-4-5", "stream": True, "messages": [{"role": "user", "content": "big stream"}]}
        ).encode("utf-8")
        hc = http.client.HTTPConnection("127.0.0.1", px.port, timeout=20)
        hc.putrequest("POST", "/anthropic/v1/messages", skip_accept_encoding=True)
        hc.putheader("Content-Type", "application/json")
        hc.putheader("X-Test-Case", "2mb-anthropic-sse")
        hc.putheader("Content-Length", str(len(ant_req)))
        hc.endheaders(ant_req)
        r_big = hc.getresponse()
        r_big_servers = r_big.msg.get_all("Server") or []
        r_big_dates = r_big.msg.get_all("Date") or []
        big_bytes = r_big.read()
        hc.close()
        assert r_big.status == 200 and len(big_bytes) > 2_200_000, (r_big.status, len(big_bytes))
        assert len(r_big_servers) == 1, f"Duplicate Server headers: {r_big_servers}"
        assert len(r_big_dates) == 1, f"Duplicate Date headers: {r_big_dates}"

        # 3b: 2.2 MB OpenAI Responses SSE stream
        resp_req = json.dumps(
            {"model": "gpt-4.1", "stream": True, "input": [{"role": "user", "content": "big responses stream"}]}
        ).encode("utf-8")
        hc2 = http.client.HTTPConnection("127.0.0.1", px.port, timeout=20)
        hc2.request(
            "POST",
            "/openai/v1/responses",
            body=resp_req,
            headers={"Content-Type": "application/json", "X-Test-Case": "2mb-openai-responses-sse"},
        )
        r_big2 = hc2.getresponse()
        big2_bytes = r_big2.read()
        hc2.close()
        assert r_big2.status == 200 and len(big2_bytes) > 2_100_000, (r_big2.status, len(big2_bytes))

        # 3c: Gzipped request body + duplicate headers + openai-organization/project + gzipped SSE response
        chat_plain = json.dumps(
            {
                "model": "gpt-4o",
                "stream": True,
                "messages": [{"role": "user", "content": "Compressed request body " + ("q" * 300)}],
            }
        ).encode("utf-8")
        chat_gz = gzip.compress(chat_plain)
        hc3 = http.client.HTTPConnection("127.0.0.1", px.port, timeout=10)
        hc3.putrequest("POST", "/openai/v1/chat/completions", skip_accept_encoding=True)
        hc3.putheader("Content-Type", "application/json")
        hc3.putheader("Content-Encoding", "gzip")
        hc3.putheader("Accept-Encoding", "gzip, deflate")
        hc3.putheader("openai-organization", "org-keep-billing-123")
        hc3.putheader("openai-project", "proj-keep-billing-456")
        hc3.putheader("anthropic-beta", "prompt-caching-2024-07-31")
        hc3.putheader("anthropic-beta", "token-counting-2024-11-01")
        hc3.putheader("X-Multi", "alpha")
        hc3.putheader("X-Multi", "beta")
        hc3.putheader("x-stainless-os", "MacOS")
        hc3.putheader("X-Test-Case", "gzip-sse-openai-chat")
        hc3.putheader("Content-Length", str(len(chat_gz)))
        hc3.endheaders(chat_gz)
        r_gz = hc3.getresponse()
        gz_resp_bytes = r_gz.read()
        hc3.close()
        assert r_gz.status == 200
        assert r_gz.getheader("Content-Encoding") == "gzip"
        assert b"[DONE]" in gzip.decompress(gz_resp_bytes)

        # 3d: Transfer-Encoding: chunked request + gzip JSON response
        chunk_plain = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "chunked req"}]}).encode("utf-8")
        sock_c = socket.create_connection(("127.0.0.1", px.port), timeout=10)
        p1, p2 = chunk_plain[:24], chunk_plain[24:]
        raw_chunked = (
            f"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
            f"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
            f"Accept-Encoding: gzip\r\nX-Test-Case: gzip-json\r\n\r\n"
            f"{len(p1):x}\r\n".encode("ascii")
            + p1
            + b"\r\n"
            + f"{len(p2):x}\r\n".encode("ascii")
            + p2
            + b"\r\n0\r\n\r\n"
        )
        sock_c.sendall(raw_chunked)
        raw_c_resp = b""
        while True:
            bch = sock_c.recv(4096)
            if not bch:
                break
            raw_c_resp += bch
        sock_c.close()
        assert b"200 OK" in raw_c_resp.splitlines()[0]

        for _ in range(50):
            if len(px.get_traces(limit=20)) >= 4:
                break
            time.sleep(0.03)

        traces_chron = px.get_traces(limit=20)
        assert len(traces_chron) == 4, len(traces_chron)
        # Verify 2.3 MB Anthropic SSE usage
        assert traces_chron[0]["input_tokens"] == 512
        assert traces_chron[0]["cached_input_tokens"] == 2048
        assert traces_chron[0]["cache_creation_input_tokens"] == 128
        assert traces_chron[0]["output_tokens"] == 9876
        assert traces_chron[0]["ttft_ms"] is not None
        # Verify 2.2 MB OpenAI Responses SSE usage (1500 total - 1100 cached = 400 uncached)
        assert traces_chron[1]["input_tokens"] == 400
        assert traces_chron[1]["cached_input_tokens"] == 1100
        assert traces_chron[1]["output_tokens"] == 4321
        # Verify gzip request classified + gzip SSE response usage (900 - 600 = 300 uncached, 77 output)
        assert traces_chron[2]["buckets"]["total_estimated"] > 50
        assert traces_chron[2]["input_tokens"] == 300
        assert traces_chron[2]["cached_input_tokens"] == 600
        assert traces_chron[2]["output_tokens"] == 77
        # Verify chunked request + gzip JSON response usage (500 - 300 = 200 uncached, 55 output)
        assert traces_chron[3]["input_tokens"] == 200
        assert traces_chron[3]["cached_input_tokens"] == 300
        assert traces_chron[3]["output_tokens"] == 55

        totals = px.get_totals()
        assert totals["turn_count"] == 4 and len(totals["turns"]) == 4
        assert totals["output_tokens"] == 9876 + 4321 + 77 + 55
        assert totals["truncated_count"] == 0
        assert all(tr["stream_truncated"] is False for tr in traces_chron), traces_chron

    # Check upstream received NO forced Accept-Encoding on request #1, and headers & bodies verbatim on request #3 & #4
    up1_hdrs = [(k.lower(), v) for k, v in captured_up_requests[0]["headers"]]  # type: ignore[index]
    assert not any(k == "accept-encoding" for k, _ in up1_hdrs), f"Forced Accept-Encoding leaked: {up1_hdrs}"
    up3 = captured_up_requests[2]
    up3_hdrs = [(k.lower(), v) for k, v in up3["headers"]]  # type: ignore[index]
    assert ("openai-organization", "org-keep-billing-123") in up3_hdrs, up3_hdrs
    assert ("openai-project", "proj-keep-billing-456") in up3_hdrs, up3_hdrs
    assert ("accept-encoding", "gzip, deflate") in up3_hdrs, up3_hdrs
    assert [v for k, v in up3_hdrs if k == "anthropic-beta"] == [
        "prompt-caching-2024-07-31",
        "token-counting-2024-11-01",
    ], up3_hdrs
    assert [v for k, v in up3_hdrs if k == "x-multi"] == ["alpha", "beta"], up3_hdrs
    assert not any(k.startswith("x-stainless-") for k, _ in up3_hdrs), up3_hdrs
    assert up3["body"] == chat_gz, "Gzipped request body was altered in transit!"
    assert captured_up_requests[3]["body"] == chunk_plain, "Chunked request body mismatch!"

    print(
        "ROW 3 [PASS]: 2.3MB Anthropic SSE output_tokens=9876, 2.2MB Responses SSE output_tokens=4321, "
        "gzip req/resp intact, openai-organization/project & duplicate headers preserved, programmatic API totals verified"
    )
finally:
    fid_srv.shutdown()
    fid_srv.server_close()


# ===========================================================================
# ROW 4: `run` Chains Existing ANTHROPIC_BASE_URL / OPENAI_BASE_URL + --upstream
# ===========================================================================
print("\n--- [Row 4] `run` Upstream Gateway Chaining & `--upstream` CLI Flag ---")

chained_paths: list[tuple[str, str]] = []


def make_gateway_handler(tag: str) -> type[BaseHTTPRequestHandler]:
    class _GW(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            cl = int(self.headers.get("Content-Length") or "0")
            _ = self.rfile.read(cl) if cl else b""
            chained_paths.append((tag, self.path))
            out = json.dumps(
                {"id": "gw_1", "model": "claude-sonnet-4-5", "usage": {"input_tokens": 50, "output_tokens": 12}}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    return _GW


gw_ant = ThreadingHTTPServer(("127.0.0.1", 0), make_gateway_handler("ant_env"))
gw_oai = ThreadingHTTPServer(("127.0.0.1", 0), make_gateway_handler("oai_env"))
gw_flag = ThreadingHTTPServer(("127.0.0.1", 0), make_gateway_handler("flag_up"))
for s in (gw_ant, gw_oai, gw_flag):
    threading.Thread(target=s.serve_forever, daemon=True).start()

try:
    child_py = tmp_dir / "row4_child.py"
    child_py.write_text(
        """import json, os, sys, urllib.request
ant_u = os.environ["ANTHROPIC_BASE_URL"]
oai_u = os.environ["OPENAI_BASE_URL"]
for url, body in [
    (f"{ant_u}/v1/messages", {"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}),
    (f"{oai_u}/chat/completions", {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
]:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200
sys.exit(7)
""",
        encoding="utf-8",
    )

    env_chain = os.environ.copy()
    env_chain["HOME"] = str(tmp_dir / "isolated-home")
    env_chain.pop("AGENT_XRAY_ANTHROPIC_UPSTREAM", None)
    env_chain.pop("AGENT_XRAY_OPENAI_UPSTREAM", None)
    env_chain["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{gw_ant.server_address[1]}"
    env_chain["OPENAI_BASE_URL"] = f"http://127.0.0.1:{gw_oai.server_address[1]}/v1"

    r4_db = tmp_dir / "row4_chain.db"
    res_r4 = subprocess.run(
        [xray_bin, "--lang", "en", "run", "--db", str(r4_db), "--", python_bin, str(child_py)],
        env=env_chain,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert res_r4.returncode == 7, (res_r4.returncode, res_r4.stdout, res_r4.stderr)
    assert ("ant_env", "/v1/messages") in chained_paths, chained_paths
    assert ("oai_env", "/v1/chat/completions") in chained_paths, chained_paths

    # Also test explicit --upstream override
    r4_flag_db = tmp_dir / "row4_flag.db"
    res_flag = subprocess.run(
        [
            xray_bin,
            "--lang",
            "en",
            "run",
            "--upstream",
            f"http://127.0.0.1:{gw_flag.server_address[1]}",
            "--db",
            str(r4_flag_db),
            "--",
            python_bin,
            str(child_py),
        ],
        env=env_chain,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert res_flag.returncode == 7
    assert ("flag_up", "/v1/messages") in chained_paths, chained_paths
    assert ("flag_up", "/v1/chat/completions") in chained_paths, chained_paths

    # Invalid --upstream must exit 2 before creating DB
    bad_db = tmp_dir / "never_created_bad_up.db"
    res_bad = subprocess.run(
        [xray_bin, "serve", "--upstream", "ftp://invalid.example", "--db", str(bad_db)],
        env=env_chain,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert res_bad.returncode == 2 and not bad_db.exists(), (res_bad.returncode, bad_db.exists())
    print(
        "ROW 4 [PASS]: Parent ANTHROPIC_BASE_URL & OPENAI_BASE_URL(/v1) chained without /v1/v1 duplication; "
        "exit code 7 preserved; `--upstream` override & invalid-scheme guard (exit 2) verified"
    )
finally:
    for s in (gw_ant, gw_oai, gw_flag):
        s.shutdown()
        s.server_close()


# ===========================================================================
# ROW 5: 3-Format Block-Level 5-Bucket Classification & OpenAI tool_calls /
#        function_call / reasoning vs Independent Hand-Computed Oracle
# ===========================================================================
print("\n--- [Row 5] 3-Format Block-Level 5-Bucket Classification & OpenAI Tool Calls / Reasoning ---")


def ref_tok_prose(ascii_s: str) -> int:
    # Independent reference calculation for pure ASCII text: max(1, round(len / 3.75))
    return max(1, int(round(len(ascii_s) / 3.75)))


def ref_tok_code_str(ascii_s: str) -> int:
    return max(1, int(round(len(ascii_s) / 3.25)))


def ref_tok_schema(obj: object) -> int:
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return max(1, int(round(len(s) / 3.25)))


sys_plain = "You are Claude Code. Check CLAUDE.md or AGENTS.md only when instructed. " + ("S" * 528)
rule_tag = "<system-reminder>" + ("R" * 342) + "</system-reminder>"
user_question = "Explain the parser retry loop in detail. " + ("U" * 559)
mixed_block = rule_tag + user_question
tool_out_txt = "Exit 0: 42 files checked. " + ("T" * 474)
call_args_txt = '{"path":"src/parser.py","pad":"' + ("A" * 340) + '"}'
reasoning_txt = "Compare retry backoff bounds first. " + ("K" * 264)
mcp_tool = {"name": "mcp__scholar__search_papers", "description": "Search papers", "input_schema": {"type": "object"}}
builtin_tool = {"name": "Bash", "description": "Execute command", "input_schema": {"type": "object"}}
ant_tool_use_block = {"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {"cmd": "ls"}}

# Independent expected numbers for Anthropic Messages:
exp_ant_sys = ref_tok_prose(sys_plain)
exp_ant_rules = ref_tok_prose(rule_tag)
exp_ant_tools = ref_tok_schema(mcp_tool) + ref_tok_schema(builtin_tool)
exp_ant_results = ref_tok_code_str(tool_out_txt)
exp_ant_conv = ref_tok_prose(user_question) + ref_tok_schema(ant_tool_use_block)

ant_payload = {
    "model": "claude-sonnet-4-5",
    "system": [{"type": "text", "text": sys_plain}],
    "tools": [mcp_tool, builtin_tool],
    "messages": [
        {"role": "user", "content": [{"type": "text", "text": mixed_block}]},
        {"role": "assistant", "content": [ant_tool_use_block]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu_1", "content": tool_out_txt}]},
    ],
}

oai_tool = {"type": "function", "function": {"name": "mcp__scholar__search_papers", "parameters": {"type": "object"}}}
chat_tc_obj = {"id": "call_1", "type": "function", "function": {"name": "Bash", "arguments": call_args_txt}}
exp_chat_sys = ref_tok_prose(sys_plain)
exp_chat_rules = ref_tok_prose(rule_tag)
exp_chat_tools = ref_tok_schema(oai_tool)
exp_chat_results = ref_tok_code_str(tool_out_txt)
exp_chat_conv = (
    ref_tok_prose(user_question)
    + ref_tok_prose(reasoning_txt)
    + ref_tok_prose(json.dumps(chat_tc_obj["function"], separators=(",", ":")))
)

chat_payload = {
    "model": "gpt-4o",
    "tools": [oai_tool],
    "messages": [
        {"role": "system", "content": sys_plain},
        {"role": "user", "content": mixed_block},
        {"role": "assistant", "content": None, "reasoning_content": reasoning_txt, "tool_calls": [chat_tc_obj]},
        {"role": "tool", "tool_call_id": "call_1", "content": tool_out_txt},
    ],
}

resp_fc_item = {"type": "function_call", "call_id": "fc_1", "name": "Bash", "arguments": call_args_txt}
resp_reason_item = {"type": "reasoning", "summary": [{"type": "summary_text", "text": reasoning_txt}]}
resp_Payload = {
    "model": "o4-mini",
    "instructions": sys_plain,
    "tools": [oai_tool],
    "input": [
        {"role": "user", "content": [{"type": "input_text", "text": mixed_block}]},
        resp_reason_item,
        resp_fc_item,
        {"type": "function_call_output", "call_id": "fc_1", "output": tool_out_txt},
    ],
}

r5_srv = ThreadingHTTPServer(
    ("127.0.0.1", 0),
    make_gateway_handler("row5"),
)
threading.Thread(target=r5_srv.serve_forever, daemon=True).start()
try:
    with start_background_proxy(upstream=f"http://127.0.0.1:{r5_srv.server_address[1]}") as px5:
        for path5, body5 in (
            ("/anthropic/v1/messages", ant_payload),
            ("/openai/v1/chat/completions", chat_payload),
            ("/openai/v1/responses", resp_Payload),
        ):
            req5 = urllib.request.Request(
                f"{px5.base_url}{path5}",
                data=json.dumps(body5).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req5, timeout=5) as r5:
                assert r5.status == 200

        for _ in range(40):
            if len(px5.get_traces(limit=10)) >= 3:
                break
            time.sleep(0.03)
        t_list = px5.get_traces(limit=10)
        b_ant, b_chat, b_resp = t_list[0]["buckets"], t_list[1]["buckets"], t_list[2]["buckets"]

        for b in (b_ant, b_chat, b_resp):
            five_sum = (
                b["system_prompt"]
                + b["workspace_rules"]
                + b["mcp_and_tools"]
                + b["tool_results"]
                + b["conversation"]
            )
            assert five_sum == b["total_estimated"], (five_sum, b)

        # Verify Anthropic exact oracle match
        assert b_ant["system_prompt"] == exp_ant_sys, (b_ant["system_prompt"], exp_ant_sys)
        assert b_ant["workspace_rules"] == exp_ant_rules, (b_ant["workspace_rules"], exp_ant_rules)
        assert b_ant["mcp_and_tools"] == exp_ant_tools, (b_ant["mcp_and_tools"], exp_ant_tools)
        assert b_ant["tool_results"] == exp_ant_results, (b_ant["tool_results"], exp_ant_results)
        assert b_ant["conversation"] == exp_ant_conv, (b_ant["conversation"], exp_ant_conv)

        # Verify OpenAI Chat exact system, rules, tools, results & tool_calls+reasoning inclusion
        assert b_chat["system_prompt"] == exp_chat_sys, (b_chat["system_prompt"], exp_chat_sys)
        assert b_chat["workspace_rules"] == exp_chat_rules, (b_chat["workspace_rules"], exp_chat_rules)
        assert b_chat["mcp_and_tools"] == exp_chat_tools, (b_chat["mcp_and_tools"], exp_chat_tools)
        assert b_chat["tool_results"] == exp_chat_results, (b_chat["tool_results"], exp_chat_results)
        assert b_chat["conversation"] >= ref_tok_prose(user_question) + ref_tok_prose(call_args_txt) + ref_tok_prose(reasoning_txt), b_chat

        # Verify OpenAI Responses exact system, rules, tools, results & function_call+reasoning inclusion
        assert b_resp["system_prompt"] == exp_chat_sys, (b_resp["system_prompt"], exp_chat_sys)
        assert b_resp["workspace_rules"] == exp_chat_rules, (b_resp["workspace_rules"], exp_chat_rules)
        assert b_resp["mcp_and_tools"] == exp_chat_tools, (b_resp["mcp_and_tools"], exp_chat_tools)
        assert b_resp["tool_results"] == exp_chat_results, (b_resp["tool_results"], exp_chat_results)
        assert b_resp["conversation"] >= ref_tok_prose(user_question) + ref_tok_prose(call_args_txt) + ref_tok_prose(reasoning_txt), b_resp

        # XR3 check: developer prose mentioning AGENTS.md / CLAUDE.md stays in system_prompt
        from agent_xray.classifier import classify_request_payload
        xr3_cls = classify_request_payload(
            "/openai/v1/chat/completions",
            {
                "model": "gpt-4o",
                "messages": [{"role": "developer", "content": "Follow repo style; see AGENTS.md if needed."}],
            },
        )
        assert xr3_cls.buckets.system_prompt > 0 and xr3_cls.buckets.workspace_rules == 0, xr3_cls.buckets.to_dict()

        print(
            f"ROW 5 [PASS]: 3 formats verified vs hand oracle (incl. XR3 developer prose -> system_prompt) -> "
            f"Anthropic={b_ant}, OpenAI_Chat={b_chat}, OpenAI_Responses={b_resp}"
        )
finally:
    r5_srv.shutdown()
    r5_srv.server_close()


# ===========================================================================
# ROW 6: Comprehensive `--block-secrets` Across Endpoints, Gzip, Query,
#        Headers, Unicode Escapes, `_` Prefix + False-Positive Corpus
# ===========================================================================
print("\n--- [Row 6] Comprehensive `--block-secrets` & False-Positive Corpus ---")

r6_upstream_bytes = 0
r6_upstream_hits = 0


class CountingUpstream(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        global r6_upstream_bytes, r6_upstream_hits
        cl = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(cl) if cl else b""
        r6_upstream_hits += 1
        r6_upstream_bytes += len(self.path.encode("utf-8")) + len(body)
        out = b'{"id":"ok_r6","usage":{"input_tokens":10,"output_tokens":2}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


r6_srv = ThreadingHTTPServer(("127.0.0.1", 0), CountingUpstream)
threading.Thread(target=r6_srv.serve_forever, daemon=True).start()

try:
    with start_background_proxy(
        upstream=f"http://127.0.0.1:{r6_srv.server_address[1]}",
        block_secrets=True,
    ) as px6:
        live_ant = "sk-ant-api03-" + ("Z9y8X7w6V5u4" * 3)
        live_ghp = "ghp_" + ("AbCdEfGhIjKlMnOpQrStUvWxYz1234567890")
        live_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNlY3JldCJ9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        real_pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj\n"
            "MzEfYyjiWA4R4g8SecretPemMaterialRow69999999999999999999999999999\n"
            "-----END PRIVATE KEY-----"
        )
        gz_secret_body = gzip.compress(
            json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": live_ant}]}).encode("utf-8")
        )
        escaped_json_bytes = (
            b'{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"\\u0073k-ant-api03-'
            + (b"Q1w2E3r4T5y6" * 3)
            + b'"}]}'
        )

        must_block_cases: list[tuple[str, str, bytes, dict[str, str]]] = [
            (
                "count_tokens_endpoint",
                "/anthropic/v1/messages/count_tokens",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": live_ant}]}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "batches_endpoint",
                "/anthropic/v1/messages/batches",
                json.dumps({"requests": [{"params": {"messages": [{"role": "user", "content": live_ghp}]}}]}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "embeddings_endpoint",
                "/openai/v1/embeddings",
                json.dumps({"model": "text-embedding-3-small", "input": live_ant}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "responses_compact_endpoint",
                "/openai/v1/responses/compact",
                json.dumps({"model": "gpt-4.1", "input": live_ant}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "gzip_request_body",
                "/anthropic/v1/messages",
                gz_secret_body,
                {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            ),
            (
                "query_string_secret",
                f"/anthropic/v1/messages?api_key={live_ant}",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "custom_header_secret",
                "/anthropic/v1/messages",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}).encode(),
                {"Content-Type": "application/json", "X-Debug-Credential": live_ant},
            ),
            (
                "unicode_escaped_json_secret",
                "/anthropic/v1/messages",
                escaped_json_bytes,
                {"Content-Type": "application/json"},
            ),
            (
                "underscore_glued_secret_and_jwt",
                "/anthropic/v1/messages",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": f"ENV_{live_ant} {live_jwt}"}]}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "non_json_raw_body_secret",
                "/anthropic/v1/messages",
                f"not-valid-json {{ raw={live_ant}".encode("utf-8"),
                {"Content-Type": "text/plain"},
            ),
            (
                "real_multiline_pem_key",
                "/anthropic/v1/messages",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": real_pem}]}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "double_percent_encoded_url_path_secret",
                "/anthropic/sk%252Dant%252Dapi03%252DM1DOUBLEENC88888888/v1/messages",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "hi"}]}).encode(),
                {"Content-Type": "application/json"},
            ),
            (
                "uppercase_prefix_secret_8char_tail",
                "/anthropic/v1/messages",
                json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "SK-ANT-M1UP8888"}]}).encode(),
                {"Content-Type": "application/json"},
            ),
        ]

        for label6, path6, body6, hdrs6 in must_block_cases:
            req6 = urllib.request.Request(f"{px6.base_url}{path6}", data=body6, headers=hdrs6, method="POST")
            try:
                urllib.request.urlopen(req6, timeout=5)
                raise AssertionError(f"Row 6 FAILED: {label6} was NOT blocked!")
            except urllib.error.HTTPError as he:
                assert he.code == 400, f"{label6}: expected 400, got {he.code}"

        assert r6_upstream_hits == 0 and r6_upstream_bytes == 0, (
            f"Row 6 FAILED: upstream received {r6_upstream_hits} requests ({r6_upstream_bytes} bytes) on blocked cases!"
        )

        # Benign / False-Positive Guard Cases -> ALL must pass with HTTP 200
        benign_prose = (
            "SSH key type sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256@openssh.com; "
            "AWS example AKIAIOSFODNN7EXAMPLE and AKIAXXXXXXXXXXXXXXXX; "
            "placeholders ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx and sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx; "
            "prose warning about -----BEGIN PRIVATE KEY----- without key lines; "
            "commit df9c5420123456789abcdef0123456789abcdef0 and UUID baa0b1f4-80be-48e7-a2b9-91982f2f5961."
        )
        req_benign = urllib.request.Request(
            f"{px6.base_url}/anthropic/v1/messages",
            data=json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": benign_prose}]}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": live_ant,
                "Authorization": "Bearer sk-proj-LegitCallerAuthHeaderToken1234567890",
            },
            method="POST",
        )
        with urllib.request.urlopen(req_benign, timeout=5) as r_ok6:
            assert r_ok6.status == 200
        assert r6_upstream_hits == 1

        print(
            f"ROW 6 [PASS]: 13/13 secret vectors (count_tokens, batches, embeddings, responses/compact, gzip, query, "
            f"custom header, \\u0073 escape, _-glued, non-JSON, PEM, double-encoded URL path, uppercase 8-char tail) "
            f"returned HTTP 400 with upstream_bytes=0; benign auth headers, sk-ssh-ed25519, placeholders, PEM prose, SHA & UUID returned HTTP 200"
        )
finally:
    r6_srv.shutdown()
    r6_srv.server_close()


# ===========================================================================
# PART 2 ADDITIONS (`07-tools-m0-review.md` Part 2):
#   P2.1 All-Column Dynamic PRAGMA table_info SQLite Secret Audit (15 cols)
#   P2.2 Claude Sonnet 4 <=200k vs >200k Tiered Pricing Verification
#   P2.3 Explicit `(Estimated)` / `（估算）` Labels in CLI, JSON, and HTML
#   P2.4 Non-UI Source Scan for Fixed Ratios (0.12 / 0.28 / 0.34)
# ===========================================================================
print("\n--- [Part 2 Additions] All-Column SQLite Audit, Sonnet >200k Pricing, & Estimated Labels ---")

from agent_xray.store import TraceStore, compute_turn_cost_usd

# P2.1: Dynamic all-table, all-column SQLite check with block_secrets OFF and ON
p2_srv = ThreadingHTTPServer(("127.0.0.1", 0), make_gateway_handler("p2"))
threading.Thread(target=p2_srv.serve_forever, daemon=True).start()
try:
    for blk_flag in (False, True):
        p2_db = tmp_dir / f"p2_x14_{'on' if blk_flag else 'off'}.db"
        with start_background_proxy(
            db_path=p2_db,
            upstream=f"http://127.0.0.1:{p2_srv.server_address[1]}",
            block_secrets=blk_flag,
            store_previews=True,
        ) as px_p2:
            inj_body = json.dumps(
                {
                    "model": "claude-sk-ant-api03-M1COLMODEL11111111111111111111",
                    "tools": [
                        {
                            "name": "mcp__sk-ant-api03-M1COLNS22222222222222222222__run",
                            "description": "d",
                            "input_schema": {"type": "object"},
                        }
                    ],
                    "messages": [{"role": "user", "content": "msg sk-ant-api03-M1COLMSG33333333333333333333"}],
                }
            ).encode("utf-8")
            req_p2 = urllib.request.Request(
                f"{px_p2.base_url}/anthropic/v1/sk%252Dant%252Dapi03%252DM1COLPATH44444444444444444444/messages?k=sk-ant-api03-M1COLQ55555555555555555555",
                data=inj_body,
                headers={
                    "Content-Type": "application/json",
                    "X-sk-ant-api03-M1COLHN66666666666666666666": "sk-ant-api03-M1COLHV77777777777777777777",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req_p2, timeout=5) as rp2:
                    assert not blk_flag and rp2.status == 200
            except urllib.error.HTTPError as he:
                assert blk_flag and he.code == 400

        conn_p2 = sqlite3.connect(str(p2_db))
        tables = [r[0] for r in conn_p2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        all_cols = [r[1] for r in conn_p2.execute("PRAGMA table_info(traces)").fetchall()]
        assert "ttft_ms" in all_cols and "stream_truncated" in all_cols and len(all_cols) == 16, all_cols
        dump_p2 = "\n".join(conn_p2.iterdump())
        conn_p2.close()
        for needle in ("sk-ant-", "%252D", "M1COLMODEL", "M1COLNS", "M1COLMSG", "M1COLPATH", "M1COLQ", "M1COLHN", "M1COLHV"):
            assert needle not in dump_p2, f"Leaked {needle} in SQLite dump (block={blk_flag})"

    print(
        f"PART2-X14 [PASS]: Dynamic PRAGMA table_info verified {len(all_cols)} columns ({','.join(all_cols)}) "
        f"across tables={tables}; sqlite3 .dump secret matches=0 incl. double-encoded %252D path (block OFF & ON)"
    )
finally:
    p2_srv.shutdown()
    p2_srv.server_close()

# P2.2: Claude Sonnet 4 / 4.5 <=200k vs >200k tiered pricing & Sonnet 4.6 flat pricing
# <= 200k: 50k*$3 + 100k*$0.30 + 0*$3.75 + 1k*$15 = $0.15 + $0.03 + $0 + $0.015 = $0.1950
cost_under = compute_turn_cost_usd(
    model="claude-sonnet-4-5",
    status_code=200,
    blocked=False,
    input_tokens=50_000,
    cache_read_tokens=100_000,
    cache_write_tokens=0,
    output_tokens=1_000,
)
# > 200k (250k prompt tokens) on Sonnet 4.5: 50k*$6 + 160k*$0.60 + 40k*$7.50 + 2k*$22.50 = $0.7410
cost_over = compute_turn_cost_usd(
    model="claude-sonnet-4-5",
    status_code=200,
    blocked=False,
    input_tokens=50_000,
    cache_read_tokens=160_000,
    cache_write_tokens=40_000,
    output_tokens=2_000,
)
# > 200k (250k prompt tokens) on Sonnet 4.6: flat rate $0.15 + $0.048 + $0.15 + $0.03 = $0.3780
cost_46_flat = compute_turn_cost_usd(
    model="claude-sonnet-4-6",
    status_code=200,
    blocked=False,
    input_tokens=50_000,
    cache_read_tokens=160_000,
    cache_write_tokens=40_000,
    output_tokens=2_000,
)
cost_unlisted = compute_turn_cost_usd(
    model="claude-sonnet-4-7",
    status_code=200,
    blocked=False,
    input_tokens=10_000,
    cache_read_tokens=0,
    cache_write_tokens=0,
    output_tokens=500,
)
assert cost_under is not None and math.isclose(cost_under, 0.1950, rel_tol=0, abs_tol=1e-9), cost_under
assert cost_over is not None and math.isclose(cost_over, 0.7410, rel_tol=0, abs_tol=1e-9), cost_over
assert cost_46_flat is not None and math.isclose(cost_46_flat, 0.3780, rel_tol=0, abs_tol=1e-9), cost_46_flat
assert cost_unlisted is None, cost_unlisted
print(
    f"PART2-PRICING [PASS]: claude-sonnet-4-5 <=200k=${cost_under:.4f} vs >200k=${cost_over:.4f}; "
    f"claude-sonnet-4-6 >200k flat=${cost_46_flat:.4f}; unlisted claude-sonnet-4-7=None (Unknown price)"
)

# P2.3: Explicit Estimated / 估算 labels across CLI (EN/ZH), JSON, and HTML (EN/ZH)
lbl_db = tmp_dir / "p2_labels.db"
lbl_store = TraceStore(lbl_db)
lbl_store.record_turn(
    provider="anthropic",
    model="claude-sonnet-4-5",
    path="/v1/messages",
    status_code=200,
    latency_ms=42,
    ttft_ms=8.5,
    blocked=False,
    buckets={"system_prompt": 100, "workspace_rules": 50, "mcp_and_tools": 200, "tool_results": 50, "conversation": 100, "total_estimated": 500},
    tool_namespaces=[{"namespace": "mcp:scholar", "tool_count": 2, "estimated_tokens": 200}],
    usage={"input_tokens": 480, "cache_read_tokens": 0, "cache_write_tokens": 0, "output_tokens": 40},
    header_audit=[],
    secret_findings=[],
)
lbl_summary = lbl_store.build_summary(limit=10)
lbl_store.close()

assert lbl_summary["summary"]["buckets_are_estimated"] is True
assert lbl_summary["summary"]["bucket_unit"] == "estimated_tokens"
assert lbl_summary["traces"][0]["is_estimated"] is True
assert lbl_summary["traces"][0]["bucket_unit"] == "estimated_tokens"

res_rep_en = subprocess.run([xray_bin, "--lang", "en", "report", "--db", str(lbl_db)], capture_output=True, text=True, check=True)
res_rep_zh = subprocess.run([xray_bin, "--lang", "zh", "report", "--db", str(lbl_db)], capture_output=True, text=True, check=True)
rep_en = (res_rep_en.stdout or "") + (res_rep_en.stderr or "")
rep_zh = (res_rep_zh.stdout or "") + (res_rep_zh.stderr or "")
assert "(Estimated)" in rep_en, rep_en
assert "（估算）" in rep_zh, rep_zh

demo_en = tmp_dir / "demo_en.html"
demo_zh = tmp_dir / "demo_zh.html"
subprocess.run([xray_bin, "--lang", "en", "export-demo", "--out", str(demo_en)], check=True, capture_output=True)
subprocess.run([xray_bin, "--lang", "zh", "export-demo", "--out", str(demo_zh)], check=True, capture_output=True)
assert "(Estimated)" in demo_en.read_text(encoding="utf-8")
assert "（估算）" in demo_zh.read_text(encoding="utf-8")
print("PART2-ESTIMATED [PASS]: JSON `is_estimated=true`, CLI `(Estimated)`/`（估算）`, and HTML `(Estimated)`/`（估算）` verified")

# P2.XR5: 9-layer & 12-layer nested percent-encoding placeholder & --block-secrets HTTP 400 (with _MAX_UNQUOTE_ROUNDS == 8)
from agent_xray.privacy import _MAX_UNQUOTE_ROUNDS, UNCONVERGED_PATH_PLACEHOLDER
from agent_xray.ui_html import render_inspector_html

assert _MAX_UNQUOTE_ROUNDS == 8, f"_MAX_UNQUOTE_ROUNDS must stay 8, got {_MAX_UNQUOTE_ROUNDS}"


def _enc_layers(secret: str, depth: int, full_hex: bool = False) -> str:
    cur = "".join(f"%{ord(ch):02X}" for ch in secret) if full_hex else secret.replace("-", "%2D")
    for _ in range(depth - 1):
        cur = urllib.parse.quote(cur, safe="")
    return cur


xr5_srv = ThreadingHTTPServer(("127.0.0.1", 0), make_gateway_handler("xr5"))
threading.Thread(target=xr5_srv.serve_forever, daemon=True).start()
try:
    s_xr5_a = "sk-test-FAKE1234567890abcdef"
    s_xr5_b = "sk-ant-FAKE00001234567890abcdef"
    xr5_body = json.dumps({"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "ok"}]}).encode("utf-8")
    for blk_xr5 in (False, True):
        db_xr5 = tmp_dir / f"p2_xr5_{'on' if blk_xr5 else 'off'}.db"
        with start_background_proxy(
            db_path=db_xr5,
            upstream=f"http://127.0.0.1:{xr5_srv.server_address[1]}",
            block_secrets=blk_xr5,
            store_previews=True,
        ) as px_xr5:
            for d_xr5 in (9, 12):
                for sec_val, fh in [(s_xr5_a, False), (s_xr5_b, True)]:
                    enc_seg = _enc_layers(sec_val, d_xr5, full_hex=fh)
                    req_xr5 = urllib.request.Request(
                        f"{px_xr5.base_url}/anthropic/{enc_seg}/v1/messages",
                        data=xr5_body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        with urllib.request.urlopen(req_xr5, timeout=5) as r_xr5:
                            assert not blk_xr5 and r_xr5.status == 200
                    except urllib.error.HTTPError as he_xr5:
                        assert blk_xr5 and he_xr5.code == 400
        c_xr5 = sqlite3.connect(str(db_xr5))
        paths_xr5 = [r[0] for r in c_xr5.execute("SELECT path FROM traces").fetchall()]
        dump_xr5 = "\n".join(c_xr5.iterdump())
        c_xr5.close()
        assert paths_xr5 == [UNCONVERGED_PATH_PLACEHOLDER] * 4, paths_xr5
        raw_xr5 = b"".join(
            p.read_bytes() for p in [db_xr5, pathlib.Path(f"{db_xr5}-wal"), pathlib.Path(f"{db_xr5}-shm")] if p.exists()
        )
        for bad_tok in ("FAKE1234567890abcdef", "FAKE00001234567890abcdef", "%2525"):
            assert bad_tok not in dump_xr5 and bad_tok.encode("utf-8") not in raw_xr5
    print(
        f"PART2-XR5 [PASS]: _MAX_UNQUOTE_ROUNDS=8 preserved; 9-layer & 12-layer encoded fake secrets stored as "
        f"{UNCONVERGED_PATH_PLACEHOLDER} (0 bytes leaked in SQLite/WAL) and rejected with HTTP 400 under --block-secrets"
    )
finally:
    xr5_srv.shutdown()
    xr5_srv.server_close()

# P2.XR6: Truncated stream explicitly surfaced in CLI `report` (EN/ZH) and Web UI HTML (EN/ZH)
xr6_db = tmp_dir / "p2_xr6_trunc.db"
xr6_store = TraceStore(xr6_db)
xr6_store.record_turn(
    provider="anthropic",
    model="claude-sonnet-4-5",
    path="/anthropic/v1/messages",
    status_code=200,
    latency_ms=95,
    ttft_ms=11.2,
    blocked=False,
    stream_truncated=True,
    buckets={"system_prompt": 100, "workspace_rules": 0, "mcp_and_tools": 0, "tool_results": 0, "conversation": 50, "total_estimated": 150},
    tool_namespaces=[],
    usage={"input_tokens": 120, "cache_read_tokens": 0, "cache_write_tokens": 0, "output_tokens": 0},
    header_audit=[],
    secret_findings=[],
)
xr6_data = xr6_store.build_summary(limit=10)
xr6_store.close()

r_xr6_en = subprocess.run([xray_bin, "--lang", "en", "report", "--db", str(xr6_db)], capture_output=True, text=True, check=True)
r_xr6_zh = subprocess.run([xray_bin, "--lang", "zh", "report", "--db", str(xr6_db)], capture_output=True, text=True, check=True)
out_xr6_en = (r_xr6_en.stdout or "") + (r_xr6_en.stderr or "")
out_xr6_zh = (r_xr6_zh.stdout or "") + (r_xr6_zh.stderr or "")
assert "[TRUNCATED]" in out_xr6_en and "usage & cost incomplete" in out_xr6_en and "Truncated Streams: 1" in out_xr6_en, out_xr6_en
assert "[流已截断]" in out_xr6_zh and "用量与费用不完整" in out_xr6_zh and "截断流轮次：1" in out_xr6_zh, out_xr6_zh
html_xr6_en = render_inspector_html(xr6_data, lang="en")
html_xr6_zh = render_inspector_html(xr6_data, lang="zh")
assert "[TRUNCATED]" in html_xr6_en and "usage &amp; cost incomplete" in html_xr6_en, "Missing EN HTML truncation warning"
assert "[流已截断]" in html_xr6_zh and "用量与费用不完整" in html_xr6_zh, "Missing ZH HTML truncation warning"
print("PART2-XR6 [PASS]: CLI `report` (EN/ZH) and Web UI HTML (EN/ZH) flag `[TRUNCATED]`/`[流已截断]` and `usage & cost incomplete`/`用量与费用不完整`")
PY

# P2.4: Non-UI Source Scan for Fixed Ratios (W4)
echo ""
echo "--- [Part 2 W4] Collection & Estimation Source Scan for Fixed Ratios (0.12 / 0.28 / 0.34) ---"
if grep -rnE '\b0\.(12|28|34)\b' src/ --include='*.py' --exclude='ui_html.py'; then
  echo "FAIL: Found fixed-ratio multipliers in non-UI Python source!" >&2
  exit 1
fi
echo "PART2-W4 [PASS]: grep -rnE '\\b0\\.(12|28|34)\\b' src/ --exclude='ui_html.py' -> 0 matches"

# ---------------------------------------------------------------------------
# Row 7: Real Paid API Tokenizer Error Calibration (Gated by XRAY_REAL_API=1)
#        + Offline Pipeline Wiring Self-Check (`离线管线自检`, NOT tokenizer error)
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 7] Live External API Tokenizer Calibration Check ---"
ROW7_SELF_OUT="$("$PYTHON" "${ROOT_DIR}/Scripts/acceptance/calibrate_tokenizer.py" --offline-self-check)"
echo "$ROW7_SELF_OUT"
if [[ "$ROW7_SELF_OUT" != *"离线管线自检"* || "$ROW7_SELF_OUT" != *"offline_pipeline_self_check"* ]]; then
  echo "FAIL: Row 7 offline self-check missing explicit offline_pipeline_self_check label!" >&2
  exit 1
fi
if [[ "$ROW7_SELF_OUT" == *"max_err"* || "$ROW7_SELF_OUT" == *"mean_error"* || "$ROW7_SELF_OUT" == *"median_error"* ]]; then
  echo "FAIL: Row 7 offline self-check must NOT report synthetic ratios as tokenizer error!" >&2
  exit 1
fi

M1_ROW7_SKIPPED=0
if [[ "${XRAY_REAL_API:-0}" == "1" ]]; then
  "$PYTHON" "${ROOT_DIR}/Scripts/acceptance/calibrate_tokenizer.py"
else
  M1_ROW7_SKIPPED=1
  echo "ROW 7 [SKIPPED / 没跑]: XRAY_REAL_API!=1; live paid API calibration not executed (counted as skipped=1, NOT passed)"
fi

# ---------------------------------------------------------------------------
# Row 8: `start_background_proxy` Programmatic Interface Parity vs docs/SPEC.md
#        (All documented kwargs, 127.0.0.1-only bind, SQLite turn, port release,
#         0 lingering background threads / subprocesses)
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 8] start_background_proxy Programmatic Interface & Lifecycle Check ---"
"$PYTHON" - "${ROOT_DIR}" "${TMP_DIR}" <<'PY'
from __future__ import annotations

import http.client
import inspect
import json
import multiprocessing
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agent_xray
from agent_xray.proxy import start_background_proxy

root_dir = pathlib.Path(sys.argv[1])
tmp_dir = pathlib.Path(sys.argv[2])
spec_text = (root_dir / "docs" / "SPEC.md").read_text(encoding="utf-8")

m_sig = re.search(r"`(start_background_proxy)\(\*,\s*([^)]+)\)\s*->\s*RunningXRayProxy`", spec_text)
assert m_sig is not None, "Could not parse start_background_proxy(...) signature from docs/SPEC.md"
fn_name = m_sig.group(1)
spec_params = [
    part.strip().split("=", 1)[0].split(":", 1)[0].strip()
    for part in m_sig.group(2).split(",")
    if part.strip()
]

fn = getattr(agent_xray, fn_name)
assert fn is start_background_proxy
actual_params = list(inspect.signature(fn).parameters.keys())
assert actual_params == spec_params, (actual_params, spec_params)
assert "strip_telemetry" in actual_params, actual_params

# Verify non-127.0.0.1 bind is rejected unconditionally
for bad_host in ("0.0.0.0", "localhost", "::1"):
    try:
        fn(host=bad_host, auth_token="tok")
        raise AssertionError(f"Expected ValueError for host={bad_host!r}")
    except ValueError:
        pass


class _Row8FakeUpstream(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        _ = self.rfile.read(length) if length else b""
        resp = {
            "id": "msg_row8",
            "model": "claude-sonnet-4-6",
            "usage": {
                "input_tokens": 321,
                "cache_read_input_tokens": 654,
                "cache_creation_input_tokens": 12,
                "output_tokens": 45,
            },
        }
        out = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


r8_srv = ThreadingHTTPServer(("127.0.0.1", 0), _Row8FakeUpstream)
r8_up_port = r8_srv.server_address[1]
r8_up_thread = threading.Thread(target=r8_srv.serve_forever, daemon=True)
r8_up_thread.start()

try:
    r8_db = tmp_dir / "row8_programmatic.db"
    baseline_threads = {t.ident for t in threading.enumerate()}
    kwargs = {
        "db_path": str(r8_db),
        "host": "127.0.0.1",
        "port": 0,
        "store": None,
        "upstream": f"http://127.0.0.1:{r8_up_port}",
        "anthropic_upstream": f"http://127.0.0.1:{r8_up_port}",
        "openai_upstream": f"http://127.0.0.1:{r8_up_port}",
        "strip_telemetry": True,
        "block_secrets": True,
        "store_previews": False,
        "auth_token": "row8-secret-token-123456",
    }
    assert list(kwargs.keys()) == spec_params, (list(kwargs.keys()), spec_params)

    px = fn(**kwargs)
    bound_port = px.port
    try:
        assert px.host == "127.0.0.1"
        assert px.server.server_address[0] == "127.0.0.1"
        req_body = json.dumps(
            {"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "Row 8 programmatic check"}]}
        ).encode("utf-8")
        hc = http.client.HTTPConnection("127.0.0.1", bound_port, timeout=5)
        hc.request(
            "POST",
            "/anthropic/v1/messages",
            body=req_body,
            headers={"Content-Type": "application/json", "x-stainless-os": "MacOS"},
        )
        hr = hc.getresponse()
        _ = hr.read()
        hc.close()
        assert hr.status == 200, hr.status

        turns = px.get_turns(limit=10)
        assert len(turns) == 1, turns
        assert turns[0]["input_tokens"] == 321, turns[0]
        assert turns[0]["cached_input_tokens"] == 654, turns[0]
        assert turns[0]["cache_creation_input_tokens"] == 12, turns[0]
        assert turns[0]["output_tokens"] == 45, turns[0]
        assert turns[0]["stream_truncated"] is False, turns[0]
    finally:
        px.stop()

    # Verify SQLite file persisted exact 1 turn
    conn_r8 = sqlite3.connect(str(r8_db))
    rows_r8 = conn_r8.execute("SELECT provider, model, status_code, stream_truncated, usage_json FROM traces").fetchall()
    conn_r8.close()
    assert len(rows_r8) == 1 and rows_r8[0][:4] == ("anthropic", "claude-sonnet-4-6", 200, 0), rows_r8
    usage_r8 = json.loads(rows_r8[0][4])
    assert usage_r8["input_tokens"] == 321 and usage_r8["output_tokens"] == 45, usage_r8

    # Verify port is released and can be rebound immediately on 127.0.0.1
    rebind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        rebind.bind(("127.0.0.1", bound_port))
    finally:
        rebind.close()

    # Verify 0 leftover proxy threads and 0 child subprocesses
    after_threads = {t.ident for t in threading.enumerate()}
    lingering_threads = after_threads - baseline_threads
    assert lingering_threads == set(), f"Lingering threads after stop(): {lingering_threads}"
    assert multiprocessing.active_children() == []
    ps_proc = subprocess.Popen(["ps", "-ax", "-o", "pid=,ppid="], stdout=subprocess.PIPE, text=True)
    ps_out, _ = ps_proc.communicate(timeout=5)
    my_pid = os.getpid()
    child_pids = []
    for line in ps_out.splitlines():
        parts = line.split()
        if len(parts) == 2 and int(parts[1]) == my_pid and int(parts[0]) != ps_proc.pid:
            child_pids.append(int(parts[0]))
    assert child_pids == [], f"Unexpected child subprocesses: {child_pids}"

    # Side-by-side behavioral parity: CLI `agent-xray serve` vs programmatic `start_background_proxy`
    import signal
    import time

    par_upstream_hits: list[tuple[str, dict[str, str], bytes]] = []
    par_lock = threading.Lock()

    def _row8_parity_upstream(srv_sock: socket.socket) -> None:
        while True:
            try:
                cs, _ = srv_sock.accept()
            except OSError:
                break
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    ch = cs.recv(1024)
                    if not ch:
                        break
                    buf += ch
                if b"\r\n\r\n" not in buf:
                    cs.close()
                    continue
                head_b, rest_b = buf.split(b"\r\n\r\n", 1)
                lines = head_b.decode("iso-8859-1").split("\r\n")
                req_p = lines[0].split(" ")[1]
                hmap: dict[str, str] = {}
                cl_len = 0
                for ln in lines[1:]:
                    if ":" in ln:
                        hk, hv = ln.split(":", 1)
                        hmap[hk.strip().lower()] = hv.strip()
                        if hk.strip().lower() == "content-length":
                            cl_len = int(hv.strip())
                while len(rest_b) < cl_len:
                    ch = cs.recv(min(4096, cl_len - len(rest_b)))
                    if not ch:
                        break
                    rest_b += ch
                for drop_h in ("host", "content-length", "accept-encoding", "connection"):
                    hmap.pop(drop_h, None)
                with par_lock:
                    par_upstream_hits.append((req_p, hmap, rest_b))
                pl = json.loads(rest_b.decode("utf-8"))
                tag = str(pl.get("user") or "")
                if tag == "sse_ok":
                    cs.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                        b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":80,"cache_read_input_tokens":20}}}\n\n'
                        b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":15}}\n\n'
                        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
                    )
                elif tag == "sse_trunc":
                    cs.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                        b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":60}}}\n\n'
                    )
                else:
                    body_out = json.dumps(
                        {"id": "msg_r8_par", "usage": {"input_tokens": 110, "cache_read_input_tokens": 40, "output_tokens": 22}}
                    ).encode("utf-8")
                    cs.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(body_out)}\r\n\r\n".encode("ascii")
                        + body_out
                    )
            finally:
                cs.close()

    par_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    par_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    par_sock.bind(("127.0.0.1", 0))
    par_sock.listen(16)
    par_up_port = par_sock.getsockname()[1]
    threading.Thread(target=_row8_parity_upstream, args=(par_sock,), daemon=True).start()

    def _send_r8_suite(p_port: int) -> list[int]:
        fk = "sk-ant-FAKE00001234567890abcdef"
        suite = [
            ("/anthropic/v1/messages", {"model": "claude-sonnet-4-5", "user": "json_ok", "messages": [{"role": "user", "content": "hi"}]}, {"Content-Type": "application/json", "x-api-key": fk, "x-stainless-os": "Darwin"}),
            ("/anthropic/v1/messages", {"model": "claude-sonnet-4-5", "stream": True, "user": "sse_ok", "messages": [{"role": "user", "content": "sse"}]}, {"Content-Type": "application/json", "x-api-key": fk}),
            ("/anthropic/v1/messages", {"model": "claude-sonnet-4-5", "stream": True, "user": "sse_trunc", "messages": [{"role": "user", "content": "cut"}]}, {"Content-Type": "application/json", "x-api-key": fk}),
            ("/anthropic/v1/messages", {"model": "claude-sonnet-4-5", "user": "blocked_secret", "messages": [{"role": "user", "content": f"leak {fk}"}]}, {"Content-Type": "application/json"}),
        ]
        codes: list[int] = []
        for spath, sobj, shdrs in suite:
            hc_s = http.client.HTTPConnection("127.0.0.1", p_port, timeout=5)
            hc_s.request("POST", spath, body=json.dumps(sobj).encode("utf-8"), headers=shdrs)
            rs_s = hc_s.getresponse()
            _ = rs_s.read()
            codes.append(rs_s.status)
            hc_s.close()
        return codes

    def _norm_rows(db_file_p: pathlib.Path) -> list[tuple[object, ...]]:
        c_n = sqlite3.connect(str(db_file_p))
        r_n = c_n.execute(
            "SELECT provider, model, path, status_code, blocked, stream_truncated, "
            "buckets_json, namespaces_json, usage_json, headers_json, secrets_json, prompt_preview "
            "FROM traces ORDER BY id"
        ).fetchall()
        c_n.close()
        return r_n

    try:
        cli_par_db = tmp_dir / "row8_cli_serve.db"
        prog_par_db = tmp_dir / "row8_prog_api.db"
        ep = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ep.bind(("127.0.0.1", 0))
        cli_par_port = ep.getsockname()[1]
        ep.close()

        env_par = os.environ.copy()
        env_par["PYTHONPATH"] = str(root_dir / "src")
        cli_srv_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agent_xray.cli",
                "--lang",
                "en",
                "serve",
                "--port",
                str(cli_par_port),
                "--db",
                str(cli_par_db),
                "--upstream",
                f"http://127.0.0.1:{par_up_port}",
                "--strip-telemetry-headers",
                "--block-secrets",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env_par,
        )
        try:
            cli_up_ready = False
            for _ in range(100):
                try:
                    pr_s = socket.create_connection(("127.0.0.1", cli_par_port), timeout=0.2)
                    pr_s.close()
                    cli_up_ready = True
                    break
                except OSError:
                    time.sleep(0.03)
            assert cli_up_ready, "CLI serve did not bind in time"
            cli_codes = _send_r8_suite(cli_par_port)
            with par_lock:
                cli_up_captured = list(par_upstream_hits)
                par_upstream_hits.clear()
        finally:
            cli_srv_proc.send_signal(signal.SIGINT)
            cli_srv_proc.communicate(timeout=5)

        with fn(
            db_path=str(prog_par_db),
            upstream=f"http://127.0.0.1:{par_up_port}",
            strip_telemetry=True,
            block_secrets=True,
        ) as px_par:
            prog_codes = _send_r8_suite(px_par.port)
            for _ in range(50):
                if len(px_par.get_turns(limit=10)) >= 4:
                    break
                time.sleep(0.02)
            with par_lock:
                prog_up_captured = list(par_upstream_hits)
                par_upstream_hits.clear()

        assert cli_codes == [200, 200, 200, 400], cli_codes
        assert prog_codes == cli_codes, (prog_codes, cli_codes)
        assert cli_up_captured == prog_up_captured, (cli_up_captured, prog_up_captured)
        assert _norm_rows(cli_par_db) == _norm_rows(prog_par_db), (_norm_rows(cli_par_db), _norm_rows(prog_par_db))

        # Also compare secret-redacted HTTP 200 mode (`--store-previews`, no `--block-secrets`)
        cli_red_db = tmp_dir / "row8_cli_redact.db"
        prog_red_db = tmp_dir / "row8_prog_redact.db"
        ep2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ep2.bind(("127.0.0.1", 0))
        cli_red_port = ep2.getsockname()[1]
        ep2.close()
        fk2 = "sk-ant-FAKE00001234567890abcdef"
        red_payload = json.dumps({"model": "claude-sonnet-4-5", "user": "redact_200", "messages": [{"role": "user", "content": f"sec {fk2}"}]}).encode("utf-8")
        red_url_path = f"/anthropic/{fk2}/v1/messages"

        cli_red_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agent_xray.cli",
                "--lang",
                "en",
                "serve",
                "--port",
                str(cli_red_port),
                "--db",
                str(cli_red_db),
                "--upstream",
                f"http://127.0.0.1:{par_up_port}",
                "--strip-telemetry-headers",
                "--store-previews",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env_par,
        )
        try:
            for _ in range(100):
                try:
                    pr2 = socket.create_connection(("127.0.0.1", cli_red_port), timeout=0.2)
                    pr2.close()
                    break
                except OSError:
                    time.sleep(0.03)
            hc_rc = http.client.HTTPConnection("127.0.0.1", cli_red_port, timeout=5)
            hc_rc.request("POST", red_url_path, body=red_payload, headers={"Content-Type": "application/json", "x-stainless-os": "Darwin"})
            resp_rc = hc_rc.getresponse()
            _ = resp_rc.read()
            hc_rc.close()
            assert resp_rc.status == 200
            with par_lock:
                cli_red_up = list(par_upstream_hits)
                par_upstream_hits.clear()
        finally:
            cli_red_proc.send_signal(signal.SIGINT)
            cli_red_proc.communicate(timeout=5)

        with fn(
            db_path=str(prog_red_db),
            upstream=f"http://127.0.0.1:{par_up_port}",
            strip_telemetry=True,
            block_secrets=False,
            store_previews=True,
        ) as px_red:
            hc_rp = http.client.HTTPConnection("127.0.0.1", px_red.port, timeout=5)
            hc_rp.request("POST", red_url_path, body=red_payload, headers={"Content-Type": "application/json", "x-stainless-os": "Darwin"})
            resp_rp = hc_rp.getresponse()
            _ = resp_rp.read()
            hc_rp.close()
            assert resp_rp.status == 200
            for _ in range(50):
                if len(px_red.get_turns(limit=5)) >= 1:
                    break
                time.sleep(0.02)
            with par_lock:
                prog_red_up = list(par_upstream_hits)
                par_upstream_hits.clear()

        assert cli_red_up == prog_red_up, (cli_red_up, prog_red_up)
        assert _norm_rows(cli_red_db) == _norm_rows(prog_red_db), (_norm_rows(cli_red_db), _norm_rows(prog_red_db))
    finally:
        par_sock.close()

    print(
        f"ROW 8 [PASS]: start_background_proxy({len(spec_params)} SPEC kwargs) -> TypeError=0, "
        f"bind=127.0.0.1:{bound_port}, SQLite turns=1 (in=321, cached=654, out=45), "
        f"port released, lingering_threads=0, child_subprocesses=0; "
        f"CLI `serve` vs `start_background_proxy` 5-request parity (JSON 200, SSE 200, truncated SSE 200, blocked secret 400, redacted secret 200) -> 100% identical statuses, SQLite rows, & upstream headers"
    )
finally:
    r8_srv.shutdown()
    r8_srv.server_close()
PY

# ---------------------------------------------------------------------------
# Supplemental W1: Automated M1 Mutation Suite in Isolated Temp Copy
#                  Apply each M1 fault -> run named test -> assert FAILED
# ---------------------------------------------------------------------------
echo ""
echo "--- [Supplemental W1] Automated M1 Mutation Verification (16 M1 & Rework Faults) ---"

MUT_DIR="$TMP_DIR/m1_mut_copy"
mkdir -p "$MUT_DIR"
cp -R "${ROOT_DIR}/src" "${ROOT_DIR}/tests" "${ROOT_DIR}/Scripts" "${ROOT_DIR}/docs" "${ROOT_DIR}/README.md" "${ROOT_DIR}/README.zh-CN.md" "${ROOT_DIR}/pyproject.toml" "$MUT_DIR/"

"$PYTHON" - "$MUT_DIR" "$PYTHON" <<'PY'
import pathlib, subprocess, sys

mut_dir = pathlib.Path(sys.argv[1])
python_bin = sys.argv[2]

mutations = [
    (
        "M1_Row1_buffered_read_instead_of_read1",
        "src/agent_xray/proxy.py",
        '                read_chunk = getattr(up_resp, "read1", None)\n'
        '                if read_chunk is None and getattr(up_resp, "fp", None) is not None:\n'
        '                    read_chunk = getattr(up_resp.fp, "read1", None)',
        "                read_chunk = None",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_m1_sse_streaming_latency_midstream_disconnect_and_2mb_usage",
    ),
    (
        "M1_Row2_midstream_disconnect_injects_502",
        "src/agent_xray/proxy.py",
        "            if headers_sent:",
        "            if False and headers_sent:",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_m1_sse_streaming_latency_midstream_disconnect_and_2mb_usage",
    ),
    (
        "M1_Item2_strip_openai_organization_header",
        "src/agent_xray/privacy.py",
        '    "x-client-telemetry",',
        '    "x-client-telemetry",\n    "openai-organization",',
        "tests.test_privacy.PrivacyAndRedactionTests.test_m1_preserve_openai_org_project_and_duplicate_headers",
    ),
    (
        "M1_Row4_run_ignores_parent_base_url",
        "src/agent_xray/cli.py",
        "ant_upstream, oai_upstream = _resolve_upstreams(args, chain_parent_base_urls=True)",
        "ant_upstream, oai_upstream = _resolve_upstreams(args, chain_parent_base_urls=False)",
        "tests.test_cli.CliHonestyTests.test_m1_run_chains_existing_base_urls_supports_upstream_flag_and_labels_estimated",
    ),
    (
        "M1_Row5_monolithic_claude_md_rule_misclassification",
        "src/agent_xray/classifier.py",
        "    segments = _split_rule_tag_segments(text)",
        '    if "claude.md" in text.lower():\n        buckets.workspace_rules += estimate_tokens(text)\n        return ""\n    segments = _split_rule_tag_segments(text)',
        "tests.test_classifier.ClassifierHonestyTests.test_m1_block_level_and_inline_tag_splitting_across_three_formats",
    ),
    (
        "M1_Row6_skip_gzip_request_body_decompression",
        "src/agent_xray/privacy.py",
        '        if enc in ("gzip", "x-gzip"):',
        '        if False and enc in ("gzip", "x-gzip"):',
        "tests.test_privacy.PrivacyAndRedactionTests.test_m1_pem_prose_false_positive_and_request_surfaces_gzip_query_headers_escapes",
    ),
    (
        "X18_single_unquote_misses_double_encoded_path",
        "src/agent_xray/privacy.py",
        "    for _ in range(max_rounds):",
        "    for _ in range(1):",
        "tests.test_privacy.PrivacyAndRedactionTests.test_x18_iterative_unquote_case_insensitive_prefixes_8char_tail_and_doc_scope",
    ),
    (
        "XR3_developer_prose_mentioning_agents_md_misclassified",
        "src/agent_xray/classifier.py",
        "        if _STANDALONE_RULE_HEADER_RE.search(seg):",
        '        if _STANDALONE_RULE_HEADER_RE.search(seg) or (default_bucket == "system_prompt" and "agents.md" in seg.lower()):',
        "tests.test_classifier.ClassifierHonestyTests.test_xr3_developer_role_prose_mentioning_agents_or_claude_md_stays_in_system_prompt",
    ),
    (
        "XR4_send_response_duplicates_server_and_date_headers",
        "src/agent_xray/proxy.py",
        "            self.send_response_only(status_code, up_resp.reason or None)",
        "            self.send_response(status_code, up_resp.reason or None)",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_xr4_no_duplicate_server_date_headers_and_no_forced_accept_encoding_identity",
    ),
    (
        "XR4_sonnet_4_6_missing_flat_rate_entry",
        "src/agent_xray/store.py",
        '    ("claude-sonnet-4-6", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL)),',
        '    ("claude-sonnet-4-6", _rate_entry(3.00, 0.30, 3.75, 15.00, _ANTHROPIC_PRICING_URL, long_context_threshold_tokens=200_000, long_context_input_multiplier=2.0, long_context_output_multiplier=1.5)),',
        "tests.test_store.StorePricingCacheAndLabelsTests.test_xr4_sonnet_4_6_flat_pricing_vs_sonnet_4_5_200k_tier_and_stream_truncated_schema",
    ),
    (
        "XR4_stream_truncated_flag_not_recorded",
        "src/agent_xray/proxy.py",
        "                stream_truncated=stream_truncated,",
        "                stream_truncated=False,",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_xr4_premature_upstream_disconnect_sets_stream_truncated_across_framing_modes",
    ),
    (
        "XR5_unconverged_path_skips_placeholder",
        "src/agent_xray/privacy.py",
        "    stages, converged = _unquote_with_convergence(stripped, max_rounds=_MAX_UNQUOTE_ROUNDS)\n"
        "    if not converged:\n"
        "        return UNCONVERGED_PATH_PLACEHOLDER",
        "    stages, converged = _unquote_with_convergence(stripped, max_rounds=_MAX_UNQUOTE_ROUNDS)\n"
        "    if False and not converged:\n"
        "        return UNCONVERGED_PATH_PLACEHOLDER",
        "tests.test_privacy.PrivacyAndRedactionTests.test_xr5_unconverged_percent_encoding_placeholder_and_strict_8_round_cap",
    ),
    (
        "XR5_block_secrets_ignores_unconverged_path",
        "src/agent_xray/privacy.py",
        "        if not path_converged:",
        "        if False and not path_converged:",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_xr5_proxy_9_and_12_layer_encoded_secrets_placeholder_in_sqlite_and_blocked",
    ),
    (
        "XR6_content_length_shortfall_ignored",
        "src/agent_xray/proxy.py",
        "                    and raw_bytes_read < expected_content_length",
        "                    and False and raw_bytes_read < expected_content_length",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_xr6_three_independent_truncation_paths_and_inspector_html_warnings",
    ),
    (
        "XR6_cli_report_hides_truncation_warning",
        "src/agent_xray/cli.py",
        '    truncated_count = int(s.get("truncated_count") or 0)',
        "    truncated_count = 0",
        "tests.test_cli.CliHonestyTests.test_xr6_cli_report_flags_truncated_streams_and_incomplete_cost_bilingually",
    ),
    (
        "XR7_server_close_skips_handler_thread_join",
        "src/agent_xray/proxy.py",
        "            if th is not cur and th.is_alive():\n                th.join(timeout=2.0)",
        "            if th is not cur and th.is_alive():\n                pass",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_xr7_server_close_joins_live_handler_threads_before_returning",
    ),
]

for label, rel_path, target, replacement, dotted_test in mutations:
    fpath = mut_dir / rel_path
    orig = fpath.read_text(encoding="utf-8")
    assert target in orig, f"Mutation target missing in {rel_path}: {target!r}"
    assert orig.count(target) == 1, f"Mutation target non-unique in {rel_path}"

    try:
        fpath.write_text(orig.replace(target, replacement, 1), encoding="utf-8")
        # Verify mutated Python file compiles cleanly (syntax errors do NOT count per W1)
        subprocess.run(
            [python_bin, "-m", "py_compile", str(fpath)],
            check=True,
            capture_output=True,
            text=True,
        )
        res = subprocess.run(
            [python_bin, "-m", "unittest", dotted_test],
            cwd=str(mut_dir),
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONPATH": str(mut_dir / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "BROWSER": "true",
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = (res.stdout or "") + "\n" + (res.stderr or "")
        short_test = dotted_test.rsplit(".", 1)[-1]
        assert res.returncode != 0, f"Mutation {label} SURVIVED {dotted_test}!"
        assert ("FAIL:" in combined or "ERROR:" in combined) and short_test in combined, (
            f"Mutation {label} did not fail in named test {short_test}:\n{combined}"
        )
        assert "SyntaxError" not in combined and "IndentationError" not in combined, combined
        print(f"  [MUTATION KILLED] {label} -> {short_test} failed as expected (exit={res.returncode})")
    finally:
        fpath.write_text(orig, encoding="utf-8")
PY

echo ""
if [[ "$M1_ROW7_SKIPPED" -eq 1 ]]; then
  echo "=== M1 ACCEPTANCE SUMMARY: rows_passed=7 (Rows 1,2,3,4,5,6,8), rows_skipped=1 (Row 7 live paid API: 没跑), rows_failed=0, mutations_killed=16/16 ==="
else
  echo "=== M1 ACCEPTANCE SUMMARY: rows_passed=8 (Rows 1,2,3,4,5,6,7,8), rows_skipped=0, rows_failed=0, mutations_killed=16/16 ==="
fi
