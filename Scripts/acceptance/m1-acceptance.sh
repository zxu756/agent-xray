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
    tail_ev = b'event: message_delta\ndata: {"type":"message_delta","usage":{"input_tokens":140,"output_tokens":20}}\n\n'
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
    assert conn1_trace["ttft_ms"] is not None and conn1_trace["ttft_ms"] >= 0.0, conn1_trace
    assert conn1_trace["output_tokens"] == 20 and conn1_trace["input_tokens"] == 140, conn1_trace
    print(
        f"ROW 2 [PASS]: Upstream mid-stream disconnect -> 10 complete events, clean EOF, "
        f"'HTTP/1.1' in body=0, '502' in body=0; client disconnect survived cleanly (recorded ttft_ms={conn1_trace['ttft_ms']:.2f})"
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
        strip_telemetry_headers=True,
        block_secrets=True,
    ) as px:
        # 3a: 2.3 MB Anthropic SSE stream
        ant_req = json.dumps(
            {"model": "claude-sonnet-4-5", "stream": True, "messages": [{"role": "user", "content": "big stream"}]}
        ).encode("utf-8")
        hc = http.client.HTTPConnection("127.0.0.1", px.port, timeout=20)
        hc.request(
            "POST",
            "/anthropic/v1/messages",
            body=ant_req,
            headers={"Content-Type": "application/json", "X-Test-Case": "2mb-anthropic-sse"},
        )
        r_big = hc.getresponse()
        big_bytes = r_big.read()
        hc.close()
        assert r_big.status == 200 and len(big_bytes) > 2_200_000, (r_big.status, len(big_bytes))

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

    # Check upstream received headers & bodies verbatim on request #3 & #4
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

        print(
            f"ROW 5 [PASS]: 3 formats verified vs hand oracle -> "
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
            f"ROW 6 [PASS]: 11/11 secret vectors (count_tokens, batches, embeddings, responses/compact, gzip, query, "
            f"custom header, \\u0073 escape, _-glued, non-JSON, PEM) returned HTTP 400 with upstream_bytes=0; "
            f"benign auth headers, sk-ssh-ed25519, placeholders, PEM prose, SHA & UUID returned HTTP 200"
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
                f"{px_p2.base_url}/anthropic/v1/sk-ant-api03-M1COLPATH44444444444444444444/messages?k=sk-ant-api03-M1COLQ55555555555555555555",
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
        assert "ttft_ms" in all_cols and len(all_cols) == 15, all_cols
        dump_p2 = "\n".join(conn_p2.iterdump())
        conn_p2.close()
        for needle in ("sk-ant-", "M1COLMODEL", "M1COLNS", "M1COLMSG", "M1COLPATH", "M1COLQ", "M1COLHN", "M1COLHV"):
            assert needle not in dump_p2, f"Leaked {needle} in SQLite dump (block={blk_flag})"

    print(
        f"PART2-X14 [PASS]: Dynamic PRAGMA table_info verified {len(all_cols)} columns ({','.join(all_cols)}) "
        f"across tables={tables}; sqlite3 .dump secret matches=0 (block OFF & ON)"
    )
finally:
    p2_srv.shutdown()
    p2_srv.server_close()

# P2.2: Claude Sonnet 4 <=200k vs >200k long-context tiered pricing
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
# > 200k (250k prompt tokens): 50k*$6 + 160k*$0.60 + 40k*$7.50 + 2k*$22.50 = $0.30 + $0.096 + $0.30 + $0.045 = $0.7410
cost_over = compute_turn_cost_usd(
    model="claude-sonnet-4-5",
    status_code=200,
    blocked=False,
    input_tokens=50_000,
    cache_read_tokens=160_000,
    cache_write_tokens=40_000,
    output_tokens=2_000,
)
assert cost_under is not None and math.isclose(cost_under, 0.1950, rel_tol=0, abs_tol=1e-9), cost_under
assert cost_over is not None and math.isclose(cost_over, 0.7410, rel_tol=0, abs_tol=1e-9), cost_over
print(f"PART2-PRICING [PASS]: claude-sonnet-4-5 <=200k=${cost_under:.4f} vs >200k=${cost_over:.4f} (2x input/cache, 1.5x output)")

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
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 7] Live External API Tokenizer Calibration Check ---"
if [[ "${XRAY_REAL_API:-0}" == "1" ]]; then
  "$PYTHON" - <<'PY'
import json, os, statistics, sys, urllib.request
from agent_xray.classifier import classify_request

ant_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
oai_key = os.environ.get("OPENAI_API_KEY", "").strip()
if not ant_key and not oai_key:
    print("Error: XRAY_REAL_API=1 requires ANTHROPIC_API_KEY and/or OPENAI_API_KEY in environment.", file=sys.stderr)
    raise SystemExit(2)

if ant_key:
    errs = []
    for i in range(5):
        body = {"model": "claude-3-5-haiku-latest", "max_tokens": 1, "messages": [{"role": "user", "content": f"Sample prompt {i}: " + ("word " * (20 + i * 15))}]}
        est = classify_request("/v1/messages", body).buckets.total_estimated
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-api-key": ant_key, "anthropic-version": "2023-06-01"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            actual = json.loads(resp.read().decode("utf-8"))["usage"]["input_tokens"]
        errs.append(abs(est - actual) / max(1, actual))
    print(f"ROW 7 [Anthropic]: mean_error={statistics.mean(errs)*100:.2f}%, max_error={max(errs)*100:.2f}%")
PY
else
  echo "SKIPPED (没跑): XRAY_REAL_API!=1; requires user approval for paid API calibration"
fi

# ---------------------------------------------------------------------------
# Supplemental W1: Automated M1 Mutation Suite in Isolated Temp Copy
#                  Apply each M1 fault -> run named test -> assert FAILED
# ---------------------------------------------------------------------------
echo ""
echo "--- [Supplemental W1] Automated M1 Mutation Verification (6 M1 Faults) ---"

MUT_DIR="$TMP_DIR/m1_mut_copy"
mkdir -p "$MUT_DIR"
cp -R "${ROOT_DIR}/src" "${ROOT_DIR}/tests" "${ROOT_DIR}/pyproject.toml" "$MUT_DIR/"

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
        "            if not headers_sent:",
        "            if True or not headers_sent:",
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
echo "=== ALL M1 ACCEPTANCE CHECKS & MUTATIONS PASSED ==="
