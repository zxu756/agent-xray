from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent_xray.local_sessions import import_local_desktop_sessions
from agent_xray.proxy import ProxyConfig, XRayHTTPServer
from agent_xray.store import TraceStore


class _FakeUpstream(BaseHTTPRequestHandler):
    requests: list[dict[str, object]] = []

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b""
        type(self).requests.append(
            {
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": raw,
            }
        )
        resp = json.dumps(
            {
                "id": "msg_test",
                "usage": {
                    "input_tokens": 200,
                    "cache_read_input_tokens": 800,
                    "cache_creation_input_tokens": 100,
                    "output_tokens": 50,
                },
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


class ProxySecurityAndPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeUpstream.requests = []
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstream)
        self.up_port = self.upstream.server_address[1]
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.upstream.shutdown()
        self.upstream.server_close()

    def test_host_origin_and_token_guards_on_ui_and_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            store = TraceStore(tmp_path / "traces.db")
            cfg = ProxyConfig(
                host="127.0.0.1",
                port=0,
                anthropic_upstream=f"http://127.0.0.1:{self.up_port}",
                openai_upstream=f"http://127.0.0.1:{self.up_port}",
                desktop_home=tmp_path,
            )
            srv = XRayHTTPServer(cfg, store)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                self.assertTrue(len(cfg.auth_token) >= 24)

                # 1. Host header validation (DNS rebinding guard)
                for bad_host in ("attacker.example", f"attacker.example:{port}", "127.0.0.1:1"):
                    for route in ("/_xray/api/summary", "/_xray/api/traces", "/_xray/", "/"):
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        c.putrequest("GET", route, skip_host=True)
                        c.putheader("Host", bad_host)
                        c.endheaders()
                        r = c.getresponse()
                        _ = r.read()
                        c.close()
                        self.assertEqual(r.status, 403, f"Expected 403 for Host={bad_host} on {route}")

                # 2. Cross-origin GET rejected + no wildcard CORS
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("GET", "/_xray/api/summary", headers={"Origin": "http://attacker.example"})
                r = c.getresponse()
                _ = r.read()
                c.close()
                self.assertEqual(r.status, 403)

                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("GET", "/_xray/api/summary")
                r = c.getresponse()
                _ = r.read()
                cors = r.getheader("Access-Control-Allow-Origin")
                c.close()
                self.assertEqual(r.status, 200)
                self.assertIsNone(cors)

                # 3. POST /_xray/api/scan-desktop: cross-origin Origin or Referer rejected
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(
                    "POST",
                    "/_xray/api/scan-desktop",
                    headers={
                        "Origin": "http://attacker.example",
                        "X-Xray-Token": cfg.auth_token,
                    },
                )
                r = c.getresponse()
                _ = r.read()
                c.close()
                self.assertEqual(r.status, 403)

                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(
                    "POST",
                    "/_xray/api/scan-desktop",
                    headers={
                        "Referer": "http://attacker.example/csrf.html",
                        "X-Xray-Token": cfg.auth_token,
                    },
                )
                r = c.getresponse()
                _ = r.read()
                c.close()
                self.assertEqual(r.status, 403)

                # 4. POST without token -> 401; wrong token -> 403; valid token -> 200
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(
                    "POST",
                    "/_xray/api/scan-desktop",
                    headers={"Origin": f"http://127.0.0.1:{port}"},
                )
                r = c.getresponse()
                _ = r.read()
                c.close()
                self.assertIn(r.status, (401, 403))

                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(
                    "POST",
                    "/_xray/api/scan-desktop",
                    headers={
                        "Origin": f"http://127.0.0.1:{port}",
                        "X-Xray-Token": "wrong-token",
                    },
                )
                r = c.getresponse()
                _ = r.read()
                c.close()
                self.assertIn(r.status, (401, 403))

                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request(
                    "POST",
                    "/_xray/api/scan-desktop",
                    headers={
                        "Origin": f"http://127.0.0.1:{port}",
                        "Authorization": f"Bearer {cfg.auth_token}",
                    },
                )
                r = c.getresponse()
                payload = json.loads(r.read().decode("utf-8"))
                c.close()
                self.assertEqual(r.status, 200)
                self.assertEqual(payload["imported"], 0)
            finally:
                srv.shutdown()
                srv.server_close()
                store.close()

    def test_allow_lan_requires_explicit_token_and_guards_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TraceStore(Path(tmp) / "lan.db")
            try:
                with self.assertRaises(ValueError):
                    XRayHTTPServer(ProxyConfig(host="0.0.0.0", port=0, allow_lan=True), store)

                cfg = ProxyConfig(
                    host="127.0.0.1",
                    port=0,
                    allow_lan=True,
                    auth_token="explicit-lan-token-123456",
                )
                srv = XRayHTTPServer(cfg, store)
                port = srv.server_address[1]
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                try:
                    # Without token, even GET /_xray/api/summary must be rejected under allow_lan!
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    c.request("GET", "/_xray/api/summary")
                    r = c.getresponse()
                    _ = r.read()
                    c.close()
                    self.assertIn(r.status, (401, 403))

                    # With token, GET succeeds
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    c.request("GET", "/_xray/api/summary", headers={"X-Xray-Token": "explicit-lan-token-123456"})
                    r = c.getresponse()
                    _ = r.read()
                    c.close()
                    self.assertEqual(r.status, 200)
                finally:
                    srv.shutdown()
                    srv.server_close()
            finally:
                store.close()

    def test_proxy_end_to_end_zero_secret_or_header_leak_in_sqlite_dump(self) -> None:
        ant = "sk-ant-api03-" + ("LeakCheckA1" * 3)
        or_key = "sk-or-v1-" + ("OpenRouter99" * 3)
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAPrivateKeyBodyNeverPersisted12345\n"
            "-----END RSA PRIVATE KEY-----"
        )
        custom_hdr_val = "custom-header-token-value-xyz987"

        for block in (True, False):
            for previews in (False, True):
                with self.subTest(block=block, previews=previews):
                    with tempfile.TemporaryDirectory() as tmp:
                        db_path = Path(tmp) / "e2e.db"
                        store = TraceStore(db_path)
                        cfg = ProxyConfig(
                            host="127.0.0.1",
                            port=0,
                            anthropic_upstream=f"http://127.0.0.1:{self.up_port}",
                            openai_upstream=f"http://127.0.0.1:{self.up_port}",
                            block_secrets=block,
                            store_previews=previews,
                        )
                        srv = XRayHTTPServer(cfg, store)
                        port = srv.server_address[1]
                        threading.Thread(target=srv.serve_forever, daemon=True).start()
                        try:
                            prompt_txt = ("P" * 130) + f" {ant} {or_key}\n{pem}"
                            body = json.dumps(
                                {
                                    "model": "claude-sonnet-4-5",
                                    "messages": [{"role": "user", "content": prompt_txt}],
                                }
                            ).encode("utf-8")
                            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                            c.request(
                                "POST",
                                "/anthropic/v1/messages",
                                body=body,
                                headers={
                                    "Content-Type": "application/json",
                                    "X-Custom-Token": custom_hdr_val,
                                },
                            )
                            r = c.getresponse()
                            resp_raw = r.read().decode("utf-8")
                            c.close()
                            self.assertEqual(r.status, 400 if block else 200)
                            for secret_piece in ("LeakCheckA1", "OpenRouter99", "MIIEow", custom_hdr_val):
                                self.assertNotIn(secret_piece, resp_raw)
                        finally:
                            srv.shutdown()
                            srv.server_close()
                            store.close()

                        conn = sqlite3.connect(db_path)
                        dump_sql = "\n".join(conn.iterdump())
                        row = conn.execute("SELECT blocked, prompt_preview, secrets_json FROM traces").fetchone()
                        conn.close()

                        for forbidden in (
                            "sk-ant",
                            "LeakCheckA1",
                            "sk-or-v1",
                            "OpenRouter99",
                            "BEGIN RSA PRIVATE KEY",
                            "MIIEow",
                            "PrivateKeyBodyNeverPersisted",
                            custom_hdr_val,
                        ):
                            self.assertNotIn(forbidden, dump_sql)

                        if block:
                            self.assertEqual(row[0], 1)
                            self.assertEqual(row[1], "")  # Blocked never stores preview even if store_previews=True!
                            sec = json.loads(row[2])
                            self.assertTrue(any(s["field"] == "messages[0].content" for s in sec))
                        elif not previews:
                            self.assertEqual(row[1], "")
                        else:
                            self.assertTrue(row[1].startswith("P" * 130))

    def test_all_sqlite_columns_sanitized_against_request_secrets(self) -> None:
        expected_text_cols = {
            "provider",
            "model",
            "path",
            "buckets_json",
            "namespaces_json",
            "usage_json",
            "headers_json",
            "secrets_json",
            "prompt_preview",
        }
        for block in (False, True):
            with self.subTest(block_secrets=block):
                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    db_path = tmp_path / f"all_cols_{int(block)}.db"
                    store = TraceStore(db_path)

                    # 1. Dynamically introspect every table and TEXT column in traces.db
                    conn_meta = sqlite3.connect(db_path)
                    tables = [
                        r[0]
                        for r in conn_meta.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                        ).fetchall()
                    ]
                    self.assertEqual(tables, ["traces"])
                    col_rows = conn_meta.execute("PRAGMA table_info(traces)").fetchall()
                    conn_meta.close()
                    discovered_text_cols = {
                        str(c[1]) for c in col_rows if "TEXT" in str(c[2]).upper()
                    }
                    self.assertEqual(discovered_text_cols, expected_text_cols)

                    cfg = ProxyConfig(
                        host="127.0.0.1",
                        port=0,
                        anthropic_upstream=f"http://127.0.0.1:{self.up_port}",
                        openai_upstream=f"http://127.0.0.1:{self.up_port}",
                        block_secrets=block,
                        store_previews=True,
                    )
                    srv = XRayHTTPServer(cfg, store)
                    port = srv.server_address[1]
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    try:
                        # 2. HTTP request injecting secrets into path segment, query key/value,
                        #    model, tool namespace, header name/value, JSON key (secrets_json.field),
                        #    and user message (prompt_preview)
                        req_url = (
                            "/anthropic/sk-ant-api03-LEAKPROBE_PATHSEG_111111111111/v1/messages"
                            "?key=sk-ant-api03-LEAKPROBE_QUERYVAL_222222222222"
                            "&sk-ant-api03-LEAKPROBE_QUERYKEY_333333333333=1"
                            "&ghp=ghp_LEAKPROBE_GHP_4444444444444444444444"
                        )
                        body = json.dumps(
                            {
                                "model": "claude-sk-ant-api03-LEAKPROBE_MODEL_555555555555",
                                "tools": [
                                    {
                                        "name": "mcp__sk-ant-api03-LEAKPROBE_NS_666666666666__exec",
                                        "input_schema": {"type": "object"},
                                    }
                                ],
                                "sk-ant-api03-LEAKPROBE_SECKEY_999999999999": (
                                    "sk-ant-api03-LEAKPROBE_SECVAL_000000000000"
                                ),
                                "messages": [
                                    {
                                        "role": "user",
                                        "content": "Prompt prefix sk-ant-api03-LEAKPROBE_PREVIEW_121212121212",
                                    }
                                ],
                            }
                        ).encode("utf-8")
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        c.request(
                            "POST",
                            req_url,
                            body=body,
                            headers={
                                "Content-Type": "application/json",
                                "X-sk-ant-api03-LEAKPROBE_HDRNAME_777777777777": (
                                    "sk-ant-api03-LEAKPROBE_HDRVAL_888888888888"
                                ),
                            },
                        )
                        r = c.getresponse()
                        err_or_ok = r.read().decode("utf-8")
                        c.close()
                        self.assertEqual(r.status, 400 if block else 200)
                        self.assertNotIn("LEAKPROBE", err_or_ok)
                        self.assertNotIn("sk-ant-", err_or_ok)

                        # Query-string secret: blocked (400) when block_secrets=True, forwarded (200) when False
                        c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        c2.request(
                            "POST",
                            "/anthropic/v1/messages?api_key=sk-ant-api03-LEAKPROBE_QONLY_141414141414",
                            body=json.dumps(
                                {
                                    "model": "claude-sonnet-4-5",
                                    "messages": [{"role": "user", "content": "ping"}],
                                }
                            ).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                        )
                        r2 = c2.getresponse()
                        _ = r2.read()
                        c2.close()
                        self.assertEqual(r2.status, 400 if block else 200)

                        # Benign query string: always 200, query stripped from persisted `path`
                        c2b = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        c2b.request(
                            "POST",
                            "/anthropic/v1/messages?beta=true",
                            body=json.dumps(
                                {
                                    "model": "claude-sonnet-4-5",
                                    "messages": [{"role": "user", "content": "ping"}],
                                }
                            ).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                        )
                        r2b = c2b.getresponse()
                        _ = r2b.read()
                        c2b.close()
                        self.assertEqual(r2b.status, 200)

                        # 3. Local session import with secret in session filename -> buckets_json & path
                        fake_home = tmp_path / "home"
                        cdir = fake_home / ".claude/projects/demo"
                        cdir.mkdir(parents=True)
                        (cdir / "sk-ant-api03-LEAKPROBE_CLAUDEFILE_151515151515.jsonl").write_text(
                            json.dumps(
                                {
                                    "requestId": "r1",
                                    "message": {
                                        "id": "m1",
                                        "role": "assistant",
                                        "model": "claude-sk-ant-api03-LEAKPROBE_LOCALMOD_161616161616",
                                        "usage": {"input_tokens": 10, "output_tokens": 5},
                                    },
                                }
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                        import_local_desktop_sessions(store, home=fake_home, max_turns=5, store_previews=True)

                        # 4. Direct TraceStore write boundary probe across EVERY remaining column
                        #    (provider, buckets_json, usage_json, plus all other columns)
                        store.record_turn(
                            provider="prov-sk-ant-api03-LEAKPROBE_PROVIDER_171717171717",
                            model="mod-sk-ant-api03-LEAKPROBE_DIRECTMOD_181818181818",
                            path="/v1/messages?key=sk-ant-api03-LEAKPROBE_DIRECTPATH_191919191919",
                            status_code=400 if block else 200,
                            latency_ms=12,
                            blocked=block,
                            buckets={
                                "session_id": "ses-sk-ant-api03-LEAKPROBE_BUCKET_202020202020",
                                "system_prompt": 1,
                                "total_estimated": 1,
                            },
                            tool_namespaces=[
                                {
                                    "namespace": "mcp:sk-ant-api03-LEAKPROBE_DIRECTNS_212121212121",
                                    "tool_count": 1,
                                    "estimated_tokens": 10,
                                }
                            ],
                            usage={
                                "input_tokens": 10,
                                "output_tokens": 2,
                                "cache_read_tokens": 0,
                                "cache_write_tokens": 0,
                                "note": "sk-ant-api03-LEAKPROBE_USAGE_222222222222",  # type: ignore[dict-item]
                            },
                            header_audit=[
                                {
                                    "name": "X-sk-ant-api03-LEAKPROBE_DIRECTHDR_232323232323",
                                    "value_length": 42,
                                    "category": "protocol",
                                    "action": "forwarded",
                                }
                            ],
                            secret_findings=[
                                {
                                    "rule": "Rule-sk-ant-api03-LEAKPROBE_DIRECTRULE_242424242424",
                                    "field": "field.sk-ant-api03-LEAKPROBE_DIRECTFLD_252525252525",
                                }
                            ],
                            prompt_preview="Preview sk-ant-api03-LEAKPROBE_DIRECTPREV_262626262626",
                            store_previews=True,
                        )
                    finally:
                        srv.shutdown()
                        srv.server_close()
                        store.close()

                    conn = sqlite3.connect(db_path)
                    dump_sql = "\n".join(conn.iterdump())
                    paths = [r[0] for r in conn.execute("SELECT path FROM traces").fetchall()]
                    conn.close()

                    self.assertNotIn("LEAKPROBE", dump_sql)
                    self.assertNotIn("sk-ant-", dump_sql)
                    self.assertNotIn("ghp_LEAKPROBE", dump_sql)
                    self.assertTrue(all("?" not in p for p in paths), f"Query string persisted in paths: {paths}")
                    self.assertIn("/anthropic/v1/messages", paths)

                    # Verify every column in PRAGMA table_info(traces) (including M1 ttft_ms)
                    conn_chk = sqlite3.connect(db_path)
                    all_cols = {str(r[1]) for r in conn_chk.execute("PRAGMA table_info(traces)").fetchall()}
                    conn_chk.close()
                    self.assertIn("ttft_ms", all_cols)

    def test_m1_sse_streaming_latency_midstream_disconnect_and_2mb_usage(self) -> None:
        import socket
        import time
        from agent_xray.proxy import start_background_proxy

        sent_times: list[float] = []

        def raw_sse_upstream(srv_sock: socket.socket) -> None:
            # Request 1: 20 small ~100 B events spaced 60 ms apart -> each must arrive < 50 ms after send
            conn, _ = srv_sock.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._drain_http_head(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            for idx in range(20):
                pad = "x" * 35
                ev = f'event: delta\ndata: {{"i":{idx:02d},"p":"{pad}"}}\n\n'.encode("utf-8")
                sent_times.append(time.monotonic())
                conn.sendall(ev)
                if idx < 19:
                    time.sleep(0.06)
            conn.sendall(
                b'event: message_delta\ndata: {"type":"message_delta","usage":{"input_tokens":120,"output_tokens":20}}\n\n'
                b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
            )
            conn.close()

            # Request 2: mid-stream chunked SSE disconnect after 10 events (no 0\r\n\r\n terminator)
            # -> raises IncompleteRead in http.client; proxy must close cleanly with zero HTTP/1.1 502 injected
            conn2, _ = srv_sock.accept()
            conn2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._drain_http_head(conn2)
            conn2.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            for idx in range(10):
                ev2 = f'data: {{"i":{idx}}}\n\n'.encode("utf-8")
                conn2.sendall(f"{len(ev2):x}\r\n".encode("ascii") + ev2 + b"\r\n")
                time.sleep(0.005)
            conn2.close()

            # Request 3: 2.3 MB SSE stream with usage at the very end -> exact output_tokens recorded
            conn3, _ = srv_sock.accept()
            conn3.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._drain_http_head(conn3)
            conn3.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            conn3.sendall(
                b'event: message_start\n'
                b'data: {"type":"message_start","message":{"usage":{"input_tokens":333,"cache_read_input_tokens":444,"cache_creation_input_tokens":55}}}\n\n'
            )
            big_chunk = (
                b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"'
                + (b"y" * 1000)
                + b'"}}\n\n'
            )
            for _ in range(2200):
                conn3.sendall(big_chunk)
            conn3.sendall(
                b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":8888}}\n\n'
                b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
            )
            conn3.close()

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(8)
        up_port = srv_sock.getsockname()[1]
        threading.Thread(target=raw_sse_upstream, args=(srv_sock,), daemon=True).start()

        try:
            with start_background_proxy(upstream=f"http://127.0.0.1:{up_port}") as px:
                req_json = json.dumps(
                    {
                        "model": "claude-sonnet-4-5",
                        "stream": True,
                        "messages": [{"role": "user", "content": "stream"}],
                    }
                ).encode("utf-8")

                # 1. Per-event latency delta < 50 ms across all 20 events
                cli = socket.create_connection(("127.0.0.1", px.port), timeout=10)
                cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                cli.sendall(
                    f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(req_json)}\r\n\r\n".encode("utf-8")
                    + req_json
                )
                buf = b""
                while b"\r\n\r\n" not in buf:
                    buf += cli.recv(4096)
                _, rest = buf.split(b"\r\n\r\n", 1)
                recv_times: dict[int, float] = {}
                t_init = time.monotonic()
                self._extract_delta_indices(rest, recv_times, t_init)
                while len(recv_times) < 20:
                    ch = cli.recv(4096)
                    if not ch:
                        break
                    t_now = time.monotonic()
                    rest += ch
                    self._extract_delta_indices(rest, recv_times, t_now)
                while cli.recv(4096):
                    pass
                cli.close()

                self.assertEqual(len(recv_times), 20)
                deltas_ms = [(recv_times[i] - sent_times[i]) * 1000.0 for i in range(20)]
                self.assertLess(max(deltas_ms), 50.0, f"Max SSE delta {max(deltas_ms):.2f} ms >= 50 ms")

                # 2. Mid-stream upstream disconnect: 10 events, clean EOF, no HTTP/1.1 injected in body
                cli2 = socket.create_connection(("127.0.0.1", px.port), timeout=10)
                cli2.sendall(
                    f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(req_json)}\r\n\r\n".encode("utf-8")
                    + req_json
                )
                raw2 = b""
                while True:
                    ch = cli2.recv(4096)
                    if not ch:
                        break
                    raw2 += ch
                cli2.close()
                _, body2 = raw2.split(b"\r\n\r\n", 1)
                self.assertEqual(body2.count(b"data: "), 10)
                self.assertNotIn(b"HTTP/1.1", body2)
                self.assertNotIn(b"502", body2)

                # 3. 2.3 MB SSE stream: trailing usage captured accurately
                hc = http.client.HTTPConnection("127.0.0.1", px.port, timeout=15)
                hc.request(
                    "POST",
                    "/anthropic/v1/messages",
                    body=req_json,
                    headers={"Content-Type": "application/json"},
                )
                hr = hc.getresponse()
                stream_out = hr.read()
                hc.close()
                self.assertEqual(hr.status, 200)
                self.assertGreater(len(stream_out), 2_200_000)

                # Wait briefly for proxy handler post-response record_turn
                turns = self._wait_for_turn_count(px, 3)
                self.assertIsNotNone(turns[0]["ttft_ms"])
                self.assertGreaterEqual(turns[0]["ttft_ms"], 0.0)
                self.assertEqual(turns[2]["input_tokens"], 333)
                self.assertEqual(turns[2]["cached_input_tokens"], 444)
                self.assertEqual(turns[2]["cache_creation_input_tokens"], 55)
                self.assertEqual(turns[2]["output_tokens"], 8888)
        finally:
            srv_sock.close()

    def test_m1_headers_duplicates_gzip_chunked_and_all_endpoint_secrets(self) -> None:
        import gzip
        from agent_xray.proxy import start_background_proxy

        captured_up: list[dict[str, object]] = []

        class _FidelityUpstream(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                cl = int(self.headers.get("Content-Length") or "0")
                raw_b = self.rfile.read(cl) if cl else b""
                captured_up.append(
                    {
                        "path": self.path,
                        "header_pairs": list(self.headers.items()),
                        "body": raw_b,
                    }
                )
                resp_json = json.dumps(
                    {
                        "id": "resp_1",
                        "usage": {
                            "input_tokens": 300,
                            "output_tokens": 45,
                            "input_tokens_details": {"cached_tokens": 100},
                        },
                    }
                ).encode("utf-8")
                if "gzip" in (self.headers.get("Accept-Encoding") or "").lower():
                    gz_resp = gzip.compress(resp_json)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(gz_resp)))
                    self.end_headers()
                    self.wfile.write(gz_resp)
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_json)))
                    self.end_headers()
                    self.wfile.write(resp_json)

        up_srv = ThreadingHTTPServer(("127.0.0.1", 0), _FidelityUpstream)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, daemon=True).start()

        try:
            with start_background_proxy(
                upstream=f"http://127.0.0.1:{up_port}",
                strip_telemetry=True,
                block_secrets=True,
            ) as px:
                # 1. Duplicate headers + openai-organization/project + gzip request & gzip response
                plain_req = json.dumps(
                    {
                        "model": "gpt-5",
                        "instructions": "Base instructions",
                        "input": "Hello world",
                    }
                ).encode("utf-8")
                gz_req = gzip.compress(plain_req)

                c = http.client.HTTPConnection("127.0.0.1", px.port, timeout=10)
                c.putrequest("POST", "/openai/v1/responses", skip_accept_encoding=True)
                c.putheader("Content-Type", "application/json")
                c.putheader("Content-Encoding", "gzip")
                c.putheader("Accept-Encoding", "gzip")
                c.putheader("openai-organization", "org-keep-me")
                c.putheader("openai-project", "proj-keep-me")
                c.putheader("X-Multi", "alpha")
                c.putheader("X-Multi", "beta")
                c.putheader("x-stainless-os", "MacOS")
                c.putheader("Content-Length", str(len(gz_req)))
                c.endheaders(gz_req)
                r = c.getresponse()
                resp_raw = r.read()
                resp_ce = r.getheader("Content-Encoding")
                c.close()

                self.assertEqual(r.status, 200)
                self.assertEqual(resp_ce, "gzip")
                self.assertEqual(json.loads(gzip.decompress(resp_raw))["id"], "resp_1")
                self.assertEqual(len(captured_up), 1)

                up_pairs = captured_up[0]["header_pairs"]
                assert isinstance(up_pairs, list)
                up_lower_map = {k.lower(): v for k, v in up_pairs}
                self.assertEqual(up_lower_map.get("openai-organization"), "org-keep-me")
                self.assertEqual(up_lower_map.get("openai-project"), "proj-keep-me")
                self.assertEqual(up_lower_map.get("accept-encoding"), "gzip")
                self.assertEqual(up_lower_map.get("content-encoding"), "gzip")
                self.assertNotIn("x-stainless-os", up_lower_map)
                self.assertEqual([v for k, v in up_pairs if k.lower() == "x-multi"], ["alpha", "beta"])
                self.assertEqual(captured_up[0]["body"], gz_req)

                turns = self._wait_for_turn_count(px, 1)
                self.assertEqual(turns[0]["input_tokens"], 200)
                self.assertEqual(turns[0]["cached_input_tokens"], 100)
                self.assertEqual(turns[0]["output_tokens"], 45)
                self.assertGreater(turns[0]["buckets"]["total_estimated"], 0)

                # 2. All-endpoint secret blocking: count_tokens, batches, embeddings, gzip body, query, header, \u0073
                ant = "sk-ant-api03-" + ("Z1x2C3v4B5" * 3)
                blocked_vectors = [
                    ("/anthropic/v1/messages/count_tokens", {}, json.dumps({"messages": [{"role": "user", "content": ant}]}).encode()),
                    ("/anthropic/v1/messages/batches", {}, json.dumps({"requests": [{"custom_id": "1", "params": {"content": ant}}]}).encode()),
                    ("/openai/v1/embeddings", {}, json.dumps({"model": "text-embedding-3-small", "input": ant}).encode()),
                    ("/openai/v1/responses/compact", {}, gzip.compress(json.dumps({"input": ant}).encode()), {"Content-Encoding": "gzip"}),
                    (f"/anthropic/v1/messages?key={ant}", {}, b'{"model":"m","messages":[{"role":"user","content":"ok"}]}'),
                    ("/anthropic/v1/messages", {"X-Custom-Secret": ant}, b'{"model":"m","messages":[{"role":"user","content":"ok"}]}'),
                    ("/anthropic/v1/messages", {}, (b'{"model":"m","messages":[{"role":"user","content":"\\u0073k-ant-api03-' + (b"Z1x2C3v4B5" * 3) + b'"}]}')),
                    ("/anthropic/v1/messages", {}, b"not-json " + ant.encode()),
                ]
                for item in blocked_vectors:
                    path = item[0]
                    hdrs = dict(item[1])
                    b_raw = item[2]
                    if len(item) == 4:
                        hdrs.update(item[3])
                    hdrs.setdefault("Content-Type", "application/json")
                    c_blk = http.client.HTTPConnection("127.0.0.1", px.port, timeout=5)
                    c_blk.request("POST", path, body=b_raw, headers=hdrs)
                    r_blk = c_blk.getresponse()
                    _ = r_blk.read()
                    c_blk.close()
                    self.assertEqual(r_blk.status, 400, f"Expected 400 on {path}")

                # Upstream MUST NOT have received a single blocked request!
                self.assertEqual(len(captured_up), 1)
        finally:
            up_srv.shutdown()
            up_srv.server_close()

    @staticmethod
    def _drain_http_head(conn: object) -> None:
        import socket
        assert isinstance(conn, socket.socket)
        buf = b""
        while b"\r\n\r\n" not in buf:
            ch = conn.recv(4096)
            if not ch:
                break
            buf += ch
        if b"\r\n\r\n" in buf:
            head, rest = buf.split(b"\r\n\r\n", 1)
            cl = 0
            for line in head.decode("latin-1").split("\r\n")[1:]:
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
            while len(rest) < cl:
                ch = conn.recv(4096)
                if not ch:
                    break
                rest += ch

    @staticmethod
    def _extract_delta_indices(buf: bytes, out: dict[int, float], ts: float) -> None:
        import re
        for m in re.finditer(rb'"i":(\d+)', buf):
            idx = int(m.group(1))
            if idx not in out:
                out[idx] = ts

    @staticmethod
    def _wait_for_turn_count(px: object, expected: int) -> list[dict[str, object]]:
        import time
        for _ in range(50):
            turns = px.get_turns()  # type: ignore[attr-defined]
            if len(turns) >= expected:
                return turns
            time.sleep(0.02)
        return px.get_turns()  # type: ignore[attr-defined]

    def test_m1_client_disconnect_chunked_request_and_programmatic_metering_api(self) -> None:
        import socket
        import time
        from agent_xray import XrayProxyServer, start_background_proxy

        self.assertIs(XrayProxyServer, XRayHTTPServer)
        upstream_closed_early = threading.Event()
        chunked_bodies: list[bytes] = []

        class _MultiProtocolUpstream(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                cl = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(cl) if cl else b""
                if self.path == "/v1/chunked-echo":
                    chunked_bodies.append(raw)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return

                payload = json.loads(raw.decode("utf-8"))
                if payload.get("model") == "client-drop-test":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    try:
                        for idx in range(30):
                            self.wfile.write(f'data: {{"i":{idx},"pad":"{"z" * 200}"}}\n\n'.encode("utf-8"))
                            self.wfile.flush()
                            time.sleep(0.03)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        upstream_closed_early.set()
                    return

                if "/messages" in self.path:
                    resp = {
                        "id": "m_1",
                        "usage": {
                            "input_tokens": 100,
                            "cache_read_input_tokens": 400,
                            "cache_creation_input_tokens": 50,
                            "output_tokens": 30,
                        },
                    }
                    b_out = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b_out)))
                    self.end_headers()
                    self.wfile.write(b_out)
                elif "/chat/completions" in self.path:
                    resp = {
                        "id": "c_1",
                        "usage": {
                            "prompt_tokens": 500,
                            "completion_tokens": 60,
                            "prompt_tokens_details": {"cached_tokens": 300},
                        },
                    }
                    b_out = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b_out)))
                    self.end_headers()
                    self.wfile.write(b_out)
                elif "/responses" in self.path and payload.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(
                        b'event: response.output_text.delta\n'
                        b'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
                        b'event: response.completed\n'
                        b'data: {"type":"response.completed","response":{"usage":{"input_tokens":700,"output_tokens":75,"input_tokens_details":{"cached_tokens":500}}}}\n\n'
                    )
                    self.wfile.flush()
                else:
                    resp = {
                        "id": "r_1",
                        "usage": {
                            "input_tokens": 600,
                            "output_tokens": 40,
                            "input_tokens_details": {"cached_tokens": 250},
                        },
                    }
                    b_out = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b_out)))
                    self.end_headers()
                    self.wfile.write(b_out)

        up_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MultiProtocolUpstream)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, daemon=True).start()

        try:
            with start_background_proxy(upstream=f"http://127.0.0.1:{up_port}") as px:
                env = px.agent_env()
                self.assertTrue(env["ANTHROPIC_BASE_URL"].endswith("/anthropic"))
                self.assertTrue(env["OPENAI_BASE_URL"].endswith("/openai/v1"))

                # 1. Client disconnects mid-SSE stream -> proxy cleans up upstream & stays healthy
                drop_sock = socket.create_connection(("127.0.0.1", px.port), timeout=5)
                drop_body = b'{"model":"client-drop-test","stream":true,"messages":[{"role":"user","content":"hi"}]}'
                drop_sock.sendall(
                    f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(drop_body)}\r\n\r\n".encode("utf-8")
                    + drop_body
                )
                _ = drop_sock.recv(512)
                drop_sock.close()
                upstream_closed_early.wait(timeout=2.0)
                self.assertTrue(upstream_closed_early.is_set())
                px.clear()

                # 2. Chunked request body with trailer -> reassembled cleanly for upstream
                chunk_sock = socket.create_connection(("127.0.0.1", px.port), timeout=5)
                p1, p2 = b'{"hello":', b'"chunked"}'
                chunk_wire = (
                    f"POST /openai/v1/chunked-echo HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
                    f"Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n"
                    f"{len(p1):x}\r\n".encode("utf-8")
                    + p1
                    + f"\r\n{len(p2):x}\r\n".encode("utf-8")
                    + p2
                    + b"\r\n0\r\nX-Trailer: done\r\n\r\n"
                )
                chunk_sock.sendall(chunk_wire)
                chunk_resp = b""
                while True:
                    ch = chunk_sock.recv(4096)
                    if not ch:
                        break
                    chunk_resp += ch
                chunk_sock.close()
                self.assertIn(b'{"hello":"chunked"}', chunk_resp)
                self.assertEqual(chunked_bodies, [b'{"hello":"chunked"}'])

                # 3. Four-mode metering across Anthropic, OpenAI Chat, OpenAI Responses JSON & SSE
                reqs = [
                    ("/anthropic/v1/messages", {"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "a"}]}),
                    ("/openai/v1/chat/completions", {"model": "gpt-4o", "messages": [{"role": "user", "content": "b"}]}),
                    ("/openai/v1/responses", {"model": "gpt-5", "input": "c", "stream": False}),
                    ("/openai/v1/responses", {"model": "gpt-5", "input": "d", "stream": True}),
                ]
                for r_path, r_obj in reqs:
                    hc = http.client.HTTPConnection("127.0.0.1", px.port, timeout=5)
                    hc.request("POST", r_path, body=json.dumps(r_obj).encode("utf-8"), headers={"Content-Type": "application/json"})
                    hr = hc.getresponse()
                    _ = hr.read()
                    hc.close()
                    self.assertEqual(hr.status, 200)

                turns = self._wait_for_turn_count(px, 4)
                self.assertEqual(len(turns), 4)
                for tr in turns:
                    self.assertIsNotNone(tr["ttft_ms"])
                    self.assertGreaterEqual(float(tr["ttft_ms"]), 0.0)  # type: ignore[arg-type]

                totals = px.get_totals()
                # input_tokens: 100 + (500-300) + (600-250) + (700-500) = 100 + 200 + 350 + 200 = 850
                # cached_input_tokens: 400 + 300 + 250 + 500 = 1450
                # cache_creation_input_tokens: 50 + 0 + 0 + 0 = 50
                # output_tokens: 30 + 60 + 40 + 75 = 205
                self.assertEqual(totals["turn_count"], 4)
                self.assertEqual(totals["input_tokens"], 850)
                self.assertEqual(totals["cached_input_tokens"], 1450)
                self.assertEqual(totals["cache_creation_input_tokens"], 50)
                self.assertEqual(totals["output_tokens"], 205)
                self.assertEqual(len(totals["ttft_ms_values"]), 4)
        finally:
            up_srv.shutdown()
            up_srv.server_close()

    def test_xr4_no_duplicate_server_date_headers_and_no_forced_accept_encoding_identity(self) -> None:
        import socket
        from agent_xray.proxy import start_background_proxy

        captured_wire_headers: list[list[tuple[str, str]]] = []

        def raw_header_upstream(srv_sock: socket.socket) -> None:
            try:
                # Request 1: upstream returns explicit Server + Date
                c1, _ = srv_sock.accept()
            except OSError:
                return
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += c1.recv(4096)
            head, rest = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")[1:]
            hdrs = [(ln.split(":", 1)[0], ln.split(":", 1)[1].strip()) for ln in lines if ":" in ln]
            captured_wire_headers.append(hdrs)
            cl = next((int(v) for k, v in hdrs if k.lower() == "content-length"), 0)
            while len(rest) < cl:
                rest += c1.recv(4096)
            body1 = b'{"id":"m1","usage":{"input_tokens":10,"output_tokens":2}}'
            c1.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Server: UpstreamEdge/9.1\r\n"
                b"Date: Sat, 14 Nov 2026 20:00:00 GMT\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body1)}\r\n\r\n".encode("ascii")
                + body1
            )
            c1.close()

            try:
                # Request 2: upstream omits both Server and Date
                c2, _ = srv_sock.accept()
            except OSError:
                return
            buf2 = b""
            while b"\r\n\r\n" not in buf2:
                buf2 += c2.recv(4096)
            head2, rest2 = buf2.split(b"\r\n\r\n", 1)
            lines2 = head2.decode("latin-1").split("\r\n")[1:]
            hdrs2 = [(ln.split(":", 1)[0], ln.split(":", 1)[1].strip()) for ln in lines2 if ":" in ln]
            captured_wire_headers.append(hdrs2)
            cl2 = next((int(v) for k, v in hdrs2 if k.lower() == "content-length"), 0)
            while len(rest2) < cl2:
                rest2 += c2.recv(4096)
            body2 = b'{"id":"m2","usage":{"input_tokens":12,"output_tokens":3}}'
            c2.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body2)}\r\n\r\n".encode("ascii")
                + body2
            )
            c2.close()

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(4)
        up_port = srv_sock.getsockname()[1]
        threading.Thread(target=raw_header_upstream, args=(srv_sock,), daemon=True).start()

        try:
            with start_background_proxy(upstream=f"http://127.0.0.1:{up_port}") as px:
                req_body = b'{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}'

                # 1. Client omits Accept-Encoding -> upstream receives NO Accept-Encoding;
                #    client receives exact single Server and single Date header!
                hc1 = http.client.HTTPConnection("127.0.0.1", px.port, timeout=5)
                hc1.putrequest("POST", "/anthropic/v1/messages", skip_accept_encoding=True)
                hc1.putheader("Content-Type", "application/json")
                hc1.putheader("Content-Length", str(len(req_body)))
                hc1.endheaders(req_body)
                r1 = hc1.getresponse()
                _ = r1.read()
                r1_hdrs = r1.getheaders()
                hc1.close()

                up1_names = [k.lower() for k, _ in captured_wire_headers[0]]
                self.assertNotIn("accept-encoding", up1_names)

                server_vals_1 = [v for k, v in r1_hdrs if k.lower() == "server"]
                date_vals_1 = [v for k, v in r1_hdrs if k.lower() == "date"]
                self.assertEqual(server_vals_1, ["UpstreamEdge/9.1"])
                self.assertEqual(date_vals_1, ["Sat, 14 Nov 2026 20:00:00 GMT"])

                # 2. Client sends explicit Accept-Encoding: gzip, br -> forwarded untouched;
                #    upstream omits Date/Server -> proxy adds 1 Date and 0 Server headers!
                hc2 = http.client.HTTPConnection("127.0.0.1", px.port, timeout=5)
                hc2.putrequest("POST", "/anthropic/v1/messages", skip_accept_encoding=True)
                hc2.putheader("Content-Type", "application/json")
                hc2.putheader("Accept-Encoding", "gzip, br")
                hc2.putheader("Content-Length", str(len(req_body)))
                hc2.endheaders(req_body)
                r2 = hc2.getresponse()
                _ = r2.read()
                r2_hdrs = r2.getheaders()
                hc2.close()

                up2_ae = [v for k, v in captured_wire_headers[1] if k.lower() == "accept-encoding"]
                self.assertEqual(up2_ae, ["gzip, br"])
                self.assertEqual([v for k, v in r2_hdrs if k.lower() == "server"], [])
                self.assertEqual(len([v for k, v in r2_hdrs if k.lower() == "date"]), 1)
        finally:
            srv_sock.close()

    def test_xr4_premature_upstream_disconnect_sets_stream_truncated_across_framing_modes(self) -> None:
        import socket
        from agent_xray.proxy import start_background_proxy

        def truncation_upstream(srv_sock: socket.socket) -> None:
            # 1. Complete SSE stream with message_stop -> stream_truncated = False
            c1, _ = srv_sock.accept()
            self._drain_http_head(c1)
            c1.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":50}}}\n\n'
                b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":12}}\n\n'
                b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
            )
            c1.close()

            # 2. Chunked SSE dropping mid-stream without 0\r\n\r\n -> stream_truncated = True
            c2, _ = srv_sock.accept()
            self._drain_http_head(c2)
            ev = b'data: {"type":"content_block_delta","delta":{"text":"partial"}}\n\n'
            c2.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
                + f"{len(ev):x}\r\n".encode("ascii")
                + ev
                + b"\r\n"
            )
            c2.close()

            # 3. Unframed SSE closing TCP without message_stop / [DONE] -> stream_truncated = True
            c3, _ = srv_sock.accept()
            self._drain_http_head(c3)
            c3.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":40}}}\n\n'
                b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"cut"}}\n\n'
            )
            c3.close()

            # 4. Non-SSE JSON with Content-Length: 400 closing after 32 bytes -> stream_truncated = True
            c4, _ = srv_sock.accept()
            self._drain_http_head(c4)
            c4.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n"
                b'{"id":"msg_short","usage":{"inpu'
            )
            c4.close()

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(8)
        up_port = srv_sock.getsockname()[1]
        threading.Thread(target=truncation_upstream, args=(srv_sock,), daemon=True).start()

        try:
            with start_background_proxy(upstream=f"http://127.0.0.1:{up_port}") as px:
                req_body = b'{"model":"claude-sonnet-4-6","stream":true,"messages":[{"role":"user","content":"go"}]}'
                for _ in range(4):
                    s = socket.create_connection(("127.0.0.1", px.port), timeout=5)
                    s.sendall(
                        f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(req_body)}\r\n\r\n".encode("utf-8")
                        + req_body
                    )
                    while s.recv(4096):
                        pass
                    s.close()

                turns = self._wait_for_turn_count(px, 4)
                self.assertEqual([t["stream_truncated"] for t in turns], [False, True, True, True])
                totals = px.get_totals()
                self.assertEqual(totals["truncated_count"], 3)
                self.assertEqual(totals["summary"]["truncated_count"], 3)
        finally:
            srv_sock.close()

    def test_m1_row8_start_background_proxy_spec_signature_parity_loopback_only_and_clean_stop(self) -> None:
        import inspect
        import re
        import socket
        import agent_xray
        from agent_xray.proxy import start_background_proxy

        repo_root = Path(__file__).resolve().parents[1]
        spec_text = (repo_root / "docs" / "SPEC.md").read_text(encoding="utf-8")

        # Parse function name and parameter names directly from docs/SPEC.md §2.2
        m_sig = re.search(r"`(start_background_proxy)\(\*,\s*([^)]+)\)\s*->\s*RunningXRayProxy`", spec_text)
        self.assertIsNotNone(m_sig, "Could not parse start_background_proxy signature from docs/SPEC.md")
        fn_name = m_sig.group(1)
        spec_params = [
            part.strip().split("=", 1)[0].split(":", 1)[0].strip()
            for part in m_sig.group(2).split(",")
            if part.strip()
        ]
        fn = getattr(agent_xray, fn_name)
        self.assertIs(fn, start_background_proxy)
        actual_params = list(inspect.signature(fn).parameters.keys())
        self.assertEqual(actual_params, spec_params)
        self.assertIn("strip_telemetry", actual_params)

        # Enforce strict 127.0.0.1 binding on start_background_proxy
        for forbidden_host in ("0.0.0.0", "localhost", "::1"):
            with self.assertRaises(ValueError):
                fn(host=forbidden_host, auth_token="tok")

        with tempfile.TemporaryDirectory() as tmp:
            db_file = Path(tmp) / "row8.db"
            baseline_threads = {t.ident for t in threading.enumerate()}

            kwargs = {
                "db_path": str(db_file),
                "host": "127.0.0.1",
                "port": 0,
                "store": None,
                "upstream": f"http://127.0.0.1:{self.up_port}",
                "anthropic_upstream": f"http://127.0.0.1:{self.up_port}",
                "openai_upstream": f"http://127.0.0.1:{self.up_port}",
                "strip_telemetry": True,
                "block_secrets": True,
                "store_previews": False,
                "auth_token": "row8-token-1234567890",
            }
            self.assertEqual(set(kwargs.keys()), set(spec_params))

            px = fn(**kwargs)
            bound_port = px.port
            try:
                self.assertEqual(px.host, "127.0.0.1")
                self.assertEqual(px.server.server_address[0], "127.0.0.1")
                self.assertEqual(px.db_path, str(db_file))

                req_body = json.dumps(
                    {
                        "model": "claude-sonnet-4-6",
                        "messages": [{"role": "user", "content": "Row 8 programmatic check"}],
                    }
                ).encode("utf-8")
                hc = http.client.HTTPConnection("127.0.0.1", bound_port, timeout=5)
                hc.request(
                    "POST",
                    "/anthropic/v1/messages",
                    body=req_body,
                    headers={
                        "Content-Type": "application/json",
                        "x-stainless-os": "MacOS",
                    },
                )
                hr = hc.getresponse()
                _ = hr.read()
                hc.close()
                self.assertEqual(hr.status, 200)

                turns = px.get_turns()
                self.assertEqual(len(turns), 1)
                self.assertEqual(turns[0]["input_tokens"], 200)
                self.assertEqual(turns[0]["cached_input_tokens"], 800)
                self.assertEqual(turns[0]["cache_creation_input_tokens"], 100)
                self.assertEqual(turns[0]["output_tokens"], 50)
                self.assertFalse(turns[0]["stream_truncated"])
                self.assertNotIn("x-stainless-os", _FakeUpstream.requests[-1]["headers"])
            finally:
                px.stop()

            # Verify SQLite persisted 1 turn accurately after stop()
            conn = sqlite3.connect(db_file)
            row_count = conn.execute("SELECT COUNT(*) FROM traces").fetchone()[0]
            usage_raw = json.loads(conn.execute("SELECT usage_json FROM traces").fetchone()[0])
            conn.close()
            self.assertEqual(row_count, 1)
            self.assertEqual(usage_raw["input_tokens"], 200)
            self.assertEqual(usage_raw["output_tokens"], 50)

            # Verify port is released immediately after stop()
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", bound_port))
            finally:
                probe.close()

            # Verify 0 leftover background threads
            after_threads = {t.ident for t in threading.enumerate()}
            self.assertEqual(after_threads - baseline_threads, set())

    def test_xr5_proxy_9_and_12_layer_encoded_secrets_placeholder_in_sqlite_and_blocked(self) -> None:
        import urllib.parse
        from agent_xray.proxy import start_background_proxy

        def encode_layers(secret: str, layers: int, full_hex: bool = False) -> str:
            cur = "".join(f"%{ord(ch):02X}" for ch in secret) if full_hex else secret.replace("-", "%2D")
            for _ in range(layers - 1):
                cur = urllib.parse.quote(cur, safe="")
            return cur

        up_hits = 0

        class _XR5Upstream(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                nonlocal up_hits
                cl = int(self.headers.get("Content-Length") or "0")
                if cl:
                    _ = self.rfile.read(cl)
                up_hits += 1
                out = b'{"id":"msg_xr5","usage":{"input_tokens":15,"output_tokens":3}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        up_srv = ThreadingHTTPServer(("127.0.0.1", 0), _XR5Upstream)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as tmp:
                s_test = "sk-test-FAKE1234567890abcdef"
                s_ant = "sk-ant-FAKE00001234567890abcdef"
                body_ok = json.dumps(
                    {"model": "claude-sonnet-4-5", "messages": [{"role": "user", "content": "ping"}]}
                ).encode("utf-8")

                # 1. --block-secrets OFF: 9-layer and 12-layer paths forward (200), but SQLite stores ONLY placeholder path
                db_off = Path(tmp) / "xr5_off.db"
                with start_background_proxy(
                    db_path=db_off,
                    upstream=f"http://127.0.0.1:{up_port}",
                    block_secrets=False,
                    store_previews=True,
                ) as px_off:
                    for depth in (9, 12):
                        for raw_sec, full_hex in [(s_test, False), (s_ant, True)]:
                            enc = encode_layers(raw_sec, depth, full_hex=full_hex)
                            hc = http.client.HTTPConnection("127.0.0.1", px_off.port, timeout=5)
                            hc.request(
                                "POST",
                                f"/anthropic/{enc}/v1/messages",
                                body=body_ok,
                                headers={"Content-Type": "application/json"},
                            )
                            resp = hc.getresponse()
                            _ = resp.read()
                            hc.close()
                            self.assertEqual(resp.status, 200)

                self.assertEqual(up_hits, 4)
                conn_off = sqlite3.connect(str(db_off))
                rows_off = conn_off.execute("SELECT provider, path, status_code, blocked FROM traces").fetchall()
                dump_off = "\n".join(conn_off.iterdump())
                conn_off.close()
                self.assertEqual(len(rows_off), 4)
                for prov, p_stored, code, blk in rows_off:
                    self.assertEqual(prov, "anthropic")
                    self.assertEqual(p_stored, "/[REDACTED_UNCONVERGED_ENCODED_PATH]")
                    self.assertEqual(code, 200)
                    self.assertEqual(blk, 0)
                raw_bytes_off = b"".join(
                    p.read_bytes() for p in [db_off, Path(f"{db_off}-wal"), Path(f"{db_off}-shm")] if p.exists()
                )
                for needle in ("FAKE1234567890abcdef", "FAKE00001234567890abcdef", "%2525", "73%25"):
                    self.assertNotIn(needle, dump_off)
                    self.assertNotIn(needle.encode("utf-8"), raw_bytes_off)

                # 2. --block-secrets ON: 9-layer, 12-layer, and 17-layer paths/queries rejected with HTTP 400 (upstream=0)
                up_hits = 0
                db_on = Path(tmp) / "xr5_on.db"
                with start_background_proxy(
                    db_path=db_on,
                    upstream=f"http://127.0.0.1:{up_port}",
                    block_secrets=True,
                ) as px_on:
                    for depth in (9, 12, 17):
                        for raw_sec, full_hex in [(s_test, False), (s_ant, True)]:
                            enc = encode_layers(raw_sec, depth, full_hex=full_hex)
                            hc = http.client.HTTPConnection("127.0.0.1", px_on.port, timeout=5)
                            hc.request(
                                "POST",
                                f"/anthropic/{enc}/v1/messages",
                                body=body_ok,
                                headers={"Content-Type": "application/json"},
                            )
                            resp = hc.getresponse()
                            err_raw = resp.read().decode("utf-8", errors="replace")
                            hc.close()
                            self.assertEqual(resp.status, 400, f"Expected 400 at depth={depth} full_hex={full_hex}")
                            self.assertNotIn("FAKE1234567890abcdef", err_raw)
                            self.assertNotIn("%2525", err_raw)

                    # Query string at 9 and 12 layers also rejected with HTTP 400
                    for depth in (9, 12):
                        enc_q = encode_layers(s_test, depth, full_hex=False)
                        hc = http.client.HTTPConnection("127.0.0.1", px_on.port, timeout=5)
                        hc.request(
                            "POST",
                            f"/anthropic/v1/messages?api_key={enc_q}",
                            body=body_ok,
                            headers={"Content-Type": "application/json"},
                        )
                        resp = hc.getresponse()
                        _ = resp.read()
                        hc.close()
                        self.assertEqual(resp.status, 400)

                self.assertEqual(up_hits, 0)
                conn_on = sqlite3.connect(str(db_on))
                rows_on = conn_on.execute("SELECT provider, path, status_code, blocked FROM traces ORDER BY id").fetchall()
                dump_on = "\n".join(conn_on.iterdump())
                conn_on.close()
                self.assertEqual(len(rows_on), 8)
                for prov, p_stored, code, blk in rows_on[:6]:
                    self.assertEqual(prov, "anthropic")
                    self.assertEqual(p_stored, "/[REDACTED_UNCONVERGED_ENCODED_PATH]")
                    self.assertEqual(code, 400)
                    self.assertEqual(blk, 1)
                for prov, p_stored, code, blk in rows_on[6:]:
                    self.assertEqual(prov, "anthropic")
                    self.assertEqual(p_stored, "/anthropic/v1/messages")
                    self.assertEqual(code, 400)
                    self.assertEqual(blk, 1)
                raw_bytes_on = b"".join(
                    p.read_bytes() for p in [db_on, Path(f"{db_on}-wal"), Path(f"{db_on}-shm")] if p.exists()
                )
                for needle in ("FAKE1234567890abcdef", "FAKE00001234567890abcdef", "%2525", "73%25"):
                    self.assertNotIn(needle, dump_on)
                    self.assertNotIn(needle.encode("utf-8"), raw_bytes_on)
        finally:
            up_srv.shutdown()
            up_srv.server_close()

    def test_xr6_three_independent_truncation_paths_and_inspector_html_warnings(self) -> None:
        import socket
        from agent_xray.proxy import start_background_proxy
        from agent_xray.store import build_demo_dataset
        from agent_xray.ui_html import render_inspector_html

        def orthogonal_truncation_upstream(srv_sock: socket.socket) -> None:
            # Turn 1 (Control): complete SSE with message_stop -> stream_truncated = False
            c1, _ = srv_sock.accept()
            self._drain_http_head(c1)
            c1.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":100}}}\n\n'
                b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":20}}\n\n'
                b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
            )
            c1.close()

            # Turn 2 (Path 1 ONLY - usage_parser.is_truncated):
            # Unframed SSE closes cleanly at EOF without message_stop / [DONE] (no Content-Length, no read error)
            c2, _ = srv_sock.accept()
            self._drain_http_head(c2)
            c2.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":120}}}\n\n'
                b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"half"}}\n\n'
            )
            c2.close()

            # Turn 3 (Path 2 ONLY - Content-Length shortfall):
            # Sends syntactically complete JSON (59 bytes) so usage_parser.is_truncated is False,
            # and closes cleanly so read1 returns b"" without exception, while Content-Length declares 500!
            c3, _ = srv_sock.accept()
            self._drain_http_head(c3)
            valid_json_short = b'{"id":"m_cl","usage":{"input_tokens":50,"output_tokens":5}}'
            c3.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n"
                + valid_json_short
            )
            c3.close()

            # Turn 4 (Path 3 ONLY - mid-stream broken chunked / abnormal disconnect):
            # Chunk 1 contains syntactically complete JSON so usage_parser.is_truncated is False,
            # Content-Length is absent, and trailing broken chunk header without 0\r\n\r\n raises in read1!
            c4, _ = srv_sock.accept()
            self._drain_http_head(c4)
            valid_json_chunk = b'{"id":"m_ch","usage":{"input_tokens":40,"output_tokens":8}}'
            c4.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                + f"{len(valid_json_chunk):x}\r\n".encode("ascii")
                + valid_json_chunk
                + b"\r\nZZZZ_BROKEN_CHUNK\r\n"
            )
            c4.close()

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(8)
        up_port = srv_sock.getsockname()[1]
        threading.Thread(target=orthogonal_truncation_upstream, args=(srv_sock,), daemon=True).start()

        try:
            with start_background_proxy(upstream=f"http://127.0.0.1:{up_port}") as px:
                req_body = b'{"model":"claude-sonnet-4-5","stream":true,"messages":[{"role":"user","content":"test"}]}'
                for _ in range(4):
                    s = socket.create_connection(("127.0.0.1", px.port), timeout=5)
                    s.sendall(
                        f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{px.port}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(req_body)}\r\n\r\n".encode("utf-8")
                        + req_body
                    )
                    try:
                        while s.recv(4096):
                            pass
                    except OSError:
                        pass
                    s.close()

                turns = self._wait_for_turn_count(px, 4)
                self.assertEqual([t["stream_truncated"] for t in turns], [False, True, True, True])
                dataset = px.get_totals()
                self.assertEqual(dataset["summary"]["truncated_count"], 3)

                html_en = render_inspector_html(dataset, lang="en")
                html_zh = render_inspector_html(dataset, lang="zh")

                # Static SSR & client I18N must surface truncated badge, count, turn numbers, and incomplete cost note
                self.assertIn('id="truncation-notice" class="alert-banner">', html_en)
                self.assertIn("[TRUNCATED]", html_en)
                self.assertIn("usage &amp; cost incomplete", html_en)
                for turn_ref in ("#2", "#3", "#4"):
                    self.assertIn(turn_ref, html_en)

                self.assertIn('id="truncation-notice" class="alert-banner">', html_zh)
                self.assertIn("[流已截断]", html_zh)
                self.assertIn("用量与费用不完整", html_zh)
                for turn_ref in ("#2", "#3", "#4"):
                    self.assertIn(turn_ref, html_zh)

                # Healthy demo dataset (truncated_count == 0) keeps notice hidden
                demo_html = render_inspector_html(build_demo_dataset(), lang="en")
                self.assertIn('id="truncation-notice" class="alert-banner" hidden>', demo_html)
        finally:
            srv_sock.close()

    def test_xr7_server_close_joins_live_handler_threads_before_returning(self) -> None:
        import socket
        import time
        from agent_xray.proxy import start_background_proxy

        with start_background_proxy() as px:
            # Open a client socket and send an incomplete HTTP request line (no \r\n\r\n),
            # keeping the spawned handler thread alive in parse_request() outside _inflight_count.
            slow_client = socket.create_connection(("127.0.0.1", px.port), timeout=5)
            slow_client.sendall(b"POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1")

            deadline = time.monotonic() + 2.0
            live_handlers: list[threading.Thread] = []
            while time.monotonic() < deadline:
                with px.server._threads_lock:
                    live_handlers = [th for th in px.server._handler_threads if th.is_alive()]
                if live_handlers:
                    break
                time.sleep(0.01)
            self.assertEqual(len(live_handlers), 1)
            handler_thread = live_handlers[0]
            self.assertTrue(handler_thread.is_alive())

            # First stop the accept loop (`shutdown()` polls at 0.5s), then verify handler_thread
            # is STILL alive right before `server_close()` is invoked!
            px.server.shutdown()
            self.assertTrue(handler_thread.is_alive())

            entering_close = threading.Event()

            def _release_client_during_server_close() -> None:
                entering_close.wait(timeout=2.0)
                time.sleep(0.12)
                try:
                    slow_client.close()
                except OSError:
                    pass

            releaser = threading.Thread(target=_release_client_during_server_close, daemon=True)
            releaser.start()

            # Because XRayHTTPServer sets daemon_threads = True, stdlib ThreadingMixIn.server_close()
            # skips joining threads; XRayHTTPServer.server_close() MUST join handler_thread itself!
            entering_close.set()
            px.server.server_close()
            try:
                self.assertFalse(
                    handler_thread.is_alive(),
                    "XRayHTTPServer.server_close() returned while handler_thread was still alive!",
                )
            finally:
                slow_client.close()
                releaser.join(timeout=1.0)

    def test_xr7_cli_serve_vs_start_background_proxy_side_by_side_parity(self) -> None:
        import os
        import signal
        import socket
        import subprocess
        import sys
        import time
        from agent_xray.proxy import start_background_proxy

        upstream_records: list[tuple[str, dict[str, str], bytes]] = []
        rec_lock = threading.Lock()

        def parity_upstream(srv_sock: socket.socket) -> None:
            while True:
                try:
                    conn_s, _ = srv_sock.accept()
                except OSError:
                    break
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        ch = conn_s.recv(1024)
                        if not ch:
                            break
                        buf += ch
                    if b"\r\n\r\n" not in buf:
                        conn_s.close()
                        continue
                    head_b, rest_b = buf.split(b"\r\n\r\n", 1)
                    lines = head_b.decode("iso-8859-1").split("\r\n")
                    req_path = lines[0].split(" ")[1]
                    hdr_map: dict[str, str] = {}
                    cl = 0
                    for ln in lines[1:]:
                        if ":" in ln:
                            k, v = ln.split(":", 1)
                            hdr_map[k.strip().lower()] = v.strip()
                            if k.strip().lower() == "content-length":
                                cl = int(v.strip())
                    while len(rest_b) < cl:
                        ch = conn_s.recv(min(4096, cl - len(rest_b)))
                        if not ch:
                            break
                        rest_b += ch
                    for hk in ("host", "content-length", "accept-encoding", "connection"):
                        hdr_map.pop(hk, None)
                    with rec_lock:
                        upstream_records.append((req_path, hdr_map, rest_b))

                    payload = json.loads(rest_b.decode("utf-8"))
                    tag = str(payload.get("user") or "")
                    if tag == "sse_ok":
                        conn_s.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                            b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":80,"cache_read_input_tokens":20}}}\n\n'
                            b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":15}}\n\n'
                            b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
                        )
                    elif tag == "sse_trunc":
                        conn_s.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                            b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":60}}}\n\n'
                        )
                    else:
                        out = json.dumps(
                            {"id": "m_par", "usage": {"input_tokens": 110, "cache_read_input_tokens": 40, "output_tokens": 22}}
                        ).encode("utf-8")
                        conn_s.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + f"Content-Length: {len(out)}\r\n\r\n".encode("ascii")
                            + out
                        )
                finally:
                    conn_s.close()

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(16)
        up_port = srv_sock.getsockname()[1]
        threading.Thread(target=parity_upstream, args=(srv_sock,), daemon=True).start()

        def _send_four_requests(port: int) -> list[int]:
            fake_key = "sk-ant-FAKE00001234567890abcdef"
            cases = [
                # 1. Normal JSON with telemetry header (stripped) + auth header (redacted)
                (
                    "/anthropic/v1/messages",
                    {"model": "claude-sonnet-4-5", "user": "json_ok", "messages": [{"role": "user", "content": "hello"}]},
                    {"Content-Type": "application/json", "x-api-key": fake_key, "x-stainless-os": "Darwin"},
                ),
                # 2. Streaming SSE
                (
                    "/anthropic/v1/messages",
                    {"model": "claude-sonnet-4-5", "stream": True, "user": "sse_ok", "messages": [{"role": "user", "content": "stream"}]},
                    {"Content-Type": "application/json", "x-api-key": fake_key},
                ),
                # 3. Prematurely truncated SSE stream
                (
                    "/anthropic/v1/messages",
                    {"model": "claude-sonnet-4-5", "stream": True, "user": "sse_trunc", "messages": [{"role": "user", "content": "trunc"}]},
                    {"Content-Type": "application/json", "x-api-key": fake_key},
                ),
                # 4. Leaked secret in body blocked with HTTP 400 under --block-secrets
                (
                    "/anthropic/v1/messages",
                    {"model": "claude-sonnet-4-5", "user": "blocked_leak", "messages": [{"role": "user", "content": f"leak {fake_key}"}]},
                    {"Content-Type": "application/json"},
                ),
            ]
            statuses: list[int] = []
            for path, obj, hdrs in cases:
                raw_b = json.dumps(obj).encode("utf-8")
                hc = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                hc.request("POST", path, body=raw_b, headers=hdrs)
                r = hc.getresponse()
                _ = r.read()
                statuses.append(r.status)
                hc.close()
            return statuses

        def _read_normalized_db_rows(db_p: Path) -> list[tuple[object, ...]]:
            conn = sqlite3.connect(str(db_p))
            rows = conn.execute(
                "SELECT provider, model, path, status_code, blocked, stream_truncated, "
                "buckets_json, namespaces_json, usage_json, headers_json, secrets_json, prompt_preview "
                "FROM traces ORDER BY id"
            ).fetchall()
            conn.close()
            return rows

        try:
            with tempfile.TemporaryDirectory() as tmp:
                repo_root = Path(__file__).resolve().parents[1]
                cli_db = Path(tmp) / "cli_serve.db"
                prog_db = Path(tmp) / "prog_api.db"

                # Pick free loopback port for CLI `serve`
                ephem = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ephem.bind(("127.0.0.1", 0))
                cli_port = ephem.getsockname()[1]
                ephem.close()

                env_cli = os.environ.copy()
                env_cli["PYTHONPATH"] = str(repo_root / "src")
                cli_proc = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "agent_xray.cli",
                        "--lang",
                        "en",
                        "serve",
                        "--port",
                        str(cli_port),
                        "--db",
                        str(cli_db),
                        "--upstream",
                        f"http://127.0.0.1:{up_port}",
                        "--strip-telemetry-headers",
                        "--block-secrets",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env_cli,
                )
                try:
                    # Wait for CLI proxy socket to accept connections
                    ready = False
                    for _ in range(100):
                        try:
                            probe = socket.create_connection(("127.0.0.1", cli_port), timeout=0.2)
                            probe.close()
                            ready = True
                            break
                        except OSError:
                            time.sleep(0.03)
                    self.assertTrue(ready, "CLI `agent-xray serve` did not start in time")

                    cli_statuses = _send_four_requests(cli_port)
                    with rec_lock:
                        cli_upstream = list(upstream_records)
                        upstream_records.clear()
                finally:
                    cli_proc.send_signal(signal.SIGINT)
                    cli_proc.communicate(timeout=5)

                with start_background_proxy(
                    db_path=prog_db,
                    upstream=f"http://127.0.0.1:{up_port}",
                    strip_telemetry=True,
                    block_secrets=True,
                ) as px_prog:
                    prog_statuses = _send_four_requests(px_prog.port)
                    _ = self._wait_for_turn_count(px_prog, 4)
                    with rec_lock:
                        prog_upstream = list(upstream_records)
                        upstream_records.clear()

                self.assertEqual(cli_statuses, [200, 200, 200, 400])
                self.assertEqual(prog_statuses, cli_statuses)
                self.assertEqual(cli_upstream, prog_upstream)
                self.assertEqual(_read_normalized_db_rows(cli_db), _read_normalized_db_rows(prog_db))

                # Also compare secret-redacted HTTP 200 mode (`--store-previews`, no `--block-secrets`)
                cli_red_db = Path(tmp) / "cli_redact.db"
                prog_red_db = Path(tmp) / "prog_redact.db"
                ephem2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ephem2.bind(("127.0.0.1", 0))
                cli_port2 = ephem2.getsockname()[1]
                ephem2.close()

                fake_key = "sk-ant-FAKE00001234567890abcdef"
                red_body = json.dumps(
                    {
                        "model": "claude-sonnet-4-5",
                        "user": "redact_200",
                        "messages": [{"role": "user", "content": f"inline key {fake_key}"}],
                    }
                ).encode("utf-8")
                red_path = f"/anthropic/{fake_key}/v1/messages"

                cli_proc2 = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "agent_xray.cli",
                        "--lang",
                        "en",
                        "serve",
                        "--port",
                        str(cli_port2),
                        "--db",
                        str(cli_red_db),
                        "--upstream",
                        f"http://127.0.0.1:{up_port}",
                        "--strip-telemetry-headers",
                        "--store-previews",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env_cli,
                )
                try:
                    for _ in range(100):
                        try:
                            pr = socket.create_connection(("127.0.0.1", cli_port2), timeout=0.2)
                            pr.close()
                            break
                        except OSError:
                            time.sleep(0.03)
                    hc_c = http.client.HTTPConnection("127.0.0.1", cli_port2, timeout=5)
                    hc_c.request("POST", red_path, body=red_body, headers={"Content-Type": "application/json", "x-stainless-os": "Darwin"})
                    rc_c = hc_c.getresponse()
                    _ = rc_c.read()
                    hc_c.close()
                    self.assertEqual(rc_c.status, 200)
                    with rec_lock:
                        cli_red_up = list(upstream_records)
                        upstream_records.clear()
                finally:
                    cli_proc2.send_signal(signal.SIGINT)
                    cli_proc2.communicate(timeout=5)

                with start_background_proxy(
                    db_path=prog_red_db,
                    upstream=f"http://127.0.0.1:{up_port}",
                    strip_telemetry=True,
                    block_secrets=False,
                    store_previews=True,
                ) as px_red:
                    hc_p = http.client.HTTPConnection("127.0.0.1", px_red.port, timeout=5)
                    hc_p.request("POST", red_path, body=red_body, headers={"Content-Type": "application/json", "x-stainless-os": "Darwin"})
                    rc_p = hc_p.getresponse()
                    _ = rc_p.read()
                    hc_p.close()
                    self.assertEqual(rc_p.status, 200)
                    _ = self._wait_for_turn_count(px_red, 1)
                    with rec_lock:
                        prog_red_up = list(upstream_records)
                        upstream_records.clear()

                self.assertEqual(cli_red_up, prog_red_up)
                self.assertEqual(_read_normalized_db_rows(cli_red_db), _read_normalized_db_rows(prog_red_db))
        finally:
            srv_sock.close()


if __name__ == "__main__":
    unittest.main()
