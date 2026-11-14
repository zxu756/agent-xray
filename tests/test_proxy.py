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

                        # Also send a clean-body request with query secret so even when
                        # block_secrets=True it records a non-blocked turn testing path query stripping
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
                        self.assertEqual(r2.status, 200)

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


if __name__ == "__main__":
    unittest.main()
