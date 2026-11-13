"""Loopback HTTP/SSE streaming passthrough proxy for Anthropic & OpenAI coding agents."""

from __future__ import annotations

import http.client
import json
import os
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .classifier import classify_request_payload, parse_usage_from_response
from .local_sessions import import_local_desktop_sessions
from .privacy import audit_and_prepare_headers, scan_body_for_secrets
from .store import TraceStore
from .ui_html import render_inspector_html


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8788
    anthropic_upstream: str = os.environ.get("AGENT_XRAY_ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
    openai_upstream: str = os.environ.get("AGENT_XRAY_OPENAI_UPSTREAM", "https://api.openai.com")
    strip_telemetry_headers: bool = False
    block_secrets: bool = False
    lang: str = "auto"


class XRayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: ProxyConfig, store: TraceStore) -> None:
        self.xray_config = config
        self.trace_store = store
        super().__init__((config.host, config.port), XRayRequestHandler)


class XRayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
        req_lang = (qs.get("lang") or [cfg.lang])[0]

        if parsed.path in ("/_xray", "/_xray/"):
            data = self.server.trace_store.build_summary()  # type: ignore[attr-defined]
            html = render_inspector_html(data, live_poll=True, lang=req_lang).encode("utf-8")
            self._send_bytes(200, "text/html; charset=utf-8", html)
            return
        if parsed.path.startswith("/_xray/api/summary"):
            data = self.server.trace_store.build_summary()  # type: ignore[attr-defined]
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", body)
            return
        if parsed.path.startswith("/_xray/api/traces"):
            traces = self.server.trace_store.list_traces()  # type: ignore[attr-defined]
            body = json.dumps({"traces": traces}, ensure_ascii=False).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", body)
            return
        self._forward_upstream("GET")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/_xray/api/scan-desktop":
            _ = self._read_request_body()
            store: TraceStore = self.server.trace_store  # type: ignore[attr-defined]
            imported = import_local_desktop_sessions(store, max_turns=16)
            payload = store.build_summary()
            payload["imported"] = imported
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", body)
            return
        self._forward_upstream("POST")

    def do_PUT(self) -> None:
        self._forward_upstream("PUT")

    def do_PATCH(self) -> None:
        self._forward_upstream("PATCH")

    def do_HEAD(self) -> None:
        self._forward_upstream("HEAD")

    def do_OPTIONS(self) -> None:
        self._forward_upstream("OPTIONS")

    def do_DELETE(self) -> None:
        self._forward_upstream("DELETE")

    def _read_request_body(self) -> bytes:
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            chunks = bytearray()
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                size_str = line.split(b";", 1)[0].strip()
                if not size_str:
                    continue
                size = int(size_str, 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.extend(self.rfile.read(size))
                self.rfile.read(2)  # trailing CRLF
            return bytes(chunks)
        content_len = int(self.headers.get("Content-Length") or "0")
        return self.rfile.read(content_len) if content_len > 0 else b""

    @staticmethod
    def _is_llm_turn_endpoint(method: str, raw_path: str) -> bool:
        if method.upper() != "POST":
            return False
        clean = raw_path.split("?", 1)[0].rstrip("/").lower()
        if clean.endswith("/count_tokens"):
            return False
        return clean.endswith(
            (
                "/v1/messages",
                "/v1/chat/completions",
                "/v1/responses",
                "/v1/completions",
            )
        )

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _resolve_upstream(self) -> tuple[str, str]:
        cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
        if self.path.startswith("/anthropic/") or self.path == "/anthropic":
            sub = self.path[len("/anthropic") :] or "/"
            return cfg.anthropic_upstream, sub
        if self.path.startswith("/openai/") or self.path == "/openai":
            sub = self.path[len("/openai") :] or "/"
            return cfg.openai_upstream, sub
        has_anthropic_hdr = (
            "anthropic-version" in self.headers
            or "anthropic-beta" in self.headers
            or "x-api-key" in self.headers
            or "sk-ant-" in (self.headers.get("Authorization") or "")
        )
        if has_anthropic_hdr or "/v1/messages" in self.path or self.path.startswith("/api/"):
            return cfg.anthropic_upstream, self.path
        return cfg.openai_upstream, self.path

    def _forward_upstream(self, method: str) -> None:
        t0 = time.monotonic()
        cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
        store: TraceStore = self.server.trace_store  # type: ignore[attr-defined]

        req_body = self._read_request_body()
        is_turn = self._is_llm_turn_endpoint(method, self.path)

        outbound_headers, header_audit = audit_and_prepare_headers(
            self.headers.items(),
            strip_telemetry=cfg.strip_telemetry_headers,
        )

        payload_dict: dict[str, Any] | None = None
        raw_text = ""
        if req_body and is_turn:
            raw_text = req_body.decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw_text)
                if isinstance(parsed, dict):
                    payload_dict = parsed
            except Exception:
                payload_dict = None

        classification = (
            classify_request_payload(self.path, payload_dict)
            if (is_turn and payload_dict is not None)
            else None
        )
        secret_findings = scan_body_for_secrets(raw_text) if raw_text else []

        if cfg.block_secrets and secret_findings:
            latency_ms = int((time.monotonic() - t0) * 1000)
            if classification is not None:
                store.record_turn(
                    provider=classification.provider,
                    model=classification.model,
                    path=self.path,
                    status_code=400,
                    latency_ms=latency_ms,
                    blocked=True,
                    buckets=classification.buckets.to_dict(),
                    tool_namespaces=[ns.to_dict() for ns in classification.tool_namespaces],
                    usage={"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0},
                    header_audit=[h.to_dict() for h in header_audit],
                    secret_findings=[s.to_dict() for s in secret_findings],
                    prompt_preview=classification.prompt_preview,
                )
            err_payload = {
                "type": "error",
                "error": {
                    "type": "agent_xray_secret_egress_blocked",
                    "message": (
                        f"Blocked outbound request containing {len(secret_findings)} credential pattern(s): "
                        + ", ".join(f"{s.rule} ({s.redacted_snippet})" for s in secret_findings)
                    ),
                },
            }
            self._send_bytes(400, "application/json", json.dumps(err_payload).encode("utf-8"))
            return

        upstream_base, sub_path = self._resolve_upstream()
        parsed_up = urllib.parse.urlsplit(upstream_base)
        base_prefix = parsed_up.path.rstrip("/")
        target_path = f"{base_prefix}{sub_path}" if sub_path.startswith("/") else f"{base_prefix}/{sub_path}"

        outbound_headers["Host"] = parsed_up.netloc
        outbound_headers["Accept-Encoding"] = "identity"
        if req_body:
            outbound_headers["Content-Length"] = str(len(req_body))

        conn: http.client.HTTPConnection
        if parsed_up.scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(parsed_up.hostname or "", parsed_up.port or 443, context=ctx, timeout=180)
        else:
            conn = http.client.HTTPConnection(parsed_up.hostname or "127.0.0.1", parsed_up.port or 80, timeout=180)

        captured_resp = bytearray()
        status_code = 502
        is_sse = False
        try:
            conn.request(method, target_path, body=req_body if req_body else None, headers=outbound_headers)
            up_resp = conn.getresponse()
            status_code = up_resp.status
            resp_ct = up_resp.getheader("Content-Type") or "application/octet-stream"
            is_sse = "text/event-stream" in resp_ct.lower()

            self.send_response(status_code)
            skip_resp_hdrs = {"transfer-encoding", "connection", "keep-alive", "content-length"}
            for hk, hv in up_resp.getheaders():
                if hk.lower() in skip_resp_hdrs:
                    continue
                self.send_header(hk, hv)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()

            while True:
                chunk = up_resp.read(1024 if is_sse else 8192)
                if not chunk:
                    break
                if len(captured_resp) < 524_288:
                    captured_resp.extend(chunk)
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception as exc:
            err = json.dumps({"error": f"Upstream connection failed: {exc}"}).encode("utf-8")
            try:
                self._send_bytes(502, "application/json", err)
            except Exception:
                pass
        finally:
            conn.close()

        latency_ms = int((time.monotonic() - t0) * 1000)
        if classification is not None:
            usage = parse_usage_from_response(bytes(captured_resp), is_sse=is_sse)
            store.record_turn(
                provider=classification.provider,
                model=classification.model,
                path=self.path,
                status_code=status_code,
                latency_ms=latency_ms,
                blocked=False,
                buckets=classification.buckets.to_dict(),
                tool_namespaces=[ns.to_dict() for ns in classification.tool_namespaces],
                usage=usage,
                header_audit=[h.to_dict() for h in header_audit],
                secret_findings=[s.to_dict() for s in secret_findings],
                prompt_preview=classification.prompt_preview,
            )
