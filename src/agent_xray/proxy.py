"""Loopback HTTP/SSE passthrough proxy for Anthropic & OpenAI coding agents."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import secrets
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .classifier import classify_request_payload, parse_usage_from_response
from .local_sessions import import_local_desktop_sessions
from .privacy import audit_and_prepare_headers, normalize_trace_path, redact_secrets_in_text, scan_payload_for_secrets
from .store import TraceStore
from .ui_html import render_inspector_html

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8788
    anthropic_upstream: str = field(
        default_factory=lambda: os.environ.get("AGENT_XRAY_ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
    )
    openai_upstream: str = field(
        default_factory=lambda: os.environ.get("AGENT_XRAY_OPENAI_UPSTREAM", "https://api.openai.com")
    )
    strip_telemetry_headers: bool = False
    block_secrets: bool = False
    store_previews: bool = False
    allow_lan: bool = False
    auth_token: str = ""
    desktop_home: Path | None = None
    lang: str = "auto"


class XRayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: ProxyConfig, store: TraceStore) -> None:
        is_loopback = config.host in _LOOPBACK_HOSTS
        if (config.allow_lan or not is_loopback) and not config.auth_token.strip():
            raise ValueError(
                "--allow-lan (or non-loopback bind) requires an explicit --auth-token"
            )
        if not config.auth_token.strip():
            config.auth_token = secrets.token_urlsafe(24)
        self.xray_config = config
        self.trace_store = store
        super().__init__((config.host, config.port), XRayRequestHandler)


class XRayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    @staticmethod
    def _is_inspector_path(path_only: str) -> bool:
        return path_only == "/" or path_only == "/_xray" or path_only.startswith("/_xray/")

    @staticmethod
    def _is_ip_host(raw_host: str, bound_port: int) -> bool:
        if not raw_host:
            return False
        host_part = raw_host
        port_part: str | None = None
        if raw_host.startswith("["):
            if "]" not in raw_host:
                return False
            end_idx = raw_host.index("]")
            host_part = raw_host[1:end_idx]
            rest = raw_host[end_idx + 1 :]
            if rest.startswith(":"):
                port_part = rest[1:]
            elif rest:
                return False
        elif ":" in raw_host:
            host_part, port_part = raw_host.rsplit(":", 1)

        if port_part is not None and port_part != str(bound_port):
            return False
        try:
            ipaddress.ip_address(host_part)
            return True
        except ValueError:
            return False

    def _send_json_error(self, status: int, message: str) -> None:
        body = json.dumps({"error": message}, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", body)

    def _extract_auth_token(self, query_params: dict[str, list[str]] | None = None) -> str:
        hdr_tok = (self.headers.get("X-Xray-Token") or "").strip()
        if hdr_tok:
            return hdr_tok
        auth_hdr = (self.headers.get("Authorization") or "").strip()
        if auth_hdr.lower().startswith("bearer "):
            return auth_hdr[7:].strip()
        if self.command == "GET" and query_params:
            q_tok = (query_params.get("token") or [""])[0].strip()
            if q_tok:
                return q_tok
        return ""

    def _check_inspector_access(
        self,
        *,
        require_token: bool,
        query_params: dict[str, list[str]] | None = None,
    ) -> bool:
        cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
        bound_port = int(self.server.server_address[1])
        raw_host = (self.headers.get("Host") or "").strip().lower()

        loopback_hosts = {
            "127.0.0.1",
            "localhost",
            "[::1]",
            f"127.0.0.1:{bound_port}",
            f"localhost:{bound_port}",
            f"[::1]:{bound_port}",
        }
        is_lan_mode = bool(cfg.allow_lan or cfg.host not in _LOOPBACK_HOSTS)

        if not is_lan_mode:
            if raw_host not in loopback_hosts:
                self._send_json_error(403, "Forbidden: invalid Host header for loopback inspector")
                return False
        else:
            cfg_h = cfg.host.lower()
            configured_hosts = {cfg_h, f"{cfg_h}:{bound_port}"} if cfg_h != "0.0.0.0" else set()
            if (
                raw_host not in loopback_hosts
                and raw_host not in configured_hosts
                and not self._is_ip_host(raw_host, bound_port)
            ):
                self._send_json_error(403, "Forbidden: invalid Host header")
                return False

        allowed_origins = {
            f"http://127.0.0.1:{bound_port}",
            f"http://localhost:{bound_port}",
            f"http://[::1]:{bound_port}",
        }
        if bound_port == 80:
            allowed_origins.update({"http://127.0.0.1", "http://localhost", "http://[::1]"})
        if is_lan_mode and raw_host:
            allowed_origins.add(f"http://{raw_host}")

        origin = (self.headers.get("Origin") or "").strip().lower().rstrip("/")
        if origin:
            if origin not in allowed_origins:
                self._send_json_error(403, "Forbidden: cross-origin Origin rejected")
                return False
        elif self.command != "GET":
            referer = (self.headers.get("Referer") or "").strip()
            if referer:
                ref_parts = urllib.parse.urlsplit(referer)
                ref_origin = f"{ref_parts.scheme.lower()}://{ref_parts.netloc.lower()}".rstrip("/")
                if ref_origin not in allowed_origins:
                    self._send_json_error(403, "Forbidden: cross-origin Referer rejected")
                    return False

        if require_token or is_lan_mode:
            candidate = self._extract_auth_token(query_params)
            if not candidate:
                self._send_json_error(401, "Unauthorized: X-Xray-Token or Bearer token required")
                return False
            if not secrets.compare_digest(candidate, cfg.auth_token):
                self._send_json_error(403, "Forbidden: invalid authentication token")
                return False

        return True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            qs = urllib.parse.parse_qs(parsed.query)
            if not self._check_inspector_access(require_token=False, query_params=qs):
                return
            cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
            req_lang = (qs.get("lang") or [cfg.lang])[0]

            if parsed.path in ("/", "/_xray", "/_xray/"):
                data = self.server.trace_store.build_summary()  # type: ignore[attr-defined]
                html = render_inspector_html(
                    data,
                    live_poll=True,
                    lang=req_lang,
                    auth_token=cfg.auth_token,
                ).encode("utf-8")
                self._send_bytes(200, "text/html; charset=utf-8", html)
                return
            if parsed.path == "/_xray/api/summary":
                data = self.server.trace_store.build_summary()  # type: ignore[attr-defined]
                body = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", body)
                return
            if parsed.path == "/_xray/api/traces":
                traces = self.server.trace_store.list_traces()  # type: ignore[attr-defined]
                body = json.dumps({"traces": traces}, ensure_ascii=False).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", body)
                return
            self._send_json_error(404, "Not found")
            return
        self._forward_upstream("GET")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            _ = self._read_request_body()
            if not self._check_inspector_access(require_token=True):
                return
            cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
            store: TraceStore = self.server.trace_store  # type: ignore[attr-defined]
            if parsed.path == "/_xray/api/scan-desktop":
                imported = import_local_desktop_sessions(
                    store,
                    home=cfg.desktop_home,
                    max_turns=16,
                    store_previews=cfg.store_previews,
                )
                payload = store.build_summary()
                payload["imported"] = imported
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", body)
                return
            if parsed.path == "/_xray/api/clear":
                if hasattr(store, "clear"):
                    store.clear()
                payload = store.build_summary()
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", body)
                return
            self._send_json_error(404, "Not found")
            return
        self._forward_upstream("POST")

    def do_PUT(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            _ = self._read_request_body()
            if not self._check_inspector_access(require_token=True):
                return
            self._send_json_error(405, "Method not allowed")
            return
        self._forward_upstream("PUT")

    def do_PATCH(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            _ = self._read_request_body()
            if not self._check_inspector_access(require_token=True):
                return
            self._send_json_error(405, "Method not allowed")
            return
        self._forward_upstream("PATCH")

    def do_HEAD(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            if not self._check_inspector_access(require_token=False):
                return
            self._send_bytes(200, "text/plain; charset=utf-8", b"")
            return
        self._forward_upstream("HEAD")

    def do_OPTIONS(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            if not self._check_inspector_access(require_token=False):
                return
            self._send_bytes(204, "text/plain; charset=utf-8", b"")
            return
        self._forward_upstream("OPTIONS")

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if self._is_inspector_path(parsed.path):
            _ = self._read_request_body()
            if not self._check_inspector_access(require_token=True):
                return
            self._send_json_error(405, "Method not allowed")
            return
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
        stored_path = normalize_trace_path(self.path)
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
            classify_request_payload(
                stored_path,
                payload_dict,
                store_previews=cfg.store_previews,
            )
            if (is_turn and payload_dict is not None)
            else None
        )
        secret_findings = (
            scan_payload_for_secrets(payload_dict, raw_fallback=raw_text)
            if raw_text
            else []
        )

        if cfg.block_secrets and secret_findings:
            latency_ms = int((time.monotonic() - t0) * 1000)
            provider = classification.provider if classification is not None else (
                "anthropic" if ("anthropic" in stored_path.lower() or "messages" in stored_path.lower()) else "openai"
            )
            model = classification.model if classification is not None else "unknown"
            store.record_turn(
                provider=provider,
                model=model,
                path=stored_path,
                status_code=400,
                latency_ms=latency_ms,
                blocked=True,
                buckets={
                    "system_prompt": 0,
                    "workspace_rules": 0,
                    "mcp_and_tools": 0,
                    "tool_results": 0,
                    "conversation": 0,
                    "total_estimated": 0,
                },
                tool_namespaces=[],
                usage={"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0},
                header_audit=[h.to_dict() for h in header_audit],
                secret_findings=[s.to_dict() for s in secret_findings],
                prompt_preview="",
                store_previews=False,
            )
            err_payload = {
                "type": "error",
                "error": {
                    "type": "agent_xray_secret_egress_blocked",
                    "message": (
                        f"Blocked outbound request containing {len(secret_findings)} credential pattern(s): "
                        + ", ".join(
                            f"{redact_secrets_in_text(s.rule)} (in {redact_secrets_in_text(s.field)})"
                            for s in secret_findings
                        )
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
                path=stored_path,
                status_code=status_code,
                latency_ms=latency_ms,
                blocked=False,
                buckets=classification.buckets.to_dict(),
                tool_namespaces=[ns.to_dict() for ns in classification.tool_namespaces],
                usage=usage,
                header_audit=[h.to_dict() for h in header_audit],
                secret_findings=[s.to_dict() for s in secret_findings],
                prompt_preview=classification.prompt_preview,
                store_previews=cfg.store_previews,
            )
