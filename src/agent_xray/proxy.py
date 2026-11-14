"""Loopback HTTP/SSE passthrough proxy for Anthropic & OpenAI coding agents."""

from __future__ import annotations

from collections.abc import Mapping
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .classifier import IncrementalResponseUsageParser, classify_request_payload
from .local_sessions import import_local_desktop_sessions
from .privacy import (
    SecretFinding,
    audit_and_prepare_headers,
    normalize_trace_path,
    redact_secrets_in_text,
    scan_request_for_secrets,
)
from .store import TraceStore
from .ui_html import render_inspector_html

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_STREAM_READ_SIZE = 4096


def validate_upstream_url(url: str) -> str:
    """Validates an upstream HTTP(S) base URL and strips trailing slashes."""
    cleaned = (url or "").strip()
    parts = urllib.parse.urlsplit(cleaned)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(
            f"Invalid upstream URL {url!r}: expected http:// or https:// with hostname"
        )
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid upstream URL port in {url!r}") from exc
    return cleaned.rstrip("/") if parts.path in ("", "/") and not parts.query else cleaned


def _join_upstream_path(base_prefix: str, base_query: str, sub_path: str) -> str:
    """Joins upstream base URL path prefix with incoming request path without /v1/v1 duplication."""
    sub_parts = urllib.parse.urlsplit(sub_path)
    sub_only = sub_parts.path or "/"
    if not sub_only.startswith("/"):
        sub_only = "/" + sub_only

    bp = base_prefix.rstrip("/")
    if bp.endswith("/v1") and (sub_only == "/v1" or sub_only.startswith("/v1/")):
        sub_only = sub_only[3:] or "/"

    joined_path = f"{bp}{sub_only}" if bp else sub_only
    if base_query and sub_parts.query:
        joined_query = f"{base_query}&{sub_parts.query}"
    else:
        joined_query = base_query or sub_parts.query
    return f"{joined_path}?{joined_query}" if joined_query else joined_path


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8788
    anthropic_upstream: str = field(
        default_factory=lambda: os.environ.get(
            "AGENT_XRAY_ANTHROPIC_UPSTREAM", "https://api.anthropic.com"
        )
    )
    openai_upstream: str = field(
        default_factory=lambda: os.environ.get(
            "AGENT_XRAY_OPENAI_UPSTREAM", "https://api.openai.com"
        )
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
        config.anthropic_upstream = validate_upstream_url(config.anthropic_upstream)
        config.openai_upstream = validate_upstream_url(config.openai_upstream)
        if not config.auth_token.strip():
            config.auth_token = secrets.token_urlsafe(24)
        self.xray_config = config
        self.trace_store = store
        self._inflight_cond = threading.Condition()
        self._inflight_count = 0
        self._threads_lock = threading.Lock()
        self._handler_threads: list[threading.Thread] = []
        super().__init__((config.host, config.port), XRayRequestHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        t = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            daemon=True,
        )
        with self._threads_lock:
            self._handler_threads = [th for th in self._handler_threads if th.is_alive()]
            self._handler_threads.append(t)
        t.start()

    def server_close(self) -> None:
        super().server_close()
        cur = threading.current_thread()
        with self._threads_lock:
            pending = list(self._handler_threads)
            self._handler_threads.clear()
        for th in pending:
            if th is not cur and th.is_alive():
                th.join(timeout=2.0)

    def begin_inflight(self) -> None:
        with self._inflight_cond:
            self._inflight_count += 1

    def end_inflight(self) -> None:
        with self._inflight_cond:
            self._inflight_count = max(0, self._inflight_count - 1)
            if self._inflight_count == 0:
                self._inflight_cond.notify_all()

    def wait_for_inflight(self, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._inflight_cond:
            while self._inflight_count > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._inflight_cond.wait(timeout=remaining)
            return True


# Canonical alias for downstream programmatic callers (e.g. skill-arena M1).
XrayProxyServer = XRayHTTPServer


@dataclass
class RunningXRayProxy:
    """Programmatic handle to a background XRayHTTPServer instance and its TraceStore."""

    server: XRayHTTPServer
    store: TraceStore
    thread: threading.Thread
    owns_store: bool = False
    _stopped: bool = field(default=False, init=False, repr=False)

    @property
    def host(self) -> str:
        addr_host = str(self.server.server_address[0])
        return "127.0.0.1" if addr_host in ("0.0.0.0", "") else addr_host

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def db_path(self) -> str:
        return self.store.db_path

    @property
    def base_url(self) -> str:
        h = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"http://{h}:{self.port}"

    @property
    def anthropic_base_url(self) -> str:
        return f"{self.base_url}/anthropic"

    @property
    def openai_base_url(self) -> str:
        return f"{self.base_url}/openai/v1"

    @property
    def auth_token(self) -> str:
        return self.server.xray_config.auth_token

    def agent_env(self, base_env: Mapping[str, str] | None = None) -> dict[str, str]:
        """Returns an environment dictionary routing Anthropic & OpenAI SDKs through this proxy."""
        env = dict(base_env) if base_env is not None else {}
        env["ANTHROPIC_BASE_URL"] = self.anthropic_base_url
        env["OPENAI_BASE_URL"] = self.openai_base_url
        return env

    def get_turns(self, limit: int = 500) -> list[dict[str, Any]]:
        self.server.wait_for_inflight(timeout=1.0)
        return self.store.list_traces(limit=limit)

    def get_traces(self, limit: int = 500) -> list[dict[str, Any]]:
        self.server.wait_for_inflight(timeout=1.0)
        return self.store.list_traces(limit=limit)

    def get_totals(self, limit: int = 500) -> dict[str, Any]:
        self.server.wait_for_inflight(timeout=1.0)
        data = self.store.build_summary(limit=limit)
        s = data["summary"]
        turns = data["traces"]
        ttft_vals = [
            float(t["ttft_ms"])
            for t in turns
            if isinstance(t.get("ttft_ms"), (int, float)) and not t.get("blocked")
        ]
        return {
            "turn_count": s["turn_count"],
            "blocked_count": s["blocked_count"],
            "truncated_count": s["truncated_count"],
            "input_tokens": s["total_actual_input"],
            "cached_input_tokens": s["total_cache_read"],
            "cache_creation_input_tokens": s["total_cache_write"],
            "output_tokens": s["total_output_tokens"],
            "estimated_cost_usd": s["estimated_cost_usd"],
            "cache_hit_ratio": s["cache_hit_ratio"],
            "ttft_ms_values": ttft_vals,
            "min_ttft_ms": min(ttft_vals) if ttft_vals else None,
            "max_ttft_ms": max(ttft_vals) if ttft_vals else None,
            "summary": s,
            "turns": turns,
        }

    def clear(self) -> None:
        self.store.clear()

    def reset(self) -> None:
        self.store.clear()

    def close(self) -> None:
        self.stop()

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        try:
            self.server.wait_for_inflight(timeout=2.0)
            self.server.shutdown()
        finally:
            self.server.server_close()
            self.thread.join(timeout=3.0)
            if self.owns_store:
                self.store.close()

    def __enter__(self) -> RunningXRayProxy:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


def start_background_proxy(
    *,
    db_path: str | Path | None = ":memory:",
    host: str = "127.0.0.1",
    port: int = 0,
    store: TraceStore | None = None,
    upstream: str | None = None,
    anthropic_upstream: str | None = None,
    openai_upstream: str | None = None,
    strip_telemetry: bool = False,
    block_secrets: bool = False,
    store_previews: bool = False,
    auth_token: str = "",
) -> RunningXRayProxy:
    """Starts an XRayHTTPServer bound strictly to 127.0.0.1 on a background thread."""
    if host != "127.0.0.1":
        raise ValueError(
            f"start_background_proxy binds strictly to '127.0.0.1' (got {host!r})"
        )
    owns_store = store is None
    active_store = store if store is not None else TraceStore(db_path if db_path is not None else ":memory:")
    ant_up = (
        anthropic_upstream
        or upstream
        or os.environ.get("AGENT_XRAY_ANTHROPIC_UPSTREAM")
        or "https://api.anthropic.com"
    )
    oai_up = (
        openai_upstream
        or upstream
        or os.environ.get("AGENT_XRAY_OPENAI_UPSTREAM")
        or "https://api.openai.com"
    )
    cfg = ProxyConfig(
        host=host,
        port=port,
        anthropic_upstream=ant_up,
        openai_upstream=oai_up,
        strip_telemetry_headers=strip_telemetry,
        block_secrets=block_secrets,
        store_previews=store_previews,
        auth_token=auth_token,
    )
    try:
        srv = XRayHTTPServer(cfg, active_store)
    except Exception:
        if owns_store:
            active_store.close()
        raise
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return RunningXRayProxy(
        server=srv,
        store=active_store,
        thread=thread,
        owns_store=owns_store,
    )


class XRayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

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
                self.server.wait_for_inflight(timeout=0.5)  # type: ignore[attr-defined]
                data = self.server.trace_store.build_summary()  # type: ignore[attr-defined]
                body = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", body)
                return
            if parsed.path == "/_xray/api/traces":
                self.server.wait_for_inflight(timeout=0.5)  # type: ignore[attr-defined]
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
                    # Consume optional trailer headers up to terminating blank line
                    while True:
                        trailer = self.rfile.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
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
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
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

    @staticmethod
    def _infer_provider(stored_path: str, headers: Any) -> str:
        lp = stored_path.lower()
        if "anthropic" in lp or "/messages" in lp or "x-api-key" in headers or "anthropic-version" in headers:
            return "anthropic"
        return "openai"

    def _forward_upstream(self, method: str) -> None:
        self.server.begin_inflight()  # type: ignore[attr-defined]
        try:
            self._forward_upstream_inner(method)
        finally:
            self.server.end_inflight()  # type: ignore[attr-defined]

    def _forward_upstream_inner(self, method: str) -> None:
        t0 = time.monotonic()
        cfg: ProxyConfig = self.server.xray_config  # type: ignore[attr-defined]
        store: TraceStore = self.server.trace_store  # type: ignore[attr-defined]

        req_body = self._read_request_body()
        stored_path = normalize_trace_path(self.path)
        is_turn = self._is_llm_turn_endpoint(method, self.path)
        inbound_pairs = list(self.headers.items())
        req_encoding = self.headers.get("Content-Encoding")

        outbound_headers, header_audit = audit_and_prepare_headers(
            inbound_pairs,
            strip_telemetry=cfg.strip_telemetry_headers,
        )

        # Scan ALL endpoints across path, query, non-auth headers, and (decompressed) body
        scan_res = scan_request_for_secrets(
            raw_path=self.path,
            headers=inbound_pairs,
            raw_body=req_body,
            content_encoding=req_encoding,
        )
        secret_findings = list(scan_res.findings)
        if cfg.block_secrets and scan_res.compression_error and not secret_findings:
            secret_findings.append(
                SecretFinding(
                    rule=f"Uninspectable Compressed Body ({scan_res.compression_error})",
                    field="header.Content-Encoding",
                )
            )

        payload_dict = scan_res.parsed_payload if isinstance(scan_res.parsed_payload, dict) else None
        classification = (
            classify_request_payload(
                stored_path,
                payload_dict,
                store_previews=cfg.store_previews,
            )
            if (is_turn and payload_dict is not None)
            else None
        )

        if cfg.block_secrets and secret_findings:
            latency_ms = int((time.monotonic() - t0) * 1000)
            provider = (
                classification.provider
                if classification is not None
                else self._infer_provider(stored_path, self.headers)
            )
            model = (
                classification.model
                if classification is not None
                else str((payload_dict or {}).get("model") or "unknown")
            )
            store.record_turn(
                provider=provider,
                model=model,
                path=stored_path,
                status_code=400,
                latency_ms=latency_ms,
                ttft_ms=None,
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
        target_path = _join_upstream_path(parsed_up.path, parsed_up.query, sub_path)

        conn: http.client.HTTPConnection
        if parsed_up.scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(
                parsed_up.hostname or "",
                parsed_up.port or 443,
                context=ctx,
                timeout=180,
            )
        else:
            conn = http.client.HTTPConnection(
                parsed_up.hostname or "127.0.0.1",
                parsed_up.port or 80,
                timeout=180,
            )

        status_code = 502
        is_sse = False
        headers_sent = False
        stream_truncated = False
        raw_bytes_read = 0
        expected_content_length: int | None = None
        ttft_ms: float | None = None
        usage_parser: IncrementalResponseUsageParser | None = None

        try:
            conn.connect()
            if conn.sock is not None:
                try:
                    conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass

            conn.putrequest(
                method,
                target_path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            conn.putheader("Host", parsed_up.netloc)
            for h_name, h_val in outbound_headers.pairs():
                conn.putheader(h_name, h_val)
            if req_body:
                conn.putheader("Content-Length", str(len(req_body)))
            elif method.upper() in ("POST", "PUT", "PATCH") and (
                "content-length" in self.headers or "transfer-encoding" in self.headers
            ):
                conn.putheader("Content-Length", "0")
            conn.endheaders(req_body if req_body else None)

            up_resp = conn.getresponse()
            status_code = up_resp.status
            resp_ct = up_resp.getheader("Content-Type") or "application/octet-stream"
            resp_ce = up_resp.getheader("Content-Encoding") or ""
            resp_te = (up_resp.getheader("Transfer-Encoding") or "").lower()
            is_sse = "text/event-stream" in resp_ct.lower()
            raw_cl = up_resp.getheader("Content-Length")
            if raw_cl is not None and "chunked" not in resp_te:
                try:
                    parsed_cl = int(raw_cl.strip())
                    if parsed_cl >= 0:
                        expected_content_length = parsed_cl
                except ValueError:
                    pass

            if classification is not None and status_code < 400 and method.upper() != "HEAD":
                usage_parser = IncrementalResponseUsageParser(
                    is_sse=is_sse,
                    content_encoding=resp_ce,
                )

            self.close_connection = True
            self.send_response_only(status_code, up_resp.reason or None)
            up_headers = up_resp.getheaders()
            if not any(hk.lower() == "date" for hk, _ in up_headers):
                self.send_header("Date", self.date_time_string())
            skip_resp_hdrs = {"transfer-encoding", "connection", "keep-alive"}
            if is_sse or "chunked" in resp_te:
                skip_resp_hdrs.add("content-length")
            for hk, hv in up_headers:
                if hk.lower() in skip_resp_hdrs:
                    continue
                self.send_header(hk, hv)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()
            headers_sent = True

            if method.upper() != "HEAD":
                read_chunk = getattr(up_resp, "read1", None)
                if read_chunk is None and getattr(up_resp, "fp", None) is not None:
                    read_chunk = getattr(up_resp.fp, "read1", None)
                while True:
                    chunk = (
                        read_chunk(_STREAM_READ_SIZE)
                        if read_chunk is not None
                        else up_resp.read(_STREAM_READ_SIZE)
                    )
                    if not chunk:
                        break
                    raw_bytes_read += len(chunk)
                    if ttft_ms is None:
                        ttft_ms = round((time.monotonic() - t0) * 1000.0, 3)
                    if usage_parser is not None:
                        usage_parser.feed(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                if (
                    expected_content_length is not None
                    and raw_bytes_read < expected_content_length
                ):
                    stream_truncated = True
        except Exception as exc:
            self.close_connection = True
            if headers_sent:
                stream_truncated = True
            else:
                err = json.dumps(
                    {"error": f"Upstream connection failed: {redact_secrets_in_text(str(exc))}"}
                ).encode("utf-8")
                try:
                    self._send_bytes(502, "application/json", err)
                except Exception:
                    pass
            # Once response headers have been flushed to the client, NEVER write
            # "HTTP/1.1 502..." or JSON error bytes into the middle of the stream.
        finally:
            try:
                conn.close()
            except Exception:
                pass

        latency_ms = int((time.monotonic() - t0) * 1000)
        if classification is not None:
            if usage_parser is not None:
                usage = usage_parser.finish()
                if usage_parser.is_truncated:
                    stream_truncated = True
            else:
                usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0}
            store.record_turn(
                provider=classification.provider,
                model=classification.model,
                path=stored_path,
                status_code=status_code,
                latency_ms=latency_ms,
                ttft_ms=ttft_ms,
                blocked=False,
                stream_truncated=stream_truncated,
                buckets=classification.buckets.to_dict(),
                tool_namespaces=[ns.to_dict() for ns in classification.tool_namespaces],
                usage=usage,
                header_audit=[h.to_dict() for h in header_audit],
                secret_findings=[s.to_dict() for s in secret_findings],
                prompt_preview=classification.prompt_preview,
                store_previews=cfg.store_previews,
            )
