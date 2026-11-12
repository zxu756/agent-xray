"""Command-line entrypoint for agent-xray (`run`, `serve`, `export-demo`, `report`)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from .local_sessions import import_local_desktop_sessions
from .proxy import ProxyConfig, XRayHTTPServer
from .store import TraceStore, build_demo_dataset
from .ui_html import render_inspector_html


def _print_terminal_summary(store: TraceStore) -> None:
    data = store.build_summary()
    s = data["summary"]
    if s["turn_count"] == 0:
        print("[agent-xray] No API turns captured during session.", file=sys.stderr)
        return
    bt = s["bucket_totals"]
    tot = max(1, s["total_estimated_input"])
    mcp_pct = round(bt["mcp_and_tools"] / tot * 100)
    print(
        f"\n[agent-xray] Session summary: {s['turn_count']} turns | "
        f"~{s['total_estimated_input']:,} prompt tok ({mcp_pct}% MCP schemas) | "
        f"{s['total_cache_read']:,} cache hits | "
        f"{s['stripped_header_count']} telemetry headers stripped | "
        f"{s['blocked_count']} blocked leaks",
        file=sys.stderr,
    )
    for ns in data["top_namespaces"][:5]:
        print(
            f"  - {ns['namespace']:<18} {ns['max_tools']:>3} tools   "
            f"{ns['per_turn_tokens']:>7,} tok/turn",
            file=sys.stderr,
        )


def cmd_serve(args: argparse.Namespace) -> int:
    host = "0.0.0.0" if args.allow_lan else "127.0.0.1"
    store = TraceStore(args.db)
    cfg = ProxyConfig(
        host=host,
        port=args.port,
        strip_telemetry_headers=args.strip_telemetry_headers,
        block_secrets=args.block_secrets,
    )
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    print(f"agent-xray listening on http://{host}:{bound_port}")
    print(f"  Live Inspector UI : http://127.0.0.1:{bound_port}/_xray/")
    print(f"  ANTHROPIC_BASE_URL=http://127.0.0.1:{bound_port}/anthropic")
    print(f"  OPENAI_BASE_URL=http://127.0.0.1:{bound_port}/openai/v1")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        _print_terminal_summary(store)
        store.close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: specify a command to wrap, e.g. `agent-xray run -- claude`", file=sys.stderr)
        return 2

    store = TraceStore(args.db)
    cfg = ProxyConfig(
        host="127.0.0.1",
        port=args.port,
        strip_telemetry_headers=args.strip_telemetry_headers,
        block_secrets=args.block_secrets,
    )
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    env = os.environ.copy()
    env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{bound_port}"
    env["OPENAI_BASE_URL"] = f"http://127.0.0.1:{bound_port}/openai/v1"
    existing_no_proxy = env.get("NO_PROXY") or env.get("no_proxy") or ""
    loopback_entries = "127.0.0.1,localhost,::1"
    merged_no_proxy = f"{existing_no_proxy},{loopback_entries}".strip(",")
    env["NO_PROXY"] = merged_no_proxy
    env["no_proxy"] = merged_no_proxy
    print(
        f"[agent-xray] Live Flamegraph UI: http://127.0.0.1:{bound_port}/_xray/ — launching {' '.join(cmd)}",
        file=sys.stderr,
    )
    if args.open_ui:
        webbrowser.open(f"http://127.0.0.1:{bound_port}/_xray/")
    try:
        completed = subprocess.run(cmd, env=env)
        return int(completed.returncode)
    finally:
        srv.shutdown()
        srv.server_close()
        _print_terminal_summary(store)
        store.close()


def cmd_export_demo(args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html = render_inspector_html(build_demo_dataset(), live_poll=False)
    out_path.write_text(html, encoding="utf-8")
    print(f"Wrote static demo inspector to {out_path}")
    return 0


def cmd_desktop(args: argparse.Namespace) -> int:
    store = TraceStore(":memory:")
    count = import_local_desktop_sessions(store, max_turns=args.limit)
    print(f"[agent-xray] Imported {count} recent Desktop/local turns (OpenCode Desktop & Claude).", file=sys.stderr)
    cfg = ProxyConfig(host="127.0.0.1", port=args.port)
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    url = f"http://127.0.0.1:{bound_port}/_xray/"
    print(f"  Live Inspector UI : {url}", file=sys.stderr)
    if args.open_ui:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        store.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = TraceStore(args.db)
    _print_terminal_summary(store)
    store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-xray",
        description="Zero-MITM-cert local context token flamegraph & outbound privacy proxy for AI coding agents.",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    for name, fn, help_txt in (
        ("serve", cmd_serve, "Start standalone loopback proxy & live inspector"),
        ("run", cmd_run, "Wrap a coding agent CLI command with automatic BASE_URL injection"),
    ):
        p = sub.add_parser(name, help=help_txt)
        p.add_argument("--port", type=int, default=8788 if name == "serve" else 0, help="Loopback TCP port (0 = ephemeral)")
        p.add_argument("--db", type=str, default=None, help="Path to SQLite trace database")
        p.add_argument("--strip-telemetry-headers", action="store_true", help="Strip SDK telemetry headers and normalize User-Agent")
        p.add_argument("--block-secrets", action="store_true", help="Abort requests containing live API keys or private keys before upstream egress")
        p.add_argument("--open", dest="open_ui", action="store_true", help="Automatically open the live Flamegraph UI in your default browser")
        if name == "serve":
            p.add_argument("--allow-lan", action="store_true", help="Bind 0.0.0.0 instead of 127.0.0.1")
        else:
            p.add_argument("command", nargs=argparse.REMAINDER, help="Agent command after `--`")
        p.set_defaults(func=fn)

    p_demo = sub.add_parser("export-demo", help="Export a self-contained static HTML demo inspector")
    p_demo.add_argument("--out", type=str, default="docs/demo-inspector.html", help="Output HTML file path")
    p_demo.set_defaults(func=cmd_export_demo)

    p_desk = sub.add_parser("desktop", help="Inspect local OpenCode Desktop & Claude sessions without proxy setup")
    p_desk.add_argument("--port", type=int, default=0, help="Loopback TCP port (0 = ephemeral)")
    p_desk.add_argument("--limit", type=int, default=24, help="Maximum recent local turns to import")
    p_desk.add_argument("--open", dest="open_ui", action="store_true", help="Automatically open the UI in your default browser")
    p_desk.set_defaults(func=cmd_desktop)

    p_rep = sub.add_parser("report", help="Print terminal summary from an existing SQLite trace DB")
    p_rep.add_argument("--db", type=str, default=None, help="Path to SQLite trace database")
    p_rep.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
