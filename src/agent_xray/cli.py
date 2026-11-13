"""Command-line entrypoint for agent-xray (`run`, `serve`, `export-demo`, `desktop`, `report`)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .i18n import SUPPORTED_LANG_CHOICES, resolve_lang
from .local_sessions import import_local_desktop_sessions
from .proxy import ProxyConfig, XRayHTTPServer
from .store import TraceStore, build_demo_dataset
from .ui_html import render_inspector_html


def _print_terminal_summary(store: TraceStore, lang: str = "en") -> None:
    is_zh = lang == "zh"
    data = store.build_summary()
    s = data["summary"]
    if s["turn_count"] == 0:
        msg = (
            "[agent-xray] 本次会话未捕获到任何 API 请求轮次。"
            if is_zh
            else "[agent-xray] No API turns captured during session."
        )
        print(msg, file=sys.stderr)
        return
    bt = s["bucket_totals"]
    tot = max(1, s["total_estimated_input"])
    mcp_pct = round(bt["mcp_and_tools"] / tot * 100)
    cost = float(s.get("estimated_cost_usd", 0.0))
    if is_zh:
        print(
            f"\n[agent-xray] 会话摘要：共 {s['turn_count']} 轮 | "
            f"约 {s['total_estimated_input']:,} 输入 tok（MCP 定义占 {mcp_pct}%）| "
            f"{s['total_cache_read']:,} 缓存命中 | "
            f"预估成本 ${cost:.4f} | "
            f"剥离 {s['stripped_header_count']} 个遥测请求头 | "
            f"拦截 {s['blocked_count']} 次密钥外泄",
            file=sys.stderr,
        )
        for ns in data["top_namespaces"][:5]:
            print(
                f"  - {ns['namespace']:<18} {ns['max_tools']:>3} 个工具   "
                f"{ns['per_turn_tokens']:>7,} tok/轮",
                file=sys.stderr,
            )
        return

    print(
        f"\n[agent-xray] Session summary: {s['turn_count']} turns | "
        f"~{s['total_estimated_input']:,} prompt tok ({mcp_pct}% MCP schemas) | "
        f"{s['total_cache_read']:,} cache hits | "
        f"${cost:.4f} est | "
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
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    is_zh = lang == "zh"
    host = "0.0.0.0" if args.allow_lan else "127.0.0.1"
    store = TraceStore(args.db)
    cfg = ProxyConfig(
        host=host,
        port=args.port,
        strip_telemetry_headers=args.strip_telemetry_headers,
        block_secrets=args.block_secrets,
        lang=raw_lang,
    )
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    if is_zh:
        print(f"agent-xray 正在监听 http://{host}:{bound_port}")
        print(f"  实时火焰图工作台 : http://127.0.0.1:{bound_port}/_xray/")
    else:
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
        _print_terminal_summary(store, lang=lang)
        store.close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    is_zh = lang == "zh"
    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        msg = (
            "错误：请指定要包装执行的命令，例如 `agent-xray run -- claude`"
            if is_zh
            else "Error: specify a command to wrap, e.g. `agent-xray run -- claude`"
        )
        print(msg, file=sys.stderr)
        return 2

    store = TraceStore(args.db)
    cfg = ProxyConfig(
        host="127.0.0.1",
        port=args.port,
        strip_telemetry_headers=args.strip_telemetry_headers,
        block_secrets=args.block_secrets,
        lang=raw_lang,
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
    if is_zh:
        print(
            f"[agent-xray] 实时上下文火焰图：http://127.0.0.1:{bound_port}/_xray/ | 正在启动 {' '.join(cmd)}",
            file=sys.stderr,
        )
    else:
        print(
            f"[agent-xray] Live Flamegraph UI: http://127.0.0.1:{bound_port}/_xray/ - launching {' '.join(cmd)}",
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
        _print_terminal_summary(store, lang=lang)
        store.close()


def cmd_export_demo(args: argparse.Namespace) -> int:
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html = render_inspector_html(build_demo_dataset(), live_poll=False, lang=raw_lang)
    out_path.write_text(html, encoding="utf-8")
    if lang == "zh":
        print(f"已导出静态演示检查器至 {out_path}")
    else:
        print(f"Wrote static demo inspector to {out_path}")
    return 0


def cmd_desktop(args: argparse.Namespace) -> int:
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    is_zh = lang == "zh"
    store = TraceStore(":memory:")
    count = import_local_desktop_sessions(store, max_turns=args.limit)
    if is_zh:
        print(
            f"[agent-xray] 已导入 {count} 条近期本地桌面会话轮次（OpenCode Desktop 与 Claude）。",
            file=sys.stderr,
        )
    else:
        print(
            f"[agent-xray] Imported {count} recent Desktop/local turns (OpenCode Desktop & Claude).",
            file=sys.stderr,
        )
    cfg = ProxyConfig(host="127.0.0.1", port=args.port, lang=raw_lang)
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    url = f"http://127.0.0.1:{bound_port}/_xray/"
    if is_zh:
        print(f"  实时火焰图工作台 : {url}", file=sys.stderr)
    else:
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
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    store = TraceStore(args.db)
    _print_terminal_summary(store, lang=lang)
    store.close()
    return 0


def _add_subparser_lang_arg(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--lang",
        choices=SUPPORTED_LANG_CHOICES,
        default=argparse.SUPPRESS,
        help="Output & Web UI default language: auto (AGENT_XRAY_LANG / LANG), zh, or en.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-xray",
        description="Zero-MITM-cert local context token flamegraph & outbound privacy proxy for AI coding agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--lang",
        choices=SUPPORTED_LANG_CHOICES,
        default="auto",
        help="Output & Web UI default language: auto (AGENT_XRAY_LANG / LANG), zh, or en.",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    for name, fn, help_txt in (
        ("serve", cmd_serve, "Start standalone loopback proxy & live inspector"),
        ("run", cmd_run, "Wrap a coding agent CLI command with automatic BASE_URL injection"),
    ):
        p = sub.add_parser(name, help=help_txt)
        _add_subparser_lang_arg(p)
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
    _add_subparser_lang_arg(p_demo)
    p_demo.add_argument("--out", type=str, default="docs/demo-inspector.html", help="Output HTML file path")
    p_demo.set_defaults(func=cmd_export_demo)

    p_desk = sub.add_parser("desktop", help="Inspect local OpenCode Desktop & Claude sessions without proxy setup")
    _add_subparser_lang_arg(p_desk)
    p_desk.add_argument("--port", type=int, default=0, help="Loopback TCP port (0 = ephemeral)")
    p_desk.add_argument("--limit", type=int, default=24, help="Maximum recent local turns to import")
    p_desk.add_argument("--open", dest="open_ui", action="store_true", help="Automatically open the UI in your default browser")
    p_desk.set_defaults(func=cmd_desktop)

    p_rep = sub.add_parser("report", help="Print terminal summary from an existing SQLite trace DB")
    _add_subparser_lang_arg(p_rep)
    p_rep.add_argument("--db", type=str, default=None, help="Path to SQLite trace database")
    p_rep.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
