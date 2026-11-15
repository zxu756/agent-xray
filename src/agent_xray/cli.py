"""Command-line entrypoint for agent-xray (`run`, `serve`, `export-demo`, `desktop`, `report`, `purge-db`)."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .i18n import HONEST_LABELS, SUPPORTED_LANG_CHOICES, format_usd, resolve_lang
from .local_sessions import import_local_desktop_sessions
from .proxy import ProxyConfig, XRayHTTPServer, validate_upstream_url
from .store import TraceStore, build_demo_dataset, purge_trace_db
from .ui_html import render_inspector_html


def _format_summary_cost(summary: dict[str, object], lang: str) -> str:
    labels = HONEST_LABELS[lang]
    est_cost = summary.get("estimated_cost_usd")
    unknown_turns = int(summary.get("unknown_price_turn_count") or 0)
    truncated_turns = int(summary.get("truncated_count") or 0)
    pricing_date = str(summary.get("pricing_date") or "unverified")
    inc_note = labels["truncated_incomplete_note"]
    if est_cost is None:
        if truncated_turns > 0:
            return f"{labels['unknown_price']}（{inc_note}）" if lang == "zh" else f"{labels['unknown_price']} ({inc_note})"
        return labels["unknown_price"]
    base = format_usd(float(est_cost))
    if unknown_turns > 0:
        detail = f"+{unknown_turns} 轮{labels['unknown_price']}" if lang == "zh" else f"+{unknown_turns} {labels['unknown_price']}"
    elif pricing_date == "unverified":
        detail = "未核对" if lang == "zh" else "unverified"
    else:
        detail = pricing_date
    if truncated_turns > 0:
        detail = f"{detail}；{inc_note}" if lang == "zh" else f"{detail}; {inc_note}"
    return f"{base}（{detail}）" if lang == "zh" else f"{base} ({detail})"


def _print_startup_token(token: str, lang: str) -> None:
    if lang == "zh":
        print(f"[agent-xray] 启动鉴权令牌（X-Xray-Token）：{token}", file=sys.stderr)
    else:
        print(f"[agent-xray] Startup auth token (X-Xray-Token): {token}", file=sys.stderr)


def _print_terminal_summary(store: TraceStore, lang: str = "en") -> None:
    is_zh = lang == "zh"
    labels = HONEST_LABELS["zh" if is_zh else "en"]
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

    has_any_buckets = any(bool(t.get("has_bucket_breakdown", True)) for t in data["traces"])
    est_input = int(s["total_estimated_input"])
    tool_def_tok = int(s["tool_definition_tokens"])
    mcp_share_pct = round(float(s["mcp_tool_share"]) * 100)

    cache_denom = int(s["total_actual_input"]) + int(s["total_cache_read"]) + int(s["total_cache_write"])
    hit_pct = round(float(s["cache_hit_ratio"]) * 100)
    cost_str = _format_summary_cost(s, "zh" if is_zh else "en")
    truncated_count = int(s.get("truncated_count") or 0)
    truncated_traces = [t for t in data["traces"] if bool(t.get("stream_truncated"))]

    if is_zh:
        if has_any_buckets and est_input > 0:
            tool_str = f"{labels['tool_definition_tokens']}：{tool_def_tok:,} / ~{est_input:,} tok（{labels['estimated']}）"
            mcp_str = f"{labels['mcp_tool_share']}：{mcp_share_pct}%（{labels['estimated']}）"
        else:
            tool_str = f"{labels['tool_definition_tokens']}：{labels['no_data']}"
            mcp_str = f"{labels['mcp_tool_share']}：{labels['no_data']}"
        trunc_part_zh = f" | {labels['truncated_streams']}：{truncated_count}" if truncated_count > 0 else ""
        print(
            f"\n[agent-xray] 会话摘要：共 {s['turn_count']} 轮 | "
            f"{tool_str} | {mcp_str} | "
            f"{labels['cache_hit_rate']}：{hit_pct}%（{s['total_cache_read']:,} / {cache_denom:,} tok）| "
            f"估算费用：{cost_str} | "
            f"{labels['stripped_telemetry_headers']}：{s['stripped_header_count']} | "
            f"拦截密钥外泄：{s['blocked_count']}{trunc_part_zh}",
            file=sys.stderr,
        )
        for tr in truncated_traces:
            print(
                f"  ! {labels['truncated_badge']} 第 {tr['turn_number']} 轮（{tr['model']} {tr['path']}）：{labels['truncated_turn_warning']}",
                file=sys.stderr,
            )
        for ns in data["top_namespaces"][:5]:
            print(
                f"  - {ns['namespace']:<18} {ns['max_tools']:>3} 个工具   "
                f"{ns['per_turn_tokens']:>7,} tok/轮（{labels['estimated']}）",
                file=sys.stderr,
            )
        return

    if has_any_buckets and est_input > 0:
        tool_str = f"{labels['tool_definition_tokens']}: {tool_def_tok:,} / ~{est_input:,} tok ({labels['estimated']})"
        mcp_str = f"{labels['mcp_tool_share']}: {mcp_share_pct}% ({labels['estimated']})"
    else:
        tool_str = f"{labels['tool_definition_tokens']}: {labels['no_data']}"
        mcp_str = f"{labels['mcp_tool_share']}: {labels['no_data']}"

    trunc_part_en = f" | {labels['truncated_streams']}: {truncated_count}" if truncated_count > 0 else ""
    print(
        f"\n[agent-xray] Session summary: {s['turn_count']} turns | "
        f"{tool_str} | {mcp_str} | "
        f"{labels['cache_hit_rate']}: {hit_pct}% ({s['total_cache_read']:,} / {cache_denom:,} tok) | "
        f"Cost: {cost_str} | "
        f"{labels['stripped_telemetry_headers']}: {s['stripped_header_count']} | "
        f"Blocked leaks: {s['blocked_count']}{trunc_part_en}",
        file=sys.stderr,
    )
    for tr in truncated_traces:
        print(
            f"  ! {labels['truncated_badge']} Turn #{tr['turn_number']} ({tr['model']} {tr['path']}): {labels['truncated_turn_warning']}",
            file=sys.stderr,
        )
    for ns in data["top_namespaces"][:5]:
        print(
            f"  - {ns['namespace']:<18} {ns['max_tools']:>3} tools   "
            f"{ns['per_turn_tokens']:>7,} tok/turn ({labels['estimated']})",
            file=sys.stderr,
        )


def _resolve_upstreams(
    args: argparse.Namespace,
    *,
    chain_parent_base_urls: bool,
) -> tuple[str, str]:
    cli_up = (getattr(args, "upstream", None) or "").strip()
    cli_ant = (getattr(args, "anthropic_upstream", None) or "").strip()
    cli_oai = (getattr(args, "openai_upstream", None) or "").strip()

    env_ant_up = (os.environ.get("AGENT_XRAY_ANTHROPIC_UPSTREAM") or "").strip()
    env_oai_up = (os.environ.get("AGENT_XRAY_OPENAI_UPSTREAM") or "").strip()
    parent_ant = (os.environ.get("ANTHROPIC_BASE_URL") or "").strip() if chain_parent_base_urls else ""
    parent_oai = (os.environ.get("OPENAI_BASE_URL") or "").strip() if chain_parent_base_urls else ""

    ant_raw = cli_ant or cli_up or env_ant_up or parent_ant or "https://api.anthropic.com"
    oai_raw = cli_oai or cli_up or env_oai_up or parent_oai or "https://api.openai.com"
    return validate_upstream_url(ant_raw), validate_upstream_url(oai_raw)


def cmd_serve(args: argparse.Namespace) -> int:
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    is_zh = lang == "zh"
    auth_token = (getattr(args, "auth_token", "") or "").strip()
    if args.allow_lan and not auth_token:
        msg = (
            "错误：启用 --allow-lan 监听局域网时必须显式提供 --auth-token <token> 以保护检查器界面与 API。"
            if is_zh
            else "Error: --allow-lan requires an explicit --auth-token <token> to protect the Inspector UI and API."
        )
        print(msg, file=sys.stderr)
        return 2

    try:
        ant_upstream, oai_upstream = _resolve_upstreams(args, chain_parent_base_urls=False)
    except ValueError as exc:
        err_msg = f"错误：无效的上游地址（{exc}）" if is_zh else f"Error: {exc}"
        print(err_msg, file=sys.stderr)
        return 2

    host = "0.0.0.0" if args.allow_lan else "127.0.0.1"
    store = TraceStore(args.db)
    cfg = ProxyConfig(
        host=host,
        port=args.port,
        anthropic_upstream=ant_upstream,
        openai_upstream=oai_upstream,
        strip_telemetry_headers=args.strip_telemetry_headers,
        block_secrets=args.block_secrets,
        store_previews=args.store_previews,
        allow_lan=args.allow_lan,
        auth_token=auth_token,
        lang=raw_lang,
    )
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    _print_startup_token(cfg.auth_token, lang)
    if is_zh:
        print(f"agent-xray 正在监听 http://{host}:{bound_port}")
        print(f"  实时火焰图工作台 : http://127.0.0.1:{bound_port}/_xray/")
    else:
        print(f"agent-xray listening on http://{host}:{bound_port}")
        print(f"  Live Inspector UI : http://127.0.0.1:{bound_port}/_xray/")
    print(f"  ANTHROPIC_BASE_URL=http://127.0.0.1:{bound_port}/anthropic")
    print(f"  OPENAI_BASE_URL=http://127.0.0.1:{bound_port}/openai/v1")
    def _sigterm_to_interrupt(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    prev_sigterm = None
    if threading.current_thread() is threading.main_thread():
        prev_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _sigterm_to_interrupt)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if prev_sigterm is not None:
            signal.signal(signal.SIGTERM, prev_sigterm)
        srv.wait_for_inflight(timeout=2.0)
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

    # Inspect existing ANTHROPIC_BASE_URL / OPENAI_BASE_URL in parent env BEFORE overwriting
    try:
        ant_upstream, oai_upstream = _resolve_upstreams(args, chain_parent_base_urls=True)
    except ValueError as exc:
        err_msg = f"错误：无效的上游地址（{exc}）" if is_zh else f"Error: {exc}"
        print(err_msg, file=sys.stderr)
        return 2

    store = TraceStore(args.db)
    cfg = ProxyConfig(
        host="127.0.0.1",
        port=args.port,
        anthropic_upstream=ant_upstream,
        openai_upstream=oai_upstream,
        strip_telemetry_headers=args.strip_telemetry_headers,
        block_secrets=args.block_secrets,
        store_previews=args.store_previews,
        auth_token=(getattr(args, "auth_token", "") or "").strip(),
        lang=raw_lang,
    )
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    _print_startup_token(cfg.auth_token, lang)
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
        srv.wait_for_inflight(timeout=2.0)
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
    db_target = args.db if args.db else ":memory:"
    home_override = Path(args.home) if getattr(args, "home", None) else None
    store = TraceStore(db_target)
    count = import_local_desktop_sessions(store, home=home_override, max_turns=args.limit)
    if is_zh:
        print(
            f"[agent-xray] 已导入 {count} 条近期本地桌面会话轮次（OpenCode Desktop 与 Claude Code，仅聚合 Token，不含原始请求五桶拆分）。",
            file=sys.stderr,
        )
    else:
        print(
            f"[agent-xray] Imported {count} recent Desktop/local turns (OpenCode Desktop & Claude Code; aggregate usage only, no 5-bucket breakdown).",
            file=sys.stderr,
        )
    if getattr(args, "import_only", False):
        _print_terminal_summary(store, lang=lang)
        store.close()
        return 0

    cfg = ProxyConfig(
        host="127.0.0.1",
        port=args.port,
        auth_token=(getattr(args, "auth_token", "") or "").strip(),
        desktop_home=home_override,
        lang=raw_lang,
    )
    srv = XRayHTTPServer(cfg, store)
    bound_port = srv.server_address[1]
    _print_startup_token(cfg.auth_token, lang)
    url = f"http://127.0.0.1:{bound_port}/_xray/"
    if is_zh:
        print(f"  实时火焰图工作台 : {url}", file=sys.stderr)
    else:
        print(f"  Live Inspector UI : {url}", file=sys.stderr)
    if args.open_ui:
        webbrowser.open(url)
    def _sigterm_to_interrupt(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    prev_sigterm = None
    if threading.current_thread() is threading.main_thread():
        prev_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _sigterm_to_interrupt)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if prev_sigterm is not None:
            signal.signal(signal.SIGTERM, prev_sigterm)
        srv.wait_for_inflight(timeout=2.0)
        srv.server_close()
        _print_terminal_summary(store, lang=lang)
        store.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    store = TraceStore(args.db)
    _print_terminal_summary(store, lang=lang)
    store.close()
    return 0


def cmd_purge_db(args: argparse.Namespace) -> int:
    raw_lang = getattr(args, "lang", "auto")
    lang = resolve_lang(raw_lang)
    target, removed = purge_trace_db(args.db)
    if removed:
        if lang == "zh":
            print(f"[agent-xray] 已清理 SQLite 追踪数据库：{target}（已删除 {len(removed)} 个文件）。")
        else:
            print(f"[agent-xray] Purged SQLite trace database: {target} (removed {len(removed)} file(s)).")
    else:
        if lang == "zh":
            print(f"[agent-xray] 未在 {target} 发现 SQLite 追踪数据库（无需清理）。")
        else:
            print(f"[agent-xray] No SQLite trace database found at {target} (nothing to purge).")
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
        p.add_argument("--upstream", type=str, default=None, help="Upstream gateway base URL for both Anthropic and OpenAI requests")
        p.add_argument("--anthropic-upstream", type=str, default=None, help="Override upstream base URL for Anthropic requests")
        p.add_argument("--openai-upstream", type=str, default=None, help="Override upstream base URL for OpenAI requests")
        p.add_argument("--strip-telemetry-headers", action="store_true", help="Strip SDK telemetry headers and normalize User-Agent")
        p.add_argument("--block-secrets", action="store_true", help="Abort requests containing live API keys or private keys before upstream egress")
        p.add_argument("--store-previews", action="store_true", help="Opt-in: store secret-redacted 140-char prompt previews (off by default)")
        p.add_argument("--auth-token", type=str, default="", help="Explicit startup auth token (auto-generated on loopback; required with --allow-lan)")
        p.add_argument("--open", dest="open_ui", action="store_true", help="Automatically open the live Flamegraph UI in your default browser")
        if name == "serve":
            p.add_argument("--allow-lan", action="store_true", help="Bind 0.0.0.0 instead of 127.0.0.1 (requires --auth-token)")
        else:
            p.add_argument("command", nargs=argparse.REMAINDER, help="Agent command after `--`")
        p.set_defaults(func=fn)

    p_demo = sub.add_parser("export-demo", help="Export a self-contained static HTML demo inspector")
    _add_subparser_lang_arg(p_demo)
    p_demo.add_argument("--out", type=str, default="docs/demo-inspector.html", help="Output HTML file path")
    p_demo.set_defaults(func=cmd_export_demo)

    p_desk = sub.add_parser("desktop", help="Inspect local OpenCode Desktop & Claude Code sessions (aggregate usage only)")
    _add_subparser_lang_arg(p_desk)
    p_desk.add_argument("--port", type=int, default=0, help="Loopback TCP port (0 = ephemeral)")
    p_desk.add_argument("--db", type=str, default=":memory:", help="Path to SQLite trace database (defaults to :memory:)")
    p_desk.add_argument("--home", type=str, default=None, help="Override home directory when scanning local sessions")
    p_desk.add_argument("--limit", type=int, default=24, help="Maximum recent local turns to import")
    p_desk.add_argument("--auth-token", type=str, default="", help="Explicit startup auth token")
    p_desk.add_argument("--import-only", action="store_true", help="Import local turns into --db, print summary, and exit")
    p_desk.add_argument("--open", dest="open_ui", action="store_true", help="Automatically open the UI in your default browser")
    p_desk.set_defaults(func=cmd_desktop)

    p_rep = sub.add_parser("report", help="Print terminal summary from an existing SQLite trace DB")
    _add_subparser_lang_arg(p_rep)
    p_rep.add_argument("--db", type=str, default=None, help="Path to SQLite trace database")
    p_rep.set_defaults(func=cmd_report)

    p_purge = sub.add_parser("purge-db", help="Delete SQLite trace database and -wal/-shm sidecar files")
    _add_subparser_lang_arg(p_purge)
    p_purge.add_argument("--db", type=str, default=None, help="Path to SQLite trace database (defaults to ~/.agent-xray/traces.db)")
    p_purge.set_defaults(func=cmd_purge_db)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
