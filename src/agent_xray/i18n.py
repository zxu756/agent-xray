"""Bilingual (zh-CN / en) locale detection, canonical metric labels, and formatting helpers."""

from __future__ import annotations

from collections.abc import Mapping
import os

SUPPORTED_LANG_CHOICES = ("auto", "zh", "en")

HONEST_LABELS: dict[str, dict[str, str]] = {
    "en": {
        "tool_definition_tokens": "Tool Definition Tokens",
        "mcp_tool_share": "MCP Tool Share",
        "cache_hit_rate": "Cache Hit Rate",
        "stripped_telemetry_headers": "Stripped Telemetry Headers",
        "unknown_price": "Unknown price",
        "no_data": "No data",
        "estimated": "Estimated",
    },
    "zh": {
        "tool_definition_tokens": "工具定义占用",
        "mcp_tool_share": "MCP 工具定义占比",
        "cache_hit_rate": "缓存命中率",
        "stripped_telemetry_headers": "去掉的遥测头",
        "unknown_price": "未知价格",
        "no_data": "没有数据",
        "estimated": "估算",
    },
}


def format_usd(cost_val: float) -> str:
    """Format USD with at least 4 decimal places and up to 6 significant decimals."""
    s6 = f"{float(cost_val):.6f}"
    head, frac = s6.split(".")
    frac_trimmed = frac[:4] + frac[4:].rstrip("0")
    return f"${head}.{frac_trimmed}"


def _parse_lang_tag(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = raw.strip().lower().replace("_", "-")
    if not cleaned or cleaned in {"auto", "c", "posix"}:
        return None
    if cleaned.startswith("zh"):
        return "zh"
    if cleaned.startswith("en"):
        return "en"
    return None


def resolve_lang(cli_lang: str | None = None, env: Mapping[str, str] | None = None) -> str:
    """Resolve active language ('zh' or 'en') from CLI flag, AGENT_XRAY_LANG, or POSIX locale."""
    environ = os.environ if env is None else env

    if cli_lang and cli_lang != "auto":
        parsed = _parse_lang_tag(cli_lang)
        if parsed:
            return parsed

    env_override = _parse_lang_tag(environ.get("AGENT_XRAY_LANG"))
    if env_override:
        return env_override

    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = environ.get(var, "").strip()
        if val:
            parsed = _parse_lang_tag(val)
            if parsed:
                return parsed
            if val.lower() not in {"c", "posix", "c.utf-8"}:
                return "en"

    return "en"


def resolve_html_lang_mode(
    cli_lang: str | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Return (initial_render_lang, data_default_lang_attr) for exported/live HTML."""
    environ = os.environ if env is None else env

    if cli_lang and cli_lang != "auto":
        parsed = _parse_lang_tag(cli_lang) or "en"
        return parsed, parsed

    env_override = _parse_lang_tag(environ.get("AGENT_XRAY_LANG"))
    if env_override:
        return env_override, env_override

    detected = resolve_lang("auto", environ)
    if detected == "zh":
        return "zh", "zh"
    return "en", "auto"
