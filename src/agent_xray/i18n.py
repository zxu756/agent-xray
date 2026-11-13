"""Bilingual (zh-CN / en) locale detection and formatting helpers for agent-xray."""

from __future__ import annotations

from collections.abc import Mapping
import os

SUPPORTED_LANG_CHOICES = ("auto", "zh", "en")


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
