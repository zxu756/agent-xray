"""5-bucket prompt token classifier, MCP namespace analyzer, and streaming usage parser."""

from __future__ import annotations

import codecs
import json
import re
import zlib
from dataclasses import asdict, dataclass, field
from typing import Any

from .privacy import redact_secrets_in_text

# Inline XML-style rule / system-reminder tags injected by coding agents.
# Matches both closed <tag>...</tag> spans and unclosed <tag>... trailing spans
# within a single content block so mixed blocks split cleanly.
_INLINE_RULE_TAG_RE = re.compile(
    r"(?:"
    r"<system-reminder\b[^>]*>.*?(?:</system-reminder>|$)"
    r"|<user_rules\b[^>]*>.*?(?:</user_rules>|$)"
    r"|<workspace_rules\b[^>]*>.*?(?:</workspace_rules>|$)"
    r"|<cursor_rules\b[^>]*>.*?(?:</cursor_rules>|$)"
    r"|<RULE\[[^\]]*\]>.*?(?:</RULE\[[^\]]*\]>|$)"
    r")",
    re.DOTALL | re.IGNORECASE,
)

# Standalone block header patterns indicating an entire untagged block is an
# injected workspace rule file dump rather than prose merely mentioning a filename.
_STANDALONE_RULE_HEADER_RE = re.compile(
    r"^\s*(?:"
    r"#+\s*(?:AGENTS\.md|CLAUDE\.md|\.cursorrules|copilot-instructions\.md)\b"
    r"|Contents of [^\n]{0,200}?(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|copilot-instructions\.md)\b"
    r"|Instructions from [^\n]{0,200}?(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|copilot-instructions\.md)\b"
    r")",
    re.IGNORECASE,
)

_MAX_SSE_LINE_CHARS = 1_048_576
_MAX_NON_SSE_JSON_CHARS = 16 * 1024 * 1024


@dataclass
class Buckets:
    system_prompt: int = 0
    workspace_rules: int = 0
    mcp_and_tools: int = 0
    tool_results: int = 0
    conversation: int = 0

    @property
    def total_estimated(self) -> int:
        return (
            self.system_prompt
            + self.workspace_rules
            + self.mcp_and_tools
            + self.tool_results
            + self.conversation
        )

    def to_dict(self) -> dict[str, int]:
        d = asdict(self)
        d["total_estimated"] = self.total_estimated
        return d


@dataclass
class ToolNamespaceStat:
    namespace: str
    tool_count: int = 0
    estimated_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TurnClassification:
    provider: str
    model: str
    stream: bool
    buckets: Buckets
    tool_namespaces: list[ToolNamespaceStat] = field(default_factory=list)
    cache_breakpoint_count: int = 0
    message_count: int = 0
    prompt_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "stream": self.stream,
            "buckets": self.buckets.to_dict(),
            "tool_namespaces": [ns.to_dict() for ns in self.tool_namespaces],
            "cache_breakpoint_count": self.cache_breakpoint_count,
            "message_count": self.message_count,
            "prompt_preview": self.prompt_preview,
        }


def estimate_tokens(value: Any, *, code_heavy: bool = False) -> int:
    """Fast deterministic token estimator without external C/tiktoken dependencies."""
    if value is None:
        return 0
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if not text:
        return 0
    cjk_chars = len(re.findall(r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]", text))
    ascii_len = max(0, len(text) - cjk_chars)
    divisor = 3.25 if code_heavy else 3.75
    return max(1, int(round(ascii_len / divisor + cjk_chars * 0.85)))


def extract_tool_namespace(tool_name: str) -> str:
    """Groups MCP tools like `mcp__rea__inspect_macho` or `mcp_box.shell` by server."""
    if not tool_name:
        return "builtin"
    m_double = re.match(r"^mcp__([a-zA-Z0-9_-]+)__.+$", tool_name)
    if m_double:
        return f"mcp:{redact_secrets_in_text(m_double.group(1))}"
    m_dot = re.match(r"^mcp_([a-zA-Z0-9_-]+)[._].+$", tool_name)
    if m_dot:
        return f"mcp:{redact_secrets_in_text(m_dot.group(1))}"
    if ":" in tool_name:
        prefix = tool_name.split(":", 1)[0]
        return f"mcp:{redact_secrets_in_text(prefix)}"
    return "builtin"


def _split_rule_tag_segments(text: str) -> list[tuple[bool, str]]:
    """Splits a single text block into (is_rule_tag, segment) spans."""
    if not text:
        return []
    segments: list[tuple[bool, str]] = []
    pos = 0
    matched_any = False
    for m in _INLINE_RULE_TAG_RE.finditer(text):
        matched_any = True
        if m.start() > pos:
            outside = text[pos : m.start()]
            if outside.strip():
                segments.append((False, outside))
        tag_span = m.group(0)
        if tag_span:
            segments.append((True, tag_span))
        pos = m.end()

    if not matched_any:
        return [(False, text)]

    if pos < len(text):
        tail = text[pos:]
        if tail.strip():
            segments.append((False, tail))
    return segments


def _classify_text_block(
    buckets: Buckets,
    text: str,
    *,
    default_bucket: str,
) -> str:
    """Classifies one text block into buckets, splitting embedded rule tags cleanly.

    Returns the non-rule text portion (for optional user prompt preview extraction).
    """
    if not text:
        return ""
    segments = _split_rule_tag_segments(text)
    non_rule_parts: list[str] = []
    for is_rule_tag, seg in segments:
        if is_rule_tag:
            buckets.workspace_rules += estimate_tokens(seg)
            continue
        if _STANDALONE_RULE_HEADER_RE.search(seg):
            buckets.workspace_rules += estimate_tokens(seg)
            continue
        toks = estimate_tokens(seg)
        if default_bucket == "system_prompt":
            buckets.system_prompt += toks
        else:
            buckets.conversation += toks
        non_rule_parts.append(seg)
    return "".join(non_rule_parts)


def _build_redacted_preview(raw_text: str, *, store_previews: bool) -> str:
    if not store_previews or not raw_text:
        return ""
    return redact_secrets_in_text(raw_text).strip()[:140]


def classify_request_payload(
    path: str,
    payload: dict[str, Any],
    *,
    store_previews: bool = False,
) -> TurnClassification:
    """Classifies Anthropic Messages or OpenAI Chat/Responses JSON payloads into 5 buckets."""
    lower_path = path.lower()
    is_anthropic = "messages" in lower_path and (
        "anthropic" in lower_path or "system" in payload or "max_tokens" in payload
    )
    if is_anthropic and "input" not in payload:
        return _classify_anthropic(payload, store_previews=store_previews)
    return _classify_openai(payload, store_previews=store_previews)


def _classify_anthropic(payload: dict[str, Any], *, store_previews: bool = False) -> TurnClassification:
    buckets = Buckets()
    cache_breakpoints = 0
    model = str(payload.get("model") or "claude-unknown")
    stream = bool(payload.get("stream", False))

    # 1 & 2: System prompt vs Workspace rules (per content block + inline tag split)
    system_val = payload.get("system")
    if isinstance(system_val, str):
        _classify_text_block(buckets, system_val, default_bucket="system_prompt")
    elif isinstance(system_val, list):
        for block in system_val:
            if not isinstance(block, dict):
                _classify_text_block(buckets, str(block or ""), default_bucket="system_prompt")
                continue
            if block.get("cache_control"):
                cache_breakpoints += 1
            txt = str(block.get("text") or "")
            _classify_text_block(buckets, txt, default_bucket="system_prompt")

    # 3: MCP & Tool Schemas
    ns_map: dict[str, ToolNamespaceStat] = {}
    for tool in payload.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        if tool.get("cache_control"):
            cache_breakpoints += 1
        name = str(tool.get("name") or "")
        ns = extract_tool_namespace(name)
        toks = estimate_tokens(tool, code_heavy=True)
        buckets.mcp_and_tools += toks
        stat = ns_map.setdefault(ns, ToolNamespaceStat(namespace=ns))
        stat.tool_count += 1
        stat.estimated_tokens += toks

    # 4 & 5: Messages (Tool results vs Conversation + split embedded system reminders)
    messages = payload.get("messages") or []
    last_user_preview = ""
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "user")
        content = msg.get("content")
        if isinstance(content, str):
            non_rule = _classify_text_block(buckets, content, default_bucket="conversation")
            if role == "user" and store_previews and non_rule.strip():
                last_user_preview = _build_redacted_preview(non_rule, store_previews=True)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, str):
                    non_rule = _classify_text_block(buckets, part, default_bucket="conversation")
                    if role == "user" and store_previews and non_rule.strip():
                        last_user_preview = _build_redacted_preview(non_rule, store_previews=True)
                    continue
                if not isinstance(part, dict):
                    buckets.conversation += estimate_tokens(part)
                    continue
                if part.get("cache_control"):
                    cache_breakpoints += 1
                ptype = str(part.get("type") or "text")
                if ptype in ("tool_result", "mcp_tool_result", "web_search_tool_result", "code_execution_tool_result"):
                    buckets.tool_results += estimate_tokens(part.get("content"), code_heavy=True)
                elif ptype in ("tool_use", "server_tool_use", "mcp_tool_use"):
                    buckets.conversation += estimate_tokens(part, code_heavy=True)
                elif ptype in ("thinking", "redacted_thinking"):
                    buckets.conversation += estimate_tokens(
                        str(part.get("thinking") or part.get("data") or "")
                    )
                elif "text" in part or "thinking" in part:
                    txt = str(part.get("text") or part.get("thinking") or "")
                    non_rule = _classify_text_block(buckets, txt, default_bucket="conversation")
                    if role == "user" and store_previews and non_rule.strip():
                        last_user_preview = _build_redacted_preview(non_rule, store_previews=True)
                else:
                    buckets.conversation += estimate_tokens(part, code_heavy=True)

    sorted_ns = sorted(ns_map.values(), key=lambda s: s.estimated_tokens, reverse=True)
    return TurnClassification(
        provider="anthropic",
        model=model,
        stream=stream,
        buckets=buckets,
        tool_namespaces=sorted_ns,
        cache_breakpoint_count=cache_breakpoints,
        message_count=len(messages) if isinstance(messages, list) else 0,
        prompt_preview=last_user_preview,
    )


def _estimate_content_parts_code_heavy(val: Any) -> int:
    if val is None or val == "":
        return 0
    if isinstance(val, list):
        total = 0
        for elem in val:
            if isinstance(elem, dict) and "text" in elem:
                total += estimate_tokens(str(elem.get("text") or ""), code_heavy=True)
            else:
                total += estimate_tokens(elem, code_heavy=True)
        return total
    return estimate_tokens(val, code_heavy=True)


def _estimate_reasoning_parts(val: Any) -> int:
    if val is None or val == "":
        return 0
    if isinstance(val, str):
        return estimate_tokens(val)
    if isinstance(val, list):
        total = 0
        for elem in val:
            if isinstance(elem, dict) and "text" in elem:
                total += estimate_tokens(str(elem.get("text") or ""))
            elif isinstance(elem, str):
                total += estimate_tokens(elem)
            else:
                total += estimate_tokens(elem)
        return total
    return estimate_tokens(val)


def _classify_openai(payload: dict[str, Any], *, store_previews: bool = False) -> TurnClassification:
    buckets = Buckets()
    model = str(payload.get("model") or "gpt-unknown")
    stream = bool(payload.get("stream", False))

    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions:
        _classify_text_block(buckets, instructions, default_bucket="system_prompt")
    elif isinstance(instructions, list):
        for blk in instructions:
            if isinstance(blk, dict) and "text" in blk:
                _classify_text_block(buckets, str(blk.get("text") or ""), default_bucket="system_prompt")
            elif isinstance(blk, str):
                _classify_text_block(buckets, blk, default_bucket="system_prompt")

    ns_map: dict[str, ToolNamespaceStat] = {}
    for tool in payload.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = str(fn.get("name") or tool.get("type") or "")
        ns = extract_tool_namespace(name)
        toks = estimate_tokens(tool, code_heavy=True)
        buckets.mcp_and_tools += toks
        stat = ns_map.setdefault(ns, ToolNamespaceStat(namespace=ns))
        stat.tool_count += 1
        stat.estimated_tokens += toks

    raw_items = payload.get("messages") if "messages" in payload else payload.get("input")
    preview = ""
    if isinstance(raw_items, str):
        non_rule = _classify_text_block(buckets, raw_items, default_bucket="conversation")
        items_list: list[Any] = [raw_items] if raw_items else []
        if store_previews and non_rule.strip():
            preview = _build_redacted_preview(non_rule, store_previews=True)
        sorted_ns = sorted(ns_map.values(), key=lambda s: s.estimated_tokens, reverse=True)
        return TurnClassification(
            provider="openai",
            model=model,
            stream=stream,
            buckets=buckets,
            tool_namespaces=sorted_ns,
            cache_breakpoint_count=0,
            message_count=len(items_list),
            prompt_preview=preview,
        )

    items_list = list(raw_items) if isinstance(raw_items, list) else []

    for item in items_list:
        if isinstance(item, str):
            non_rule = _classify_text_block(buckets, item, default_bucket="conversation")
            if store_previews and non_rule.strip():
                preview = _build_redacted_preview(non_rule, store_previews=True)
            continue
        if not isinstance(item, dict):
            continue

        itype = str(item.get("type") or "")
        role = str(item.get("role") or "")

        # 1. Tool / function outputs (Chat `role=="tool"` or Responses `function_call_output`)
        if role in ("tool", "function") or itype in (
            "function_call_output",
            "custom_tool_call_output",
            "computer_call_output",
            "mcp_call_output",
        ):
            out_val = item.get("output") if "output" in item else item.get("content")
            buckets.tool_results += _estimate_content_parts_code_heavy(out_val)
            continue

        # 2. Standalone Responses API tool / function call items
        if itype in ("function_call", "custom_tool_call", "computer_call", "mcp_call"):
            fn_name = str(item.get("name") or "")
            fn_args = (
                item.get("arguments")
                if "arguments" in item
                else item.get("input") if "input" in item else item.get("action")
            )
            added = 0
            if fn_name:
                added += estimate_tokens(fn_name, code_heavy=True)
            if fn_args is not None and fn_args != "":
                added += estimate_tokens(fn_args, code_heavy=True)
            if added == 0:
                added = estimate_tokens(item, code_heavy=True)
            buckets.conversation += added
            continue

        # 3. Standalone Responses API `reasoning` items
        if itype == "reasoning":
            buckets.conversation += _estimate_reasoning_parts(item.get("summary"))
            buckets.conversation += _estimate_reasoning_parts(item.get("content"))
            enc = item.get("encrypted_content")
            if isinstance(enc, str) and enc:
                buckets.conversation += estimate_tokens(enc, code_heavy=True)
            continue

        # 4. Role-based messages (`system`, `developer`, `user`, `assistant`)
        default_bucket = "system_prompt" if role in ("system", "developer") else "conversation"

        content = item.get("content")
        if isinstance(content, str) and content:
            non_rule = _classify_text_block(
                buckets,
                content,
                default_bucket=default_bucket,
            )
            if role == "user" and store_previews and non_rule.strip():
                preview = _build_redacted_preview(non_rule, store_previews=True)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, str):
                    non_rule = _classify_text_block(
                        buckets,
                        part,
                        default_bucket=default_bucket,
                    )
                    if role == "user" and store_previews and non_rule.strip():
                        preview = _build_redacted_preview(non_rule, store_previews=True)
                elif isinstance(part, dict):
                    ptype = str(part.get("type") or "")
                    if "text" in part or ptype in (
                        "text",
                        "input_text",
                        "output_text",
                        "summary_text",
                        "reasoning_text",
                    ):
                        txt = str(part.get("text") or "")
                        non_rule = _classify_text_block(
                            buckets,
                            txt,
                            default_bucket=default_bucket,
                        )
                        if role == "user" and store_previews and non_rule.strip():
                            preview = _build_redacted_preview(non_rule, store_previews=True)
                    elif ptype == "refusal":
                        buckets.conversation += estimate_tokens(str(part.get("refusal") or ""))
                    else:
                        buckets.conversation += estimate_tokens(part, code_heavy=True)
                elif part is not None:
                    buckets.conversation += estimate_tokens(part)

        # Assistant `tool_calls`, legacy `function_call`, and `reasoning_content` on Chat messages
        tool_calls = item.get("tool_calls")
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
                fn_name = str(fn.get("name") or "")
                fn_args = fn.get("arguments")
                if fn_name:
                    buckets.conversation += estimate_tokens(fn_name, code_heavy=True)
                if fn_args is not None and fn_args != "":
                    buckets.conversation += estimate_tokens(fn_args, code_heavy=True)

        fc = item.get("function_call")
        if isinstance(fc, dict):
            fc_name = str(fc.get("name") or "")
            fc_args = fc.get("arguments")
            if fc_name:
                buckets.conversation += estimate_tokens(fc_name, code_heavy=True)
            if fc_args is not None and fc_args != "":
                buckets.conversation += estimate_tokens(fc_args, code_heavy=True)

        rc = item.get("reasoning_content") or (
            item.get("reasoning") if isinstance(item.get("reasoning"), str) else None
        )
        if isinstance(rc, str) and rc:
            buckets.conversation += estimate_tokens(rc)

    sorted_ns = sorted(ns_map.values(), key=lambda s: s.estimated_tokens, reverse=True)
    return TurnClassification(
        provider="openai",
        model=model,
        stream=stream,
        buckets=buckets,
        tool_namespaces=sorted_ns,
        cache_breakpoint_count=0,
        message_count=len(items_list),
        prompt_preview=preview,
    )


_TERMINAL_SSE_EVENTS = frozenset(
    {
        "message_stop",
        "response.completed",
        "response.incomplete",
        "response.failed",
        "response.cancelled",
        "error",
    }
)


class IncrementalResponseUsageParser:
    """Streaming O(1)-memory SSE & JSON usage extractor supporting gzip/deflate responses."""

    def __init__(self, *, is_sse: bool, content_encoding: str | None = None) -> None:
        self.is_sse = is_sse
        self.saw_terminal_event = False
        self.sse_frame_truncated = False
        self.decompression_truncated = False
        self.json_truncated = False
        self._usage: dict[str, int] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        }
        self._utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._line_buf = ""
        self._line_overflow = False
        self._json_parts: list[str] = []
        self._json_chars = 0
        self._json_overflow = False

        enc = (content_encoding or "").strip().lower()
        if "," in enc:
            enc = [p.strip() for p in enc.split(",") if p.strip()][-1]
        self._encoding = enc
        self._decomp: Any = None
        self._deflate_tried_raw = False
        self._decompress_failed = False
        if enc in ("gzip", "x-gzip"):
            self._decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            self._decomp = zlib.decompressobj(zlib.MAX_WBITS)

    @property
    def is_truncated(self) -> bool:
        if self.decompression_truncated:
            return True
        if self.is_sse:
            return bool(self.sse_frame_truncated or not self.saw_terminal_event)
        return bool(self.json_truncated)

    def _decompress_chunk(self, chunk: bytes) -> bytes:
        if self._decomp is None or self._decompress_failed or not chunk:
            return b"" if self._decompress_failed else chunk
        out = bytearray()
        data = chunk
        try:
            while data:
                out.extend(self._decomp.decompress(data))
                if self._decomp.eof and self._decomp.unused_data:
                    data = self._decomp.unused_data
                    wbits = (16 + zlib.MAX_WBITS) if self._encoding in ("gzip", "x-gzip") else zlib.MAX_WBITS
                    self._decomp = zlib.decompressobj(wbits)
                else:
                    break
            return bytes(out)
        except zlib.error:
            if self._encoding == "deflate" and not self._deflate_tried_raw:
                self._deflate_tried_raw = True
                try:
                    self._decomp = zlib.decompressobj(-zlib.MAX_WBITS)
                    return self._decomp.decompress(chunk)
                except zlib.error:
                    pass
            self._decompress_failed = True
            return b""

    def _consume_sse_line(self, line: str, *, at_eof: bool = False) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith(":"):
            return
        if stripped.startswith("event:"):
            ev_name = stripped[6:].strip()
            if ev_name in _TERMINAL_SSE_EVENTS:
                self.saw_terminal_event = True
            return
        if not stripped.startswith("data:"):
            if at_eof:
                self.sse_frame_truncated = True
            return
        data_str = stripped[5:].strip()
        if not data_str:
            return
        if data_str == "[DONE]":
            self.saw_terminal_event = True
            return
        has_marker = (
            "usage" in data_str
            or "message_stop" in data_str
            or "response.completed" in data_str
            or "response.incomplete" in data_str
            or "response.failed" in data_str
            or "response.cancelled" in data_str
            or "finish_reason" in data_str
            or '"error"' in data_str
            or at_eof
        )
        if not has_marker:
            return
        try:
            evt = json.loads(data_str)
        except ValueError:
            if data_str.startswith("{") or at_eof:
                self.sse_frame_truncated = True
            return
        if isinstance(evt, dict):
            ev_type = str(evt.get("type") or "")
            if ev_type in _TERMINAL_SSE_EVENTS:
                self.saw_terminal_event = True
            choices = evt.get("choices")
            if isinstance(choices, list) and any(
                isinstance(c, dict) and c.get("finish_reason") is not None for c in choices
            ):
                self.saw_terminal_event = True
            if isinstance(evt.get("usage"), dict):
                _merge_usage_dict(self._usage, evt["usage"])
            msg = evt.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("usage"), dict):
                _merge_usage_dict(self._usage, msg["usage"])
            resp = evt.get("response")
            if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
                _merge_usage_dict(self._usage, resp["usage"])

    def _feed_decoded_text(self, text: str) -> None:
        if not text:
            return
        if not self.is_sse:
            if self._json_overflow:
                return
            if self._json_chars + len(text) > _MAX_NON_SSE_JSON_CHARS:
                self._json_overflow = True
                self._json_parts.clear()
                return
            self._json_parts.append(text)
            self._json_chars += len(text)
            return

        idx = 0
        n = len(text)
        while idx < n:
            nl = text.find("\n", idx)
            if nl == -1:
                rem = text[idx:]
                if not self._line_overflow:
                    if len(self._line_buf) + len(rem) <= _MAX_SSE_LINE_CHARS:
                        self._line_buf += rem
                    else:
                        self._line_buf = ""
                        self._line_overflow = True
                break
            piece = text[idx:nl]
            if not self._line_overflow:
                if len(self._line_buf) + len(piece) <= _MAX_SSE_LINE_CHARS:
                    full_line = self._line_buf + piece
                    self._line_buf = ""
                    self._consume_sse_line(full_line)
                else:
                    self._line_buf = ""
            else:
                self._line_overflow = False
                self._line_buf = ""
            idx = nl + 1

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        raw = self._decompress_chunk(chunk)
        if raw:
            self._feed_decoded_text(self._utf8_decoder.decode(raw, final=False))

    def finish(self) -> dict[str, int]:
        if self._decomp is not None:
            if self._decompress_failed:
                self.decompression_truncated = True
            else:
                try:
                    flushed = self._decomp.flush()
                    if flushed:
                        self._feed_decoded_text(self._utf8_decoder.decode(flushed, final=False))
                except zlib.error:
                    self.decompression_truncated = True
                if not self._decomp.eof:
                    self.decompression_truncated = True
        tail_txt = self._utf8_decoder.decode(b"", final=True)
        if tail_txt:
            self._feed_decoded_text(tail_txt)

        if self.is_sse:
            if self._line_buf and not self._line_overflow:
                self._consume_sse_line(self._line_buf, at_eof=True)
            self._line_buf = ""
            return dict(self._usage)

        if not self._json_overflow:
            if not self._json_parts:
                self.json_truncated = True
            else:
                full_text = "".join(self._json_parts)
                self._json_parts.clear()
                if not full_text.strip():
                    self.json_truncated = True
                else:
                    try:
                        obj = json.loads(full_text)
                        if isinstance(obj, dict):
                            if isinstance(obj.get("usage"), dict):
                                _merge_usage_dict(self._usage, obj["usage"])
                            resp = obj.get("response")
                            if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
                                _merge_usage_dict(self._usage, resp["usage"])
                    except ValueError:
                        self.json_truncated = True
        return dict(self._usage)


def parse_usage_from_response(
    raw_body: bytes,
    is_sse: bool,
    *,
    content_encoding: str | None = None,
) -> dict[str, int]:
    """Extracts exact input/output/cached token counts from JSON or SSE frames."""
    parser = IncrementalResponseUsageParser(is_sse=is_sse, content_encoding=content_encoding)
    parser.feed(raw_body)
    return parser.finish()


def _merge_usage_dict(target: dict[str, int], u: dict[str, Any]) -> None:
    details = u.get("prompt_tokens_details") or u.get("input_tokens_details")
    openai_cached = (
        int(details["cached_tokens"])
        if isinstance(details, dict) and isinstance(details.get("cached_tokens"), int)
        else None
    )
    has_anthropic_cache = (
        "cache_read_input_tokens" in u or "cache_creation_input_tokens" in u
    )

    if openai_cached is not None and not has_anthropic_cache:
        raw_prompt = 0
        if "prompt_tokens" in u and isinstance(u["prompt_tokens"], int):
            raw_prompt = u["prompt_tokens"]
        elif "input_tokens" in u and isinstance(u["input_tokens"], int):
            raw_prompt = u["input_tokens"]
        uncached = max(0, raw_prompt - openai_cached)
        target["input_tokens"] = max(target["input_tokens"], uncached)
        target["cache_read_tokens"] = max(target["cache_read_tokens"], openai_cached)
    else:
        if "input_tokens" in u and isinstance(u["input_tokens"], int):
            target["input_tokens"] = max(target["input_tokens"], u["input_tokens"])
        if "prompt_tokens" in u and isinstance(u["prompt_tokens"], int):
            target["input_tokens"] = max(target["input_tokens"], u["prompt_tokens"])

    if "output_tokens" in u and isinstance(u["output_tokens"], int):
        target["output_tokens"] = max(target["output_tokens"], u["output_tokens"])
    if "completion_tokens" in u and isinstance(u["completion_tokens"], int):
        target["output_tokens"] = max(target["output_tokens"], u["completion_tokens"])
    if "cache_read_input_tokens" in u and isinstance(u["cache_read_input_tokens"], int):
        target["cache_read_tokens"] = max(target["cache_read_tokens"], u["cache_read_input_tokens"])
    if "cache_creation_input_tokens" in u and isinstance(u["cache_creation_input_tokens"], int):
        target["cache_write_tokens"] = max(target["cache_write_tokens"], u["cache_creation_input_tokens"])
