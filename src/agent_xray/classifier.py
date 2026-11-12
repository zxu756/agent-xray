"""5-bucket prompt token classifier and MCP namespace bloat analyzer."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

WORKSPACE_RULE_MARKERS = (
    "agents.md",
    "claude.md",
    "<user_rules>",
    "<system-reminder>",
    ".cursorrules",
    "copilot-instructions.md",
)


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
        return f"mcp:{m_double.group(1)}"
    m_dot = re.match(r"^mcp_([a-zA-Z0-9_-]+)[._].+$", tool_name)
    if m_dot:
        return f"mcp:{m_dot.group(1)}"
    if ":" in tool_name:
        prefix = tool_name.split(":", 1)[0]
        return f"mcp:{prefix}"
    return "builtin"


def _is_workspace_rule_text(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in WORKSPACE_RULE_MARKERS)


def classify_request_payload(path: str, payload: dict[str, Any]) -> TurnClassification:
    """Classifies Anthropic Messages or OpenAI Chat/Responses JSON payloads into 5 buckets."""
    lower_path = path.lower()
    is_anthropic = "messages" in lower_path and ("anthropic" in lower_path or "system" in payload or "max_tokens" in payload)
    if is_anthropic and "input" not in payload:
        return _classify_anthropic(payload)
    return _classify_openai(payload)


def _classify_anthropic(payload: dict[str, Any]) -> TurnClassification:
    buckets = Buckets()
    cache_breakpoints = 0
    model = str(payload.get("model") or "claude-unknown")
    stream = bool(payload.get("stream", False))

    # 1 & 2: System prompt vs Workspace rules
    system_val = payload.get("system")
    if isinstance(system_val, str):
        toks = estimate_tokens(system_val)
        if _is_workspace_rule_text(system_val):
            buckets.workspace_rules += toks
        else:
            buckets.system_prompt += toks
    elif isinstance(system_val, list):
        for block in system_val:
            if not isinstance(block, dict):
                buckets.system_prompt += estimate_tokens(block)
                continue
            if block.get("cache_control"):
                cache_breakpoints += 1
            txt = str(block.get("text") or "")
            toks = estimate_tokens(txt)
            if _is_workspace_rule_text(txt):
                buckets.workspace_rules += toks
            else:
                buckets.system_prompt += toks

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

    # 4 & 5: Messages (Tool results vs Conversation + embedded system reminders)
    messages = payload.get("messages") or []
    last_user_preview = ""
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "user")
        content = msg.get("content")
        if isinstance(content, str):
            toks = estimate_tokens(content)
            if _is_workspace_rule_text(content):
                buckets.workspace_rules += toks
            else:
                buckets.conversation += toks
                if role == "user":
                    last_user_preview = content.strip()[:140]
        elif isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    buckets.conversation += estimate_tokens(part)
                    continue
                if part.get("cache_control"):
                    cache_breakpoints += 1
                ptype = str(part.get("type") or "text")
                if ptype == "tool_result":
                    buckets.tool_results += estimate_tokens(part.get("content"), code_heavy=True)
                elif ptype == "tool_use":
                    buckets.conversation += estimate_tokens(part, code_heavy=True)
                else:
                    txt = str(part.get("text") or part.get("thinking") or "")
                    if _is_workspace_rule_text(txt):
                        buckets.workspace_rules += estimate_tokens(txt)
                    else:
                        buckets.conversation += estimate_tokens(txt)
                        if role == "user" and txt.strip():
                            last_user_preview = txt.strip()[:140]

    sorted_ns = sorted(ns_map.values(), key=lambda s: s.estimated_tokens, reverse=True)
    return TurnClassification(
        provider="anthropic",
        model=model,
        stream=stream,
        buckets=buckets,
        tool_namespaces=sorted_ns,
        cache_breakpoint_count=cache_breakpoints,
        message_count=len(messages),
        prompt_preview=last_user_preview,
    )


def _classify_openai(payload: dict[str, Any]) -> TurnClassification:
    buckets = Buckets()
    model = str(payload.get("model") or "gpt-unknown")
    stream = bool(payload.get("stream", False))

    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions:
        if _is_workspace_rule_text(instructions):
            buckets.workspace_rules += estimate_tokens(instructions)
        else:
            buckets.system_prompt += estimate_tokens(instructions)

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

    items = payload.get("messages") or payload.get("input") or []
    if isinstance(items, str):
        buckets.conversation += estimate_tokens(items)
        items_list: list[Any] = [items]
        preview = items.strip()[:140]
    else:
        items_list = list(items) if isinstance(items, list) else []
        preview = ""

    for item in items_list:
        if not isinstance(item, dict):
            continue
        itype = str(item.get("type") or "")
        role = str(item.get("role") or "")
        content = item.get("content") if "content" in item else item.get("output")
        text_repr = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False) if content is not None else ""

        if role in ("system", "developer"):
            if _is_workspace_rule_text(text_repr):
                buckets.workspace_rules += estimate_tokens(text_repr)
            else:
                buckets.system_prompt += estimate_tokens(text_repr)
        elif role == "tool" or itype in ("function_call_output", "custom_tool_call_output"):
            buckets.tool_results += estimate_tokens(text_repr, code_heavy=True)
        else:
            if _is_workspace_rule_text(text_repr):
                buckets.workspace_rules += estimate_tokens(text_repr)
            else:
                buckets.conversation += estimate_tokens(text_repr)
                if role == "user" and isinstance(content, str) and content.strip():
                    preview = content.strip()[:140]

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


def parse_usage_from_response(raw_body: bytes, is_sse: bool) -> dict[str, int]:
    """Extracts exact input/output/cached token counts from JSON or SSE frames."""
    usage = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }
    text = raw_body.decode("utf-8", errors="replace")
    if not is_sse:
        try:
            obj = json.loads(text)
            _merge_usage_dict(usage, obj.get("usage") or {})
        except Exception:
            pass
        return usage

    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        data_str = line[5:].strip()
        if not data_str or data_str == "[DONE]":
            continue
        try:
            evt = json.loads(data_str)
        except Exception:
            continue
        if isinstance(evt, dict):
            if isinstance(evt.get("usage"), dict):
                _merge_usage_dict(usage, evt["usage"])
            msg = evt.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("usage"), dict):
                _merge_usage_dict(usage, msg["usage"])
            resp = evt.get("response")
            if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
                _merge_usage_dict(usage, resp["usage"])
    return usage


def _merge_usage_dict(target: dict[str, int], u: dict[str, Any]) -> None:
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
    details = u.get("prompt_tokens_details") or u.get("input_tokens_details")
    if isinstance(details, dict) and isinstance(details.get("cached_tokens"), int):
        target["cache_read_tokens"] = max(target["cache_read_tokens"], details["cached_tokens"])
