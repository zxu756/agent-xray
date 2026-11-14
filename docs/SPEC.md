# agent-xray - Engineering Specification

> **Release status:** Tagged release `v0.2.0` (`main`) predates the M0/M1 security, streaming forwarding, header fidelity, block-level classification, pricing, and SQLite write-boundary sanitization changes documented below, which live on the unreleased post-`v0.2.0` revision.

## 1. Problem Statement & Scope
AI coding agents (`Claude Code`, `Codex`, `OpenCode`) send structured multi-part JSON payloads on every turn, including system instructions, workspace rule files (`AGENTS.md`, `CLAUDE.md`), MCP tool JSON Schemas, and tool execution results.

**agent-xray** is a zero-dependency Python 3.10+ local loopback streaming HTTP/SSE proxy CLI, programmatic metering library (`agent_xray.proxy`), and bilingual (`zh-CN` / `en`) Web inspector (`http://127.0.0.1:<port>/_xray/`) that wraps coding agent sessions via `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` without requiring custom TLS root certificates.

---

## 2. Core Capabilities & Exact Formulas

### 2.1 Loopback Streaming Proxy, Header Fidelity, & Inspector Security (`proxy.py`, `cli.py`)
- Binds `127.0.0.1:<port>` by default (`TCP_NODELAY` enabled on server, client, and upstream sockets). Passing `--allow-lan` (`0.0.0.0`) requires an explicit `--auth-token <token>` or exits non-zero (`2`) before opening any database.
- **Upstream routing & gateway chaining**:
  - Routes `/anthropic/*` (or `/v1/messages*`) to `anthropic_upstream` (default `https://api.anthropic.com`) and `/openai/*` (or `/v1/chat/completions`, `/v1/responses*`, `/v1/embeddings`, etc.) to `openai_upstream` (default `https://api.openai.com`), deduplicating overlapping `/v1` base paths via `_join_upstream_path()`.
  - `agent-xray run` inspects existing `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` in the parent environment *before* overwriting them in the child process environment, chaining pre-configured gateways automatically.
  - Both `serve` and `run` accept `--upstream <url>`, `--anthropic-upstream <url>`, and `--openai-upstream <url>` (validated at startup; invalid URLs exit `2` before opening SQLite).
- **True `read1` SSE streaming & clean mid-stream disconnect**:
  - Reads upstream chunks via `up_resp.read1(4096)` (or `up_resp.fp.read1(4096)`) and flushes `self.wfile` immediately on every chunk, recording `ttft_ms` on the first non-empty response chunk.
  - Tracks `headers_sent`: if upstream disconnects after `200 OK` headers are flushed, closes the client connection cleanly at EOF without writing `HTTP/1.1 502` into the stream; if the client disconnects (`BrokenPipeError` / `ConnectionResetError`), closes the upstream connection cleanly without crashing server threads.
  - Parses `usage` incrementally via `IncrementalResponseUsageParser` (bounded line buffer + incremental `zlib` decompression for `Content-Encoding: gzip` / `deflate`) across multi-megabyte SSE or JSON responses while forwarding raw upstream bytes intact.
- **Request body & header fidelity**:
  - Reads both `Content-Length` and `Transfer-Encoding: chunked` incoming request bodies; forwards raw compressed bytes intact when `Content-Encoding: gzip` / `deflate` is present while decoding a bounded (`<= 32 MB`) copy in memory for classification and secret inspection.
  - Uses `HeaderPairs` and `conn.putheader()` to preserve duplicate HTTP header lines verbatim and never strips `openai-organization`, `openai-project`, or `Accept-Encoding`.
- **DNS-rebinding & CSRF protection**:
  - Validates `Host` (`127.0.0.1`, `localhost`, `[::1]` matching bound port) and `Origin`/`Referer` on all UI and `/_xray/api/*` endpoints (`HTTP 403` otherwise).
  - Requires startup-generated `X-Xray-Token` (or `Authorization: Bearer <token>`) on state-changing `POST` endpoints (`/_xray/api/scan-desktop`, `/_xray/api/clear`) and on all UI/API reads when `--allow-lan` is active.

### 2.2 Programmatic Python Metering API (`agent_xray.proxy`)
Downstream tools (such as `skill-arena`) can start an isolated in-process metering proxy without spawning a CLI subprocess:
- `start_background_proxy(*, db_path=":memory:", host="127.0.0.1", port=0, anthropic_upstream=..., openai_upstream=..., strip_telemetry=False, block_secrets=False, store_previews=False) -> RunningXRayProxy`
- `RunningXRayProxy` exposes `.port`, `.base_url`, `.anthropic_base_url`, `.openai_base_url`, `.store` (`TraceStore`), `.get_traces()`, `.get_totals()` (returning `turns`, `input_tokens`, `cached_input_tokens`, `cache_creation_input_tokens`, `output_tokens`, `estimated_cost_usd`, `ttft_ms_values`), `.reset()`, and context-manager cleanup (`close()`).

### 2.3 Block-Level Five-Bucket Context Token Classifier (`classifier.py`)
Decomposes JSON request payloads (after bounded `gzip`/`deflate` decompression if needed) into five heuristic integer token buckets (`is_estimated = True`, `bucket_unit = "estimated_tokens"`, `sum(5 buckets) == total_estimated`):
1. **`system_prompt` (`Estimated`)** - Core agent harness instructions (`system`, `instructions`, `role: "system"` / plain `"developer"`). Plain system prompts mentioning `"CLAUDE.md"` or `"AGENTS.md"` in prose remain in `system_prompt`.
2. **`workspace_rules` (`Estimated`)** - Dedicated workspace rule blocks (`Contents of CLAUDE.md`, `# AGENTS.md`, `developer` role rule dumps) and inline `<system-reminder>...</system-reminder>`, `<user_rules>...</user_rules>`, `<workspace_rules>...</workspace_rules>`, `<cursor_rules>...</cursor_rules>`, or `<RULE[...]>...</RULE[...]>` segments split out of mixed content blocks via `_split_rule_tag_segments()`.
3. **`mcp_and_tools` (`Tool Definition Tokens (Estimated)`)** - All `tools[]` / `functions[]` JSON Schema definitions, grouped by namespace (`mcp:<server>` vs `builtin`). **`MCP Tool Share (Estimated)`** is strictly `mcp_tool_tokens / total_estimated_input`.
4. **`tool_results` (`Estimated`)** - `tool_result` blocks, `role: "tool"` / `"function"` messages, and OpenAI Responses `function_call_output` items.
5. **`conversation` (`Estimated`)** - User/assistant text outside rule tags, OpenAI Chat `assistant.tool_calls` / `function_call` / `reasoning_content`, and OpenAI Responses `function_call` (`name` + `arguments`) and `reasoning` (`summary`, `content`, `encrypted_content`) items.

### 2.4 Cache Hit Rate & Per-Model Pricing (`store.py`)
- **Prompt Cache Hit Rate**:
  `cache_read_tokens / (input_tokens + cache_read_tokens + cache_write_tokens)` (`0.0` when denominator is `0`).
  For OpenAI `/v1/chat/completions` and `/v1/responses`, `prompt_tokens` / `input_tokens` reported inclusive of `cached_tokens` are normalized to uncached `input_tokens = max(0, total_prompt - cached_tokens)`.
- **Per-Model Pricing (`PRICING_TABLE_DATE = "unverified"`)**:
  - Computes `(input * p_in + cache_read * p_read + cache_write * p_write + output * p_out) / 1_000_000` for recognized Anthropic and OpenAI model families (`verified_at = "unverified"` offline).
  - **Claude Sonnet 4 Long-Context Tier (`> 200,000` prompt tokens)**: When model prefix matches `claude-sonnet-4*` and `input_tokens + cache_read_tokens + cache_write_tokens > 200_000`, applies `2x` input/cache rates (`$6.00` / `$0.60` / `$7.50` per MTok) and `1.5x` output rate (`$22.50` per MTok).
  - Returns `None` (`Unknown price` / `未知价格`) for unrecognized models, and `0.0` whenever `blocked == True` or `status_code >= 400`.

### 2.5 All-Endpoint Secret Guard & SQLite Write-Boundary Sanitization (`privacy.py`, `store.py`)
- **All-Surface Request Scanning (`scan_request_for_secrets`)**: Runs across all forwarded proxy endpoints, inspecting URL path segments, URL query keys/values, non-auth HTTP headers (skipping `Authorization`, `x-api-key`, `api-key`), bounded decompressed `gzip`/`deflate` bodies (`<= 32 MB`; fails closed with `HTTP 400` if decompression fails or exceeds cap while `--block-secrets` is enabled), JSON strings + `\uXXXX` / `\xXX` escapes, and raw UTF-8 text.
- **False-Positive Guards & Non-Guarantees**: Rejects PEM headers without newline + base64/header key material, OpenSSH `sk-ssh-*` / `sk-ecdsa-*` identifiers, documentation placeholders (`AKIAIOSFODNN7EXAMPLE`, `AKIAXXXXXXXXXXXXXXXX`, repeated-`x` placeholders), git SHAs, and UUIDs, while catching secrets glued after `_` or `=`. **Base64-encoded secrets and secrets split across multiple JSON fields are not guaranteed.**
- **Storage-Boundary Sanitization**: `normalize_trace_path()` strips query strings via `urlsplit(raw_path).path`; `TraceStore._execute_write()` applies `_sanitize_db_value()` (`redact_secrets_in_text`) to every SQLite write parameter across all 15 columns of `traces` (including `ttft_ms`). `headers_json` stores only redacted `name`, `value_length`, `category`, and `action`; `prompt_preview` is `""` unless `--store-previews` is passed (redact-before-truncate, always `""` on `400`).

### 2.6 Local Session Aggregate Import (`local_sessions.py`)
- Reads per-turn assistant usage from `OpenCode Desktop` (`session_message` table, ignoring cumulative `session_v2` totals) and `Claude Code` (`~/.claude/projects/*/*.jsonl`, deduplicated by `(message.id, requestId)`), setting `has_bucket_breakdown = False` (`No data` / `没有数据`).

---

## 3. Package Layout & CLI Commands
```text
agent-xray/
├── Scripts/
│   ├── test.sh                 # Scoped unit test & milestone (0 / 1) acceptance runner
│   └── acceptance/             # m0-acceptance.sh, m1-acceptance.sh & readme-commands.sh
├── docs/
│   ├── SPEC.md
│   ├── demo-inspector.html     # Static [DEMO] HTML export
│   ├── screenshot.png          # [DEMO] dataset screenshot (EN)
│   └── screenshot-zh.png       # [DEMO] dataset screenshot (ZH)
├── src/agent_xray/
│   ├── __init__.py             # Version & exported programmatic proxy helpers
│   ├── classifier.py           # Block-level 5-bucket classifier & incremental usage parser
│   ├── cli.py                  # `run`, `serve`, `desktop`, `report`, `export-demo`, `purge-db`
│   ├── i18n.py                 # Locale resolution, canonical (Estimated) labels & USD formatter
│   ├── local_sessions.py       # Per-turn OpenCode & deduplicated Claude usage importer
│   ├── privacy.py              # HeaderPairs auditor, gzip decoder & multi-surface secret scanner
│   ├── proxy.py                # `read1` streaming loopback proxy & `start_background_proxy`
│   ├── store.py                # SQLite (0600) persistence, sanitization & tiered pricing table
│   └── ui_html.py              # Bilingual Web UI with [DEMO] banner & (Estimated) labels
└── tests/
    ├── fixtures/
    │   └── opencode_schema.sql # Real OpenCode Desktop SQLite DDL (.schema, zero rows)
    ├── test_classifier.py
    ├── test_cli.py
    ├── test_desktop.py
    ├── test_i18n.py
    ├── test_privacy.py
    ├── test_proxy.py
    ├── test_store.py
    └── test_xray.py
```

## 4. Known Boundaries
1. Five-bucket input counts use deterministic character/CJK heuristics (`is_estimated = True`) rather than live vendor BPE tokenizers; paid-API calibration is gated behind `XRAY_REAL_API=1`.
2. `--block-secrets` does not guarantee detection of base64-encoded secrets or secrets split across multiple JSON fields.
3. Offline per-model pricing entries carry `verified_at = "unverified"`.
