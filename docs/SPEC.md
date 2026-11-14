# agent-xray - Engineering Specification

> **Release status:** Tagged release `v0.2.0` (`main`) predates the M0 security, pricing, and SQLite write-boundary sanitization changes documented below, which live on the unreleased post-`v0.2.0` revision.

## 1. Problem Statement & Scope
AI coding agents (`Claude Code`, `Codex`, `OpenCode`) send structured multi-part JSON payloads on every turn, including system instructions, workspace rule files (`AGENTS.md`, `CLAUDE.md`), MCP tool JSON Schemas, and tool execution results.

**agent-xray** is a zero-dependency Python 3.10+ local loopback HTTP/SSE proxy CLI and bilingual (`zh-CN` / `en`) Web inspector (`http://127.0.0.1:<port>/_xray/`) that wraps coding agent sessions via `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` without requiring custom TLS root certificates.

---

## 2. Core Capabilities & Exact Formulas

### 2.1 Loopback Proxy & Inspector Security (`proxy.py`)
- Binds `127.0.0.1:<port>` by default. Passing `--allow-lan` (`0.0.0.0`) requires an explicit `--auth-token <token>` or exits non-zero (`2`) before opening any database.
- Routes `/anthropic/*` (or `/v1/messages`) to `$AGENT_XRAY_ANTHROPIC_UPSTREAM` (`https://api.anthropic.com`) and `/openai/*` to `$AGENT_XRAY_OPENAI_UPSTREAM` (`https://api.openai.com`).
- **DNS-rebinding & CSRF protection**:
  - Validates the `Host` header on all UI and `/_xray/api/*` requests (`127.0.0.1`, `localhost`, `[::1]` matching the bound port; returns HTTP `403` otherwise).
  - Validates `Origin` (and `Referer` on `POST` when `Origin` is absent) against the allowed local origin (`HTTP 403` on cross-origin requests; zero wildcard CORS headers).
  - Generates a cryptographic `secrets.token_urlsafe(24)` token at startup (printed to `stderr`) and requires `X-Xray-Token` or `Authorization: Bearer <token>` on all state-changing `POST` endpoints (`/_xray/api/scan-desktop`, `/_xray/api/clear`), as well as on `GET` UI/API reads when `--allow-lan` is active.

### 2.2 Five-Bucket Context Token Classifier (`classifier.py`)
Decomposes uncompressed JSON request payloads on `/v1/messages`, `/v1/chat/completions`, and `/v1/responses` into five buckets:
1. **`system_prompt`** - Core agent harness instructions.
2. **`workspace_rules`** - Blocks matching `AGENTS.md`, `CLAUDE.md`, `<user_rules>`, `.cursorrules`, `<system-reminder>`, or `copilot-instructions.md`.
3. **`mcp_and_tools`** (`Tool Definition Tokens` / `工具定义占用`) - All `tools[]` JSON Schema definitions, grouped by namespace (`mcp:<server>` vs `builtin`). **`MCP Tool Share`** (`MCP 工具定义占比`) is strictly `mcp_tool_tokens / total_estimated_input`.
4. **`tool_results`** - `tool_result` blocks, `role: "tool"` messages, and `function_call_output` items.
5. **`conversation`** - User prompts, assistant responses, and reasoning blocks.

### 2.3 Cache Hit Rate & Per-Model Pricing (`store.py`)
- **Prompt Cache Hit Rate**:
  `cache_read_tokens / (input_tokens + cache_read_tokens + cache_write_tokens)` (`0.0` when denominator is `0`).
  For OpenAI `/v1/chat/completions` and `/v1/responses`, `prompt_tokens` / `input_tokens` reported inclusive of `cached_tokens` are normalized to uncached `input_tokens = max(0, total_prompt - cached_tokens)` so `cached_tokens` are never double-counted.
- **Per-Model Pricing (`PRICING_TABLE_DATE = "unverified"`)**:
  - Computes `(input * p_in + cache_read * p_read + cache_write * p_write + output * p_out) / 1_000_000` for recognized Anthropic (`claude-sonnet-*`, `claude-opus-*`, `claude-haiku-*`; URL: `https://docs.anthropic.com/en/docs/about-claude/pricing`) and OpenAI (`gpt-4o*`, `gpt-4.1*`, `gpt-5*`, `o1*`, `o3*`, `o4-mini*`, `codex-mini*`; URL: `https://openai.com/api/pricing/`) model families, with `verified_at = "unverified"` (`未核对`) because rates are not fetched live online. Anthropic Sonnet `>200k` long-context tiered surcharge is not modeled in M0.
  - Returns `None` (`null` in JSON, rendered as `Unknown price` / `未知价格`) when a model is not in `MODEL_PRICING_USD_PER_MTOK`.
  - Returns `0.0` whenever `blocked == True` or `status_code >= 400`.

### 2.4 Outbound Header Audit, Secret Guard & SQLite Write-Boundary Sanitization (`privacy.py`, `store.py`)
- **Storage-Boundary Sanitization**: `normalize_trace_path()` strips query strings via `urlsplit(raw_path).path` and redacts path segments; `TraceStore._execute_write()` applies `_sanitize_db_value()` (recursive `redact_secrets_in_text()` across strings, dict keys/values, lists, and serialized JSON) to **every SQLite write parameter** on both normal (`200`) and blocked (`400`) turns.
- **Header Persistence Rule**: `headers_json` stores **only** redacted `name`, `value_length`, `category`, and `action` (`forwarded`, `redacted`, `normalized`, `stripped`). Raw or masked header values are never persisted. `stripped_header_count` counts strictly `action == "stripped"`.
- **Prompt Preview Rule**: `prompt_preview` is `""` by default. When `--store-previews` is passed, `redact_secrets_in_text()` runs across the full text *before* truncating to 140 characters. Blocked turns (`400`) always store `prompt_preview = ""` and zeroed buckets, recording only redacted `{"rule": ..., "field": ...}` in `secrets_json`.
- **Secret Patterns**: Covers closed and unclosed PEM private key blocks, `sk-ant-...`, `sk-proj-...`/`sk-svcacct-...`, `sk-or-v1-...`, legacy `sk-...` tokens, `ghp_...`/`github_pat_...`, `AKIA...`, `xox[baprs]-...`, `AIza...`, and JWTs across JSON values and keys.

### 2.5 Local Session Aggregate Import (`local_sessions.py`)
- Reads per-turn assistant usage from `OpenCode Desktop` (`session_message` table, ignoring cumulative `session_v2` totals) and `Claude Code` (`~/.claude/projects/*/*.jsonl`, deduplicated by `(message.id, requestId)`).
- Sets `has_bucket_breakdown = False` and zero bucket estimates because local transcripts do not store raw wire payloads; UI and CLI report `No data` / `没有数据` for 5-bucket metrics instead of fixed-ratio splits.

---

## 3. Package Layout & CLI Commands
```text
agent-xray/
├── Scripts/
│   ├── test.sh                 # Scoped unit test & milestone acceptance runner
│   └── acceptance/             # M0 acceptance & README command verification scripts
├── docs/
│   ├── SPEC.md
│   ├── demo-inspector.html     # Static [DEMO] HTML export
│   ├── screenshot.png          # [DEMO] dataset screenshot (EN)
│   └── screenshot-zh.png       # [DEMO] dataset screenshot (ZH)
├── src/agent_xray/
│   ├── classifier.py           # 5-bucket JSON classifier & usage parser
│   ├── cli.py                  # `run`, `serve`, `desktop`, `report`, `export-demo`, `purge-db`
│   ├── i18n.py                 # Locale resolution, canonical labels & USD formatter
│   ├── local_sessions.py       # Per-turn OpenCode & deduplicated Claude usage importer
│   ├── privacy.py              # Length-only header auditor & recursive secret scanner
│   ├── proxy.py                # Loopback server with Host/Origin/X-Xray-Token guards
│   ├── store.py                # SQLite (0600) persistence, sanitization & pricing table
│   └── ui_html.py              # Bilingual Web UI with [DEMO] banner & honest labels
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

## 4. Known M0 Boundaries (Deferred to M1)
1. Upstream response forwarding currently reads fixed chunks (`up_resp.read(1024)` for `text/event-stream`, `up_resp.read(8192)` for non-SSE) and buffers response chunks for `usage` extraction rather than non-buffering `read1()` streaming.
2. `--block-secrets` interception inspects uncompressed JSON request bodies on `/v1/messages`, `/v1/chat/completions`, and `/v1/responses` (gzip request bodies, URL query parameters for blocking, and multipart `/v1/files` uploads are not decoded in M0; URL query strings are stripped prior to SQLite persistence).
3. `run` sets `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` without reading caller-supplied upstream URLs from those same variables prior to overwrite (use `AGENT_XRAY_ANTHROPIC_UPSTREAM` / `AGENT_XRAY_OPENAI_UPSTREAM` when pointing upstream elsewhere).
