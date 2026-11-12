# agent-xray — Engineering Specification (`v0.1.0`)

## 1. Problem Statement & Motivation
Modern AI coding agents (Claude Code, Codex, OpenCode, Cursor/CLI harnesses) send massive multi-part JSON payloads on every turn. Developers routinely burn 30,000–80,000 input tokens per turn without realizing that:
- Mounting multiple MCP servers (`mcp__rea__*`, `mcp__playwright__*`, `mcp__zotero__*`) injects tens of thousands of tokens of JSON Schema definitions on **every single turn**.
- `AGENTS.md` / `CLAUDE.md` workspace rule injections and uncached tool outputs compound across multi-step loops.
- Client SDKs attach detailed OS, CPU architecture, runtime, and telemetry headers (`x-stainless-os`, `x-stainless-arch`, `x-stainless-runtime-version`, verbose `User-Agent` strings), and pasted `.env` snippets or keys in tool outputs can leave the machine unnoticed.

Existing proxy tools either require invasive root CA certificates (`mitmproxy`), depend on heavy Node/Docker stacks, or log raw JSON blobs without understanding Coding Agent payload anatomy.

**agent-xray** is a zero-dependency Python 3.10+ local loopback streaming proxy CLI and live browser inspector (`http://127.0.0.1:8788/_xray/`) that wraps any coding agent command with zero TLS MITM certificates.

---

## 2. Core Capabilities

### 2.1 Zero-Cert Loopback Passthrough (`ANTHROPIC_BASE_URL` & `OPENAI_BASE_URL`)
- Listens strictly on `127.0.0.1:<port>` (never `0.0.0.0`).
- Routes `/anthropic/*` → `https://api.anthropic.com/*` (or `$AGENT_XRAY_ANTHROPIC_UPSTREAM`) and `/openai/*` → `https://api.openai.com/*` (or `$AGENT_XRAY_OPENAI_UPSTREAM`).
- `agent-xray run [flags] -- <cmd...>` spawns the target CLI with `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` pointed at the local loopback proxy and shuts down cleanly when the child process exits.
- Preserves **chunk-by-chunk SSE (`text/event-stream`) streaming** with immediate socket flushing so interactive terminal output experiences zero buffering delay.

### 2.2 Five-Bucket Context Token Flamegraph (`classifier.py`)
Supports Anthropic Messages API (`/v1/messages`) and OpenAI Chat Completions / Responses APIs (`/v1/chat/completions`, `/v1/responses`). Every turn is decomposed into five token buckets:
1. **`system_prompt`** — Core agent harness system prompt blocks.
2. **`workspace_rules`** — `AGENTS.md`, `CLAUDE.md`, `<user_rules>`, `.cursorrules`, and `<system-reminder>` blocks detected inside system or developer messages.
3. **`mcp_and_tools`** — Tool JSON Schema definitions (`tools[]`), further grouped by MCP server prefix (`mcp__<server>__<tool>`, `mcp_<server>.<tool>`, or `builtin`) to rank **Top Token-Hungry Tool Namespaces**.
4. **`tool_results`** — `tool_result` blocks, `role: "tool"` messages, and `function_call_output` items (file reads, grep dumps, shell outputs).
5. **`conversation`** — User prompts, assistant text, and thinking/reasoning blocks.

Token estimation uses deterministic UTF-8 / code-aware subword heuristics (~3.8 chars/token for prose, ~3.2 chars/token for JSON schemas/code) reconciled against exact upstream `usage` (`input_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`, `output_tokens`) as soon as the response or SSE stream finishes.

### 2.3 Outbound Header Audit & Secret Egress Firewall (`privacy.py`)
- **Credential Redaction Invariant**: `Authorization`, `x-api-key`, `Proxy-Authorization`, and cookie headers are **never** stored raw in memory rings or SQLite (`sk-ant-••••••••`).
- **Telemetry & Fingerprint Header Audit**: Flags SDK/OS fingerprint headers (`x-stainless-*`, `x-client-data`, `openai-organization`, OS/arch tokens in `User-Agent`). Passing `--strip-telemetry-headers` removes telemetry headers and normalizes `User-Agent: agent-xray/0.1.0` before upstream forwarding.
- **Secret Egress Guard (`--block-secrets`)**: Scans outbound user messages and tool outputs for accidental live credentials (`sk-ant-api03-...`, `sk-proj-...`, `ghp_...`, `github_pat_...`, `AKIA...`, PEM private keys). Matches are redacted in the trace log (`sk-ant… [REDACTED]`); when `--block-secrets` is enabled, the proxy aborts upstream transmission locally with HTTP `400` and a clear JSON error so the secret never leaves localhost.

### 2.4 Embedded Dark Fluoroscopy Inspector (`ui_html.py`)
- Served at `http://127.0.0.1:<port>/_xray/` with JSON API `/_xray/api/summary` and `/_xray/api/traces`.
- Offline static export via `agent-xray export-demo --out <file.html>` for reproducible sharing and documentation screenshots.
- Visual hierarchy:
  - **Turn-by-Turn Context Token Flamegraph**: Stacked horizontal bars across turns showing exact token growth and MCP schema overhead.
  - **MCP Namespace Bloat Leaderboard**: Exact token cost and tool count per MCP server (`rea`, `playwright`, `scholar`, `builtin`).
  - **Outbound Header & Egress Audit**: Side-by-side table of kept, redacted, and stripped outbound headers plus secret-scan status.

---

## 3. Package Layout & CLI Surface
```text
agent-xray/
├── docs/
│   ├── SPEC.md
│   └── screenshot.png
├── pyproject.toml
├── src/agent_xray/
│   ├── __init__.py
│   ├── classifier.py     # 5-bucket Anthropic + OpenAI payload & SSE usage parser
│   ├── privacy.py        # Header fingerprint auditor, stripper & secret scanner
│   ├── store.py          # Redacted SQLite (0600) trace persistence
│   ├── proxy.py          # Loopback ThreadingHTTPServer + streaming HTTPS forwarder
│   ├── ui_html.py        # Self-contained dark fluoroscopy SPA + static demo renderer
│   └── cli.py            # `run`, `serve`, `export-demo`, `report` commands
└── tests/
    └── test_xray.py      # Classifier, MCP ranking, privacy guard & live SSE proxy tests
```

## 4. Security & Privacy Invariants
1. Loopback bind (`127.0.0.1`) by default; refuses `0.0.0.0` unless `--allow-lan` is explicitly passed.
2. SQLite database created with `0600` file permissions; raw API keys and matched secret literals are redacted *before* database insertion.
3. Zero external network calls by `agent-xray` itself — only forwards requests initiated by the wrapped client to the configured LLM API upstream.
