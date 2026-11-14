# agent-xray

**[English](README.md)** | **简体中文**

**免安装 MITM 根证书的本地回环流式 HTTP/SSE 代理与中英双语（`中文 | EN`）五维上下文 Token 火焰图检查器，面向 AI 编程智能体（`Claude Code`、`Codex`、`OpenCode`）。**

![agent-xray 上下文 Token 火焰图与出站请求审计（演示数据集）](docs/screenshot-zh.png)

> **[DEMO / 演示数据] 截图说明：** 上方截图展示的是由 `agent-xray export-demo`（`build_demo_dataset()`）生成的确定性静态演示数据集，并非真实用户会话记录。`v0.2.0` 之后的未发布修订已将指标名称与底层公式及估算性质对齐（`MCP 工具定义占比（估算）`、`工具定义占用（估算）`、`五维输入构成（估算）`、`去掉的遥测头`、请求头 `值长度`）；可直接打开或重新导出 [`docs/demo-inspector.html`](docs/demo-inspector.html) 查看最新界面。

**agent-xray** 通过 `127.0.0.1` 本地回环流式 HTTP/SSE 代理（注入 `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`）包装编程智能体 CLI，**无需安装自定义 TLS 根证书**，**零第三方 Python 运行时依赖**，并同时提供可编程 Python 计量接口（`agent_xray.start_background_proxy`）供下游评测框架直接复用。

> **发布状态说明（`v0.2.0` vs 未发布）：** 已打标签的 `v0.2.0`（`main`）包含 `serve`、`run`、`export-demo`、`desktop` 与 `report`。下文中标注为 **`[未发布，v0.2.0 之后]`** 的子命令、参数与能力（`purge-db`、`--store-previews`、`--auth-token`、`--upstream` / `--anthropic-upstream` / `--openai-upstream`、`desktop --db` / `--home` / `--import-only`、`read1` 真流式 SSE 转发与 `ttft_ms` 计时、带 `（估算）` 标注的逐块五桶分类、全端点 `--block-secrets` 扫描、SQLite 写入边界统一脱敏、本地回环 `Host`/`Origin`/`X-Xray-Token` 校验及分模型含缓存计价）位于 `main`（`v0.2.0`）之后的当前源码分支，尚未打新标签发布。

> **升级安全提示（`<= v0.2.0` 老版本用户必读）：** `v0.1.0` 与 `v0.2.0` 生成的追踪数据库（默认 `~/.agent-xray/traces.db`）曾默认保存先截断后正则脱敏的 140 字符提示词预览，并保存了非认证类 HTTP 请求头的原始值。从当前源码安装（`[未发布，v0.2.0 之后]`）后，请执行以下命令删除旧数据库：
> ```bash
> agent-xray --lang zh purge-db
> ```

## 核心功能与指标定义

1. **逐块五维上下文 Token 构成火焰图（`（估算）`，`[未发布，v0.2.0 之后]` 更新）** - 将捕获到的 Anthropic `/v1/messages` 与 OpenAI `/v1/responses`、`/v1/chat/completions` JSON 请求（含 `gzip`/`deflate` 压缩请求体与 `Transfer-Encoding: chunked` 分块请求体）逐个内容块拆解为启发式估算 Token（`is_estimated = true`，`bucket_unit = "estimated_tokens"`，五桶之和恒等于 `total_estimated`）：
   - **系统提示词（`估算`）**：智能体核心底座提示词（普通 `system`、`developer` 或 `instructions` 正文中仅提及 `CLAUDE.md` 或 `AGENTS.md` 文件名时仍归入系统提示词桶）
   - **工作区规则（`估算`）**：独立规则块，以及从混合文本块中按 `<system-reminder>`、`<user_rules>`、`<workspace_rules>`、`<cursor_rules>`、`<RULE[...]>` 标签精确切分出的规则片段
   - **MCP 与工具定义（`工具定义占用（估算）`）**：按服务命名空间（`mcp:rea`、`mcp:playwright`、`mcp:scholar`、`builtin`）分组排序，区分 **`MCP 工具定义占比（估算）`**（`mcp:*` 定义 Token / 总估算输入 Token）与内置工具定义
   - **工具输出与文件读取（`估算`）**：`tool_result`、`role: "tool"` 与 `function_call_output` 返回内容
   - **对话历史（`估算`）**：用户与助手消息，以及 OpenAI `tool_calls` / `function_call` 调用参数与 `reasoning` 推理项（`summary`、`content`、`encrypted_content`）
2. **低延迟 `read1` 真流式 SSE 转发、`ttft_ms`、半截流标记与大响应 `usage` 提取（`[未发布，v0.2.0 之后]`）** - 使用 `read1(4096)` + `TCP_NODELAY` 并在每块后立即刷新套接字转发流式响应，记录首块响应延迟 `ttft_ms`；若上游在 `200 OK` 发出后中途断开，直接干净关闭客户端连接（不往 SSE 流中拼入 `HTTP/1.1 502` 文本）并在 SQLite 中记录 `stream_truncated = true`（汇总含 `truncated_count`）；通过增量行解析器（`IncrementalResponseUsageParser`）在 `2 MB+` 超大流及 `gzip`/`deflate` 压缩响应中准确提取结尾 `usage`。
3. **请求/响应头保真转发与上游网关串联（`[未发布，v0.2.0 之后]`）** - 即使开启 `--strip-telemetry-headers`（仅移除 `x-stainless-*`、`sentry-trace`、`baggage`、`x-client-data` 等遥测头并归一化 `User-Agent`），仍完整保留 `openai-organization`、`openai-project`、客户端显式发送的 `Accept-Encoding`（客户端未发时绝不注入 `Accept-Encoding: identity`）、上游 `Server`/`Date` 响应头（不重复追加）及同名重复请求头（如多行 `anthropic-beta`）。`agent-xray run` 在改写子进程环境前会先读取父环境中已有的 `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` 并自动串联为本轮上游，且 `serve` 与 `run` 均支持 `--upstream <url>`（及 `--anthropic-upstream`、`--openai-upstream`）。
4. **分模型计价表与提示词缓存命中率（`[未发布，v0.2.0 之后]`）** - 缓存命中率统一按 `cache_read / (input + cache_read + cache_write)` 计算；单轮与汇总费用按对应模型单价计算（离线环境统一标注为 `（未核对）`），其中 `claude-sonnet-4`（`4.0`）与 `claude-sonnet-4-5` 在超过 `200,000` 输入提示词 Token 时启用长上下文分段加价，而 `claude-sonnet-4-6` 采用固定单价（`$3.00 / $0.30 / $3.75 / $15.00`）。未收录价格的模型显示 **`未知价格`**（JSON 中为 `null`）；失败或本地拦截轮次（`HTTP >= 400`）计费为 `$0.0000`。
5. **本地会话聚合用量导入（`desktop`，`[未发布，v0.2.0 之后]`）** - 只读读取本机 `OpenCode Desktop`（`session_message` 逐轮表）与 `Claude Code`（`~/.claude/projects/*/*.jsonl`，按 `(message.id, requestId)` 去重）中的单轮 Token 用量（`input`、`cache_read`、`cache_write`、`output`）。由于本地日志不含原始请求体，五桶拆解标记为 **`没有数据`**（`has_bucket_breakdown = false`）。
6. **全端点密钥外泄拦截（`--block-secrets`，`[未发布，v0.2.0 之后]` 更新）与本地回环鉴权** - 对流经代理的所有转发端点（含 `/v1/messages/count_tokens`、`/v1/messages/batches`、`/v1/embeddings`、`/v1/responses`、`/v1/responses/compact` 等）、URL 路径与查询串（含循环多层 URL 百分号解码）、非认证类请求头（放行合法的 `Authorization`、`x-api-key`、`api-key` 上游鉴权头）、`gzip`/`deflate` 压缩请求体（`<= 32 MB`）、JSON `\uXXXX` 转义字符串及原始 UTF-8 字节扫描 `SECRET_PATTERNS` 列出的凭据格式（大小写无关前缀：`sk-ant-...`、`sk-proj-...`、`sk-svcacct-...`、`sk-or-v1-...`、传统 `sk-...`、`ghp_...`、`github_pat_...`、`AKIA...`、`xoxb-...`、`AIza...`、JWT 与含实际密钥体的 PEM 私钥块），命中后在本地直接返回 HTTP `400` 阻断，上游收到 0 字节。**拦截与落盘脱敏边界说明：** `--block-secrets` 与 **「密钥不写入 SQLite」仅对 `SECRET_PATTERNS` 列出的密钥格式成立**；**无固定格式的任意凭据、经过 Base64 编码的密钥以及跨多个 JSON 字段拆分的密钥无法识别。** 检查器页面与接口同时强制校验本地回环 `Host`/`Origin`（`HTTP 403`）与 `X-Xray-Token` 写操作令牌。

## 分模型单价表（`store.py`，`[未发布，v0.2.0 之后]`）

所有单价单位均为美元 / 百万 Token（`$/MTok`，依次为 `input` / `cache_read` / `cache_write` / `output`）。因离线校验未访问外部网页，各模型核对状态均标记为 `未核对`（代码中 `verified_at = "unverified"`，`PRICING_TABLE_DATE = "unverified"`）。**长上下文分段加价说明（`> 200,000` 提示词 Token）：** 对 `claude-sonnet-4`（`4.0`，含 `claude-sonnet-4-0` / `claude-sonnet-4-20*`）与 `claude-sonnet-4-5*` / `claude-sonnet-4.5*` 模型，当单轮 `input_tokens + cache_read_tokens + cache_write_tokens > 200,000` 时，`agent-xray` **启用**长上下文费率（输入与缓存读写按 `2x` 计价：输入 `$6.00`、缓存读取 `$0.60`、缓存写入 `$7.50` / 百万 Token；输出按 `1.5x` 计价：`$22.50` / 百万 Token）。`claude-sonnet-4-6*` / `claude-sonnet-4.6*` 及表中其余已收录模型系列按固定单价计算（未列出的未来 Sonnet 子版本返回 `未知价格`，不默认套用加价）。

| 模型前缀族 | 输入 ($/MTok) | 缓存读取 ($/MTok) | 缓存写入 ($/MTok) | 输出 ($/MTok) | 官方定价页 URL | 核对日期 |
|---|---:|---:|---:|---:|---|---|
| `claude-sonnet-4-6*`、`claude-sonnet-4.6*`（全窗口固定单价）、`claude-sonnet-4` / `4.0` / `4.5`（`<= 200k` 提示词 Token）、`claude-3-7-sonnet*`、`claude-3.7-sonnet*`、`claude-3-5-sonnet*`、`claude-3.5-sonnet*` | `$3.00` | `$0.30` | `$3.75` | `$15.00` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `claude-sonnet-4`（`4.0`）、`claude-sonnet-4-5*`、`claude-sonnet-4.5*`（`> 200k` 提示词 Token：`input + cache_read + cache_write > 200,000`） | `$6.00` | `$0.60` | `$7.50` | `$22.50` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `claude-opus-4-6*`、`claude-opus-4.6*`、`claude-opus-4-5*`、`claude-opus-4.5*` | `$5.00` | `$0.50` | `$6.25` | `$25.00` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `claude-opus-4*`（`4` / `4.1`）、`claude-3-opus*` | `$15.00` | `$1.50` | `$18.75` | `$75.00` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `claude-haiku-4-5*`、`claude-haiku-4.5*` | `$1.00` | `$0.10` | `$1.25` | `$5.00` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `claude-3-5-haiku*`、`claude-3.5-haiku*` | `$0.80` | `$0.08` | `$1.00` | `$4.00` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `claude-3-haiku*` | `$0.25` | `$0.03` | `$0.30` | `$1.25` | https://docs.anthropic.com/en/docs/about-claude/pricing | `未核对` |
| `gpt-4o-mini*` | `$0.15` | `$0.075` | `$0.15` | `$0.60` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-4o*` | `$2.50` | `$1.25` | `$2.50` | `$10.00` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-4.1-nano*` | `$0.10` | `$0.025` | `$0.10` | `$0.40` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-4.1-mini*` | `$0.40` | `$0.10` | `$0.40` | `$1.60` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-4.1*` | `$2.00` | `$0.50` | `$2.00` | `$8.00` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-5-nano*` | `$0.05` | `$0.005` | `$0.05` | `$0.40` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-5-mini*` | `$0.25` | `$0.025` | `$0.25` | `$2.00` | https://openai.com/api/pricing/ | `未核对` |
| `gpt-5*` | `$1.25` | `$0.125` | `$1.25` | `$10.00` | https://openai.com/api/pricing/ | `未核对` |
| `codex-mini*` | `$1.50` | `$0.375` | `$1.50` | `$6.00` | https://openai.com/api/pricing/ | `未核对` |
| `o4-mini*` | `$1.10` | `$0.275` | `$1.10` | `$4.40` | https://openai.com/api/pricing/ | `未核对` |
| `o3-mini*` | `$1.10` | `$0.55` | `$1.10` | `$4.40` | https://openai.com/api/pricing/ | `未核对` |
| `o3*` | `$2.00` | `$0.50` | `$2.00` | `$8.00` | https://openai.com/api/pricing/ | `未核对` |
| `o1*` | `$15.00` | `$7.50` | `$15.00` | `$60.00` | https://openai.com/api/pricing/ | `未核对` |

## SQLite 落盘字段说明（`traces` 表）

默认数据库路径为 `~/.agent-xray/traces.db`（权限 `0600`，可通过 `--db <路径>` 或 `:memory:` 覆盖）。在 `[未发布，v0.2.0 之后]` 中，**写入 SQLite 的所有参数**（无论正常 `200` 还是拦截 `400` 轮次）均统一经过 `TraceStore._execute_write`（`_sanitize_db_value` -> 递归 `redact_secrets_in_text`）脱敏（**「密钥不写入 SQLite」仅对 `SECRET_PATTERNS` 列出的密钥格式成立；开启 `--store-previews` 或写入自由文本字段时，无固定格式的任意凭据无法识别**）：

| 字段名 | 落盘内容 | 隐私与数据规则（`[未发布，v0.2.0 之后]`） |
|---|---|---|
| `provider`, `model`, `path`, `status_code`, `latency_ms`, `ttft_ms`, `blocked`, `stream_truncated` | 供应商、模型名、路径、HTTP 状态码、总耗时毫秒、首块响应耗时毫秒（`REAL`，可为空）、拦截标记、上游半截断流标记（`INTEGER`） | `path` 通过 `urlsplit(path).path` 剥离查询参数并循环解码脱敏路径密钥；`provider`、`model` 与 `path` 落盘前均执行密钥脱敏 |
| `buckets_json`, `namespaces_json`, `usage_json` | 五桶启发式估算整数 Token、MCP 命名空间统计（导入会话含 `session_id`）与上游精确 `usage` 计数 | 数值统计及脱敏后的命名空间/会话标识 |
| `headers_json` | `[{"name": "...", "value_length": 54, "category": "...", "action": "..."}]` | **仅保存脱敏后的请求头名称与长度 `value_length`**，不保存原始或截断请求头值 |
| `secrets_json` | `[{"rule": "Anthropic API Key", "field": "messages[0].content"}]` | **仅保存脱敏后的规则名与字段/请求头/查询参数位置**，不保存密钥原文或片段 |
| `prompt_preview` | 默认为空字符串 `""` | **默认不落盘任何提示词文本**；仅在显式开启 `--store-previews` 时先对全文做密钥脱敏、再截断至 140 字符，且被拦截（`400`）轮次始终为空字符串 `""` |

## 当前已知边界

- **密钥拦截与落盘脱敏范围（`--block-secrets`、`SECRET_PATTERNS`）**：`--block-secrets` 与「密钥不写入 SQLite」**仅对 `SECRET_PATTERNS` 列出的密钥格式成立**；**无固定格式的任意凭据、经过 Base64 编码的密钥以及跨多个 JSON 字段拆分的密钥无法识别**（多部分上传中的任意二进制编码内容同样不做解码）。启用 `--block-secrets` 时，解压后超过 `32 MB` 安全上限或损坏无法解压的 `gzip`/`deflate` 请求体会按失败关闭策略直接返回 `HTTP 400`。
- **启发式五桶 Token 估算**：五桶输入拆解基于确定性字符/中日韩（CJK）启发式比例（ASCII 约 `3.75` 字符/Token、CJK 约 `1.18` 字符/Token［即 `0.85` Token/CJK 字符］、工具 JSON Schema 约 `3.25` 字符/Token），并非厂商 BPE 分词器，因此统一显式标注为 **`估算`**（`is_estimated = true`）。联网调用真实付费 API 的估算误差标定由环境变量 `XRAY_REAL_API=1` 门控，离线验收默认不执行。
- **离线单价核对状态与本地桌面日志**：分模型单价表（含 `claude-sonnet-4`［`4.0`］/ `claude-sonnet-4-5` 的 `> 200k` 长上下文分段费率及 `claude-sonnet-4-6` 固定单价）在离线环境下均标记为 `未核对`（`unverified`）；`desktop` 导入的本地日志因不含原始网络请求体，五桶拆解显示为 `没有数据`。

## 快速上手

环境要求：Python 3.10+（仅依赖 Python 标准库）：

```bash
git clone https://github.com/zxu756/agent-xray.git
cd agent-xray
python3 -m venv .venv
.venv/bin/pip install -e .
```

### 查看版本并导出离线 `[DEMO]` 演示工作台

```bash
agent-xray --version
agent-xray --lang zh export-demo --out docs/demo-inspector.html
```

### 包装编程智能体会话（本地回环代理与上游网关串联）

```bash
# 包装智能体命令（自动串联父环境中已有的 ANTHROPIC_BASE_URL / OPENAI_BASE_URL）
agent-xray --lang zh run --strip-telemetry-headers --block-secrets -- <你的智能体命令>

# 指定独立 SQLite 数据库路径运行
agent-xray --lang zh run --db /tmp/xray-session.db --strip-telemetry-headers --block-secrets -- <你的智能体命令>

# 显式指定自定义上游网关地址（`[未发布，v0.2.0 之后]`）
agent-xray --lang zh run --upstream http://127.0.0.1:9000 --db /tmp/xray-gateway.db --strip-telemetry-headers --block-secrets -- <你的智能体命令>
```

### 独立代理服务模式

```bash
agent-xray --lang zh serve --port 8788 --db /tmp/xray-serve.db --strip-telemetry-headers --block-secrets
```

将客户端指向（或通过 `--upstream <url>` / `--anthropic-upstream <url>` / `--openai-upstream <url>` 指定上游）：
- `ANTHROPIC_BASE_URL=http://127.0.0.1:8788/anthropic`
- `OPENAI_BASE_URL=http://127.0.0.1:8788/openai/v1`

### 导入本机桌面会话（`desktop`）、终端汇总（`report`）与清理数据库（`purge-db`，`[未发布，v0.2.0 之后]`）

```bash
# 将本机 OpenCode Desktop 与 Claude Code 的单轮聚合 Token 导入临时数据库
agent-xray --lang zh desktop --db /tmp/xray-desktop.db --import-only

# 从指定数据库输出英文或中文终端摘要
agent-xray --lang en report --db /tmp/xray-desktop.db
agent-xray --lang zh report --db /tmp/xray-desktop.db

# 删除指定追踪数据库及其 -wal / -shm 附属文件
agent-xray --lang zh purge-db --db /tmp/xray-desktop.db
```

## 架构与工程规范

完整工程规范（含可编程 Python 接口 `start_background_proxy` 说明）请参阅：[docs/SPEC.md](docs/SPEC.md)。

## 开源许可

MIT
