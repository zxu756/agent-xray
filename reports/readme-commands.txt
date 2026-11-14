=== agent-xray README & README.zh-CN Command Verification ===
Isolated temp dir: <mktemp>/xray-readme-cmds (cleaned on exit)

1) agent-xray --version
agent-xray 0.2.0

2) agent-xray export-demo (EN & ZH)
Wrote static demo inspector to /tmp/xray-readme-cmds.Px6Afd/demo-en.html
已导出静态演示检查器至 /tmp/xray-readme-cmds.Px6Afd/demo-zh.html

3) agent-xray run --strip-telemetry-headers --block-secrets (EN & ZH)
[agent-xray] Startup auth token (X-Xray-Token): Ss5hBg9XiGH52SkroxJD8FZuYiTtSMWV
[agent-xray] Live Flamegraph UI: http://127.0.0.1:53352/_xray/ - launching python3 /tmp/xray-readme-cmds.Px6Afd/mock_agent.py

[agent-xray] Session summary: 1 turns | Tool Definition Tokens: 56 / ~83 tok | MCP Tool Share: 37% | Cache Hit Rate: 90% (2,700 / 3,000 tok) | Cost: $0.00336 (2026-11) | Stripped Telemetry Headers: 1 | Blocked leaks: 0
  - mcp:scholar          1 tools        31 tok/turn
  - builtin              1 tools        25 tok/turn
[agent-xray] 启动鉴权令牌（X-Xray-Token）：MqZACyEFAQwCi9KnhqlnUOU5YirLb4Yz
[agent-xray] 实时上下文火焰图：http://127.0.0.1:53355/_xray/ | 正在启动 python3 /tmp/xray-readme-cmds.Px6Afd/mock_agent.py

[agent-xray] 会话摘要：共 1 轮 | 工具定义占用：56 / ~83 tok | MCP 工具定义占比：37% | 缓存命中率：90%（2,700 / 3,000 tok）| 估算费用：$0.00336 (2026-11) | 去掉的遥测头：1 | 拦截密钥外泄：0
  - mcp:scholar          1 个工具        31 tok/轮
  - builtin              1 个工具        25 tok/轮

4) agent-xray serve + ANTHROPIC_BASE_URL & OPENAI_BASE_URL client requests

[agent-xray] Session summary: 2 turns | Tool Definition Tokens: 0 / ~7 tok | MCP Tool Share: 0% | Cache Hit Rate: 86% (3,600 / 4,200 tok) | Cost: $0.006435 (2026-11) | Stripped Telemetry Headers: 0 | Blocked leaks: 0

[agent-xray] 会话摘要：共 2 轮 | 工具定义占用：0 / ~7 tok | MCP 工具定义占比：0% | 缓存命中率：86%（3,600 / 4,200 tok）| 估算费用：$0.006435 (2026-11) | 去掉的遥测头：0 | 拦截密钥外泄：0

5) agent-xray desktop --import-only + report + purge-db (EN & ZH)
[agent-xray] Imported 24 recent Desktop/local turns (OpenCode Desktop & Claude Code; aggregate usage only, no 5-bucket breakdown).

[agent-xray] Session summary: 24 turns | Tool Definition Tokens: No data | MCP Tool Share: No data | Cache Hit Rate: 95% (4,264,007 / 4,482,524 tok) | Cost: Unknown price | Stripped Telemetry Headers: 0 | Blocked leaks: 0

[agent-xray] Session summary: 24 turns | Tool Definition Tokens: No data | MCP Tool Share: No data | Cache Hit Rate: 95% (4,264,007 / 4,482,524 tok) | Cost: Unknown price | Stripped Telemetry Headers: 0 | Blocked leaks: 0

[agent-xray] 会话摘要：共 24 轮 | 工具定义占用：没有数据 | MCP 工具定义占比：没有数据 | 缓存命中率：95%（4,264,007 / 4,482,524 tok）| 估算费用：未知价格 | 去掉的遥测头：0 | 拦截密钥外泄：0
[agent-xray] Purged SQLite trace database: /tmp/xray-readme-cmds.Px6Afd/desktop.db (removed 1 file(s)).
[agent-xray] 未在 /tmp/xray-readme-cmds.Px6Afd/desktop.db 发现 SQLite 追踪数据库（无需清理）。

=== ALL README & README.zh-CN COMMANDS SUCCEEDED ===
