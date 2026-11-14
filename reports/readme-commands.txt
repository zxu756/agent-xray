=== agent-xray README.md & README.zh-CN.md Extracted Command Verification ===
Isolated temp dir: <mktemp>/xray-readme-cmds (cleaned on exit)
Extracted bash blocks: README.md=6 blocks (15 commands), README.zh-CN.md=6 blocks (15 commands)

--- Verifying README.md ---
[EXEC PASS] README.md block#1.1: `agent-xray purge-db` -> exit=0 | [agent-xray] Purged SQLite trace database: <mktemp> (removed 1 file(s)).
[SKIP] README.md block#2.1: `git clone https://github.com/zxu756/agent-xray.git` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[SKIP] README.md block#2.2: `cd agent-xray` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[SKIP] README.md block#2.3: `python3 -m venv .venv` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[SKIP] README.md block#2.4: `.venv/bin/pip install -e .` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[EXEC PASS] README.md block#3.1: `agent-xray --version` -> exit=0 | agent-xray 0.2.0
[EXEC PASS] README.md block#3.2: `agent-xray export-demo --out docs/demo-inspector.html` -> exit=0 | Wrote static demo inspector to <mktemp>
[SUBSTITUTE] README.md block#4.1: replacing `<your-agent-command>` in `agent-xray run --strip-telemetry-headers --block-secrets -- <your-agent-command>` with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)
  [X15 DB ASSERT PASS] README.md#b4.1: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets=[{'rule': 'Anthropic API Key', 'field': 'url.query.key'}, {'rule': 'Anthropic API Key', 'field': 'model'}, {'rule': 'Anthropic API Key', 'field': 'messages[0].content'}], dump_hits=0)
[SUBSTITUTE] README.md block#4.2: replacing `<your-agent-command>` in `agent-xray --lang zh run --db <mktemp> --strip-telemetry-headers --block-secrets -- <your-agent-command>` with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)
  [X15 DB ASSERT PASS] README.md#b4.2: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets=[{'rule': 'Anthropic API Key', 'field': 'url.query.key'}, {'rule': 'Anthropic API Key', 'field': 'model'}, {'rule': 'Anthropic API Key', 'field': 'messages[0].content'}], dump_hits=0)
[SUBSTITUTE] README.md block#4.3: replacing `<your-agent-command>` in `agent-xray run --upstream http://127.0.0.1:9000 --db <mktemp> --strip-telemetry-headers --block-secrets -- <your-agent-command>` with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)
  [X15 DB ASSERT PASS] README.md#b4.3: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets=[{'rule': 'Anthropic API Key', 'field': 'url.query.key'}, {'rule': 'Anthropic API Key', 'field': 'model'}, {'rule': 'Anthropic API Key', 'field': 'messages[0].content'}], dump_hits=0)
[EXEC PASS] README.md block#5.1: `agent-xray serve --port 8788 --db <mktemp> --strip-telemetry-headers --block-secrets` -> exit=0, rows=2 (200 & 400), dump_secret_hits=0
[EXEC PASS] README.md block#6.1: `agent-xray desktop --db <mktemp> --import-only` -> exit=0 | [agent-xray] Imported 3 recent Desktop/local turns (OpenCode Desktop & Claude Code; aggregate usage only, no 5-bucket breakdown).
[EXEC PASS] README.md block#6.2: `agent-xray --lang en report --db <mktemp>` -> exit=0 | [agent-xray] Session summary: 3 turns | Tool Definition Tokens: No data | MCP Tool Share: No data | Cache Hit Rate: 86% (4,300 / 5,000 tok) | Cost: $0.00624 (unverified) | Stripped Telemetry Headers: 0 | Blocked leaks: 0
[EXEC PASS] README.md block#6.3: `agent-xray --lang zh report --db <mktemp>` -> exit=0 | [agent-xray] 会话摘要：共 3 轮 | 工具定义占用：没有数据 | MCP 工具定义占比：没有数据 | 缓存命中率：86%（4,300 / 5,000 tok）| 估算费用：$0.00624（未核对） | 去掉的遥测头：0 | 拦截密钥外泄：0
[EXEC PASS] README.md block#6.4: `agent-xray purge-db --db <mktemp>` -> exit=0 | [agent-xray] Purged SQLite trace database: <mktemp> (removed 1 file(s)).

--- Verifying README.zh-CN.md ---
[EXEC PASS] README.zh-CN.md block#1.1: `agent-xray --lang zh purge-db` -> exit=0 | [agent-xray] 已清理 SQLite 追踪数据库：<mktemp> 1 个文件）。
[SKIP] README.zh-CN.md block#2.1: `git clone https://github.com/zxu756/agent-xray.git` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[SKIP] README.zh-CN.md block#2.2: `cd agent-xray` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[SKIP] README.zh-CN.md block#2.3: `python3 -m venv .venv` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[SKIP] README.zh-CN.md block#2.4: `.venv/bin/pip install -e .` -> Reason: network clone / virtualenv pip install skipped in offline isolated check; running working-tree CLI directly
[EXEC PASS] README.zh-CN.md block#3.1: `agent-xray --version` -> exit=0 | agent-xray 0.2.0
[EXEC PASS] README.zh-CN.md block#3.2: `agent-xray --lang zh export-demo --out docs/demo-inspector.html` -> exit=0 | 已导出静态演示检查器至 <mktemp>
[SUBSTITUTE] README.zh-CN.md block#4.1: replacing `<你的智能体命令>` in `agent-xray --lang zh run --strip-telemetry-headers --block-secrets -- <你的智能体命令>` with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)
  [X15 DB ASSERT PASS] README.zh-CN.md#b4.1: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets=[{'rule': 'Anthropic API Key', 'field': 'url.query.key'}, {'rule': 'Anthropic API Key', 'field': 'model'}, {'rule': 'Anthropic API Key', 'field': 'messages[0].content'}], dump_hits=0)
[SUBSTITUTE] README.zh-CN.md block#4.2: replacing `<你的智能体命令>` in `agent-xray --lang zh run --db <mktemp> --strip-telemetry-headers --block-secrets -- <你的智能体命令>` with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)
  [X15 DB ASSERT PASS] README.zh-CN.md#b4.2: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets=[{'rule': 'Anthropic API Key', 'field': 'url.query.key'}, {'rule': 'Anthropic API Key', 'field': 'model'}, {'rule': 'Anthropic API Key', 'field': 'messages[0].content'}], dump_hits=0)
[SUBSTITUTE] README.zh-CN.md block#4.3: replacing `<你的智能体命令>` in `agent-xray --lang zh run --upstream http://127.0.0.1:9000 --db <mktemp> --strip-telemetry-headers --block-secrets -- <你的智能体命令>` with local loopback mock_agent_normal.py & mock_agent_blocked.py (real external CLI not invoked)
  [X15 DB ASSERT PASS] README.zh-CN.md#b4.3: normal(200, path=/v1/messages, preview='') & blocked(400, model=claude-[REDACTED], secrets=[{'rule': 'Anthropic API Key', 'field': 'url.query.key'}, {'rule': 'Anthropic API Key', 'field': 'model'}, {'rule': 'Anthropic API Key', 'field': 'messages[0].content'}], dump_hits=0)
[EXEC PASS] README.zh-CN.md block#5.1: `agent-xray --lang zh serve --port 8788 --db <mktemp> --strip-telemetry-headers --block-secrets` -> exit=0, rows=2 (200 & 400), dump_secret_hits=0
[EXEC PASS] README.zh-CN.md block#6.1: `agent-xray --lang zh desktop --db <mktemp> --import-only` -> exit=0 | [agent-xray] 已导入 3 条近期本地桌面会话轮次（OpenCode Desktop 与 Claude Code，仅聚合 Token，不含原始请求五桶拆分）。
[EXEC PASS] README.zh-CN.md block#6.2: `agent-xray --lang en report --db <mktemp>` -> exit=0 | [agent-xray] Session summary: 3 turns | Tool Definition Tokens: No data | MCP Tool Share: No data | Cache Hit Rate: 86% (4,300 / 5,000 tok) | Cost: $0.00624 (unverified) | Stripped Telemetry Headers: 0 | Blocked leaks: 0
[EXEC PASS] README.zh-CN.md block#6.3: `agent-xray --lang zh report --db <mktemp>` -> exit=0 | [agent-xray] 会话摘要：共 3 轮 | 工具定义占用：没有数据 | MCP 工具定义占比：没有数据 | 缓存命中率：86%（4,300 / 5,000 tok）| 估算费用：$0.00624（未核对） | 去掉的遥测头：0 | 拦截密钥外泄：0
[EXEC PASS] README.zh-CN.md block#6.4: `agent-xray --lang zh purge-db --db <mktemp>` -> exit=0 | [agent-xray] 已清理 SQLite 追踪数据库：<mktemp> 1 个文件）。

=== ALL EXTRACTED README.md & README.zh-CN.md COMMANDS & DB ASSERTIONS PASSED ===
