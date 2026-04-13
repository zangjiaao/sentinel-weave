# Hermes Runtime Bootstrap (Phase 2)

## Scope

- 仅覆盖 Hermes runtime 接入
- 默认模式：本地 CLI Tool 注册
- 不包含真实设备接入
- 不包含自动发送通知

## Prerequisites

1. Hermes runtime 已安装并可运行
2. 已执行 `uv sync --extra dev`
3. 已执行数据库引导：`uv run python -m security_analyst_agent.bootstrap --db-path ./spike.db`
4. 已设置环境变量（建议绝对路径）：`export SPIKE_DB_PATH=/Users/zangjiaao/Codebase/ai-pentester/spike.db`
5. 确认 CLI 可调用：`uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{}'`

## Register Tool Registry

1. 在 Hermes 中导入 `hermes/tool-registry.json`
2. 确认识别到 9 个 Tool：
   - `alert.fetch`
   - `alert.detail`
   - `asset.search`
   - `case.get`
   - `case.timeline`
   - `case.explain-link`
   - `intel.lookup`
   - `notify.preview`
   - `report.draft`
3. 任选一个 Tool 用最小 payload 试跑，确认 Hermes 能消费 JSON 输出

## Optional: Register via MCP CLI

如果你的 Hermes 使用 MCP 管理 Tool，可直接用 CLI 注册本地 stdio server：

1. 设置数据库路径环境变量：
   - `export SPIKE_DB_PATH=/Users/zangjiaao/Codebase/ai-pentester/spike.db`
2. 添加 MCP server：
   - `hermes mcp add secagent --command uv --args run python -m security_analyst_agent.mcp_server --env UV_WORKING_DIR=/Users/zangjiaao/Codebase/ai-pentester SPIKE_DB_PATH=/Users/zangjiaao/Codebase/ai-pentester/spike.db`
3. 验证连通：
   - `hermes mcp test secagent`
4. 按需启用工具：
   - `hermes mcp configure secagent`
5. 在会话中刷新：
   - `/reload-mcp`

## Create Main Analyst Agent

1. 新建单个 `main analyst agent`
2. 将 `hermes/agents/main-analyst.md` 作为系统提示词
3. 确认提示词中存在以下护栏：
   - 默认先调用 `alert.fetch`
   - 只在证据不足时调用 `intel.lookup`
   - 只生成 `notify.preview`，不直接发送通知
   - 不要直接处理海量原始日志

## Configure Patrol Loop

1. 在 Hermes 中加载 `hermes/patrol-loop.json`
2. 核对关键字段：
   - `schedule = every_5m`
   - `entry_tool = alert.fetch`
   - `default_filters.status = [new, open]`
   - `max_alerts_per_run = 10`
   - `write_memory_on_finish = true`

## Minimal Smoke Loop

1. 手工触发一轮巡检
2. Confirm `alert.fetch` is called first
3. 选择一个告警并继续调用 `case.get` 与 `case.timeline`
4. 若证据不足，再触发一次 `intel.lookup`
5. 对高风险案件生成 `notify.preview`
6. 最后生成 `report.draft`
7. 确认本轮无任何通知发送动作，仅有草稿输出
