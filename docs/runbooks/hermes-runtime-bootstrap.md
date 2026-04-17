# Hermes Runtime Bootstrap (Phase 2)

## Scope

- 仅覆盖 Hermes runtime 接入
- 默认模式：MCP Tool Discovery
- 不包含真实设备接入
- 不包含自动发送通知
- Hermes 仅作为当前 Spike 的 `Runner Adapter`，不是业务核心或唯一状态源
- 仓库文件是 Skill / Prompt / Tool 配置真源，`~/.hermes` 下的内容只视为本机运行态产物
- 为降低 patrol 轮询 token 成本，推荐为巡检任务单独使用 `~/.hermes-patrol`

## Prerequisites

1. Hermes runtime 已安装并可运行
2. 已执行 `uv sync --extra dev`
3. 已执行数据库引导：`uv run python -m security_analyst_agent.bootstrap --db-path ./spike.db`
4. 已设置环境变量（建议绝对路径）：`export SPIKE_DB_PATH=/Users/zangjiaao/Codebase/ai-pentester/spike.db`
5. 确认 CLI 可调用：`uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{}'`
6. 确认 Hermes 全局提示词文件存在：`/Users/zangjiaao/.hermes/SOUL.md`
7. 建议设置巡检运行态目录：`export HERMES_PATROL_HOME=/Users/zangjiaao/.hermes-patrol`

## Verify MCP Tool Discovery

1. 启动 MCP server（见下一节）
2. 执行 `hermes mcp test secagent`，确认能连通并发现工具列表
3. 任选一个 Tool 用最小 payload 试跑，确认 Hermes 能消费 JSON 输出

## Recommended: Run MCP Server in Listener Mode

推荐将 `secagent` 作为独立 MCP server 常驻，再让 Hermes 通过 URL 连接，避免每次会话重复拉起 stdio 进程。

1. 启动 MCP server（新终端）：
   - `make mcp-server`
   - 可指定数据库：`make mcp-server SPIKE_DB_PATH=/Users/zangjiaao/Codebase/ai-pentester/spike.db`
   - 默认监听：`http://127.0.0.1:8787/mcp`
2. 将 Hermes MCP 客户端切换到 URL：
   - `make sync-hermes-mcp-url`
   - 若手工设置，推荐：`hermes config set mcp_servers.secagent.url http://127.0.0.1:8787/mcp`
3. 验证连通：
   - `hermes mcp test secagent`

## Optional: Register via MCP CLI (Stdio Mode)

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

## Configure SOUL + Skill

1. 更新 Hermes 全局行为文件：`/Users/zangjiaao/.hermes/SOUL.md`
   - 注意：该文件是本机运行态配置，不是项目真源
   - 后续部署到其他机器时，应从仓库模板或 bootstrap 脚本生成
   - 推荐从仓库模板同步：`cp hermes/SOUL.template.md ~/.hermes/SOUL.md`
2. 在 `SOUL.md` 中声明：
   - 优先加载 `secagent-patrol`
   - 巡检时不要自由试探 `alert.ack`、`case.explain-link`、`case.upsert`、`case.link-alert`、`case.update-risk`、`intel.lookup`、`notify.send`、`report.draft` 参数
   - MCP prompt 仅作为兜底说明
3. 将仓库中的 Skill 同步到 Hermes：
   - `rm -rf ~/.hermes/skills/secagent-patrol && cp -R skills/secagent-patrol ~/.hermes/skills/secagent-patrol`
4. 确认 `secagent-patrol` 已出现在 Hermes 可用技能列表
5. 将 Skill 绑定到 patrol cron：
   - `hermes cron edit d27a82c0fa79 --add-skill secagent-patrol`

## Recommended: Isolated Patrol Runtime (Lower Token Overhead)

为了避免 cron 每轮启动都复用整套全局技能与长提示词，建议把巡检任务放到专用运行态目录中：

1. 一键同步专用运行态（推荐）：
   - `make sync-hermes-patrol`
2. 上述命令会执行：
   - 将 `hermes/SOUL.patrol.template.md` 同步到 `~/.hermes-patrol/SOUL.md`
   - 仅同步 `skills/secagent-patrol` 到 `~/.hermes-patrol/skills`
   - 将 `~/.hermes` 中 `config.yaml/.env/auth.json`（若存在）复制到 `~/.hermes-patrol`
   - 对 patrol job 执行 `--clear-skills`，再只添加 `secagent-patrol`
   - 用 `hermes/patrol-prompt.md` 覆盖 patrol job prompt
3. 运行触发器时，系统会自动使用 `HERMES_PATROL_HOME`（默认 `~/.hermes-patrol`）执行：
   - `hermes chat --continue`（优先复用最近 patrol 会话）
   - 若继续会话失败，自动回退到新会话 `hermes chat -q "<patrol prompt>"`
4. 如需兼容旧路径，仍可保留 `make sync-hermes` + `~/.hermes` 流程

## Create Main Analyst Agent

1. 新建单个 `main analyst agent`
2. 将 `hermes/agents/main-analyst.md` 作为系统提示词
3. 确认提示词中存在以下护栏：
   - 默认先调用 `alert.fetch`
   - 只在证据不足时调用 `intel.lookup`
   - 达到升级阈值时调用 `notify.send`（当前为模拟发送）
   - 仅在用户明确要求时调用 `report.draft`
   - 不要直接处理海量原始日志

## Configure Patrol Loop

1. 在 Hermes 中加载 `hermes/patrol-loop.json`
2. 核对关键字段：
   - `schedule = every_5m`
   - `entry_tool = alert.fetch`
   - `default_filters.status = [new, open]`
   - `max_alerts_per_run = 10`
   - `write_memory_on_finish = true`
3. 优先依赖 `SOUL.md + secagent-patrol` 约束巡检行为
4. 使用仓库中的 prompt 模板同步 cron 提示词：
   - `hermes cron edit d27a82c0fa79 --prompt "$(cat hermes/patrol-prompt.md)"`

## Minimal Smoke Loop

1. 手工触发一轮巡检
2. Confirm `alert.fetch` is called first
3. Confirm patrol run has `secagent-patrol` attached
4. 选择一个告警并继续调用 `case.get` 与 `case.timeline`
5. 处理完成后对告警调用 `alert.ack`（`status=triaged` 或 `closed`）避免重复巡检
6. 若证据不足，再触发一次 `intel.lookup`
7. 对高风险案件触发 `notify.send`（当前为模拟发送）
8. 仅在用户明确要求时生成 `report.draft`
9. 巡检无实质变化时输出 `[SILENT]`
10. Confirm output includes `Tool Calls`
11. Confirm output includes `Memory Summary`
12. Confirm output includes `Remaining Uncertainty`
13. Confirm all report timestamps use `Asia/Shanghai`
14. Confirm assessment wording avoids unjustified absolute claims

## Runtime Boundary Checks

每次调整 Hermes 接入方式时，都要确认：

1. 资产、告警、案件、证据、评分、用户反馈仍以数据库为事实源
2. Hermes memory 只保存巡检摘要、关注点、临时假设和待补证项
3. Tool 合约仍可被 CLI / MCP / Hermes / OpenAI SDK runner 复用
4. Skill、SOP、Prompt 模板仍以仓库文件为真源
5. Hermes session 不是唯一审计来源，关键输入、工具调用和输出需要能被系统记录或复现
