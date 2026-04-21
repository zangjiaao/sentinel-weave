# Security Analyst Agent (Phase 1)

本仓库当前实现安全分析后端（SQLite + Tool + OpenAI patrol），用于本地与半真实样本验证。

## Scope

- OpenAI patrol（默认）+ MCP/CLI 工具链
- SQLite 事实库 + 导入作业化（CSV 上传/采样/映射/问题行回流）
- 不依赖 Hermes runtime
- Web 端可复用 `services/web_backend.py` 作为后端服务层

## Quick Start

```bash
uv sync --extra dev
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.bootstrap --db-path ./spike.db
```

建议在 `.env` 中配置：

```bash
OPENAI_API_KEY=...
OPENAI_BASE_URL=...
OPENAI_PATROL_MODEL=gpt-5.4
HERMES_PATROL_TRIGGER_MODE=openai
```

## Web API (FastAPI)

```bash
UV_CACHE_DIR=.uv-cache uv run uvicorn security_analyst_agent.web_api:app --reload --port 18080
```

示例接口：

- `GET /api/intake/sources`
- `GET /api/cases`
- `GET /api/assets`
- `POST /api/intake/uploads/{job_id}/apply-map`
- `POST /api/intake/uploads/{job_id}/trigger-analysis`
- `GET /api/intake/uploads/{job_id}/analysis`
- `POST /api/notifications/preview`
- `POST /api/reports/preview`

## Web UI（MVP 页面壳）

```bash
cd web-ui
npm install
NEXT_PUBLIC_API_BASE=http://127.0.0.1:18080 npm run dev
```

当前主入口：`/alerts`（`/intake` 会重定向）。
核心流程：上传任务 → 抽样映射预览 → 确认入库 → 任务级触发分析 → 查看进展/成本。

## Example

```bash
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{"status":["new","open"],"limit":5}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli case.get --db-path ./spike.db --payload '{"case_id":"case_demo_001"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli report.draft --db-path ./spike.db --payload '{"case_id":"case_demo_001","template":"incident_report_v1","tone":"professional"}'
```

## CSV 导入作业（Web 前置流程）

```bash
# 1) 上传 CSV 并创建导入作业
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.import-csv \
  --db-path ./spike.db \
  --payload '{"csv_path":"./attacklist-2026-04-15.csv"}'

# 2) 采样（给 Agent 产出 map）
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.import-sample \
  --db-path ./spike.db \
  --payload '{"job_id":"job_xxx","limit_groups":20,"samples_per_group":3}'

# 3) dry-run 预演 / 正式导入
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.import-apply \
  --db-path ./spike.db \
  --payload '{"job_id":"job_xxx","dry_run":true}'
```

## Memory Spike 一步导入并触发巡检

```bash
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.memory_spike \
  apply-round \
  --db-path ./spike.db \
  --fixture-dir ./fixtures/spike_memory_realistic \
  --round-id round_01_realistic \
  --enqueue-events \
  --trigger \
  --trigger-dry-run
```

## Validate the Demo Chain

1. 运行 `alert.fetch` 查看最新告警队列  
2. 运行 `alert.detail` 查看 `alt_day2_webshell_01`  
3. 运行 `case.timeline` 查看 `case_demo_001` 三天链路  
4. 运行 `case.explain-link` 解释 `alt_day3_shell_01` 关联理由  
5. 运行 `notify.preview` 和 `report.draft` 验证输出草稿

## Verification

```bash
UV_CACHE_DIR=.uv-cache uv run ruff check .
UV_CACHE_DIR=.uv-cache uv run pytest tests -q
```
