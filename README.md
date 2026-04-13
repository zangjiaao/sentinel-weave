# Security Analyst Agent (Phase 1)

本仓库当前只实现 Phase 1 Tool backend（Task 1–8），用于本地 Spike 验证。

## Scope

- 只读分析工具（本地 CLI + JSON 输入输出）
- 仅使用 SQLite 种子数据
- 不接 Hermes runtime
- 不接真实设备
- 不做前端

## Quick Start

```bash
uv sync --extra dev
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.bootstrap --db-path ./spike.db
```

## Example

```bash
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{"status":["new","open"],"limit":5}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli case.get --db-path ./spike.db --payload '{"case_id":"case_demo_001"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli report.draft --db-path ./spike.db --payload '{"case_id":"case_demo_001","template":"incident_report_v1","tone":"professional"}'
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
