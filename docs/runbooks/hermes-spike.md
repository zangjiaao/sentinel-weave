# Hermes Spike Runbook (Phase 1 Tool Backend)

> 本 runbook 只覆盖 Phase 1：本地 Tool backend，不含 Hermes runtime 接线。

## Bootstrap

```bash
uv sync --extra dev
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.bootstrap --db-path ./spike.db
```

说明：

- `bootstrap` 现在只预置事实样本：`assets` / `alerts` / `intel_cache`
- `cases` / `case_alert_links` / `timeline_events` / `evidence` 不再由 fixture 直接灌入
- 如果你想快速复现旧版 demo 攻击链，可以显式 materialize 一次运行态对象：

```bash
UV_CACHE_DIR=.uv-cache uv run python - <<'PY'
from pathlib import Path
from security_analyst_agent.bootstrap import materialize_spike_runtime_demo
materialize_spike_runtime_demo(Path("./spike.db"))
print("materialized runtime demo: ./spike.db")
PY
```

## Core Tool Commands

```bash
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{"status":["new","open"],"limit":5}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.detail --db-path ./spike.db --payload '{"alert_id":"alt_day2_webshell_01"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli asset.search --db-path ./spike.db --payload '{"indicators":["203.0.113.10","api.example.com"]}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli case.get --db-path ./spike.db --payload '{"case_id":"case_demo_001"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli case.timeline --db-path ./spike.db --payload '{"case_id":"case_demo_001","include_evidence":true}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli case.explain-link --db-path ./spike.db --payload '{"case_id":"case_demo_001","target_type":"alert","target_id":"alt_day3_shell_01"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli intel.lookup --db-path ./spike.db --payload '{"indicator":"198.51.100.23","indicator_type":"ip"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli notify.preview --db-path ./spike.db --payload '{"case_id":"case_demo_001","channel":"feishu","template":"high_risk_case_brief"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli report.draft --db-path ./spike.db --payload '{"case_id":"case_demo_001","template":"incident_report_v1","tone":"professional"}'
```

## Validate Three-Day Attack Chain

1. `alert.fetch` 确认队列包含 `alt_day1_scan_01`、`alt_day2_webshell_01`、`alt_day3_shell_01`
2. `case.timeline` 确认阶段顺序为 `recon -> persistence -> command_execution`
3. `case.explain-link` 确认 `positive_factors` 非空
4. `notify.preview` 输出 `why_now`
5. `report.draft` 输出包含 `timeline` 的大纲

## Verification

```bash
UV_CACHE_DIR=.uv-cache uv run ruff check .
UV_CACHE_DIR=.uv-cache uv run pytest tests -q
```
