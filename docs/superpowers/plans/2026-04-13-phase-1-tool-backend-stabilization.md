# Phase 1 Tool Backend Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不接入 `Hermes runtime`、不做前端的前提下，先把安全分析 `Tool backend`、`CLI`、`Schema`、`SQLite` 种子数据和自动化测试做稳定。

**Architecture:** 本阶段只实现确定性组件：`Pydantic schema`、`SQLite` 种子数据、领域服务、`Typer CLI` 和测试。运行时先脱离 `Hermes`，通过本地 CLI 和 JSON 输入输出验证工具稳定性。

**Tech Stack:** Python 3.12、`uv`、`pydantic`、`typer`、标准库 `sqlite3`、`pytest`、`ruff`

---

## Scope

- 包含主计划 `docs/superpowers/plans/2026-04-13-hermes-security-analyst-spike.md` 中的 `Task 1` 到 `Task 8`
- 不包含 `Hermes tool registry`、`agent prompt`、`patrol loop`
- 不包含真实设备接入
- 不包含前端

## Deliverables

- `Python` 工程骨架
- `9` 个核心 Tool 的请求/响应 schema
- `SQLite` 种子数据与三天攻击链样本
- `9` 个核心 Tool 的本地实现
- JSON CLI 分发与端到端测试
- 本地运行手册

## File Structure

- Create: `pyproject.toml`
- Create: `README.md`
- Create: `fixtures/spike/assets.json`
- Create: `fixtures/spike/alerts.json`
- Create: `fixtures/spike/cases.json`
- Create: `fixtures/spike/timeline.json`
- Create: `fixtures/spike/evidence.json`
- Create: `fixtures/spike/intel_cache.json`
- Create: `src/security_analyst_agent/__init__.py`
- Create: `src/security_analyst_agent/cli.py`
- Create: `src/security_analyst_agent/config.py`
- Create: `src/security_analyst_agent/db.py`
- Create: `src/security_analyst_agent/bootstrap.py`
- Create: `src/security_analyst_agent/tool_dispatch.py`
- Create: `src/security_analyst_agent/schemas/common.py`
- Create: `src/security_analyst_agent/schemas/asset_tools.py`
- Create: `src/security_analyst_agent/schemas/alert_tools.py`
- Create: `src/security_analyst_agent/schemas/case_tools.py`
- Create: `src/security_analyst_agent/schemas/intel_tools.py`
- Create: `src/security_analyst_agent/schemas/output_tools.py`
- Create: `src/security_analyst_agent/repositories/assets.py`
- Create: `src/security_analyst_agent/repositories/alerts.py`
- Create: `src/security_analyst_agent/repositories/cases.py`
- Create: `src/security_analyst_agent/services/link_explainer.py`
- Create: `src/security_analyst_agent/services/intel.py`
- Create: `src/security_analyst_agent/services/output.py`
- Create: `src/security_analyst_agent/tools/asset_tools.py`
- Create: `src/security_analyst_agent/tools/alert_tools.py`
- Create: `src/security_analyst_agent/tools/case_tools.py`
- Create: `src/security_analyst_agent/tools/intel_tools.py`
- Create: `src/security_analyst_agent/tools/output_tools.py`
- Create: `tests/conftest.py`
- Create: `tests/test_cli.py`
- Create: `tests/test_bootstrap.py`
- Create: `tests/test_alert_tools.py`
- Create: `tests/test_asset_tools.py`
- Create: `tests/test_case_tools.py`
- Create: `tests/test_intel_tools.py`
- Create: `tests/test_output_tools.py`
- Create: `tests/test_cli_e2e.py`
- Create: `docs/runbooks/hermes-spike.md`

## Execution Slices

### Slice 1: 工程骨架与 schema

- 执行主计划中的 `Task 1` 与 `Task 2`
- 目标：
  - CLI 帮助页可用
  - 通用 `ToolResponse` 骨架稳定
  - `alert.fetch` 等请求模型默认值正确

**Verification**

Run:
- `uv run pytest tests/test_cli.py::test_cli_shows_help -q`
- `uv run pytest tests/test_alert_tools.py -q`

Expected:
- PASS

### Slice 2: 种子数据与数据库

- 执行主计划中的 `Task 3`
- 目标：
  - `SQLite` schema 可初始化
  - 三天攻击链样本可导入
  - `db_conn` fixture 可复用

**Verification**

Run:
- `uv run pytest tests/test_bootstrap.py::test_bootstrap_loads_attack_chain -q`

Expected:
- PASS

### Slice 3: 读工具稳定化

- 执行主计划中的 `Task 4` 与 `Task 5`
- 目标：
  - `alert.fetch`
  - `alert.detail`
  - `asset.search`
  - `case.get`
  - `case.timeline`
  - `case.explain-link`

**Verification**

Run:
- `uv run pytest tests/test_alert_tools.py tests/test_asset_tools.py -q`
- `uv run pytest tests/test_case_tools.py -q`

Expected:
- PASS

### Slice 4: 情报与输出工具

- 执行主计划中的 `Task 6`
- 目标：
  - `intel.lookup`
  - `notify.preview`
  - `report.draft`

**Verification**

Run:
- `uv run pytest tests/test_intel_tools.py tests/test_output_tools.py -q`

Expected:
- PASS

### Slice 5: CLI 接线与文档

- 执行主计划中的 `Task 7` 与 `Task 8`
- 目标：
  - `9` 个核心 Tool 可通过 CLI 以 JSON 调用
  - 本地运行手册可用
  - `README` 和 runbook 说明边界清晰

**Verification**

Run:
- `uv run pytest tests/test_cli_e2e.py::test_cli_alert_fetch_returns_json -q`
- `uv run ruff check .`
- `uv run pytest tests -q`

Expected:
- PASS

## Acceptance Criteria

- `9` 个核心 Tool 全部可本地调用
- 所有 Tool 返回统一 JSON 骨架：`ok/summary/data/warnings/refs/page/meta`
- 三天攻击链样本可被 `case.timeline` 和 `case.explain-link` 正确表达
- `notify.preview` 和 `report.draft` 能基于种子数据输出结果
- `uv run ruff check . && uv run pytest tests -q` 通过

## Out of Scope

- `Hermes runtime` 集成
- `tool registry manifest`
- `main analyst prompt`
- `patrol loop`
- 长期记忆适配
- 真实设备 CLI/API 接入
- 前端页面

## Handoff To Phase 2

进入 Phase 2 前必须满足：

- Phase 1 所有测试通过
- CLI 输入输出契约稳定
- `report.draft` 和 `notify.preview` 已可用
- 运行手册可让他人在本地复现

Phase 2 只在此基础上增加 `Hermes runtime` 接线，不应回头修改 Tool 基础契约，除非发现阻塞型问题。

## Source Of Truth

- 详细任务明细仍以 `docs/superpowers/plans/2026-04-13-hermes-security-analyst-spike.md` 中的 `Task 1` 到 `Task 8` 为准。
