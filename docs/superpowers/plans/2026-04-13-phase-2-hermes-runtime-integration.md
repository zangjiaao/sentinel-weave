# Phase 2 Hermes Runtime Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Phase 1 的 Tool backend 已稳定的基础上，补齐 `Hermes runtime` 所需的工具注册、Agent Prompt、巡检 Loop 和运行手册，验证 `Hermes` 能稳定消费这些 Tool。

**Architecture:** 本阶段不重写 Tool backend，而是在其之上补充引擎侧接线产物：`tool registry manifest`、`main analyst prompt`、`patrol loop config` 和接入 runbook。默认采用本地 CLI Tool 注册模式，不做深度 SDK 绑定。

**Tech Stack:** `Hermes runtime`、Python 3.12、`uv`、JSON manifest、Markdown prompt、`pytest`

---

## Scope

- 包含主计划 `docs/superpowers/plans/2026-04-13-hermes-security-analyst-spike.md` 中的 `Task 9`
- 依赖 Phase 1 已完成
- 不做前端
- 不做真实设备接入

## Deliverables

- `hermes/tool-registry.json`
- `hermes/patrol-loop.json`
- `hermes/agents/main-analyst.md`
- `docs/runbooks/hermes-runtime-bootstrap.md`
- `tests/test_hermes_artifacts.py`

## File Structure

- Create: `hermes/tool-registry.json`
- Create: `hermes/patrol-loop.json`
- Create: `hermes/agents/main-analyst.md`
- Create: `docs/runbooks/hermes-runtime-bootstrap.md`
- Create: `tests/test_hermes_artifacts.py`

## Preconditions

开始 Phase 2 前必须确认：

- Phase 1 已完成
- `uv run pytest tests -q` 在本地通过
- `uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{...}'` 可返回 JSON
- 你的 `Hermes` 已安装完成

## Execution Slices

### Slice 1: 运行时产物测试先行

- 执行主计划 `Task 9` 的 `Step 1` 与 `Step 2`
- 目标：
  - 测试先约束 `tool-registry`、`patrol-loop`、`main-analyst prompt`

**Verification**

Run:
- `uv run pytest tests/test_hermes_artifacts.py -q`

Expected:
- FAIL first, because runtime artifact files do not exist yet

### Slice 2: Tool Registry Manifest

- 执行主计划 `Task 9` 的 `Step 3`
- 目标：
  - 把 `9` 个核心 Tool 注册成 `Hermes` 可理解的清单
  - 每个 Tool 都有：
    - `name`
    - `description`
    - `when_to_use`
    - `command_template`
    - `read_only`
    - `timeout_sec`
    - `cost_level`
    - `idempotent`

**Verification**

Run:
- `uv run pytest tests/test_hermes_artifacts.py::test_tool_registry_contains_nine_core_tools -q`

Expected:
- PASS

### Slice 3: Main Analyst Prompt

- 执行主计划 `Task 9` 的 `Step 4`
- 目标：
  - 给 `Hermes` 一个稳定的蓝队分析行为边界
  - 明确：
    - 默认先 `alert.fetch`
    - 证据不足时才 `intel.lookup`
    - 只做 `notify.preview`
    - 不处理海量原始日志

**Verification**

Run:
- `uv run pytest tests/test_hermes_artifacts.py::test_main_analyst_prompt_contains_guardrails -q`

Expected:
- PASS

### Slice 4: Patrol Loop 与接入手册

- 执行主计划 `Task 9` 的 `Step 5`
- 目标：
  - 用 `every_5m` 的最小巡检表达式启动
  - 首入口固定为 `alert.fetch`
  - 明确 stop conditions
  - 产出接入 `Hermes` 的 runbook

**Verification**

Run:
- `uv run pytest tests/test_hermes_artifacts.py::test_patrol_loop_starts_from_alert_fetch -q`

Expected:
- PASS

### Slice 5: Hermes 手工冒烟验证

- 基于 `docs/runbooks/hermes-runtime-bootstrap.md`
- 目标：
  - 把 `tool-registry`、`prompt`、`patrol-loop` 真正喂给 `Hermes`
  - 验证一次手工巡检闭环

**Manual Verification**

- 在 `Hermes` 中加载 `hermes/tool-registry.json`
- 使用 `hermes/agents/main-analyst.md` 创建单个 `main analyst agent`
- 加载 `hermes/patrol-loop.json`
- 手工触发一轮巡检
- 确认：
  - 第一个调用的是 `alert.fetch`
  - 能继续调用 `case.get` / `case.timeline`
  - 高风险案件可产出 `notify.preview`
  - 可生成 `report.draft`

## Acceptance Criteria

- `tests/test_hermes_artifacts.py` 全部通过
- `Hermes` 可识别并调用 `9` 个核心 Tool
- `Hermes` 的第一步是 `alert.fetch`
- `Hermes` 不会默认调用高成本情报查询
- `Hermes` 不会直接发送通知，只会生成 `notify.preview`
- 一次手工巡检可从告警摘要走到通知/报告草稿

## Out of Scope

- 多 Agent 协作
- 深度绑定 `Hermes` 私有 SDK
- 自动发送通知
- 长期记忆的复杂压缩/召回策略
- 真正生产级调度器
- 前端

## Handoff To Next Stage

Phase 2 完成后，下一步才进入：

- 更真实的 `Hermes` 长期运行验证
- 接入真实设备 CLI/API
- 前端页面与用户交互

如果 Phase 2 失败，优先回头检查：

- Tool 注册方式是否与 Hermes 兼容
- CLI 输出是否稳定
- Prompt 是否约束不足
- Loop 配置是否过于激进

## Source Of Truth

- 详细任务明细仍以 `docs/superpowers/plans/2026-04-13-hermes-security-analyst-spike.md` 中的 `Task 9` 为准。
