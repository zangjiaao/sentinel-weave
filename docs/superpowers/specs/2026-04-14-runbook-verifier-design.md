# Runbook Verifier Design

## 背景

`docs/runbooks/manifests/hermes-memory-spike.json` 是机器可执行 runbook。每次调整 fixture、Agent Tool 或巡检流程后，都需要手工执行多轮命令，容易出现两类问题：

- 人工脚本一次性灌完所有轮次，验证结果不能代表真实逐轮巡检。
- 只看自然语言报告，无法快速验证数据库中的 `run_id`、`analysis_cutoff_at`、审计表和实体评估是否自洽。

## 目标

提供一个可重复执行的 runbook 验证入口：

```bash
uv run python -m security_analyst_agent.runbook_verify --scenario hermes-memory-spike
```

它用于快速验证 `fixtures/spike_memory` + `docs/runbooks/manifests/hermes-memory-spike.json` 对应的核心工作流。

## 非目标

- 不解析 Markdown。
- 不真实调用 Hermes CLI。
- 不做生产级编排系统。

## 方案

采用 “JSON Runbook + Verifier” 结构：

- `docs/runbooks/manifests/hermes-memory-spike.json`：机器可执行 runbook，包含 round 顺序、Tool 动作和断言。
- `src/security_analyst_agent/runbook_verify.py`：读取 manifest，逐轮应用 fixture，创建本轮巡检 run，执行本轮 Tool 动作和断言。
- `tests/test_runbook_verify.py`：pytest 包装测试，确保 verifier 能在 CI/本地回归中运行。

## 数据流

1. 初始化临时数据库。
2. 执行 `bootstrap_memory_spike_database(db_path)`。
3. 读取 manifest 中的 round 顺序。
4. 对每一轮：
   - `apply_memory_spike_round(db_path, round_id)`
   - 创建独立 `patrol_runs` 记录。
   - 使用该轮 `analysis_cutoff_at` 绑定 Tool 上下文。
   - 执行本轮指定 Tool 调用。
   - 执行本轮断言。
5. 执行最终断言并输出 JSON summary。

## 核心断言

- 第 1 轮看不到 `evi_webshell_01` / `evi_shell_conn_01` 等未来证据。
- 每轮 `run_id` 和 `analysis_cutoff_at` 自洽。
- `alert_decisions` 不包含 `link_alert` / `risk_update`。
- `link_decisions`、`case_assessments`、`entity_assessments` 有结构化记录。
- 高风险攻击 IP 最终为：
  - `198.51.100.23`
  - `198.51.100.77`
  - `198.51.100.91`
- `192.0.2.91`、`192.0.2.123` 不会成为高风险攻击者。
- `203.0.113.10` 被标记为 `compromised_host`，风险为 `high` 或 `medium`。

## 输出

成功时输出：

```text
PASS: runbook scenario hermes-memory-spike
{...json summary...}
```

失败时抛出明确错误，包含：

- `scenario`
- `round_id`
- `assertion`
- `detail`

## 边界说明

这套 verifier 验证的是“工作流 contract”，不是 Hermes 的自然语言质量。Hermes 质量仍需要后续通过真实 cron 输出和人工抽样复盘评估。
